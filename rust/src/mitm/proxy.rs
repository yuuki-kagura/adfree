//! The splice: decides where each byte goes once both TLS halves exist.
//!
//! ```text
//!   client bytes ─▶ ServerConnection ─▶ plaintext ─▶ [edit] ─▶ ClientConnection ─▶ peer
//!   peer bytes   ─▶ ClientConnection ─▶ plaintext ─▶ [edit] ─▶ ServerConnection ─▶ client
//! ```
//!
//! Everything is non-blocking and returns the payloads to write back, so the
//! packet loop stays in charge of TCP segmentation and never blocks a syscall.

use crate::mitm::http::{self, Injectable};
use crate::mitm::tls::{
    self, feed_client, feed_client_wire, feed_server, send_to_client, FlowResolver, TlsSession,
};
use rustls::{ClientConfig, ServerConnection};
use std::sync::Arc;

/// Upper bound on client bytes buffered while waiting for the ClientHello.
/// A hello is a few KB; anything beyond this is not TLS we can terminate and
/// is spliced through untouched.
const MAX_PENDING_WIRE: usize = 64 * 1024;

/// What a caller must do with the bytes a step produced.
#[derive(Default, Debug)]
pub struct Outcome {
    /// Bytes destined for the client (encrypted with our leaf).
    pub to_client: Vec<u8>,
    /// Bytes destined for the real server (encrypted with the real cert).
    pub to_peer: Vec<u8>,
    /// Set when either side closed the session.
    pub closed: bool,
    /// Bytes we rewrote on the way through (HTML injection).
    pub injected: usize,
}

impl Outcome {
    pub fn is_empty(&self) -> bool {
        self.to_client.is_empty() && self.to_peer.is_empty() && !self.closed
    }

    /// Folds another step's result in (a flush produced by the pending state
    /// as it turned active, on top of the step that triggered it).
    pub fn merge(&mut self, other: Outcome) {
        self.to_client.extend(other.to_client);
        self.to_peer.extend(other.to_peer);
        self.closed |= other.closed;
        self.injected += other.injected;
    }
}

/// Where a relay's TLS termination stands.
enum ProxyState {
    /// Armed but not open: the hostname to present upstream comes from the
    /// ClientHello, so the upstream half is created once rustls has parsed it.
    /// `raw` keeps the client's bytes so a non-TLS stream can still be spliced
    /// through untouched.
    Pending(Box<PendingState>),
    /// Both halves are up; bytes are decrypted, edited and re-encrypted.
    Active(Box<TlsSession>),
    /// The client is not speaking TLS to us: bytes are spliced untouched.
    Plain,
}

/// What the pending state holds until the ClientHello names a host.
struct PendingState {
    server: ServerConnection,
    resolver: Arc<FlowResolver>,
    upstream: Arc<ClientConfig>,
    raw: Vec<u8>,
}

/// One intercepted connection.
pub struct ProxySession {
    state: ProxyState,
    /// The SNI the flow opened with (the hostname filtering sees).
    captured: Option<String>,
    /// Buffers for a partial HTTP response, so injection sees a whole body.
    pub pending_response: Vec<u8>,
    /// Plaintext body we already injected into, waiting to be flushed.
    pub outbound_response: Vec<u8>,
    /// Bytes read from the peer that are not yet processed.
    pub peer_buffer: Vec<u8>,
    /// Bytes from the client that are not yet processed.
    pub client_buffer: Vec<u8>,
    /// Scripts to inject into HTML (already combined).
    pub script_src: String,
}

impl ProxySession {
    /// A session whose halves are already open (tests, and any caller that
    /// knows the hostname up front).
    pub fn new(session: TlsSession, script_src: String) -> Self {
        ProxySession {
            state: ProxyState::Active(Box::new(session)),
            captured: None,
            pending_response: Vec::new(),
            outbound_response: Vec::new(),
            peer_buffer: Vec::new(),
            client_buffer: Vec::new(),
            script_src,
        }
    }

    /// A session that opens itself from the client's ClientHello.
    ///
    /// The DNS table is not consulted: a browser's own cache (or any client
    /// that resolved through a channel we do not see) can put a connection on
    /// an address we never learned, and HTTPS filtering must not silently
    /// skip those. The SNI in the hello is the authoritative hostname.
    pub fn new_pending(
        resolver: Arc<tls::SniCertResolver>,
        upstream_config: Arc<ClientConfig>,
        script_src: String,
    ) -> Result<Self, String> {
        let resolver = FlowResolver::new(resolver);
        let server = tls::new_server(tls::server_config_dyn(resolver.clone()))?;
        Ok(ProxySession {
            state: ProxyState::Pending(Box::new(PendingState {
                server,
                resolver,
                upstream: upstream_config,
                raw: Vec::new(),
            })),
            captured: None,
            pending_response: Vec::new(),
            outbound_response: Vec::new(),
            peer_buffer: Vec::new(),
            client_buffer: Vec::new(),
            script_src,
        })
    }

    /// The SNI captured from the ClientHello, once it has arrived.
    pub fn captured_sni(&self) -> Option<String> {
        self.captured.clone()
    }

    /// True while the client half has not finished its handshake.
    pub fn server_handshaking(&self) -> bool {
        match &self.state {
            ProxyState::Pending { .. } => true,
            ProxyState::Active(session) => tls::server_handshaking(&session.server),
            ProxyState::Plain => false,
        }
    }

    /// True while the server half has not finished its handshake.
    pub fn client_handshaking(&self) -> bool {
        match &self.state {
            ProxyState::Pending { .. } => true,
            ProxyState::Active(session) => tls::client_handshaking(&session.client),
            ProxyState::Plain => false,
        }
    }

    /// Bytes the client just sent (already decrypted is not possible yet).
    ///
    /// `payload` is raw TLS from the client: it goes into the server half, and
    /// during the handshake the resulting wire bytes must be handed to the
    /// client, not the peer.
    pub fn on_client_payload(&mut self, payload: &[u8]) -> Result<Outcome, String> {
        match &mut self.state {
            // Not TLS: the relay degrades to a transparent splice.
            ProxyState::Plain => Ok(Outcome {
                to_peer: payload.to_vec(),
                ..Outcome::default()
            }),
            ProxyState::Pending { .. } => self.pending_client_payload(payload),
            ProxyState::Active(session) => {
                let plain = feed_server(&mut session.server, payload)?;
                self.after_client_feed(plain)
            }
        }
    }

    /// The pending state: accumulate, watch for the hello, open and hand off.
    fn pending_client_payload(&mut self, payload: &[u8]) -> Result<Outcome, String> {
        let ProxyState::Pending(state) = &mut self.state else {
            return Ok(Outcome::default());
        };
        if state.raw.len() + payload.len() > MAX_PENDING_WIRE {
            return Ok(self.splice_pending_verbatim());
        }
        state.raw.extend_from_slice(payload);
        let fed = feed_server(&mut state.server, payload);
        let captured = state.resolver.captured();
        match fed {
            Err(e) => {
                if captured.is_some() {
                    // Mid-handshake failure: the client has already seen our
                    // answers, splicing raw bytes now would corrupt the flow.
                    return Err(e);
                }
                // Not a ClientHello: splice the stream through untouched.
                Ok(self.splice_pending_verbatim())
            }
            Ok(plain) => {
                let Some(name) = captured else {
                    // Partial hello: rustls is waiting for the rest. Nothing
                    // meaningful to send yet (normally empty).
                    let ProxyState::Pending(state) = &mut self.state else {
                        return Ok(Outcome::default());
                    };
                    return Ok(Outcome {
                        to_client: tls::take_server_outbound(&mut state.server),
                        ..Outcome::default()
                    });
                };
                // The hello named a host: open the upstream half for it.
                let (server, upstream, raw) =
                    match std::mem::replace(&mut self.state, ProxyState::Plain) {
                        ProxyState::Pending(state) => {
                            let PendingState {
                                server,
                                upstream,
                                raw,
                                ..
                            } = *state;
                            (server, upstream, raw)
                        }
                        other => {
                            self.state = other;
                            return Ok(Outcome::default());
                        }
                    };
                let client = match tls::new_client(upstream, &name) {
                    Ok(client) => client,
                    Err(_) => {
                        // Unusable name: keep the connection alive as a splice.
                        return Ok(Outcome {
                            to_peer: raw,
                            ..Outcome::default()
                        });
                    }
                };
                self.state = ProxyState::Active(Box::new(TlsSession { server, client }));
                self.captured = Some(name);
                let mut outcome = self.after_client_feed(plain)?;
                // Peer bytes that raced in while pending are processed now
                // that the upstream half exists.
                if !self.peer_buffer.is_empty() {
                    let buffered = std::mem::take(&mut self.peer_buffer);
                    outcome.merge(self.after_peer_wire(buffered)?);
                }
                Ok(outcome)
            }
        }
    }

    /// Gives up on intercepting: everything the client sent so far goes to the
    /// peer verbatim and later bytes follow the plain path.
    fn splice_pending_verbatim(&mut self) -> Outcome {
        let raw = match std::mem::replace(&mut self.state, ProxyState::Plain) {
            ProxyState::Pending(state) => state.raw,
            other => {
                self.state = other;
                return Outcome::default();
            }
        };
        Outcome {
            to_peer: raw,
            ..Outcome::default()
        }
    }

    /// Everything that follows a client feed once both halves are up.
    fn after_client_feed(&mut self, plain: Vec<u8>) -> Result<Outcome, String> {
        let ProxyState::Active(session) = &mut self.state else {
            return Ok(Outcome::default());
        };
        let mut outcome = Outcome::default();
        if tls::server_handshaking(&session.server) {
            // Our own handshake answers go back to the client.
            outcome.to_client = tls::take_server_outbound(&mut session.server);
            return Ok(outcome);
        }
        // Our handshake with the client is complete: everything the server
        // half produced (NewSessionTicket and friends) is for the client, and
        // any plaintext is an HTTP request. The request waits until the
        // upstream half finishes its own handshake (`client_buffer`), because
        // the real server must not see it as raw bytes.
        if !plain.is_empty() {
            self.client_buffer.extend_from_slice(&plain);
        }
        // Open the upstream handshake: rustls queues the ClientHello inside
        // the connection and nobody sends it unless we drain it here. Without
        // this the real server is never asked and every HTTPS page hangs.
        let hello = tls::take_client_outbound(&mut session.client);
        outcome.to_peer = hello;
        if !tls::client_handshaking(&session.client) && !self.client_buffer.is_empty() {
            let request = std::mem::take(&mut self.client_buffer);
            outcome.to_peer.extend(feed_client(&mut session.client, &request)?);
        }
        outcome.to_client = tls::take_server_outbound(&mut session.server);
        Ok(outcome)
    }

    /// Bytes the real server just sent.
    pub fn on_peer_payload(&mut self, payload: &[u8]) -> Result<Outcome, String> {
        match &mut self.state {
            ProxyState::Plain => Ok(Outcome {
                to_client: payload.to_vec(),
                ..Outcome::default()
            }),
            ProxyState::Pending { .. } => {
                // A TLS server never speaks first; anything arriving here
                // waits until the client's hello decides the flow's fate.
                self.peer_buffer.extend_from_slice(payload);
                Ok(Outcome::default())
            }
            ProxyState::Active(session) => {
                let plain = feed_client_wire(&mut session.client, payload)?;
                self.after_peer_wire(plain)
            }
        }
    }

    /// Everything that follows a peer feed once both halves are up.
    fn after_peer_wire(&mut self, plain: Vec<u8>) -> Result<Outcome, String> {
        let mut outcome = Outcome::default();
        {
            let ProxyState::Active(session) = &mut self.state else {
                return Ok(Outcome::default());
            };
            // The upstream half has wire bytes of its own: the rest of its
            // handshake, and the request buffered while it was still handshaking.
            outcome.to_peer = tls::take_client_outbound(&mut session.client);
            if !tls::client_handshaking(&session.client) && !self.client_buffer.is_empty() {
                let request = std::mem::take(&mut self.client_buffer);
                outcome.to_peer.extend(feed_client(&mut session.client, &request)?);
            }

            if tls::server_handshaking(&session.server) {
                outcome.to_client = tls::take_server_outbound(&mut session.server);
                return Ok(outcome);
            }
        }
        // Decrypt, edit, re-encrypt for the client.
        let (edited, injected) = self.rewrite_response_for_test(&plain);
        outcome.injected = injected;
        if let ProxyState::Active(session) = &mut self.state {
            outcome.to_client = send_to_client(&mut session.server, &edited)?;
        }
        Ok(outcome)
    }

    /// Wire bytes the upstream half wants to put on the wire (drained when the
    /// peer socket becomes writable).
    pub fn take_upstream_outbound(&mut self) -> Vec<u8> {
        match &mut self.state {
            ProxyState::Active(session) => tls::take_client_outbound(&mut session.client),
            _ => Vec::new(),
        }
    }

    /// Decrypt → maybe inject a script → re-encrypt for the client.
    ///
    /// Split out so it can be tested without a live TLS handshake.
    pub fn rewrite_response_for_test(&mut self, plain: &[u8]) -> (Vec<u8>, usize) {
        if self.script_src.is_empty() {
            return (plain.to_vec(), 0);
        }

        // Wait for the full response: the head tells us whether it is HTML.
        if !plain.is_empty() {
            self.pending_response.extend_from_slice(plain);
        }
        if self.pending_response.len() > http::MAX_INJECTABLE_BODY {
            let out = std::mem::take(&mut self.pending_response);
            return (out, 0);
        }

        let Some(split) = header_end(&self.pending_response) else {
            // No complete head yet; wait for more.
            return (Vec::new(), 0);
        };
        // Copy out of the buffer: the borrow checker cannot track split_at
        // across the rewrite below.
        let head = self.pending_response[..split].to_vec();
        let body = self.pending_response[split..].to_vec();
        if body.is_empty() {
            // Head only so far; headers may arrive before the body does.
            return (Vec::new(), 0);
        }

        let injectable = http::should_inject(&head);
        if injectable == Injectable::Html {
            let (new_body, decision) = http::inject_script(&body, &self.script_src);
            if decision == http::Decision::Injected {
                let mut buf = Vec::with_capacity(head.len() + new_body.len());
                buf.extend_from_slice(&http::fix_content_length(&head, new_body.len()));
                buf.extend_from_slice(&new_body);
                self.pending_response.clear();
                (buf, new_body.len() - body.len())
            } else {
                // Not the shape we inject into: flush unchanged.
                let flushed = std::mem::take(&mut self.pending_response);
                (flushed, 0)
            }
        } else {
            let flushed = std::mem::take(&mut self.pending_response);
            (flushed, 0)
        }
    }
}

/// Byte offset just past the HTTP header block, if it is complete.
fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// Builds a proxy session for `sni` connecting on to `real_server`.
pub fn open(
    ca: &Arc<crate::mitm::ca::CertificateAuthority>,
    resolver: &Arc<tls::SniCertResolver>,
    real_server: &str,
    script_src: String,
) -> Result<ProxySession, String> {
    let ca = Arc::clone(ca);
    let _ = ca;
    let session = tls::open_session(resolver, real_server)?;
    Ok(ProxySession::new(session, script_src))
}
