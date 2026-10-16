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
    self, feed_client, feed_server, send_to_client, TlsSession,
};
use std::sync::Arc;

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
}

/// One intercepted connection.
pub struct ProxySession {
    pub session: TlsSession,
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
    pub fn new(session: TlsSession, script_src: String) -> Self {
        ProxySession {
            session,
            pending_response: Vec::new(),
            outbound_response: Vec::new(),
            peer_buffer: Vec::new(),
            client_buffer: Vec::new(),
            script_src,
        }
    }

    /// True while the client half has not finished its handshake.
    pub fn server_handshaking(&self) -> bool {
        tls::server_handshaking(&self.session.server)
    }

    /// True while the server half has not finished its handshake.
    pub fn client_handshaking(&self) -> bool {
        tls::client_handshaking(&self.session.client)
    }

    /// Bytes the client just sent (already decrypted is not possible yet).
    ///
    /// `payload` is raw TLS from the client: it goes into the server half, and
    /// during the handshake the resulting wire bytes must be handed to the
    /// client, not the peer.
    pub fn on_client_payload(&mut self, payload: &[u8]) -> Result<Outcome, String> {
        let mut outcome = Outcome::default();
        let plain = feed_server(&mut self.session.server, payload)?;

        if self.server_handshaking() {
            // Our own handshake answers go back to the client.
            outcome.to_client = tls::take_server_outbound(&mut self.session.server);
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
        let hello = tls::take_client_outbound(&mut self.session.client);
        outcome.to_peer = hello;
        if !self.client_handshaking() && !self.client_buffer.is_empty() {
            let request = std::mem::take(&mut self.client_buffer);
            outcome.to_peer.extend(feed_client(&mut self.session.client, &request)?);
        }
        outcome.to_client = tls::take_server_outbound(&mut self.session.server);
        Ok(outcome)
    }

    /// Bytes the real server just sent.
    pub fn on_peer_payload(&mut self, payload: &[u8]) -> Result<Outcome, String> {
        let mut outcome = Outcome::default();
        let plain = tls::feed_client_wire(&mut self.session.client, payload)?;

        // The upstream half has wire bytes of its own: the rest of its
        // handshake, and the request buffered while it was still handshaking.
        outcome.to_peer = tls::take_client_outbound(&mut self.session.client);
        if !self.client_handshaking() && !self.client_buffer.is_empty() {
            let request = std::mem::take(&mut self.client_buffer);
            outcome.to_peer.extend(feed_client(&mut self.session.client, &request)?);
        }

        if self.server_handshaking() {
            outcome.to_client = tls::take_server_outbound(&mut self.session.server);
            return Ok(outcome);
        }
        // Decrypt, edit, re-encrypt for the client.
        let (edited, injected) = self.rewrite_response_for_test(&plain);
        outcome.injected = injected;
        outcome.to_client = send_to_client(&mut self.session.server, &edited)?;
        Ok(outcome)
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
