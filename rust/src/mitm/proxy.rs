//! The splice: decides where each byte goes once both TLS halves exist.
//!
//! ```text
//!   client bytes ─▶ ServerConnection ─▶ plaintext ─▶ [edit] ─▶ ClientConnection ─▶ peer
//!   peer bytes   ─▶ ClientConnection ─▶ plaintext ─▶ [edit] ─▶ ServerConnection ─▶ client
//! ```
//!
//! Everything is non-blocking and returns the payloads to write back, so the
//! packet loop stays in charge of TCP segmentation and never blocks a syscall.

use crate::filter::FilterEngine;
use crate::mitm::http;
use crate::mitm::tls::{
    self, feed_client, feed_client_wire, feed_server, send_to_client, FlowResolver, TlsSession,
};
use crate::stats::Stats;
use rustls::{ClientConfig, ServerConnection};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

/// Upper bound on client bytes buffered while waiting for the ClientHello.
/// A hello is a few KB; anything beyond this is not TLS we can terminate and
/// is spliced through untouched.
const MAX_PENDING_WIRE: usize = 64 * 1024;

/// Upper bound on the response head we are willing to parse. Heads are a few
/// hundred bytes; anything larger is not HTTP/1.1 we understand.
const MAX_RESPONSE_HEAD: usize = 32 * 1024;

/// Path the injected page runtime is served from. Same-origin on purpose: CSP
/// commonly blocks inline scripts, and the browser resolves a relative tag
/// against the page it was injected into.
pub const PAGE_SCRIPT_PATH: &str = "/adfree-page.js";

/// Path the page runtime uses to ask for generic class/id rules that the
/// proxy's initial HTML scan could not see.
pub const GENERIC_PATH: &str = "/adfree-generic.js";

/// Path the page's element-hiding stylesheet is served from.
///
/// Element hiding is the bulk of the cosmetic work (11 KB of all-site rules on
/// a typical page) and repeats on every page of a site, so it travels as a
/// stylesheet the browser caches instead of inline script data.
pub const HIDE_PATH: &str = "/adfree-hide.css";

/// Cache policy for the local answers whose URL carries a content hash: the
/// bytes behind a given URL can never change, so the browser need not ask
/// again. (A filter update changes the hash, which changes the URL.)
const IMMUTABLE_CACHE: &str = "max-age=31536000, immutable";

/// The page runtime itself, compiled into the binary.
pub const PAGE_RUNTIME: &str = include_str!("page_runtime.js");

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

/// Records one TLS half's cost in the engine counters. `handshake` marks
/// feeds that ran while the half was still handshaking: key agreements are the
/// expensive part, and separating them tells whether the cost is one-time
/// connection setup or steady-state encryption (the worker-pool question).
fn record_tls(stats: Option<&Stats>, started: Instant, handshake: bool) {
    let Some(stats) = stats else {
        return;
    };
    let ns = started.elapsed().as_nanos() as u64;
    stats.add(&stats.tls_ns, ns);
    if handshake {
        stats.add(&stats.handshake_ns, ns);
    }
}

/// One intercepted connection.
pub struct ProxySession {
    state: ProxyState,
    /// The SNI the flow opened with (the hostname filtering sees).
    captured: Option<String>,
    /// Response bytes held back until the current response can be rewritten.
    pub resp_pending: Vec<u8>,
    /// Where the response rewriter stands on this connection.
    resp_phase: RespPhase,
    /// One entry per forwarded request: what its response will look like.
    head_requests: VecDeque<http::RequestInfo>,
    /// Bytes read from the peer that are not yet processed.
    pub peer_buffer: Vec<u8>,
    /// Bytes from the client that are not yet processed.
    pub client_buffer: Vec<u8>,
    /// Scripts to inject into HTML (already combined).
    pub script_src: String,
    /// The tag the browser sees: `script_src` plus the content hash of
    /// [`Self::script_body`], so the answer can be cached per origin until the
    /// script itself changes.
    script_tag_src: String,
    /// Combined JS served back for requests to `script_src` (empty = nothing
    /// to serve, and the request is forwarded like any other).
    pub script_body: Arc<str>,
    /// Cosmetic filtering: rules are computed per page when set.
    pub cosmetic: Option<Arc<FilterEngine>>,
    /// Hot counters of the owning engine, for the TLS and rewrite timings the
    /// HTTPS path adds. `None` when no engine owns the session (tests).
    stats: Option<Arc<Stats>>,
}

/// Where a connection's response stream stands.
///
/// HTTP/1.1 puts every response of a connection back to back, so the rewriter
/// has to know where one body ends before it can look for the next head.
/// Bodies it wants to edit are held whole: HTML needs one pass over the class
/// and id tokens anyway, and editing a body it has only seen half of would
/// break its framing.
enum RespPhase {
    /// Reading a response head into `resp_pending`.
    Head,
    /// A head was parsed; its body is being collected whole.
    Buffer {
        head: Vec<u8>,
        framing: Framing,
        encoding: http::Encoding,
    },
    /// The body is already on its way to the client while the rest of it is
    /// still being edited.
    Stream(Box<StreamState>),
    /// Bytes flow through untouched; `left` tracks the current body.
    Pass { left: Left },
}

/// State for a response whose body is streamed to the client as it is edited.
///
/// Holding a body whole only works while it fits in the client's receive
/// window: unacknowledged bytes stall the relay, and a stalled relay never
/// hands over the rest. Anything longer than [`http::STREAM_AFTER`] is
/// therefore decoded, injected and re-encoded on the fly.
struct StreamState {
    /// The rewritten head, chunked and CSP-free, sent before the first chunk.
    head: Vec<u8>,
    /// How the origin framed the body.
    framing: Framing,
    /// Wire bytes of a length-framed body still to come.
    left: usize,
    /// Origin framing, when it was chunked.
    dechunk: Option<http::DechunkState>,
    /// Origin encoding, when it was gzip.
    gunzip: Option<http::GunzipState>,
    /// Client encoding: the body leaves compressed like it arrived.
    gzip: Option<http::GzipState>,
    /// Decoded bytes held until the snippet has a home.
    prefix: Vec<u8>,
    head_sent: bool,
    injected: bool,
    finished: bool,
    /// Bytes the snippet added, for the log line.
    injected_bytes: usize,
}

impl StreamState {
    fn new(head: &[u8], framing: Framing, encoding: http::Encoding) -> Self {
        let gzip = matches!(encoding, http::Encoding::Gzip);
        Self {
            head: http::head_for_chunked_body(
                head,
                if gzip { Some("gzip") } else { None },
            ),
            framing,
            left: match framing {
                Framing::Length(n) => n,
                Framing::Chunked => 0,
            },
            dechunk: matches!(framing, Framing::Chunked).then(http::DechunkState::new),
            gunzip: gzip.then(http::GunzipState::new),
            gzip: gzip.then(http::GzipState::new),
            prefix: Vec::new(),
            head_sent: false,
            injected: false,
            finished: false,
            injected_bytes: 0,
        }
    }

    /// The head goes out before the first body chunk, and only once.
    fn ensure_head(&mut self, out: &mut Vec<u8>) {
        if !self.head_sent {
            self.head_sent = true;
            out.extend_from_slice(&self.head);
        }
    }

    /// True when the last byte the origin promised has been handed over.
    fn input_done(&self) -> bool {
        match self.framing {
            Framing::Length(_) => self.left == 0,
            Framing::Chunked => self.dechunk.as_ref().is_none_or(|d| d.is_done()),
        }
    }

    /// Where the snippet goes: the document's own `</head>`, `</body>` or
    /// `<body ...>`, or — once the prefix has grown past its limit — just past
    /// the last complete tag.
    fn injection_offset(&self) -> Option<usize> {
        if let Some(pos) = http::injection_point(&self.prefix) {
            return Some(pos);
        }
        if self.prefix.len() >= http::STREAM_PREFIX_LIMIT {
            return Some(http::safe_injection_point(&self.prefix));
        }
        None
    }
}

/// Encodings the streaming path can decode and encode again: identity needs
/// no codec, gzip keeps the page compressed on the wire.
fn streamable(encoding: http::Encoding) -> bool {
    matches!(encoding, http::Encoding::Identity | http::Encoding::Gzip)
}

/// How the body of the response being collected is framed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Framing {
    /// `content-length: N`.
    Length(usize),
    /// `transfer-encoding: chunked`.
    Chunked,
}

/// How many bytes of a passed-through body are still to come.
#[derive(Clone, Copy, Debug)]
enum Left {
    /// `content-length` bytes.
    Length(usize),
    /// Until the peer closes: chunked bodies the proxy does not frame, and
    /// close-delimited ones. Nothing more can be parsed on this connection.
    End,
}

impl ProxySession {
    /// A session whose halves are already open (tests, and any caller that
    /// knows the hostname up front).
    pub fn new(session: TlsSession, script_src: String, script_body: Arc<str>) -> Self {
        let script_tag_src = versioned_path(&script_src, content_hash(script_body.as_bytes()));
        ProxySession {
            state: ProxyState::Active(Box::new(session)),
            captured: None,
            resp_pending: Vec::new(),
            resp_phase: RespPhase::Head,
            head_requests: VecDeque::new(),
            peer_buffer: Vec::new(),
            client_buffer: Vec::new(),
            script_src,
            script_tag_src,
            script_body,
            cosmetic: None,
            stats: None,
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
        script_body: Arc<str>,
    ) -> Result<Self, String> {
        let resolver = FlowResolver::new(resolver);
        let server = tls::new_server(tls::server_config_dyn(resolver.clone()))?;
        let script_tag_src = versioned_path(&script_src, content_hash(script_body.as_bytes()));
        Ok(ProxySession {
            state: ProxyState::Pending(Box::new(PendingState {
                server,
                resolver,
                upstream: upstream_config,
                raw: Vec::new(),
            })),
            captured: None,
            resp_pending: Vec::new(),
            resp_phase: RespPhase::Head,
            head_requests: VecDeque::new(),
            peer_buffer: Vec::new(),
            client_buffer: Vec::new(),
            script_src,
            script_tag_src,
            script_body,
            cosmetic: None,
            stats: None,
        })
    }

    /// Enables cosmetic filtering for this session: per-page rules are
    /// computed from `filter` and injected alongside the user scripts.
    pub fn set_cosmetic(&mut self, filter: Arc<FilterEngine>) {
        self.cosmetic = Some(filter);
    }

    /// Points the session at the engine's counters so TLS and rewrite costs
    /// show up in the stats the UI already polls.
    pub fn set_stats(&mut self, stats: Arc<Stats>) {
        self.stats = Some(stats);
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
                let started = Instant::now();
                let handshaking = tls::server_handshaking(&session.server);
                let plain = feed_server(&mut session.server, payload)?;
                record_tls(self.stats.as_deref(), started, handshaking);
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
        let started = Instant::now();
        let handshaking = tls::server_handshaking(&state.server);
        let fed = feed_server(&mut state.server, payload);
        record_tls(self.stats.as_deref(), started, handshaking);
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
        outcome.to_client = tls::take_server_outbound(&mut session.server);
        Self::flush_client_requests(
            session,
            &mut self.client_buffer,
            &self.script_src,
            &self.script_body,
            self.cosmetic.as_deref().zip(self.captured.as_deref()),
            self.stats.as_deref(),
            &mut self.head_requests,
            &mut outcome,
        )?;
        Ok(outcome)
    }

    /// Drains buffered client requests towards the peer, answering requests
    /// for the injected user script locally first.
    ///
    /// The injected tag is a same-origin path (`<script src="/adfree-user.js">`)
    /// because CSP commonly blocks inline scripts; the browser then asks the
    /// *origin* for that path, and without this the real server would answer
    /// 404 and nothing would run.
    fn flush_client_requests(
        session: &mut TlsSession,
        buffer: &mut Vec<u8>,
        serve_path: &str,
        script_body: &str,
        cosmetic: Option<(&FilterEngine, &str)>,
        stats: Option<&Stats>,
        head_requests: &mut VecDeque<http::RequestInfo>,
        outcome: &mut Outcome,
    ) -> Result<(), String> {
        if tls::client_handshaking(&session.client) || buffer.is_empty() {
            return Ok(());
        }
        if !tls::server_handshaking(&session.server) {
            while let Some(local) = take_local_request(serve_path, script_body, cosmetic, buffer) {
                let started = Instant::now();
                let handshaking = tls::server_handshaking(&session.server);
                outcome
                    .to_client
                    .extend(send_to_client(&mut session.server, &local)?);
                record_tls(stats, started, handshaking);
            }
        }
        // A buffer that starts with a method is a request head, not the tail of
        // a body; only those are safe to edit. Remember what the response will
        // look like (a HEAD has no body, an HTTP/1.0 client cannot take a
        // chunked one) and stop HTML negotiations the rewriter cannot follow.
        if let Some(info) = http::request_info(buffer) {
            head_requests.push_back(info);
            if let Some(fixed) = http::drop_undecodable_encodings(buffer) {
                *buffer = fixed;
            }
        }
        let request = std::mem::take(buffer);
        if !request.is_empty() {
            let started = Instant::now();
            let handshaking = tls::client_handshaking(&session.client);
            outcome.to_peer.extend(feed_client(&mut session.client, &request)?);
            record_tls(stats, started, handshaking);
        }
        Ok(())
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
                let started = Instant::now();
                let handshaking = tls::client_handshaking(&session.client);
                let plain = feed_client_wire(&mut session.client, payload)?;
                record_tls(self.stats.as_deref(), started, handshaking);
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
            Self::flush_client_requests(
                session,
                &mut self.client_buffer,
                &self.script_src,
                &self.script_body,
                self.cosmetic.as_deref().zip(self.captured.as_deref()),
                self.stats.as_deref(),
                &mut self.head_requests,
                &mut outcome,
            )?;

            if tls::server_handshaking(&session.server) {
                outcome.to_client = tls::take_server_outbound(&mut session.server);
                return Ok(outcome);
            }
        }
        // Decrypt, edit, re-encrypt for the client.
        let rewrite_started = Instant::now();
        let (edited, injected) = self.rewrite_response(&plain);
        if let Some(stats) = self.stats.as_deref() {
            stats.add(&stats.rewrite_ns, rewrite_started.elapsed().as_nanos() as u64);
        }
        outcome.injected = injected;
        if let ProxyState::Active(session) = &mut self.state {
            // Append, never replace: flush_client_requests may already have
            // queued the locally served script for this very round, and a
            // handshake bookkeeping record (NewSessionTicket) can still be
            // waiting even when there is no body to forward.
            let started = Instant::now();
            let handshaking = tls::server_handshaking(&session.server);
            outcome
                .to_client
                .extend(send_to_client(&mut session.server, &edited)?);
            record_tls(self.stats.as_deref(), started, handshaking);
            outcome
                .to_client
                .extend(tls::take_server_outbound(&mut session.server));
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

    /// Decrypt → maybe inject scripts and cosmetic rules → re-encrypt.
    ///
    /// Returns the bytes to hand to the client and how many bytes the rewrite
    /// added. Split out so it can be tested without a live TLS handshake.
    pub fn rewrite_response(&mut self, plain: &[u8]) -> (Vec<u8>, usize) {
        if self.script_src.is_empty() && self.cosmetic.is_none() {
            return (plain.to_vec(), 0);
        }
        if !plain.is_empty() {
            self.resp_pending.extend_from_slice(plain);
        }
        let mut out = Vec::with_capacity(plain.len() + 512);
        let mut injected = 0usize;
        loop {
            match std::mem::replace(&mut self.resp_phase, RespPhase::Head) {
                RespPhase::Head => {
                    let Some(split) = http::head_end(&self.resp_pending) else {
                        if self.resp_pending.len() > MAX_RESPONSE_HEAD {
                            // Not HTTP/1.1 we can parse: hand it over as it came
                            // and stop looking for response boundaries.
                            out.append(&mut self.resp_pending);
                            self.resp_phase = RespPhase::Pass { left: Left::End };
                        }
                        break;
                    };
                    let head = self.resp_pending[..split].to_vec();
                    self.resp_pending.drain(..split);
                    let info = http::parse_response_head(&head);
                    // Protocol switch (WebSocket): everything after this is
                    // not HTTP, and nothing may be held back.
                    if info.status == 101 {
                        out.extend_from_slice(&head);
                        self.resp_phase = RespPhase::Pass { left: Left::End };
                        continue;
                    }
                    let req = self.head_requests.pop_front().unwrap_or_default();
                    // A response to HEAD advertises the length of the body it
                    // would have carried, and then carries no body at all.
                    if info.bodyless() || req.head {
                        out.extend_from_slice(&head);
                        continue;
                    }
                    let framing = if info.chunked {
                        Some(Framing::Chunked)
                    } else {
                        info.content_length.map(Framing::Length)
                    };
                    // A redirect's body is never rendered: nothing to hide
                    // there, and injecting would only inflate it.
                    let renderable = !(300..400).contains(&info.status);
                    // Edit only what the next stage can actually handle: HTML
                    // we can decode, with a body we can bound. An HTTP/1.0
                    // client cannot read the chunked body streaming produces.
                    let decodable = matches!(
                        info.encoding,
                        http::Encoding::Identity | http::Encoding::Gzip | http::Encoding::Deflate
                    );
                    let edit =
                        info.html && renderable && decodable && framing.is_some() && !req.http10;
                    if edit {
                        let framing = framing.expect("framing is Some when edit holds");
                        crate::logbuf::push(&format!(
                            "mitm {}: html {} {:?} {:?}: {}",
                            self.captured.as_deref().unwrap_or("?"),
                            info.status,
                            framing,
                            info.encoding,
                            if streamable(info.encoding) { "reading" } else { "buffering" }
                        ));
                        // A body that is already known to be longer than the
                        // injector may hold goes straight to streaming.
                        if streamable(info.encoding)
                            && matches!(framing, Framing::Length(n) if n > http::STREAM_AFTER)
                        {
                            self.resp_phase = RespPhase::Stream(Box::new(StreamState::new(
                                &head,
                                framing,
                                info.encoding,
                            )));
                            continue;
                        }
                        self.resp_phase = RespPhase::Buffer {
                            head,
                            framing,
                            encoding: info.encoding,
                        };
                        continue;
                    }
                    if info.html && renderable {
                        crate::logbuf::push(&format!(
                            "mitm {}: html {} passed through (framing={:?} encoding={:?})",
                            self.captured.as_deref().unwrap_or("?"),
                            info.status,
                            framing,
                            info.encoding
                        ));
                    }
                    out.extend_from_slice(&head);
                    self.resp_phase = RespPhase::Pass {
                        left: match framing {
                            Some(Framing::Length(n)) => Left::Length(n),
                            _ => Left::End,
                        },
                    };
                    continue;
                }
                RespPhase::Buffer {
                    head,
                    framing,
                    encoding,
                } => {
                    let Some(body) = self.take_body(framing) else {
                        if self.resp_pending.len() > http::STREAM_AFTER {
                            if streamable(encoding) {
                                // Too much to keep holding: what is here goes
                                // out now and the rest follows as it arrives.
                                self.resp_phase = RespPhase::Stream(Box::new(StreamState::new(
                                    &head, framing, encoding,
                                )));
                                continue;
                            }
                            // A body the streaming path cannot decode is not
                            // ours to touch: hand it over as it came.
                            crate::logbuf::push(&format!(
                                "mitm {}: body over {} bytes in {:?}, passing through",
                                self.captured.as_deref().unwrap_or("?"),
                                http::STREAM_AFTER,
                                encoding
                            ));
                            out.extend_from_slice(&head);
                            out.append(&mut self.resp_pending);
                            self.resp_phase = RespPhase::Pass { left: Left::End };
                        } else {
                            self.resp_phase = RespPhase::Buffer {
                                head,
                                framing,
                                encoding,
                            };
                        }
                        break;
                    };
                    // Compressed despite the request asking for an encoding we
                    // can read: decode, edit, and put it back compressed so the
                    // page still travels compressed to the phone.
                    let decoded = http::decode_body(&body, encoding);
                    if decoded.is_none() && encoding != http::Encoding::Identity {
                        // Not a stream we can read: not ours to touch either.
                        out.extend_from_slice(&head);
                        out.extend_from_slice(&body);
                        self.resp_phase = RespPhase::Head;
                        continue;
                    }
                    let recompress = decoded.is_some();
                    let plain = decoded.as_deref().unwrap_or(&body);
                    let snippet = self.injection_snippet(plain);
                    let (new_body, decision) = if snippet.is_empty() {
                        (plain.to_vec(), http::Decision::Skip)
                    } else {
                        http::inject_snippet(plain, &snippet)
                    };
                    if decision == http::Decision::Injected {
                        injected += new_body.len() - plain.len();
                        crate::logbuf::push(&format!(
                            "mitm {}: injected {} bytes into a {} byte body (recompressed={})",
                            self.captured.as_deref().unwrap_or("?"),
                            new_body.len() - plain.len(),
                            plain.len(),
                            recompress
                        ));
                        match (recompress, http::gzip_encode(&new_body)) {
                            (true, Some(gzipped)) => {
                                out.extend_from_slice(&http::head_for_new_body(
                                    &head,
                                    gzipped.len(),
                                    Some("gzip"),
                                ));
                                out.extend_from_slice(&gzipped);
                            }
                            _ => {
                                out.extend_from_slice(&http::head_for_new_body(
                                    &head,
                                    new_body.len(),
                                    None,
                                ));
                                out.extend_from_slice(&new_body);
                            }
                        }
                    } else {
                        // Nothing to inject, or nowhere to put it: the bytes the
                        // origin sent go on untouched.
                        out.extend_from_slice(&head);
                        out.extend_from_slice(&body);
                    }
                    self.resp_phase = RespPhase::Head;
                    continue;
                }
                RespPhase::Stream(mut state) => {
                    let wire: Vec<u8> = match state.framing {
                        Framing::Length(_) => {
                            let take = state.left.min(self.resp_pending.len());
                            self.resp_pending.drain(..take).collect()
                        }
                        Framing::Chunked => std::mem::take(&mut self.resp_pending),
                    };
                    if let Err(e) = self.stream_feed(&mut state, &wire, &mut out) {
                        crate::logbuf::push(&format!(
                            "mitm {}: streamed body gave up ({e}), passing through",
                            self.captured.as_deref().unwrap_or("?")
                        ));
                        // The chunked body is already on its way to the client.
                        // Close it cleanly so the page it has so far survives,
                        // then hand the rest of the connection over untouched.
                        if !state.finished {
                            if let Some(encoder) = state.gzip.as_mut() {
                                let mut tail = Vec::new();
                                if encoder.finish(&mut tail).is_ok() {
                                    http::emit_chunk(&mut out, &tail);
                                }
                            }
                            state.ensure_head(&mut out);
                            http::emit_last_chunk(&mut out);
                            state.finished = true;
                        }
                        self.resp_phase = RespPhase::Pass { left: Left::End };
                        break;
                    }
                    if state.finished {
                        injected += state.injected_bytes;
                        // Bytes that followed a chunked body belong to the next
                        // response on this connection.
                        if let Some(d) = state.dechunk.as_ref() {
                            if !d.leftover().is_empty() {
                                self.resp_pending.extend_from_slice(d.leftover());
                            }
                        }
                        self.resp_phase = RespPhase::Head;
                        continue;
                    }
                    self.resp_phase = RespPhase::Stream(state);
                    break;
                }
                RespPhase::Pass { left } => {
                    let take = match left {
                        Left::Length(n) => n.min(self.resp_pending.len()),
                        Left::End => self.resp_pending.len(),
                    };
                    out.extend(self.resp_pending.drain(..take));
                    match left {
                        Left::Length(n) if n > take => {
                            self.resp_phase = RespPhase::Pass {
                                left: Left::Length(n - take),
                            };
                            break;
                        }
                        Left::Length(_) => {
                            // This response is done: the next bytes are a head.
                            self.resp_phase = RespPhase::Head;
                            continue;
                        }
                        Left::End => {
                            self.resp_phase = RespPhase::Pass { left: Left::End };
                            break;
                        }
                    }
                }
            }
        }
        (out, injected)
    }

    /// Removes and returns the complete body of the response being collected,
    /// leaving whatever belongs to the next response in the buffer.
    fn take_body(&mut self, framing: Framing) -> Option<Vec<u8>> {
        match framing {
            Framing::Length(n) => {
                if self.resp_pending.len() < n {
                    return None;
                }
                let rest = self.resp_pending.split_off(n);
                Some(std::mem::replace(&mut self.resp_pending, rest))
            }
            Framing::Chunked => match http::dechunk(&self.resp_pending) {
                http::Dechunk::Complete { payload, consumed } => {
                    let rest = self.resp_pending.split_off(consumed);
                    self.resp_pending = rest;
                    Some(payload)
                }
                _ => None,
            },
        }
    }

    /// Feeds one batch of upstream wire bytes through the streaming rewrite:
    /// de-frame, decode, inject once, re-encode and chunk.
    fn stream_feed(
        &self,
        state: &mut StreamState,
        wire: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), String> {
        if matches!(state.framing, Framing::Length(_)) {
            state.left = state.left.saturating_sub(wire.len());
        }
        if !wire.is_empty() {
            let framed: Vec<u8> = match state.dechunk.as_mut() {
                Some(dechunk) => {
                    let mut decoded = Vec::with_capacity(wire.len());
                    dechunk.push(wire, &mut decoded)?;
                    decoded
                }
                None => wire.to_vec(),
            };
            let decoded: Vec<u8> = match state.gunzip.as_mut() {
                Some(gunzip) => {
                    let mut plain = Vec::with_capacity(framed.len() * 3);
                    gunzip.push(&framed, &mut plain)?;
                    plain
                }
                None => framed,
            };
            if state.injected {
                self.stream_body(state, &decoded, out)?;
            } else {
                state.prefix.extend_from_slice(&decoded);
                if let Some(pos) = state.injection_offset() {
                    let snippet = self.injection_snippet(&state.prefix);
                    let before: Vec<u8> = state.prefix[..pos].to_vec();
                    let after: Vec<u8> = state.prefix[pos..].to_vec();
                    state.prefix.clear();
                    state.ensure_head(out);
                    self.stream_body(state, &before, out)?;
                    self.stream_body(state, &snippet, out)?;
                    state.injected_bytes += snippet.len();
                    self.stream_body(state, &after, out)?;
                    state.injected = true;
                }
            }
        }
        if !state.finished && state.input_done() {
            if !state.injected {
                // No `</head>` ever showed up: the snippet lands after the last
                // complete tag, so the document stays well formed.
                let pos = http::safe_injection_point(&state.prefix);
                let snippet = self.injection_snippet(&state.prefix);
                let before: Vec<u8> = state.prefix[..pos].to_vec();
                let after: Vec<u8> = state.prefix[pos..].to_vec();
                state.prefix.clear();
                state.ensure_head(out);
                self.stream_body(state, &before, out)?;
                self.stream_body(state, &snippet, out)?;
                state.injected_bytes += snippet.len();
                self.stream_body(state, &after, out)?;
                state.injected = true;
            }
            if let Some(encoder) = state.gzip.as_mut() {
                let mut tail = Vec::new();
                encoder.finish(&mut tail)?;
                http::emit_chunk(out, &tail);
            }
            state.ensure_head(out);
            http::emit_last_chunk(out);
            state.finished = true;
            crate::logbuf::push(&format!(
                "mitm {}: streamed body, {} bytes of rules injected",
                self.captured.as_deref().unwrap_or("?"),
                state.injected_bytes
            ));
        }
        Ok(())
    }

    /// Re-encodes and frames one piece of the edited body for the client.
    fn stream_body(
        &self,
        state: &mut StreamState,
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), String> {
        if data.is_empty() {
            return Ok(());
        }
        match state.gzip.as_mut() {
            Some(encoder) => {
                let mut compressed = Vec::with_capacity(data.len() / 2 + 64);
                encoder.push(data, &mut compressed)?;
                http::emit_chunk(out, &compressed);
            }
            None => http::emit_chunk(out, data),
        }
        Ok(())
    }

    /// The HTML snippet injected before `</head>`: the hiding stylesheet, the
    /// cosmetic payload (rule data inline, runtime fetched from the local
    /// endpoint) plus the user script tag when one is installed. Empty when
    /// nothing applies.
    fn injection_snippet(&self, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(filter) = self.cosmetic.as_deref() {
            // Without a hostname there are no rules to look up (a session that
            // never saw a ClientHello keeps only the runtime).
            if let Some(host) = self.captured.as_deref() {
                // What the rules hide goes out as a stylesheet, not as inline
                // data: the same 11 KB of all-site selectors applies to every
                // page of a site, and this way the browser fetches it once and
                // keeps it.
                if let Some((href, _)) = hide_stylesheet(filter, host) {
                    out.extend_from_slice(http::style_link_tag(&href, "adfree-hide").as_bytes());
                }
                if let Some(data) = self.cosmetic_payload(filter, host, body) {
                    out.extend_from_slice(b"<script>window.__adfree_page=");
                    out.extend_from_slice(data.as_bytes());
                    out.extend_from_slice(b";</script>");
                }
            }
            // The runtime goes out whenever cosmetic filtering runs, payload or
            // not: it is what finds rules for the tokens the proxy never saw,
            // which on a streamed page is everything past `</head>`.
            // Not deferred: the hiding stylesheet must land before the body
            // renders, and the answer comes from this very connection.
            let runtime = versioned_path(PAGE_SCRIPT_PATH, content_hash(PAGE_RUNTIME.as_bytes()));
            out.extend_from_slice(http::script_tag(&runtime, false).as_bytes());
        }
        if !self.script_src.is_empty() {
            out.extend_from_slice(http::script_tag(&self.script_tag_src, true).as_bytes());
        }
        out
    }

    /// The per-page cosmetic payload as JSON, or `None` when the page has
    /// nothing left to carry inline (element hiding travels as a stylesheet).
    fn cosmetic_payload(
        &self,
        filter: &FilterEngine,
        host: &str,
        body: &[u8],
    ) -> Option<String> {
        let url = format!("https://{host}/");
        let rules = filter.cosmetic_resources(&url);

        // Generic class/id rules: the page's own tokens decide which apply.
        // The initial HTML is scanned here so the first paint is covered; the
        // runtime asks again for whatever the page adds later.
        let mut generic = Vec::new();
        if !rules.generichide {
            let (classes, ids) = http::collect_class_id_tokens(body);
            if !classes.is_empty() || !ids.is_empty() {
                generic = filter.generic_selectors(&classes, &ids, &rules.exceptions);
            }
        }

        let mut obj = serde_json::Map::new();
        if !rules.style_rules.is_empty() {
            obj.insert("style".into(), serde_json::json!(rules.style_rules));
        }
        if !generic.is_empty() {
            obj.insert("generic".into(), serde_json::json!(generic));
        }
        if !rules.procedural.is_empty() {
            obj.insert("procedural".into(), serde_json::json!(rules.procedural));
        }
        if !rules.scriptlets.is_empty() {
            obj.insert("scriptlets".into(), serde_json::json!(rules.scriptlets));
        }
        // With `$generichide` in play the dynamic lookup would answer `[]`
        // every time; say so, and only then — the runtime assumes it is on, so
        // a page whose payload never made it out still gets the lookup.
        if rules.generichide {
            obj.insert("dynamic".into(), serde_json::json!(false));
        }
        if obj.is_empty() {
            return None;
        }
        Some(escape_for_script(&serde_json::Value::Object(obj).to_string()))
    }
}

/// Answers a request for one of our local endpoints without touching the peer.
///
/// Three paths are ours: the user script (`serve_path`), the page runtime and
/// the generic class/id lookup. Returns the whole HTTP response and removes
/// the request from `buffer`. Split out so the check is unit-testable without
/// a live TLS session.
pub fn take_local_request(
    serve_path: &str,
    script_body: &str,
    cosmetic: Option<(&FilterEngine, &str)>,
    buffer: &mut Vec<u8>,
) -> Option<Vec<u8>> {
    let head = header_end(buffer)?;
    let line_end = buffer.windows(2).position(|w| w == b"\r\n")?;
    let first_line = std::str::from_utf8(&buffer[..line_end]).ok()?.to_string();
    let target = request_target(&first_line)?;
    let gzip = http::accepts_gzip(&buffer[..head]);

    if !serve_path.is_empty() && !script_body.is_empty() && target == serve_path {
        buffer.drain(..head);
        // The tag carries the script's content hash, so this answer may be
        // kept: a changed script is requested under a different URL.
        return Some(local_response(
            "application/javascript; charset=utf-8",
            IMMUTABLE_CACHE,
            script_body.as_bytes(),
            gzip,
        ));
    }
    let (filter, host) = cosmetic?;
    if target == PAGE_SCRIPT_PATH {
        buffer.drain(..head);
        return Some(local_response(
            "application/javascript; charset=utf-8",
            IMMUTABLE_CACHE,
            PAGE_RUNTIME.as_bytes(),
            gzip,
        ));
    }
    if target == HIDE_PATH {
        buffer.drain(..head);
        // Only the bytes matter here; the hash in the URL was computed over
        // exactly these bytes when the link was written. An empty stylesheet
        // (rules changed since) is a valid answer.
        let body = hide_stylesheet(filter, host).map(|(_, body)| body);
        return Some(local_response(
            "text/css; charset=utf-8",
            IMMUTABLE_CACHE,
            body.as_deref().unwrap_or("").as_bytes(),
            gzip,
        ));
    }
    if target == GENERIC_PATH {
        buffer.drain(..head);
        let (classes, ids) = generic_query(&first_line);
        let selectors = if classes.is_empty() && ids.is_empty() {
            Vec::new()
        } else {
            let url = format!("https://{host}/");
            let rules = filter.cosmetic_resources(&url);
            if rules.generichide {
                Vec::new()
            } else {
                filter.generic_selectors(&classes, &ids, &rules.exceptions)
            }
        };
        let body = serde_json::to_string(&selectors).unwrap_or_else(|_| "[]".to_string());
        return Some(http_response(
            "application/json; charset=utf-8",
            body.as_bytes(),
        ));
    }
    None
}

/// `GET /path?query HTTP/1.1` → `/path`, and only for GET requests.
fn request_target(first_line: &str) -> Option<&str> {
    let mut parts = first_line.split(' ');
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    Some(match target.find('?') {
        Some(i) => &target[..i],
        None => target,
    })
}

/// Classes and ids out of `GET /adfree-generic.js?c=a%20b&i=x HTTP/1.1`.
fn generic_query(first_line: &str) -> (Vec<String>, Vec<String>) {
    let mut classes = Vec::new();
    let mut ids = Vec::new();
    let Some(target) = first_line.split(' ').nth(1) else {
        return (classes, ids);
    };
    let Some(q) = target.find('?').map(|i| &target[i + 1..]) else {
        return (classes, ids);
    };
    for pair in q.split('&') {
        let Some(eq) = pair.find('=') else {
            continue;
        };
        let list = match &pair[..eq] {
            "c" => &mut classes,
            "i" => &mut ids,
            _ => continue,
        };
        let value = percent_decode(&pair[eq + 1..]);
        for token in value.split(' ') {
            if !token.is_empty() && token.len() <= 64 && list.len() < 800 {
                list.push(token.to_string());
            }
        }
    }
    (classes, ids)
}

/// Minimal `%XX` decoding for query values. `+` stays literal: the runtime
/// encodes with `encodeURIComponent`, which spells spaces as `%20`.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A complete HTTP/1.1 response for a locally answered request.
fn http_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    local_response(content_type, "no-store", body, false)
}

/// A locally answered response with an explicit cache policy.
///
/// `gzip` encodes the body when the caller saw the client accept it: the page
/// runtime and the hiding stylesheet are document-sized, and page data stays
/// compressed on the wire.
fn local_response(content_type: &str, cache: &str, body: &[u8], gzip: bool) -> Vec<u8> {
    let compressed = if gzip && !body.is_empty() {
        http::gzip_bytes(body)
    } else {
        None
    };
    let payload = compressed.as_deref().unwrap_or(body);
    // `Vary` keeps any cache from handing the gzipped answer to a client that
    // never said it takes one.
    let encoding = if compressed.is_some() {
        "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n"
    } else {
        ""
    };
    let mut resp = Vec::with_capacity(payload.len() + 200);
    resp.extend_from_slice(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: {cache}\r\n{encoding}Content-Length: {}\r\n\r\n",
            payload.len()
        )
        .as_bytes(),
    );
    resp.extend_from_slice(payload);
    resp
}

/// FNV-1a over the bytes: a cheap, stable content hash for cache busting.
///
/// Local answers carry it in their URL, which is what lets them be cached
/// forever: the URL changes when the bytes do, and only then.
pub(crate) fn content_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Appends the content hash to a local path (`?h=…`, or `&h=…` if the path
/// already carries a query) so its answer can be cached until it changes.
fn versioned_path(path: &str, hash: u64) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}h={hash:016x}")
}

/// The elements-hiding stylesheet of a host: its bytes and the same-origin URL
/// they are served from. `None` when nothing is hidden on this host.
///
/// The bytes are what the URL hashes, so the two can never disagree: whoever
/// writes the link and whoever answers it build the same string.
pub(crate) fn hide_stylesheet(filter: &FilterEngine, host: &str) -> Option<(String, String)> {
    let selectors = filter.hide_selectors_for(host);
    if selectors.is_empty() {
        return None;
    }
    let body = format!("{}{{display:none!important}}\n", selectors.join(","));
    Some((versioned_path(HIDE_PATH, content_hash(body.as_bytes())), body))
}

/// Escapes a JSON payload for embedding inside an inline `<script>`.
///
/// `<` is the one character that can terminate the element early
/// (`</script>`, `<!--`); U+2028/2029 are valid JSON but were invalid in JS
/// string literals before ES2019.
fn escape_for_script(json: &str) -> String {
    let mut out = String::with_capacity(json.len() + 16);
    for ch in json.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(ch),
        }
    }
    out
}

/// Byte offset just past the HTTP header block, if it is complete.
fn header_end(buf: &[u8]) -> Option<usize> {
    http::head_end(buf)
}

/// Builds a proxy session for `sni` connecting on to `real_server`.
pub fn open(
    ca: &Arc<crate::mitm::ca::CertificateAuthority>,
    resolver: &Arc<tls::SniCertResolver>,
    real_server: &str,
    script_src: String,
    script_body: Arc<str>,
) -> Result<ProxySession, String> {
    let ca = Arc::clone(ca);
    let _ = ca;
    let session = tls::open_session(resolver, real_server)?;
    Ok(ProxySession::new(session, script_src, script_body))
}
