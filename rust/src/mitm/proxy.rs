//! The splice: decides where each byte goes once both TLS halves exist.
//!
//! ```text
//!   client bytes ─▶ ServerConnection ─▶ plaintext ─▶ [edit] ─▶ ClientConnection ─▶ peer
//!   peer bytes   ─▶ ClientConnection ─▶ plaintext ─▶ [edit] ─▶ ServerConnection ─▶ client
//! ```
//!
//! Everything is non-blocking and returns the payloads to write back, so the
//! packet loop stays in charge of TCP segmentation and never blocks a syscall.

use crate::filter::{
    CookiePlan, FilterEngine, HeaderEdit, HlsPlan, HtmlPlan, JsonprunePlan, Replace,
};
use crate::mitm::http;
use crate::mitm::tls::{
    self, feed_client, feed_client_wire, feed_server, send_to_client, FlowResolver, TlsSession,
};
use crate::stats::Stats;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
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

/// Path the injected page runtime is served from. The injected tag is
/// absolute (`https://192.0.2.1/adfree-page.js…`), not relative: the runtime
/// lives on this app's own origin, which is exactly what the rewritten policy
/// lists, so a strict page still lets it load.
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

/// Origin every injected asset is fetched from.
///
/// A reserved address (TEST-NET-1, RFC 5737) that the app answers out of the
/// tunnel and never dials. A separate origin is what keeps the page's service
/// worker out of the way: a worker intercepts *every* same-origin fetch and
/// may answer it with a shell document, a stale cache entry or a 404 — on the
/// sites that use one (most large Vietnamese news sites) that silently kills
/// cosmetic filtering. AdGuard solves the same problem by serving from
/// `local.adguard.org`; an address literal is what makes it work without DNS,
/// whose lookup Chrome would otherwise take over (secure DNS / Private DNS)
/// and never route through the filter.
pub const LOCAL_ORIGIN: &str = "https://192.0.2.1";

/// The host part of [`LOCAL_ORIGIN`], and the name its leaf is minted for.
pub const LOCAL_ORIGIN_HOST: &str = "192.0.2.1";

/// The IPv4 address of [`LOCAL_ORIGIN`], for the packet path.
pub const LOCAL_ORIGIN_V4: [u8; 4] = [192, 0, 2, 1];

/// Prefixes an injected path with the local origin.
pub(crate) fn local_asset(path: &str) -> String {
    format!("{LOCAL_ORIGIN}{path}")
}

/// [`LOCAL_ORIGIN`] as an address, for matching packets in the engine.
pub fn local_origin_addr() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::from(LOCAL_ORIGIN_V4))
}

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

/// A request an intercepted session answered itself, for the app's log.
#[derive(Clone, Copy)]
pub struct MitmBlock<'a> {
    /// The host the request was for.
    pub host: &'a str,
    /// The rule that matched, when the engine reported one.
    pub rule: Option<&'a str>,
    pub list_name: Option<&'a str>,
    pub category: u8,
}

/// Where the HTTPS path reports what it blocked.
///
/// A plain function pointer: in production the only sink is the process-wide
/// engine ([`crate::engine::log_mitm_block`]) and tests run without one, so the
/// proxy never has to know how the log is stored.
pub type MitmSink = fn(&MitmBlock<'_>);

/// Where a relay's TLS termination stands.
enum ProxyState {
    /// Armed but not open: the hostname to present upstream comes from the
    /// ClientHello, so the upstream half is created once rustls has parsed it.
    /// `raw` keeps the client's bytes so a non-TLS stream can still be spliced
    /// through untouched.
    Pending(Box<PendingState>),
    /// Both halves are up; bytes are decrypted, edited and re-encrypted.
    Active(Box<TlsSession>),
    /// The local injection origin: TLS terminates here and every request is
    /// answered locally. There is no upstream half and no peer socket — the
    /// reserved address never leaves the device.
    Local(Box<ServerConnection>),
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
    head_requests: VecDeque<ResponseEdit>,
    /// Bytes read from the peer that are not yet processed.
    pub peer_buffer: Vec<u8>,
    /// Bytes from the client that are not yet processed.
    pub client_buffer: Vec<u8>,
    /// The body bytes of a request this proxy answered itself, still to be
    /// swallowed before anything is parsed again (see [`swallow_body`]). A
    /// body may look like a request line at any offset, so nothing after the
    /// head of an answered request may ever be read.
    client_discard: Option<ClientDiscard>,
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
    /// The page URL of the response being rewritten, when the loaded lists
    /// carry `[$path=…]` rules. Set from the request's plan as its response
    /// head goes out, so the injection — buffered or streamed, long after —
    /// can match those rules. `None` when no plan named one.
    page_url: Option<String>,
    /// Hot counters of the owning engine, for the TLS and rewrite timings the
    /// HTTPS path adds. `None` when no engine owns the session (tests).
    stats: Option<Arc<Stats>>,
    /// Where requests answered locally (`$redirect`, URL-level blocks) are
    /// reported. `None` when no engine owns the session (tests).
    sink: Option<MitmSink>,
    /// The applications the flow belongs to, as the kernel's socket table
    /// named them when the connection opened (see [`crate::uidmap`]). Empty
    /// when nothing was attributed — the `$app=` rules then apply to no app.
    apps: Vec<String>,
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
        /// The `$replace` rule the response matched: applied once the whole
        /// body is here.
        replace: Option<Arc<Replace>>,
        /// The `$jsonprune` rules the request matched: applied to the body
        /// before `$replace` has it.
        jsonprune: Option<Arc<JsonprunePlan>>,
        /// The `$hls` rules the request matched: applied to the body before
        /// `$jsonprune` and `$replace` have it.
        hls: Option<Arc<HlsPlan>>,
        /// The `$$` / `##^` HTML filtering rules the request matched: applied
        /// to the body after `$jsonprune` and before `$replace` has it.
        html: Option<Arc<HtmlPlan>>,
        /// The body may be a page: only then does the injector look at it.
        inject: bool,
    },
    /// The body is already on its way to the client while the rest of it is
    /// still being edited.
    Stream(Box<StreamState>),
    /// Bytes flow through untouched; `left` tracks the current body.
    Pass { left: Left },
}

/// What the response of one forwarded request needs to know about it.
#[derive(Default)]
struct ResponseEdit {
    /// Frame facts the rewriter needs: a HEAD has no body to rewrite, and an
    /// HTTP/1.0 client cannot take a chunked one.
    info: http::RequestInfo,
    /// The `$replace` rule the request matched: its response body is rewritten
    /// instead of the request being blocked. `None` on every other request.
    replace: Option<Arc<Replace>>,
    /// The `$csp` / `$permissions` / `$removeheader` rules the request
    /// matched: applied to the response head when it comes back.
    headers: Option<Arc<HeaderEdit>>,
    /// The `$cookie` rules the request matched: the response head loses the
    /// `set-cookie` headers they name.
    cookies: Option<Arc<CookiePlan>>,
    /// The `$jsonprune` rules the request matched: the response body loses
    /// the JSON items they name.
    jsonprune: Option<Arc<JsonprunePlan>>,
    /// The `$hls` rules the request matched: the response body loses the
    /// playlist segments they name.
    hls: Option<Arc<HlsPlan>>,
    /// The `$$` / `##^` HTML filtering rules the request matched: the
    /// response body loses the elements they name.
    html: Option<Arc<HtmlPlan>>,
    /// The URL of the page this request is for, when the loaded lists carry
    /// `[$path=…]` rules: the injection matches those rules against it. The
    /// request head is the only place the URL exists, so it rides along.
    page_url: Option<String>,
}

/// What one forwarded request carries back from the filter: the response body
/// rewrite it matched, if any, and the header edits its response needs.
#[derive(Default)]
struct RequestPlan {
    /// The `$replace` rule: its response body is rewritten when it comes back.
    replace: Option<Arc<Replace>>,
    /// Header edits, computed once, here, and held until the response arrives.
    headers: Option<Arc<HeaderEdit>>,
    /// The `$cookie` rules the request matched: the request loses the cookies
    /// they name now, and the response may not set them — the same plan
    /// answers both, so it rides along.
    cookies: Option<Arc<CookiePlan>>,
    /// The `$jsonprune` rules the request matched: held until the response
    /// body arrives.
    jsonprune: Option<Arc<JsonprunePlan>>,
    /// The `$hls` rules the request matched: held until the response body
    /// arrives.
    hls: Option<Arc<HlsPlan>>,
    /// The `$$` / `##^` HTML filtering rules the request matched: held until
    /// the response body arrives.
    html: Option<Arc<HtmlPlan>>,
    /// The request's page URL when the loaded lists carry `[$path=…]` rules:
    /// what the injection matches those rules against. Rides on the plan so
    /// the response edit — which happens long after the head was read — can
    /// find it again.
    page_url: Option<String>,
}

/// State for a response whose body is streamed to the client as it is edited.
///
/// Holding a body whole only works while it fits in the client's receive
/// window: unacknowledged bytes stall the relay, and a stalled relay never
/// hands over the rest. Anything longer than [`http::STREAM_AFTER`] is
/// therefore decoded, injected and re-encoded on the fly.
struct StreamState {
    /// The head as the origin sent it; the policy inside it is rewritten by
    /// [`StreamState::ensure_head`], once it is known whether anything is
    /// injected.
    head: Vec<u8>,
    /// The nonce this response's tags carry, decided when the state is made.
    nonce: String,
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
            head: head.to_vec(),
            nonce: http::new_nonce(),
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
    ///
    /// `injecting` says whether a snippet goes out with it: only then does the
    /// page's policy learn our nonce. The head cannot wait for the decision —
    /// it is written just before the first body bytes either way — so a body
    /// that gives up mid-stream keeps the policy it arrived with.
    fn ensure_head(&mut self, out: &mut Vec<u8>, injecting: bool) {
        if self.head_sent {
            return;
        }
        self.head_sent = true;
        let encoding = if self.gzip.is_some() { Some("gzip") } else { None };
        let mut head = std::mem::take(&mut self.head);
        if injecting {
            head = http::csp_with_nonce(&head, &self.nonce, LOCAL_ORIGIN);
        }
        out.extend_from_slice(&http::head_for_chunked_body(&head, encoding));
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

/// The name of the body edit a response gave up on: the log lines that say
/// which modifier could not run name the first one the request carried —
/// `$replace`, then `$$`, then `$jsonprune` and `$hls`.
fn body_edit_name(replace: bool, jsonprune: bool, html: bool) -> &'static str {
    if replace {
        "$replace"
    } else if html {
        "$$"
    } else if jsonprune {
        "$jsonprune"
    } else {
        "$hls"
    }
}

/// Hands one complete, unedited response body back to the client.
///
/// A length-framed body is still framed exactly as it arrived, head included.
/// A chunked one is not: [`ProxySession::take_body`] had to strip the chunk
/// framing to hand the body over, so the framing is rebuilt around it — the
/// stripped bytes under the origin's `transfer-encoding: chunked` head are
/// what Chrome reports as `ERR_INVALID_CHUNKED_ENCODING`.
fn emit_passthrough(
    out: &mut Vec<u8>,
    head: &[u8],
    body: &[u8],
    framing: Framing,
    encoding: http::Encoding,
) {
    match framing {
        Framing::Length(_) => {
            out.extend_from_slice(head);
            out.extend_from_slice(body);
        }
        Framing::Chunked => {
            out.extend_from_slice(&http::head_for_chunked_body(head, encoding.name()));
            http::emit_chunk(out, body);
            http::emit_last_chunk(out);
        }
    }
}

/// Hands one complete, re-encoded response body back to the client.
///
/// The head goes out with the length of what follows it, compressed again when
/// the origin's body was: a page that arrived compressed leaves compressed.
fn emit_edited(out: &mut Vec<u8>, head: &[u8], body: &[u8], recompress: bool) {
    match (recompress, http::gzip_encode(body)) {
        (true, Some(gzipped)) => {
            out.extend_from_slice(&http::head_for_new_body(head, gzipped.len(), Some("gzip")));
            out.extend_from_slice(&gzipped);
        }
        _ => {
            out.extend_from_slice(&http::head_for_new_body(head, body.len(), None));
            out.extend_from_slice(body);
        }
    }
}

/// How the body of the response being collected is framed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Framing {
    /// `content-length: N`.
    Length(usize),
    /// `transfer-encoding: chunked`.
    Chunked,
}

/// One `$replace` payload, short enough for a log line.
///
/// The payload is the rule's own text — what the list author wrote between
/// `$replace=` and the end of the line — so it is worth showing whole when it
/// fits, and cut on a character boundary when it does not.
fn payload_summary(payload: &str) -> String {
    const MAX: usize = 96;
    if payload.chars().count() <= MAX {
        return payload.to_string();
    }
    let cut: String = payload.chars().take(MAX - 1).collect();
    format!("{cut}…")
}

/// The text of the rules one response edit applied, short enough for a log
/// line: the rules as they come, cut on a character boundary when there are
/// too many or they are too long.
fn rules_summary(rules: &[String]) -> String {
    const MAX: usize = 160;
    let joined = rules.join("; ");
    if joined.chars().count() <= MAX {
        return joined;
    }
    let cut: String = joined.chars().take(MAX - 1).collect();
    format!("{cut}…")
}

/// How a passed-through body is framed, and how far it still has to go.
#[derive(Debug)]
enum Left {
    /// `content-length` bytes.
    Length(usize),
    /// A chunked body: the bytes go on exactly as the origin sent them, and
    /// the framing is followed to its end — the head behind the terminating
    /// chunk is the next response's, and only the Head phase sees heads.
    Chunked(ChunkPass),
    /// Until the peer closes: a close-delimited body. Nothing more can be
    /// parsed on this connection.
    End,
}

/// A chunked body going over untouched.
///
/// The framing walker never reads the payload, so the bytes on the wire are
/// the origin's own; what it holds is the position, and what [`ChunkPass::tail`]
/// holds is the handful of bytes that position is short of — a size line or a
/// trailer still arriving.
#[derive(Debug)]
struct ChunkPass {
    /// Bytes the walker has taken in but not consumed yet.
    tail: Vec<u8>,
    /// The position in the chunked stream.
    framing: http::DechunkState,
}

impl ProxySession {
    /// A session whose halves are already open (tests, and any caller that
    /// knows the hostname up front).
    pub fn new(session: TlsSession, script_src: String, script_body: Arc<str>) -> Self {
        let script_tag_src = local_asset(&versioned_path(
            &script_src,
            content_hash(script_body.as_bytes()),
        ));
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
            page_url: None,
            stats: None,
            sink: None,
            client_discard: None,
            apps: Vec::new(),
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
        let script_tag_src = local_asset(&versioned_path(
            &script_src,
            content_hash(script_body.as_bytes()),
        ));
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
            page_url: None,
            stats: None,
            sink: None,
            client_discard: None,
            apps: Vec::new(),
        })
    }

    /// Enables cosmetic filtering for this session: per-page rules are
    /// computed from `filter` and injected alongside the user scripts.
    pub fn set_cosmetic(&mut self, filter: Arc<FilterEngine>) {
        self.cosmetic = Some(filter);
    }

    /// A session for the local injection origin.
    ///
    /// It terminates TLS for the reserved address (the leaf is minted for the
    /// address itself: no SNI travels for one) and answers the injected
    /// assets. No peer socket is opened, ever — the engine does not even dial
    /// the address — so a page can only ever reach the assets, nothing else.
    pub fn new_local(
        resolver: Arc<tls::SniCertResolver>,
        script_src: String,
        script_body: Arc<str>,
    ) -> Result<Self, String> {
        let server = tls::new_server(tls::server_config_fixed(resolver, LOCAL_ORIGIN_HOST))?;
        let script_tag_src = local_asset(&versioned_path(
            &script_src,
            content_hash(script_body.as_bytes()),
        ));
        Ok(ProxySession {
            state: ProxyState::Local(Box::new(server)),
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
            page_url: None,
            stats: None,
            sink: None,
            client_discard: None,
            apps: Vec::new(),
        })
    }

    /// Points the session at the engine's counters so TLS and rewrite costs
    /// show up in the stats the UI already polls.
    pub fn set_stats(&mut self, stats: Arc<Stats>) {
        self.stats = Some(stats);
    }

    /// Points the session at the app's log, so a request it answered itself
    /// (`$redirect`, a URL-scoped block) is visible in it like any other.
    pub fn set_sink(&mut self, sink: MitmSink) {
        self.sink = Some(sink);
    }

    /// Names the applications the flow belongs to: what the `$app=` rules of
    /// the loaded lists are matched against. Set once, when the connection
    /// opens; empty (the default) means nothing was attributed.
    pub fn set_apps(&mut self, apps: Vec<String>) {
        self.apps = apps;
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
            ProxyState::Local(server) => tls::server_handshaking(server),
            ProxyState::Plain => false,
        }
    }

    /// True while the server half has not finished its handshake.
    pub fn client_handshaking(&self) -> bool {
        match &self.state {
            ProxyState::Pending { .. } => true,
            ProxyState::Active(session) => tls::client_handshaking(&session.client),
            // Nothing to hand shake with: the local origin has no upstream.
            ProxyState::Local(_) => false,
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
            // The local origin: decrypt, answer our own endpoints (anything
            // else 404s), and never write towards a peer that does not exist.
            ProxyState::Local(server) => {
                let started = Instant::now();
                let handshaking = tls::server_handshaking(server);
                let plain = feed_server(server, payload)?;
                record_tls(self.stats.as_deref(), started, handshaking);
                let mut outcome = Outcome {
                    to_client: tls::take_server_outbound(server),
                    ..Outcome::default()
                };
                if tls::server_handshaking(server) {
                    return Ok(outcome);
                }
                if !plain.is_empty() {
                    self.client_buffer.extend_from_slice(&plain);
                }
                Self::flush_local_requests(
                    server,
                    &self.script_src,
                    &self.script_body,
                    self.cosmetic.as_deref(),
                    &mut self.client_buffer,
                    self.stats.as_deref(),
                    &mut outcome,
                )?;
                Ok(outcome)
            }
        }
    }

    /// The pending state: accumulate, watch for the hello, open and hand off.
    fn pending_client_payload(&mut self, payload: &[u8]) -> Result<Outcome, String> {
        let ProxyState::Pending(state) = &mut self.state else {
            return Ok(Outcome::default());
        };
        if state.raw.len() + payload.len() > MAX_PENDING_WIRE {
            crate::logbuf::push(&format!(
                "mitm {}: no ClientHello in {} KiB, splicing verbatim",
                self.captured.as_deref().unwrap_or("?"),
                MAX_PENDING_WIRE / 1024
            ));
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
                crate::logbuf::push(&format!(
                    "mitm {}: not a TLS ClientHello, splicing verbatim",
                    self.captured.as_deref().unwrap_or("?")
                ));
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
                        crate::logbuf::push(&format!(
                            "mitm {name}: the name is unusable for TLS, splicing verbatim"
                        ));
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
        // What a request answered earlier still owes comes off the front:
        // body bytes belong to no request and must not be parsed as one.
        if self.client_discard.is_some() {
            let mut buffer = std::mem::take(&mut self.client_buffer);
            self.client_discard = swallow_body(
                self.client_discard.take(),
                None,
                &mut buffer,
                self.captured.as_deref(),
            );
            self.client_buffer = buffer;
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
            self.cosmetic.as_deref(),
            self.captured.as_deref(),
            self.stats.as_deref(),
            self.sink,
            &self.apps,
            &mut self.head_requests,
            &mut outcome,
            &mut self.client_discard,
        )?;
        Ok(outcome)
    }

    /// Drains buffered client requests towards the peer, answering requests
    /// for the injected assets locally first.
    ///
    /// An injected tag is an absolute URL on the app's own origin, so the
    /// browser asks *that* origin for the runtime, the stylesheet and the
    /// dynamic-rule lookups; without this the session would forward them (and
    /// a legacy same-origin tag lands here the same way). A request whose
    /// head is not ours goes to the real server untouched.
    #[allow(clippy::too_many_arguments)]
    fn flush_client_requests(
        session: &mut TlsSession,
        buffer: &mut Vec<u8>,
        serve_path: &str,
        script_body: &str,
        filter: Option<&FilterEngine>,
        session_host: Option<&str>,
        stats: Option<&Stats>,
        sink: Option<MitmSink>,
        apps: &[String],
        head_requests: &mut VecDeque<ResponseEdit>,
        outcome: &mut Outcome,
        discard: &mut Option<ClientDiscard>,
    ) -> Result<(), String> {
        if tls::client_handshaking(&session.client) || buffer.is_empty() {
            return Ok(());
        }
        // What the filter decided for this request: a `$replace` rule means the
        // response body is rewritten when it comes back, header rules mean the
        // response head is edited (and the request head may already have been).
        let mut plan = RequestPlan::default();
        if !tls::server_handshaking(&session.server) {
            while let Some(local) =
                take_local_request(serve_path, script_body, filter, session_host, buffer)
            {
                let started = Instant::now();
                let handshaking = tls::server_handshaking(&session.server);
                outcome
                    .to_client
                    .extend(send_to_client(&mut session.server, &local)?);
                record_tls(stats, started, handshaking);
            }
            // The same loop answers a request the *network* rules want stopped
            // or rewritten: the head is the only place the URL exists.
            if let Some(filter) = filter {
                plan = Self::filter_url_request(
                    session,
                    buffer,
                    filter,
                    session_host,
                    stats,
                    sink,
                    apps,
                    outcome,
                    discard,
                )?;
            }
        }
        // A buffer that starts with a method is a request head, not the tail of
        // a body; only those are safe to edit. Remember what the response will
        // look like (a HEAD has no body, an HTTP/1.0 client cannot take a
        // chunked one) and stop HTML negotiations the rewriter cannot follow.
        if let Some(info) = http::request_info(buffer) {
            // A body edit cannot read a response the request did not ask to
            // be encoded readably.
            let forced = plan.replace.is_some()
                || plan.jsonprune.is_some()
                || plan.hls.is_some()
                || plan.html.is_some();
            head_requests.push_back(ResponseEdit {
                info,
                replace: plan.replace,
                headers: plan.headers,
                cookies: plan.cookies,
                jsonprune: plan.jsonprune,
                hls: plan.hls,
                html: plan.html,
                page_url: plan.page_url,
            });
            if let Some(fixed) = http::drop_undecodable_encodings(buffer, forced) {
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

    /// Applies the URL-level network rules to the request head at the front of
    /// `buffer`.
    ///
    /// This is the only place that has the whole request, so it is where the
    /// rules that need a URL live: `$redirect` (answer with a no-op resource
    /// instead of blocking outright — what keeps an anti-adblock page alive),
    /// `$removeparam` and `$urltransform` (the forwarded request line is
    /// rewritten, see [`FilterEngine::url_edit`]) and blocks scoped to a path
    /// or a request type. A request that carries a body is read like any
    /// other — the head is all these rules touch — and when one of them
    /// answers here, the body bytes that follow go to `discard`
    /// ([`swallow_body`]) instead of the origin. The one exception is a body
    /// the proxy cannot count: such a request is never answered here.
    #[allow(clippy::too_many_arguments)]
    fn filter_url_request(
        session: &mut TlsSession,
        buffer: &mut Vec<u8>,
        filter: &FilterEngine,
        session_host: Option<&str>,
        stats: Option<&Stats>,
        sink: Option<MitmSink>,
        apps: &[String],
        outcome: &mut Outcome,
        discard: &mut Option<ClientDiscard>,
    ) -> Result<RequestPlan, String> {
        let Some(mut head_end) = header_end(buffer) else {
            return Ok(RequestPlan::default());
        };
        // Everything the filter needs is copied out of the head up front: the
        // buffer is edited (or drained) below, which ends the borrow.
        let Some(facts) = request_facts(&buffer[..head_end]) else {
            return Ok(RequestPlan::default());
        };
        if !facts.target.starts_with('/')
            && !facts.target.starts_with("http://")
            && !facts.target.starts_with("https://")
        {
            return Ok(RequestPlan::default());
        }
        let Some(host) = session_host
            .map(str::to_string)
            .or_else(|| facts.authority.map(str::to_string))
            .filter(|host| !host.is_empty())
        else {
            return Ok(RequestPlan::default());
        };
        let url = request_url(&facts, &host);
        // The page URL the cosmetics of the response will be matched against.
        // Only `[$path=…]` rules read it, so it is only carried when the
        // loaded lists hold any.
        let page_url = filter.has_path_rules().then(|| url.clone());
        // A `Content-Length` the proxy cannot read is a body it cannot count:
        // the bytes after the head can never be told from the next request, so
        // this exchange is never answered here — it goes to the origin whole,
        // the way every body request used to.
        if matches!(facts.body, Some(RequestBody::Unknown)) {
            return Ok(RequestPlan {
                page_url,
                ..RequestPlan::default()
            });
        }
        let target = facts.target.to_string();
        let method = facts.method.to_string();
        let request_type = facts.request_type();
        // A document is its own first party: with no referrer, the page every
        // rule asks about is the request's own URL. An empty source reads as a
        // third-party request from nowhere, which is what `$third-party`,
        // `$domain` and the page-scoped asks must not see.
        let source = match facts.referer {
            Some(referer) if !referer.is_empty() => referer.to_string(),
            _ if request_type == "document" => url.clone(),
            _ => String::new(),
        };
        let closes = facts.closes;
        // What the request's body amounts to if the rules answer it here.
        let body = facts.body;

        // `$urlblock` (and `$document`, which implies it): the page asked for
        // its own requests not to be blocked. The page is the document itself,
        // or the referrer of a subresource. AdGuard spells the coverage out —
        // blocking, redirects *and* `$removeparam` — so the whole decision is
        // skipped for such a page.
        let page_host = if request_type == "document" {
            crate::filter::url_host(&url)
        } else {
            crate::filter::url_host(&source)
        };
        if !page_host.is_empty() && filter.cosmetic_switches_for(page_host).urlblock {
            // The network decision is skipped, but the page's cosmetics still
            // run: `$urlblock` alone unblocks requests, it does not switch
            // element hiding off.
            return Ok(RequestPlan {
                page_url,
                ..RequestPlan::default()
            });
        }

        // The response-header rules (`$csp`, `$permissions`, `$removeheader`)
        // are matched once, here, and ride on the plan: the response they shape
        // is the next thing to come back. The request-side half of
        // `$removeheader` happens now, while the head is here — the rest waits.
        let mut plan = RequestPlan {
            page_url,
            ..RequestPlan::default()
        };
        if filter.has_header_rules() {
            if let Some(edit) = filter.header_edit(&url, &source, request_type, &method) {
                // `drop_headers` is `None` when none of the names is there, so
                // the request is spliced only when it actually changes.
                if let Some(fixed) =
                    http::drop_headers(&buffer[..head_end], &edit.remove_request)
                {
                    let old_end = head_end;
                    head_end = fixed.len();
                    buffer.splice(..old_end, fixed);
                    crate::logbuf::push(&format!(
                        "mitm {host}: request headers dropped: {}",
                        edit.remove_request.join(", ")
                    ));
                }
                plan.headers = Some(Arc::new(edit));
            }
        }

        // `$jsonprune`: the response body loses the JSON items the matching
        // rules name. Matched here, like the header edits, and held until the
        // body comes back; a request that ends up blocked discards the plan
        // with its answer, and the page's own switches were asked above
        // (`$urlblock`) and inside the finder (`$content`, an empty
        // `$replace`).
        if filter.has_jsonprune_rules() {
            if let Some(rules) = filter.jsonprune_plan(&url, &source, request_type, &method) {
                plan.jsonprune = Some(Arc::new(rules));
            }
        }

        // `$hls`: the response playlist loses the segments the matching rules
        // name, media playlists and master playlists alike. Matched here like
        // the other body edits, held until the body comes back; a blocked
        // request discards the plan with its answer.
        if filter.has_hls_rules() {
            if let Some(rules) = filter.hls_plan(&url, &source, request_type, &method) {
                plan.hls = Some(Arc::new(rules));
            }
        }

        // `$$` / `##^`: the response body loses the elements the matching
        // rules name. Matched here like the other body edits and held until
        // the body comes back; the body pipeline runs it after `$jsonprune`
        // and before `$replace`.
        if filter.has_html_rules() {
            if let Some(rules) = filter.html_plan(&url, &source, request_type) {
                plan.html = Some(Arc::new(rules));
            }
        }

        // `$replace`: the response body is rewritten *instead of* the request
        // being blocked — AdGuard gives the modifier priority over every other
        // basic rule, so a URL it matches is never blocked. The request goes
        // out untouched; the response is picked up again when it comes back.
        if filter.has_replace() {
            if let Some(rule) = filter.replace_for(&url, &source, request_type, &method) {
                plan.replace = Some(rule);
                Self::apply_cookie_plan(
                    filter, buffer, head_end, &url, &source, &method, &host, &mut plan,
                );
                return Ok(plan);
            }
        }

        let mut verdict = filter.check_url(&url, &source, request_type, &method, apps);
        if !verdict.blocked {
            // The request-URL modifiers. `$urltransform` and the shapes of
            // `$removeparam` the crate refuses are run by our own engine here;
            // the `=name` shape the crate does implement comes back on the
            // verdict itself. AdGuard keeps `$urltransform` out of the way of a
            // URL basic rules already block, so this only runs on a clear
            // verdict.
            let mut rewritten_target: Option<String> = None;
            let mut transformed: Option<crate::filter::UrlEdit> = None;
            if filter.has_url_rules() {
                if let Some(edit) = filter.url_edit(&url, &source, request_type, &method) {
                    if !crate::filter::same_origin(&url, &edit.url) {
                        // The rule reaches for another origin, which no rewrite
                        // of the request line can take the request to — but a
                        // redirect can, and only a method that allows one may
                        // be answered that way.
                        if matches!(method.as_str(), "GET" | "HEAD") {
                            let rules = edit.rules.join("; ");
                            crate::logbuf::push(&format!(
                                "mitm {host}: URL transform redirects to {} ({rules})",
                                edit.url
                            ));
                            let mut response = transform_redirect_response(&edit.url);
                            if closes {
                                response = closing_response(response);
                            }
                            buffer.drain(..head_end);
                            *discard = swallow_body(None, body, buffer, Some(host.as_str()));
                            let started = Instant::now();
                            let handshaking = tls::server_handshaking(&session.server);
                            outcome
                                .to_client
                                .extend(send_to_client(&mut session.server, &response)?);
                            record_tls(stats, started, handshaking);
                            if let Some(sink) = sink {
                                sink(&MitmBlock {
                                    host: &host,
                                    rule: Some(&rules),
                                    list_name: None,
                                    category: 0,
                                });
                            }
                            return Ok(RequestPlan::default());
                        }
                    } else if rewritable(&method) {
                        if let Some(new_target) = origin_form(&edit.url) {
                            if new_target != target {
                                // The transformed URL is a request of its own:
                                // it is matched against the rest of the rules
                                // before it goes out.
                                verdict = filter.check_url(
                                    &edit.url,
                                    &source,
                                    request_type,
                                    &method,
                                    apps,
                                );
                                if !verdict.blocked {
                                    rewritten_target = Some(new_target);
                                    transformed = Some(edit);
                                }
                            }
                        }
                    }
                }
            } else if let Some(rewritten) = verdict
                .rewritten_url
                .as_deref()
                .filter(|_| rewritable(&method))
            {
                // A `$removeparam` rule the crate implements itself: the
                // request still goes out, with the parameters the list dropped
                // taken off. GET, HEAD, OPTIONS and POST — see [`rewritable`]
                // — so anything else keeps its query.
                if let Some(new_target) = origin_form(rewritten) {
                    if new_target != target {
                        rewritten_target = Some(new_target);
                    }
                }
            }
            if !verdict.blocked {
                if let Some(rewritten_target) = rewritten_target {
                    // The rebuilt line is as long as the target it carries, so
                    // the head end moves with it: the cookie plan below (and
                    // the plan's own record) reads the head that actually goes
                    // out, and the old end would slice past its end whenever
                    // the rewrite is shorter.
                    let old_end = head_end;
                    let rebuilt = rebuilt_head(&buffer[..old_end], &rewritten_target);
                    head_end = rebuilt.len();
                    buffer.splice(..old_end, rebuilt);
                    if let Some(edit) = transformed {
                        crate::logbuf::push(&format!(
                            "mitm {host}: URL rewritten to {} by {} rule(s)",
                            edit.url,
                            edit.rules.len(),
                        ));
                    }
                }
                Self::apply_cookie_plan(
                    filter, buffer, head_end, &url, &source, &method, &host, &mut plan,
                );
                return Ok(plan);
            }
        }

        let mut response = verdict
            .redirect
            .as_deref()
            .and_then(redirect_response)
            .unwrap_or_else(blocked_response);
        if method == "HEAD" {
            // A HEAD answer is headers only. The length of the body the same
            // request would have carried is already in the head, so dropping
            // the bytes is all it takes.
            if let Some(end) = header_end(&response) {
                response.truncate(end);
            }
        }
        if closes {
            response = closing_response(response);
        }
        buffer.drain(..head_end);
        *discard = swallow_body(None, body, buffer, Some(host.as_str()));
        let started = Instant::now();
        let handshaking = tls::server_handshaking(&session.server);
        outcome
            .to_client
            .extend(send_to_client(&mut session.server, &response)?);
        record_tls(stats, started, handshaking);
        if let Some(sink) = sink {
            sink(&MitmBlock {
                host: &host,
                rule: verdict.rule_text.as_deref(),
                list_name: verdict.list_name.as_deref(),
                category: verdict.category,
            });
        }
        Ok(RequestPlan::default())
    }

    /// Applies the `$cookie` plan to the request head at the front of `buffer`:
    /// the cookies the rules name come off the `Cookie` header, and the plan
    /// rides on `plan` so the response that request produces cannot set them
    /// either.
    ///
    /// The rules are matched against the URL the client sent — the way the
    /// reference reads its matching result — so a request a `$urltransform`
    /// rewrote is still the exchange that client meant to make. A page that
    /// switched content modification off (`$urlblock`) never gets here: the
    /// caller returns before this point, exactly like the reference's cookie
    /// finder sees an empty rule set there.
    #[allow(clippy::too_many_arguments)]
    fn apply_cookie_plan(
        filter: &FilterEngine,
        buffer: &mut Vec<u8>,
        head_end: usize,
        url: &str,
        source: &str,
        method: &str,
        host: &str,
        plan: &mut RequestPlan,
    ) {
        if !filter.has_cookie_rules() {
            return;
        }
        let Some(cookie_plan) = filter.cookie_plan(url, source, method) else {
            return;
        };
        let names = http::request_cookie_names(&buffer[..head_end]);
        if !names.is_empty() {
            if let Some(edit) = cookie_plan.dropped(&names) {
                // `drop_request_cookies` is `None` when none of the names is
                // there, so the request is spliced only when it really changes.
                if let Some(fixed) = http::drop_request_cookies(&buffer[..head_end], &edit.drop) {
                    let old_end = head_end;
                    buffer.splice(..old_end, fixed);
                    crate::logbuf::push(&format!(
                        "mitm {host}: request cookies dropped: {} by {} rule(s)",
                        edit.drop.join(", "),
                        edit.rules.len(),
                    ));
                }
            }
        }
        plan.cookies = Some(Arc::new(cookie_plan));
    }

    /// Answers whatever the client asks the local injection origin.
    ///
    /// There is no peer to forward to: our endpoints are served, and anything
    /// else (a page probing the origin, a stale tag) gets a 404 and the
    /// connection is closed so a stray body cannot be read as a next request.
    fn flush_local_requests(
        server: &mut ServerConnection,
        serve_path: &str,
        script_body: &str,
        filter: Option<&FilterEngine>,
        buffer: &mut Vec<u8>,
        stats: Option<&Stats>,
        outcome: &mut Outcome,
    ) -> Result<(), String> {
        while header_end(buffer).is_some() {
            let started = Instant::now();
            let handshaking = tls::server_handshaking(server);
            let response = match take_local_request(serve_path, script_body, filter, None, buffer)
            {
                Some(response) => response,
                None => {
                    let head = header_end(buffer).expect("checked by the loop condition");
                    buffer.drain(..head);
                    not_found_response()
                }
            };
            outcome.to_client.extend(send_to_client(server, &response)?);
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
            // No upstream socket exists for the local origin, so nothing can
            // arrive from one.
            ProxyState::Local(_) => Ok(Outcome::default()),
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
                self.cosmetic.as_deref(),
                self.captured.as_deref(),
                self.stats.as_deref(),
                self.sink,
                &self.apps,
                &mut self.head_requests,
                &mut outcome,
                &mut self.client_discard,
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
        // Nothing to hide and no header or body to edit: the connection
        // bypasses the rewriter entirely. Header edits alone still need it —
        // they are what `$csp`, `$permissions`, `$removeheader` and `$cookie`
        // matched — and so does a body edit (`$replace`, `$jsonprune`,
        // `$hls`).
        if self.script_src.is_empty()
            && self.cosmetic.is_none()
            && !self.head_requests.iter().any(|req| {
                req.headers.is_some()
                    || req.cookies.is_some()
                    || req.replace.is_some()
                    || req.jsonprune.is_some()
                    || req.hls.is_some()
            })
        {
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
                    // What the injection will match `[$path=…]` rules
                    // against, until the next response head replaces it.
                    self.page_url = req.page_url;
                    // The header edits the request matched are applied as the
                    // head goes out — before anything decides what to do with
                    // the body, so an injected `$csp` value is rewritten with
                    // the injected nonce like any policy the origin wrote.
                    let mut head = head;
                    if let Some(edit) = &req.headers {
                        let done = http::apply_response_headers(
                            &mut head,
                            &edit.remove_response,
                            &edit.csp,
                            &edit.permissions,
                        );
                        let host = self.captured.as_deref().unwrap_or("?");
                        if !done.dropped.is_empty() {
                            crate::logbuf::push(&format!(
                                "mitm {host}: response headers dropped: {} by {} rule(s)",
                                done.dropped.join(", "),
                                edit.rules.len(),
                            ));
                        }
                        if !done.added.is_empty() {
                            crate::logbuf::push(&format!(
                                "mitm {host}: response gained {} by {} rule(s)",
                                done.added.join(", "),
                                edit.rules.len(),
                            ));
                        }
                    }
                    // `$cookie`: the response may not set a cookie the rules
                    // the request matched name, the same way the request lost
                    // the ones it carried. A `set-cookie` names one cookie, so
                    // the whole header goes.
                    if let Some(plan) = &req.cookies {
                        let names = http::set_cookie_names(&head);
                        if let Some(edit) = plan.dropped(&names) {
                            if let Some((fixed, dropped)) =
                                http::drop_set_cookie_headers(&head, &edit.drop)
                            {
                                head = fixed;
                                let host = self.captured.as_deref().unwrap_or("?");
                                crate::logbuf::push(&format!(
                                    "mitm {host}: set-cookie dropped: {} by {} rule(s)",
                                    dropped.join(", "),
                                    edit.rules.len(),
                                ));
                            }
                        }
                    }
                    // A response to HEAD advertises the length of the body it
                    // would have carried, and then carries no body at all.
                    if info.bodyless() || req.info.head {
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
                    let editable = decodable && framing.is_some() && !req.info.http10;
                    // Injection has something to do only when the page runtime
                    // or the cosmetic rules are in play; a connection that is
                    // here for header edits alone must not hold bodies back.
                    let can_inject = !self.script_src.is_empty() || self.cosmetic.is_some();
                    let html_edit = can_inject && info.html && renderable && editable;
                    // `$replace`, `$jsonprune` and `$hls` only ever look at
                    // text bodies: media, images and downloads travel
                    // untouched.
                    let replace = req.replace.filter(|_| info.text && editable);
                    let jsonprune = req.jsonprune.filter(|_| info.text && editable);
                    let hls = req.hls.filter(|_| info.text && editable);
                    // `$$` / `##^` read only a page that arrived whole: a
                    // document response with 200. What the response holds is
                    // read as bytes, so the content type only has to say
                    // `text/html` — nothing is decoded but the body itself.
                    let html = req
                        .html
                        .filter(|_| info.html && info.status == 200 && editable);
                    let holding = replace.is_some()
                        || jsonprune.is_some()
                        || hls.is_some()
                        || html.is_some();
                    // A body edit needs the whole body, which is the one thing
                    // streaming cannot give it: a body already known to be over
                    // the cap is left to the page's own handling below.
                    let over_cap =
                        matches!(framing, Some(Framing::Length(n)) if n > http::REPLACE_AFTER);
                    if holding && !over_cap {
                        let framing = framing.expect("framing is Some when a rule holds");
                        // Rewriting on the fly is what makes a gzip body
                        // affordable; without a codec the whole body is
                        // held instead.
                        let how = if streamable(info.encoding) {
                            "rewriting"
                        } else {
                            "buffering"
                        };
                        crate::logbuf::push(&format!(
                            "mitm {}: {} {} {:?} {:?}: {how}",
                            self.captured.as_deref().unwrap_or("?"),
                            if info.html { "html" } else { "text" },
                            info.status,
                            framing,
                            info.encoding,
                        ));
                        self.resp_phase = RespPhase::Buffer {
                            head,
                            framing,
                            encoding: info.encoding,
                            replace,
                            jsonprune,
                            hls,
                            html,
                            inject: html_edit,
                        };
                        continue;
                    }
                    if holding {
                        // The list matched and the body is too big to hold, so
                        // the edit cannot happen. The response goes out exactly
                        // as the page's own handling decides.
                        crate::logbuf::push(&format!(
                            "mitm {}: {} {:?} over the {} cap, left alone",
                            self.captured.as_deref().unwrap_or("?"),
                            info.status,
                            framing.expect("over the cap means a length was known"),
                            body_edit_name(
                                replace.is_some(),
                                jsonprune.is_some(),
                                html.is_some()
                            ),
                        ));
                    }
                    if html_edit {
                        let framing = framing.expect("framing is Some when html_edit holds");
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
                            replace: None,
                            jsonprune: None,
                            hls: None,
                            html: None,
                            inject: true,
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
                            Some(Framing::Chunked) => Left::Chunked(ChunkPass {
                                tail: Vec::new(),
                                framing: http::DechunkState::new(),
                            }),
                            None => Left::End,
                        },
                    };
                    continue;
                }
                RespPhase::Buffer {
                    head,
                    framing,
                    encoding,
                    replace,
                    inject,
                    jsonprune,
                    hls,
                    html,
                } => {
                    // A body edit needs the whole body, so it holds one far
                    // longer than an injection does.
                    let cap = if replace.is_some()
                        || jsonprune.is_some()
                        || hls.is_some()
                        || html.is_some()
                    {
                        http::REPLACE_AFTER
                    } else {
                        http::STREAM_AFTER
                    };
                    let Some(body) = self.take_body(framing) else {
                        if self.resp_pending.len() > cap {
                            if inject && streamable(encoding) {
                                // Too much to keep holding: what is here goes
                                // out now and the rest follows as it arrives.
                                // Only a page can fall back this way — the
                                // injector re-encodes on the fly, a body edit
                                // cannot.
                                if replace.is_some()
                                    || jsonprune.is_some()
                                    || hls.is_some()
                                    || html.is_some()
                                {
                                    crate::logbuf::push(&format!(
                                        "mitm {}: body over {} bytes in {:?}, {} dropped",
                                        self.captured.as_deref().unwrap_or("?"),
                                        cap,
                                        encoding,
                                        body_edit_name(
                                            replace.is_some(),
                                            jsonprune.is_some(),
                                            html.is_some()
                                        ),
                                    ));
                                }
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
                                cap,
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
                                replace,
                                jsonprune,
                                hls,
                                html,
                                inject,
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
                        emit_passthrough(&mut out, &head, &body, framing, encoding);
                        self.resp_phase = RespPhase::Head;
                        continue;
                    }
                    let recompress = decoded.is_some();
                    let plain = decoded.as_deref().unwrap_or(&body);
                    // `$hls` first: the playlist edit drops whole lines, and
                    // the passes below read what it left. Each log line names
                    // the bytes its own pass started from.
                    let original = plain.len();
                    let trimmed = hls.as_ref().and_then(|plan| plan.apply(plain));
                    let plain = trimmed
                        .as_ref()
                        .map(|(body, _)| body.as_slice())
                        .unwrap_or(plain);
                    if let Some((_, applied)) = trimmed.as_ref() {
                        crate::logbuf::push(&format!(
                            "mitm {}: $hls applied ({} to {} bytes): {}",
                            self.captured.as_deref().unwrap_or("?"),
                            original,
                            plain.len(),
                            applied.join("; "),
                        ));
                    }
                    // `$jsonprune` takes its matches out of the document
                    // itself, and the `$replace` pass below then reads the
                    // pruned bytes — a regexp written for what the client
                    // will get.
                    let before_prune = plain.len();
                    let pruned = jsonprune.as_ref().and_then(|plan| plan.apply(plain));
                    let plain = pruned
                        .as_ref()
                        .map(|(body, _)| body.as_slice())
                        .unwrap_or(plain);
                    if let Some((_, applied)) = pruned.as_ref() {
                        crate::logbuf::push(&format!(
                            "mitm {}: $jsonprune applied ({} to {} bytes): {}",
                            self.captured.as_deref().unwrap_or("?"),
                            before_prune,
                            plain.len(),
                            applied.join("; "),
                        ));
                    }
                    // `$$` / `##^`: the elements the matching rules name are
                    // cut out of the document itself, and the `$replace` pass
                    // below then reads what they left — a regexp written for
                    // what the client will get.
                    let before_html = plain.len();
                    let cut = html.as_ref().and_then(|plan| plan.apply(plain));
                    let plain = cut
                        .as_ref()
                        .map(|(body, _)| body.as_slice())
                        .unwrap_or(plain);
                    if let Some((_, applied)) = cut.as_ref() {
                        crate::logbuf::push(&format!(
                            "mitm {}: $$ applied ({} to {} bytes): {}",
                            self.captured.as_deref().unwrap_or("?"),
                            before_html,
                            plain.len(),
                            rules_summary(applied),
                        ));
                    }
                    // `$replace` second: what a list rewrites is the page's own
                    // bytes, and the snippet injected below is ours, not the
                    // list's — the two never feed into one another.
                    let before = plain.len();
                    let replaced = replace.as_ref().and_then(|rule| rule.apply(plain));
                    let plain = replaced.as_deref().unwrap_or(plain);
                    if let Some(rule) = replace.as_ref().filter(|_| replaced.is_some()) {
                        crate::logbuf::push(&format!(
                            "mitm {}: $replace applied ({} to {} bytes): {}",
                            self.captured.as_deref().unwrap_or("?"),
                            before,
                            plain.len(),
                            payload_summary(rule.payload())
                        ));
                    }
                    let edited =
                        replaced.is_some() || pruned.is_some() || trimmed.is_some() || cut.is_some();
                    // One nonce for this response: the tags carry it, and the
                    // policy does too when the head goes out rewritten below.
                    let nonce = http::new_nonce();
                    let snippet = if inject {
                        self.injection_snippet(plain, &nonce)
                    } else {
                        Vec::new()
                    };
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
                        // The page keeps its policy: it just learns the nonce
                        // the snippet's tags carry.
                        let head = http::csp_with_nonce(&head, &nonce, LOCAL_ORIGIN);
                        emit_edited(&mut out, &head, &new_body, recompress);
                    } else if edited {
                        // A rewrite without a snippet: the head only learns the
                        // length its body now has.
                        emit_edited(&mut out, &head, &new_body, recompress);
                    } else {
                        // Nothing to inject, or nowhere to put it: the bytes
                        // the origin sent go on untouched.
                        emit_passthrough(&mut out, &head, &body, framing, encoding);
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
                        // Close the chunked encoding cleanly so the part of the
                        // body the client did get stays readable, then hand the
                        // rest of the connection over untouched. The head may
                        // not have gone out yet — an error can strike before
                        // the injection point is ever found — and it goes
                        // before any body byte does.
                        if !state.finished {
                            if !state.head_sent {
                                let injecting = state.injected;
                                state.ensure_head(&mut out, injecting);
                                let prefix = std::mem::take(&mut state.prefix);
                                let _ = self.stream_body(&mut state, &prefix, &mut out);
                            }
                            if let Some(encoder) = state.gzip.as_mut() {
                                let mut tail = Vec::new();
                                if encoder.finish(&mut tail).is_ok() {
                                    http::emit_chunk(&mut out, &tail);
                                }
                            }
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
                RespPhase::Pass { left } => match left {
                    Left::Length(n) => {
                        let take = n.min(self.resp_pending.len());
                        out.extend(self.resp_pending.drain(..take));
                        if n > take {
                            self.resp_phase = RespPhase::Pass {
                                left: Left::Length(n - take),
                            };
                            break;
                        }
                        // This response is done: the next bytes are a head.
                        self.resp_phase = RespPhase::Head;
                        continue;
                    }
                    Left::Chunked(mut pass) => {
                        let fresh = std::mem::take(&mut self.resp_pending);
                        let before = pass.framing.consumed();
                        pass.tail.extend_from_slice(&fresh);
                        match pass.framing.walk(&fresh) {
                            Ok(done) => {
                                let eaten = pass.framing.consumed() - before;
                                out.extend_from_slice(&pass.tail[..eaten]);
                                pass.tail.drain(..eaten);
                                if done {
                                    // What followed the terminating chunk is
                                    // the next response's head — and this
                                    // connection is back to reading heads.
                                    self.resp_pending.append(&mut pass.tail);
                                    self.resp_phase = RespPhase::Head;
                                    continue;
                                }
                                self.resp_phase = RespPhase::Pass {
                                    left: Left::Chunked(pass),
                                };
                                break;
                            }
                            Err(e) => {
                                crate::logbuf::push(&format!(
                                    "mitm {}: chunked body is not framed ({e}), passing through",
                                    self.captured.as_deref().unwrap_or("?")
                                ));
                                // A body that is not framed the way it claims
                                // has no end this proxy can find: the rest of
                                // the connection goes over untouched.
                                out.extend_from_slice(&pass.tail);
                                self.resp_phase = RespPhase::Pass { left: Left::End };
                                break;
                            }
                        }
                    }
                    Left::End => {
                        out.append(&mut self.resp_pending);
                        self.resp_phase = RespPhase::Pass { left: Left::End };
                        break;
                    }
                },
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
                    let snippet = self.injection_snippet(&state.prefix, &state.nonce);
                    let before: Vec<u8> = state.prefix[..pos].to_vec();
                    let after: Vec<u8> = state.prefix[pos..].to_vec();
                    state.prefix.clear();
                    state.ensure_head(out, !snippet.is_empty());
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
                let snippet = self.injection_snippet(&state.prefix, &state.nonce);
                let before: Vec<u8> = state.prefix[..pos].to_vec();
                let after: Vec<u8> = state.prefix[pos..].to_vec();
                state.prefix.clear();
                state.ensure_head(out, !snippet.is_empty());
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
            let injecting = state.injected;
            state.ensure_head(out, injecting);
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

    /// The HTML snippet injected early in `<head>`: the hiding stylesheet, the
    /// cosmetic payload (rule data inline, runtime fetched from the app's own
    /// origin) plus the user script tag when one is installed. Empty when
    /// nothing applies.
    ///
    /// Every tag carries `nonce`, and the head's policy is taught the same
    /// value before it leaves, so a strict `script-src`/`style-src` lets the
    /// snippet through without the page losing its policy.
    fn injection_snippet(&self, body: &[u8], nonce: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(filter) = self.cosmetic.as_deref() {
            let switches = self
                .captured
                .as_deref()
                .map(|host| filter.cosmetic_switches_for(host))
                .unwrap_or_default();
            // A page the lists unblocked (`$document`, or `$elemhide` together
            // with `$jsinject`) has nothing left to hide, look up or inject:
            // every tag would be a fetch for nothing. The user's own script is
            // not the lists' to switch off, and still goes out below.
            if !(switches.elemhide && switches.jsinject) {
                // Without a hostname there are no rules to look up (a session
                // that never saw a ClientHello keeps only the runtime).
                if let Some(host) = self.captured.as_deref() {
                    // What the rules hide goes out as a stylesheet, not as inline
                    // data: the same 11 KB of all-site selectors applies to every
                    // page of a site, and this way the browser fetches it once and
                    // keeps it. It is fetched from the app's own origin, where the
                    // page's service worker cannot answer in our place.
                    if let Some((href, _)) = hide_stylesheet(filter, host) {
                        out.extend_from_slice(
                            http::style_link_tag(&local_asset(&href), "adfree-hide", nonce)
                                .as_bytes(),
                        );
                    }
                    if let Some(data) =
                        self.cosmetic_payload(filter, host, body, self.page_url.as_deref())
                    {
                        out.extend_from_slice(
                            format!("<script{}>window.__adfree_page=", http::nonce_attr(nonce))
                                .as_bytes(),
                        );
                        out.extend_from_slice(data.as_bytes());
                        out.extend_from_slice(b";</script>");
                    }
                }
                // The runtime goes out whenever cosmetic filtering runs, payload or
                // not: it is what finds rules for the tokens the proxy never saw,
                // which on a streamed page is everything past the anchor.
                // Not deferred: the hiding stylesheet must land before the body
                // renders, and every answer comes from the app itself.
                // `dmn=` is what tells the cross-origin runtime which host's rules
                // its lookups are for (AdGuard's content script carries the same
                // parameter).
                let runtime = match self.captured.as_deref() {
                    Some(host) => versioned_path(
                        &format!("{PAGE_SCRIPT_PATH}?dmn={host}"),
                        content_hash(PAGE_RUNTIME.as_bytes()),
                    ),
                    None => versioned_path(PAGE_SCRIPT_PATH, content_hash(PAGE_RUNTIME.as_bytes())),
                };
                out.extend_from_slice(
                    http::script_tag(&local_asset(&runtime), false, nonce).as_bytes(),
                );
            }
        }
        if !self.script_src.is_empty() {
            out.extend_from_slice(http::script_tag(&self.script_tag_src, true, nonce).as_bytes());
        }
        out
    }

    /// The per-page cosmetic payload as JSON, or `None` when the page has
    /// nothing left to carry inline (element hiding travels as a stylesheet).
    ///
    /// `page_url` is the page's own URL when the request carried one — that is
    /// what `[$path=…]` rules are matched against. Without it the answer is
    /// the host's alone: no `/`-path may stand in for a page nobody named.
    fn cosmetic_payload(
        &self,
        filter: &FilterEngine,
        host: &str,
        body: &[u8],
        page_url: Option<&str>,
    ) -> Option<String> {
        let rules = match page_url {
            Some(url) => filter.cosmetic_resources(url),
            None => filter.cosmetic_resources_for_host(host),
        };

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
        if !rules.jsrules.is_empty() {
            obj.insert("jsrules".into(), serde_json::json!(rules.jsrules));
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
///
/// The host whose rules the answer carries comes from the `dmn` parameter the
/// injected URLs carry; a legacy same-origin tag (a page cached before an app
/// update) has none, and falls back to the session's SNI.
pub fn take_local_request(
    serve_path: &str,
    script_body: &str,
    filter: Option<&FilterEngine>,
    session_host: Option<&str>,
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
            false,
        ));
    }
    let filter = filter?;
    let host = query_value(&first_line, "dmn")
        .filter(|h| is_plausible_host(h))
        .or_else(|| session_host.map(str::to_string));
    if target == PAGE_SCRIPT_PATH {
        buffer.drain(..head);
        return Some(local_response(
            "application/javascript; charset=utf-8",
            IMMUTABLE_CACHE,
            PAGE_RUNTIME.as_bytes(),
            gzip,
            false,
        ));
    }
    if target == HIDE_PATH {
        buffer.drain(..head);
        // Only the bytes matter here; the hash in the URL was computed over
        // exactly these bytes when the link was written. An empty stylesheet
        // (rules changed since) is a valid answer.
        let body = host
            .as_deref()
            .and_then(|h| hide_stylesheet(filter, h))
            .map(|(_, body)| body);
        return Some(local_response(
            "text/css; charset=utf-8",
            IMMUTABLE_CACHE,
            body.as_deref().unwrap_or("").as_bytes(),
            gzip,
            false,
        ));
    }
    if target == GENERIC_PATH {
        buffer.drain(..head);
        let (classes, ids) = generic_query(&first_line);
        let selectors = match host.as_deref() {
            Some(host) if !classes.is_empty() || !ids.is_empty() => {
                let rules = filter.cosmetic_resources_for_host(host);
                if rules.generichide {
                    Vec::new()
                } else {
                    filter.generic_selectors(&classes, &ids, &rules.exceptions)
                }
            }
            _ => Vec::new(),
        };
        let body = serde_json::to_string(&selectors).unwrap_or_else(|_| "[]".to_string());
        return Some(http_response(
            "application/json; charset=utf-8",
            body.as_bytes(),
        ));
    }
    None
}

/// One query parameter out of `GET /path?a=1 HTTP/1.1`.
fn query_value(first_line: &str, key: &str) -> Option<String> {
    let target = first_line.split(' ').nth(1)?;
    let query = target.find('?').map(|i| &target[i + 1..])?;
    for pair in query.split('&') {
        let Some(eq) = pair.find('=') else {
            continue;
        };
        if &pair[..eq] == key {
            return Some(percent_decode(&pair[eq + 1..]));
        }
    }
    None
}

/// Whether a `dmn` value looks like a hostname: the parameter is page-supplied,
/// and a garbage name would only waste a rule lookup, never leak anything.
fn is_plausible_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
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
///
/// The lookup is the one local answer a page *reads* (the runtime fetches it
/// across origins), so it is the one that carries CORS.
fn http_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    local_response(content_type, "no-store", body, false, true)
}

/// A locally answered response with an explicit cache policy.
///
/// `gzip` encodes the body when the caller saw the client accept it: the page
/// runtime and the hiding stylesheet are document-sized, and page data stays
/// compressed on the wire.
///
/// `Cross-Origin-Resource-Policy` keeps pages served under COEP working and is
/// on every answer; `Access-Control-Allow-Origin` is only on the ones a page
/// is allowed to *read* (the rule lookup). Scripts and stylesheets are loaded
/// by their tags and need no CORS — and the user script is the user's own
/// code, which a page must not be able to fetch behind their back.
fn local_response(content_type: &str, cache: &str, body: &[u8], gzip: bool, cors: bool) -> Vec<u8> {
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
    let cors = if cors {
        "Access-Control-Allow-Origin: *\r\n"
    } else {
        ""
    };
    let mut resp = Vec::with_capacity(payload.len() + 200);
    resp.extend_from_slice(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: {cache}\r\n{encoding}{cors}Cross-Origin-Resource-Policy: cross-origin\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        )
        .as_bytes(),
    );
    resp.extend_from_slice(payload);
    resp
}

/// The answer to anything else asked of the local origin: only the injected
/// assets live there, and a page may probe for more. `Connection: close` keeps
/// a stray request body from being read as the next request head.
fn not_found_response() -> Vec<u8> {
    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 9\r\nCache-Control: no-store\r\nConnection: close\r\n\r\nnot found"
        .to_vec()
}

/// The answer to a request a network rule blocked: no body and no cache entry,
/// so the page sees a failed subresource rather than a bogus one.
pub(super) fn blocked_response() -> Vec<u8> {
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n".to_vec()
}

/// The answer a `$urltransform` rule gets when it moves the request to another
/// origin.
///
/// A rewrite of the request line could not take the request there — the peer
/// the connection reaches is fixed — but a redirect can, and AdGuard defines
/// exactly that as the limit of the modifier: a transform changing the origin
/// only applies when it is achievable via an HTTP redirect.
pub(super) fn transform_redirect_response(location: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n"
    )
    .into_bytes()
}

/// Marks a locally answered response as the last one on the connection.
///
/// It matters for the clients that asked to be closed down — an HTTP/1.0
/// client without `Connection: keep-alive` waits for EOF, and a locally
/// answered response has no origin to bring it.
pub(super) fn closing_response(mut response: Vec<u8>) -> Vec<u8> {
    // The marker goes *inside* the head: the head ends with a CRLF pair, and
    // the line break before the blank line belongs to the last header that is
    // already there.
    if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
        response.splice(end + 2..end + 2, b"Connection: close\r\n".iter().copied());
    }
    response
}

/// Turns the engine's redirect form (`data:<mime>;base64,<payload>`) into a
/// response body that stands in for the blocked request.
///
/// The one shape the crate produces for a `$redirect` resource is a `data:`
/// URL; anything else is not a redirect we can serve and the caller falls back
/// to a plain block.
pub(super) fn redirect_response(data_url: &str) -> Option<Vec<u8>> {
    let (mime, payload) = data_url.strip_prefix("data:")?.split_once(',')?;
    let mime = mime.strip_suffix(";base64")?;
    let body = BASE64_STANDARD.decode(payload).ok()?;
    let mime = if mime.is_empty() { "text/plain" } else { mime };
    Some(local_response(mime, "max-age=3600", &body, false, true))
}

/// The body a request announced, as far as answering it locally goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestBody {
    /// `Content-Length: n`, n > 0.
    Length(u64),
    /// `Transfer-Encoding`: the body is chunked and ends at its last chunk.
    Chunked,
    /// A `Content-Length` this proxy cannot read. The body cannot be counted,
    /// so a body byte can never be told from the next request: the request is
    /// not answered locally.
    Unknown,
}

/// A body the proxy owes itself: the request it belongs to was answered
/// locally, and the bytes that follow its head are nobody's.
///
/// `pub(super)` so the splice's own tests can drive the swallow directly.
pub(super) enum ClientDiscard {
    /// `Content-Length` bytes still to come.
    Length(u64),
    /// A chunked body, followed as far as its last chunk.
    Chunked(http::DechunkState),
    /// A body whose framing could not be followed: everything the client sends
    /// from here on is dropped, so no body byte is ever parsed as a request of
    /// its own. The connection is left to end on its own terms.
    Poisoned,
}

/// Swallows the body bytes of a request this proxy answered itself.
///
/// The head was taken out of `buffer` when the answer went out; the bytes
/// after it belong to nobody and must be gone before anything is parsed again
/// — a body may look like a request line at any offset. What the buffer
/// already carries is dropped here, and the state for what is still on its
/// way comes back (`None` once the body is done).
///
/// `state` says a swallow is already running, `body` only says how one
/// starts; a caller continuing one passes `None` there.
///
/// `pub(super)` so the splice's own tests can drive it directly.
pub(super) fn swallow_body(
    state: Option<ClientDiscard>,
    body: Option<RequestBody>,
    buffer: &mut Vec<u8>,
    host: Option<&str>,
) -> Option<ClientDiscard> {
    let state = match state {
        Some(state) => state,
        None => match body? {
            // A length nobody can read is never answered locally: see
            // [`RequestBody::Unknown`].
            RequestBody::Unknown => return None,
            RequestBody::Length(left) => ClientDiscard::Length(left),
            RequestBody::Chunked => ClientDiscard::Chunked(http::DechunkState::new()),
        },
    };
    match state {
        ClientDiscard::Length(left) => {
            let take = (left.min(buffer.len() as u64)) as usize;
            buffer.drain(..take);
            let left = left - take as u64;
            (left > 0).then_some(ClientDiscard::Length(left))
        }
        ClientDiscard::Chunked(mut framing) => match framing.walk(buffer) {
            Ok(false) => {
                // All of it was body: the rest of the framing is still to
                // come, and the walker kept what it could not place yet.
                buffer.clear();
                Some(ClientDiscard::Chunked(framing))
            }
            Ok(true) => {
                // Whatever follows the last chunk is the next request.
                let leftover = framing.leftover().to_vec();
                buffer.clear();
                buffer.extend_from_slice(&leftover);
                None
            }
            Err(e) => {
                crate::logbuf::push(&format!(
                    "mitm {}: the body of an answered request is not chunked framing ({e}), \
                     dropping the rest of the connection's requests",
                    host.unwrap_or("?")
                ));
                buffer.clear();
                Some(ClientDiscard::Poisoned)
            }
        },
        ClientDiscard::Poisoned => {
            buffer.clear();
            Some(ClientDiscard::Poisoned)
        }
    }
}

/// One client request head, as far as the URL filter needs it.
///
/// `pub(super)` so the splice's own tests can drive the parser directly.
pub(super) struct RequestFacts<'a> {
    pub(super) method: &'a str,
    pub(super) target: &'a str,
    pub(super) authority: Option<&'a str>,
    pub(super) referer: Option<&'a str>,
    /// `Sec-Fetch-Dest`, the only trustworthy word on what the request is for.
    pub(super) dest: Option<&'a str>,
    /// The body the head announced, when there is one and it said how to
    /// count it — what a locally served answer has to swallow
    /// ([`swallow_body`]). A bodyless request leaves this `None`.
    pub(super) body: Option<RequestBody>,
    /// The connection ends after this exchange: a locally answered response
    /// has to say so, because no origin ever will.
    pub(super) closes: bool,
}

impl RequestFacts<'_> {
    /// The engine's name for the request type. Chrome sends `Sec-Fetch-Dest`;
    /// anything else counts as `other`, which keeps type-scoped rules from
    /// firing on a guess.
    pub(super) fn request_type(&self) -> &'static str {
        match self.dest.unwrap_or("") {
            "document" => "document",
            "iframe" | "frame" => "subdocument",
            "script" => "script",
            "style" => "stylesheet",
            "image" | "imageset" => "image",
            "font" => "font",
            "audio" | "video" | "track" => "media",
            "object" | "embed" => "object",
            "empty" => "xmlhttprequest",
            "report" => "csp_report",
            _ => "other",
        }
    }
}

/// Parses a request head. `None` when it is not an HTTP/1.x request at all
/// (the injected assets and any non-HTTP bytes never get this far).
pub(super) fn request_facts(head: &[u8]) -> Option<RequestFacts<'_>> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") || method.is_empty() {
        return None;
    }
    let mut facts = RequestFacts {
        method,
        target,
        authority: None,
        referer: None,
        dest: None,
        body: None,
        closes: false,
    };
    let mut connection = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "host" => facts.authority = Some(value),
            "referer" => facts.referer = Some(value),
            "sec-fetch-dest" => facts.dest = Some(value),
            "connection" => connection = Some(value),
            "transfer-encoding" => {
                facts.body = Some(RequestBody::Chunked);
            }
            "content-length" => match value.parse::<u64>() {
                Ok(0) => {}
                Ok(len) => {
                    // `Transfer-Encoding` wins when both are spelled.
                    facts.body.get_or_insert(RequestBody::Length(len));
                }
                Err(_) => {
                    facts.body.get_or_insert(RequestBody::Unknown);
                }
            },
            _ => {}
        }
    }
    // HTTP/1.1 defaults to keeping the connection, HTTP/1.0 to closing it.
    facts.closes = match connection {
        Some(value) => {
            let value = value.to_ascii_lowercase();
            value.contains("close") || (version == "HTTP/1.0" && !value.contains("keep-alive"))
        }
        None => version == "HTTP/1.0",
    };
    Some(facts)
}

/// The absolute URL of a request: its target, resolved against the host the
/// connection was opened for.
pub(super) fn request_url(facts: &RequestFacts<'_>, host: &str) -> String {
    if facts.target.starts_with("http://") || facts.target.starts_with("https://") {
        return facts.target.to_string();
    }
    let mut url = String::with_capacity(host.len() + facts.target.len() + 8);
    url.push_str("https://");
    url.push_str(host);
    url.push_str(facts.target);
    url
}

/// The origin-form target of a URL (`/path?query`): what a request line wants.
pub(super) fn origin_form(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let start = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let origin = &rest[start..];
    if origin.is_empty() || origin.starts_with('#') {
        return Some("/".to_string());
    }
    if origin.starts_with('/') {
        Some(origin.to_string())
    } else {
        Some(format!("/{origin}"))
    }
}

/// Replaces the target of a request line, leaving the rest of the head alone.
pub(super) fn rebuilt_head(head: &[u8], target: &str) -> Vec<u8> {
    let Some(line_end) = head.windows(2).position(|w| w == b"\r\n") else {
        return head.to_vec();
    };
    let line = String::from_utf8_lossy(&head[..line_end]);
    let mut parts = line.splitn(3, ' ');
    let (Some(method), Some(_), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return head.to_vec();
    };
    let mut rebuilt = Vec::with_capacity(head.len() + target.len());
    rebuilt.extend_from_slice(format!("{method} {target} {version}").as_bytes());
    rebuilt.extend_from_slice(&head[line_end..]);
    rebuilt
}

/// Whether a URL rewrite may touch this request.
///
/// `$removeparam` is "only applied to `GET`, `HEAD`, `OPTIONS`, and sometimes
/// `POST` requests" (the knowledge base), so a POST that reached this far may
/// have its query rewritten; anything else keeps it untouched. `$urltransform`
/// changes of origin are gated separately — they need a redirect, and only a
/// request-line method may be answered with one.
pub(super) fn rewritable(method: &str) -> bool {
    matches!(method, "GET" | "HEAD" | "OPTIONS" | "POST")
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

/// The elements-hiding stylesheet of a host: its bytes and the URL they are
/// served from. `None` when nothing is hidden on this host.
///
/// The bytes are what the URL hashes, so the two can never disagree: whoever
/// writes the link and whoever answers it build the same string. The host
/// travels in the URL (`dmn=`) because the answer comes from the app's own
/// origin, where the session's SNI is not the page's hostname.
pub(crate) fn hide_stylesheet(filter: &FilterEngine, host: &str) -> Option<(String, String)> {
    let selectors = filter.hide_selectors_for(host);
    if selectors.is_empty() {
        return None;
    }
    let body = format!("{}{{display:none!important}}\n", selectors.join(","));
    let path = format!("{HIDE_PATH}?dmn={host}");
    Some((versioned_path(&path, content_hash(body.as_bytes())), body))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::ca::CertificateAuthority;
    use crate::mitm::tls::open_session;

    /// A session with nothing to inject and nothing to hide: only a header edit
    /// makes the rewriter do any work on such a flow.
    fn quiet_proxy(ca: &CertificateAuthority) -> ProxySession {
        let resolver = Arc::new(tls::SniCertResolver::new(Arc::new(
            CertificateAuthority::from_pem(&ca.cert_pem(), &ca.key_pem()).expect("restore"),
        )));
        let session = open_session(&resolver, "origin.example.com").expect("session");
        ProxySession::new(session, String::new(), Arc::from(""))
    }

    /// A cookie plan the test engine produces for one request.
    fn cookie_plan(tag: &str, rules: &str, url: &str) -> Arc<CookiePlan> {
        let dir = std::env::temp_dir().join("adfree-proxy-cookie-tests");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(format!("{tag}-list.txt"));
        std::fs::write(&path, rules).expect("write list");
        let engine = FilterEngine::new();
        engine.rebuild(
            &[crate::filter::FilterListInfo {
                id: 1,
                name: tag.to_string(),
                url: String::new(),
                enabled: true,
                local_path: Some(path),
                format: crate::filter::ListFormat::Standard,
                category: 0,
                trusted: true,
                rule_count: 0,
                last_error: None,
            }],
            &[],
        );
        Arc::new(
            engine
                .cookie_plan(url, url, "GET")
                .expect("the rules match the request"),
        )
    }

    /// A `$jsonprune` plan the test engine produces for one request.
    fn jsonprune_plan(tag: &str, rules: &str, url: &str) -> Arc<JsonprunePlan> {
        let dir = std::env::temp_dir().join("adfree-proxy-jsonprune-tests");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(format!("{tag}-list.txt"));
        std::fs::write(&path, rules).expect("write list");
        let engine = FilterEngine::new();
        engine.rebuild(
            &[crate::filter::FilterListInfo {
                id: 1,
                name: tag.to_string(),
                url: String::new(),
                enabled: true,
                local_path: Some(path),
                format: crate::filter::ListFormat::Standard,
                category: 0,
                trusted: true,
                rule_count: 0,
                last_error: None,
            }],
            &[],
        );
        Arc::new(
            engine
                .jsonprune_plan(url, url, "xmlhttprequest", "GET")
                .expect("the rules match the request"),
        )
    }

    /// A `$jsonprune` plan alone rewrites the body the origin sends — the
    /// document goes out with the items removed and a head whose length names
    /// what the client will actually read, with no script or cosmetic to keep
    /// the rewriter awake.
    #[test]
    fn a_jsonprune_plan_alone_rewrites_the_body() {
        let ca = CertificateAuthority::generate().expect("ca");
        let mut proxy = quiet_proxy(&ca);
        let plan = jsonprune_plan(
            "jsonprune-body",
            "||origin.example.com^$jsonprune=\\$.ads\n",
            "https://origin.example.com/x",
        );
        proxy.head_requests.push_back(ResponseEdit {
            info: http::RequestInfo {
                head: false,
                http10: false,
            },
            replace: None,
            headers: None,
            cookies: None,
            jsonprune: Some(plan),
            hls: None,
            html: None,
            page_url: None,
        });

        let body = br#"{"ads": [1, 2], "keep": 3}"#;
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        let (out, _) = proxy.rewrite_response(&response);

        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains(r#"{"keep":3}"#), "{text}");
        assert!(!text.contains("ads"), "{text}");
        assert!(text.contains("Content-Length: 10"), "{text}");
    }

    /// An `$hls` plan the test engine produces for one request.
    fn hls_plan(tag: &str, rules: &str, url: &str) -> Arc<HlsPlan> {
        let dir = std::env::temp_dir().join("adfree-proxy-hls-tests");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(format!("{tag}-list.txt"));
        std::fs::write(&path, rules).expect("write list");
        let engine = FilterEngine::new();
        engine.rebuild(
            &[crate::filter::FilterListInfo {
                id: 1,
                name: tag.to_string(),
                url: String::new(),
                enabled: true,
                local_path: Some(path),
                format: crate::filter::ListFormat::Standard,
                category: 0,
                trusted: true,
                rule_count: 0,
                last_error: None,
            }],
            &[],
        );
        Arc::new(
            engine
                .hls_plan(url, url, "xmlhttprequest", "GET")
                .expect("the rules match the request"),
        )
    }

    /// An `$hls` plan alone rewrites the body the origin sends — the playlist
    /// goes out with the segments removed and a head whose length names what
    /// the client will actually read.
    #[test]
    fn an_hls_plan_alone_rewrites_the_body() {
        let ca = CertificateAuthority::generate().expect("ca");
        let mut proxy = quiet_proxy(&ca);
        let plan = hls_plan(
            "hls-body",
            "||origin.example.com^$hls=ad.ts\n",
            "https://origin.example.com/hls/index.m3u8",
        );
        proxy.head_requests.push_back(ResponseEdit {
            info: http::RequestInfo {
                head: false,
                http10: false,
            },
            replace: None,
            headers: None,
            cookies: None,
            jsonprune: None,
            hls: Some(plan),
            html: None,
            page_url: None,
        });

        let body = b"#EXTM3U\n#EXTINF:10,\nad.ts\n#EXTINF:10,\n01.ts\n";
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        let (out, _) = proxy.rewrite_response(&response);

        let text = String::from_utf8(out).expect("utf8");
        let expected = "#EXTM3U\n#EXTINF:10,\n01.ts\n";
        assert!(text.contains(expected), "{text}");
        assert!(!text.contains("ad.ts"), "{text}");
        assert!(
            text.contains(&format!("Content-Length: {}", expected.len())),
            "{text}"
        );
        assert!(!text.contains(&format!("Content-Length: {}", body.len())), "{text}");
    }

    /// A connection that carries a `$cookie` plan and nothing else still needs
    /// the rewriter: the response head is where a `set-cookie` the rules name
    /// is taken off, and with no plan at all the bytes would bypass it.
    #[test]
    fn a_cookie_plan_alone_keeps_the_response_rewriter_awake() {
        let ca = CertificateAuthority::generate().expect("ca");
        let mut proxy = quiet_proxy(&ca);
        let plan = cookie_plan(
            "cookie-awake",
            "||origin.example.com^$cookie=dropme\n",
            "https://origin.example.com/x",
        );
        proxy.head_requests.push_back(ResponseEdit {
            info: http::RequestInfo {
                head: false,
                http10: false,
            },
            replace: None,
            headers: None,
            cookies: Some(plan),
            jsonprune: None,
            hls: None,
            html: None,
            page_url: None,
        });

        let response =
            b"HTTP/1.1 200 OK\r\nSet-Cookie: dropme=1\r\nSet-Cookie: keepme=2\r\nContent-Length: 0\r\n\r\n";
        let (out, injected) = proxy.rewrite_response(response);
        assert_eq!(injected, 0, "nothing is injected on this flow");
        let text = String::from_utf8(out).expect("utf8");
        assert!(
            !text.to_lowercase().contains("set-cookie: dropme"),
            "the named cookie must be gone: {text}"
        );
        assert!(
            text.contains("Set-Cookie: keepme=2"),
            "every other cookie stays: {text}"
        );
    }

    /// The same session without a plan is a pass-through: no edit, no copy.
    #[test]
    fn a_session_with_nothing_to_edit_bypasses_the_rewriter() {
        let ca = CertificateAuthority::generate().expect("ca");
        let mut proxy = quiet_proxy(&ca);
        let response = b"HTTP/1.1 200 OK\r\nSet-Cookie: dropme=1\r\nContent-Length: 0\r\n\r\n";
        let (out, injected) = proxy.rewrite_response(response);
        assert_eq!(injected, 0);
        assert_eq!(out, response);
    }

    /// A chunked body nobody edits still has to be followed to its end: the
    /// head behind the terminating chunk is the next response's, and a
    /// connection that stops looking for heads after a chunked body lets
    /// every later response go by unedited.
    #[test]
    fn a_chunked_body_passes_through_and_the_next_head_is_still_read() {
        let ca = CertificateAuthority::generate().expect("ca");
        let mut proxy = quiet_proxy(&ca);
        let plan = cookie_plan(
            "chunked-next-head",
            "||origin.example.com^$cookie=dropme\n",
            "https://origin.example.com/x",
        );
        for _ in 0..2 {
            proxy.head_requests.push_back(ResponseEdit {
                info: http::RequestInfo {
                    head: false,
                    http10: false,
                },
                replace: None,
                headers: None,
                cookies: Some(Arc::clone(&plan)),
                jsonprune: None,
                hls: None,
                html: None,
                page_url: None,
            });
        }
        // The first response — the shape the device showed: a JSON body
        // compressed and chunked, nothing for the rules to edit — arrives in
        // two reads, the first ending right after a chunk's payload.
        let first = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let cut = first.len() - 7;
        let (out, _) = proxy.rewrite_response(&first[..cut]);
        assert_eq!(out, &first[..cut], "the bytes go over as they came");
        let second = b"HTTP/1.1 200 OK\r\nSet-Cookie: dropme=1\r\nSet-Cookie: keepme=2\r\nContent-Length: 0\r\n\r\n";
        // The rest of the chunked body and the next response, one read.
        let (out, _) = proxy.rewrite_response(&[&first[cut..], second.as_slice()].concat());
        assert!(
            out.starts_with(&first[cut..]),
            "the tail of the body goes over as it came: {:?}",
            String::from_utf8_lossy(&out)
        );
        let text = String::from_utf8(out).expect("utf8");
        assert!(
            !text.to_lowercase().contains("set-cookie: dropme"),
            "the head behind a chunked body must still be edited: {text}"
        );
        assert!(
            text.contains("Set-Cookie: keepme=2"),
            "and only the cookie the rules name is taken: {text}"
        );
    }

    /// A body that claims to be chunked and is not: no end can be found, so
    /// nothing is guessed at — the rest of the connection goes over as it
    /// came.
    #[test]
    fn a_body_that_is_not_chunked_framing_gives_up_the_connection() {
        let ca = CertificateAuthority::generate().expect("ca");
        let mut proxy = quiet_proxy(&ca);
        let plan = cookie_plan(
            "chunked-give-up",
            "||origin.example.com^$cookie=dropme\n",
            "https://origin.example.com/x",
        );
        for _ in 0..2 {
            proxy.head_requests.push_back(ResponseEdit {
                info: http::RequestInfo {
                    head: false,
                    http10: false,
                },
                replace: None,
                headers: None,
                cookies: Some(Arc::clone(&plan)),
                jsonprune: None,
                hls: None,
                html: None,
                page_url: None,
            });
        }
        let broken = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nnot hex at all";
        let (out, _) = proxy.rewrite_response(broken);
        assert_eq!(out, broken, "a broken body is not rewritten or dropped");
        let next = b"HTTP/1.1 200 OK\r\nSet-Cookie: dropme=1\r\nContent-Length: 0\r\n\r\n";
        let (out, _) = proxy.rewrite_response(next);
        assert_eq!(out, next, "and neither is anything after it");
    }

    /// The head goes out before any body byte, even when the stream fails
    /// before the injection point was ever found.
    #[test]
    fn a_stream_that_fails_before_its_head_goes_out_still_writes_the_head_first() {
        let ca = CertificateAuthority::generate().expect("ca");
        let mut proxy = quiet_proxy(&ca);
        // A snippet to inject: the streaming path holds the head until it
        // knows what the snippet is and where it goes.
        proxy.script_src = "https://192.0.2.1/adfree.js?h=1".to_string();
        proxy.script_body = "/* snip */".into();
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 40000\r\n\r\n";
        let (out, _) = proxy.rewrite_response(head);
        assert!(out.is_empty(), "the head waits for the injection decision");
        // Bytes that are not gzip: the decode fails before `</head>` is found,
        // while the head is still unsent.
        let (out, _) = proxy.rewrite_response(b"not a gzip stream at all");
        assert!(
            out.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "the head goes out first: {:?}",
            String::from_utf8_lossy(&out[..out.len().min(32)])
        );
        assert!(out.ends_with(b"0\r\n\r\n"), "the chunked body is closed");
    }
}
