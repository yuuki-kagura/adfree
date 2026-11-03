//! HTTP/3 request filtering over QUIC.
//!
//! The client-facing endpoint terminates the client's QUIC connection, every
//! request runs through the same decision layer the HTTP/1.1 splice uses
//! ([`crate::mitm::decide`]), and what survives is re-originated over a fresh
//! QUIC connection to the real server. Bodies are streamed in both directions:
//! the edits that need a whole body belong to the response stage.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use http::uri::Authority;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request as HttpRequest, Response as HttpResponse,
    StatusCode, Uri,
};
use tokio::sync::Mutex;

use crate::engine::StealthConfig;
use crate::filter::FilterEngine;
use crate::mitm::decide::{self, Injector, RequestContext, RequestPlan, ResponsePlans};
use crate::mitm::proxy::{
    request_facts, request_url, take_local_request, MitmBlock, MitmSink, ProxySession, LOCAL_ORIGIN,
};
use crate::mitm::tls::UpstreamTls;

type ServerStream = RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ServerSend = RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ClientSend = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type ClientRecv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// What the local origin answers for a path it does not own.
const LOCAL_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 9\r\nCache-Control: no-store\r\n\r\nnot found";

/// Headers that describe an HTTP/1.1 connection and mean nothing in HTTP/3.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Everything one terminated QUIC connection needs to filter its requests.
pub struct HubConfig {
    pub filter: Arc<FilterEngine>,
    /// Packages owning the flow, for app-scoped rules.
    pub apps: Vec<String>,
    /// The host the connection was opened for (the QUIC SNI).
    pub server_name: String,
    /// Where the origin lives: the destination address of the flow.
    pub origin: SocketAddr,
    /// The connection belongs to the local injection origin: every request is
    /// answered here and no peer is dialed.
    pub local: bool,
    /// Path the user script is served from; empty when none is installed.
    pub serve_path: String,
    pub script_body: Arc<str>,
    /// The origin-absolute URL the user-script tag carries (the versioned
    /// local asset, the same one the HTTP/1.1 splice injects).
    pub script_tag_src: String,
    /// The engine cosmetic rules are read from, when the user enabled element
    /// hiding; `None` leaves the snippet to the user script and the runtime.
    pub cosmetic: Option<Arc<FilterEngine>>,
    /// The stealth switches: request edits run before the rules see the head,
    /// the WebRTC guard is injected with the rest of the snippet.
    pub stealth: StealthConfig,
    pub upstream: Arc<UpstreamTls>,
    /// The protected UDP socket the upstream QUIC connections leave through.
    pub endpoint: quinn::Endpoint,
    pub sink: Option<MitmSink>,
}

impl HubConfig {
    /// The per-session inputs the shared snippet builder reads.
    fn injector<'a>(&'a self, page_url: Option<&'a str>) -> Injector<'a> {
        Injector {
            script_src: &self.serve_path,
            script_tag_src: &self.script_tag_src,
            cosmetic: self.cosmetic.as_deref(),
            host: Some(&self.server_name),
            page_url,
            apps: &self.apps,
            stealth: self.stealth,
        }
    }
}

/// Serves one terminated QUIC connection until the client closes it.
pub async fn serve_connection(connection: quinn::Connection, config: Arc<HubConfig>) {
    let mut server = match h3::server::Connection::new(h3_quinn::Connection::new(connection)).await
    {
        Ok(server) => server,
        Err(e) => {
            crate::logbuf::push_error(&format!(
                "quic {}: h3 setup failed: {e}",
                config.server_name
            ));
            return;
        }
    };
    let upstream = Arc::new(Upstream::default());
    loop {
        // Resolving the request head is part of the task: a client that opens
        // a stream and sends nothing must not stall every other stream.
        let resolver = match server.accept().await {
            Ok(Some(resolver)) => resolver,
            Ok(None) => break,
            Err(e) => {
                crate::logbuf::push_error(&format!(
                    "quic {}: accept failed: {e}",
                    config.server_name
                ));
                break;
            }
        };
        let config = Arc::clone(&config);
        let upstream = Arc::clone(&upstream);
        tokio::spawn(async move {
            let (request, stream) = match resolver.resolve_request().await {
                Ok(pair) => pair,
                Err(e) => {
                    crate::logbuf::push_error(&format!(
                        "quic {}: request failed: {e}",
                        config.server_name
                    ));
                    return;
                }
            };
            if let Err(e) = handle_request(request, stream, &config, &upstream).await {
                crate::logbuf::push_error(&format!("quic {}: {e}", config.server_name));
            }
        });
    }
}

/// The upstream HTTP/3 connection of one client connection.
///
/// Browsers open one QUIC connection per origin and many requests over it;
/// re-originating each request on its own connection would pay a handshake per
/// subresource. The sender is held behind a mutex only long enough to open a
/// request stream.
#[derive(Default)]
struct Upstream {
    sender: Mutex<Option<ClientSend>>,
}

impl Upstream {
    async fn request(
        &self,
        config: &HubConfig,
        request: HttpRequest<()>,
    ) -> Result<ClientStream, String> {
        let mut guard = self.sender.lock().await;
        if guard.is_none() {
            *guard = Some(connect(config).await?);
        }
        let sender = guard.as_mut().expect("just filled");
        match sender.send_request(request).await {
            Ok(stream) => Ok(stream),
            Err(e) => {
                // The connection is unusable; the next request dials again.
                *guard = None;
                Err(format!("upstream request: {e}"))
            }
        }
    }
}

/// Opens the upstream QUIC connection for `config.origin`.
async fn connect(config: &HubConfig) -> Result<ClientSend, String> {
    let client = quinn_client_config(config.upstream.plain_h3())?;
    let connecting = config
        .endpoint
        .connect_with(client, config.origin, &config.server_name)
        .map_err(|e| format!("upstream connect: {e}"))?;
    let connection = connecting
        .await
        .map_err(|e| format!("upstream handshake: {e}"))?;
    let (mut h3_conn, sender) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| format!("upstream h3: {e}"))?;
    // The h3 client only makes progress while its connection is polled.
    tokio::spawn(async move {
        let _ = h3_conn.wait_idle().await;
    });
    Ok(sender)
}

/// Wraps a rustls client config so quinn can drive the QUIC handshake.
pub fn quinn_client_config(tls: Arc<rustls::ClientConfig>) -> Result<quinn::ClientConfig, String> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| format!("QUIC client config: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

/// Wraps a rustls server config for a client-facing endpoint.
pub fn quinn_server_config(tls: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig, String> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| format!("QUIC server config: {e}"))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Filters one request and carries it to the origin (or answers it here).
async fn handle_request(
    request: HttpRequest<()>,
    stream: ServerStream,
    config: &HubConfig,
    upstream: &Upstream,
) -> Result<(), String> {
    let (mut send_back, mut recv) = stream.split();
    let Some((mut head, authority)) = serialize_request(&request) else {
        return reply_status(&mut send_back, StatusCode::BAD_REQUEST).await;
    };

    if config.local {
        let response = take_local_request(
            &config.serve_path,
            &config.script_body,
            Some(&config.filter),
            Some(authority.as_str()),
            &mut head,
        )
        .unwrap_or_else(|| LOCAL_404.to_vec());
        return reply_http1(&mut send_back, &response).await;
    }

    // Stealth mode edits the same serialized head the HTTP/1.1 splice edits,
    // through the same routine: the tracking parameters, the third-party
    // cookies and the user agent are as far as this path differs from the TCP
    // one.
    let mut stealth_plan = RequestPlan::default();
    ProxySession::apply_stealth(
        &mut head,
        &mut stealth_plan,
        Some(&config.server_name),
        config.stealth,
    );

    // The decision layer expects the same HTTP/1.1 head the splice hands it;
    // everything it needs is parsed out before the head is edited.
    let Some(head_end) = crate::mitm::http::head_end(&head) else {
        return reply_status(&mut send_back, StatusCode::BAD_REQUEST).await;
    };
    // Everything the decision needs is copied out of the head first: the head
    // itself is edited below, which ends the borrow.
    let Some((target, method, request_type, url, source)) = ({
        let facts = request_facts(&head[..head_end]);
        facts.map(|facts| {
            let request_type = facts.request_type();
            let url = request_url(&facts, authority.as_str());
            let source = match facts.referer {
                Some(referer) if !referer.is_empty() => referer.to_string(),
                _ if request_type == "document" => url.clone(),
                _ => String::new(),
            };
            (
                facts.target.to_string(),
                facts.method.to_string(),
                request_type,
                url,
                source,
            )
        })
    }) else {
        return reply_status(&mut send_back, StatusCode::BAD_REQUEST).await;
    };
    if !target.starts_with('/') {
        return reply_status(&mut send_back, StatusCode::BAD_REQUEST).await;
    }
    let page_url = config.filter.has_path_rules().then(|| url.clone());
    let decision = decide::decide_request(
        &RequestContext {
            filter: &config.filter,
            host: &config.server_name,
            url: &url,
            method: &method,
            target: &target,
            source: &source,
            request_type,
            apps: &config.apps,
            page_url,
            closes: false,
        },
        &mut head,
        head_end,
    );
    let mut plan = decision.plan;
    // A cross-site request went out without its cookies; the answer may not
    // hand it new ones either.
    plan.block_cookies |= stealth_plan.block_cookies;
    plan.drop_etag |= stealth_plan.drop_etag;
    if let Some(answer) = decision.answer {
        if let Some(sink) = config.sink {
            sink(&MitmBlock {
                host: &config.server_name,
                url: None,
                rule: answer.rule.as_deref(),
                list_name: answer.list_name.as_deref(),
                category: answer.category,
                apps: &config.apps,
            });
        }
        return reply_http1(&mut send_back, &answer.response).await;
    }

    // The buffer holds the head alone, and the cookie/cookie-header edits
    // below can shrink it without moving the offset the decision reports, so
    // the whole buffer is the head that goes out.
    let Some(parsed) = parse_head(&head) else {
        return reply_status(&mut send_back, StatusCode::BAD_REQUEST).await;
    };
    let upstream_request = build_request(&parsed, &authority)?;
    let upstream_stream = match upstream.request(config, upstream_request).await {
        Ok(stream) => stream,
        Err(e) => {
            crate::logbuf::push_error(&format!("quic {}: {e}", config.server_name));
            return reply_status(&mut send_back, StatusCode::BAD_GATEWAY).await;
        }
    };

    // Request body and response are independent directions of the same
    // stream: pumping the body on its own task keeps a server that answers
    // before the client finishes its upload from waiting on it.
    let (mut up_send, mut up_recv) = upstream_stream.split();
    let body = tokio::spawn(async move {
        loop {
            match recv.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let data = chunk.copy_to_bytes(chunk.remaining());
                    if up_send.send_data(data).await.is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = up_send.finish().await;
                    break;
                }
                Err(_) => break,
            }
        }
    });
    let result = relay_response(&mut up_recv, &mut send_back, config, &plan).await;
    body.abort();
    result
}

/// Serializes an h3 request into the HTTP/1.1 head the decision layer reads.
fn serialize_request(request: &HttpRequest<()>) -> Option<(Vec<u8>, Authority)> {
    let authority = request_authority(request)?;
    let method = request.method().as_str();
    let target = request
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(format!("{method} {target} HTTP/1.1\r\n").as_bytes());
    head.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    for (name, value) in request.headers() {
        if name == http::header::HOST || HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    Some((head, authority))
}

/// The `:authority` of a request, or its `Host` header when a client sent one
/// instead.
fn request_authority(request: &HttpRequest<()>) -> Option<Authority> {
    if let Some(authority) = request.uri().authority() {
        return Some(authority.clone());
    }
    let value = request.headers().get(http::header::HOST)?;
    std::str::from_utf8(value.as_bytes()).ok()?.parse().ok()
}

/// One request head, after the rules may have edited it.
struct ParsedHead {
    method: Method,
    target: String,
    headers: Vec<(HeaderName, HeaderValue)>,
}

fn parse_head(head: &[u8]) -> Option<ParsedHead> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let method = Method::from_bytes(parts.next()?.as_bytes()).ok()?;
    let target = parts.next()?.to_string();
    let _version = parts.next()?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(value.trim()) else {
            continue;
        };
        headers.push((name, value));
    }
    Some(ParsedHead {
        method,
        target,
        headers,
    })
}

/// Rebuilds the upstream request from the head the rules left behind.
fn build_request(parsed: &ParsedHead, authority: &Authority) -> Result<HttpRequest<()>, String> {
    let path = if parsed.target.starts_with('/') {
        parsed.target.as_str()
    } else {
        "/"
    };
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority.clone())
        .path_and_query(path)
        .build()
        .map_err(|e| format!("request uri: {e}"))?;
    let mut request = HttpRequest::builder()
        .method(parsed.method.clone())
        .uri(uri)
        .body(())
        .map_err(|e| format!("request: {e}"))?;
    for (name, value) in &parsed.headers {
        request.headers_mut().append(name.clone(), value.clone());
    }
    Ok(request)
}

/// A response body up to this size may be buffered for the rules that need the
/// whole of it; a longer one passes through untouched.
const BODY_EDIT_CAP: usize = 512 * 1024;

/// Relays the origin's response to the client, applying the header and body
/// edits the request's plan carries.
///
/// A response no rule needs whole streams straight through. One that does
/// (`$replace`, `$jsonprune`, `$hls`, `$$`, injection) is buffered up to
/// [`BODY_EDIT_CAP`], decoded when it arrived compressed, edited, and encoded
/// again before it goes out. A body over the cap, or in an encoding this
/// cannot read, keeps every byte the origin sent.
async fn relay_response(
    up: &mut ClientRecv,
    send: &mut ServerSend,
    config: &HubConfig,
    plan: &RequestPlan,
) -> Result<(), String> {
    let response = up
        .recv_response()
        .await
        .map_err(|e| format!("upstream response: {e}"))?;
    let status = response.status();
    let original = response.headers().clone();
    let host = config.server_name.as_str();
    let mut wire = serialize_response_head(status, &original);
    let info = crate::mitm::http::parse_response_head(&wire);

    // A redirect's body is never rendered, so there is nothing to inject into
    // and nothing a list rewrites there. `$$` reads only a document that
    // arrived whole; the other body edits read any text.
    let renderable = !(300..400).contains(&status.as_u16());
    let injector = config.injector(plan.page_url.as_deref());
    let inject = injector.active() && info.html && renderable && !info.bodyless();
    let text = info.text;
    let plans = ResponsePlans {
        replace: plan.replace.clone().filter(|_| text),
        jsonprune: plan.jsonprune.clone().filter(|_| text),
        hls: plan.hls.clone().filter(|_| text),
        html: plan
            .html
            .clone()
            .filter(|_| info.html && status == StatusCode::OK),
    };
    let needs_whole_body = inject
        || plans.replace.is_some()
        || plans.jsonprune.is_some()
        || plans.hls.is_some()
        || plans.html.is_some();
    let decodable = matches!(
        info.encoding,
        crate::mitm::http::Encoding::Identity
            | crate::mitm::http::Encoding::Gzip
            | crate::mitm::http::Encoding::Deflate
    );
    let hold = needs_whole_body && decodable && !info.bodyless();

    let mut body = Vec::new();
    let mut overflow = false;
    if hold {
        loop {
            match up.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let data = chunk.copy_to_bytes(chunk.remaining());
                    body.extend_from_slice(&data);
                    if body.len() > BODY_EDIT_CAP {
                        overflow = true;
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(format!("upstream body: {e}")),
            }
        }
    }

    let mut nonce: Option<String> = None;
    let mut edited_body: Option<Vec<u8>> = None;
    let mut recompressed = false;
    if hold && !overflow {
        let decoded = crate::mitm::http::decode_body(&body, info.encoding);
        let plain = match (&decoded, info.encoding) {
            (Some(decoded), _) => Some(decoded.as_slice()),
            (None, crate::mitm::http::Encoding::Identity) => Some(body.as_slice()),
            _ => None,
        };
        if let Some(plain) = plain {
            let edited = decide::edit_response(&plans, plain, inject, &injector, host);
            if edited.decision == crate::mitm::http::Decision::Injected || edited.edited {
                let mut bytes = edited.body;
                if decoded.is_some() {
                    // The page leaves as compressed as it arrived, so the
                    // phone keeps the win the origin negotiated.
                    bytes = crate::mitm::http::gzip_encode(&bytes)
                        .ok_or_else(|| "gzip encode failed".to_string())?;
                    recompressed = true;
                }
                if edited.decision == crate::mitm::http::Decision::Injected {
                    crate::logbuf::push(&format!(
                        "quic {host}: injected {} bytes into a {} byte body (recompressed={recompressed})",
                        edited.injected,
                        plain.len(),
                    ));
                    nonce = Some(edited.nonce);
                }
                edited_body = Some(bytes);
            }
        }
    }

    apply_response_plan(&mut wire, plan, host);
    if let Some(nonce) = nonce.as_deref() {
        // The page keeps its policy: it just learns the nonce the snippet's
        // tags carry.
        wire = crate::mitm::http::csp_with_nonce(&wire, nonce, LOCAL_ORIGIN);
    }
    if let Some(bytes) = edited_body.as_ref() {
        wire = crate::mitm::http::head_for_new_body(
            &wire,
            bytes.len(),
            recompressed.then_some("gzip"),
        );
    }
    let Some((_, headers, _)) = parse_http1_response(&wire) else {
        return Err("upstream response head is not readable".to_string());
    };
    let mut out = HttpResponse::builder()
        .status(status)
        .body(())
        .map_err(|e| format!("upstream response: {e}"))?;
    *out.headers_mut() = headers;
    send.send_response(out)
        .await
        .map_err(|e| format!("response send: {e}"))?;

    match edited_body {
        Some(bytes) => {
            if !bytes.is_empty() {
                send.send_data(Bytes::from(bytes))
                    .await
                    .map_err(|e| format!("body send: {e}"))?;
            }
        }
        None if overflow => {
            // The body outgrew the cap: what was held goes out first, then the
            // rest streams as it arrives, unedited.
            if !body.is_empty() {
                send.send_data(Bytes::from(body))
                    .await
                    .map_err(|e| format!("body send: {e}"))?;
            }
            loop {
                match up.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let data = chunk.copy_to_bytes(chunk.remaining());
                        send.send_data(data)
                            .await
                            .map_err(|e| format!("body send: {e}"))?;
                    }
                    Ok(None) => break,
                    Err(e) => return Err(format!("upstream body: {e}")),
                }
            }
        }
        None if hold => {
            // Held whole but left alone: an encoding we cannot read, or no
            // rule actually changed it. The origin's bytes go out as they came.
            if !body.is_empty() {
                send.send_data(Bytes::from(body))
                    .await
                    .map_err(|e| format!("body send: {e}"))?;
            }
        }
        None => loop {
            match up.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let data = chunk.copy_to_bytes(chunk.remaining());
                    send.send_data(data)
                        .await
                        .map_err(|e| format!("body send: {e}"))?;
                }
                Ok(None) => break,
                Err(e) => return Err(format!("upstream body: {e}")),
            }
        },
    }

    match up.recv_trailers().await {
        Ok(Some(mut trailers)) => {
            strip_hop_by_hop(&mut trailers);
            send.send_trailers(trailers)
                .await
                .map_err(|e| format!("trailers: {e}"))
        }
        Ok(None) => send.finish().await.map_err(|e| format!("finish: {e}")),
        Err(e) => Err(format!("trailers: {e}")),
    }
}

/// The h3 response headers as the HTTP/1.1 head the shared editing helpers
/// read: status line, one line per header, blank line.
fn serialize_response_head(status: StatusCode, headers: &HeaderMap) -> Vec<u8> {
    let mut wire = Vec::with_capacity(256);
    wire.extend_from_slice(
        format!(
            "HTTP/1.1 {} {}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("")
        )
        .as_bytes(),
    );
    for (name, value) in headers {
        wire.extend_from_slice(name.as_str().as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    wire
}

/// Applies the response-header side of a request's plan to a wire head:
/// `$removeheader`, `$csp`/`$permissions`, the `$cookie` names the answer may
/// not set, and the stealth switch that drops every `set-cookie`.
fn apply_response_plan(wire: &mut Vec<u8>, plan: &RequestPlan, host: &str) {
    if let Some(edit) = &plan.headers {
        let done = crate::mitm::http::apply_response_headers(
            wire,
            &edit.remove_response,
            &edit.csp,
            &edit.permissions,
        );
        if !done.dropped.is_empty() {
            crate::logbuf::push(&format!(
                "quic {host}: response headers dropped: {} by {} rule(s)",
                done.dropped.join(", "),
                edit.rules.len(),
            ));
        }
        if !done.added.is_empty() {
            crate::logbuf::push(&format!(
                "quic {host}: response gained {} by {} rule(s)",
                done.added.join(", "),
                edit.rules.len(),
            ));
        }
    }
    if let Some(cookie_plan) = &plan.cookies {
        let names = crate::mitm::http::set_cookie_names(wire);
        if let Some(edit) = cookie_plan.dropped(&names) {
            if let Some((fixed, dropped)) =
                crate::mitm::http::drop_set_cookie_headers(wire, &edit.drop)
            {
                *wire = fixed;
                crate::logbuf::push(&format!(
                    "quic {host}: set-cookie dropped: {} by {} rule(s)",
                    dropped.join(", "),
                    edit.rules.len(),
                ));
            }
        }
    }
    if plan.block_cookies {
        if let Some(fixed) = crate::mitm::http::drop_headers(wire, &["set-cookie".to_string()]) {
            *wire = fixed;
            crate::logbuf::push_debug(&format!("quic {host}: third-party set-cookie dropped"));
        }
    }
    if plan.drop_etag {
        if let Some(fixed) = crate::mitm::http::drop_headers(wire, &["etag".to_string()]) {
            *wire = fixed;
            crate::logbuf::push_debug(&format!("quic {host}: etag dropped"));
        }
    }
}

/// Answers with an HTTP/1.1 message a rule produced.
async fn reply_http1(send: &mut ServerSend, response: &[u8]) -> Result<(), String> {
    let Some((status, headers, body)) = parse_http1_response(response) else {
        return reply_status(send, StatusCode::INTERNAL_SERVER_ERROR).await;
    };
    let mut out = HttpResponse::builder()
        .status(status)
        .body(())
        .map_err(|e| format!("local response: {e}"))?;
    *out.headers_mut() = headers;
    send.send_response(out)
        .await
        .map_err(|e| format!("local response: {e}"))?;
    if !body.is_empty() {
        send.send_data(body)
            .await
            .map_err(|e| format!("local body: {e}"))?;
    }
    send.finish()
        .await
        .map_err(|e| format!("local finish: {e}"))
}

/// An empty answer with just a status.
async fn reply_status(send: &mut ServerSend, status: StatusCode) -> Result<(), String> {
    let mut out = HttpResponse::builder()
        .status(status)
        .body(())
        .map_err(|e| format!("reply: {e}"))?;
    out.headers_mut()
        .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    send.send_response(out)
        .await
        .map_err(|e| format!("reply: {e}"))?;
    send.finish()
        .await
        .map_err(|e| format!("reply finish: {e}"))
}

/// Splits a local HTTP/1.1 answer into the parts an h3 response needs.
fn parse_http1_response(raw: &[u8]) -> Option<(StatusCode, HeaderMap, Bytes)> {
    let end = crate::mitm::http::head_end(raw)?;
    let text = std::str::from_utf8(&raw[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse::<u16>().ok()?;
    let status = StatusCode::from_u16(status).ok()?;
    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if HOP_BY_HOP.contains(&name.to_ascii_lowercase().as_str()) {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(value.trim()) else {
            continue;
        };
        headers.append(name, value);
    }
    Some((status, headers, Bytes::copy_from_slice(&raw[end..])))
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::ca::CertificateAuthority;
    use crate::mitm::proxy::{content_hash, local_asset, versioned_path};
    use crate::mitm::quic::socket::{Datagram, OutDatagram, TunUdpSocket};
    use crate::mitm::tls::{self, SniCertResolver, UpstreamTls};
    use quinn::{Endpoint, EndpointConfig, TokioRuntime};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
    use std::time::Duration;

    const SERVER_ADDR: &str = "127.0.0.1:4433";
    const CLIENT_ADDR: &str = "127.0.0.1:5555";
    const CHANNEL: usize = 4096;

    fn engine_with(tag: &str, rules: &str) -> Arc<FilterEngine> {
        let dir = std::env::temp_dir().join("adfree-quic-hub-tests");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(format!("{tag}-list.txt"));
        std::fs::write(&path, rules).expect("write list");
        let engine = Arc::new(FilterEngine::new());
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
                dns_only: false,
            }],
            &[],
        );
        engine
    }

    fn endpoint_socket(local: SocketAddr) -> (Arc<TunUdpSocket>, Receiver<OutDatagram>) {
        let (tx, rx): (SyncSender<OutDatagram>, Receiver<OutDatagram>) = sync_channel(CHANNEL);
        (TunUdpSocket::new(local, tx), rx)
    }

    fn pump(to: Arc<TunUdpSocket>, rx: Receiver<OutDatagram>) {
        std::thread::spawn(move || {
            while let Ok(out) = rx.recv() {
                let dst_ip = Some(to.local().ip());
                to.recv(Datagram {
                    peer: out.source,
                    dst_ip,
                    payload: out.payload,
                });
            }
        });
    }

    /// What the test origin answers with.
    #[derive(Clone, Default)]
    struct OriginAnswer {
        /// `text/plain` when nothing else is asked for.
        content_type: Option<&'static str>,
        /// `None` keeps the echo body (`METHOD URI`).
        body: Option<&'static str>,
        headers: Vec<(&'static str, &'static str)>,
    }

    /// An h3 origin on a real loopback socket, echoing what reached it.
    ///
    /// The response body is `METHOD URI`, and the `x-keep`/`cookie` headers
    /// come back as `x-echo-keep`/`x-echo-cookie` — the assertions read the
    /// request the origin actually received, not just the client's view.
    fn spawn_origin_with(answer: OriginAnswer) -> (Endpoint, SocketAddr, rustls::RootCertStore) {
        let generated = rcgen::generate_simple_self_signed(vec!["filtered.test".to_string()])
            .expect("self-signed certificate");
        let cert = CertificateDer::from(generated.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("origin tls");
        tls.alpn_protocols = vec![tls::ALPN_H3.to_vec()];
        let config = quinn_server_config(Arc::new(tls)).expect("origin quic");
        let endpoint =
            Endpoint::server(config, "127.0.0.1:0".parse().expect("origin addr")).expect("origin");
        let addr = endpoint.local_addr().expect("origin addr");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).expect("origin trust anchor");

        let answer = Arc::new(answer);
        let accept = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accept.accept().await {
                let answer = Arc::clone(&answer);
                tokio::spawn(async move {
                    let answer = Arc::clone(&answer);
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(_) => return,
                    };
                    let mut server =
                        match h3::server::Connection::new(h3_quinn::Connection::new(connection))
                            .await
                        {
                            Ok(server) => server,
                            Err(_) => return,
                        };
                    while let Ok(Some(resolver)) = server.accept().await {
                        let answer = Arc::clone(&answer);
                        tokio::spawn(async move {
                            let Ok((request, stream)) = resolver.resolve_request().await else {
                                return;
                            };
                            let (mut send, mut recv) = stream.split();
                            while let Ok(Some(_)) = recv.recv_data().await {}
                            let mut response = http::Response::builder()
                                .status(200)
                                .header("content-type", answer.content_type.unwrap_or("text/plain"))
                                .body(())
                                .expect("origin response");
                            for (name, value) in &answer.headers {
                                let name = HeaderName::from_bytes(name.as_bytes())
                                    .expect("origin header name");
                                let value =
                                    HeaderValue::from_str(value).expect("origin header value");
                                response.headers_mut().append(name, value);
                            }
                            for header in ["x-keep", "x-remove", "cookie"] {
                                if let Some(value) = request.headers().get(header) {
                                    let echo = HeaderName::from_bytes(
                                        format!(
                                            "x-echo-{}",
                                            header.strip_prefix("x-").unwrap_or(header)
                                        )
                                        .as_bytes(),
                                    )
                                    .expect("echo name");
                                    response.headers_mut().insert(echo, value.clone());
                                }
                            }
                            let _ = send.send_response(response).await;
                            let body = match answer.body {
                                Some(body) => body.to_string(),
                                None => format!("{} {}", request.method(), request.uri()),
                            };
                            let _ = send.send_data(Bytes::from(body)).await;
                            let _ = send.finish().await;
                        });
                    }
                });
            }
        });
        (endpoint, addr, roots)
    }

    /// One client-side h3 exchange through an in-memory endpoint pair.
    async fn exchange(
        rules: &str,
        tag: &str,
        local: bool,
        script_body: &str,
        request: HttpRequest<()>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        exchange_with(
            OriginAnswer::default(),
            rules,
            tag,
            local,
            script_body,
            request,
        )
        .await
    }

    async fn exchange_with(
        answer: OriginAnswer,
        rules: &str,
        tag: &str,
        local: bool,
        script_body: &str,
        request: HttpRequest<()>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let serve_path = "/adfree-user.js";
        let (origin, origin_addr, roots) = spawn_origin_with(answer);
        let ca = Arc::new(CertificateAuthority::generate().expect("ca"));
        let resolver = Arc::new(SniCertResolver::new(Arc::clone(&ca)));
        let server_tls = tls::server_config_h3(resolver);
        let server_config = quinn_server_config(server_tls).expect("mitm quic server");

        let (server_socket, server_rx) = endpoint_socket(SERVER_ADDR.parse().unwrap());
        let (client_socket, client_rx) = endpoint_socket(CLIENT_ADDR.parse().unwrap());
        pump(Arc::clone(&client_socket), server_rx);
        pump(Arc::clone(&server_socket), client_rx);

        let runtime = Arc::new(TokioRuntime);
        let server_endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            server_socket,
            runtime.clone(),
        )
        .expect("mitm endpoint");
        let client_endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            client_socket,
            runtime,
        )
        .expect("client endpoint");

        let filter = engine_with(tag, rules);
        let config = Arc::new(HubConfig {
            filter: Arc::clone(&filter),
            apps: Vec::new(),
            server_name: "filtered.test".to_string(),
            origin: origin_addr,
            local,
            serve_path: serve_path.to_string(),
            script_body: Arc::from(script_body),
            script_tag_src: local_asset(&versioned_path(
                serve_path,
                content_hash(script_body.as_bytes()),
            )),
            cosmetic: Some(filter),
            stealth: StealthConfig::default(),
            upstream: UpstreamTls::with_roots(roots),
            endpoint: origin.clone(),
            sink: None,
        });
        tokio::spawn(async move {
            if let Some(incoming) = server_endpoint.accept().await {
                if let Ok(connection) = incoming.await {
                    serve_connection(connection, config).await;
                }
            }
        });

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.cert_der()))
            .expect("app trust anchor");
        let client = quinn_client_config(tls::client_config_h3_with(roots)).expect("client quic");
        let connecting = client_endpoint
            .connect_with(
                client,
                SERVER_ADDR.parse().expect("server addr"),
                "filtered.test",
            )
            .expect("connect");
        let connection = tokio::time::timeout(Duration::from_secs(5), connecting)
            .await
            .expect("handshake timeout")
            .expect("handshake");
        let (mut h3_conn, mut sender) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .expect("h3 client");
        tokio::spawn(async move {
            let _ = h3_conn.wait_idle().await;
        });

        let mut stream = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
            .await
            .expect("request timeout")
            .expect("send request");
        stream.finish().await.expect("finish request");
        let response = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
            .await
            .expect("response timeout")
            .expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.recv_data()).await {
                Ok(Ok(Some(mut chunk))) => {
                    body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()))
                }
                Ok(Ok(None)) => break,
                Ok(Err(e)) => panic!("body failed: {e}"),
                Err(_) => panic!("body timeout"),
            }
        }
        (status, headers, body)
    }

    fn get(uri: &str) -> HttpRequest<()> {
        HttpRequest::builder()
            .method("GET")
            .uri(uri)
            // What a browser sends for a subresource; the engine keys the
            // request type off it.
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-site", "same-origin")
            .header("x-keep", "yes")
            .header("x-remove", "secret")
            .header("cookie", "tracker=1; session=2")
            .body(())
            .expect("request")
    }

    fn run(future: impl std::future::Future<Output = ()>) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            tokio::time::timeout(Duration::from_secs(20), future)
                .await
                .expect("test timeout")
        });
    }

    #[test]
    fn forwards_and_applies_url_level_edits() {
        run(async {
            // The removal names the request kind: without a type option the
            // modifier only covers documents and frames, and this request is a
            // subresource (the same spelling the HTTP/1 e2e suite uses).
            let rules = "\
||filtered.test/page$removeparam=utm_source,xmlhttprequest
||filtered.test^$removeheader=request:x-remove
||filtered.test^$cookie=tracker
";
            let (status, headers, body) = exchange(
                rules,
                "edits",
                false,
                "",
                get("https://filtered.test/page?utm_source=news&keep=1"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                std::str::from_utf8(&body).expect("utf8"),
                "GET https://filtered.test/page?keep=1"
            );
            assert_eq!(
                headers
                    .get("x-echo-keep")
                    .expect("kept header")
                    .to_str()
                    .expect("header text"),
                "yes"
            );
            assert!(
                headers.get("x-echo-remove").is_none(),
                "$removeheader took the request header out"
            );
            let cookie = headers.get("x-echo-cookie").expect("cookie echoed");
            let cookie = cookie.to_str().expect("cookie text");
            assert!(!cookie.contains("tracker"), "cookie stayed: {cookie}");
            assert!(cookie.contains("session=2"), "cookie lost: {cookie}");
        });
    }

    /// The injection the HTTP/1.1 splice performs, over QUIC: the snippet goes
    /// into the document, and the policy the origin wrote learns its nonce so
    /// a strict `script-src` does not drop it.
    #[test]
    fn injects_the_snippet_and_teaches_the_policy_the_nonce() {
        run(async {
            let answer = OriginAnswer {
                content_type: Some("text/html; charset=utf-8"),
                body: Some("<html><head><title>t</title></head><body>hi</body></html>"),
                headers: vec![("content-security-policy", "script-src 'self'")],
            };
            let (status, headers, body) = exchange_with(
                answer,
                "",
                "inject",
                false,
                "",
                get("https://filtered.test/page"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let body = std::str::from_utf8(&body).expect("utf8");
            assert!(
                body.starts_with("<html><head>"),
                "the snippet must land inside the head: {body}"
            );
            assert!(
                body.contains("adfree-page.js?dmn=filtered.test"),
                "the runtime tag must be injected: {body}"
            );
            let nonce = body
                .split("nonce=\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .expect("the injected tag carries a nonce");
            let policy = headers
                .get("content-security-policy")
                .expect("the policy survives")
                .to_str()
                .expect("policy text");
            assert!(
                policy.contains(&format!("'nonce-{nonce}'")),
                "the policy must learn the tag's nonce: {policy}"
            );
            let length: usize = headers
                .get("content-length")
                .expect("the edited body declares its length")
                .to_str()
                .expect("length text")
                .parse()
                .expect("a number");
            assert_eq!(length, body.len(), "the length must follow the edit");
        });
    }

    /// The response-body and response-header modifiers, over QUIC.
    #[test]
    fn rewrites_the_response_body_and_headers() {
        run(async {
            let answer = OriginAnswer {
                content_type: Some("text/javascript"),
                body: Some("var secret = 1;"),
                headers: vec![("x-internal", "trace")],
            };
            let rules = "\
||filtered.test/page$replace=/secret/redacted/
||filtered.test^$removeheader=x-internal
||filtered.test^$csp=script-src 'self'
";
            let (status, headers, body) = exchange_with(
                answer,
                rules,
                "response-edits",
                false,
                "",
                get("https://filtered.test/page"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                std::str::from_utf8(&body).expect("utf8"),
                "var redacted = 1;",
                "$replace must rewrite the body"
            );
            assert!(
                headers.get("x-internal").is_none(),
                "$removeheader must take the response header out"
            );
            assert_eq!(
                headers
                    .get("content-security-policy")
                    .expect("$csp adds the policy")
                    .to_str()
                    .expect("policy text"),
                "script-src 'self'"
            );
            let length: usize = headers
                .get("content-length")
                .expect("the edited body declares its length")
                .to_str()
                .expect("length text")
                .parse()
                .expect("a number");
            assert_eq!(length, body.len());
        });
    }

    #[test]
    fn blocked_host_never_reaches_the_origin() {
        run(async {
            let (status, _, body) = exchange(
                "||blocked.test^\n",
                "blocked",
                false,
                "",
                get("https://blocked.test/ad.js"),
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT);
            assert!(body.is_empty(), "a blocked answer carries no body");
        });
    }

    #[test]
    fn local_origin_serves_the_user_script() {
        run(async {
            let (status, headers, body) = exchange(
                "",
                "local",
                true,
                "console.log('adfree');",
                HttpRequest::builder()
                    .method("GET")
                    .uri("https://192.0.2.1/adfree-user.js")
                    .body(())
                    .expect("request"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                headers
                    .get("content-type")
                    .expect("content type")
                    .to_str()
                    .expect("header text"),
                "application/javascript; charset=utf-8"
            );
            assert_eq!(
                String::from_utf8(body).expect("utf8"),
                "console.log('adfree');"
            );
        });
    }

    #[test]
    fn local_origin_answers_unknown_paths_with_404() {
        run(async {
            let (status, _, body) = exchange(
                "",
                "local404",
                true,
                "let x = 1;",
                HttpRequest::builder()
                    .method("GET")
                    .uri("https://192.0.2.1/probe")
                    .body(())
                    .expect("request"),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert_eq!(String::from_utf8(body).expect("utf8"), "not found");
        });
    }
}
