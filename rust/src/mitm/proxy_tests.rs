//! Round-trip tests of the splice.
//!
//! `tls_tests.rs` already covers the handshake and both directions of a TLS
//! conversation end to end. These tests therefore focus on what this module adds
//! on top of TLS: the response rewriter that injects scripts into HTML.

use super::proxy::{
    blocked_response, closing_response, content_hash, local_asset, origin_form, redirect_response,
    rebuilt_head, request_facts, request_url, rewritable, swallow_body, take_local_request,
    ClientDiscard, ProxySession, RequestBody, HIDE_PATH,
};
use super::*;
use crate::mitm::ca::CertificateAuthority;
use crate::mitm::tls::{open_session, SniCertResolver};
use std::io::{Read, Write};
use std::sync::Arc;

/// A nonce of the length the injector writes: 18 random bytes in hex.
///
/// The value differs per response, the length never does, so byte-count
/// assertions can lean on this one and text assertions read the real nonce out
/// of the response with [`nonce_in`].
const TEST_NONCE: &str = "0123456789abcdef0123456789abcdef0123";

/// The URL the injector gives the user script, hash and all.
///
/// The session `build_proxy` makes has an empty script body, so the tag's URL
/// carries the hash of nothing; the hash itself is what keeps the browser from
/// re-fetching the script on every page.
fn user_tag_src() -> String {
    format!(
        "{}?h={:016x}",
        local_asset("/adfree-user.js"),
        content_hash(b"")
    )
}

/// The tag the injector emits for the user script, for a given nonce.
fn expected_tag(nonce: &str) -> String {
    crate::mitm::http::script_tag(&user_tag_src(), true, nonce)
}

/// The nonce an injected tag carries, read out of the response itself.
fn nonce_in(text: &str) -> String {
    let at = text
        .find(" nonce=\"")
        .expect("an injected tag carries a nonce")
        + " nonce=\"".len();
    let rest = &text[at..];
    rest[..rest.find('"').expect("the nonce is quoted")].to_string()
}

/// Whether `text` holds the user-script tag with the nonce that same response
/// issued: the two travel together, so both ends are checked at once.
fn has_user_tag(text: &str) -> bool {
    text.contains(&expected_tag(&nonce_in(text)))
}

/// A filter engine built from a list written to disk, exactly like the app
/// ships them.
fn engine_with(tag: &str, rules: &str) -> Arc<crate::filter::FilterEngine> {
    let dir = std::env::temp_dir().join("adfree-proxy-tests");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(format!("{tag}-list.txt"));
    std::fs::write(&path, rules).expect("write list");
    let engine = Arc::new(crate::filter::FilterEngine::new());
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
    engine
}

/// The content hash a locally served URL advertises.
fn href_hash(href: &str) -> u64 {
    let value = href.split("h=").nth(1).expect("the URL carries a hash");
    u64::from_str_radix(value, 16).expect("the hash is hexadecimal")
}

/// Splits a locally served response into its head and body.
fn split_local(response: &[u8]) -> (String, Vec<u8>) {
    let split = http::head_end(response).expect("the head is complete");
    (
        String::from_utf8(response[..split].to_vec()).expect("utf8"),
        response[split..].to_vec(),
    )
}

fn build_proxy(ca: &CertificateAuthority, script: &str) -> ProxySession {
    let resolver = Arc::new(SniCertResolver::new(Arc::new(
        CertificateAuthority::from_pem(&ca.cert_pem(), &ca.key_pem()).expect("restore"),
    )));
    let session = open_session(&resolver, "origin.example.com").expect("session");
    ProxySession::new(session, script.to_string(), Arc::from(""))
}

/// Answers the injected tag's request locally: the client asks the origin for
/// the script path, and the response must come from us, not the server.
#[test]
fn script_request_is_answered_locally() {
    let mut buffer = b"GET /adfree-user.js HTTP/1.1\r\nHost: origin.example.com\r\n\r\n".to_vec();
    let response =
        take_local_request("/adfree-user.js", "let x = 1;", None, None, &mut buffer).expect("served");
    assert!(buffer.is_empty(), "the request is consumed");
    let text = String::from_utf8(response).expect("utf8");
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text.contains("Content-Type: application/javascript"));
    assert!(text.contains("Content-Length: 10\r\n"));
    assert!(text.ends_with("let x = 1;"));
}

#[test]
fn script_request_ignores_other_requests() {
    let mut buffer = b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    assert!(take_local_request("/adfree-user.js", "let x = 1;", None, None, &mut buffer).is_none());
    assert!(!buffer.is_empty(), "untouched");
}

#[test]
fn script_request_waits_for_the_full_head() {
    let mut buffer = b"GET /adfree-user.js HTTP/1.1\r\nHost: x\r\n".to_vec();
    assert!(take_local_request("/adfree-user.js", "let x = 1;", None, None, &mut buffer).is_none());
    buffer.extend_from_slice(b"\r\n");
    assert!(take_local_request("/adfree-user.js", "let x = 1;", None, None, &mut buffer).is_some());
}

#[test]
fn script_request_serves_only_when_enabled() {
    let mut buffer = b"GET /adfree-user.js HTTP/1.1\r\n\r\n".to_vec();
    assert!(take_local_request("/adfree-user.js", "", None, None, &mut buffer).is_none());
    assert!(!buffer.is_empty());
}

/// A minimal HTML response whose declared length matches its real body.
fn html_response(body: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ");
    v.extend_from_slice(body.len().to_string().as_bytes());
    v.extend_from_slice(b"\r\n\r\n");
    v.extend_from_slice(body.as_bytes());
    v
}

#[test]
fn injects_into_html_and_fixes_content_length() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    // A partial head must be buffered, not flushed.
    let (out, injected) = proxy.rewrite_response(b"HTTP/1.1 200 OK\r\nContent-Ty");
    assert!(out.is_empty(), "a partial head must be buffered");
    assert_eq!(injected, 0);

    let body = "<html><head></head><body>ad</body></html>";
    let (out, injected) = proxy.rewrite_response(&html_response(body));
    assert_eq!(injected, expected_tag(TEST_NONCE).len(), "the whole tag is added");

    let text = String::from_utf8(out).expect("utf8");
    let new_len = body.len() + expected_tag(TEST_NONCE).len();
    assert!(
        text.contains(&format!("Content-Length: {new_len}")),
        "length rewritten to {new_len}: {text}"
    );
    assert!(has_user_tag(&text));
}

#[test]
fn response_split_across_reads_is_reassembled() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let body = "<html><head></head><body>x</body></html>";
    let full = html_response(body);
    let head = &full[..full.len() - body.len()];

    // Chunk 1: everything but the body.
    let (out, injected) = proxy.rewrite_response(head);
    assert!(out.is_empty(), "head only: wait for the body");
    assert_eq!(injected, 0);

    // Chunk 2: the body.
    let (out, injected) = proxy.rewrite_response(body.as_bytes());
    assert_eq!(injected, expected_tag(TEST_NONCE).len());

    let text = String::from_utf8(out).expect("utf8");
    let new_len = body.len() + expected_tag(TEST_NONCE).len();
    assert!(text.contains(&format!("Content-Length: {new_len}")), "{text}");
    assert!(has_user_tag(&text));
}

#[test]
fn gzip_responses_are_decoded_rewritten_and_recompressed() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let body = "<html><head></head><body>ad</body></html>";
    let gz = http::gzip_encode(body.as_bytes()).expect("gzip");
    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: ");
    response.extend_from_slice(gz.len().to_string().as_bytes());
    response.extend_from_slice(b"\r\n\r\n");
    response.extend_from_slice(&gz);

    let (out, injected) = proxy.rewrite_response(&response);
    assert_eq!(injected, expected_tag(TEST_NONCE).len(), "the tag is added to the page");

    let split = http::head_end(&out).expect("head");
    let head = String::from_utf8(out[..split].to_vec()).expect("utf8");
    assert!(head.contains("Content-Encoding: gzip\r\n"), "{head}");
    // The body stays compressed, and decodes back to the injected HTML.
    let plain = http::decode_body(&out[split..], http::Encoding::Gzip).expect("decoded");
    let decoded = String::from_utf8(plain).expect("utf8");
    assert!(has_user_tag(&decoded), "{decoded}");
    assert_eq!(
        http::parse_response_head(&out[..split]).content_length,
        Some(out.len() - split)
    );
}
#[test]
fn undecodable_bodies_pass_through() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    // Not gzip at all, despite the header: nothing about it is ours to touch.
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 12\r\n\r\n\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x00\x00";
    let (out, injected) = proxy.rewrite_response(response);
    assert_eq!(injected, 0, "an undecodable body must not be rewritten");
    assert_eq!(out, response);

    // brotli/zstd are readable by the client but not by us.
    let br = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: br\r\nContent-Length: 3\r\n\r\nabc";
    let (out, injected) = proxy.rewrite_response(br);
    assert_eq!(injected, 0);
    assert_eq!(out, br);
}

#[test]
fn chunked_responses_become_identity_with_a_length() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let body = "<html><head></head><body>ad</body></html>";
    let mut response = Vec::new();
    response.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    response.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
    response.extend_from_slice(body.as_bytes());
    response.extend_from_slice(b"\r\n0\r\n\r\n");

    let (out, injected) = proxy.rewrite_response(&response);
    assert_eq!(injected, expected_tag(TEST_NONCE).len());

    let text = String::from_utf8(out.clone()).expect("utf8");
    assert!(!text.contains("Transfer-Encoding"), "{text}");
    let split = http::head_end(&out).expect("head");
    let new_len = body.len() + expected_tag(TEST_NONCE).len();
    assert_eq!(
        http::parse_response_head(&out[..split]).content_length,
        Some(new_len)
    );
    assert_eq!(out.len() - split, new_len, "the body is not chunked anymore");
    assert!(has_user_tag(std::str::from_utf8(&out[split..]).expect("utf8")));
}

/// The regression this stage exists for: a body that arrives in several reads
/// must not get a `content-length` computed from a prefix of itself.
#[test]
fn multi_read_bodies_get_the_full_length() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    // Below the streaming threshold: held whole, so the length stays exact.
    let filler = "x".repeat(20 * 1024);
    let body = format!("<html><head></head><body>{filler}</body></html>");
    let response = html_response(&body);

    // Dribble it in, exactly how the packet path would hand it over.
    let mut out = Vec::new();
    let mut injected = 0;
    for chunk in response.chunks(1024) {
        let (part, count) = proxy.rewrite_response(chunk);
        out.extend_from_slice(&part);
        injected += count;
    }
    assert_eq!(injected, expected_tag(TEST_NONCE).len());

    let split = http::head_end(&out).expect("head");
    let declared = http::parse_response_head(&out[..split])
        .content_length
        .expect("content-length");
    assert_eq!(declared, out.len() - split, "the declared length is the real one");
    let text = String::from_utf8(out[split..].to_vec()).expect("utf8");
    assert!(has_user_tag(&text));
    assert!(text.ends_with("</body></html>"), "the body must be complete");
}

#[test]
fn several_responses_on_one_connection_are_each_rewritten() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    // Two keep-alive responses in one read.
    let mut response = html_response("<html><head></head><body>one</body></html>");
    response.extend_from_slice(&html_response(
        "<html><head></head><body>two</body></html>",
    ));
    let (out, injected) = proxy.rewrite_response(&response);
    assert_eq!(injected, expected_tag(TEST_NONCE).len() * 2, "both bodies got a tag");

    let text = String::from_utf8(out).expect("utf8");
    assert_eq!(text.matches(&user_tag_src()).count(), 2);
    assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 2);
}

#[test]
fn bodyless_responses_do_not_hold_the_connection() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    // A 304 advertises a length but never sends a body; the next response must
    // still be found.
    let mut response = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 4242\r\n\r\n".to_vec();
    response.extend_from_slice(&html_response(
        "<html><head></head><body>after</body></html>",
    ));
    let (out, injected) = proxy.rewrite_response(&response);
    assert_eq!(injected, expected_tag(TEST_NONCE).len());
    let text = String::from_utf8(out).expect("utf8");
    assert!(text.contains("304 Not Modified"));
    assert!(has_user_tag(&text));
}

#[test]
fn json_responses_pass_through_byte_for_byte() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
    let (out, injected) = proxy.rewrite_response(response);
    assert_eq!(injected, 0, "JSON must not be touched");
    assert_eq!(out, response, "the body must arrive unchanged");
}

#[test]
fn empty_script_url_disables_the_rewriter() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "");

    let body = "<html><head></head></html>";
    let (out, injected) = proxy.rewrite_response(&html_response(body));
    assert_eq!(injected, 0);
    assert_eq!(out, html_response(body));
}

#[test]
fn oversized_bodies_are_flushed_unchanged() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
    response.extend(std::iter::repeat_n(b'a', http::MAX_INJECTABLE_BODY + 64));
    let (out, injected) = proxy.rewrite_response(&response);
    assert_eq!(injected, 0);
    assert_eq!(out.len(), response.len(), "must flush unchanged");
}

/// Feeds wire bytes into a browser connection and collects its plaintext.
pub(crate) fn feed_browser(browser: &mut rustls::ClientConnection, wire: &[u8], out: &mut Vec<u8>) {
    let mut cursor = std::io::Cursor::new(wire);
    loop {
        match browser.read_tls(&mut cursor) {
            Ok(0) => break,
            Ok(_) => {
                browser.process_new_packets().expect("browser packets");
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                // Same backpressure signal the production feed handles: rustls
                // pauses once its 16 KiB plaintext buffer fills, so drain and
                // retry instead of giving up.
                let before = out.len();
                let mut buf = [0u8; 4096];
                while let Ok(n) = browser.reader().read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                if out.len() == before || e.kind() != std::io::ErrorKind::Other {
                    break;
                }
                continue;
            }
        }
        let mut buf = [0u8; 4096];
        while let Ok(n) = browser.reader().read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
}

/// Feeds wire bytes into the origin server and collects what it decrypted.
pub(crate) fn feed_origin(server: &mut rustls::ServerConnection, wire: &[u8], out: &mut Vec<u8>) {
    let mut cursor = std::io::Cursor::new(wire);
    loop {
        match server.read_tls(&mut cursor) {
            Ok(0) => break,
            Ok(_) => {
                server.process_new_packets().expect("origin packets");
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                let before = out.len();
                let mut buf = [0u8; 4096];
                while let Ok(n) = server.reader().read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                if out.len() == before || e.kind() != std::io::ErrorKind::Other {
                    break;
                }
                continue;
            }
        }
        let mut buf = [0u8; 4096];
        while let Ok(n) = server.reader().read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
}

/// The full splice, driven like the device drives it: a fake browser on one
/// side, a rustls origin on the other, and only wire bytes in between.
///
/// This is the test that catches the classic MITM deadlock: the client's
/// handshake finishes and its request arrives while the upstream half has not
/// even sent its ClientHello. If the splice does not drain the upstream
/// connection, the request is dropped and the page hangs forever.
#[test]
fn a_request_and_its_response_cross_the_splice() {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};

    // The origin's CA: what a real certificate chains to.
    let origin_ca = CertificateAuthority::generate().expect("origin ca");
    let mut origin_roots = rustls::RootCertStore::empty();
    origin_roots
        .add(rustls::pki_types::CertificateDer::from(origin_ca.cert_der()))
        .expect("origin root");
    let upstream_config = tls::client_config_with(origin_roots);

    // The CA the fake browser trusts: the one we present to it.
    let mitm_ca = CertificateAuthority::generate().expect("mitm ca");
    let resolver = Arc::new(SniCertResolver::new(Arc::new(
        CertificateAuthority::from_pem(&mitm_ca.cert_pem(), &mitm_ca.key_pem()).expect("restore"),
    )));
    let session =
        tls::open_session_with(&resolver, "origin.example.com", upstream_config).expect("session");
    let mut proxy = ProxySession::new(session, String::new(), Arc::from(""));

    // The origin, minting leaves from its own CA.
    let origin_resolver = Arc::new(SniCertResolver::new(Arc::new(origin_ca)));
    let mut origin = ServerConnection::new(tls::server_config(origin_resolver)).expect("origin");

    // The fake browser.
    let mut browser_roots = rustls::RootCertStore::empty();
    browser_roots
        .add(rustls::pki_types::CertificateDer::from(mitm_ca.cert_der()))
        .expect("browser root");
    let name = ServerName::try_from("origin.example.com".to_string()).expect("server name");
    let mut browser =
        ClientConnection::new(tls::client_config_with(browser_roots), name).expect("browser");

    let request = b"GET / HTTP/1.1\r\nHost: origin.example.com\r\n\r\n";
    let response_body = b"<html><head></head><body>hi</body></html>";
    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ");
    response.extend_from_slice(response_body.len().to_string().as_bytes());
    response.extend_from_slice(b"\r\n\r\n");
    response.extend_from_slice(response_body);
    browser
        .writer()
        .write_all(request)
        .expect("browser writes the request");

    let mut to_origin: Vec<u8> = Vec::new();
    let mut origin_request: Vec<u8> = Vec::new();
    let mut origin_answered = false;
    let mut browser_plain: Vec<u8> = Vec::new();

    for _round in 0..64 {
        // browser -> proxy -> origin
        let wire = tls::take_client_outbound(&mut browser);
        if !wire.is_empty() {
            let out = proxy.on_client_payload(&wire).expect("proxy client step");
            to_origin.extend_from_slice(&out.to_peer);
            feed_browser(&mut browser, &out.to_client, &mut browser_plain);
        }
        if !to_origin.is_empty() {
            feed_origin(&mut origin, &to_origin, &mut origin_request);
            to_origin.clear();
            if !origin_answered && !origin_request.is_empty() {
                origin
                    .writer()
                    .write_all(&response)
                    .expect("origin writes the response");
                origin_answered = true;
            }
        }
        // origin -> proxy -> browser
        let wire = tls::take_server_outbound(&mut origin);
        if !wire.is_empty() {
            let out = proxy.on_peer_payload(&wire).expect("proxy peer step");
            to_origin.extend_from_slice(&out.to_peer);
            feed_browser(&mut browser, &out.to_client, &mut browser_plain);
        }
        if browser_plain.windows(12).any(|w| w == b"HTTP/1.1 200") {
            break;
        }
    }

    assert_eq!(
        origin_request, request,
        "the origin must receive the request byte for byte"
    );
    assert!(
        browser_plain.starts_with(b"HTTP/1.1 200 OK"),
        "the browser must receive the response: {:?}",
        String::from_utf8_lossy(&browser_plain)
    );
    assert!(
        browser_plain.ends_with(response_body),
        "the body must survive the splice"
    );
}

/// The engine's actual path: the relay is armed before the flow's hostname is
/// known, and the session opens from the ClientHello itself — the DNS table
/// is not consulted (a browser's own cache, DoH or a shared CDN address can
/// put the flow on an address we never learned).
#[test]
fn a_pending_session_opens_from_the_client_hello() {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};

    let origin_ca = CertificateAuthority::generate().expect("origin ca");
    let mut origin_roots = rustls::RootCertStore::empty();
    origin_roots
        .add(rustls::pki_types::CertificateDer::from(origin_ca.cert_der()))
        .expect("origin root");
    let upstream_config = tls::client_config_with(origin_roots);

    let mitm_ca = CertificateAuthority::generate().expect("mitm ca");
    let resolver = Arc::new(SniCertResolver::new(Arc::new(
        CertificateAuthority::from_pem(&mitm_ca.cert_pem(), &mitm_ca.key_pem()).expect("restore"),
    )));
    let mut proxy =
        ProxySession::new_pending(resolver, upstream_config, "/adfree-user.js".into(), Arc::from(""))
            .expect("pending session");
    assert_eq!(proxy.captured_sni(), None, "no hostname before the hello");

    let origin_resolver = Arc::new(SniCertResolver::new(Arc::new(origin_ca)));
    let mut origin = ServerConnection::new(tls::server_config(origin_resolver)).expect("origin");

    let mut browser_roots = rustls::RootCertStore::empty();
    browser_roots
        .add(rustls::pki_types::CertificateDer::from(mitm_ca.cert_der()))
        .expect("browser root");
    let name = ServerName::try_from("origin.example.com".to_string()).expect("server name");
    let mut browser =
        ClientConnection::new(tls::client_config_with(browser_roots), name).expect("browser");

    let request = b"GET / HTTP/1.1\r\nHost: origin.example.com\r\n\r\n";
    let body = "<html><head></head><body>hi</body></html>";
    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ");
    response.extend_from_slice(body.len().to_string().as_bytes());
    response.extend_from_slice(b"\r\n\r\n");
    response.extend_from_slice(body.as_bytes());
    browser
        .writer()
        .write_all(request)
        .expect("browser writes the request");

    let mut to_origin: Vec<u8> = Vec::new();
    let mut origin_request: Vec<u8> = Vec::new();
    let mut browser_plain: Vec<u8> = Vec::new();
    let mut origin_answered = false;

    for _round in 0..64 {
        // browser -> proxy -> origin
        let wire = tls::take_client_outbound(&mut browser);
        if !wire.is_empty() {
            let out = proxy.on_client_payload(&wire).expect("proxy client step");
            to_origin.extend_from_slice(&out.to_peer);
            feed_browser(&mut browser, &out.to_client, &mut browser_plain);
        }
        if !to_origin.is_empty() {
            feed_origin(&mut origin, &to_origin, &mut origin_request);
            to_origin.clear();
            if !origin_answered && !origin_request.is_empty() {
                origin
                    .writer()
                    .write_all(&response)
                    .expect("origin writes the response");
                origin_answered = true;
            }
        }
        // origin -> proxy -> browser
        let wire = tls::take_server_outbound(&mut origin);
        if !wire.is_empty() {
            let out = proxy.on_peer_payload(&wire).expect("proxy peer step");
            to_origin.extend_from_slice(&out.to_peer);
            feed_browser(&mut browser, &out.to_client, &mut browser_plain);
        }
        if browser_plain.windows(12).any(|w| w == b"HTTP/1.1 200") {
            break;
        }
    }

    assert_eq!(
        proxy.captured_sni().as_deref(),
        Some("origin.example.com"),
        "the ClientHello is the source of the hostname"
    );
    assert_eq!(
        origin_request, request,
        "the origin must receive the request byte for byte"
    );
    assert!(
        browser_plain.starts_with(b"HTTP/1.1 200 OK"),
        "the browser must receive the response: {:?}",
        String::from_utf8_lossy(&browser_plain)
    );
    assert!(
        browser_plain
            .windows(user_tag_src().len())
            .any(|w| w == user_tag_src().as_bytes()),
        "the script must still be injected through a pending-opened session"
    );
}

/// A script body larger than rustls' 64 KiB buffer cap must still reach the
/// client: the write has to drain records between chunks, or the splice dies
/// with `WriteZero` and the page hangs (the stitched AdGuard Extra + Disable
/// AMP userscript is ~600 KB).
#[test]
fn a_large_script_body_reaches_the_client() {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, ServerConnection};

    let origin_ca = CertificateAuthority::generate().expect("origin ca");
    let mut origin_roots = rustls::RootCertStore::empty();
    origin_roots
        .add(rustls::pki_types::CertificateDer::from(origin_ca.cert_der()))
        .expect("origin root");
    let upstream_config = tls::client_config_with(origin_roots);

    let mitm_ca = CertificateAuthority::generate().expect("mitm ca");
    let resolver = Arc::new(SniCertResolver::new(Arc::new(
        CertificateAuthority::from_pem(&mitm_ca.cert_pem(), &mitm_ca.key_pem()).expect("restore"),
    )));
    let session =
        tls::open_session_with(&resolver, "origin.example.com", upstream_config).expect("session");
    // ~220 KB: well past the rustls buffer cap that used to stall the write.
    let script = "var x = 1;\n".repeat(20_000);
    let mut proxy = ProxySession::new(
        session,
        "/adfree-user.js".into(),
        Arc::from(script.as_str()),
    );

    let origin_resolver = Arc::new(SniCertResolver::new(Arc::new(origin_ca)));
    let mut origin = ServerConnection::new(tls::server_config(origin_resolver)).expect("origin");

    let mut browser_roots = rustls::RootCertStore::empty();
    browser_roots
        .add(rustls::pki_types::CertificateDer::from(mitm_ca.cert_der()))
        .expect("browser root");
    let name = ServerName::try_from("origin.example.com".to_string()).expect("server name");
    let mut browser =
        ClientConnection::new(tls::client_config_with(browser_roots), name).expect("browser");

    // The request the injected tag makes: it must be answered locally.
    let request = b"GET /adfree-user.js HTTP/1.1\r\nHost: origin.example.com\r\n\r\n";
    browser
        .writer()
        .write_all(request)
        .expect("browser writes the request");

    let mut to_origin: Vec<u8> = Vec::new();
    let mut origin_request: Vec<u8> = Vec::new();
    let mut browser_plain: Vec<u8> = Vec::new();

    for _round in 0..64 {
        // browser -> proxy -> origin
        let wire = tls::take_client_outbound(&mut browser);
        if !wire.is_empty() {
            let out = proxy.on_client_payload(&wire).expect("proxy client step");
            to_origin.extend_from_slice(&out.to_peer);
            feed_browser(&mut browser, &out.to_client, &mut browser_plain);
        }
        if !to_origin.is_empty() {
            feed_origin(&mut origin, &to_origin, &mut origin_request);
            to_origin.clear();
        }
        // origin -> proxy -> browser
        let wire = tls::take_server_outbound(&mut origin);
        if !wire.is_empty() {
            let out = proxy.on_peer_payload(&wire).expect("proxy peer step");
            to_origin.extend_from_slice(&out.to_peer);
            feed_browser(&mut browser, &out.to_client, &mut browser_plain);
        }
        if browser_plain.len() >= script.len() {
            break;
        }
    }

    assert!(
        origin_request.is_empty(),
        "the script request is served locally, never forwarded"
    );
    let text = String::from_utf8_lossy(&browser_plain).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK"), "served locally");
    assert!(
        text.contains(&format!("Content-Length: {}", script.len())),
        "the declared length must match the script"
    );
    assert!(
        text.ends_with(&script),
        "the whole body must survive: got {} of {} bytes",
        browser_plain.len(),
        script.len()
    );
}

/// A stream that is not TLS is spliced through untouched even though the
/// relay was armed for interception: arming must never break a flow.
#[test]
fn a_pending_session_splices_non_tls_streams_untouched() {
    let ca = CertificateAuthority::generate().expect("ca");
    let resolver = Arc::new(SniCertResolver::new(Arc::new(
        CertificateAuthority::from_pem(&ca.cert_pem(), &ca.key_pem()).expect("restore"),
    )));
    let mut proxy =
        ProxySession::new_pending(resolver, tls::client_config(), String::new(), Arc::from(""))
            .expect("pending session");

    let request = b"GET / HTTP/1.1\r\nHost: plain.example.com\r\n\r\n";
    let out = proxy.on_client_payload(request).expect("client step");
    assert_eq!(out.to_peer, request, "a non-TLS stream must pass verbatim");
    assert!(out.to_client.is_empty());

    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let out = proxy.on_peer_payload(response).expect("peer step");
    assert_eq!(out.to_client, response);

    // Later bytes keep flowing in both directions.
    let out = proxy.on_client_payload(b"tail").expect("client step 2");
    assert_eq!(out.to_peer, b"tail");
}

/// A hello split across two TCP segments still opens the session.
#[test]
fn a_fragmented_client_hello_still_opens_the_session() {
    use rustls::pki_types::ServerName;
    use rustls::ClientConnection;

    let mitm_ca = CertificateAuthority::generate().expect("mitm ca");
    let resolver = Arc::new(SniCertResolver::new(Arc::new(
        CertificateAuthority::from_pem(&mitm_ca.cert_pem(), &mitm_ca.key_pem()).expect("restore"),
    )));
    let mut proxy =
        ProxySession::new_pending(resolver, tls::client_config(), String::new(), Arc::from(""))
            .expect("pending session");

    let mut browser_roots = rustls::RootCertStore::empty();
    browser_roots
        .add(rustls::pki_types::CertificateDer::from(mitm_ca.cert_der()))
        .expect("browser root");
    let name = ServerName::try_from("split.example.com".to_string()).expect("server name");
    let mut browser =
        ClientConnection::new(tls::client_config_with(browser_roots), name).expect("browser");

    let hello = tls::take_client_outbound(&mut browser);
    assert!(hello.len() > 8, "the hello spans a whole record");

    // First segment: a partial record. Nothing can be decided yet.
    let out = proxy.on_client_payload(&hello[..7]).expect("first chunk");
    assert!(
        out.to_peer.is_empty(),
        "no upstream bytes before the hello is complete"
    );
    assert!(out.to_client.is_empty());
    assert_eq!(proxy.captured_sni(), None);

    // Second segment: the rest. The session opens and our own server flight
    // answers the hello.
    let out = proxy.on_client_payload(&hello[7..]).expect("second chunk");
    assert_eq!(proxy.captured_sni().as_deref(), Some("split.example.com"));
    assert!(
        !out.to_client.is_empty(),
        "our server flight must answer the completed hello"
    );

    // The browser finishes its handshake; the upstream ClientHello (now that
    // the server half is done) is drained towards the real server.
    let mut browser_plain: Vec<u8> = Vec::new();
    feed_browser(&mut browser, &out.to_client, &mut browser_plain);
    let finished = tls::take_client_outbound(&mut browser);
    assert!(!finished.is_empty(), "the client sends its Finished");
    let out = proxy.on_client_payload(&finished).expect("finished");
    assert!(
        !out.to_peer.is_empty(),
        "the upstream hello must be drained once the server handshake is done"
    );
}

/// A filler that does not compress away: a repeated character would shrink the
/// page to nothing and never reach the streaming path.
fn noisy(len: usize) -> String {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    (0..len)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (b'a' + ((seed >> 33) % 26) as u8) as char
        })
        .collect()
}

/// De-chunks (and, when `gzip`, decodes) a streamed response, the way a client
/// would: returns `(head, page)`.
fn read_streamed(out: &[u8], gzip: bool) -> (String, String) {
    let split = http::head_end(out).expect("head");
    let head = String::from_utf8(out[..split].to_vec()).expect("utf8 head");
    let mut payload = Vec::new();
    let mut framing = http::DechunkState::new();
    assert!(
        framing.push(&out[split..], &mut payload).expect("chunks"),
        "the streamed body must end with a terminating chunk"
    );
    assert!(framing.leftover().is_empty(), "no trailing bytes");
    let plain = if gzip {
        let mut decoded = Vec::new();
        let mut decoder = http::GunzipState::new();
        decoder
            .push(&payload, &mut decoded)
            .expect("the body must be gzip");
        assert!(decoder.is_done(), "the gzip stream must be complete");
        decoded
    } else {
        payload
    };
    (head, String::from_utf8(plain).expect("utf8 page"))
}

/// A page too long to hold whole: the body is streamed to the client as it is
/// edited instead of being buffered until the end of the response.
#[test]
fn a_long_identity_body_streams_with_the_tag_in_it() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let filler = "y".repeat(120 * 1024);
    let body = format!("<html><head><title>t</title></head><body>{filler}</body></html>");
    let response = html_response(&body);

    let mut out = Vec::new();
    let mut injected = 0;
    for chunk in response.chunks(7 * 1024) {
        let (part, count) = proxy.rewrite_response(chunk);
        out.extend_from_slice(&part);
        injected += count;
    }
    assert_eq!(injected, expected_tag(TEST_NONCE).len());

    let (head, page) = read_streamed(&out, false);
    let lower = head.to_lowercase();
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(lower.contains("transfer-encoding: chunked"), "{head}");
    assert!(!lower.contains("content-length"), "framing must be chunked: {head}");

    let tag = page
        .find(&expected_tag(&nonce_in(&page)))
        .expect("the tag must be in the page");
    let head_close = page.find("</head>").expect("</head>");
    assert!(tag < head_close, "the tag must land before </head>");
    assert!(page.ends_with("</body></html>"), "the body must be complete");
    assert_eq!(page.len(), body.len() + expected_tag(TEST_NONCE).len());
}

#[test]
fn a_long_gzip_body_streams_still_compressed() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let filler = noisy(120 * 1024);
    let body = format!("<html><head><title>t</title></head><body>{filler}</body></html>");
    let gzipped = http::gzip_encode(body.as_bytes()).expect("gzip");
    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: ");
    response.extend_from_slice(gzipped.len().to_string().as_bytes());
    response.extend_from_slice(b"\r\n\r\n");
    response.extend_from_slice(&gzipped);

    let mut out = Vec::new();
    let mut injected = 0;
    for chunk in response.chunks(3 * 1024) {
        let (part, count) = proxy.rewrite_response(chunk);
        out.extend_from_slice(&part);
        injected += count;
    }
    assert_eq!(injected, expected_tag(TEST_NONCE).len());

    let (head, page) = read_streamed(&out, true);
    let lower = head.to_lowercase();
    assert!(lower.contains("transfer-encoding: chunked"), "{head}");
    assert!(lower.contains("content-encoding: gzip"), "must stay compressed: {head}");
    assert!(!lower.contains("content-length"), "{head}");
    assert!(has_user_tag(&page));
    assert!(page.ends_with("</body></html>"));
    assert_eq!(page.len(), body.len() + expected_tag(TEST_NONCE).len());
}

/// The shape a real site serves: chunked *and* compressed, bytes arriving a
/// few at a time.
#[test]
fn a_chunked_gzip_body_streams() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let filler = noisy(96 * 1024);
    let body = format!("<html><head></head><body>{filler}</body></html>");
    let gzipped = http::gzip_encode(body.as_bytes()).expect("gzip");
    let mut response = Vec::new();
    response.extend_from_slice(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    // Two chunks of compressed data, the way an origin writes them out.
    let half = gzipped.len() / 2;
    for piece in [&gzipped[..half], &gzipped[half..]] {
        response.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        response.extend_from_slice(piece);
        response.extend_from_slice(b"\r\n");
    }
    response.extend_from_slice(b"0\r\n\r\n");

    let mut out = Vec::new();
    let mut injected = 0;
    for chunk in response.chunks(997) {
        let (part, count) = proxy.rewrite_response(chunk);
        out.extend_from_slice(&part);
        injected += count;
    }
    assert_eq!(injected, expected_tag(TEST_NONCE).len());

    let (head, page) = read_streamed(&out, true);
    assert!(head.to_lowercase().contains("content-encoding: gzip"));
    assert!(has_user_tag(&page));
    assert!(page.ends_with("</body></html>"));
    assert_eq!(page.len(), body.len() + expected_tag(TEST_NONCE).len());
}

/// The streaming encoder must write a gzip stream the *library* decoder accepts
/// too, not only the one this crate reads back.
#[test]
fn the_streamed_gzip_body_is_valid_gzip() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let filler = noisy(96 * 1024);
    let body = format!("<html><head></head><body>{filler}</body></html>");
    let gzipped = http::gzip_encode(body.as_bytes()).expect("gzip");
    let mut response = Vec::new();
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: ");
    response.extend_from_slice(gzipped.len().to_string().as_bytes());
    response.extend_from_slice(b"\r\n\r\n");
    response.extend_from_slice(&gzipped);

    let (out, _) = proxy.rewrite_response(&response);
    let split = http::head_end(&out).expect("head");
    let mut payload = Vec::new();
    let mut framing = http::DechunkState::new();
    assert!(framing.push(&out[split..], &mut payload).expect("chunks"));
    let plain = http::decode_body(&payload, http::Encoding::Gzip).expect("flate2 must accept it");
    let page = String::from_utf8(plain).expect("utf8");
    assert!(has_user_tag(&page));
    assert!(page.ends_with("</body></html>"));
}

/// The exact shape that broke a real page: the network hands over bytes that
/// end precisely where a chunk's payload ends, so the CRLF closing it starts
/// the next read. The framing decoder has to keep that state.
#[test]
fn chunked_bodies_cut_at_the_payload_end_still_stream() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let filler = noisy(96 * 1024);
    let body = format!("<html><head></head><body>{filler}</body></html>");
    let gzipped = http::gzip_encode(body.as_bytes()).expect("gzip");
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n";

    // Pieces of the wire stream: the head, then for every chunk its size line
    // and payload in one read and the CRLF in the next.
    let mut pieces: Vec<Vec<u8>> = vec![head.to_vec()];
    for piece in gzipped.chunks(3 * 1024) {
        let mut size_and_payload = format!("{:x}\r\n", piece.len()).into_bytes();
        size_and_payload.extend_from_slice(piece);
        pieces.push(size_and_payload);
        pieces.push(b"\r\n".to_vec());
    }
    pieces.push(b"0\r\n\r\n".to_vec());

    let mut out = Vec::new();
    let mut injected = 0;
    for piece in &pieces {
        let (part, count) = proxy.rewrite_response(piece);
        out.extend_from_slice(&part);
        injected += count;
    }
    assert_eq!(injected, expected_tag(TEST_NONCE).len());

    let (head, page) = read_streamed(&out, true);
    assert!(head.to_lowercase().contains("transfer-encoding: chunked"));
    assert!(has_user_tag(&page));
    assert!(page.ends_with("</body></html>"));
    assert_eq!(page.len(), body.len() + expected_tag(TEST_NONCE).len());
}

/// Cosmetic filtering has to run even when the proxy found no rules of its own:
/// the runtime is what asks for the class/id tokens it meets, which is the only
/// way a *streamed* page gets covered — the proxy only ever saw its head. This
/// is the shape a real Wikipedia page has.
#[test]
fn the_page_runtime_is_injected_even_without_a_payload() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    // A list whose rules match nothing on the page that follows.
    proxy.cosmetic = Some(engine_with("no-match", "other.test##.ad-box\n"));

    let body = "<html><head><title>t</title></head><body>plain text</body></html>";
    let (out, injected) = proxy.rewrite_response(&html_response(body));
    let text = String::from_utf8(out).expect("utf8");
    let runtime = format!("{}?h=", local_asset("/adfree-page.js"));
    let nonce = nonce_in(&text);
    assert!(
        text.contains(&format!("<script nonce=\"{nonce}\" src=\"{runtime}")),
        "the runtime must go out with the nonce: {text}"
    );
    assert!(
        !text.contains("window.__adfree_page"),
        "there is no payload to send for this page: {text}"
    );
    assert!(has_user_tag(&text), "{text}");
    assert!(injected > 0);
}

/// A redirect body is never rendered, so nothing is injected into it: an 11 KB
/// payload on every hop would be paid for nothing.
#[test]
fn redirect_bodies_are_left_alone() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");
    let body = "<html><head><title>Moved</title></head><body>go</body></html>";
    let mut raw = Vec::new();
    raw.extend_from_slice(
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://elsewhere.test/\r\nContent-Type: text/html\r\nContent-Length: ",
    );
    raw.extend_from_slice(body.len().to_string().as_bytes());
    raw.extend_from_slice(b"\r\n\r\n");
    raw.extend_from_slice(body.as_bytes());

    let (out, injected) = proxy.rewrite_response(&raw);
    assert_eq!(injected, 0);
    assert!(
        out.windows(body.len()).any(|w| w == body.as_bytes()),
        "the body must travel untouched"
    );
    assert!(!out.windows(6).any(|w| w == b"adfree"));
}

/// The hiding selectors are the bulk of the per-page payload, and they repeat
/// on every page of a site: they are served as a stylesheet whose URL carries
/// their content hash, so the browser fetches them once and keeps them.
#[test]
fn the_hiding_stylesheet_is_served_from_a_content_addressed_url() {
    let engine = engine_with(
        "hide-sheet",
        "origin.example.com##.ad-slot\norigin.example.com##.ad-box\n",
    );
    let (href, body) = super::proxy::hide_stylesheet(&engine, "origin.example.com")
        .expect("the host hides something");
    assert!(href.starts_with(HIDE_PATH), "{href}");
    // Sorted, so the same page always produces the same bytes and the same URL.
    assert_eq!(body, ".ad-box,.ad-slot{display:none!important}\n");
    assert_eq!(href_hash(&href), content_hash(body.as_bytes()));

    // A host the rules do not cover has no stylesheet at all.
    assert!(super::proxy::hide_stylesheet(&engine, "other.test").is_none());
}

#[test]
fn answering_the_stylesheet_request_repeats_the_bytes_the_link_hashed() {
    let engine = engine_with(
        "hide-serve",
        "origin.example.com##.ad-box\norigin.example.com##.ad-slot\n",
    );
    let (href, body) = super::proxy::hide_stylesheet(&engine, "origin.example.com").expect("sheet");

    // The request the browser sends for the link it was given.
    let mut buffer = format!(
        "GET {href} HTTP/1.1\r\nHost: origin.example.com\r\nAccept-Encoding: gzip, deflate\r\n\r\n"
    )
    .into_bytes();
    let response = take_local_request(
        "/adfree-user.js",
        "",
        Some(engine.as_ref()),
        Some("origin.example.com"),
        &mut buffer,
    )
    .expect("served");
    assert!(buffer.is_empty(), "the request is consumed");

    let (head, compressed) = split_local(&response);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(head.contains("Content-Type: text/css; charset=utf-8"), "{head}");
    // Cacheable forever: the URL changes when the bytes do, and only then.
    assert!(head.contains("Cache-Control: max-age=31536000, immutable"), "{head}");
    assert!(head.contains("Content-Encoding: gzip"), "{head}");
    assert!(head.contains("Vary: Accept-Encoding"), "{head}");

    let plain = http::decode_body(&compressed, http::Encoding::Gzip).expect("decoded");
    let css = String::from_utf8(plain).expect("utf8");
    assert_eq!(css, body, "the served bytes must be the ones hashed");
    assert_eq!(href_hash(&href), content_hash(css.as_bytes()));
}

/// A client that never said it takes gzip gets the bytes plain.
#[test]
fn the_hiding_stylesheet_travels_plain_when_gzip_is_not_accepted() {
    let engine = engine_with("hide-plain", "origin.example.com##.ad-box\n");
    let (href, body) = super::proxy::hide_stylesheet(&engine, "origin.example.com").expect("sheet");
    let mut buffer =
        format!("GET {href} HTTP/1.1\r\nHost: origin.example.com\r\n\r\n").into_bytes();
    let response = take_local_request(
        "/adfree-user.js",
        "",
        Some(engine.as_ref()),
        Some("origin.example.com"),
        &mut buffer,
    )
    .expect("served");

    let (head, payload) = split_local(&response);
    assert!(!head.contains("Content-Encoding"), "{head}");
    assert_eq!(String::from_utf8(payload).expect("utf8"), body);
}

/// The page runtime is document-sized and was re-fetched on every navigation;
/// its tag carries a content hash so the answer is cacheable too.
#[test]
fn the_runtime_is_served_from_a_content_addressed_url() {
    let expected = format!(
        "{}?h={:016x}",
        super::proxy::PAGE_SCRIPT_PATH,
        content_hash(super::proxy::PAGE_RUNTIME.as_bytes())
    );

    // The request is the one the injected tag asks for.
    let mut buffer = format!(
        "GET {expected} HTTP/1.1\r\nHost: origin.example.com\r\nAccept-Encoding: gzip\r\n\r\n"
    )
    .into_bytes();
    let engine = engine_with("runtime-serve", "origin.example.com##.ad-box\n");
    let response = take_local_request(
        "/adfree-user.js",
        "",
        Some(engine.as_ref()),
        Some("origin.example.com"),
        &mut buffer,
    )
    .expect("served");
    let (head, compressed) = split_local(&response);
    assert!(
        head.contains("Cache-Control: max-age=31536000, immutable"),
        "{head}"
    );
    assert!(head.contains("Content-Encoding: gzip"), "{head}");
    let plain = http::decode_body(&compressed, http::Encoding::Gzip).expect("decoded");
    assert_eq!(plain, super::proxy::PAGE_RUNTIME.as_bytes());
}

/// The same treatment for the user script: it is re-served to every page, and
/// a big one is why the tag carries a hash of its body.
#[test]
fn the_user_script_is_served_from_a_content_addressed_url() {
    let script = "/* big */ window.__adfree_user=\"x\";";
    let href = format!(
        "/adfree-user.js?h={:016x}",
        content_hash(script.as_bytes())
    );
    let mut buffer = format!(
        "GET {href} HTTP/1.1\r\nHost: origin.example.com\r\nAccept-Encoding: gzip\r\n\r\n"
    )
    .into_bytes();
    let response = take_local_request("/adfree-user.js", script, None, None, &mut buffer).expect("served");
    let (head, compressed) = split_local(&response);
    assert!(head.contains("Cache-Control: max-age=31536000, immutable"), "{head}");
    let plain = http::decode_body(&compressed, http::Encoding::Gzip).expect("decoded");
    assert_eq!(String::from_utf8(plain).expect("utf8"), script);
}

/// The request parser behind the URL rules: what it makes of a head, and the
/// body it announces — what a locally served answer has to swallow to keep
/// the bytes after the head from being read as the next request.
#[test]
fn request_facts_read_whole_requests_and_their_bodies() {
    let head = b"GET /ads.js?x=1 HTTP/1.1\r\nHost: shop.test:8443\r\n\
                 Referer: https://page.test/p\r\nSec-Fetch-Dest: script\r\n\
                 Accept: */*\r\n\r\n";
    let facts = request_facts(head).expect("parseable");
    assert_eq!(facts.method, "GET");
    assert_eq!(facts.target, "/ads.js?x=1");
    assert_eq!(facts.authority, Some("shop.test:8443"));
    assert_eq!(facts.referer, Some("https://page.test/p"));
    assert_eq!(facts.dest, Some("script"));
    assert_eq!(facts.request_type(), "script");
    assert_eq!(facts.body, None);

    // A declared body: the head is not the last thing on the wire, and how it
    // is counted decides what an answer served here has to swallow.
    let with_body = b"POST /api HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 5\r\n\r\nhello";
    assert_eq!(
        request_facts(with_body).expect("parseable").body,
        Some(RequestBody::Length(5))
    );
    let chunked = b"POST /api HTTP/1.1\r\nHost: shop.test\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(
        request_facts(chunked).expect("parseable").body,
        Some(RequestBody::Chunked)
    );
    // `Transfer-Encoding` wins when a client spells both.
    let both = b"POST /api HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 5\r\n\
                 Transfer-Encoding: chunked\r\n\r\n";
    assert_eq!(
        request_facts(both).expect("parseable").body,
        Some(RequestBody::Chunked)
    );
    let empty_body = b"POST /api HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(request_facts(empty_body).expect("parseable").body, None);
    // A length nobody can read cannot be swallowed either.
    let broken = b"POST /api HTTP/1.1\r\nHost: shop.test\r\nContent-Length: soon\r\n\r\n";
    assert_eq!(
        request_facts(broken).expect("parseable").body,
        Some(RequestBody::Unknown)
    );

    // Not an HTTP/1.x request: nothing else may be read as a request line.
    assert!(request_facts(b"\x16\x03\x01\x00\x00binary").is_none());
    assert!(request_facts(b"hello there\r\n\r\n").is_none());
}

/// The body of a request answered locally is swallowed byte for byte —
/// whatever frames it, and across feeds when it does not arrive whole — so
/// the next request is parsed where it really starts.
#[test]
fn an_answered_request_body_is_swallowed_before_the_next_parse() {
    // A declared length: what has arrived goes, what follows it survives.
    let mut buffer = b"hello world".to_vec();
    let state = swallow_body(None, Some(RequestBody::Length(5)), &mut buffer, None);
    assert_eq!(buffer, b" world");
    assert!(state.is_none());

    // Cut short: the rest is owed, and the next feed pays it.
    let mut buffer = b"hel".to_vec();
    let mut state = swallow_body(None, Some(RequestBody::Length(5)), &mut buffer, None);
    assert!(matches!(state, Some(ClientDiscard::Length(2))));
    assert!(buffer.is_empty());
    let mut buffer = b"loGET /x HTTP/1.1\r\n\r\n".to_vec();
    state = swallow_body(state, None, &mut buffer, None);
    assert_eq!(buffer, b"GET /x HTTP/1.1\r\n\r\n");
    assert!(state.is_none());

    // A chunked body: its last chunk ends it, and what follows survives.
    let mut buffer = b"5\r\nhello\r\n0\r\n\r\nGET /x HTTP/1.1\r\n\r\n".to_vec();
    let state = swallow_body(None, Some(RequestBody::Chunked), &mut buffer, None);
    assert!(state.is_none());
    assert_eq!(buffer, b"GET /x HTTP/1.1\r\n\r\n");

    // Chunked framing cut in half: the state carries it across feeds.
    let mut buffer = b"5\r\nhel".to_vec();
    let mut state = swallow_body(None, Some(RequestBody::Chunked), &mut buffer, None);
    assert!(matches!(state, Some(ClientDiscard::Chunked(_))));
    assert!(buffer.is_empty());
    let mut buffer = b"lo\r\n0\r\n\r\nGET /y HTTP/1.1\r\n\r\n".to_vec();
    state = swallow_body(state, None, &mut buffer, None);
    assert!(state.is_none());
    assert_eq!(buffer, b"GET /y HTTP/1.1\r\n\r\n");

    // Framing nobody can follow: everything from here on goes nowhere, so no
    // body byte is ever read as a request of its own.
    let mut buffer = b"zz\r\nGET /x HTTP/1.1\r\n\r\n".to_vec();
    let state = swallow_body(None, Some(RequestBody::Chunked), &mut buffer, None);
    assert!(matches!(state, Some(ClientDiscard::Poisoned)));
    assert!(buffer.is_empty());
    let mut buffer = b"GET /x HTTP/1.1\r\n\r\n".to_vec();
    let state = swallow_body(state, None, &mut buffer, None);
    assert!(matches!(state, Some(ClientDiscard::Poisoned)));
    assert!(buffer.is_empty());

    // No body at all: nothing to swallow.
    let mut buffer = b"GET /x HTTP/1.1\r\n\r\n".to_vec();
    assert!(swallow_body(None, None, &mut buffer, None).is_none());
    assert_eq!(buffer, b"GET /x HTTP/1.1\r\n\r\n");
}

/// Who asked for the connection to end: HTTP/1.1 keeps it unless it says
/// `close`, HTTP/1.0 closes it unless it asks for keep-alive. A response the
/// app answers itself has to carry that, or an HTTP/1.0 client waits for an
/// EOF that no origin will send.
#[test]
fn request_facts_know_who_wants_the_connection_closed() {
    let closes = |head: &[u8]| request_facts(head).expect("parseable").closes;
    assert!(!closes(
        b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive\r\n\r\n"
    ));
    assert!(closes(
        b"GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n"
    ));
    assert!(!closes(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"));
    assert!(closes(b"GET / HTTP/1.0\r\nHost: a.test\r\n\r\n"));
    assert!(!closes(
        b"GET / HTTP/1.0\r\nHost: a.test\r\nConnection: keep-alive\r\n\r\n"
    ));
    assert!(closes(b"GET / HTTP/1.0\r\nHost: a.test\r\nConnection: Close\r\n\r\n"));

    // The marker sits before the blank line, so the head stays a head.
    let marked = closing_response(blocked_response());
    let head = String::from_utf8_lossy(&marked);
    assert!(head.contains("Connection: close\r\n\r\n"), "{head}");
    let (head, body) = split_local(&marked);
    assert!(head.starts_with("HTTP/1.1 204 No Content\r\n"), "{head}");
    assert!(body.is_empty(), "{body:?}");
}

/// Request types come from `Sec-Fetch-Dest`; anything unknown is `other`,
/// never a guess — a `$script`-scoped rule must not fire on an image.
#[test]
fn request_types_follow_sec_fetch_dest() {
    let of = |dest: &str| {
        let head = format!("GET /x HTTP/1.1\r\nHost: a.test\r\nSec-Fetch-Dest: {dest}\r\n\r\n");
        request_facts(head.as_bytes())
            .expect("parseable")
            .request_type()
    };
    assert_eq!(of("document"), "document");
    assert_eq!(of("iframe"), "subdocument");
    assert_eq!(of("script"), "script");
    assert_eq!(of("style"), "stylesheet");
    assert_eq!(of("empty"), "xmlhttprequest");
    assert_eq!(of("image"), "image");
    assert_eq!(of("video"), "media");
    assert_eq!(of("track"), "media");
    assert_eq!(of("report"), "csp_report");
    assert_eq!(of("made-up"), "other");
    let head = b"GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n";
    assert_eq!(request_facts(head).expect("parseable").request_type(), "other");
}

/// The URL a request line and its host make, and the origin-form target a
/// rewritten URL has to turn back into.
#[test]
fn urls_and_targets_round_trip() {
    let facts =
        request_facts(b"GET /ads.js?a=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n").expect("head");
    assert_eq!(
        request_url(&facts, "shop.test"),
        "https://shop.test/ads.js?a=1"
    );
    // An absolute-form target is already a URL.
    let facts =
        request_facts(b"GET http://x.test/a HTTP/1.1\r\nHost: x.test\r\n\r\n").expect("head");
    assert_eq!(request_url(&facts, "x.test"), "http://x.test/a");

    assert_eq!(
        origin_form("https://shop.test/api?keep=2").as_deref(),
        Some("/api?keep=2")
    );
    assert_eq!(origin_form("https://shop.test").as_deref(), Some("/"));
    assert_eq!(origin_form("https://shop.test?a=1").as_deref(), Some("/?a=1"));
    assert_eq!(origin_form("not a url").as_deref(), None);
}

/// A rewritten request line changes the target and nothing else.
#[test]
fn a_rewritten_head_only_changes_the_target() {
    let head = b"GET /api?secret=1&keep=2 HTTP/1.1\r\nHost: shop.test\r\nAccept: */*\r\n\r\n";
    assert_eq!(
        rebuilt_head(head, "/api?keep=2"),
        b"GET /api?keep=2 HTTP/1.1\r\nHost: shop.test\r\nAccept: */*\r\n\r\n"
    );
    // A line we cannot make sense of is handed back untouched.
    assert_eq!(rebuilt_head(b"garbage\r\n\r\n", "/x"), b"garbage\r\n\r\n");

    // `$removeparam` is AdGuard's GET/HEAD/OPTIONS (and sometimes POST)
    // affair; everything else keeps its query untouched.
    assert!(rewritable("GET") && rewritable("HEAD") && rewritable("OPTIONS"));
    assert!(rewritable("POST") && !rewritable("DELETE"));
}

/// The two answers the URL rules produce locally: an empty block and the
/// engine's `data:` redirect turned back into a response.
#[test]
fn blocked_and_redirect_answers_are_shaped_for_a_browser() {
    let blocked = blocked_response();
    let head = String::from_utf8_lossy(&blocked);
    assert!(head.starts_with("HTTP/1.1 204 No Content\r\n"), "{head}");
    assert!(head.contains("Content-Length: 0\r\n"), "{head}");

    let redirect =
        redirect_response("data:application/javascript;base64,KGZ1bmN0aW9uKCl7fSkoKTs=")
            .expect("decodable");
    let (head, body) = split_local(&redirect);
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(
        head.contains("Content-Type: application/javascript\r\n"),
        "{head}"
    );
    assert_eq!(body, b"(function(){})();");

    // Anything that is not the shape the crate produces is not a redirect the
    // session can serve: the caller has to fall back to a plain block.
    assert!(redirect_response("https://example.com/x.js").is_none());
    assert!(redirect_response("data:application/javascript;base64,!!!").is_none());
}
