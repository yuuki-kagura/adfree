//! Round-trip tests of the splice.
//!
//! `tls_tests.rs` already covers the handshake and both directions of a TLS
//! conversation end to end. These tests therefore focus on what this module adds
//! on top of TLS: the response rewriter that injects scripts into HTML.

use super::proxy::{take_script_request, ProxySession};
use super::*;
use crate::mitm::ca::CertificateAuthority;
use crate::mitm::tls::{open_session, SniCertResolver};
use std::io::{Read, Write};
use std::sync::Arc;

/// The tag the injector emits, so expectations stay in sync with the code.
fn expected_tag() -> &'static str {
    "<script src=\"/adfree-user.js\" defer></script>"
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
        take_script_request("/adfree-user.js", "let x = 1;", &mut buffer).expect("served");
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
    assert!(take_script_request("/adfree-user.js", "let x = 1;", &mut buffer).is_none());
    assert!(!buffer.is_empty(), "untouched");
}

#[test]
fn script_request_waits_for_the_full_head() {
    let mut buffer = b"GET /adfree-user.js HTTP/1.1\r\nHost: x\r\n".to_vec();
    assert!(take_script_request("/adfree-user.js", "let x = 1;", &mut buffer).is_none());
    buffer.extend_from_slice(b"\r\n");
    assert!(take_script_request("/adfree-user.js", "let x = 1;", &mut buffer).is_some());
}

#[test]
fn script_request_serves_only_when_enabled() {
    let mut buffer = b"GET /adfree-user.js HTTP/1.1\r\n\r\n".to_vec();
    assert!(take_script_request("/adfree-user.js", "", &mut buffer).is_none());
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
    let (out, injected) = proxy.rewrite_response_for_test(b"HTTP/1.1 200 OK\r\nContent-Ty");
    assert!(out.is_empty(), "a partial head must be buffered");
    assert_eq!(injected, 0);

    let body = "<html><head></head><body>ad</body></html>";
    let (out, injected) = proxy.rewrite_response_for_test(&html_response(body));
    assert_eq!(injected, expected_tag().len(), "the whole tag is added");

    let text = String::from_utf8(out).expect("utf8");
    let new_len = body.len() + expected_tag().len();
    assert!(
        text.contains(&format!("Content-Length: {new_len}")),
        "length rewritten to {new_len}: {text}"
    );
    assert!(text.contains(expected_tag()));
}

#[test]
fn response_split_across_reads_is_reassembled() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let body = "<html><head></head><body>x</body></html>";
    let full = html_response(body);
    let head = &full[..full.len() - body.len()];

    // Chunk 1: everything but the body.
    let (out, injected) = proxy.rewrite_response_for_test(head);
    assert!(out.is_empty(), "head only: wait for the body");
    assert_eq!(injected, 0);

    // Chunk 2: the body.
    let (out, injected) = proxy.rewrite_response_for_test(body.as_bytes());
    assert_eq!(injected, expected_tag().len());

    let text = String::from_utf8(out).expect("utf8");
    let new_len = body.len() + expected_tag().len();
    assert!(text.contains(&format!("Content-Length: {new_len}")), "{text}");
    assert!(text.contains(expected_tag()));
}

#[test]
fn json_responses_pass_through_byte_for_byte() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
    let (out, injected) = proxy.rewrite_response_for_test(response);
    assert_eq!(injected, 0, "JSON must not be touched");
    assert_eq!(out, response, "the body must arrive unchanged");
}

#[test]
fn compressed_responses_are_left_alone() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 12\r\n\r\n\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x00\x00";
    let (out, injected) = proxy.rewrite_response_for_test(response);
    assert_eq!(injected, 0, "gzip must not be rewritten");
    assert_eq!(out, response);
}

#[test]
fn chunked_responses_are_left_alone() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "/adfree-user.js");

    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let (out, injected) = proxy.rewrite_response_for_test(response);
    assert_eq!(injected, 0, "chunked bodies have no length to fix");
    assert_eq!(out, response);
}

#[test]
fn empty_script_url_disables_the_rewriter() {
    let ca = CertificateAuthority::generate().expect("ca");
    let mut proxy = build_proxy(&ca, "");

    let body = "<html><head></head></html>";
    let (out, injected) = proxy.rewrite_response_for_test(&html_response(body));
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
    let (out, injected) = proxy.rewrite_response_for_test(&response);
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
            .windows(expected_tag().len())
            .any(|w| w == expected_tag().as_bytes()),
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
