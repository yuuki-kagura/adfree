//! Round-trip tests of the splice.
//!
//! `tls_tests.rs` already covers the handshake and both directions of a TLS
//! conversation end to end. These tests therefore focus on what this module adds
//! on top of TLS: the response rewriter that injects scripts into HTML.

use super::proxy::ProxySession;
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
    ProxySession::new(session, script.to_string())
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
    while let Ok(n) = browser.read_tls(&mut cursor) {
        if n == 0 {
            break;
        }
        browser.process_new_packets().expect("browser packets");
    }
    let mut buf = [0u8; 4096];
    while let Ok(n) = browser.reader().read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

/// Feeds wire bytes into the origin server and collects what it decrypted.
pub(crate) fn feed_origin(server: &mut rustls::ServerConnection, wire: &[u8], out: &mut Vec<u8>) {
    let mut cursor = std::io::Cursor::new(wire);
    while let Ok(n) = server.read_tls(&mut cursor) {
        if n == 0 {
            break;
        }
        server.process_new_packets().expect("origin packets");
    }
    let mut buf = [0u8; 4096];
    while let Ok(n) = server.reader().read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
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
    let mut proxy = ProxySession::new(session, String::new());

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
