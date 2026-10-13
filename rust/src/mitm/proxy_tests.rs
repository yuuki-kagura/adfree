//! Round-trip tests of the splice.
//!
//! `tls_tests.rs` already covers the handshake and both directions of a TLS
//! conversation end to end. These tests therefore focus on what this module adds
//! on top of TLS: the response rewriter that injects scripts into HTML.

use super::proxy::ProxySession;
use super::*;
use crate::mitm::ca::CertificateAuthority;
use crate::mitm::tls::{open_session, SniCertResolver};
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
