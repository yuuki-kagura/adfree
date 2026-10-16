//! End-to-end test of the TLS termination path over an in-memory transport.
//!
//! This is what proves a MITM actually works: a real `ServerConnection` (our
//! forged leaf) is driven by a real `ClientConnection` that trusts our CA and
//! nothing else. If the handshake, ALPN or the plaintext plumbing break, this
//! fails before any device ever sees it.

use crate::mitm::tls::*;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, ClientConnection, ServerConnection};
use std::io::Write;
use std::sync::Arc;

/// Builds a client config that trusts this CA only.
fn client_trusting(ca: &crate::mitm::ca::CertificateAuthority) -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca.cert_der()))
        .expect("root accepted");
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H1.to_vec()];
    Arc::new(config)
}

/// Server side that mints leaves through the same per-SNI resolver the device uses.
fn server_using(ca: Arc<crate::mitm::ca::CertificateAuthority>) -> ServerConnection {
    let resolver = Arc::new(SniCertResolver::new(ca));
    ServerConnection::new(server_config(resolver)).expect("server conn")
}

/// Runs a full handshake between our `ServerConnection` and the client side.
fn handshake(
    server: &mut ServerConnection,
    client: &mut ClientConnection,
) {
    let mut rounds = 0;
    let mut outbound = take_client_outbound(client);
    while server_handshaking(server) || client_handshaking(client) {
        rounds += 1;
        assert!(rounds < 24, "handshake must converge");

        // client -> server
        feed_server(server, &outbound).ok();
        let to_client = take_server_outbound(server);
        // server -> client
        let _ = feed_client_bytes(client, &to_client);
        outbound = take_client_outbound(client);
        if outbound.is_empty() && to_client.is_empty() {
            break;
        }
    }
    assert!(!server_handshaking(server), "server finished handshaking");
    assert!(!client_handshaking(client), "client finished handshaking");
}

/// Feeds wire bytes into a `ClientConnection`, draining its plaintext away.
fn feed_client_bytes(connection: &mut ClientConnection, chunk: &[u8]) -> usize {
    let mut reader = std::io::Cursor::new(chunk);
    let mut fed = 0;
    while let Ok(n) = connection.read_tls(&mut reader) {
        if n == 0 {
            break;
        }
        fed += n;
        if let Err(e) = connection.process_new_packets() {
            panic!("client process_new_packets: {e}");
        }
    }
    drain_client_plain(connection);
    fed
}

#[test]
fn terminates_a_full_tls_conversation() {
    let ca = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("ca"));
    let mut server = server_using(Arc::clone(&ca));

    let cconfig = client_trusting(&ca);
    let name = rustls::pki_types::ServerName::try_from("origin.example.com".to_string())
        .expect("server name");
    let mut client = ClientConnection::new(cconfig, name).expect("client conn");

    handshake(&mut server, &mut client);
    assert_eq!(client.alpn_protocol(), Some(ALPN_H1));
    assert_eq!(server_alpn(&server), Some(ALPN_H1.to_vec()));

    // --- application data in both directions ---
    let request = b"GET / HTTP/1.1\r\nHost: origin.example.com\r\n\r\n";
    let cipher = send_from_client(&mut client, request);
    let plain = feed_server(&mut server, &cipher).expect("server read");
    assert_eq!(plain, request, "the origin must see the exact plaintext");

    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    let cipher = send_from_server(&mut server, response);
    let plain = feed_client_read_only(&mut client, &cipher);
    assert_eq!(plain, response, "the app must see the exact plaintext");
}

#[test]
fn spliced_body_survives_the_tls_round_trip() {
    let ca = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("ca"));
    let mut server = server_using(Arc::clone(&ca));

    let cconfig = client_trusting(&ca);
    let name = rustls::pki_types::ServerName::try_from("html.example.com".to_string())
        .expect("server name");
    let mut client = ClientConnection::new(cconfig, name).expect("client conn");

    handshake(&mut server, &mut client);

    // Inject into the response body before it is encrypted.
    let body = b"<html><head></head><body>ad here</body></html>";
    let (modified, decision) = crate::mitm::http::inject_script(body, "/adfree-user.js");
    assert_eq!(decision, crate::mitm::http::Decision::Injected);

    let cipher = send_from_server(&mut server, &modified);
    let plain = feed_client_read_only(&mut client, &cipher);
    let text = String::from_utf8(plain).expect("utf8");
    assert!(
        text.contains("<script src=\"/adfree-user.js\""),
        "injected script must reach the client: {text}"
    );
    assert!(text.contains("ad here"));
}

#[test]
fn a_restored_ca_still_signs_leaves_the_original_trusts() {
    // This is the path a real device takes after a restart: the CA is rebuilt
    // from persisted PEM (rcgen cannot parse its DER back), so the issuer
    // object is fresh while the DER the client installed is the original one.
    // If `from_pem` stops mirroring the stored CA, every leaf would fail to
    // chain and HTTPS pages would die with CERT_AUTHORITY_INVALID.
    let ca = crate::mitm::ca::CertificateAuthority::generate().expect("ca");
    let stored_der = ca.cert_der();
    let restored = crate::mitm::ca::CertificateAuthority::from_pem(
        &ca.cert_pem(),
        &ca.key_pem(),
    )
    .expect("restore");

    let issued = restored.issue("origin.example.com").expect("leaf");
    let _ = &issued; // the resolver mints its own leaf; keep the call to exercise the cache
    let mut server = server_using(Arc::new(restored));

    // The client trusts only what the user installed: the original DER.
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(stored_der))
        .expect("root accepted");
    let mut cconfig = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cconfig.alpn_protocols = vec![ALPN_H1.to_vec()];
    let cconfig = Arc::new(cconfig);

    let name = rustls::pki_types::ServerName::try_from("origin.example.com".to_string())
        .expect("server name");
    let mut client = ClientConnection::new(cconfig, name).expect("client conn");

    handshake(&mut server, &mut client);
}

/// Reads new plaintext from a client connection without draining old data.
fn feed_client_read_only(
    connection: &mut ClientConnection,
    cipher: &[u8],
) -> Vec<u8> {
    let mut reader = std::io::Cursor::new(cipher);
    while let Ok(n) = connection.read_tls(&mut reader) {
        if n == 0 {
            break;
        }
        if let Err(e) = connection.process_new_packets() {
            panic!("process_new_packets: {e}");
        }
    }
    drain_client_plain(connection)
}

/// Encrypts a payload on the server side, returning the wire bytes.
fn send_from_server(connection: &mut ServerConnection, plaintext: &[u8]) -> Vec<u8> {
    connection.writer().write_all(plaintext).expect("server write");
    take_server_outbound(connection)
}

/// Encrypts a payload on the client side, returning the wire bytes.
fn send_from_client(connection: &mut ClientConnection, plaintext: &[u8]) -> Vec<u8> {
    connection.writer().write_all(plaintext).expect("client write");
    take_client_outbound(connection)
}
