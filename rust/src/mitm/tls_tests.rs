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

#[test]
fn the_flow_resolver_captures_the_clients_sni() {
    // The engine opens the upstream half only after this capture: if the
    // wrapper ever stops storing the hello's server_name, every intercepted
    // flow would present the wrong name (or none) upstream.
    let ca = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("ca"));
    let inner = Arc::new(SniCertResolver::new(Arc::clone(&ca)));
    let flow = FlowResolver::new(Arc::clone(&inner));
    let mut server = new_server(server_config_dyn(flow.clone())).expect("server conn");

    let cconfig = client_trusting(&ca);
    let name = rustls::pki_types::ServerName::try_from("captured.example.com".to_string())
        .expect("server name");
    let mut client = ClientConnection::new(cconfig, name).expect("client conn");

    assert_eq!(flow.captured(), None, "nothing captured before the hello");

    handshake(&mut server, &mut client);

    assert_eq!(flow.captured().as_deref(), Some("captured.example.com"));
    assert!(
        inner.issued_hosts().iter().any(|h| h == "captured.example.com"),
        "the shared resolver must still mint the leaf: {:?}",
        inner.issued_hosts()
    );
}

/// A client's first flight: the bytes the proxy sniffs for a ClientHello.
fn client_flight(host: &str) -> Vec<u8> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H1.to_vec()];
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).expect("server name");
    let mut client = ClientConnection::new(Arc::new(config), name).expect("client conn");
    take_client_outbound(&mut client)
}

/// Re-frames one handshake flight as two TLS records, the way a ClientHello
/// large enough to carry ECH arrives.
fn split_into_records(flight: &[u8], at: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in [&flight[5..5 + at], &flight[5 + at..]] {
        out.push(0x16);
        out.extend_from_slice(&flight[1..3]);
        out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        out.extend_from_slice(chunk);
    }
    out
}

#[test]
fn a_hello_without_ech_is_read_as_such() {
    let flight = client_flight("shop.test");
    assert_eq!(
        first_flight(&flight),
        Flight::Hello {
            ech_len: None,
            server_name: Some("shop.test".to_string()),
        }
    );
    // A partial record says nothing yet.
    assert_eq!(first_flight(&flight[..flight.len() - 4]), Flight::Pending);
    assert_eq!(first_flight(&flight[..3]), Flight::Pending);
    // Something that is not a handshake record is not a hello either.
    assert_eq!(
        first_flight(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]),
        Flight::NotHello
    );
}

#[test]
fn a_hello_that_offers_ech_keeps_its_outer_name() {
    let flight = client_flight("shop.test");
    let patched = with_fake_ech(&flight).expect("the hello must be patchable");
    assert!(
        patched.len() > flight.len(),
        "the extension has to be in there"
    );
    assert_eq!(
        first_flight(&patched),
        Flight::Hello {
            // type(1) + cipher_suite(4) + config_id(1) + enc(2 + 32)
            // + payload(2 + 48), the shape `with_fake_ech` writes.
            ech_len: Some(90),
            server_name: Some("shop.test".to_string()),
        },
        "a GREASE hello still names the real host"
    );
    // A real ECH hello is large enough that it normally spans several records:
    // the parser has to put the fragments back together.
    let split = split_into_records(&patched, 700.min(patched.len() - 6));
    assert_eq!(
        first_flight(&split),
        Flight::Hello {
            ech_len: Some(90),
            server_name: Some("shop.test".to_string()),
        }
    );
}

#[test]
fn a_client_hello_can_be_told_from_garbage() {
    // A record that promises a hello but carries junk: nothing readable, and
    // no panic.
    let mut junk = vec![0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0, 0, 0, 0];
    assert_eq!(
        first_flight(&junk),
        Flight::Hello {
            ech_len: None,
            server_name: None,
        }
    );
    junk[5] = 0x02; // a ServerHello, not a ClientHello
    assert_eq!(first_flight(&junk), Flight::NotHello);
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
