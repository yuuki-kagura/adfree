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
fn handshake(server: &mut ServerConnection, client: &mut ClientConnection) {
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
fn the_log_reads_the_certificate_the_session_ended_up_with() {
    // The point of recording a certificate is that the user can see which name
    // the connection carried and who signed it — and on a MITM the signer is
    // our own CA, which is exactly the fact a "why does the browser trust
    // this?" question turns on.
    let ca = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("ca"));
    let mut server = server_using(Arc::clone(&ca));
    let cconfig = client_trusting(&ca);
    let name = rustls::pki_types::ServerName::try_from("origin.example.com".to_string())
        .expect("server name");
    let mut client = ClientConnection::new(cconfig, name).expect("client conn");
    handshake(&mut server, &mut client);

    let cert = peer_cert(&client).expect("the finished session has a leaf");
    assert_eq!(cert.subject, "origin.example.com");
    assert_eq!(cert.issuer, "AdFree Personal CA");
    assert!(cert.not_before_ms > 0);
    assert!(
        cert.not_after_ms > cert.not_before_ms,
        "a window that runs backwards is a parse that went wrong"
    );
}

#[test]
fn a_session_still_handshaking_has_no_certificate_to_report() {
    // Rows are written for refused requests too, and some of those never saw a
    // Certificate. An absent certificate has to stay absent in the log rather
    // than arrive as an empty name the UI would render as a blank row.
    let ca = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("ca"));
    let cconfig = client_trusting(&ca);
    let name = rustls::pki_types::ServerName::try_from("origin.example.com".to_string())
        .expect("server name");
    let client = ClientConnection::new(cconfig, name).expect("client conn");
    assert!(peer_cert(&client).is_none());
}

#[test]
fn spliced_body_survives_the_tls_round_trip() {    let ca = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("ca"));
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
    let restored = crate::mitm::ca::CertificateAuthority::from_pem(&ca.cert_pem(), &ca.key_pem())
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
        inner
            .issued_hosts()
            .iter()
            .any(|h| h == "captured.example.com"),
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
            alpn_http1: Some(true),
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

/// The MITM speaks HTTP/1.1 only, so the hello has to say whether the client
/// would accept it: Chrome's Secure DNS and gRPC list `h2` alone, and those
/// flows must go to the origin instead of failing the handshake.
#[test]
fn a_hello_reports_whether_it_offers_http1() {
    fn flight_for(alpn: Option<&[&[u8]]>) -> Vec<u8> {
        let mut config = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        if let Some(list) = alpn {
            config.alpn_protocols = list.iter().map(|p| p.to_vec()).collect();
        }
        let name =
            rustls::pki_types::ServerName::try_from("shop.test".to_string()).expect("server name");
        let mut client = ClientConnection::new(Arc::new(config), name).expect("client conn");
        take_client_outbound(&mut client)
    }
    fn http1(flight: &[u8]) -> Option<bool> {
        match first_flight(flight) {
            Flight::Hello { alpn_http1, .. } => alpn_http1,
            other => panic!("expected a hello, got {other:?}"),
        }
    }
    assert_eq!(http1(&flight_for(Some(&[b"h2"]))), Some(false));
    assert_eq!(http1(&flight_for(Some(&[b"h2", b"http/1.1"]))), Some(true));
    // No ALPN extension at all: nothing to judge, the MITM terminates as
    // before.
    assert_eq!(http1(&flight_for(None)), None);
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
            alpn_http1: Some(true),
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
            alpn_http1: Some(true),
        }
    );
}

#[test]
fn a_client_hello_can_be_told_from_garbage() {
    // A record that promises a hello but carries junk: nothing readable, and
    // no panic.
    let mut junk = vec![
        0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0, 0, 0, 0,
    ];
    assert_eq!(
        first_flight(&junk),
        Flight::Hello {
            ech_len: None,
            server_name: None,
            alpn_http1: None,
        }
    );
    junk[5] = 0x02; // a ServerHello, not a ClientHello
    assert_eq!(first_flight(&junk), Flight::NotHello);
}

/// Reads new plaintext from a client connection without draining old data.
fn feed_client_read_only(connection: &mut ClientConnection, cipher: &[u8]) -> Vec<u8> {
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
    connection
        .writer()
        .write_all(plaintext)
        .expect("server write");
    take_server_outbound(connection)
}

/// Encrypts a payload on the client side, returning the wire bytes.
fn send_from_client(connection: &mut ClientConnection, plaintext: &[u8]) -> Vec<u8> {
    connection
        .writer()
        .write_all(plaintext)
        .expect("client write");
    take_client_outbound(connection)
}

/// A syntactically valid ECHConfigList naming `public_name`, with a key no
/// server knows. Enough for rustls to build a real ECH offer.
fn ech_config_list(public_name: &str) -> Vec<u8> {
    let mut contents = Vec::new();
    contents.push(7); // config_id
    contents.extend_from_slice(&0x0020u16.to_be_bytes()); // DHKEM(X25519)
    contents.extend_from_slice(&32u16.to_be_bytes());
    contents.extend_from_slice(&[0x42; 32]); // HPKE public key
    contents.extend_from_slice(&4u16.to_be_bytes()); // cipher_suites length
    contents.extend_from_slice(&0x0001u16.to_be_bytes()); // HKDF-SHA256
    contents.extend_from_slice(&0x0001u16.to_be_bytes()); // AES-128-GCM
    contents.push(0); // maximum_name_length
    contents.push(public_name.len() as u8);
    contents.extend_from_slice(public_name.as_bytes());
    contents.extend_from_slice(&0u16.to_be_bytes()); // extensions

    let mut config = Vec::new();
    config.extend_from_slice(&0xfe0du16.to_be_bytes());
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);

    let mut list = Vec::new();
    list.extend_from_slice(&(config.len() as u16).to_be_bytes());
    list.extend_from_slice(&config);
    list
}

/// The upstream half armed with a host's ECHConfig must put a real offer on
/// the wire, with the config's public name as the visible SNI — that is what
/// keeps a host that requires ECH filterable.
#[test]
fn an_upstream_config_with_ech_offers_the_hosts_config() {
    let upstream = UpstreamTls::with_roots(rustls::RootCertStore::empty());
    let list = ech_config_list("cover.example.net");
    let config = upstream.with_ech(&list).expect("the suite is supported");
    let name = rustls::pki_types::ServerName::try_from("shop.example.com".to_string())
        .expect("server name");
    let mut client = ClientConnection::new(config, name).expect("client conn");

    let hello = take_client_outbound(&mut client);
    match first_flight(&hello) {
        Flight::Hello {
            ech_len: Some(len),
            server_name,
            ..
        } => {
            assert!(
                len > 100,
                "a real offer wraps the inner hello, got {len} bytes"
            );
            assert_eq!(
                server_name.as_deref(),
                Some("cover.example.net"),
                "the outer SNI is the config's public name"
            );
        }
        other => panic!("expected a complete ECH hello, got {other:?}"),
    }
    assert_eq!(
        client_ech_status(&client),
        rustls::client::EchStatus::Offered,
        "the offer is out and not yet answered"
    );

    // A list this build cannot speak is refused whole, never half-offered.
    assert!(upstream.with_ech(&[0x00, 0x00]).is_none());
    assert!(upstream.with_ech(&[]).is_none());
}

/// The rejection is detected through the string the flow logs: rustls has no
/// other accessor once `process_new_packets` has formatted the error.
#[test]
fn ech_rejection_is_recognized_in_the_formatted_error() {
    let observed = "client process_new_packets: peer is incompatible: \
                    ServerRejectedEncryptedClientHello(Some([V18(EchConfigPayload)]))";
    assert!(ech_rejected(observed));
    assert!(!ech_rejected(
        "client process_new_packets: peer is incompatible: Tls12NotOffered"
    ));
    assert!(!ech_rejected(
        "client process_new_packets: peer sent no certificates"
    ));
}

/// Roots for a live check on a developer machine: the device store when it is
/// there, the host's PEM bundle otherwise.
#[cfg(test)]
fn live_roots() -> rustls::RootCertStore {
    let mut store = system_root_store();
    if store.is_empty() {
        for path in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ] {
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            for cert in rustls_pemfile::read_all(&mut std::io::Cursor::new(&bytes)).flatten() {
                if let rustls_pemfile::Item::X509Certificate(der) = cert {
                    store.add(CertificateDer::from(der.to_vec())).ok();
                }
            }
        }
    }
    store
}

/// Not part of the normal run: this needs the network, so it is `#[ignore]`d.
/// It is the only way to see the one path no local server can produce — a real
/// ECH rejection, followed by the plain retry that is supposed to recover:
///
///     cargo test --lib ech_rejection_from_a_real_server -- --ignored \
///         --nocapture
#[test]
#[ignore = "needs the network"]
fn ech_rejection_from_a_real_server_recovers_with_a_plain_retry() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let host = "tls-ech.dev";
    let upstream = UpstreamTls::with_roots(live_roots());
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).expect("server name");

    // A well-formed config the server cannot decrypt: not one of its own.
    let config = upstream
        .with_ech(&ech_config_list(host))
        .expect("the suite is supported");
    let mut client = ClientConnection::new(config, name.clone()).expect("client conn");
    let mut sock = TcpStream::connect((host, 443)).expect("connect");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .expect("timeout");
    sock.write_all(&take_client_outbound(&mut client))
        .expect("client hello");

    let mut buf = [0u8; 16 * 1024];
    let mut rejection = None;
    for _ in 0..12 {
        let n = sock.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        match feed_client_wire(&mut client, &buf[..n]) {
            Ok(_) => {
                let out = take_client_outbound(&mut client);
                if !out.is_empty() {
                    sock.write_all(&out).expect("client flight");
                }
            }
            Err(e) => {
                rejection = Some(e);
                break;
            }
        }
    }
    let rejection = rejection.expect("the server must reject a config it never published");
    assert!(ech_rejected(&rejection), "unexpected error: {rejection}");

    // The recovery: the same host, a plain handshake, no ECH.
    let mut plain = ClientConnection::new(upstream.plain(), name).expect("plain conn");
    let mut sock = TcpStream::connect((host, 443)).expect("connect again");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .expect("timeout");
    sock.write_all(&take_client_outbound(&mut plain))
        .expect("plain hello");
    for _ in 0..12 {
        if !client_handshaking(&plain) {
            break;
        }
        let n = sock.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        for byte in feed_client_wire(&mut plain, &buf[..n]).expect("plain handshake") {
            let _ = byte;
        }
        let out = take_client_outbound(&mut plain);
        if !out.is_empty() {
            sock.write_all(&out).expect("plain flight");
        }
    }
    assert!(!client_handshaking(&plain), "the plain retry must complete");
    assert_eq!(
        client_ech_status(&plain),
        rustls::client::EchStatus::NotOffered
    );

    plain
        .writer()
        .write_all(b"GET / HTTP/1.1\r\nHost: tls-ech.dev\r\nConnection: close\r\n\r\n")
        .expect("request");
    sock.write_all(&take_client_outbound(&mut plain))
        .expect("encrypted request");
    let mut seen = Vec::new();
    for _ in 0..16 {
        let n = sock.read(&mut buf).expect("read response");
        if n == 0 {
            break;
        }
        for byte in feed_client_wire(&mut plain, &buf[..n]).expect("response") {
            seen.push(byte);
        }
        if seen.windows(12).any(|w| w == b"HTTP/1.1 200") {
            break;
        }
    }
    assert!(
        seen.windows(12).any(|w| w == b"HTTP/1.1 200"),
        "the plain retry must serve the page: {:?}",
        String::from_utf8_lossy(&seen[..seen.len().min(200)])
    );
}

/// Queries `name`'s HTTPS record through the host's own resolver, the way the
/// engine's DNS half sees it.
#[cfg(test)]
fn https_record(name: &str) -> Vec<u8> {
    use std::net::{IpAddr, SocketAddr, UdpSocket};

    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&65u16.to_be_bytes()); // HTTPS
    query.extend_from_slice(&1u16.to_be_bytes()); // IN

    let server = std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("nameserver ")
                    .and_then(|addr| addr.trim().parse::<IpAddr>().ok())
            })
        })
        .expect("a resolver in /etc/resolv.conf");
    let socket = UdpSocket::bind("0.0.0.0:0").expect("udp socket");
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("timeout");
    socket
        .send_to(&query, SocketAddr::new(server, 53))
        .expect("send query");
    let mut buf = [0u8; 8192];
    let n = socket.recv(&mut buf).expect("receive answer");
    buf[..n].to_vec()
}

/// The accepted path, end to end and by hand: the config is learned from the
/// host's real HTTPS record (the same parse the engine uses), offered upstream,
/// and the origin confirms it with `ECH-Accepted: 1`. Run with:
///
///     cargo test --lib a_real_host_accepts_the_dns_learned_config \
///         -- --ignored --nocapture
#[test]
#[ignore = "needs the network"]
fn a_real_host_accepts_the_dns_learned_config() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let host = "tls-ech.dev";
    let answer = https_record(host);
    let list = crate::dns::ech_config_list(&answer).expect("the host advertises ECH");
    let public = crate::dns::ech_public_name(&answer).expect("the config names a public name");
    assert_ne!(
        public, host,
        "the outer name must differ from the inner one"
    );

    let upstream = UpstreamTls::with_roots(live_roots());
    let config = upstream.with_ech(&list).expect("the list names our suite");
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).expect("server name");
    let mut client = ClientConnection::new(config, name).expect("client conn");
    let hello = take_client_outbound(&mut client);
    match first_flight(&hello) {
        Flight::Hello {
            ech_len: Some(_),
            server_name,
            ..
        } => assert_eq!(server_name.as_deref(), Some(public.as_str())),
        other => panic!("expected a real ECH hello, got {other:?}"),
    }

    let mut sock = TcpStream::connect((host, 443)).expect("connect");
    sock.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .expect("timeout");
    sock.write_all(&hello).expect("client hello");
    let mut buf = [0u8; 16 * 1024];
    let mut plain = Vec::new();
    for _ in 0..12 {
        if !client_handshaking(&client) {
            break;
        }
        let n = sock.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        plain.extend(feed_client_wire(&mut client, &buf[..n]).expect("handshake"));
        let out = take_client_outbound(&mut client);
        if !out.is_empty() {
            sock.write_all(&out).expect("client flight");
        }
    }
    assert!(
        !client_handshaking(&client),
        "the ECH handshake must finish"
    );
    assert_eq!(
        client_ech_status(&client),
        rustls::client::EchStatus::Accepted,
        "the origin must accept the offer"
    );

    client
        .writer()
        .write_all(b"GET / HTTP/1.1\r\nHost: tls-ech.dev\r\nConnection: close\r\n\r\n")
        .expect("request");
    sock.write_all(&take_client_outbound(&mut client))
        .expect("encrypted request");
    let mut seen = Vec::new();
    for _ in 0..16 {
        let n = sock.read(&mut buf).expect("read response");
        if n == 0 {
            break;
        }
        seen.extend(feed_client_wire(&mut client, &buf[..n]).expect("response"));
        if seen.windows(12).any(|w| w == b"HTTP/1.1 200") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&seen);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "the page must load through the terminator: {head}"
    );
    assert!(
        head.to_ascii_lowercase().contains("ech-accepted: 1"),
        "the origin must confirm ECH: {head}"
    );
}
