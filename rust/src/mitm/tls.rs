//! TLS termination with rustls.
//!
//! Every MITM flow needs two TLS endpoints:
//!
//! ```text
//!   client ──TLS(forged cert)──▶ app ──TLS(real)──▶ server
//!            ServerConnection              ClientConnection
//! ```
//!
//! [`ServerConnection`] takes the client's ciphertext and yields plaintext we may
//! edit; [`ClientConnection`] re-encrypts that plaintext for the real server over
//! a socket that was `protect()`ed. Everything uses rustls' *synchronous* API
//! (`read_tls` / `process_new_packets` / `write_tls`) so it slots straight into
//! the TUN relay without an async runtime.
//!
//! Two traps this module is built around:
//! * `process_new_packets()` must run after every `read_tls()`, otherwise no
//!   plaintext ever appears;
//! * rustls' `Connection` is an *enum* in 0.23, not a trait, so helpers are
//!   generated per direction rather than written generically.
//!
//! The leaf certificate is chosen by [`SniCertResolver`] when the ClientHello
//! arrives, which is the only moment the SNI is known — that avoids parsing the
//! handshake by hand.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

/// ALPN we offer: HTTP/1.1 first. HTTP/2 support is a later stage.
pub const ALPN_H1: &[u8] = b"http/1.1";

/// The two halves of one intercepted flow.
pub struct TlsSession {
    pub server: ServerConnection,
    pub client: ClientConnection,
}

/// One flow's view of the shared resolver: mints the same leaves, but keeps
/// the last SNI rustls parsed.
///
/// The upstream half cannot open before the client's ClientHello lands (that
/// is where the hostname comes from), and rustls hands that hostname to the
/// certificate resolver at exactly that moment. Wrapping the engine's resolver
/// per flow therefore captures the SNI without parsing the handshake by hand.
pub struct FlowResolver {
    inner: Arc<SniCertResolver>,
    captured: Mutex<Option<String>>,
}

impl FlowResolver {
    pub fn new(inner: Arc<SniCertResolver>) -> Arc<Self> {
        Arc::new(FlowResolver {
            inner,
            captured: Mutex::new(None),
        })
    }

    /// The SNI the client asked for, if its ClientHello has arrived.
    pub fn captured(&self) -> Option<String> {
        self.captured.lock().ok().and_then(|slot| slot.clone())
    }
}

impl std::fmt::Debug for FlowResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FlowResolver")
    }
}

impl ResolvesServerCert for FlowResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            if let Ok(mut slot) = self.captured.lock() {
                *slot = Some(name.to_string());
            }
        }
        self.inner.resolve(client_hello)
    }
}

/// Resolves the leaf for whatever SNI the client asked for.
///
/// We only learn the hostname when the ClientHello lands, so the resolver is the
/// right place to mint a certificate: rustls asks for it at exactly that moment.
pub struct SniCertResolver {
    ca: Arc<crate::mitm::ca::CertificateAuthority>,
    /// Hosts minted so far, for the UI's "certificates issued" counter.
    issued: Mutex<Vec<String>>,
}

impl SniCertResolver {
    pub fn new(ca: Arc<crate::mitm::ca::CertificateAuthority>) -> Self {
        SniCertResolver {
            ca,
            issued: Mutex::new(Vec::new()),
        }
    }

    /// Hosts this resolver has signed a leaf for.
    pub fn issued_hosts(&self) -> Vec<String> {
        self.issued.lock().unwrap().clone()
    }
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SniCertResolver")
    }
}

impl SniCertResolver {
    /// The leaf for one hostname, minted from the app's CA.
    ///
    /// `host` may be a DNS name or an address literal: the local injection
    /// origin is reached through a reserved IPv4 address (browsers put no SNI
    /// on the wire for one), and rcgen puts an address in the IP SAN when the
    /// string parses as one.
    fn cert_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let issued = self.ca.issue(host).ok()?;
        let chain = self.ca.chain_for(&issued);
        let key = crate::mitm::ca::private_key_der(&issued);

        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).ok()?;
        let certified = Arc::new(CertifiedKey::new(
            chain
                .into_iter()
                .map(CertificateDer::from)
                .collect::<Vec<_>>(),
            signing_key,
        ));
        if let Ok(mut issued) = self.issued.lock() {
            if !issued.iter().any(|h| h == host) {
                issued.push(host.to_string());
            }
        }
        Some(certified)
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        self.cert_for(name)
    }
}

/// Resolves the leaf for one fixed host, whatever the ClientHello says.
///
/// The local injection origin is an address literal (no SNI is sent for one),
/// so a session that serves it cannot key its certificate off the hello.
pub struct FixedCertResolver {
    inner: Arc<SniCertResolver>,
    host: String,
}

impl FixedCertResolver {
    pub fn new(inner: Arc<SniCertResolver>, host: impl Into<String>) -> Arc<Self> {
        Arc::new(FixedCertResolver {
            inner,
            host: host.into(),
        })
    }
}

impl std::fmt::Debug for FixedCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FixedCertResolver")
    }
}

impl ResolvesServerCert for FixedCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.inner.cert_for(&self.host)
    }
}

/// Loads the device's CA roots from disk.
///
/// Android ships its trust anchors as PEM files; reading them directly avoids
/// depending on the JVM's own store, which this library cannot see.
pub fn system_root_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    for dir in [
        "/system/etc/security/cacerts",
        "/apex/com.android.conscrypt/cacerts",
    ] {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            for cert in rustls_pemfile::read_all(&mut std::io::Cursor::new(&bytes)).flatten() {
                if let rustls_pemfile::Item::X509Certificate(der) = cert {
                    store
                        .add(CertificateDer::from(der.to_vec()))
                        .ok();
                }
            }
        }
    }
    store
}

/// Client config used to talk to the real server (normal verification).
pub fn client_config() -> Arc<ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| client_config_with(system_root_store()))
        .clone()
}

/// A client config with an explicit root set: the real server's certificate
/// must chain to one of `roots`. Split out so tests can stand in a server of
/// their own without touching the device's trust store.
pub fn client_config_with(roots: rustls::RootCertStore) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H1.to_vec()];
    Arc::new(config)
}

/// Server config that asks [`SniCertResolver`] for the leaf per connection.
pub fn server_config(resolver: Arc<SniCertResolver>) -> Arc<ServerConfig> {
    server_config_dyn(resolver)
}

/// Server config bound to one host, for connections that carry no SNI (the
/// local injection origin is reached through an address literal).
pub fn server_config_fixed(resolver: Arc<SniCertResolver>, host: &str) -> Arc<ServerConfig> {
    server_config_dyn(FixedCertResolver::new(resolver, host))
}

/// Server config with any per-connection resolver: the engine passes a
/// [`FlowResolver`] wrapper so the ClientHello's SNI is captured per flow.
pub fn server_config_dyn(resolver: Arc<dyn ResolvesServerCert>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![ALPN_H1.to_vec()];
    Arc::new(config)
}

/// One server half, waiting for the client's ClientHello.
pub fn new_server(config: Arc<ServerConfig>) -> Result<ServerConnection, String> {
    ServerConnection::new(config).map_err(|e| format!("server conn: {e}"))
}

/// The upstream half for `real_server`: the name goes out as SNI and anchors
/// certificate verification.
pub fn new_client(
    upstream_config: Arc<ClientConfig>,
    real_server: &str,
) -> Result<ClientConnection, String> {
    let name = rustls::pki_types::ServerName::try_from(real_server.to_string())
        .map_err(|e| format!("server name: {e}"))?;
    ClientConnection::new(upstream_config, name).map_err(|e| format!("client conn: {e}"))
}

/// Opens both halves for a flow towards `real_server`.
pub fn open_session(resolver: &Arc<SniCertResolver>, real_server: &str) -> Result<TlsSession, String> {
    open_session_with(resolver, real_server, client_config())
}

/// Like [`open_session`], but the upstream half verifies against the caller's
/// own client config instead of the device trust store.
pub fn open_session_with(
    resolver: &Arc<SniCertResolver>,
    real_server: &str,
    upstream_config: Arc<ClientConfig>,
) -> Result<TlsSession, String> {
    let server = new_server(server_config(Arc::clone(resolver)))?;
    let client = new_client(upstream_config, real_server)?;

    Ok(TlsSession { server, client })
}

/// `Connection` is an enum, so one macro generates the per-side plumbing.
macro_rules! connection_helpers {
    ($drain:ident, $drain_into:ident, $take:ident, $conn:ty) => {
        /// Drains decrypted plaintext into `out`, returning how many bytes
        /// were appended.
        pub fn $drain_into(connection: &mut $conn, out: &mut Vec<u8>) -> usize {
            let start = out.len();
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = connection.reader().read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                if out.len() - start > 1024 * 1024 {
                    break; // bound memory: this is a filter, not a data plane
                }
            }
            out.len() - start
        }

        /// Drains whatever plaintext this connection has already decrypted.
        pub fn $drain(connection: &mut $conn) -> Vec<u8> {
            let mut out = Vec::new();
            $drain_into(connection, &mut out);
            out
        }

        /// Takes every byte this connection wants to put on the wire.
        pub fn $take(connection: &mut $conn) -> Vec<u8> {
            let mut out = Vec::new();
            let _ = connection.write_tls(&mut out);
            out
        }
    };
}

connection_helpers!(
    drain_server_plain,
    drain_server_plain_into,
    take_server_outbound,
    ServerConnection
);
connection_helpers!(
    drain_client_plain,
    drain_client_plain_into,
    take_client_outbound,
    ClientConnection
);

/// Feeds wire bytes from the client into `ServerConnection`, returning the
/// plaintext that was decrypted.
///
/// rustls reports backpressure as `ErrorKind::Other` ("received plaintext
/// buffer full", a 16 KiB cap) and pauses decryption once that buffer fills;
/// draining after every record is what lets a large burst through. Treating
/// the signal as fatal used to reset flows mid-response.
pub fn feed_server(connection: &mut ServerConnection, chunk: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = std::io::Cursor::new(chunk);
    let mut out = Vec::new();
    loop {
        match connection.read_tls(&mut reader) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                // Only the buffer-full signal is recoverable: drain and retry.
                let drained = drain_server_plain_into(connection, &mut out);
                if drained == 0 || e.kind() != std::io::ErrorKind::Other {
                    return Err(format!("read_tls: {e}"));
                }
                continue;
            }
        }
        if let Err(e) = connection.process_new_packets() {
            return Err(format!("process_new_packets: {e}"));
        }
        drain_server_plain_into(connection, &mut out);
        if out.len() > 1024 * 1024 {
            break;
        }
    }
    Ok(out)
}

/// Feeds wire bytes from the real server into `ClientConnection`, returning the
/// plaintext that was decrypted.
///
/// This is the peer-direction mirror of [`feed_server`]: handshake records and
/// encrypted application data must go through `read_tls`/`process_new_packets`,
/// never through `writer()` (which would try to encrypt them again).
pub fn feed_client_wire(
    connection: &mut ClientConnection,
    chunk: &[u8],
) -> Result<Vec<u8>, String> {
    let mut reader = std::io::Cursor::new(chunk);
    let mut out = Vec::new();
    loop {
        match connection.read_tls(&mut reader) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                // Mirror of `feed_server`: the 16 KiB plaintext cap reports
                // backpressure as an `Other` error, not a fatal condition.
                let drained = drain_client_plain_into(connection, &mut out);
                if drained == 0 || e.kind() != std::io::ErrorKind::Other {
                    return Err(format!("client read_tls: {e}"));
                }
                continue;
            }
        }
        if let Err(e) = connection.process_new_packets() {
            return Err(format!("client process_new_packets: {e}"));
        }
        drain_client_plain_into(connection, &mut out);
        if out.len() > 1024 * 1024 {
            break;
        }
    }
    Ok(out)
}

/// Encrypts `plaintext` on `ClientConnection` and returns the wire bytes to send
/// to the real server.
pub fn feed_client(
    connection: &mut ClientConnection,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    if plaintext.is_empty() {
        return Ok(Vec::new());
    }
    write_plaintext_draining(plaintext, |chunk| {
        let written = connection
            .writer()
            .write(chunk)
            .map_err(|e| format!("write plaintext: {e}"))?;
        Ok((written, take_client_outbound(connection)))
    })
}

/// Re-encrypts (possibly edited) plaintext on `ServerConnection` for the client.
pub fn send_to_client(
    connection: &mut ServerConnection,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    if plaintext.is_empty() {
        return Ok(Vec::new());
    }
    write_plaintext_draining(plaintext, |chunk| {
        let written = connection
            .writer()
            .write(chunk)
            .map_err(|e| format!("write plaintext: {e}"))?;
        Ok((written, take_server_outbound(connection)))
    })
}

/// Feeds `plaintext` to `write_chunk`, draining records between chunks.
///
/// rustls caps its unsent-record buffer (64 KiB by default) and `write` only
/// accepts what the cap leaves: a single `write_all` of a larger body (the
/// stitched userscript is ~600 KB) stalls at the cap and dies with
/// `WriteZero`. Draining after every accepted chunk empties the buffer again,
/// so the whole body is encrypted and every record ends up in the result.
fn write_plaintext_draining(
    plaintext: &[u8],
    mut write_chunk: impl FnMut(&[u8]) -> Result<(usize, Vec<u8>), String>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut rest = plaintext;
    while !rest.is_empty() {
        let (written, drained) = write_chunk(rest)?;
        out.extend(drained);
        if written == 0 {
            // The drain should have freed the buffer; a refusal here would
            // otherwise loop forever.
            return Err("write plaintext: send buffer full".into());
        }
        rest = &rest[written..];
    }
    Ok(out)
}

/// Is the server half still handshaking?
pub fn server_handshaking(connection: &ServerConnection) -> bool {
    connection.is_handshaking()
}

/// Is the client half still handshaking?
pub fn client_handshaking(connection: &ClientConnection) -> bool {
    connection.is_handshaking()
}

/// The ALPN protocol negotiated on a server connection.
pub fn server_alpn(connection: &ServerConnection) -> Option<Vec<u8>> {
    connection.alpn_protocol().map(|p| p.to_vec())
}

