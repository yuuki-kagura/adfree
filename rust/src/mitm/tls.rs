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

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

/// ALPN we offer: HTTP/1.1 first. HTTP/2 support is a later stage.
pub const ALPN_H1: &[u8] = b"http/1.1";

/// ALPN for HTTP/3. QUIC runs the same TLS 1.3 handshake; only the protocol
/// name on the wire differs.
pub const ALPN_H3: &[u8] = b"h3";

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
}

impl SniCertResolver {
    pub fn new(ca: Arc<crate::mitm::ca::CertificateAuthority>) -> Self {
        SniCertResolver { ca }
    }

    /// Hosts this resolver has signed a leaf for.
    ///
    /// The CA's cache already holds exactly one entry per host, so a second
    /// list here would only be a linear-scan price paid on every handshake.
    pub fn issued_hosts(&self) -> Vec<String> {
        self.ca.cached_host_names()
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
/// depending on the JVM's own store, which this library cannot see. The desktop
/// keeps the same shape — a PEM bundle the distribution maintains — so one
/// reader covers both, and an engine with no anchors says so instead of failing
/// every HTTPS session with a certificate error the user cannot interpret.
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
            add_pem_file(&entry.path(), &mut store);
        }
    }
    // The usual places a Linux or macOS box keeps the extracted bundle. Every
    // distribution names its own; the first that exists wins, and reading the
    // rest only ever adds anchors.
    for file in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/cert.pem",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/ca-bundle.pem",
        "/usr/local/share/certs/ca-root-nss.crt",
    ] {
        add_pem_file(std::path::Path::new(file), &mut store);
    }
    if store.is_empty() {
        crate::logbuf::push(
            "mitm: no trust anchors found; HTTPS filtering cannot verify servers \
             until the system CA bundle is readable",
        );
    }
    store
}

/// Adds every certificate one PEM file carries (a bundle holds hundreds).
fn add_pem_file(path: &std::path::Path, store: &mut rustls::RootCertStore) {
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    for cert in rustls_pemfile::read_all(&mut std::io::Cursor::new(&bytes)).flatten() {
        if let rustls_pemfile::Item::X509Certificate(der) = cert {
            store.add(CertificateDer::from(der.to_vec())).ok();
        }
    }
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

/// The QUIC variant of [`client_config_with`]: same trust anchors, negotiated
/// as `h3`.
pub fn client_config_h3_with(roots: rustls::RootCertStore) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Arc::new(config)
}

/// The upstream TLS settings of one engine: the plain client config, the root
/// store it was built from, and the per-host ECH configs built from it.
///
/// rustls only accepts ECH through the builder (`with_ech` sits on the versions
/// stage), so a config carrying one host's ECHConfigList has to be built next
/// to the plain one. Keeping the roots here is what makes that possible without
/// re-reading the device store per connection.
pub struct UpstreamTls {
    roots: rustls::RootCertStore,
    plain: Arc<ClientConfig>,
    ech: Mutex<HashMap<Vec<u8>, Arc<ClientConfig>>>,
}

/// How many per-host ECH configs to keep built: one per distinct ECHConfigList,
/// a handful in practice (`defo.ie` alone offers three configs in one list).
const ECH_CONFIG_CAP: usize = 16;

impl UpstreamTls {
    /// The device trust store, loaded once.
    pub fn system() -> Arc<UpstreamTls> {
        static CONFIG: std::sync::OnceLock<Arc<UpstreamTls>> = std::sync::OnceLock::new();
        CONFIG
            .get_or_init(|| UpstreamTls::with_roots(system_root_store()))
            .clone()
    }

    /// The same, with an explicit root set: tests stand in their own server.
    pub fn with_roots(roots: rustls::RootCertStore) -> Arc<UpstreamTls> {
        let plain = client_config_with(roots.clone());
        Arc::new(UpstreamTls {
            roots,
            plain,
            ech: Mutex::new(HashMap::new()),
        })
    }

    /// The client config for a host with no ECHConfig on offer.
    pub fn plain(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.plain)
    }

    /// The QUIC client config: the same roots, negotiated as `h3`.
    ///
    /// ECH is not offered here: QUIC's handshake changes the record framing
    /// and the ECH path in rustls only covers the TCP configuration today.
    pub fn plain_h3(&self) -> Arc<ClientConfig> {
        client_config_h3_with(self.roots.clone())
    }

    /// A client config that offers `list` — the raw ECHConfigList from the
    /// host's HTTPS record, 2-byte length included — in its ClientHello.
    ///
    /// `None` when no config in the list names a suite this build speaks (see
    /// [`crate::mitm::hpke`]): the caller then falls back to [`Self::plain`].
    pub fn with_ech(&self, list: &[u8]) -> Option<Arc<ClientConfig>> {
        if let Some(cached) = self.ech.lock().unwrap().get(list) {
            return Some(Arc::clone(cached));
        }
        let config = self.build_ech_config(list)?;
        let mut cache = self.ech.lock().unwrap();
        if cache.len() >= ECH_CONFIG_CAP {
            cache.clear();
        }
        cache.insert(list.to_vec(), Arc::clone(&config));
        Some(config)
    }

    fn build_ech_config(&self, list: &[u8]) -> Option<Arc<ClientConfig>> {
        let ech = rustls::client::EchConfig::new(list.into(), crate::mitm::hpke::SUITES).ok()?;
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_ech(rustls::client::EchMode::Enable(ech))
                .ok()?
                .with_root_certificates(self.roots.clone())
                .with_no_client_auth();
        config.alpn_protocols = vec![ALPN_H1.to_vec()];
        Some(Arc::new(config))
    }
}

/// Did this upstream handshake fail because the server rejected the ECH offer?
///
/// rustls' typed error (`PeerIncompatible::ServerRejectedEncryptedClientHello`)
/// is formatted into the flow's error string at the TLS boundary, and the
/// variant name survives that. One retry without ECH is the recovery RFC 9849
/// describes — on a fresh connection, since the rejected one cannot continue.
pub fn ech_rejected(error: &str) -> bool {
    error.contains("ServerRejectedEncryptedClientHello")
}

/// What the upstream handshake did with ECH, for the engine's log.
pub fn client_ech_status(connection: &ClientConnection) -> rustls::client::EchStatus {
    connection.ech_status()
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

/// The QUIC variant of [`server_config_dyn`]: same resolver, `h3` negotiated.
///
/// The resolver still signs the leaf from the ClientHello's SNI; QUIC only
/// changes the framing around the same TLS 1.3 handshake.
pub fn server_config_h3(resolver: Arc<dyn ResolvesServerCert>) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
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
pub fn open_session(
    resolver: &Arc<SniCertResolver>,
    real_server: &str,
) -> Result<TlsSession, String> {
    open_session_with(resolver, real_server, UpstreamTls::system())
}

/// Like [`open_session`], but the upstream half verifies against the caller's
/// own upstream settings instead of the device trust store.
pub fn open_session_with(
    resolver: &Arc<SniCertResolver>,
    real_server: &str,
    upstream: Arc<UpstreamTls>,
) -> Result<TlsSession, String> {
    let server = new_server(server_config(Arc::clone(resolver)))?;
    let client = new_client(upstream.plain(), real_server)?;

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
pub fn feed_client(connection: &mut ClientConnection, plaintext: &[u8]) -> Result<Vec<u8>, String> {
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

/// What the upstream half settled on, for the log: a version code from
/// [`crate::events::tls_ver`] and the cipher suite's own name.
///
/// Both are unknown until the server has answered the handshake, and rustls
/// negotiates nothing below TLS 1.2, so those two codes are the whole range a
/// session can report.
pub fn negotiated(client: &ClientConnection) -> (u8, &'static str) {
    let version = match client.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_2) => crate::events::tls_ver::TLS12,
        Some(rustls::ProtocolVersion::TLSv1_3) => crate::events::tls_ver::TLS13,
        _ => crate::events::tls_ver::NONE,
    };
    let cipher = client
        .negotiated_cipher_suite()
        .and_then(|suite| suite.suite().as_str())
        .unwrap_or("");
    (version, cipher)
}

/// What the server's certificate said about itself, for the log.
///
/// rustls has already run the chain against its root store by the time it
/// hands the leaf over, so this is not a check. It is the answer to the
/// question a filtering log is uniquely placed to ask: which name did this
/// connection actually present, and who signed the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCert {
    pub subject: String,
    pub issuer: String,
    /// Validity window in epoch milliseconds — coarse on purpose, the log
    /// prints a date and never a time of day.
    pub not_before_ms: i64,
    pub not_after_ms: i64,
}

/// Reads the leaf the upstream server presented.
///
/// `None` while the handshake is still open, and for a peer that sent no
/// certificate at all — a spliced TCP flow never has one.
pub fn peer_cert(client: &ClientConnection) -> Option<PeerCert> {
    let der = client.peer_certificates()?.first()?.as_ref();
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(der).ok()?;
    let tbs = &cert.tbs_certificate;
    Some(PeerCert {
        subject: party_name(&tbs.subject),
        issuer: party_name(&tbs.issuer),
        not_before_ms: tbs.validity.not_before.timestamp() * 1000,
        not_after_ms: tbs.validity.not_after.timestamp() * 1000,
    })
}

/// The one attribute of a distinguished name that says who the party is.
///
/// A full DN runs past 200 bytes and its trailing attributes (country, state,
/// locality) add nothing a user acts on, so the log keeps the common name and
/// falls back through the attributes that also name an organization.
fn party_name(name: &x509_parser::x509::X509Name<'_>) -> String {
    if let Some(cn) = name.iter_common_name().find_map(|attr| attr.as_str().ok()) {
        return cn.to_string();
    }
    if let Some(org) = name
        .iter_organization()
        .find_map(|attr| attr.as_str().ok())
    {
        return org.to_string();
    }
    if let Some(unit) = name
        .iter_organizational_unit()
        .find_map(|attr| attr.as_str().ok())
    {
        return unit.to_string();
    }
    if let Some(any) = name.iter_attributes().find_map(|attr| attr.as_str().ok()) {
        return any.to_string();
    }
    name.to_string()
}

/// The ALPN protocol negotiated on a server connection.
pub fn server_alpn(connection: &ServerConnection) -> Option<Vec<u8>> {
    connection.alpn_protocol().map(|p| p.to_vec())
}

/// Extension type 0xfe0d, `encrypted_client_hello` (RFC 9849, RFC 9460
/// Table 1 for the `ech` SvcParam it is built from).
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// Extension type 0x0000, `server_name`.
const EXT_SERVER_NAME: u16 = 0x0000;

/// Extension type 0x0010, `application_layer_protocol_negotiation`.
const EXT_ALPN: u16 = 0x0010;

/// What the first flight of a connection holds.
#[derive(Debug, PartialEq, Eq)]
pub enum Flight {
    /// Not enough bytes yet: TLS records fragment the hello, and a real ECH
    /// one is large enough to span more than one.
    Pending,
    /// The first handshake message is not a ClientHello.
    NotHello,
    /// A complete ClientHello.
    Hello {
        /// The body length of the `encrypted_client_hello` extension, when the
        /// hello carries one. A real ECH offer hides an encrypted ClientHello
        /// in there (hundreds of bytes); the GREASE browsers send on ordinary
        /// connections carries a short dummy.
        ech_len: Option<usize>,
        /// The name the hello exposes: the real host for an ordinary hello,
        /// the ECH public name for a real ECH one, `None` without an SNI.
        server_name: Option<String>,
        /// Whether the hello's ALPN list includes `http/1.1`, the only
        /// protocol the MITM speaks. `None` when the hello carries no ALPN
        /// extension at all: those are terminated as before.
        alpn_http1: Option<bool>,
    },
}

/// Reads the head of a connection's first flight without feeding it to
/// rustls.
///
/// The proxy has to decide *before* it terminates: browsers attach a GREASE
/// `encrypted_client_hello` extension to ordinary connections, rustls ignores
/// it, and the hello terminates as usual — but a real ECH hello exposes only
/// the config's public name, and terminating it can only serve a certificate
/// for the wrong host. Telling the two apart takes the outer name, which is
/// why both come out of one parse; [`crate::mitm::ech`] owns which names get
/// spliced.
pub fn first_flight(bytes: &[u8]) -> Flight {
    let mut handshake = Vec::new();
    let mut off = 0usize;
    loop {
        let Some(header) = bytes.get(off..off + 5) else {
            return Flight::Pending;
        };
        if header[0] != 0x16 {
            // Not a handshake record: no ClientHello to read.
            return Flight::NotHello;
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let Some(end) = off.checked_add(5 + len) else {
            return Flight::Pending;
        };
        let Some(record) = bytes.get(off + 5..end) else {
            return Flight::Pending;
        };
        handshake.extend_from_slice(record);
        off = end;
        if handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return Flight::NotHello;
            }
            let len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | handshake[3] as usize;
            if let Some(body) = handshake.get(4..4 + len) {
                let Some(extensions) = client_hello_extensions(body) else {
                    return Flight::Hello {
                        ech_len: None,
                        server_name: None,
                        alpn_http1: None,
                    };
                };
                return Flight::Hello {
                    ech_len: extension(extensions, EXT_ENCRYPTED_CLIENT_HELLO)
                        .map(|body| body.len()),
                    server_name: server_name_of(extensions),
                    alpn_http1: extension(extensions, EXT_ALPN)
                        .map(|list| alpn_offers(list, ALPN_H1)),
                };
            }
        }
        if off == bytes.len() {
            return Flight::Pending;
        }
    }
}

/// The host name a ClientHello exposes, lowercased like every other name the
/// core compares.
fn server_name_of(extensions: &[u8]) -> Option<String> {
    // server_name_list: a 2-byte length, then one type(1) + host_name
    // (2-byte length + bytes) entry. Only host_name exists today.
    let list = extension(extensions, EXT_SERVER_NAME)?;
    let len = u16::from_be_bytes([*list.first()?, *list.get(1)?]) as usize;
    let end = 2 + len;
    if end > list.len() || *list.get(2)? != 0 {
        return None;
    }
    let name_len = u16::from_be_bytes([*list.get(3)?, *list.get(4)?]) as usize;
    let name = list.get(5..5 + name_len)?;
    std::str::from_utf8(name)
        .ok()
        .map(|n| n.to_ascii_lowercase())
}

/// Does an `application_layer_protocol_negotiation` body list `wanted`?
///
/// The body is a 2-byte list length followed by 1-byte-length names.
fn alpn_offers(list: &[u8], wanted: &[u8]) -> bool {
    let mut off = 2;
    while off < list.len() {
        let Some(len) = list.get(off) else {
            return false;
        };
        let len = *len as usize;
        let Some(proto) = list.get(off + 1..off + 1 + len) else {
            return false;
        };
        if proto == wanted {
            return true;
        }
        off += 1 + len;
    }
    false
}

/// One extension's body out of a ClientHello extension block.
fn extension(extensions: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut off = 0usize;
    while off + 4 <= extensions.len() {
        let key = u16::from_be_bytes([extensions[off], extensions[off + 1]]);
        let len = u16::from_be_bytes([extensions[off + 2], extensions[off + 3]]) as usize;
        let end = off.checked_add(4 + len)?;
        if end > extensions.len() {
            return None;
        }
        if key == wanted {
            return Some(&extensions[off + 4..end]);
        }
        off = end;
    }
    None
}

/// The extension block of a ClientHello body, if the fixed fields add up.
fn client_hello_extensions(hello: &[u8]) -> Option<&[u8]> {
    // legacy_version(2) + random(32), then three length-prefixed lists, then
    // the extension block: the end of the hello is the end of its extensions.
    let mut off = 2 + 32;
    let session = *hello.get(off)? as usize;
    off += 1 + session;
    let suites = u16::from_be_bytes([*hello.get(off)?, *hello.get(off + 1)?]) as usize;
    off += 2 + suites;
    let compression = *hello.get(off)? as usize;
    off += 1 + compression;
    let len = u16::from_be_bytes([*hello.get(off)?, *hello.get(off + 1)?]) as usize;
    off += 2;
    hello.get(off..off.checked_add(len)?)
}

/// A ClientHello record with an `encrypted_client_hello` extension appended.
///
/// The test build cannot ask rustls for a real ECH hello: the ECH client modes
/// need an HPKE provider this crate does not compile in (`ring` has none), and
/// a hand-rolled hello would break the client's own transcript. So tests take
/// a real hello and add the extension the way a client with an ECHConfig
/// would, which is all the proxy ever looks at.
#[cfg(test)]
pub(crate) fn with_fake_ech(record: &[u8]) -> Option<Vec<u8>> {
    let handshake_len = ((*record.get(6)? as usize) << 16)
        | ((*record.get(7)? as usize) << 8)
        | *record.get(8)? as usize;
    let mut body = record.get(9..9 + handshake_len)?.to_vec();
    let extensions_len = client_hello_extensions(&body)?.len();
    let at = body.len().checked_sub(extensions_len)?;
    if at < 2 {
        return None;
    }
    // The extension `ECHClientHelloOuter` shape: type, cipher suite, config
    // id, `enc`, then the payload — a client's hello would carry a real HPKE
    // encapsulation; the tests only need the keys to look right.
    let mut extension = Vec::new();
    extension.extend_from_slice(&EXT_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
    let mut payload = Vec::new();
    payload.push(0x00); // outer
    payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // HKDF-SHA256 + AES-128-GCM
    payload.push(7); // config id
    payload.extend_from_slice(&32u16.to_be_bytes());
    payload.extend_from_slice(&[0x5a; 32]); // enc
    payload.extend_from_slice(&48u16.to_be_bytes());
    payload.extend_from_slice(&[0xa5; 48]); // payload
    extension.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    extension.extend_from_slice(&payload);
    body.extend_from_slice(&extension);
    // Fix the extension block length, then the handshake length, then the
    // record length: three fields grow by the same 4 + payload amount.
    let new_len = (extensions_len + extension.len()) as u16;
    body[at - 2..at].copy_from_slice(&new_len.to_be_bytes());
    let mut out = record[..9].to_vec();
    out[6..9].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&body);
    let record_len = (out.len() - 5) as u16;
    out[3..5].copy_from_slice(&record_len.to_be_bytes());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_bundle_yields_anchors_on_a_desktop() {
        // An empty store is what made every desktop HTTPS session fail with
        // `UnknownIssuer`: the reader only knew Android's layout. A host that
        // ships a bundle must end up with anchors.
        let bundle = std::path::Path::new("/etc/ssl/certs/ca-certificates.crt");
        let store = system_root_store();
        if bundle.exists() {
            assert!(store.len() > 20, "the system CA bundle should be read");
        }
    }

    #[test]
    fn a_certificate_names_the_party_and_the_window_it_claimed() {
        // The reason the log keeps a certificate at all is these two names:
        // who the connection said it was, and who signed that claim. A window
        // that survives as milliseconds is what lets the UI say whether the
        // claim was good at the time.
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["cdn.example".to_string()]).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "cdn.example");
        dn.push(rcgen::DnType::OrganizationName, "Example Networks");
        params.distinguished_name = dn;
        params.not_before = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let cert = params.self_signed(&key).unwrap();

        use x509_parser::prelude::FromDer;
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(cert.der()).unwrap();
        let tbs = &parsed.tbs_certificate;
        assert_eq!(party_name(&tbs.subject), "cdn.example");
        // Self-signed, so the signer is the party — which is precisely the
        // reading a user needs when a device endpoint carries its own name.
        assert_eq!(party_name(&tbs.issuer), "cdn.example");
        assert_eq!(tbs.validity.not_before.timestamp() * 1000, 1_700_000_000_000);
        assert_eq!(tbs.validity.not_after.timestamp() * 1000, 1_800_000_000_000);
    }

    #[test]
    fn a_name_with_no_common_name_still_names_somebody() {
        // CAs are not obliged to put a CN in, and an empty column would read
        // as "no certificate" rather than "a certificate nobody signed by
        // name", so the fallbacks matter more than the preference.
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::OrganizationName, "Example Networks");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).unwrap();

        use x509_parser::prelude::FromDer;
        let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(cert.der()).unwrap();
        assert_eq!(
            party_name(&parsed.tbs_certificate.subject),
            "Example Networks"
        );
    }
}
