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

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

/// ALPN we offer: HTTP/1.1 first. HTTP/2 support is a later stage.
pub const ALPN_H1: &[u8] = b"http/1.1";

/// The two halves of one intercepted flow.
pub struct TlsSession {
    pub server: ServerConnection,
    pub client: ClientConnection,
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
                        .add(rustls::pki_types::CertificateDer::from(der.to_vec()))
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
        .get_or_init(|| {
            let roots = system_root_store();
            let mut config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![ALPN_H1.to_vec()];
            Arc::new(config)
        })
        .clone()
}

/// Server config presenting a leaf signed by our CA.
pub fn server_config(chain: Vec<Vec<u8>>, key: Vec<u8>) -> Result<Arc<ServerConfig>, String> {
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = chain
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key),
    );
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("server config: {e}"))?;
    config.alpn_protocols = vec![ALPN_H1.to_vec()];
    Ok(Arc::new(config))
}

/// Opens both halves for `server_name` (SNI seen from the client) connecting on
/// to `real_server` (what we connect to).
pub fn open_session(
    ca: &crate::mitm::ca::CertificateAuthority,
    server_name: &str,
    real_server: &str,
) -> Result<TlsSession, String> {
    let issued = ca.issue(server_name)?;
    let sconfig = server_config(ca.chain_for(&issued), issued.key.clone())?;
    let server = ServerConnection::new(sconfig).map_err(|e| format!("server conn: {e}"))?;

    let name = rustls::pki_types::ServerName::try_from(real_server.to_string())
        .map_err(|e| format!("server name: {e}"))?;
    let client = ClientConnection::new(client_config(), name)
        .map_err(|e| format!("client conn: {e}"))?;

    Ok(TlsSession { server, client })
}

/// `Connection` is an enum, so one macro generates the per-side plumbing.
macro_rules! connection_helpers {
    ($drain:ident, $take:ident, $conn:ty) => {
        /// Drains whatever plaintext this connection has already decrypted.
        pub fn $drain(connection: &mut $conn) -> Vec<u8> {
            let mut out = Vec::new();
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = connection.reader().read(&mut buf) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
                if out.len() > 1024 * 1024 {
                    break; // bound memory: the app is not a data plane
                }
            }
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

connection_helpers!(drain_server_plain, take_server_outbound, ServerConnection);
connection_helpers!(drain_client_plain, take_client_outbound, ClientConnection);

/// Feeds wire bytes from the client into `ServerConnection`, returning the
/// plaintext that was decrypted.
pub fn feed_server(connection: &mut ServerConnection, chunk: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = std::io::Cursor::new(chunk);
    loop {
        match connection.read_tls(&mut reader) {
            Ok(0) => break,
            Ok(_) => {
                if let Err(e) = connection.process_new_packets() {
                    return Err(format!("process_new_packets: {e}"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read_tls: {e}")),
        }
    }
    Ok(drain_server_plain(connection))
}

/// Encrypts `plaintext` on `ClientConnection` and returns the bytes to send to
/// the real server.
pub fn feed_client(
    connection: &mut ClientConnection,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    if plaintext.is_empty() {
        return Ok(Vec::new());
    }
    connection
        .writer()
        .write_all(plaintext)
        .map_err(|e| format!("write plaintext: {e}"))?;
    Ok(take_client_outbound(connection))
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
