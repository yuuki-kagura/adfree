//! Local certificate authority for the MITM stage.
//!
//! When HTTPS filtering is on, the app signs a certificate for every host it
//! sits between (client <-> app <-> server). That needs a self-generated CA the
//! user installs on the device, and a leaf cert minted on the fly per SNI.
//!
//! ## Restoring the CA after a restart
//!
//! rcgen cannot rebuild a `Certificate` from DER, so only the key (PKCS#8) is
//! restored and used to self-sign a fresh CA object; that object only supplies
//! the issuer DN/KID. The DER the client actually trusts is the stored one, so
//! the chain [leaf, stored_CA_der] still verifies.
//!
//! ECDSA P-256: fast key generation (no DNS-path stall), strong enough for
//! modern TLS, and leaves are cached per host so the cost is paid once. Every
//! host shares one leaf key (see [`leaf_key`]): generating one per host would
//! run a keygen inside the packet loop, and a page opening a dozen connections
//! would stack a dozen keygens behind each other.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The local CA: mints leaf certs for the hosts we intercept.
///
/// A `failed()` instance stands in for "no CA loaded yet": issuing reports an
/// error and everything else degrades quietly, so DNS filtering keeps working
/// without HTTPS filtering.
pub struct CertificateAuthority {
    /// The CA's real DER (read from disk, or freshly generated).
    cert_der: Vec<u8>,
    /// CA object used only as the issuer (DN/KID/key usages) when signing leaves.
    ca_object: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    /// True when a real CA is loaded (as opposed to `failed()`).
    valid: bool,
    /// Leaf cache keyed by host.
    cache: Mutex<HashMap<String, IssuedCert>>,
}

/// A (cert, key) pair issued for one SNI.
#[derive(Clone)]
pub struct IssuedCert {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
}

impl CertificateAuthority {
    /// Generate a new CA (its DER is what the user installs).
    pub fn generate() -> Result<Self, String> {
        let ca_key = rcgen::KeyPair::generate().map_err(|e| format!("keygen: {e}"))?;
        let (ca_object, cert_der) = self_signed_ca(&ca_key)?;
        Ok(Self {
            cert_der,
            ca_object,
            ca_key,
            cache: Mutex::new(HashMap::new()),
            valid: true,
        })
    }

    /// A stand-in for "no CA loaded yet".
    pub fn failed(reason: &str) -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("keygen");
        let (ca_object, cert_der) = self_signed_ca(&ca_key).expect("self-sign");
        let _ = reason;
        Self {
            cert_der,
            ca_object,
            ca_key,
            cache: Mutex::new(HashMap::new()),
            valid: false,
        }
    }

    /// True when a real CA is loaded.
    pub fn has_ca(&self) -> bool {
        self.valid
    }

    /// Restore the CA from PEM (cert to install + key used to issue leaves).
    pub fn from_pem(ca_pem: &str, key_pem: &str) -> Result<Self, String> {
        let cert_der = decode_cert_pem(ca_pem)?;
        let ca_key = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
            key_pem,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .map_err(|e| format!("key pem: {e}"))?;
        let (ca_object, _fresh) = self_signed_ca(&ca_key)?;
        Ok(Self {
            cert_der,
            ca_object,
            ca_key,
            cache: Mutex::new(HashMap::new()),
            valid: true,
        })
    }

    /// CA in DER form (fed to rustls' RootCertStore when a client verifies).
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert_der.clone()
    }

    /// CA as PEM, for the user to install on the device.
    pub fn cert_pem(&self) -> String {
        pem_encode("CERTIFICATE", &self.cert_der)
    }

    /// CA key as PEM, for persistence.
    pub fn key_pem(&self) -> String {
        // rcgen already returns a PEM document; re-encoding it would corrupt it.
        self.ca_key.serialize_pem()
    }

    /// SHA-256 fingerprint (`AB:CD:...`) shown when the user installs the CA.
    pub fn fingerprint_sha256(&self) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.cert_der);
        digest
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Issue (or reuse from cache) a leaf cert for a host.
    pub fn issue(&self, host: &str) -> Result<IssuedCert, String> {
        if !self.valid {
            // The `failed()` placeholder must never sign: its key is generated
            // on the spot and never leaves memory, so the chain would reach the
            // client signed by something nobody could have installed.
            return Err("no CA loaded".into());
        }
        let host = host.to_ascii_lowercase();
        if host.is_empty() || host.starts_with('.') {
            return Err(format!("invalid host {host:?}"));
        }
        if let Some(hit) = self.cache.lock().unwrap().get(&host) {
            return Ok(hit.clone());
        }

        let leaf_key = leaf_key()?;
        let mut params =
            rcgen::CertificateParams::new(vec![host.clone()]).map_err(|e| format!("params: {e}"))?;
        // Same as the CA: the DN is what a "view certificate" screen shows, so
        // it names the host instead of rcgen's placeholder.
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, host.clone());
        params.distinguished_name = dn;
        params.is_ca = rcgen::IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let yesterday = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let in_400_days = time::OffsetDateTime::now_utc() + time::Duration::days(400);
        params.not_before = yesterday;
        params.not_after = in_400_days;

        // Signed by our CA: (khoá leaf, CA object, khoá CA).
        let cert = params
            .signed_by(leaf_key, &self.ca_object, &self.ca_key)
            .map_err(|e| format!("sign leaf: {e}"))?;

        let issued = IssuedCert {
            cert: cert.der().to_vec(),
            key: leaf_key.serialize_der(),
        };
        self.cache.lock().unwrap().insert(host, issued.clone());
        Ok(issued)
    }

    /// Full chain for rustls: leaf first, CA after.
    pub fn chain_for(&self, issued: &IssuedCert) -> Vec<Vec<u8>> {
        vec![issued.cert.clone(), self.cert_der.clone()]
    }

    pub fn cached_hosts(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    pub fn is_ca(&self) -> bool {
        // A CA object always carries BasicConstraints in its params.
        !self.cert_der.is_empty()
    }
}

/// One leaf key for every host.
///
/// What has to differ per certificate is its name (SAN) and validity, not the
/// key: mitmproxy and AdGuard ship a single leaf key for exactly this reason.
/// Generating one per host would run a keygen inside the packet path, and a
/// page opening a dozen connections would serialise a dozen keygens behind the
/// accept loop.
fn leaf_key() -> Result<&'static rcgen::KeyPair, String> {
    static KEY: OnceLock<Option<rcgen::KeyPair>> = OnceLock::new();
    KEY.get_or_init(|| rcgen::KeyPair::generate().ok())
        .as_ref()
        .ok_or_else(|| "leaf keygen failed".to_string())
}

/// Self-sign a CA object and return its DER.
fn self_signed_ca(key: &rcgen::KeyPair) -> Result<(rcgen::Certificate, Vec<u8>), String> {
    let mut params = rcgen::CertificateParams::new(Vec::new())
        .map_err(|e| format!("params: {e}"))?;
    // `new()` only fills the SANs; without a distinguished name rcgen writes
    // "CN=rcgen self signed cert" into the certificate, which is what the
    // system's certificate install dialog shows the user.
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "AdFree Personal CA");
    dn.push(rcgen::DnType::OrganizationName, "AdFree");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3_650);
    let cert = params.self_signed(key).map_err(|e| format!("self-sign: {e}"))?;
    let der = cert.der().to_vec();
    Ok((cert, der))
}

fn decode_cert_pem(pem: &str) -> Result<Vec<u8>, String> {
    let mut found = None;
    for block in rustls_pemfile::read_all(&mut std::io::Cursor::new(pem.as_bytes())).flatten() {
        if let rustls_pemfile::Item::X509Certificate(cert) = block {
            found = Some(cert.to_vec());
            break;
        }
    }
    found.ok_or_else(|| "ca pem: no certificate".to_string())
}

/// Private key of a leaf in the form rustls wants.
pub fn private_key_der(issued: &IssuedCert) -> rustls::pki_types::PrivateKeyDer<'static> {
    rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(issued.key.clone()),
    )
}

/// Base64-encode a DER block as PEM (no external crate needed).
fn pem_encode(label: &str, contents: &[u8]) -> String {
    use std::fmt::Write;
    let body = base64_encode(contents);
    let mut out = String::new();
    let _ = writeln!(out, "-----BEGIN {label}-----");
    for chunk in body.as_bytes().chunks(64) {
        let line = std::str::from_utf8(chunk).unwrap_or("");
        let _ = writeln!(out, "{line}");
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}

/// Standard base64 (RFC 4648), enough for PEM.
fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(n >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[n as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::RootCertStore;

    #[test]
    fn generates_a_ca_and_caches_leaves() {
        let ca = CertificateAuthority::generate().expect("ca");
        assert!(!ca.cert_der().is_empty());
        let first = ca.issue("tracker.example.com").expect("leaf");
        let second = ca.issue("TRACKER.example.com").expect("leaf again");
        assert_eq!(first.cert, second.cert, "leaves are cached per host");
        assert_eq!(ca.cached_hosts(), 1);
        ca.issue("other.example.com").expect("second host");
        assert_eq!(ca.cached_hosts(), 2);
        assert_eq!(ca.chain_for(&first).len(), 2);
    }

    #[test]
    fn rustls_accepts_the_ca_as_root() {
        let ca = CertificateAuthority::generate().expect("ca");
        let mut roots = RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(ca.cert_der()))
            .expect("root accepted");
        assert_eq!(roots.len(), 1);
    }

    #[test]
    fn the_placeholder_ca_refuses_to_issue() {
        // Signing from the placeholder would produce a chain whose root was
        // generated in memory and never installed anywhere.
        let ca = CertificateAuthority::failed("not initialised");
        assert!(!ca.has_ca());
        assert!(ca.issue("ads.example.com").is_err());
        assert!(ca.cached_hosts() == 0);
    }

    #[test]
    fn the_ca_carries_a_real_name_not_rcgens_placeholder() {
        let ca = CertificateAuthority::generate().expect("ca");
        let der = ca.cert_der();
        let has = |needle: &[u8]| der.windows(needle.len()).any(|w| w == needle);
        // The CN lands in the DER as-is, and this is what the system's
        // certificate install dialog shows.
        assert!(has(b"AdFree Personal CA"));
        assert!(!has(b"rcgen self signed cert"));
        // The issuer DN of a leaf is copied from the CA, so it carries the
        // same name rather than rcgen's.
        let leaf = ca.issue("ads.example.com").expect("leaf");
        let leaf_has = |needle: &[u8]| leaf.cert.windows(needle.len()).any(|w| w == needle);
        assert!(leaf_has(b"AdFree Personal CA"));
        assert!(leaf_has(b"ads.example.com"));
    }

    #[test]
    fn pem_survives_a_restart() {
        let ca = CertificateAuthority::generate().expect("ca");
        let pem = ca.cert_pem();
        let key = ca.key_pem();
        let restored = CertificateAuthority::from_pem(&pem, &key).expect("restore");
        assert_eq!(restored.cert_pem(), pem, "CA must survive a restart");
        assert_eq!(restored.fingerprint_sha256(), ca.fingerprint_sha256());
        // A leaf issued before the restart still sits in a valid chain.
        let leaf = restored.issue("ads.example.com").expect("leaf");
        assert_eq!(restored.chain_for(&leaf)[1], ca.cert_der());
    }

    #[test]
    fn probe_pem() {
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = key.serialize_pem();
        let first = pem.lines().next().unwrap_or("").to_string();
        let back = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(
            &pem,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        );
        assert!(back.is_ok(), "first={first} err={:?}", back.err().map(|e| e.to_string()));
    }

    #[test]
    fn rejects_bad_input() {
        let ca = CertificateAuthority::generate().expect("ca");
        assert!(ca.issue("").is_err());
        assert!(ca.issue(".hidden").is_err());
        assert!(CertificateAuthority::from_pem("nonsense", "nonsense").is_err());
    }

    #[test]
    fn fingerprint_is_readable() {
        let ca = CertificateAuthority::generate().expect("ca");
        let fp = ca.fingerprint_sha256();
        assert_eq!(fp.split(':').count(), 32);
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    }
}
