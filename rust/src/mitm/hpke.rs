//! RFC 9180 HPKE (base mode) for ECH client support, on ring primitives.
//!
//! Implements DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
//! (KEM 0x0020, KDF 0x0001, AEAD 0x0001) — the suite the ECH hosts in the wild
//! advertise. rustls only ships HPKE with its aws-lc-rs provider, and this
//! crate builds rustls on ring: without this module the upstream half could
//! not offer ECH at all, and filtering a host that requires ECH would stay
//! impossible (see [`crate::mitm::ech`]).
//!
//! ring 0.17 cannot import an X25519 private key, so the suite is client-side
//! only: seal/setup_sealer are implemented, open/setup_opener/generate_key_pair
//! return an error. That is exactly what the ECH *client* path uses — rustls
//! only calls `setup_sealer` and `seal`.
//!
//! Correctness is pinned to RFC 9180 A.1.1 (DHKEM shared secret, key schedule,
//! the first two AEAD ciphertexts) and was cross-checked against aws-lc-rs'
//! implementation during development (the probe is not part of the crate).

use std::fmt;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::Error;

/// KEM id 0x0020, DHKEM(X25519, HKDF-SHA256).
const KEM_ID: u16 = 0x0020;
/// KDF id 0x0001, HKDF-SHA256.
const KDF_ID: u16 = 0x0001;
/// AEAD id 0x0001, AES-128-GCM.
const AEAD_ID: u16 = 0x0001;

/// `Nsecret` for HKDF-SHA256 (RFC 9180, 7.1.1).
const N_SECRET: usize = 32;
/// `Nk` for AES-128-GCM (RFC 9180, 7.3).
const N_K: usize = 16;
/// `Nn` for AES-128-GCM (RFC 9180, 7.3).
const N_N: usize = 12;

/// The suite rustls' ECH client asks for, as a value usable in
/// [`rustls::client::EchConfig::new`].
pub static X25519_HKDF_SHA256_AES128_GCM: X25519Aes128Gcm = X25519Aes128Gcm;

/// Every suite this build can offer. One entry: the suite ECH deployments use.
pub static SUITES: &[&dyn Hpke] = &[&X25519_HKDF_SHA256_AES128_GCM];

static SUITE: HpkeSuite = HpkeSuite {
    kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
    sym: HpkeSymmetricCipherSuite {
        kdf_id: HpkeKdf::HKDF_SHA256,
        aead_id: HpkeAead::AES_128_GCM,
    },
};

#[derive(Debug)]
pub struct X25519Aes128Gcm;

fn err(msg: &str) -> Error {
    Error::General(msg.to_string())
}

impl X25519Aes128Gcm {
    /// The sealing half, with a caller-provided RNG.
    fn setup_sealer_with_rng(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
        rng: &dyn SecureRandom,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        if pub_key.0.len() != 32 {
            return Err(err("hpke: bad X25519 public key length"));
        }
        let sk_e = EphemeralPrivateKey::generate(&X25519, rng)
            .map_err(|_| err("hpke: key generation failed"))?;
        let enc = sk_e
            .compute_public_key()
            .map_err(|_| err("hpke: key generation failed"))?
            .as_ref()
            .to_vec();
        let peer = UnparsedPublicKey::new(&X25519, &pub_key.0);
        let dh = agree_ephemeral(sk_e, &peer, |z| z.to_vec())
            .map_err(|_| err("hpke: x25519 agreement failed"))?;
        let mut kem_context = enc.clone();
        kem_context.extend_from_slice(&pub_key.0);
        let shared_secret = extract_and_expand(&dh, &kem_context);
        let (key, base_nonce) = key_schedule(&shared_secret, info);
        Ok((
            EncapsulatedSecret(enc),
            Box::new(Sealer {
                key: aead_key(&key)?,
                base_nonce,
                seq: 0,
            }),
        ))
    }
}

impl Hpke for X25519Aes128Gcm {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut sealer) = self.setup_sealer(info, pub_key)?;
        let ct = sealer.seal(aad, plaintext)?;
        Ok((enc, ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        self.setup_sealer_with_rng(info, pub_key, &SystemRandom::new())
    }

    fn open(
        &self,
        _enc: &EncapsulatedSecret,
        _info: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
        _secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        Err(err("hpke: ring suite is client-side only"))
    }

    fn setup_opener(
        &self,
        _enc: &EncapsulatedSecret,
        _info: &[u8],
        _secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        Err(err("hpke: ring suite is client-side only"))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        Err(err("hpke: ring suite is client-side only"))
    }

    fn suite(&self) -> HpkeSuite {
        SUITE
    }
}

struct Sealer {
    key: LessSafeKey,
    base_nonce: [u8; N_N],
    seq: u64,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HpkeSealer")
    }
}

impl HpkeSealer for Sealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = nonce_for(&self.base_nonce, self.seq);
        self.seq += 1;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| err("hpke: seal failed"))?;
        Ok(buf)
    }
}

fn aead_key(key: &[u8]) -> Result<LessSafeKey, Error> {
    UnboundKey::new(&AES_128_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| err("hpke: bad AEAD key length"))
}

/// `base_nonce XOR I2OSP(seq, Nn)` (RFC 9180, 5.2): the sequence number is a
/// 12-byte big-endian counter, so only the last 8 bytes ever change.
fn nonce_for(base: &[u8; N_N], seq: u64) -> [u8; N_N] {
    let mut nonce = *base;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    nonce
}

fn kem_suite_id() -> Vec<u8> {
    let mut v = b"KEM".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v
}

fn hpke_suite_id() -> Vec<u8> {
    let mut v = b"HPKE".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v.extend_from_slice(&KDF_ID.to_be_bytes());
    v.extend_from_slice(&AEAD_ID.to_be_bytes());
    v
}

/// HKDF-Extract(salt, ikm); an empty salt is all-zero bytes of hash length.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let zeros = [0u8; 32];
    let salt = if salt.is_empty() { &zeros[..] } else { salt };
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let tag = hmac::sign(&key, ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut msg = Vec::with_capacity(t.len() + info.len() + 1);
        msg.extend_from_slice(&t);
        msg.extend_from_slice(info);
        msg.push(counter);
        t = hmac::sign(&key, &msg).as_ref().to_vec();
        out.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

fn labeled_extract(salt: &[u8], suite_id: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled_ikm = Vec::with_capacity(7 + suite_id.len() + label.len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(suite_id);
    labeled_ikm.extend_from_slice(label);
    labeled_ikm.extend_from_slice(ikm);
    hkdf_extract(salt, &labeled_ikm)
}

fn labeled_expand(prk: &[u8], suite_id: &[u8], label: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut labeled_info = Vec::with_capacity(2 + 7 + suite_id.len() + label.len() + info.len());
    labeled_info.extend_from_slice(&(len as u16).to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(suite_id);
    labeled_info.extend_from_slice(label);
    labeled_info.extend_from_slice(info);
    hkdf_expand(prk, &labeled_info, len)
}

/// DHKEM ExtractAndExpand (RFC 9180, 4.1).
///
/// The extract label is `eae_prk` — `dh` is the variable, not the label; the
/// distinction cost a day of debugging against real servers, so the RFC vector
/// below pins it.
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Vec<u8> {
    let kem_suite = kem_suite_id();
    let eae_prk = labeled_extract(&[], &kem_suite, b"eae_prk", dh);
    labeled_expand(
        &eae_prk,
        &kem_suite,
        b"shared_secret",
        kem_context,
        N_SECRET,
    )
}

/// Base-mode key schedule (RFC 9180, 5.1).
fn key_schedule(shared_secret: &[u8], info: &[u8]) -> (Vec<u8>, [u8; N_N]) {
    let suite = hpke_suite_id();
    let psk_id_hash = labeled_extract(&[], &suite, b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&[], &suite, b"info_hash", info);
    let mut ks_context = Vec::with_capacity(1 + 32 + 32);
    ks_context.push(0); // mode_base
    ks_context.extend_from_slice(&psk_id_hash);
    ks_context.extend_from_slice(&info_hash);
    let secret = labeled_extract(shared_secret, &suite, b"secret", &[]);
    let key = labeled_expand(&secret, &suite, b"key", &ks_context, N_K);
    let nonce = labeled_expand(&secret, &suite, b"base_nonce", &ks_context, N_N);
    let mut base_nonce = [0u8; N_N];
    base_nonce.copy_from_slice(&nonce);
    (key, base_nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let digits: Vec<u8> = s
            .bytes()
            .filter(|b| b.is_ascii_hexdigit())
            .map(|b| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => unreachable!(),
            })
            .collect();
        digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
    }

    /// Test-only seam: a sealer with an explicit key and base nonce, so the
    /// RFC's AEAD vectors can be checked without controlling the ephemeral key.
    fn sealer_with_key(
        key: &[u8],
        base_nonce: [u8; N_N],
    ) -> Result<Box<dyn HpkeSealer + 'static>, Error> {
        Ok(Box::new(Sealer {
            key: aead_key(key)?,
            base_nonce,
            seq: 0,
        }))
    }

    #[test]
    fn the_suite_is_the_one_ech_deployments_use() {
        let suite = X25519_HKDF_SHA256_AES128_GCM.suite();
        assert_eq!(suite.kem, HpkeKem::DHKEM_X25519_HKDF_SHA256);
        assert_eq!(suite.sym.kdf_id, HpkeKdf::HKDF_SHA256);
        assert_eq!(suite.sym.aead_id, HpkeAead::AES_128_GCM);
        assert_eq!(SUITES.len(), 1);
        // The ids are the wire values, not just enum equality.
        assert_eq!(KEM_ID, 0x0020);
        assert_eq!(KDF_ID, 0x0001);
        assert_eq!(AEAD_ID, 0x0001);
    }

    /// RFC 9180 A.1.1: the DHKEM shared secret for (skEm, pkRm). The raw DH is
    /// pinned (computed independently as X25519(skEm, pkRm) per RFC 7748), so
    /// the test isolates the labels, suite id and expansion.
    #[test]
    fn dhkem_matches_rfc_9180_a_1_1() {
        let dh = hex("b3b5c19eab3f088ac18f23f774ff6414ba4fde45404d10085efc3e4dc9c72e35");
        let pk_em = hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
        let pk_rm = hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let kem_context = [pk_em, pk_rm].concat();
        assert_eq!(
            extract_and_expand(&dh, &kem_context),
            hex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"),
            "RFC 9180 A.1.1 shared_secret"
        );
    }

    #[test]
    fn key_schedule_matches_rfc_9180_a_1_1() {
        let info = hex("4f6465206f6e2061204772656369616e2055726e");
        let shared_secret = hex("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
        let (key, base_nonce) = key_schedule(&shared_secret, &info);
        assert_eq!(key, hex("4531685d41d65f03dc48f6b8302c05b0"), "RFC key");
        assert_eq!(
            base_nonce.to_vec(),
            hex("56d890e5accaaf011cff4b7d"),
            "RFC base_nonce"
        );
    }

    /// RFC 9180 A.1.1.1: the AEAD half, sequence numbers included.
    #[test]
    fn sealer_matches_rfc_9180_a_1_1() {
        let key = hex("4531685d41d65f03dc48f6b8302c05b0");
        let base_nonce: [u8; N_N] = hex("56d890e5accaaf011cff4b7d").try_into().unwrap();
        let pt = hex("4265617574792069732074727574682c20747275746820626561757479");
        let mut sealer = sealer_with_key(&key, base_nonce).unwrap();
        assert_eq!(
            sealer.seal(&hex("436f756e742d30"), &pt).unwrap(),
            hex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
            "RFC ct #0"
        );
        assert_eq!(
            sealer.seal(&hex("436f756e742d31"), &pt).unwrap(),
            hex("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
            "RFC ct #1"
        );
    }
}
