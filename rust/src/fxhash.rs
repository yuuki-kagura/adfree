//! Fast non-cryptographic hashing helpers.
//!
//! The filter hot path performs a handful of hashes per DNS query. SipHash (the
//! `std` default) costs ~20x more than the Fx-style hash used here for our short
//! (< 64 byte) keys, which directly translates into battery life.

use std::hash::{BuildHasherDefault, Hasher};

const FX_SEED64: u64 = 0x51_7c_c1_b7_27_22_0a_95;

/// FxHasher (as used by rustc) — multiply + rotate over 8 byte lanes.
#[derive(Default, Clone, Copy)]
pub struct FxHasher {
    hash: u64,
}

impl FxHasher {
    #[inline]
    pub fn new() -> Self {
        FxHasher { hash: 0 }
    }

    #[inline]
    fn add(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(FX_SEED64);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }

    #[inline]
    fn write(&mut self, mut bytes: &[u8]) {
        while bytes.len() >= 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            self.add(u64::from_le_bytes(buf));
            bytes = &bytes[8..];
        }
        if bytes.len() >= 4 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[..4]);
            self.add(u32::from_le_bytes(buf) as u64);
            bytes = &bytes[4..];
        }
        for &b in bytes {
            self.add(b as u64);
        }
    }
}

pub type FxBuildHasher = BuildHasherDefault<FxHasher>;

pub type FxHashMap<K, V> = std::collections::HashMap<K, V, FxBuildHasher>;

/// Stable 64 bit hash of a lower-cased domain / label sequence.
#[inline]
pub fn hash_str(s: &str) -> u64 {
    let mut h = FxHasher::new();
    h.write(s.as_bytes());
    h.write_u8(0xff);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_distinct() {
        assert_eq!(hash_str("example.com"), hash_str("example.com"));
        assert_ne!(hash_str("example.com"), hash_str("example.org"));
        assert_ne!(hash_str("a.com"), hash_str("ab.com"));
    }
}
