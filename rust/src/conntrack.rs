//! Connection tracking: `IP -> hostname -> decision`.
//!
//! DNS filtering alone is not enough: a client that learned an address some
//! other way (hardcoded IP, peer cache, or an encrypted DNS channel we do not
//! intercept) would bypass it. Learning the answer section of every upstream
//! response lets us kill the *connection* locally with a RST the moment a SYN
//! arrives for a host we already blocked.
//!
//! That is cheaper than any NAT/relay approach: no userspace TCP stack, no
//! payload inspection, no bytes spent, and the client stops instantly instead
//! of waiting for a connect timeout.

use crate::dns::LearnedRecord;
use crate::fxhash::FxHashMap;
use crate::packet::IpKey;

/// Maximum hostname kept inline per tracked address.
pub const MAX_HOST_INLINE: usize = 64;
/// How long a learned mapping stays valid (bounded by the answer's TTL).
const MIN_TTL_SECS: u64 = 30;
const MAX_TTL_SECS: u64 = 300;
const CAPACITY: usize = 8_192;

#[derive(Clone, Copy)]
struct Entry {
    host: [u8; MAX_HOST_INLINE],
    host_len: u8,
    expires_ms: u64,
    blocked: bool,
}

impl Entry {
    const EMPTY: Entry = Entry {
        host: [0; MAX_HOST_INLINE],
        host_len: 0,
        expires_ms: 0,
        blocked: false,
    };

    fn host(&self) -> &str {
        std::str::from_utf8(&self.host[..self.host_len as usize]).unwrap_or("")
    }
}

pub struct ConnTable {
    map: FxHashMap<IpKey, Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpVerdict {
    /// We have no information about this address; let the kernel route it.
    Unknown,
    /// The address resolves to a blocked host: kill the connection locally.
    Blocked { host: String },
    /// The address resolves to an allowed host.
    Allowed { host: String },
}

impl ConnTable {
    pub fn new() -> Self {
        ConnTable {
            map: FxHashMap::default(),
        }
    }

    /// Records the answer of an upstream lookup.
    pub fn learn(&mut self, record: &LearnedRecord, host: &str, blocked: bool, now_ms: u64) {
        let ttl = (record.ttl as u64).clamp(MIN_TTL_SECS, MAX_TTL_SECS);
        let expires_ms = now_ms + ttl * 1000;
        if self.map.len() >= CAPACITY {
            // A full table means either a very busy device or an app that
            // rotated addresses; a wholesale reset keeps lookups O(1) and cheap.
            self.map.clear();
        }
        let mut entry = Entry::EMPTY;
        let bytes = host.as_bytes();
        let n = bytes.len().min(MAX_HOST_INLINE);
        entry.host[..n].copy_from_slice(&bytes[..n]);
        entry.host_len = n as u8;
        entry.expires_ms = expires_ms;
        entry.blocked = blocked;
        self.map.insert(record.ip, entry);
    }

    pub fn lookup(&self, ip: &IpKey, now_ms: u64) -> IpVerdict {
        match self.map.get(ip) {
            None => IpVerdict::Unknown,
            Some(entry) if entry.expires_ms <= now_ms => IpVerdict::Unknown,
            Some(entry) => {
                let host = entry.host().to_string();
                if entry.blocked {
                    IpVerdict::Blocked { host }
                } else {
                    IpVerdict::Allowed { host }
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Drops expired entries. Called from the forwarder thread when it is idle.
    pub fn expire(&mut self, now_ms: u64) {
        self.map.retain(|_, entry| entry.expires_ms > now_ms);
    }
}

impl Default for ConnTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Compact CIDR set used to recognise well known DoH/DoT (encrypted DNS)
/// providers, whose traffic we cannot inspect without breaking TLS and which
/// would otherwise bypass the filter completely.
#[derive(Clone, Copy)]
struct V4Cidr {
    network: u32,
    prefix: u8,
}

#[derive(Clone, Copy)]
struct V6Cidr {
    network: u128,
    prefix: u8,
}

pub struct CidrSet {
    v4: Vec<V4Cidr>,
    v6: Vec<V6Cidr>,
}

impl CidrSet {
    pub fn new() -> Self {
        CidrSet {
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }

    pub fn add_v4(&mut self, network: u32, prefix: u8) {
        let prefix = prefix.min(32);
        let mask = v4_mask(prefix);
        self.v4.push(V4Cidr {
            network: network & mask,
            prefix,
        });
    }

    pub fn add_v6(&mut self, network: u128, prefix: u8) {
        let prefix = prefix.min(128);
        let mask = v6_mask(prefix);
        self.v6.push(V6Cidr {
            network: network & mask,
            prefix,
        });
    }

    pub fn contains_v4(&self, addr: u32) -> bool {
        self.v4.iter().any(|c| addr & v4_mask(c.prefix) == c.network)
    }

    pub fn contains_v6(&self, addr: u128) -> bool {
        self.v6.iter().any(|c| addr & v6_mask(c.prefix) == c.network)
    }

    pub fn contains_key(&self, key: IpKey) -> bool {
        match key {
            IpKey::V4(v) => self.contains_v4(v),
            IpKey::V6(v) => self.contains_v6(v),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

#[inline]
fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[inline]
fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

impl Default for CidrSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::LearnedRecord;

    fn record(ip: IpKey, ttl: u32) -> LearnedRecord {
        LearnedRecord { ip, ttl }
    }

    #[test]
    fn learns_and_expires() {
        let mut t = ConnTable::new();
        let now = 1_000u64;
        t.learn(&record(IpKey::V4(0x0808_0808), 60), "dns.test", true, now);
        assert_eq!(
            t.lookup(&IpKey::V4(0x0808_0808), now + 1_000),
            IpVerdict::Blocked {
                host: "dns.test".to_string()
            }
        );
        assert_eq!(t.lookup(&IpKey::V4(0x0808_0808), now + 90_000), IpVerdict::Unknown);
        assert_eq!(t.lookup(&IpKey::V4(0x0102_0304), now), IpVerdict::Unknown);
    }

    #[test]
    fn ttl_is_bounded() {
        let mut t = ConnTable::new();
        t.learn(&record(IpKey::V4(1), 0), "a.test", false, 0);
        assert_eq!(
            t.lookup(&IpKey::V4(1), 1),
            IpVerdict::Allowed {
                host: "a.test".to_string()
            }
        );
        t.learn(&record(IpKey::V4(2), 100_000), "b.test", true, 0);
        assert_eq!(
            t.lookup(&IpKey::V4(2), 1),
            IpVerdict::Blocked {
                host: "b.test".to_string()
            }
        );
    }

    #[test]
    fn long_hostnames_are_truncated() {
        let mut t = ConnTable::new();
        let long = "x".repeat(300);
        t.learn(&record(IpKey::V4(5), 60), &long, true, 0);
        assert!(t.lookup(&IpKey::V4(5), 1) != IpVerdict::Unknown);
    }

    #[test]
    fn capacity_clears() {
        let mut t = ConnTable::new();
        for i in 0..(CAPACITY as u32 + 10) {
            t.learn(&record(IpKey::V4(i), 60), "a.test", true, 0);
        }
        assert!(t.len() <= CAPACITY);
    }

    #[test]
    fn cidr_matching() {
        let mut c = CidrSet::new();
        c.add_v4(0x0101_0100, 24); // 1.1.1.0/24
        c.add_v6(0x2606_4700_0000_0000_0000_0000_0000_0000, 48); // 2606:4700::/48
        assert!(c.contains_v4(0x0101_0101)); // 1.1.1.1
        assert!(c.contains_v4(0x0101_01ff));
        assert!(!c.contains_v4(0x0101_0201)); // 1.1.2.1
        assert!(c.contains_key(IpKey::V4(0x0101_0101)));
        assert!(!c.contains_key(IpKey::V4(0x0808_0808)));
        assert!(c.contains_v6(0x2606_4700_0000_0000_0000_0000_0000_00ff));
        c.add_v4(0, 0); // 0.0.0.0/0 matches everything
        assert!(c.contains_v4(0x0808_0808));
    }
}
