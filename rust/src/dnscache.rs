//! Bounded answer cache for the DNS forwarder.
//!
//! The tunnel forwards every query it lets through to a resolver, and a page
//! load asks for the same handful of names several times (the document, its
//! workers, the retries its own resolver makes). Answering a repeated query
//! from here costs neither a radio wakeup nor a resolver round trip, which is
//! the difference between a warm lookup and a cold one.
//!
//! The cache deliberately does not decide anything: the filter, the app
//! firewall and the SafeSearch rewrite all run before a lookup, so a hit only
//! ever stands in for the *answer* of a query that would have been forwarded.
//! Entries are whole DNS messages, replayed through the normal reply path, so
//! ECH handling and connection learning apply to a hit exactly as they do to
//! the upstream answer.
//!
//! Memory is bounded twice: by entry count and by payload bytes. The working
//! set of one device (the names a page load touches, times the record types)
//! fits in a fraction of the cap; the oldest entry is evicted first, which is
//! what keeps the hot names in and the one-off lookups out.

use std::collections::HashMap;

/// Entries kept at most. A page load touches tens of names, each with an A and
/// an AAAA (and often an HTTPS) record.
const MAX_ENTRIES: usize = 512;
/// Payload bytes kept at most, on top of the per-entry map overhead.
const MAX_BYTES: usize = 128 * 1024;
/// An answer larger than this is not worth the bookkeeping: the EDNS payload
/// this tunnel advertises caps ordinary answers well below it.
const MAX_ENTRY_BYTES: usize = 1232;

type Key = (String, u16, u16);

struct Entry {
    message: Vec<u8>,
    stored_ms: u64,
    expires_ms: u64,
    /// Insertion order, for eviction.
    seq: u64,
}

pub struct DnsCache {
    entries: HashMap<Key, Entry>,
    bytes: usize,
    seq: u64,
    hits: u64,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub fn new() -> Self {
        DnsCache {
            entries: HashMap::new(),
            bytes: 0,
            seq: 0,
            hits: 0,
        }
    }

    /// The fresh answer for `name`/`qtype`/`qclass`, plus how many whole
    /// seconds have passed since it was stored.
    ///
    /// The caller ages the TTLs by that much before handing the message on: a
    /// client must not restart the origin's clock from the moment of the hit.
    pub fn get(
        &mut self,
        name: &str,
        qtype: u16,
        qclass: u16,
        now_ms: u64,
    ) -> Option<(Vec<u8>, u32)> {
        let key = (name.to_string(), qtype, qclass);
        match self.entries.get(&key) {
            Some(entry) if entry.expires_ms > now_ms => {
                self.hits += 1;
                let age = ((now_ms.saturating_sub(entry.stored_ms)) / 1_000) as u32;
                Some((entry.message.clone(), age))
            }
            Some(_) => {
                self.remove(&key);
                None
            }
            None => None,
        }
    }

    pub fn insert(
        &mut self,
        name: &str,
        qtype: u16,
        qclass: u16,
        message: &[u8],
        ttl_secs: u32,
        now_ms: u64,
    ) {
        if message.len() > MAX_ENTRY_BYTES {
            return;
        }
        let key = (name.to_string(), qtype, qclass);
        self.remove(&key);
        while !self.entries.is_empty()
            && (self.entries.len() >= MAX_ENTRIES || self.bytes + message.len() > MAX_BYTES)
        {
            self.evict_oldest();
        }
        self.seq += 1;
        self.bytes += message.len();
        self.entries.insert(
            key,
            Entry {
                message: message.to_vec(),
                stored_ms: now_ms,
                expires_ms: now_ms.saturating_add(ttl_secs as u64 * 1_000),
                seq: self.seq,
            },
        );
    }

    /// Drops every entry. Called when the resolver changes: another server
    /// would not necessarily give the same answers, so its predecessor's must
    /// not be replayed as if it had.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub fn hits(&self) -> u64 {
        self.hits
    }

    fn remove(&mut self, key: &Key) {
        if let Some(old) = self.entries.remove(key) {
            self.bytes -= old.message.len();
        }
    }

    fn evict_oldest(&mut self) {
        let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.seq)
            .map(|(key, _)| key.clone())
        else {
            return;
        };
        self.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: u32 = 300;

    #[test]
    fn a_stored_answer_comes_back_until_it_expires() {
        let mut cache = DnsCache::new();
        cache.insert("example.com", 1, 1, &[1, 2, 3, 4], TTL, 10_000);
        let (message, age) = cache.get("example.com", 1, 1, 11_500).expect("hit");
        assert_eq!(message, vec![1, 2, 3, 4]);
        assert_eq!(age, 1);
        assert_eq!(cache.hits(), 1);
        // Another type is another question.
        assert!(cache.get("example.com", 28, 1, 11_500).is_none());
        // Past the TTL the entry is gone for good.
        assert!(cache.get("example.com", 1, 1, 10_000 + TTL as u64 * 1_000).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_flood_of_names_never_grows_the_cache_past_its_cap() {
        let mut cache = DnsCache::new();
        for i in 0..(MAX_ENTRIES * 2) {
            cache.insert(&format!("host{i}.example"), 1, 1, &[0u8; 64], TTL, i as u64);
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        assert!(cache.bytes <= MAX_BYTES);
        // The newest names are the ones kept.
        assert!(cache.get("host0.example", 1, 1, 1_000).is_none());
        let last = format!("host{}.example", MAX_ENTRIES * 2 - 1);
        assert!(cache.get(&last, 1, 1, 1_000).is_some());
    }

    #[test]
    fn an_oversized_answer_is_left_out() {
        let mut cache = DnsCache::new();
        cache.insert("big.example", 1, 1, &[0u8; MAX_ENTRY_BYTES + 1], TTL, 0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn clearing_forgets_every_entry_and_its_bytes() {
        let mut cache = DnsCache::new();
        cache.insert("a.example", 1, 1, &[0u8; 32], TTL, 0);
        cache.insert("b.example", 1, 1, &[0u8; 32], TTL, 0);
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.bytes, 0);
        assert!(cache.get("a.example", 1, 1, 1).is_none());
    }
}