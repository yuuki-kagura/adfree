//! Maps a local UDP port to the owning app (uid) by reading `/proc/net/udp`.
//!
//! This is what makes the "per app" view real: a DNS query seen on the TUN
//! interface only carries a source port, and the port-to-uid table published by
//! the kernel is the cheapest way to attribute it to a package.
//!
//! The table is refreshed lazily (at most every few seconds, and only when an
//! unknown port actually needs to be resolved) so the cost shows up at most a
//! couple of times per second while the screen is on, and never while it is off.

use crate::fxhash::FxHashMap;
use std::time::Instant;

const REFRESH_INTERVAL_MS: u64 = 2_000;

pub struct UidMap {
    port_to_uid: FxHashMap<u16, u32>,
    last_refresh: Option<Instant>,
}

impl Default for UidMap {
    fn default() -> Self {
        Self::new()
    }
}

impl UidMap {
    pub fn new() -> Self {
        UidMap {
            port_to_uid: FxHashMap::default(),
            last_refresh: None,
        }
    }

    /// Returns the uid owning `port`, or 0 (= `android` / unknown).
    pub fn lookup(&mut self, port: u16) -> u32 {
        if let Some(uid) = self.port_to_uid.get(&port) {
            return *uid;
        }
        self.refresh_if_needed();
        self.port_to_uid.get(&port).copied().unwrap_or(0)
    }

    /// Only used when the caller wants to force a refresh.
    pub fn invalidate(&mut self) {
        self.port_to_uid.clear();
        self.last_refresh = None;
    }

    fn refresh_if_needed(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_refresh {
            if now.duration_since(last).as_millis() < REFRESH_INTERVAL_MS as u128 {
                return;
            }
        }
        self.last_refresh = Some(now);
        self.port_to_uid.clear();
        for path in ["/proc/net/udp", "/proc/net/udp6"] {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for line in text.lines().skip(1) {
                // sl local_address rem_address st tx_rx tr tm->when ...
                let mut cols = line.split_whitespace();
                let _local = match cols.next() {
                    Some(v) => v,
                    None => continue,
                };
                let Some(uid_col) = cols.nth(6) else { continue };
                let Ok(uid) = uid_col.parse::<u32>() else {
                    continue;
                };
                let Some(local) = line.split_whitespace().nth(1) else {
                    continue;
                };
                let Some(port_hex) = local.rsplit(':').next() else {
                    continue;
                };
                let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                    continue;
                };
                self.port_to_uid.entry(port).or_insert(uid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_safe_without_proc() {
        let mut map = UidMap::new();
        // Must never panic, even on hosts without the kernel tables.
        let _ = map.lookup(53);
        map.invalidate();
        let _ = map.lookup(53);
    }
}
