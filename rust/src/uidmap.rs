//! Maps a local UDP/TCP port to the owning app (uid) by reading
//! `/proc/net/{udp,udp6,tcp,tcp6}`.
//!
//! This is what makes the "per app" view real: a DNS query seen on the TUN
//! interface only carries a source port, and the port-to-uid table published by
//! the kernel is the cheapest way to attribute it to a package. TCP is the
//! same table, and it is what the `$app=` network rules need: a connection is
//! attributed once, when it opens.
//!
//! The table is refreshed lazily (at most every few seconds, and only when an
//! unknown port actually needs to be resolved) so the cost shows up at most a
//! couple of times per second while the screen is on, and never while it is off.
//! A TCP lookup is the exception: a socket that was just created may not be in
//! a snapshot taken seconds ago, so a miss refreshes after a short gap.

use crate::fxhash::FxHashMap;
use std::time::Instant;

const REFRESH_INTERVAL_MS: u64 = 2_000;
/// The shortest gap between two refreshes triggered by a TCP miss: a burst of
/// new connections refreshes once, and the whole burst is in the snapshot.
const TCP_MISS_INTERVAL_MS: u64 = 100;

pub struct UidMap {
    port_to_uid: FxHashMap<u16, u32>,
    tcp_port_to_uid: FxHashMap<u16, u32>,
    /// Test-only pins, ahead of the kernel table: the unit tests and the
    /// engine e2e drive synthetic packets, and their source ports are not the
    /// host's.
    #[cfg(test)]
    pinned_tcp: FxHashMap<u16, u32>,
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
            tcp_port_to_uid: FxHashMap::default(),
            #[cfg(test)]
            pinned_tcp: FxHashMap::default(),
            last_refresh: None,
        }
    }

    /// Returns the uid owning the UDP `port`, or 0 (= `android` / unknown).
    pub fn lookup(&mut self, port: u16) -> u32 {
        if let Some(uid) = self.port_to_uid.get(&port) {
            return *uid;
        }
        self.refresh_if_needed(REFRESH_INTERVAL_MS);
        self.port_to_uid.get(&port).copied().unwrap_or(0)
    }

    /// Returns the uid owning the TCP `port` (the local port of the
    /// connection), or 0 (= `android` / unknown).
    ///
    /// A hit after the table has gone stale refreshes it too: ports are
    /// recycled, and a stale entry would name the app that used the port
    /// before the one that owns it now.
    pub fn lookup_tcp(&mut self, port: u16) -> u32 {
        #[cfg(test)]
        if let Some(uid) = self.pinned_tcp.get(&port) {
            return *uid;
        }
        match self.tcp_port_to_uid.get(&port) {
            Some(uid) => {
                let uid = *uid;
                self.refresh_if_needed(REFRESH_INTERVAL_MS);
                self.tcp_port_to_uid.get(&port).copied().unwrap_or(uid)
            }
            None => {
                self.refresh_if_needed(TCP_MISS_INTERVAL_MS);
                self.tcp_port_to_uid.get(&port).copied().unwrap_or(0)
            }
        }
    }

    /// Test hook: pins a TCP source port to a uid, the way the kernel table
    /// would on a device. Never cleared by a refresh.
    #[cfg(test)]
    pub fn pin_tcp(&mut self, port: u16, uid: u32) {
        self.pinned_tcp.insert(port, uid);
    }

    /// Only used when the caller wants to force a refresh.
    pub fn invalidate(&mut self) {
        self.port_to_uid.clear();
        self.tcp_port_to_uid.clear();
        self.last_refresh = None;
    }

    fn refresh_if_needed(&mut self, min_gap_ms: u64) {
        let now = Instant::now();
        if let Some(last) = self.last_refresh {
            if now.duration_since(last).as_millis() < min_gap_ms as u128 {
                return;
            }
        }
        self.last_refresh = Some(now);
        self.port_to_uid.clear();
        self.tcp_port_to_uid.clear();
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
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            for line in text.lines().skip(1) {
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
                self.tcp_port_to_uid.entry(port).or_insert(uid);
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
        let _ = map.lookup_tcp(443);
        map.invalidate();
        let _ = map.lookup(53);
        let _ = map.lookup_tcp(443);
    }

    #[test]
    fn a_pinned_tcp_port_survives_the_refreshes() {
        let mut map = UidMap::new();
        map.pin_tcp(40_000, 10_123);
        // Two lookups: the first may refresh the kernel tables, the second
        // cannot be allowed to forget the pin.
        assert_eq!(map.lookup_tcp(40_000), 10_123);
        map.invalidate();
        assert_eq!(map.lookup_tcp(40_000), 10_123);
        // An unpinned port still reads the real table (0 on a host with no
        // entry for it): the pin does not leak into it.
        let _ = map.lookup_tcp(12_345);
        assert_eq!(map.lookup_tcp(40_000), 10_123);
    }
}
