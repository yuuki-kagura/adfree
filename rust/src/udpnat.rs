//! UDP NAT for relayed flows.
//!
//! Everything that is neither DNS (handled by the dedicated forwarder) nor
//! deliberately dropped (QUIC, DoT, blocked addresses) is spliced through a
//! protected, `connect()`ed datagram socket: the client's datagrams go out
//! unchanged, and replies are rewritten back into the tunnel with
//! [`crate::packet::Packet::rewrite_udp`].
//!
//! Like TCP relays, mappings are added from the tun thread but only reaped on
//! the forwarder thread — the one that polls their descriptors — so a file
//! descriptor is never closed under a running `poll()`.

use crate::packet::IpKey;
use std::collections::HashMap;
use std::os::unix::io::RawFd;

/// How long a mapping may stay silent before it is dropped. Long enough for
/// keepalives (games, VoIP), short enough that one-shot lookups do not pin
/// descriptors.
pub const UDP_FLOW_IDLE_MS: u64 = 60_000;

/// Safety cap: a single app spraying destination ports must not be able to
/// exhaust the process descriptor budget.
pub const UDP_MAX_FLOWS: usize = 512;

/// Proxied mappings each own a helper thread and a SOCKS5 association, so they
/// get a much smaller cap than direct sockets.
pub const UDP_MAX_PROXIED_FLOWS: usize = 64;

/// Identity of one NAT mapping: who sent it and where it is headed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpKey {
    pub client: IpKey,
    pub client_port: u16,
    pub server: IpKey,
    pub server_port: u16,
}

/// One client <-> server UDP mapping.
pub struct UdpFlow {
    /// Protected, connected datagram socket towards the server.
    pub fd: RawFd,
    pub key: UdpKey,
    /// The client's first datagram, kept as the template replies are rewritten
    /// from (addresses and ports swapped, checksums recomputed).
    pub template: Vec<u8>,
    pub last_ms: u64,
    /// Packages that own the mapping, resolved once when it opens. The app
    /// firewall reevaluates them when the network or screen state changes.
    pub app_packages: Vec<String>,
    /// Set by a policy change from another thread; the forwarder drops the
    /// mapping on its next pass, so its descriptor is never closed under poll.
    pub retire: bool,
    /// The descriptor is the engine end of a bridge to a UDP ASSOCIATE thread
    /// instead of a connected socket: payloads are raw server data and a clean
    /// EOF means the thread is gone.
    pub proxied: bool,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        // The engine created this descriptor (and had the app protect it), so
        // retiring the mapping must close it. -1 is a test sentinel.
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// Every live UDP mapping.
pub struct UdpNat {
    flows: HashMap<UdpKey, UdpFlow>,
}

impl Default for UdpNat {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpNat {
    pub fn new() -> Self {
        UdpNat {
            flows: HashMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn get_mut(&mut self, key: &UdpKey) -> Option<&mut UdpFlow> {
        self.flows.get_mut(key)
    }

    /// How many mappings are relayed through a SOCKS5 proxy.
    pub fn proxied_len(&self) -> usize {
        self.flows.values().filter(|f| f.proxied).count()
    }

    pub fn insert(&mut self, flow: UdpFlow) {
        self.flows.insert(flow.key, flow);
    }

    pub fn remove(&mut self, key: &UdpKey) -> Option<UdpFlow> {
        self.flows.remove(key)
    }

    /// Drops every mapping (closing their descriptors). Used on shutdown so a
    /// restart never inherits sockets nobody polls anymore.
    pub fn clear(&mut self) {
        self.flows.clear();
    }

    /// Marks mappings matching `retire` for removal. The descriptors are owned
    /// by the forwarder thread, so this only flags them; [`Self::expire`]
    /// performs the actual drop on that thread.
    pub fn retire_matching(&mut self, retire: impl Fn(&UdpFlow) -> bool) {
        for flow in self.flows.values_mut() {
            if retire(flow) {
                flow.retire = true;
            }
        }
    }

    /// Frees mappings that have been silent for too long or were retired by a
    /// policy change; their descriptors are closed by [`UdpFlow`]'s drop.
    pub fn expire(&mut self, now: u64) -> usize {
        let before = self.flows.len();
        self.flows
            .retain(|_, f| !f.retire && now.saturating_sub(f.last_ms) < UDP_FLOW_IDLE_MS);
        before - self.flows.len()
    }

    /// The descriptors to poll, each paired with the key that identifies its
    /// mapping when a reply comes in. Retired mappings are left out: they will
    /// be dropped on the next housekeeping pass.
    pub fn poll_snapshot(&self) -> Vec<(UdpKey, RawFd)> {
        self.flows
            .values()
            .filter(|f| !f.retire)
            .map(|f| (f.key, f.fd))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> UdpKey {
        UdpKey {
            client: IpKey::V4(0x0a00_0002),
            client_port: 40000,
            server: IpKey::V4(0x0808_0808),
            server_port: port,
        }
    }

    #[test]
    fn flows_are_found_by_key() {
        let mut nat = UdpNat::new();
        nat.insert(UdpFlow {
            fd: -1,
            key: key(5000),
            template: Vec::new(),
            last_ms: 1000,
            app_packages: Vec::new(),
            retire: false,
            proxied: false,
        });
        assert_eq!(nat.len(), 1);
        assert!(nat.get_mut(&key(5000)).is_some());
        assert!(nat.get_mut(&key(5001)).is_none());
    }

    #[test]
    fn silent_flows_are_expired() {
        let mut nat = UdpNat::new();
        nat.insert(UdpFlow {
            fd: -1,
            key: key(5000),
            template: Vec::new(),
            last_ms: 1000,
            app_packages: Vec::new(),
            retire: false,
            proxied: false,
        });
        // Still fresh just under the threshold...
        assert_eq!(nat.expire(1000 + UDP_FLOW_IDLE_MS - 1), 0);
        // ...and gone just over it.
        assert_eq!(nat.expire(1000 + UDP_FLOW_IDLE_MS + 1), 1);
        assert!(nat.is_empty());
    }

    #[test]
    fn the_snapshot_carries_the_fd_and_key() {
        let mut nat = UdpNat::new();
        nat.insert(UdpFlow {
            fd: 7,
            key: key(5000),
            template: Vec::new(),
            last_ms: 1000,
            app_packages: Vec::new(),
            retire: false,
            proxied: false,
        });
        let snapshot = nat.poll_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].1, 7);
        assert_eq!(snapshot[0].0, key(5000));
    }
}
