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

use crate::mitm::relay::TrafficSink;
use crate::packet::IpKey;
use std::collections::HashMap;
use crate::sys::fd::RawFd;
use crate::sys::libc;

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
    /// Datagram bytes the client pushed through this mapping.
    pub sent: u64,
    /// Datagram bytes the server answered with.
    pub recv: u64,
    /// Where a retired mapping reports what crossed it — the same sink the TCP
    /// relays use, so datagrams land in the same per-app totals.
    pub traffic: Option<TrafficSink>,
    /// Instance token of `fd`, handed out by [`UdpNat::insert`].
    ///
    /// Zero in a flow that never entered a table. The forwarder's `epoll`
    /// registration is keyed on it: a mapping that reopens the same four-tuple
    /// on the descriptor number the expired one freed is otherwise
    /// indistinguishable from its predecessor, and the new socket would never
    /// be waited on.
    pub id: u64,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        // Idle expiry, a policy retire and the shutdown clear all end here, so
        // this is the one place a mapping can report its traffic. A flow that
        // moved nothing reports nothing.
        if self.sent != 0 || self.recv != 0 {
            if let Some(sink) = self.traffic {
                let app = self.app_packages.first().map(String::as_str).unwrap_or("");
                sink(app, self.sent, self.recv);
            }
        }
        // The engine created this descriptor (and had the app protect it), so
        // retiring the mapping must close it. -1 is a test sentinel.
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// One NAT mapping's descriptor as the forwarder's wait set needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPoll {
    /// Instance token of `fd`; see [`UdpFlow::id`].
    pub id: u64,
    pub key: UdpKey,
    pub fd: RawFd,
}

/// Every live UDP mapping.
pub struct UdpNat {
    flows: HashMap<UdpKey, UdpFlow>,
    /// Next instance token to hand out; see [`UdpFlow::id`].
    next_id: u64,
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
            next_id: 1,
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

    pub fn insert(&mut self, mut flow: UdpFlow) {
        // The token is handed out here rather than at construction so that a
        // mapping which reuses a retired one's four-tuple — and, once that one
        // closed, its descriptor number — is a different instance as far as the
        // wait set is concerned.
        flow.id = self.next_id;
        self.next_id += 1;
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

    /// The descriptors to wait on, each with the key that identifies its
    /// mapping when a reply comes in and the instance token that says which
    /// socket its descriptor is. Retired mappings are left out: they will be
    /// dropped on the next housekeeping pass.
    pub fn poll_snapshot(&self) -> Vec<UdpPoll> {
        self.flows
            .values()
            .filter(|f| !f.retire && f.fd >= 0)
            .map(|f| UdpPoll {
                id: f.id,
                key: f.key,
                fd: f.fd,
            })
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
            sent: 0,
            recv: 0,
            traffic: None,
            id: 0,
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
            sent: 0,
            recv: 0,
            traffic: None,
            id: 0,
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
            sent: 0,
            recv: 0,
            traffic: None,
            id: 0,
        });
        let snapshot = nat.poll_snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].fd, 7);
        assert_eq!(snapshot[0].key, key(5000));
        assert_ne!(snapshot[0].id, 0, "insert must token the mapping");
    }

    /// What the last retired mapping reported.
    static REPORTED: std::sync::Mutex<(String, u64, u64)> =
        std::sync::Mutex::new((String::new(), 0, 0));

    fn record(app: &str, sent: u64, recv: u64) {
        let mut slot = REPORTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = (app.to_string(), sent, recv);
    }

    fn reported() -> (String, u64, u64) {
        REPORTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn counted_flow(port: u16, sent: u64, recv: u64) -> UdpFlow {
        UdpFlow {
            fd: -1,
            key: key(port),
            template: Vec::new(),
            last_ms: 1000,
            app_packages: vec!["com.example.app".to_string()],
            retire: false,
            proxied: false,
            sent,
            recv,
            traffic: Some(record),
            // UdpNat::insert hands out the real token.
            id: 0,
        }
    }

    /// A datagram mapping reports both directions once it is reaped, exactly
    /// like a TCP relay, so the per-app totals hold one row per connection.
    #[test]
    fn a_retired_mapping_reports_its_datagrams() {
        let mut nat = UdpNat::new();
        nat.insert(counted_flow(5000, 120, 3400));
        assert_eq!(nat.expire(1000 + UDP_FLOW_IDLE_MS + 1), 1);
        assert_eq!(reported(), ("com.example.app".to_string(), 120, 3400));

        // A mapping that never carried a datagram is not a row: the report is
        // still the previous one.
        let mut quiet = UdpNat::new();
        quiet.insert(counted_flow(5001, 0, 0));
        drop(quiet);
        assert_eq!(reported(), ("com.example.app".to_string(), 120, 3400));
    }

    /// A policy retire is a retirement too — the flag path must report as well.
    #[test]
    fn a_retired_flag_reports_before_the_mapping_goes() {
        let mut nat = UdpNat::new();
        nat.insert(counted_flow(5002, 512, 0));
        nat.retire_matching(|_| true);
        assert_eq!(nat.expire(1000), 1);
        assert_eq!(reported(), ("com.example.app".to_string(), 512, 0));
    }
}
