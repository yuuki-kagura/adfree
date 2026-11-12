//! What the Windows redirector decides, kept apart from WinDivert itself.
//!
//! On Linux the kernel does this part: `nft` rewrites the destination of
//! matching packets, conntrack remembers what the connection was really for,
//! and `SO_ORIGINAL_DST` reads that memory back. Windows has no such tables, so
//! the port supplies them — and this module is that supply, expressed as pure
//! functions over packet bytes so it can be tested on a Linux laptop.
//!
//! The shape of the problem:
//!
//! * **outbound** — a client's `SYN` names the server. The connection is
//!   re-pointed at the proxy's own port, and the name is remembered under the
//!   client's endpoint, because every later packet of that connection still
//!   carries the server's address and has to be re-pointed too;
//! * **inbound** — the proxy answers as itself, and the client would drop that
//!   answer (it never opened a socket to the proxy). The source address is put
//!   back to the server's, which is the second half of the same illusion;
//! * **DNS** — queries are pointed at the local resolver and their answers
//!   pointed back, so a query to `8.8.8.8:53` is answered as if by `8.8.8.8`;
//! * **QUIC** — dropped, so an application falls back to TCP and its TLS can be
//!   filtered at all;
//! * **the proxy's own traffic** — never touched. It is recognised by the local
//!   port range it binds from, because Windows has no firewall mark to carry
//!   that fact (`sys::windows::mark_own_traffic` is empty for the same reason).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::packet::{self, IpKey, Packet, PROTO_TCP, PROTO_UDP};

/// The transparent proxy's listening port, matching Linux's redirect target.
pub const PROXY_PORT: u16 = 3129;
/// The local resolver's port, matching Linux's.
pub const DNS_PORT: u16 = 5300;

/// How long a remembered connection survives without traffic.
const TCP_IDLE: u64 = 600;
/// UDP mappings are shorter-lived: a DNS transaction is one request and one
/// answer, and a stale mapping would misdirect an unrelated later query.
const UDP_IDLE: u64 = 60;

/// An address and a port: the two things a mapping has to remember.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }

    pub fn v4(octets: [u8; 4], port: u16) -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::from(octets)),
            port,
        }
    }

    pub fn is_loopback(&self) -> bool {
        self.addr.is_loopback()
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

/// What to do with one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Leave it alone: it is not ours to redirect.
    Pass,
    /// Swallow it. QUIC, so that the same application will use TLS over TCP.
    Drop,
    /// Re-point it at this endpoint, remembering where it was going.
    Destination(Endpoint),
    /// Put this endpoint back as the source: the answer of a redirected flow.
    Source(Endpoint),
}

struct Mapping {
    target: Endpoint,
    seen: u64,
    proto: u8,
}

/// The redirect tables, and the rules that fill them.
pub struct Nat {
    proxy: Endpoint,
    dns: Endpoint,
    /// The local port range the proxy's own outbound sockets bind from. Traffic
    /// from here is never redirected: it is the proxy talking to an origin, and
    /// re-pointing it at the proxy is an infinite loop.
    own_ports: (u16, u16),
    /// Keyed by the *client's* endpoint, which is unique per connection.
    maps: HashMap<(IpKey, u16), Mapping>,
    /// Redirected endpoints, counted for the log line the desktop shows.
    redirected: u64,
    dropped: u64,
}

impl Nat {
    pub fn new(proxy: Endpoint, dns: Endpoint, own_ports: (u16, u16)) -> Self {
        Self {
            proxy,
            dns,
            own_ports,
            maps: HashMap::new(),
            redirected: 0,
            dropped: 0,
        }
    }

    pub fn proxy_endpoint(&self) -> Endpoint {
        self.proxy
    }

    pub fn dns_endpoint(&self) -> Endpoint {
        self.dns
    }

    pub fn redirected(&self) -> u64 {
        self.redirected
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn live_mappings(&self) -> usize {
        self.maps.len()
    }

    /// A packet leaving the machine.
    pub fn outbound(&mut self, pkt: &Packet<'_>, now: u64) -> Decision {
        let (Some(src), Some(dst)) = (pkt.src_ip(), pkt.dst_ip()) else {
            return Decision::Pass;
        };
        let from = Endpoint::new(src.as_ip(), pkt.src_port);
        let to = Endpoint::new(dst.as_ip(), pkt.dst_port);

        // The proxy's own dialling, and anything already aimed inside.
        if self.own_ports.0 <= from.port && from.port <= self.own_ports.1 {
            return Decision::Pass;
        }
        if to == self.proxy || to == self.dns || to.is_loopback() {
            return Decision::Pass;
        }

        match pkt.proto {
            PROTO_UDP => {
                // QUIC: no TLS handshake to filter, so no filtering at all.
                if to.port == 443 {
                    self.dropped += 1;
                    return Decision::Drop;
                }
                if to.port != 53 {
                    return Decision::Pass;
                }
                self.maps.insert(
                    (src, from.port),
                    Mapping {
                        target: to,
                        seen: now,
                        proto: PROTO_UDP,
                    },
                );
                self.redirected += 1;
                Decision::Destination(self.dns)
            }
            PROTO_TCP => {
                if to.port != 80 && to.port != 443 {
                    return Decision::Pass;
                }
                let key = (src, from.port);
                // A mid-flow packet (the redirector started after the client
                // did) still gets its connection, so the mapping is created by
                // any packet, not just a `SYN`.
                let entry = self.maps.entry(key).or_insert_with(|| Mapping {
                    target: to,
                    seen: now,
                    proto: PROTO_TCP,
                });
                entry.seen = now;
                self.redirected += 1;
                Decision::Destination(self.proxy)
            }
            _ => Decision::Pass,
        }
    }

    /// A packet arriving at the machine.
    pub fn inbound(&mut self, pkt: &Packet<'_>, now: u64) -> Decision {
        let (Some(src), Some(dst)) = (pkt.src_ip(), pkt.dst_ip()) else {
            return Decision::Pass;
        };
        let from = Endpoint::new(src.as_ip(), pkt.src_port);
        if from != self.proxy && from != self.dns {
            return Decision::Pass;
        }
        let key = (dst, pkt.dst_port);
        let Some(entry) = self.maps.get_mut(&key) else {
            return Decision::Pass;
        };
        entry.seen = now;
        let target = entry.target;
        // The answer is the last thing a UDP mapping is needed for.
        if entry.proto == PROTO_UDP {
            self.maps.remove(&key);
        }
        Decision::Source(target)
    }

    /// Forgets connections that have been quiet for too long. Called from the
    /// redirector's loop once a second, so a long-lived machine does not
    /// accumulate a mapping per connection it has ever seen.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.maps.len();
        self.maps.retain(|_, m| {
            let idle = if m.proto == PROTO_UDP { UDP_IDLE } else { TCP_IDLE };
            now.saturating_sub(m.seen) < idle
        });
        before - self.maps.len()
    }
}

/// The only facts the rewrite needs from a parsed packet, copied out so the
/// buffer can be edited while they are still in hand: a `Packet` borrows the
/// bytes it describes, and the edit is exactly a mutable borrow of them.
#[derive(Debug, Clone, Copy)]
pub struct Shape {
    version: u8,
    proto: u8,
    l4_offset: usize,
    ip_hdr_len: usize,
}

impl Shape {
    pub fn of(pkt: &Packet<'_>) -> Self {
        Self {
            version: pkt.version,
            proto: pkt.proto,
            l4_offset: pkt.l4_offset,
            ip_hdr_len: pkt.ip_hdr_len,
        }
    }
}

/// Writes a new destination into a packet and fixes its checksums.
///
/// The L4 ports follow the address: a redirect that re-points an address but
/// leaves the port would send the packet to a different service than the one it
/// asked for, and one that re-points the port but leaves the address would be
/// routed to a machine that is not running the proxy.
pub fn set_destination(raw: &mut [u8], shape: Shape, to: Endpoint) -> bool {
    if !write_endpoint(raw, shape, to, Side::Destination) {
        return false;
    }
    if shape.version == 4 {
        packet::fix_ipv4_checksum(raw);
    }
    // WinDivert recomputes L4 checksums on injection
    // (`WinDivertHelperCalcChecksums`), so this is only for tests and for the
    // case where the helper is unavailable.
    packet::fix_l4_checksum_raw(raw, shape.version, shape.ip_hdr_len, shape.l4_offset, proto_of(shape));
    true
}

/// Writes the original destination back as the source of an answer.
pub fn set_source(raw: &mut [u8], shape: Shape, from: Endpoint) -> bool {
    if !write_endpoint(raw, shape, from, Side::Source) {
        return false;
    }
    if shape.version == 4 {
        packet::fix_ipv4_checksum(raw);
    }
    packet::fix_l4_checksum_raw(raw, shape.version, shape.ip_hdr_len, shape.l4_offset, proto_of(shape));
    true
}

fn proto_of(shape: Shape) -> u8 {
    shape.proto
}

enum Side {
    Source,
    Destination,
}

fn write_endpoint(raw: &mut [u8], shape: Shape, ep: Endpoint, side: Side) -> bool {
    let l4 = shape.l4_offset;
    if l4 + 4 > raw.len() {
        return false;
    }
    let port_at = match side {
        Side::Source => l4,
        Side::Destination => l4 + 2,
    };
    raw[port_at..port_at + 2].copy_from_slice(&ep.port.to_be_bytes());
    match (shape.version, ep.addr) {
        (4, IpAddr::V4(v4)) => {
            let at = if matches!(side, Side::Source) { 12 } else { 16 };
            raw[at..at + 4].copy_from_slice(&v4.octets());
            true
        }
        (6, IpAddr::V6(v6)) => {
            let at = if matches!(side, Side::Source) { 8 } else { 24 };
            raw[at..at + 16].copy_from_slice(&v6.octets());
            true
        }
        // A family change is not a rewrite, it is a different connection: the
        // proxy is reached over v4 loopback and a v6 packet cannot be turned
        // into a v4 one without rebuilding the header.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    /// A TCP segment as the client would send it: IPv4, one SYN.
    fn tcp_v4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
        let mut out = vec![0u8; 20 + 20];
        out[0] = 0x45;
        out[2..4].copy_from_slice(&40u16.to_be_bytes());
        out[8] = 64;
        out[9] = PROTO_TCP;
        out[12..16].copy_from_slice(&src);
        out[16..20].copy_from_slice(&dst);
        packet::fix_ipv4_checksum(&mut out);
        out[20..22].copy_from_slice(&sport.to_be_bytes());
        out[22..24].copy_from_slice(&dport.to_be_bytes());
        out[32] = 0x50; // data offset 5
        out[33] = flags;
        out[34..36].copy_from_slice(&65535u16.to_be_bytes());
        out
    }

    fn udp_v4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut out = vec![0u8; total];
        out[0] = 0x45;
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[8] = 64;
        out[9] = PROTO_UDP;
        out[12..16].copy_from_slice(&src);
        out[16..20].copy_from_slice(&dst);
        packet::fix_ipv4_checksum(&mut out);
        out[20..22].copy_from_slice(&sport.to_be_bytes());
        out[22..24].copy_from_slice(&dport.to_be_bytes());
        out[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        out[28..].copy_from_slice(payload);
        out
    }

    fn nat() -> Nat {
        Nat::new(
            Endpoint::v4([127, 0, 0, 1], PROXY_PORT),
            Endpoint::v4([127, 0, 0, 1], DNS_PORT),
            (40000, 40999),
        )
    }

    #[test]
    fn a_clients_syn_is_pointed_at_the_proxy() {
        let raw = tcp_v4([192, 168, 1, 5], 50000, [93, 184, 216, 34], 443, 0x02);
        let pkt = Packet::parse(&raw).unwrap();
        let mut nat = nat();
        assert_eq!(
            nat.outbound(&pkt, 0),
            Decision::Destination(Endpoint::v4([127, 0, 0, 1], PROXY_PORT))
        );
        assert_eq!(nat.live_mappings(), 1);
    }

    #[test]
    fn the_answer_carries_the_servers_address_back() {
        let raw = tcp_v4([192, 168, 1, 5], 50000, [93, 184, 216, 34], 443, 0x02);
        let mut nat = nat();
        nat.outbound(&Packet::parse(&raw).unwrap(), 0);

        // The proxy answers from its own port.
        let reply = tcp_v4([127, 0, 0, 1], PROXY_PORT, [192, 168, 1, 5], 50000, 0x12);
        let decision = nat.inbound(&Packet::parse(&reply).unwrap(), 1);
        assert_eq!(
            decision,
            Decision::Source(Endpoint::v4([93, 184, 216, 34], 443))
        );

        let mut rewritten = reply.clone();
        let shape = Shape::of(&Packet::parse(&rewritten).unwrap());
        let Decision::Source(server) = decision else {
            unreachable!()
        };
        assert!(set_source(&mut rewritten, shape, server));
        assert_eq!(&rewritten[12..16], &[93, 184, 216, 34]);
        assert_eq!(u16::from_be_bytes([rewritten[20], rewritten[21]]), 443);
        assert_eq!(packet::ipv4_checksum(&rewritten), 0);
    }

    #[test]
    fn a_redirected_syn_names_the_proxy_and_verifies() {
        let raw = tcp_v4([192, 168, 1, 5], 50000, [93, 184, 216, 34], 443, 0x02);
        let mut rewritten = raw.clone();
        let shape = Shape::of(&Packet::parse(&rewritten).unwrap());
        assert!(set_destination(
            &mut rewritten,
            shape,
            Endpoint::v4([127, 0, 0, 1], PROXY_PORT)
        ));
        assert_eq!(&rewritten[16..20], &[127, 0, 0, 1]);
        assert_eq!(
            u16::from_be_bytes([rewritten[22], rewritten[23]]),
            PROXY_PORT
        );
        assert_eq!(packet::ipv4_checksum(&rewritten), 0);
        let after = Packet::parse(&rewritten).unwrap();
        // A checksum computed over the segment that carries it sums to zero.
        assert_eq!(
            packet::tcp_checksum_v4(&rewritten[..20], &rewritten[20..]),
            0,
            "the TCP checksum must cover the new address"
        );
        assert_eq!(after.dst_ip(), Some(IpKey::V4(u32::from_be_bytes([127, 0, 0, 1]))));
    }

    #[test]
    fn a_later_packet_of_the_same_connection_is_redirected_too() {
        let syn = tcp_v4([192, 168, 1, 5], 50000, [93, 184, 216, 34], 443, 0x02);
        let mut nat = nat();
        nat.outbound(&Packet::parse(&syn).unwrap(), 0);
        // The client's ACK still names the server: nothing on this machine has
        // told it otherwise, and nothing should.
        let ack = tcp_v4([192, 168, 1, 5], 50000, [93, 184, 216, 34], 443, 0x10);
        assert_eq!(
            nat.outbound(&Packet::parse(&ack).unwrap(), 1),
            Decision::Destination(Endpoint::v4([127, 0, 0, 1], PROXY_PORT))
        );
    }

    #[test]
    fn quic_is_dropped_so_the_app_falls_back_to_tls() {
        let raw = udp_v4([192, 168, 1, 5], 51000, [142, 250, 80, 46], 443, &[0u8; 8]);
        let mut nat = nat();
        assert_eq!(nat.outbound(&Packet::parse(&raw).unwrap(), 0), Decision::Drop);
        assert_eq!(nat.dropped(), 1);
    }

    #[test]
    fn a_dns_query_is_answered_as_if_by_the_server_it_named() {
        let query = udp_v4([192, 168, 1, 5], 52000, [8, 8, 8, 8], 53, &[1, 2, 3, 4]);
        let mut nat = nat();
        assert_eq!(
            nat.outbound(&Packet::parse(&query).unwrap(), 0),
            Decision::Destination(Endpoint::v4([127, 0, 0, 1], DNS_PORT))
        );
        let answer = udp_v4([127, 0, 0, 1], DNS_PORT, [192, 168, 1, 5], 52000, &[5, 6, 7, 8]);
        assert_eq!(
            nat.inbound(&Packet::parse(&answer).unwrap(), 1),
            Decision::Source(Endpoint::v4([8, 8, 8, 8], 53))
        );
        // The mapping is spent: a second answer cannot be attributed.
        assert_eq!(nat.live_mappings(), 0);
    }

    #[test]
    fn the_proxys_own_dialling_is_left_alone() {
        // From inside the proxy's port range, to a real server.
        let raw = tcp_v4([192, 168, 1, 5], 40100, [93, 184, 216, 34], 443, 0x02);
        let mut nat = nat();
        assert_eq!(nat.outbound(&Packet::parse(&raw).unwrap(), 0), Decision::Pass);
        assert_eq!(nat.live_mappings(), 0);
    }

    #[test]
    fn traffic_already_inside_is_left_alone() {
        let raw = tcp_v4([192, 168, 1, 5], 50000, [127, 0, 0, 1], PROXY_PORT, 0x02);
        let mut nat = nat();
        assert_eq!(nat.outbound(&Packet::parse(&raw).unwrap(), 0), Decision::Pass);
    }

    #[test]
    fn a_quiet_connection_is_forgotten() {
        let syn = tcp_v4([192, 168, 1, 5], 50000, [93, 184, 216, 34], 443, 0x02);
        let mut nat = nat();
        nat.outbound(&Packet::parse(&syn).unwrap(), 0);
        assert_eq!(nat.live_mappings(), 1);
        assert_eq!(nat.sweep(TCP_IDLE + 1), 1);
        assert_eq!(nat.live_mappings(), 0);
    }

    #[test]
    fn ipv6_keeps_its_own_family() {
        let mut raw = vec![0u8; 40 + 20];
        raw[0] = 0x60;
        raw[4..6].copy_from_slice(&20u16.to_be_bytes());
        raw[6] = PROTO_TCP;
        raw[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        raw[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        raw[40..42].copy_from_slice(&50000u16.to_be_bytes());
        raw[42..44].copy_from_slice(&443u16.to_be_bytes());
        raw[52] = 0x50;
        let shape = Shape::of(&Packet::parse(&raw).unwrap());
        assert!(set_destination(
            &mut raw,
            shape,
            Endpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), PROXY_PORT)
        ));
        assert_eq!(u16::from_be_bytes([raw[42], raw[43]]), PROXY_PORT);
    }
}
