//! Upstream DNS forwarder.
//!
//! The VPN sits between the apps and the world, so every query the filter core
//! does not block has to be forwarded to a real resolver and its answer relayed
//! back. Doing that on the packet path would mean creating a socket per query,
//! so this module owns a small pool of sockets that the JNI layer has already
//! run `VpnService.protect()` on (their traffic bypasses the tunnel, otherwise
//! DNS would loop) plus a single poll thread serving all of them.
//!
//! Battery notes:
//! * the poll thread wakes up only when a socket is readable, and the timeout is
//!   stretched to a second when nothing is in flight — no periodic work at all;
//! * transaction ids are rewritten to locally unique values, so a reply is
//!   matched with one hash lookup and a stuck query just times out.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;

/// Number of parallel upstream sockets.
pub const SOCKET_POOL_PUB: usize = 4;
const SOCKET_POOL: usize = SOCKET_POOL_PUB;
const QUERY_TIMEOUT_MS: u64 = 12_000;
const MAX_MESSAGE: usize = 4096;
const MAX_REPLIES_PER_POLL: usize = 32;

/// A query that is currently in flight.
#[derive(Clone)]
pub struct Pending {
    pub client_txid: u16,
    pub socket: u8,
    /// Original client DNS message with our own transaction id patched in.
    pub packet: Vec<u8>,
    pub sent_ms: u64,
}

/// An answer that came back from upstream.
pub struct Reply {
    pub pending: Pending,
    pub socket: u8,
    pub message: Vec<u8>,
}

pub struct Upstream {
    fds: Vec<RawFd>,
    resolver: SocketAddr,
    pending: HashMap<u32, Pending>,
    next_txid: u32,
    timeouts: u64,
}

impl Upstream {
    pub fn new(resolver: SocketAddr) -> Self {
        Upstream {
            fds: vec![-1; SOCKET_POOL],
            resolver,
            pending: HashMap::new(),
            next_txid: 0x8000,
            timeouts: 0,
        }
    }

    /// Replaces the socket pool with descriptors that Java has protected.
    pub fn set_socket_fds(&mut self, fds: &[RawFd]) {
        for (i, fd) in self.fds.iter_mut().enumerate() {
            *fd = fds.get(i).copied().unwrap_or(-1);
        }
    }

    pub fn is_ready(&self) -> bool {
        self.fds.iter().any(|fd| *fd > 0)
    }

    pub fn resolver(&self) -> SocketAddr {
        self.resolver
    }

    pub fn set_resolver(&mut self, resolver: SocketAddr) {
        if self.resolver != resolver {
            self.resolver = resolver;
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()    }

    pub fn timeouts(&self) -> u64 {
        self.timeouts
    }

    /// Allocates the next locally unique transaction id.
    pub fn alloc_txid(&mut self) -> u16 {
        let id = (self.next_txid & 0x7fff) as u16;
        self.next_txid = (self.next_txid + 1) & 0x7fff;
        id
    }

    /// Builds the `sockaddr_in` used for every `sendto`. Separated out so the
    /// byte order of `s_addr` is covered by a unit test.
    pub(crate) fn sockaddr_for(addr: &SocketAddr) -> libc::sockaddr_in {
        match addr {
            SocketAddr::V4(a) => libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            },
            _ => libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            },
        }
    }

    /// Sends one query. `socket` is the preferred pool slot (chosen by the
    /// caller so a host keeps using the same socket); if that slot has no
    /// descriptor the first usable one is taken instead, so a partially
    /// populated pool still works. Returns the key used to match the reply, or
    /// `None` when no socket is usable.
    pub fn send(
        &mut self,
        socket: usize,
        packet: &[u8],
        client_txid: u16,
        txid: u16,
        now_ms: u64,
    ) -> Option<u32> {
        // `self.fds.get(socket)` covers both "out of range" and "slot empty".
        if self.fds.get(socket).is_some_and(|fd| *fd > 0) {
            self.send_on(socket, packet, client_txid, txid, now_ms)
        } else {
            let fallback = self.fds.iter().position(|fd| *fd > 0)?;
            self.send_on(fallback, packet, client_txid, txid, now_ms)
        }
    }

    fn send_on(
        &mut self,
        socket: usize,
        packet: &[u8],
        client_txid: u16,
        txid: u16,
        now_ms: u64,
    ) -> Option<u32> {
        let fd = *self.fds.get(socket)?;
        if fd <= 0 {
            return None;
        }
        if packet.len() > MAX_MESSAGE + 40 {
            return None;
        }
        // `packet` is the client's IP packet; only its DNS payload goes on the
        // wire, so strip the IP and UDP headers.
        let Some(payload) = dns_payload(packet) else {
            crate::logbuf::push(&format!(
                "dns forward: no payload in a {}-byte packet",
                packet.len()
            ));
            return None;
        };
        // One place builds the sockaddr (byte order covered by a unit test).
        let sent = match self.resolver {
            SocketAddr::V4(_) => sendto(fd, payload, Self::sockaddr_for(&self.resolver)),
            SocketAddr::V6(a) => sendto6(fd, payload, a),
        };
        if sent < 0 {
            let err = std::io::Error::last_os_error();
            crate::logbuf::push(&format!(
                "dns forward: sendto {} on fd {} (slot {socket}) failed: {}",
                self.resolver, fd, err
            ));
            return None;
        }

        let key = pending_key(socket, txid);
        self.pending.insert(
            key,
            Pending {
                client_txid,
                socket: socket as u8,
                packet: packet.to_vec(),
                sent_ms: now_ms,
            },
        );
        Some(key)
    }

    /// Waits for answers, reusing `out` to avoid allocating per wakeup.
    ///
    /// `timeout_ms` is explicit so a caller can wait for a long while only when
    /// it holds no lock a UI thread might need. Holding the upstream lock
    /// across a long `poll()` stalls `set_resolver` for that whole time.
    pub fn poll(&mut self, out: &mut Vec<Reply>, timeout_ms: libc::c_int) -> usize {
        let mut fds: [libc::pollfd; SOCKET_POOL] = unsafe { std::mem::zeroed() };
        for (i, fd) in self.fds.iter().enumerate() {
            fds[i] = libc::pollfd {
                fd: *fd,
                events: libc::POLLIN,
                revents: 0,
            };
        }
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), SOCKET_POOL as libc::nfds_t, timeout_ms) };
        if rc <= 0 {
            return 0;
        }

        let mut buf = [0u8; MAX_MESSAGE];
        let mut received = 0;
        for (i, p) in fds.iter().enumerate() {
            // Drain every pending datagram: poll reports that data is ready but not how
        // much, so read until EWOULDBLOCK.
            if p.revents & libc::POLLIN == 0 {
                continue;
            }
            loop {
                let n = unsafe {
                    libc::recv(
                        p.fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n <= 0 {
                    break; // nothing left, or EWOULDBLOCK
                }
                let msg = &buf[..n as usize];
                if msg.len() < 12 {
                    continue;
                }
                let txid = u16::from_be_bytes([msg[0], msg[1]]);
                let key = pending_key(i, txid);
                match self.pending.remove(&key) {
                    Some(pending) => {
                        out.push(Reply {
                            pending,
                            socket: i as u8,
                            message: msg.to_vec(),
                        });
                        received += 1;
                        // At most 32 replies per poll; the rest come on the next tick.
                        if received >= MAX_REPLIES_PER_POLL {
                            return received;
                        }
                    }
                    None => continue,
                }
            }
        }
        received
    }

    /// Drops queries that were never answered.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, p)| now_ms.saturating_sub(p.sent_ms) > QUERY_TIMEOUT_MS)
            .map(|(k, _)| *k)
            .collect();
        let count = expired.len();
        for key in expired {
            self.pending.remove(&key);
            self.timeouts += 1;
        }
        count
    }

    pub fn clear(&mut self) {
        self.pending.clear();
    }
}

/// Returns the DNS message inside a client IP packet.
fn dns_payload(packet: &[u8]) -> Option<&[u8]> {
    let parsed = crate::packet::Packet::parse(packet)?;
    if parsed.proto != crate::packet::PROTO_UDP {
        return None;
    }
    let start = parsed.l4_payload_offset();
    if start >= packet.len() {
        return None;
    }
    Some(&packet[start..parsed.total_len.min(packet.len())])
}

#[inline]
fn sendto(
    fd: RawFd,
    packet: &[u8],
    sock: libc::sockaddr_in,
) -> isize {
    unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            &sock as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    }
}

#[inline]
fn sendto6(fd: RawFd, packet: &[u8], a: std::net::SocketAddrV6) -> isize {
    let sock = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: a.port().to_be(),
        sin6_flowinfo: a.flowinfo(),
        sin6_addr: libc::in6_addr {
            s6_addr: a.ip().octets(),
        },
        sin6_scope_id: a.scope_id(),
    };
    unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            &sock as *const libc::sockaddr_in6 as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    }
}

#[inline]
fn pending_key(socket: usize, txid: u16) -> u32 {
    ((socket as u32) << 16) | txid as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn upstream() -> Upstream {
        Upstream::new(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(9, 9, 9, 9),
            53,
        )))
    }

    #[test]
    fn txid_is_unique_until_wrap() {
        let mut u = upstream();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32_000 {
            assert!(seen.insert(u.alloc_txid()));
        }
        assert!(u.alloc_txid() < 0x8000);
    }

    #[test]
    fn pending_keys_do_not_collide_across_sockets() {
        assert_ne!(pending_key(0, 1), pending_key(1, 1));
        assert_eq!(pending_key(3, 0x1234), (3 << 16) | 0x1234);
    }

    #[test]
    fn send_fails_without_sockets() {
        let mut u = upstream();
        assert!(u.send(0, &[0u8; 32], 1, 2, 0).is_none());
        assert_eq!(u.pending_len(), 0);
    }

    #[test]
    fn sockaddr_uses_network_byte_order() {
        let resolver = SocketAddr::V4(SocketAddrV4::new(
            std::net::Ipv4Addr::new(94, 140, 14, 14),
            53,
        ));
        let sock = Upstream::sockaddr_for(&resolver);
        // The real contract: the RAM bytes of s_addr must be the address's octets
        // in order, because the kernel reads s_addr as network byte order. Getting
        // this wrong makes sendto() return EINVAL.
        assert_eq!(
            sock.sin_addr.s_addr.to_ne_bytes(),
            [94, 140, 14, 14],
            "s_addr must hold the octets in order"
        );
        assert_eq!(sock.sin_addr.s_addr.to_be(), 0x5e8c_0e0e);
        // The port must be in network byte order too.
        assert_eq!(sock.sin_port, 53u16.to_be());
    }

    #[test]
    fn expire_drops_stale_queries() {
        let mut u = upstream();
        // Fake a pending entry without a socket.
        u.pending.insert(
            7,
            Pending {
                client_txid: 1,
                socket: 0,
                packet: vec![0u8; 20],
                sent_ms: 1_000,
            },
        );
        assert_eq!(u.expire(1_000 + QUERY_TIMEOUT_MS + 1), 1);
        assert_eq!(u.pending_len(), 0);
        assert_eq!(u.timeouts(), 1);
    }

    #[test]
    fn poll_with_no_sockets_returns_zero() {
        let mut u = upstream();
        let mut out = Vec::new();
        // Sockets are `-1`: poll must not hang or crash.
        assert_eq!(u.poll(&mut out, 0), 0);
    }
}
