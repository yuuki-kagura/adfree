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
/// A silent primary is retried through the fallback after this long.
///
/// The resolver this device talks to drops the odd query, and Android's own
/// stub gives a lookup roughly a second before it retries or fails, so a
/// two-second wait turned every dropped packet into a visible stall. The
/// retry is now hedged: a duplicate is a few dozen bytes, and the first
/// answer wins, so a short delay can only help. It stays above the warm
/// latency of a healthy resolver (~60-80 ms here), which keeps every lookup
/// from being sent twice.
const BACKUP_AFTER_MS: u64 = 100;
/// Encrypted transports pay a handshake before the first answer and were
/// chosen for their privacy, so a slow reply must not be duplicated in the
/// clear. Only a resolver that is clearly not going to answer is retried.
pub const SECURE_BACKUP_AFTER_MS: u64 = 2_000;
const MAX_MESSAGE: usize = 4096;
const MAX_REPLIES_PER_POLL: usize = 32;

/// Why a query is in flight. A SafeSearch lookup carries the client packet it
/// is standing in for, so its answer becomes a synthetic reply for that packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Client,
    SafeSearch,
}

/// A query that is currently in flight.
#[derive(Clone)]
pub struct Pending {
    pub client_txid: u16,
    pub socket: u8,
    /// Original client DNS message with our own transaction id patched in.
    pub packet: Vec<u8>,
    pub sent_ms: u64,
    pub purpose: Purpose,
    /// The filtered host a SafeSearch query was sent to; empty otherwise.
    pub safe_host: String,
    /// The primary never answered and the query now waits on the fallback.
    pub via_backup: bool,
    /// How long this query waits for the primary before the fallback is
    /// tried; plain UDP races ahead, encrypted transports are given time to
    /// finish their handshake.
    pub backup_after_ms: u64,
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
    /// Plain UDP resolver tried once when the primary stays silent.
    backup: Option<SocketAddr>,
    pending: HashMap<u32, Pending>,
    next_txid: u32,
    timeouts: u64,
}

impl Upstream {
    pub fn new(resolver: SocketAddr) -> Self {
        Upstream {
            fds: vec![-1; SOCKET_POOL],
            resolver,
            backup: None,
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

    /// Pool descriptors, for the forwarder's combined wait.
    ///
    /// Slots that hold no socket are reported as `-1`; `poll` ignores those.
    pub fn socket_fds(&self) -> &[RawFd] {
        &self.fds
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

    /// Installs (or removes) the fallback resolver. Queries already waiting
    /// are unaffected until they are retried.
    pub fn set_backup(&mut self, backup: Option<SocketAddr>) {
        self.backup = backup;
    }

    pub fn backup(&self) -> Option<SocketAddr> {
        self.backup
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

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
        // `packet` is the client's IP packet; only its DNS payload goes on the
        // wire, so strip the IP and UDP headers.
        let payload = dns_payload(packet)?;
        let slot = self.slot(socket)?;
        self.send_payload(
            slot,
            payload,
            packet,
            client_txid,
            txid,
            now_ms,
            Purpose::Client,
            "",
        )
    }

    /// Sends one DNS message the engine built itself (SafeSearch's second
    /// lookup). `client_packet` is the packet the eventual reply stands in
    /// for; it is kept so the normal rewrite path can answer the client.
    pub fn send_message(
        &mut self,
        socket: usize,
        message: &[u8],
        client_packet: &[u8],
        client_txid: u16,
        txid: u16,
        now_ms: u64,
        safe_host: &str,
    ) -> Option<u32> {
        let slot = self.slot(socket)?;
        self.send_payload(
            slot,
            message,
            client_packet,
            client_txid,
            txid,
            now_ms,
            Purpose::SafeSearch,
            safe_host,
        )
    }

    /// The preferred pool slot, or the first usable one when that slot has no
    /// descriptor (a partially populated pool still works).
    fn slot(&self, socket: usize) -> Option<usize> {
        if self.fds.get(socket).is_some_and(|fd| *fd > 0) {
            Some(socket)
        } else {
            self.fds.iter().position(|fd| *fd > 0)
        }
    }

    fn send_payload(
        &mut self,
        slot: usize,
        payload: &[u8],
        packet: &[u8],
        client_txid: u16,
        txid: u16,
        now_ms: u64,
        purpose: Purpose,
        safe_host: &str,
    ) -> Option<u32> {
        let fd = *self.fds.get(slot)?;
        if payload.len() > MAX_MESSAGE {
            return None;
        }
        if !send_query(fd, payload, self.resolver) {
            crate::logbuf::push(&format!(
                "dns forward: sendto {} on fd {} (slot {slot}) failed: {}",
                self.resolver,
                fd,
                std::io::Error::last_os_error()
            ));
            return None;
        }

        let key = pending_key(slot, txid);
        self.pending.insert(
            key,
            Pending {
                client_txid,
                socket: slot as u8,
                packet: packet.to_vec(),
                sent_ms: now_ms,
                purpose,
                safe_host: safe_host.to_string(),
                via_backup: false,
                backup_after_ms: BACKUP_AFTER_MS,
            },
        );
        Some(key)
    }

    /// Re-sends a waiting query to the fallback resolver.
    ///
    /// The message already carries our transaction id, so the client keeps
    /// waiting for the same answer; the record moves to whichever pool slot
    /// actually sent it. `false` means no fallback is configured or the send
    /// failed, and the caller should give up on this query.
    pub fn retry_via_backup(&mut self, pending: &Pending, now_ms: u64) -> bool {
        let Some(backup) = self.backup else {
            return false;
        };
        let Some(payload) = dns_payload(&pending.packet) else {
            return false;
        };
        if payload.len() > MAX_MESSAGE {
            return false;
        }
        let Some(slot) = self.slot(pending.socket as usize) else {
            return false;
        };
        let fd = self.fds[slot];
        if !send_query(fd, payload, backup) {
            crate::logbuf::push(&format!(
                "dns fallback: sendto {backup} on fd {fd} failed: {}",
                std::io::Error::last_os_error()
            ));
            return false;
        }
        let txid = u16::from_be_bytes([payload[0], payload[1]]);
        let key = pending_key(slot, txid);
        let mut retried = pending.clone();
        retried.socket = slot as u8;
        retried.sent_ms = now_ms;
        retried.via_backup = true;
        // The old record may sit under a different slot; leaving it would let
        // a late primary answer race the fallback one.
        let stale: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, p)| p.client_txid == pending.client_txid && p.packet == pending.packet)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            self.pending.remove(&k);
        }
        self.pending.insert(key, retried);
        true
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

    /// Drops queries that were never answered, handing them back so the
    /// caller can answer SafeSearch clients with SERVFAIL instead of leaving
    /// them to time out.
    pub fn expire(&mut self, now_ms: u64) -> Vec<Pending> {
        // A silent primary moves to the fallback first; only a query that has
        // also waited out the full budget there is handed back as failed.
        let retry_due: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                !p.via_backup
                    && now_ms.saturating_sub(p.sent_ms) > p.backup_after_ms
                    && self.backup.is_some()
            })
            .map(|(k, _)| *k)
            .collect();
        let mut out = Vec::with_capacity(retry_due.len());
        for key in retry_due {
            let Some(pending) = self.pending.remove(&key) else {
                continue;
            };
            if !self.retry_via_backup(&pending, now_ms) {
                self.timeouts += 1;
                let mut failed = pending;
                // The fallback was the last resort, so callers answer the
                // client now instead of waiting for the primary's budget.
                failed.via_backup = true;
                out.push(failed);
            }
        }

        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, p)| now_ms.saturating_sub(p.sent_ms) > QUERY_TIMEOUT_MS)
            .map(|(k, _)| *k)
            .collect();
        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                out.push(pending);
            }
            self.timeouts += 1;
        }
        out
    }

    /// Milliseconds until some pending query is due attention: a silent
    /// primary is retried through the fallback, and every query is failed at
    /// the full budget. The forwarder caps its blocking wait with this so a
    /// retry fires when it is due instead of on the next idle tick, which was
    /// up to a second later. `None` means nothing is in flight.
    pub fn next_deadline_in(&self, now_ms: u64) -> Option<u64> {
        let fallback = self.backup.is_some();
        self.pending
            .values()
            .map(|p| {
                let due = if fallback && !p.via_backup {
                    p.sent_ms.saturating_add(p.backup_after_ms)
                } else {
                    p.sent_ms.saturating_add(QUERY_TIMEOUT_MS)
                };
                // `expire` uses a strict comparison, so a wait that ends
                // exactly on the deadline must not spin in a zero timeout.
                due.saturating_sub(now_ms).max(1)
            })
            .min()
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

/// One datagram to `resolver`, whichever address family it uses.
fn send_query(fd: RawFd, payload: &[u8], resolver: SocketAddr) -> bool {
    let sent = match resolver {
        SocketAddr::V4(_) => sendto(fd, payload, Upstream::sockaddr_for(&resolver)),
        SocketAddr::V6(a) => sendto6(fd, payload, a),
    };
    sent >= 0
}

#[inline]
fn sendto(fd: RawFd, packet: &[u8], sock: libc::sockaddr_in) -> isize {
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
                purpose: Purpose::Client,
                safe_host: String::new(),
                via_backup: false,
                backup_after_ms: BACKUP_AFTER_MS,
            },
        );
        assert_eq!(u.expire(1_000 + QUERY_TIMEOUT_MS + 1).len(), 1);
        assert_eq!(u.pending_len(), 0);
        assert_eq!(u.timeouts(), 1);
    }

    #[test]
    fn a_silent_primary_falls_back_before_the_full_budget() {
        let mut u = upstream();
        u.set_backup(Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 1),
            53,
        ))));
        u.pending.insert(
            7,
            Pending {
                client_txid: 1,
                socket: 0,
                packet: vec![0u8; 20],
                sent_ms: 1_000,
                purpose: Purpose::Client,
                safe_host: String::new(),
                via_backup: false,
                backup_after_ms: BACKUP_AFTER_MS,
            },
        );
        // Still inside the retry delay: the primary gets its chance.
        assert!(u.expire(1_000 + BACKUP_AFTER_MS).is_empty());
        // The retry delay lapsed. No pool socket exists here, so the send
        // fails and the query is handed back as a fallback failure.
        let expired = u.expire(1_000 + BACKUP_AFTER_MS + 1);
        assert_eq!(expired.len(), 1);
        assert!(expired[0].via_backup);
        assert_eq!(u.pending_len(), 0);
        assert_eq!(u.timeouts(), 1);
    }

    #[test]
    fn the_wake_deadline_follows_the_retry_delay() {
        let mut u = upstream();
        assert_eq!(u.next_deadline_in(1_000), None);
        u.pending.insert(
            7,
            Pending {
                client_txid: 1,
                socket: 0,
                packet: vec![0u8; 20],
                sent_ms: 1_000,
                purpose: Purpose::Client,
                safe_host: String::new(),
                via_backup: false,
                backup_after_ms: BACKUP_AFTER_MS,
            },
        );
        // Without a fallback there is nothing to do before the full budget.
        assert_eq!(u.next_deadline_in(1_000), Some(QUERY_TIMEOUT_MS));
        u.set_backup(Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 1),
            53,
        ))));
        assert_eq!(u.next_deadline_in(1_000), Some(BACKUP_AFTER_MS));
        assert_eq!(u.next_deadline_in(1_000 + BACKUP_AFTER_MS - 10), Some(10));
        // Exactly on the deadline the wait stays non-zero so the loop cannot
        // spin; the next pass has `expire` firing.
        assert_eq!(u.next_deadline_in(1_000 + BACKUP_AFTER_MS), Some(1));
    }

    #[test]
    fn poll_with_no_sockets_returns_zero() {
        let mut u = upstream();
        let mut out = Vec::new();
        // Sockets are `-1`: poll must not hang or crash.
        assert_eq!(u.poll(&mut out, 0), 0);
    }
}
