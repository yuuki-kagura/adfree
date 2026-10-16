//! The relay: one intercepted connection, end to end.
//!
//! ```text
//!   TUN ──▶ client TCP ──▶ ServerConnection ─▶ plaintext ─▶ ClientConnection ──▶ peer socket
//!   TUN ◀── client TCP ◀── ServerConnection ◀── plaintext ◀── ClientConnection ◀── peer socket
//! ```
//!
//! Every step returns the payloads to write back, so the packet loop stays in
//! charge of TCP segmentation and no syscall ever blocks.

use crate::mitm::proxy::ProxySession;
use crate::mitm::tcp::{Flow, FlowState};
use crate::util::now_ms;
use std::os::unix::io::RawFd;

/// Port we intercept for TLS termination. Everything else keeps flowing.
pub const MITM_PORT: u16 = 443;

/// Fallback payload cap when the client's SYN carried no MSS option.
pub const DEFAULT_MSS: usize = 1460;

/// One relayed connection.
///
/// `session` is `Some` only for TLS-terminated flows (HTTPS filtering): with
/// `None` the relay is a transparent splice that just moves bytes between the
/// client and the peer socket.
pub struct Relay {
    pub flow: Flow,
    pub session: Option<ProxySession>,
    /// Protected socket to the real server; the relay owns it and closes it on
    /// drop (-1 in tests).
    pub peer_fd: RawFd,
    /// The client's SYN, kept as the template for every reply we build.
    pub syn_packet: Vec<u8>,
    /// Set once either side is done.
    pub closed: bool,
    /// Largest TCP payload we may put in one segment towards the client.
    /// Anything above the client's MSS is dropped by its stack, and anything
    /// above the tunnel MTU cannot even be written to the descriptor.
    pub mss: usize,
    /// Last time either side moved bytes; the engine expires idle relays.
    pub last_ms: u64,
    /// The client already sent its FIN.
    pub client_fin: bool,
    /// The peer `connect()` has not completed yet: `send()` would fail with
    /// EAGAIN until the socket is writable, so bytes wait in `pending_to_peer`.
    pub connecting: bool,
    /// Peer connect attempts already spent; one retry is allowed after a
    /// failure, because a fresh socket picks a fresh source port.
    pub connect_retries: u8,
    /// Client bytes not yet accepted by the peer socket (it is connecting, or
    /// its send buffer is full). Flushed by the engine on the next writable.
    pub pending_to_peer: Vec<u8>,
    /// Set while some thread is inside `send()` for this relay, so two threads
    /// never interleave writes and scramble the byte order.
    pub flushing: bool,
    /// The client sent its FIN while bytes were still queued for the peer: the
    /// half-close waits until the queue is empty (writes are refused after).
    pub shutdown_after_flush: bool,
}

impl Relay {
    /// A relay that TLS-terminates: the client's HTTPS traffic is decrypted,
    /// filtered and re-encrypted towards the real server.
    pub fn new_tls(
        flow: Flow,
        peer_fd: RawFd,
        session: ProxySession,
        syn_packet: Vec<u8>,
        mss: usize,
        connecting: bool,
    ) -> Self {
        Relay {
            flow,
            session: Some(session),
            peer_fd,
            syn_packet,
            closed: false,
            mss,
            last_ms: now_ms(),
            client_fin: false,
            connecting,
            connect_retries: 0,
            pending_to_peer: Vec::new(),
            flushing: false,
            shutdown_after_flush: false,
        }
    }

    /// A relay that only splices bytes: no TLS, no filtering, used for every
    /// TCP flow that is not an HTTPS connection we intercept.
    pub fn new_plain(
        flow: Flow,
        peer_fd: RawFd,
        syn_packet: Vec<u8>,
        mss: usize,
        connecting: bool,
    ) -> Self {
        Relay {
            flow,
            session: None,
            peer_fd,
            syn_packet,
            closed: false,
            mss,
            last_ms: now_ms(),
            client_fin: false,
            connecting,
            connect_retries: 0,
            pending_to_peer: Vec::new(),
            flushing: false,
            shutdown_after_flush: false,
        }
    }

    /// Buffers client bytes until the peer connection is writable.
    pub fn queue_to_peer(&mut self, bytes: &[u8]) {
        self.pending_to_peer.extend_from_slice(bytes);
    }

    /// Turns a payload into the TCP segments addressed to the client.
    ///
    /// The relay owns the flow, so it is the right place to advance the
    /// client-facing sequence number; the engine just writes the result out.
    pub fn segments_for_client(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for chunk in Relay::split_segments(payload.to_vec(), self.mss) {
            let Some(pkt) = crate::packet::Packet::parse(&self.syn_packet) else {
                break;
            };
            let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
            let seg = crate::mitm::segment::build_data_segment(
                &pkt,
                seq,
                self.flow.acked_seq,
                &chunk,
            );
            match seg {
                Some(segment) => {
                    self.flow.up_bytes += chunk.len() as u64;
                    out.push(segment);
                }
                None => break,
            }
        }
        out
    }

    /// Is the client-facing half ready to carry application data?
    pub fn is_established(&self) -> bool {
        !self.closed
            && match &self.session {
                // A plain splice is always ready; the TLS half is only ready
                // once the handshake finished.
                Some(s) => !s.server_handshaking(),
                None => true,
            }
    }

    /// A segment arrived from the client.
    ///
    /// `seq` is the segment's own sequence number. Until our ACK reaches the
    /// client it retransmits, so duplicates and overlaps are routine and each
    /// byte may only be handed forward once: a second copy of a POST would hit
    /// the server twice, and a second copy of a TLS record would corrupt the
    /// rustls stream.
    ///
    /// Returns `(to_peer, to_client)`: both directions can produce bytes, because
    /// during the handshake our own answers count towards the client.
    pub fn on_client_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        if payload.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let expected = self.flow.acked_seq;
        let fresh = if seq == expected {
            payload
        } else if seq.wrapping_sub(expected) & 0x8000_0000 != 0 {
            // An older segment: the head was already forwarded, at best.
            let skipped = expected.wrapping_sub(seq) as usize;
            if skipped >= payload.len() {
                return Ok((Vec::new(), Vec::new())); // a pure retransmission
            }
            &payload[skipped..]
        } else {
            // A gap. Client packets are read straight off the tun device and
            // cannot be dropped by us, so this is a retransmission that raced
            // ahead of our ACK; stay quiet and the caller's ACK pulls the
            // missing hole back.
            return Ok((Vec::new(), Vec::new()));
        };
        // Every client byte must be acknowledged exactly once: the ACK the
        // caller sends after this call carries `acked_seq`, and without it the
        // client retransmits everything forever.
        self.flow.acked_seq = self.flow.acked_seq.wrapping_add(fresh.len() as u32);
        self.flow.down_bytes += fresh.len() as u64;
        self.last_ms = now_ms();
        let Some(session) = self.session.as_mut() else {
            // Plain splice: forward the bytes untouched.
            return Ok((fresh.to_vec(), Vec::new()));
        };
        let out = session.on_client_payload(fresh)?;
        if out.closed {
            self.closed = true;
        }
        Ok((out.to_peer, out.to_client))
    }

    /// Data arrived from the real server.
    ///
    /// Returns `(to_peer, to_client)`: the peer direction carries wire bytes
    /// the upstream half produced while processing server data (its protocol
    /// handshake finishing, plus a request that waited for it). Dropping those
    /// silently deadlocks the flow: the real server never sees the client's
    /// Finished and never answers.
    pub fn on_peer_data(&mut self, bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        if bytes.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        self.last_ms = now_ms();
        let Some(session) = self.session.as_mut() else {
            // Plain splice: forward the bytes untouched.
            return Ok((Vec::new(), bytes.to_vec()));
        };
        let out = session.on_peer_payload(bytes)?;
        if out.closed {
            self.closed = true;
        }
        Ok((out.to_peer, out.to_client))
    }

    /// The client sent a FIN. Shut our write side to the peer down and
    /// acknowledge: a FIN consumes one sequence number.
    pub fn on_client_fin(&mut self) -> Option<Vec<u8>> {
        self.client_fin = true;
        self.last_ms = now_ms();
        self.flow.acked_seq = self.flow.acked_seq.wrapping_add(1);
        let pkt = crate::packet::Packet::parse(&self.syn_packet)?;
        let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
        crate::mitm::segment::build_ack(&pkt, seq, self.flow.acked_seq, false)
    }

    /// A pure ACK for every client byte received so far.
    ///
    /// A plain splice has nothing to piggyback on, so this segment is the only
    /// thing that stops the client from retransmitting its request.
    pub fn ack_to_client(&mut self) -> Option<Vec<u8>> {
        let pkt = crate::packet::Packet::parse(&self.syn_packet)?;
        let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
        crate::mitm::segment::build_ack(&pkt, seq, self.flow.acked_seq, false)
    }

    /// The peer closed its side: send the client a FIN and retire the relay.
    pub fn on_peer_eof(&mut self) -> Option<Vec<u8>> {
        let pkt = crate::packet::Packet::parse(&self.syn_packet)?;
        let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
        self.flow.up_bytes += 1; // the FIN we send consumes one sequence number
        self.closed = true;
        self.flow.state = FlowState::Closed;
        crate::mitm::segment::build_fin(&pkt, seq, self.flow.acked_seq)
    }

    /// A hard reset towards the client (peer refused the connection, idle
    /// timeout...): better than leaving the app waiting on a dead flow.
    pub fn rst_to_client(&mut self) -> Option<Vec<u8>> {
        let pkt = crate::packet::Packet::parse(&self.syn_packet)?;
        let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
        crate::mitm::segment::build_rst(&pkt, seq)
    }

    /// Bytes the peer-facing TLS half wants to put on the wire.
    pub fn client_outbound(&mut self) -> Vec<u8> {
        match self.session.as_mut() {
            Some(s) => s.take_upstream_outbound(),
            None => Vec::new(),
        }
    }

    /// Marks the relay as finished when either side goes away.
    pub fn close(&mut self) {
        self.closed = true;
        self.flow.state = FlowState::Closed;
    }

    /// Chunks a payload into segments the client can understand.
    pub fn split_segments(payload: Vec<u8>, max: usize) -> Vec<Vec<u8>> {
        let max = max.max(1);
        if payload.len() <= max {
            return if payload.is_empty() { Vec::new() } else { vec![payload] };
        }
        payload.chunks(max).map(<[u8]>::to_vec).collect()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // The engine created this descriptor for us (and had the app protect
        // it), so retiring the relay must close it. -1 is the test sentinel.
        if self.peer_fd >= 0 {
            unsafe {
                libc::close(self.peer_fd);
            }
        }
    }
}

/// Every live relay, keyed by the client's port.
pub struct RelayTable {
    relays: std::collections::HashMap<u16, Relay>,
}

impl Default for RelayTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayTable {
    pub fn new() -> Self {
        RelayTable {
            relays: std::collections::HashMap::new(),
        }
    }

    pub fn insert(&mut self, relay: Relay) {
        self.relays.insert(relay.flow.client_port, relay);
    }

    pub fn get(&self, port: u16) -> Option<&Relay> {
        self.relays.get(&port)
    }

    /// Mutable walk over the live relays (housekeeping).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u16, &mut Relay)> {
        self.relays.iter_mut().map(|(p, r)| (*p, r))
    }

    pub fn get_mut(&mut self, port: u16) -> Option<&mut Relay> {
        self.relays.get_mut(&port)
    }

    pub fn remove(&mut self, port: u16) -> Option<Relay> {
        self.relays.remove(&port)
    }

    /// Drops every relay (and closes its peer descriptor). Used on shutdown:
    /// a restart must not inherit half-dead flows whose client ports are about
    /// to be reused by fresh sessions.
    pub fn clear(&mut self) {
        self.relays.clear();
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Every peer socket in play, so the engine can poll them: client port,
    /// descriptor, whether the connection is still being established, and
    /// whether buffered client bytes are waiting for a writable socket.
    pub fn poll_snapshot(&self) -> Vec<(u16, RawFd, bool, bool)> {
        self.relays
            .values()
            .filter(|r| !r.closed)
            .map(|r| {
                (
                    r.flow.client_port,
                    r.peer_fd,
                    r.connecting,
                    !r.connecting && !r.pending_to_peer.is_empty(),
                )
            })
            .collect()
    }

    /// Drops relays that already finished. The engine calls this from its
    /// housekeeping pass so finished flows do not pile up.
    pub fn drop_closed(&mut self) -> usize {
        let before = self.relays.len();
        self.relays.retain(|_, r| !r.closed);
        before - self.relays.len()
    }
}

/// Decides whether a destination port is worth terminating TLS for.
pub fn is_mitm_port(port: u16) -> bool {
    port == MITM_PORT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::ca::CertificateAuthority;
    use crate::mitm::proxy::ProxySession;
    use crate::mitm::tls::{open_session, SniCertResolver};
    use std::sync::Arc;

    fn syn_packet() -> Vec<u8> {
        // Minimal IPv4/TCP SYN: enough for the segment builders, which parse
        // the template to swap addresses and ports.
        let mut p = Vec::new();
        p.extend_from_slice(&[0x45, 0x00, 0x00, 40, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0]);
        p.extend_from_slice(&[10, 111, 42, 1]);
        p.extend_from_slice(&[142, 250, 185, 194]);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        crate::packet::fix_ipv4_checksum(&mut p);
        p
    }

    fn relay() -> Relay {
        let ca = CertificateAuthority::generate().expect("ca");
        let resolver = Arc::new(SniCertResolver::new(Arc::new(
            CertificateAuthority::from_pem(&ca.cert_pem(), &ca.key_pem()).expect("restore"),
        )));
        let session = open_session(&resolver, "x.example.com").expect("session");
        let proxy = ProxySession::new(session, "/adfree-user.js".into());
        Relay::new_tls(
            crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 443, 1000, 5000),
            -1,
            proxy,
            Vec::new(),
            DEFAULT_MSS,
            false,
        )
    }

    fn relay_with_syn() -> Relay {
        let mut r = relay();
        r.syn_packet = syn_packet();
        // The engine sets this right after it answers the SYN: the SYN-ACK
        // consumed one client-facing sequence number.
        r.flow.up_bytes = 1;
        r
    }

    fn plain_relay_with_syn() -> Relay {
        let flow = crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 80, 1000, 5000);
        let mut r = Relay::new_plain(flow, -1, syn_packet(), DEFAULT_MSS, false);
        r.flow.up_bytes = 1;
        r
    }

    #[test]
    fn a_fresh_relay_is_not_yet_established() {
        // The client half is still handshaking, so no application data flows.
        let r = relay();
        assert!(!r.is_established());
        assert!(!r.closed);
    }

    #[test]
    fn a_plain_relay_moves_bytes_untouched() {
        let flow =
            crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 80, 1000, 5000);
        let mut r = Relay::new_plain(flow, -1, syn_packet(), DEFAULT_MSS, false);
        // No handshake to complete: bytes can flow immediately.
        assert!(r.is_established());
        let (to_peer, to_client) = r
            .on_client_segment(1001, b"GET / HTTP/1.1\r\n\r\n")
            .expect("step");
        assert_eq!(to_peer, b"GET / HTTP/1.1\r\n\r\n");
        assert!(to_client.is_empty());
        // The request must be acknowledged (client seq + 1 from the SYN).
        assert_eq!(r.flow.acked_seq, 1001 + 18);
        assert_eq!(r.flow.down_bytes, 18);
        let back = r.on_peer_data(b"HTTP/1.1 200 OK\r\n\r\n").expect("peer step");
        assert_eq!(back, (Vec::new(), b"HTTP/1.1 200 OK\r\n\r\n".to_vec()));
    }

    #[test]
    fn a_retransmission_is_forwarded_only_once() {
        let mut r = plain_relay_with_syn();
        let request = b"POST /x HTTP/1.1\r\n\r\nAB";
        let (first, _) = r.on_client_segment(1001, request).expect("step");
        assert_eq!(first, request);
        assert_eq!(r.flow.acked_seq, 1001 + 22);
        // The client retransmits while our ACK is in flight: a second copy of a
        // POST must never reach the peer.
        let (again, _) = r.on_client_segment(1001, request).expect("dup");
        assert!(again.is_empty());
        assert_eq!(r.flow.acked_seq, 1001 + 22, "a duplicate must not advance the ack");
        assert_eq!(r.flow.down_bytes, 22);
    }

    #[test]
    fn a_partial_overlap_forwards_only_the_new_tail() {
        let mut r = plain_relay_with_syn();
        let _ = r.on_client_segment(1001, b"abcdef").expect("step");
        // A retransmission that starts mid-way and carries new bytes at the
        // end (the client packeted ahead before our ACK arrived).
        let (tail, _) = r.on_client_segment(1004, b"defghi").expect("overlap");
        assert_eq!(tail, b"ghi");
        // 1004..1007 was already delivered ("def"); only the tail is new.
        assert_eq!(r.flow.acked_seq, 1010);
    }

    #[test]
    fn an_ack_to_the_client_carries_the_running_sequence() {
        let mut r = plain_relay_with_syn();
        let _ = r.on_client_segment(1001, b"GET /").expect("step");
        let ack = r.ack_to_client().expect("ack");
        let pkt = crate::packet::Packet::parse(&ack).expect("parse");
        assert!(pkt.is_ack && !pkt.is_fin);
        assert_eq!(pkt.seq, 5001, "no data sent yet: seq stays after the SYN-ACK");
        assert_eq!(pkt.ack_seq, 1001 + 5);
    }

    #[test]
    fn an_invalid_tls_record_is_rejected() {
        let mut r = relay();
        // Record type 0 does not exist: rustls must fail loudly instead of
        // buffering noise forever.
        let bogus = [0x00, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00];
        let out = r.on_client_segment(1001, &bogus);
        assert!(out.is_err(), "an invalid record must be rejected: {out:?}");
    }

    #[test]
    fn a_partial_record_is_buffered_not_rejected() {
        let mut r = relay();
        // Only the first 4 bytes of a 5 byte record header: nothing to judge yet.
        let out = r.on_client_segment(1001, &[0x16, 0x03, 0x01, 0x00]);
        assert!(out.is_ok(), "a partial record is not an error: {out:?}");
        assert!(out.unwrap() == (Vec::new(), Vec::new()));
    }

    #[test]
    fn invalid_peer_records_never_become_plaintext() {
        let mut r = relay();
        // rustls is free to buffer or reject this; what must never happen is
        // junk surfacing as application data.
        let out = r.on_peer_data(&[0x00, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00]);
        match out {
            Err(_) => {}
            Ok((to_peer, to_client)) => {
                assert!(to_peer.is_empty(), "junk must not reach the peer");
                assert!(to_client.is_empty(), "junk must not become plaintext");
            }
        }
    }

    #[test]
    fn close_marks_the_flow_closed() {
        let mut r = relay();
        r.close();
        assert!(r.closed);
        assert_eq!(r.flow.state, FlowState::Closed);
    }

    #[test]
    fn segments_are_bounded() {
        assert!(Relay::split_segments(Vec::new(), 100).is_empty());
        let small = Relay::split_segments(vec![1, 2, 3], 100);
        assert_eq!(small, vec![vec![1, 2, 3]]);

        let big = vec![7u8; 100 * 2 + 5];
        let chunks = Relay::split_segments(big.clone(), 100);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.len() <= 100));
        assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), big.len());
    }

    #[test]
    fn segments_never_exceed_the_client_mss() {
        // The tunnel MTU is 1500: a 1460 byte payload plus headers is the most
        // that can be written to the descriptor at once.
        let mut r = relay_with_syn();
        let payload = vec![1u8; 10_000];
        let segs = r.segments_for_client(&payload);
        assert!(segs.len() >= 7, "10k must split into MSS-sized pieces");
        for seg in &segs {
            let pkt = crate::packet::Packet::parse(seg).expect("parse");
            assert!(
                pkt.l4_payload_len <= DEFAULT_MSS,
                "segment payload {} above the MSS",
                pkt.l4_payload_len
            );
        }
    }

    #[test]
    fn client_data_advances_the_acknowledgement() {
        let mut r = relay_with_syn();
        let before = r.flow.acked_seq;
        // A bogus TLS record still counts as bytes the peer must be acked for:
        // the sequence bookkeeping must not depend on handshake state.
        let _ = r.on_client_segment(1001, &[0x16, 0x03, 0x01, 0x00]);
        assert_eq!(r.flow.acked_seq, before + 4);
    }

    #[test]
    fn peer_data_does_not_double_count_the_sequence() {
        let mut r = relay_with_syn();
        // Whatever the session returns, the client-facing sequence is advanced
        // exactly once, by `segments_for_client`.
        let payload = b"hello".to_vec();
        let segs = r.segments_for_client(&payload);
        assert_eq!(segs.len(), 1);
        let first = crate::packet::Packet::parse(&segs[0]).expect("parse");
        assert_eq!(first.seq, 5001); // my_seq + the SYN's sequence
        assert_eq!(r.flow.up_bytes, 6); // 1 (SYN) + 5
        let segs = r.segments_for_client(b"world");
        let second = crate::packet::Packet::parse(&segs[0]).expect("parse");
        assert_eq!(second.seq, 5006, "consecutive segments must not skip");
    }

    #[test]
    fn client_fin_is_acked_once() {
        let mut r = relay_with_syn();
        let before = r.flow.acked_seq;
        let ack = r.on_client_fin().expect("ack");
        let pkt = crate::packet::Packet::parse(&ack).expect("parse");
        assert!(pkt.is_ack && !pkt.is_fin);
        assert_eq!(r.flow.acked_seq, before + 1);
        assert!(r.client_fin);
    }

    #[test]
    fn peer_eof_sends_a_fin_and_closes() {
        let mut r = relay_with_syn();
        let fin = r.on_peer_eof().expect("fin");
        let pkt = crate::packet::Packet::parse(&fin).expect("parse");
        assert!(pkt.is_fin && pkt.is_ack);
        assert!(r.closed);
        assert_eq!(r.flow.up_bytes, 2, "the FIN consumes one sequence number");
    }

    #[test]
    fn closed_relays_are_pruned() {
        let mut table = RelayTable::new();
        table.insert(relay());
        assert_eq!(table.len(), 1);
        table.get_mut(40000).unwrap().close();
        assert_eq!(table.drop_closed(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn only_https_is_terminated() {
        assert!(is_mitm_port(443));
        assert!(!is_mitm_port(80));
        assert!(!is_mitm_port(53));
    }

    #[test]
    fn empty_payloads_are_no_ops() {
        let mut r = relay();
        assert_eq!(r.on_client_segment(1001, &[]).unwrap(), (Vec::new(), Vec::new()));
        assert_eq!(r.on_peer_data(&[]).unwrap(), (Vec::new(), Vec::new()));
    }

    /// The engine's own path: a browser, a `Relay`, and an origin, with the
    /// relay in the middle exactly as the engine drives it.
    ///
    /// Regression: `on_peer_data` used to return only the client-bound bytes,
    /// dropping what the upstream half produced while processing server data
    /// (its protocol Finished and the request buffered behind it). The origin
    /// then never completed its handshake, and every HTTPS page died with an
    /// empty response.
    #[test]
    fn on_peer_data_carries_the_upstreams_own_bytes() {
        use crate::mitm::proxy_tests::{feed_browser, feed_origin};
        use rustls::pki_types::ServerName;
        use rustls::{ClientConnection, ServerConnection};
        use std::io::Write;

        // The origin's CA: the certificate the upstream half must trust.
        let origin_ca = CertificateAuthority::generate().expect("origin ca");
        let mut origin_roots = rustls::RootCertStore::empty();
        origin_roots
            .add(rustls::pki_types::CertificateDer::from(origin_ca.cert_der()))
            .expect("origin root");

        // The CA the browser trusts: the one we present to it.
        let mitm_ca = CertificateAuthority::generate().expect("mitm ca");
        let resolver = Arc::new(SniCertResolver::new(Arc::new(
            CertificateAuthority::from_pem(&mitm_ca.cert_pem(), &mitm_ca.key_pem())
                .expect("restore"),
        )));
        let session = crate::mitm::tls::open_session_with(
            &resolver,
            "origin.example.com",
            crate::mitm::tls::client_config_with(origin_roots),
        )
        .expect("session");
        let proxy = ProxySession::new(session, String::new());
        let mut relay = Relay::new_tls(
            crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 443, 1000, 5000),
            -1,
            proxy,
            Vec::new(),
            DEFAULT_MSS,
            false,
        );

        // The origin, minting leaves from its own CA.
        let origin_resolver = Arc::new(SniCertResolver::new(Arc::new(origin_ca)));
        let mut origin = ServerConnection::new(crate::mitm::tls::server_config(origin_resolver))
            .expect("origin");

        // The fake browser.
        let mut browser_roots = rustls::RootCertStore::empty();
        browser_roots
            .add(rustls::pki_types::CertificateDer::from(mitm_ca.cert_der()))
            .expect("browser root");
        let name = ServerName::try_from("origin.example.com".to_string()).expect("server name");
        let mut browser =
            ClientConnection::new(crate::mitm::tls::client_config_with(browser_roots), name)
                .expect("browser");

        let request = b"GET / HTTP/1.1\r\nHost: origin.example.com\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        browser
            .writer()
            .write_all(request)
            .expect("browser writes the request");

        let mut to_origin: Vec<u8> = Vec::new();
        let mut origin_request: Vec<u8> = Vec::new();
        let mut browser_plain: Vec<u8> = Vec::new();
        let mut origin_answered = false;

        for _round in 0..64 {
            // browser -> relay -> origin
            let wire = crate::mitm::tls::take_client_outbound(&mut browser);
            if !wire.is_empty() {
                let seq = relay.flow.acked_seq;
                let (to_peer, to_client) =
                    relay.on_client_segment(seq, &wire).expect("client step");
                to_origin.extend_from_slice(&to_peer);
                feed_browser(&mut browser, &to_client, &mut browser_plain);
            }
            if !to_origin.is_empty() {
                feed_origin(&mut origin, &to_origin, &mut origin_request);
                to_origin.clear();
                if !origin_answered && !origin_request.is_empty() {
                    origin
                        .writer()
                        .write_all(response)
                        .expect("origin writes the response");
                    origin_answered = true;
                }
            }
            // origin -> relay -> browser
            let wire = crate::mitm::tls::take_server_outbound(&mut origin);
            if !wire.is_empty() {
                let (to_peer, to_client) = relay.on_peer_data(&wire).expect("peer step");
                to_origin.extend_from_slice(&to_peer);
                feed_browser(&mut browser, &to_client, &mut browser_plain);
            }
            if browser_plain.windows(12).any(|w| w == b"HTTP/1.1 200") {
                break;
            }
        }

        assert_eq!(
            origin_request, request,
            "the origin must receive the request byte for byte"
        );
        assert!(
            browser_plain.starts_with(b"HTTP/1.1 200 OK"),
            "the browser must receive the response"
        );
    }
}
