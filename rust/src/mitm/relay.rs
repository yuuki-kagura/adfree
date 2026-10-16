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
use crate::mitm::tls::take_client_outbound;
use crate::mitm::tcp::{Flow, FlowState};
use crate::util::now_ms;
use std::os::unix::io::RawFd;

/// Port we intercept for TLS termination. Everything else keeps flowing.
pub const MITM_PORT: u16 = 443;

/// Fallback payload cap when the client's SYN carried no MSS option.
pub const DEFAULT_MSS: usize = 1460;

/// One relayed connection.
pub struct Relay {
    pub flow: Flow,
    pub session: Option<ProxySession>,
    /// Protected socket to the real server.
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
}

impl Relay {
    pub fn new(flow: Flow, peer_fd: RawFd, session: ProxySession, syn_packet: Vec<u8>, mss: usize) -> Self {
        Relay {
            flow,
            session: Some(session),
            peer_fd,
            syn_packet,
            closed: false,
            mss,
            last_ms: now_ms(),
            client_fin: false,
        }
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
                Some(s) => !s.server_handshaking(),
                None => false,
            }
    }

    /// A segment arrived from the client.
    ///
    /// Returns `(to_peer, to_client)`: both directions can produce bytes, because
    /// during the handshake our own answers count towards the client.
    pub fn on_client_segment(&mut self, payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        if payload.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        // Every client byte must be acknowledged exactly once. The ack we
        // piggyback on the next segment we send is built from this counter;
        // without advancing it the client retransmits everything forever.
        self.flow.acked_seq = self.flow.acked_seq.wrapping_add(payload.len() as u32);
        self.last_ms = now_ms();
        let Some(session) = self.session.as_mut() else {
            return Ok((Vec::new(), Vec::new()));
        };
        let out = session.on_client_payload(payload)?;
        self.flow.down_bytes += payload.len() as u64;
        if out.closed {
            self.closed = true;
        }
        Ok((out.to_peer, out.to_client))
    }

    /// Data arrived from the real server.
    ///
    /// Returns the plaintext to send to the client (with any script injected).
    /// Sequence bookkeeping happens in [`Relay::segments_for_client`], not here.
    pub fn on_peer_data(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        self.last_ms = now_ms();
        let Some(session) = self.session.as_mut() else {
            return Ok(Vec::new());
        };
        let out = session.on_peer_payload(bytes)?;
        if out.closed {
            self.closed = true;
        }
        Ok(out.to_client)
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
            Some(s) => tls_outbound_client(&mut s.session.client),
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

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Every peer socket in play, so the engine can poll them.
    pub fn peer_fds(&self) -> Vec<(u16, RawFd)> {
        self.relays
            .values()
            .filter(|r| !r.closed)
            .map(|r| (r.flow.client_port, r.peer_fd))
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


#[inline]
fn tls_outbound_client(conn: &mut rustls::ClientConnection) -> Vec<u8> {
    take_client_outbound(conn)
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
        Relay::new(
            crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 443, 1000, 5000),
            -1,
            proxy,
            Vec::new(),
            DEFAULT_MSS,
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

    #[test]
    fn a_fresh_relay_is_not_yet_established() {
        // The client half is still handshaking, so no application data flows.
        let r = relay();
        assert!(!r.is_established());
        assert!(!r.closed);
    }

    #[test]
    fn an_invalid_tls_record_is_rejected() {
        let mut r = relay();
        // Record type 0 does not exist: rustls must fail loudly instead of
        // buffering noise forever.
        let bogus = [0x00, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00];
        let out = r.on_client_segment(&bogus);
        assert!(out.is_err(), "an invalid record must be rejected: {out:?}");
    }

    #[test]
    fn a_partial_record_is_buffered_not_rejected() {
        let mut r = relay();
        // Only the first 4 bytes of a 5 byte record header: nothing to judge yet.
        let out = r.on_client_segment(&[0x16, 0x03, 0x01, 0x00]);
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
            Ok(bytes) => assert!(bytes.is_empty(), "junk must not become plaintext"),
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
        let _ = r.on_client_segment(&[0x16, 0x03, 0x01, 0x00]);
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
        assert_eq!(r.on_client_segment(&[]).unwrap(), (Vec::new(), Vec::new()));
        assert_eq!(r.on_peer_data(&[]).unwrap(), Vec::<u8>::new());
    }
}
