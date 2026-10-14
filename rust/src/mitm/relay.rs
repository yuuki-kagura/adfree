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
use crate::mitm::tls::{
    take_client_outbound, take_server_outbound,
};
use crate::mitm::tcp::{Flow, FlowState};
use std::os::unix::io::RawFd;

/// Port we intercept for TLS termination. Everything else keeps flowing.
pub const MITM_PORT: u16 = 443;

/// Largest payload we are willing to splice without back-pressure.
const MAX_SEGMENT: usize = 16 * 1024;

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
}

impl Relay {
    pub fn new(flow: Flow, peer_fd: RawFd, session: ProxySession, syn_packet: Vec<u8>) -> Self {
        Relay {
            flow,
            session: Some(session),
            peer_fd,
            syn_packet,
            closed: false,
        }
    }

    /// Turns a payload into the TCP segments addressed to the client.
    ///
    /// The relay owns the flow, so it is the right place to advance the
    /// client-facing sequence number; the engine just writes the result out.
    pub fn segments_for_client(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for chunk in Relay::split_segments(payload.to_vec()) {
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
    pub fn on_peer_data(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let Some(session) = self.session.as_mut() else {
            return Ok(Vec::new());
        };
        let out = session.on_peer_payload(bytes)?;
        self.flow.up_bytes += out.to_client.len() as u64;
        if out.closed {
            self.closed = true;
        }
        Ok(out.to_client)
    }

    /// Bytes the client-facing TLS half wants to put on the wire.
    pub fn server_outbound(&mut self) -> Vec<u8> {
        match self.session.as_mut() {
            Some(s) => tls_outbound_server(&mut s.session.server),
            None => Vec::new(),
        }
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
    pub fn split_segments(payload: Vec<u8>) -> Vec<Vec<u8>> {
        if payload.len() <= MAX_SEGMENT {
            return if payload.is_empty() { Vec::new() } else { vec![payload] };
        }
        payload.chunks(MAX_SEGMENT).map(<[u8]>::to_vec).collect()
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

    /// Drops relays whose peer socket went away.
    pub fn drop_closed(&mut self) -> usize {
        let before = self.relays.len();
        self.relays.retain(|_, r| !r.closed || r.session.is_some());
        before - self.relays.len()
    }
}

/// Decides whether a destination port is worth terminating TLS for.
pub fn is_mitm_port(port: u16) -> bool {
    port == MITM_PORT
}


#[inline]
fn tls_outbound_server(conn: &mut rustls::ServerConnection) -> Vec<u8> {
    take_server_outbound(conn)
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
        )
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
        assert!(Relay::split_segments(Vec::new()).is_empty());
        let small = Relay::split_segments(vec![1, 2, 3]);
        assert_eq!(small, vec![vec![1, 2, 3]]);

        let big = vec![7u8; MAX_SEGMENT * 2 + 5];
        let chunks = Relay::split_segments(big.clone());
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), big.len());
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
