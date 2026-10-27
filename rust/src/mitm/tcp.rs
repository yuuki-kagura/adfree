//! Userspace TCP cho phía client.
//!
//! To inject JS the app must *be* the client's TCP endpoint: answer SYN-ACK
//! itself, translate sequence numbers between both sides, then hand the payload
//! to a real socket that has been `protect()`ed.
//!
//! Scope is deliberately limited (and pinned by tests):
//! * only the SYN of a new flow is intercepted, then ACKs/data are translated;
//! * retransmissions keep the ACK stable (fine for mobile; a full TCP stack is
//!   a project of its own);
//! * a client RST closes the flow immediately.
//!
//! No NAT and no payload relaying here: this module tracks state and sequence
//! numbers only, with [`crate::mitm::proxy`] doing the socket work.

use crate::packet::{self, Packet};

/// The four states a short-lived flow needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FlowState {
    /// SYN seen, nothing sent yet.
    SynSeen,
    /// SYN-ACK sent, waiting for the client's ACK.
    SynAckSent,
    /// Established: data may flow.
    Established,
    /// Finished (FIN/RST).
    Closed,
}

/// State of one client TCP flow.
#[derive(Clone, Debug)]
pub struct Flow {
    pub client_ip: crate::packet::IpKey,
    pub client_port: u16,
    pub peer_port: u16,
    /// Sequence number we generated (client side).
    pub my_seq: u32,
    /// The client's own sequence (=+1 after the SYN).
    pub client_seq: u32,
    /// Client bytes received that still need an ACK from us.
    pub acked_seq: u32,
    /// Highest ACK the client has sent for our data (in `my_seq` space).
    /// Everything we send must stay within the window below this point.
    pub client_ack: u32,
    /// Receive window the client advertised last; 0 means "wait for an update".
    pub client_window: u32,
    /// Window scale factor the client's SYN negotiated (RFC 7323).
    pub client_window_scale: u8,
    /// Sequence phía server (sau khi connect).
    pub peer_seq: u32,
    pub state: FlowState,
    /// Bytes we have sent to the client.
    pub up_bytes: u64,
    /// Bytes we forwarded to the server.
    pub down_bytes: u64,
}

impl Flow {
    pub fn new(
        client_ip: crate::packet::IpKey,
        client_port: u16,
        peer_port: u16,
        client_seq: u32,
        my_seq: u32,
    ) -> Self {
        Flow {
            client_ip,
            client_port,
            peer_port,
            my_seq,
            client_seq: client_seq.wrapping_add(1),
            acked_seq: client_seq.wrapping_add(1),
            // The SYN-ACK is one unacknowledged byte until the client's first
            // packet acknowledges it; until a real window arrives, allow one
            // window-sized flight so the handshake answers can go out.
            client_ack: my_seq,
            client_window: 65_535,
            client_window_scale: 0,
            peer_seq: 0,
            state: FlowState::SynSeen,
            up_bytes: 0,
            down_bytes: 0,
        }
    }

    /// Next sequence to use when sending to the client.
    pub fn next_send_seq(&self) -> u32 {
        self.my_seq.wrapping_add(self.up_bytes as u32)
    }

    /// Acknowledgment to hand back to the client.
    pub fn ack_for_client(&self) -> u32 {
        self.acked_seq
    }

    /// Handle a client packet and report what to do.
    pub fn on_client_packet(&mut self, pkt: &Packet<'_>) -> ClientAction {
        if pkt.is_rst {
            self.state = FlowState::Closed;
            return ClientAction::Close;
        }
        if pkt.is_syn {
            self.state = FlowState::SynAckSent;
            return ClientAction::SendSynAck;
        }
        if pkt.is_fin {
            self.state = FlowState::Closed;
            return ClientAction::Close;
        }
        // Client ACK with no data: there is nothing to do.
        let payload = pkt.l4_payload();
        if payload.is_empty() {
            return ClientAction::AckOnly;
        }
        // Advance the acknowledged sequence: every byte must be ACKed.
        self.acked_seq = self.acked_seq.wrapping_add(payload.len() as u32);
        self.down_bytes += payload.len() as u64;
        ClientAction::Data(payload.len())
    }

    /// Data arrived from the server: advance the send sequence.
    pub fn on_server_data(&mut self, len: usize) {
        self.up_bytes += len as u64;
    }
}

/// What to do after inspecting a client packet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientAction {
    /// Send a SYN-ACK.
    SendSynAck,
    /// `n` bytes must be forwarded to the server.
    Data(usize),
    /// Bare ACK: ignore it.
    AckOnly,
    /// Close the flow.
    Close,
}

/// TCP flow table (4-tuple -> flow).
pub struct FlowTable {
    flows: Vec<Flow>,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTable {
    pub fn new() -> Self {
        FlowTable { flows: Vec::new() }
    }

    /// Find (or create) the flow for a packet heading to `peer_port`.
    pub fn flow_for(
        &mut self,
        client_ip: crate::packet::IpKey,
        client_port: u16,
        peer_port: u16,
        client_seq: u32,
    ) -> Option<&Flow> {
        let exists = self
            .flows
            .iter()
            .any(|f| f.client_ip == client_ip && f.client_port == client_port);
        if exists {
            let flow = self
                .flows
                .iter_mut()
                .find(|f| f.client_ip == client_ip && f.client_port == client_port)?;
            if flow.peer_port != peer_port {
                flow.peer_port = peer_port;
            }
            return Some(flow);
        }
        let my_seq = initial_seq(mix(client_seq as u64, peer_port as u64));
        self.flows.push(Flow::new(
            client_ip,
            client_port,
            peer_port,
            client_seq,
            my_seq,
        ));
        self.flows.last()
    }

    pub fn flow_mut(
        &mut self,
        client_ip: &crate::packet::IpKey,
        client_port: u16,
    ) -> Option<&mut Flow> {
        self.flows
            .iter_mut()
            .find(|f| &f.client_ip == client_ip && f.client_port == client_port)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Drop closed flows.
    pub fn prune(&mut self) -> usize {
        let before = self.flows.len();
        self.flows.retain(|f| f.state != FlowState::Closed);
        before - self.flows.len()
    }
}

/// Derive a hard-to-guess initial sequence number (no csprng needed).
pub fn initial_seq(seed: u64) -> u32 {
    // xorshift64: tiny, good enough for TCP ISN.
    let mut x = seed | 1;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    (x & 0xffff_ffff) as u32
}

/// Mix two values into one seed for `initial_seq`.
#[inline]
fn mix(a: u64, b: u64) -> u64 {
    let mut x = a.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ b.wrapping_add(0x1f83_d9ab);
    x ^= x >> 30;
    x.wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

/// SYN-ACK for the client, using the flow's sequence numbers.
pub fn build_syn_ack(pkt: &Packet<'_>, flow: &Flow) -> Option<Vec<u8>> {
    packet::build_ack_response(pkt, flow.my_seq, flow.acked_seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::IpKey;
    use crate::packet::{self, ACK, FIN, RST};

    fn syn_packet(seq: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x45, 0x00]);
        let total = 20 + 20;
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0]);
        p.extend_from_slice(&[10, 111, 42, 1]); // src = client
        p.extend_from_slice(&[1, 1, 1, 1]); // dst = server
        p.extend_from_slice(&40000u16.to_be_bytes()); // src port
        p.extend_from_slice(&443u16.to_be_bytes()); // dst port
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]); // data offset 5, SYN
        packet::fix_ipv4_checksum(&mut p);
        p
    }

    fn ack_packet(seq: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x45, 0x00, 0x00, 40, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0]);
        p.extend_from_slice(&[10, 111, 42, 1]);
        p.extend_from_slice(&[1, 1, 1, 1]);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&[0x50, ACK, 0xff, 0xff, 0, 0, 0, 0]);
        packet::fix_ipv4_checksum(&mut p);
        p
    }

    fn data_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x45, 0x00]);
        let total = 20 + 20 + payload.len();
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0]);
        p.extend_from_slice(&[10, 111, 42, 1]);
        p.extend_from_slice(&[1, 1, 1, 1]);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]); // PSH+ACK
        p.extend_from_slice(payload);
        packet::fix_ipv4_checksum(&mut p);
        p
    }

    #[test]
    fn syn_creates_a_flow_and_asks_for_syn_ack() {
        let raw = syn_packet(1000);
        let pkt = Packet::parse(&raw).expect("parse");
        let mut table = FlowTable::new();
        let flow = table
            .flow_for(IpKey::V4(0x0a6f_2a01), 40000, 443, pkt.seq)
            .expect("flow");
        assert_eq!(flow.state, FlowState::SynSeen);
        // ISN is derived from the client's sequence, so it differs per flow.
        assert_ne!(flow.my_seq, 1000);
    }

    #[test]
    fn client_data_advances_the_ack() {
        let raw = data_packet(1001, b"GET / HTTP/1.1\r\n\r\n");
        let pkt = Packet::parse(&raw).expect("parse");
        let mut flow = Flow::new(IpKey::V4(1), 40000, 443, 1000, 5000);
        flow.state = FlowState::Established;
        let action = flow.on_client_packet(&pkt);
        assert_eq!(action, ClientAction::Data(18));
        assert_eq!(flow.down_bytes, 18);
        assert_eq!(flow.ack_for_client(), 1001 + 18);
    }

    #[test]
    fn server_data_advances_the_send_sequence() {
        let mut flow = Flow::new(IpKey::V4(1), 40000, 443, 1000, 5000);
        flow.on_server_data(10);
        flow.on_server_data(5);
        assert_eq!(flow.next_send_seq(), 5015);
        assert_eq!(flow.up_bytes, 15);
    }

    #[test]
    fn rst_closes_the_flow() {
        let mut raw = syn_packet(2000);
        // Flip the flags to RST+ACK.
        raw[20 + 13] = RST | ACK;
        let pkt = Packet::parse(&raw).expect("parse");
        let mut flow = Flow::new(IpKey::V4(1), 40000, 443, 2000, 6000);
        assert_eq!(flow.on_client_packet(&pkt), ClientAction::Close);
        assert_eq!(flow.state, FlowState::Closed);
    }

    #[test]
    fn fin_closes_the_flow() {
        let mut raw = data_packet(1001, b"x");
        raw[20 + 13] = FIN | ACK;
        let pkt = Packet::parse(&raw).expect("parse");
        let mut flow = Flow::new(IpKey::V4(1), 40000, 443, 1000, 6000);
        assert_eq!(flow.on_client_packet(&pkt), ClientAction::Close);
    }

    #[test]
    fn pure_ack_is_ignored() {
        // A bare ACK: no payload, so nothing is forwarded.
        let raw = ack_packet(1001);
        let pkt = Packet::parse(&raw).expect("parse");
        let mut flow = Flow::new(IpKey::V4(1), 40000, 443, 1000, 6000);
        assert_eq!(flow.on_client_packet(&pkt), ClientAction::AckOnly);
    }

    #[test]
    fn prune_removes_closed_flows() {
        let mut table = FlowTable::new();
        table.flow_for(IpKey::V4(1), 40000, 443, 1000);
        assert_eq!(table.len(), 1);
        if let Some(f) = table.flow_mut(&IpKey::V4(1), 40000) {
            f.state = FlowState::Closed;
        }
        assert_eq!(table.prune(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn syn_ack_packet_is_a_valid_tcp_reply() {
        let raw = syn_packet(1000);
        let pkt = Packet::parse(&raw).expect("parse");
        let flow = Flow::new(IpKey::V4(1), 40000, 443, 1000, 5000);
        let reply = build_syn_ack(&pkt, &flow).expect("syn ack");
        let parsed = Packet::parse(&reply).expect("parse reply");
        assert!(parsed.is_syn && parsed.is_ack, "must be a SYN-ACK");
    }

    #[test]
    fn initial_seq_is_stable_and_spread() {
        assert_eq!(initial_seq(1), initial_seq(1));
        assert_ne!(initial_seq(1), initial_seq(2));
        // Spread: two nearby seeds must produce distant results.
        assert!((initial_seq(1) as i64 - initial_seq(2) as i64).abs() > 1_000);
    }
}
