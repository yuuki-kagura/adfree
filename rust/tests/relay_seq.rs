//! Relay-level integration tests.
//!
//! `tls_tests.rs` covers the TLS handshake and both directions of a TLS
//! conversation; `segment.rs` covers the segment bytes; `relay.rs` covers the
//! state machine. This file covers what only shows up when the three meet: the
//! sequence numbers the client sees must advance by exactly what we sent, because
//! getting that wrong silently stalls the connection.

use adfree_core::mitm::ca::CertificateAuthority;
use adfree_core::mitm::proxy::ProxySession;
use adfree_core::mitm::relay::Relay;
use adfree_core::mitm::tcp::Flow;
use adfree_core::mitm::tls::{open_session, SniCertResolver};
use adfree_core::packet::{self, Packet, ACK, SYN};
use std::sync::Arc;

fn make_relay() -> Relay {
    let ca = CertificateAuthority::generate().expect("ca");
    let resolver = Arc::new(SniCertResolver::new(Arc::new(
        CertificateAuthority::from_pem(&ca.cert_pem(), &ca.key_pem()).expect("restore"),
    )));
    let session = open_session(&resolver, "ads.example.com").expect("session");
    let proxy = ProxySession::new(session, "/adfree-user.js".into());
    let flow = Flow::new(packet::IpKey::V4(0x0a6f_2a01), 40000, 443, 1000, 55_000);
    Relay::new(flow, -1, proxy, syn_packet())
}

/// The SYN that would have started the connection.
fn syn_packet() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x45, 0x00, 0x00, 40, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0]);
    p.extend_from_slice(&[10, 111, 42, 1]);
    p.extend_from_slice(&[142, 250, 185, 194]);
    p.extend_from_slice(&40000u16.to_be_bytes());
    p.extend_from_slice(&443u16.to_be_bytes());
    p.extend_from_slice(&1000u32.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(&[0x50, SYN | ACK, 0xff, 0xff, 0, 0, 0, 0]);
    p
}

#[test]
fn client_facing_sequence_advances_with_every_payload() {
    let mut relay = make_relay();
    // The SYN-ACK consumed one sequence number, as on a real connection.
    relay.flow.up_bytes = 1;

    let segs = relay.segments_for_client(b"one");
    assert_eq!(segs.len(), 1);
    let parsed = Packet::parse(&segs[0]).expect("parse");
    assert_eq!(parsed.seq, 55_000 + 1, "first data byte follows the SYN-ACK");

    relay.segments_for_client(b"two!");
    let segs = relay.segments_for_client(b"three!");
    let parsed = Packet::parse(&segs[0]).expect("parse");
    // 1 (SYN) + 3 ("one") + 4 ("two!") = 8
    assert_eq!(parsed.seq, 55_000 + 8);
    assert_eq!(parsed.l4_payload(), b"three!");
}

#[test]
fn large_payloads_are_split_into_bounded_segments() {
    let mut relay = make_relay();
    relay.flow.up_bytes = 1;
    let payload = vec![0xABu8; 40 * 1024];
    let segs = relay.segments_for_client(&payload);
    assert_eq!(segs.len(), 3, "40 KiB splits into 16 KiB segments");

    // Each segment must carry the right slice at the right sequence number.
    let mut expect_seq = 55_000 + 1;
    let mut offset = 0usize;
    for seg in &segs {
        let parsed = Packet::parse(seg).expect("parse");
        assert_eq!(parsed.seq, expect_seq);
        let len = parsed.l4_payload().len();
        assert_eq!(parsed.l4_payload(), &payload[offset..offset + len]);
        expect_seq = expect_seq.wrapping_add(len as u32);
        offset += len;
    }
    assert_eq!(offset, payload.len(), "no bytes may be lost");
}

#[test]
fn the_client_half_blocks_until_the_handshake_is_done() {
    let relay = make_relay();
    assert!(!relay.is_established(), "a fresh relay is still handshaking");
}

#[test]
fn closing_a_relay_is_idempotent() {
    let mut relay = make_relay();
    let fd = relay.peer_fd;
    relay.close();
    assert!(relay.closed);
    assert_eq!(relay.peer_fd, fd, "the socket is the caller's to close");
}

#[test]
fn every_segment_is_addressed_back_to_the_client() {
    let mut relay = make_relay();
    let segs = relay.segments_for_client(b"hello");
    let seg = Packet::parse(&segs[0]).expect("parse");
    // The reply must go to the client, from the server it asked for.
    assert_eq!(seg.dst_ip_text(), "10.111.42.1");
    assert_eq!(seg.src_ip_text(), "142.250.185.194");
    assert_eq!(seg.dst_port, 40000);
    assert_eq!(seg.src_port, 443);
    // And acknowledge everything the client sent.
    assert_eq!(seg.ack_seq, 1001, "one byte of SYN must be acknowledged");
    assert!(seg.is_ack && !seg.is_syn);
}

#[test]
fn the_relay_table_tracks_flows_by_client_port() {
    use adfree_core::mitm::relay::RelayTable;
    let mut table = RelayTable::new();
    assert!(table.is_empty());
    table.insert(make_relay());
    assert_eq!(table.len(), 1);
    assert!(table.get(40000).is_some());
    assert!(table.get_mut(40000).is_some());
    assert_eq!(table.peer_fds().len(), 1);
    assert!(table.remove(40000).is_some());
    assert!(table.is_empty());
}
