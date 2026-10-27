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
    let proxy = ProxySession::new(session, "/adfree-user.js".into(), Arc::from(""));
    let flow = Flow::new(packet::IpKey::V4(0x0a6f_2a01), 40000, 443, 1000, 55_000);
    Relay::new_tls(flow, -1, proxy, syn_packet(), 1460, false)
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
    assert_eq!(
        parsed.seq,
        55_000 + 1,
        "first data byte follows the SYN-ACK"
    );

    relay.segments_for_client(b"two!");
    let segs = relay.segments_for_client(b"three!");
    let parsed = Packet::parse(&segs[0]).expect("parse");
    // 1 (SYN) + 3 ("one") + 4 ("two!") = 8
    assert_eq!(parsed.seq, 55_000 + 8);
    assert_eq!(parsed.l4_payload(), b"three!");
}

#[test]
fn large_payloads_are_split_into_mss_sized_segments() {
    let mut relay = make_relay();
    relay.flow.up_bytes = 1;
    let payload = vec![0xABu8; 40 * 1024];
    let segs = relay.segments_for_client(&payload);
    assert!(segs.len() >= 28, "40 KiB cannot fit under the MSS in fewer");

    // Each segment must carry the right slice at the right sequence number,
    // and none may exceed the client's MSS: anything bigger is dropped by its
    // stack, or cannot even be written to the tun descriptor.
    let mut expect_seq = 55_000 + 1;
    let mut offset = 0usize;
    for seg in &segs {
        let parsed = Packet::parse(seg).expect("parse");
        assert_eq!(parsed.seq, expect_seq);
        assert!(
            parsed.l4_payload_len <= 1460,
            "segment payload {} above the MSS",
            parsed.l4_payload_len
        );
        let len = parsed.l4_payload().len();
        assert_eq!(parsed.l4_payload(), &payload[offset..offset + len]);
        expect_seq = expect_seq.wrapping_add(len as u32);
        offset += len;
    }
    assert_eq!(offset, payload.len(), "no bytes may be lost");
}

#[test]
fn every_segment_carries_a_valid_ipv4_tcp_checksum() {
    let mut relay = make_relay();
    relay.flow.up_bytes = 1;
    let segs = relay.segments_for_client(b"checksum me");
    assert_eq!(segs.len(), 1);
    let seg = &segs[0];
    let parsed = Packet::parse(seg).expect("parse");
    let l4 = parsed.ip_hdr_len;
    // The receiving stack validates this before the socket sees a byte: a zero
    // or stale checksum silently discards the segment on device.
    assert_eq!(
        packet::tcp_checksum_v4(&seg[..l4], &seg[l4..]),
        0,
        "recomputed checksum must verify"
    );
    // And the IPv4 header checksum too, since we rewrote the addresses.
    assert_eq!(packet::ipv4_checksum(&seg[..l4]), 0);
}

#[test]
fn the_client_half_blocks_until_the_handshake_is_done() {
    let relay = make_relay();
    assert!(
        !relay.is_established(),
        "a fresh relay is still handshaking"
    );
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
fn client_bound_bytes_wait_for_the_receive_window() {
    let mut relay = make_relay();
    // The SYN-ACK consumed one sequence number, as on a real connection.
    relay.flow.up_bytes = 1;
    // A 2 KB window funds exactly one 2 KB burst; the rest must wait.
    relay.on_client_ack(55_000 + 1, 2_000);
    let segs = relay.segments_for_client(&vec![0x5Au8; 5_000]);
    let sent: usize = segs
        .iter()
        .map(|s| Packet::parse(s).expect("parse").l4_payload().len())
        .sum();
    assert_eq!(sent, 2_000, "only the window's worth may leave at once");

    // The ACK covering those bytes opens the window for the next burst.
    relay.on_client_ack(55_000 + 1 + 2_000, 2_000);
    let segs = relay.segments_for_client(&[]);
    let sent: usize = segs
        .iter()
        .map(|s| Packet::parse(s).expect("parse").l4_payload().len())
        .sum();
    assert_eq!(sent, 2_000, "the next ACK releases the next burst");

    // A zero window stalls everything until an update arrives.
    relay.on_client_ack(55_000 + 1 + 4_000, 0);
    assert!(relay.segments_for_client(&[]).is_empty(), "zero window");
    relay.on_client_ack(55_000 + 1 + 4_000, 1_000);
    let segs = relay.segments_for_client(&[]);
    let sent: usize = segs
        .iter()
        .map(|s| Packet::parse(s).expect("parse").l4_payload().len())
        .sum();
    assert_eq!(sent, 1_000, "the window update releases the last bytes");
}

#[test]
fn a_peer_eof_waits_for_pending_bytes() {
    let mut relay = make_relay();
    relay.flow.up_bytes = 1;
    relay.on_client_ack(55_000 + 1, 100);
    relay.queue_to_client(&vec![0xABu8; 300]);
    let segs = relay.flush_to_client();
    assert_eq!(segs.len(), 1, "a 100-byte window funds one segment");

    // The peer closing now must not retire the relay: 200 bytes are unsent.
    assert!(relay.on_peer_eof().is_none(), "the FIN must wait");
    assert!(!relay.closed, "and the relay stays open");

    relay.on_client_ack(55_000 + 1 + 100, 100);
    assert_eq!(relay.flush_to_client().len(), 1, "second burst");
    let last = relay.flush_to_client();
    assert!(last.is_empty(), "window exhausted again");

    relay.on_client_ack(55_000 + 1 + 200, 100);
    let last = relay.flush_to_client();
    assert_eq!(last.len(), 1, "the last data segment");
    assert!(!relay.closed, "the FIN still needs window room of its own");

    // The ACK covering every data byte opens room for the FIN's sequence
    // number, and the deferred FIN rides out with the next flush.
    relay.on_client_ack(55_000 + 1 + 300, 100);
    let last = relay.flush_to_client();
    assert_eq!(last.len(), 1, "the deferred FIN");
    let fin = Packet::parse(&last[0]).expect("parse");
    assert!(fin.is_fin, "the last segment carries the FIN");
    assert_eq!(fin.seq, 55_000 + 1 + 300, "the FIN follows the data");
    assert!(relay.closed, "the relay retires with the FIN");
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
    assert_eq!(table.poll_snapshot().len(), 1);
    assert!(table.remove(40000).is_some());
    assert!(table.is_empty());
}
