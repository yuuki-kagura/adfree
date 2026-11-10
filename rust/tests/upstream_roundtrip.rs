//! Round-trip test of the upstream DNS forwarder.
//!
//! Mirrors the real device path: a full IP packet goes in, `poll()` on the
//! socket, `recv()` the answer, and match it against the waiting query. This is
//! exactly where the byte-order bug broke `s_addr` (sendto returned EINVAL), and
//! where handing over a bare DNS message instead of the IP packet made the reply
//! impossible to rewrite.

use adfree_core::packet;
use adfree_core::upstream::Upstream;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// A bare DNS `A example.com` query.
fn query_named(txid: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&txid.to_be_bytes());
    v.extend_from_slice(&[0x01, 0x00]); // recursion desired
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["example", "com"] {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    v
}

/// Wraps a DNS message into a minimal IPv4/UDP packet.
fn wrap_in_ip_packet(dns: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&((20 + 8 + dns.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0, 0]);
    p.extend_from_slice(&[10, 111, 42, 1]);
    p.extend_from_slice(&[127, 0, 0, 1]);
    p.extend_from_slice(&40000u16.to_be_bytes());
    p.extend_from_slice(&53u16.to_be_bytes());
    p.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(dns);
    packet::fix_ipv4_checksum(&mut p);
    p
}

#[test]
fn sends_to_the_configured_resolver_and_matches_the_reply() {
    // Fake resolver: answer a query by echoing the question.
    let responder =
        std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind responder");
    let responder_addr = responder.local_addr().expect("responder addr");
    let client =
        std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind client");
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");

    let responder_handle = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (n, peer) = responder.recv_from(&mut buf).expect("recv query");
        assert!(n >= 12, "query phải đủ header");
        // Like a real resolver: keep the header (qdcount=1) and the question,
        // just set QR/RA.
        let mut reply = buf[..n].to_vec();
        reply[2] = 0x81;
        reply[3] = 0x80;
        responder.send_to(&reply, peer).expect("send reply");
    });

    let mut upstream = Upstream::new(responder_addr);
    upstream.set_socket_fds(&[client.as_raw_fd()]);

    let our_txid = upstream.alloc_txid();
    let patched = wrap_in_ip_packet(&query_named(our_txid));

    upstream
        // The ordinary path: no resolver override for an excepted page.
        .send(0, &patched, 0x1234, our_txid, 0, None)
        .expect("send must succeed: an error here means the sockaddr is wrong");
    assert_eq!(upstream.pending_len(), 1);

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut replies = Vec::new();
    while replies.is_empty() && Instant::now() < deadline {
        replies.clear();
        upstream.poll(&mut replies, 200);
    }
    responder_handle.join().expect("responder thread");

    assert_eq!(replies.len(), 1);
    let reply = &replies[0];
    // The reply carries the txid we sent (matched via pending), and pending keeps
    // the client's original txid so the engine can rewrite it.
    assert_eq!(
        u16::from_be_bytes([reply.message[0], reply.message[1]]),
        our_txid,
    );
    assert_eq!(reply.pending.client_txid, 0x1234);
    // The question must survive unchanged.
    assert_eq!(&reply.message[12..], &query_named(0)[12..]);
    // The QR bit must be set.
    assert_eq!(reply.message[2] & 0x80, 0x80);
    assert_eq!(
        upstream.pending_len(),
        0,
        "matched, so pending must be empty"
    );

    drop(client);
}

#[test]
fn a_non_dns_packet_is_rejected() {
    let mut upstream = Upstream::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)));
    // Any IP packet that does not carry UDP cannot be forwarded.
    let mut tcp_packet = wrap_in_ip_packet(&query_named(1));
    tcp_packet[9] = crate::PROTO_TCP_PLACEHOLDER;
    // `plain` names a resolver to ask instead of the configured one; this test
    // exercises the ordinary path, so nothing overrides it.
    assert!(upstream.send(0, &tcp_packet, 1, 1, 0, None).is_none());
}

/// Protocol number used by the test above.
#[allow(dead_code)]
pub const PROTO_TCP_PLACEHOLDER: u8 = 6;
