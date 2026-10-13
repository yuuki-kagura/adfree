//! End-to-end test of the upstream DNS forwarder.
//!
//! Mirrors the real device path: `sendto()` to the resolver, `poll()` on the
//! socket, `recv()` the answer, and match it against the waiting query. This is
//! exactly where the byte-order bug broke `s_addr` (sendto returned EINVAL).

use adfree_core::upstream::Upstream;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// A bare DNS `A example.com` query, no IP packet.
fn query_named(name: &str, txid: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&txid.to_be_bytes());
    v.extend_from_slice(&[0x01, 0x00]); // recursion desired
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    v
}

#[test]
fn sends_to_the_configured_resolver_and_matches_the_reply() {
    // Fake resolver: answer a query by echoing the question.
    let responder = std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
    .expect("bind responder");
    let responder_addr = responder.local_addr().expect("responder addr");

    let client = std::net::UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
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

    let payload = query_named("example.com", 0x1234);
    let our_txid = upstream.alloc_txid();
    let mut patched = payload.clone();
    patched[0] = (our_txid >> 8) as u8;
    patched[1] = (our_txid & 0xff) as u8;

    let key = upstream
        .send(0, &patched, 0x1234, our_txid, 0)
        .expect("send must succeed: lỗi ở đây đồng nghĩa sockaddr sai");
    assert_eq!(upstream.pending_len(), 1);

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut replies = Vec::new();
    while replies.is_empty() && Instant::now() < deadline {
        replies.clear();
        upstream.poll(&mut replies);
    }
    responder_handle.join().expect("responder thread");

    assert_eq!(_key_eq(key, replies.len()), 1);
    let reply = &replies[0];
    // The reply carries the txid we sent (matched via pending), and pending keeps
    // the client's original txid so the engine can rewrite it.
    assert_eq!(
        u16::from_be_bytes([reply.message[0], reply.message[1]]),
        our_txid,
    );
    assert_eq!(reply.pending.client_txid, 0x1234);
    // The question must survive unchanged.
    assert_eq!(&reply.message[12..], &payload[12..]);
    // The QR bit must be set.
    assert_eq!(reply.message[2] & 0x80, 0x80);
    assert_eq!(upstream.pending_len(), 0, "khớp xong thì pending phải rỗng");

    drop(client);
}

fn _key_eq(key: u32, replies: usize) -> usize {
    let _ = key;
    replies
}
