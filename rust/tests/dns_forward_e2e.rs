//! End-to-end test of the DNS forward path the engine uses.
//!
//! This is the path that silently broke: the engine hands the *whole IP packet*
//! to `Upstream::send` so the reply can be rewritten for the client. If the
//! forwarder sends the IP packet instead of the DNS message, the resolver gets
//! garbage; if `handle_reply` then tries to parse the reply as if it were the
//! original packet, nothing is ever answered and every lookup fails.

use adfree_core::dns::{self, BlockMode};
use adfree_core::engine::{core, Core};
use adfree_core::packet::{self, Packet, PROTO_UDP};
use adfree_core::upstream::Upstream;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::io::AsRawFd;

/// A DNS query for `host`, wrapped into an IPv4/UDP packet like a real one.
fn query_packet(host: &str, txid: u16) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&txid.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00]);
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in host.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let mut p = Vec::new();
    p.extend_from_slice(&[0x45, 0x00]);
    let total = 20 + 8 + dns.len();
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0, 0]);
    p.extend_from_slice(&[10, 111, 42, 1]);
    p.extend_from_slice(&[8, 8, 8, 8]);
    p.extend_from_slice(&40000u16.to_be_bytes());
    p.extend_from_slice(&53u16.to_be_bytes());
    p.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&dns);
    packet::fix_ipv4_checksum(&mut p);
    p
}

/// A fake resolver: reads a query, answers with `0.0.0.0`, and echoes the question.
fn spawn_resolver(socket: UdpSocket) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (n, peer) = socket.recv_from(&mut buf).expect("recv query");
        let q = dns::parse_query(&buf[..n]).expect("valid DNS query");
        assert!(
            q.has_question,
            "the resolver must receive a real DNS message"
        );
        let mut reply = Vec::new();
        reply.extend_from_slice(&q.id.to_be_bytes());
        reply.extend_from_slice(&[0x85, 0x80]); // QR + RD + RA
        reply.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0]);
        reply.extend_from_slice(&query_buf(&q));
        reply.extend_from_slice(&[0xc0, 0x0c]); // name pointer to the question
        reply.extend_from_slice(&1u16.to_be_bytes()); // type A
        reply.extend_from_slice(&1u16.to_be_bytes()); // class IN
        reply.extend_from_slice(&60u32.to_be_bytes()); // ttl
        reply.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        reply.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
        socket.send_to(&reply, peer).expect("send reply");
    });
}

fn query_buf(q: &dns::Query<'_>) -> Vec<u8> {
    q.body[12..q.q_end].to_vec()
}

#[test]
fn an_ip_packet_is_forwarded_as_a_dns_message_and_answered() {
    let resolver =
        UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))).expect("bind");
    let resolver_addr = resolver.local_addr().expect("addr");
    let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind client");
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("timeout");
    spawn_resolver(resolver);

    let mut upstream = Upstream::new(resolver_addr);
    upstream.set_socket_fds(&[socket.as_raw_fd()]);

    let packet = query_packet("allowed.example.com", 0x4321);
    let packet = Packet::parse(&packet).expect("parse");
    let query = dns::parse_query(packet.l4_payload()).expect("parse dns");
    let our_txid = upstream.alloc_txid();

    // The engine patches the transaction id inside the IP packet it hands over.
    let mut full = packet.raw.to_vec();
    let off = packet.l4_payload_offset();
    full[off] = (our_txid >> 8) as u8;
    full[off + 1] = (our_txid & 0xff) as u8;

    let key = upstream
        // `plain` is the resolver an excepted page is sent to; this test asks
        // the configured one, so nothing is overridden.
        .send(0, &full, query.id, our_txid, 0, None)
        .expect("the query must be forwarded");

    let mut replies = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while replies.is_empty() && std::time::Instant::now() < deadline {
        replies.clear();
        upstream.poll(&mut replies, 200);
    }
    assert_eq!(replies.len(), 1, "the resolver must answer exactly once");

    let reply = &replies[0];
    assert_eq!(reply.pending.client_txid, query.id);
    let _ = key;

    // The client-facing rewrite has to turn this into a packet the client
    // accepts: same addresses, same ports, restored transaction id.
    let client_packet =
        Packet::parse(&reply.pending.packet).expect("the stored packet is an IP packet");
    let mut message = reply.message.clone();
    dns::patch_txid(&mut message, reply.pending.client_txid);
    let rewritten = client_packet.rewrite_udp(&message);

    let parsed = Packet::parse(&rewritten).expect("the rewritten packet must parse");
    assert_eq!(parsed.proto, PROTO_UDP);
    assert_eq!(parsed.src_ip_text(), "8.8.8.8");
    assert_eq!(parsed.dst_ip_text(), "10.111.42.1");
    assert_eq!(parsed.src_port, 53);
    assert_eq!(parsed.dst_port, 40000);

    let answered = dns::parse_query(parsed.l4_payload()).expect("the DNS answer must decode");
    assert_eq!(
        answered.id, 0x4321,
        "the client's transaction id must be restored"
    );
    assert!(!answered.is_query());
    assert_eq!(answered.qname.as_str(), "allowed.example.com");
}

#[test]
fn a_blocked_domain_is_answered_locally() {
    // Blocked hosts never touch the network: the answer is synthesized from the
    // query packet alone.
    let packet = query_packet("blocked.example.com", 0x9999);
    let packet = Packet::parse(&packet).expect("parse");
    let query = dns::parse_query(packet.l4_payload()).expect("parse dns");

    let reply = dns::synthesize_reply(&packet, &query, BlockMode::NxDomain).expect("reply");
    let parsed = Packet::parse(&reply).expect("parse reply");
    let answered = dns::parse_query(parsed.l4_payload()).expect("decode");
    assert_eq!(answered.rcode(), dns::RCODE_NXDOMAIN);
    assert_eq!(answered.qname.as_str(), "blocked.example.com");
    assert_eq!(answered.id, 0x9999);
}

#[test]
fn the_core_is_usable_as_a_singleton() {
    // `core()` is a process-wide handle; make sure repeated calls are cheap and
    // stable, since every JNI entry point goes through it.
    let a = core() as *const Core;
    let b = core() as *const Core;
    assert_eq!(a, b);
}
