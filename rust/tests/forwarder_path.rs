//! End-to-end test of the whole DNS forward path.
//!
//! A real query packet goes into the engine on a fake TUN (a pipe), a fake
//! resolver answers it, and the rewritten reply must come out of the pipe as a
//! packet the client can use. This is the path that was dead on device: the
//! query was forwarded and the resolver answered, but no packet ever came back.

use adfree_core::dns;
use adfree_core::engine::{core, Config};
use adfree_core::packet::{self, Packet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

fn query_packet(host: &str, txid: u16) -> Vec<u8> {
    query_packet_of_type(host, txid, 0x0001)
}

fn query_packet_of_type(host: &str, txid: u16, qtype: u16) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&txid.to_be_bytes());
    dns.extend_from_slice(&[0x01, 0x00]);
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in host.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&qtype.to_be_bytes());
    dns.extend_from_slice(&[0x00, 0x01]);

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

/// Creates a pipe; the write end stands in for the TUN device. The read end is
/// non-blocking so a test never hangs waiting for the engine.
fn fake_tun() -> (RawFd, RawFd) {
    let mut fds = [0 as RawFd; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL, 0) };
    assert!(flags >= 0);
    assert_eq!(unsafe { libc::fcntl(fds[0], libc::F_SETFL, flags | libc::O_NONBLOCK) }, 0);
    (fds[1], fds[0])
}

/// Reads from a raw fd (the TUN stand-in) without pulling in `std::fs::File`.
fn read_raw_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe {
        libc::read(
            fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[test]
fn the_answer_comes_back_out_of_the_tun() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let resolver = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        0,
    )))
    .expect("bind resolver");
    let resolver_addr = resolver.local_addr().expect("resolver addr");
    resolver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("resolver timeout");
    let resolver_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        let (n, peer) = resolver.recv_from(&mut buf).expect("recv query");
        let q = dns::parse_query(&buf[..n]).expect("a valid DNS query must arrive");
        let mut reply = Vec::new();
        reply.extend_from_slice(&q.id.to_be_bytes());
        reply.extend_from_slice(&[0x85, 0x80]);
        reply.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0]);
        reply.extend_from_slice(&q.body[12..q.q_end]);
        reply.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        reply.extend_from_slice(&60u32.to_be_bytes());
        reply.extend_from_slice(&4u16.to_be_bytes());
        reply.extend_from_slice(&[93, 184, 216, 34]);
        resolver.send_to(&reply, peer).expect("answer");
    });

    // A pool like the platform provides: the engine spreads hosts over slots.
    let sockets: Vec<UdpSocket> = (0..4)
        .map(|_| {
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("bind socket")
        })
        .collect();
    let fds: Vec<i32> = sockets.iter().map(|s| s.as_raw_fd()).collect();
    let (tun_w, tun_r) = fake_tun();

    let core = core();
    core.set_config(Config::default());
    core.set_socket_fds(&fds);
    core.set_resolver(resolver_addr);
    core.set_tun_fd_for_test(tun_w);

    // 1. the query goes in.
    let packet = query_packet("forwarded.example.com", 0x5555);
    let replies = core.handle_packet(&packet);
    assert!(replies.is_empty(), "with a live upstream the answer is async");

    // 2. the forwarder delivers it.
    let mut buf = [0u8; 4096];
    let mut delivered = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while delivered == 0 && std::time::Instant::now() < deadline {
        core.poll_upstream_once_for_test();
        match read_raw_fd(tun_r, &mut buf) {
            Ok(0) | Err(_) => {}
            Ok(n) => delivered += n,
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let snap = core.snapshot();
    eprintln!(
        "delivered={delivered} dns_queries={} dns_timeouts={} forwarded={}",
        snap.dns_queries, snap.dns_timeouts, snap.packets_forwarded
    );
    if delivered > 0 {
        let p = Packet::parse(&buf[..delivered]).expect("parse");
        if let Some(a) = adfree_core::dns::parse_query(p.l4_payload()) {
            eprintln!("got answer: rcode={} qname={}", a.rcode(), a.qname.as_str());
        }
    }
    assert!(
        delivered > 0,
        "the client must receive the rewritten answer (delivered={delivered})"
    );
    resolver_thread.join().expect("resolver thread");

    // 3. the packet the client sees must be usable.
    let parsed = Packet::parse(&buf[..delivered]).expect("valid packet");
    assert_eq!(parsed.src_ip_text(), "8.8.8.8");
    assert_eq!(parsed.dst_ip_text(), "10.111.42.1");
    assert_eq!(parsed.src_port, 53);
    assert_eq!(parsed.dst_port, 40000);
    let answered = dns::parse_query(parsed.l4_payload()).expect("valid DNS answer");
    assert_eq!(answered.id, 0x5555, "the client's transaction id must survive");
    assert!(!answered.is_query());
    assert_eq!(answered.qname.as_str(), "forwarded.example.com");

    unsafe { libc::close(tun_w) };
    unsafe { libc::close(tun_r) };
}

/// Offset just past the name field at `off` (handles the sole `c00c` pointer
/// the answers below use).
fn name_at(message: &[u8], mut off: usize) -> usize {
    loop {
        let len = message[off] as usize;
        if len & 0xc0 == 0xc0 {
            return off + 2;
        }
        if len == 0 {
            return off + 1;
        }
        off += 1 + len;
    }
}

/// The SvcParam keys of the first HTTPS answer in a DNS message.
fn https_param_keys(message: &[u8]) -> Vec<u16> {
    let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
    let an = u16::from_be_bytes([message[6], message[7]]) as usize;
    let mut off = 12usize;
    for _ in 0..qd {
        off = name_at(message, off) + 4;
    }
    let mut keys = Vec::new();
    for _ in 0..an {
        off = name_at(message, off);
        let rtype = u16::from_be_bytes([message[off], message[off + 1]]);
        let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
        off += 10;
        if rtype == 0x0041 {
            let end = off + rdlen;
            let mut p = name_at(message, off + 2);
            while p + 4 <= end {
                let key = u16::from_be_bytes([message[p], message[p + 1]]);
                let len = u16::from_be_bytes([message[p + 2], message[p + 3]]) as usize;
                keys.push(key);
                p += 4 + len;
            }
            break;
        }
        off += rdlen;
    }
    keys
}

/// The upstream answer for a type-65 query: priority, alpn, an ECHConfigList,
/// an address hint, and an A record *after* all of them.
fn https_answer(query: &dns::Query<'_>, ech: &[u8]) -> Vec<u8> {
    let mut reply = Vec::new();
    reply.extend_from_slice(&query.id.to_be_bytes());
    reply.extend_from_slice(&[0x85, 0x80]);
    reply.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0, 0, 0, 0]);
    reply.extend_from_slice(&query.body[12..query.q_end]);
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&1u16.to_be_bytes());
    rdata.push(0);
    for (key, value) in [
        (1u16, &[0x02, b'h', b'2'][..]),
        (5, ech),
        (4, &[93, 184, 216, 34][..]),
    ] {
        rdata.extend_from_slice(&key.to_be_bytes());
        rdata.extend_from_slice(&(value.len() as u16).to_be_bytes());
        rdata.extend_from_slice(value);
    }
    reply.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01]);
    reply.extend_from_slice(&300u32.to_be_bytes());
    reply.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    reply.extend_from_slice(&rdata);
    reply.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
    reply.extend_from_slice(&300u32.to_be_bytes());
    reply.extend_from_slice(&4u16.to_be_bytes());
    reply.extend_from_slice(&[93, 184, 216, 34]);
    reply
}

/// Sends one HTTPS query in and returns the answer message.
fn ask_https_message(
    core: &adfree_core::engine::Core,
    tun_r: RawFd,
    host: &str,
    txid: u16,
) -> Vec<u8> {
    let packet = query_packet_of_type(host, txid, 0x0041);
    assert!(
        core.handle_packet(&packet).is_empty(),
        "with a live upstream the answer is async"
    );
    let mut buf = [0u8; 4096];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        core.poll_upstream_once_for_test();
        if let Ok(n) = read_raw_fd(tun_r, &mut buf) {
            if n > 0 {
                let parsed = Packet::parse(&buf[..n]).expect("valid packet");
                let answer = dns::parse_query(parsed.l4_payload()).expect("valid DNS answer");
                assert_eq!(answer.id, txid, "the client's transaction id must survive");
                return parsed.l4_payload().to_vec();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("the client never received an answer");
}

/// Sends one HTTPS query in and returns the SvcParam keys of the answer.
fn ask_https(core: &adfree_core::engine::Core, tun_r: RawFd, host: &str, txid: u16) -> Vec<u16> {
    https_param_keys(&ask_https_message(core, tun_r, host, txid))
}

/// The TTL of the first answer record in a DNS message.
fn first_answer_ttl(message: &[u8]) -> u32 {
    let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
    let mut off = 12usize;
    for _ in 0..qd {
        off = name_at(message, off) + 4;
    }
    let ttl_at = name_at(message, off) + 4;
    u32::from_be_bytes([
        message[ttl_at],
        message[ttl_at + 1],
        message[ttl_at + 2],
        message[ttl_at + 3],
    ])
}

/// An ECHConfig is only useful while nothing terminates TLS. Once HTTPS
/// filtering is armed the client must not be told about ECH: its first attempt
/// would die on the forged certificate and the retry costs a round trip.
#[test]
fn ech_configs_are_stripped_only_while_https_filtering_is_on() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let resolver = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind resolver");
    let resolver_addr = resolver.local_addr().expect("resolver addr");
    resolver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("resolver timeout");
    let resolver_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        for _ in 0..2 {
            let (n, peer) = resolver.recv_from(&mut buf).expect("recv query");
            let q = dns::parse_query(&buf[..n]).expect("a valid DNS query must arrive");
            assert_eq!(q.qtype, 0x0041, "the type-65 query must reach the resolver");
            let reply = https_answer(&q, &[0xab; 8]);
            resolver.send_to(&reply, peer).expect("answer");
        }
    });

    let sockets: Vec<UdpSocket> = (0..4)
        .map(|_| {
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("bind socket")
        })
        .collect();
    let fds: Vec<i32> = sockets.iter().map(|s| s.as_raw_fd()).collect();
    let (tun_w, tun_r) = fake_tun();

    let core = core();
    core.set_config(Config::default());
    core.set_socket_fds(&fds);
    core.set_resolver(resolver_addr);
    core.set_tun_fd_for_test(tun_w);

    // 1. No TLS termination: the ECHConfig is none of the filter's business.
    let keys = ask_https(core, tun_r, "ech.example.com", 0x6001);
    assert!(
        keys.contains(&5),
        "without HTTPS filtering the ECHConfig must reach the client: {keys:?}"
    );

    // 2. HTTPS filtering armed (the CA is what arms it): the parameter goes,
    //    and the rest of the record stays readable.
    core.set_config(Config {
        mitm_enabled: true,
        ..Config::default()
    });
    core.set_mitm_ca(std::sync::Arc::new(
        adfree_core::mitm::ca::CertificateAuthority::generate().expect("generate a CA"),
    ));
    let keys = ask_https(core, tun_r, "ech.example.com", 0x6002);
    assert!(
        !keys.contains(&5),
        "with HTTPS filtering the ECHConfig must be stripped: {keys:?}"
    );
    assert!(
        keys.contains(&1) && keys.contains(&4),
        "the other parameters must survive: {keys:?}"
    );
    let learned = core.snapshot();
    assert!(learned.dns_replies >= 2, "both answers must have gone out");

    core.set_config(Config::default());
    unsafe { libc::close(tun_w) };
    unsafe { libc::close(tun_r) };
    resolver_thread.join().expect("resolver thread");
}

/// A host that requires ECH cannot be filtered at all: the terminator sees
/// only the refusal. Once that refusal is learned (`mitm::ech`), the DNS half
/// leaves the host's ECHConfig in place so the browser can use ECH — and the
/// answers it *did* rewrite carry a TTL short enough that the client picks the
/// config back up quickly instead of caching a lie for five minutes.
#[test]
fn a_host_that_requires_ech_keeps_its_config() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // The ECHConfigList `crypto.cloudflare.com` served on 19/10/2026: a real
    // 0xfe0d config whose public name is `cloudflare-ech.com`.
    const CF_ECH_CONFIG: &[u8] = &[
        0x00, 0x45, 0xfe, 0x0d, 0x00, 0x41, 0x3f, 0x00, 0x20, 0x00, 0x20, 0x98, 0x25, 0xe1, 0xdb,
        0x0b, 0xf9, 0x5a, 0x81, 0x67, 0x61, 0x6c, 0x83, 0x39, 0x10, 0x9a, 0x22, 0xfd, 0x35, 0x47,
        0x20, 0xa6, 0x37, 0xd2, 0x66, 0x16, 0xa6, 0xa3, 0xc2, 0xaf, 0x8d, 0x88, 0x29, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72,
        0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    ];

    let resolver = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind resolver");
    let resolver_addr = resolver.local_addr().expect("resolver addr");
    resolver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("resolver timeout");
    let resolver_thread = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        for _ in 0..2 {
            let (n, peer) = resolver.recv_from(&mut buf).expect("recv query");
            let q = dns::parse_query(&buf[..n]).expect("a valid DNS query must arrive");
            let reply = https_answer(&q, CF_ECH_CONFIG);
            resolver.send_to(&reply, peer).expect("answer");
        }
    });

    let sockets: Vec<UdpSocket> = (0..4)
        .map(|_| {
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("bind socket")
        })
        .collect();
    let fds: Vec<i32> = sockets.iter().map(|s| s.as_raw_fd()).collect();
    let (tun_w, tun_r) = fake_tun();

    let core = core();
    core.set_config(Config {
        mitm_enabled: true,
        ..Config::default()
    });
    core.set_socket_fds(&fds);
    core.set_resolver(resolver_addr);
    core.set_tun_fd_for_test(tun_w);
    core.set_mitm_ca(std::sync::Arc::new(
        adfree_core::mitm::ca::CertificateAuthority::generate().expect("generate a CA"),
    ));

    // 1. Stripped — and short-lived: an answer the proxy rewrote is not the
    //    answer the origin published.
    let answer = ask_https_message(core, tun_r, "required-ech.test", 0x6101);
    assert!(
        !https_param_keys(&answer).contains(&5),
        "with HTTPS filtering the ECHConfig must be stripped"
    );
    assert_eq!(
        first_answer_ttl(&answer),
        60,
        "a rewritten answer must not be cached as if it came from the origin"
    );
    // The config still reaches the proxy's own upstream half: offering it is
    // what keeps a host that requires ECH filterable (R18).
    assert_eq!(
        core.ech_hosts
            .upstream_ech("required-ech.test", adfree_core::util::now_ms()),
        Some(CF_ECH_CONFIG.to_vec()),
        "a stripped answer still teaches the upstream config"
    );
    // And the public name is learned even from a stripped answer: a client that
    // cached the config before the proxy started still opens a real ECH hello,
    // whose outer SNI is this name, and that flow must be spliced — not
    // terminated with a certificate for the wrong host. The host itself is
    // still terminated: a GREASE hello keeps the real name as its SNI.
    assert!(
        core.ech_hosts.splices("cloudflare-ech.com"),
        "the public name is learned from the stripped answer too"
    );
    assert!(
        !core.ech_hosts.splices("required-ech.test"),
        "the host itself is not spliced until it refuses"
    );

    // 2. The host answered a plain connection with the refusal, so it is known
    //    to require ECH. Its config now reaches the client, untouched.
    assert!(core.ech_hosts.note_refusal("required-ech.test"));
    let answer = ask_https_message(core, tun_r, "required-ech.test", 0x6102);
    assert!(
        https_param_keys(&answer).contains(&5),
        "a host that requires ECH must keep its config: {:?}",
        https_param_keys(&answer)
    );
    assert_eq!(
        first_answer_ttl(&answer),
        300,
        "an answer left alone keeps the origin's TTL"
    );
    assert!(
        core.ech_hosts.splices("cloudflare-ech.com"),
        "a kept answer still teaches the public name"
    );
    assert!(core.ech_hosts.splices("required-ech.test"));

    core.set_config(Config::default());
    unsafe { libc::close(tun_w) };
    unsafe { libc::close(tun_r) };
    resolver_thread.join().expect("resolver thread");
}
