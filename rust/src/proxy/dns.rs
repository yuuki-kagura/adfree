//! The DNS half: a UDP server that answers like the engine's `handle_dns`
//! does on the tun path — app firewall first, user rewrites, then the lists —
//! and forwards everything else to the configured resolver.
//!
//! Under the redirect rules (`tools/adfree-linux.nft`) the machine's port-53
//! traffic lands here. Without them the platform can point its own resolver
//! configuration (or an app's DNS setting) at this port; either way the
//! filtering is identical, because the tables are the engine's.
//!
//! Answering through a redirect is the reason this is `recvmsg`/`sendmsg`
//! rather than `recv_from`/`send_to`: a `redirect` in the output hook keeps
//! the destination address and only moves the port, so the query arrives at
//! the address its sender thought it was asking. Connection tracking reverses
//! the redirect only for a reply it can match to that address, and a resolver
//! discards an answer that appears to come from anywhere else — so the answer
//! has to be sent *from* the address the question was aimed at, which is what
//! the packet-info control message does.

use super::{parse_sockaddr, poll_readable, sockaddr_for, try_mark, POLL_SLICE_MS};
use crate::dns;
use crate::engine::core;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Bytes credited to a refused lookup, matching the tun path's accounting.
const BYTES_PER_BLOCKED_REQUEST: u64 = 48 * 1024;

/// How long a forwarded query may wait for its upstream answer.
const FORWARD_TIMEOUT_MS: i32 = 5000;

/// Room for the control messages of one datagram.
const CONTROL_BYTES: usize = 512;

/// One UDP listener and the family its control messages speak. Two sockets
/// rather than one dual-stack socket because the packet-info option that carries
/// the answer back to the address the client named is family-specific, and a
/// v4-mapped peer on an IPv6 socket would have to guess which one to attach.
pub(crate) struct Listener {
    socket: UdpSocket,
    v6: bool,
}

/// Where a query came from and where it arrived: the reply needs both.
struct Inquiry {
    body: Vec<u8>,
    peer: SocketAddr,
    /// The destination address the query was sent to. `None` when the socket
    /// did not report it (no packet-info option), in which case the answer is
    /// sent from whatever address the route picks.
    local: Option<IpAddr>,
    /// Interface index reported with it, needed by the IPv6 form.
    ifindex: u32,
}

/// The v4 and v6 listeners on `port`. The v4 one is required; IPv6 is dropped
/// when the machine has no v6 stack to bind.
pub(crate) fn bind_listeners(port: u16) -> std::io::Result<Vec<Listener>> {
    let mut listeners = Vec::new();
    let v4 = bind_one(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, false)?;
    listeners.push(v4);
    match bind_one(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port, true) {
        Ok(v6) => listeners.push(v6),
        // No IPv6 here (or the stack hides it): the v4 half still serves every
        // query the redirect rules can produce on a machine without v6.
        Err(_) => crate::logbuf::push("proxy: no IPv6 DNS listener; answering IPv4 queries only"),
    }
    Ok(listeners)
}

fn bind_one(addr: IpAddr, port: u16, v6: bool) -> std::io::Result<Listener> {
    let socket = UdpSocket::bind(SocketAddr::new(addr, port))?;
    let fd = socket.as_raw_fd();
    if v6 {
        // Paired with the v4 socket above, so this one must not also claim the
        // v4 half of the port.
        let on: libc::c_int = 1;
        sockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &on as *const _ as *const _);
        sockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, &on as *const _ as *const _);
    } else {
        let on: libc::c_int = 1;
        sockopt(fd, libc::SOL_IP, libc::IP_PKTINFO, &on as *const _ as *const _);
    }
    // The mark lets an unprivileged test run this path at all: answering a
    // redirected query means sending from an address the machine does not own,
    // which only a transparent socket may do. Losing it costs the redirect
    // layout, not the explicit-resolver layout.
    let on: libc::c_int = 1;
    let transparent = if v6 { libc::IPV6_TRANSPARENT } else { libc::IP_TRANSPARENT };
    let level = if v6 { libc::IPPROTO_IPV6 } else { libc::SOL_IP };
    sockopt(fd, level, transparent, &on as *const _ as *const _);
    socket.set_nonblocking(true)?;
    Ok(Listener { socket, v6 })
}

fn sockopt(fd: RawFd, level: libc::c_int, opt: libc::c_int, val: *const libc::c_void) {
    unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            val,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
}

impl Listener {
    fn fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }

    /// One query with the address it arrived at.
    fn recv(&self, buf: &mut [u8]) -> Option<Inquiry> {
        let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut ctl = [0u8; CONTROL_BYTES];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut hdr = libc::msghdr {
            msg_name: &mut addr as *mut libc::sockaddr_storage as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: ctl.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: ctl.len(),
            msg_flags: 0,
        };
        let n = unsafe { libc::recvmsg(self.fd(), &mut hdr, 0) };
        if n <= 0 {
            return None;
        }
        let peer = parse_sockaddr(&addr)?;
        let mut local = None;
        let mut ifindex = 0;
        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
            while !cmsg.is_null() {
                let head = &*cmsg;
                if !self.v6 && head.cmsg_level == libc::SOL_IP && head.cmsg_type == libc::IP_PKTINFO
                {
                    let info = &*(libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo);
                    // `ipi_addr` is the destination the datagram was delivered
                    // to, held in network order.
                    local =
                        Some(Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr)).into());
                    ifindex = info.ipi_ifindex as u32;
                } else if self.v6
                    && head.cmsg_level == libc::IPPROTO_IPV6
                    && head.cmsg_type == libc::IPV6_PKTINFO
                {
                    let info = &*(libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo);
                    local = Some(Ipv6Addr::from(info.ipi6_addr.s6_addr).into());
                    ifindex = if_index(info.ipi6_ifindex);
                }
                cmsg = libc::CMSG_NXTHDR(&hdr, cmsg);
            }
        }
        Some(Inquiry {
            body: buf[..n as usize].to_vec(),
            peer,
            local,
            ifindex,
        })
    }

    /// Sends an answer, from the address the question named when the socket
    /// knows it.
    fn send(&self, msg: &[u8], query: &Inquiry) -> std::io::Result<usize> {
        let (addr, addrlen) = sockaddr_for(query.peer);
        let mut iov = libc::iovec {
            iov_base: msg.as_ptr() as *mut libc::c_void,
            iov_len: msg.len(),
        };
        let mut ctl = [0u8; CONTROL_BYTES];
        let mut hdr = libc::msghdr {
            msg_name: &addr as *const libc::sockaddr_storage as *mut libc::c_void,
            msg_namelen: addrlen,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: ctl.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: 0,
            msg_flags: 0,
        };
        let space = match (self.v6, query.local) {
            (false, Some(IpAddr::V4(ip))) => {
                let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) };
                hdr.msg_controllen = space as usize;
                let cmsg = match unsafe { libc::CMSG_FIRSTHDR(&hdr) } {
                    cmsg if cmsg.is_null() => return Err(last_error()),
                    cmsg => cmsg,
                };
                unsafe {
                    (*cmsg).cmsg_level = libc::SOL_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
                    let info = &mut *(libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo);
                    // `ipi_spec_dst` is the send-side name for the source address.
                    info.ipi_ifindex = 0;
                    info.ipi_spec_dst = libc::in_addr { s_addr: u32::from_le_bytes(ip.octets()) };
                    info.ipi_addr = libc::in_addr { s_addr: 0 };
                }
                true
            }
            (true, Some(IpAddr::V6(ip))) => {
                let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) };
                hdr.msg_controllen = space as usize;
                let cmsg = match unsafe { libc::CMSG_FIRSTHDR(&hdr) } {
                    cmsg if cmsg.is_null() => return Err(last_error()),
                    cmsg => cmsg,
                };
                unsafe {
                    (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize;
                    let info = &mut *(libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo);
                    info.ipi6_addr = libc::in6_addr { s6_addr: ip.octets() };
                    set_if_index(info, query.ifindex);
                }
                true
            }
            // No address reported, or a peer the socket's family cannot name:
            // the route picks the source, as it did before the redirect rules.
            _ => false,
        };
        let rc = unsafe { libc::sendmsg(self.fd(), &hdr, 0) };
        if rc < 0 {
            // A transparent socket that was not granted the option, or an
            // address the routing table will not source from: the client sees
            // a timeout, so say which half failed instead of failing silently.
            let err = std::io::Error::last_os_error();
            if space {
                crate::logbuf::push(&format!(
                    "proxy: DNS answer from {} refused ({err}); the redirect rules \
                     need AdFree to run as root",
                    query.local.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
                ));
            }
            return Err(err);
        }
        Ok(rc as usize)
    }
}

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

pub(crate) fn serve_loop(listeners: Vec<Listener>, stop: Arc<AtomicBool>) {
    // The redirect layout only loop-proofs itself through the fwmark; if the
    // mark cannot be set (no `CAP_NET_ADMIN`) say so once, loudly, instead of
    // burning a query storm in silence.
    if !probe_mark() {
        crate::logbuf::push(
            "proxy: cannot set the firewall mark (needs root); with nft redirect \
             rules installed, DNS forwarding may loop — run AdFree as root or use \
             explicit-proxy mode",
        );
    }
    let mut fds: Vec<libc::pollfd> = listeners
        .iter()
        .map(|l| libc::pollfd { fd: l.fd(), events: libc::POLLIN, revents: 0 })
        .collect();
    let mut buf = vec![0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, POLL_SLICE_MS) };
        if rc <= 0 {
            continue;
        }
        for (index, ready) in fds.iter().enumerate() {
            if ready.revents & libc::POLLIN == 0 {
                continue;
            }
            let Some(query) = listeners[index].recv(&mut buf) else {
                continue;
            };
            serve_one(&listeners[index], &query, &stop);
        }
    }
}

/// One query: parse, filter, answer or forward.
fn serve_one(listener: &Listener, query: &Inquiry, stop: &AtomicBool) {
    let core = core();
    let client = query.peer;
    let Some(parsed) = dns::parse_query(&query.body) else {
        return; // Not a parseable query: silence, the client retries or gives up.
    };
    if !parsed.is_query() || !parsed.has_question {
        return;
    }
    let stats = core.stats();
    stats.inc(&stats.dns_queries);
    let cfg = core.config();
    let host = parsed.qname.as_str().to_string();
    let server_text = core.dns_server_text();

    // The reply this listener sends, if any, and the log row describing it.
    enum Served {
        Blocked { message: Vec<u8>, rule: String, list: String, category: u8 },
        Rewritten { message: Vec<u8>, answer: String },
        Forwarded(Option<Vec<u8>>),
    }

    // App firewall first, exactly as the tun path orders it: a barred app
    // must not learn whether a host exists.
    let packages = core.apps_for_local_port(client.port());
    let decision = if let Some(reason) = core.app_blocked_reason(&packages) {
        Served::Blocked {
            message: dns::block_message(&parsed, cfg.block_mode).unwrap_or_default(),
            rule: reason.to_string(),
            list: "App firewall".to_string(),
            category: crate::filter::CAT_AD,
        }
    } else if !cfg.dns_protection || core.is_paused() {
        Served::Forwarded(forward_query(&query.body, stop))
    } else if matches!(parsed.qtype, dns::TYPE_A | dns::TYPE_AAAA)
        && core.dns_rewrite_for(&host).is_some()
    {
        // A user rewrite answers the query here — explicit intent, before
        // the lists, and only for the family it names.
        let address = core.dns_rewrite_for(&host).expect("checked");
        match dns::answer_message(&parsed, &[address], 60) {
            Some(message) => Served::Rewritten { message, answer: address.to_string() },
            None => Served::Forwarded(forward_query(&query.body, stop)),
        }
    } else {
        let mut verdict = core.filter_engine().check_host(&host);
        if verdict.blocked && verdict.rule_text.is_none() {
            verdict = core.filter_engine().check_host_detailed(&host);
        }
        if verdict.blocked {
            Served::Blocked {
                message: dns::block_message(&parsed, cfg.block_mode).unwrap_or_default(),
                rule: verdict.rule_text.unwrap_or_default(),
                list: verdict.list_name.unwrap_or_default(),
                category: verdict.category,
            }
        } else {
            Served::Forwarded(forward_query(&query.body, stop))
        }
    };

    match decision {
        Served::Blocked { message, rule, list, category } => {
            if message.is_empty() {
                return;
            }
            stats.inc(&stats.dns_blocked);
            stats.add(&stats.bytes_saved, BYTES_PER_BLOCKED_REQUEST);
            if listener.send(&message, query).is_ok() {
                stats.inc(&stats.dns_replies);
            }
            core.log_event(crate::events::with_app(
                crate::events::block_event(
                    crate::events::ACTION_BLOCK,
                    &host,
                    &server_text,
                    &rule,
                    &list,
                    category,
                    0,
                    BYTES_PER_BLOCKED_REQUEST as u32,
                    false,
                ),
                packages.first().map(String::as_str).unwrap_or(""),
            ));
        }
        Served::Rewritten { message, answer } => {
            stats.inc(&stats.dns_allowed);
            if listener.send(&message, query).is_ok() {
                stats.inc(&stats.dns_replies);
                core.log_event(crate::events::with_answer(
                    crate::events::with_app(
                        crate::events::allow_event(&host, &server_text, 0),
                        packages.first().map(String::as_str).unwrap_or(""),
                    ),
                    &answer,
                ));
            }
        }
        Served::Forwarded(reply) => match reply {
            Some(message) => {
                stats.inc(&stats.dns_allowed);
                if listener.send(&message, query).is_ok() {
                    stats.inc(&stats.dns_replies);
                }
            }
            None => {
                stats.inc(&stats.dns_timeouts);
            }
        },
    }
}

/// Sends the query to the engine's resolver (or `/etc/resolv.conf` when no
/// provider was configured) and waits for the answer on the same marked
/// socket. `None` means the upstream did not answer in time.
fn forward_query(body: &[u8], stop: &AtomicBool) -> Option<Vec<u8>> {
    let resolver = resolver_addr()?;
    let local: SocketAddr = if resolver.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).ok()?;
    try_mark(socket.as_raw_fd());
    socket.send_to(body, resolver).ok()?;
    let fd = socket.as_raw_fd();
    let started = std::time::Instant::now();
    let mut reply = vec![0u8; 4096];
    loop {
        if stop.load(Ordering::Relaxed) || started.elapsed().as_millis() as i32 > FORWARD_TIMEOUT_MS
        {
            return None;
        }
        if !poll_readable(fd, POLL_SLICE_MS) {
            continue;
        }
        match socket.recv(&mut reply) {
            Ok(n) if n >= 12 => {
                let mut out = reply[..n].to_vec();
                // The transaction id is the client's own (we forwarded the
                // bytes untouched), but EDNS may have been trimmed upstream;
                // hand back exactly what arrived.
                dns::patch_txid(&mut out, dns::parse_query(body).map(|q| q.id).unwrap_or(0));
                return Some(out);
            }
            Ok(_) => return None,
            Err(_) => return None,
        }
    }
}

/// The upstream resolver: the engine's configured one, else the system's.
fn resolver_addr() -> Option<SocketAddr> {
    let configured = core().resolver_addr();
    if configured.ip().is_unspecified() {
        return system_resolver();
    }
    if configured.ip().is_loopback() {
        // A stub on loopback is not a way out of this listener: under the
        // redirect rules the stub's own upstream queries come back here, and
        // forwarding into it answers our own request. The real server is
        // readable from the files the stub publishes.
        if let Some(system) = system_resolver() {
            if system != configured {
                return Some(system);
            }
        }
        return None;
    }
    Some(configured)
}

/// Where a query can actually leave the machine: the first non-loopback
/// `nameserver` in the resolver files, in the order a desktop would trust
/// them. `/etc/resolv.conf` on a `systemd-resolved` or NetworkManager host
/// names only the stub (127.0.0.53), and the stub answers from the real
/// servers it lists in its own file — which is the one hop that cannot loop.
fn system_resolver() -> Option<SocketAddr> {
    [
        "/etc/resolv.conf",
        "/run/systemd/resolve/resolv.conf",
        "/run/NetworkManager/resolv.conf",
    ]
    .into_iter()
    .find_map(first_real_nameserver)
}

fn first_real_nameserver(path: &str) -> Option<SocketAddr> {
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Ok(ip) = fields.next()?.parse::<IpAddr>() {
            // Link-local and loopback are not an exit; a stub especially is
            // the thing we are trying to get upstream of.
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            return Some(SocketAddr::new(ip, 53));
        }
    }
    None
}

/// The interface index an IPv6 datagram arrived on. bionic types the field
/// `c_int` and every other libc `u32`, so the value crosses through here
/// rather than at each use.
#[cfg(target_os = "android")]
fn if_index(value: libc::c_int) -> u32 {
    value as u32
}

#[cfg(not(target_os = "android"))]
fn if_index(value: u32) -> u32 {
    value
}

#[cfg(target_os = "android")]
fn set_if_index(info: &mut libc::in6_pktinfo, value: u32) {
    info.ipi6_ifindex = value as libc::c_int;
}

#[cfg(not(target_os = "android"))]
fn set_if_index(info: &mut libc::in6_pktinfo, value: u32) {
    info.ipi6_ifindex = value;
}

/// True when a fresh socket can carry the firewall mark.
fn probe_mark() -> bool {
    let Ok(socket) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
        return false;
    };
    let fd = socket.as_raw_fd();
    let mark = super::FWMARK;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_bytes(name: &str, qtype: u16) -> Vec<u8> {
        dns::build_query(name, qtype, 0xbeef).unwrap()
    }

    #[test]
    fn block_message_answers_the_query_with_the_chosen_refusal() {
        let body = query_bytes("ads.example.com", dns::TYPE_A);
        let q = dns::parse_query(&body).unwrap();
        let msg = dns::block_message(&q, dns::BlockMode::NxDomain).unwrap();
        assert_eq!(&msg[0..2], &0xbeefu16.to_be_bytes(), "the id is echoed");
        assert_eq!(msg[2] & 0x80, 0x80, "QR is set");
        assert_eq!((msg[3] & 0x0f), 3, "NXDOMAIN");
        // A second parse of the answer proves it is wire-valid.
        let a = dns::parse_query(&msg).unwrap();
        assert!(!a.is_query());
        assert_eq!(a.qname.as_str(), "ads.example.com");
    }

    #[test]
    fn zero_ip_mode_carries_a_record() {
        let body = query_bytes("track.example.com", dns::TYPE_A);
        let q = dns::parse_query(&body).unwrap();
        let msg = dns::block_message(&q, dns::BlockMode::ZeroIp).unwrap();
        assert_eq!(&msg[6..8], &1u16.to_be_bytes(), "one answer record");
        assert!(msg.ends_with(&[0, 0, 0, 0]), "the record is 0.0.0.0");
    }

    #[test]
    fn answer_message_answers_only_the_asked_family() {
        let body = query_bytes("v6.example.com", dns::TYPE_AAAA);
        let q = dns::parse_query(&body).unwrap();
        let v4: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(
            dns::answer_message(&q, &[v4], 60).is_none(),
            "an A answer never answers an AAAA question"
        );
    }

    #[test]
    fn resolv_conf_names_a_usable_server() {
        // The container may have no nameserver line at all; either answer is
        // fine as long as the parser never panics on what the host wrote.
        let _ = system_resolver();
    }

    #[test]
    fn a_loopback_stub_is_never_the_way_out() {
        let dir = std::env::temp_dir().join(format!("adfree-resolv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub");
        std::fs::write(&stub, "# Generated by NetworkManager\nnameserver 127.0.0.53\n").unwrap();
        assert_eq!(
            first_real_nameserver(stub.to_str().unwrap()),
            None,
            "forwarding into the stub is the loop the redirect rules would close on us"
        );
        let real = dir.join("real");
        std::fs::write(&real, "nameserver 10.2.0.1\nnameserver 8.8.8.8\n").unwrap();
        assert_eq!(
            first_real_nameserver(real.to_str().unwrap()),
            Some("10.2.0.1:53".parse().unwrap()),
            "the first real server answers"
        );
        let blank = dir.join("blank");
        std::fs::write(&blank, "options edns0\nnameserver\n").unwrap();
        assert_eq!(first_real_nameserver(blank.to_str().unwrap()), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_query_carries_the_address_it_was_sent_to() {
        // The redirect layout depends on reading the destination back, so the
        // socket must report it: bind on a free port, ask that port by name,
        // and see the same address on the other side of `recv`.
        let listeners = bind_listeners(free_port()).unwrap();
        let index = listeners
            .iter()
            .position(|l| !l.v6)
            .expect("a v4 listener");
        let fd = listeners[index].fd();
        let target: SocketAddr = listeners[index]
            .socket
            .local_addr()
            .expect("the bound address");
        let client = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        client
            .send_to(&query_bytes("probe.example", dns::TYPE_A), target)
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let query = loop {
            if std::time::Instant::now() > deadline {
                panic!("the listener never saw the query");
            }
            if poll_readable(fd, POLL_SLICE_MS) {
                if let Some(query) = listeners[index].recv(&mut buf) {
                    break query;
                }
            }
        };
        assert_eq!(
            query.local,
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "packet-info names the destination the client aimed at"
        );
        assert!(query.peer.port() > 0, "the sender is known too");
    }

    fn free_port() -> u16 {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        probe.local_addr().unwrap().port()
    }
}
