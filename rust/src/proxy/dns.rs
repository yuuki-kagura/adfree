//! The DNS half: a UDP server that answers like the engine's `handle_dns`
//! does on the tun path — app firewall first, user rewrites, then the lists —
//! and forwards everything else to the configured resolver.
//!
//! Under the redirect rules (`tools/adfree-linux.nft`) the machine's port-53
//! traffic lands here. Without them the platform can point its own resolver
//! configuration (or an app's DNS setting) at this port; either way the
//! filtering is identical, because the tables are the engine's.

use super::{poll_readable, try_mark, POLL_SLICE_MS};
use crate::dns;
use crate::engine::core;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Bytes credited to a refused lookup, matching the tun path's accounting.
const BYTES_PER_BLOCKED_REQUEST: u64 = 48 * 1024;

/// How long a forwarded query may wait for its upstream answer.
const FORWARD_TIMEOUT_MS: i32 = 5000;

/// The DNS listener, dual-stack like the TCP one: the redirect rules send the
/// v4 questions to `127.0.0.1` and the v6 ones to `::1`, and a single socket
/// answers both. std maps an IPv4 peer onto the IPv6 socket for the reply.
pub(crate) fn bind_socket(port: u16) -> std::io::Result<UdpSocket> {
    match bind_v6(port) {
        Ok(socket) => Ok(socket),
        Err(_) => {
            let socket = UdpSocket::bind(("0.0.0.0", port))?;
            socket.set_nonblocking(true)?;
            Ok(socket)
        }
    }
}

fn bind_v6(port: u16) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(std::net::SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        port,
    ))?;
    let off: libc::c_int = 0;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    socket.set_nonblocking(true)?;
    Ok(socket)
}

pub(crate) fn serve_loop(socket: UdpSocket, stop: Arc<AtomicBool>) {
    let fd = socket.as_raw_fd();
    let mut buf = vec![0u8; 4096];
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
    while !stop.load(Ordering::Relaxed) {
        if !poll_readable(fd, POLL_SLICE_MS) {
            continue;
        }
        let Ok((n, client)) = socket.recv_from(&mut buf) else {
            continue;
        };
        serve_one(&socket, &buf[..n], client, &stop);
    }
}

/// One query: parse, filter, answer or forward.
fn serve_one(socket: &UdpSocket, body: &[u8], client: SocketAddr, stop: &AtomicBool) {
    let core = core();
    let Some(query) = dns::parse_query(body) else {
        return; // Not a parseable query: silence, the client retries or gives up.
    };
    if !query.is_query() || !query.has_question {
        return;
    }
    let stats = core.stats();
    stats.inc(&stats.dns_queries);
    let cfg = core.config();
    let host = query.qname.as_str().to_string();
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
            message: dns::block_message(&query, cfg.block_mode).unwrap_or_default(),
            rule: reason.to_string(),
            list: "App firewall".to_string(),
            category: crate::filter::CAT_AD,
        }
    } else if !cfg.dns_protection || core.is_paused() {
        Served::Forwarded(forward_query(body, stop))
    } else if matches!(query.qtype, dns::TYPE_A | dns::TYPE_AAAA)
        && core.dns_rewrite_for(&host).is_some()
    {
        // A user rewrite answers the query here — explicit intent, before
        // the lists, and only for the family it names.
        let address = core.dns_rewrite_for(&host).expect("checked");
        match dns::answer_message(&query, &[address], 60) {
            Some(message) => Served::Rewritten { message, answer: address.to_string() },
            None => Served::Forwarded(forward_query(body, stop)),
        }
    } else {
        let mut verdict = core.filter_engine().check_host(&host);
        if verdict.blocked && verdict.rule_text.is_none() {
            verdict = core.filter_engine().check_host_detailed(&host);
        }
        if verdict.blocked {
            Served::Blocked {
                message: dns::block_message(&query, cfg.block_mode).unwrap_or_default(),
                rule: verdict.rule_text.unwrap_or_default(),
                list: verdict.list_name.unwrap_or_default(),
                category: verdict.category,
            }
        } else {
            Served::Forwarded(forward_query(body, stop))
        }
    };

    match decision {
        Served::Blocked { message, rule, list, category } => {
            if message.is_empty() {
                return;
            }
            stats.inc(&stats.dns_blocked);
            stats.add(&stats.bytes_saved, BYTES_PER_BLOCKED_REQUEST);
            if socket.send_to(&message, client).is_ok() {
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
            if socket.send_to(&message, client).is_ok() {
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
                if socket.send_to(&message, client).is_ok() {
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
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(local).ok()?;
    try_mark(socket.as_raw_fd());
    socket.send_to(body, resolver).ok()?;
    let fd = socket.as_raw_fd();
    let started = std::time::Instant::now();
    let mut reply = vec![0u8; 4096];
    loop {
        if stop.load(Ordering::Relaxed) || started.elapsed().as_millis() as i32 > FORWARD_TIMEOUT_MS {
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
        // Under the redirect rules a loopback resolver is likely our own port
        // in disguise; the real server from resolv.conf is the honest upstream.
        if let Some(system) = system_resolver() {
            if system != configured {
                return Some(system);
            }
        }
    }
    Some(configured)
}

/// The first `nameserver` line of `/etc/resolv.conf`, port 53.
fn system_resolver() -> Option<SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("nameserver") {
            if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, 53));
            }
        }
    }
    None
}

/// True when a fresh socket can carry the firewall mark.
fn probe_mark() -> bool {
    let Ok(socket) = UdpSocket::bind(("127.0.0.1", 0)) else {
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
}
