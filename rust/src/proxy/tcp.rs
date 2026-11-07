//! The TCP half: one listener, one thread per flow, the same filtering the
//! tun relay arms for an intercepted 443.
//!
//! The destination comes from `SO_ORIGINAL_DST` when the redirect rules are
//! installed; without them the listener answers plain proxy requests
//! (`CONNECT host:443`, absolute-form `GET http://host/`), so a browser can be
//! pointed at it with no root at all. Both roads end in the same pump: raw
//! splice for what is not terminated, [`ProxySession`] for HTTPS.

use super::{
    dial_marked, parse_sockaddr, poll2, reset_on_close, set_nonblocking, set_reuse,
    write_all_nb, IDLE_TIMEOUT, POLL_SLICE_MS,
};
use crate::engine::core;
use crate::mitm::proxy::ProxySession;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Binds the listener. Dual-stack `::` so a redirected flow arrives whatever
/// family the app asked for: `redirect` in the output hook keeps the
/// destination address and only moves the port, so the socket has to answer on
/// every local address, not just loopback. That reach is closed again per
/// connection — [`super::is_local_peer`] — so the listener sits on the LAN
/// interfaces without serving them.
pub(crate) fn bind_listener(port: u16) -> std::io::Result<TcpListener> {
    match bind_v6(port) {
        Ok(listener) => Ok(listener),
        // No IPv6 on this machine (or a container that hides it): the v4
        // listener still serves every flow the rules can produce here.
        Err(_) => bind_v4(port),
    }
}

fn bind_v6(port: u16) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(std::net::SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        port,
    ))?;
    let fd = listener.as_raw_fd();
    // Linux defaults to dual-stack, but `net.ipv6.bindv6only=1` would otherwise
    // silently cost the v4 half of the redirect rules.
    let off: libc::c_int = 0;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &off as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    set_reuse(fd);
    set_nonblocking(fd);
    Ok(listener)
}

fn bind_v4(port: u16) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    set_reuse(listener.as_raw_fd());
    set_nonblocking(listener.as_raw_fd());
    Ok(listener)
}

/// The accept loop: one thread per connection; the slot each thread carries
/// is what bounds how many may live at once.
pub(crate) fn accept_loop(listener: TcpListener, stop: Arc<AtomicBool>) {
    let fd = listener.as_raw_fd();
    while !stop.load(Ordering::Relaxed) {
        if !super::poll_readable(fd, POLL_SLICE_MS) {
            continue;
        }
        let (client, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        // The wildcard bind is for the redirect's sake, not the network's:
        // a flow that did not start on this machine is not ours to filter,
        // and serving it would make AdFree an open proxy.
        let local = client
            .peer_addr()
            .ok()
            .is_some_and(|peer| super::is_local_peer(peer));
        if !local {
            reset_on_close(client.as_raw_fd());
            continue;
        }
        let Some(slot) = super::Slot::new() else {
            // Past the connection cap: refuse fast, the client retries later.
            reset_on_close(client.as_raw_fd());
            continue;
        };
        set_nonblocking(client.as_raw_fd());
        let stop = Arc::clone(&stop);
        if std::thread::Builder::new()
            .name("adfree-proxy-conn".into())
            .stack_size(1024 * 1024)
            .spawn(move || {
                let _slot = slot; // Released when the flow retires.
                handle(client, &stop);
            })
            .is_err()
        {
            crate::logbuf::push("proxy: could not spawn a connection thread");
        }
    }
}

/// Which way the destination is known, and what the client's first bytes
/// still owe the pump.
enum Target {
    /// Set by the redirect rules: bytes start at the protocol itself.
    Original(SocketAddr),
    /// `CONNECT host:port` was parsed and answered; the head is consumed.
    Connect(SocketAddr),
    /// Absolute-form `GET http://host/path` was rewritten to origin form:
    /// `head` is what the peer must receive before any other byte.
    PlainHttp { addr: SocketAddr, head: Vec<u8> },
}

fn handle(client: TcpStream, stop: &AtomicBool) {
    let core = core();
    let cfg = core.config();
    let client_fd = client.as_raw_fd();

    let Some(target) = resolve_target(client_fd, stop) else {
        reset_on_close(client_fd);
        return;
    };
    let addr = match &target {
        Target::Original(a) | Target::Connect(a) | Target::PlainHttp { addr: a, .. } => *a,
    };
    if Some(addr) == local_addr(client_fd) {
        // An explicit-proxy request that names this very listener. Dialing it
        // would fork a connection onto ourselves until the slot table fills.
        crate::logbuf::push("proxy: request aimed at the proxy itself; refused");
        reset_on_close(client_fd);
        return;
    }

    // The per-app firewall decides before any socket is opened, exactly as
    // `engine::complete_setup` does on the tun path. On this path the
    // connecting process is knowable, and naming it is what makes the desktop
    // log answer the question it exists to answer: which app asked for this.
    let apps = match (client.peer_addr().ok(), local_addr(client_fd)) {
        (Some(from), Some(our)) => core.peer_apps(from, our),
        _ => Vec::new(),
    };
    if let Some(reason) = core.app_blocked_reason(&apps) {
        crate::logbuf::push(&format!(
            "proxy: {} refused by the app firewall",
            apps.first().map(String::as_str).unwrap_or("app")
        ));
        core.log_event(crate::events::with_protocol(
            crate::events::with_url(
                crate::events::with_type(
                    crate::events::with_app(
                        crate::events::block_event(
                            crate::events::ACTION_BLOCK,
                            &addr.ip().to_string(),
                            &addr.to_string(),
                            reason,
                            "App firewall",
                            crate::filter::CAT_AD,
                            0,
                            0,
                            addr.is_ipv6(),
                        ),
                        apps.first().map(String::as_str).unwrap_or(""),
                    ),
                    // No request was ever made: the app firewall refused the
                    // connection itself, which is the log's Connection row.
                    crate::events::req_type::CONNECTION,
                ),
                &format!("tcp://{addr}"),
            ),
            crate::events::protocol::TCP,
        ));
        reset_on_close(client_fd);
        return;
    }

    let local = addr.ip() == crate::mitm::proxy::local_origin_addr();
    // AdGuard for Windows' "Filter localhost": off leaves this machine's own
    // conversations alone — a local dev server is not intercepted, its
    // certificate not swapped for ours, because the destination is this very
    // machine rather than a host out there being judged. The app firewall has
    // already decided above whether this app may dial at all: that question
    // is about the app, not about what it is fetching.
    let filter_localhost = super::filters_loopback();
    let mitm_armed = core.mitm_ready(&cfg)
        && (filter_localhost || !addr.ip().is_loopback())
        && core.mitm_port.load(Ordering::Relaxed) == addr.port();
    if local && !mitm_armed {
        crate::logbuf::push("proxy: local origin asked without HTTPS filtering");
        reset_on_close(client_fd);
        return;
    }

    let (mut session, mut peer) = if mitm_armed {
        let session = if local {
            arm_local_session(core, &cfg, &apps)
        } else {
            arm_session(core, &cfg, &apps)
        };
        let Some(session) = session else {
            reset_on_close(client_fd);
            return;
        };
        if local {
            (Some(session), None)
        } else {
            match dial_marked(addr) {
                Some(peer) => (Some(session), Some(peer)),
                None => {
                    crate::logbuf::push(&format!("proxy: dial {addr} failed"));
                    reset_on_close(client_fd);
                    return;
                }
            }
        }
    } else if local {
        // The injection origin only exists as a TLS session; nothing to splice.
        reset_on_close(client_fd);
        return;
    } else {
        match dial_marked(addr) {
            Some(peer) => (None, Some(peer)),
            None => {
                crate::logbuf::push(&format!("proxy: dial {addr} failed"));
                reset_on_close(client_fd);
                return;
            }
        }
    };

    let mut peer_fd = peer.as_ref().map(TcpStream::as_raw_fd).unwrap_or(-1);

    // A connection this proxy only relays is still something the log should
    // name: AdGuard's Connection tab lists what passed untouched, and without
    // the row an encrypted session to a host no rule mentions is invisible.
    // A flow that got a TLS session writes its own rows, one per request.
    if session.is_none() && cfg.log_allowed {
        core.log_event(connection_row(&addr, apps.first().map(String::as_str).unwrap_or("")));
    }

    let mut buf = vec![0u8; 16 * 1024];
    let mut last_activity = std::time::Instant::now();
    let mut peer_open = peer_fd >= 0;

    if let Target::PlainHttp { head, .. } = &target {
        if write_all_nb(peer_fd, head, stop).is_err() {
            return;
        }
    }

    while !stop.load(Ordering::Relaxed) {
        if last_activity.elapsed() > IDLE_TIMEOUT {
            break;
        }
        let (client_ready, peer_ready) = if peer_open {
            poll2(client_fd, Some(peer_fd), POLL_SLICE_MS)
        } else {
            poll2(client_fd, None, POLL_SLICE_MS)
        };
        if !client_ready && !peer_ready {
            continue;
        }
        last_activity = std::time::Instant::now();

        // Client bytes first: on a session they decide the handshake.
        if client_ready {
            match read_nb(client_fd, &mut buf) {
                Read::Bytes(n) => {
                    let outcome = match &mut session {
                        Some(session) => session.on_client_payload(&buf[..n]),
                        None => Ok(crate::mitm::proxy::Outcome {
                            to_peer: buf[..n].to_vec(),
                            ..Default::default()
                        }),
                    };
                    if apply_outcome(
                        outcome,
                        client_fd,
                        &mut peer,
                        &mut peer_fd,
                        &mut peer_open,
                        stop,
                        session.as_mut(),
                        &apps,
                        addr,
                    ) == Step::Done
                    {
                        break;
                    }
                }
                Read::Closed => {
                    // A client that finished the handshake and left without a
                    // request refused the certificate (see
                    // `ProxySession::on_client_eof`).
                    if let Some(session) = session.as_mut() {
                        if let Some(host) = session.on_client_eof() {
                            core.note_client_refusal(&host, &apps);
                        }
                    }
                    break;
                }
                Read::Retry => {}
            }
        }

        // Then the upstream half.
        if peer_open && peer_ready {
            match read_nb(peer_fd, &mut buf) {
                Read::Bytes(n) => {
                    let outcome = match &mut session {
                        Some(session) => session.on_peer_payload(&buf[..n]),
                        None => Ok(crate::mitm::proxy::Outcome {
                            to_client: buf[..n].to_vec(),
                            ..Default::default()
                        }),
                    };
                    if apply_outcome(
                        outcome,
                        client_fd,
                        &mut peer,
                        &mut peer_fd,
                        &mut peer_open,
                        stop,
                        session.as_mut(),
                        &apps,
                        addr,
                    ) == Step::Done
                    {
                        break;
                    }
                }
                Read::Closed => break,
                Read::Retry => {}
            }
        }

        // Requests the client queued while the upstream handshake ran.
        if let Some(session) = session.as_mut() {
            if peer_open {
                let extra = session.take_upstream_outbound();
                if !extra.is_empty() && write_all_nb(peer_fd, &extra, stop).is_err() {
                    break;
                }
            }
        }
    }
}

#[derive(PartialEq, Eq)]
enum Step {
    Continue,
    Done,
}

/// The row for a connection this proxy carries without looking inside it.
/// Nothing was refused, so the answer column stays empty and the name is the
/// pseudo-URL AdGuard gives a connection: the address the client was told to
/// reach, with its port, which is all this path can know before TLS starts.
fn connection_row(addr: &SocketAddr, app: &str) -> crate::events::Event {
    let event = crate::events::with_app(
        crate::events::block_event(
            crate::events::ACTION_ALLOW,
            &addr.ip().to_string(),
            &addr.to_string(),
            "",
            "",
            0,
            0,
            0,
            addr.is_ipv6(),
        ),
        app,
    );
    crate::events::with_protocol(
        crate::events::with_url(
            crate::events::with_type(event, crate::events::req_type::CONNECTION),
            &format!("tcp://{addr}"),
        ),
        crate::events::protocol::TCP,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_outcome(
    outcome: Result<crate::mitm::proxy::Outcome, String>,
    client_fd: RawFd,
    peer: &mut Option<TcpStream>,
    peer_fd: &mut RawFd,
    peer_open: &mut bool,
    stop: &AtomicBool,
    session: Option<&mut ProxySession>,
    apps: &[String],
    redial: SocketAddr,
) -> Step {
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(e) => {
            if let Some(session) = session {
                if let Some(host) = session.captured_sni() {
                    // An app that refuses our CA gets spliced from now on —
                    // the same learning the tun path does.
                    core().note_client_cert_rejection(&e, apps, &host);
                }
            }
            crate::logbuf::push(&format!("proxy: session: {e}"));
            return Step::Done;
        }
    };
    let to_client = outcome.to_client;
    let to_peer = outcome.to_peer;
    if outcome.restart_peer && *peer_open {
        // The old upstream connection is dead; the retry hello goes to a new
        // one (the ECH fallback, see `mitm::proxy::Outcome`).
        drop(peer.take());
        *peer = dial_marked(redial);
        *peer_fd = peer.as_ref().map(TcpStream::as_raw_fd).unwrap_or(-1);
        *peer_open = *peer_fd >= 0;
        if !*peer_open {
            return Step::Done;
        }
    }
    if !to_client.is_empty() && write_all_nb(client_fd, &to_client, stop).is_err() {
        return Step::Done;
    }
    if !to_peer.is_empty() {
        if !*peer_open {
            return Step::Done;
        }
        if write_all_nb(*peer_fd, &to_peer, stop).is_err() {
            return Step::Done;
        }
    }
    if outcome.closed {
        return Step::Done;
    }
    Step::Continue
}

enum Read {
    Bytes(usize),
    Closed,
    Retry,
}

fn read_nb(fd: RawFd, buf: &mut [u8]) -> Read {
    let rc = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if rc > 0 {
        return Read::Bytes(rc as usize);
    }
    if rc == 0 {
        return Read::Closed;
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EAGAIN) | Some(libc::EINTR) => Read::Retry,
        _ => Read::Closed,
    }
}

/// The original destination the redirect rules recorded, if any.
fn original_dst(client_fd: RawFd) -> Option<SocketAddr> {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            client_fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut sa as *mut libc::sockaddr_storage as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        return parse_sockaddr(&sa);
    }
    // v6 redirect: the same option under SOL_IPV6.
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            client_fd,
            libc::SOL_IPV6,
            libc::IP6T_SO_ORIGINAL_DST,
            &mut sa as *mut libc::sockaddr_storage as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        parse_sockaddr(&sa)
    } else {
        None
    }
}

/// This socket's own local address — the port the listener is bound to.
fn local_addr(fd: RawFd) -> Option<SocketAddr> {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockname(
            fd,
            &mut sa as *mut libc::sockaddr_storage as *mut libc::sockaddr,
            &mut len,
        )
    };
    if rc == 0 {
        parse_sockaddr(&sa)
    } else {
        None
    }
}

/// Where this connection is headed: the redirected destination, or the one
/// named by a plain proxy request.
fn resolve_target(fd: RawFd, stop: &AtomicBool) -> Option<Target> {
    if let Some(addr) = original_dst(fd) {
        // A socket nobody redirected has no conntrack entry, and the kernel
        // then answers `SO_ORIGINAL_DST` with the connection's *current*
        // destination — the proxy's own address. Taking that at face value
        // would send every explicit-proxy request back into the listener, so
        // the answer only counts when it names something other than ourselves.
        if Some(addr) != local_addr(fd) {
            return Some(Target::Original(addr));
        }
    }
    // Explicit proxy mode: the first request names the destination. Peek
    // until a head terminates (or 3 seconds give up).
    let mut peek = vec![0u8; 8192];
    let head = loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        if !super::poll_readable(fd, 3000) {
            return None;
        }
        let rc = unsafe {
            libc::recv(
                fd,
                peek.as_mut_ptr() as *mut libc::c_void,
                peek.len(),
                libc::MSG_PEEK,
            )
        };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                _ => return None,
            }
        }
        let bytes = &peek[..rc as usize];
        if let Some(end) = find_head_end(bytes) {
            break bytes[..end].to_vec();
        }
        if (rc as usize) == peek.len() {
            return None; // A head over 8 KiB is not a proxy request.
        }
    };
    let text = String::from_utf8_lossy(&head).into_owned();
    let first_line = text.split("\r\n").next().unwrap_or("");
    let mut parts = first_line.split(' ');
    let (
        Some(method),
        Some(uri),
    ) = (parts.next(), parts.next())
    else {
        return None;
    };
    let version = parts.next().unwrap_or("HTTP/1.1");
    if method == "CONNECT" {
        let addr = resolve_authority(uri, 443)?;
        let reply = b"HTTP/1.1 200 Connection established\r\n\r\n";
        write_all_nb(fd, reply, stop).ok()?;
        let mut sink = vec![0u8; head.len()];
        read_exact_nb(fd, &mut sink, stop)?;
        return Some(Target::Connect(addr));
    }
    if method == "GET" || method == "POST" {
        if let Some(rest) = uri.strip_prefix("http://") {
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            let addr = resolve_authority(authority, 80)?;
            // Rebuild the head with an origin-form request line; every other
            // line (and everything after it) travels untouched.
            let mut rebuilt: Vec<u8> = Vec::with_capacity(head.len() + 16);
            rebuilt.extend_from_slice(method.as_bytes());
            rebuilt.push(b' ');
            rebuilt.extend_from_slice(path.as_bytes());
            rebuilt.push(b' ');
            rebuilt.extend_from_slice(version.as_bytes());
            rebuilt.extend_from_slice(b"\r\n");
            for line in text.split("\r\n").skip(1) {
                rebuilt.extend_from_slice(line.as_bytes());
                rebuilt.extend_from_slice(b"\r\n");
                // The blank line that terminates the head is the last one to
                // emit: `head` stopped exactly there, and a split on an
                // empty tail would otherwise duplicate it.
                if line.is_empty() {
                    break;
                }
            }
            let mut sink = vec![0u8; head.len()];
            read_exact_nb(fd, &mut sink, stop)?;
            return Some(Target::PlainHttp { addr, head: rebuilt });
        }
    }
    None
}

fn resolve_authority(text: &str, default_port: u16) -> Option<SocketAddr> {
    let (host, port) = match text.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (text, default_port),
    };
    let host = host.trim_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let mut addrs = (host, port).to_socket_addrs().ok()?;
    addrs.find(SocketAddr::is_ipv4).or_else(|| addrs.next())
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn read_exact_nb(fd: RawFd, buf: &mut [u8], stop: &AtomicBool) -> Option<()> {
    let mut off = 0usize;
    while off < buf.len() {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        if !super::poll_readable(fd, POLL_SLICE_MS) {
            continue;
        }
        let rc = unsafe {
            libc::read(
                fd,
                buf[off..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - off,
            )
        };
        if rc > 0 {
            off += rc as usize;
            continue;
        }
        if rc == 0 {
            return None;
        }
        let err = std::io::Error::last_os_error();
        if !matches!(err.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
            return None;
        }
    }
    Some(())
}

/// A TLS-terminating session armed exactly like the tun path arms one (see
/// `engine::complete_setup`): scripts, cosmetics, stealth, the firewall
/// lists, ECH knowledge and the DNS lists that refuse a blocked host's hello.
fn arm_session(
    core: &crate::engine::Core,
    cfg: &crate::engine::Config,
    apps: &[String],
) -> Option<ProxySession> {
    let (script_path, script_body) = {
        let scripts = core.mitm_scripts.read().unwrap();
        (scripts.serve_path().to_string(), scripts.combined_arc())
    };
    let mut session = ProxySession::new_pending(
        core.mitm_resolver(),
        core.upstream_tls_config(),
        script_path,
        script_body,
    )
    .map_err(|e| crate::logbuf::push(&format!("proxy: open tls session: {e}")))
    .ok()?;
    if cfg.cosmetic_filtering {
        session.set_cosmetic(core.filter_engine());
    }
    session.set_stealth(cfg.stealth);
    session.set_stats(core.stats_arc());
    session.set_sink(crate::engine::log_mitm_block);
    session.set_apps(apps.to_vec());
    session.set_https_skip_apps(core.effective_https_skip_apps());
    session.set_ech_hosts(Arc::clone(&core.ech_hosts), cfg.full_ech);
    session.set_untrusted(Arc::clone(&core.untrusted_clients));
    let (skip, only, only_mode) = core.https_host_lists();
    session.set_https_hosts(skip, only, only_mode);
    session.set_host_filter(core.filter_engine());
    Some(session)
}

/// The local injection origin's session: TLS terminates here and every
/// request is answered from the same tables the HTML rewrite uses.
fn arm_local_session(
    core: &crate::engine::Core,
    cfg: &crate::engine::Config,
    apps: &[String],
) -> Option<ProxySession> {
    let (script_path, script_body) = {
        let scripts = core.mitm_scripts.read().unwrap();
        (scripts.serve_path().to_string(), scripts.combined_arc())
    };
    let mut session = ProxySession::new_local(core.mitm_resolver(), script_path, script_body)
        .map_err(|e| {
            crate::logbuf::push(&format!("proxy: open local session: {e}"));
            e
        })
        .ok()?;
    if cfg.cosmetic_filtering {
        session.set_cosmetic(core.filter_engine());
    }
    session.set_stats(core.stats_arc());
    session.set_apps(apps.to_vec());
    Some(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_head_ends_at_the_blank_line() {
        let bytes = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nrest";
        assert_eq!(find_head_end(bytes), Some(bytes.len() - 4));
        assert_eq!(find_head_end(b"GET /x HTTP/1.1\r\n"), None);
    }

    /// AdGuard's Connection tab is not only refusals: a session this proxy
    /// relays untouched is a row too, named by the address the client was sent
    /// to because nothing here can see inside the TLS that starts after it.
    #[test]
    fn a_relayed_connection_is_a_row_of_its_own() {
        let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let event = connection_row(&addr, "com.example.browser");
        assert_eq!(event.action, crate::events::ACTION_ALLOW);
        assert_eq!(event.protocol(), crate::events::protocol::TCP);
        assert_eq!(event.req_type_name(), "connection");
        assert_eq!(event.url(), "tcp://93.184.216.34:443");
        assert_eq!(event.domain(), "93.184.216.34");
        assert_eq!(event.app(), "com.example.browser");
        assert_eq!(event.answer(), "", "a relayed connection claims no answer");
    }

    #[test]
    fn authorities_resolve_with_the_right_default_port() {
        let ip_only = resolve_authority("93.184.216.34", 443).unwrap();
        assert_eq!(ip_only.port(), 443);
        let with_port = resolve_authority("93.184.216.34:8080", 443).unwrap();
        assert_eq!(with_port.port(), 8080);
        let v6 = resolve_authority("[::1]:53", 443).unwrap();
        assert_eq!(v6.port(), 53);
        // A port that is not a number is part of the name, not a port.
        assert!(resolve_authority("example.com:notaport", 443).is_none());
    }

    #[test]
    fn an_absolute_head_is_rebuilt_in_origin_form() {
        // The shape `resolve_target` produces for `GET http://host/path`:
        // origin-form request line with its version, every later line kept.
        let head = "GET http://example.com/ads/banner.js HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let first_line = head.split("\r\n").next().unwrap();
        let mut parts = first_line.split(' ');
        let method = parts.next().unwrap();
        let uri = parts.next().unwrap();
        let version = parts.next().unwrap_or("HTTP/1.1");
        let path = uri
            .strip_prefix("http://example.com")
            .unwrap_or("/");
        let mut rebuilt = String::new();
        rebuilt.push_str(method);
        rebuilt.push(' ');
        rebuilt.push_str(path);
        rebuilt.push(' ');
        rebuilt.push_str(version);
        rebuilt.push_str("\r\n");
        for line in head.split("\r\n").skip(1) {
            rebuilt.push_str(line);
            rebuilt.push_str("\r\n");
            if line.is_empty() {
                break;
            }
        }
        assert_eq!(
            rebuilt,
            "GET /ads/banner.js HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
        );
    }
}
