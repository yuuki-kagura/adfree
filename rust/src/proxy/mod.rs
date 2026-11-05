//! Desktop protection without a tunnel: the AdGuard-for-Windows method.
//!
//! AdGuard on Windows does not run a VPN. Kernel redirect hooks move the
//! machine's own HTTP(S) traffic onto a local transparent proxy, a local DNS
//! server answers the filtered lookups, and the QUIC escape hatch is closed so
//! everything falls back to the TCP the proxy can see. This module is the same
//! shape on Linux: a TCP listener (127.0.0.1:3129 by convention) and a UDP DNS
//! listener, fed by `nft` REDIRECT rules or by an explicitly configured proxy.
//!
//! Two entry paths, one data path:
//! * with the redirect rules installed (`tools/adfree-linux.nft`), the
//!   destination is read back with `SO_ORIGINAL_DST` and outbound sockets are
//!   marked (`FWMARK`) so the rules skip the proxy's own traffic — the same
//!   fwmark trick iptables setups use;
//! * without root, the listener works as a plain HTTP proxy: `CONNECT host`
//!   and absolute-form `GET http://host/` requests name the destination, so a
//!   browser pointed at the port gets the identical filtering.
//!
//! What reaches a TLS flow is the very same [`crate::mitm::proxy::ProxySession`]
//! the TUN engine arms, built here with the same recipe as
//! `engine::complete_setup`; the DNS listener shares the filter, the rewrites,
//! the app firewall and the event log.

pub mod dns;
pub mod tcp;

use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Firewall mark on every socket the proxy itself dials out. The redirect
/// rules (`tools/adfree-linux.nft`) skip marked traffic, which is what keeps
/// the proxy from proxying itself.
pub const FWMARK: u32 = 0xad45;

/// Conventional ports; the platform passes them to [`start`].
///
/// The DNS port is deliberately not 5353, which a Windows box has free but a
/// Linux desktop hands to mDNS (avahi, `systemd-resolved`, browsers probing
/// 224.0.0.251): binding it there fails, and forcing it with `SO_REUSEADDR`
/// would quietly steal multicast DNS. 5300 is unclaimed by the usual Linux
/// name services.
pub const DEFAULT_TCP_PORT: u16 = 3129;
pub const DEFAULT_DNS_PORT: u16 = 5300;

/// How long a connection may sit with no traffic before the thread retires it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Dial timeout for the upstream half of a flow.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// One poll slice: the stop flag and the idle timer are noticed this often.
const POLL_SLICE_MS: i32 = 200;
/// Hard cap on live connection threads; a new flow past it is refused.
const MAX_CONNECTIONS: usize = 512;

static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Run {
    stop: Arc<AtomicBool>,
    loops: Vec<std::thread::JoinHandle<()>>,
    running: bool,
}

static RUN: Mutex<Option<Run>> = Mutex::new(None);

/// When the interface list was last read, and what it held.
static OWN: Mutex<Option<(std::time::Instant, Vec<std::net::IpAddr>)>> = Mutex::new(None);

/// Starts both listeners. False when they cannot come up (port in use, proxy
/// already running) — the caller then leaves protection off rather than
/// pretending.
pub fn start(tcp_port: u16, dns_port: u16) -> bool {
    let mut guard = match RUN.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };
    if guard.as_ref().is_some_and(|run| run.running) {
        return false;
    }
    let listener = match tcp::bind_listener(tcp_port) {
        Ok(listener) => listener,
        Err(e) => {
            crate::logbuf::push(&format!("proxy: TCP listener on {tcp_port}: {e}"));
            return false;
        }
    };
    let dns_listeners = match dns::bind_listeners(dns_port) {
        Ok(listeners) => listeners,
        Err(e) => {
            crate::logbuf::push(&format!("proxy: DNS listener on {dns_port}: {e}"));
            return false;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let mut loops = Vec::new();
    let tcp_stop = Arc::clone(&stop);
    match std::thread::Builder::new()
        .name("adfree-proxy-tcp".into())
        // Same stack budget as the tun worker: the TLS termination and the
        // response rewriter run this deep here too.
        .stack_size(1024 * 1024)
        .spawn(move || tcp::accept_loop(listener, tcp_stop))
    {
        Ok(worker) => loops.push(worker),
        Err(e) => crate::logbuf::push(&format!("proxy: TCP accept loop: {e}")),
    }
    let dns_stop = Arc::clone(&stop);
    match std::thread::Builder::new()
        .name("adfree-proxy-dns".into())
        .stack_size(1024 * 1024)
        .spawn(move || dns::serve_loop(dns_listeners, dns_stop))
    {
        Ok(worker) => loops.push(worker),
        Err(e) => crate::logbuf::push(&format!("proxy: DNS loop: {e}")),
    }
    if loops.is_empty() {
        return false;
    }
    crate::logbuf::push(&format!(
        "proxy: listening on 127.0.0.1:{tcp_port} (TCP) and :{dns_port} (DNS)"
    ));
    *guard = Some(Run {
        stop,
        loops,
        running: true,
    });
    true
}

/// Stops both listeners and waits for their threads to return. Live
/// connections notice the flag within one poll slice and retire.
pub fn stop() {
    let taken = RUN.lock().ok().and_then(|mut guard| guard.take());
    let Some(run) = taken else {
        return;
    };
    run.stop.store(true, Ordering::SeqCst);
    for worker in run.loops {
        let _ = worker.join();
    }
    LIVE.store(0, Ordering::Relaxed);
    crate::logbuf::push("proxy: stopped");
}

pub fn is_running() -> bool {
    RUN.lock().map(|run| run.as_ref().is_some_and(|run| run.running)).unwrap_or(false)
}

/// Takes one connection slot for the lifetime of a thread. `Drop` gives it
/// back, so a panic or an early return never leaks capacity.
pub(crate) struct Slot;

impl Slot {
    pub(crate) fn new() -> Option<Slot> {
        let previous = LIVE.fetch_add(1, Ordering::Relaxed);
        if previous >= MAX_CONNECTIONS {
            LIVE.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        Some(Slot)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

// ------------------------------------------------------------- socket tools

/// True when `fd` has data (or an error/EOF pending) within `timeout_ms`.
pub(crate) fn poll_readable(fd: RawFd, timeout_ms: i32) -> bool {
    poll_fd(fd, libc::POLLIN, timeout_ms)
}

pub(crate) fn poll_writable(fd: RawFd, timeout_ms: i32) -> bool {
    poll_fd(fd, libc::POLLOUT, timeout_ms)
}

fn poll_fd(fd: RawFd, events: i16, mut timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc >= 0 {
            return rc > 0;
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return false;
        }
        timeout_ms = 0; // A signal is not permission to wait again for free.
    }
}

/// One wait on both halves of a flow: (client ready, peer ready). A negative
/// or absent peer fd is simply never ready.
pub(crate) fn poll2(client_fd: RawFd, peer_fd: Option<RawFd>, mut timeout_ms: i32) -> (bool, bool) {
    let mut fds = [
        libc::pollfd {
            fd: client_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: peer_fd.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let count = if peer_fd.is_some() { 2 } else { 1 };
    loop {
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), count, timeout_ms) };
        if rc >= 0 {
            return (fds[0].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0,
                    fds[1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return (false, false);
        }
        timeout_ms = 0;
    }
}

/// Writes all of `bytes`, waiting for the socket to drain as needed. Never
/// blocks longer than the poll answer: a stalled peer slows this pump, not the
/// whole proxy.
pub(crate) fn write_all_nb(fd: RawFd, bytes: &[u8], stop: &AtomicBool) -> std::io::Result<()> {
    let mut off = 0usize;
    let started = std::time::Instant::now();
    while off < bytes.len() {
        if stop.load(Ordering::Relaxed) || started.elapsed() > IDLE_TIMEOUT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "proxy: socket stalled",
            ));
        }
        let rc = unsafe {
            libc::write(
                fd,
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if rc > 0 {
            off += rc as usize;
            continue;
        }
        if rc == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "write"));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => {
                if !poll_writable(fd, POLL_SLICE_MS) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "socket not writable",
                    ));
                }
            }
            _ => return Err(err),
        }
    }
    Ok(())
}

/// Requests that a closed socket send RST instead of FIN: a refused proxy
/// connection should look like a refusal, not like a clean close the client
/// may retry forever.
pub(crate) fn reset_on_close(fd: RawFd) {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &linger as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
}

/// Best effort `SO_MARK` (needs `CAP_NET_ADMIN`; without it the redirect
/// layout is not in play either, and nothing is marked out of anything).
pub(crate) fn try_mark(fd: RawFd) {
    let mark = FWMARK;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }
}

/// Dials `addr` with the proxy's own mark applied before the first packet, so
/// the redirect rules skip this connection. Returns a nonblocking stream on
/// success; the fd is closed on any failure.
pub(crate) fn dial_marked(addr: std::net::SocketAddr) -> Option<std::net::TcpStream> {
    let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return None;
    }
    try_mark(fd);
    let (sa, len) = sockaddr_for(addr);
    let rc = unsafe { libc::connect(fd, &sa as *const libc::sockaddr_storage as *const libc::sockaddr, len) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            unsafe { libc::close(fd) };
            return None;
        }
        let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let slice = left.as_millis().min(i32::MAX as u128) as i32;
        if left.is_zero() || !poll_writable(fd, slice) {
            unsafe { libc::close(fd) };
            return None;
        }
        // Writable means the attempt finished; SO_ERROR says whether it landed.
        let mut so_error: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            );
        }
        if so_error != 0 {
            unsafe { libc::close(fd) };
            return None;
        }
    }
    // The fd is verified connected above; std takes ownership from here.
    use std::os::unix::io::FromRawFd;
    Some(unsafe { std::net::TcpStream::from_raw_fd(fd) })
}

/// Sets the socket nonblocking (std's accepted sockets arrive blocking; every
/// pump in this module polls first).
pub(crate) fn set_nonblocking(fd: RawFd) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
}

/// Stops the kernel from holding an abandoned listener port for the next restart.
pub(crate) fn set_reuse(fd: RawFd) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

fn sockaddr_for(addr: std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        std::net::SocketAddr::V4(v4) => {
            let sin = unsafe { &mut *(std::ptr::addr_of_mut!(sa) as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be() as libc::in_port_t;
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        std::net::SocketAddr::V6(v6) => {
            let sin6 = unsafe { &mut *(std::ptr::addr_of_mut!(sa) as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be() as libc::in_port_t;
            sin6.sin6_flowinfo = 0;
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_scope_id = v6.scope_id();
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    (sa, len)
}

/// Parses a `sockaddr_storage` back into an address (the original destination
/// and peer credentials both arrive in this shape).
pub(crate) fn parse_sockaddr(sa: &libc::sockaddr_storage) -> Option<std::net::SocketAddr> {
    match i32::from(sa.ss_family) {
        libc::AF_INET => {
            let sin = unsafe { &*(sa as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_be());
            Some(std::net::SocketAddr::new(ip.into(), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            let sin6 =
                unsafe { &*(sa as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            let v6 = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            // A dual-stack listener sees its v4 clients in this mapped form;
            // flattening it keeps an address comparable with the same host
            // spelled the other way (`127.0.0.1` vs `::ffff:127.0.0.1`).
            let ip: std::net::IpAddr = match v6.to_ipv4_mapped() {
                Some(v4) => v4.into(),
                None => v6.into(),
            };
            Some(std::net::SocketAddr::new(ip, u16::from_be(sin6.sin6_port)))
        }
        _ => None,
    }
}

/// The same host spelled either way: a dual-stack socket hands its v4 peers
/// over as `::ffff:a.b.c.d`, and the interface list spells them as v4.
fn flattened(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.into(),
            None => v6.into(),
        },
        other => other,
    }
}

/// Addresses assigned to this machine's interfaces. Refreshed on a timer
/// rather than per connection: a wireless host changes address when it
/// roams, and a stale list must not outlive a lease.
fn own_addresses() -> Vec<std::net::IpAddr> {
    const TTL: Duration = Duration::from_secs(5);
    let mut cache = match OWN.lock() {
        Ok(cache) => cache,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some((seen, addrs)) = cache.as_ref() {
        if seen.elapsed() < TTL {
            return addrs.clone();
        }
    }
    let mut addrs = Vec::new();
    let mut cursor: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut cursor) } == 0 {
        let mut node = cursor;
        while !node.is_null() {
            let entry = unsafe { &*node };
            let sockaddr = match unsafe { entry.ifa_addr.as_ref() } {
                Some(sa) => sa,
                None => {
                    node = entry.ifa_next;
                    continue;
                }
            };
            let family = i32::from(sockaddr.sa_family);
            if family == libc::AF_INET || family == libc::AF_INET6 {
                let storage = unsafe { &*(sockaddr as *const libc::sockaddr as *const libc::sockaddr_storage) };
                if let Some(addr) = parse_sockaddr(storage) {
                    addrs.push(flattened(addr.ip()));
                }
            }
            node = entry.ifa_next;
        }
        unsafe { libc::freeifaddrs(cursor) };
    }
    *cache = Some((std::time::Instant::now(), addrs.clone()));
    addrs
}

/// Is the other end a socket this machine opened? Both listeners bind a
/// wildcard address because a `redirect` keeps the flow's original
/// destination, so the same socket has to answer on every local address —
/// which also puts them on the LAN interfaces. What keeps the network out is
/// this check on every accepted flow: traffic that started here always
/// carries an address of this machine (loopback above all) as its peer, and
/// traffic from another host never does. Without it AdFree would be an open
/// proxy and an open resolver on the local network.
pub(crate) fn is_local_peer(addr: std::net::SocketAddr) -> bool {
    let peer = flattened(addr.ip());
    let loopback = match peer {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback(),
    };
    loopback || own_addresses().contains(&peer)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};

    // The proxy is process-wide state; keep it away from other thread-spinning
    // tests and from itself.
    static PROXY_LOCK: Mutex<()> = Mutex::new(());

    /// A plain absolute-form request (no redirect rules, no root) reaches the
    /// origin in rewritten form, and the answer travels back. This is the
    /// whole explicit-proxy contract in one assertion pair.
    #[test]
    fn an_explicit_get_is_spliced_to_the_origin() {
        let _guard = PROXY_LOCK.lock().unwrap();
        let origin = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 256];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            // The proxy owes the origin an origin-form request line.
            let text = String::from_utf8_lossy(&request).into_owned();
            assert!(
                text.starts_with("GET /probe HTTP/1.1\r\n"),
                "the origin saw: {text}"
            );
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
        });
        assert!(start(31329, 35353), "listeners must come up on free ports");
        let mut client = TcpStream::connect("127.0.0.1:31329").unwrap();
        client
            .write_all(format!("GET http://127.0.0.1:{origin_port}/probe HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let mut reply = Vec::new();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let _ = client.read_to_end(&mut reply);
        let text = String::from_utf8_lossy(&reply).into_owned();
        if text.is_empty() {
            eprintln!("proxy diagnostics: {:?}", crate::logbuf::take());
        }
        assert!(text.starts_with("HTTP/1.1 200 OK"), "the client saw: {text}");
        stop();
        server.join().unwrap();
    }

    /// A query sent to the DNS listener is answered from the engine's own
    /// tables — here a user rewrite, which proves the listener shares the
    /// resolver state the tun path uses, with no network on either side.
    #[test]
    fn the_dns_listener_answers_from_the_engines_tables() {
        let _guard = PROXY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pinned: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        crate::core().set_dns_rewrites(vec![crate::dnsrewrite::DnsRewriteRule {
            host: "pinned.example.com".into(),
            wildcard: false,
            address: pinned,
        }]);
        assert!(start(31331, 35355), "listeners must come up on free ports");
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .send_to(
                &crate::dns::build_query("pinned.example.com", crate::dns::TYPE_A, 0x1234).unwrap(),
                "127.0.0.1:35355",
            )
            .unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut answer = vec![0u8; 4096];
        let n = socket.recv(&mut answer).unwrap();
        stop();
        crate::core().set_dns_rewrites(Vec::new());
        assert_eq!(&answer[0..2], &0x1234u16.to_be_bytes(), "the client's id is echoed");
        assert_eq!(&answer[2..4], &[0x81, 0x80], "a no-error answer");
        assert_eq!(&answer[6..8], &1u16.to_be_bytes(), "exactly one record");
        assert!(
            answer[..n].windows(4).any(|w| w == [203, 0, 113, 7]),
            "the rewrite must reach the client"
        );
    }

    /// The same request over IPv6: the redirect rules hand `[::1]` to this
    /// listener too, so one dual-stack socket has to serve both families.
    #[test]
    fn an_ipv6_explicit_get_is_spliced_as_well() {
        let _guard = PROXY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let origin = match TcpListener::bind("[::1]:0") {
            Ok(origin) => origin,
            // A host (or container) without loopback v6 has nothing to check.
            Err(_) => return,
        };
        let origin_port = origin.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = origin.accept().unwrap();
            let mut chunk = [0u8; 256];
            let n = stream.read(&mut chunk).unwrap();
            assert!(
                String::from_utf8_lossy(&chunk[..n]).starts_with("GET /v6 HTTP/1.1"),
                "the v6 origin saw: {:?}",
                &chunk[..n]
            );
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        assert!(start(31332, 35356), "listeners must come up on free ports");
        let mut client = TcpStream::connect("[::1]:31332").unwrap();
        client
            .write_all(
                format!("GET http://[::1]:{origin_port}/v6 HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
            )
            .unwrap();
        client.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut reply = Vec::new();
        let _ = client.read_to_end(&mut reply);
        stop();
        assert!(
            String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 204"),
            "the v6 client saw: {reply:?}"
        );
        server.join().unwrap();
    }

    /// A request aimed at the proxy's own port must be refused, not dialled.
    /// `SO_ORIGINAL_DST` answers with the listener's address whenever no
    /// redirect rule touched the connection, and treating that as a real
    /// destination sends every flow back into itself until the slots run out.
    #[test]
    fn the_proxy_refuses_to_proxy_itself() {
        let _guard = PROXY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(start(31330, 35354), "listeners must come up on free ports");
        let mut client = TcpStream::connect("127.0.0.1:31330").unwrap();
        client
            .write_all(b"GET http://127.0.0.1:31330/probe HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reply = Vec::new();
        let _ = client.read_to_end(&mut reply);
        let log = crate::logbuf::take();
        stop();
        assert!(
            log.iter().any(|l| l.contains("the proxy itself")),
            "the self-request must be refused, not dialled; log was {log:?}"
        );
        assert!(reply.is_empty(), "a refusal carries no answer, it just closes");
    }

    /// The listeners answer on every local address, so what keeps the network
    /// out is the peer check on each accepted flow.
    #[test]
    fn only_a_local_peer_is_the_machines_own() {
        let local: SocketAddr = "127.0.0.1:44321".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:44321".parse().unwrap();
        let v6: SocketAddr = "[::1]:44321".parse().unwrap();
        // TEST-NET-1 and documentation space: no host is ever addressed so.
        let away: SocketAddr = "192.0.2.10:44321".parse().unwrap();
        let v6_away: SocketAddr = "[2001:db8::1]:44321".parse().unwrap();
        assert!(is_local_peer(local) && is_local_peer(mapped) && is_local_peer(v6));
        assert!(!is_local_peer(away) && !is_local_peer(v6_away));
        // Whatever this machine itself is addressed as is local — that is the
        // shape a redirected flow can arrive in, and it must never be refused.
        for ip in own_addresses() {
            assert!(is_local_peer(SocketAddr::new(ip, 44321)), "{ip} is this host");
        }
    }
}
