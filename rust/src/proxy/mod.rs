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
pub mod egress;
pub mod peer;
pub mod tcp;

use crate::sys::fd::RawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use crate::sys::libc;

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

/// Lowest port a listener may be moved to. Below it a bind needs root, and a
/// desktop app that asks for the port and then quietly fails to bind it is
/// worse than one that says the number is not its to take.
pub const MIN_LISTENER_PORT: u16 = 1024;

/// How long a connection may sit with no traffic before the thread retires it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
/// Dial timeout for the upstream half of a flow.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// One poll slice: the stop flag and the idle timer are noticed this often.
const POLL_SLICE_MS: i32 = 200;
/// Hard cap on live connection threads; a new flow past it is refused.
const MAX_CONNECTIONS: usize = 512;

static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Said once per start, when the slot table is full: a refusal is silent on the
/// wire, and silence is what made a wrapped counter look like a broken network.
static CAP_ANNOUNCED: AtomicBool = AtomicBool::new(false);

/// AdGuard for Windows' "Filter localhost", read per flow: with it off a
/// conversation this machine is having with itself is relayed untouched —
/// never intercepted, never judged by the lists. Written by [start], which
/// the settings screen restarts through when the switch moves, so the value
/// in play is always the one the rules were installed for.
static FILTER_LOCALHOST: AtomicBool = AtomicBool::new(true);

struct Run {
    stop: Arc<AtomicBool>,
    loops: Vec<std::thread::JoinHandle<()>>,
    running: bool,
    /// The ports these listeners were bound on, so a caller can tell whether
    /// what is up matches what the settings now ask for.
    tcp_port: u16,
    dns_port: u16,
}

static RUN: Mutex<Option<Run>> = Mutex::new(None);

/// What the listeners are doing, and what refused them when they were last
/// asked to come up.
///
/// The two error strings are the reason this is a record and not a bool: a
/// switch that reads "off" tells the user nothing about the service already
/// holding port 3129, and they cannot move the listener without knowing it.
#[derive(uniffi::Record, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProxyStatus {
    pub running: bool,
    pub tcp_port: u16,
    pub dns_port: u16,
    pub tcp_error: String,
    pub dns_error: String,
}

/// The last start attempt that did not come up. Cleared by a successful start
/// and by a stop, so a deliberate shutdown never reads as a refusal.
static FAILED: Mutex<Option<ProxyStatus>> = Mutex::new(None);

/// When the interface list was last read, and what it held.
static OWN: Mutex<Option<(std::time::Instant, Vec<std::net::IpAddr>)>> = Mutex::new(None);

/// Starts both listeners and says what came of it.
///
/// Both or neither: a stack that sees TCP but answers no lookup is a filter
/// that quietly does nothing, and the redirect rules would send the machine's
/// DNS to a port nobody listens on. `filter_localhost` is the loopback switch
/// the settings screen edits: it decides whether a flow to this machine's own
/// addresses is filtered or merely carried.
pub fn start(tcp_port: u16, dns_port: u16, filter_localhost: bool) -> ProxyStatus {
    FILTER_LOCALHOST.store(filter_localhost, Ordering::Relaxed);
    CAP_ANNOUNCED.store(false, Ordering::Relaxed);
    let mut guard = match RUN.lock() {
        Ok(guard) => guard,
        // The record of which listener is live is exactly what could not be
        // read, so nothing can be said about the ports from here.
        Err(_) => {
            return remember(ProxyStatus {
                running: false,
                tcp_port,
                dns_port,
                tcp_error: "the proxy state lock was poisoned".to_string(),
                dns_error: String::new(),
            });
        }
    };
    if let Some(run) = guard.as_ref().filter(|run| run.running) {
        // Already up, which is not a failure — but the ports it asked for are
        // not necessarily the ports it got, and that difference is the whole
        // reason a caller has to rebind.
        return ProxyStatus {
            running: true,
            tcp_port: run.tcp_port,
            dns_port: run.dns_port,
            tcp_error: String::new(),
            dns_error: String::new(),
        };
    }
    let (listener, tcp_bind) = match tcp::bind_listener(tcp_port) {
        Ok(listener) => (Some(listener), String::new()),
        Err(e) => {
            crate::logbuf::push(&format!("proxy: TCP listener on {tcp_port}: {e}"));
            (None, e.to_string())
        }
    };
    let (dns_listeners, dns_bind) = match dns::bind_listeners(dns_port) {
        Ok(listeners) => (Some(listeners), String::new()),
        Err(e) => {
            crate::logbuf::push(&format!("proxy: DNS listener on {dns_port}: {e}"));
            (None, e.to_string())
        }
    };
    let (Some(listener), Some(dns_listeners)) = (listener, dns_listeners) else {
        return remember(ProxyStatus {
            running: false,
            tcp_port,
            dns_port,
            tcp_error: tcp_bind,
            dns_error: dns_bind,
        });
    };
    let stop = Arc::new(AtomicBool::new(false));
    let mut loops = Vec::new();
    let tcp_stop = Arc::clone(&stop);
    let tcp_spawn = match std::thread::Builder::new()
        .name("adfree-proxy-tcp".into())
        // Same stack budget as the tun worker: the TLS termination and the
        // response rewriter run this deep here too.
        .stack_size(1024 * 1024)
        .spawn(move || tcp::accept_loop(listener, tcp_stop))
    {
        Ok(worker) => {
            loops.push(worker);
            String::new()
        }
        Err(e) => {
            crate::logbuf::push(&format!("proxy: TCP accept loop: {e}"));
            e.to_string()
        }
    };
    let dns_stop = Arc::clone(&stop);
    let dns_spawn = match std::thread::Builder::new()
        .name("adfree-proxy-dns".into())
        .stack_size(1024 * 1024)
        .spawn(move || dns::serve_loop(dns_listeners, dns_stop))
    {
        Ok(worker) => {
            loops.push(worker);
            String::new()
        }
        Err(e) => {
            crate::logbuf::push(&format!("proxy: DNS loop: {e}"));
            e.to_string()
        }
    };
    if loops.is_empty() {
        return remember(ProxyStatus {
            running: false,
            tcp_port,
            dns_port,
            tcp_error: refused(&tcp_bind, &tcp_spawn),
            dns_error: refused(&dns_bind, &dns_spawn),
        });
    }
    crate::logbuf::push(&format!(
        "proxy: listening on 127.0.0.1:{tcp_port} (TCP) and :{dns_port} (DNS)"
    ));
    *guard = Some(Run {
        stop,
        loops,
        running: true,
        tcp_port,
        dns_port,
    });
    forget_failure();
    ProxyStatus {
        running: true,
        tcp_port,
        dns_port,
        tcp_error: String::new(),
        dns_error: String::new(),
    }
}

/// Stops both listeners and waits for their threads to return. Live
/// connections notice the flag within one poll slice and retire.
pub fn stop() {
    // A shutdown the user asked for is not a refusal — and that holds whether
    // or not a stack was up: the reason an earlier attempt was refused belongs
    // to that attempt, and must not keep explaining a stop that was deliberate.
    forget_failure();
    let taken = RUN.lock().ok().and_then(|mut guard| guard.take());
    let Some(run) = taken else {
        return;
    };
    run.stop.store(true, Ordering::SeqCst);
    for worker in run.loops {
        let _ = worker.join();
    }
    // `LIVE` is the number of slots threads are *holding*, and a stop does not
    // take them back: a flow that is finishing what it was sending keeps its
    // slot until its thread ends (see `tcp::DRAIN`). Zeroing it here made every
    // one of those threads subtract from zero on its way out, and an unsigned
    // count that goes below zero reads as nearly the cap — so the next
    // connection was refused instantly, silently, and every connection after it
    // until the process restarted. Turning protection off and on again was
    // enough to do it.
    crate::logbuf::push("proxy: stopped");
}

pub fn is_running() -> bool {
    RUN.lock().map(|run| run.as_ref().is_some_and(|run| run.running)).unwrap_or(false)
}

/// Whether a flow to this machine's own addresses is filtered or carried.
/// The answer is the settings screen's switch, taken at the last start.
pub fn filters_loopback() -> bool {
    FILTER_LOCALHOST.load(Ordering::Relaxed)
}

/// What the listeners are doing now: the ports they hold, or the reason the
/// last attempt to raise them was refused. A stack that never ran answers with
/// nothing at all rather than a stale complaint.
pub fn status() -> ProxyStatus {
    if let Ok(guard) = RUN.lock() {
        if let Some(run) = guard.as_ref().filter(|run| run.running) {
            return ProxyStatus {
                running: true,
                tcp_port: run.tcp_port,
                dns_port: run.dns_port,
                ..Default::default()
            };
        }
    }
    FAILED.lock().ok().and_then(|failed| failed.clone()).unwrap_or_default()
}

/// Keeps a failed attempt so the screen can still explain it after the call
/// that produced it has returned, and hands the same record back to that call.
fn remember(status: ProxyStatus) -> ProxyStatus {
    if let Ok(mut failed) = FAILED.lock() {
        *failed = Some(status.clone());
    }
    status
}

fn forget_failure() {
    if let Ok(mut failed) = FAILED.lock() {
        *failed = None;
    }
}

/// One listener can be refused twice: by `bind`, and by the thread that would
/// have served it. Both are the reason it is not listening, so neither is
/// dropped to make the message shorter.
fn refused(bind: &str, spawn: &str) -> String {
    match (bind.is_empty(), spawn.is_empty()) {
        (true, _) => spawn.to_string(),
        (_, true) => bind.to_string(),
        _ if bind == spawn => bind.to_string(),
        _ => format!("{bind}; {spawn}"),
    }
}

/// Takes one connection slot for the lifetime of a thread. `Drop` gives it
/// back, so a panic or an early return never leaks capacity.
pub(crate) struct Slot;

impl Slot {
    pub(crate) fn new() -> Option<Slot> {
        let previous = LIVE.fetch_add(1, Ordering::Relaxed);
        if previous >= MAX_CONNECTIONS {
            LIVE.fetch_sub(1, Ordering::Relaxed);
            // Refusing here is a bare reset on the wire, so it has to say so
            // once per start: this is what "protection is on and everything
            // resets" looked like, with nothing in the log to explain it.
            if !CAP_ANNOUNCED.swap(true, Ordering::Relaxed) {
                crate::logbuf::push(&format!(
                    "proxy: {} connections are open; refusing new ones",
                    MAX_CONNECTIONS
                ));
            }
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
            fd: peer_fd.unwrap_or(crate::sys::fd::NO_FD),
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
                // One poll slice passing without writability is not a failure:
                // a peer that stops reading for a moment is normal — a slow
                // uplink draining a 100 KB request body, a server busy with
                // another response. Treating a single 200 ms slice as fatal
                // tore down exactly those flows, which is why a large request
                // died in half a second while small ones went through. The
                // deadline at the top of the loop bounds the write instead.
                // (`EWOULDBLOCK` is the same value on Linux.)
                poll_writable(fd, POLL_SLICE_MS);
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
///
/// The call itself lives in `sys`: it is one of the two things the proxy asks of
/// the kernel that Windows does not have.
pub(crate) fn try_mark(fd: RawFd) {
    crate::sys::mark_own_traffic(fd, FWMARK);
}

/// Dials `addr` with the proxy's own mark applied before the first packet, so
/// the redirect rules skip this connection. Returns a nonblocking stream on
/// success; the fd is closed on any failure.
///
/// Every attempt is reported to [`egress`], which is the only thing that lets
/// the DNS half know whether this machine can carry the family it is about to
/// hand out records for.
pub(crate) fn dial_marked(addr: std::net::SocketAddr) -> Option<std::net::TcpStream> {
    if addr.is_ipv6() && !egress::dial_worth_making() {
        // The verdict knows how this ends and the client should not have been
        // given the address in the first place: what is left is a record it
        // cached earlier, or one it was told by a config. Refusing is faster
        // for it than proving the verdict right, once per flow, in the dark.
        return None;
    }
    match dial_fd(addr) {
        Ok(fd) => {
            egress::note_dial(addr, None);
            use crate::sys::fd::FromRawFd;
            // The fd is verified connected by `dial_fd`; std takes ownership
            // from here.
            Some(unsafe { std::net::TcpStream::from_raw_fd(fd) })
        }
        Err(kind) => {
            egress::note_dial(addr, Some(kind));
            None
        }
    }
}

/// The attempt itself: the connected fd, or why it failed in the terms the
/// IPv6 verdict understands. The fd is closed here on every failure.
fn dial_fd(addr: std::net::SocketAddr) -> Result<RawFd, egress::Failure> {
    let domain = if addr.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 };
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        // No such family on this machine at all.
        return Err(egress::Failure::from_errno(last_errno()));
    }
    try_mark(fd);
    let (sa, len) = sockaddr_for(addr);
    let rc = unsafe { libc::connect(fd, &sa as *const libc::sockaddr_storage as *const libc::sockaddr, len) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            unsafe { libc::close(fd) };
            return Err(egress::Failure::from_errno(err.raw_os_error().unwrap_or(0)));
        }
        let deadline = std::time::Instant::now() + CONNECT_TIMEOUT;
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let slice = left.as_millis().min(i32::MAX as u128) as i32;
        if left.is_zero() || !poll_writable(fd, slice) {
            unsafe { libc::close(fd) };
            // Nothing said either way inside the budget: the SYN went out and
            // no answer came back, which is the shape of a black-holed route.
            return Err(egress::Failure::Timeout);
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
            return Err(egress::Failure::from_errno(so_error));
        }
    }
    Ok(fd)
}

/// `errno` as a number, for the failures that arrive without an `io::Error`.
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Sets the socket nonblocking (std's accepted sockets arrive blocking; every
/// pump in this module polls first).
pub(crate) fn set_nonblocking(fd: RawFd) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
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
        assert!(start(31329, 35353, true).running, "listeners must come up on free ports");
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
        assert!(start(31331, 35355, true).running, "listeners must come up on free ports");
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
        assert!(start(31332, 35356, true).running, "listeners must come up on free ports");
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
        assert!(start(31330, 35354, true).running, "listeners must come up on free ports");
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

    /// A port somebody else already listens on is refused, and the refusal
    /// keeps its reason: `start` says it, `status` still says it afterwards,
    /// and only a clean start or a stop puts the explanation away.
    #[test]
    fn a_taken_port_is_refused_and_says_why() {
        let _guard = PROXY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let squatter = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = squatter.local_addr().unwrap().port();
        // A DNS port this test just released, so the one number is not a
        // guess about what else the machine has open.
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dns_port = probe.local_addr().unwrap().port();
        drop(probe);

        let attempt = start(tcp_port, dns_port, true);
        assert!(!attempt.running, "a listener on a taken port must not claim to run");
        assert!(!attempt.tcp_error.is_empty(), "the TCP refusal owes a reason");
        assert!(attempt.dns_error.is_empty(), "the DNS port was free: {}", attempt.dns_error);
        assert!(!is_running(), "a half-bound stack is not a running proxy");

        let seen = status();
        assert!(!seen.running);
        assert_eq!(seen.tcp_port, tcp_port, "the screen must name the port it tried");
        assert!(!seen.tcp_error.is_empty(), "status() must still explain the refusal");
        assert!(
            std::net::UdpSocket::bind(("127.0.0.1", dns_port)).is_ok(),
            "the half that did bind must not stay held behind a failed start"
        );

        // A stop the user asked for puts the explanation away even when there
        // was nothing running to stop: "refused because the port was taken"
        // would otherwise keep describing a shutdown that was deliberate.
        stop();
        let after_stop = status();
        assert!(!after_stop.running);
        assert!(
            after_stop.tcp_error.is_empty() && after_stop.dns_error.is_empty(),
            "a stop ends the complaint: {after_stop:?}"
        );

        // A later success both answers and wipes the stale complaint.
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let free_tcp = other.local_addr().unwrap().port();
        drop(other);
        assert!(start(free_tcp, dns_port, true).running, "free ports must come up");
        let live = status();
        assert!(live.running && live.tcp_port == free_tcp && live.dns_port == dns_port);
        assert!(live.tcp_error.is_empty() && live.dns_error.is_empty(), "{live:?}");
        stop();
        let after = status();
        assert!(!after.running);
        assert!(
            after.tcp_error.is_empty() && after.dns_error.is_empty(),
            "a stop the user asked for is not a refusal: {after:?}"
        );
        drop(squatter);
    }

    /// The loopback switch belongs to the stack being raised: what the start
    /// was asked for is what flows are judged by, and the next start with the
    /// opposite choice takes over — the settings screen restarts through the
    /// listeners and the redirect rules together when the switch moves.
    #[test]
    fn the_loopback_switch_is_the_one_the_start_was_asked_for() {
        let _guard = PROXY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = other.local_addr().unwrap().port();
        drop(other);
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dns_port = probe.local_addr().unwrap().port();
        drop(probe);

        assert!(start(tcp_port, dns_port, false).running, "listeners must come up on free ports");
        assert!(!filters_loopback(), "a start told to leave loopback alone must leave it alone");
        stop();

        assert!(start(tcp_port, dns_port, true).running, "the same free ports must come back");
        assert!(filters_loopback(), "the next start takes the choice it was given");
        stop();
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
