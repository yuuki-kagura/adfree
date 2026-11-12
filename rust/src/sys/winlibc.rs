//! A `libc` the proxy can hold onto on Windows.
//!
//! The forwarding code is written against BSD sockets, because that is what a
//! proxy is: `socket`, `bind`, `accept`, `poll`, `recv`, `send`. Winsock speaks
//! the same vocabulary with three differences that matter and one that looks
//! scarier than it is:
//!
//! * constants differ (`POLLIN` is a bit in a mask on Linux, `POLLRDNORM` is a
//!   different bit on Windows), so this module keeps *libc's* numbering for the
//!   vocabulary the callers use and translates at the two edges: [`poll`] builds
//!   the `WSAPOLLFD` events and folds the results back into `POLLIN`-shaped bits;
//! * errno numbers differ, and `io::Error::raw_os_error` hands back WSA codes,
//!   so the `EAGAIN`-family constants here are the WSA values;
//! * a socket is a `SOCKET` (a pointer-sized handle), not an `int`. It is
//!   exposed as [`RawFd`] = `usize`, which is why every call site that compares a
//!   descriptor against `-1` has to say `sys::fd_invalid()` instead;
//! * there is no `fork`, no `eventfd`, no `epoll`, no `SO_ORIGINAL_DST` and no
//!   firewall mark. Those are not shimmed: the modules that need them are gated
//!   to Unix, or answer differently on Windows (see `sys::windows`).
//!
//! Everything here is a thin wrapper. Nothing is emulated on top of something
//! else, except `poll`, which is a real `WSAPoll`.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::io;

use windows_sys::Win32::Networking::WinSock as ws;

pub type c_int = i32;
pub type c_short = i16;
pub type c_ushort = u16;
pub type c_char = i8;
pub type c_uchar = u8;
pub type c_void = std::ffi::c_void;
pub type c_ulong = u32;
pub type size_t = usize;
pub type ssize_t = isize;
pub type socklen_t = i32;
pub type sa_family_t = u16;
pub type in_port_t = u16;
pub type nfds_t = u32;

/// A socket handle. Winsock's `SOCKET` is a pointer-sized integer whose
/// "invalid" value is `INVALID_SOCKET` (all bits set), not `-1` as an `int`.
pub type RawFd = u64;
/// What `socket()` returning "no socket" looks like here.
pub const INVALID_SOCKET: RawFd = u64::MAX;

pub fn fd_invalid(fd: RawFd) -> bool {
    fd == INVALID_SOCKET
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in_addr {
    pub s_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [c_char; 14],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

/// `SOCKADDR_STORAGE`: 128 bytes, 8-byte aligned, on every Windows target.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_pad: [u8; 126],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct pollfd {
    pub fd: RawFd,
    pub events: c_short,
    pub revents: c_short,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct linger {
    pub l_onoff: c_int,
    pub l_linger: c_int,
}

// Address families, socket types and protocol levels, in Winsock's numbering.
pub const AF_INET: c_int = 2;
pub const AF_INET6: c_int = 23;
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_SEQPACKET: c_int = 5;
pub const AF_UNIX: c_int = 1;
// Not Winsock's flags — Winsock has none — but the two bits the callers OR into
// the type. `socket()` strips them and applies `FIONBIO` for `SOCK_NONBLOCK`;
// `SOCK_CLOEXEC` is what `WSA_FLAG_NO_HANDLE_INHERIT` already gives every
// socket this module makes.
pub const SOCK_NONBLOCK: c_int = 0x2000_0000;
pub const SOCK_CLOEXEC: c_int = 0x4000_0000;
pub const EFD_CLOEXEC: c_int = 0;
pub const EFD_NONBLOCK: c_int = 0;
// The option names the redirect layout uses on Linux. Nothing on Windows
// interprets them: every site that sets one ignores the result, and the
// answers come from the component that redirects instead.
pub const SOL_IP: c_int = 0;
pub const IP_PKTINFO: c_int = 8;
pub const IP_TRANSPARENT: c_int = 19;
pub const IPV6_TRANSPARENT: c_int = 75;
pub const IPV6_RECVPKTINFO: c_int = 49;
pub const IPV6_PKTINFO: c_int = 50;
pub const SO_MARK: c_int = 0;
pub const SO_ORIGINAL_DST: c_int = 80;
pub const IP6T_SO_ORIGINAL_DST: c_int = 80;
pub const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
pub const SOL_SOCKET: c_int = 0xffff;
pub const IPPROTO_TCP: c_int = 6;
pub const IPPROTO_IPV6: c_int = 41;
pub const SO_REUSEADDR: c_int = 0x0004;
pub const SO_ERROR: c_int = 0x1007;
pub const SO_LINGER: c_int = 0x0080;
pub const SO_RCVTIMEO: c_int = 0x1006;
pub const SO_SNDTIMEO: c_int = 0x1005;
pub const TCP_NODELAY: c_int = 0x0001;
pub const IPV6_V6ONLY: c_int = 27;
pub const SHUT_WR: c_int = 1;
pub const SHUT_RDWR: c_int = 2;

// Flag arguments the forwarding code passes. Non-blocking is a socket property
// on Windows (`ioctlsocket`), so `MSG_DONTWAIT` has nothing to do; there are no
// SIGPIPEs to suppress, so `MSG_NOSIGNAL` is zero.
pub const MSG_PEEK: c_int = 0x2;
pub const MSG_DONTWAIT: c_int = 0;
pub const MSG_NOSIGNAL: c_int = 0;

// `poll` vocabulary, kept in libc's numbering and translated in `poll`.
pub const POLLIN: c_short = 0x001;
pub const POLLPRI: c_short = 0x002;
pub const POLLOUT: c_short = 0x004;
pub const POLLERR: c_short = 0x008;
pub const POLLHUP: c_short = 0x010;
pub const POLLNVAL: c_short = 0x020;
pub const POLLRDHUP: c_short = 0x2000;

const POLLRDNORM: c_short = 0x0100;
const POLLWRNORM: c_short = 0x0010;

// The wait-set vocabulary. wepoll uses Linux's own numbering, so these need no
// translation at all — `EPOLLIN` is bit 0 on both, and `poll_revents` in
// `waitset` reads them exactly as it does on Unix.
pub const EPOLLIN: c_int = POLLIN as c_int;
pub const EPOLLPRI: c_int = POLLPRI as c_int;
pub const EPOLLOUT: c_int = POLLOUT as c_int;
pub const EPOLLERR: c_int = POLLERR as c_int;
pub const EPOLLHUP: c_int = POLLHUP as c_int;
pub const EPOLLRDHUP: c_int = POLLRDHUP as c_int;
pub const EPOLL_CTL_ADD: c_int = 1;
pub const EPOLL_CTL_MOD: c_int = 2;
pub const EPOLL_CTL_DEL: c_int = 3;
pub const EPOLL_CLOEXEC: c_int = 0;

/// wepoll's `struct epoll_event`: `uint32_t events` then an 8-byte union, so 16
/// bytes with the padding the C struct has (Linux's is packed into 12).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct epoll_event {
    pub events: u32,
    pub u64: u64,
}

extern "C" {
    fn epoll_create1(flags: c_int) -> *mut c_void;
    fn epoll_ctl(ephnd: *mut c_void, op: c_int, sock: usize, event: *mut epoll_event) -> c_int;
    fn epoll_wait(
        ephnd: *mut c_void,
        events: *mut epoll_event,
        maxevents: c_int,
        timeout: c_int,
    ) -> c_int;
    fn epoll_close(ephnd: *mut c_void) -> c_int;
}

pub unsafe fn wepoll_create1(flags: c_int) -> isize {
    unsafe { epoll_create1(flags) as isize }
}

pub unsafe fn wepoll_ctl(ep: isize, op: c_int, fd: RawFd, ev: &mut epoll_event) -> c_int {
    unsafe { epoll_ctl(ep as *mut c_void, op, fd as usize, ev) }
}

pub unsafe fn wepoll_wait(ep: isize, evs: &mut [epoll_event], timeout: c_int) -> c_int {
    unsafe {
        epoll_wait(
            ep as *mut c_void,
            evs.as_mut_ptr(),
            evs.len() as c_int,
            timeout,
        )
    }
}

pub unsafe fn wepoll_close(ep: isize) {
    unsafe {
        epoll_close(ep as *mut c_void);
    }
}

// `fcntl` stand-ins: only `O_NONBLOCK` exists here, and it is not a flag bit.
pub const F_GETFL: c_int = 0;
pub const F_SETFL: c_int = 1;
pub const O_NONBLOCK: c_int = 0x4000;

// Winsock error numbers, because `raw_os_error()` reports these.
pub const EAGAIN: c_int = 10035;
pub const EWOULDBLOCK: c_int = EAGAIN;
pub const EINPROGRESS: c_int = 10036;
pub const EALREADY: c_int = 10037;
pub const EINTR: c_int = 10004;
pub const ENOBUFS: c_int = 10055;
pub const ECONNRESET: c_int = 10054;
pub const ECONNREFUSED: c_int = 10061;
pub const ETIMEDOUT: c_int = 10060;
pub const EADDRINUSE: c_int = 10048;
pub const EADDRNOTAVAIL: c_int = 10049;
pub const ENETDOWN: c_int = 10050;
pub const ENETUNREACH: c_int = 10051;
pub const EHOSTUNREACH: c_int = 10065;
pub const EAFNOSUPPORT: c_int = 10047;
pub const EPIPE: c_int = 10058;
pub const ENOTCONN: c_int = 10057;
pub const ENOTSOCK: c_int = 10038;
pub const EPERM: c_int = 10013;
pub const EMSGSIZE: c_int = 10040;
pub const ENOSYS: c_int = 10042;

/// Winsock must be initialised once per process before any socket call.
/// `std`'s own socket types do this, but the forwarding code calls raw
/// `socket()` before it ever constructs one, so do it here. Calling
/// `WSAStartup` more than once is harmless (it is reference counted).
fn startup() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let mut data: ws::WSADATA = std::mem::zeroed();
        ws::WSAStartup(0x0202, &mut data);
    });
}

/// The last Winsock error as an `io::Error`, so callers keep using
/// `raw_os_error()` the way they do on Unix.
pub fn last_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() })
}

pub unsafe fn socket(af: c_int, ty: c_int, proto: c_int) -> RawFd {
    startup();
    let nonblock = ty & SOCK_NONBLOCK != 0;
    let ty = ty & !(SOCK_NONBLOCK | SOCK_CLOEXEC);
    let fd = unsafe {
        ws::WSASocketW(
            af,
            ty,
            proto,
            std::ptr::null(),
            0,
            ws::WSA_FLAG_OVERLAPPED | ws::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    let fd = fd as RawFd;
    if !fd_invalid(fd) && nonblock {
        unsafe {
            fcntl(fd, F_SETFL, O_NONBLOCK);
        }
    }
    fd
}

pub unsafe fn bind(fd: RawFd, addr: *const sockaddr, len: socklen_t) -> c_int {
    unsafe { ws::bind(fd as usize, addr as *const ws::SOCKADDR, len) }
}

pub unsafe fn listen(fd: RawFd, backlog: c_int) -> c_int {
    unsafe { ws::listen(fd as usize, backlog) }
}

pub unsafe fn accept(fd: RawFd, addr: *mut sockaddr, len: *mut socklen_t) -> RawFd {
    unsafe { ws::accept(fd as usize, addr as *mut ws::SOCKADDR, len) as RawFd }
}

pub unsafe fn connect(fd: RawFd, addr: *const sockaddr, len: socklen_t) -> c_int {
    unsafe { ws::connect(fd as usize, addr as *const ws::SOCKADDR, len) }
}

/// Closes a socket. Named `close` because that is what the proxy calls: on
/// Windows there is one kind of descriptor here, and it is always a socket.
pub unsafe fn close(fd: RawFd) -> c_int {
    unsafe { ws::closesocket(fd as usize) }
}

pub unsafe fn shutdown(fd: RawFd, how: c_int) -> c_int {
    unsafe { ws::shutdown(fd as usize, how) }
}

pub unsafe fn recv(fd: RawFd, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    unsafe { ws::recv(fd as usize, buf as *mut u8, len as c_int, flags) as ssize_t }
}

pub unsafe fn send(fd: RawFd, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    unsafe { ws::send(fd as usize, buf as *const u8, len as c_int, flags) as ssize_t }
}

pub unsafe fn recvfrom(
    fd: RawFd,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
    addr: *mut sockaddr,
    alen: *mut socklen_t,
) -> ssize_t {
    unsafe {
        ws::recvfrom(fd as usize,
            buf as *mut u8,
            len as c_int,
            flags,
            addr as *mut ws::SOCKADDR,
            alen,
        ) as ssize_t
    }
}

pub unsafe fn sendto(
    fd: RawFd,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    addr: *const sockaddr,
    alen: socklen_t,
) -> ssize_t {
    unsafe {
        ws::sendto(fd as usize,
            buf as *const u8,
            len as c_int,
            flags,
            addr as *const ws::SOCKADDR,
            alen,
        ) as ssize_t
    }
}

pub unsafe fn getsockname(fd: RawFd, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    unsafe { ws::getsockname(fd as usize, addr as *mut ws::SOCKADDR, len) }
}

pub unsafe fn getpeername(fd: RawFd, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    unsafe { ws::getpeername(fd as usize, addr as *mut ws::SOCKADDR, len) }
}

pub unsafe fn setsockopt(
    fd: RawFd,
    level: c_int,
    name: c_int,
    val: *const c_void,
    len: socklen_t,
) -> c_int {
    unsafe { ws::setsockopt(fd as usize, level, name, val as *const u8, len) }
}

pub unsafe fn getsockopt(
    fd: RawFd,
    level: c_int,
    name: c_int,
    val: *mut c_void,
    len: *mut socklen_t,
) -> c_int {
    unsafe { ws::getsockopt(fd as usize, level, name, val as *mut u8, len) }
}

/// `poll(2)` over `WSAPoll`.
///
/// The translation is the whole point of this function: callers pass and read
/// `POLLIN`/`POLLOUT` bits in libc's numbering, while Winsock wants
/// `POLLRDNORM`/`POLLWRNORM` and reports `POLLHUP` only as a closed socket
/// (`POLLNVAL`-ish), so hang-ups are folded out of errors and end-of-stream.
pub unsafe fn poll(fds: *mut pollfd, nfds: nfds_t, timeout_ms: c_int) -> c_int {
    if nfds == 0 {
        std::thread::sleep(std::time::Duration::from_millis(timeout_ms.max(0) as u64));
        return 0;
    }
    let slice = unsafe { std::slice::from_raw_parts_mut(fds, nfds as usize) };
    let mut ask: Vec<ws::WSAPOLLFD> = slice
        .iter()
        .map(|p| {
            let mut events: c_short = 0;
            if p.events & POLLIN != 0 {
                events |= POLLRDNORM;
            }
            if p.events & POLLOUT != 0 {
                events |= POLLWRNORM;
            }
            ws::WSAPOLLFD {
                fd: p.fd as usize,
                events,
                revents: 0,
            }
        })
        .collect();
    let rc = unsafe { ws::WSAPoll(ask.as_mut_ptr(), nfds, timeout_ms) };
    if rc == 0 {
        for p in slice.iter_mut() {
            p.revents = 0;
        }
        return 0;
    }
    if rc < 0 {
        let err = unsafe { ws::WSAGetLastError() };
        if err == EINTR {
            return 0;
        }
        return -1;
    }
    let mut ready = 0;
    for (p, w) in slice.iter_mut().zip(ask.iter()) {
        let mut bits: c_short = 0;
        if w.revents & POLLRDNORM != 0 {
            bits |= POLLIN;
        }
        if w.revents & POLLWRNORM != 0 {
            bits |= POLLOUT;
        }
        if w.revents & POLLERR != 0 {
            bits |= POLLERR;
        }
        if w.revents & POLLHUP != 0 {
            bits |= POLLHUP;
        }
        if w.revents & POLLNVAL != 0 {
            bits |= POLLNVAL;
        }
        if bits != 0 {
            ready += 1;
        }
        p.revents = bits;
    }
    ready
}

/// `ioctl(FIONBIO)`, which is what `O_NONBLOCK` means here.
pub unsafe fn fcntl(fd: RawFd, cmd: c_int, arg: c_int) -> c_int {
    if cmd != F_SETFL {
        return 0;
    }
    let mut mode: u32 = if arg & O_NONBLOCK != 0 { 1 } else { 0 };
    unsafe { ws::ioctlsocket(fd as usize, ws::FIONBIO, &mut mode) }
}

pub unsafe fn read(fd: RawFd, buf: *mut c_void, len: size_t) -> ssize_t {
    recv(fd, buf, len, 0)
}

pub unsafe fn write(fd: RawFd, buf: *const c_void, len: size_t) -> ssize_t {
    send(fd, buf, len, 0)
}

// ---------------------------------------------------------------- message
// `sendmsg`/`recvmsg` carry the Linux packet-info ancillary data. Windows has
// no equivalent and nothing in this crate needs one: the redirect that would
// have supplied it is done by our own component, which names the target
// directly. The types exist so the shared code compiles; the two calls fail,
// and the callers already treat a failed ancillary read as "no destination
// hint" and fall back to the plain `recvfrom` path.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct iovec {
    pub iov_base: *mut c_void,
    pub iov_len: size_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct cmsghdr {
    pub cmsg_len: size_t,
    pub cmsg_level: c_int,
    pub cmsg_type: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: socklen_t,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: size_t,
    pub msg_control: *mut c_void,
    pub msg_controllen: size_t,
    pub msg_flags: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in_pktinfo {
    pub ipi_ifindex: c_int,
    pub ipi_spec_dst: in_addr,
    pub ipi_addr: in_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct in6_pktinfo {
    pub ipi6_addr: in6_addr,
    pub ipi6_ifindex: u32,
}

pub unsafe fn CMSG_FIRSTHDR(mhdr: *const msghdr) -> *mut cmsghdr {
    if (*mhdr).msg_controllen == 0 {
        return std::ptr::null_mut();
    }
    (*mhdr).msg_control as *mut cmsghdr
}

pub unsafe fn CMSG_NXTHDR(_mhdr: *const msghdr, _cmsg: *const cmsghdr) -> *mut cmsghdr {
    std::ptr::null_mut()
}

pub unsafe fn CMSG_DATA(cmsg: *const cmsghdr) -> *mut u8 {
    (cmsg as *mut u8).add(std::mem::size_of::<cmsghdr>())
}

pub unsafe fn CMSG_LEN(len: u32) -> u32 {
    (std::mem::size_of::<cmsghdr>() as u32).wrapping_add(len)
}

pub unsafe fn CMSG_SPACE(len: u32) -> u32 {
    CMSG_LEN(len)
}

pub unsafe fn recvmsg(_fd: RawFd, _msg: *mut msghdr, _flags: c_int) -> ssize_t {
    -1
}

pub unsafe fn sendmsg(_fd: RawFd, _msg: *const msghdr, _flags: c_int) -> ssize_t {
    -1
}

/// Interface enumeration exists to find the TUN device; Windows has no TUN in
/// this design, so there is nothing to enumerate and the callers' "no
/// interfaces" path is the right answer.
#[repr(C)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut c_char,
    pub ifa_flags: u32,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_ifu: *mut sockaddr,
    pub ifa_data: *mut c_void,
}

pub unsafe fn getifaddrs(_out: *mut *mut ifaddrs) -> c_int {
    -1
}

pub unsafe fn freeifaddrs(_list: *mut ifaddrs) {}

/// Who is asking. The proxy uses the answer to decide whether it may set up the
/// redirect layout; on Windows that decision is made by the elevation check, and
/// the core only ever runs with the privileges it needs.
pub fn geteuid() -> u32 {
    0
}

pub unsafe fn clock_gettime(_clock: c_int, _ts: *mut timespec) -> c_int {
    0
}

// -------------------------------------------------------------- wakeups
//
// `eventfd` and `socketpair` are the loop's two wake channels. Windows has
// neither, but it does have a datagram socket that can talk to itself: bound to
// `127.0.0.1`, connected to that same address, a write is immediately a
// readable event on the very handle the loop is polling. `socketpair` makes the
// pair by duplicating that handle, so a write from either end wakes a read on
// the other — which is exactly what the wake channels ask for.

fn loopback_self() -> RawFd {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd_invalid(fd) {
        return fd;
    }
    let mut addr = sockaddr_in {
        sin_family: AF_INET as sa_family_t,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0x0100_007f },
        sin_zero: [0; 8],
    };
    let len = std::mem::size_of::<sockaddr_in>() as socklen_t;
    if unsafe { bind(fd, &addr as *const _ as *const sockaddr, len) } != 0 {
        unsafe {
            close(fd);
        }
        return INVALID_SOCKET;
    }
    let mut got: sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut got_len = std::mem::size_of::<sockaddr_storage>() as socklen_t;
    if unsafe { getsockname(fd, &mut got as *mut _ as *mut sockaddr, &mut got_len) } != 0 {
        unsafe {
            close(fd);
        }
        return INVALID_SOCKET;
    }
    // Loopback plus an ephemeral port, so it can be connected to itself.
    let mut target: sockaddr_in = unsafe { std::mem::zeroed() };
    std::mem::swap(&mut addr, &mut target);
    target.sin_port = unsafe {
        let mut sin: sockaddr_in = std::mem::zeroed();
        std::ptr::copy_nonoverlapping(
            &got as *const _ as *const u8,
            &mut sin as *mut _ as *mut u8,
            std::mem::size_of::<sockaddr_in>(),
        );
        sin.sin_port
    };
    target.sin_family = AF_INET as sa_family_t;
    target.sin_addr = in_addr { s_addr: 0x0100_007f };
    if unsafe { connect(fd, &target as *const _ as *const sockaddr, len) } != 0 {
        unsafe {
            close(fd);
        }
        return INVALID_SOCKET;
    }
    unsafe {
        fcntl(fd, F_SETFL, O_NONBLOCK);
    }
    fd
}

/// `WSADuplicateSocket` on this process: another handle to the same socket, so
/// both ends of a "pipe" read the same stream.
fn duplicate(fd: RawFd) -> RawFd {
    use windows_sys::Win32::System::Threading::GetCurrentProcessId;
    let mut info: ws::WSAPROTOCOL_INFOW = unsafe { std::mem::zeroed() };
    let pid = unsafe { GetCurrentProcessId() };
    if unsafe { ws::WSADuplicateSocketW(fd as usize, pid, &mut info) } != 0 {
        return INVALID_SOCKET;
    }
    let dup = unsafe {
        ws::WSASocketW(
            info.iAddressFamily,
            info.iSocketType,
            info.iProtocol,
            &info,
            0,
            ws::WSA_FLAG_OVERLAPPED | ws::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    dup as RawFd
}

pub unsafe fn eventfd(initval: u32, _flags: c_int) -> RawFd {
    let fd = loopback_self();
    if !fd_invalid(fd) && initval != 0 {
        let bytes = initval.to_ne_bytes();
        unsafe {
            send(fd, bytes.as_ptr() as *const c_void, 8, 0);
        }
    }
    fd
}

pub unsafe fn socketpair(
    _domain: c_int,
    _ty: c_int,
    _proto: c_int,
    out: *mut RawFd,
) -> c_int {
    let a = loopback_self();
    if fd_invalid(a) {
        return -1;
    }
    let b = duplicate(a);
    if fd_invalid(b) {
        unsafe {
            close(a);
        }
        return -1;
    }
    unsafe {
        *out = a;
        *out.add(1) = b;
    }
    0
}

pub unsafe fn pipe(out: *mut RawFd) -> c_int {
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, out)
}
