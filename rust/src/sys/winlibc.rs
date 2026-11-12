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

#![allow(non_camel_case_types, dead_code)]

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
pub type RawFd = usize;
/// What `socket()` returning "no socket" looks like here.
pub const INVALID_SOCKET: RawFd = usize::MAX;

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

pub fn socket(af: c_int, ty: c_int, proto: c_int) -> RawFd {
    startup();
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
    fd as usize
}

pub fn bind(fd: RawFd, addr: *const sockaddr, len: socklen_t) -> c_int {
    unsafe { ws::bind(fd, addr as *const ws::SOCKADDR, len) }
}

pub fn listen(fd: RawFd, backlog: c_int) -> c_int {
    unsafe { ws::listen(fd, backlog) }
}

pub fn accept(fd: RawFd, addr: *mut sockaddr, len: *mut socklen_t) -> RawFd {
    unsafe { ws::accept(fd, addr as *mut ws::SOCKADDR, len) as usize }
}

pub fn connect(fd: RawFd, addr: *const sockaddr, len: socklen_t) -> c_int {
    unsafe { ws::connect(fd, addr as *const ws::SOCKADDR, len) }
}

/// Closes a socket. Named `close` because that is what the proxy calls: on
/// Windows there is one kind of descriptor here, and it is always a socket.
pub fn close(fd: RawFd) -> c_int {
    unsafe { ws::closesocket(fd) }
}

pub fn shutdown(fd: RawFd, how: c_int) -> c_int {
    unsafe { ws::shutdown(fd, how) }
}

pub fn recv(fd: RawFd, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    unsafe { ws::recv(fd, buf as *mut u8, len as c_int, flags) as ssize_t }
}

pub fn send(fd: RawFd, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    unsafe { ws::send(fd, buf as *const u8, len as c_int, flags) as ssize_t }
}

pub fn recvfrom(
    fd: RawFd,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
    addr: *mut sockaddr,
    alen: *mut socklen_t,
) -> ssize_t {
    unsafe {
        ws::recvfrom(
            fd,
            buf as *mut u8,
            len as c_int,
            flags,
            addr as *mut ws::SOCKADDR,
            alen,
        ) as ssize_t
    }
}

pub fn sendto(
    fd: RawFd,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    addr: *const sockaddr,
    alen: socklen_t,
) -> ssize_t {
    unsafe {
        ws::sendto(
            fd,
            buf as *const u8,
            len as c_int,
            flags,
            addr as *const ws::SOCKADDR,
            alen,
        ) as ssize_t
    }
}

pub fn getsockname(fd: RawFd, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    unsafe { ws::getsockname(fd, addr as *mut ws::SOCKADDR, len) }
}

pub fn getpeername(fd: RawFd, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    unsafe { ws::getpeername(fd, addr as *mut ws::SOCKADDR, len) }
}

pub fn setsockopt(
    fd: RawFd,
    level: c_int,
    name: c_int,
    val: *const c_void,
    len: socklen_t,
) -> c_int {
    unsafe { ws::setsockopt(fd, level, name, val as *const u8, len) }
}

pub fn getsockopt(
    fd: RawFd,
    level: c_int,
    name: c_int,
    val: *mut c_void,
    len: *mut socklen_t,
) -> c_int {
    unsafe { ws::getsockopt(fd, level, name, val as *mut u8, len) }
}

/// `poll(2)` over `WSAPoll`.
///
/// The translation is the whole point of this function: callers pass and read
/// `POLLIN`/`POLLOUT` bits in libc's numbering, while Winsock wants
/// `POLLRDNORM`/`POLLWRNORM` and reports `POLLHUP` only as a closed socket
/// (`POLLNVAL`-ish), so hang-ups are folded out of errors and end-of-stream.
pub fn poll(fds: *mut pollfd, nfds: nfds_t, timeout_ms: c_int) -> c_int {
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
                fd: p.fd,
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
pub fn fcntl(fd: RawFd, cmd: c_int, arg: c_int) -> c_int {
    if cmd != F_SETFL {
        return 0;
    }
    let mut mode: u32 = if arg & O_NONBLOCK != 0 { 1 } else { 0 };
    unsafe { ws::ioctlsocket(fd, ws::FIONBIO, &mut mode) }
}

pub fn read(fd: RawFd, buf: *mut c_void, len: size_t) -> ssize_t {
    recv(fd, buf, len, 0)
}

pub fn write(fd: RawFd, buf: *const c_void, len: size_t) -> ssize_t {
    send(fd, buf, len, 0)
}
