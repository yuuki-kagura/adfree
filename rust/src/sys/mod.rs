//! What the proxy needs from the operating system, in one place.
//!
//! Two things differ between Linux and Windows and change nothing above them:
//!
//! * where a redirected connection was headed **before** the rules moved it —
//!   Linux answers that with `SO_ORIGINAL_DST` from conntrack, Windows has no
//!   such question because its interception names the target itself;
//! * how a socket the proxy dials out is kept out of the redirect rules —
//!   Linux uses a firewall mark, Windows needs nothing.
//!
//! Everything else the core does (rule matching, cosmetic injection, TLS
//! rewriting, the log store) is already portable, so this module is the seam
//! where a second platform starts rather than a port of its own.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// The Windows redirect: WinDivert loaded at run time, driven by `winnat`.
#[cfg(windows)]
pub mod windivert;

/// The `libc` the proxy sees: the real one on Unix, and a Winsock-backed
/// namesake on Windows (`sys::winlibc`). Modules say `use crate::sys::libc;`
/// once instead of `extern crate libc`, so both platforms compile the same
/// forwarding code.
#[cfg(unix)]
pub use ::libc as libc;
#[cfg(windows)]
#[doc(hidden)]
pub mod winlibc;
#[cfg(windows)]
pub use winlibc as libc;

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

/// Descriptor vocabulary: file descriptors on Unix, socket handles on Windows.
///
/// The proxy's own code says `RawFd` and `as_raw_fd()` everywhere; on Windows
/// those names are backed by the socket-oriented traits, which have the same
/// shape under different names.
#[cfg(unix)]
pub mod fd {
    pub use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

    /// "No descriptor": the sentinel the proxy stores where Unix would say `-1`.
    pub const NO_FD: RawFd = -1;
    /// Whether a stored descriptor names a live socket.
    pub fn fd_ok(fd: RawFd) -> bool {
        fd >= 0
    }
    /// A descriptor in an atomic cell (the engine's TUN handle).
    pub type AtomicFd = std::sync::atomic::AtomicI32;

    /// The wait set's kernel handle: here, an `epoll` descriptor.
    pub type Epoll = RawFd;
    pub const NO_EPOLL: Epoll = -1;
    pub fn epoll_ok(ep: Epoll) -> bool {
        ep >= 0
    }
    pub fn epoll_create1(flags: i32) -> Epoll {
        unsafe { ::libc::epoll_create1(flags) }
    }
    pub fn epoll_ctl(ep: Epoll, op: i32, fd: RawFd, ev: &mut ::libc::epoll_event) -> i32 {
        unsafe { ::libc::epoll_ctl(ep, op, fd, ev) }
    }
    pub fn epoll_wait(ep: Epoll, evs: &mut [::libc::epoll_event], timeout: i32) -> i32 {
        unsafe {
            ::libc::epoll_wait(ep, evs.as_mut_ptr(), evs.len() as i32, timeout)
        }
    }
    pub fn epoll_close(ep: Epoll) {
        unsafe {
            ::libc::close(ep);
        }
    }
}

#[cfg(windows)]
pub mod fd {
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::os::windows::io::{
        AsRawSocket, FromRawSocket, IntoRawSocket, RawSocket,
    };

    /// Winsock's `SOCKET`: pointer-sized, and `INVALID_SOCKET` is all bits set.
    pub type RawFd = RawSocket;

    /// "No descriptor": `INVALID_SOCKET`, which is *not* `-1` on Windows.
    pub const NO_FD: RawFd = RawFd::MAX;
    /// Whether a stored descriptor names a live socket.
    pub fn fd_ok(fd: RawFd) -> bool {
        fd != NO_FD
    }
    /// A descriptor in an atomic cell (the engine's TUN handle).
    pub type AtomicFd = std::sync::atomic::AtomicU64;

    /// The wait set's kernel handle. Windows has no `epoll`, so this is a wepoll
    /// instance — an IOCP port dressed in epoll's clothes — and the four calls
    /// below are the same four the Unix branch makes. One wait set, one set of
    /// semantics, no second implementation to keep in step.
    pub type Epoll = isize;
    pub const NO_EPOLL: Epoll = 0;
    pub fn epoll_ok(ep: Epoll) -> bool {
        ep != NO_EPOLL
    }
    pub fn epoll_create1(flags: i32) -> Epoll {
        unsafe { crate::sys::winlibc::wepoll_create1(flags) }
    }
    pub fn epoll_ctl(ep: Epoll, op: i32, fd: RawFd, ev: &mut crate::sys::winlibc::epoll_event) -> i32 {
        unsafe { crate::sys::winlibc::wepoll_ctl(ep, op, fd, ev) }
    }
    pub fn epoll_wait(ep: Epoll, evs: &mut [crate::sys::winlibc::epoll_event], timeout: i32) -> i32 {
        unsafe { crate::sys::winlibc::wepoll_wait(ep, evs, timeout) }
    }
    pub fn epoll_close(ep: Epoll) {
        unsafe {
            crate::sys::winlibc::wepoll_close(ep);
        }
    }

    pub trait AsRawFd {
        fn as_raw_fd(&self) -> RawFd;
    }

    pub trait IntoRawFd {
        fn into_raw_fd(self) -> RawFd;
    }

    pub trait FromRawFd {
        /// # Safety
        /// The handle must be a live socket nobody else closes.
        unsafe fn from_raw_fd(fd: RawFd) -> Self;
    }

    macro_rules! impl_traits {
        ($($t:ty),*) => {$(
            impl AsRawFd for $t {
                fn as_raw_fd(&self) -> RawFd {
                    self.as_raw_socket()
                }
            }
            impl IntoRawFd for $t {
                fn into_raw_fd(self) -> RawFd {
                    self.into_raw_socket()
                }
            }
            impl FromRawFd for $t {
                unsafe fn from_raw_fd(fd: RawFd) -> Self {
                    unsafe { <$t>::from_raw_socket(fd) }
                }
            }
        )*};
    }

    impl_traits!(TcpStream, TcpListener, UdpSocket);
}

/// Positional file reads: `FileExt::read_at` on Unix, `seek_read` on Windows.
pub fn read_at(file: &std::fs::File, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt as _;
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt as _;
        file.seek_read(buf, offset)
    }
}
