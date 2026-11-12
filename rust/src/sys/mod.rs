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
