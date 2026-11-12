//! The Unix half of the seam: `SO_ORIGINAL_DST` and the redirect mark.

use std::net::SocketAddr;

pub use std::os::unix::io::RawFd as RawSock;

/// The original destination `nft` recorded when it redirected this connection.
///
/// `None` means "the kernel never redirected this socket" — an explicit proxy
/// request, whose target arrives in the request head instead. Getting that
/// distinction wrong sends every explicit request back into the listener, so
/// the caller compares the answer against the socket's own address (see
/// `proxy::tcp::resolve_target`).
pub fn original_destination(fd: RawSock) -> Option<SocketAddr> {
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut sa as *mut libc::sockaddr_storage as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        return crate::proxy::parse_sockaddr(&sa);
    }
    // v6 redirect: the same option under SOL_IPV6.
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            libc::IP6T_SO_ORIGINAL_DST,
            &mut sa as *mut libc::sockaddr_storage as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        crate::proxy::parse_sockaddr(&sa)
    } else {
        None
    }
}

/// Stamps the proxy's own outbound sockets so the redirect rules skip them.
///
/// Best effort: without `CAP_NET_ADMIN` the rules are not in play either, and
/// nothing is being marked out of anything.
pub fn mark_own_traffic(fd: RawSock, mark: u32) {
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
