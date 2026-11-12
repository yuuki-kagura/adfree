//! The Windows half of the seam.
//!
//! Both of these exist on Unix because the kernel moves traffic without asking
//! the application. Windows interception is the opposite arrangement: the
//! component that redirects a connection is our own, so it already knows where
//! the connection was going and there is no kernel mark to keep the proxy's own
//! traffic out of anything.
//!
//! Until the socket layer is ported (`docs/plans/windows-support.md`), the
//! functions below are the whole of what the proxy asks of the operating
//! system. They are honest no-ops, not placeholders that pretend to work: a
//! caller that gets `None` here falls back to reading the destination from the
//! request head, which is exactly what an explicit proxy is supposed to do.

use std::net::SocketAddr;

pub use std::os::windows::raw::SOCKET as RawSock;

/// No redirect rules, no conntrack entry: the target is named by the request.
pub fn original_destination(_socket: RawSock) -> Option<SocketAddr> {
    None
}

/// Nothing to mark, because nothing is being redirected. The driver the
/// Windows build will use filters on its own rule set, which excludes the
/// proxy's own traffic by pid and port rather than by firewall mark.
pub fn mark_own_traffic(_socket: RawSock, _mark: u32) {}
