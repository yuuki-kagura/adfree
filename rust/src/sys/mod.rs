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

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;
