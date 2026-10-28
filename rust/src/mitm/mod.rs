//! MITM stage: local CA, per-SNI leaf certs, TLS termination, script injection.
//!
//! The pieces below are deliberately independent and unit-tested in isolation:
//! the CA can mint leaves, the HTTP layer can splice scripts, the TCP layer can
//! translate a handshake, the TLS layer can terminate a real conversation, and
//! the relay decides where each byte of an intercepted connection goes.
//!
//! The remaining step is the packet-engine hook-up, which carries the client's
//! payload across the userspace TCP relay into the splice.

pub mod ca;
pub mod decide;
pub mod doh;
pub mod ech;
pub mod hosts;
pub mod hpke;
pub mod http;
pub mod proxy;
pub mod quic;
pub mod relay;
pub mod script;
pub mod segment;
pub mod stealth;
pub mod tcp;
pub mod tls;

#[cfg(test)]
mod e2e_tests;

#[cfg(test)]
mod proxy_tests;

#[cfg(test)]
mod tls_tests;

/// Where the MITM stage stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Every piece exists and is tested; connections are not terminated yet.
    Armed,
    /// Connections to the MITM port are terminated and spliced.
    Live,
}

pub const CURRENT_STAGE: Stage = Stage::Armed;

impl Stage {
    /// Stable string for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Stage::Armed => "armed",
            Stage::Live => "live",
        }
    }
}
