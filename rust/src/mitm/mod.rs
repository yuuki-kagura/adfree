//! MITM stage: local CA, per-SNI leaf certs, TLS termination, script injection.
//!
//! The pieces below are deliberately independent and unit-tested in isolation:
//! the CA can mint leaves, the HTTP layer can splice scripts, the TCP layer can
//! translate a handshake, and the TLS layer can terminate a real conversation.
//! Wiring them into the packet engine is the next step; the seams exist so it
//! can be done incrementally.

pub mod ca;
pub mod http;
pub mod script;
pub mod tcp;
pub mod tls;

/// Where the MITM stage stands: everything is ready except the packet-engine
/// hook-up, which needs the userspace TCP relay to carry the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Packets are inspected and dropped/reset, nothing is terminated.
    ObserveOnly,
    /// The CA and scripts exist; connections are still not terminated.
    Armed,
}

pub const CURRENT_STAGE: Stage = Stage::Armed;

impl Stage {
    /// Stable string for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Stage::ObserveOnly => "observe",
            Stage::Armed => "armed",
        }
    }
}
