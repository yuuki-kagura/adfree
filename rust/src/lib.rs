//! AdFree native core.
//!
//! Everything the app needs to filter traffic lives here: packet decoding,
//! DNS interception, the `adblock` filter engine (the same code AdGuard and
//! Brave use), upstream forwarding, connection tracking, statistics and the
//! event log that feeds the UI.
//!
//! The Kotlin side reaches the core through [`api`] — a `uniffi` bridge that
//! keeps small, checked types on both ends. Three things the core never does:
//! talk to Android directly, block in a syscall it does not own, or allocate on
//! the packet path.

#![allow(clippy::too_many_arguments)]

// uniffi emits FFI symbols that carry their own namespace; the scaffolding macro
// must live in the crate root for the generated code to find `UniFfiTag`.
uniffi::setup_scaffolding!("adfree");

pub mod sys;
/// The Windows redirector's tables and rewrites. Portable and tested: the
/// packet surgery is the same bytes on either platform, only the driver that
/// delivers them differs.
pub mod winnat;
/// The Windows redirect's lifecycle: start, stop, and the counters the tray
/// shows. A no-op with a sentence elsewhere.
pub mod wredirect;
pub mod api;
/// The browser extension's wire: Chrome's framing, the endpoint, and the
/// callback that answers it.
pub mod assistant;
mod appmask;
pub mod assets;
pub mod conntrack;
pub mod dns;
pub mod dnscache;
pub mod dnsrewrite;
pub mod dnssecure;
pub mod engine;
pub mod events;
pub mod filter;
pub mod fxhash;
pub mod hls;
pub mod htmlfilter;
pub mod jsonprune;
pub mod logbuf;
pub mod packet;
pub mod page_exception;
pub mod pathmask;
pub mod proxy;
pub mod safesearch;
pub mod services;
pub mod shell_trust;
pub mod smart;
pub mod socks5;
pub mod state;
pub mod stats;
pub mod store;
pub mod trust;
pub mod udpnat;
pub mod udpproxy;
pub mod uidmap;
pub mod upstream;
pub mod util;
pub mod waitset;

pub use engine::core;

/// Version of the core, reported by the UI so field reports are traceable.
pub const CORE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " + adblock 0.13.3");

#[cfg(test)]
mod tests {
    #[test]
    fn version_reports_the_adblock_core() {
        assert!(crate::CORE_VERSION.contains("adblock 0.13.3"));
    }

    #[test]
    fn log_buffer_is_wired_up() {
        let _guard = crate::logbuf::lock();
        crate::logbuf::clear();
        crate::logbuf::push("native core online");
        assert_eq!(
            crate::logbuf::take(),
            vec!["native core online".to_string()]
        );
    }
}
pub mod mitm;
