//! Hosts whose client refused this proxy's certificate.
//!
//! Filtering assumes the client trusts the CA the engine holds. Some do not and
//! never will: a Node binary carries its own root set inside itself, a Rust
//! program can link `webpki-roots`, a game client can pin a certificate. No
//! store this install can write reaches any of them — `/etc/ssl/certs`, the NSS
//! databases and every JDK keystore are all consulted only by libraries that
//! were built to consult them.
//!
//! For those clients the only way to stay usable is not to terminate the TLS at
//! all: the flow is spliced verbatim, the app keeps working, and DNS filtering
//! still applies to it. What makes that automatic is the evidence a client
//! leaves when it refuses — a TLS alert naming a certificate problem. The proxy
//! sees it at the handshake, remembers the pair, and splices that host for that
//! client from then on.
//!
//! The pair is `(host, client fingerprint)` rather than the host alone, because
//! the same host is usually reached by a browser too: learning `api.example`
//! from a Node script must not cost Chrome its filtering on that host. The
//! fingerprint is the shape of the ClientHello (cipher suites and extension
//! types), which every distinct TLS stack gets wrong in its own way
//! (`tls::client_hello_fingerprint`) — a browser and a `fetch()` call do not
//! look alike.
//!
//! The set is bounded and deliberately not persisted: it is rebuilt by one
//! failed handshake per app per engine life, and a persisted copy would outlive
//! the reason it was learned (the user installing the CA into that app's store,
//! or the app being replaced by one that trusts it).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// How many hosts the set may hold. A client that refuses one host refuses the
/// handful it talks to; the cap only exists so a hostile or broken client
/// cannot grow the map without end.
const MAX_HOSTS: usize = 256;

/// The remembered `(host → client fingerprints)` pairs.
#[derive(Default)]
pub struct UntrustedClients {
    /// One entry per host, holding the fingerprints seen refusing it.
    entries: Mutex<HashMap<String, HashSet<String>>>,
}

impl UntrustedClients {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records that the client behind `fingerprint` rejected the certificate
    /// for `host`. Returns true when this is news, so the caller logs once
    /// rather than on every retry.
    pub(crate) fn note(&self, host: &str, fingerprint: &str) -> bool {
        if host.is_empty() || host == "?" || fingerprint.is_empty() {
            return false;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if !entries.contains_key(host) && entries.len() >= MAX_HOSTS {
            // Too many to remember: filtering everywhere is the safer default
            // for the hosts that no longer fit.
            return false;
        }
        entries
            .entry(host.to_string())
            .or_default()
            .insert(fingerprint.to_string())
    }

    /// Whether this client has already refused the certificate for `host`.
    ///
    /// An unknown fingerprint never matches: the pair is the whole evidence,
    /// and splicing a host for a client that never complained would give its
    /// traffic away unfiltered on the strength of somebody else's failure.
    pub(crate) fn refuses(&self, host: &str, fingerprint: &str) -> bool {
        if fingerprint.is_empty() {
            return false;
        }
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(host)
            .is_some_and(|fingerprints| fingerprints.contains(fingerprint))
    }

    /// Every host learned so far, with the number of clients that refused it.
    /// The log writes these out; nothing decides on them.
    pub(crate) fn snapshot(&self) -> Vec<(String, usize)> {
        let mut hosts: Vec<(String, usize)> = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(host, fingerprints)| (host.clone(), fingerprints.len()))
            .collect();
        hosts.sort();
        hosts
    }

    /// Whether anything was learned at all: the caller keeps the log quiet
    /// unless it was.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// Forgets every pair. The tests use it; so would a "start over" button.
    pub(crate) fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_remembered_per_host_and_client() {
        let set = UntrustedClients::new();
        assert!(set.note("api.example", "node-fp"));
        assert!(set.refuses("api.example", "node-fp"));
        // The same host from another TLS stack is somebody else's trust store.
        assert!(!set.refuses("api.example", "chrome-fp"));
        // And the same client on another host was never refused.
        assert!(!set.refuses("other.example", "node-fp"));
    }

    #[test]
    fn learning_the_same_pair_twice_is_not_news() {
        let set = UntrustedClients::new();
        assert!(set.note("api.example", "node-fp"));
        assert!(!set.note("api.example", "node-fp"));
        assert_eq!(vec![("api.example".to_string(), 1)], set.snapshot());
    }

    #[test]
    fn an_unknown_fingerprint_never_matches() {
        let set = UntrustedClients::new();
        set.note("api.example", "node-fp");
        assert!(!set.refuses("api.example", ""));
    }

    #[test]
    fn a_host_without_a_name_is_never_remembered() {
        let set = UntrustedClients::new();
        assert!(!set.note("", "node-fp"));
        assert!(!set.note("?", "node-fp"));
        assert!(set.is_empty());
    }

    #[test]
    fn the_set_stops_growing_at_the_cap() {
        let set = UntrustedClients::new();
        for i in 0..MAX_HOSTS {
            assert!(set.note(&format!("h{i}.example"), "node-fp"));
        }
        assert!(!set.note("one-too-many.example", "node-fp"));
        // A host already present keeps learning new clients.
        assert!(set.note("h0.example", "other-fp"));
        assert_eq!(MAX_HOSTS, set.snapshot().len());
    }

    #[test]
    fn clearing_forgets_everything() {
        let set = UntrustedClients::new();
        set.note("api.example", "node-fp");
        set.clear();
        assert!(set.is_empty());
        assert!(!set.refuses("api.example", "node-fp"));
    }
}
