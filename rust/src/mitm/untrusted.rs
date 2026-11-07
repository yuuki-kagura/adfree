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

/// The `state` row the learned pairs survive a restart in.
const STATE_KEY: &str = "mitm.untrusted_clients";

/// The remembered `(host → client fingerprints)` pairs.
#[derive(Default)]
pub struct UntrustedClients {
    /// One entry per host, holding the fingerprints seen refusing it.
    entries: Mutex<HashMap<String, HashSet<String>>>,
    /// The database the set is written back to, once the platform has handed
    /// the data root down. Without it the set lives as long as the engine,
    /// which is what a platform that never calls `set_store` gets.
    store: Mutex<Option<Arc<crate::store::Store>>>,
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
        let learned = entries
            .entry(host.to_string())
            .or_default()
            .insert(fingerprint.to_string());
        if learned {
            drop(entries);
            self.save();
        }
        learned
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
        self.save();
    }

    /// Points the set at the store: loads what an earlier run learned and
    /// writes every later change back.
    ///
    /// Persisted because the evidence costs one failed handshake per app, and
    /// a restart is not a reason to make the user watch that again. Installing
    /// the system CA clears the set, so a stale verdict cannot outlive the
    /// certificate it was learned against.
    pub fn set_store(&self, store: Arc<crate::store::Store>) {
        // An engine that ran before this was a database row may have left its
        // own file behind; it is not read any more, so it is not left to
        // suggest otherwise.
        std::fs::remove_file(store.root().join("untrusted-clients.json")).ok();
        if let Some(text) = store.state_get(STATE_KEY) {
            match serde_json::from_str::<HashMap<String, HashSet<String>>>(&text) {
                Ok(learned) => {
                    let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
                    for (host, fingerprints) in learned.into_iter().take(MAX_HOSTS) {
                        entries.entry(host).or_default().extend(fingerprints);
                    }
                }
                Err(e) => crate::logbuf::push_error(&format!(
                    "mitm: unreadable certificate-refusal memory: {e}"
                )),
            }
        }
        *self.store.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    /// Writes the current set out, if the platform gave it somewhere to go.
    ///
    /// One row in the same database as everything else the app remembers: the
    /// write is a single upsert into a page already in cache, and the set is
    /// small (one entry per app that refused, not per connection).
    fn save(&self) {
        let store = self.store.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(store) = store else {
            return;
        };
        let snapshot: HashMap<String, HashSet<String>> = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let body = match serde_json::to_string(&snapshot) {
            Ok(body) => body,
            Err(e) => {
                crate::logbuf::push_error(&format!("mitm: cannot encode the refusal memory: {e}"));
                return;
            }
        };
        if let Err(e) = store.state_set(STATE_KEY, &body) {
            crate::logbuf::push_error(&format!("mitm: cannot save the refusal memory: {e}"));
        }
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

    /// A restart must not cost the same app another failed handshake: what was
    /// learned is written to the data root and read back by the next engine.
    #[test]
    fn the_set_survives_a_restart_through_the_store() {
        let root = std::env::temp_dir().join(format!(
            "adfree-untrusted-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = Arc::new(crate::store::Store::open(&root).expect("store"));

        let first = UntrustedClients::new();
        first.set_store(Arc::clone(&store));
        assert!(first.note("api.example.com", "node-fp"));

        // The next engine over the same database finds it already learned.
        let second = UntrustedClients::new();
        second.set_store(Arc::clone(&store));
        assert!(second.refuses("api.example.com", "node-fp"));
        assert!(!second.refuses("api.example.com", "chrome-fp"));

        // Installing the CA clears the memory in the database too.
        second.clear();
        let third = UntrustedClients::new();
        third.set_store(Arc::clone(&store));
        assert!(third.is_empty(), "a cleared set must not come back");
        assert!(!third.refuses("api.example.com", "node-fp"));

        drop(store);
        std::fs::remove_dir_all(&root).ok();
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
