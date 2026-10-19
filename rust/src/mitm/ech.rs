//! ECH state, shared by the DNS half and the TLS half of the engine.
//!
//! `dns::strip_ech` keeps clients from ever attempting ECH: with no ECHConfig
//! in the HTTPS record, a browser cannot hide the name the proxy needs, and
//! that is what makes HTTPS filtering work at all. The hosts that *require*
//! ECH are the exception — `crypto.cloudflare.com` answers every plain
//! connection with a bare `502`, so the page cannot load through a terminator
//! no matter what it does. There the only correct move left is not to
//! terminate the TLS: the client keeps ECH, the site works, and that one host
//! goes unfiltered.
//!
//! The three sets here bridge the halves:
//!
//! * `advertised` — every host whose ECHConfig the DNS half rewrote away. What
//!   the TLS half may learn a refusal from: a bare `502`/`421` means something
//!   on a host that advertises ECH, and nothing on the rest of the web.
//! * `exempt` — hosts learned to require ECH. The DNS half leaves their
//!   ECHConfig alone from then on, so the browser can actually use ECH.
//! * `public_names` — the names the ECHConfigs expose (`cloudflare-ech.com`),
//!   read out of the answers whose config was left in place. Browsers attach
//!   a GREASE `encrypted_client_hello` extension to ordinary connections too —
//!   Chrome 149 offered one on *every* host measured on 19/10/2026 — so "the
//!   hello offers ECH" cannot be the splice condition by itself: only a hello
//!   whose SNI is a public name, or whose host is exempt, is one that cannot be
//!   terminated at all.
//!
//! Nothing is persisted: the sets are rebuilt by their own traffic, and a
//! false `exempt` only costs filtering for one host — the side to err on.

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

/// How many hosts to remember advertising ECH. A host falls out of the window
/// only long after a browser that asked about it would have asked again.
const ADVERTISED_CAP: usize = 512;

/// How many ECH public names to remember. One per provider in practice.
const PUBLIC_NAME_CAP: usize = 64;

/// The TTL an answer is clamped to when the DNS half rewrote its ECHConfig
/// away. The answer is no longer the origin's, so it must not be cached as if
/// it were — and the client only re-reads the record, and can only then pick
/// the ECHConfig back up, when what it holds expires.
pub const ANSWER_TTL_SECS: u32 = 60;

/// The ECH knowledge of one running engine.
#[derive(Default)]
pub struct EchHosts {
    advertised: Mutex<VecDeque<String>>,
    exempt: Mutex<HashSet<String>>,
    public_names: Mutex<VecDeque<String>>,
}

impl EchHosts {
    pub fn new() -> EchHosts {
        EchHosts::default()
    }

    /// The DNS half rewrote this host's ECHConfig away; a browser asking about
    /// it learned nothing about ECH.
    pub fn note_advertised(&self, host: &str) {
        let mut advertised = self.advertised.lock().unwrap();
        if advertised.iter().any(|h| h == host) {
            return;
        }
        if advertised.len() >= ADVERTISED_CAP {
            advertised.pop_front();
        }
        advertised.push_back(host.to_string());
    }

    /// Did the DNS half rewrite this host's ECHConfig away?
    pub fn advertised(&self, host: &str) -> bool {
        self.advertised.lock().unwrap().iter().any(|h| h == host)
    }

    /// Is this host known to refuse connections that do not use ECH?
    pub fn exempt(&self, host: &str) -> bool {
        self.exempt.lock().unwrap().contains(host)
    }

    /// A host that advertises ECH refused a plain connection: from now on it
    /// is left its ECHConfig and its TLS is not terminated. Returns whether
    /// this is news.
    pub fn note_refusal(&self, host: &str) -> bool {
        self.exempt.lock().unwrap().insert(host.to_string())
    }

    /// The DNS half handed this ECHConfig out, so a hello wrapped with it can
    /// reach this name on the wire. Only ever called for the answers the client
    /// actually sees — the ones whose config was *not* stripped — because those
    /// are the only flows that can be real ECH and that the proxy therefore
    /// must not terminate.
    pub fn note_public_name(&self, name: &str) {
        let mut names = self.public_names.lock().unwrap();
        if names.iter().any(|n| n == name) {
            return;
        }
        if names.len() >= PUBLIC_NAME_CAP {
            names.pop_front();
        }
        names.push_back(name.to_string());
    }

    /// Should a first flight whose SNI is `name` be spliced?
    ///
    /// True for an ECH public name — a real ECH hello exposes one, and its
    /// inner host cannot be recovered — and for an exempt host, whose flow the
    /// proxy is past filtering anyway. A GREASE hello keeps the real host as
    /// its SNI and is terminated as usual.
    pub fn splices(&self, name: &str) -> bool {
        self.exempt.lock().unwrap().contains(name)
            || self.public_names.lock().unwrap().iter().any(|n| n == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_is_advertised_only_once() {
        let ech = EchHosts::new();
        assert!(!ech.advertised("shop.test"));
        ech.note_advertised("shop.test");
        ech.note_advertised("shop.test");
        assert!(ech.advertised("shop.test"));
        assert!(!ech.advertised("other.test"));
    }

    #[test]
    fn the_advertised_window_forgets_the_oldest_hosts() {
        let ech = EchHosts::new();
        for i in 0..(ADVERTISED_CAP + 8) {
            ech.note_advertised(&format!("host{i}.test"));
        }
        assert!(!ech.advertised("host0.test"), "the window must slide");
        assert!(ech.advertised(&format!("host{}.test", ADVERTISED_CAP + 7)));
    }

    #[test]
    fn a_refusal_exempts_a_host_once() {
        let ech = EchHosts::new();
        assert!(ech.note_refusal("crypto.test"));
        assert!(!ech.note_refusal("crypto.test"), "the second time is not news");
        assert!(ech.exempt("crypto.test"));
        assert!(!ech.exempt("other.test"));
    }

    #[test]
    fn a_grease_hello_is_terminated_but_a_public_name_is_not() {
        let ech = EchHosts::new();
        assert!(!ech.splices("shop.test"), "a normal host stays terminated");
        ech.note_public_name("cloudflare-ech.test");
        assert!(ech.splices("cloudflare-ech.test"));
        assert!(!ech.splices("shop.test"));
        ech.note_refusal("crypto.test");
        assert!(ech.splices("crypto.test"));
    }

    #[test]
    fn the_public_name_window_stays_bounded() {
        let ech = EchHosts::new();
        for i in 0..(PUBLIC_NAME_CAP + 4) {
            ech.note_public_name(&format!("ech{i}.test"));
        }
        assert!(!ech.splices("ech0.test"), "the window must slide");
        assert!(ech.splices(&format!("ech{}.test", PUBLIC_NAME_CAP + 3)));
    }
}
