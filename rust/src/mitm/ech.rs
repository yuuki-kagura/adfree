//! ECH state, shared by the DNS half and the TLS half of the engine.
//!
//! ECH exists to keep this proxy out of the connection; the user asked for it
//! to be in. The halves split the problem:
//!
//! * The DNS half rewrites the `ech` SvcParam away (see `dns::strip_ech`), so
//!   no client can wrap a hello in a config the proxy cannot read, and keeps
//!   the raw ECHConfigList for the upstream half. The user can opt out of that
//!   rewrite (`Config::full_ech`): the config then reaches the client, which
//!   may run ECH end to end and hide its inner name — and that host is
//!   spliced, not filtered. Every set below still applies; only the DNS
//!   rewrite is skipped.
//! * The TLS half offers that config itself when it terminates the connection:
//!   with the config the origin published, the origin accepts the handshake
//!   even when it requires ECH, and the plaintext stays filterable. A server
//!   that rejects the offer gets one more try on a plain handshake, and the
//!   host sits ECH out for [`ECH_COOLDOWN_MS`], so a broken config cannot cost
//!   a rejected handshake per connection.
//!
//! What remains is the host that will not work even then — one that answered
//! every plain connection with a bare `502` in older measurements. There the
//! only move left is not to terminate the TLS at all: the client keeps its
//! (cached) ECHConfig, the flow is spliced, and that one host goes unfiltered.
//! The sets here bridge that too:
//!
//! * `advertised` — every host whose ECHConfig the DNS half rewrote away. What
//!   the TLS half may learn a refusal from: a bare `502`/`421` means something
//!   on a host that advertises ECH, and nothing on the rest of the web.
//! * `exempt` — hosts learned to require ECH anyway. The DNS half leaves their
//!   ECHConfig alone from then on, so the browser can actually use ECH.
//! * `public_names` — the names the ECHConfigs expose (`cloudflare-ech.com`),
//!   read out of the HTTPS answers. Browsers attach a GREASE
//!   `encrypted_client_hello` extension to ordinary connections too — Chrome
//!   149 offered one on *every* host measured on 19/10/2026 — so "the hello
//!   offers ECH" cannot be the splice condition by itself. A hello whose SNI
//!   is a public name is only spliced when the user opted into full ECH:
//!   otherwise terminating it makes the browser retry in the clear, which
//!   keeps the page filterable. An exempt host is still spliced without that
//!   switch, because the origin has already refused every plain handshake.
//! * `configs` — the raw ECHConfigList per host, refreshed by every HTTPS
//!   answer. Answers whose parameter was stripped are clamped to
//!   [`ANSWER_TTL_SECS`], so the copy cannot get far out of date.
//! * `rejected` — hosts whose upstream refused the offered config, until when
//!   the cooldown ends.
//!
//! Nothing is persisted: the sets are rebuilt by their own traffic, and a
//! false `exempt` only costs filtering for one host — the side to err on.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

/// How many hosts to remember advertising ECH. A host falls out of the window
/// only long after a browser that asked about it would have asked again.
const ADVERTISED_CAP: usize = 512;

/// How many ECH public names to remember. One per provider in practice.
const PUBLIC_NAME_CAP: usize = 64;

/// How many host configs to keep. One per HTTPS host contacted through the
/// proxy; the eviction scan only runs when the window is full.
const CONFIG_CAP: usize = 256;

/// The largest ECHConfigList to keep. Real ones are tens to hundreds of bytes
/// (`defo.ie` served 194 across three configs); anything far past that is not
/// worth carrying around.
const CONFIG_MAX_BYTES: usize = 2048;

/// How many host cooldowns to keep. Entries expire on their own; the cap only
/// bounds a burst of never-repeating hosts.
const REJECTED_CAP: usize = 256;

/// How long a host sits out upstream ECH after its server rejected the offer.
///
/// The rejection is about this proxy's offer, not about one connection: the
/// config is the origin's own and freshly learned, so retrying immediately
/// would only repeat it. Ten minutes also keeps a host whose ECH support is
/// being deployed or withdrawn from oscillating per connection.
pub const ECH_COOLDOWN_MS: u64 = 10 * 60 * 1000;

/// The TTL an answer is clamped to when the DNS half rewrote its ECHConfig
/// away. The answer is no longer the origin's, so it must not be cached as if
/// it were — and the client only re-reads the record, and can only then pick
/// the ECHConfig back up, when what it holds expires.
pub const ANSWER_TTL_SECS: u32 = 60;

/// One host's ECHConfigList, as last learned from DNS.
struct StoredConfig {
    /// The SvcParam value verbatim: 2-byte length, then the list.
    list: Vec<u8>,
    /// Epoch ms of the answer that taught it, for eviction order.
    seen_ms: u64,
}

/// The ECH knowledge of one running engine.
#[derive(Default)]
pub struct EchHosts {
    advertised: Mutex<VecDeque<String>>,
    exempt: Mutex<HashSet<String>>,
    public_names: Mutex<VecDeque<String>>,
    configs: Mutex<HashMap<String, StoredConfig>>,
    rejected: Mutex<HashMap<String, u64>>,
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
    /// reach this name on the wire.
    ///
    /// Called for every HTTPS answer that carries a readable config, stripped
    /// or not: a client that cached one before the proxy started (or through
    /// another resolver) still opens a real ECH hello, and its outer SNI is
    /// the only name visible on the wire. Those flows must be spliced, not
    /// terminated, or the page fails.
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
    /// An exempt host is always spliced: the origin refused the proxy's own
    /// plaintext handshake, so terminating it would only fail again. A public
    /// name is spliced only when `full_ech` is on. With the switch off, a
    /// browser that cached an ECHConfig elsewhere gets a failed handshake and
    /// retries in the clear; the retry is terminated and filtered. Splicing it
    /// instead would silently drop filtering for a host the lists still name.
    pub fn splices(&self, name: &str, full_ech: bool) -> bool {
        self.exempt(name) || (full_ech && self.public_name(name))
    }

    /// Was `name` read as an ECHConfig public name in an HTTPS answer?
    pub fn public_name(&self, name: &str) -> bool {
        self.public_names.lock().unwrap().iter().any(|n| n == name)
    }

    /// The HTTPS answer for `host` carried this ECHConfigList: remember it for
    /// the proxy's own upstream connection. `list` is the SvcParam value as it
    /// came off the wire (2-byte length included).
    pub fn note_config(&self, host: &str, list: Vec<u8>, now_ms: u64) {
        if list.is_empty() || list.len() > CONFIG_MAX_BYTES {
            return;
        }
        let mut configs = self.configs.lock().unwrap();
        if !configs.contains_key(host) && configs.len() >= CONFIG_CAP {
            // Configs are re-learned from DNS, so the least recently seen host
            // is the cheapest to forget. A missing entry only means the next
            // connection to that host goes out without ECH.
            if let Some(oldest) = configs
                .iter()
                .min_by_key(|(_, config)| config.seen_ms)
                .map(|(host, _)| host.clone())
            {
                configs.remove(&oldest);
            }
        }
        configs.insert(
            host.to_string(),
            StoredConfig {
                list,
                seen_ms: now_ms,
            },
        );
    }

    /// The ECHConfigList to offer upstream for `host`, unless the host has no
    /// known config or is cooling down after a rejection.
    pub fn upstream_ech(&self, host: &str, now_ms: u64) -> Option<Vec<u8>> {
        {
            let mut rejected = self.rejected.lock().unwrap();
            if let Some(until) = rejected.get(host) {
                if *until > now_ms {
                    return None;
                }
                rejected.remove(host);
            }
        }
        self.configs
            .lock()
            .unwrap()
            .get(host)
            .map(|config| config.list.clone())
    }

    /// The upstream server rejected the config offered for `host`: stop
    /// offering one for [`ECH_COOLDOWN_MS`].
    pub fn note_ech_rejected(&self, host: &str, now_ms: u64) {
        let mut rejected = self.rejected.lock().unwrap();
        if rejected.len() >= REJECTED_CAP {
            rejected.retain(|_, until| *until > now_ms);
            if rejected.len() >= REJECTED_CAP {
                rejected.clear();
            }
        }
        rejected.insert(host.to_string(), now_ms.saturating_add(ECH_COOLDOWN_MS));
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
        assert!(
            !ech.splices("shop.test", false),
            "a normal host stays terminated"
        );
        ech.note_public_name("cloudflare-ech.test");
        assert!(
            !ech.splices("cloudflare-ech.test", false),
            "a public name is not spliced with full ECH off"
        );
        assert!(
            ech.splices("cloudflare-ech.test", true),
            "full ECH is the opt-in that splices a public name"
        );
        assert!(!ech.splices("shop.test", true));
        ech.note_refusal("crypto.test");
        assert!(
            ech.splices("crypto.test", false),
            "an exempt host is spliced even without full ECH"
        );
    }

    #[test]
    fn the_public_name_window_stays_bounded() {
        let ech = EchHosts::new();
        for i in 0..(PUBLIC_NAME_CAP + 4) {
            ech.note_public_name(&format!("ech{i}.test"));
        }
        assert!(!ech.splices("ech0.test", true), "the window must slide");
        assert!(ech.splices(&format!("ech{}.test", PUBLIC_NAME_CAP + 3), true));
    }

    #[test]
    fn a_stored_config_is_offered_until_a_refusal_cools_it_down() {
        let ech = EchHosts::new();
        assert_eq!(ech.upstream_ech("shop.test", 1_000), None, "nothing known");
        ech.note_config("shop.test", vec![0x00, 0x05, 0xfe, 0x0d], 1_000);
        assert_eq!(
            ech.upstream_ech("shop.test", 2_000),
            Some(vec![0x00, 0x05, 0xfe, 0x0d])
        );

        ech.note_ech_rejected("shop.test", 5_000);
        assert_eq!(ech.upstream_ech("shop.test", 5_001), None, "cooling down");
        assert_eq!(
            ech.upstream_ech("shop.test", 5_000 + ECH_COOLDOWN_MS - 1),
            None,
            "the whole cooldown must pass"
        );
        assert_eq!(
            ech.upstream_ech("shop.test", 5_000 + ECH_COOLDOWN_MS),
            Some(vec![0x00, 0x05, 0xfe, 0x0d]),
            "the config is still good once the cooldown ends"
        );
    }

    #[test]
    fn a_refusal_without_a_config_still_cools_the_host_down() {
        let ech = EchHosts::new();
        ech.note_ech_rejected("shop.test", 10);
        assert_eq!(ech.upstream_ech("shop.test", 20), None);
        assert_eq!(ech.upstream_ech("other.test", 20), None);
    }

    #[test]
    fn the_newest_config_for_a_host_wins() {
        let ech = EchHosts::new();
        ech.note_config("shop.test", vec![1], 10);
        ech.note_config("shop.test", vec![2], 20);
        assert_eq!(ech.upstream_ech("shop.test", 30), Some(vec![2]));
    }

    #[test]
    fn the_config_window_forgets_the_least_recently_seen_host() {
        let ech = EchHosts::new();
        for i in 0..CONFIG_CAP {
            ech.note_config(&format!("h{i}.test"), vec![i as u8], i as u64);
        }
        ech.note_config("fresh.test", vec![0xff], CONFIG_CAP as u64);
        assert_eq!(
            ech.upstream_ech("h0.test", CONFIG_CAP as u64),
            None,
            "the oldest entry makes room"
        );
        assert_eq!(
            ech.upstream_ech("fresh.test", CONFIG_CAP as u64),
            Some(vec![0xff])
        );
    }

    #[test]
    fn an_unreasonable_config_is_not_kept() {
        let ech = EchHosts::new();
        ech.note_config("empty.test", Vec::new(), 1);
        assert_eq!(ech.upstream_ech("empty.test", 2), None);
        ech.note_config("huge.test", vec![0; CONFIG_MAX_BYTES + 1], 1);
        assert_eq!(ech.upstream_ech("huge.test", 2), None);
    }
}
