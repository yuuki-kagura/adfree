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
//! * `exempt` — hosts learned to require ECH, **with an expiry**. The DNS half
//!   leaves their ECHConfig alone until then, so the browser can actually use
//!   ECH, and hellos carrying it are spliced by public name. The window has to
//!   end because the evidence can be wrong: a transient bare `502` from a
//!   healthy host must not cost filtering for the rest of the engine's life.
//! * `evidence` / `confirmed` — how a host earns that exemption. `421` is
//!   definitive and exempts at once; a bare `502` needs two within
//!   [`REFUSAL_WINDOW_MS`], because a single one can be any edge failure. A
//!   host confirmed once needs only one more refusal to re-earn the exemption
//!   after it lapses.
//! * `host_public` — the public name each host's ECHConfig exposes
//!   (`cloudflare-ech.com`), read out of the HTTPS answers. This mapping is
//!   what makes an exemption actionable: a real ECH hello names the *public
//!   name*, never the host inside, so `exempt(host)` alone can never match the
//!   SNI on the wire. Browsers also attach a GREASE
//!   `encrypted_client_hello` extension to ordinary connections — Chrome 149
//!   offered one on *every* host measured on 19/10/2026 — so "the hello
//!   offers ECH" cannot be the splice condition by itself. A hello whose SNI
//!   is a public name is spliced only when the user opted into full ECH or the
//!   name belongs to a host currently exempt; otherwise terminating it makes
//!   the browser retry in the clear, which keeps the page filterable.
//!   Exempting a host does **not** splice plain hellos that name it: those are
//!   still terminated, and the upstream half's own ECH offer keeps them
//!   filterable.
//! * `configs` — the raw ECHConfigList per host, refreshed by every HTTPS
//!   answer. Answers whose parameter was stripped, and answers kept for an
//!   exempt host, are clamped to [`ANSWER_TTL_SECS`], so the copy cannot get
//!   far out of date and a lapsed exemption takes effect within a minute.
//! * `rejected` — hosts whose upstream refused the offered config, until when
//!   the cooldown ends.
//!
//! Nothing is persisted: the sets are rebuilt by their own traffic, and a
//! false `exempt` only costs filtering for the hosts behind that public name,
//! for the exemption's window — the side to err on.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

/// How many hosts to remember advertising ECH. A host falls out of the window
/// only long after a browser that asked about it would have asked again.
const ADVERTISED_CAP: usize = 512;

/// How many host → public-name pairs to keep. One per HTTPS host contacted
/// through the proxy.
const HOST_PUBLIC_CAP: usize = 512;

/// How many host configs to keep. One per HTTPS host contacted through the
/// proxy; the eviction scan only runs when the window is full.
const CONFIG_CAP: usize = 256;

/// The largest ECHConfigList to keep. Real ones are tens to hundreds of bytes
/// (`defo.ie` served 194 across three configs); anything far past that is not
/// worth carrying around.
const CONFIG_MAX_BYTES: usize = 2048;

/// How many exemptions to keep. Entries expire on their own; the cap only
/// bounds a burst of never-repeating hosts.
const EXEMPT_CAP: usize = 256;

/// How many hosts to remember as ever confirmed ECH-required.
const CONFIRMED_CAP: usize = 256;

/// How many pending single refusals to keep. The cap only bounds a burst of
/// hosts that each sent one bare `502`.
const EVIDENCE_CAP: usize = 256;

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

/// How long an ECH-required exemption lasts before the host must earn it
/// again.
///
/// The evidence behind an exemption is a refusal on a plain connection, and a
/// bare `502` can come from an ordinary edge failure. Without an expiry such a
/// false positive would turn filtering off for that host's public name for the
/// rest of the engine's life. Six hours keeps a genuinely required host usable
/// (one refusal re-earns the window) while a mistaken one heals the same day.
pub const EXEMPT_TTL_MS: u64 = 6 * 60 * 60 * 1000;

/// The window in which two bare `502`s count as one confirmation. Separate
/// refusals further apart than this say nothing about the host as it is now.
pub const REFUSAL_WINDOW_MS: u64 = 10 * 60 * 1000;

/// How many bare `502`s within [`REFUSAL_WINDOW_MS`] confirm an ECH-required
/// host. `421` confirms at once; `502` is also what a downed edge sends.
const EXEMPT_CONFIRMATIONS: u32 = 2;

/// The TTL an answer is clamped to when the DNS half rewrote its ECHConfig
/// away, or kept it for an exempt host. Such an answer is not what the origin
/// would have sent — the client only re-reads the record, and can only then
/// pick a change back up, when what it holds expires.
pub const ANSWER_TTL_SECS: u32 = 60;

/// What a bare `502` did to a host's exemption state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareRefusal {
    /// The host is already exempt; the window was extended quietly.
    Known,
    /// One refusal seen. Another within [`REFUSAL_WINDOW_MS`] confirms it.
    Suspected,
    /// This refusal confirmed the host (or re-confirmed it after a lapse).
    Confirmed,
}

/// One host's ECHConfigList, as last learned from DNS.
struct StoredConfig {
    /// The SvcParam value verbatim: 2-byte length, then the list.
    list: Vec<u8>,
    /// Epoch ms of the answer that taught it, for eviction order.
    seen_ms: u64,
}

/// One host's unconfirmed bare refusals.
struct Evidence {
    count: u32,
    first_ms: u64,
}

/// The ECH knowledge of one running engine.
#[derive(Default)]
pub struct EchHosts {
    advertised: Mutex<VecDeque<String>>,
    exempt: Mutex<HashMap<String, u64>>,
    confirmed: Mutex<HashSet<String>>,
    evidence: Mutex<HashMap<String, Evidence>>,
    host_public: Mutex<VecDeque<(String, String)>>,
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

    /// Is this host currently exempt from termination?
    pub fn exempt(&self, host: &str, now_ms: u64) -> bool {
        self.exempt
            .lock()
            .unwrap()
            .get(host)
            .is_some_and(|until| *until > now_ms)
    }

    /// Drop an expired exemption and report it, so the caller can log the
    /// return to filtering once.
    pub fn lapsed(&self, host: &str, now_ms: u64) -> bool {
        let mut exempt = self.exempt.lock().unwrap();
        match exempt.get(host) {
            Some(until) if *until <= now_ms => {
                exempt.remove(host);
                true
            }
            _ => false,
        }
    }

    /// A host that advertises ECH refused a plain connection in a way only an
    /// ECH-required origin sends (`421`): exempt it from termination for
    /// [`EXEMPT_TTL_MS`], and remember it as confirmed so a later refusal
    /// after the window lapses needs no second proof. Returns whether this is
    /// news.
    pub fn note_refusal(&self, host: &str, now_ms: u64) -> bool {
        let news = !self.exempt(host, now_ms);
        {
            let mut exempt = self.exempt.lock().unwrap();
            if exempt.len() >= EXEMPT_CAP && !exempt.contains_key(host) {
                exempt.retain(|_, until| *until > now_ms);
                if exempt.len() >= EXEMPT_CAP {
                    exempt.clear();
                }
            }
            exempt.insert(host.to_string(), now_ms.saturating_add(EXEMPT_TTL_MS));
        }
        self.evidence.lock().unwrap().remove(host);
        let mut confirmed = self.confirmed.lock().unwrap();
        if confirmed.len() >= CONFIRMED_CAP && !confirmed.contains(host) {
            confirmed.clear();
        }
        confirmed.insert(host.to_string());
        news
    }

    /// A host that advertises ECH answered a plain connection with a bare
    /// `502` (no `Server` header). That is weaker evidence than `421`, so the
    /// first one only counts and the second within [`REFUSAL_WINDOW_MS`]
    /// confirms. A host confirmed before re-earns its exemption on one hit.
    pub fn note_bare_refusal(&self, host: &str, now_ms: u64) -> BareRefusal {
        if self.exempt(host, now_ms) {
            self.note_refusal(host, now_ms);
            return BareRefusal::Known;
        }
        if self.confirmed.lock().unwrap().contains(host) {
            self.note_refusal(host, now_ms);
            return BareRefusal::Confirmed;
        }
        let confirmed = {
            let mut evidence = self.evidence.lock().unwrap();
            if evidence.len() >= EVIDENCE_CAP && !evidence.contains_key(host) {
                evidence.retain(|_, seen| {
                    now_ms.saturating_sub(seen.first_ms) <= REFUSAL_WINDOW_MS
                });
                if evidence.len() >= EVIDENCE_CAP {
                    evidence.clear();
                }
            }
            let seen = evidence.entry(host.to_string()).or_insert(Evidence {
                count: 0,
                first_ms: now_ms,
            });
            if now_ms.saturating_sub(seen.first_ms) > REFUSAL_WINDOW_MS {
                seen.count = 1;
                seen.first_ms = now_ms;
            } else {
                seen.count += 1;
            }
            seen.count >= EXEMPT_CONFIRMATIONS
        };
        if confirmed {
            self.note_refusal(host, now_ms);
            BareRefusal::Confirmed
        } else {
            BareRefusal::Suspected
        }
    }

    /// An HTTPS answer for `host` carried this public name in its ECHConfig:
    /// remember which host a hello naming it may belong to.
    pub fn note_public_name(&self, host: &str, name: &str) {
        let mut pairs = self.host_public.lock().unwrap();
        if let Some(pair) = pairs.iter_mut().find(|(known, _)| known == host) {
            pair.1 = name.to_string();
            return;
        }
        if pairs.len() >= HOST_PUBLIC_CAP {
            pairs.pop_front();
        }
        pairs.push_back((host.to_string(), name.to_string()));
    }

    /// Is `name` a public name read out of any HTTPS answer?
    pub fn public_name(&self, name: &str) -> bool {
        self.host_public
            .lock()
            .unwrap()
            .iter()
            .any(|(_, public)| public == name)
    }

    /// The public name last read out of `host`'s HTTPS answer.
    pub fn public_name_for(&self, host: &str) -> Option<String> {
        self.host_public
            .lock()
            .unwrap()
            .iter()
            .find(|(known, _)| known == host)
            .map(|(_, name)| name.clone())
    }

    /// Why should a hello whose SNI is `name` be spliced?
    ///
    /// A real ECH hello exposes only its config's public name, so this is the
    /// name that can be matched: an active exemption for a host behind it, or
    /// the user's full-ECH opt-in for any public name. Plain hellos that name
    /// an exempt host are deliberately not matched — they are terminated, and
    /// the upstream half's own ECH offer keeps them filterable.
    pub fn splice_reason(&self, name: &str, full_ech: bool, now_ms: u64) -> Option<&'static str> {
        if self.exempt_public(name, now_ms) {
            Some("its origin requires ECH")
        } else if full_ech && self.public_name(name) {
            Some("full ECH is on")
        } else {
            None
        }
    }

    /// Should a first flight whose SNI is `name` be spliced?
    pub fn splices(&self, name: &str, full_ech: bool, now_ms: u64) -> bool {
        self.splice_reason(name, full_ech, now_ms).is_some()
    }

    /// Does any currently exempt host publish `name` as its ECH public name?
    fn exempt_public(&self, name: &str, now_ms: u64) -> bool {
        let pairs = self.host_public.lock().unwrap();
        if pairs.is_empty() {
            return false;
        }
        let exempt = self.exempt.lock().unwrap();
        if exempt.is_empty() {
            return false;
        }
        pairs.iter().any(|(host, public)| {
            public == name && exempt.get(host).is_some_and(|until| *until > now_ms)
        })
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
    fn an_exemption_lapses_and_is_reported_once() {
        let ech = EchHosts::new();
        assert!(ech.note_refusal("crypto.test", 1_000));
        assert!(
            !ech.note_refusal("crypto.test", 2_000),
            "the second time is not news"
        );
        assert!(ech.exempt("crypto.test", 2_000));
        assert!(ech.exempt("crypto.test", 2_000 + EXEMPT_TTL_MS - 1));
        assert!(
            !ech.exempt("crypto.test", 2_000 + EXEMPT_TTL_MS),
            "the window must end"
        );
        assert!(
            ech.lapsed("crypto.test", 2_000 + EXEMPT_TTL_MS),
            "the lapse is reported"
        );
        assert!(
            !ech.lapsed("crypto.test", 2_000 + EXEMPT_TTL_MS),
            "and only once"
        );
        assert!(!ech.exempt("crypto.test", 2_000 + EXEMPT_TTL_MS));
        assert!(!ech.exempt("other.test", 2_000));
    }

    #[test]
    fn a_single_bare_refusal_does_not_exempt() {
        let ech = EchHosts::new();
        assert_eq!(
            ech.note_bare_refusal("crypto.test", 1_000),
            BareRefusal::Suspected
        );
        assert!(!ech.exempt("crypto.test", 1_000));
        assert_eq!(
            ech.note_bare_refusal("crypto.test", 2_000),
            BareRefusal::Confirmed
        );
        assert!(ech.exempt("crypto.test", 2_000));
        assert_eq!(
            ech.note_bare_refusal("crypto.test", 3_000),
            BareRefusal::Known,
            "a refusal while exempt only extends the window"
        );
        assert!(ech.exempt("crypto.test", 3_000 + EXEMPT_TTL_MS - 1));
    }

    #[test]
    fn bare_refusals_further_apart_than_the_window_do_not_confirm() {
        let ech = EchHosts::new();
        assert_eq!(
            ech.note_bare_refusal("crypto.test", 1_000),
            BareRefusal::Suspected
        );
        let late = 1_000 + REFUSAL_WINDOW_MS + 1;
        assert_eq!(
            ech.note_bare_refusal("crypto.test", late),
            BareRefusal::Suspected,
            "the old refusal is stale evidence"
        );
        assert!(!ech.exempt("crypto.test", late));
    }

    #[test]
    fn a_confirmed_host_re_earns_the_exemption_on_one_refusal() {
        let ech = EchHosts::new();
        assert_eq!(
            ech.note_bare_refusal("crypto.test", 0),
            BareRefusal::Suspected
        );
        assert_eq!(
            ech.note_bare_refusal("crypto.test", 1),
            BareRefusal::Confirmed
        );
        let after = 1 + EXEMPT_TTL_MS;
        assert!(!ech.exempt("crypto.test", after), "the window has ended");
        assert_eq!(
            ech.note_bare_refusal("crypto.test", after),
            BareRefusal::Confirmed,
            "a host already confirmed needs no second proof"
        );
        assert!(ech.exempt("crypto.test", after));
    }

    #[test]
    fn only_an_exempt_hosts_public_name_is_spliced() {
        let ech = EchHosts::new();
        ech.note_public_name("shop.test", "cloudflare-ech.test");
        ech.note_public_name("other.test", "other-ech.test");

        assert!(!ech.splices("shop.test", false, 1_000), "a plain host stays terminated");
        assert!(
            !ech.splices("cloudflare-ech.test", false, 1_000),
            "no exemption yet"
        );
        assert!(
            ech.splices("cloudflare-ech.test", true, 1_000),
            "full ECH is the opt-in that splices a public name"
        );
        assert!(!ech.splices("shop.test", true, 1_000));

        ech.note_refusal("shop.test", 1_000);
        assert_eq!(
            ech.splice_reason("cloudflare-ech.test", false, 1_000),
            Some("its origin requires ECH")
        );
        assert!(
            !ech.splices("other-ech.test", false, 1_000),
            "another host's public name is unaffected"
        );
        assert!(
            !ech.splices("shop.test", false, 1_000),
            "a plain hello naming the exempt host is still terminated"
        );
        assert!(
            !ech.splices("cloudflare-ech.test", false, 1_000 + EXEMPT_TTL_MS),
            "the splice ends with the exemption"
        );
    }

    #[test]
    fn the_host_public_window_stays_bounded() {
        let ech = EchHosts::new();
        for i in 0..(HOST_PUBLIC_CAP + 4) {
            ech.note_public_name(&format!("host{i}.test"), &format!("ech{i}.test"));
        }
        assert!(!ech.public_name("ech0.test"), "the window must slide");
        assert!(ech.public_name(&format!("ech{}.test", HOST_PUBLIC_CAP + 3)));
        assert_eq!(ech.public_name_for("host0.test"), None);
        assert_eq!(
            ech.public_name_for(&format!("host{}.test", HOST_PUBLIC_CAP + 3)),
            Some(format!("ech{}.test", HOST_PUBLIC_CAP + 3))
        );
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
