//! The engine: TUN packet loop, packet classification, and glue between
//! filtering, DNS forwarding, connection tracking, stats and the UI event log.
//!
//! ## Threading model
//!
//! ```text
//!   tun-thread   poll(TUN) ─► Packet::parse
//!                              ├─ UDP:53   ─► filter core ─► synthetic answer ─► TUN
//!                              │             └► forward upstream (protected socket)
//!                              ├─ UDP:443  ─► QUIC drop
//!                              ├─ UDP:853  ─► DoT drop
//!                              ├─ TCP      ─► blocked? ─► RST
//!                              │             └► new SYN ─► relay table
//!                              │                (443 with filtering armed ─► TLS term)
//!                              └─ UDP      ─► conntrack check ─► drop
//!   dns-thread   poll(upstream sockets) ─► rewrite answer ─► learn IPs ─► TUN
//!                poll(peer sockets)     ─► splice back ─► TUN
//!                                          └► reap finished relays
//!   setup-thread answered SYN ─► app attribution, protect(), dial, TLS session
//!                └► install the upstream half ─► TUN (replayed client bytes)
//! ```
//!
//! Each thread is blocked in a `poll` most of the time: that is why a DNS level
//! filter costs a fraction of a percent of battery. Nothing is allocated on the
//! packet path but the (rare) synthetic DNS answer. Relays are added from the
//! tun-thread but only reaped on the dns-thread (which also polls their
//! descriptors), so a peer socket is never closed under `poll()`. The upstream
//! half of a new flow is built on the setup-thread, never on the reader: the
//! client's SYN-ACK is answered first, so a burst of connections does not make
//! each `connect()` wait for the previous flow's dial.

use crate::conntrack::{CidrSet, ConnTable, IpVerdict};
use crate::dns::{self, BlockMode, Query};
use crate::events::{self, Event, EventLog};
use crate::filter::{FilterEngine, FilterListInfo, HostVerdict};
use crate::fxhash::{hash_str, FxHashMap};
use crate::mitm::quic::bridge;
use crate::mitm::quic::socket::{Datagram, TunUdpSocket};
use crate::mitm::relay::TrafficSink;
use crate::packet::{self, IpKey, Packet, PROTO_TCP, PROTO_UDP};
use crate::socks5::Socks5Handshake;
use crate::state::model::{FirewallAccess, ProxyAccess};
use crate::stats::{self, Stats};
use crate::udpnat::{UdpFlow, UdpKey, UdpNat, UDP_MAX_FLOWS, UDP_MAX_PROXIED_FLOWS};
use crate::uidmap::UidMap;
use crate::upstream::Upstream;
use crate::util::{now_ms, now_ns};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::RawFd;
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering,
};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// Read size for the TUN descriptor.
const TUN_BUF_BYTES: usize = 64 * 1024;

/// How long the tun loop waits before re-checking the shutdown flag. Short
/// because nothing wakes it but a packet or the timeout.
const POLL_TIMEOUT_MS: i32 = 250;

/// Upper bound on the forwarder's wait between events.
///
/// Real work ends the wait through a descriptor (the wake eventfd, a DNS
/// socket, a flow socket); this timeout only paces reaping and idle expiry,
/// so it can be generous without costing latency.
const FORWARD_WAIT_MS: i32 = 1_000;

/// The forwarder's wait with nothing at all in flight.
///
/// No query is pending, no relay or NAT mapping exists and no QUIC flow is
/// terminated, so the only work left is expiry bookkeeping whose own deadlines
/// are minutes away. The slow cadence keeps the process out of the 1 Hz wake
/// the default costs while a browser page is sitting still. Every descriptor
/// joining the wait set (a relay, a mapping, a query) is announced through the
/// wake eventfd, so a long sleep never delays real traffic.
const IDLE_WAIT_MS: i32 = 10_000;

/// Parallel encrypted-DNS exchanges. A DoH query is a TLS handshake plus one
/// request, so a single worker would serialize a page load; more than a
/// handful only burns battery.
const SECURE_DNS_WORKERS: usize = 2;

/// Queries allowed in flight on an encrypted transport. Beyond this the
/// client gets SERVFAIL, which its resolver can retry, instead of a queue
/// that keeps growing while the network is down.
const SECURE_DNS_IN_FLIGHT: usize = 64;

/// Rough upstream cost of one blocked request; only used for the "data saved"
/// figure shown in the UI.
const BYTES_PER_BLOCKED_REQUEST: u64 = 48 * 1024;

/// TLS alerts a client sends when it refuses our certificate, by number.
///
/// The TCP path sees them formatted by rustls (`UnknownCA` and friends); QUIC
/// hands back the numeric alert inside a CRYPTO_ERROR close. One table feeds
/// both paths.
const CERT_ALERTS: [(&str, u8); 7] = [
    ("BadCertificate", 42),
    ("UnsupportedCertificate", 43),
    ("CertificateRevoked", 44),
    ("CertificateExpired", 45),
    ("CertificateUnknown", 46),
    ("UnknownCA", 48),
    ("AccessDenied", 49),
];

/// Is `alert` a client refusing the leaf (as opposed to, say, a protocol
/// error)?
pub(crate) fn cert_alert_is_rejection(alert: u8) -> bool {
    CERT_ALERTS.iter().any(|(_, code)| *code == alert)
}

/// The TTL one synthetic answer may carry: the shortest record's, held inside
/// the range a search engine's endpoint is worth trusting for.
fn record_ttl(records: &[(std::net::IpAddr, u32)]) -> u32 {
    records
        .iter()
        .map(|(_, ttl)| *ttl)
        .min()
        .unwrap_or(60)
        .clamp(30, 600)
}

/// Client bytes a relay may buffer while its peer socket is full; beyond this
/// the flow counts as stuck and is reset rather than buffering forever.
const MAX_PENDING_TO_PEER: usize = 4 * 1024 * 1024;

/// Client bytes buffered while a flow's upstream half is being built. A
/// ClientHello is a few hundred bytes; the cap only bounds a client that
/// keeps sending into a setup that is not finishing.
const MAX_PENDING_CLIENT_SETUP: usize = 64 * 1024;

/// Client bytes buffered per QUIC flow until its SNI decides the path.
const H3_PENDING_BYTES: usize = 16 * 1024;
/// Idle timeout for a terminated QUIC flow. The bridge's own quinn timeout is
/// the same; this reaps flows whose handshake never completed.
const H3_IDLE_MS: u64 = 60_000;
/// How long a spliced five-tuple stays on the NAT path: a client reconnects
/// from the same socket after the refused handshake.
const H3_SPLICE_MS: u64 = 60_000;
/// Datagrams moved to the tun in one forwarder pass.
const H3_DRAIN_MAX: usize = 256;

/// Built-in list of well known encrypted DNS providers. Blocking these is the
/// only way to stop apps from silently bypassing the filter.
fn default_doh_cidrs() -> CidrSet {
    let mut set = CidrSet::new();
    let v4 = [
        (0x0101_0100u32, 24), // Cloudflare
        (0x0100_0000, 24),    // Cloudflare secondary anycast
        (0x0808_0400, 24),    // Google
        (0x0808_0800, 24),
        (0x0909_0900, 24), // Quad9
        (0x0909_0600, 24),
        (0x0d0d_0d00, 24),
        (0x5e8c_0e00, 24), // AdGuard DNS
        (0x5e8c_0f00, 24),
        (0xd043_ded0, 32), // OpenDNS
        (0xd043_ded1, 32),
        (0xb9e4_a800, 24), // CleanBrowsing
        (0xb9e4_a900, 24),
        (0x4d58_0800, 24), // Yandex
        (0x2d5a_1c00, 24), // NextDNS
        (0x2d5a_1e00, 24),
        (0x081a_3800, 24), // Comodo
        (0x54c8_4500, 24), // DNS.WATCH
    ];
    for (net, prefix) in v4 {
        set.add_v4(net, prefix);
    }
    let v6 = [
        (0x2606_4700_0000_0000_0000_0000_0000_0000u128, 48), // Cloudflare
        (0x2001_0486_4800_0000_0000_0000_0000_0000, 32),     // Google
        (0x2620_00fe_0000_0000_0000_0000_0000_0000, 32),     // Quad9
        (0x2a07_a880_0000_0000_0000_0000_0000_0000, 32),     // AdGuard
        (0x2620_0119_0000_0000_0000_0000_0000_0000, 32),     // CleanBrowsing
    ];
    for (net, prefix) in v6 {
        set.add_v6(net, prefix);
    }
    set
}

/// What the stealth switches hide. Every effect is gated by [`Self::enabled`]:
/// the sub-switches remember what the user chose while the mode is off, the
/// same way the UI keeps them.
#[derive(Clone, Copy, Debug, Default)]
pub struct StealthConfig {
    /// The master switch: when off, none of the effects below run.
    pub enabled: bool,
    /// Drop `utm_*`/`fbclid`-style parameters from HTTPS requests.
    pub strip_utm: bool,
    /// Drop STUN/TURN traffic, which is how WebRTC discovers the real IP.
    pub block_web_rtc: bool,
    /// Replace `User-Agent` and the client hints that repeat it.
    pub disguise_user_agent: bool,
    /// Drop cookies that belong to another site than the one being visited.
    pub block_third_party_cookies: bool,
}
impl StealthConfig {
    pub fn strips_utm(self) -> bool {
        self.enabled && self.strip_utm
    }

    pub fn blocks_web_rtc(self) -> bool {
        self.enabled && self.block_web_rtc
    }

    pub fn disguises_user_agent(self) -> bool {
        self.enabled && self.disguise_user_agent
    }

    pub fn blocks_third_party_cookies(self) -> bool {
        self.enabled && self.block_third_party_cookies
    }
}

#[derive(Clone)]
pub struct Config {
    /// Terminate TLS for intercepted connections and inject user scripts.
    pub mitm_enabled: bool,
    /// Terminate QUIC (HTTP/3) and filter it like HTTPS instead of dropping
    /// it. Requires `mitm_enabled`: the same CA and decision layer are used.
    pub filter_http3: bool,
    /// Leave ECHConfigs in DNS answers so clients can run ECH end to end.
    ///
    /// This is the shipped default (AdGuard's "Block ECH" is off): ECH hides
    /// the inner name from the proxy, so an ECH hello can only be spliced, and
    /// the host behind it goes unfiltered. When the user turns Block ECH on,
    /// the config is stripped instead and clients that do not use ECH (GREASE,
    /// older stacks) are still terminated and filtered as usual. See
    /// `mitm::ech`.
    pub full_ech: bool,
    pub block_quic: bool,
    pub block_doh: bool,
    pub block_dot: bool,
    /// Ad blocking module (ad category).
    pub ad_blocking: bool,
    /// Annoyances module (cookie notices, popups, widgets).
    pub annoyances: bool,
    /// Browsing security module (malware and phishing lists).
    pub browsing_security: bool,
    /// Tracking protection (privacy, analytics and social categories).
    pub tracking_protection: bool,
    /// DNS protection; off means host lookups are forwarded unfiltered.
    pub dns_protection: bool,
    /// Let a host that is blocked in a tight retry loop through for a cooldown
    /// (see [`crate::smart`]). On by default: a refused request an app insists
    /// on otherwise costs CPU on every retry.
    pub smart_filtering: bool,
    pub block_mode: BlockMode,
    /// Log requests that were *not* blocked (off by default: pure CPU cost).
    pub log_allowed: bool,
    /// Screen-off battery mode: stop pushing events, keep stats.
    pub eco_mode: bool,
    /// Hosts whose HTTPS traffic is left undecrypted (allowlist).
    pub https_skip_hosts: Vec<String>,
    /// Hosts to decrypt when `https_only_mode` is on (blocklist).
    pub https_only_hosts: Vec<String>,
    /// Invert the model: decrypt only `https_only_hosts`.
    pub https_only_mode: bool,
    /// SOCKS5 proxy new TCP flows are sent through instead of dialing the
    /// destination directly. UDP and the engine's own DNS sockets stay direct.
    pub proxy: Option<Arc<crate::socks5::ProxyEndpoint>>,
    /// Stealth-mode effects: UTM stripping, WebRTC blocking, third-party
    /// cookies and the disguised user agent.
    pub stealth: StealthConfig,
    /// Inject element-hiding rules, scriptlets and the page runtime. Requires
    /// `mitm_enabled`: cosmetics ride the decrypted HTTPS path.
    pub cosmetic_filtering: bool,
    /// Send search-engine queries to their family-filtered host and answer the
    /// original name with the filtered addresses (see [`crate::safesearch`]).
    pub safe_search: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mitm_enabled: false,
            filter_http3: false,
            full_ech: false,
            block_quic: true,
            // Off by default, like AdGuard: clients with a custom secure
            // resolver (Chrome's DoH, Private DNS) have no insecure fallback,
            // so refusing it leaves them without any DNS at all. Hostname
            // blocking still carries filtering on the TLS path.
            block_doh: false,
            block_dot: true,
            ad_blocking: true,
            annoyances: true,
            browsing_security: true,
            tracking_protection: true,
            dns_protection: true,
            smart_filtering: true,
            block_mode: BlockMode::NxDomain,
            log_allowed: false,
            eco_mode: true,
            https_skip_hosts: Vec::new(),
            https_only_hosts: Vec::new(),
            https_only_mode: false,
            proxy: None,
            stealth: StealthConfig::default(),
            cosmetic_filtering: true,
            safe_search: false,
        }
    }
}

/// The active default network, as classified by the platform. Only Wi-Fi and
/// cellular carry per-app restrictions; anything else is treated as unmetered
/// and unrestricted.
pub const NETWORK_UNKNOWN: u8 = 0;
pub const NETWORK_WIFI: u8 = 1;
pub const NETWORK_CELLULAR: u8 = 2;
pub const NETWORK_OTHER: u8 = 3;

/// Per-app firewall rules: overrides on top of the global defaults for the
/// current network, screen state and roaming flag.
///
/// The map is pushed by the platform (only it knows package names). A flow is
/// evaluated against it when it opens and again whenever the network, screen
/// or roaming state changes. The hot path only does one map lookup per
/// dimension, so no allocation happens per packet.
#[derive(Clone, Copy, Debug, Default)]
pub struct AppFirewallState {
    pub wifi: FirewallAccess,
    pub wifi_screen_off: FirewallAccess,
    pub cellular: FirewallAccess,
    pub cellular_screen_off: FirewallAccess,
    pub roaming: FirewallAccess,
}

#[derive(Clone, Debug)]
pub struct AppNetworkPolicy {
    /// The master firewall switch. Off means no dimension applies at all.
    pub active: bool,
    pub allow_wifi: bool,
    pub allow_wifi_screen_off: bool,
    pub allow_cellular: bool,
    pub allow_cellular_screen_off: bool,
    pub allow_roaming: bool,
    pub rules: Arc<FxHashMap<String, AppFirewallState>>,
    /// Per-app answers for the global SOCKS5 proxy. Separate from `rules`:
    /// routing is a proxy feature and keeps working when the firewall is off.
    pub proxy_rules: Arc<FxHashMap<String, ProxyAccess>>,
}

impl Default for AppNetworkPolicy {
    fn default() -> Self {
        AppNetworkPolicy {
            active: false,
            allow_wifi: true,
            allow_wifi_screen_off: true,
            allow_cellular: true,
            allow_cellular_screen_off: true,
            allow_roaming: true,
            rules: Arc::new(FxHashMap::default()),
            proxy_rules: Arc::new(FxHashMap::default()),
        }
    }
}

impl AppNetworkPolicy {
    pub fn is_empty(&self) -> bool {
        let no_network = !self.active
            || (self.rules.is_empty()
                && self.allow_wifi
                && self.allow_wifi_screen_off
                && self.allow_cellular
                && self.allow_cellular_screen_off
                && self.allow_roaming);
        no_network && self.proxy_rules.is_empty()
    }

    /// Whether a flow owned by `packages` should take the SOCKS5 proxy, given
    /// that `global` says whether the proxy is configured for everything.
    ///
    /// Any explicit `Direct` wins over `Through` when apps share a flow: the
    /// strictest answer keeps a flow the user pinned to the direct path off
    /// the proxy. Unattributed flows, and packages with no opinion, follow
    /// the global switch.
    pub fn proxy_through(&self, packages: &[String], global: bool) -> bool {
        let mut through = global;
        for package in packages {
            match self.proxy_rules.get(package) {
                Some(ProxyAccess::Direct) => return false,
                Some(ProxyAccess::Through) => through = true,
                Some(ProxyAccess::Inherit) | None => {}
            }
        }
        through
    }

    /// Whether every package sharing the flow may use this dimension. With no
    /// attribution the global default alone decides, so a globally blocked
    /// network still cuts an unattributed flow.
    fn allowed(
        &self,
        packages: &[String],
        access: impl Fn(&AppFirewallState) -> FirewallAccess,
        fallback: bool,
    ) -> bool {
        if packages.is_empty() {
            return fallback;
        }
        packages.iter().all(|package| {
            let access = self
                .rules
                .get(package)
                .map(&access)
                .unwrap_or(FirewallAccess::Inherit);
            match access {
                FirewallAccess::Allow => true,
                FirewallAccess::Block => false,
                FirewallAccess::Inherit => fallback,
            }
        })
    }

    fn blocked_reason(
        &self,
        packages: &[String],
        network: u8,
        screen_off: bool,
        roaming: bool,
    ) -> Option<&'static str> {
        if !self.active {
            return None;
        }
        // Roaming is an additional restriction on cellular, independent of
        // the screen: an app barred from roaming stays offline on a visited
        // network even while the screen is on.
        if network == NETWORK_CELLULAR
            && roaming
            && !self.allowed(packages, |r| r.roaming, self.allow_roaming)
        {
            return Some("app not allowed while roaming");
        }
        match network {
            NETWORK_WIFI if screen_off => {
                if self.allowed(packages, |r| r.wifi_screen_off, self.allow_wifi_screen_off) {
                    None
                } else {
                    Some("app not allowed on Wi-Fi while the screen is off")
                }
            }
            NETWORK_WIFI => {
                if self.allowed(packages, |r| r.wifi, self.allow_wifi) {
                    None
                } else {
                    Some("app not allowed on Wi-Fi")
                }
            }
            NETWORK_CELLULAR if screen_off => {
                if self.allowed(
                    packages,
                    |r| r.cellular_screen_off,
                    self.allow_cellular_screen_off,
                ) {
                    None
                } else {
                    Some("app not allowed on cellular data while the screen is off")
                }
            }
            NETWORK_CELLULAR => {
                if self.allowed(packages, |r| r.cellular, self.allow_cellular) {
                    None
                } else {
                    Some("app not allowed on cellular data")
                }
            }
            _ => None,
        }
    }
}

/// Result of trying to open a TCP relay.
enum RelayStart {
    Started,
    /// The flow was answered and then refused or dropped: the SYN-ACK went
    /// out first and any reset has already followed it.
    Answered,
    /// Nothing went out (the packet itself was unusable): fail the client
    /// from its own SYN.
    Failed,
}

/// One answered flow whose upstream half is not built yet.
///
/// The packet reader writes the SYN-ACK and queues this; the setup worker
/// runs the slow half (app attribution through the platform, `protect()`, the
/// dial, the TLS session) so a burst of connections does not serialize on the
/// reader, one setup per connect.
struct SetupJob {
    /// Client port, which is also the relay table key.
    port: u16,
    /// Our ISN for this flow: a pruned and reused port is told apart by it.
    my_seq: u32,
    /// The client's SYN, from which the destination and the reply template
    /// are parsed again on the worker.
    syn: Vec<u8>,
    /// The config the SYN was classified under; a settings change mid-setup
    /// must not rewrite a flow that already started.
    cfg: Config,
}

/// The upstream half of an answered flow, ready to be installed.
struct UpstreamHalf {
    peer_fd: RawFd,
    connecting: bool,
    session: Option<crate::mitm::proxy::ProxySession>,
    app_packages: Vec<String>,
    proxy: Option<Arc<crate::socks5::ProxyEndpoint>>,
    handshake: Option<Socks5Handshake>,
}

/// What a relay's peer socket delivered.
enum PeerInput {
    /// Ordinary origin bytes.
    Data,
    /// The SOCKS5 handshake consumed them; the vector carries any origin bytes
    /// that were coalesced behind the final reply.
    Handshake(Vec<u8>),
    /// The handshake failed and the flow must be reset.
    ProxyFailed(&'static str),
}

/// The HTTPS website lists, parsed once per config change.
///
/// A connection clones the Arcs when it opens, so raising or lowering the
/// lists never takes a lock in the packet path and never disturbs a session
/// that is already running.
#[derive(Clone, Default)]
struct HttpsHosts {
    skip: Arc<crate::mitm::hosts::HostPatterns>,
    only: Arc<crate::mitm::hosts::HostPatterns>,
    only_mode: bool,
}

/// Snapshot handed to the JNI layer.
#[derive(Clone, Copy, Default)]
pub struct VpnStats {
    pub packets_total: u64,
    pub packets_dns: u64,
    pub packets_forwarded: u64,
    pub dns_blocked: u64,
    pub dns_allowed: u64,
    pub tcp_reset: u64,
    pub quic_dropped: u64,
    /// HTTP/3 requests blocked inside a terminated QUIC flow.
    pub quic_blocked: u64,
    pub udp_dropped: u64,
    pub dns_queries: u64,
    pub dns_replies: u64,
    pub dns_timeouts: u64,
    pub bytes_saved: u64,
    pub decision_ns_avg: u64,
    pub decision_ns_ewma: u64,
    pub decision_ns_max: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub active_rules: u64,
    pub engine_bytes: u64,
    pub rss_kb: u64,
    pub loop_iterations: u64,
    pub busy_ns: u64,
    pub tls_ns: u64,
    pub handshake_ns: u64,
    pub rewrite_ns: u64,
    pub log_dropped: u64,
    pub events_pending: u64,
    pub events_dropped: u64,
    pub filter_build_ms: u64,
    pub conntrack_entries: u64,
    pub pending_dns: u64,
    pub uptime_ms: u64,
}

/// Addresses a SafeSearch lookup produced, and when they stop being trusted.
struct SafeCacheEntry {
    addresses: Vec<std::net::IpAddr>,
    expires_ms: u64,
}

/// One terminated QUIC flow.
struct H3Flow {
    /// Where the engine feeds the client's datagrams; quinn owns the rest.
    socket: Arc<TunUdpSocket>,
    apps: Vec<String>,
    last_ms: u64,
    /// Client packets seen before the SNI decided the flow's fate. If the host
    /// turns out to be excluded they are replayed into a plain NAT mapping, so
    /// the splice does not wait for the client's retransmission.
    pending: Vec<Vec<u8>>,
    pending_bytes: usize,
    /// Datagram bytes the client sent into the terminations; quinn's own
    /// retransmits are not counted, only what crossed the tun.
    sent: u64,
    /// Datagram bytes the engine wrote back to the client.
    recv: u64,
    /// Reports what crossed the flow once it is reaped, spliced or abandoned —
    /// the same sink the TCP relays and NAT mappings use.
    traffic: Option<TrafficSink>,
}

impl Drop for H3Flow {
    fn drop(&mut self) {
        if self.sent != 0 || self.recv != 0 {
            if let Some(sink) = self.traffic {
                let app = self.apps.first().map(String::as_str).unwrap_or("");
                sink(app, self.sent, self.recv);
            }
        }
    }
}

pub struct Core {
    cfg: RwLock<Config>,
    filter: Arc<FilterEngine>,
    lists: RwLock<Vec<FilterListInfo>>,
    user_rules: RwLock<Vec<String>>,
    upstream: Mutex<Upstream>,
    /// Eventfd the forwarder sleeps on. Anything that changes what the loop
    /// must look at writes it — a queued DNS query, a new flow, bytes stuck
    /// in a peer socket, `stop()` — so a long wait never delays real work.
    /// A negative value means creation failed and the loop runs on its
    /// timeout cadence instead.
    wake_fd: RawFd,
    /// Eventfd the setup worker sleeps on. Separate from `wake_fd` so the
    /// forwarder never wakes for a job it does not service.
    setup_fd: RawFd,
    /// Answered flows waiting for their upstream half. FIFO: two connections
    /// opened back to back are set up in the order they were answered.
    setup_jobs: Mutex<std::collections::VecDeque<SetupJob>>,
    conntrack: Mutex<ConnTable>,
    /// Hosts let through because their block is being retried in a loop
    /// (see [`crate::smart`]); disabled by the matching config switch.
    smart: Mutex<crate::smart::SmartFilter>,
    /// User `host -> address` answers, checked before the filter lists.
    dns_rewrites: RwLock<Vec<crate::dnsrewrite::DnsRewriteRule>>,
    /// SafeSearch addresses, keyed by the filtered host: the extra lookup is
    /// an RTT the next query for the same engine should not pay.
    safe_cache: Mutex<FxHashMap<String, SafeCacheEntry>>,
    /// Answers to repeated queries (see [`crate::dnscache`]). Bounded, and
    /// cleared when the resolver it repeats changes.
    dns_cache: Mutex<crate::dnscache::DnsCache>,
    /// Encrypted resolver selected by the user; `None` means the plain UDP
    /// forwarder owns the queries.
    secure_resolver: RwLock<Option<crate::dnssecure::SecureResolver>>,
    /// One channel per encrypted-DNS worker. A query is handed to a worker
    /// and never blocks the packet path.
    secure_jobs: Mutex<Vec<std::sync::mpsc::Sender<crate::dnssecure::SecureJob>>>,
    /// Receivers stay here until [`Core::start`] launches the workers: tests
    /// construct cores without ever starting a session, and should not spawn
    /// threads that wait forever.
    secure_receivers: Mutex<Vec<std::sync::mpsc::Receiver<crate::dnssecure::SecureJob>>>,
    secure_replies: Mutex<std::sync::mpsc::Receiver<crate::dnssecure::SecureReply>>,
    secure_replies_tx: std::sync::mpsc::Sender<crate::dnssecure::SecureReply>,
    secure_next: AtomicUsize,
    /// Queries handed to an encrypted transport and not answered yet. Capped
    /// so an unreachable resolver cannot grow the queue without bound.
    secure_outstanding: AtomicUsize,
    doh_ips: RwLock<CidrSet>,
    stats: Arc<Stats>,
    events: Mutex<EventLog>,
    /// Writable data directory handed down once by the platform: the request
    /// log database and (later) everything else the app persists. `None` until
    /// `set_data_root` runs, and tests run without it.
    store: OnceLock<Arc<crate::store::Store>>,
    /// The typed, core-owned settings/filters/scripts, opened with the store.
    state: OnceLock<Arc<crate::state::StateStore>>,
    /// The port->uid table of the kernel, which says whose UDP/TCP sockets
    /// are whose.
    uidmap: Mutex<UidMap>,
    /// uid -> package names, pushed down by the platform (Kotlin, the only
    /// side with a package manager); the kernel knows uids alone. Empty until
    /// the first push.
    uid_apps: RwLock<FxHashMap<u32, Vec<String>>>,
    /// Platform callback that names the uid owning one connection (Android's
    /// `ConnectivityManager`). `None` — desktop, tests — falls back to the
    /// kernel's own table in [`crate::uidmap`].
    uid_lookup: RwLock<Option<Arc<dyn crate::api::ConnectionUidLookup>>>,
    screen_off: AtomicBool,
    /// Transient pause from the notification: the tunnel stays up and every
    /// filtering module is off until the user resumes or the process ends.
    /// Deliberately not persisted — "protection on" in the store is the user's
    /// choice, which a pause must not overwrite.
    paused: AtomicBool,
    running: AtomicBool,
    tun_fd: AtomicI32,
    tx_counter: AtomicU64,
    /// Monotonic id attached to every logged decision; the UI shows it as the
    /// connection id and the store keeps it stable across ring and database.
    next_flow_id: AtomicU32,
    started_at: u64,
    resolver: RwLock<SocketAddr>,
    last_tick_ns: AtomicU64,
    /// Local CA used to forge certs for HTTPS filtering; `failed()` stands for
    /// "no CA loaded yet".
    pub mitm_ca: RwLock<Arc<crate::mitm::ca::CertificateAuthority>>,
    /// User scripts injected into HTML responses.
    pub mitm_scripts: RwLock<crate::mitm::script::ScriptSet>,
    /// Shared per-SNI leaf resolver for the TLS termination.
    pub mitm_resolver: RwLock<Option<Arc<crate::mitm::tls::SniCertResolver>>>,
    /// Live intercepted connections.
    relays: Mutex<crate::mitm::relay::RelayTable>,
    /// Live UDP NAT mappings (everything except DNS).
    udp_nat: Mutex<UdpNat>,
    /// The HTTP/3 worker: one tokio thread owning every QUIC endpoint.
    h3: Mutex<Option<Arc<crate::mitm::quic::bridge::Bridge>>>,
    /// Live terminated QUIC flows, keyed by the client's five-tuple.
    h3_flows: Mutex<FxHashMap<UdpKey, H3Flow>>,
    /// Five-tuples whose QUIC is spliced verbatim (HTTPS exclusions, apps that
    /// refused the CA), with the moment the verdict expires. A client that
    /// reconnects lands on the NAT path without a new handshake.
    h3_spliced: Mutex<FxHashMap<UdpKey, u64>>,
    /// Tun and forwarder threads of the current session. A new session joins
    /// them before starting its own, so two tunnels never share the tables.
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    /// App callback that routes engine-created sockets around the VPN.
    socket_protector: Mutex<Option<Arc<dyn crate::api::SocketProtector>>>,
    /// TLS settings for the upstream half of an intercepted connection: the
    /// plain client config plus the per-host ECH configs built from it.
    /// Replaceable so the engine's own tests can trust a loopback origin.
    upstream_config: RwLock<Arc<crate::mitm::tls::UpstreamTls>>,
    /// Port whose flows are TLS-terminated. Always 443 in production; the
    /// end-to-end tests point it at a loopback origin instead (binding 443
    /// needs privileges the test runner does not have).
    pub(crate) mitm_port: AtomicU16,
    /// ECH knowledge shared by the DNS half and the TLS half: which hosts had
    /// their ECHConfig rewritten away, and which turned out to require ECH
    /// (see [`crate::mitm::ech`]). Public like the other state the tests and
    /// the platform poke at.
    pub ech_hosts: Arc<crate::mitm::ech::EchHosts>,
    /// The HTTPS website lists, parsed once per config change and shared with
    /// every connection (see [`crate::mitm::hosts`]).
    https_hosts: RwLock<HttpsHosts>,
    /// Packages whose TLS is spliced untouched (per-app HTTPS filtering off).
    /// Replaced as a whole, so a running session keeps the set it opened with.
    https_skip_apps: RwLock<Arc<HashSet<String>>>,
    /// Packages whose TLS client rejected the forged certificate mid-handshake
    /// (`CertificateUnknown` and friends). Learned from the alert the client
    /// sends, so the next connection of that app is spliced instead of failing
    /// the same way. Kept for the life of the core: a trust decision does not
    /// change because a page was reloaded.
    ca_rejecting_apps: RwLock<HashSet<String>>,
    /// Per-app network/screen-off restrictions, replaced as a whole.
    app_network_policy: RwLock<Arc<AppNetworkPolicy>>,
    /// The active default network, classified by the platform.
    network_type: AtomicU8,
    /// Whether that cellular network is roaming (`NET_CAPABILITY_NOT_ROAMING`).
    roaming: AtomicBool,
    /// Packets produced for the tun, collected only in tests: the end-to-end
    /// tests drive the packet loop without a device, and this is where
    /// client-bound segments would land.
    #[cfg(test)]
    pub outbox: Mutex<Vec<Vec<u8>>>,
}

static CORE: OnceLock<Core> = OnceLock::new();

/// Global handle: the JNI layer runs in the app's single process and the engine
/// must be reachable from any thread.
pub fn core() -> &'static Core {
    CORE.get_or_init(Core::new)
}

/// Reports a request the HTTPS path answered itself: a block scoped to a URL,
/// or a `$redirect` resource standing in for one.
///
/// It runs wherever the session runs, so it goes through the process-wide
/// engine exactly like the packet path — and, like the packet path, it counts
/// the bytes the network never had to carry.
pub(crate) fn log_mitm_block(block: &crate::mitm::proxy::MitmBlock<'_>) {
    let core = core();
    let saved = BYTES_PER_BLOCKED_REQUEST as u32;
    let event = events::with_app(
        events::block_event(
            events::ACTION_BLOCK,
            block.host,
            "",
            block.rule.unwrap_or(""),
            block.list_name.unwrap_or(""),
            block.category,
            0,
            saved,
            false,
        ),
        first_app(block.apps),
    );
    let event = match block.url {
        Some(url) if !url.is_empty() => events::with_url(event, url),
        _ => event,
    };
    core.log_event(event);
    core.stats.add(&core.stats.bytes_saved, u64::from(saved));
}

/// A uid can resolve to several packages (shared uid); the log names the first
/// one, which is what the platform's attribution reported.
fn first_app(packages: &[String]) -> &str {
    packages.first().map(String::as_str).unwrap_or("")
}

/// The relay, NAT and QUIC sinks: one row per closed connection, holding the
/// bytes that actually crossed it.
///
/// The request log cannot carry these: its rows are decisions, and a host the
/// app opened a dozen connections to still has one. This is what the statistics
/// screens read for "data used".
pub(crate) fn record_flow_traffic(app: &str, sent: u64, recv: u64) {
    let core = core();
    let Some(store) = core.store.get() else {
        return;
    };
    let row = crate::store::FlowTraffic {
        ts_ms: now_ms() as i64,
        app: app.to_string(),
        transport: i64::from(core.network_type.load(Ordering::Relaxed) & 0b11),
        roaming: core.roaming.load(Ordering::Relaxed),
        sent: i64::try_from(sent).unwrap_or(i64::MAX),
        recv: i64::try_from(recv).unwrap_or(i64::MAX),
    };
    if !store.log_enqueue_traffic(row) {
        core.stats.inc(&core.stats.log_dropped);
    }
}

/// The HTTP/3 sink: a request answered by the QUIC hub is counted in its own
/// bucket (so the UI can tell terminated QUIC from dropped datagrams) and then
/// logged exactly like an HTTPS block.
fn log_http3_block(block: &crate::mitm::proxy::MitmBlock<'_>) {
    let core = core();
    core.stats.inc(&core.stats.quic_blocked);
    log_mitm_block(block);
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

impl Core {
    pub fn new() -> Self {
        let resolver = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(94, 140, 14, 14), 53));
        let (secure_replies_tx, secure_replies) = std::sync::mpsc::channel();
        let mut secure_jobs = Vec::with_capacity(SECURE_DNS_WORKERS);
        let mut secure_receivers = Vec::with_capacity(SECURE_DNS_WORKERS);
        for _ in 0..SECURE_DNS_WORKERS {
            let (jobs, receivers) = std::sync::mpsc::channel();
            secure_jobs.push(jobs);
            secure_receivers.push(receivers);
        }
        Core {
            cfg: RwLock::new(Config::default()),
            filter: Arc::new(FilterEngine::new()),
            lists: RwLock::new(Vec::new()),
            user_rules: RwLock::new(Vec::new()),
            upstream: Mutex::new(Upstream::new(resolver)),
            wake_fd: unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) },
            setup_fd: unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) },
            setup_jobs: Mutex::new(std::collections::VecDeque::new()),
            conntrack: Mutex::new(ConnTable::new()),
            smart: Mutex::new(crate::smart::SmartFilter::new(true)),
            dns_rewrites: RwLock::new(Vec::new()),
            safe_cache: Mutex::new(FxHashMap::default()),
            dns_cache: Mutex::new(crate::dnscache::DnsCache::new()),
            secure_resolver: RwLock::new(None),
            secure_jobs: Mutex::new(secure_jobs),
            secure_receivers: Mutex::new(secure_receivers),
            secure_replies: Mutex::new(secure_replies),
            secure_replies_tx,
            secure_next: AtomicUsize::new(0),
            secure_outstanding: AtomicUsize::new(0),
            doh_ips: RwLock::new(default_doh_cidrs()),
            stats: Arc::new(Stats::new()),
            events: Mutex::new(EventLog::default()),
            store: OnceLock::new(),
            state: OnceLock::new(),
            uidmap: Mutex::new(UidMap::new()),
            uid_apps: RwLock::new(FxHashMap::default()),
            uid_lookup: RwLock::new(None),
            screen_off: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            running: AtomicBool::new(false),
            tun_fd: AtomicI32::new(-1),
            tx_counter: AtomicU64::new(0),
            next_flow_id: AtomicU32::new(0),
            started_at: now_ms(),
            resolver: RwLock::new(resolver),
            last_tick_ns: AtomicU64::new(0),
            mitm_ca: RwLock::new(Arc::new(crate::mitm::ca::CertificateAuthority::failed(
                "not initialised",
            ))),
            mitm_scripts: RwLock::new(crate::mitm::script::ScriptSet::new()),
            mitm_resolver: RwLock::new(None),
            relays: Mutex::new(crate::mitm::relay::RelayTable::new()),
            udp_nat: Mutex::new(UdpNat::new()),
            h3: Mutex::new(None),
            h3_flows: Mutex::new(FxHashMap::default()),
            h3_spliced: Mutex::new(FxHashMap::default()),
            workers: Mutex::new(Vec::new()),
            socket_protector: Mutex::new(None),
            upstream_config: RwLock::new(crate::mitm::tls::UpstreamTls::system()),
            mitm_port: AtomicU16::new(crate::mitm::relay::MITM_PORT),
            ech_hosts: Arc::new(crate::mitm::ech::EchHosts::new()),
            https_hosts: RwLock::new(HttpsHosts::default()),
            https_skip_apps: RwLock::new(Arc::new(HashSet::new())),
            ca_rejecting_apps: RwLock::new(HashSet::new()),
            app_network_policy: RwLock::new(Arc::new(AppNetworkPolicy::default())),
            network_type: AtomicU8::new(NETWORK_UNKNOWN),
            roaming: AtomicBool::new(false),
            #[cfg(test)]
            outbox: Mutex::new(Vec::new()),
        }
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Opens the writable data root (files + database). The platform calls
    /// this once, as soon as it knows the app's file directory; every later
    /// call is a no-op, so a reconnect never re-opens a live store.
    pub fn set_data_root(&self, path: &str) -> bool {
        if self.store.get().is_some() {
            return true;
        }
        match crate::store::Store::open(std::path::Path::new(path)) {
            Ok(store) => {
                let store = Arc::new(store);
                // The compiled engine survives launches under the data root,
                // next to the list bodies it was built from. Set here and not
                // in `rebuild`: the platform pushes lists through the async
                // path, which never passes through a rebuild that could do it.
                self.filter.set_cache_dir(store.root().join("engine"));
                // Opening the state runs the one-time import from the blobs
                // older builds wrote, so it must happen before the platform
                // reads the state back.
                let state = crate::state::StateStore::open(Arc::clone(&store));
                let stored = self.store.set(store).is_ok();
                let stated = self.state.set(state).is_ok();
                stored && stated
            }
            Err(e) => {
                crate::logbuf::push(&format!("store open: {e}"));
                false
            }
        }
    }

    /// The store, once the platform has handed the data root down.
    pub fn store(&self) -> Option<&Arc<crate::store::Store>> {
        self.store.get()
    }

    /// The typed state, once the store is open. Every setting the UI edits
    /// lives here; the platform only projects it.
    pub fn state(&self) -> Option<&Arc<crate::state::StateStore>> {
        self.state.get()
    }

    /// Loads the local CA from the store, or mints one and persists the pair
    /// under `core/`. Returns the certificate PEM (empty without a store).
    pub fn ensure_ca(&self) -> String {
        let Some(store) = self.store.get() else {
            return String::new();
        };
        let dir = store.core_dir();
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca-key.pem");
        if let (Ok(cert), Ok(key)) = (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            if !cert.trim().is_empty() && !key.trim().is_empty() {
                if let Ok(ca) = crate::mitm::ca::CertificateAuthority::from_pem(&cert, &key) {
                    let pem = ca.cert_pem();
                    self.set_mitm_ca(Arc::new(ca));
                    return pem;
                }
                crate::logbuf::push("ensure_ca: persisted pair did not parse; minting a new one");
            }
        }
        let Ok(ca) = crate::mitm::ca::CertificateAuthority::generate() else {
            return String::new();
        };
        let (pem, key) = (ca.cert_pem(), ca.key_pem());
        // The private half must not be readable by anything but this app, so
        // it is created 0600 and only then renamed into place.
        if write_atomic(&dir, "ca-key.pem.tmp", "ca-key.pem", &key, true)
            && write_atomic(&dir, "ca.pem.tmp", "ca.pem", &pem, false)
        {
            // persisted for the next launch
        }
        self.set_mitm_ca(Arc::new(ca));
        pem
    }

    /// Drops the persisted CA pair; the next [`Self::ensure_ca`] mints a fresh
    /// one.
    pub fn reset_ca(&self) {
        let Some(store) = self.store.get() else {
            return;
        };
        let dir = store.core_dir();
        let _ = std::fs::remove_file(dir.join("ca.pem"));
        let _ = std::fs::remove_file(dir.join("ca-key.pem"));
    }

    pub fn uptime_ms(&self) -> u64 {
        now_ms().saturating_sub(self.started_at)
    }

    // ---------------------------------------------------------------- config

    pub fn set_config(&self, cfg: Config) {
        // Cosmetics and scriptlets have no per-rule category, so an ads,
        // annoyances, tracking or browsing-security switch changes which lists
        // belong in the build as well as the live category gate below.
        let lists_changed = {
            let old = self.cfg.read().unwrap();
            old.ad_blocking != cfg.ad_blocking
                || old.annoyances != cfg.annoyances
                || old.browsing_security != cfg.browsing_security
                || old.tracking_protection != cfg.tracking_protection
        };
        // The filter engine owns the hot-path copy so a module switch takes
        // effect on the next packet without recompiling the lists. A transient
        // pause wins over the persisted switches: `set_paused` restores them
        // from this config when the user resumes.
        if self.is_paused() {
            self.filter.set_module_flags(false, false, false, false, false);
        } else {
            self.filter.set_module_flags(
                cfg.ad_blocking,
                cfg.tracking_protection,
                cfg.dns_protection,
                cfg.annoyances,
                cfg.browsing_security,
            );
        }
        self.smart.lock().unwrap().set_enabled(cfg.smart_filtering);
        *self.https_hosts.write().unwrap() = HttpsHosts {
            skip: Arc::new(crate::mitm::hosts::HostPatterns::new(
                cfg.https_skip_hosts.clone(),
            )),
            only: Arc::new(crate::mitm::hosts::HostPatterns::new(
                cfg.https_only_hosts.clone(),
            )),
            only_mode: cfg.https_only_mode,
        };
        // A terminated QUIC flow keeps the transport it started with. When the
        // HTTP/3 switch goes away (or a proxy takes the traffic over) the open
        // flows are cut, so the client retries on a path the new config covers.
        let h3_off = !cfg.filter_http3 || !cfg.mitm_enabled || cfg.proxy.is_some();
        *self.cfg.write().unwrap() = cfg;
        if h3_off {
            self.close_h3_flows();
        }
        if lists_changed {
            // Recompile off the caller's thread: the previous engine keeps
            // serving (with the new live category gate) until this one is
            // published. Without a build the cosmetics of the module that was
            // just switched off would keep hiding elements.
            let lists = self.lists.read().unwrap().clone();
            if !lists.is_empty() {
                let rules = self.user_rules.read().unwrap().clone();
                self.rebuild_async(lists, rules);
            }
        }
    }

    pub fn config(&self) -> Config {
        self.cfg.read().unwrap().clone()
    }

    pub fn set_screen_off(&self, off: bool) {
        self.screen_off.store(off, Ordering::Relaxed);
        if off {
            // The kernel's socket tables churn while idle, and nobody is
            // reading the log, so drop both.
            self.uidmap.lock().unwrap().invalidate();
            self.upstream.lock().unwrap().clear();
            // Apps configured to stay off the network while the screen is off
            // lose their open flows now, not when they next reconnect.
            self.drop_restricted_flows();
        }
    }

    /// Replaces the per-app network firewall. Open flows belonging to a newly
    /// restricted app are cut immediately.
    pub fn set_app_network_policy(&self, policy: AppNetworkPolicy) {
        *self.app_network_policy.write().unwrap() = Arc::new(policy);
        self.drop_restricted_flows();
    }

    /// Records the platform's classification of the default network. A change
    /// reevaluates every open flow against the per-app rules.
    pub fn set_network_type(&self, network: u8) {
        if self.network_type.swap(network, Ordering::Relaxed) == network {
            return;
        }
        self.drop_restricted_flows();
    }

    pub fn network_type(&self) -> u8 {
        self.network_type.load(Ordering::Relaxed)
    }

    /// Records whether the active cellular network is roaming.
    pub fn set_roaming(&self, roaming: bool) {
        if self.roaming.swap(roaming, Ordering::Relaxed) == roaming {
            return;
        }
        self.drop_restricted_flows();
    }

    pub fn is_roaming(&self) -> bool {
        self.roaming.load(Ordering::Relaxed)
    }

    /// The reason this collection of packages may not use the network right
    /// now, or `None` when it is allowed.
    fn app_blocked_reason(&self, packages: &[String]) -> Option<&'static str> {
        let policy = Arc::clone(&*self.app_network_policy.read().unwrap());
        policy.blocked_reason(
            packages,
            self.network_type(),
            self.is_screen_off(),
            self.is_roaming(),
        )
    }

    /// Cuts every TCP relay and retires every UDP mapping whose app is now
    /// restricted.
    ///
    /// Runs on whichever thread pushed the change (the platform callback), so
    /// descriptors are never closed here: relays are marked closed and dropped
    /// by the forwarder, and UDP mappings are flagged for the same pass.
    fn drop_restricted_flows(&self) {
        let network = self.network_type();
        let screen_off = self.is_screen_off();
        let roaming = self.is_roaming();
        let policy = Arc::clone(&*self.app_network_policy.read().unwrap());
        if policy.is_empty() {
            return;
        }
        let mut resets = Vec::new();
        {
            let mut guard = self.relays.lock().unwrap();
            for (_, relay) in guard.iter_mut() {
                if relay.closed
                    || policy
                        .blocked_reason(&relay.app_packages, network, screen_off, roaming)
                        .is_none()
                {
                    continue;
                }
                if let Some(rst) = relay.rst_to_client() {
                    resets.push(rst);
                }
                relay.close();
            }
        }
        for rst in resets {
            self.write_raw(&rst);
        }
        {
            let mut nat = self.udp_nat.lock().unwrap();
            nat.retire_matching(|flow| {
                policy
                    .blocked_reason(&flow.app_packages, network, screen_off, roaming)
                    .is_some()
            });
        }
        {
            let mut flows = self.h3_flows.lock().unwrap();
            let blocked: Vec<UdpKey> = flows
                .iter()
                .filter(|(_, flow)| {
                    policy
                        .blocked_reason(&flow.apps, network, screen_off, roaming)
                        .is_some()
                })
                .map(|(key, _)| *key)
                .collect();
            if !blocked.is_empty() {
                let bridge = self.h3.lock().unwrap().clone();
                for key in blocked {
                    flows.remove(&key);
                    if let Some(bridge) = &bridge {
                        bridge.close(key);
                    }
                }
            }
        }
        // The forwarder owns relay and mapping descriptors; it has to run the
        // removals and may be parked in poll() right now.
        self.wake();
    }

    pub fn is_screen_off(&self) -> bool {
        self.screen_off.load(Ordering::Relaxed)
    }

    /// Pauses or resumes filtering without tearing the tunnel down.
    ///
    /// Pausing is transient by design: the persisted protection record is the
    /// user's choice and is never rewritten here. Every module gate reads the
    /// flag, and the filter engine's module flags are switched with it, so the
    /// next lookup is answered unfiltered instead of paying for a rebuild.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
        let (ads, tracking, dns, annoyances, security) = {
            let cfg = self.cfg.read().unwrap();
            if paused {
                (false, false, false, false, false)
            } else {
                (
                    cfg.ad_blocking,
                    cfg.tracking_protection,
                    cfg.dns_protection,
                    cfg.annoyances,
                    cfg.browsing_security,
                )
            }
        };
        self.filter
            .set_module_flags(ads, tracking, dns, annoyances, security);
        if paused {
            // A paused tunnel forwards QUIC verbatim, so the terminated flows
            // are closed: keeping them would leave the client on a filtered
            // transport while the user believes filtering is off.
            self.close_h3_flows();
        }
        // A paused engine still forwards DNS and UDP: every worker sleeps on
        // this fd, so nothing more is needed, but a wake keeps the UI's first
        // stats tick from waiting out the idle poll.
        self.wake();
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    pub fn set_resolver(&self, addr: SocketAddr) {
        let changed = {
            let mut resolver = self.resolver.write().unwrap();
            let changed = *resolver != addr;
            *resolver = addr;
            changed
        };
        // Every config apply names the resolver again; only an actual change
        // invalidates what is in flight or cached.
        if !changed {
            return;
        }
        {
            let mut upstream = self.upstream.lock().unwrap();
            upstream.set_resolver(addr);
            upstream.clear();
        }
        // Answers learned from the previous server are no longer valid.
        self.conntrack.lock().unwrap().clear();
        self.dns_cache.lock().unwrap().clear();
    }

    /// Installs (or removes) the plain UDP resolver retried when the selected
    /// server stays silent. Works for every primary transport, including
    /// DoT/DoH, because the retry always travels over the UDP pool.
    pub fn set_backup_resolver(&self, backup: Option<SocketAddr>) {
        self.upstream.lock().unwrap().set_backup(backup);
    }

    pub fn set_socket_fds(&self, fds: &[RawFd]) {
        self.upstream.lock().unwrap().set_socket_fds(fds);
        // The DNS descriptors are part of the forwarder's wait set: a parked
        // loop has to pick up the new ones now, not at its idle cadence.
        self.wake();
    }

    /// Replaces the user's DNS rewrites. The caller parses the rows, so a
    /// hand-edited store can only hand over rules the validator accepted.
    pub fn set_dns_rewrites(&self, rules: Vec<crate::dnsrewrite::DnsRewriteRule>) {
        *self.dns_rewrites.write().unwrap() = rules;
    }

    /// Selects the transport upstream queries use. `None` restores the plain
    /// UDP forwarder; a `Some` value bypasses it entirely.
    pub fn set_secure_resolver(&self, resolver: Option<crate::dnssecure::SecureResolver>) {
        let changed = {
            let mut slot = self.secure_resolver.write().unwrap();
            let changed = *slot != resolver;
            *slot = resolver;
            changed
        };
        if changed {
            // The cached answers came from the previous transport's server.
            self.dns_cache.lock().unwrap().clear();
        }
    }

    /// Sends one `example.com` query to a resolver the user is editing.
    ///
    /// The settings screen runs this on its own IO thread: a DoH endpoint can
    /// take seconds to fail. While the tunnel is up the probe socket has to
    /// bypass it, which is the same protector the forwarder uses; before the
    /// first connect there is no tunnel to loop back into.
    pub fn probe_dns(
        &self,
        protocol: crate::state::model::DnsProtocol,
        raw: &str,
    ) -> crate::state::model::DnsProbeResult {
        use crate::state::model::{DnsProbeError, DnsProbeResult, DnsProtocol};

        let started = now_ms();
        let fail = |error: DnsProbeError| DnsProbeResult {
            ok: false,
            latency_ms: now_ms().saturating_sub(started) as u32,
            error,
        };
        let (address, port) = match crate::state::dnsaddr::normalize(protocol, raw) {
            Ok(parts) => parts,
            Err(_) => return fail(DnsProbeError::AddressInvalid),
        };
        let protector = self.socket_protector.lock().unwrap().clone();
        let protector = if self.is_running() {
            match protector {
                Some(protector) => Some(protector),
                None => return fail(DnsProbeError::ProtectedSocket),
            }
        } else {
            None
        };

        let txid = (now_ms() & 0x7fff) as u16;
        let query = match dns::build_query("example.com", dns::TYPE_A, txid) {
            Some(query) => query,
            None => return fail(DnsProbeError::BadResponse),
        };
        let outcome = match protocol {
            DnsProtocol::Udp => crate::dnssecure::probe_udp(&address, port, protector.as_deref()),
            DnsProtocol::Dot | DnsProtocol::Doh => {
                match crate::dnssecure::SecureResolver::from_parts(protocol, &address, port) {
                    Some(resolver) => {
                        crate::dnssecure::exchange(&resolver, &query, protector.as_deref())
                    }
                    None => Err(crate::dnssecure::SecureError::Address),
                }
            }
        };
        match outcome {
            Ok(_) => DnsProbeResult {
                ok: true,
                latency_ms: now_ms().saturating_sub(started) as u32,
                error: DnsProbeError::None,
            },
            Err(error) => {
                crate::logbuf::push(&format!("dns probe {raw}: {error:?}"));
                fail(error.probe_error())
            }
        }
    }

    /// Launches the encrypted-DNS workers for this session. The receivers are
    /// taken once: a later `start()` reuses the workers already running.
    fn start_secure_workers(&self) {
        let receivers = std::mem::take(&mut *self.secure_receivers.lock().unwrap());
        for (index, receiver) in receivers.into_iter().enumerate() {
            let replies = self.secure_replies_tx.clone();
            let wake_fd = self.wake_fd;
            if let Ok(_worker) = std::thread::Builder::new()
                .name(format!("adfree-secure-dns-{index}"))
                .stack_size(256 * 1024)
                .spawn(move || crate::dnssecure::worker_loop(receiver, replies, wake_fd))
            {
                // Dropping the handle detaches the worker: it lives for the
                // process, so a session restart never leaves queued queries
                // with no thread to answer them.
            }
        }
    }

    /// Hands one already-framed query to a worker. False when no worker can
    /// take it (the tunnel has not started yet, or the channel closed).
    fn enqueue_secure(&self, job: crate::dnssecure::SecureJob) -> bool {
        let senders = self.secure_jobs.lock().unwrap();
        if senders.is_empty() {
            return false;
        }
        let index = self.secure_next.fetch_add(1, Ordering::Relaxed) % senders.len();
        senders[index].send(job).is_ok()
    }

    /// Answers that finished on an encrypted transport since the last pass.
    fn take_secure_replies(&self) -> Vec<crate::dnssecure::SecureReply> {
        self.secure_replies.lock().unwrap().try_iter().collect()
    }

    fn handle_secure_reply(&self, reply: crate::dnssecure::SecureReply) {
        self.secure_outstanding.fetch_sub(1, Ordering::Relaxed);
        if reply.message.is_empty() {
            // The encrypted transport failed. The fallback is plain UDP, so it
            // can still answer even when TLS is what broke.
            if !reply.pending.via_backup
                && self
                    .upstream
                    .lock()
                    .unwrap()
                    .retry_via_backup(&reply.pending, now_ms())
            {
                return;
            }
            self.fail_pending(&reply.pending);
            return;
        }
        let upstream_reply = crate::upstream::Reply {
            pending: reply.pending,
            // Only the UDP path uses the slot; a secure answer has none.
            socket: 0,
            message: reply.message,
        };
        self.handle_reply(&upstream_reply);
    }

    /// The client of a query that will never be answered gets SERVFAIL at
    /// once. SafeSearch clients wait on a filtered-host lookup, so they take
    /// the same path as an expired UDP pending.
    fn fail_pending(&self, pending: &crate::upstream::Pending) {
        self.stats.inc(&self.stats.dns_timeouts);
        let Some(pkt) = Packet::parse(&pending.packet) else {
            return;
        };
        let Some(query) = dns::parse_query(pkt.l4_payload()) else {
            return;
        };
        if let Some(err) = dns::synthesize_error(&pkt, Some(&query), dns::RCODE_SERVFAIL) {
            self.write_raw(&err);
        }
    }

    /// Addresses from a fresh SafeSearch answer, or `None` when the cached
    /// entry lapsed. The lock is never held across the packet work below.
    fn cached_safe_search(&self, safe_host: &str, now_ms: u64) -> Option<Vec<std::net::IpAddr>> {
        let mut cache = self.safe_cache.lock().unwrap();
        let entry = cache.get(safe_host)?;
        if entry.expires_ms <= now_ms {
            cache.remove(safe_host);
            return None;
        }
        Some(entry.addresses.clone())
    }

    fn remember_safe_search(
        &self,
        safe_host: &str,
        records: &[(std::net::IpAddr, u32)],
        now_ms: u64,
    ) {
        if records.is_empty() {
            return;
        }
        // The answer's own TTL, bounded so a stale engine address cannot live
        // longer than the user's switch.
        let ttl = records
            .iter()
            .map(|(_, ttl)| *ttl)
            .min()
            .unwrap_or(60)
            .clamp(30, 600) as u64;
        let mut cache = self.safe_cache.lock().unwrap();
        if cache.len() >= 32 {
            cache.clear();
        }
        cache.insert(
            safe_host.to_string(),
            SafeCacheEntry {
                addresses: records.iter().map(|(ip, _)| *ip).collect(),
                expires_ms: now_ms + ttl * 1_000,
            },
        );
    }

    /// Replaces the encrypted-DNS provider ranges. Returns false when nothing
    /// usable was parsed (the built-in list is kept in that case).
    pub fn set_doh_cidrs(&self, ranges: &[String]) -> bool {
        let mut set = CidrSet::new();
        for raw in ranges {
            if let Some((net, prefix)) = parse_cidr(raw) {
                match net {
                    IpKey::V4(v) => set.add_v4(v, prefix),
                    IpKey::V6(v) => set.add_v6(v, prefix),
                }
            }
        }
        if set.is_empty() {
            return false;
        }
        *self.doh_ips.write().unwrap() = set;
        true
    }

    /// Same, but from an already built set (used by the JNI layer and tests).
    pub fn install_doh_cidrs(&self, set: CidrSet) -> bool {
        if set.is_empty() {
            return false;
        }
        *self.doh_ips.write().unwrap() = set;
        true
    }

    // ------------------------------------------------------------ filtering

    pub fn set_lists(&self, lists: Vec<FilterListInfo>, user_rules: Vec<String>) {
        {
            let mut guard = self.lists.write().unwrap();
            *guard = lists.clone();
        }
        {
            let mut guard = self.user_rules.write().unwrap();
            *guard = user_rules.clone();
        }
        self.rebuild(&lists, &user_rules);
    }

    pub fn rebuild(&self, lists: &[FilterListInfo], user_rules: &[String]) {
        self.filter.rebuild(lists, user_rules);
        self.sync_engine_stats();
    }

    /// Rebuilds on a background thread; the previous engine keeps serving.
    pub fn rebuild_async(&self, lists: Vec<FilterListInfo>, user_rules: Vec<String>) {
        {
            let mut guard = self.lists.write().unwrap();
            *guard = lists.clone();
        }
        {
            let mut guard = self.user_rules.write().unwrap();
            *guard = user_rules.clone();
        }
        FilterEngine::rebuild_async(&self.filter, lists, user_rules);
    }

    /// Keeps the stats snapshot in sync with the engine.
    pub fn sync_engine_stats(&self) {
        self.stats
            .set(&self.stats.filter_rules, self.filter.active_rules());
        self.stats
            .set(&self.stats.engine_bytes, self.filter.memory_bytes() as u64);
        let hits = self.filter.cache_hits() as i64;
        let misses = self.filter.cache_misses() as i64;
        self.stats.set(&self.stats.cache_hits, hits.max(0) as u64);
        self.stats
            .set(&self.stats.cache_misses, misses.max(0) as u64);
    }

    pub fn filter_engine(&self) -> Arc<FilterEngine> {
        Arc::clone(&self.filter)
    }

    /// Lists whose body the last filter build could not read.
    pub fn filter_build_errors(&self) -> Vec<(u16, String)> {
        self.filter.build_errors()
    }

    pub fn lists(&self) -> Vec<FilterListInfo> {
        self.lists.read().unwrap().clone()
    }

    pub fn user_rules(&self) -> Vec<String> {
        self.user_rules.read().unwrap().clone()
    }

    /// UI helper: is this host blocked, and by what?
    pub fn check_host(&self, host: &str) -> HostVerdict {
        self.filter.check_host_detailed(host)
    }

    pub fn clear_dns_cache(&self) {
        self.dns_cache.lock().unwrap().clear();
        self.filter.clear_cache();
        self.conntrack.lock().unwrap().clear();
        self.upstream.lock().unwrap().clear();
    }

    // ------------------------------------------------------------- lifecycle

    /// Starts the engine on a TUN descriptor. `tun_fd` must be a valid,
    /// readable/writable TUN descriptor owned by this process, and must stay
    /// open until [`stop`] is called.
    pub fn start(&self, tun_fd: RawFd) {
        self.stop();
        // The previous session's thread must be gone before this one starts:
        // two forwarders would poll the same tables, and the departing one
        // would retire the arriving one's flows. It notices `stop()` within
        // its poll timeout, so this blocks for a few hundred milliseconds at
        // most (and not at all when the tunnel was already down).
        self.join_workers();
        // Jobs left behind by the previous session belong to flows whose
        // relays are gone; answering them now would dial for nobody.
        self.setup_jobs.lock().unwrap().clear();
        self.drain_setup_wake();
        self.start_secure_workers();
        self.tun_fd.store(tun_fd, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);
        let statics: &'static Core = core();
        let mut workers = Vec::with_capacity(3);
        // The tun worker runs the whole data path — TLS, the response rewriter
        // and gzip bodies — in one call chain, and a 128 KiB stack overflowed
        // it on a real response (SIGSEGV in `decode_body`, measured on the
        // emulator 19/10/2026). One MiB matches what bionic gives a thread.
        if let Ok(worker) = std::thread::Builder::new()
            .name("adfree-tun".into())
            .stack_size(1024 * 1024)
            .spawn(move || tun_loop(statics, tun_fd))
        {
            workers.push(worker);
        }
        if let Ok(worker) = std::thread::Builder::new()
            .name("adfree-dns".into())
            .stack_size(1024 * 1024)
            .spawn(move || forwarder_loop(statics))
        {
            workers.push(worker);
        }
        // The upstream half of every intercepted flow is built here, off the
        // packet reader: app attribution (a platform round-trip), protect()
        // and the TLS session together cost milliseconds that would otherwise
        // delay the next SYN the client sends.
        if let Ok(worker) = std::thread::Builder::new()
            .name("adfree-setup".into())
            .stack_size(1024 * 1024)
            .spawn(move || setup_loop(statics))
        {
            workers.push(worker);
        }
        // HTTP/3 termination lives on its own tokio thread; `stop()` shuts it
        // down so this join returns promptly.
        if let Some(worker) = statics.start_h3() {
            workers.push(worker);
        }
        *self.workers.lock().unwrap() = workers;
    }

    /// Waits for the previous session's workers to return.
    fn join_workers(&self) {
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        for worker in workers {
            let _ = worker.join();
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.tun_fd.store(-1, Ordering::SeqCst);
        // QUIC flows own their transport and never touch the tun, so ending
        // them here releases the sockets even if the forwarder's last pass is
        // already gone.
        self.stop_h3();
        // The forwarder may be halfway through its one-second wait; without
        // this it would only notice the stop on the next timeout.
        self.wake();
        self.poke_setup();
    }

    /// Asks the forwarder to take a pass now.
    ///
    /// One 8-byte counter write on the eventfd. Ignored when creation failed:
    /// the loop's timeout cadence still services everything, just later.
    pub(crate) fn wake(&self) {
        if self.wake_fd < 0 {
            return;
        }
        let one: u64 = 1;
        unsafe {
            libc::write(
                self.wake_fd,
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }

    /// Asks the setup worker to take the queued flows now.
    fn poke_setup(&self) {
        if self.setup_fd < 0 {
            return;
        }
        let one: u64 = 1;
        unsafe {
            libc::write(
                self.setup_fd,
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            );
        }
    }

    fn drain_setup_wake(&self) {
        if self.setup_fd < 0 {
            return;
        }
        let mut buf = [0u8; 8];
        unsafe {
            libc::read(
                self.setup_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            );
        }
    }

    /// Resets the wake counter after a wait.
    ///
    /// An eventfd stays readable while its counter is positive: without this
    /// every later poll would return immediately.
    fn drain_wake(&self) {
        if self.wake_fd < 0 {
            return;
        }
        let mut buf = [0u8; 8];
        unsafe {
            libc::read(
                self.wake_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            );
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    // -------------------------------------------------------- packet handling

    /// Classifies one raw IP packet and returns any locally synthesized reply.
    ///
    /// Cost for traffic we do not care about: one `Packet::parse` and a couple
    /// of atomic increments.
    pub fn handle_packet(&self, raw: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        self.stats.inc(&self.stats.packets_total);
        self.stats.inc(&self.stats.loop_iterations);

        let Some(pkt) = Packet::parse(raw) else {
            return out;
        };

        let cfg = self.cfg.read().unwrap().clone();
        let paused = self.is_paused();
        if pkt.proto == PROTO_UDP && pkt.dst_port == 53 {
            self.stats.inc(&self.stats.packets_dns);
            self.handle_dns(&pkt, &cfg, &mut out);
        } else if pkt.proto == PROTO_UDP && pkt.dst_port == 443 {
            // HTTP/3 precedence: paused → plain relay; filtering armed → QUIC
            // termination; the QUIC switch → drop; otherwise relay.
            self.handle_quic(&pkt, &cfg);
        } else if pkt.proto == PROTO_UDP && pkt.dst_port == 853 && cfg.block_dot && !paused {
            self.stats.inc(&self.stats.udp_dropped);
        } else if pkt.proto == PROTO_UDP
            && !paused
            && cfg.stealth.blocks_web_rtc()
            && (crate::mitm::stealth::is_webrtc_port(pkt.dst_port)
                || crate::mitm::stealth::is_stun_datagram(pkt.l4_payload()))
        {
            // STUN binding requests are how a page learns the address the
            // carrier gave the phone; TURN then relays media through it.
            // Nothing else on these ports is useful to a browser.
            self.stats.inc(&self.stats.udp_dropped);
        } else if pkt.proto == PROTO_UDP {
            if self.udp_blocked(&pkt, &cfg) {
                self.stats.inc(&self.stats.udp_dropped);
            } else {
                // Everything left is spliced through a NAT mapping: without it
                // games, VoIP and video would die the moment protection is on.
                self.relay_udp(&pkt);
            }
        } else if pkt.proto == PROTO_TCP {
            self.handle_tcp(&pkt, &cfg, &mut out);
        }
        out
    }

    /// TCP is terminated locally: the client talks to us and we talk to the
    /// real server, so every flow stays visible (and filterable).
    ///
    /// Blocked verdicts win over relaying; a new SYN starts a relay; anything
    /// else that belongs to no relay is unrouteable here and fails fast.
    fn handle_tcp(&self, pkt: &Packet<'_>, cfg: &Config, out: &mut Vec<Vec<u8>>) {
        if self.relay_tcp(pkt, out) {
            return;
        }
        if let Some(reason) = self.tcp_blocked(pkt, cfg) {
            self.reset_tcp_with_reason(pkt, reason);
            return;
        }
        if pkt.is_syn {
            match self.begin_tcp_relay(pkt, cfg, out) {
                // The two answered outcomes: a live relay, or a SYN-ACK that
                // was already followed by whatever refusal applied.
                RelayStart::Started | RelayStart::Answered => {}
                RelayStart::Failed => self.reset_tcp(pkt),
            }
        } else if !pkt.is_rst && !pkt.l4_payload().is_empty() {
            // Data for a flow that predates protection, or whose relay already
            // died: nothing can carry it, so cut it.
            self.reset_tcp(pkt);
        }
    }

    /// Sends the datagrams of one non-DNS UDP flow through a protected socket.
    ///
    /// The mapping is keyed by both endpoints; the first datagram opens the
    /// socket and later ones reuse it, so a game keeps one descriptor (and one
    /// NAT port on the server's side) for the whole session. With a proxy
    /// configured the mapping is bridged to a SOCKS5 UDP ASSOCIATE thread
    /// instead of a direct socket. Replies are handled by
    /// [`Core::handle_udp_reply`].
    fn relay_udp(&self, pkt: &Packet<'_>) {
        let (Some(client), Some(server)) = (pkt.src_ip(), pkt.dst_ip()) else {
            return;
        };
        if server.as_ip() == crate::mitm::proxy::local_origin_addr() {
            // The injection origin is a TCP-only local service: a stray
            // datagram (a QUIC probe) must not leak out to a reserved address.
            return;
        }
        let key = UdpKey {
            client,
            client_port: pkt.src_port,
            server,
            server_port: pkt.dst_port,
        };
        // The mapping is reused as-is: its proxy choice was made when the
        // first datagram opened it, and the app cannot change mid-flow.
        let payload = pkt.l4_payload();
        let mut nat = self.udp_nat.lock().unwrap();
        if let Some(flow) = nat.get_mut(&key) {
            flow.last_ms = now_ms();
            // The lock is held across the send so the polling thread cannot
            // retire (and close) the descriptor between the lookup and the
            // syscall. `send()` on a non-blocking socket never blocks.
            if !Self::send_udp(flow.fd, payload) {
                // The route behind this mapping died (typically IPv6 the
                // network cannot carry). Answering with ICMP is what makes
                // QUIC-first clients fall back instead of retrying into the
                // dark for the rest of the session.
                self.stats.inc(&self.stats.udp_dropped);
                self.refuse_udp(pkt);
                return;
            }
            flow.sent += payload.len() as u64;
            self.stats.inc(&self.stats.udp_relayed);
            return;
        }
        // A new mapping. The lock is dropped first because `open_peer_socket`
        // makes a `protect()` binder round-trip; only the tun thread inserts,
        // and the socket is not in the table yet, so nothing can touch it
        // while it is built. The cap cannot fill up meanwhile: the table only
        // shrinks while unlocked.
        drop(nat);
        let policy = Arc::clone(&*self.app_network_policy.read().unwrap());
        let app_packages = if policy.is_empty() {
            Vec::new()
        } else {
            let packages = self.apps_for_udp(pkt);
            if self.app_blocked_reason(&packages).is_some() {
                self.stats.inc(&self.stats.udp_dropped);
                return;
            }
            packages
        };
        // The same rule the TCP relay uses: the global proxy takes every flow
        // unless automatic routing keeps LAN and other non-internet
        // destinations direct, and a per-app DIRECT/THROUGH answer overrides
        // the global switch.
        let global_proxy = self.cfg.read().unwrap().proxy.clone();
        let through = policy.proxy_through(&app_packages, global_proxy.is_some());
        let proxy = if through {
            global_proxy
                .filter(|p| !p.automatic || !crate::socks5::bypasses_automatic(server))
        } else {
            None
        };
        let proxied = proxy.is_some();
        let nat = self.udp_nat.lock().unwrap();
        if nat.len() >= UDP_MAX_FLOWS || (proxied && nat.proxied_len() >= UDP_MAX_PROXIED_FLOWS) {
            // One app spraying destination ports must not drain the descriptor
            // budget; the flow simply loses its packets, like a full NAT box.
            drop(nat);
            self.stats.inc(&self.stats.udp_dropped);
            return;
        }
        drop(nat);
        let fd = match proxy {
            Some(endpoint) => self.open_proxied_udp(server, pkt.dst_port, endpoint),
            None => {
                let fd = self.open_peer_socket(server, libc::SOCK_DGRAM);
                match fd {
                    Some(fd) if connect_fd(fd, server, pkt.dst_port) != Connect::Failed => Some(fd),
                    Some(fd) => {
                        unsafe { libc::close(fd) };
                        None
                    }
                    None => None,
                }
            }
        };
        let Some(fd) = fd else {
            // No route, no protected descriptor: the flow cannot exist. Tell
            // the client so it can move on to a transport that works.
            self.stats.inc(&self.stats.udp_dropped);
            self.refuse_udp(pkt);
            return;
        };
        if !Self::send_udp(fd, payload) {
            unsafe { libc::close(fd) };
            self.stats.inc(&self.stats.udp_dropped);
            self.refuse_udp(pkt);
            return;
        }
        self.stats.inc(&self.stats.udp_relayed);
        self.udp_nat.lock().unwrap().insert(UdpFlow {
            fd,
            key,
            // The client's first datagram doubles as the template every reply
            // is rewritten from (addresses and ports swapped).
            template: pkt.raw[..pkt.total_len.min(pkt.raw.len())].to_vec(),
            last_ms: now_ms(),
            app_packages,
            retire: false,
            proxied,
            // The datagram that opened the mapping is already through.
            sent: payload.len() as u64,
            recv: 0,
            traffic: Some(record_flow_traffic),
        });
        // The reply can only arrive on this descriptor, so the forwarder must
        // start watching it now rather than at its next cadence tick.
        self.wake();
    }

    /// Fire-and-forget datagram send. Returns `false` only when the error
    /// means the flow itself cannot work (no route, unreachable host) — a
    /// full send buffer just loses one datagram, which UDP does anyway.
    fn send_udp(fd: RawFd, payload: &[u8]) -> bool {
        let sent = unsafe {
            libc::send(
                fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent >= 0 {
            return true;
        }
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        !matches!(err, libc::EAGAIN | libc::ENOBUFS)
    }

    // ---------------------------------------------------------------- HTTP/3

    /// Routes one UDP/443 datagram.
    ///
    /// QUIC is the one transport the engine cannot inspect without terminating
    /// it. With HTTP/3 filtering armed the flow is handed to the QUIC bridge;
    /// flows the user excluded (and apps that refuse our CA) are spliced
    /// verbatim through the ordinary NAT path; everything else keeps the old
    /// behavior — drop when `block_quic` is on, relay otherwise.
    fn handle_quic(&self, pkt: &Packet<'_>, cfg: &Config) {
        let (Some(client), Some(server)) = (pkt.src_ip(), pkt.dst_ip()) else {
            return;
        };
        if server.as_ip() == crate::mitm::proxy::local_origin_addr() {
            // The injection origin is a TCP-only local service: a QUIC probe
            // must not leak out towards a reserved address.
            return;
        }
        let key = UdpKey {
            client,
            client_port: pkt.src_port,
            server,
            server_port: pkt.dst_port,
        };
        if self.is_paused() {
            // A pause closed every terminated flow; what is left is a plain
            // datagram the paused tunnel forwards like any other.
            self.relay_udp(pkt);
            return;
        }
        // Encrypted DNS and blocked-address verdicts come first: terminating
        // DoH3 would defeat the point of blocking it.
        if self.udp_blocked(pkt, cfg) {
            self.stats.inc(&self.stats.udp_dropped);
            self.refuse_udp(pkt);
            return;
        }
        // The proxy carries TCP (and non-DNS UDP); a QUIC flow is dropped so
        // the client falls back to TCP, which the proxy filters end to end.
        let proxied = cfg
            .proxy
            .as_ref()
            .is_some_and(|p| !p.automatic || !crate::socks5::bypasses_automatic(server));
        if proxied {
            self.stats.inc(&self.stats.quic_dropped);
            self.refuse_udp(pkt);
            return;
        }
        if cfg.filter_http3 && self.mitm_ready(cfg) {
            if self.feed_h3(key, pkt) {
                return;
            }
            if self.spliced_until(key).is_some() {
                self.relay_udp(pkt);
                return;
            }
            self.open_h3(pkt, cfg, key, server);
            return;
        }
        if cfg.block_quic {
            // Encrypted DNS rides QUIC too and is unfilterable either way.
            // Dropping it strands HTTP/3-first clients — Chrome's Secure DNS
            // retries its QUIC handshake forever instead of falling back —
            // while relaying it loses nothing the filter could have seen.
            if self
                .host_for_ip(Some(server))
                .is_some_and(|host| crate::mitm::doh::is_endpoint(&host))
            {
                self.relay_udp(pkt);
                return;
            }
            self.stats.inc(&self.stats.quic_dropped);
            self.refuse_udp(pkt);
        } else {
            self.relay_udp(pkt);
        }
    }

    /// Forwards one datagram to an already terminated flow.
    ///
    /// The raw packet is also buffered until the flow's fate is decided: if the
    /// SNI turns out to be excluded, the buffered flight is replayed into a
    /// plain NAT mapping instead of costing the client a retransmission.
    fn feed_h3(&self, key: UdpKey, pkt: &Packet<'_>) -> bool {
        let Some(server) = pkt.dst_ip() else {
            return false;
        };
        let raw = &pkt.raw[..pkt.total_len.min(pkt.raw.len())];
        let mut flows = self.h3_flows.lock().unwrap();
        let Some(flow) = flows.get_mut(&key) else {
            return false;
        };
        flow.last_ms = now_ms();
        flow.sent += pkt.l4_payload().len() as u64;
        if flow.pending_bytes + raw.len() <= H3_PENDING_BYTES {
            flow.pending.push(raw.to_vec());
            flow.pending_bytes += raw.len();
        }
        flow.socket.recv(Datagram {
            peer: SocketAddr::new(key.client.as_ip(), key.client_port),
            dst_ip: Some(server.as_ip()),
            payload: pkt.l4_payload().to_vec(),
        });
        true
    }

    /// Starts terminating a new QUIC flow, or splices it when a DNS-learned
    /// host is already known to be excluded.
    fn open_h3(&self, pkt: &Packet<'_>, cfg: &Config, key: UdpKey, server: IpKey) {
        let apps = self.quic_apps(pkt);
        if self.app_blocked_reason(&apps).is_some() {
            self.stats.inc(&self.stats.udp_dropped);
            return;
        }
        if let Some(host) = self.host_for_ip(Some(server)) {
            let full_ech = cfg.full_ech;
            if let Some(reason) = self.ech_hosts.splice_reason(&host, full_ech, now_ms()) {
                crate::logbuf::push(&format!("quic {host}: spliced verbatim ({reason})"));
                self.h3_splice(key, &host);
                self.relay_udp(pkt);
                return;
            }
            if self.https_excluded(&host, &apps) {
                crate::logbuf::push(&format!(
                    "quic {host}: excluded from HTTPS filtering, splicing verbatim"
                ));
                self.h3_splice(key, &host);
                self.relay_udp(pkt);
                return;
            }
        }
        if self.h3_flows.lock().unwrap().len() >= bridge::MAX_FLOWS {
            // A full table loses the flow, like a congested NAT box; the
            // client falls back to TCP instead of hanging.
            self.stats.inc(&self.stats.quic_dropped);
            return;
        }
        let bridge = self.h3.lock().unwrap().clone();
        let Some(bridge) = bridge else {
            if cfg.block_quic {
                self.stats.inc(&self.stats.quic_dropped);
            } else {
                self.relay_udp(pkt);
            }
            return;
        };
        let info = self.h3_info(key, cfg, apps.clone());
        let Some(socket) = bridge.open(key, info) else {
            self.stats.inc(&self.stats.quic_dropped);
            return;
        };
        self.h3_flows.lock().unwrap().insert(
            key,
            H3Flow {
                socket,
                apps,
                last_ms: now_ms(),
                pending: Vec::new(),
                pending_bytes: 0,
                sent: 0,
                recv: 0,
                traffic: Some(record_flow_traffic),
            },
        );
        self.feed_h3(key, pkt);
    }

    /// Packages owning the flow, when something needs the name: app rules, the
    /// per-app firewall, HTTPS exclusions, learned CA rejections, or the log.
    fn quic_apps(&self, pkt: &Packet<'_>) -> Vec<String> {
        let needed = !self.app_network_policy.read().unwrap().is_empty()
            || self.filter.has_app_rules()
            || !self.https_skip_apps.read().unwrap().is_empty()
            || !self.ca_rejecting_apps.read().unwrap().is_empty()
            // The QUIC path logs the app on every request it blocks.
            || self.logging_live();
        if !needed {
            return Vec::new();
        }
        self.apps_for_udp(pkt)
    }

    /// The same HTTPS exclusion rules the TCP path applies: the website lists,
    /// the inverted "only" model, and the per-app skip set (including apps
    /// learned to reject the AdFree CA).
    fn https_excluded(&self, host: &str, apps: &[String]) -> bool {
        let hosts = self.https_hosts.read().unwrap();
        let excluded = hosts.skip.matches(host) || (hosts.only_mode && !hosts.only.matches(host));
        drop(hosts);
        if excluded {
            return true;
        }
        let skip_apps = self.effective_https_skip_apps();
        apps.iter().any(|app| skip_apps.contains(app))
    }

    /// The shared inputs the HTTP/3 hub reads, built from the same sources the
    /// HTTP/1.1 session uses.
    fn h3_info(&self, key: UdpKey, cfg: &Config, apps: Vec<String>) -> bridge::FlowInfo {
        let (serve_path, script_body) = {
            let scripts = self.mitm_scripts.read().unwrap();
            (scripts.serve_path().to_string(), scripts.combined_arc())
        };
        let script_tag_src = crate::mitm::proxy::script_tag_src(&serve_path, &script_body);
        bridge::FlowInfo {
            local: SocketAddr::new(key.server.as_ip(), key.server_port),
            apps,
            filter: Arc::clone(&self.filter),
            resolver: self.mitm_resolver(),
            cosmetic: cfg.cosmetic_filtering.then(|| Arc::clone(&self.filter)),
            stealth: cfg.stealth,
            upstream: self.upstream_tls_config(),
            serve_path,
            script_body,
            script_tag_src,
            sink: Some(log_http3_block),
        }
    }

    /// The client's ClientHello named an excluded host. Called on the QUIC
    /// thread, before any leaf is minted.
    pub(crate) fn h3_should_splice(&self, key: UdpKey, host: &str, apps: &[String]) -> bool {
        let full_ech = self.cfg.read().unwrap().full_ech;
        if let Some(reason) = self.ech_hosts.splice_reason(host, full_ech, now_ms()) {
            crate::logbuf::push(&format!("quic {host}: spliced verbatim ({reason})"));
            self.h3_splice(key, host);
            return true;
        }
        if self.https_excluded(host, apps) {
            self.h3_splice(key, host);
            return true;
        }
        false
    }

    /// Moves a terminated flow onto the plain NAT path and remembers the
    /// verdict, so the client's retry does not pay another handshake.
    pub(crate) fn h3_splice(&self, key: UdpKey, host: &str) {
        self.mark_spliced(key);
        let flow = self.h3_flows.lock().unwrap().remove(&key);
        if let Some(bridge) = self.h3.lock().unwrap().clone() {
            bridge.close(key);
        }
        let Some(flow) = flow else {
            return;
        };
        crate::logbuf::push(&format!(
            "quic {host}: excluded from HTTPS filtering, splicing verbatim"
        ));
        self.replay_spliced(flow);
    }

    /// No transport could be built for the flow; splice instead of hanging.
    pub(crate) fn h3_abandon(&self, key: UdpKey) {
        self.mark_spliced(key);
        let flow = self.h3_flows.lock().unwrap().remove(&key);
        let Some(flow) = flow else {
            return;
        };
        crate::logbuf::push("quic: no upstream transport, splicing the flow verbatim");
        self.replay_spliced(flow);
    }

    /// The client refused the forged certificate. Learn the app (the same list
    /// the TCP path uses) and keep the five-tuple on the raw path for its retry.
    pub(crate) fn h3_cert_rejected(&self, key: UdpKey, host: &str, apps: &[String], alert: u8) {
        if apps.is_empty() || !cert_alert_is_rejection(alert) {
            return;
        }
        self.learn_ca_rejections(apps, host);
        self.mark_spliced(key);
        let flow = self.h3_flows.lock().unwrap().remove(&key);
        if flow.is_none() {
            return;
        }
        if let Some(bridge) = self.h3.lock().unwrap().clone() {
            bridge.close(key);
        }
        crate::logbuf::push(&format!(
            "quic {host}: the client rejected the AdFree certificate, \
             splicing its QUIC verbatim from now on"
        ));
    }

    /// Sends the buffered flight of a spliced flow through a fresh NAT mapping.
    fn replay_spliced(&self, mut flow: H3Flow) {
        // `take` rather than a move: the flow still has to run its Drop, which
        // reports the datagrams that crossed the terminated half.
        for raw in std::mem::take(&mut flow.pending) {
            if let Some(pkt) = Packet::parse(&raw) {
                self.relay_udp(&pkt);
            }
        }
    }

    fn mark_spliced(&self, key: UdpKey) {
        self.h3_spliced
            .lock()
            .unwrap()
            .insert(key, now_ms() + H3_SPLICE_MS);
    }

    fn spliced_until(&self, key: UdpKey) -> Option<u64> {
        let now = now_ms();
        let mut spliced = self.h3_spliced.lock().unwrap();
        match spliced.get(&key).copied() {
            Some(until) if until > now => Some(until),
            Some(_) => {
                spliced.remove(&key);
                None
            }
            None => None,
        }
    }

    /// A protected, bound wildcard socket for the shared upstream endpoint.
    ///
    /// quinn reads `local_addr()` at construction to learn the address family,
    /// so the socket is bound explicitly instead of relying on the implicit
    /// bind the first `sendto` would do.
    pub(crate) fn open_upstream_quic_socket(&self, ipv6: bool) -> Option<std::net::UdpSocket> {
        use std::os::unix::io::FromRawFd;
        let family = if ipv6 { libc::AF_INET6 } else { libc::AF_INET };
        let fd = unsafe {
            libc::socket(
                family,
                libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            crate::logbuf::push("quic: upstream socket() failed");
            return None;
        }
        if !self.protect_socket(fd) {
            unsafe { libc::close(fd) };
            crate::logbuf::push("quic: the app refused to protect the upstream socket");
            return None;
        }
        let bound = unsafe {
            if ipv6 {
                let addr = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr { s6_addr: [0u8; 16] },
                    sin6_scope_id: 0,
                };
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            } else {
                let addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr { s_addr: 0 },
                    sin_zero: [0; 8],
                };
                libc::bind(
                    fd,
                    &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        };
        if bound != 0 {
            crate::logbuf::push("quic: upstream bind() failed");
            unsafe { libc::close(fd) };
            return None;
        }
        Some(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
    }

    /// Turns datagrams quinn produced into packets for the tun.
    ///
    /// The bridge reports the source (the original server address) and the
    /// destination (the client); rebuilding the packet here is what lets the
    /// endpoint be socketless on the client side.
    fn drain_quic(&self) {
        let bridge = self.h3.lock().unwrap().clone();
        let Some(bridge) = bridge else {
            return;
        };
        let mut out = Vec::with_capacity(16);
        bridge.drain(&mut out, H3_DRAIN_MAX);
        for datagram in out {
            let src = packet::ip_key_from(datagram.source.ip());
            let dst = packet::ip_key_from(datagram.destination.ip());
            if src.as_ip().is_unspecified() || dst.as_ip().is_unspecified() {
                continue;
            }
            // The client's five-tuple is still the key here, so a datagram
            // quinn produced is attributed to its flow before it is built.
            let key = UdpKey {
                client: dst,
                client_port: datagram.destination.port(),
                server: src,
                server_port: datagram.source.port(),
            };
            if let Some(flow) = self.h3_flows.lock().unwrap().get_mut(&key) {
                flow.recv += datagram.payload.len() as u64;
            }
            let Some(raw) = packet::build_udp(
                src,
                datagram.source.port(),
                dst,
                datagram.destination.port(),
                &datagram.payload,
            ) else {
                continue;
            };
            self.stats.inc(&self.stats.udp_relayed);
            self.write_raw(&raw);
        }
    }

    /// Reaps idle terminated flows and lapsed splice verdicts.
    fn expire_quic(&self, now: u64) {
        let expired = {
            let mut flows = self.h3_flows.lock().unwrap();
            let expired: Vec<UdpKey> = flows
                .iter()
                .filter(|(_, flow)| now.saturating_sub(flow.last_ms) >= H3_IDLE_MS)
                .map(|(key, _)| *key)
                .collect();
            for key in &expired {
                flows.remove(key);
            }
            expired
        };
        if !expired.is_empty() {
            if let Some(bridge) = self.h3.lock().unwrap().clone() {
                for key in expired {
                    bridge.close(key);
                }
            }
        }
        self.h3_spliced
            .lock()
            .unwrap()
            .retain(|_, until| *until > now);
    }

    /// Drops every terminated flow (pause, switch-off, CA change, firewall).
    fn close_h3_flows(&self) {
        let flows = std::mem::take(&mut *self.h3_flows.lock().unwrap());
        if flows.is_empty() {
            return;
        }
        if let Some(bridge) = self.h3.lock().unwrap().clone() {
            for key in flows.keys() {
                bridge.close(*key);
            }
        }
    }

    /// Spawns the QUIC thread for this session. Returns the handle so `start`
    /// joins it like the other workers.
    pub(crate) fn start_h3(&'static self) -> Option<std::thread::JoinHandle<()>> {
        let (bridge, worker) = bridge::Bridge::start(bridge::CoreHost::new(self))?;
        *self.h3.lock().unwrap() = Some(bridge);
        Some(worker)
    }

    /// Stops the QUIC thread and closes every terminated flow. Idempotent: a
    /// second call finds neither flows nor a bridge.
    pub(crate) fn stop_h3(&self) {
        self.close_h3_flows();
        self.h3_spliced.lock().unwrap().clear();
        let bridge = self.h3.lock().unwrap().take();
        if let Some(bridge) = bridge {
            bridge.shutdown();
        }
    }

    /// Feeds a packet to its relay, if one owns the flow.
    ///
    /// Returns true when the packet was consumed; false means there is no
    /// relay for this flow and the caller decides what happens next.
    fn relay_tcp(&self, pkt: &Packet<'_>, out: &mut Vec<Vec<u8>>) -> bool {
        let port = pkt.src_port;
        if pkt.is_syn {
            // A retransmitted SYN for a live relay: answer again without
            // disturbing the flow (the first answer may have been lost).
            let existing = {
                let guard = self.relays.lock().unwrap();
                guard.get(port).filter(|r| !r.closed).map(|relay| {
                    (
                        relay.syn_packet.clone(),
                        relay.flow.my_seq,
                        relay.flow.acked_seq,
                    )
                })
            };
            let Some((syn_packet, my_seq, acked_seq)) = existing else {
                return false;
            };
            if let Some(template) = Packet::parse(&syn_packet) {
                if let Some(reply) =
                    crate::mitm::segment::build_ack(&template, my_seq, acked_seq, true)
                {
                    out.push(reply);
                }
            }
            return true;
        }
        if pkt.is_rst {
            // The client gave up: retire the flow quietly. The entry is only
            // marked here; the poller thread is the one that reaps relays and
            // closes their descriptors, so a descriptor is never yanked from
            // under a concurrent poll().
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(port) else {
                return false;
            };
            relay.close();
            return true;
        }
        // Work on the relay under the lock, collect what has to go out, then
        // release before pushing (which locks the table itself).
        let mut to_peer = Vec::new();
        let mut reset = false;
        let mut refused = false;
        let mut fin_pending = false;
        let resumed;
        {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(port) else {
                return false;
            };
            if relay.closed {
                // Finished, waiting to be reaped: consume silently.
                return true;
            }
            // Every packet from the client carries an ACK and a window: this
            // is what funds the bytes we still owe it, so a ~600 KB script
            // body leaves in window-sized bursts, one burst per ACK.
            relay.on_client_ack(pkt.ack_seq, pkt.window);
            let payload = pkt.l4_payload();
            // While the upstream half is being built, client bytes are only
            // buffered: the replay on the setup worker is what acknowledges
            // them, through the session the flow will actually use.
            if relay.setup_pending && !payload.is_empty() {
                if relay.pending_client_bytes + payload.len() <= MAX_PENDING_CLIENT_SETUP {
                    relay.pending_client_bytes += payload.len();
                    relay.pending_client.push((pkt.seq, payload.to_vec()));
                }
                return true;
            }
            let mut saw_data = false;
            if !payload.is_empty() {
                match relay.on_client_segment(pkt.seq, payload) {
                    Ok((peer_bytes, to_client)) => {
                        to_peer = peer_bytes;
                        saw_data = true;
                        // A session that closed itself with nothing to say
                        // refused the flow; it is not a normal finish.
                        refused = relay.closed && to_client.is_empty();
                        relay.queue_to_client(&to_client);
                    }
                    Err(e) => {
                        // Name the flow: without the host these errors (a
                        // pinned client rejecting the forged certificate, say)
                        // are impossible to tell apart in the log.
                        let host = relay
                            .session
                            .as_ref()
                            .and_then(|s| s.captured_sni())
                            .unwrap_or_else(|| "?".to_string());
                        crate::logbuf::push(&format!("relay client step: {e} ({host})"));
                        // A client that does not trust the AdFree CA would
                        // lose every HTTPS page; the next flow of that app is
                        // spliced instead of decrypted.
                        self.note_client_cert_rejection(&e, &relay.app_packages, &host);
                        if let Some(rst) = relay.rst_to_client() {
                            out.push(rst);
                        }
                        reset = true;
                    }
                }
            }
            // Flush whatever the window now takes. A pure ACK lands here too:
            // it is exactly the event that opens the window further.
            let was_paused = relay.client_paused;
            for segment in relay.flush_to_client() {
                out.push(segment);
            }
            // The peer was left out of the wait set while the backlog was at
            // its cap; the forwarder has to re-arm it now that ACKs drained
            // the queue below the low-water mark.
            resumed = was_paused && !relay.client_paused;
            if refused {
                // The session refused the flow itself (a ClientHello naming
                // a blocked host): a reset is what makes the client's request
                // fail instead of waiting on a flow nobody will answer.
                if let Some(rst) = relay.rst_to_client() {
                    out.push(rst);
                }
                reset = true;
            }
            if reset {
                relay.close();
            } else if pkt.is_fin && !relay.client_fin {
                if let Some(ack) = relay.on_client_fin() {
                    out.push(ack);
                }
                fin_pending = true;
            } else if saw_data {
                // A plain splice produces no reply of its own, so without this
                // bare ACK the client keeps retransmitting its request (and
                // the retransmissions must then be filtered by `seq`).
                if let Some(ack) = relay.ack_to_client() {
                    out.push(ack);
                }
            }
        }
        if reset {
            return true;
        }
        if resumed {
            self.wake();
        }
        if !to_peer.is_empty() {
            self.push_to_peer(port, &to_peer);
        }
        if fin_pending {
            // Half-close the peer's write side, but only once everything the
            // client sent has actually been handed to the socket: writes are
            // refused after the shutdown.
            self.half_close_peer(port);
        }
        // Anything else on a live relay (bare ACKs, window updates, the FIN we
        // just acknowledged) is consumed here: falling through would let
        // `tcp_blocked` reset a flow the engine itself owns.
        true
    }

    /// Sends FIN towards the peer, deferring it if unsent bytes are queued.
    fn half_close_peer(&self, client_port: u16) {
        let fd = {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(client_port) else {
                return;
            };
            if !relay.pending_to_peer.is_empty() || relay.flushing {
                relay.shutdown_after_flush = true;
                return;
            }
            // A flow still waiting for its upstream half has no descriptor
            // yet; the install closes its write side once the socket exists.
            relay.peer_fd
        };
        if fd < 0 {
            return;
        }
        unsafe {
            libc::shutdown(fd, libc::SHUT_WR);
        }
    }

    /// The largest payload one segment towards the client may carry.
    ///
    /// The client's own MSS is authoritative (its stack drops anything bigger)
    /// and the tunnel MTU is the hard ceiling.
    fn relay_mss(&self, pkt: &Packet<'_>) -> usize {
        let cap = if pkt.version == 4 { 1460 } else { 1440 };
        pkt.tcp_mss().map(|m| (m as usize).min(cap)).unwrap_or(cap)
    }

    /// Answers a new TCP flow and queues its upstream half.
    ///
    /// The SYN-ACK goes out here, before any of the expensive work: the
    /// client's handshake completes on it, and the rest (app attribution
    /// through the platform, `protect()`, the dial, the TLS session) runs on
    /// the setup worker. Doing that work inline would make every `connect()`
    /// wait for the previous flow's setup.
    ///
    /// Port 443 is additionally TLS-terminated (and filtered) when HTTPS
    /// filtering is armed and the destination hostname is known; every other
    /// flow is a transparent splice. The one exception is the app's own
    /// injection origin: it is answered locally, with no peer socket at all.
    fn begin_tcp_relay(
        &self,
        pkt: &Packet<'_>,
        cfg: &Config,
        out: &mut Vec<Vec<u8>>,
    ) -> RelayStart {
        let Some(client_ip) = pkt.src_ip() else {
            return RelayStart::Failed;
        };
        if pkt.dst_ip().is_none() {
            return RelayStart::Failed;
        }
        let mut flow = crate::mitm::tcp::Flow::new(
            client_ip,
            pkt.src_port,
            pkt.dst_port,
            pkt.seq,
            crate::mitm::tcp::initial_seq(pkt.seq as u64),
        );
        let my_seq = flow.my_seq;
        let Some(syn_ack) = crate::mitm::segment::build_ack(pkt, my_seq, flow.acked_seq, true)
        else {
            return RelayStart::Failed;
        };
        // With a tunnel attached the answer goes out now. Without one (tests)
        // it is collected like any other reply for whoever inspects them.
        if self.tun_fd.load(Ordering::SeqCst) > 0 {
            self.write_raw(&syn_ack);
        } else {
            out.push(syn_ack);
        }
        // The handshake we just answered consumed one sequence number.
        flow.up_bytes = 1;
        let mss = self.relay_mss(pkt);
        let mut relay =
            crate::mitm::relay::Relay::new_plain(flow, -1, pkt.raw.to_vec(), mss, true);
        relay.setup_pending = true;
        // The relay reports what crossed it when it retires; nothing else knows
        // both byte totals of one connection.
        relay.traffic = Some(record_flow_traffic);
        {
            let mut guard = self.relays.lock().unwrap();
            if guard.get(pkt.src_port).is_some() {
                // A finished relay for this port is waiting for the poller to
                // reap it. Inserting now would swap it out from under a
                // concurrent poll(), so the answered flow is refused instead.
                drop(guard);
                self.refuse_answered_flow(pkt, my_seq, None);
                return RelayStart::Answered;
            }
            guard.insert(relay);
        }
        self.setup_jobs.lock().unwrap().push_back(SetupJob {
            port: pkt.src_port,
            my_seq,
            syn: pkt.raw.to_vec(),
            cfg: cfg.clone(),
        });
        self.poke_setup();
        RelayStart::Started
    }

    /// Builds the upstream half of an answered flow, or refuses it.
    ///
    /// Runs on the setup worker: nothing here may hold the relay table across
    /// the platform round-trips or the dial — the packet reader keeps feeding
    /// every other flow meanwhile.
    fn complete_setup(&self, job: SetupJob) {
        let cfg = &job.cfg;
        let Some(pkt) = Packet::parse(&job.syn) else {
            return;
        };
        let Some(dst) = pkt.dst_ip() else {
            return;
        };
        if !self.pending_relay(job.port, job.my_seq) {
            return;
        }
        // The per-app firewall decides before any socket is opened: a blocked
        // app costs no upstream connection and is told why.
        let app_packages = self.apps_for_packet(&pkt, cfg);
        if let Some(reason) = self.app_blocked_reason(&app_packages) {
            self.refuse_setup(&pkt, job.port, job.my_seq, Some(reason));
            return;
        }
        // The local injection origin: a reserved address (TEST-NET-1) that the
        // app answers out of the tunnel. Nothing is ever dialed for it — and
        // without TLS termination there is nothing to answer with, so a stray
        // connection is refused instead of leaking a SYN to a documentation
        // address.
        let local = dst.as_ip() == crate::mitm::proxy::local_origin_addr();
        let mitm_armed =
            self.mitm_ready(cfg) && pkt.dst_port == self.mitm_port.load(Ordering::Relaxed);
        if local && !mitm_armed {
            crate::logbuf::push("relay: local origin asked without HTTPS filtering");
            self.refuse_setup(&pkt, job.port, job.my_seq, None);
            return;
        }
        // In proxy mode every flow dials the SOCKS5 endpoint; the destination
        // moves into the CONNECT request instead of the socket address. The
        // local injection origin never leaves the device, so it stays direct.
        // Automatic routing also keeps LAN and other non-internet addresses
        // off the proxy: a remote endpoint cannot reach them anyway. A per-app
        // DIRECT rule overrides all of that; a THROUGH rule pins the app to
        // the proxy even when it is not the global default.
        let policy = Arc::clone(&*self.app_network_policy.read().unwrap());
        let through = !local && policy.proxy_through(&app_packages, cfg.proxy.is_some());
        let proxy = if through {
            cfg.proxy
                .clone()
                .filter(|p| !p.automatic || !crate::socks5::bypasses_automatic(dst))
        } else {
            None
        };
        let handshake = match &proxy {
            Some(p) => match Socks5Handshake::new(dst, pkt.dst_port, p.credentials()) {
                Ok(h) => Some(h),
                Err(e) => {
                    crate::logbuf::push(&format!("relay: {e}"));
                    self.refuse_setup(&pkt, job.port, job.my_seq, None);
                    return;
                }
            },
            None => None,
        };
        let (dial_addr, dial_port) = match &proxy {
            Some(p) => (p.addr, p.port),
            None => (dst, pkt.dst_port),
        };
        let (peer_fd, connecting) = if local {
            (-1, false)
        } else {
            let Some(peer_fd) = self.open_peer_socket(dial_addr, libc::SOCK_STREAM) else {
                self.refuse_setup(&pkt, job.port, job.my_seq, None);
                return;
            };
            let connect = connect_fd(peer_fd, dial_addr, dial_port);
            if connect == Connect::Failed {
                crate::logbuf::push(if proxy.is_some() {
                    "relay: connect() to the SOCKS5 proxy failed"
                } else {
                    "relay: connect() to the peer failed"
                });
                unsafe { libc::close(peer_fd) };
                self.refuse_setup(&pkt, job.port, job.my_seq, None);
                return;
            }
            (peer_fd, connect == Connect::InProgress)
        };
        // TLS termination needs a loaded CA. The hostname to present upstream
        // comes from the ClientHello itself, not from the DNS table: a
        // browser's own cache, DoH or a shared CDN address can put a flow on
        // an address we never learned, and filtering must not silently skip
        // those. Without a CA the flow is still relayed, just not filtered
        // (protecting the user beats breaking their pages).
        let session = if local {
            // The injection origin is the app: TLS terminates here and every
            // request is answered from the same tables the HTML rewrite uses.
            let (script_path, script_body) = {
                let scripts = self.mitm_scripts.read().unwrap();
                (scripts.serve_path().to_string(), scripts.combined_arc())
            };
            match crate::mitm::proxy::ProxySession::new_local(
                self.mitm_resolver(),
                script_path,
                script_body,
            ) {
                Ok(mut proxy) => {
                    if cfg.cosmetic_filtering {
                        proxy.set_cosmetic(self.filter.clone());
                    }
                    proxy.set_stats(Arc::clone(&self.stats));
                    Some(proxy)
                }
                Err(e) => {
                    crate::logbuf::push(&format!("open local session: {e}"));
                    self.refuse_setup(&pkt, job.port, job.my_seq, None);
                    return;
                }
            }
        } else if mitm_armed {
            let (script_path, script_body) = {
                let scripts = self.mitm_scripts.read().unwrap();
                (scripts.serve_path().to_string(), scripts.combined_arc())
            };
            match crate::mitm::proxy::ProxySession::new_pending(
                self.mitm_resolver(),
                self.upstream_tls_config(),
                script_path,
                script_body,
            ) {
                Ok(mut proxy) => {
                    // Cosmetic filtering rides along with HTTPS filtering:
                    // same opt-in, same CA gate, and the user can turn the
                    // element hiding off without disabling the TLS rewrite.
                    if cfg.cosmetic_filtering {
                        proxy.set_cosmetic(self.filter.clone());
                    }
                    // Stealth request edits (UTM, cookies, user agent) are
                    // decided per flow, like cosmetics.
                    proxy.set_stealth(cfg.stealth);
                    // Timing counters (TLS cost, rewrite cost) land in the same
                    // snapshot the UI already polls once a second.
                    proxy.set_stats(Arc::clone(&self.stats));
                    // Requests the session answers itself (URL-scoped blocks,
                    // `$redirect` resources) belong in the app's log.
                    proxy.set_sink(log_mitm_block);
                    // Who the flow belongs to, resolved once at SYN time: the
                    // platform names the app the `$app=` rules are about, and
                    // the flow keeps that name for as long as it lives.
                    proxy.set_apps(app_packages.clone());
                    // Per-app HTTPS exclusions: decided once per flow, like
                    // the app name, and read before any byte reaches rustls.
                    proxy.set_https_skip_apps(self.effective_https_skip_apps());
                    // ECH: which hosts had their ECHConfig rewritten away, so
                    // a refusal from one of them can be learned as "requires
                    // ECH" (see `mitm::ech`).
                    proxy.set_ech_hosts(Arc::clone(&self.ech_hosts), cfg.full_ech);
                    let https = self.https_hosts.read().unwrap().clone();
                    proxy.set_https_hosts(https.skip, https.only, https.only_mode);
                    // The TLS half learns the hostname before the first
                    // request exists. Hand it the same lists the DNS half
                    // uses, so a host that reached it without a lookup
                    // (Secure DNS, the client's own cache) is refused at the
                    // handshake, the way the resolver's NXDOMAIN would.
                    proxy.set_host_filter(Arc::clone(&self.filter));
                    Some(proxy)
                }
                Err(e) => {
                    crate::logbuf::push(&format!("open tls session: {e}"));
                    None
                }
            }
        } else {
            None
        };
        self.install_upstream(
            job.port,
            job.my_seq,
            UpstreamHalf {
                peer_fd,
                connecting,
                session,
                app_packages,
                proxy,
                handshake,
            },
        );
    }

    /// Installs a completed upstream half on its answered flow and replays
    /// whatever the client sent while it was being built.
    ///
    /// The relay entry itself was inserted by [`Self::begin_tcp_relay`], which
    /// is what lets the reader buffer client bytes without a gap: from the
    /// SYN-ACK on, the flow already exists.
    fn install_upstream(&self, port: u16, my_seq: u32, half: UpstreamHalf) {
        let UpstreamHalf {
            peer_fd,
            connecting,
            session,
            app_packages,
            proxy,
            handshake,
        } = half;
        let mut segments = Vec::new();
        let mut to_peer = Vec::new();
        let mut reset = false;
        let replayed;
        let mut fin = false;
        {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(port) else {
                // The flow was retired (client reset, idle expiry) while its
                // half was being built: the descriptor is ours to close.
                drop(guard);
                if peer_fd >= 0 {
                    unsafe { libc::close(peer_fd) };
                }
                return;
            };
            if relay.closed || relay.flow.my_seq != my_seq {
                drop(guard);
                if peer_fd >= 0 {
                    unsafe { libc::close(peer_fd) };
                }
                return;
            }
            relay.peer_fd = peer_fd;
            relay.connecting = connecting;
            relay.session = session;
            relay.app_packages = app_packages;
            relay.proxy = proxy;
            relay.handshake = handshake;
            relay.setup_pending = false;
            relay.last_ms = now_ms();
            let pending = std::mem::take(&mut relay.pending_client);
            relay.pending_client_bytes = 0;
            replayed = !pending.is_empty();
            for (seq, payload) in pending {
                match relay.on_client_segment(seq, &payload) {
                    Ok((peer_bytes, to_client)) => {
                        to_peer.extend_from_slice(&peer_bytes);
                        for segment in relay.segments_for_client(&to_client) {
                            segments.push(segment);
                        }
                    }
                    Err(e) => {
                        let host = relay
                            .session
                            .as_ref()
                            .and_then(|s| s.captured_sni())
                            .unwrap_or_else(|| "?".to_string());
                        crate::logbuf::push(&format!("relay client step: {e} ({host})"));
                        self.note_client_cert_rejection(&e, &relay.app_packages, &host);
                        if let Some(rst) = relay.rst_to_client() {
                            segments.push(rst);
                        }
                        reset = true;
                        break;
                    }
                }
            }
            if reset {
                relay.close();
            } else {
                fin = relay.client_fin;
                if replayed {
                    // Replayed bytes need their own acknowledgement, exactly
                    // like the reader's data path; without it a plain splice
                    // never stops retransmitting the request.
                    if let Some(ack) = relay.ack_to_client() {
                        segments.push(ack);
                    }
                }
            }
        }
        if reset {
            for segment in &segments {
                self.write_raw(segment);
            }
            return;
        }
        for segment in &segments {
            self.write_raw(segment);
        }
        if !to_peer.is_empty() {
            self.push_to_peer(port, &to_peer);
        }
        if fin {
            // The client half-closed while its half was being built; the FIN
            // can only go out now that the peer descriptor exists.
            self.half_close_peer(port);
        }
        // The peer descriptor has to join the wait set before the server can
        // possibly answer: waking here is what makes a long forwarder wait
        // safe, including for a connect() that finishes after the poll began.
        self.wake();
        self.stats.inc(&self.stats.tcp_relayed);
    }

    /// Is this flow still waiting for its upstream half, under the ISN it was
    /// answered with? A reused client port must not receive another flow's
    /// session.
    fn pending_relay(&self, port: u16, my_seq: u32) -> bool {
        self.relays
            .lock()
            .unwrap()
            .get(port)
            .is_some_and(|r| r.setup_pending && !r.closed && r.flow.my_seq == my_seq)
    }

    /// Refuses a flow whose upstream half failed, after its SYN-ACK went out:
    /// the reset sits in the client's window, and the relay is marked closed
    /// so the poller reaps it.
    fn refuse_setup(&self, pkt: &Packet<'_>, port: u16, my_seq: u32, reason: Option<&'static str>) {
        self.refuse_answered_flow(pkt, my_seq, reason);
        if let Some(relay) = self.relays.lock().unwrap().get_mut(port) {
            relay.close();
        }
    }

    /// Builds every queued upstream half. Tests call this directly (through
    /// `pump_once`) because they never start threads; the device has the
    /// setup worker do the same in [`setup_loop`].
    #[cfg(test)]
    fn run_setup_jobs(&self) {
        while let Some(job) = self.setup_jobs.lock().unwrap().pop_front() {
            self.complete_setup(job);
        }
    }

    /// Opens a non-blocking socket towards `dst` and asks the app to route it
    /// around the VPN. Without protection the socket would loop right back
    /// into the tunnel, so it is closed and the call fails.
    fn open_peer_socket(&self, dst: IpKey, kind: libc::c_int) -> Option<RawFd> {
        let family = match dst {
            IpKey::V4(_) => libc::AF_INET,
            IpKey::V6(_) => libc::AF_INET6,
        };
        let fd =
            unsafe { libc::socket(family, kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            crate::logbuf::push("relay: socket() failed");
            return None;
        }
        if !self.protect_socket(fd) {
            unsafe { libc::close(fd) };
            crate::logbuf::push("relay: the app refused to protect a peer socket");
            return None;
        }
        Some(fd)
    }

    /// Wires one mapping to a SOCKS5 UDP ASSOCIATE thread. The returned
    /// descriptor is the engine end of a `SEQPACKET` pair; the thread owns the
    /// protected sockets that reach the proxy and does the relaying, so the
    /// poll loop only sees plain server payloads on this descriptor.
    fn open_proxied_udp(
        &self,
        server: IpKey,
        server_port: u16,
        proxy: Arc<crate::socks5::ProxyEndpoint>,
    ) -> Option<RawFd> {
        let protector = self.socket_protector.lock().unwrap().clone()?;
        let mut fds = [0 as RawFd; 2];
        let paired = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        if paired != 0 {
            crate::logbuf::push("udp relay: socketpair() failed");
            return None;
        }
        if let Err(error) = crate::udpproxy::spawn(fds[1], proxy, protector, server, server_port) {
            crate::logbuf::push(&format!(
                "udp relay: cannot start the proxy thread: {error}"
            ));
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return None;
        }
        Some(fds[0])
    }

    /// Installs the app-side protector new sockets are handed to.
    pub fn set_socket_protector(&self, protector: Arc<dyn crate::api::SocketProtector>) {
        *self.socket_protector.lock().unwrap() = Some(protector);
    }

    /// Hands one descriptor to the app so it bypasses the VPN.
    fn protect_socket(&self, fd: RawFd) -> bool {
        let protector = self.socket_protector.lock().unwrap().clone();
        match protector {
            Some(p) => p.protect(fd),
            None => false,
        }
    }

    /// Buffers client bytes for a relay's peer socket and pushes them out.
    ///
    /// `send()` returning EAGAIN is normal (the peer accepts slower than the
    /// client produces): whatever the socket refuses stays queued and
    /// `poll_relays` retries when the socket becomes writable.
    fn push_to_peer(&self, client_port: u16, bytes: &[u8]) {
        let overflow = {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(client_port) else {
                return;
            };
            relay.queue_to_peer(bytes);
            relay.pending_to_peer.len() > MAX_PENDING_TO_PEER
        };
        if overflow {
            // A peer that never drains would let the queue grow without bound;
            // the flow is broken anyway, so cut it.
            crate::logbuf::push("relay: peer socket never drains");
            let segment = {
                let mut guard = self.relays.lock().unwrap();
                let Some(relay) = guard.get_mut(client_port) else {
                    return;
                };
                let segment = relay.rst_to_client();
                relay.close();
                segment
            };
            if let Some(segment) = segment {
                self.write_raw(&segment);
            }
            return;
        }
        self.flush_peer(client_port);
        // Bytes the socket refused stay queued; the forwarder has to rebuild
        // its wait set with POLLOUT on this relay, and the wake makes it do
        // that now instead of after the long timeout.
        let still_queued = self
            .relays
            .lock()
            .unwrap()
            .get(client_port)
            .is_some_and(|relay| !relay.pending_to_peer.is_empty());
        if still_queued {
            self.wake();
        }
    }

    /// Drains a relay's queued client bytes towards its peer socket.
    ///
    /// While a SOCKS5 handshake runs, only its own bytes go out: application
    /// data waits so a proxy reply can never be mistaken for origin data.
    /// Only one thread is ever inside `send()` for a relay (`flushing`), so the
    /// byte stream order the client produced is preserved.
    fn flush_peer(&self, client_port: u16) {
        loop {
            let (fd, chunk, handshake) = {
                let mut guard = self.relays.lock().unwrap();
                let Some(relay) = guard.get_mut(client_port) else {
                    return;
                };
                if relay.connecting || relay.flushing {
                    return;
                }
                match relay.handshake.as_mut() {
                    Some(hs) if !hs.is_done() => {
                        let out = hs.take_output();
                        if out.is_empty() {
                            return; // waiting for the proxy's next reply
                        }
                        relay.flushing = true;
                        (relay.peer_fd, out, true)
                    }
                    _ => {
                        if relay.pending_to_peer.is_empty() {
                            return;
                        }
                        relay.flushing = true;
                        (
                            relay.peer_fd,
                            std::mem::take(&mut relay.pending_to_peer),
                            false,
                        )
                    }
                }
            };
            let written = self.write_some(fd, &chunk);
            let (more, half_close) = {
                let mut guard = self.relays.lock().unwrap();
                let Some(relay) = guard.get_mut(client_port) else {
                    return;
                };
                relay.flushing = false;
                if written < chunk.len() {
                    // Prepend the unwritten remainder: anything queued while we
                    // were writing came later in the stream.
                    if handshake {
                        if let Some(hs) = relay.handshake.as_mut() {
                            hs.requeue_output(&chunk[written..]);
                        }
                    } else {
                        let mut rest = chunk[written..].to_vec();
                        rest.extend_from_slice(&relay.pending_to_peer);
                        relay.pending_to_peer = rest;
                    }
                }
                if handshake {
                    // Handshake output has no FIN semantics; a writable wake
                    // returns if the proxy has not answered yet.
                    (false, false)
                } else {
                    let drained = relay.pending_to_peer.is_empty();
                    // A FIN that surfaced while we were writing is owed now
                    // that the queue is empty.
                    let half_close = drained && relay.shutdown_after_flush;
                    if half_close {
                        relay.shutdown_after_flush = false;
                    }
                    (!drained, half_close)
                }
            };
            if half_close {
                unsafe {
                    libc::shutdown(fd, libc::SHUT_WR);
                }
            }
            if written == chunk.len() && more {
                continue; // the callers queued more while we were writing
            }
            return;
        }
    }

    /// Writes as much as the socket accepts; returns how many bytes were taken.
    fn write_some(&self, fd: RawFd, bytes: &[u8]) -> usize {
        let mut off = 0;
        while off < bytes.len() {
            let n = unsafe {
                libc::send(
                    fd,
                    bytes.as_ptr().add(off) as *const libc::c_void,
                    bytes.len() - off,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n <= 0 {
                break;
            }
            off += n as usize;
        }
        off
    }

    /// `Some(rule)` when the flow must be refused, naming the reason the log
    /// will show. The label is decided here, where the cause is known, so a
    /// failed relay is never reported as an encrypted-DNS block.
    fn tcp_blocked(&self, pkt: &Packet<'_>, cfg: &Config) -> Option<&'static str> {
        if self.is_paused() {
            return None;
        }
        let dst = pkt.dst_ip()?;
        // TURN over TCP/TLS rides the same signalling ports as the UDP half.
        if cfg.stealth.blocks_web_rtc() && crate::mitm::stealth::is_webrtc_port(pkt.dst_port) {
            return Some("WebRTC blocked");
        }
        // DoT over TCP bypasses the DNS filter exactly like the UDP port does.
        if cfg.block_dot && pkt.dst_port == 853 {
            return Some("connection to encrypted DNS blocked");
        }
        // DoH is HTTPS. The provider ranges also carry plain DNS and DoT
        // endpoints (1.1.1.1:853, 8.8.8.8:53); matching every port there would
        // break Private DNS in strict mode, which has no UDP fallback.
        if cfg.block_doh && pkt.dst_port == 443 && self.is_encrypted_dns_elsewhere(dst) {
            return Some("connection to encrypted DNS blocked");
        }
        let conn = self.conntrack.lock().unwrap();
        let verdict = conn.lookup(&dst, now_ms());
        drop(conn);
        // The address came from a DNS answer learned as blocked. An app
        // that keeps dialling it is the retry loop smart filtering exists
        // for: once the host trips the limit the SYN is relayed as usual.
        match verdict {
            IpVerdict::Blocked { host } => {
                if self.smart.lock().unwrap().note_blocked(&host) {
                    None
                } else {
                    Some("connection dropped")
                }
            }
            _ => None,
        }
    }

    fn udp_blocked(&self, pkt: &Packet<'_>, cfg: &Config) -> bool {
        if self.is_paused() {
            return false;
        }
        let Some(dst) = pkt.dst_ip() else {
            return false;
        };
        // DoH3 runs on UDP 443. The same provider ranges answer plain DNS on
        // port 53, which the filter has to be able to inspect itself.
        if cfg.block_doh && pkt.dst_port == 443 && self.is_encrypted_dns_elsewhere(dst) {
            return true;
        }
        let conn = self.conntrack.lock().unwrap();
        matches!(conn.lookup(&dst, now_ms()), IpVerdict::Blocked { .. })
    }

    /// Kills a connection locally with a RST: the app fails on the spot instead
    /// of waiting for a connect timeout, and no traffic was ever spent.
    fn reset_tcp(&self, pkt: &Packet<'_>) {
        self.reset_tcp_inner(pkt, None);
    }

    /// Same reset, but the log names the per-app firewall rule that refused
    /// the flow.
    fn reset_tcp_with_reason(&self, pkt: &Packet<'_>, reason: &'static str) {
        self.reset_tcp_inner(pkt, Some(reason));
    }

    fn reset_tcp_inner(&self, pkt: &Packet<'_>, reason: Option<&'static str>) {
        let Some(reply) = packet::build_rst(pkt) else {
            return;
        };
        if !self.write_raw(&reply) {
            return;
        }
        self.record_tcp_reset(pkt, reason);
    }

    /// Refuses a flow whose SYN-ACK is already on the wire.
    ///
    /// The reset has to carry our own sequence number: the client's stack is
    /// ESTABLISHED by now, and a reset built from its SYN again (as
    /// [`reset_tcp_inner`] does) would be dropped as out of window, leaving it
    /// to time out instead of seeing the refusal.
    fn refuse_answered_flow(&self, pkt: &Packet<'_>, my_seq: u32, reason: Option<&'static str>) {
        let Some(reply) = crate::mitm::segment::build_rst(pkt, my_seq) else {
            return;
        };
        if !self.write_raw(&reply) {
            return;
        }
        self.record_tcp_reset(pkt, reason);
    }

    /// Counts and logs a refused flow whose reset has already been sent.
    fn record_tcp_reset(&self, pkt: &Packet<'_>, reason: Option<&'static str>) {
        self.stats.inc(&self.stats.tcp_reset);
        let saved = BYTES_PER_BLOCKED_REQUEST;
        self.stats.add(&self.stats.bytes_saved, saved);
        let host = self
            .host_for_ip(pkt.dst_ip())
            .unwrap_or_else(|| pkt.dst_ip_text());
        let rule = reason.unwrap_or("connection dropped");
        let category = if rule.contains("DNS") {
            crate::filter::CAT_TRACKER
        } else {
            crate::filter::CAT_AD
        };
        let app_packages = if self.logging_live() {
            self.resolve_tcp_apps(pkt)
        } else {
            Vec::new()
        };
        let event = events::with_app(
            events::block_event(
                events::ACTION_TCP_RESET,
                &host,
                // The port belongs to the destination: AdGuard's log shows the
                // connection as `ip:port`, not the bare address.
                &format!("{}:{}", pkt.dst_ip_text(), pkt.dst_port),
                rule,
                "Protection",
                category,
                0,
                saved as u32,
                pkt.version == 6,
            ),
            first_app(&app_packages),
        );
        self.log_event(event);
    }

    /// Answers a dropped datagram with ICMP port unreachable.
    ///
    /// A quiet drop makes a QUIC sender keep retrying its handshake instead of
    /// moving to the TCP flow the filter can see; Chrome's Secure DNS is
    /// HTTP/3 first and never falls back without this, leaving the browser
    /// with no DNS at all.
    fn refuse_udp(&self, pkt: &Packet<'_>) {
        if let Some(reply) = packet::build_unreachable(pkt) {
            self.write_raw(&reply);
        }
    }

    fn handle_dns(&self, pkt: &Packet<'_>, cfg: &Config, out: &mut Vec<Vec<u8>>) {
        let Some(query) = dns::parse_query(pkt.l4_payload()) else {
            // Malformed: forwarding is the safest reaction.
            self.forward_query(pkt, None, None);
            return;
        };
        if !query.is_query() {
            return;
        }
        if !query.has_question {
            self.forward_query(pkt, Some(&query), None);
            return;
        }

        let host = query.qname.as_str();
        // Attribution is resolved at most once per query: the app firewall may
        // already have needed it, and the log needs it for whatever event this
        // query produces.
        let mut app_packages: Option<Vec<String>> = None;
        // The app firewall runs before the lists: an app barred from this
        // network must not even get a filtered answer (a cached NXDOMAIN or a
        // sinkhole IP would still tell it whether a host exists).
        if !self.app_network_policy.read().unwrap().is_empty() {
            let packages = self.apps_for_udp(pkt);
            if let Some(reason) = self.app_blocked_reason(&packages) {
                self.stats.inc(&self.stats.dns_blocked);
                let saved = BYTES_PER_BLOCKED_REQUEST;
                self.stats.add(&self.stats.bytes_saved, saved);
                if let Some(reply) = dns::synthesize_reply(pkt, &query, cfg.block_mode) {
                    out.push(reply);
                }
                let event = events::with_app(
                    events::block_event(
                        events::ACTION_BLOCK,
                        host,
                        &self.dns_server_text(),
                        reason,
                        "App firewall",
                        crate::filter::CAT_AD,
                        0,
                        saved as u32,
                        pkt.version == 6,
                    ),
                    first_app(&packages),
                );
                self.log_event(event);
                return;
            }
            app_packages = Some(packages);
        }
        // A user rewrite answers the query here. It is explicit intent, so it
        // runs before the lists, and only for the address family it names:
        // an A rule does not answer an AAAA question (the real address may
        // differ, and inventing one would be worse than forwarding).
        if matches!(query.qtype, dns::TYPE_A | dns::TYPE_AAAA) {
            let address = crate::dnsrewrite::lookup(&self.dns_rewrites.read().unwrap(), host);
            if let Some(address) = address {
                if let Some(reply) = dns::synthesize_answer(pkt, &query, &[address], 60) {
                    crate::logbuf::push(&format!("dns: rewrite {host} -> {address}"));
                    self.stats.inc(&self.stats.dns_allowed);
                    let reply_len = reply.len().min(u32::MAX as usize) as u32;
                    out.push(reply);
                    if cfg.log_allowed && self.logging_live() {
                        let packages = app_packages.unwrap_or_else(|| self.apps_for_udp(pkt));
                        let event = events::with_traffic(
                            events::with_answer(
                                events::with_app(
                                    events::allow_event(host, &self.dns_server_text(), 0),
                                    first_app(&packages),
                                ),
                                &address.to_string(),
                            ),
                            0,
                            reply_len,
                        );
                        self.log_event(event);
                    }
                    return;
                }
            }
        }
        let t0 = now_ns();
        let mut verdict = self.filter.check_host(host);
        let decision_ns = now_ns() - t0;
        self.stats.record_decision(decision_ns);
        let latency_ns = decision_ns.min(u32::MAX as u64) as u32;
        // A cached decision keeps the verdict but not the rule that made it,
        // and a log row is supposed to name its list and rule. Only the path
        // that writes a row pays for the lookup the cache skipped.
        if verdict.blocked && verdict.rule_text.is_none() && self.logging_live() {
            verdict = self.filter.check_host_detailed(host);
        }

        // A host whose match wants a `$redirect` is not refused here: the
        // resource stands in for it, and only the HTTPS path knows the URL the
        // rule really applies to. Without TLS termination there is nothing to
        // serve it, so the host is sinkholed as usual rather than let through.
        let deferred = verdict.redirect && self.mitm_ready(cfg);
        // A host the app keeps demanding must not become a retry storm: after
        // a few blocked attempts inside the window it is forwarded for a
        // cooldown and the answer below is learned as allowed.
        let smart_allowed =
            verdict.blocked && !deferred && self.smart.lock().unwrap().note_blocked(host);
        if verdict.blocked && !deferred && !smart_allowed {
            self.stats.inc(&self.stats.dns_blocked);
            let saved = BYTES_PER_BLOCKED_REQUEST;
            self.stats.add(&self.stats.bytes_saved, saved);
            if let Some(reply) = dns::synthesize_reply(pkt, &query, cfg.block_mode) {
                out.push(reply);
            }
            let packages = app_packages.unwrap_or_else(|| {
                if self.logging_live() {
                    self.apps_for_udp(pkt)
                } else {
                    Vec::new()
                }
            });
            let event = events::with_app(
                events::block_event(
                    events::ACTION_BLOCK,
                    host,
                    &self.dns_server_text(),
                    verdict.rule_text.as_deref().unwrap_or(""),
                    verdict.list_name.as_deref().unwrap_or(""),
                    verdict.category,
                    latency_ns,
                    saved as u32,
                    pkt.version == 6,
                ),
                first_app(&packages),
            );
            self.log_event(event);
        } else {
            self.stats.inc(&self.stats.dns_allowed);
            // SafeSearch rewrites the question, not the answer: see
            // [`crate::safesearch`]. A cached answer skips the second lookup;
            // a cold one forwards the filtered host and answers the client
            // when that reply lands.
            let mut forwarded = false;
            // The answer and its size are only known when the engine produced
            // the reply itself; a forwarded query's reply lands later.
            let mut served: Option<(String, u32)> = None;
            if cfg.safe_search
                && !self.is_paused()
                && matches!(query.qtype, dns::TYPE_A | dns::TYPE_AAAA)
            {
                if let Some(safe_host) = crate::safesearch::safe_host(host) {
                    let addresses = self.cached_safe_search(safe_host, now_ms());
                    if let Some(addresses) = addresses {
                        if let Some(reply) = dns::synthesize_answer(pkt, &query, &addresses, 60) {
                            let answer = addresses
                                .iter()
                                .take(4)
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ");
                            served = Some((answer, reply.len().min(u32::MAX as usize) as u32));
                            out.push(reply);
                            forwarded = true;
                            crate::logbuf::push(&format!(
                                "dns: SafeSearch {host} answered from cache"
                            ));
                        }
                    }
                    if !forwarded {
                        self.forward_query(pkt, Some(&query), Some(safe_host));
                        forwarded = true;
                    }
                }
            }
            if !forwarded {
                served = self.serve_cached_answer(pkt, &query);
                forwarded = served.is_some();
            }
            if !forwarded {
                self.forward_query(pkt, Some(&query), None);
            }
            if cfg.log_allowed && self.logging_live() {
                let packages = app_packages.unwrap_or_else(|| self.apps_for_udp(pkt));
                let mut event = events::with_app(
                    events::allow_event(host, &self.dns_server_text(), latency_ns),
                    first_app(&packages),
                );
                if let Some((answer, reply_len)) = &served {
                    if !answer.is_empty() {
                        event = events::with_answer(event, answer);
                    }
                    event = events::with_traffic(event, 0, *reply_len);
                }
                self.log_event(event);
            }
        }
    }

    /// Answers a client query from the DNS cache when a fresh entry exists.
    ///
    /// The hit is replayed through [`Self::handle_reply`], exactly like the
    /// upstream answer it stands in for, so the ECH policy, the TTL aging and
    /// the connection learning all apply to it unchanged. It runs after the
    /// filter and the SafeSearch rewrite, so only a query that would have been
    /// forwarded can ever be served from here. Returns whether the client was
    /// answered; a miss leaves the query to the forwarder. The hit also
    /// returns the addresses and the reply size, for the log row.
    fn serve_cached_answer(&self, pkt: &Packet<'_>, query: &dns::Query<'_>) -> Option<(String, u32)> {
        let now = now_ms();
        let hit = self.dns_cache.lock().unwrap().get(
            query.qname.as_str(),
            query.qtype,
            query.qclass,
            now,
        );
        let Some((mut message, age_secs)) = hit else {
            return None;
        };
        if !dns::adopt_question(&mut message, query) {
            return None;
        }
        dns::age_ttls(&mut message, age_secs);
        let answer = dns::answer_addresses(&message)
            .into_iter()
            .take(4)
            .map(|(address, _)| address.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let reply_len = message.len().min(u32::MAX as usize) as u32;
        let reply = crate::upstream::Reply {
            pending: crate::upstream::Pending {
                client_txid: query.id,
                socket: 0,
                packet: pkt.raw.to_vec(),
                sent_ms: now,
                purpose: crate::upstream::Purpose::Client,
                safe_host: String::new(),
                via_backup: false,
                backup_after_ms: 0,
            },
            socket: 0,
            message,
        };
        self.handle_reply(&reply);
        Some((answer, reply_len))
    }

    /// Sends the query upstream through a protected socket.
    ///
    /// `safe_host` sends the question to the filtered host instead of the one
    /// the client asked; the reply becomes a synthetic answer for the original
    /// name (see [`Self::handle_reply`]).
    fn forward_query(&self, pkt: &Packet<'_>, query: Option<&Query<'_>>, safe_host: Option<&str>) {
        let Some(query) = query else {
            // Without a question there is nothing to forward: answer SERVFAIL
            // so the client fails fast instead of timing out.
            let synthetic = dns::synthesize_error(pkt, query, dns::RCODE_SERVFAIL);
            if let Some(err) = synthetic {
                self.write_raw(&err);
            }
            return;
        };
        // The whole IP packet travels with the query, not just the DNS message:
        // `handle_reply` rewrites this packet to answer the client. The
        // transaction id is patched inside it, and `Upstream::send` strips the
        // headers for the wire.
        let host = query.qname.as_str();
        if let Some(resolver) = self.secure_resolver.read().unwrap().clone() {
            self.forward_secure(pkt, query, safe_host, resolver);
            return;
        }
        // Spread queries over the socket pool deterministically, so a host keeps
        // using the same socket (friendlier to the kernel's flow cache).
        let socket = (hash_str(host) as usize) % crate::upstream::SOCKET_POOL_PUB;
        let mut upstream = self.upstream.lock().unwrap();
        if !upstream.is_ready() {
            self.stats.inc(&self.stats.dns_timeouts);
            crate::logbuf::push("dns forward: upstream not ready");
            if let Some(err) = dns::synthesize_error(pkt, Some(query), dns::RCODE_SERVFAIL) {
                self.write_raw(&err);
            }
            return;
        }
        let txid = upstream.alloc_txid();
        self.stats.inc(&self.stats.dns_queries);
        let sent = match safe_host {
            Some(safe_host) => dns::build_query(safe_host, query.qtype, txid).and_then(|message| {
                upstream.send_message(
                    socket,
                    &message,
                    pkt.raw,
                    query.id,
                    txid,
                    now_ms(),
                    safe_host,
                )
            }),
            None => {
                let mut packet = pkt.raw.to_vec();
                let off = pkt.l4_payload_offset();
                packet[off] = (txid >> 8) as u8;
                packet[off + 1] = (txid & 0xff) as u8;
                upstream.send(socket, &packet, query.id, txid, now_ms())
            }
        };
        drop(upstream);
        if sent.is_none() {
            self.stats.inc(&self.stats.dns_timeouts);
            crate::logbuf::push(&format!(
                "dns forward: {host} to {} dropped (slot {socket})",
                self.resolver_addr()
            ));
            if let Some(err) = dns::synthesize_error(pkt, Some(query), dns::RCODE_SERVFAIL) {
                self.write_raw(&err);
            }
        } else {
            self.stats.inc(&self.stats.packets_forwarded);
            // Wake the forwarder so the answer is picked up the moment it
            // lands instead of after its idle wait.
            self.wake();
        }
    }

    /// Sends a query over DoT/DoH. The exchange is blocking, so it goes to a
    /// worker and the answer comes back through [`Core::handle_secure_reply`];
    /// the packet path only pays for the channel send.
    fn forward_secure(
        &self,
        pkt: &Packet<'_>,
        query: &Query<'_>,
        safe_host: Option<&str>,
        resolver: crate::dnssecure::SecureResolver,
    ) {
        if self.secure_outstanding.load(Ordering::Relaxed) >= SECURE_DNS_IN_FLIGHT {
            self.stats.inc(&self.stats.dns_timeouts);
            crate::logbuf::push("dns secure: too many queries in flight, answering SERVFAIL");
            if let Some(err) = dns::synthesize_error(pkt, Some(query), dns::RCODE_SERVFAIL) {
                self.write_raw(&err);
            }
            return;
        }
        // A descriptor created without `protect()` would send the handshake
        // back into the tunnel. The app installs the protector before the
        // tunnel starts, so a missing one is a real failure, not a fallback.
        let protector = match self.socket_protector.lock().unwrap().clone() {
            Some(protector) => protector,
            None => {
                self.stats.inc(&self.stats.dns_timeouts);
                crate::logbuf::push("dns secure: no socket protector installed");
                if let Some(err) = dns::synthesize_error(pkt, Some(query), dns::RCODE_SERVFAIL) {
                    self.write_raw(&err);
                }
                return;
            }
        };

        let txid = self.upstream.lock().unwrap().alloc_txid();
        let message = match safe_host {
            Some(safe_host) => dns::build_query(safe_host, query.qtype, txid),
            None => {
                let mut message = pkt.l4_payload().to_vec();
                if message.len() >= 12 {
                    message[0] = (txid >> 8) as u8;
                    message[1] = (txid & 0xff) as u8;
                    Some(message)
                } else {
                    None
                }
            }
        };
        let Some(message) = message else {
            self.stats.inc(&self.stats.dns_timeouts);
            crate::logbuf::push(&format!(
                "dns secure: {host} produced no query",
                host = query.qname.as_str()
            ));
            if let Some(err) = dns::synthesize_error(pkt, Some(query), dns::RCODE_SERVFAIL) {
                self.write_raw(&err);
            }
            return;
        };

        let pending = crate::upstream::Pending {
            client_txid: query.id,
            // The secure transport has no socket-pool slot; the field is
            // unused by `handle_reply`.
            socket: 0,
            packet: pkt.raw.to_vec(),
            sent_ms: now_ms(),
            // The fallback retry re-sends this very packet over UDP, so the
            // record must know it came from the encrypted transport.
            via_backup: false,
            // The handshake on a fresh connection is not a sign of a dead
            // server, so encrypted queries keep the longer fallback delay.
            backup_after_ms: crate::upstream::SECURE_BACKUP_AFTER_MS,
            purpose: if safe_host.is_some() {
                crate::upstream::Purpose::SafeSearch
            } else {
                crate::upstream::Purpose::Client
            },
            safe_host: safe_host.unwrap_or("").to_string(),
        };
        let job = crate::dnssecure::SecureJob {
            resolver,
            message,
            pending,
            protector,
        };
        if !self.enqueue_secure(job) {
            self.stats.inc(&self.stats.dns_timeouts);
            crate::logbuf::push("dns secure: no worker is running");
            if let Some(err) = dns::synthesize_error(pkt, Some(query), dns::RCODE_SERVFAIL) {
                self.write_raw(&err);
            }
            return;
        }
        self.secure_outstanding.fetch_add(1, Ordering::Relaxed);
        self.stats.inc(&self.stats.dns_queries);
        self.stats.inc(&self.stats.packets_forwarded);
    }

    /// A pending query left the forwarder. One that already used the fallback
    /// has no path left, so the client gets SERVFAIL at once instead of
    /// retrying against the same dead resolvers.
    fn on_pending_expired(&self, pending: &crate::upstream::Pending) {
        if pending.via_backup {
            self.fail_pending(pending);
            return;
        }
        self.safe_search_expired(pending);
    }

    /// A SafeSearch lookup timed out: the client that was waiting on it gets
    /// SERVFAIL, which is the failure its resolver can retry immediately.
    fn safe_search_expired(&self, pending: &crate::upstream::Pending) {
        if pending.purpose != crate::upstream::Purpose::SafeSearch {
            return;
        }
        let Some(pkt) = Packet::parse(&pending.packet) else {
            return;
        };
        let Some(query) = dns::parse_query(pkt.l4_payload()) else {
            return;
        };
        if let Some(err) = dns::synthesize_error(&pkt, Some(&query), dns::RCODE_SERVFAIL) {
            self.write_raw(&err);
        }
    }

    /// Turns one filtered-search answer into the reply the client actually
    /// asked for: the filtered addresses are cached under the safe host, and
    /// the original question is answered with them.
    fn finish_safe_search(&self, reply: &crate::upstream::Reply) {
        let records = dns::answer_addresses(&reply.message);
        self.remember_safe_search(&reply.pending.safe_host, &records, now_ms());
        let Some(client_packet) = Packet::parse(&reply.pending.packet) else {
            return;
        };
        let Some(query) = dns::parse_query(client_packet.l4_payload()) else {
            return;
        };
        let addresses: Vec<std::net::IpAddr> = records.iter().map(|(ip, _)| *ip).collect();
        let ttl = if records.is_empty() {
            60
        } else {
            record_ttl(&records)
        };
        let reply_packet = match dns::synthesize_answer(&client_packet, &query, &addresses, ttl) {
            Some(packet) => packet,
            None => {
                // The filtered host had no address of the requested family:
                // fail fast instead of handing the client an empty answer it
                // would cache.
                let Some(error) =
                    dns::synthesize_error(&client_packet, Some(&query), dns::RCODE_SERVFAIL)
                else {
                    return;
                };
                error
            }
        };
        if !self.write_raw(&reply_packet) {
            return;
        }
        self.stats.inc(&self.stats.dns_replies);
        if let Some(body) = dns::answer_message(&query, &addresses, ttl) {
            let mitm = {
                let cfg = self.cfg.read().unwrap();
                self.mitm_ready(&cfg)
            };
            self.learn_answers(&body, mitm);
        }
    }

    /// Handles one upstream answer: rewrite it for the client, learn the address
    /// mapping and write it back through the tunnel.
    /// Test-only entry point for the reply path (normally driven by the
    /// `adfree-dns` thread).
    #[doc(hidden)]
    pub fn handle_reply_for_test(&self, reply: &crate::upstream::Reply) {
        self.handle_reply(reply);
    }

    /// Test-only: runs one iteration of the upstream poller and delivers what it
    /// finds, which is what the `adfree-dns` thread does continuously.
    #[doc(hidden)]
    pub fn poll_upstream_once_for_test(&self) -> usize {
        let mut replies: Vec<crate::upstream::Reply> = Vec::new();
        let n = {
            let mut upstream = self.upstream.lock().unwrap();
            upstream.poll(&mut replies, 0)
        };
        for reply in &replies {
            self.handle_reply(reply);
        }
        n
    }

    /// Test-only: installs a TUN descriptor (a pipe write end works) so replies
    /// can be captured.
    #[doc(hidden)]
    pub fn set_tun_fd_for_test(&self, fd: RawFd) {
        self.tun_fd.store(fd, Ordering::SeqCst);
    }

    fn handle_reply(&self, reply: &crate::upstream::Reply) {
        if reply.pending.purpose == crate::upstream::Purpose::SafeSearch {
            self.finish_safe_search(reply);
            return;
        }
        let Some(client_packet) = Packet::parse(&reply.pending.packet) else {
            return;
        };
        // Cached as the origin sent it, before the rewrites below: a hit
        // replays this same path, so whichever ECH policy is in force when it
        // is served still decides what the client sees.
        self.cache_answer(&reply.message);
        let mut message = reply.message.clone();
        dns::patch_txid(&mut message, reply.pending.client_txid);
        // A client that is about to have its TLS terminated must not be told
        // an ECHConfig: the handshake cannot negotiate ECH through the
        // terminator, so the attempt either dies on the forged certificate (a
        // wasted round trip) or, on hosts in ECH-required mode, fails the
        // connection outright (see `dns::strip_ech`).
        //
        // The parameter is not thrown away, though: the TLS half offers the
        // host's own config on the proxy's own connection, so even a host that
        // requires ECH stays filterable. Only if the origin refuses that too
        // does the host become the exception — learned from the refusal the
        // terminator sees (`proxy::note_plain_refusal`) — after which its
        // ECHConfig is left in place for a bounded window and hellos carrying
        // it are spliced by the public name they expose.
        let (mitm, full_ech) = {
            let cfg = self.cfg.read().unwrap();
            (self.mitm_ready(&cfg), cfg.full_ech)
        };
        // The name and the type come from the same question: the string is
        // taken up front because the answer is rewritten in place below.
        let (host, https_query) = match if mitm {
            dns::parse_query(&message)
        } else {
            None
        } {
            Some(query) => (
                Some(query.qname.as_str().to_string()),
                query.qtype == 65 || query.qtype == 64,
            ),
            None => (None, false),
        };
        let now_ms = crate::util::now_ms();
        if let Some(host) = host.as_deref() {
            if self.ech_hosts.lapsed(host, now_ms) {
                crate::logbuf::push(&format!(
                    "dns: ECH exemption for {host} lapsed, its config is stripped again"
                ));
            }
        }
        let exempt = host
            .as_deref()
            .is_some_and(|host| self.ech_hosts.exempt(host, now_ms));
        // Read before the strip below rewrites the parameter away: the raw
        // config is what the upstream half offers, and the public name is what
        // a real ECH hello will expose on the wire. Only an HTTPS query can
        // carry either.
        let (config, public_name) = if mitm && https_query {
            (
                dns::ech_config_list(&message),
                dns::ech_public_name(&message),
            )
        } else {
            (None, None)
        };
        if mitm && exempt {
            if let (Some(host), true) = (host.as_deref(), https_query) {
                crate::logbuf::push(&format!("dns: ECH kept for {host} (the host requires it)"));
                // The name inside the config is what a real ECH hello will
                // expose on the wire, and the DNS half is the only place that
                // can read it. It is learned only for the hosts whose config
                // is actually handed out: an ECH hello can only reach one of
                // those, and every other flow stays terminated (`mitm::ech`).
                if let Some(name) = public_name.as_deref() {
                    self.ech_hosts.note_public_name(host, name);
                }
                // The kept answer is clamped like the stripped one: a lapsed
                // exemption must take effect within a minute, and the client
                // re-reads the record only when what it holds expires.
                let clamped =
                    dns::clamp_answer_ttl(&mut message, crate::mitm::ech::ANSWER_TTL_SECS);
                if clamped > 0 {
                    crate::logbuf::push(&format!(
                        "dns: ECH answer for {host} clamped to {}s",
                        crate::mitm::ech::ANSWER_TTL_SECS
                    ));
                }
            }
        } else if mitm && full_ech {
            // ECH runs end to end (Block ECH is off): the client keeps the
            // origin's config and may hide its inner name. Its hello can then
            // only be spliced (`mitm::ech`), so that host goes unfiltered —
            // the trade both AdGuard and this engine accept by default. The
            // config is still remembered for the upstream half, because
            // clients that do *not* use ECH (GREASE, older stacks) are
            // terminated and filtered as usual, even against an origin that
            // requires ECH.
            if let (Some(host), Some(list)) = (host.as_deref(), config) {
                crate::logbuf::push(&format!("dns: ECH kept for {host} (Block ECH is off)"));
                self.ech_hosts
                    .note_config(host, list, crate::util::now_ms());
                // The refusal fallback still applies: if the origin turns down
                // the proxy's own offer too, a client that does not use ECH
                // must not be left with the bare 502. Marking the host exempt
                // splices it, which is a trade this mode already accepts.
                self.ech_hosts.note_advertised(host);
            }
            if let (Some(host), Some(name)) = (host.as_deref(), public_name.as_deref()) {
                self.ech_hosts.note_public_name(host, name);
            }
        } else if mitm {
            // The client half must not see the parameter ([`dns::strip_ech`]),
            // but the proxy's own upstream half can use it: offering the
            // host's own ECHConfig is what keeps a host that requires ECH
            // filterable (see `mitm::ech`). Answers that carried one are
            // clamped to a minute, so the copy kept upstream cannot get far
            // out of date.
            if dns::strip_ech(&mut message) {
                let text = host.as_deref().unwrap_or("?");
                crate::logbuf::push(&format!("dns: ECH stripped for {text}"));
                if let Some(host) = host.as_deref() {
                    self.ech_hosts.note_advertised(host);
                    if let Some(list) = config {
                        self.ech_hosts
                            .note_config(host, list, crate::util::now_ms());
                    }
                }
                if let (Some(host), Some(name)) = (host.as_deref(), public_name.as_deref()) {
                    // A client that cached the config before the proxy was
                    // running still opens a real ECH hello, whose outer SNI is
                    // this name; those flows are spliced, never terminated.
                    self.ech_hosts.note_public_name(host, name);
                }
                // The answer is not the origin's any more, so it may not be
                // cached as if it were: a short TTL also keeps the way back
                // short when the host turns out to require ECH.
                let clamped =
                    dns::clamp_answer_ttl(&mut message, crate::mitm::ech::ANSWER_TTL_SECS);
                if clamped > 0 {
                    crate::logbuf::push(&format!(
                        "dns: ECH answer for {text} clamped to {}s",
                        crate::mitm::ech::ANSWER_TTL_SECS
                    ));
                }
            }
        }
        let rewritten = client_packet.rewrite_udp(&message);
        if !self.write_raw(&rewritten) {
            return;
        }
        self.stats.inc(&self.stats.dns_replies);
        self.learn_answers(&message, mitm);
    }

    /// Remembers one upstream answer for later queries for the same name.
    fn cache_answer(&self, message: &[u8]) {
        let Some(query) = dns::parse_query(message) else {
            return;
        };
        if !query.has_question {
            return;
        }
        let Some(ttl) = dns::cache_ttl(message) else {
            return;
        };
        self.dns_cache.lock().unwrap().insert(
            query.qname.as_str(),
            query.qtype,
            query.qclass,
            message,
            ttl,
            now_ms(),
        );
    }

    /// Teaches the connection tracker which addresses belong to which host.
    /// `mitm` is the gate `handle_reply` already read for this reply.
    fn learn_answers(&self, message: &[u8], mitm: bool) {
        let Some(query) = dns::parse_query(message) else {
            return;
        };
        if !query.has_question {
            return;
        }
        let host = query.qname.as_str().to_string();
        let verdict = self.filter.check_host(&host);
        // A `$redirect` host is answered by the HTTPS path, so its addresses
        // must stay reachable — but only while that path is actually armed.
        // A host in a smart-allow window is reachable too, otherwise the DNS
        // answer would contradict the forwarded query.
        let blocked = verdict.blocked
            && !(verdict.redirect && mitm)
            && !self.smart.lock().unwrap().allows(&host);
        let records = dns::parse_answers(message);
        if records.is_empty() {
            return;
        }
        let now = now_ms();
        let mut conn = self.conntrack.lock().unwrap();
        for record in records {
            conn.learn(&record, host.as_str(), blocked, now);
        }
    }

    /// Is this address an encrypted-DNS provider we should block?
    ///
    /// The configured upstream is deliberately *not* exempt: blocking DoT/DoH
    /// towards it is what forces the platform resolver back onto plain UDP:53,
    /// which is the only transport we can filter and forward. Our own upstream
    /// traffic travels on protected sockets outside the tunnel, so it is
    /// unaffected by this.
    pub fn is_encrypted_dns_elsewhere(&self, dst: IpKey) -> bool {
        self.doh_ips.read().unwrap().contains_key(dst)
    }

    fn host_for_ip(&self, ip: Option<IpKey>) -> Option<String> {
        let ip = ip?;
        let conn = self.conntrack.lock().unwrap();
        match conn.lookup(&ip, now_ms()) {
            IpVerdict::Blocked { host } | IpVerdict::Allowed { host } => Some(host.clone()),
            IpVerdict::Unknown => None,
        }
    }

    // ------------------------------------------------------------------ I/O

    fn write_raw(&self, bytes: &[u8]) -> bool {
        #[cfg(test)]
        {
            // No tun in tests: collect instead of dropping, so a test can see
            // exactly what the device would have received.
            self.outbox.lock().unwrap().push(bytes.to_vec());
        }
        let fd = self.tun_fd.load(Ordering::SeqCst);
        if fd <= 0 {
            return false;
        }
        let mut off = 0usize;
        while off < bytes.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    bytes.as_ptr().add(off) as *const libc::c_void,
                    bytes.len() - off,
                )
            };
            if n <= 0 {
                return false;
            }
            off += n as usize;
        }
        self.stats.inc(&self.tx_counter);
        true
    }

    // --------------------------------------------------------------- logging

    fn log_event(&self, event: Event) {
        // With the screen off nobody reads the log, and writing it would keep
        // the process out of the deepest sleep states.
        if self.is_screen_off() && self.cfg.read().unwrap().eco_mode {
            return;
        }
        let mut event = event;
        // One place stamps what every row shares: the decision id and the
        // network it was made on. Call sites only build the decision itself.
        event.flow_id = self.next_flow_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        event.set_network(
            self.network_type.load(Ordering::Relaxed) & 0b11,
            self.roaming.load(Ordering::Relaxed),
        );
        // Durable copy first: the ring is only the live tail the UI polls, so
        // the record survives even while a UI reader holds the ring lock.
        if let Some(store) = self.store.get() {
            if !store.log_enqueue(&event) {
                self.stats.inc(&self.stats.log_dropped);
            }
        }
        let Ok(mut log) = self.events.try_lock() else {
            return;
        };
        log.push(event);
    }

    /// Mirrors the drop rule in [`Self::log_event`], so a caller does not pay
    /// for attribution (a platform round-trip) the eco mode will discard.
    fn logging_live(&self) -> bool {
        !(self.is_screen_off() && self.cfg.read().unwrap().eco_mode)
    }

    pub fn drain_events(&self, out: &mut Vec<u8>, max: usize) -> usize {
        match self.events.try_lock() {
            Ok(mut log) => log.drain_into(out, max),
            Err(_) => 0,
        }
    }

    /// Takes events out of the ring, newest last. Used by the API layer.
    pub fn take_events(&self, max: usize) -> Vec<crate::events::Event> {
        self.events
            .lock()
            .map(|mut log| log.drain_events(max))
            .unwrap_or_default()
    }

    pub fn clear_events(&self) {
        if let Ok(mut log) = self.events.try_lock() {
            log.clear();
        }
    }

    /// Empties the request log everywhere: the database and the live ring.
    pub fn clear_log(&self) {
        if let Some(store) = self.store.get() {
            store.log_clear();
        }
        self.clear_events();
    }

    pub fn events_pending(&self) -> u64 {
        self.events.lock().map(|l| l.len() as u64).unwrap_or(0)
    }

    pub fn events_dropped(&self) -> u64 {
        self.events.lock().map(|l| l.dropped()).unwrap_or(0)
    }

    // ----------------------------------------------------------------- stats

    pub fn snapshot(&self) -> VpnStats {
        // Always refresh engine counters: housekeeping only runs while the VPN is
        // up, so it cannot be the only place that syncs them.
        self.sync_engine_stats();
        let s = self.stats.snapshot();
        VpnStats {
            packets_total: s.packets_total,
            packets_dns: s.packets_dns,
            packets_forwarded: s.packets_forwarded,
            dns_blocked: s.dns_blocked,
            dns_allowed: s.dns_allowed,
            tcp_reset: s.tcp_reset,
            quic_dropped: s.quic_dropped,
            quic_blocked: s.quic_blocked,
            udp_dropped: s.udp_dropped,
            dns_queries: s.dns_queries,
            dns_replies: s.dns_replies,
            dns_timeouts: s.dns_timeouts,
            bytes_saved: s.bytes_saved,
            decision_ns_avg: s.decision_ns_avg,
            decision_ns_ewma: s.decision_ns_ewma,
            decision_ns_max: s.decision_ns_max,
            cache_hits: s.cache_hits,
            cache_misses: s.cache_misses,
            active_rules: s.filter_rules,
            engine_bytes: s.engine_bytes,
            rss_kb: s.rss_kb,
            loop_iterations: s.loop_iterations,
            busy_ns: s.busy_ns,
            tls_ns: s.tls_ns,
            handshake_ns: s.handshake_ns,
            rewrite_ns: s.rewrite_ns,
            log_dropped: s.log_dropped,
            events_pending: self.events_pending(),
            events_dropped: self.events_dropped(),
            filter_build_ms: self.filter.build_time_ms(),
            conntrack_entries: self.conntrack_entries(),
            pending_dns: self
                .upstream
                .lock()
                .map(|u| u.pending_len() as u64)
                .unwrap_or(0),
            uptime_ms: self.uptime_ms(),
        }
    }

    pub fn reset_stats(&self) {
        self.stats.reset();
        self.clear_events();
    }

    pub fn conntrack_entries(&self) -> u64 {
        self.conntrack.lock().map(|c| c.len() as u64).unwrap_or(0)
    }

    /// Uid of the app that owns a given source port (0 = unknown).
    pub fn uid_for_port(&self, port: u16) -> u32 {
        self.uidmap.lock().unwrap().lookup(port)
    }

    /// Test hook: pins a TCP source port to a uid, the way the kernel table
    /// would on a device. The engine e2e drives synthetic packets whose
    /// source port belongs to no real process.
    #[cfg(test)]
    pub fn pin_uid_for_port(&self, port: u16, uid: u32) {
        self.uidmap.lock().unwrap().pin_tcp(port, uid);
    }

    /// Replaces the uid -> packages table the `$app=` rules are matched
    /// against. Pushed by the platform, the only side holding a package
    /// manager; the core keeps it until the next push.
    pub fn set_uid_apps(&self, entries: Vec<(u32, Vec<String>)>) {
        let mut table = self.uid_apps.write().unwrap();
        table.clear();
        for (uid, names) in entries {
            // 0 is the kernel's `android`/unknown uid: nobody's rules.
            if uid != 0 && !names.is_empty() {
                table.insert(uid, names);
            }
        }
    }

    /// Replaces the per-app HTTPS exclusions: flows owned by these packages are
    /// spliced untouched instead of decrypted. Applies to connections opened
    /// after the call; a live session keeps the decision it started with.
    pub fn set_https_skip_apps(&self, apps: Vec<String>) {
        *self.https_skip_apps.write().unwrap() = Arc::new(apps.into_iter().collect());
    }

    /// The splice set a new connection opens with: the user's exclusions plus
    /// the apps that turned out to reject the AdFree CA. Learned entries are
    /// per app, not per host: the alert says the client's trust store refused
    /// us, and every later connection of that app would fail the same way.
    fn effective_https_skip_apps(&self) -> Arc<HashSet<String>> {
        let configured = self.https_skip_apps.read().unwrap();
        let learned = self.ca_rejecting_apps.read().unwrap();
        if learned.is_empty() {
            return Arc::clone(&configured);
        }
        let mut merged = (**configured).clone();
        merged.extend(learned.iter().cloned());
        Arc::new(merged)
    }

    /// True when `err` is the client's own TLS stack refusing our certificate.
    /// The origin-facing feed is prefixed `client process_new_packets` and its
    /// alerts must not condemn the app, so those never match.
    fn client_rejected_certificate(err: &str) -> bool {
        err.contains("received fatal alert")
            && !err.contains("client process_new_packets")
            && CERT_ALERTS.iter().any(|(name, _)| err.contains(name))
    }

    /// The client-facing half just received a certificate alert: the app does
    /// not trust the AdFree CA. Remember the owner so its next connection is
    /// handed to the origin untouched — DNS filtering and `$app=` rules still
    /// apply, the TLS payload just stays encrypted. Logged once per app.
    fn note_client_cert_rejection(&self, err: &str, apps: &[String], host: &str) {
        if apps.is_empty() || !Self::client_rejected_certificate(err) {
            return;
        }
        self.learn_ca_rejections(apps, host);
    }

    /// Marks every package in `apps` as one that refuses the AdFree CA. Shared
    /// by the TCP path (alerts read out of the error string) and the QUIC path
    /// (numeric alerts from the CONNECTION_CLOSE).
    fn learn_ca_rejections(&self, apps: &[String], host: &str) {
        let mut learned = self.ca_rejecting_apps.write().unwrap();
        for app in apps {
            if learned.insert(app.clone()) {
                crate::logbuf::push(&format!(
                    "mitm {host}: {app} rejected the AdFree certificate, \
                     splicing its HTTPS verbatim from now on"
                ));
            }
        }
    }

    /// Installs the platform connection-to-app lookup (Android's
    /// `ConnectivityManager`). Without it the kernel's `/proc` table is read.
    pub fn set_uid_lookup(&self, lookup: Arc<dyn crate::api::ConnectionUidLookup>) {
        *self.uid_lookup.write().unwrap() = Some(lookup);
    }

    /// The package names behind the app that owns the TCP flow `pkt` opens,
    /// for the `$app=` rules. Empty when the flow is unattributed, when the
    /// platform has not pushed the table yet, or when nothing needs it
    /// (nothing is then asked of the platform or of the kernel).
    ///
    /// One lookup per connection, at SYN time: the app is a property of the
    /// flow, not of the request, and asking later would race with the first
    /// request of the same connection.
    fn apps_for_packet(&self, pkt: &Packet<'_>, cfg: &Config) -> Vec<String> {
        let intercepted =
            self.mitm_ready(cfg) && pkt.dst_port == self.mitm_port.load(Ordering::Relaxed);
        let need_apps = !self.app_network_policy.read().unwrap().is_empty()
            || self.filter.has_app_rules()
            || !self.https_skip_apps.read().unwrap().is_empty()
            // An app already known to reject the CA is spliced, and that
            // decision needs its name on every new flow.
            || !self.ca_rejecting_apps.read().unwrap().is_empty()
            // The HTTPS path logs the app on every request it blocks, so an
            // intercepted flow needs its name even without `$app=` rules —
            // unless the eco mode is dropping those events anyway.
            || (intercepted && self.logging_live());
        if !need_apps {
            return Vec::new();
        }
        self.resolve_tcp_apps(pkt)
    }

    /// Same lookup without the "is any rule asking?" shortcut, for callers
    /// that always need the name: the request log names the app on every
    /// entry, so a reset whose flows match no `$app=` rule still gets one.
    fn resolve_tcp_apps(&self, pkt: &Packet<'_>) -> Vec<String> {
        let lookup = self.uid_lookup.read().unwrap().clone();
        let uid = match lookup {
            Some(lookup) => lookup
                .owner_uid(
                    PROTO_TCP,
                    pkt.src_ip_text(),
                    pkt.src_port,
                    pkt.dst_ip_text(),
                    pkt.dst_port,
                )
                .unwrap_or(0),
            // No platform callback: the kernel's socket table answers, as it
            // does on desktop Linux. The end-to-end tests drive this path with
            // `pin_uid_for_port`, since their synthetic ports belong to no
            // real process.
            None => self.uidmap.lock().unwrap().lookup_tcp(pkt.src_port),
        };
        self.packages_for_uid(uid)
    }

    /// Packages owning one UDP datagram. The platform callback answers on
    /// Android 14+; older releases fall back to the kernel's socket table.
    fn apps_for_udp(&self, pkt: &Packet<'_>) -> Vec<String> {
        let lookup = self.uid_lookup.read().unwrap().clone();
        let uid = match lookup {
            Some(lookup) => lookup
                .owner_uid(
                    PROTO_UDP,
                    pkt.src_ip_text(),
                    pkt.src_port,
                    pkt.dst_ip_text(),
                    pkt.dst_port,
                )
                .unwrap_or(0),
            None => self.uidmap.lock().unwrap().lookup(pkt.src_port),
        };
        self.packages_for_uid(uid)
    }

    fn packages_for_uid(&self, uid: u32) -> Vec<String> {
        if uid == 0 {
            return Vec::new();
        }
        self.uid_apps
            .read()
            .unwrap()
            .get(&uid)
            .cloned()
            .unwrap_or_default()
    }

    /// The shared per-SNI resolver, creating it on first use.
    pub fn mitm_resolver(&self) -> Arc<crate::mitm::tls::SniCertResolver> {
        let mut guard = self.mitm_resolver.write().unwrap();
        guard
            .get_or_insert_with(|| {
                Arc::new(crate::mitm::tls::SniCertResolver::new(Arc::clone(
                    &self.mitm_ca.read().unwrap(),
                )))
            })
            .clone()
    }

    /// TLS config for the upstream half of an intercepted connection.
    pub fn upstream_tls_config(&self) -> Arc<crate::mitm::tls::UpstreamTls> {
        self.upstream_config.read().unwrap().clone()
    }

    /// Will port-443 flows actually be terminated and filtered?
    ///
    /// HTTPS filtering is opt-in and needs a loaded CA; both the relay and the
    /// DNS layer's deferral of `$redirect` hosts read the same gate, so a host
    /// is never let through on the promise of a filter that is not there.
    fn mitm_ready(&self, cfg: &Config) -> bool {
        cfg.mitm_enabled && !self.is_paused() && self.mitm_ca.read().unwrap().has_ca()
    }

    /// Overrides the upstream trust anchors. The engine's end-to-end tests use
    /// this to talk to a loopback origin the system store cannot know about.
    #[doc(hidden)]
    pub fn set_upstream_tls_config(&self, config: Arc<crate::mitm::tls::UpstreamTls>) {
        *self.upstream_config.write().unwrap() = config;
    }

    pub fn relay_count(&self) -> usize {
        self.relays.lock().unwrap().len()
    }

    /// One pass of the forwarder loop without a tun: polls the wake eventfd,
    /// the DNS sockets, every relay and UDP mapping, and dispatches whatever
    /// is ready. Tests use it to move bytes between synthetic client packets
    /// and the peer socket; in production the forwarder thread owns this.
    #[cfg(test)]
    pub fn pump_once(&self, timeout_ms: libc::c_int) {
        // No setup worker runs in tests: whichever thread drives the packet
        // loop also completes the flows the SYN path queued.
        self.run_setup_jobs();
        self.wait_for_events(timeout_ms);
        // The wait itself services the queued DNS and relay work; QUIC
        // datagrams are turned into packets here, like the forwarder does.
        self.drain_quic();
    }

    /// Drains the packets [`Self::write_raw`] collected for the tun.
    #[cfg(test)]
    pub fn take_outbox(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbox.lock().unwrap())
    }

    /// Installs a new CA and drops the cached resolver.
    ///
    /// The resolver captures the `Arc<CertificateAuthority>` it was built
    /// with, so keeping it after a regeneration (or after the CA is first
    /// loaded) would keep signing leaves with the previous — possibly
    /// placeholder — key.
    pub fn set_mitm_ca(&self, ca: Arc<crate::mitm::ca::CertificateAuthority>) {
        // `ensure_ca` re-loads the same pair on every UI refresh; only a real
        // key change invalidates what the apps learned about the old one.
        let changed = {
            let current = self.mitm_ca.read().unwrap();
            current.cert_der() != ca.cert_der()
        };
        *self.mitm_ca.write().unwrap() = ca;
        *self.mitm_resolver.write().unwrap() = None;
        if changed {
            // Live flows were terminated with leaves from the old key; a new
            // CA means the client must be given a chance to validate the new
            // one, so they are closed and the next connection is filtered
            // again.
            self.close_h3_flows();
            self.clear_ca_rejections();
        }
    }

    /// Forgets every app that rejected the current CA, so its next connection
    /// is decrypted again. Returns how many entries were dropped.
    pub fn clear_ca_rejections(&self) -> usize {
        let mut learned = self.ca_rejecting_apps.write().unwrap();
        let count = learned.len();
        if count > 0 {
            learned.clear();
            crate::logbuf::push(&format!(
                "mitm: retrying HTTPS decryption for {count} app(s) after the CA change"
            ));
        }
        drop(learned);
        // The QUIC path remembered five-tuples whose client refused the leaf;
        // those verdicts lapse with the rejection they came from.
        self.h3_spliced.lock().unwrap().clear();
        count
    }

    pub fn resolver_addr(&self) -> SocketAddr {
        *self.resolver.read().unwrap()
    }

    /// The DNS server the next query travels to, rendered the way the request
    /// log shows a destination: `udp://94.140.14.14:53`, `tls://host:853` or
    /// the DoH URL.
    fn dns_server_text(&self) -> String {
        if let Some(resolver) = self.secure_resolver.read().unwrap().as_ref() {
            return match resolver.protocol {
                crate::state::model::DnsProtocol::Dot => {
                    format!("tls://{}:{}", resolver.host, resolver.port)
                }
                _ => format!(
                    "https://{}:{}{}",
                    resolver.host, resolver.port, resolver.path
                ),
            };
        }
        format!("udp://{}", self.resolver_addr())
    }

    /// The longest the forwarder may sleep right now.
    ///
    /// The ordinary cadence, shortened to the first retry or timeout that is
    /// due. When nothing at all is in flight — no query, no relay, no NAT
    /// mapping, no terminated QUIC flow — the slow idle cadence applies; every
    /// descriptor that joins the wait set is announced through the wake
    /// eventfd, so the long sleep cannot delay its first byte.
    fn forward_wait_ms(&self, now_ms: u64) -> libc::c_int {
        let quiet = {
            let no_relays = self.relays.lock().unwrap().is_empty();
            let no_nat = self.udp_nat.lock().unwrap().is_empty();
            let no_h3 = self.h3_flows.lock().unwrap().is_empty();
            no_relays && no_nat && no_h3
        };
        let upstream = self.upstream.lock().unwrap();
        let cadence = if quiet && upstream.pending_len() == 0 {
            IDLE_WAIT_MS
        } else {
            FORWARD_WAIT_MS
        };
        upstream
            .next_deadline_in(now_ms)
            .map_or(cadence, |due| due.min(cadence as u64) as libc::c_int)
    }

    /// Sleeps until a descriptor is ready or the cadence ticks.
    ///
    /// One `poll()` covers the wake eventfd, the upstream DNS sockets and
    /// every relay and UDP descriptor the engine owns: the loop blocks here
    /// between bursts of real work instead of circulating on a short timeout.
    /// Readiness is dispatched before returning, which is also what keeps
    /// every descriptor owned by this thread.
    fn wait_for_events(&self, timeout_ms: libc::c_int) {
        let relays = self.relays.lock().unwrap().poll_snapshot();
        let udp = self.udp_nat.lock().unwrap().poll_snapshot();
        // Copy the DNS descriptors out and drop the lock before waiting: a UI
        // thread inside `set_resolver` must not sit on the upstream mutex for
        // a whole timeout interval.
        let dns: Vec<RawFd> = self
            .upstream
            .lock()
            .unwrap()
            .socket_fds()
            .iter()
            .copied()
            .filter(|fd| *fd > 0)
            .collect();

        let mut fds: Vec<libc::pollfd> =
            Vec::with_capacity(1 + dns.len() + relays.len() + udp.len());
        let wake_index = if self.wake_fd >= 0 {
            let index = fds.len();
            fds.push(libc::pollfd {
                fd: self.wake_fd,
                events: libc::POLLIN,
                revents: 0,
            });
            Some(index)
        } else {
            None
        };
        fds.extend(dns.iter().map(|fd| libc::pollfd {
            fd: *fd,
            events: libc::POLLIN,
            revents: 0,
        }));
        let flows_start = fds.len();
        fds.extend(
            relays
                .iter()
                .map(|(_, fd, connecting, want_write, paused)| {
                    let write = *connecting || *want_write;
                    let listen = !*paused;
                    libc::pollfd {
                        // A paused relay is left out of the read set. Dropping
                        // the descriptor entirely, rather than asking for no
                        // events, matters: POLLHUP is reported whatever the
                        // requested mask, so a peer that finished sending
                        // would wake the loop on every pass while its data
                        // sits unread in the kernel buffer.
                        fd: if listen || write { *fd } else { -1 },
                        events: (if listen { libc::POLLIN } else { 0 })
                            | (if write { libc::POLLOUT } else { 0 }),
                        revents: 0,
                    }
                }),
        );
        fds.extend(udp.iter().map(|(_, fd)| libc::pollfd {
            fd: *fd,
            events: libc::POLLIN,
            revents: 0,
        }));

        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        if let Some(index) = wake_index {
            // Drain on readiness only: a counter left behind by a racing wake
            // simply makes the next wait return at once, which costs one pass
            // and is always safe.
            if fds[index].revents != 0 {
                self.drain_wake();
            }
        }
        if n <= 0 {
            return;
        }
        for (i, p) in fds.iter().enumerate().skip(flows_start) {
            if p.revents == 0 {
                continue;
            }
            let index = i - flows_start;
            if index < relays.len() {
                self.handle_relay_ready(relays[index], p.revents);
            } else {
                let flow = udp[index - relays.len()];
                self.handle_udp_reply(flow.0, flow.1);
            }
        }
    }
}

/// Reads packets off the TUN descriptor until the engine is stopped.
fn tun_loop(core: &'static Core, fd: RawFd) {
    // Make the descriptor non-blocking: we then always `poll` before `read`,
    // which is the only way to both avoid a busy loop and react to `stop()`.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }

    let mut buf = vec![0u8; TUN_BUF_BYTES];
    let mut pfd = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];

    while core.is_running() {
        let rc = unsafe { libc::poll(pfd.as_mut_ptr(), 1, POLL_TIMEOUT_MS) };
        if rc <= 0 {
            continue; // timeout or shutdown requested
        }
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    break; // drained
                }
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // Descriptor closed: nothing more we can do here.
                core.running.store(false, Ordering::SeqCst);
                break;
            }
            let t0 = now_ns();
            let replies = core.handle_packet(&buf[..n as usize]);
            for reply in replies {
                core.write_raw(&reply);
            }
            core.stats.add(&core.stats.busy_ns, now_ns() - t0);
        }

        housekeeping(core);
    }
}

/// Waits for upstream answers and writes them back through the tunnel.
///
/// Passes are paced by descriptors, not by the clock: the loop blocks in
/// [`Core::wait_for_events`] until a wake, a DNS socket or a flow socket is
/// ready, then services everything that is due. A one-second timeout still
/// ticks when nothing at all is live, which is what retires idle relays and
/// NAT mappings.
fn forwarder_loop(core: &'static Core) {
    let mut replies: Vec<crate::upstream::Reply> = Vec::with_capacity(32);
    while core.is_running() {
        replies.clear();
        let now = now_ms();
        let mut answered = false;

        // Answers that are already on the wire. The DNS sockets are part of
        // the wait set below, so a reply ends the wait and is read here right
        // after it lands.
        {
            let mut upstream = core.upstream.lock().unwrap();
            upstream.poll(&mut replies, 0);
            for pending in upstream.expire(now) {
                core.on_pending_expired(&pending);
            }
        }
        for reply in &replies {
            core.handle_reply(reply);
        }
        answered |= !replies.is_empty();
        // Encrypted transports answer through their own channel; the worker
        // pokes the wake fd, so this drains soon after the wait below.
        for reply in core.take_secure_replies() {
            core.handle_secure_reply(reply);
            answered = true;
        }

        // The single blocking point of the loop. The idle cadence covers
        // descriptor upkeep, but an in-flight query usually needs attention
        // sooner than that: its fallback retry and its timeout are timed
        // events with no descriptor to wake us, so the wait is capped by the
        // first one due. With nothing in flight the slow cadence applies.
        let wait_ms = core.forward_wait_ms(now);
        core.wait_for_events(wait_ms);

        for reply in core.take_secure_replies() {
            core.handle_secure_reply(reply);
            answered = true;
        }
        // QUIC handed datagrams for the client since the last pass; the
        // endpoints wake this thread through the eventfd, so they land here
        // right after the wait.
        core.drain_quic();

        // Relayed connections: whatever the real server answered has been
        // spliced back to the client by the wait itself, and finished relays
        // are reaped here so their descriptors are only ever closed on this
        // thread.
        core.prune_relays();
        // Idle NAT mappings are retired here too, for the same reason.
        core.udp_nat.lock().unwrap().expire(now);
        // Terminated QUIC flows live on their own thread; this only tells it
        // which five-tuples to shut down.
        core.expire_quic(now);

        if !answered {
            core.conntrack.lock().unwrap().expire(now);
        }
    }

    // The tunnel is going away: every peer and NAT descriptor belongs to a
    // flow the next session will recreate from scratch, and leaving them in
    // the tables would have the next forwarder poll dead sockets (and refuse
    // new sessions whose client ports are still taken). This thread is the
    // only one that closes flow descriptors, so clean up here, after the last
    // poll and before returning.
    core.relays.lock().unwrap().clear();
    core.udp_nat.lock().unwrap().clear();
    // Same for the QUIC side: `stop()` already asked the bridge to shut down,
    // but a loop that exits for any other reason must not leave flows behind.
    core.stop_h3();
}

/// Builds the upstream half of answered flows until the engine stops.
///
/// One worker, FIFO: connections opened back to back are set up in the order
/// they were answered. Each setup costs a platform round-trip (attribution), a
/// `protect()`, a dial and a TLS session — milliseconds the packet reader must
/// not spend, or every `connect()` would queue behind the previous flow.
fn setup_loop(core: &'static Core) {
    let mut pfd = [libc::pollfd {
        fd: core.setup_fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    while core.is_running() {
        let rc = unsafe { libc::poll(pfd.as_mut_ptr(), 1, POLL_TIMEOUT_MS) };
        if rc > 0 {
            core.drain_setup_wake();
        }
        loop {
            if !core.is_running() {
                break;
            }
            let job = core.setup_jobs.lock().unwrap().pop_front();
            let Some(job) = job else {
                break;
            };
            core.complete_setup(job);
        }
    }
    core.setup_jobs.lock().unwrap().clear();
}

/// Services every flow descriptor the engine owns.
///
/// Polling all of them in one `poll()` keeps the cost independent of how many
/// connections are open, which matters for battery when a page opens dozens of
/// them. TCP peers whose `connect()` has not finished yet also ask for
/// `POLLOUT` (how their completion or failure is noticed), as do peers whose
/// queued client bytes could not be sent yet. The wait set now lives in
/// [`Core::wait_for_events`], which also covers the wake eventfd and the DNS
/// sockets.
impl Core {
    /// One relay's peer socket became readable (or writable again).
    fn handle_relay_ready(&self, peer: (u16, RawFd, bool, bool, bool), revents: libc::c_short) {
        let (client_port, fd, was_connecting, was_writing, _) = peer;
        // A client RST may have marked the relay closed since the poll(); the
        // entry itself is still there (only this thread reaps relays), so
        // matching it back means the descriptor is ours to touch.
        let still_live = self
            .relays
            .lock()
            .unwrap()
            .get(client_port)
            .map(|r| !r.closed && r.peer_fd == fd)
            .unwrap_or(false);
        if !still_live {
            return;
        }
        if was_connecting && revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0 {
            // The connect() finished: either it worked (flush what the
            // client sent meanwhile) or it failed (cut the flow).
            let err = so_error(fd);
            if err != 0 {
                // A SYN can die with a reset when its source port collides
                // with stale NAT bookkeeping (seen on emulators), and an IPv6
                // destination with no route dies with ENETUNREACH. The
                // client's own retry is seconds away, so try once on a fresh
                // socket first: a new port usually goes through and the flow
                // never notices.
                if self.retry_peer_connect(client_port) {
                    crate::logbuf::push(&format!(
                        "relay: peer connect failed (errno {err}), retrying on a fresh socket"
                    ));
                    return;
                }
                crate::logbuf::push(&format!("relay: connect to the peer failed (errno {err})"));
                self.close_relay_from_peer(client_port, true);
                return;
            }
            {
                let mut guard = self.relays.lock().unwrap();
                if let Some(relay) = guard.get_mut(client_port) {
                    relay.connecting = false;
                }
            }
            self.flush_peer(client_port);
        } else if was_writing && revents & libc::POLLOUT != 0 {
            // The send buffer drained: push what is left of the queue.
            self.flush_peer(client_port);
        }
        if revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
            return;
        }
        let mut buf = [0u8; 32 * 1024];
        loop {
            let read = unsafe {
                libc::recv(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if read < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                // Hard error (ECONNRESET, ECONNREFUSED...): the flow is
                // dead, reset the client so it does not wait forever.
                self.close_relay_from_peer(client_port, true);
                break;
            }
            if read == 0 {
                // A proxy that hangs up before replying is a failure, not an
                // orderly origin shutdown: reset instead of sending a FIN.
                let mid_handshake = self
                    .relays
                    .lock()
                    .unwrap()
                    .get(client_port)
                    .is_some_and(|r| r.proxy_handshaking());
                self.close_relay_from_peer(client_port, mid_handshake);
                break;
            }
            if self.relay_peer_bytes(client_port, &buf[..read as usize]) {
                // The client is not draining what it already owes: stop
                // pulling from the peer until the backlog clears.
                break;
            }
        }
    }

    /// One NAT mapping's socket has datagrams (or an ICMP error) waiting.
    fn handle_udp_reply(&self, key: UdpKey, fd: RawFd) {
        let mut buf = [0u8; 64 * 1024];
        loop {
            let read = unsafe {
                libc::recv(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if read < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return;
                }
                // ICMP port unreachable and friends surface as hard errors
                // here: the mapping can never produce a reply, so retire it.
                self.udp_nat.lock().unwrap().remove(&key);
                return;
            }
            if read == 0 {
                // A proxied mapping is fed by its association thread: a clean
                // EOF means the thread is gone and nothing can answer through
                // it. A direct socket's zero-length datagram stays a datagram.
                let mut nat = self.udp_nat.lock().unwrap();
                if nat.get_mut(&key).is_some_and(|flow| flow.proxied) {
                    nat.remove(&key);
                    return;
                }
            }
            let reply = {
                let mut nat = self.udp_nat.lock().unwrap();
                let Some(flow) = nat.get_mut(&key) else {
                    return;
                };
                flow.last_ms = now_ms();
                flow.recv += read as u64;
                match Packet::parse(&flow.template) {
                    // Swaps addresses and ports, recomputes lengths and
                    // checksums: the datagram looks like it came from the real
                    // server. A zero-length reply is a datagram too, not EOF.
                    Some(template) => template.rewrite_udp(&buf[..read as usize]),
                    None => return,
                }
            };
            self.stats.inc(&self.stats.udp_relayed);
            self.write_raw(&reply);
        }
    }

    /// One free retry of a failed peer connect, on a fresh socket.
    ///
    /// A connect can die with ECONNRESET when the forwarder's SYN collides
    /// with stale NAT state (guest source ports get reused, and emulator
    /// NATs have been seen to answer with a reset). A fresh socket gets a
    /// fresh port and usually goes through; the client flow is untouched,
    /// so a success here is invisible to the app. Returns true when the
    /// relay is back in business.
    fn retry_peer_connect(&self, client_port: u16) -> bool {
        let (dst, dport, old_fd, proxy) = {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(client_port) else {
                return false;
            };
            if relay.closed || !relay.connecting || relay.connect_retries > 0 {
                return false;
            }
            let Some(pkt) = Packet::parse(&relay.syn_packet) else {
                return false;
            };
            let Some(dst) = pkt.dst_ip() else {
                return false;
            };
            (dst, pkt.dst_port, relay.peer_fd, relay.proxy.clone())
        };
        let (dial_addr, dial_port) = match &proxy {
            Some(p) => (p.addr, p.port),
            None => (dst, dport),
        };
        let Some(new_fd) = self.open_peer_socket(dial_addr, libc::SOCK_STREAM) else {
            return false;
        };
        let connect = connect_fd(new_fd, dial_addr, dial_port);
        if connect == Connect::Failed {
            unsafe { libc::close(new_fd) };
            return false;
        }
        let handshake = match &proxy {
            Some(p) => match Socks5Handshake::new(dst, dport, p.credentials()) {
                Ok(h) => Some(h),
                Err(e) => {
                    crate::logbuf::push(&format!("relay: {e}"));
                    unsafe { libc::close(new_fd) };
                    return false;
                }
            },
            None => None,
        };
        let swapped = {
            let mut guard = self.relays.lock().unwrap();
            match guard.get_mut(client_port) {
                Some(relay) if !relay.closed => {
                    relay.peer_fd = new_fd;
                    relay.connecting = connect == Connect::InProgress;
                    relay.connect_retries += 1;
                    relay.handshake = handshake;
                    true
                }
                _ => false,
            }
        };
        if !swapped {
            unsafe { libc::close(new_fd) };
            return false;
        }
        // Retire the failed socket and let whatever was queued go out.
        unsafe { libc::close(old_fd) };
        if connect == Connect::Connected {
            self.flush_peer(client_port);
        }
        true
    }

    /// Reopens the peer socket for a flow whose upstream half rebuilt itself
    /// after the server rejected its ECH offer.
    ///
    /// The rejected TLS connection cannot continue (RFC 9849 §6.1.6), so the
    /// plain retry needs a fresh TCP connection to the same origin. Everything
    /// queued for the old socket belonged to the old handshake — the HTTP
    /// request itself was never written, it waits in the session — so the
    /// queue is dropped with it, and the new ClientHello follows on the new
    /// socket. The client-facing half is untouched.
    fn restart_peer_socket(&self, client_port: u16) -> bool {
        let (dst, dport, old_fd, proxy) = {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(client_port) else {
                return false;
            };
            if relay.closed {
                return false;
            }
            let Some(pkt) = Packet::parse(&relay.syn_packet) else {
                return false;
            };
            let Some(dst) = pkt.dst_ip() else {
                return false;
            };
            (dst, pkt.dst_port, relay.peer_fd, relay.proxy.clone())
        };
        let (dial_addr, dial_port) = match &proxy {
            Some(p) => (p.addr, p.port),
            None => (dst, dport),
        };
        let Some(new_fd) = self.open_peer_socket(dial_addr, libc::SOCK_STREAM) else {
            return false;
        };
        let connect = connect_fd(new_fd, dial_addr, dial_port);
        if connect == Connect::Failed {
            unsafe { libc::close(new_fd) };
            return false;
        }
        let handshake = match &proxy {
            Some(p) => match Socks5Handshake::new(dst, dport, p.credentials()) {
                Ok(h) => Some(h),
                Err(e) => {
                    crate::logbuf::push(&format!("relay: {e}"));
                    unsafe { libc::close(new_fd) };
                    return false;
                }
            },
            None => None,
        };
        let swapped = {
            let mut guard = self.relays.lock().unwrap();
            match guard.get_mut(client_port) {
                Some(relay) if !relay.closed => {
                    relay.pending_to_peer.clear();
                    relay.peer_fd = new_fd;
                    relay.connecting = connect == Connect::InProgress;
                    relay.handshake = handshake;
                    true
                }
                _ => false,
            }
        };
        if !swapped {
            unsafe { libc::close(new_fd) };
            return false;
        }
        unsafe { libc::close(old_fd) };
        if connect == Connect::Connected {
            self.flush_peer(client_port);
        }
        true
    }

    /// The peer side finished (EOF or error): tell the client and retire the
    /// relay so the table entry and the descriptor stop leaking.
    fn close_relay_from_peer(&self, client_port: u16, reset: bool) {
        let segment = {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(client_port) else {
                return;
            };
            let segment = if reset {
                relay.rst_to_client()
            } else {
                relay.on_peer_eof()
            };
            guard.remove(client_port);
            segment
        };
        if let Some(segment) = segment {
            self.write_raw(&segment);
        }
    }

    /// Moves server bytes through the splice and writes them back to the client.
    ///
    /// Returns `true` when the caller must stop reading the peer socket: the
    /// client-facing backlog reached its cap, the relay is gone, or the socket
    /// was replaced and the current descriptor is stale.
    fn relay_peer_bytes(&self, client_port: u16, bytes: &[u8]) -> bool {
        // While SOCKS5 negotiates, the peer is the proxy: its bytes are
        // protocol replies, not origin data.
        let input = {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(client_port) else {
                return true;
            };
            match relay.handshake.as_mut() {
                Some(hs) if !hs.is_done() => match hs.on_bytes(bytes) {
                    Ok(rest) => PeerInput::Handshake(rest),
                    Err(reason) => PeerInput::ProxyFailed(reason),
                },
                _ => PeerInput::Data,
            }
        };
        match input {
            PeerInput::ProxyFailed(reason) => {
                crate::logbuf::push(&format!("relay: SOCKS5 {reason}"));
                self.close_relay_from_peer(client_port, true);
                true
            }
            PeerInput::Handshake(rest) => {
                // The reply may have queued the CONNECT request, or released
                // application bytes that waited behind the handshake.
                self.flush_peer(client_port);
                if rest.is_empty() {
                    false
                } else {
                    self.relay_peer_bytes(client_port, &rest)
                }
            }
            PeerInput::Data => {
                let (segments, to_peer, restart, paused) = {
                    let mut guard = self.relays.lock().unwrap();
                    let Some(relay) = guard.get_mut(client_port) else {
                        return true;
                    };
                    match relay.on_peer_data(bytes) {
                        // The upstream half may want bytes on its own socket
                        // (its protocol handshake finishing, a buffered
                        // request): those must reach the peer or the flow
                        // deadlocks.
                        Ok((to_peer, outbound, restart)) => {
                            let segments = if outbound.is_empty() {
                                Vec::new()
                            } else {
                                relay.segments_for_client(&outbound)
                            };
                            (segments, to_peer, restart, relay.client_paused())
                        }
                        Err(e) => {
                            crate::logbuf::push(&format!("relay peer step: {e}"));
                            return true;
                        }
                    }
                };
                if restart {
                    if !self.restart_peer_socket(client_port) {
                        crate::logbuf::push("relay: no fresh peer socket for the plain ECH retry");
                    }
                    return true;
                }
                for segment in segments {
                    self.write_raw(&segment);
                }
                if !to_peer.is_empty() {
                    self.push_to_peer(client_port, &to_peer);
                }
                paused
            }
        }
    }
}

/// Once-a-second maintenance: RSS sampling and engine bookkeeping.
fn housekeeping(core: &Core) {
    let now = now_ns();
    let last = core.last_tick_ns.load(Ordering::Relaxed);
    if now.saturating_sub(last) < 1_000_000_000 {
        return;
    }
    core.last_tick_ns.store(now, Ordering::Relaxed);
    core.stats.set(&core.stats.rss_kb, stats::read_rss_kb());
    core.sync_engine_stats();
}

/// How long a relay may sit silent before it is presumed dead.
const RELAY_IDLE_MS: u64 = 300_000;

impl Core {
    /// Frees finished relays and resets ones that went silent.
    ///
    /// Runs on the forwarder thread, the same one that polls relays and their
    /// descriptors: keeping every removal on one thread means a peer
    /// descriptor can never be closed from under a concurrent `poll()`.
    fn prune_relays(&self) {
        let now = now_ms();
        let mut resets = Vec::new();
        {
            let mut guard = self.relays.lock().unwrap();
            for (_, relay) in guard.iter_mut() {
                if now.saturating_sub(relay.last_ms) > RELAY_IDLE_MS {
                    if let Some(rst) = relay.rst_to_client() {
                        resets.push(rst);
                    }
                    relay.close();
                }
            }
            guard.drop_closed();
        }
        for rst in resets {
            self.write_raw(&rst);
        }
    }
}

/// Outcome of a non-blocking `connect()`.
#[derive(PartialEq)]
enum Connect {
    /// The connection is already up.
    Connected,
    /// Still being established; the socket becomes writable when it resolves.
    InProgress,
    /// Refused on the spot (bad address, network unreachable...).
    Failed,
}

/// Connects `fd` (already protected) to `addr:port` without blocking.
fn connect_fd(fd: RawFd, addr: IpKey, port: u16) -> Connect {
    let ret = match addr {
        IpKey::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.to_be_bytes()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::connect(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        IpKey::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.to_be_bytes(),
                },
                sin6_scope_id: 0,
            };
            unsafe {
                libc::connect(
                    fd,
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if ret == 0 {
        return Connect::Connected;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EINPROGRESS) | Some(libc::EALREADY) | Some(libc::EINTR) => Connect::InProgress,
        _ => Connect::Failed,
    }
}

/// Reads `SO_ERROR` off a socket whose connect just completed. Zero means the
/// connection is up; anything else is the reason it failed.
fn so_error(fd: RawFd) -> i32 {
    let mut err: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut err as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        );
    }
    err
}

fn parse_cidr(text: &str) -> Option<(IpKey, u8)> {
    let (net, prefix) = text.trim().split_once('/')?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    let ip: std::net::IpAddr = net.trim().parse().ok()?;
    match ip {
        std::net::IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            Some((IpKey::V4(u32::from_be_bytes(v4.octets())), prefix))
        }
        std::net::IpAddr::V6(v6) => {
            if prefix > 128 {
                return None;
            }
            Some((IpKey::V6(u128::from_be_bytes(v6.octets())), prefix))
        }
    }
}

/// Writes `contents` to `dir/name` through `tmp_name`, optionally 0600 from
/// the first byte. False when the directory or the write refused.
fn write_atomic(
    dir: &std::path::Path,
    tmp_name: &str,
    name: &str,
    contents: &str,
    private: bool,
) -> bool {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let tmp = dir.join(tmp_name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    if private {
        options.mode(0o600);
    }
    let Ok(mut file) = options.open(&tmp) else {
        return false;
    };
    if file.write_all(contents.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    std::fs::rename(&tmp, dir.join(name)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnsrewrite::DnsRewriteRule;

    /// A policy with every global default allowed and only the given overrides.
    fn app_policy(rules: &[(&str, AppFirewallState)]) -> AppNetworkPolicy {
        AppNetworkPolicy {
            active: true,
            allow_wifi: true,
            allow_wifi_screen_off: true,
            allow_cellular: true,
            allow_cellular_screen_off: true,
            allow_roaming: true,
            rules: Arc::new(
                rules
                    .iter()
                    .map(|(package, state)| ((*package).to_string(), *state))
                    .collect(),
            ),
            proxy_rules: Arc::new(FxHashMap::default()),
        }
    }

    fn blocked_cellular(package: &str) -> AppNetworkPolicy {
        app_policy(&[(
            package,
            AppFirewallState {
                cellular: FirewallAccess::Block,
                ..AppFirewallState::default()
            },
        )])
    }

    fn blocked_screen_off(package: &str) -> AppNetworkPolicy {
        app_policy(&[(
            package,
            AppFirewallState {
                wifi_screen_off: FirewallAccess::Block,
                cellular_screen_off: FirewallAccess::Block,
                ..AppFirewallState::default()
            },
        )])
    }

    #[test]
    fn proxy_routing_prefers_the_strictest_per_app_answer() {
        let mut policy = AppNetworkPolicy::default();
        policy.proxy_rules = Arc::new(
            [
                ("com.example.direct".to_string(), ProxyAccess::Direct),
                ("com.example.through".to_string(), ProxyAccess::Through),
                ("com.example.inherit".to_string(), ProxyAccess::Inherit),
            ]
            .into_iter()
            .collect(),
        );
        let names = |pkg: &str| vec![pkg.to_string()];
        // The global switch is the fallback for packages with no opinion.
        assert!(policy.proxy_through(&names("com.example.inherit"), true));
        assert!(!policy.proxy_through(&names("com.example.inherit"), false));
        // Unattributed flows have no opinion and follow the global switch.
        assert!(policy.proxy_through(&[], true));
        assert!(!policy.proxy_through(&[], false));
        // An explicit answer overrides the global switch both ways.
        assert!(!policy.proxy_through(&names("com.example.direct"), true));
        assert!(policy.proxy_through(&names("com.example.through"), false));
        // A shared flow with one DIRECT owner stays off the proxy.
        let shared = vec![
            "com.example.through".to_string(),
            "com.example.direct".to_string(),
        ];
        assert!(!policy.proxy_through(&shared, true));
    }

    #[test]
    fn proxy_rules_keep_the_policy_live_without_a_firewall() {
        let mut policy = AppNetworkPolicy::default();
        assert!(policy.is_empty());
        policy.proxy_rules =
            Arc::new([("com.example".to_string(), ProxyAccess::Through)].into_iter().collect());
        assert!(!policy.is_empty(), "attribution is needed to honor routing");
    }

    #[test]
    fn config_defaults_are_battery_friendly() {
        let cfg = Config::default();
        assert!(cfg.block_quic);
        assert!(!cfg.block_doh);
        assert!(!cfg.log_allowed);
        assert!(cfg.eco_mode);
    }

    #[test]
    fn cidr_parsing() {
        let (key, prefix) = parse_cidr("1.1.1.0/24").unwrap();
        assert_eq!(prefix, 24);
        assert_eq!(key.as_ip().to_string(), "1.1.1.0");
        let (key, prefix) = parse_cidr("2606:4700::/48").unwrap();
        assert_eq!(prefix, 48);
        assert_eq!(key.as_ip().to_string(), "2606:4700::");
        assert!(parse_cidr("garbage").is_none());
        assert!(parse_cidr("1.2.3.4").is_none());
        assert!(parse_cidr("1.2.3.4/99").is_none());
    }

    #[test]
    fn default_doh_list_covers_the_big_providers() {
        let set = default_doh_cidrs();
        assert!(set.contains_v4(u32::from_be_bytes([1, 1, 1, 1])));
        assert!(set.contains_v4(u32::from_be_bytes([8, 8, 8, 8])));
        assert!(set.contains_v4(u32::from_be_bytes([9, 9, 9, 9])));
        assert!(set.contains_v4(u32::from_be_bytes([94, 140, 14, 14])));
        assert!(!set.contains_v4(u32::from_be_bytes([142, 250, 185, 194])));
        assert!(set.contains_v4(u32::from_be_bytes([1, 0, 0, 1])));
        assert!(!set.contains_v4(u32::from_be_bytes([1, 1, 2, 3])));
        assert!(!set.is_empty());
    }

    /// A dropped QUIC datagram is answered with ICMP port unreachable: a
    /// quiet drop leaves HTTP/3-first clients (Chrome's Secure DNS) retrying
    /// their handshake forever instead of falling back to the TCP path the
    /// filter can see, which costs them DNS entirely.
    #[test]
    fn a_dropped_quic_flow_is_answered_with_icmp_unreachable() {
        let core = Core::new();
        core.set_config(Config::default());
        core.handle_packet(&udp_packet(50000, [203, 0, 113, 7], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 1);
        let packets = core.take_outbox();
        let icmp = packets
            .iter()
            .find(|p| p.len() > 28 && p[0] == 0x45 && p[9] == 1)
            .expect("an ICMP error for the dropped datagram");
        assert_eq!(&icmp[12..16], &[203, 0, 113, 7], "sent by the dialed host");
        assert_eq!(&icmp[16..20], &[10, 0, 2, 15], "addressed to the client");
        assert_eq!(&icmp[20..22], &[3, 3], "destination unreachable, port");
    }

    /// QUIC to an address the DNS half learned as an encrypted-DNS endpoint
    /// is relayed, not dropped: those datagrams carry queries the filter can
    /// never see, and dropping them strands HTTP/3-first clients that moved
    /// their DoH onto QUIC after learning h3 from the first TCP connection.
    #[test]
    fn quic_to_a_learned_doh_endpoint_is_relayed() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_config(Config::default());
        core.conntrack.lock().unwrap().learn(
            &crate::dns::LearnedRecord {
                ip: packet::ip_key_from(std::net::IpAddr::from([203, 0, 113, 7])),
                ttl: 60,
            },
            "dns.google",
            false,
            now_ms(),
        );
        core.handle_packet(&udp_packet(50000, [203, 0, 113, 7], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(core.udp_nat.lock().unwrap().len(), 1);
        assert_eq!(core.stats().udp_relayed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn short_packets_are_ignored() {
        let core = Core::new();
        assert!(core.handle_packet(&[]).is_empty());
        assert!(core.handle_packet(&[0u8; 5]).is_empty());
    }

    /// The forwarder sleeps on the slow cadence only while nothing at all is
    /// in flight; one descriptor suffices to bring back the ordinary one.
    #[test]
    fn the_forwarder_sleeps_longer_when_it_has_nothing_to_do() {
        let core = Core::new();
        assert_eq!(core.forward_wait_ms(0), IDLE_WAIT_MS);

        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(fd > 0, "socket: {}", std::io::Error::last_os_error());
        core.udp_nat.lock().unwrap().insert(UdpFlow {
            fd,
            key: quic_key(50000, [203, 0, 113, 7]),
            template: Vec::new(),
            last_ms: 0,
            app_packages: Vec::new(),
            retire: false,
            proxied: false,
            sent: 0,
            recv: 0,
            traffic: None,
        });
        assert_eq!(core.forward_wait_ms(0), FORWARD_WAIT_MS);
    }

    /// Pause is a runtime gate, not a settings edit: the persisted switches
    /// stay on, the anti-bypass drops stop, and resuming restores both.
    #[test]
    fn pause_is_transient_and_stops_the_anti_bypass_drops() {
        let core = Core::new();
        core.set_config(Config::default());
        assert!(!core.is_paused());

        core.handle_packet(&udp_packet(50000, [142, 250, 185, 194], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 1);

        core.set_paused(true);
        assert!(core.is_paused());
        core.handle_packet(&udp_packet(50001, [142, 250, 185, 194], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 1);
        let cfg = core.config();
        assert!(
            cfg.ad_blocking
                && cfg.annoyances
                && cfg.browsing_security
                && cfg.tracking_protection
                && cfg.dns_protection
        );

        core.set_paused(false);
        assert!(!core.is_paused());
        core.handle_packet(&udp_packet(50002, [142, 250, 185, 194], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 2);
    }

    /// A `Core` that outlives the test: the QUIC bridge holds a
    /// `&'static Core`, the same way the process-wide engine does.
    fn leaked_core() -> &'static Core {
        Box::leak(Box::new(Core::new()))
    }

    /// HTTPS filtering armed (CA loaded) plus the HTTP/3 sub-switch. The
    /// anti-bypass drop stays on: a filtered flow must terminate first.
    fn arm_http3(core: &Core) {
        core.set_mitm_ca(Arc::new(
            crate::mitm::ca::CertificateAuthority::generate().expect("ca"),
        ));
        core.set_config(Config {
            mitm_enabled: true,
            filter_http3: true,
            ..Config::default()
        });
    }

    fn quic_key(client_port: u16, server: [u8; 4]) -> UdpKey {
        UdpKey {
            client: packet::ip_key_from(std::net::IpAddr::from([10, 0, 2, 15])),
            client_port,
            server: packet::ip_key_from(std::net::IpAddr::from(server)),
            server_port: 443,
        }
    }

    fn test_quic_flow(socket: Arc<TunUdpSocket>) -> H3Flow {
        H3Flow {
            socket,
            apps: Vec::new(),
            last_ms: now_ms(),
            pending: Vec::new(),
            pending_bytes: 0,
            sent: 0,
            recv: 0,
            traffic: None,
        }
    }

    /// HTTP/3 filtering is a sub-switch of HTTPS filtering: without the parent
    /// (or before a CA is loaded) the old QUIC drop still wins.
    #[test]
    fn http3_filtering_requires_https_filtering() {
        let core = Core::new();
        core.set_config(Config {
            filter_http3: true,
            ..Config::default()
        });
        core.handle_packet(&udp_packet(50000, [203, 0, 113, 7], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 1);
        assert!(core.udp_nat.lock().unwrap().is_empty());

        core.set_config(Config {
            mitm_enabled: true,
            filter_http3: true,
            ..Config::default()
        });
        core.handle_packet(&udp_packet(50001, [203, 0, 113, 7], 443));
        assert_eq!(
            core.stats().quic_dropped.load(Ordering::Relaxed),
            2,
            "no CA yet: the flow must never be terminated"
        );
        assert!(core.udp_nat.lock().unwrap().is_empty());
    }

    /// A five-tuple learned as "splice this" takes the NAT path even with the
    /// HTTP/3 switch on and the anti-bypass drop armed.
    #[test]
    fn a_spliced_quic_flow_takes_the_nat_path() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        arm_http3(&core);
        let key = quic_key(50002, [203, 0, 113, 7]);
        core.mark_spliced(key);
        core.handle_packet(&udp_packet(50002, [203, 0, 113, 7], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 0);
        assert_eq!(core.udp_nat.lock().unwrap().len(), 1);
        assert!(core.h3_flows.lock().unwrap().is_empty());
    }

    /// The armed bridge terminates a flow; pause and the switch-off both cut
    /// it so the client retries on a path the new state covers.
    #[test]
    fn an_armed_bridge_terminates_quic_and_pause_closes_it() {
        let core = leaked_core();
        arm_http3(core);
        let worker = core.start_h3().expect("quic thread");

        core.handle_packet(&udp_packet(50003, [203, 0, 113, 7], 443));
        {
            let flows = core.h3_flows.lock().unwrap();
            assert_eq!(flows.len(), 1);
            assert!(flows.contains_key(&quic_key(50003, [203, 0, 113, 7])));
        }

        core.set_paused(true);
        assert!(core.h3_flows.lock().unwrap().is_empty());
        core.set_paused(false);

        core.handle_packet(&udp_packet(50004, [203, 0, 113, 7], 443));
        assert_eq!(core.h3_flows.lock().unwrap().len(), 1);
        core.set_config(Config::default());
        assert!(
            core.h3_flows.lock().unwrap().is_empty(),
            "switching HTTP/3 off must end the terminated flows"
        );

        core.stop();
        let _ = worker.join();
    }

    /// Client packets buffered before the SNI lands are replayed into the NAT
    /// mapping, so an excluded host does not pay a retransmission.
    #[test]
    fn splicing_replays_the_buffered_client_flight() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        let key = quic_key(50005, [203, 0, 113, 7]);
        let raw = udp_packet(50005, [203, 0, 113, 7], 443);
        let socket = TunUdpSocket::new(
            SocketAddr::new(key.server.as_ip(), 443),
            std::sync::mpsc::sync_channel(4).0,
        );
        let mut flow = test_quic_flow(socket);
        flow.pending.push(raw);
        flow.pending_bytes = 32;
        core.h3_flows.lock().unwrap().insert(key, flow);

        core.h3_splice(key, "example.com");
        assert!(core.h3_flows.lock().unwrap().is_empty());
        assert!(core.spliced_until(key).is_some());
        assert_eq!(
            core.udp_nat.lock().unwrap().len(),
            1,
            "the buffered datagram opened a NAT mapping"
        );
    }

    /// Terminated flows are reaped after sixty idle seconds; splice verdicts
    /// lapse on their own clock.
    #[test]
    fn idle_quic_flows_and_lapsed_splices_are_reaped() {
        let core = Core::new();
        let key = quic_key(50006, [203, 0, 113, 7]);
        let socket = TunUdpSocket::new(
            SocketAddr::new(key.server.as_ip(), 443),
            std::sync::mpsc::sync_channel(1).0,
        );
        let mut flow = test_quic_flow(socket);
        flow.last_ms = 0;
        core.h3_flows.lock().unwrap().insert(key, flow);
        core.mark_spliced(key);

        let now = now_ms();
        core.expire_quic(now);
        assert!(core.h3_flows.lock().unwrap().is_empty());
        assert!(
            core.spliced_until(key).is_some(),
            "the verdict is still fresh"
        );

        core.expire_quic(now + H3_SPLICE_MS + 1);
        assert!(core.spliced_until(key).is_none());
    }

    /// What the last reaped QUIC flow reported.
    static H3_REPORTED: std::sync::Mutex<(String, u64, u64)> =
        std::sync::Mutex::new((String::new(), 0, 0));

    fn record_h3(app: &str, sent: u64, recv: u64) {
        let mut slot = H3_REPORTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = (app.to_string(), sent, recv);
    }

    fn h3_reported() -> (String, u64, u64) {
        H3_REPORTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// A terminated flow counts the client's datagrams as they are fed to
    /// quinn and reports them when it is reaped, so HTTP/3 is not invisible in
    /// the per-app totals.
    #[test]
    fn a_reaped_quic_flow_reports_its_datagrams() {
        let core = Core::new();
        let key = quic_key(50007, [203, 0, 113, 7]);
        let socket = TunUdpSocket::new(
            SocketAddr::new(key.server.as_ip(), 443),
            std::sync::mpsc::sync_channel(4).0,
        );
        let mut flow = test_quic_flow(socket);
        flow.apps = vec!["com.example.app".to_string()];
        flow.traffic = Some(record_h3);
        flow.last_ms = 0;
        core.h3_flows.lock().unwrap().insert(key, flow);

        core.feed_h3(
            key,
            &Packet::parse(&udp_packet(50007, [203, 0, 113, 7], 443)).expect("pkt"),
        );
        let sent = {
            let flows = core.h3_flows.lock().unwrap();
            flows.get(&key).expect("flow").sent
        };
        assert_eq!(sent, 4, "the fed datagram was counted");

        // Feeding refreshed the idle clock, so reap it a full window later.
        core.expire_quic(now_ms() + H3_IDLE_MS + 1);
        assert!(core.h3_flows.lock().unwrap().is_empty());
        assert_eq!(
            h3_reported(),
            ("com.example.app".to_string(), 4, 0),
            "reaping reported the client's half"
        );
    }

    /// The traffic counters cost three words per live flow, and the plan's
    /// memory note wants that pinned rather than assumed.
    #[test]
    fn a_live_flow_carries_a_known_cost() {
        let relay = std::mem::size_of::<crate::mitm::relay::Relay>();
        let udp = std::mem::size_of::<UdpFlow>();
        let h3 = std::mem::size_of::<H3Flow>();
        assert!(relay <= 1024, "a TCP relay is {relay} B");
        assert!(udp <= 192, "a datagram mapping is {udp} B");
        assert!(h3 <= 112, "a terminated QUIC flow is {h3} B");
        // The worst case for both datagram tables at the caps the engine
        // enforces: no app can grow them past this.
        let worst = udp * UDP_MAX_FLOWS + h3 * bridge::MAX_FLOWS;
        assert!(worst <= 128 * 1024, "the datagram tables cost {worst} B");
    }

    /// A full table loses the new flow instead of growing without bound; the
    /// client falls back to TCP (or keeps the drop the QUIC switch asked for).
    #[test]
    fn a_full_quic_table_drops_new_flows() {
        let core = Core::new();
        arm_http3(&core);
        let socket = TunUdpSocket::new(
            SocketAddr::new(IpKey::V4(0).as_ip(), 443),
            std::sync::mpsc::sync_channel(1).0,
        );
        {
            let mut flows = core.h3_flows.lock().unwrap();
            for i in 0..bridge::MAX_FLOWS {
                let key = quic_key(40000 + i as u16, [203, 0, 113, 7]);
                flows.insert(key, test_quic_flow(Arc::clone(&socket)));
            }
        }
        core.handle_packet(&udp_packet(51000, [203, 0, 113, 7], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 1);
        assert!(core.udp_nat.lock().unwrap().is_empty());
    }

    /// The proxy carries TCP and non-DNS UDP, but QUIC is dropped so the
    /// client falls back to TCP, which the proxy filters end to end.
    #[test]
    fn a_proxy_carries_tcp_so_quic_is_dropped() {
        let core = Core::new();
        arm_http3(&core);
        core.set_config(Config {
            mitm_enabled: true,
            filter_http3: true,
            proxy: Some(Arc::new(crate::socks5::ProxyEndpoint {
                addr: packet::ip_key_from("127.0.0.1".parse().unwrap()),
                port: 1080,
                username: String::new(),
                password: String::new(),
                automatic: false,
            })),
            ..Config::default()
        });
        core.handle_packet(&udp_packet(51001, [203, 0, 113, 7], 443));
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 1);
        assert!(core.udp_nat.lock().unwrap().is_empty());
    }

    /// The QUIC worker is per session: `stop()` ends it and a later start gets
    /// a fresh bridge instead of a dead one.
    #[test]
    fn the_quic_worker_restarts_after_stop() {
        let core = leaked_core();
        let worker = core.start_h3().expect("first quic thread");
        assert!(core.h3.lock().unwrap().is_some());
        core.stop();
        let _ = worker.join();
        assert!(core.h3.lock().unwrap().is_none());

        let worker = core.start_h3().expect("second quic thread");
        assert!(core.h3.lock().unwrap().is_some());
        core.stop();
        let _ = worker.join();
    }

    fn udp6_packet(src_port: u16, dst: std::net::Ipv6Addr, dst_port: u16) -> Vec<u8> {
        let src: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        packet::build_udp(
            packet::ip_key_from(std::net::IpAddr::V6(src)),
            src_port,
            packet::ip_key_from(std::net::IpAddr::V6(dst)),
            dst_port,
            &[1, 2, 3, 4],
        )
        .expect("ipv6 udp packet")
    }

    /// IPv6 UDP/443 follows the same route as IPv4: the five-tuple includes
    /// version-tagged addresses, so v6 flows terminate instead of leaking.
    #[test]
    fn quic_flows_terminate_over_ipv6() {
        let core = leaked_core();
        arm_http3(core);
        let worker = core.start_h3().expect("quic thread");
        let server: std::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
        core.handle_packet(&udp6_packet(52000, server, 443));

        let key = UdpKey {
            client: packet::ip_key_from("2001:db8::2".parse().unwrap()),
            client_port: 52000,
            server: packet::ip_key_from(std::net::IpAddr::V6(server)),
            server_port: 443,
        };
        let flows = core.h3_flows.lock().unwrap();
        assert_eq!(flows.len(), 1);
        assert!(flows.contains_key(&key));
        drop(flows);

        core.stop();
        let _ = worker.join();
    }

    /// The injection origin is a TCP-only local service: a QUIC probe sent to
    /// it must neither open a flow nor leak towards a reserved address.
    #[test]
    fn a_datagram_to_the_local_origin_is_ignored() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        arm_http3(&core);
        core.handle_packet(&udp_packet(52001, [192, 0, 2, 1], 443));
        assert!(core.h3_flows.lock().unwrap().is_empty());
        assert!(core.udp_nat.lock().unwrap().is_empty());
        assert_eq!(core.stats().quic_dropped.load(Ordering::Relaxed), 0);
    }

    /// The pre-SNI client flight is buffered for a possible splice, so a
    /// client that keeps sending must not grow that buffer without bound.
    #[test]
    fn a_burst_into_a_flow_keeps_the_replay_buffer_bounded() {
        let core = leaked_core();
        arm_http3(core);
        let worker = core.start_h3().expect("quic thread");
        let raw = packet::build_udp(
            packet::ip_key_from("10.0.2.15".parse().unwrap()),
            52002,
            packet::ip_key_from("203.0.113.7".parse().unwrap()),
            443,
            &[0u8; 1000],
        )
        .expect("packet");
        for _ in 0..200 {
            core.handle_packet(&raw);
        }

        let flows = core.h3_flows.lock().unwrap();
        let flow = flows.values().next().expect("flow");
        assert!(flow.pending_bytes <= H3_PENDING_BYTES);
        assert!(flow.pending.len() <= 16);
        drop(flows);

        core.stop();
        let _ = worker.join();
    }

    /// The packet path and the QUIC worker share the flow table from different
    /// threads; concurrent bursts must not deadlock, panic or corrupt it.
    #[test]
    fn concurrent_bursts_keep_one_flow_per_five_tuple() {
        let core = leaked_core();
        arm_http3(core);
        let worker = core.start_h3().expect("quic thread");
        std::thread::scope(|scope| {
            for thread in 0..4u16 {
                scope.spawn(move || {
                    let port = 53000 + thread * 10;
                    let raw = packet::build_udp(
                        packet::ip_key_from("10.0.2.15".parse().unwrap()),
                        port,
                        packet::ip_key_from("203.0.113.7".parse().unwrap()),
                        443,
                        &[0u8; 64],
                    )
                    .expect("packet");
                    for _ in 0..250 {
                        core.handle_packet(&raw);
                    }
                });
            }
        });

        let flows = core.h3_flows.lock().unwrap();
        assert_eq!(flows.len(), 4, "one terminated flow per client port");
        assert!(flows
            .values()
            .all(|flow| flow.pending_bytes <= H3_PENDING_BYTES));
        drop(flows);

        core.stop();
        let _ = worker.join();
    }

    /// Minimal IPv4 TCP SYN; only the fields `Packet::parse` reads matter.
    fn tcp_packet(dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let total = 20 + 20;
        let mut p = Vec::with_capacity(total);
        p.extend_from_slice(&[0x45, 0x00]);
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 6, 0x00, 0x00]);
        p.extend_from_slice(&[10, 0, 2, 15]);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // seq
        p.extend_from_slice(&0u32.to_be_bytes()); // ack
        p.extend_from_slice(&[0x50, 0x02]); // data offset 5, SYN
        p.extend_from_slice(&0xffffu16.to_be_bytes()); // window
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum, urgent
        crate::packet::fix_ipv4_checksum(&mut p);
        p
    }

    /// The provider ranges include plain DNS and DoT endpoints next to their
    /// DoH one. Blocking every port there resets the strict Private DNS
    /// connection (1.1.1.1:853), which has no fallback and leaves the device
    /// with no resolution at all.
    #[test]
    fn encrypted_dns_ranges_only_block_https() {
        let core = Core::new();
        let cfg = Config {
            block_dot: false,
            block_doh: true,
            ..Config::default()
        };

        let dot_raw = tcp_packet([1, 1, 1, 1], 853);
        let dot = Packet::parse(&dot_raw).expect("dot syn");
        assert_eq!(
            core.tcp_blocked(&dot, &cfg),
            None,
            "DoT to a DoH provider must survive while its RST is off"
        );

        let doh_raw = tcp_packet([1, 1, 1, 1], 443);
        let doh = Packet::parse(&doh_raw).expect("doh syn");
        assert_eq!(
            core.tcp_blocked(&doh, &cfg),
            Some("connection to encrypted DNS blocked"),
            "DoH on 443 is still blocked, and the log says why"
        );

        let plain_raw = udp_packet(40000, [1, 1, 1, 1], 53);
        let plain = Packet::parse(&plain_raw).expect("dns datagram");
        assert!(
            !core.udp_blocked(&plain, &cfg),
            "plain DNS on a DoH provider range reaches the filter"
        );

        let doh3_raw = udp_packet(40000, [1, 1, 1, 1], 443);
        let doh3 = Packet::parse(&doh3_raw).expect("doh3 datagram");
        assert!(
            core.udp_blocked(&doh3, &cfg),
            "DoH3 on 443 is still blocked"
        );
    }

    /// Chrome with a custom secure DNS provider has no insecure fallback, so
    /// refusing its DoH endpoint leaves the browser with no DNS at all. The
    /// default allows DoH; hostname filtering rides the TLS path instead.
    #[test]
    fn doh_is_allowed_when_the_switch_is_off() {
        let core = Core::new();
        let cfg = Config::default();
        assert!(!cfg.block_doh);

        let doh_raw = tcp_packet([1, 1, 1, 1], 443);
        let doh = Packet::parse(&doh_raw).expect("doh syn");
        assert_eq!(core.tcp_blocked(&doh, &cfg), None);

        let doh3_raw = udp_packet(40000, [1, 1, 1, 1], 443);
        let doh3 = Packet::parse(&doh3_raw).expect("doh3 datagram");
        assert!(!core.udp_blocked(&doh3, &cfg));
    }

    #[test]
    fn snapshot_is_well_formed() {
        let core = Core::new();
        let snap = core.snapshot();
        assert_eq!(snap.packets_total, 0);
        assert_eq!(snap.active_rules, 0);
        assert_eq!(snap.pending_dns, 0);
    }

    #[test]
    fn a_new_ca_drops_the_resolver_that_cached_the_old_one() {
        let core = Core::new();
        let before = core.mitm_resolver();
        // The same CA keeps the same resolver...
        assert!(Arc::ptr_eq(&before, &core.mitm_resolver()));
        // ...but a swap (a restored CA, or a regenerated one) must rebuild it,
        // or port 443 would keep being signed by the previous key.
        let ca = crate::mitm::ca::CertificateAuthority::generate().expect("ca");
        core.set_mitm_ca(Arc::new(ca));
        assert!(!Arc::ptr_eq(&before, &core.mitm_resolver()));
    }

    /// Minimal IPv4 UDP packet; only the fields `Packet::parse` reads matter.
    fn udp_packet(src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let payload = [1u8, 2, 3, 4];
        let total = 20 + 8 + payload.len();
        let mut p = Vec::with_capacity(total);
        p.extend_from_slice(&[0x45, 0x00]);
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00]);
        p.extend_from_slice(&[10, 0, 2, 15]);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&src_port.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]);
        p.extend_from_slice(&payload);
        crate::packet::fix_ipv4_checksum(&mut p);
        p
    }

    /// Minimal IPv4 UDP packet carrying a DNS query for `host`.
    ///
    /// The resolver address is TEST-NET-3: it is not in the encrypted-DNS list,
    /// so the datagram takes the plain DNS path the filter sits on.
    fn dns_query_packet(host: &str) -> Vec<u8> {
        dns_query_packet_typed(host, crate::dns::TYPE_A)
    }

    fn dns_query_packet_typed(host: &str, qtype: u16) -> Vec<u8> {
        let mut dns = Vec::new();
        dns.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        dns.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
        dns.extend_from_slice(&1u16.to_be_bytes()); // one question
        dns.extend_from_slice(&[0u8; 6]); // no answer/authority/additional records
        for label in host.split('.') {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&qtype.to_be_bytes());
        dns.extend_from_slice(&1u16.to_be_bytes()); // class IN

        let total = 20 + 8 + dns.len();
        let mut p = Vec::with_capacity(total);
        p.extend_from_slice(&[0x45, 0x00]);
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00]);
        p.extend_from_slice(&[10, 0, 2, 15]);
        p.extend_from_slice(&[203, 0, 113, 53]);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]);
        p.extend_from_slice(&dns);
        crate::packet::fix_ipv4_checksum(&mut p);
        p
    }

    /// The rcode of the first DNS answer the engine produced for a query,
    /// whether it was returned straight away or written to the tun.
    fn dns_reply_rcode(core: &Core, host: &str) -> Option<u8> {
        let mut out = core.handle_packet(&dns_query_packet(host));
        out.extend(core.take_outbox());
        let raw = out.first()?;
        let pkt = Packet::parse(raw)?;
        pkt.l4_payload().get(3).map(|flags| flags & 0x0f)
    }

    /// The A/AAAA addresses of the first answer the engine produced.
    fn dns_reply_addresses(core: &Core, query: Vec<u8>) -> Vec<std::net::IpAddr> {
        let mut out = core.handle_packet(&query);
        out.extend(core.take_outbox());
        let Some(raw) = out.first() else {
            return Vec::new();
        };
        let Some(pkt) = Packet::parse(raw) else {
            return Vec::new();
        };
        crate::dns::answer_addresses(pkt.l4_payload())
            .into_iter()
            .map(|(ip, _)| ip)
            .collect()
    }

    /// A `$redirect` host is left to the HTTPS path, which is the only place
    /// that can serve the resource — but only while TLS termination is armed,
    /// and only for resources this app actually carries. Without either, the
    /// host is sinkholed exactly as before.
    #[test]
    fn a_redirect_host_is_left_for_the_https_path() {
        let dir = std::env::temp_dir().join("adfree-engine-dns");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("dns-list.txt");
        std::fs::write(
            &path,
            "||ads.test^\n||redir.test^$redirect=nooptext\n||media.test^$redirect=noopmp4-1s\n||missing.test^$redirect=not-a-resource\n",
        )
        .expect("write list");
        let lists = vec![FilterListInfo {
            id: 1,
            name: "dns-list".to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format: crate::filter::ListFormat::Standard,
            category: 0,
            trusted: true,
            rule_count: 0,
            last_error: None,
            dns_only: false,
        }];

        /// The sinkhole the default block mode asks for.
        const NXDOMAIN: u8 = 3;

        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_lists(lists, Vec::new());
        // No TLS termination: a redirect host is a block like any other. (The
        // upstream is not up in a test either, which is why the forwarded case
        // can only be told apart by *not* being the sinkhole.)
        assert_eq!(dns_reply_rcode(&core, "ads.test"), Some(NXDOMAIN));
        assert_eq!(dns_reply_rcode(&core, "redir.test"), Some(NXDOMAIN));

        core.set_config(Config {
            mitm_enabled: true,
            ..Config::default()
        });
        core.set_mitm_ca(Arc::new(
            crate::mitm::ca::CertificateAuthority::generate().expect("ca"),
        ));
        assert_ne!(dns_reply_rcode(&core, "redir.test"), Some(NXDOMAIN));
        assert_ne!(dns_reply_rcode(&core, "media.test"), Some(NXDOMAIN));
        // A resource this app does not carry is no reason to let a host
        // through: nothing could serve it.
        assert_eq!(dns_reply_rcode(&core, "missing.test"), Some(NXDOMAIN));
        // A plain block stays a block.
        assert_eq!(dns_reply_rcode(&core, "ads.test"), Some(NXDOMAIN));

        core.set_config(Config {
            mitm_enabled: false,
            ..Config::default()
        });
        assert_eq!(dns_reply_rcode(&core, "redir.test"), Some(NXDOMAIN));
    }

    /// Some apps retry a refused request until it succeeds. After a few
    /// attempts inside the window the host is forwarded, which stops the
    /// storm; turning the switch off restores plain blocking.
    #[test]
    fn a_blocked_query_retry_loop_is_forwarded() {
        let dir = std::env::temp_dir().join("adfree-engine-smart");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("smart-list.txt");
        std::fs::write(&path, "||ads.test^\n").expect("write list");
        let lists = vec![FilterListInfo {
            id: 1,
            name: "smart-list".to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format: crate::filter::ListFormat::Standard,
            category: 0,
            trusted: true,
            rule_count: 0,
            last_error: None,
            dns_only: false,
        }];
        const NXDOMAIN: u8 = 3;
        const SERVFAIL: u8 = 2;

        let core = Core::new();
        core.set_lists(lists.clone(), Vec::new());
        for _ in 0..crate::smart::RETRY_LIMIT - 1 {
            assert_eq!(dns_reply_rcode(&core, "ads.test"), Some(NXDOMAIN));
        }
        // The limit is reached: the query goes to the upstream path instead
        // of the sinkhole. No sockets are protected in a test, so the
        // forwarder answers SERVFAIL — anything but NXDOMAIN is the signal.
        assert_eq!(dns_reply_rcode(&core, "ads.test"), Some(SERVFAIL));
        assert_eq!(dns_reply_rcode(&core, "ads.test"), Some(SERVFAIL));

        let plain = Core::new();
        plain.set_lists(lists, Vec::new());
        plain.set_config(Config {
            smart_filtering: false,
            ..Config::default()
        });
        for _ in 0..crate::smart::RETRY_LIMIT * 2 {
            assert_eq!(dns_reply_rcode(&plain, "ads.test"), Some(NXDOMAIN));
        }
    }

    /// A repeated query is answered from the per-host decision cache, which
    /// keeps the verdict and drops the rule text. The log row still has to
    /// name the list and the rule that blocked the host.
    #[test]
    fn a_cached_block_still_logs_its_rule() {
        let dir = std::env::temp_dir().join("adfree-engine-cached-log");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("cached-list.txt");
        std::fs::write(&path, "||cached.ads.test^\n").expect("write list");
        let lists = vec![FilterListInfo {
            id: 1,
            name: "cached-list".to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format: crate::filter::ListFormat::Standard,
            category: 0,
            trusted: true,
            rule_count: 0,
            last_error: None,
            dns_only: false,
        }];
        const NXDOMAIN: u8 = 3;

        let core = Core::new();
        core.set_lists(lists, Vec::new());
        assert_eq!(dns_reply_rcode(&core, "cached.ads.test"), Some(NXDOMAIN));
        assert_eq!(dns_reply_rcode(&core, "cached.ads.test"), Some(NXDOMAIN));

        let events = core.take_events(10);
        assert_eq!(events.len(), 2, "one row per query");
        for event in &events {
            assert_eq!(event.domain(), "cached.ads.test");
            assert_eq!(event.rule(), "||cached.ads.test^");
            assert_eq!(event.list(), "cached-list");
        }
    }

    /// A rewrite is what the user asked for, so it answers before the filter
    /// lists and only for the address family it names.
    #[test]
    fn a_user_rewrite_answers_before_the_lists() {
        let dir = std::env::temp_dir().join("adfree-engine-rewrite");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("rewrite-list.txt");
        std::fs::write(&path, "||nas.home^\n").expect("write list");
        let lists = vec![FilterListInfo {
            id: 1,
            name: "rewrite-list".to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format: crate::filter::ListFormat::Standard,
            category: 0,
            trusted: true,
            rule_count: 0,
            last_error: None,
            dns_only: false,
        }];
        const NXDOMAIN: u8 = 3;
        const NOERROR: u8 = 0;
        const SERVFAIL: u8 = 2;

        let core = Core::new();
        core.set_lists(lists, Vec::new());
        assert_eq!(dns_reply_rcode(&core, "nas.home"), Some(NXDOMAIN));

        core.set_dns_rewrites(vec![
            DnsRewriteRule::parse("nas.home", "192.168.1.10").expect("rule"),
            DnsRewriteRule::parse("lab.home", "192.168.1.11").expect("rule"),
        ]);
        assert_eq!(
            dns_reply_addresses(&core, dns_query_packet("nas.home")),
            vec!["192.168.1.10".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(dns_reply_rcode(&core, "nas.home"), Some(NOERROR));

        // An A rule does not invent an AAAA answer: that query is forwarded,
        // which in a test without sockets is a fast SERVFAIL. (For `nas.home`
        // the list still blocks the other family, which is the second half of
        // the same rule: a rewrite overrides the list only for what it names.)
        assert_eq!(
            dns_reply_addresses(
                &core,
                dns_query_packet_typed("lab.home", crate::dns::TYPE_AAAA)
            ),
            Vec::<std::net::IpAddr>::new()
        );
        assert_eq!(
            dns_reply_rcode_typed(&core, "lab.home", crate::dns::TYPE_AAAA),
            Some(SERVFAIL)
        );
        assert_eq!(
            dns_reply_rcode_typed(&core, "nas.home", crate::dns::TYPE_AAAA),
            Some(NXDOMAIN)
        );

        // Withdrawing the rule restores the list verdict.
        core.set_dns_rewrites(Vec::new());
        assert_eq!(dns_reply_rcode(&core, "nas.home"), Some(NXDOMAIN));
    }

    /// SafeSearch answers the original name with the filtered host's cached
    /// addresses; a cold lookup is forwarded instead of blocking the query.
    #[test]
    fn safe_search_answers_the_original_name_from_the_filtered_host() {
        const NOERROR: u8 = 0;
        const SERVFAIL: u8 = 2;

        let core = Core::new();
        core.set_config(Config {
            safe_search: true,
            ..Config::default()
        });

        // Cold: no upstream sockets, so the lookup cannot complete here.
        assert_eq!(dns_reply_rcode(&core, "www.google.com"), Some(SERVFAIL));

        let address = "216.239.32.32".parse::<std::net::IpAddr>().unwrap();
        core.remember_safe_search("forcesafesearch.google.com", &[(address, 120)], now_ms());
        assert_eq!(
            dns_reply_addresses(&core, dns_query_packet("www.google.com")),
            vec![address]
        );
        assert_eq!(dns_reply_rcode(&core, "www.google.com"), Some(NOERROR));

        // A host with no safe variant is never rewritten.
        assert_eq!(dns_reply_rcode(&core, "example.com"), Some(SERVFAIL));
    }

    /// The rcode for a query of any type.
    fn dns_reply_rcode_typed(core: &Core, host: &str, qtype: u16) -> Option<u8> {
        let mut out = core.handle_packet(&dns_query_packet_typed(host, qtype));
        out.extend(core.take_outbox());
        let raw = out.first()?;
        let pkt = Packet::parse(raw)?;
        pkt.l4_payload().get(3).map(|flags| flags & 0x0f)
    }

    #[test]
    fn an_encrypted_query_without_a_protector_fails_fast() {
        const SERVFAIL: u8 = 2;
        let core = Core::new();
        core.set_secure_resolver(Some(
            crate::dnssecure::SecureResolver::from_parts(
                crate::state::model::DnsProtocol::Dot,
                "127.0.0.1",
                853,
            )
            .expect("resolver"),
        ));
        // No protector: connecting would send the handshake into the tunnel.
        assert_eq!(dns_reply_rcode(&core, "example.com"), Some(SERVFAIL));
    }

    #[test]
    fn a_failed_secure_exchange_answers_servfail() {
        const SERVFAIL: u8 = 2;

        // A port nobody listens on: the worker's connect is refused at once.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("address").port();
        drop(listener);

        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_secure_resolver(Some(
            crate::dnssecure::SecureResolver::from_parts(
                crate::state::model::DnsProtocol::Dot,
                "127.0.0.1",
                port,
            )
            .expect("resolver"),
        ));
        core.start_secure_workers();
        assert!(core
            .handle_packet(&dns_query_packet("example.com"))
            .is_empty());

        let reply = wait_for_secure_reply(&core);
        core.handle_secure_reply(reply);
        let out = core.take_outbox();
        let lowest = out
            .first()
            .and_then(|raw| Packet::parse(raw))
            .and_then(|pkt| pkt.l4_payload().get(3).map(|flags| flags & 0x0f));
        assert_eq!(lowest, Some(SERVFAIL));
    }

    #[test]
    fn a_secure_answer_is_rewritten_for_the_client() {
        const NOERROR: u8 = 0;

        let core = Core::new();
        let query_packet = dns_query_packet("example.com");
        let address = "203.0.113.5".parse::<std::net::IpAddr>().unwrap();
        let message = {
            let packet = Packet::parse(&query_packet).expect("packet");
            let query = dns::parse_query(packet.l4_payload()).expect("query");
            let message = dns::answer_message(&query, &[address], 60).expect("answer");
            core.secure_outstanding.store(1, Ordering::Relaxed);
            core.handle_secure_reply(crate::dnssecure::SecureReply {
                pending: crate::upstream::Pending {
                    client_txid: query.id,
                    socket: 0,
                    packet: query_packet.clone(),
                    sent_ms: now_ms(),
                    purpose: crate::upstream::Purpose::Client,
                    safe_host: String::new(),
                    via_backup: false,
                    backup_after_ms: crate::upstream::SECURE_BACKUP_AFTER_MS,
                },
                message: message.clone(),
            });
            message
        };
        assert!(!message.is_empty());

        let out = core.take_outbox();
        let raw = out.first().expect("answer packet");
        let pkt = Packet::parse(raw).expect("packet");
        assert_eq!(dns::answer_addresses(pkt.l4_payload()), vec![(address, 60)]);
        assert_eq!(
            pkt.l4_payload().get(3).map(|flags| flags & 0x0f),
            Some(NOERROR)
        );
    }

    /// Hands `core` an upstream answer for `packet`, as the forwarder would.
    fn deliver_answer(core: &Core, packet: &[u8], ttl: u32) -> std::net::IpAddr {
        let address = "203.0.113.5".parse::<std::net::IpAddr>().unwrap();
        let parsed = Packet::parse(packet).expect("packet");
        let query = dns::parse_query(parsed.l4_payload()).expect("query");
        let message = dns::answer_message(&query, &[address], ttl).expect("answer");
        core.secure_outstanding.store(1, Ordering::Relaxed);
        core.handle_secure_reply(crate::dnssecure::SecureReply {
            pending: crate::upstream::Pending {
                client_txid: query.id,
                socket: 0,
                packet: packet.to_vec(),
                sent_ms: now_ms(),
                purpose: crate::upstream::Purpose::Client,
                safe_host: String::new(),
                via_backup: false,
                backup_after_ms: crate::upstream::SECURE_BACKUP_AFTER_MS,
            },
            message,
        });
        core.take_outbox();
        address
    }

    #[test]
    fn a_repeated_query_is_answered_from_the_cache() {
        let core = Core::new();
        let address = deliver_answer(&core, &dns_query_packet("cached.example"), 300);
        let before = core.snapshot();

        // A different transaction id, so a patched echo is visible.
        let mut second = dns_query_packet("cached.example");
        second[28] = 0xab;
        second[29] = 0xcd;
        let mut out = core.handle_packet(&second);
        out.extend(core.take_outbox());
        let raw = out.first().expect("answer packet");
        let pkt = Packet::parse(raw).expect("packet");
        assert_eq!(&pkt.l4_payload()[0..2], &[0xab, 0xcd]);
        assert_eq!(pkt.l4_payload()[2] & 0x80, 0x80, "it is a response");
        assert_eq!(dns::answer_addresses(pkt.l4_payload()), vec![(address, 300)]);

        // Nothing was forwarded; the client was answered from memory. (The
        // reply counter only moves when a tun accepted the write, and a test
        // has none, so the forwarded-query count is the signal.)
        let after = core.snapshot();
        assert_eq!(after.dns_queries, before.dns_queries);
    }

    #[test]
    fn a_cached_answer_never_outranks_a_new_block() {
        let core = Core::new();
        deliver_answer(&core, &dns_query_packet("later.test"), 300);

        let dir = std::env::temp_dir().join("adfree-engine-dns-cache");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("cache-list.txt");
        std::fs::write(&path, "||later.test^\n").expect("write list");
        core.set_lists(
            vec![FilterListInfo {
                id: 1,
                name: "cache-list".to_string(),
                url: String::new(),
                enabled: true,
                local_path: Some(path),
                format: crate::filter::ListFormat::Standard,
                category: 0,
                trusted: true,
                rule_count: 0,
                last_error: None,
                dns_only: false,
            }],
            Vec::new(),
        );
        // The filter runs before the cache: a blocked host is sinkholed even
        // though a fresh answer for it is sitting in memory.
        assert_eq!(dns_reply_rcode(&core, "later.test"), Some(3));
    }

    #[test]
    fn the_probe_rejects_an_address_the_form_cannot_use() {
        let core = Core::new();
        let result = core.probe_dns(crate::state::model::DnsProtocol::Doh, "1.1.1.1");
        assert!(!result.ok);
        assert_eq!(
            result.error,
            crate::state::model::DnsProbeError::AddressInvalid
        );
    }

    fn wait_for_secure_reply(core: &Core) -> crate::dnssecure::SecureReply {
        for _ in 0..500 {
            if let Some(reply) = core.take_secure_replies().into_iter().next() {
                return reply;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the encrypted-DNS worker never answered");
    }

    struct AllowAll;

    impl crate::api::SocketProtector for AllowAll {
        fn protect(&self, _fd: i32) -> bool {
            true
        }
    }

    /// Answers every flow lookup with one uid, the way Android's
    /// `getConnectionOwnerUid` does for a real process.
    struct FixedUid(u32);

    impl crate::api::ConnectionUidLookup for FixedUid {
        fn owner_uid(
            &self,
            _protocol: u8,
            _local_ip: String,
            _local_port: u16,
            _remote_ip: String,
            _remote_port: u16,
        ) -> Option<u32> {
            Some(self.0)
        }
    }

    #[test]
    fn udp_without_a_protector_is_dropped_not_relayed() {
        let core = Core::new();
        let pkt = udp_packet(40000, [203, 0, 113, 7], 5000);
        assert!(core.handle_packet(&pkt).is_empty());
        // The app never offered a protector, so no descriptor may be created
        // (an unprotected socket would loop the datagram right back in).
        assert!(core.udp_nat.lock().unwrap().is_empty());
        assert_eq!(core.snapshot().udp_dropped, 1);
        // The flow cannot exist at all, so the client learns that now rather
        // than waiting out a timeout.
        let packets = core.take_outbox();
        let icmp = packets
            .iter()
            .find(|p| p.len() > 28 && p[0] == 0x45 && p[9] == 1)
            .expect("an ICMP error for the unrelayable datagram");
        assert_eq!(&icmp[20..22], &[3, 3], "destination unreachable, port");
    }

    #[test]
    fn udp_flows_are_natted_per_endpoint() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        let pkt = udp_packet(40000, [203, 0, 113, 7], 5000);
        assert!(core.handle_packet(&pkt).is_empty());
        assert_eq!(core.udp_nat.lock().unwrap().len(), 1);
        // A retransmission (same four-tuple) reuses the mapping...
        core.handle_packet(&pkt);
        assert_eq!(core.udp_nat.lock().unwrap().len(), 1);
        // ...while the same server on another port is a new one.
        core.handle_packet(&udp_packet(40000, [203, 0, 113, 7], 5001));
        assert_eq!(core.udp_nat.lock().unwrap().len(), 2);
        assert_eq!(core.snapshot().udp_dropped, 0);
        // Three datagrams went out: two on the first mapping, one on the other.
        assert_eq!(core.stats.snapshot().udp_relayed, 3);
    }

    /// A datagram mapping is a connection like any other: reaping it hands its
    /// byte counters to the store, so UDP traffic shows up in the app's "data
    /// used" figure rather than only TCP.
    ///
    /// Goes through the process-wide engine because that is where the sink reads
    /// its store from; the configuration it needs is put back afterwards.
    #[test]
    fn a_reaped_udp_mapping_lands_in_the_store() {
        let dir = std::env::temp_dir().join(format!(
            "adfree-engine-udp-traffic-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let core = crate::core();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_uid_lookup(Arc::new(FixedUid(10_123)));
        core.set_uid_apps(vec![(10_123, vec!["com.example.udpsink".to_string()])]);
        // Any per-app entry makes the attribution path run; the proxy itself
        // stays off, so the mapping is a plain connected socket.
        let policy = AppNetworkPolicy {
            proxy_rules: Arc::new(
                [("com.example.udpsink".to_string(), ProxyAccess::Inherit)]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        };
        core.set_app_network_policy(policy);
        core.set_lists(Vec::new(), vec!["||ads.test^".to_string()]);
        assert!(core.set_data_root(dir.to_str().expect("utf-8 path")));

        // A blocked query gives the app a decision row, which is what the
        // per-app join hangs the traffic on.
        assert_eq!(dns_reply_rcode(core, "ads.test"), Some(3));

        let pkt = udp_packet(50020, [203, 0, 113, 9], 4433);
        core.handle_packet(&pkt);
        core.handle_packet(&pkt);
        assert_eq!(core.udp_nat.lock().unwrap().len(), 1, "one mapping");

        core.udp_nat
            .lock()
            .unwrap()
            .expire(now_ms() + crate::udpnat::UDP_FLOW_IDLE_MS + 1);
        assert!(core.udp_nat.lock().unwrap().is_empty());

        let store = core.store.get().expect("store");
        store.log_flush();
        let usage = store.log_usage_by_app(0, -1);
        let row = usage
            .iter()
            .find(|r| r.app == "com.example.udpsink")
            .expect("the app row");
        assert_eq!(row.bytes_sent, 8, "two datagrams of four bytes");
        assert_eq!(row.bytes_recv, 0, "nothing came back on the mapping");
        let totals = store.log_window_totals(0, -1);
        assert!(
            totals.bytes_sent >= 8,
            "the header adds the DNS answer bytes too: {}",
            totals.bytes_sent
        );
        // Leave the shared engine as the other tests expect to find it.
        core.set_app_network_policy(AppNetworkPolicy::default());
        *core.uid_lookup.write().unwrap() = None;
        core.set_uid_apps(Vec::new());
        core.set_lists(Vec::new(), Vec::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A SYN-only IPv4 packet (only the fields `Packet::parse` reads matter).
    fn tcp_syn(src_port: u16, dst: [u8; 4], dst_port: u16) -> Vec<u8> {
        let total = 40;
        let mut p = Vec::with_capacity(total);
        p.extend_from_slice(&[0x45, 0x00]);
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 6, 0x00, 0x00]);
        p.extend_from_slice(&[10, 0, 2, 15]);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&src_port.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&7u32.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
        crate::packet::fix_ipv4_checksum(&mut p);
        p
    }

    /// The per-app HTTPS exclusion needs the flow's package even when no loaded
    /// list carries an `$app=` rule; without that gate the proxy would see an
    /// unattributed flow and decrypt it again.
    #[test]
    fn https_skip_apps_force_flow_attribution_without_app_rules() {
        let core = Core::new();
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.pin_uid_for_port(40000, 10_123);
        let raw = tcp_syn(40000, [93, 184, 216, 34], 443);
        let pkt = Packet::parse(&raw).expect("packet");
        let off = Config::default();
        let on = Config {
            mitm_enabled: true,
            ..Config::default()
        };

        assert!(
            core.apps_for_packet(&pkt, &off).is_empty(),
            "nothing asks for attribution yet"
        );
        core.set_https_skip_apps(vec!["com.example.news".to_string()]);
        assert_eq!(
            core.apps_for_packet(&pkt, &off),
            vec!["com.example.news".to_string()],
            "the exclusion list alone must resolve the app"
        );

        // With HTTPS filtering armed the proxy names the app on every request
        // it blocks, so an intercepted flow is attributed even with no rule
        // asking for it.
        core.set_https_skip_apps(Vec::new());
        assert!(core.apps_for_packet(&pkt, &on).is_empty(), "no CA yet");
        core.set_mitm_ca(Arc::new(
            crate::mitm::ca::CertificateAuthority::generate().expect("ca"),
        ));
        assert_eq!(
            core.apps_for_packet(&pkt, &on),
            vec!["com.example.news".to_string()]
        );
    }

    /// A client that refuses the forged certificate (`CertificateUnknown`)
    /// must not keep losing every HTTPS connection: the app is learned, its
    /// future flows are attributed even with no rule asking, and the splice
    /// set a new session opens with carries its package.
    #[test]
    fn an_app_that_rejects_the_ca_is_spliced_from_then_on() {
        let core = Core::new();
        core.set_uid_apps(vec![(
            10_123,
            vec!["com.google.android.googlequicksearchbox".to_string()],
        )]);
        core.pin_uid_for_port(40000, 10_123);
        let raw = tcp_syn(40000, [142, 250, 80, 46], 443);
        let pkt = Packet::parse(&raw).expect("packet");
        let off = Config::default();

        assert!(
            core.apps_for_packet(&pkt, &off).is_empty(),
            "nothing asks for attribution yet"
        );
        assert!(!core
            .effective_https_skip_apps()
            .contains("com.google.android.googlequicksearchbox"));

        // The origin-facing feed's alerts say nothing about the client.
        core.note_client_cert_rejection(
            "client process_new_packets: received fatal alert: CertificateUnknown",
            &["com.google.android.googlequicksearchbox".to_string()],
            "android.apis.google.com",
        );
        assert!(core.effective_https_skip_apps().is_empty(), "not learned");

        core.note_client_cert_rejection(
            "process_new_packets: received fatal alert: CertificateUnknown",
            &["com.google.android.googlequicksearchbox".to_string()],
            "android.apis.google.com",
        );
        assert_eq!(
            core.apps_for_packet(&pkt, &off),
            vec!["com.google.android.googlequicksearchbox".to_string()],
            "a learned app is attributed even with no rule asking"
        );
        assert!(core
            .effective_https_skip_apps()
            .contains("com.google.android.googlequicksearchbox"));
    }

    /// `ensure_ca` re-loads the persisted pair on every UI refresh: that must
    /// not undo what the apps taught, while a genuinely new CA should.
    #[test]
    fn reloading_the_same_ca_keeps_rejections_but_a_new_ca_clears_them() {
        let core = Core::new();
        let ca = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("first CA"));
        core.set_mitm_ca(Arc::clone(&ca));
        core.note_client_cert_rejection(
            "process_new_packets: received fatal alert: CertificateUnknown",
            &["com.example.news".to_string()],
            "example.com",
        );
        assert!(core
            .effective_https_skip_apps()
            .contains("com.example.news"));

        core.set_mitm_ca(Arc::clone(&ca));
        assert!(
            core.effective_https_skip_apps()
                .contains("com.example.news"),
            "the same certificate is not a reason to retry"
        );

        let fresh = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("second CA"));
        core.set_mitm_ca(fresh);
        assert!(
            core.effective_https_skip_apps().is_empty(),
            "a new key invalidates what the apps learned about the old one"
        );
    }

    /// Unattributed flows teach nothing, and non-certificate alerts (a broken
    /// handshake, say) must not quietly disable filtering for an app.
    #[test]
    fn only_a_certificate_alert_from_a_named_app_is_learned() {
        let core = Core::new();
        core.note_client_cert_rejection(
            "process_new_packets: received fatal alert: CertificateUnknown",
            &[],
            "example.com",
        );
        core.note_client_cert_rejection(
            "process_new_packets: received fatal alert: HandshakeFailure",
            &["com.example.news".to_string()],
            "example.com",
        );
        core.note_client_cert_rejection(
            "process_new_packets: peer sent no certificates",
            &["com.example.news".to_string()],
            "example.com",
        );
        assert!(core.effective_https_skip_apps().is_empty());
    }

    /// The app firewall is evaluated before any peer socket is opened: the
    /// same flow that is relayed on Wi-Fi is reset on cellular when its app is
    /// barred from that network.
    #[test]
    fn app_policy_blocks_a_tcp_flow_on_the_wrong_network() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.pin_uid_for_port(40000, 10_123);
        core.set_app_network_policy(blocked_cellular("com.example.news"));

        core.set_network_type(NETWORK_WIFI);
        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        core.run_setup_jobs();
        assert_eq!(core.relay_count(), 1, "Wi-Fi is allowed by this policy");

        let other = Core::new();
        other.set_socket_protector(Arc::new(AllowAll));
        other.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        other.pin_uid_for_port(40000, 10_123);
        other.set_app_network_policy(blocked_cellular("com.example.news"));
        other.set_network_type(NETWORK_CELLULAR);
        other.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        other.run_setup_jobs();
        // The answered flow is refused before any socket is opened; the entry
        // is marked closed for the poller to reap.
        assert!(
            other
                .relays
                .lock()
                .unwrap()
                .get(40000)
                .is_some_and(|r| r.closed && r.peer_fd < 0),
            "no peer socket may be opened"
        );
        let reset = other.take_outbox();
        assert_eq!(reset.len(), 1, "the client gets one segment back");
        // IPv4 + TCP headers: the flags byte is 13 bytes into the TCP header.
        assert_eq!(reset[0][33] & 0x04, 0x04, "and it is a RST");
    }

    /// Global defaults apply to an app with no rule of its own: blocking
    /// Wi-Fi globally resets the flow without any per-app entry.
    #[test]
    fn a_global_default_blocks_an_unlisted_app() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.pin_uid_for_port(40000, 10_123);
        let mut policy = app_policy(&[]);
        policy.allow_wifi = false;
        core.set_app_network_policy(policy);
        core.set_network_type(NETWORK_WIFI);

        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        core.run_setup_jobs();
        assert!(
            core.relays
                .lock()
                .unwrap()
                .get(40000)
                .is_some_and(|r| r.closed && r.peer_fd < 0),
            "the inherited default must cut the flow"
        );
    }

    /// An explicit per-app allow wins over a blocked global default.
    #[test]
    fn an_explicit_allow_overrides_a_global_block() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.pin_uid_for_port(40000, 10_123);
        let mut policy = app_policy(&[(
            "com.example.news",
            AppFirewallState {
                wifi: FirewallAccess::Allow,
                ..AppFirewallState::default()
            },
        )]);
        policy.allow_wifi = false;
        core.set_app_network_policy(policy);
        core.set_network_type(NETWORK_WIFI);

        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        core.run_setup_jobs();
        assert_eq!(core.relay_count(), 1, "the app's own rule wins");
    }

    /// Roaming is a separate cellular dimension: the same flow is relayed on a
    /// home network and reset on a visited one.
    #[test]
    fn a_roaming_rule_only_applies_while_roaming() {
        let home = Core::new();
        home.set_socket_protector(Arc::new(AllowAll));
        home.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        home.pin_uid_for_port(40000, 10_123);
        home.set_app_network_policy(app_policy(&[(
            "com.example.news",
            AppFirewallState {
                roaming: FirewallAccess::Block,
                ..AppFirewallState::default()
            },
        )]));
        home.set_network_type(NETWORK_CELLULAR);
        home.set_roaming(false);
        home.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        home.run_setup_jobs();
        assert_eq!(home.relay_count(), 1, "home cellular is allowed");

        let visited = Core::new();
        visited.set_socket_protector(Arc::new(AllowAll));
        visited.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        visited.pin_uid_for_port(40000, 10_123);
        visited.set_app_network_policy(app_policy(&[(
            "com.example.news",
            AppFirewallState {
                roaming: FirewallAccess::Block,
                ..AppFirewallState::default()
            },
        )]));
        visited.set_network_type(NETWORK_CELLULAR);
        visited.set_roaming(true);
        visited.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        visited.run_setup_jobs();
        assert!(
            visited
                .relays
                .lock()
                .unwrap()
                .get(40000)
                .is_some_and(|r| r.closed && r.peer_fd < 0),
            "roaming must cut the flow"
        );
    }

    /// A flow that is refused after its SYN-ACK has gone out is reset with our
    /// own sequence: the client's stack is ESTABLISHED there, and a reset
    /// built from its SYN again (seq 0) would be dropped as out of window.
    #[test]
    fn a_refused_flow_resets_with_the_answered_sequence() {
        use std::os::fd::IntoRawFd;
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        // A real descriptor so the writes count as delivered, as on device.
        let tun = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("write end")
            .into_raw_fd();
        core.set_tun_fd_for_test(tun);
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.pin_uid_for_port(40000, 10_123);
        core.set_app_network_policy(blocked_cellular("com.example.news"));
        core.set_network_type(NETWORK_CELLULAR);

        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        core.run_setup_jobs();
        let out = core.take_outbox();
        assert_eq!(out.len(), 2, "the answer and then the refusal");
        let syn_ack = Packet::parse(&out[0]).expect("answer");
        let rst = Packet::parse(&out[1]).expect("refusal");
        assert!(syn_ack.is_syn && syn_ack.is_ack, "the SYN-ACK goes first");
        assert!(rst.is_rst, "then the flow is reset");
        assert_eq!(
            rst.seq, syn_ack.seq,
            "the reset must sit in the client's receive window"
        );
    }

    /// Turning the screen off cuts an open flow belonging to an app that is
    /// configured to stay offline, without waiting for a reconnect.
    #[test]
    fn screen_off_cuts_open_flows_of_restricted_apps() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.pin_uid_for_port(40000, 10_123);
        core.set_app_network_policy(blocked_screen_off("com.example.news"));
        core.set_network_type(NETWORK_WIFI);
        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        // The flow only carries its app once the setup worker attributed it.
        core.run_setup_jobs();
        assert_eq!(core.relay_count(), 1);

        core.set_screen_off(true);
        {
            let guard = core.relays.lock().unwrap();
            assert!(
                guard.get(40000).map(|r| r.closed).unwrap_or(false),
                "the relay is marked closed so the forwarder can reap it safely"
            );
        }
        core.prune_relays();
        assert_eq!(core.relay_count(), 0);
    }

    /// DNS queries from a restricted app are refused before the filter lists
    /// run: a filtered answer would still leak whether a host exists.
    #[test]
    fn app_policy_blocks_dns_before_the_lists() {
        let core = Core::new();
        core.set_uid_lookup(Arc::new(FixedUid(10_123)));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.set_network_type(NETWORK_CELLULAR);
        core.set_app_network_policy(blocked_cellular("com.example.news"));

        assert_eq!(dns_reply_rcode(&core, "example.test"), Some(3));
        assert_eq!(
            core.snapshot().dns_queries,
            0,
            "the blocked query never reaches the upstream resolver"
        );

        core.set_app_network_policy(AppNetworkPolicy::default());
        assert_ne!(
            dns_reply_rcode(&core, "example.test"),
            Some(3),
            "clearing the policy restores forwarding"
        );
    }

    /// The log names the app: a query the lists block carries the package of
    /// the flow that asked, so the UI can group a domain by its owner.
    #[test]
    fn a_blocked_query_names_the_app_in_the_log() {
        let dir = std::env::temp_dir().join("adfree-engine-app-log");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("app-list.txt");
        std::fs::write(&path, "||ads.test^\n").expect("write list");
        let lists = vec![FilterListInfo {
            id: 1,
            name: "app-list".to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format: crate::filter::ListFormat::Standard,
            category: 0,
            trusted: true,
            rule_count: 0,
            last_error: None,
            dns_only: false,
        }];

        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_uid_lookup(Arc::new(FixedUid(10_123)));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.set_lists(lists, Vec::new());

        assert_eq!(dns_reply_rcode(&core, "ads.test"), Some(3));
        let events = core.take_events(8);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].domain(), "ads.test");
        assert_eq!(events[0].app(), "com.example.news");
    }

    /// The same attribution on the allowed path — but only when the user asked
    /// for allowed requests in the log; otherwise nothing extra is looked up.
    #[test]
    fn an_allowed_query_names_the_app_only_when_logged() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_uid_lookup(Arc::new(FixedUid(10_123)));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);

        dns_reply_rcode(&core, "example.test");
        assert!(core.take_events(8).is_empty());

        core.set_config(Config {
            log_allowed: true,
            ..Config::default()
        });
        dns_reply_rcode(&core, "example.test");
        let events = core.take_events(8);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].app(), "com.example.news");
    }

    /// A TCP reset issued by the app firewall names the app too, even though
    /// no `$app=` rule asked for attribution.
    #[test]
    fn a_firewall_reset_names_the_app_in_the_log() {
        use std::os::unix::io::IntoRawFd;

        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        // A reset only enters the log once it actually reached the device; a
        // real descriptor is what makes `write_raw` succeed in a test.
        let tun = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("write end")
            .into_raw_fd();
        core.set_tun_fd_for_test(tun);
        core.set_uid_lookup(Arc::new(FixedUid(10_123)));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.set_network_type(NETWORK_CELLULAR);
        core.set_app_network_policy(blocked_cellular("com.example.news"));

        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        core.run_setup_jobs();
        let events = core.take_events(8);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, crate::events::ACTION_TCP_RESET);
        assert_eq!(events[0].app(), "com.example.news");
    }

    #[test]
    fn a_failed_peer_connect_is_retried_on_a_fresh_socket() {
        use std::os::fd::IntoRawFd;
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("addr").port();
        // Stand-ins: the relay's old peer descriptor (live, so the retry can
        // close it) and the SYN that remembers where the flow was going.
        let old_fd = std::net::TcpStream::connect(("127.0.0.1", port))
            .expect("first connection")
            .into_raw_fd();
        let flow = crate::mitm::tcp::Flow::new(
            crate::packet::IpKey::V4(u32::from_be_bytes([10, 0, 2, 15])),
            40000,
            port,
            7,
            7000,
        );
        let relay = crate::mitm::relay::Relay::new_plain(
            flow,
            old_fd,
            tcp_syn(40000, [127, 0, 0, 1], port),
            crate::mitm::relay::DEFAULT_MSS,
            true,
        );
        core.relays.lock().unwrap().insert(relay);

        assert!(core.retry_peer_connect(40000));
        {
            let guard = core.relays.lock().unwrap();
            let relay = guard.get(40000).expect("relay");
            assert_ne!(relay.peer_fd, old_fd, "a fresh descriptor was installed");
            assert_eq!(relay.connect_retries, 1);
        }
        // The second connection in the listener's backlog is the retry.
        listener.set_nonblocking(true).expect("nonblocking");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut accepted = 0;
        while accepted < 2 && std::time::Instant::now() < deadline {
            if listener.accept().is_ok() {
                accepted += 1;
            } else {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        assert_eq!(accepted, 2, "the retry opened a real second connection");
        // Only one retry: a second failure is left to the client's own retry.
        core.relays
            .lock()
            .unwrap()
            .get_mut(40000)
            .unwrap()
            .connecting = true;
        assert!(!core.retry_peer_connect(40000));
    }

    /// Through a SOCKS5 endpoint the proxy speaks first: application bytes
    /// stay queued until its CONNECT reply, so a status byte can never be
    /// spliced to the origin and origin bytes can never be read as a reply.
    #[test]
    fn proxy_handshake_gates_client_bytes_until_the_tunnel_is_open() {
        use std::io::{Read, Write};
        use std::os::fd::IntoRawFd;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("proxy listener");
        let proxy_port = listener.local_addr().expect("addr").port();
        // The proxy holds the connection open past the echo so the relay is
        // still in the table when the test inspects it.
        let (hold, wait) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("proxy accepts");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("timeout");

            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).expect("greeting");
            assert_eq!(greeting, [5, 1, 0], "one unauthenticated method offered");
            stream.write_all(&[5, 0]).expect("method reply");

            let mut connect = [0u8; 10];
            stream.read_exact(&mut connect).expect("connect request");
            assert_eq!(
                connect,
                [5, 1, 0, 1, 93, 184, 216, 34, 0, 80],
                "CONNECT names the destination, not the proxy"
            );

            // Anything readable before the reply is application data that
            // escaped the gate.
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(150)))
                .expect("timeout");
            let mut probe = [0u8; 1];
            let early = match stream.read(&mut probe) {
                Ok(n) => {
                    assert_eq!(n, 0, "the engine wrote {n} bytes before the CONNECT reply");
                    true
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    false
                }
                Err(e) => panic!("proxy read failed: {e}"),
            };

            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("connect reply");
            let mut hello = [0u8; 5];
            stream.read_exact(&mut hello).expect("application bytes");
            assert_eq!(&hello, b"hello", "the queued bytes follow the handshake");
            stream.write_all(b"world").expect("origin echo");
            let _ = wait.recv_timeout(std::time::Duration::from_secs(5));
            early
        });

        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        let peer = std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect");
        let dst = crate::packet::IpKey::V4(u32::from_be_bytes([93, 184, 216, 34]));
        let flow = crate::mitm::tcp::Flow::new(
            crate::packet::IpKey::V4(u32::from_be_bytes([10, 0, 2, 15])),
            40000,
            80,
            7,
            7000,
        );
        let mut relay = crate::mitm::relay::Relay::new_plain(
            flow,
            peer.into_raw_fd(),
            tcp_syn(40000, [93, 184, 216, 34], 80),
            crate::mitm::relay::DEFAULT_MSS,
            false,
        );
        relay.handshake =
            Some(crate::socks5::Socks5Handshake::new(dst, 80, None).expect("handshake"));
        core.relays.lock().unwrap().insert(relay);

        // The same queue the TCP path feeds. It must not reach the proxy until
        // the CONNECT reply has been read.
        core.push_to_peer(40000, b"hello");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut echoed = Vec::new();
        while echoed.is_empty() && std::time::Instant::now() < deadline {
            core.pump_once(20);
            for raw in core.take_outbox() {
                if raw.ends_with(b"world") {
                    echoed.extend_from_slice(b"world");
                }
            }
        }
        assert_eq!(echoed, b"world", "the origin echo reached the client");
        assert!(
            core.relays
                .lock()
                .unwrap()
                .get(40000)
                .is_some_and(|r| r.handshake.as_ref().is_some_and(|h| h.is_done())),
            "the negotiation completed before data flowed"
        );
        drop(hold);
        assert!(
            !server.join().expect("proxy thread"),
            "application bytes arrived before CONNECT succeeded"
        );
    }

    /// The plain retry after an ECH rejection needs a *fresh* peer socket: the
    /// rejected TLS connection cannot carry the new hello. Whatever was queued
    /// for the old handshake must go with it.
    #[test]
    fn an_ech_retry_reopens_the_peer_socket_and_drops_its_queue() {
        use std::os::fd::IntoRawFd;
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let old_fd = std::net::TcpStream::connect(("127.0.0.1", port))
            .expect("first connection")
            .into_raw_fd();
        let flow = crate::mitm::tcp::Flow::new(
            crate::packet::IpKey::V4(u32::from_be_bytes([10, 0, 2, 15])),
            40001,
            port,
            7,
            7001,
        );
        let mut relay = crate::mitm::relay::Relay::new_plain(
            flow,
            old_fd,
            tcp_syn(40001, [127, 0, 0, 1], port),
            crate::mitm::relay::DEFAULT_MSS,
            false,
        );
        // Bytes queued for the rejected handshake never belonged on the retry.
        relay.pending_to_peer.extend_from_slice(b"stale");
        core.relays.lock().unwrap().insert(relay);

        assert!(core.restart_peer_socket(40001));
        {
            let guard = core.relays.lock().unwrap();
            let relay = guard.get(40001).expect("relay");
            assert_ne!(relay.peer_fd, old_fd, "a fresh descriptor was installed");
            assert!(
                relay.pending_to_peer.is_empty(),
                "the old handshake's queue must be dropped"
            );
        }
        listener.set_nonblocking(true).expect("nonblocking");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut accepted = 0;
        while accepted < 2 && std::time::Instant::now() < deadline {
            if listener.accept().is_ok() {
                accepted += 1;
            } else {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        assert_eq!(accepted, 2, "the retry opened a real second connection");

        // A relay that already finished is not resurrected.
        core.relays.lock().unwrap().get_mut(40001).unwrap().closed = true;
        assert!(!core.restart_peer_socket(40001));
    }

    /// Cosmetics have no per-rule category, so a module switch must recompile
    /// the lists: the ads list drops out of the build and its hiding stops,
    /// while the tracking list keeps hiding.
    #[test]
    fn switching_a_module_off_recompiles_cosmetics() {
        let dir = std::env::temp_dir().join("adfree-engine-modules");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let ads = dir.join("ads-cosmetics.txt");
        std::fs::write(&ads, "example.com##.ad-hide\n").expect("write ads");
        let tracker = dir.join("track-cosmetics.txt");
        std::fs::write(&tracker, "example.com##.track-hide\n").expect("write tracker");
        let list = |id: u16, name: &str, path: std::path::PathBuf, category: u8| FilterListInfo {
            id,
            name: name.to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format: crate::filter::ListFormat::Standard,
            category,
            trusted: true,
            rule_count: 0,
            last_error: None,
            dns_only: false,
        };
        let core = Core::new();
        core.set_lists(
            vec![
                list(1, "ads", ads, crate::filter::CAT_AD),
                list(2, "tracking", tracker, crate::filter::CAT_TRACKER),
            ],
            Vec::new(),
        );
        let engine = core.filter_engine();
        let before = engine.generation();
        assert!(engine
            .cosmetic_resources("https://example.com/")
            .hide_selectors
            .iter()
            .any(|s| s == ".ad-hide"));
        assert!(engine
            .cosmetic_resources("https://example.com/")
            .hide_selectors
            .iter()
            .any(|s| s == ".track-hide"));

        core.set_config(Config {
            ad_blocking: false,
            ..Config::default()
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while engine.generation() == before && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            engine.generation() > before,
            "the module switch never recompiled the lists"
        );
        let res = engine.cosmetic_resources("https://example.com/");
        assert!(
            !res.hide_selectors.iter().any(|s| s == ".ad-hide"),
            "{:?}",
            res.hide_selectors
        );
        assert!(res.hide_selectors.iter().any(|s| s == ".track-hide"));
    }

    #[test]
    fn the_log_names_the_dns_server_the_way_adguard_does() {
        let core = Core::new();
        core.set_resolver("1.1.1.1:5353".parse().unwrap());
        assert_eq!(core.dns_server_text(), "udp://1.1.1.1:5353");

        let dot = crate::dnssecure::SecureResolver::from_parts(
            crate::state::model::DnsProtocol::Dot,
            "dns.example",
            853,
        )
        .unwrap();
        core.set_secure_resolver(Some(dot));
        assert_eq!(core.dns_server_text(), "tls://dns.example:853");

        let doh = crate::dnssecure::SecureResolver::from_parts(
            crate::state::model::DnsProtocol::Doh,
            "https://dns.example/dns-query",
            443,
        )
        .unwrap();
        core.set_secure_resolver(Some(doh));
        assert_eq!(core.dns_server_text(), "https://dns.example:443/dns-query");
    }

    /// The platform pushes lists through the async path (`core_set_lists_async`),
    /// so the data root itself has to arm the engine cache; one wired only into
    /// the sync rebuild never runs in the app.
    #[test]
    fn the_async_list_push_persists_the_engine_cache() {
        let root =
            std::env::temp_dir().join(format!("adfree-engine-async-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let body = root.join("base.txt");
        std::fs::write(&body, "||async-cache.test^\n").unwrap();
        let lists = vec![FilterListInfo {
            id: 1,
            name: "base".to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(body),
            format: crate::filter::ListFormat::Standard,
            category: 0,
            trusted: true,
            rule_count: 0,
            last_error: None,
            dns_only: false,
        }];

        let first = Core::new();
        assert!(first.set_data_root(root.to_str().unwrap()));
        first.rebuild_async(lists.clone(), Vec::new());
        let cache = root.join("engine").join("engine.dat");
        let mut written = false;
        for _ in 0..200 {
            if cache.exists() {
                written = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            written,
            "the async build must leave its cache under the data root"
        );

        let second = Core::new();
        assert!(second.set_data_root(root.to_str().unwrap()));
        second.set_lists(lists, Vec::new());
        assert!(second.filter.last_build_cached());
        assert!(second.filter.check_host("async-cache.test").blocked);
        let _ = std::fs::remove_dir_all(&root);
    }
}
