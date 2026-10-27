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
//! ```
//!
//! Two threads total, each blocked in a `poll` most of the time: that is why a
//! DNS level filter costs a fraction of a percent of battery. Nothing is
//! allocated on the packet path but the (rare) synthetic DNS answer. Relays are
//! added from the tun-thread but only reaped on the dns-thread (which also
//! polls their descriptors), so a peer socket is never closed under `poll()`.

use crate::conntrack::{CidrSet, ConnTable, IpVerdict};
use crate::dns::{self, BlockMode, Query};
use crate::events::{self, Event, EventLog};
use crate::filter::{FilterEngine, FilterListInfo, HostVerdict};
use crate::fxhash::{hash_str, FxHashMap};
use crate::packet::{self, IpKey, Packet, PROTO_TCP, PROTO_UDP};
use crate::socks5::Socks5Handshake;
use crate::stats::{self, Stats};
use crate::udpnat::{UdpFlow, UdpKey, UdpNat, UDP_MAX_FLOWS};
use crate::uidmap::UidMap;
use crate::upstream::Upstream;
use crate::util::{now_ms, now_ns};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU16, AtomicU64, AtomicU8, Ordering};
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

/// Rough upstream cost of one blocked request; only used for the "data saved"
/// figure shown in the UI.
const BYTES_PER_BLOCKED_REQUEST: u64 = 48 * 1024;

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
    /// Leave ECHConfigs in DNS answers so clients can run ECH end to end.
    ///
    /// Off by default: ECH hides the inner name from the proxy, so an ECH
    /// hello can only be spliced, and the host behind it goes unfiltered.
    /// Turned on, the user chooses that trade for every host that offers ECH;
    /// clients that do not use ECH (GREASE, older stacks) are still terminated
    /// and filtered as usual. See `mitm::ech`.
    pub full_ech: bool,
    pub block_quic: bool,
    pub block_doh: bool,
    pub block_dot: bool,
    /// Ad blocking module (ad + annoyance categories).
    pub ad_blocking: bool,
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
    /// Send search-engine queries to their family-filtered host and answer the
    /// original name with the filtered addresses (see [`crate::safesearch`]).
    pub safe_search: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mitm_enabled: false,
            full_ech: false,
            block_quic: true,
            block_doh: true,
            block_dot: true,
            ad_blocking: true,
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

/// Per-app firewall rules: packages that must not use the current network, or
/// must not reach the network at all while the screen is off.
///
/// The sets are pushed by the platform (only it knows package names), and a
/// flow is evaluated against them when it opens and again whenever the network
/// or screen state changes.
#[derive(Clone, Default)]
pub struct AppNetworkPolicy {
    cellular_blocked: Arc<HashSet<String>>,
    wifi_blocked: Arc<HashSet<String>>,
    screen_off_blocked: Arc<HashSet<String>>,
}

impl AppNetworkPolicy {
    pub fn is_empty(&self) -> bool {
        self.cellular_blocked.is_empty()
            && self.wifi_blocked.is_empty()
            && self.screen_off_blocked.is_empty()
    }

    fn blocked_reason(
        &self,
        packages: &[String],
        network: u8,
        screen_off: bool,
    ) -> Option<&'static str> {
        if packages.is_empty() {
            return None;
        }
        if screen_off && packages.iter().any(|p| self.screen_off_blocked.contains(p)) {
            return Some("app blocked while the screen is off");
        }
        match network {
            NETWORK_WIFI if packages.iter().any(|p| self.wifi_blocked.contains(p)) => {
                Some("app not allowed on Wi-Fi")
            }
            NETWORK_CELLULAR if packages.iter().any(|p| self.cellular_blocked.contains(p)) => {
                Some("app not allowed on cellular data")
            }
            _ => None,
        }
    }
}

/// Result of trying to open a TCP relay.
enum RelayStart {
    Started,
    /// The app firewall refuses this flow; the caller resets the client and
    /// logs this reason instead of the generic "connection dropped".
    Blocked(&'static str),
    /// No descriptor or no route: fail the client now.
    Failed,
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
    conntrack: Mutex<ConnTable>,
    /// Hosts let through because their block is being retried in a loop
    /// (see [`crate::smart`]); disabled by the matching config switch.
    smart: Mutex<crate::smart::SmartFilter>,
    /// User `host -> address` answers, checked before the filter lists.
    dns_rewrites: RwLock<Vec<crate::dnsrewrite::DnsRewriteRule>>,
    /// SafeSearch addresses, keyed by the filtered host: the extra lookup is
    /// an RTT the next query for the same engine should not pay.
    safe_cache: Mutex<FxHashMap<String, SafeCacheEntry>>,
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
    running: AtomicBool,
    tun_fd: AtomicI32,
    tx_counter: AtomicU64,
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
    core.log_event(event);
    core.stats.add(&core.stats.bytes_saved, u64::from(saved));
}

/// A uid can resolve to several packages (shared uid); the log names the first
/// one, which is what the platform's attribution reported.
fn first_app(packages: &[String]) -> &str {
    packages.first().map(String::as_str).unwrap_or("")
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

impl Core {
    pub fn new() -> Self {
        let resolver = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(94, 140, 14, 14), 53));
        Core {
            cfg: RwLock::new(Config::default()),
            filter: Arc::new(FilterEngine::new()),
            lists: RwLock::new(Vec::new()),
            user_rules: RwLock::new(Vec::new()),
            upstream: Mutex::new(Upstream::new(resolver)),
            wake_fd: unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) },
            conntrack: Mutex::new(ConnTable::new()),
            smart: Mutex::new(crate::smart::SmartFilter::new(true)),
            dns_rewrites: RwLock::new(Vec::new()),
            safe_cache: Mutex::new(FxHashMap::default()),
            doh_ips: RwLock::new(default_doh_cidrs()),
            stats: Arc::new(Stats::new()),
            events: Mutex::new(EventLog::default()),
            store: OnceLock::new(),
            state: OnceLock::new(),
            uidmap: Mutex::new(UidMap::new()),
            uid_apps: RwLock::new(FxHashMap::default()),
            uid_lookup: RwLock::new(None),
            screen_off: AtomicBool::new(false),
            running: AtomicBool::new(false),
            tun_fd: AtomicI32::new(-1),
            tx_counter: AtomicU64::new(0),
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
        // Cosmetics and scriptlets have no per-rule category, so an ads or
        // tracking switch changes which lists belong in the build as well as
        // the live category gate below.
        let lists_changed = {
            let old = self.cfg.read().unwrap();
            old.ad_blocking != cfg.ad_blocking || old.tracking_protection != cfg.tracking_protection
        };
        // The filter engine owns the hot-path copy so a module switch takes
        // effect on the next packet without recompiling the lists.
        self.filter
            .set_module_flags(cfg.ad_blocking, cfg.tracking_protection, cfg.dns_protection);
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
        *self.cfg.write().unwrap() = cfg;
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
    pub fn set_app_network_policy(
        &self,
        cellular_blocked: Vec<String>,
        wifi_blocked: Vec<String>,
        screen_off_blocked: Vec<String>,
    ) {
        *self.app_network_policy.write().unwrap() = Arc::new(AppNetworkPolicy {
            cellular_blocked: Arc::new(cellular_blocked.into_iter().collect()),
            wifi_blocked: Arc::new(wifi_blocked.into_iter().collect()),
            screen_off_blocked: Arc::new(screen_off_blocked.into_iter().collect()),
        });
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

    /// The reason this collection of packages may not use the network right
    /// now, or `None` when it is allowed.
    fn app_blocked_reason(&self, packages: &[String]) -> Option<&'static str> {
        let policy = Arc::clone(&*self.app_network_policy.read().unwrap());
        policy.blocked_reason(packages, self.network_type(), self.is_screen_off())
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
                        .blocked_reason(&relay.app_packages, network, screen_off)
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
                    .blocked_reason(&flow.app_packages, network, screen_off)
                    .is_some()
            });
        }
        // The forwarder owns relay and mapping descriptors; it has to run the
        // removals and may be parked in poll() right now.
        self.wake();
    }

    pub fn is_screen_off(&self) -> bool {
        self.screen_off.load(Ordering::Relaxed)
    }

    pub fn set_resolver(&self, addr: SocketAddr) {
        *self.resolver.write().unwrap() = addr;
        {
            let mut upstream = self.upstream.lock().unwrap();
            upstream.set_resolver(addr);
            upstream.clear();
        }
        // Answers learned from the previous server are no longer valid.
        self.conntrack.lock().unwrap().clear();
    }

    pub fn set_socket_fds(&self, fds: &[RawFd]) {
        self.upstream.lock().unwrap().set_socket_fds(fds);
    }

    /// Replaces the user's DNS rewrites. The caller parses the rows, so a
    /// hand-edited store can only hand over rules the validator accepted.
    pub fn set_dns_rewrites(&self, rules: Vec<crate::dnsrewrite::DnsRewriteRule>) {
        *self.dns_rewrites.write().unwrap() = rules;
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
        self.tun_fd.store(tun_fd, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);
        let statics: &'static Core = core();
        let mut workers = Vec::with_capacity(2);
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
        // The forwarder may be halfway through its one-second wait; without
        // this it would only notice the stop on the next timeout.
        self.wake();
    }

    /// Asks the forwarder to take a pass now.
    ///
    /// One 8-byte counter write on the eventfd. Ignored when creation failed:
    /// the loop's timeout cadence still services everything, just later.
    fn wake(&self) {
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
        if pkt.proto == PROTO_UDP && pkt.dst_port == 53 {
            self.stats.inc(&self.stats.packets_dns);
            self.handle_dns(&pkt, &cfg, &mut out);
        } else if pkt.proto == PROTO_UDP && pkt.dst_port == 443 && cfg.block_quic {
            // QUIC/HTTP3 cannot be filtered without breaking TLS; dropping it
            // sends the client back to TCP where we can see the host.
            self.stats.inc(&self.stats.quic_dropped);
        } else if pkt.proto == PROTO_UDP && pkt.dst_port == 853 && cfg.block_dot {
            self.stats.inc(&self.stats.udp_dropped);
        } else if pkt.proto == PROTO_UDP
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
        if self.tcp_blocked(pkt, cfg) {
            self.reset_tcp(pkt);
            return;
        }
        if pkt.is_syn {
            match self.start_tcp_relay(pkt, cfg, out) {
                RelayStart::Started => {}
                // The app firewall refused this flow: say why instead of the
                // generic "connection dropped" the other failures get.
                RelayStart::Blocked(reason) => self.reset_tcp_with_reason(pkt, reason),
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
    /// NAT port on the server's side) for the whole session. Replies are handled
    /// by [`Core::handle_udp_reply`].
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
        let payload = pkt.l4_payload();
        let mut nat = self.udp_nat.lock().unwrap();
        if let Some(flow) = nat.get_mut(&key) {
            flow.last_ms = now_ms();
            // The lock is held across the send so the polling thread cannot
            // retire (and close) the descriptor between the lookup and the
            // syscall. `send()` on a non-blocking socket never blocks.
            Self::send_udp(flow.fd, payload);
            self.stats.inc(&self.stats.udp_relayed);
            return;
        }
        if nat.len() >= UDP_MAX_FLOWS {
            // One app spraying destination ports must not drain the descriptor
            // budget; the flow simply loses its packets, like a full NAT box.
            drop(nat);
            self.stats.inc(&self.stats.udp_dropped);
            return;
        }
        // A new mapping. The lock is dropped first because `open_peer_socket`
        // makes a `protect()` binder round-trip; only the tun thread inserts,
        // and the socket is not in the table yet, so nothing can touch it
        // while it is built. The cap cannot fill up meanwhile: the table only
        // shrinks while unlocked.
        drop(nat);
        let app_packages = if self.app_network_policy.read().unwrap().is_empty() {
            Vec::new()
        } else {
            let packages = self.apps_for_udp(pkt);
            if self.app_blocked_reason(&packages).is_some() {
                self.stats.inc(&self.stats.udp_dropped);
                return;
            }
            packages
        };
        let Some(fd) = self.open_peer_socket(server, libc::SOCK_DGRAM) else {
            self.stats.inc(&self.stats.udp_dropped);
            return;
        };
        if connect_fd(fd, server, pkt.dst_port) == Connect::Failed {
            unsafe { libc::close(fd) };
            self.stats.inc(&self.stats.udp_dropped);
            return;
        }
        Self::send_udp(fd, payload);
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
        });
        // The reply can only arrive on this descriptor, so the forwarder must
        // start watching it now rather than at its next cadence tick.
        self.wake();
    }

    /// Fire-and-forget datagram send: UDP has no retransmission, and a packet
    /// the socket refuses would be lost on the wire anyway.
    fn send_udp(fd: RawFd, payload: &[u8]) {
        unsafe {
            libc::send(
                fd,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                libc::MSG_NOSIGNAL,
            );
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
            let mut saw_data = false;
            if !payload.is_empty() {
                match relay.on_client_segment(pkt.seq, payload) {
                    Ok((peer_bytes, to_client)) => {
                        to_peer = peer_bytes;
                        saw_data = true;
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
            if relay.pending_to_peer.is_empty() && !relay.flushing {
                relay.peer_fd
            } else {
                relay.shutdown_after_flush = true;
                return;
            }
        };
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

    /// Starts a relay for a new TCP flow.
    ///
    /// Port 443 is additionally TLS-terminated (and filtered) when HTTPS
    /// filtering is armed and the destination hostname is known; every other
    /// flow is a transparent splice. The one exception is the app's own
    /// injection origin: it is answered locally, with no peer socket at all.
    fn start_tcp_relay(
        &self,
        pkt: &Packet<'_>,
        cfg: &Config,
        out: &mut Vec<Vec<u8>>,
    ) -> RelayStart {
        let Some(client_ip) = pkt.src_ip() else {
            return RelayStart::Failed;
        };
        let Some(dst) = pkt.dst_ip() else {
            return RelayStart::Failed;
        };
        // The per-app firewall decides before any socket is opened: a blocked
        // app costs no upstream connection and gets a RST with a reason.
        let app_packages = self.apps_for_packet(pkt, cfg);
        if let Some(reason) = self.app_blocked_reason(&app_packages) {
            return RelayStart::Blocked(reason);
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
            return RelayStart::Failed;
        }
        // In proxy mode every flow dials the SOCKS5 endpoint; the destination
        // moves into the CONNECT request instead of the socket address. The
        // local injection origin never leaves the device, so it stays direct.
        let proxy = if local { None } else { cfg.proxy.clone() };
        let handshake = match &proxy {
            Some(p) => match Socks5Handshake::new(dst, pkt.dst_port, p.credentials()) {
                Ok(h) => Some(h),
                Err(e) => {
                    crate::logbuf::push(&format!("relay: {e}"));
                    return RelayStart::Failed;
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
                return RelayStart::Failed;
            };
            let connect = connect_fd(peer_fd, dial_addr, dial_port);
            if connect == Connect::Failed {
                crate::logbuf::push(if proxy.is_some() {
                    "relay: connect() to the SOCKS5 proxy failed"
                } else {
                    "relay: connect() to the peer failed"
                });
                unsafe { libc::close(peer_fd) };
                return RelayStart::Failed;
            }
            (peer_fd, connect == Connect::InProgress)
        };
        let flow = crate::mitm::tcp::Flow::new(
            client_ip,
            pkt.src_port,
            pkt.dst_port,
            pkt.seq,
            crate::mitm::tcp::initial_seq(pkt.seq as u64),
        );
        let mss = self.relay_mss(pkt);
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
                    proxy.set_cosmetic(self.filter.clone());
                    proxy.set_stats(Arc::clone(&self.stats));
                    Some(proxy)
                }
                Err(e) => {
                    crate::logbuf::push(&format!("open local session: {e}"));
                    return RelayStart::Failed;
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
                    // same opt-in, same CA gate, nothing extra to configure.
                    proxy.set_cosmetic(self.filter.clone());
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
        let mut relay = match session {
            Some(proxy) => crate::mitm::relay::Relay::new_tls(
                flow,
                peer_fd,
                proxy,
                pkt.raw.to_vec(),
                mss,
                connecting,
            ),
            None => crate::mitm::relay::Relay::new_plain(
                flow,
                peer_fd,
                pkt.raw.to_vec(),
                mss,
                connecting,
            ),
        };
        // Our own SYN-ACK (the client-facing sequence starts here).
        let syn_ack = match crate::mitm::segment::build_ack(
            pkt,
            relay.flow.my_seq,
            relay.flow.acked_seq,
            true,
        ) {
            Some(s) => s,
            // The relay drops here, which closes the peer descriptor.
            None => return RelayStart::Failed,
        };
        // The handshake we just answered consumed one sequence number.
        relay.flow.up_bytes = 1;
        // The client's SYN also carried the scale its window fields use; all
        // later windows are relative to it (RFC 7323).
        relay.flow.client_window_scale = pkt.tcp_window_scale().unwrap_or(0);
        relay.app_packages = app_packages;
        relay.proxy = proxy;
        relay.handshake = handshake;

        {
            let mut guard = self.relays.lock().unwrap();
            if guard.get(pkt.src_port).is_some() {
                // A finished relay for this port is waiting for the poller to
                // reap it. Inserting now would swap it out from under a
                // concurrent poll(), so let the client retransmit instead.
                return RelayStart::Failed;
            }
            guard.insert(relay);
        }
        // The peer descriptor has to join the wait set before the server can
        // possibly answer: waking here is what makes a long forwarder wait
        // safe, including for a connect() that finishes after the poll began.
        self.wake();
        out.push(syn_ack);
        self.stats.inc(&self.stats.tcp_relayed);
        RelayStart::Started
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

    fn tcp_blocked(&self, pkt: &Packet<'_>, cfg: &Config) -> bool {
        let Some(dst) = pkt.dst_ip() else {
            return false;
        };
        // TURN over TCP/TLS rides the same signalling ports as the UDP half.
        if cfg.stealth.blocks_web_rtc() && crate::mitm::stealth::is_webrtc_port(pkt.dst_port) {
            return true;
        }
        // DoT over TCP bypasses the DNS filter exactly like the UDP port does.
        if cfg.block_dot && pkt.dst_port == 853 {
            return true;
        }
        // DoH is HTTPS. The provider ranges also carry plain DNS and DoT
        // endpoints (1.1.1.1:853, 8.8.8.8:53); matching every port there would
        // break Private DNS in strict mode, which has no UDP fallback.
        if cfg.block_doh && pkt.dst_port == 443 && self.is_encrypted_dns_elsewhere(dst) {
            return true;
        }
        let conn = self.conntrack.lock().unwrap();
        let verdict = conn.lookup(&dst, now_ms());
        drop(conn);
        match verdict {
            // The address came from a DNS answer learned as blocked. An app
            // that keeps dialling it is the retry loop smart filtering exists
            // for: once the host trips the limit the SYN is relayed as usual.
            IpVerdict::Blocked { host } => !self.smart.lock().unwrap().note_blocked(&host),
            _ => false,
        }
    }

    fn udp_blocked(&self, pkt: &Packet<'_>, cfg: &Config) -> bool {
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
        self.stats.inc(&self.stats.tcp_reset);
        let saved = BYTES_PER_BLOCKED_REQUEST;
        self.stats.add(&self.stats.bytes_saved, saved);
        let host = self
            .host_for_ip(pkt.dst_ip())
            .unwrap_or_else(|| pkt.dst_ip_text());
        let rule = match reason {
            Some(reason) => reason,
            None if host.parse::<std::net::IpAddr>().is_ok() => {
                // A bare address only gets here from the encrypted-DNS lists.
                "connection to encrypted DNS blocked"
            }
            None => "connection dropped",
        };
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
                &pkt.dst_ip_text(),
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
                        &pkt.dst_ip_text(),
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
                    out.push(reply);
                    if cfg.log_allowed && self.logging_live() {
                        let packages = app_packages.unwrap_or_else(|| self.apps_for_udp(pkt));
                        let event = events::with_app(
                            events::allow_event(host, &pkt.dst_ip_text(), 0),
                            first_app(&packages),
                        );
                        self.log_event(event);
                    }
                    return;
                }
            }
        }
        let t0 = now_ns();
        let verdict = self.filter.check_host(host);
        let decision_ns = now_ns() - t0;
        self.stats.record_decision(decision_ns);
        let latency_ns = decision_ns.min(u32::MAX as u64) as u32;

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
                    &pkt.dst_ip_text(),
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
            if cfg.safe_search && matches!(query.qtype, dns::TYPE_A | dns::TYPE_AAAA) {
                if let Some(safe_host) = crate::safesearch::safe_host(host) {
                    let addresses = self.cached_safe_search(safe_host, now_ms());
                    if let Some(addresses) = addresses {
                        if let Some(reply) = dns::synthesize_answer(pkt, &query, &addresses, 60) {
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
                self.forward_query(pkt, Some(&query), None);
            }
            if cfg.log_allowed && self.logging_live() {
                let packages = app_packages.unwrap_or_else(|| self.apps_for_udp(pkt));
                let event = events::with_app(
                    events::allow_event(host, &pkt.dst_ip_text(), latency_ns),
                    first_app(&packages),
                );
                self.log_event(event);
            }
        }
    }

    /// Sends the query upstream through a protected socket.
    ///
    /// `safe_host` sends the question to the filtered host instead of the one
    /// the client asked; the reply becomes a synthetic answer for the original
    /// name (see [`Self::handle_reply`]).
    fn forward_query(
        &self,
        pkt: &Packet<'_>,
        query: Option<&Query<'_>>,
        safe_host: Option<&str>,
    ) {
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
            // Full ECH, the opt-in trade: the client keeps the origin's
            // config and may hide its inner name. Its hello can then only be
            // spliced (`mitm::ech`), so that host goes unfiltered — exactly
            // what the switch asks for. The config is still remembered for
            // the upstream half, because clients that do *not* use ECH
            // (GREASE, older stacks) are terminated and filtered as usual,
            // even against an origin that requires ECH.
            if let (Some(host), Some(list)) = (host.as_deref(), config) {
                crate::logbuf::push(&format!("dns: ECH kept for {host} (full ECH is on)"));
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
        const ALERTS: [&str; 5] = [
            "UnknownCA",
            "CertificateUnknown",
            "BadCertificate",
            "CertificateExpired",
            "CertificateRevoked",
        ];
        err.contains("received fatal alert")
            && !err.contains("client process_new_packets")
            && ALERTS.iter().any(|alert| err.contains(alert))
    }

    /// The client-facing half just received a certificate alert: the app does
    /// not trust the AdFree CA. Remember the owner so its next connection is
    /// handed to the origin untouched — DNS filtering and `$app=` rules still
    /// apply, the TLS payload just stays encrypted. Logged once per app.
    fn note_client_cert_rejection(&self, err: &str, apps: &[String], host: &str) {
        if apps.is_empty() || !Self::client_rejected_certificate(err) {
            return;
        }
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
        cfg.mitm_enabled && self.mitm_ca.read().unwrap().has_ca()
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
        self.wait_for_events(timeout_ms);
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
        count
    }

    pub fn resolver_addr(&self) -> SocketAddr {
        *self.resolver.read().unwrap()
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

        // Answers that are already on the wire. The DNS sockets are part of
        // the wait set below, so a reply ends the wait and is read here right
        // after it lands.
        {
            let mut upstream = core.upstream.lock().unwrap();
            upstream.poll(&mut replies, 0);
            for pending in upstream.expire(now) {
                core.safe_search_expired(&pending);
            }
        }
        for reply in &replies {
            core.handle_reply(reply);
        }

        // The single blocking point of the loop.
        core.wait_for_events(FORWARD_WAIT_MS);

        // Relayed connections: whatever the real server answered has been
        // spliced back to the client by the wait itself, and finished relays
        // are reaped here so their descriptors are only ever closed on this
        // thread.
        core.prune_relays();
        // Idle NAT mappings are retired here too, for the same reason.
        core.udp_nat.lock().unwrap().expire(now);

        if replies.is_empty() {
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
                // with stale NAT bookkeeping (seen on emulators). The
                // client's own retry is seconds away, so try once on a
                // fresh socket first: a new port usually goes through and
                // the flow never notices.
                if self.retry_peer_connect(client_port) {
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
            let reply = {
                let mut nat = self.udp_nat.lock().unwrap();
                let Some(flow) = nat.get_mut(&key) else {
                    return;
                };
                flow.last_ms = now_ms();
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
        crate::logbuf::push("relay: peer connect failed, retrying on a fresh socket");
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

    #[test]
    fn config_defaults_are_battery_friendly() {
        let cfg = Config::default();
        assert!(cfg.block_quic);
        assert!(cfg.block_doh);
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

    #[test]
    fn short_packets_are_ignored() {
        let core = Core::new();
        assert!(core.handle_packet(&[]).is_empty());
        assert!(core.handle_packet(&[0u8; 5]).is_empty());
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
            ..Config::default()
        };

        let dot_raw = tcp_packet([1, 1, 1, 1], 853);
        let dot = Packet::parse(&dot_raw).expect("dot syn");
        assert!(
            !core.tcp_blocked(&dot, &cfg),
            "DoT to a DoH provider must survive while its RST is off"
        );

        let doh_raw = tcp_packet([1, 1, 1, 1], 443);
        let doh = Packet::parse(&doh_raw).expect("doh syn");
        assert!(core.tcp_blocked(&doh, &cfg), "DoH on 443 is still blocked");

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
        core.remember_safe_search(
            "forcesafesearch.google.com",
            &[(address, 120)],
            now_ms(),
        );
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
        core.set_app_network_policy(vec!["com.example.news".to_string()], Vec::new(), Vec::new());

        core.set_network_type(NETWORK_WIFI);
        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        assert_eq!(core.relay_count(), 1, "Wi-Fi is allowed by this policy");

        let other = Core::new();
        other.set_socket_protector(Arc::new(AllowAll));
        other.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        other.pin_uid_for_port(40000, 10_123);
        other.set_app_network_policy(vec!["com.example.news".to_string()], Vec::new(), Vec::new());
        other.set_network_type(NETWORK_CELLULAR);
        other.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
        assert_eq!(other.relay_count(), 0, "no peer socket may be opened");
        let reset = other.take_outbox();
        assert_eq!(reset.len(), 1, "the client gets one segment back");
        // IPv4 + TCP headers: the flags byte is 13 bytes into the TCP header.
        assert_eq!(reset[0][33] & 0x04, 0x04, "and it is a RST");
    }

    /// Turning the screen off cuts an open flow belonging to an app that is
    /// configured to stay offline, without waiting for a reconnect.
    #[test]
    fn screen_off_cuts_open_flows_of_restricted_apps() {
        let core = Core::new();
        core.set_socket_protector(Arc::new(AllowAll));
        core.set_uid_apps(vec![(10_123, vec!["com.example.news".to_string()])]);
        core.pin_uid_for_port(40000, 10_123);
        core.set_app_network_policy(Vec::new(), Vec::new(), vec!["com.example.news".to_string()]);
        core.set_network_type(NETWORK_WIFI);
        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
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
        core.set_app_network_policy(vec!["com.example.news".to_string()], Vec::new(), Vec::new());

        assert_eq!(dns_reply_rcode(&core, "example.test"), Some(3));
        assert_eq!(
            core.snapshot().dns_queries,
            0,
            "the blocked query never reaches the upstream resolver"
        );

        core.set_app_network_policy(Vec::new(), Vec::new(), Vec::new());
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
        core.set_app_network_policy(vec!["com.example.news".to_string()], Vec::new(), Vec::new());

        core.handle_packet(&tcp_syn(40000, [93, 184, 216, 34], 80));
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
}
