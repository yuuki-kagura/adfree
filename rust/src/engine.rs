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
//!                              ├─ TCP      ─► conntrack / DoH check ─► RST
//!                              └─ UDP      ─► conntrack check ─► drop
//!   dns-thread   poll(upstream sockets) ─► rewrite answer ─► learn IPs ─► TUN
//! ```
//!
//! Two threads total, each blocked in a `poll` most of the time: that is why a
//! DNS level filter costs a fraction of a percent of battery. Nothing is
//! allocated on the packet path but the (rare) synthetic DNS answer.

use crate::conntrack::{CidrSet, ConnTable, IpVerdict};
use crate::dns::{self, BlockMode, Query};
use crate::events::{self, Event, EventLog};
use crate::filter::{FilterEngine, FilterListInfo, HostVerdict};
use crate::fxhash::hash_str;
use crate::packet::{self, IpKey, Packet, PROTO_TCP, PROTO_UDP};
use crate::stats::{self, Stats};
use crate::uidmap::UidMap;
use crate::upstream::Upstream;
use crate::util::{now_ms, now_ns};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// Read size for the TUN descriptor.
const TUN_BUF_BYTES: usize = 64 * 1024;
/// How long a single poll waits before re-checking the shutdown flag.
const POLL_TIMEOUT_MS: i32 = 250;

/// Rough upstream cost of one blocked request; only used for the "data saved"
/// figure shown in the UI.
const BYTES_PER_BLOCKED_REQUEST: u64 = 48 * 1024;

/// Built-in list of well known encrypted DNS providers. Blocking these is the
/// only way to stop apps from silently bypassing the filter.
fn default_doh_cidrs() -> CidrSet {
    let mut set = CidrSet::new();
    let v4 = [
        (0x0101_0100u32, 24), // Cloudflare
        (0x0100_0000, 24),     // Cloudflare secondary anycast
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

#[derive(Clone)]
pub struct Config {
    pub block_quic: bool,
    pub block_doh: bool,
    pub block_dot: bool,
    pub block_mode: BlockMode,
    /// Log requests that were *not* blocked (off by default: pure CPU cost).
    pub log_allowed: bool,
    /// Screen-off battery mode: stop pushing events, keep stats.
    pub eco_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            block_quic: true,
            block_doh: true,
            block_dot: true,
            block_mode: BlockMode::NxDomain,
            log_allowed: false,
            eco_mode: true,
        }
    }
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
    pub events_pending: u64,
    pub events_dropped: u64,
    pub filter_build_ms: u64,
    pub conntrack_entries: u64,
    pub pending_dns: u64,
    pub uptime_ms: u64,
}

pub struct Core {
    cfg: RwLock<Config>,
    filter: Arc<FilterEngine>,
    lists: RwLock<Vec<FilterListInfo>>,
    user_rules: RwLock<Vec<String>>,
    upstream: Mutex<Upstream>,
    conntrack: Mutex<ConnTable>,
    doh_ips: RwLock<CidrSet>,
    stats: Stats,
    events: Mutex<EventLog>,
    uidmap: Mutex<UidMap>,
    screen_off: AtomicBool,
    running: AtomicBool,
    tun_fd: AtomicI32,
    tx_counter: AtomicU64,
    started_at: u64,
    resolver: RwLock<SocketAddr>,
    last_tick_ns: AtomicU64,
    /// Local CA used to forge certs for HTTPS filtering; `failed()` stands for
    /// "no CA loaded yet".
    pub mitm_ca: RwLock<crate::mitm::ca::CertificateAuthority>,
    /// User scripts injected into HTML responses.
    pub mitm_scripts: RwLock<crate::mitm::script::ScriptSet>,
}

static CORE: OnceLock<Core> = OnceLock::new();

/// Global handle: the JNI layer runs in the app's single process and the engine
/// must be reachable from any thread.
pub fn core() -> &'static Core {
    CORE.get_or_init(Core::new)
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
            conntrack: Mutex::new(ConnTable::new()),
            doh_ips: RwLock::new(default_doh_cidrs()),
            stats: Stats::new(),
            events: Mutex::new(EventLog::default()),
            uidmap: Mutex::new(UidMap::new()),
            screen_off: AtomicBool::new(false),
            running: AtomicBool::new(false),
            tun_fd: AtomicI32::new(-1),
            tx_counter: AtomicU64::new(0),
            started_at: now_ms(),
            resolver: RwLock::new(resolver),
            last_tick_ns: AtomicU64::new(0),
            mitm_ca: RwLock::new(crate::mitm::ca::CertificateAuthority::failed("not initialised")),
            mitm_scripts: RwLock::new(crate::mitm::script::ScriptSet::new()),
        }
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn uptime_ms(&self) -> u64 {
        now_ms().saturating_sub(self.started_at)
    }

    // ---------------------------------------------------------------- config

    pub fn set_config(&self, cfg: Config) {
        *self.cfg.write().unwrap() = cfg;
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
        }
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
        self.stats.set(&self.stats.filter_rules, self.filter.active_rules());
        self.stats
            .set(&self.stats.engine_bytes, self.filter.memory_bytes() as u64);
        let hits = self.filter.cache_hits() as i64;
        let misses = self.filter.cache_misses() as i64;
        self.stats.set(&self.stats.cache_hits, hits.max(0) as u64);
        self.stats.set(&self.stats.cache_misses, misses.max(0) as u64);
    }

    pub fn filter_engine(&self) -> Arc<FilterEngine> {
        Arc::clone(&self.filter)
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
        self.tun_fd.store(tun_fd, Ordering::SeqCst);
        self.running.store(true, Ordering::SeqCst);
        let statics: &'static Core = core();
        std::thread::Builder::new()
            .name("adfree-tun".into())
            .stack_size(128 * 1024)
            .spawn(move || tun_loop(statics, tun_fd))
            .ok();
        std::thread::Builder::new()
            .name("adfree-dns".into())
            .stack_size(128 * 1024)
            .spawn(move || forwarder_loop(statics))
            .ok();
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.tun_fd.store(-1, Ordering::SeqCst);
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
        } else if pkt.proto == PROTO_UDP {
            if self.udp_blocked(&pkt, &cfg) {
                self.stats.inc(&self.stats.udp_dropped);
            }
        } else if pkt.proto == PROTO_TCP && self.tcp_blocked(&pkt, &cfg) {
            self.reset_tcp(&pkt);
        }
        out
    }

    fn tcp_blocked(&self, pkt: &Packet<'_>, cfg: &Config) -> bool {
        let Some(dst) = pkt.dst_ip() else {
            return false;
        };
        if cfg.block_doh && self.doh_ips.read().unwrap().contains_key(dst) {
            return true;
        }
        let conn = self.conntrack.lock().unwrap();
        matches!(conn.lookup(&dst, now_ms()), IpVerdict::Blocked { .. })
    }

    fn udp_blocked(&self, pkt: &Packet<'_>, cfg: &Config) -> bool {
        let Some(dst) = pkt.dst_ip() else {
            return false;
        };
        if cfg.block_doh && self.doh_ips.read().unwrap().contains_key(dst) {
            return true;
        }
        let conn = self.conntrack.lock().unwrap();
        matches!(conn.lookup(&dst, now_ms()), IpVerdict::Blocked { .. })
    }

    /// Kills a connection locally with a RST: the app fails on the spot instead
    /// of waiting for a connect timeout, and no traffic was ever spent.
    fn reset_tcp(&self, pkt: &Packet<'_>) {
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
        let rule = if host.len() > 12 && host.chars().all(|c| c.is_ascii_digit() || c == '.') {
            "connection to encrypted DNS blocked"
        } else {
            "connection dropped"
        };
        let category = if rule.contains("DNS") {
            crate::filter::CAT_TRACKER
        } else {
            crate::filter::CAT_AD
        };
        self.log_event(events::block_event(
            events::ACTION_TCP_RESET,
            &host,
            &pkt.dst_ip_text(),
            rule,
            "Protection",
            category,
            0,
            saved as u32,
            pkt.version == 6,
        ));
    }

    fn handle_dns(&self, pkt: &Packet<'_>, cfg: &Config, out: &mut Vec<Vec<u8>>) {
        let Some(query) = dns::parse_query(pkt.l4_payload()) else {
            // Malformed: forwarding is the safest reaction.
            self.forward_query(pkt, None);
            return;
        };
        if !query.is_query() {
            return;
        }
        if !query.has_question {
            self.forward_query(pkt, Some(&query));
            return;
        }

        let host = query.qname.as_str();
        let t0 = now_ns();
        let verdict = self.filter.check_host(host);
        let decision_ns = now_ns() - t0;
        self.stats.record_decision(decision_ns);
        let latency_ns = decision_ns.min(u32::MAX as u64) as u32;

        if verdict.blocked {
            self.stats.inc(&self.stats.dns_blocked);
            let saved = BYTES_PER_BLOCKED_REQUEST;
            self.stats.add(&self.stats.bytes_saved, saved);
            if let Some(reply) = dns::synthesize_reply(pkt, &query, cfg.block_mode) {
                out.push(reply);
            }
            self.log_event(events::block_event(
                events::ACTION_BLOCK,
                host,
                &pkt.dst_ip_text(),
                verdict.rule_text.as_deref().unwrap_or(""),
                verdict.list_name.as_deref().unwrap_or(""),
                verdict.category,
                latency_ns,
                saved as u32,
                pkt.version == 6,
            ));
        } else {
            self.stats.inc(&self.stats.dns_allowed);
            self.forward_query(pkt, Some(&query));
            if cfg.log_allowed {
                self.log_event(events::allow_event(host, &pkt.dst_ip_text(), latency_ns));
            }
        }
    }

    /// Sends the query upstream through a protected socket.
    fn forward_query(&self, pkt: &Packet<'_>, query: Option<&Query<'_>>) {
        let Some(query) = query else {
            // Without a question there is nothing to forward: answer SERVFAIL
            // so the client fails fast instead of timing out.
            let synthetic = dns::synthesize_error(pkt, query, dns::RCODE_SERVFAIL);
            if let Some(err) = synthetic {
                self.write_raw(&err);
            }
            return;
        };
        let mut payload = query.body.to_vec();
        let host = query.qname.as_str();
        // Spread queries over the socket pool deterministically, so a host keeps
        // using the same socket (friendlier to the kernel's flow cache).
        let socket = (hash_str(host) as usize) % crate::upstream::SOCKET_POOL_PUB;
        let mut upstream = self.upstream.lock().unwrap();
        if !upstream.is_ready() {
            self.stats.inc(&self.stats.dns_timeouts);
            if let Some(err) = dns::synthesize_error(pkt, Some(query), dns::RCODE_SERVFAIL) {
                self.write_raw(&err);
            }
            return;
        }
        let txid = upstream.alloc_txid();
        dns::patch_txid(&mut payload, txid);
        self.stats.inc(&self.stats.dns_queries);
        if upstream
            .send(socket, &payload, query.id, txid, now_ms())
            .is_none()
        {
            self.stats.inc(&self.stats.dns_timeouts);
            if let Some(err) =
                dns::synthesize_error(pkt, Some(query), dns::RCODE_SERVFAIL)
            {
                self.write_raw(&err);
            }
        } else {
            self.stats.inc(&self.stats.packets_forwarded);
        }
    }

    /// Handles one upstream answer: rewrite it for the client, learn the address
    /// mapping and write it back through the tunnel.
    fn handle_reply(&self, reply: &crate::upstream::Reply) {
        let Some(client_packet) = Packet::parse(&reply.pending.packet) else {
            return;
        };
        let mut message = reply.message.clone();
        dns::patch_txid(&mut message, reply.pending.client_txid);
        let rewritten = client_packet.rewrite_udp(&message);
        if !self.write_raw(&rewritten) {
            return;
        }
        self.stats.inc(&self.stats.dns_replies);
        self.learn_answers(&message);
    }

    /// Teaches the connection tracker which addresses belong to which host.
    fn learn_answers(&self, message: &[u8]) {
        let Some(query) = dns::parse_query(message) else {
            return;
        };
        if !query.has_question {
            return;
        }
        let host = query.qname.as_str().to_string();
        let blocked = self.filter.check_host(&host).blocked;
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
        let Ok(mut log) = self.events.try_lock() else {
            return;
        };
        log.push(event);
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
            events_pending: self.events_pending(),
            events_dropped: self.events_dropped(),
            filter_build_ms: self.filter.build_time_ms(),
            conntrack_entries: self.conntrack_entries(),
            pending_dns: self.upstream.lock().map(|u| u.pending_len() as u64).unwrap_or(0),
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

    pub fn resolver_addr(&self) -> SocketAddr {
        *self.resolver.read().unwrap()
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
            let n = unsafe {
                libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
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
fn forwarder_loop(core: &'static Core) {
    let mut replies: Vec<crate::upstream::Reply> = Vec::with_capacity(32);
    while core.is_running() {
        replies.clear();
        let now = now_ms();
        {
            let mut upstream = core.upstream.lock().unwrap();
            upstream.poll(&mut replies);
            upstream.expire(now);
        }
        for reply in &replies {
            core.handle_reply(reply);
        }
        if replies.is_empty() {
            core.conntrack.lock().unwrap().expire(now);
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

/// Parses `1.2.3.0/24` or `2001:db8::/32`.
pub fn parse_cidr(text: &str) -> Option<(IpKey, u8)> {
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn snapshot_is_well_formed() {
        let core = Core::new();
        let snap = core.snapshot();
        assert_eq!(snap.packets_total, 0);
        assert_eq!(snap.active_rules, 0);
        assert_eq!(snap.pending_dns, 0);
    }
}
