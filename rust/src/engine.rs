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
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};

/// Read size for the TUN descriptor.
const TUN_BUF_BYTES: usize = 64 * 1024;
/// How long a single poll waits before re-checking the shutdown flag.
const POLL_TIMEOUT_MS: i32 = 250;

/// How long the DNS forwarder waits for work when nothing is in flight. It
/// sleeps on a condvar with the upstream lock *released*, so a UI thread
/// changing the resolver is never made to wait for this.
const DNS_IDLE_MS: std::time::Duration = std::time::Duration::from_millis(250);

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
    /// Terminate TLS for intercepted connections and inject user scripts.
    pub mitm_enabled: bool,
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
            mitm_enabled: false,
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
    /// Signalled when a query is queued, so the forwarder can wait without
    /// holding `upstream` for the whole wait.
    dns_wake: Condvar,
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
    pub mitm_ca: RwLock<Arc<crate::mitm::ca::CertificateAuthority>>,
    /// User scripts injected into HTML responses.
    pub mitm_scripts: RwLock<crate::mitm::script::ScriptSet>,
    /// Shared per-SNI leaf resolver for the TLS termination.
    pub mitm_resolver: RwLock<Option<Arc<crate::mitm::tls::SniCertResolver>>>,
    /// Live intercepted connections.
    relays: Mutex<crate::mitm::relay::RelayTable>,
    /// Protected, unconnected TCP sockets the relays use towards the server.
    peer_sockets: Mutex<Vec<RawFd>>,
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
            dns_wake: Condvar::new(),
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
            mitm_ca: RwLock::new(Arc::new(crate::mitm::ca::CertificateAuthority::failed(
                "not initialised",
            ))),
            mitm_scripts: RwLock::new(crate::mitm::script::ScriptSet::new()),
            mitm_resolver: RwLock::new(None),
            relays: Mutex::new(crate::mitm::relay::RelayTable::new()),
            peer_sockets: Mutex::new(Vec::new()),
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
        } else if pkt.proto == PROTO_TCP
            && !self.relay_tcp(&pkt, &cfg, &mut out)
            && self.tcp_blocked(&pkt, &cfg)
        {
            self.reset_tcp(&pkt);
        }
        out
    }

    /// Handles one TCP packet, terminating the connection ourselves when MITM is
    /// armed. Returns true when the packet was consumed by a relay.
    fn relay_tcp(&self, pkt: &Packet<'_>, cfg: &Config, out: &mut Vec<Vec<u8>>) -> bool {
        if !cfg.mitm_enabled {
            return false;
        }
        let port = pkt.src_port;
        if pkt.is_syn {
            // A new flow: take a peer socket and answer the SYN ourselves.
            if !crate::mitm::relay::is_mitm_port(pkt.dst_port) {
                return false;
            }
            // A retransmitted SYN for a live relay: answer again without
            // disturbing the flow (the first answer may have been lost).
            let existing = {
                let guard = self.relays.lock().unwrap();
                guard.get(port).map(|relay| {
                    (
                        relay.syn_packet.clone(),
                        relay.flow.my_seq,
                        relay.flow.acked_seq,
                    )
                })
            };
            if let Some((syn_packet, my_seq, acked_seq)) = existing {
                if let Some(template) = Packet::parse(&syn_packet) {
                    if let Some(reply) =
                        crate::mitm::segment::build_ack(&template, my_seq, acked_seq, true)
                    {
                        out.push(reply);
                    }
                }
                return true;
            }
            return self.start_relay(pkt, out);
        }
        if pkt.is_rst {
            // The client gave up: retire the flow quietly.
            return self.relays.lock().unwrap().remove(port).is_some();
        }
        let mut guard = self.relays.lock().unwrap();
        let Some(relay) = guard.get_mut(port) else {
            return false;
        };
        let payload = pkt.l4_payload();
        let mut reset = false;
        if !payload.is_empty() {
            match relay.on_client_segment(payload) {
                Ok((to_peer, to_client)) => {
                    if !to_peer.is_empty() {
                        self.write_all(relay.peer_fd, &to_peer);
                    }
                    if !to_client.is_empty() {
                        for segment in relay.segments_for_client(&to_client) {
                            out.push(segment);
                        }
                    }
                }
                Err(e) => {
                    crate::logbuf::push(&format!("relay client step: {e}"));
                    if let Some(rst) = relay.rst_to_client() {
                        out.push(rst);
                    }
                    reset = true;
                }
            }
        }
        if reset {
            guard.remove(port);
            return true;
        }
        if pkt.is_fin && !relay.client_fin {
            if let Some(ack) = relay.on_client_fin() {
                out.push(ack);
            }
            // Half-close the peer: it can still send back its remaining bytes.
            unsafe {
                libc::shutdown(relay.peer_fd, libc::SHUT_WR);
            }
        }
        // Anything else on a live relay (bare ACKs, window updates, the FIN we
        // just acknowledged) is consumed here: falling through would let
        // `tcp_blocked` reset a flow the engine itself owns.
        true
    }

    /// The largest payload one segment towards the client may carry.
    ///
    /// The client's own MSS is authoritative (its stack drops anything bigger)
    /// and the tunnel MTU is the hard ceiling.
    fn relay_mss(&self, pkt: &Packet<'_>) -> usize {
        let cap = if pkt.version == 4 { 1460 } else { 1440 };
        pkt.tcp_mss()
            .map(|m| (m as usize).min(cap))
            .unwrap_or(cap)
    }

    /// Answers a SYN for a host we want to intercept.
    fn start_relay(&self, pkt: &Packet<'_>, out: &mut Vec<Vec<u8>>) -> bool {
        let Some(client_ip) = pkt.src_ip() else {
            return false;
        };
        let Some(target) = self.host_for_ip(pkt.dst_ip()) else {
            // No hostname for this address: nothing to forge a certificate for.
            return false;
        };
        let Some(dst) = pkt.dst_ip() else {
            return false;
        };
        let Some(peer_fd) = self.take_peer_socket() else {
            return false;
        };
        // The peer socket must be connected before any TLS byte flows, otherwise
        // the splice would talk to nothing.
        if !connect_fd(peer_fd, dst, pkt.dst_port) {
            crate::logbuf::push("relay: connect() to the peer failed");
            return false;
        }
        let resolver = self.mitm_resolver();
        let session = match crate::mitm::tls::open_session(&resolver, &target) {
            Ok(s) => s,
            Err(e) => {
                crate::logbuf::push(&format!("open tls session: {e}"));
                return false;
            }
        };
        let script = self.mitm_scripts.read().unwrap().serve_path().to_string();
        let proxy = crate::mitm::proxy::ProxySession::new(session, script);
        let flow = crate::mitm::tcp::Flow::new(
            client_ip,
            pkt.src_port,
            pkt.dst_port,
            pkt.seq,
            crate::mitm::tcp::initial_seq(pkt.seq as u64),
        );
        let mss = self.relay_mss(pkt);
        let mut relay =
            crate::mitm::relay::Relay::new(flow, peer_fd, proxy, pkt.raw.to_vec(), mss);
        // Our own SYN-ACK (the client-facing sequence starts here).
        let syn_ack = match crate::mitm::segment::build_ack(pkt, relay.flow.my_seq, relay.flow.acked_seq, true) {
            Some(s) => s,
            None => return false,
        };
        // The handshake we just answered consumed one sequence number.
        relay.flow.up_bytes = 1;

        self.relays.lock().unwrap().insert(relay);
        out.push(syn_ack);
        self.stats.inc(&self.stats.tcp_reset); // reuse the counter for "relayed"
        true
    }

    /// Pops one protected, unconnected peer socket.
    fn take_peer_socket(&self) -> Option<RawFd> {
        self.peer_sockets.lock().unwrap().pop()
    }

    fn write_all(&self, fd: RawFd, bytes: &[u8]) {
        let mut off = 0;
        while off < bytes.len() {
            let n = unsafe {
                libc::send(fd, bytes.as_ptr().add(off) as *const libc::c_void, bytes.len() - off, libc::MSG_NOSIGNAL)
            };
            if n <= 0 {
                return;
            }
            off += n as usize;
        }
    }

    fn tcp_blocked(&self, pkt: &Packet<'_>, cfg: &Config) -> bool {
        let Some(dst) = pkt.dst_ip() else {
            return false;
        };
        if cfg.block_doh && self.is_encrypted_dns_elsewhere(dst) {
            return true;
        }
        let conn = self.conntrack.lock().unwrap();
        matches!(conn.lookup(&dst, now_ms()), IpVerdict::Blocked { .. })
    }

    fn udp_blocked(&self, pkt: &Packet<'_>, cfg: &Config) -> bool {
        let Some(dst) = pkt.dst_ip() else {
            return false;
        };
        if cfg.block_doh && self.is_encrypted_dns_elsewhere(dst) {
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
        let mut packet = pkt.raw.to_vec();
        let off = pkt.l4_payload_offset();
        packet[off] = (txid >> 8) as u8;
        packet[off + 1] = (txid & 0xff) as u8;
        self.stats.inc(&self.stats.dns_queries);
        let sent = upstream.send(socket, &packet, query.id, txid, now_ms());
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
            // Wake the forwarder so the answer is picked up at once instead of
            // after its idle wait. The lock is already dropped, so the forwarder
            // can act on the signal immediately.
            self.dns_wake.notify_all();
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

    /// Installs a pool of protected, unconnected TCP sockets.
    pub fn set_peer_sockets(&self, fds: &[RawFd]) {
        let mut pool = self.peer_sockets.lock().unwrap();
        pool.clear();
        pool.extend_from_slice(fds);
    }

    pub fn peer_socket_pool_size(&self) -> usize {
        self.peer_sockets.lock().unwrap().len()
    }

    pub fn relay_count(&self) -> usize {
        self.relays.lock().unwrap().len()
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
            if upstream.pending_len() == 0 {
                // Nothing is in flight. Waiting here rather than inside `poll`
                // matters: the lock is released while we wait, so a UI thread
                // calling `set_resolver` is not blocked for a whole second.
                let (guard, _) = core
                    .dns_wake
                    .wait_timeout(upstream, DNS_IDLE_MS)
                    .unwrap_or_else(|e| e.into_inner());
                upstream = guard;
            }
            // Never block for long here: 100ms is enough to catch an answer that
            // is already on the wire, and the loop comes back immediately after.
            let timeout = if upstream.pending_len() == 0 { 0 } else { 100 };
            upstream.poll(&mut replies, timeout);
            upstream.expire(now);
        }
        for reply in &replies {
            core.handle_reply(reply);
        }

        // Relayed connections: whatever the real server answered has to be
        // spliced back to the client.
        core.poll_relays();

        if replies.is_empty() {
            core.conntrack.lock().unwrap().expire(now);
        }
    }
}

/// Reads from every relay's peer socket and writes the result to the client.
///
/// Polling all peer sockets in one `poll()` keeps the cost independent of how
/// many connections are open, which matters for battery when a page opens
/// dozens of them.
impl Core {
    fn poll_relays(&self) {
        let peers = self.relays.lock().unwrap().peer_fds();
        if peers.is_empty() {
            return;
        }
        let mut fds: Vec<libc::pollfd> = peers
            .iter()
            .map(|(_, fd)| libc::pollfd {
                fd: *fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let n = unsafe {
            libc::poll(
                fds.as_mut_ptr(),
                fds.len() as libc::nfds_t,
                50,
            )
        };
        if n <= 0 {
            return;
        }
        for (i, p) in fds.iter().enumerate() {
            if p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) == 0 {
                continue;
            }
            let (client_port, _) = peers[i];
            let mut buf = [0u8; 32 * 1024];
            loop {
                let read = unsafe {
                    libc::recv(
                        p.fd,
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
                    // Orderly shutdown: FIN back to the client.
                    self.close_relay_from_peer(client_port, false);
                    break;
                }
                self.relay_peer_bytes(client_port, &buf[..read as usize]);
            }
        }
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
    fn relay_peer_bytes(&self, client_port: u16, bytes: &[u8]) {
        let segments = {
            let mut guard = self.relays.lock().unwrap();
            let Some(relay) = guard.get_mut(client_port) else {
                return;
            };
            match relay.on_peer_data(bytes) {
                Ok(outbound) if outbound.is_empty() => Vec::new(),
                Ok(outbound) => relay.segments_for_client(&outbound),
                Err(e) => {
                    crate::logbuf::push(&format!("relay peer step: {e}"));
                    return;
                }
            }
        };
        for segment in segments {
            self.write_raw(&segment);
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
    core.prune_relays();
}

/// How long a relay may sit silent before it is presumed dead.
const RELAY_IDLE_MS: u64 = 300_000;

impl Core {
    /// Frees finished relays and resets ones that went silent.
    ///
    /// Every relay holds a peer descriptor borrowed from the pool; without
    /// this pass a page view's worth of closed connections would drain it.
    fn prune_relays(&self) {
        let now = now_ms();
        let mut resets = Vec::new();
        {
            let mut guard = self.relays.lock().unwrap();
            guard.drop_closed();
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

/// Connects `fd` (already protected) to `addr:port` without blocking.
fn connect_fd(fd: RawFd, addr: IpKey, port: u16) -> bool {
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
    ret == 0 || std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
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
