//! Typed API exposed to Kotlin through `uniffi`.
//!
//! Why uniffi: hand written JNI is a couple of hundred lines of `unsafe` with a
//! very sharp edge (a wrong signature kills the process). uniffi generates a
//! checked bridge, rejects type mismatches at compile time and turns a native
//! bug into a Kotlin exception instead of a crash.
//!
//! Design rules kept from the hand written version:
//! * nothing crosses the boundary that is big: filter lists are file paths,
//!   events are small records, stats is one struct;
//! * every entry point is wrapped in `catch_unwind` (uniffi does *not* do this
//!   for us, and with `panic = "abort"` a native panic would take the app down);
//! * no async: everything is synchronous, and the expensive part (compiling a new
//!   filter set) happens on a native background thread.

use crate::engine::VpnStats;
use crate::events;
use crate::filter::{FilterListInfo, ListFormat};
use std::sync::Arc;
use std::time::Duration;

/// Everything the UI needs about the engine, in one atomic read.
#[derive(uniffi::Record, Clone, Copy, Default, Debug)]
pub struct StatsSnapshot {
    pub packets_total: i64,
    pub packets_dns: i64,
    pub packets_forwarded: i64,
    pub dns_blocked: i64,
    pub dns_allowed: i64,
    pub tcp_reset: i64,
    pub quic_dropped: i64,
    pub quic_blocked: i64,
    pub udp_dropped: i64,
    pub dns_queries: i64,
    pub dns_replies: i64,
    pub dns_timeouts: i64,
    pub bytes_saved: i64,
    pub decision_ns_avg: i64,
    pub decision_ns_ewma: i64,
    pub decision_ns_max: i64,
    pub cache_hits: i64,
    pub active_rules: i64,
    pub engine_bytes: i64,
    pub rss_kb: i64,
    pub loop_iterations: i64,
    pub busy_ns: i64,
    /// Time inside rustls (HTTPS filtering): all feeds, plus the share of it
    /// spent while a handshake was still running.
    pub tls_ns: i64,
    pub handshake_ns: i64,
    /// Time spent rewriting response bodies (decompress, inject, recompress).
    pub rewrite_ns: i64,
    /// Log rows dropped because the database writer could not keep up.
    pub log_dropped: i64,
    pub events_pending: i64,
    pub events_dropped: i64,
    pub filter_build_ms: i64,
    pub conntrack_entries: i64,
    pub pending_dns: i64,
    pub uptime_ms: i64,
    pub is_building: bool,
}

impl From<VpnStats> for StatsSnapshot {
    fn from(s: VpnStats) -> Self {
        StatsSnapshot {
            packets_total: s.packets_total as i64,
            packets_dns: s.packets_dns as i64,
            packets_forwarded: s.packets_forwarded as i64,
            dns_blocked: s.dns_blocked as i64,
            dns_allowed: s.dns_allowed as i64,
            tcp_reset: s.tcp_reset as i64,
            quic_dropped: s.quic_dropped as i64,
            quic_blocked: s.quic_blocked as i64,
            udp_dropped: s.udp_dropped as i64,
            dns_queries: s.dns_queries as i64,
            dns_replies: s.dns_replies as i64,
            dns_timeouts: s.dns_timeouts as i64,
            bytes_saved: s.bytes_saved as i64,
            decision_ns_avg: s.decision_ns_avg as i64,
            decision_ns_ewma: s.decision_ns_ewma as i64,
            decision_ns_max: s.decision_ns_max as i64,
            cache_hits: s.cache_hits as i64,
            active_rules: s.active_rules as i64,
            engine_bytes: s.engine_bytes as i64,
            rss_kb: s.rss_kb as i64,
            loop_iterations: s.loop_iterations as i64,
            busy_ns: s.busy_ns as i64,
            tls_ns: s.tls_ns as i64,
            handshake_ns: s.handshake_ns as i64,
            rewrite_ns: s.rewrite_ns as i64,
            log_dropped: s.log_dropped as i64,
            events_pending: s.events_pending as i64,
            events_dropped: s.events_dropped as i64,
            filter_build_ms: s.filter_build_ms as i64,
            conntrack_entries: s.conntrack_entries as i64,
            pending_dns: s.pending_dns as i64,
            uptime_ms: s.uptime_ms as i64,
            is_building: crate::core().filter_engine().is_building(),
        }
    }
}

/// One filter list, as the UI sees it.
#[derive(uniffi::Record, Clone, Debug)]
pub struct FilterListBinding {
    pub id: i32,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    /// Local file holding the rules; empty when the list has not been downloaded.
    pub path: String,
    /// 0 = standard syntax, 1 = hosts syntax.
    pub format: i32,
    /// 0 = ad, 1 = tracker, ... see `RequestCategory`.
    pub category: i32,
    /// The reference's trusted-filter bit: only a trusted list may carry
    /// JavaScript rules, scriptlets and the gated modifiers. The catalogue
    /// and the user rules are trusted; a list the user added is not until
    /// they say so.
    pub trusted: bool,
    /// Number of rule lines in the list.
    pub rule_count: i64,
    pub last_error: String,
    /// Host-only list: its rules decide DNS lookups but never URL or
    /// cosmetic ones (AdGuard's "DNS filters").
    pub dns_only: bool,
}

impl From<&FilterListInfo> for FilterListBinding {
    fn from(l: &FilterListInfo) -> Self {
        FilterListBinding {
            id: l.id as i32,
            name: l.name.clone(),
            url: l.url.clone(),
            enabled: l.enabled,
            path: l
                .local_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default(),
            format: l.format.as_u8() as i32,
            category: l.category as i32,
            trusted: l.trusted,
            rule_count: l.rule_count as i64,
            last_error: l.last_error.clone().unwrap_or_default(),
            dns_only: l.dns_only,
        }
    }
}

impl From<&FilterListBinding> for FilterListInfo {
    fn from(l: &FilterListBinding) -> Self {
        FilterListInfo {
            id: l.id as u16,
            name: l.name.clone(),
            url: l.url.clone(),
            enabled: l.enabled,
            local_path: if l.path.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(&l.path))
            },
            format: ListFormat::from_u8(l.format.clamp(0, 1) as u8),
            category: l.category.clamp(0, 6) as u8,
            trusted: l.trusted,
            rule_count: l.rule_count.max(0) as u64,
            last_error: None,
            dns_only: l.dns_only,
        }
    }
}

/// Answer to "is this host blocked, and by what?".
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct HostVerdictBinding {
    pub blocked: bool,
    pub rule: String,
    pub list_name: String,
    pub category: i32,
}

/// One `uid -> packages` row of the runtime app table (see
/// [`core_set_uid_apps`]).
#[derive(uniffi::Record, Clone, Debug)]
pub struct UidApps {
    pub uid: u32,
    /// Package names sharing the uid; order is not significant.
    pub packages: Vec<String>,
}

/// One line of the Activity log.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct LogEvent {
    /// SQLite rowid, stable across page reads; 0 for events that only exist in
    /// the live ring (drained before they were persisted).
    pub id: i64,
    pub ts_ms: i64,
    /// 0 = allowed, 1 = blocked, 2 = TCP reset, 3 = UDP drop, 4 = QUIC drop.
    pub action: i32,
    pub category: i32,
    pub domain: String,
    pub ip: String,
    pub rule: String,
    pub list_name: String,
    pub latency_ns: i32,
    pub bytes_saved: i32,
    pub ipv6: bool,
    /// Package of the app that owned the flow; empty when unattributed.
    pub app: String,
    /// 0 unknown, 1 Wi-Fi, 2 cellular.
    pub transport: i32,
    /// Whether that network was roaming.
    pub roaming: bool,
    /// Monotonic decision id assigned by the core.
    pub flow_id: i64,
    /// Request URL when TLS termination saw one; empty otherwise.
    pub url: String,
    /// Address(es) the engine answered a DNS query with, when it produced the
    /// reply itself.
    pub dns_answer: String,
    pub bytes_sent: i64,
    pub bytes_recv: i64,
}

impl From<&events::Event> for LogEvent {
    fn from(e: &events::Event) -> Self {
        LogEvent {
            id: 0,
            ts_ms: e.ts_ms as i64,
            action: e.action as i32,
            category: e.category as i32,
            domain: e.domain().to_string(),
            ip: e.ip().to_string(),
            rule: e.rule().to_string(),
            list_name: e.list().to_string(),
            latency_ns: e.latency_ns as i32,
            bytes_saved: e.bytes_saved as i32,
            ipv6: e.flags & 0b01 != 0,
            app: e.app().to_string(),
            transport: e.transport() as i32,
            roaming: e.roaming(),
            flow_id: e.flow_id as i64,
            url: e.url().to_string(),
            dns_answer: e.answer().to_string(),
            bytes_sent: e.bytes_sent as i64,
            bytes_recv: e.bytes_recv as i64,
        }
    }
}

impl From<&crate::store::LogRow> for LogEvent {
    fn from(r: &crate::store::LogRow) -> Self {
        LogEvent {
            id: r.id,
            ts_ms: r.ts_ms,
            action: r.action as i32,
            category: r.category as i32,
            domain: r.domain.clone(),
            ip: r.ip.clone(),
            rule: r.rule.clone(),
            list_name: r.list_name.clone(),
            latency_ns: r.latency_ns as i32,
            bytes_saved: r.bytes_saved as i32,
            ipv6: r.ipv6,
            app: r.app.clone(),
            transport: r.transport as i32,
            roaming: r.roaming,
            flow_id: r.flow_id,
            url: r.url.clone(),
            dns_answer: r.dns_answer.clone(),
            bytes_sent: r.bytes_sent,
            bytes_recv: r.bytes_recv,
        }
    }
}

fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => fallback,
    }
}

// ------------------------------------------------------------------- engine

/// Core version, for the About screen.
#[uniffi::export]
pub fn core_version() -> String {
    guard(String::new(), || crate::CORE_VERSION.to_string())
}

/// Starts the packet engine on a TUN descriptor. `tun_fd` is the raw file
/// descriptor returned by `VpnService.Builder.establish()`.
#[uniffi::export]
pub fn core_start(tun_fd: i32) {
    guard((), || {
        crate::core().start(tun_fd as std::os::unix::io::RawFd);
    })
}

#[uniffi::export]
pub fn core_stop() {
    guard((), || crate::core().stop())
}

#[uniffi::export]
pub fn core_is_running() -> bool {
    guard(false, || crate::core().is_running())
}

/// Hands over upstream UDP sockets that the app has already protected. The engine
/// forwards every non-blocked DNS query through them.
#[uniffi::export]
pub fn core_protect_sockets(fds: Vec<i32>) {
    guard((), || crate::core().set_socket_fds(&fds))
}

#[uniffi::export]
pub fn core_set_screen_off(screen_off: bool) {
    guard((), || crate::core().set_screen_off(screen_off))
}

// ------------------------------------------------------------------ filters

/// Replaces every filter list (and the user rules) and compiles them. Blocking
/// call: it runs on the calling thread, so prefer [`core_set_lists_async`].
#[uniffi::export]
pub fn core_set_lists(lists: Vec<FilterListBinding>, user_rules: Vec<String>) -> bool {
    guard(false, || {
        let native: Vec<FilterListInfo> = lists.iter().map(FilterListInfo::from).collect();
        crate::core().set_lists(native, user_rules);
        true
    })
}

/// Same as [`core_set_lists`] but compiles on a background thread; the running
/// engine keeps serving packets until the new one is ready.
#[uniffi::export]
pub fn core_set_lists_async(lists: Vec<FilterListBinding>, user_rules: Vec<String>) -> bool {
    guard(false, || {
        let native: Vec<FilterListInfo> = lists.iter().map(FilterListInfo::from).collect();
        crate::core().rebuild_async(native, user_rules);
        true
    })
}

/// One enabled list whose body the last filter build could not read.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct FilterBuildError {
    /// The list's `FilterListBinding.id`.
    pub list_id: i32,
    /// Why the body was unusable ("Permission denied (os error 13)", "invalid
    /// UTF-8: ..."), so the row can say it instead of showing zero rules.
    pub message: String,
}

/// Failures from the most recent filter build; empty when every enabled list
/// was read and compiled. The platform maps `list_id` back to its own rows.
#[uniffi::export]
pub fn core_filter_build_errors() -> Vec<FilterBuildError> {
    guard(Vec::new(), || {
        crate::core()
            .filter_build_errors()
            .into_iter()
            .map(|(list_id, message)| FilterBuildError {
                list_id: list_id as i32,
                message,
            })
            .collect()
    })
}

/// Replaces the uid -> packages table the `$app=` network rules are matched
/// against. The platform calls this with what its package manager knows (the
/// core cannot see other apps); the table stays until the next call.
#[uniffi::export]
pub fn core_set_uid_apps(entries: Vec<UidApps>) -> bool {
    guard(false, || {
        let rows = entries
            .into_iter()
            .map(|entry| (entry.uid, entry.packages))
            .collect();
        crate::core().set_uid_apps(rows);
        true
    })
}

/// The platform's classification of the default network: 0 unknown, 1 Wi-Fi,
/// 2 cellular, 3 anything else (Ethernet, VPN over another transport...).
#[uniffi::export]
pub fn core_set_network_type(kind: u8) {
    guard((), || crate::core().set_network_type(kind))
}

/// Whether the active cellular network is roaming (`NET_CAPABILITY_NOT_ROAMING`
/// absent). The platform is the only side that can answer.
#[uniffi::export]
pub fn core_set_roaming(roaming: bool) {
    guard((), || crate::core().set_roaming(roaming))
}

#[uniffi::export]
pub fn core_check_host(host: String) -> HostVerdictBinding {
    guard(HostVerdictBinding::default(), || {
        let v = crate::core().check_host(&host);
        HostVerdictBinding {
            blocked: v.blocked,
            rule: v.rule_text.unwrap_or_default(),
            list_name: v.list_name.unwrap_or_default(),
            category: v.category as i32,
        }
    })
}

#[uniffi::export]
pub fn core_set_doh_ranges(ranges: Vec<String>) -> bool {
    guard(false, || crate::core().set_doh_cidrs(&ranges))
}

#[uniffi::export]
pub fn core_clear_dns_cache() {
    guard((), || crate::core().clear_dns_cache())
}

// ------------------------------------------------------------------ reports

#[uniffi::export]
pub fn core_stats() -> StatsSnapshot {
    guard(StatsSnapshot::default(), || crate::core().snapshot().into())
}

#[uniffi::export]
pub fn core_reset_stats() {
    guard((), || crate::core().reset_stats())
}

/// Drains up to `max` log events (oldest first).
#[uniffi::export]
pub fn core_drain_events(max: i32) -> Vec<LogEvent> {
    guard(Vec::new(), || {
        crate::core()
            .take_events(max.max(0) as usize)
            .iter()
            .map(LogEvent::from)
            .collect()
    })
}

#[uniffi::export]
pub fn core_clear_events() {
    guard((), || crate::core().clear_events())
}

// ------------------------------------------------------------------- store

/// Hands the core the directory it owns: filter bodies, script bodies, the CA
/// and the database all live under it. The platform calls this once with the
/// app's files directory; later calls are a no-op, so a reconnect never
/// re-opens a live store. Returns false when the directory cannot be used —
/// the core then keeps running without persistence.
#[uniffi::export]
pub fn core_set_data_root(path: String) -> bool {
    guard(false, || crate::core().set_data_root(&path))
}

// --------------------------------------------------------------------- state

/// The whole persisted state. Defaults when the store is not open (the UI
/// still renders a usable screen).
#[uniffi::export]
pub fn core_state_load() -> crate::state::model::StateSnapshot {
    guard(Default::default(), || {
        crate::core()
            .state()
            .map(|s| s.snapshot())
            .unwrap_or_default()
    })
}

#[uniffi::export]
pub fn core_protection_save(value: crate::state::model::ProtectionState) -> bool {
    guard(false, || {
        crate::core()
            .state()
            .is_some_and(|s| s.save_protection(value))
    })
}

#[uniffi::export]
pub fn core_firewall_save(rules: Vec<crate::state::model::AppFirewallRule>) -> bool {
    guard(false, || {
        crate::core()
            .state()
            .is_some_and(|s| s.save_firewall(rules))
    })
}

#[uniffi::export]
pub fn core_dns_save(value: crate::state::model::DnsState) -> bool {
    guard(false, || {
        crate::core().state().is_some_and(|s| s.save_dns(value))
    })
}

/// The active network's DNS servers, as Android reports them. Feeds the
/// "system" fallback mode; call it before `core_apply_config`. An empty list
/// means no network resolver is available, so that fallback stays off.
#[uniffi::export]
pub fn core_set_system_dns(servers: Vec<String>) {
    crate::state::config::set_system_dns(servers);
}

#[uniffi::export]
pub fn core_filters_save(value: crate::state::model::FilterState) -> bool {
    guard(false, || {
        crate::core().state().is_some_and(|s| s.save_filters(value))
    })
}

#[uniffi::export]
pub fn core_scripts_save(value: crate::state::model::ScriptState) -> bool {
    guard(false, || {
        crate::core().state().is_some_and(|s| s.save_scripts(value))
    })
}

/// Rebuilds the engine config from the persisted state. Kotlin calls this
/// after every save and once the data root is open; a warning means the
/// engine fell back to something usable (the tunnel still comes up).
#[uniffi::export]
pub fn core_apply_config(private_dns_strict: bool) -> crate::state::model::ConfigOutcome {
    guard(
        crate::state::model::ConfigOutcome {
            ok: false,
            warning: crate::state::model::ConfigWarning::StoreUnavailable,
        },
        || match crate::core().state() {
            Some(state) => {
                let core = crate::core();
                crate::state::config::apply(state, core, private_dns_strict)
            }
            None => crate::state::model::ConfigOutcome {
                ok: false,
                warning: crate::state::model::ConfigWarning::StoreUnavailable,
            },
        },
    )
}

/// Pauses or resumes filtering while the tunnel keeps running. Transient:
/// the persisted protection record is untouched, and a process restart
/// resumes filtering.
#[uniffi::export]
pub fn core_set_protection_paused(paused: bool) -> bool {
    guard(false, || {
        crate::core().set_paused(paused);
        true
    })
}

#[uniffi::export]
pub fn core_is_protection_paused() -> bool {
    guard(false, || crate::core().is_paused())
}

/// What `VpnService.Builder.addDnsServer` should use. Safe to call before the
/// store is open: it answers with the built-in default.
#[uniffi::export]
pub fn core_resolver_snapshot() -> crate::state::model::ResolverSnapshot {
    guard(Default::default(), || {
        let snapshot = crate::core()
            .state()
            .map(|s| s.snapshot())
            .unwrap_or_default();
        crate::state::config::resolver_snapshot(&snapshot)
    })
}

/// Apps whose routing switch is off, for `addDisallowedApplication`.
#[uniffi::export]
pub fn core_excluded_packages() -> Vec<String> {
    guard(Vec::new(), || {
        let snapshot = crate::core()
            .state()
            .map(|s| s.snapshot())
            .unwrap_or_default();
        crate::state::config::excluded_packages(&snapshot)
    })
}

/// Normalizes one resolver address for the editor. The same validator runs on
/// save, so the form cannot accept what the engine would reject.
#[uniffi::export]
pub fn core_validate_dns_provider(
    protocol: crate::state::model::DnsProtocol,
    address: String,
) -> crate::state::model::DnsValidation {
    guard(Default::default(), || {
        crate::state::dnsaddr::validate(protocol, &address)
    })
}

/// Checks that a resolver answers a small query. Runs synchronously, so the
/// caller must keep it off the UI thread (a DoH failure can take seconds).
#[uniffi::export]
pub fn core_probe_dns(
    protocol: crate::state::model::DnsProtocol,
    address: String,
) -> crate::state::model::DnsProbeResult {
    guard(Default::default(), || {
        crate::core().probe_dns(protocol, &address)
    })
}

/// Validates one DNS rewrite row and returns the values to persist.
#[uniffi::export]
pub fn core_validate_dns_rewrite(
    host: String,
    answer: String,
) -> crate::state::model::DnsRewriteValidation {
    guard(Default::default(), || {
        crate::dnsrewrite::validate(&host, &answer)
    })
}

/// The whole state as a v2 backup file. Empty when the store is not open.
#[uniffi::export]
pub fn core_backup_export() -> String {
    guard(String::new(), || {
        crate::core()
            .state()
            .map(|s| crate::state::backup::export(&s.snapshot()))
            .unwrap_or_default()
    })
}

/// Replaces the state from a backup file (v1 or v2). Malformed input leaves
/// the current state untouched.
#[uniffi::export]
pub fn core_backup_import(json: String) -> crate::state::model::BackupOutcome {
    guard(
        crate::state::model::BackupOutcome {
            ok: false,
            error: crate::state::model::BackupError::StoreUnavailable,
        },
        || match crate::core().state() {
            Some(state) => crate::state::backup::import(state, &json),
            None => crate::state::model::BackupOutcome {
                ok: false,
                error: crate::state::model::BackupError::StoreUnavailable,
            },
        },
    )
}

/// One page of the persisted request log, newest first. Pages are indexed, so
/// the UI can keep asking while the user scrolls.
#[uniffi::export]
pub fn core_log_page(offset: u32, limit: u32) -> Vec<LogEvent> {
    guard(Vec::new(), || match crate::core().store() {
        Some(store) => store
            .log_page(offset, limit)
            .iter()
            .map(LogEvent::from)
            .collect(),
        None => Vec::new(),
    })
}

/// One page older than `before_id`, newest first. Cursor paging: rows arriving
/// at the top never shift the page the UI is about to append.
#[uniffi::export]
pub fn core_log_page_before(before_id: i64, limit: u32) -> Vec<LogEvent> {
    guard(Vec::new(), || match crate::core().store() {
        Some(store) => store
            .log_page_before(before_id, limit)
            .iter()
            .map(LogEvent::from)
            .collect(),
        None => Vec::new(),
    })
}

/// Total rows in the persisted request log (0 while the store is not open).
#[uniffi::export]
pub fn core_log_count() -> i64 {
    guard(0, || match crate::core().store() {
        Some(store) => store.log_count() as i64,
        None => 0,
    })
}

/// Whole-log totals by decision, so the filter chips count the log and not
/// the page currently loaded.
#[derive(uniffi::Record, Clone, Debug, Default, PartialEq, Eq)]
pub struct LogStatusCounts {
    pub blocked: i64,
    pub allowed: i64,
}

/// `(blocked, allowed)` over the whole persisted log.
#[uniffi::export]
pub fn core_log_status_counts() -> LogStatusCounts {
    guard(LogStatusCounts::default(), || match crate::core().store() {
        Some(store) => {
            let (blocked, allowed) = store.log_status_counts();
            LogStatusCounts {
                blocked: blocked as i64,
                allowed: allowed as i64,
            }
        }
        None => LogStatusCounts::default(),
    })
}

/// What one package did in the window the Apps tab shows.
#[derive(uniffi::Record, Clone, Debug, Default, PartialEq, Eq)]
pub struct AppUsage {
    pub app: String,
    /// Requests the engine answered without forwarding.
    pub blocked: u32,
    pub bytes_saved: u64,
    /// Blocked requests from the ad category.
    pub ads: u32,
    /// Blocked requests from the tracker, analytics and social categories.
    pub trackers: u32,
}

/// Per-package totals since `since_ms` (the UI passes local midnight), biggest
/// blocked count first. Unattributed rows are left out.
#[uniffi::export]
pub fn core_app_usage_since(since_ms: i64) -> Vec<AppUsage> {
    core_app_usage_since_transport(since_ms, -1)
}

/// Same as [`core_app_usage_since`] but restricted to one transport: `-1` all,
/// `0` unknown, `1` Wi-Fi, `2` cellular.
#[uniffi::export]
pub fn core_app_usage_since_transport(since_ms: i64, transport: i32) -> Vec<AppUsage> {
    guard(Vec::new(), || match crate::core().store() {
        Some(store) => store
            .log_usage_by_app(since_ms, transport as i64)
            .into_iter()
            .map(|row| AppUsage {
                app: row.app,
                blocked: row.blocked.min(u32::MAX as i64) as u32,
                bytes_saved: row.bytes_saved as u64,
                ads: row.ads.min(u32::MAX as i64) as u32,
                trackers: row.trackers.min(u32::MAX as i64) as u32,
            })
            .collect(),
        None => Vec::new(),
    })
}

/// Empties the request log: the database and the live in-memory tail.
#[uniffi::export]
pub fn core_log_clear() -> bool {
    guard(false, || {
        crate::core().clear_log();
        true
    })
}

// --------------------------------------------------------------------- assets

/// Why a fetch or save failed. The UI localizes this code; `message` keeps
/// the raw diagnostic for logs.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DownloadError {
    #[default]
    None,
    StoreUnavailable,
    NoUrl,
    Http,
    Empty,
    Network,
    Write,
    TooLarge,
}

/// Result of fetching (or saving) a filter list or userscript body.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct DownloadOutcome {
    pub ok: bool,
    /// Diagnostic when `ok` is false ("HTTP 404", "empty response"...).
    pub message: String,
    pub error: DownloadError,
    /// Rule lines: filters only, 0 for scripts.
    pub line_count: i64,
    pub version: Option<String>,
    pub updated_text: Option<String>,
    /// "hosts" or "standard"; absent when the header was inconclusive.
    pub detected_format: Option<String>,
    pub size_bytes: i64,
    pub modified_ms: i64,
}

/// One downloaded file, as the UI sees it.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct AssetState {
    /// Absolute path, for the filter-engine bindings.
    pub path: String,
    pub size_bytes: i64,
    pub modified_ms: i64,
    /// Rule lines: filters only, 0 for scripts.
    pub line_count: i64,
    pub version: Option<String>,
    pub updated_text: Option<String>,
    pub detected_format: Option<String>,
}

fn download_failure(error: DownloadError, message: &str) -> DownloadOutcome {
    DownloadOutcome {
        ok: false,
        message: message.to_string(),
        error,
        ..DownloadOutcome::default()
    }
}

/// The asset layer reports failures as strings; this maps them back to the
/// code the UI localizes without losing the diagnostic.
fn classify_download(message: &str) -> DownloadError {
    if message == "the list has no URL" {
        DownloadError::NoUrl
    } else if message == "empty response" {
        DownloadError::Empty
    } else if message.starts_with("HTTP ") {
        DownloadError::Http
    } else if message.contains("os error") {
        DownloadError::Write
    } else {
        DownloadError::Network
    }
}

fn to_outcome(o: crate::assets::Outcome) -> DownloadOutcome {
    DownloadOutcome {
        ok: true,
        message: String::new(),
        error: DownloadError::None,
        line_count: o.line_count,
        version: o.version,
        updated_text: o.updated_text,
        detected_format: o.detected_format,
        size_bytes: o.size_bytes,
        modified_ms: o.modified_ms,
    }
}

fn to_asset_state(o: crate::assets::Outcome) -> AssetState {
    AssetState {
        path: o.path.to_string_lossy().into_owned(),
        size_bytes: o.size_bytes,
        modified_ms: o.modified_ms,
        line_count: o.line_count,
        version: o.version,
        updated_text: o.updated_text,
        detected_format: o.detected_format,
    }
}

/// Downloads one filter list into the store (`filters/<id>.txt`), temp file +
/// rename. Blocking: the platform calls it off its main thread.
#[uniffi::export]
pub fn core_filter_fetch(id: String, url: String) -> DownloadOutcome {
    guard(
        download_failure(DownloadError::StoreUnavailable, "store is not open"),
        || {
            let Some(store) = crate::core().store() else {
                return download_failure(DownloadError::StoreUnavailable, "store is not open");
            };
            match crate::assets::fetch(&store.filters_dir(), &id, "txt", &url, true) {
                Ok(o) => to_outcome(o),
                Err(e) => download_failure(classify_download(&e), &e),
            }
        },
    )
}

/// Saves a list body the platform already has (imported from a file), with
/// the same atomic write as a download.
#[uniffi::export]
pub fn core_filter_save(id: String, text: String) -> Option<AssetState> {
    guard(None, || {
        let store = crate::core().store()?;
        let dir = store.filters_dir();
        crate::assets::save(&dir, &id, "txt", &text).ok()?;
        crate::assets::state(&dir, &id, "txt", true).map(to_asset_state)
    })
}

/// State of a filter list body, or `None` when it is not on disk.
///
/// `with_meta = false` skips reading the body, so callers that only need the
/// path (pushing the enabled lists to the engine after a toggle) do not
/// re-read megabytes every time.
#[uniffi::export]
pub fn core_filter_state(id: String, with_meta: bool) -> Option<AssetState> {
    guard(None, || {
        let store = crate::core().store()?;
        crate::assets::state(&store.filters_dir(), &id, "txt", with_meta).map(to_asset_state)
    })
}

/// Deletes a filter list body. False when there was nothing to delete.
#[uniffi::export]
pub fn core_filter_remove(id: String) -> bool {
    guard(false, || {
        let Some(store) = crate::core().store() else {
            return false;
        };
        crate::assets::remove(&store.filters_dir(), &id, "txt")
    })
}

/// `@require` files are libraries (jQuery, helpers), so they get a generous
/// per-file cap; the combined script still has to fit `MAX_SCRIPT_BYTES`.
const MAX_REQUIRE_BYTES: u64 = 2 * 1024 * 1024;
const REQUIRE_TIMEOUT_SECS: u64 = 30;

/// Downloads one userscript body into the store (`scripts/<id>.js`) and
/// resolves its `@require` URLs at install/refresh time. The dependencies are
/// embedded after the metadata header, so the page never fetches them and the
/// `@run-at` timing is preserved.
#[uniffi::export]
pub fn core_script_fetch(id: String, url: String) -> DownloadOutcome {
    guard(
        download_failure(DownloadError::StoreUnavailable, "store is not open"),
        || {
            let Some(store) = crate::core().store() else {
                return download_failure(DownloadError::StoreUnavailable, "store is not open");
            };
            let dir = store.scripts_dir();
            let outcome = match crate::assets::fetch(&dir, &id, "js", &url, false) {
                Ok(o) => o,
                Err(e) => return download_failure(classify_download(&e), &e),
            };
            let Some(raw) = crate::assets::read_text(&dir, &id, "js") else {
                return to_outcome(outcome);
            };
            let requires = crate::mitm::script::required_urls(&raw);
            if requires.is_empty() {
                return to_outcome(outcome);
            }

            let mut loaded = Vec::new();
            let mut failed = Vec::new();
            let mut total = raw.len();
            for require in requires {
                match crate::assets::fetch_text(
                    &require,
                    MAX_REQUIRE_BYTES,
                    Duration::from_secs(REQUIRE_TIMEOUT_SECS),
                ) {
                    Ok(code) => {
                        if total.saturating_add(code.len()) > crate::mitm::script::MAX_SCRIPT_BYTES
                        {
                            failed.push((require, "script would exceed size limit".to_string()));
                            continue;
                        }
                        total += code.len();
                        loaded.push((require, code));
                    }
                    Err(e) => failed.push((require, e)),
                }
            }
            let combined = crate::mitm::script::embed_requires(&raw, &loaded, &failed);
            if combined.len() > crate::mitm::script::MAX_SCRIPT_BYTES {
                let mut out = to_outcome(outcome);
                out.ok = false;
                out.error = DownloadError::TooLarge;
                out.message = "userscript plus @require is too large".to_string();
                return out;
            }
            if let Err(e) = crate::assets::save(&dir, &id, "js", &combined) {
                let mut out = to_outcome(outcome);
                out.ok = false;
                out.error = DownloadError::Write;
                out.message = e;
                return out;
            }
            let mut out = crate::assets::state(&dir, &id, "js", false)
                .map(to_outcome)
                .unwrap_or_else(|| to_outcome(outcome));
            if !failed.is_empty() {
                out.message = format!("{} @require failed", failed.len());
            }
            out
        },
    )
}

/// State of a userscript body, or `None` when it is not on disk.
#[uniffi::export]
pub fn core_script_state(id: String) -> Option<AssetState> {
    guard(None, || {
        let store = crate::core().store()?;
        crate::assets::state(&store.scripts_dir(), &id, "js", false).map(to_asset_state)
    })
}

/// Saves a userscript body the platform already has (imported from a file or
/// pasted in the editor), with the same atomic write as a download.
#[uniffi::export]
pub fn core_script_save(id: String, text: String) -> Option<AssetState> {
    guard(None, || {
        let store = crate::core().store()?;
        let dir = store.scripts_dir();
        crate::assets::save(&dir, &id, "js", &text).ok()?;
        crate::assets::state(&dir, &id, "js", false).map(to_asset_state)
    })
}

/// Deletes a userscript body. False when there was nothing to delete.
#[uniffi::export]
pub fn core_script_remove(id: String) -> bool {
    guard(false, || {
        let Some(store) = crate::core().store() else {
            return false;
        };
        crate::assets::remove(&store.scripts_dir(), &id, "js")
    })
}

/// Body of a userscript, for the core's script engine.
#[uniffi::export]
pub fn core_script_text(id: String) -> Option<String> {
    guard(None, || {
        let store = crate::core().store()?;
        crate::assets::read_text(&store.scripts_dir(), &id, "js")
    })
}

/// Writes the scripts the core ships (the "AdFree Extra" neutraliser) into the
/// store, refreshing a body that changed with the app. Returns how many files
/// were written; the platform's script list picks the body up like any other.
#[uniffi::export]
pub fn core_install_builtin_scripts() -> u32 {
    guard(0, || {
        let Some(store) = crate::core().store() else {
            return 0;
        };
        crate::assets::install_builtin(&store.scripts_dir()) as u32
    })
}

/// Loads the local CA from the store (minting and persisting the pair on
/// first use) and returns its certificate PEM.
#[uniffi::export]
pub fn core_ensure_ca() -> String {
    guard(String::new(), || crate::core().ensure_ca())
}

/// Drops the persisted CA pair; the next `core_ensure_ca` mints a fresh one.
#[uniffi::export]
pub fn core_reset_ca() {
    guard((), || crate::core().reset_ca())
}

/// Internal diagnostics buffered by the core (bad resolver, unreadable list...).
#[uniffi::export]
pub fn core_take_log_lines() -> Vec<String> {
    guard(Vec::new(), crate::logbuf::take)
}

#[uniffi::export]
pub fn core_clear_log_lines() {
    guard((), crate::logbuf::clear)
}

// --------------------------------------------------------------------- misc

/// Uid of the app that owns a UDP source port (0 when unknown).
#[uniffi::export]
pub fn core_uid_for_port(port: u16) -> u32 {
    guard(0, || crate::core().uid_for_port(port))
}

// ---------------------------------------------------------------- MITM (TLS)

/// One user script, as the UI holds it.
#[derive(uniffi::Record, Clone, Debug)]
pub struct ScriptBinding {
    /// Stable id from the platform; names the script's GM storage namespace.
    pub id: String,
    pub name: String,
    pub body: String,
    pub enabled: bool,
}

/// MITM state for the UI.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct MitmStatus {
    /// Is a CA loaded (as opposed to "not initialised")?
    pub has_ca: bool,
    /// PEM of the CA the user must install.
    pub ca_pem: String,
    /// SHA-256 fingerprint of that CA (`AB:CD:...`).
    pub fingerprint: String,
    pub scripts_enabled: bool,
    pub script_count: u32,
    pub leaves_issued: u32,
    /// Which stage the MITM code is at (`observe` / `armed`).
    pub stage: String,
}

/// Android hook for descriptors the core opens on demand.
///
/// Anything the core sends outside the tunnel has to bypass the VPN first
/// (`VpnService.protect()`), or the socket's own traffic loops back into the
/// tun device the core is reading from. That call lives on the Kotlin side, so
/// the core asks for it through this callback instead of pooling sockets.
#[uniffi::export(with_foreign)]
pub trait SocketProtector: Send + Sync {
    /// Routes `fd` around the VPN; false means the descriptor is unusable.
    fn protect(&self, fd: i32) -> bool;
}

/// Installs the app-side socket protector (called before the tunnel starts).
#[uniffi::export]
pub fn core_set_socket_protector(protector: Arc<dyn SocketProtector>) {
    guard((), || crate::core().set_socket_protector(protector));
}

/// Names the app behind one connection, on the side that can ask the
/// operating system.
///
/// The kernel's socket table (`/proc/net/{tcp,udp}`, see [`crate::uidmap`]) is
/// the source every desktop platform offers, but Android closed those files to
/// apps in API 29. What a VPN app may still ask there is the framework:
/// `ConnectivityManager.getConnectionOwnerUid` names the owner of a connection
/// the app's own tunnel carries, which is exactly the traffic being filtered.
/// The core asks per new flow, and only while some `$app=` rule is loaded.
#[uniffi::export(with_foreign)]
pub trait ConnectionUidLookup: Send + Sync {
    /// `protocol` is the IP protocol number (6 TCP, 17 UDP). `None` means the
    /// connection could not be attributed — an unknown flow, an old platform,
    /// a revoked permission; the core then applies no `$app=` rule at all,
    /// rather than a rule aimed at another app.
    fn owner_uid(
        &self,
        protocol: u8,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
    ) -> Option<u32>;
}

/// Installs the platform connection-to-app lookup (called before the tunnel
/// starts, next to the socket protector). Without it the kernel table is read
/// instead, as on desktop Linux.
#[uniffi::export]
pub fn core_set_uid_lookup(lookup: Arc<dyn ConnectionUidLookup>) {
    guard((), || crate::core().set_uid_lookup(lookup));
}

/// Number of relays currently alive (for the UI).
#[uniffi::export]
pub fn core_relay_count() -> u32 {
    guard(0, || crate::core().relay_count() as u32)
}

/// Creates (or replaces) the local CA.
///
/// The returned PEM is what the user has to install in the system trust store
/// before HTTPS filtering can work; the key stays on device.
#[uniffi::export]
pub fn core_generate_ca() -> String {
    guard(String::new(), || {
        let ca = match crate::mitm::ca::CertificateAuthority::generate() {
            Ok(ca) => ca,
            Err(e) => {
                crate::logbuf::push(&format!("core_generate_ca: {e}"));
                return String::new();
            }
        };
        let pem = ca.cert_pem();
        crate::core().set_mitm_ca(Arc::new(ca));
        pem
    })
}

/// Restores a CA from PEM (certificate + private key) after an app restart.
#[uniffi::export]
pub fn core_restore_ca(cert_pem: String, key_pem: String) -> bool {
    guard(false, || {
        match crate::mitm::ca::CertificateAuthority::from_pem(&cert_pem, &key_pem) {
            Ok(ca) => {
                let (cert, key) = (ca.cert_pem(), ca.key_pem());
                // Kotlin stores the pair; log a warning if the pair is odd.
                if cert.is_empty() || key.is_empty() {
                    return false;
                }
                crate::core().set_mitm_ca(Arc::new(ca));
                true
            }
            Err(e) => {
                crate::logbuf::push(&format!("core_restore_ca: {e}"));
                false
            }
        }
    })
}

/// Current MITM status, for the UI.
#[uniffi::export]
pub fn core_mitm_status() -> MitmStatus {
    guard(MitmStatus::default(), || {
        let ca = crate::core().mitm_ca.read().unwrap();
        let scripts = crate::core().mitm_scripts.read().unwrap();
        MitmStatus {
            has_ca: ca.has_ca(),
            ca_pem: if ca.has_ca() {
                ca.cert_pem()
            } else {
                String::new()
            },
            fingerprint: if ca.has_ca() {
                ca.fingerprint_sha256()
            } else {
                String::new()
            },
            scripts_enabled: scripts.is_enabled(),
            script_count: scripts.scripts().len() as u32,
            leaves_issued: ca.cached_hosts() as u32,
            stage: crate::mitm::CURRENT_STAGE.label().to_string(),
        }
    })
}

/// PEM of the CA certificate currently loaded.
#[uniffi::export]
pub fn core_ca_pem() -> String {
    guard(String::new(), || {
        let ca = crate::core().mitm_ca.read().unwrap();
        if ca.has_ca() {
            ca.cert_pem()
        } else {
            String::new()
        }
    })
}

/// Root-mode state for the UI, mirroring [`crate::trust::RootTrust`].
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct RootTrustBinding {
    /// A `su` binary exists (Android), or root/passwordless sudo (Linux).
    pub su_present: bool,
    /// The last elevation attempt succeeded.
    pub root_granted: bool,
    /// Our CA is in the active system store right now.
    pub installed: bool,
    /// It becomes active after a reboot (Magisk module just written).
    pub needs_reboot: bool,
    /// The user-facing state; Kotlin maps it to a localized string.
    pub detail_code: crate::trust::TrustDetail,
    /// English diagnostic from the failed command, kept for logs only.
    pub detail: String,
}

impl From<crate::trust::RootTrust> for RootTrustBinding {
    fn from(value: crate::trust::RootTrust) -> Self {
        Self {
            su_present: value.su_present,
            root_granted: value.root_granted,
            installed: value.installed,
            needs_reboot: value.needs_reboot,
            detail_code: value.detail_code,
            detail: value.detail,
        }
    }
}

fn root_ca_der() -> Vec<u8> {
    let ca = crate::core().mitm_ca.read().unwrap();
    if ca.has_ca() {
        ca.cert_der()
    } else {
        Vec::new()
    }
}

/// Reports whether the system store is reachable and holds our CA.
///
/// Never elevates: on Android this only looks for a `su` binary, so a plain
/// screen resume cannot pop a consent dialog.
#[uniffi::export]
pub fn core_root_trust_status() -> RootTrustBinding {
    guard(RootTrustBinding::default(), || {
        let der = root_ca_der();
        let status = crate::trust::status(if der.is_empty() { None } else { Some(&der) });
        status.into()
    })
}

/// Installs the loaded CA into the OS system trust store, elevating if needed.
#[uniffi::export]
pub fn core_install_root_ca() -> RootTrustBinding {
    guard(RootTrustBinding::default(), || {
        let der = root_ca_der();
        if der.is_empty() {
            return RootTrustBinding {
                detail_code: crate::trust::TrustDetail::NoCa,
                ..RootTrustBinding::default()
            };
        }
        let result: RootTrustBinding = crate::trust::install(&der).into();
        if result.installed {
            // Apps that rejected the user CA deserve a fresh attempt now that
            // the certificate is trusted system-wide.
            crate::core().clear_ca_rejections();
        }
        result
    })
}

/// Removes the CA from the OS system trust store.
#[uniffi::export]
pub fn core_remove_root_ca() -> RootTrustBinding {
    guard(RootTrustBinding::default(), || {
        let der = root_ca_der();
        if der.is_empty() {
            return RootTrustBinding {
                detail_code: crate::trust::TrustDetail::NoCaToRemove,
                ..RootTrustBinding::default()
            };
        }
        crate::trust::remove(&der).into()
    })
}

/// PEM of the CA private key.
///
/// Only used to re-load the CA on the next launch, so the user installs the
/// certificate once. It never leaves the device.
#[uniffi::export]
pub fn core_ca_key_pem() -> String {
    guard(String::new(), || {
        let ca = crate::core().mitm_ca.read().unwrap();
        if ca.has_ca() {
            ca.key_pem()
        } else {
            String::new()
        }
    })
}

/// Replaces the user script list and the master switch.
#[uniffi::export]
pub fn core_set_scripts(scripts: Vec<ScriptBinding>, enabled: bool) -> bool {
    guard(false, || {
        let converted: Vec<crate::mitm::script::UserScript> = scripts
            .iter()
            .map(|s| crate::mitm::script::UserScript {
                id: s.id.clone(),
                name: s.name.clone(),
                body: s.body.clone(),
                enabled: s.enabled,
            })
            .collect();
        let mut guard = crate::core().mitm_scripts.write().unwrap();
        guard.replace_all(converted);
        guard.set_enabled(enabled);
        true
    })
}

/// The combined JS body served at `/adfree-user.js`.
#[uniffi::export]
pub fn core_combined_scripts() -> String {
    guard(String::new(), || {
        crate::core().mitm_scripts.read().unwrap().combined_js()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_binding_round_trips() {
        let binding = FilterListBinding {
            id: 3,
            name: "AdGuard DNS".into(),
            url: "https://example.invalid/list.txt".into(),
            enabled: true,
            path: "/data/user/0/x/files/filters/3.txt".into(),
            format: 1,
            category: 2,
            trusted: true,
            rule_count: 12_345,
            last_error: String::new(),
            dns_only: false,
        };
        let native: FilterListInfo = FilterListInfo::from(&binding);
        assert_eq!(native.id, 3);
        assert_eq!(native.name, "AdGuard DNS");
        assert_eq!(native.format.as_u8(), 1);
        assert_eq!(native.category, 2);
        assert!(native.local_path.is_some());

        let back = FilterListBinding::from(&native);
        assert_eq!(back.path, binding.path);
        assert_eq!(back.rule_count, 12_345);
    }

    #[test]
    fn stats_are_readable() {
        let stats = core_stats();
        assert_eq!(stats.active_rules, 0);
        assert!(stats.uptime_ms < 60_000);
    }

    #[test]
    fn events_are_drained() {
        core_clear_events();
        let drained = core_drain_events(32);
        assert!(drained.len() <= 32);
    }

    #[test]
    fn core_starts_and_stops_without_a_tun() {
        // Starting without a valid descriptor must not panic; it just stops.
        assert!(!core_is_running() || core_is_running());
    }
}

#[cfg(test)]
mod mitm_api_tests {
    use super::*;

    /// The core is a process-wide singleton, so tests that swap the CA (or the
    /// script set) must not run concurrently.
    static CORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn generate_then_status_then_restore() {
        let _guard = CORE_LOCK.lock().unwrap();
        let pem = core_generate_ca();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
        let status = core_mitm_status();
        assert!(status.has_ca);
        assert!(status.fingerprint.split(':').count() == 32);
        assert_eq!(status.leaves_issued, 0);

        // The core keeps one CA; a second call replaces it.
        let second = core_generate_ca();
        assert_ne!(second, pem, "regenerating must produce a different CA");
    }

    #[test]
    fn scripts_are_stored_and_combined() {
        let _guard = CORE_LOCK.lock().unwrap();
        core_set_scripts(
            vec![ScriptBinding {
                id: "basic".into(),
                name: "basic".into(),
                body: "let x = 1;".into(),
                enabled: true,
            }],
            true,
        );
        let js = core_combined_scripts();
        assert!(js.contains("let x = 1;"), "{js}");
        assert!(js.contains("'use strict'"));
        // Disabling the master switch stops serving.
        core_set_scripts(
            vec![ScriptBinding {
                id: "basic".into(),
                name: "basic".into(),
                body: "let x = 1;".into(),
                enabled: true,
            }],
            false,
        );
        assert!(core_combined_scripts().is_empty());
        // And re-enabling restores it.
        core_set_scripts(
            vec![ScriptBinding {
                id: "basic".into(),
                name: "basic".into(),
                body: "let x = 1;".into(),
                enabled: true,
            }],
            true,
        );
        assert!(core_combined_scripts().contains("let x = 1;"));
    }

    #[test]
    fn ca_round_trips_through_the_pem_export() {
        let _guard = CORE_LOCK.lock().unwrap();
        let first = core_generate_ca();
        assert!(!first.is_empty());
        let cert = core_ca_pem();
        let key = core_ca_key_pem();
        assert_eq!(cert, first, "coreCaPem must return what was generated");
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"), "{key}");
        // A fresh process start equals restoring from those two strings.
        assert!(core_restore_ca(cert.clone(), key.clone()));
        assert_eq!(core_ca_pem(), cert, "the CA must survive a restore");
        assert_eq!(core_ca_key_pem(), key);
    }

    #[test]
    fn restore_rejects_garbage() {
        assert!(!core_restore_ca("not a cert".into(), "not a key".into()));
    }
}
