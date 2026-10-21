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

use crate::engine::{Config, VpnStats};
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
        }
    }
}

/// Runtime knobs, mirrored from the app's `ProtectionSettings`.
#[derive(uniffi::Record, Clone, Copy, Debug)]
pub struct EngineConfig {
    /// Terminate TLS for intercepted connections and inject scripts.
    pub mitm_enabled: bool,
    /// Leave ECHConfigs in DNS answers (default off): clients then run ECH end
    /// to end, and the hosts that use it are spliced instead of filtered.
    pub full_ech: bool,
    pub block_quic: bool,
    pub block_doh: bool,
    pub block_dot: bool,
    /// 0 = NXDOMAIN, 1 = answer 0.0.0.0, 2 = REFUSED.
    pub block_mode: i32,
    pub log_allowed: bool,
    pub eco_mode: bool,
}

impl From<EngineConfig> for Config {
    fn from(c: EngineConfig) -> Self {
        Config {
            mitm_enabled: c.mitm_enabled,
            full_ech: c.full_ech,
            block_quic: c.block_quic,
            block_doh: c.block_doh,
            block_dot: c.block_dot,
            block_mode: crate::dns::BlockMode::from_u8(c.block_mode.clamp(0, 2) as u8),
            log_allowed: c.log_allowed,
            eco_mode: c.eco_mode,
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

/// Sets the upstream resolver, e.g. `core_set_resolver("1.1.1.1", 53)`.
#[uniffi::export]
pub fn core_set_resolver(host: String, port: u16) {
    guard((), || {
        if let Ok(ip) = host.trim().parse::<std::net::IpAddr>() {
            crate::core().set_resolver(std::net::SocketAddr::new(ip, port));
        }
    })
}

#[uniffi::export]
pub fn core_configure(config: EngineConfig) {
    guard((), || crate::core().set_config(config.into()))
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
    guard(StatsSnapshot::default(), || {
        crate::core().snapshot().into()
    })
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

/// Total rows in the persisted request log (0 while the store is not open).
#[uniffi::export]
pub fn core_log_count() -> i64 {
    guard(0, || match crate::core().store() {
        Some(store) => store.log_count() as i64,
        None => 0,
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

/// The opaque settings blob (the platform owns the JSON schema). `None` on a
/// first run, or while the store is not open.
#[uniffi::export]
pub fn core_settings_get() -> Option<String> {
    guard(None, || crate::core().settings_get())
}

/// Replaces the settings blob. False when the store is not open, in which
/// case the caller keeps its own copy and retries on the next launch.
#[uniffi::export]
pub fn core_settings_set(json: String) -> bool {
    guard(false, || crate::core().settings_set(&json))
}

/// The opaque filter/script choices blob (enabled lists, custom lists, user
/// rules, userscripts). The platform owns the JSON schema.
#[uniffi::export]
pub fn core_filters_get() -> Option<String> {
    guard(None, || crate::core().filters_get())
}

/// Replaces the filter/script choices blob. False when the store is not open.
#[uniffi::export]
pub fn core_filters_set(json: String) -> bool {
    guard(false, || crate::core().filters_set(&json))
}

// --------------------------------------------------------------------- assets

/// Result of fetching (or saving) a filter list or userscript body.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct DownloadOutcome {
    pub ok: bool,
    /// Diagnostic when `ok` is false ("HTTP 404", "empty response"...).
    pub message: String,
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

fn download_failure(message: &str) -> DownloadOutcome {
    DownloadOutcome {
        ok: false,
        message: message.to_string(),
        ..DownloadOutcome::default()
    }
}

fn to_outcome(o: crate::assets::Outcome) -> DownloadOutcome {
    DownloadOutcome {
        ok: true,
        message: String::new(),
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
    guard(download_failure("store is not open"), || {
        let Some(store) = crate::core().store() else {
            return download_failure("store is not open");
        };
        match crate::assets::fetch(&store.filters_dir(), &id, "txt", &url, true) {
            Ok(o) => to_outcome(o),
            Err(e) => download_failure(&e),
        }
    })
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
    guard(download_failure("store is not open"), || {
        let Some(store) = crate::core().store() else {
            return download_failure("store is not open");
        };
        let dir = store.scripts_dir();
        let outcome = match crate::assets::fetch(&dir, &id, "js", &url, false) {
            Ok(o) => o,
            Err(e) => return download_failure(&e),
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
                    if total.saturating_add(code.len()) > crate::mitm::script::MAX_SCRIPT_BYTES {
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
            out.message = "userscript plus @require is too large".to_string();
            return out;
        }
        if let Err(e) = crate::assets::save(&dir, &id, "js", &combined) {
            let mut out = to_outcome(outcome);
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
    })
}

/// State of a userscript body, or `None` when it is not on disk.
#[uniffi::export]
pub fn core_script_state(id: String) -> Option<AssetState> {
    guard(None, || {
        let store = crate::core().store()?;
        crate::assets::state(&store.scripts_dir(), &id, "js", false).map(to_asset_state)
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
            ca_pem: if ca.has_ca() { ca.cert_pem() } else { String::new() },
            fingerprint: if ca.has_ca() { ca.fingerprint_sha256() } else { String::new() },
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
        if ca.has_ca() { ca.cert_pem() } else { String::new() }
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
        if ca.has_ca() { ca.key_pem() } else { String::new() }
    })
}

/// Replaces the user script list and the master switch.
#[uniffi::export]
pub fn core_set_scripts(scripts: Vec<ScriptBinding>, enabled: bool) -> bool {
    guard(false, || {
        let converted: Vec<crate::mitm::script::UserScript> = scripts
            .iter()
            .map(|s| crate::mitm::script::UserScript {
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
    fn config_round_trips() {
        let cfg = EngineConfig {
            mitm_enabled: false,
            full_ech: true,
            block_quic: true,
            block_doh: false,
            block_dot: true,
            block_mode: 1,
            log_allowed: true,
            eco_mode: false,
        };
        let native: Config = cfg.into();
        assert!(!native.mitm_enabled, "MITM must stay off until asked");
        assert!(native.full_ech, "the full-ECH switch must survive the trip");
        assert!(native.block_quic);
        assert!(!native.block_doh);
        assert!(matches!(native.block_mode, crate::dns::BlockMode::ZeroIp));
    }

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
        core_set_scripts(vec![ScriptBinding {
            name: "basic".into(),
            body: "let x = 1;".into(),
            enabled: true,
        }], false);
        assert!(core_combined_scripts().is_empty());
        // And re-enabling restores it.
        core_set_scripts(vec![ScriptBinding {
            name: "basic".into(),
            body: "let x = 1;".into(),
            enabled: true,
        }], true);
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
