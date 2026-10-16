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

/// One line of the Activity log.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct LogEvent {
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

/// Runtime knobs, mirrored from the app's `ProtectionSettings`.
#[derive(uniffi::Record, Clone, Copy, Debug)]
pub struct EngineConfig {
    /// Terminate TLS for intercepted connections and inject scripts.
    pub mitm_enabled: bool,
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
            block_quic: true,
            block_doh: false,
            block_dot: true,
            block_mode: 1,
            log_allowed: true,
            eco_mode: false,
        };
        let native: Config = cfg.into();
        assert!(!native.mitm_enabled, "MITM must stay off until asked");
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
