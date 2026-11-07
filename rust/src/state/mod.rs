//! Rust-owned persisted state.
//!
//! The platform used to serialize two opaque JSON blobs and the core only
//! stored them. That split the schema across two languages and let defaults,
//! validation and migration disagree. Here the core parses, validates, merges
//! and writes; Kotlin keeps a write-through cache for the UI and nothing else.
//!
//! Each collection is one row in the `state` table so a save touches only what
//! changed. `state_meta` records one-time work. The old `settings` rows stay
//! behind as an archive after the lossless import in [`legacy`].

pub mod backup;
pub mod config;
pub mod dnsaddr;
pub mod legacy;
pub mod model;

use std::sync::{Arc, RwLock};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::store::Store;
use model::*;

pub const KEY_PROTECTION: &str = "protection";
pub const KEY_FIREWALL: &str = "firewall";
pub const KEY_DNS: &str = "dns";
pub const KEY_FILTERS: &str = "filters";
pub const KEY_SCRIPTS: &str = "scripts";

const META_LEGACY_IMPORTED: &str = "legacy_imported";
/// Schema of the `firewall` row. Version 2 replaced the transport booleans
/// with tri-state dimensions and the per-transport screen-off split; the
/// deserializer reads both, so the migration is a one-time rewrite.
const META_FIREWALL_SCHEMA: &str = "firewall_schema";
const FIREWALL_SCHEMA_VERSION: &str = "2";

/// The state database plus the in-memory copy the engine reads.
pub struct StateStore {
    store: Arc<Store>,
    snapshot: RwLock<StateSnapshot>,
}

impl StateStore {
    /// Opens the state for an already-open store and runs the one-time import
    /// from the platform-written blobs.
    pub fn open(store: Arc<Store>) -> Arc<StateStore> {
        let state = StateStore {
            snapshot: RwLock::new(StateSnapshot::default()),
            store,
        };
        let loaded = state.load();
        *state.snapshot.write().unwrap_or_else(|e| e.into_inner()) = loaded;
        Arc::new(state)
    }

    pub fn snapshot(&self) -> StateSnapshot {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn protection(&self) -> ProtectionState {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .protection
            .clone()
    }

    pub fn firewall(&self) -> Vec<AppFirewallRule> {
        self.snapshot().firewall
    }

    // --------------------------------------------------------------- loading

    fn load(&self) -> StateSnapshot {
        let stored_protection: Option<ProtectionState> = read_json(&self.store, KEY_PROTECTION);
        let stored_firewall: Option<Vec<AppFirewallRule>> = read_json(&self.store, KEY_FIREWALL);
        let stored_dns: Option<DnsState> = read_json(&self.store, KEY_DNS);
        let stored_filters: Option<FilterState> = read_json(&self.store, KEY_FILTERS);
        let stored_scripts: Option<ScriptState> = read_json(&self.store, KEY_SCRIPTS);

        let mut snapshot = StateSnapshot {
            protection: stored_protection.clone().unwrap_or_default().sanitized(),
            firewall: stored_firewall.clone().unwrap_or_default(),
            dns: DnsState::merged(stored_dns.clone().unwrap_or_default()),
            filters: stored_filters.clone().unwrap_or_default(),
            scripts: stored_scripts.clone().unwrap_or_default(),
        };

        if self.store.meta_get(META_LEGACY_IMPORTED).is_none() {
            self.import_legacy(
                &mut snapshot,
                [
                    stored_protection.is_none(),
                    stored_firewall.is_none(),
                    stored_dns.is_none(),
                    stored_filters.is_none(),
                    stored_scripts.is_none(),
                ],
            );
        }
        self.migrate_firewall(&snapshot.firewall);
        snapshot
    }

    /// Rewrites a pre-v2 firewall row in the tri-state shape once. The
    /// in-memory rules are already mapped by the deserializer, so this only
    /// makes the stored form match; a failed write leaves the marker unset and
    /// is retried on the next launch.
    fn migrate_firewall(&self, firewall: &[AppFirewallRule]) {
        if self.store.meta_get(META_FIREWALL_SCHEMA).as_deref() == Some(FIREWALL_SCHEMA_VERSION) {
            return;
        }
        if !firewall.is_empty() && !write_row(&self.store, KEY_FIREWALL, &firewall) {
            return;
        }
        if let Err(e) = self.store.meta_set(META_FIREWALL_SCHEMA, FIREWALL_SCHEMA_VERSION) {
            crate::logbuf::push_error(&format!("state: firewall schema marker not written: {e}"));
        }
    }

    /// Folds the pre-v4 blobs into the typed state once. A collection that
    /// already has a typed row keeps it, so a partial import (e.g. the app
    /// wrote filters before the upgrade finished) can never be overwritten.
    fn import_legacy(&self, snapshot: &mut StateSnapshot, missing: [bool; 5]) {
        let settings = self
            .store
            .settings_get()
            .map(|raw| legacy::settings_from_str(&raw));
        let filters = self
            .store
            .filters_get()
            .map(|raw| legacy::filters_from_str(&raw));

        let (legacy_protection, legacy_firewall, legacy_dns) = match settings {
            Some(part) => (Some(part.protection), Some(part.firewall), Some(part.dns)),
            None => (None, None, None),
        };
        let (legacy_filters, legacy_scripts) = match filters {
            Some(part) => (Some(part.filters), Some(part.scripts)),
            None => (None, None),
        };

        let mut rows: Vec<(String, String)> = Vec::new();
        if missing[0] {
            let value = legacy_protection.unwrap_or_default().sanitized();
            snapshot.protection = value.clone();
            push_row(&mut rows, KEY_PROTECTION, &value);
        }
        if missing[1] {
            let value = sanitize_firewall(legacy_firewall.unwrap_or_default());
            snapshot.firewall = value.clone();
            push_row(&mut rows, KEY_FIREWALL, &value);
        }
        if missing[2] {
            let value = DnsState::merged(legacy_dns.unwrap_or_default());
            snapshot.dns = value.clone();
            push_row(&mut rows, KEY_DNS, &value.stored());
        }
        if missing[3] {
            let value = legacy_filters.unwrap_or_default();
            snapshot.filters = value.clone();
            push_row(&mut rows, KEY_FILTERS, &value);
        }
        if missing[4] {
            let value = legacy_scripts.unwrap_or_default();
            snapshot.scripts = value.clone();
            push_row(&mut rows, KEY_SCRIPTS, &value);
        }

        if rows.is_empty() {
            // Nothing to import: still mark so the (possibly absent) blobs are
            // not re-read on every launch.
            self.mark_imported();
            return;
        }
        match self.store.state_put_all(&rows) {
            Ok(()) => self.mark_imported(),
            Err(e) => crate::logbuf::push_error(&format!(
                "state: legacy import not persisted, will retry: {e}"
            )),
        }
    }

    fn mark_imported(&self) {
        if let Err(e) = self.store.meta_set(META_LEGACY_IMPORTED, "1") {
            crate::logbuf::push_error(&format!("state: migration marker not written: {e}"));
        }
    }

    // ---------------------------------------------------------------- saving

    pub fn save_protection(&self, value: ProtectionState) -> bool {
        let value = value.sanitized();
        if !write_row(&self.store, KEY_PROTECTION, &value) {
            return false;
        }
        self.mutate(|s| s.protection = value);
        true
    }

    pub fn save_firewall(&self, value: Vec<AppFirewallRule>) -> bool {
        let value = sanitize_firewall(value);
        if !write_row(&self.store, KEY_FIREWALL, &value) {
            return false;
        }
        self.mutate(|s| s.firewall = value);
        true
    }

    pub fn save_dns(&self, value: DnsState) -> bool {
        let stored = value.stored();
        let merged = DnsState::merged(stored.clone());
        if !write_row(&self.store, KEY_DNS, &stored) {
            return false;
        }
        self.mutate(|s| s.dns = merged);
        true
    }

    pub fn save_filters(&self, mut value: FilterState) -> bool {
        // Saving is a user action: from now on the user's choices win over
        // the catalogue defaults, even when the list came back empty.
        value.catalog_configured = true;
        value.user_rules_configured = true;
        value.enabled_catalog_ids = dedupe(value.enabled_catalog_ids);
        value.trusted_ids = dedupe(value.trusted_ids);
        value.custom.retain(|f| !f.id.trim().is_empty());
        value.dns_filters.retain(|f| !f.id.trim().is_empty());
        if !write_row(&self.store, KEY_FILTERS, &value) {
            return false;
        }
        self.mutate(|s| s.filters = value);
        true
    }

    pub fn save_scripts(&self, mut value: ScriptState) -> bool {
        value.scripts.retain(|s| !s.id.trim().is_empty());
        if !write_row(&self.store, KEY_SCRIPTS, &value) {
            return false;
        }
        self.mutate(|s| s.scripts = value);
        true
    }

    /// Replaces every collection at once (backup restore). The write is one
    /// transaction, so a failure leaves the previous state in place.
    pub fn replace_all(&self, snapshot: StateSnapshot) -> bool {
        let snapshot = StateSnapshot {
            protection: snapshot.protection.sanitized(),
            firewall: sanitize_firewall(snapshot.firewall),
            dns: DnsState::merged(snapshot.dns.stored()),
            filters: snapshot.filters,
            scripts: snapshot.scripts,
        };
        let rows = vec![
            (
                KEY_PROTECTION.to_string(),
                match encode(&snapshot.protection) {
                    Some(v) => v,
                    None => return false,
                },
            ),
            (
                KEY_FIREWALL.to_string(),
                match encode(&snapshot.firewall) {
                    Some(v) => v,
                    None => return false,
                },
            ),
            (
                KEY_DNS.to_string(),
                match encode(&snapshot.dns.stored()) {
                    Some(v) => v,
                    None => return false,
                },
            ),
            (
                KEY_FILTERS.to_string(),
                match encode(&snapshot.filters) {
                    Some(v) => v,
                    None => return false,
                },
            ),
            (
                KEY_SCRIPTS.to_string(),
                match encode(&snapshot.scripts) {
                    Some(v) => v,
                    None => return false,
                },
            ),
        ];
        if let Err(e) = self.store.state_replace_all(&rows) {
            crate::logbuf::push_error(&format!("state: restore write failed: {e}"));
            return false;
        }
        *self.snapshot.write().unwrap_or_else(|e| e.into_inner()) = snapshot;
        true
    }

    fn mutate(&self, apply: impl FnOnce(&mut StateSnapshot)) {
        let mut guard = self.snapshot.write().unwrap_or_else(|e| e.into_inner());
        apply(&mut guard);
    }
}

fn sanitize_firewall(rules: Vec<AppFirewallRule>) -> Vec<AppFirewallRule> {
    let mut seen = std::collections::HashSet::new();
    rules
        .into_iter()
        .filter_map(|mut rule| {
            rule.package_name = rule.package_name.trim().to_string();
            if rule.package_name.is_empty() || !seen.insert(rule.package_name.clone()) {
                return None;
            }
            Some(rule)
        })
        .collect()
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    values
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && seen.insert(v.clone()))
        .collect()
}

fn read_json<T: DeserializeOwned>(store: &Store, key: &str) -> Option<T> {
    let raw = store.state_get(key)?;
    match serde_json::from_str(&raw) {
        Ok(value) => Some(value),
        Err(e) => {
            crate::logbuf::push_error(&format!("state: {key} unreadable, using defaults: {e}"));
            None
        }
    }
}

fn encode<T: Serialize>(value: &T) -> Option<String> {
    match serde_json::to_string(value) {
        Ok(json) => Some(json),
        Err(e) => {
            crate::logbuf::push_error(&format!("state: serialize failed: {e}"));
            None
        }
    }
}

fn push_row<T: Serialize>(rows: &mut Vec<(String, String)>, key: &str, value: &T) {
    if let Some(json) = encode(value) {
        rows.push((key.to_string(), json));
    }
}

fn write_row<T: Serialize>(store: &Store, key: &str, value: &T) -> bool {
    let Some(json) = encode(value) else {
        return false;
    };
    match store.state_set(key, &json) {
        Ok(()) => true,
        Err(e) => {
            crate::logbuf::push_error(&format!("state: {key} not saved: {e}"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::path::PathBuf;

    fn temp(tag: &str) -> (Arc<Store>, PathBuf) {
        let dir = std::env::temp_dir().join(format!("adfree-state-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::open(&dir).expect("store opens"));
        (store, dir)
    }

    /// Warn is what the ring buffered before levels existed, so neither a fresh
    /// install nor an older blob changes what lands in an exported log.
    #[test]
    fn the_shipped_log_level_is_the_pre_level_behaviour() {
        assert_eq!(ProtectionState::default().log_level, LogLevel::Warn);
        assert_eq!(LogLevel::Warn.code(), crate::logbuf::WARN);
        assert_eq!(LogLevel::Off.code(), crate::logbuf::OFF);
        assert_eq!(LogLevel::Error.code(), crate::logbuf::ERROR);
        assert_eq!(LogLevel::Debug.code(), crate::logbuf::DEBUG);
        let restored: ProtectionState = serde_json::from_str("{}").expect("empty blob loads");
        assert_eq!(restored.log_level, LogLevel::Warn);
    }

    /// The listener ports are only usable if a listener can take them without
    /// root, and never the same number twice: one port cannot serve both the
    /// proxy and the DNS server, and a stack that binds only one of them
    /// sends every lookup into a void.
    #[test]
    fn the_listener_ports_are_put_where_a_listener_can_take_them() {
        let below_range = ProtectionState {
            local_proxy: LocalProxyState {
                tcp_port: 80,
                dns_port: 53,
                ..Default::default()
            },
            ..Default::default()
        }
        .sanitized();
        assert_eq!(below_range.local_proxy.tcp_port, crate::proxy::DEFAULT_TCP_PORT);
        assert_eq!(below_range.local_proxy.dns_port, crate::proxy::DEFAULT_DNS_PORT);

        let tied = ProtectionState {
            local_proxy: LocalProxyState {
                tcp_port: crate::proxy::DEFAULT_DNS_PORT,
                dns_port: crate::proxy::DEFAULT_DNS_PORT,
                ..Default::default()
            },
            ..Default::default()
        }
        .sanitized();
        assert_eq!(tied.local_proxy.tcp_port, crate::proxy::DEFAULT_DNS_PORT);
        assert_ne!(
            tied.local_proxy.tcp_port, tied.local_proxy.dns_port,
            "the DNS port has to move off the port the TCP listener kept"
        );
        assert_eq!(tied.local_proxy.dns_port, crate::proxy::DEFAULT_DNS_PORT + 1);
    }

    /// An older blob names no listener ports at all: it must load with the
    /// shipped pair rather than fail to parse, or every existing install
    /// would lose its protection settings over a field it never wrote.
    #[test]
    fn a_blob_from_before_listener_ports_still_loads() {
        let old: ProtectionState =
            serde_json::from_str(r#"{"is_protection_active": true}"#).expect("old blob loads");
        assert!(old.is_protection_active);
        assert_eq!(old.local_proxy, LocalProxyState::default());
        assert_eq!(old.local_proxy.tcp_port, crate::proxy::DEFAULT_TCP_PORT);
    }

    /// The loopback switch is remembered like the ports: an install that
    /// never wrote it filters localhost (the shipped default, and the choice
    /// its redirect rules were always installed with), and a deliberate
    /// choice not to survives the save that carries it.
    #[test]
    fn the_loopback_switch_defaults_on_and_keeps_a_deliberate_off() {
        let untouched: ProtectionState =
            serde_json::from_str("{}").expect("empty blob loads");
        assert!(untouched.local_proxy.filter_localhost);

        let ports_only: ProtectionState = serde_json::from_str(
            r#"{"local_proxy":{"tcp_port":3131,"dns_port":5353}}"#,
        )
        .expect("a blob with ports but no switch loads");
        assert!(ports_only.local_proxy.filter_localhost, "a pre-switch install still filters localhost");
        assert_eq!(ports_only.local_proxy.tcp_port, 3131);

        let off = ProtectionState {
            local_proxy: LocalProxyState {
                filter_localhost: false,
                ..Default::default()
            },
            ..Default::default()
        }
        .sanitized();
        assert!(!off.local_proxy.filter_localhost, "sanitizing ports must not touch the switch");
    }

    #[test]
    fn a_fresh_store_gets_defaults_with_the_builtin_providers() {
        let (store, dir) = temp("defaults");
        let state = StateStore::open(store);
        let snapshot = state.snapshot();
        assert!(!snapshot.protection.is_protection_active);
        assert_eq!(
            snapshot.protection.selected_dns_provider_id,
            "adguard_default"
        );
        assert!(snapshot
            .dns
            .provider("adguard_default")
            .is_some_and(|p| !p.is_custom));
        assert!(snapshot.scripts.master);
        // The import ran and marked itself even though there was nothing old.
        let _ = state;
        drop(dir);
    }

    #[test]
    fn legacy_blobs_are_imported_once_and_the_archive_stays() {
        let (store, dir) = temp("legacy");
        store
            .settings_set(
                r#"{"protection":true,"adBlocking":false,"https":true,
                    "dnsProvider":"custom_1",
                    "custom_dns_providers":[
                      {"id":"custom_1","name":"Mine","address":"9.9.9.9:5353","type":"DNS_UDP"}
                    ],
                    "app_firewall":[{"package":"com.example","cellular":false}]}"#,
            )
            .unwrap();
        store
            .filters_set(
                r#"{"enabled_catalog_ids":["ag-base"],
                    "custom_filters":[{"id":"c1","name":"C1","url":"https://x"}],
                    "user_rules":["||ads.test^"],
                    "userscripts":[{"id":"s1","name":"S1","url":"https://s"}],
                    "userscripts_master":false}"#,
            )
            .unwrap();

        let state = StateStore::open(Arc::clone(&store));
        let snapshot = state.snapshot();
        assert!(snapshot.protection.is_protection_active);
        assert!(!snapshot.protection.is_ad_blocking_enabled);
        assert!(snapshot.protection.is_https_filtering_enabled);
        assert_eq!(snapshot.protection.selected_dns_provider_id, "custom_1");
        let custom = snapshot.dns.provider("custom_1").expect("custom kept");
        assert_eq!(custom.port, 5353);
        assert!(custom.is_custom);
        // Built-ins still come from code.
        assert!(snapshot.dns.provider("cloudflare").is_some());
        assert_eq!(snapshot.firewall.len(), 1);
        assert_eq!(snapshot.firewall[0].cellular, FirewallAccess::Block);
        assert!(snapshot.filters.catalog_configured);
        assert_eq!(snapshot.filters.enabled_catalog_ids, vec!["ag-base"]);
        assert_eq!(snapshot.filters.user_rules, vec!["||ads.test^"]);
        assert!(!snapshot.scripts.master);
        assert_eq!(snapshot.scripts.scripts.len(), 1);

        // Simulate a later user edit in the new layout: the import must not
        // run again and overwrite it on the next open.
        let mut edited = snapshot.protection.clone();
        edited.is_ad_blocking_enabled = true;
        assert!(state.save_protection(edited));
        drop(state);

        let reopened = StateStore::open(store);
        assert!(reopened.snapshot().protection.is_ad_blocking_enabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_v1_firewall_row_is_migrated_to_tri_state_once() {
        let (store, dir) = temp("firewall-schema");
        // Mark the legacy import done so only the firewall migration runs.
        store.meta_set(META_LEGACY_IMPORTED, "1").unwrap();
        store
            .state_set(
                KEY_FIREWALL,
                r#"[
                    {"package_name":"com.example","cellular":false,"wifi":true,
                     "filtered":true,"screen_off":true,"https":true},
                    {"package_name":"com.other","cellular":true,"wifi":true,
                     "filtered":true,"screen_off":false,"https":false}
                ]"#,
            )
            .unwrap();

        let state = StateStore::open(Arc::clone(&store));
        let snapshot = state.snapshot();
        let example = &snapshot.firewall[0];
        assert_eq!(example.cellular, FirewallAccess::Block);
        assert_eq!(example.wifi, FirewallAccess::Inherit);
        assert_eq!(example.wifi_screen_off, FirewallAccess::Block);
        assert_eq!(example.cellular_screen_off, FirewallAccess::Block);
        assert_eq!(example.roaming, FirewallAccess::Inherit);
        assert!(example.notify);
        let other = &snapshot.firewall[1];
        assert_eq!(other.wifi_screen_off, FirewallAccess::Inherit);
        assert!(!other.https);

        // The stored row now uses the schema-2 shape, under the same key, so
        // an older build would still find its rows (with the tri-state words).
        assert_eq!(
            store.meta_get(META_FIREWALL_SCHEMA).as_deref(),
            Some(FIREWALL_SCHEMA_VERSION)
        );
        let raw = store.state_get(KEY_FIREWALL).expect("row kept");
        assert!(raw.contains("\"wifi_screen_off\""), "new dimensions written");
        assert!(raw.contains("\"block\""));
        assert!(!raw.contains("\"screen_off\""), "legacy key retired");

        // Reopening is a no-op: the marker prevents a second rewrite.
        drop(state);
        let reopened = StateStore::open(store);
        assert_eq!(
            reopened.snapshot().firewall[0].wifi_screen_off,
            FirewallAccess::Block
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_a_collection_only_touches_that_row() {
        let (store, dir) = temp("save-one");
        let state = StateStore::open(store);
        let mut protection = state.snapshot().protection;
        protection.theme_mode = ThemeMode::Light;
        assert!(state.save_protection(protection));

        let mut rules = state.snapshot().firewall;
        rules.push(AppFirewallRule {
            package_name: " com.example ".to_string(),
            ..AppFirewallRule::default()
        });
        assert!(state.save_firewall(rules));
        assert_eq!(state.snapshot().firewall[0].package_name, "com.example");

        let mut filters = state.snapshot().filters;
        filters.enabled_catalog_ids = vec!["a".to_string(), "a".to_string()];
        assert!(state.save_filters(filters));
        assert_eq!(state.snapshot().filters.enabled_catalog_ids, vec!["a"]);
        assert!(state.snapshot().filters.catalog_configured);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dns_filters_persist_apart_from_the_custom_lists() {
        let (store, dir) = temp("dns-filters");
        let state = StateStore::open(store);
        let mut filters = state.snapshot().filters;
        filters.custom.push(FilterChoice {
            id: "sub_1".to_string(),
            ..FilterChoice::default()
        });
        filters.dns_filters.push(FilterChoice {
            id: "dns_1".to_string(),
            name: "Hosts".to_string(),
            url: "https://example.test/hosts".to_string(),
            format: "hosts".to_string(),
            enabled: true,
            trusted: false,
            ..FilterChoice::default()
        });
        filters.dns_filters.push(FilterChoice::default());
        assert!(state.save_filters(filters));

        let saved = state.snapshot().filters;
        assert_eq!(saved.custom.len(), 1, "a DNS filter is not a custom web list");
        assert_eq!(saved.dns_filters.len(), 1, "a blank id never persists");
        assert_eq!(saved.dns_filters[0].name, "Hosts");
        assert_eq!(saved.dns_filters[0].format, "hosts");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_collection_falls_back_to_defaults_without_losing_the_rest() {
        let (store, dir) = temp("corrupt");
        store.state_set(KEY_PROTECTION, "{not json").unwrap();
        store
            .state_set(
                KEY_FILTERS,
                r#"{"catalog_configured":true,"enabled_catalog_ids":["x"]}"#,
            )
            .unwrap();
        let state = StateStore::open(store);
        let snapshot = state.snapshot();
        assert!(!snapshot.protection.is_protection_active);
        assert_eq!(snapshot.filters.enabled_catalog_ids, vec!["x"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn replace_all_is_the_only_way_a_backup_clears_a_list() {
        let (store, dir) = temp("replace-all");
        let state = StateStore::open(store);
        let mut filters = state.snapshot().filters;
        filters.enabled_catalog_ids = vec!["a".to_string()];
        assert!(state.save_filters(filters));

        let mut empty = state.snapshot();
        empty.filters = FilterState::default();
        empty.scripts = ScriptState::default();
        assert!(state.replace_all(empty));
        assert!(state.snapshot().filters.enabled_catalog_ids.is_empty());
        assert!(state.snapshot().scripts.master);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
