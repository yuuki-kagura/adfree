//! Backup export/import.
//!
//! v2 carries the whole typed state in one envelope. v1 (the format older
//! builds wrote) carried the same two platform blobs the legacy importer reads,
//! so its decoder is reused; v1 never contained userscripts, so restoring one
//! keeps the script rows that are already on the device.

use serde::Serialize;
use serde_json::Value;

use super::legacy;
use super::model::{BackupError, BackupOutcome, DnsState, StateSnapshot};
use super::StateStore;

const FORMAT: &str = "adfree-backup";
const VERSION: u32 = 2;

#[derive(Serialize)]
struct Envelope<'a> {
    format: &'static str,
    version: u32,
    #[serde(rename = "exportedAtMs")]
    exported_at_ms: u64,
    state: &'a StateSnapshot,
}

pub fn export(snapshot: &StateSnapshot) -> String {
    let envelope = Envelope {
        format: FORMAT,
        version: VERSION,
        exported_at_ms: crate::util::now_ms(),
        state: snapshot,
    };
    serde_json::to_string_pretty(&envelope).unwrap_or_default()
}

/// Replaces the whole state when the file is a valid backup. Anything that
/// does not parse leaves the current state untouched.
pub fn import(state: &StateStore, raw: &str) -> BackupOutcome {
    let fail = |error| BackupOutcome { ok: false, error };

    let root: Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(_) => return fail(BackupError::Malformed),
    };
    if root.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return fail(BackupError::NotBackup);
    }
    let Some(version) = root.get("version").and_then(Value::as_u64) else {
        return fail(BackupError::Malformed);
    };

    let snapshot = match version {
        1 => match from_v1(&root, &state.snapshot()) {
            Some(snapshot) => snapshot,
            None => return fail(BackupError::Malformed),
        },
        2 => {
            let Some(decoded) = root.get("state") else {
                return fail(BackupError::Malformed);
            };
            match serde_json::from_value::<StateSnapshot>(decoded.clone()) {
                Ok(snapshot) => snapshot,
                Err(e) => {
                    crate::logbuf::push(&format!("backup: state unreadable: {e}"));
                    return fail(BackupError::Malformed);
                }
            }
        }
        _ => return fail(BackupError::UnsupportedVersion),
    };

    if !state.replace_all(snapshot) {
        return fail(BackupError::StoreUnavailable);
    }
    BackupOutcome {
        ok: true,
        error: BackupError::None,
    }
}

/// v1: `settings` (optional) and `filters` (required) hold the old blobs.
fn from_v1(root: &Value, current: &StateSnapshot) -> Option<StateSnapshot> {
    let filters_value = root.get("filters")?.clone();
    if !filters_value.is_object() {
        return None;
    }
    let settings = root
        .get("settings")
        .filter(|v| v.is_object())
        .map(legacy::settings_from_value)
        .unwrap_or_default();
    let filters = legacy::filters_from_value(&filters_value);
    let carries_scripts = filters_value.get("userscripts").is_some();
    Some(StateSnapshot {
        protection: settings.protection,
        firewall: settings.firewall,
        dns: DnsState::merged(settings.dns),
        filters: filters.filters,
        scripts: if carries_scripts {
            filters.scripts
        } else {
            current.scripts.clone()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::sync::Arc;

    fn temp(tag: &str) -> (Arc<Store>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("adfree-backup-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Arc::new(Store::open(&dir).expect("store opens"));
        (store, dir)
    }

    #[test]
    fn v2_round_trip_carries_every_collection() {
        let (store, dir) = temp("roundtrip");
        let state = StateStore::open(store);
        let mut snapshot = state.snapshot();
        snapshot.protection.theme_mode = crate::state::model::ThemeMode::Light;
        snapshot.protection.app_language = crate::state::model::AppLanguage::Vietnamese;
        snapshot.protection.proxy.enabled = true;
        snapshot
            .firewall
            .push(crate::state::model::AppFirewallRule {
                package_name: "com.example".to_string(),
                cellular: crate::state::model::FirewallAccess::Block,
                ..crate::state::model::AppFirewallRule::default()
            });
        snapshot.filters.enabled_catalog_ids = vec!["ag-base".to_string()];
        snapshot.filters.user_rules = vec!["||ads.test^".to_string()];
        snapshot.scripts.master = false;
        snapshot
            .scripts
            .scripts
            .push(crate::state::model::ScriptRecord {
                id: "s1".to_string(),
                name: "S1".to_string(),
                url: "https://s".to_string(),
                enabled: true,
                ..crate::state::model::ScriptRecord::default()
            });
        assert!(state.replace_all(snapshot.clone()));

        let exported = export(&state.snapshot());
        assert!(exported.contains("\"version\": 2"));

        // Wipe everything the way a user would, then restore.
        let mut empty = state.snapshot();
        empty.firewall.clear();
        empty.filters = crate::state::model::FilterState::default();
        empty.scripts = crate::state::model::ScriptState::default();
        assert!(state.replace_all(empty));

        let outcome = import(&state, &exported);
        assert!(outcome.ok);
        let restored = state.snapshot();
        assert_eq!(
            restored.protection.theme_mode,
            snapshot.protection.theme_mode
        );
        assert_eq!(
            restored.protection.app_language,
            snapshot.protection.app_language
        );
        assert!(restored.protection.proxy.enabled);
        assert_eq!(restored.firewall.len(), 1);
        assert_eq!(restored.filters.enabled_catalog_ids, vec!["ag-base"]);
        assert_eq!(restored.filters.user_rules, vec!["||ads.test^"]);
        assert!(!restored.scripts.master);
        assert_eq!(restored.scripts.scripts.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn v1_restore_keeps_the_scripts_already_on_the_device() {
        let (store, dir) = temp("v1");
        let state = StateStore::open(store);
        let mut current = state.snapshot();
        current.scripts.master = false;
        current
            .scripts
            .scripts
            .push(crate::state::model::ScriptRecord {
                id: "keep".to_string(),
                name: "Keep".to_string(),
                ..crate::state::model::ScriptRecord::default()
            });
        assert!(state.save_scripts(current.scripts.clone()));

        let v1 = r#"{
            "format": "adfree-backup",
            "version": 1,
            "exportedAtMs": 1,
            "settings": {"protection": true, "blockDoh": false},
            "filters": {
                "enabled_catalog_ids": ["ag-base"],
                "custom_filters": [],
                "user_rules": []
            }
        }"#;
        let outcome = import(&state, v1);
        assert!(outcome.ok, "{outcome:?}");
        let restored = state.snapshot();
        assert!(restored.protection.is_protection_active);
        assert!(!restored.protection.block_doh);
        assert_eq!(restored.filters.enabled_catalog_ids, vec!["ag-base"]);
        assert!(restored.filters.user_rules.is_empty());
        assert!(!restored.scripts.master);
        assert_eq!(restored.scripts.scripts[0].id, "keep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_or_foreign_files_change_nothing() {
        let (store, dir) = temp("malformed");
        let state = StateStore::open(store);
        let mut before = state.snapshot();
        before.protection.is_protection_active = true;
        assert!(state.save_protection(before.protection.clone()));

        for raw in [
            "not json",
            r#"{"format":"other","version":2,"state":{}}"#,
            r#"{"format":"adfree-backup","version":9,"state":{}}"#,
            r#"{"format":"adfree-backup","version":2}"#,
            r#"{"format":"adfree-backup","version":2,"state":{"protection":3}}"#,
            r#"{"format":"adfree-backup","version":1,"filters":[1,2]}"#,
        ] {
            let outcome = import(&state, raw);
            assert!(!outcome.ok, "accepted {raw}");
            assert!(state.snapshot().protection.is_protection_active);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
