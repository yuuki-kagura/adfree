//! One-time import of the JSON blobs older builds wrote.
//!
//! The schema is the Kotlin one (`SettingsPreferences` / `FilterPreferences`),
//! kept byte-compatible so an upgrade never loses a switch, a firewall rule, a
//! custom resolver, a filter choice or a userscript row. The same decoders also
//! read a v1 backup file, which carried exactly those two blobs.
//!
//! Every field is optional: a key that was never written falls back to the new
//! Rust default. Unknown keys are ignored.

use serde::Deserialize;
use serde_json::Value;

use super::dnsaddr;
use super::model::{
    AppFirewallRule, DnsBlockMode, DnsProtocol, DnsState, FilterChoice, FilterState,
    ProtectionState, ProxyState, ScriptRecord, ScriptState,
};

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct LegacySettings {
    protection: Option<bool>,
    ad_blocking: Option<bool>,
    tracking: Option<bool>,
    dns: Option<bool>,
    smart_filtering: Option<bool>,
    https: Option<bool>,
    full_ech: Option<bool>,
    firewall: Option<bool>,
    eco: Option<bool>,
    stealth: Option<bool>,
    block_quic: Option<bool>,
    block_doh: Option<bool>,
    block_dot: Option<bool>,
    filter_auto_update_hours: Option<u32>,
    log_allowed: Option<bool>,
    block_mode: Option<String>,
    strip_utm: Option<bool>,
    block_web_rtc: Option<bool>,
    disguise_ua: Option<bool>,
    block_cookies: Option<bool>,
    dns_provider: Option<String>,
    https_skip_hosts: Option<Vec<String>>,
    https_only_hosts: Option<Vec<String>>,
    https_only_mode: Option<bool>,
    proxy_enabled: Option<bool>,
    proxy_host: Option<String>,
    proxy_port: Option<u16>,
    proxy_username: Option<String>,
    proxy_password: Option<String>,
    #[serde(rename = "app_firewall")]
    app_firewall: Option<Vec<LegacyFirewall>>,
    #[serde(rename = "custom_dns_providers")]
    custom_dns_providers: Option<Vec<LegacyProvider>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct LegacyFirewall {
    package: Option<String>,
    cellular: Option<bool>,
    wifi: Option<bool>,
    filtered: Option<bool>,
    screen_off: Option<bool>,
    https: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct LegacyProvider {
    id: Option<String>,
    name: Option<String>,
    address: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LegacyFilters {
    enabled_catalog_ids: Option<Vec<String>>,
    custom_filters: Vec<LegacyFilter>,
    user_rules: Option<Vec<String>>,
    userscripts: Vec<LegacyScript>,
    userscripts_master: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LegacyFilter {
    id: Option<String>,
    name: Option<String>,
    url: Option<String>,
    format: Option<String>,
    enabled: Option<bool>,
    homepage: Option<String>,
    trusted: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LegacyScript {
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    url: Option<String>,
    enabled: Option<bool>,
}

#[derive(Default)]
pub struct LegacySettingsPart {
    pub protection: ProtectionState,
    pub firewall: Vec<AppFirewallRule>,
    pub dns: DnsState,
}

#[derive(Default)]
pub struct LegacyFiltersPart {
    pub filters: FilterState,
    pub scripts: ScriptState,
}

/// Reads the settings blob (SQLite row 1, or a v1 backup's `settings` object).
pub fn settings_from_str(raw: &str) -> LegacySettingsPart {
    match serde_json::from_str::<LegacySettings>(raw) {
        Ok(blob) => settings_from(blob),
        Err(e) => {
            crate::logbuf::push(&format!("state: legacy settings ignored: {e}"));
            LegacySettingsPart {
                protection: ProtectionState::default(),
                firewall: Vec::new(),
                dns: DnsState::default(),
            }
        }
    }
}

pub fn settings_from_value(value: &Value) -> LegacySettingsPart {
    match serde_json::from_value::<LegacySettings>(value.clone()) {
        Ok(blob) => settings_from(blob),
        Err(e) => {
            crate::logbuf::push(&format!("state: legacy settings ignored: {e}"));
            LegacySettingsPart::default()
        }
    }
}

/// Reads the filter/script blob (SQLite row 2, or a v1 backup's `filters`).
pub fn filters_from_str(raw: &str) -> LegacyFiltersPart {
    match serde_json::from_str::<LegacyFilters>(raw) {
        Ok(blob) => filters_from(blob),
        Err(e) => {
            crate::logbuf::push(&format!("state: legacy filters ignored: {e}"));
            LegacyFiltersPart::default()
        }
    }
}

pub fn filters_from_value(value: &Value) -> LegacyFiltersPart {
    match serde_json::from_value::<LegacyFilters>(value.clone()) {
        Ok(blob) => filters_from(blob),
        Err(e) => {
            crate::logbuf::push(&format!("state: legacy filters ignored: {e}"));
            LegacyFiltersPart::default()
        }
    }
}

fn settings_from(blob: LegacySettings) -> LegacySettingsPart {
    let defaults = ProtectionState::default();
    let mut p = defaults.clone();
    macro_rules! take {
        ($field:ident, $src:ident) => {
            if let Some(v) = blob.$src {
                p.$field = v;
            }
        };
    }
    take!(is_protection_active, protection);
    take!(is_ad_blocking_enabled, ad_blocking);
    take!(is_tracking_protection_enabled, tracking);
    take!(is_dns_protection_enabled, dns);
    take!(is_smart_filtering_enabled, smart_filtering);
    take!(is_https_filtering_enabled, https);
    take!(is_full_ech_enabled, full_ech);
    take!(is_firewall_enabled, firewall);
    take!(is_eco_battery_mode_enabled, eco);
    take!(block_quic, block_quic);
    take!(block_doh, block_doh);
    take!(log_allowed_requests, log_allowed);
    take!(strip_utm_tracking, strip_utm);
    take!(disguise_user_agent, disguise_ua);
    take!(block_third_party_cookies, block_cookies);
    take!(https_only_mode, https_only_mode);
    if let Some(v) = blob.filter_auto_update_hours {
        p.filter_auto_update_hours = v.min(168);
    }
    if let Some(v) = blob.https_skip_hosts {
        p.https_skip_hosts = v;
    }
    if let Some(v) = blob.https_only_hosts {
        p.https_only_hosts = v;
    }
    if let Some(v) = blob.dns_provider {
        if !v.is_empty() {
            p.selected_dns_provider_id = v;
        }
    }
    if let Some(v) = blob.block_mode {
        p.block_mode = parse_block_mode(&v).unwrap_or(p.block_mode);
    }
    // Older blobs had one DoH/DoT switch. A user who turned encrypted-DNS
    // blocking off must not get DoT blocked again after the upgrade.
    p.block_dot = blob
        .block_dot
        .or(blob.block_doh)
        .unwrap_or(defaults.block_dot);

    // The old stealth master controlled nothing. Carrying `true` forward
    // would suddenly drop STUN/TURN and rewrite cookies; keep the intent off
    // and let the user opt in from the new section. The sub-switches keep the
    // values the user saw.
    p.is_stealth_mode_enabled = false;
    p.block_web_rtc_leaks = false;
    let _ = blob.stealth;
    let _ = blob.block_web_rtc;

    p.proxy = ProxyState {
        enabled: blob.proxy_enabled.unwrap_or(defaults.proxy.enabled),
        automatic: defaults.proxy.automatic,
        host: blob.proxy_host.unwrap_or_default(),
        port: blob.proxy_port.unwrap_or(defaults.proxy.port),
        username: blob.proxy_username.unwrap_or_default(),
        password: blob.proxy_password.unwrap_or_default(),
    };

    let firewall = blob
        .app_firewall
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| {
            let package = f.package?.trim().to_string();
            if package.is_empty() {
                return None;
            }
            Some(AppFirewallRule {
                package_name: package,
                cellular: f.cellular.unwrap_or(true),
                wifi: f.wifi.unwrap_or(true),
                filtered: f.filtered.unwrap_or(true),
                screen_off: f.screen_off.unwrap_or(false),
                https: f.https.unwrap_or(true),
            })
        })
        .collect();

    let mut custom = Vec::new();
    for raw in blob.custom_dns_providers.unwrap_or_default() {
        let Some(id) = raw.id.filter(|s| !s.is_empty()) else {
            continue;
        };
        let protocol = parse_protocol(raw.kind.as_deref());
        let Some(address) = raw.address else { continue };
        let Ok((normalized, port)) = dnsaddr::normalize(protocol, &address) else {
            crate::logbuf::push(&format!(
                "state: legacy resolver {id} has an unusable address, dropped"
            ));
            continue;
        };
        custom.push(super::model::DnsProviderRecord {
            id,
            name: raw.name.unwrap_or_else(|| "DNS".to_string()),
            address: normalized,
            port,
            protocol,
            description: raw.description.unwrap_or_default(),
            description_key: String::new(),
            is_custom: true,
        });
    }

    LegacySettingsPart {
        protection: p.sanitized(),
        firewall,
        dns: DnsState {
            providers: custom,
            rewrites: Vec::new(),
        },
    }
}

fn filters_from(blob: LegacyFilters) -> LegacyFiltersPart {
    let catalog_configured = blob.enabled_catalog_ids.is_some();
    let custom = blob
        .custom_filters
        .into_iter()
        .filter_map(|f| {
            let id = f.id?.trim().to_string();
            if id.is_empty() {
                return None;
            }
            Some(FilterChoice {
                id,
                name: f.name.unwrap_or_default(),
                url: f.url.unwrap_or_default(),
                format: f
                    .format
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "standard".to_string()),
                homepage: f.homepage.unwrap_or_default(),
                enabled: f.enabled.unwrap_or(true),
                trusted: f.trusted.unwrap_or(false),
            })
        })
        .collect();
    let scripts = blob
        .userscripts
        .into_iter()
        .filter_map(|s| {
            let id = s.id?.trim().to_string();
            if id.is_empty() {
                return None;
            }
            Some(ScriptRecord {
                id,
                name: s.name.unwrap_or_default(),
                description: s.description.unwrap_or_default(),
                url: s.url.unwrap_or_default(),
                enabled: s.enabled.unwrap_or(false),
            })
        })
        .collect();
    LegacyFiltersPart {
        filters: FilterState {
            catalog_configured,
            enabled_catalog_ids: blob.enabled_catalog_ids.unwrap_or_default(),
            // Older blobs did not store the trusted bit.
            trusted_ids: Vec::new(),
            custom,
            user_rules_configured: blob.user_rules.is_some(),
            user_rules: blob.user_rules.unwrap_or_default(),
        },
        scripts: ScriptState {
            master: blob.userscripts_master.unwrap_or(true),
            scripts,
        },
    }
}

fn parse_block_mode(raw: &str) -> Option<DnsBlockMode> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "NXDOMAIN" | "NX_DOMAIN" => Some(DnsBlockMode::NxDomain),
        "ZERO_IP" | "ZEROIP" | "ZERO" => Some(DnsBlockMode::ZeroIp),
        "REFUSED" => Some(DnsBlockMode::Refused),
        _ => None,
    }
}

fn parse_protocol(raw: Option<&str>) -> DnsProtocol {
    match raw.unwrap_or("").trim().to_ascii_uppercase().as_str() {
        "DNS_DOH" | "DOH" | "HTTPS" => DnsProtocol::Doh,
        "DNS_DOT" | "DOT" | "TLS" => DnsProtocol::Dot,
        _ => DnsProtocol::Udp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_settings_keep_switches_and_unknown_keys_are_ignored() {
        let part = settings_from_str(
            r#"{
                "protection": true,
                "adBlocking": false,
                "https": true,
                "blockDoh": false,
                "blockMode": "ZERO_IP",
                "filterAutoUpdateHours": 999,
                "httpsSkipHosts": ["Bank.example", "bank.example", " "],
                "proxyEnabled": true,
                "proxyHost": "10.0.0.2",
                "proxyPort": 1080,
                "futureKey": 42
            }"#,
        );
        let p = part.protection;
        assert!(p.is_protection_active);
        assert!(!p.is_ad_blocking_enabled);
        assert!(p.is_https_filtering_enabled);
        assert!(!p.block_doh);
        assert!(!p.block_dot, "absent blockDot follows blockDoh");
        assert_eq!(p.block_mode, DnsBlockMode::ZeroIp);
        assert_eq!(p.filter_auto_update_hours, 168);
        assert_eq!(p.https_skip_hosts, vec!["bank.example"]);
        assert!(p.proxy.enabled);
        assert_eq!(p.proxy.port, 1080);
        assert!(!p.safe_search);
    }

    #[test]
    fn legacy_firewall_and_resolver_round_trip() {
        let part = settings_from_str(
            r#"{
                "app_firewall": [
                    {"package": "com.example", "cellular": false, "wifi": true,
                     "filtered": false, "screenOff": true, "https": false}
                ],
                "custom_dns_providers": [
                    {"id": "custom_1", "name": "Mine", "address": "9.9.9.9:5353",
                     "type": "DNS_UDP", "description": "test", "pingMs": 12}
                ]
            }"#,
        );
        assert_eq!(part.firewall.len(), 1);
        let fw = &part.firewall[0];
        assert_eq!(fw.package_name, "com.example");
        assert!(!fw.cellular);
        assert!(!fw.filtered);
        assert!(fw.screen_off);
        assert!(!fw.https);
        assert_eq!(part.dns.providers.len(), 1);
        assert_eq!(part.dns.providers[0].address, "9.9.9.9");
        assert_eq!(part.dns.providers[0].port, 5353);
        assert!(part.dns.providers[0].is_custom);
    }

    #[test]
    fn legacy_filters_keep_configured_flags() {
        let part = filters_from_str(
            r#"{
                "enabled_catalog_ids": ["ag-base"],
                "custom_filters": [
                    {"id": "c1", "name": "C1", "url": "https://x", "format": "hosts",
                     "enabled": false, "trusted": true}
                ],
                "user_rules": [],
                "userscripts": [{"id": "s1", "name": "S1", "url": "https://s"}],
                "userscripts_master": false
            }"#,
        );
        assert!(part.filters.catalog_configured);
        assert_eq!(part.filters.enabled_catalog_ids, vec!["ag-base"]);
        assert!(part.filters.user_rules_configured);
        assert_eq!(part.filters.custom[0].format, "hosts");
        assert!(!part.filters.custom[0].enabled);
        assert!(part.filters.custom[0].trusted);
        assert!(!part.scripts.master);
        assert_eq!(part.scripts.scripts.len(), 1);
    }

    #[test]
    fn absent_user_rules_stay_unconfigured() {
        let part = filters_from_str("{}");
        assert!(!part.filters.user_rules_configured);
        assert!(part.filters.user_rules.is_empty());
        assert!(part.scripts.master, "master defaults ON");
    }
}
