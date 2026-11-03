//! The persisted state, in both directions: serde for SQLite and uniffi for
//! Kotlin. The two derive sets live on the same records so a field cannot be
//! stored without being visible, or visible without being stored.
//!
//! Field names are the contract: uniffi turns `is_ad_blocking_enabled` into
//! `isAdBlockingEnabled` on the Kotlin side, which is the name the UI already
//! uses. Defaults live here and nowhere else.

use serde::{Deserialize, Serialize};

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsBlockMode {
    #[default]
    NxDomain,
    ZeroIp,
    Refused,
}

impl DnsBlockMode {
    /// Encoding the engine's `BlockMode` uses (0 = NXDOMAIN, 1 = 0.0.0.0,
    /// 2 = REFUSED).
    pub fn code(self) -> u8 {
        match self {
            DnsBlockMode::NxDomain => 0,
            DnsBlockMode::ZeroIp => 1,
            DnsBlockMode::Refused => 2,
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsProtocol {
    #[default]
    Udp,
    Dot,
    Doh,
}

impl DnsProtocol {
    pub fn default_port(self) -> u16 {
        match self {
            DnsProtocol::Udp => 53,
            DnsProtocol::Dot => 853,
            DnsProtocol::Doh => 443,
        }
    }
}

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppLanguage {
    #[default]
    System,
    English,
    Vietnamese,
}

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeMode {
    #[default]
    System,
    Dark,
    Light,
}

/// How much of the core's own diagnostics the ring keeps for Android to forward
/// to logcat. `Warn` - failures plus the lines that explain a fallback - is what
/// every install has always buffered, and it is the default for that reason.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Off,
    Error,
    #[default]
    Warn,
    Debug,
}

impl LogLevel {
    /// The severity number [`crate::logbuf`] compares a line against.
    pub fn code(self) -> u8 {
        match self {
            LogLevel::Off => crate::logbuf::OFF,
            LogLevel::Error => crate::logbuf::ERROR,
            LogLevel::Warn => crate::logbuf::WARN,
            LogLevel::Debug => crate::logbuf::DEBUG,
        }
    }
}

/// A SOCKS5 endpoint. `host` must be an IPv4/IPv6 literal: the packet loop
/// cannot resolve a name without stalling.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyState {
    pub enabled: bool,
    /// Automatic routing: only internet destinations use the proxy; LAN,
    /// loopback and other non-routable addresses stay direct.
    #[serde(default = "proxy_automatic_default")]
    pub automatic: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

fn proxy_automatic_default() -> bool {
    true
}

impl Default for ProxyState {
    fn default() -> Self {
        ProxyState {
            enabled: false,
            automatic: true,
            host: String::new(),
            port: 1080,
            username: String::new(),
            password: String::new(),
        }
    }
}

/// Everything the switches screen edits.
///
/// This mirrors the UI model one-to-one; `Default` is the only definition of
/// what a fresh install (or a missing blob) uses.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtectionState {
    pub is_protection_active: bool,
    pub is_ad_blocking_enabled: bool,
    pub is_annoyances_enabled: bool,
    pub is_browsing_security_enabled: bool,
    pub is_tracking_protection_enabled: bool,
    pub is_dns_protection_enabled: bool,
    /// Spare one app that keeps retrying a host the lists refuse (see
    /// [`crate::smart`]). Opt-in: the cooldown lets a blocked host connect.
    pub is_smart_filtering_enabled: bool,
    pub is_https_filtering_enabled: bool,
    /// Terminate and filter QUIC (HTTP/3) instead of dropping it. Needs HTTPS
    /// filtering, because the same certificate and decision layer are used.
    pub filter_http3: bool,
    /// AdGuard's "Block ECH", off by default: strip the `ech` SvcParam from
    /// DNS answers so those hosts stay decryptable. With it off an ECH
    /// connection is spliced and left unfiltered instead of failing.
    pub is_ech_blocking_enabled: bool,
    pub is_firewall_enabled: bool,
    /// Global rules and per-app overrides each have their own gate. Both
    /// default on; a disabled set contributes no restriction.
    pub firewall_global_rules: bool,
    pub firewall_custom_rules: bool,
    /// Notification master for firewall blocks.
    pub firewall_notifications: bool,
    /// Default access for any app that inherits a dimension. `true` allows.
    pub firewall_allow_wifi: bool,
    pub firewall_allow_wifi_screen_off: bool,
    pub firewall_allow_cellular: bool,
    pub firewall_allow_cellular_screen_off: bool,
    pub firewall_allow_roaming: bool,
    pub is_eco_battery_mode_enabled: bool,
    pub is_stealth_mode_enabled: bool,
    pub block_quic: bool,
    pub block_doh: bool,
    pub block_dot: bool,
    pub filter_auto_update_hours: u32,
    pub log_allowed_requests: bool,
    pub block_mode: DnsBlockMode,
    pub strip_utm_tracking: bool,
    pub block_web_rtc_leaks: bool,
    pub disguise_user_agent: bool,
    pub block_third_party_cookies: bool,
    /// Every cookie, the site's own included: the visitor is forgotten between
    /// requests, so a login has to be typed again.
    pub block_all_cookies: bool,
    /// `ETag` in and `If-None-Match`/`If-Match` out.
    pub strip_etag: bool,
    pub strip_third_party_authorization: bool,
    pub hide_third_party_referer: bool,
    /// `Sec-GPC: 1` and `DNT: 1` on every request.
    pub inject_gpc_dnt: bool,
    pub hide_search_query: bool,
    pub block_push_api: bool,
    pub block_geolocation_api: bool,
    /// Split the TLS ClientHello across segments so a device that reads the
    /// server name out of the first packet cannot. AdGuard's `Anti-DPI`.
    pub anti_dpi: bool,
    /// The address a site is told the request came through, as the user typed
    /// it. Empty or unparseable means no header is added. AdGuard's `Mask IP
    /// address`; a string rather than an address because the field is what the
    /// UI shows back, and a half-typed value must not be silently thrown away.
    pub mask_ip: String,
    pub selected_dns_provider_id: String,
    pub https_skip_hosts: Vec<String>,
    pub https_only_hosts: Vec<String>,
    pub https_only_mode: bool,
    pub proxy: ProxyState,
    /// BCP-47 language picked in the app; `System` follows the device.
    pub app_language: AppLanguage,
    pub theme_mode: ThemeMode,
    /// Bring the tunnel back after a reboot (only when it was on).
    pub auto_start: bool,
    /// Hide ad placeholders with cosmetic rules. Needs HTTPS filtering.
    pub cosmetic_filtering: bool,
    /// Force safe search on the major engines (CNAME rewrites).
    pub safe_search: bool,
    /// Group the request log by domain for the services breakdown. Off by
    /// default: it is a `GROUP BY` over the whole window on every statistics
    /// refresh, and the labels need the services table read from disk.
    pub show_services_breakdown: bool,
    /// Optional subscription for the services table, fetched with the filter
    /// lists. Empty keeps the table this build ships: no extra request.
    pub services_table_url: String,
    /// Verbosity of the core's own diagnostics ring, drained to logcat.
    pub log_level: LogLevel,
}

impl Default for ProtectionState {
    fn default() -> Self {
        ProtectionState {
            is_protection_active: false,
            is_ad_blocking_enabled: true,
            is_annoyances_enabled: true,
            is_browsing_security_enabled: true,
            is_tracking_protection_enabled: true,
            is_dns_protection_enabled: true,
            // The retry window is a hole in the blocking: a host it spares
            // connects. Off until the user asks for it.
            is_smart_filtering_enabled: false,
            is_https_filtering_enabled: false,
            // AdGuard keeps HTTP/3 blocked until the user opts in: the
            // termination is new and browser support varies.
            filter_http3: false,
            // AdGuard's Block ECH is off by default; an ECH connection is
            // spliced rather than stripped, so nothing breaks.
            is_ech_blocking_enabled: false,
            is_firewall_enabled: true,
            firewall_global_rules: true,
            firewall_custom_rules: true,
            firewall_notifications: true,
            // AdGuard's global defaults let every app use every network.
            firewall_allow_wifi: true,
            firewall_allow_wifi_screen_off: true,
            firewall_allow_cellular: true,
            firewall_allow_cellular_screen_off: true,
            firewall_allow_roaming: true,
            is_eco_battery_mode_enabled: true,
            // Stealth now has real side effects (WebRTC, cookies, UA), so it
            // is opt-in. It used to be a checkbox with no implementation.
            is_stealth_mode_enabled: false,
            block_quic: true,
            // Off by default: a client with a custom DoH URL (Chrome's secure
            // DNS, Private DNS in strict mode) has no fallback, so blocking it
            // breaks resolution entirely. SNI-level filtering still applies.
            block_doh: false,
            block_dot: true,
            filter_auto_update_hours: 24,
            log_allowed_requests: false,
            block_mode: DnsBlockMode::NxDomain,
            strip_utm_tracking: true,
            // Blocking STUN/TURN breaks video calls; opt in explicitly.
            block_web_rtc_leaks: false,
            disguise_user_agent: false,
            block_third_party_cookies: true,
            // Every one of the newer stealth switches starts off: the shipped
            // behaviour is exactly what it was before they existed, and the
            // privacy levels are what turns them on as a set.
            block_all_cookies: false,
            strip_etag: false,
            strip_third_party_authorization: false,
            hide_third_party_referer: false,
            inject_gpc_dnt: false,
            hide_search_query: false,
            block_push_api: false,
            block_geolocation_api: false,
            anti_dpi: false,
            mask_ip: String::new(),
            selected_dns_provider_id: "adguard_default".to_string(),
            https_skip_hosts: Vec::new(),
            https_only_hosts: Vec::new(),
            https_only_mode: false,
            proxy: ProxyState::default(),
            app_language: AppLanguage::System,
            theme_mode: ThemeMode::System,
            auto_start: false,
            cosmetic_filtering: true,
            safe_search: false,
            // The breakdown is a query the user has to ask for.
            show_services_breakdown: false,
            services_table_url: String::new(),
            // Warn is the pre-level behaviour, so a fresh install logs exactly
            // what it always did.
            log_level: LogLevel::default(),
        }
    }
}

impl ProtectionState {
    /// Clamps values the UI could not have produced and normalises host lists
    /// so the engine never sees duplicates or empty patterns.
    pub fn sanitized(mut self) -> Self {
        self.filter_auto_update_hours = self.filter_auto_update_hours.min(168);
        self.https_skip_hosts = normalize_hosts(self.https_skip_hosts);
        self.https_only_hosts = normalize_hosts(self.https_only_hosts);
        if !matches!(
            self.block_mode,
            DnsBlockMode::NxDomain | DnsBlockMode::ZeroIp | DnsBlockMode::Refused
        ) {
            self.block_mode = DnsBlockMode::NxDomain;
        }
        self
    }
}

fn normalize_hosts(hosts: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    hosts
        .into_iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty() && seen.insert(h.clone()))
        .collect()
}

/// One per-app answer for a firewall dimension.
///
/// `Inherit` follows the global default, `Allow`/`Block` are explicit
/// overrides. The serialized bool form is the one older builds wrote: `true`
/// meant "allowed by the rule" and becomes `Inherit` (the global defaults were
/// not configurable then), `false` becomes `Block`.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FirewallAccess {
    #[default]
    Inherit,
    Allow,
    Block,
}

impl Serialize for FirewallAccess {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            FirewallAccess::Inherit => "inherit",
            FirewallAccess::Allow => "allow",
            FirewallAccess::Block => "block",
        })
    }
}

impl<'de> Deserialize<'de> for FirewallAccess {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AccessVisitor;

        impl serde::de::Visitor<'_> for AccessVisitor {
            type Value = FirewallAccess;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an access word (inherit/allow/block) or the legacy boolean")
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(if value {
                    FirewallAccess::Inherit
                } else {
                    FirewallAccess::Block
                })
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value.trim().to_ascii_lowercase().as_str() {
                    "inherit" => Ok(FirewallAccess::Inherit),
                    "allow" | "allowed" => Ok(FirewallAccess::Allow),
                    "block" | "blocked" => Ok(FirewallAccess::Block),
                    _ => Err(E::custom(format!("unknown firewall access: {value}"))),
                }
            }
        }

        deserializer.deserialize_any(AccessVisitor)
    }
}

/// One app's routing answer for the SOCKS5 proxy.
///
/// `Inherit` follows the global proxy switch, `Through` forces the app's
/// flows through the proxy even when it is not the default for everything,
/// and `Direct` keeps them off it.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProxyAccess {
    #[default]
    Inherit,
    Through,
    Direct,
}

impl Serialize for ProxyAccess {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            ProxyAccess::Inherit => "inherit",
            ProxyAccess::Through => "through",
            ProxyAccess::Direct => "direct",
        })
    }
}

impl<'de> Deserialize<'de> for ProxyAccess {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AccessVisitor;

        impl serde::de::Visitor<'_> for AccessVisitor {
            type Value = ProxyAccess;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a proxy access word (inherit/through/direct)")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value.trim().to_ascii_lowercase().as_str() {
                    "inherit" | "" => Ok(ProxyAccess::Inherit),
                    "through" | "proxy" => Ok(ProxyAccess::Through),
                    "direct" | "off" => Ok(ProxyAccess::Direct),
                    _ => Err(E::custom(format!("unknown proxy access: {value}"))),
                }
            }
        }

        deserializer.deserialize_any(AccessVisitor)
    }
}

/// One app's firewall overrides. The five network dimensions are independent;
/// the global defaults apply wherever a dimension is `Inherit`.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "AppFirewallRuleWire", into = "AppFirewallRuleWire")]
pub struct AppFirewallRule {
    pub package_name: String,
    pub wifi: FirewallAccess,
    pub wifi_screen_off: FirewallAccess,
    pub cellular: FirewallAccess,
    pub cellular_screen_off: FirewallAccess,
    pub roaming: FirewallAccess,
    pub filtered: bool,
    pub https: bool,
    /// Whether a firewall block may raise a notification for this app.
    pub notify: bool,
    /// This app's routing answer for the global SOCKS5 proxy.
    pub proxy: ProxyAccess,
}

impl Default for AppFirewallRule {
    fn default() -> Self {
        AppFirewallRule {
            package_name: String::new(),
            wifi: FirewallAccess::Inherit,
            wifi_screen_off: FirewallAccess::Inherit,
            cellular: FirewallAccess::Inherit,
            cellular_screen_off: FirewallAccess::Inherit,
            roaming: FirewallAccess::Inherit,
            filtered: true,
            https: true,
            notify: true,
            proxy: ProxyAccess::Inherit,
        }
    }
}

/// Wire form: optional fields so a row written before the tri-state model
/// still loads. `screen_off` was the transport-agnostic switch and maps onto
/// both screen-off dimensions.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct AppFirewallRuleWire {
    package_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    wifi: Option<FirewallAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wifi_screen_off: Option<FirewallAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cellular: Option<FirewallAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cellular_screen_off: Option<FirewallAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    roaming: Option<FirewallAccess>,
    #[serde(skip_serializing)]
    screen_off: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filtered: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    https: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy: Option<ProxyAccess>,
}

impl From<AppFirewallRuleWire> for AppFirewallRule {
    fn from(wire: AppFirewallRuleWire) -> Self {
        let legacy_screen_off = if wire.screen_off == Some(true) {
            FirewallAccess::Block
        } else {
            FirewallAccess::Inherit
        };
        AppFirewallRule {
            package_name: wire.package_name,
            wifi: wire.wifi.unwrap_or_default(),
            wifi_screen_off: wire.wifi_screen_off.unwrap_or(legacy_screen_off),
            cellular: wire.cellular.unwrap_or_default(),
            cellular_screen_off: wire.cellular_screen_off.unwrap_or(legacy_screen_off),
            roaming: wire.roaming.unwrap_or_default(),
            filtered: wire.filtered.unwrap_or(true),
            https: wire.https.unwrap_or(true),
            notify: wire.notify.unwrap_or(true),
            proxy: wire.proxy.unwrap_or_default(),
        }
    }
}

impl From<AppFirewallRule> for AppFirewallRuleWire {
    fn from(rule: AppFirewallRule) -> Self {
        AppFirewallRuleWire {
            package_name: rule.package_name,
            wifi: Some(rule.wifi),
            wifi_screen_off: Some(rule.wifi_screen_off),
            cellular: Some(rule.cellular),
            cellular_screen_off: Some(rule.cellular_screen_off),
            roaming: Some(rule.roaming),
            screen_off: None,
            filtered: Some(rule.filtered),
            https: Some(rule.https),
            notify: Some(rule.notify),
            proxy: Some(rule.proxy),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsProviderRecord {
    pub id: String,
    pub name: String,
    /// UDP: an IPv4 literal. DoT: a hostname or IP. DoH: the full HTTPS URL.
    pub address: String,
    pub port: u16,
    pub protocol: DnsProtocol,
    /// Free text for custom providers; empty for built-ins.
    pub description: String,
    /// String-resource key for built-ins; ignored for custom providers.
    pub description_key: String,
    pub is_custom: bool,
}

impl Default for DnsProviderRecord {
    fn default() -> Self {
        DnsProviderRecord {
            id: String::new(),
            name: String::new(),
            address: String::new(),
            port: 53,
            protocol: DnsProtocol::Udp,
            description: String::new(),
            description_key: String::new(),
            is_custom: false,
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRewrite {
    pub host: String,
    /// An IPv4 or IPv6 literal; the core answers A/AAAA with it directly.
    pub answer: String,
}

/// Plain UDP resolver queried once when the selected server stays silent.
/// Kept transport-agnostic on purpose: AdGuard's fallback is also plain DNS,
/// and a fallback that needs TLS would share the failure it exists to cover.
#[derive(uniffi::Record, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsBackup {
    /// An IPv4 literal, like the primary UDP providers.
    pub address: String,
    pub port: u16,
}

/// Where the fallback query goes.
///
/// `System` is the default, like AdGuard: the network's own resolvers are
/// handed over by Android before every apply, so resolution survives a dead
/// or misconfigured upstream. `Fixed` stores one address in `DnsState::backup`.
#[derive(uniffi::Enum, Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsBackupMode {
    #[default]
    System,
    Off,
    Fixed,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsState {
    /// Built-ins plus custom entries on the way out; only custom entries are
    /// written to disk, so a future build can add or fix a built-in.
    pub providers: Vec<DnsProviderRecord>,
    pub rewrites: Vec<DnsRewrite>,
    pub backup_mode: DnsBackupMode,
    /// Only used when `backup_mode` is `Fixed`. Persisted as-is: unlike the
    /// provider list there is no built-in entry to re-merge on load.
    pub backup: Option<DnsBackup>,
}

impl Default for DnsState {
    fn default() -> Self {
        DnsState {
            providers: builtin_dns_providers(),
            rewrites: Vec::new(),
            backup_mode: DnsBackupMode::default(),
            backup: None,
        }
    }
}

impl DnsState {
    /// What actually goes to the database.
    pub fn stored(&self) -> DnsState {
        DnsState {
            providers: self
                .providers
                .iter()
                .filter(|p| p.is_custom)
                .cloned()
                .collect(),
            rewrites: self.rewrites.clone(),
            backup_mode: self.backup_mode,
            backup: self.backup.clone(),
        }
    }

    /// Rebuilds the full list: the built-ins are code, the stored custom ones
    /// follow. A custom id that shadows a built-in is dropped.
    pub fn merged(stored: DnsState) -> DnsState {
        let mut providers = builtin_dns_providers();
        let builtin_ids: std::collections::HashSet<String> =
            providers.iter().map(|p| p.id.clone()).collect();
        for p in stored.providers {
            if !builtin_ids.contains(&p.id) {
                providers.push(p);
            }
        }
        DnsState {
            providers,
            rewrites: stored
                .rewrites
                .into_iter()
                .filter(|r| !r.host.trim().is_empty() && !r.answer.trim().is_empty())
                .collect(),
            backup_mode: stored.backup_mode,
            backup: stored.backup,
        }
    }

    pub fn provider(&self, id: &str) -> Option<&DnsProviderRecord> {
        self.providers.iter().find(|p| p.id == id)
    }
}

/// The built-in resolvers are code, not persisted state. Descriptions are
/// resource keys so the two locales can render them.
pub fn builtin_dns_providers() -> Vec<DnsProviderRecord> {
    fn udp(id: &str, name: &str, address: &str, key: &str) -> DnsProviderRecord {
        DnsProviderRecord {
            id: id.to_string(),
            name: name.to_string(),
            address: address.to_string(),
            port: 53,
            protocol: DnsProtocol::Udp,
            description: String::new(),
            description_key: key.to_string(),
            is_custom: false,
        }
    }
    vec![
        udp(
            "adguard_default",
            "AdGuard DNS",
            "94.140.14.14",
            "dns_desc_adguard_default",
        ),
        udp(
            "adguard_family",
            "AdGuard Family",
            "94.140.15.16",
            "dns_desc_adguard_family",
        ),
        udp(
            "cloudflare",
            "Cloudflare 1.1.1.1",
            "1.1.1.1",
            "dns_desc_cloudflare",
        ),
        udp("quad9", "Quad9", "9.9.9.9", "dns_desc_quad9"),
        udp("google", "Google DNS", "8.8.8.8", "dns_desc_google"),
    ]
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterChoice {
    pub id: String,
    pub name: String,
    pub url: String,
    /// "standard" or "hosts".
    pub format: String,
    pub homepage: String,
    pub enabled: bool,
    pub trusted: bool,
}

impl Default for FilterChoice {
    fn default() -> Self {
        FilterChoice {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            format: "standard".to_string(),
            homepage: String::new(),
            enabled: true,
            trusted: false,
        }
    }
}

/// The user's deviations from the catalogue (which is code in Kotlin).
#[derive(uniffi::Record, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterState {
    /// False means "never chosen": the caller applies catalogue defaults.
    pub catalog_configured: bool,
    pub enabled_catalog_ids: Vec<String>,
    pub trusted_ids: Vec<String>,
    pub custom: Vec<FilterChoice>,
    pub user_rules: Vec<String>,
    /// False means the starter rules should be seeded on first use; an empty
    /// list that the user emptied must stay empty.
    pub user_rules_configured: bool,
    /// Lists the user added under "DNS filters". They are consulted by name
    /// lookups only, never by URL or SNI checks.
    pub dns_filters: Vec<FilterChoice>,
}

#[derive(uniffi::Record, Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScriptRecord {
    pub id: String,
    pub name: String,
    pub description: String,
    pub url: String,
    pub enabled: bool,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScriptState {
    /// Master switch; ON follows AdGuard's default and the catalogue rows,
    /// which start enabled.
    pub master: bool,
    pub scripts: Vec<ScriptRecord>,
}

impl Default for ScriptState {
    fn default() -> Self {
        ScriptState {
            master: true,
            scripts: Vec::new(),
        }
    }
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StateSnapshot {
    pub protection: ProtectionState,
    pub firewall: Vec<AppFirewallRule>,
    pub dns: DnsState,
    pub filters: FilterState,
    pub scripts: ScriptState,
}

// ---------------------------------------------------------------- outcomes

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigWarning {
    #[default]
    None,
    ProviderMissing,
    AddressInvalid,
    ProxyInvalid,
    StoreUnavailable,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigOutcome {
    pub ok: bool,
    pub warning: ConfigWarning,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolverSnapshot {
    /// What the tunnel should hand Android as its DNS server.
    pub tunnel_dns: String,
    pub provider_id: String,
    pub warning: ConfigWarning,
}

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsError {
    #[default]
    None,
    Empty,
    InvalidAddress,
    InvalidPort,
    UnsupportedScheme,
    /// Plain UDP upstream currently dials IPv4 only.
    IpV6UdpUnsupported,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsValidation {
    pub valid: bool,
    pub address: String,
    pub port: u16,
    pub protocol: DnsProtocol,
    pub error: DnsError,
}

/// Why a rewrite row was rejected; the UI owns the wording.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsRewriteError {
    #[default]
    None,
    HostEmpty,
    HostInvalid,
    AnswerEmpty,
    AnswerInvalid,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsRewriteValidation {
    pub valid: bool,
    /// Canonical host: lower-case, no trailing dot, `*.` kept for wildcards.
    pub host: String,
    /// Canonical IP literal.
    pub answer: String,
    pub error: DnsRewriteError,
}

/// Why a resolver probe failed; the UI owns the wording.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsProbeError {
    #[default]
    None,
    AddressInvalid,
    /// The transport exists but the endpoint does not speak it (for example
    /// an HTTP/2-only DoH server).
    Unsupported,
    /// The tunnel is running and the app refused to protect the probe socket.
    ProtectedSocket,
    Network,
    Timeout,
    BadResponse,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsProbeResult {
    pub ok: bool,
    /// Round trip measured by the probe, in milliseconds.
    pub latency_ms: u32,
    pub error: DnsProbeError,
}

#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupError {
    #[default]
    None,
    NotBackup,
    UnsupportedVersion,
    Malformed,
    StoreUnavailable,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Default)]
pub struct BackupOutcome {
    pub ok: bool,
    pub error: BackupError,
}
