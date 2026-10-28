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
    pub is_tracking_protection_enabled: bool,
    pub is_dns_protection_enabled: bool,
    pub is_smart_filtering_enabled: bool,
    pub is_https_filtering_enabled: bool,
    /// Terminate and filter QUIC (HTTP/3) instead of dropping it. Needs HTTPS
    /// filtering, because the same certificate and decision layer are used.
    pub filter_http3: bool,
    pub is_full_ech_enabled: bool,
    pub is_firewall_enabled: bool,
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
}

impl Default for ProtectionState {
    fn default() -> Self {
        ProtectionState {
            is_protection_active: false,
            is_ad_blocking_enabled: true,
            is_tracking_protection_enabled: true,
            is_dns_protection_enabled: true,
            is_smart_filtering_enabled: true,
            is_https_filtering_enabled: false,
            // AdGuard keeps HTTP/3 blocked until the user opts in: the
            // termination is new and browser support varies.
            filter_http3: false,
            is_full_ech_enabled: false,
            is_firewall_enabled: true,
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

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppFirewallRule {
    pub package_name: String,
    pub cellular: bool,
    pub wifi: bool,
    pub filtered: bool,
    pub screen_off: bool,
    pub https: bool,
}

impl Default for AppFirewallRule {
    fn default() -> Self {
        AppFirewallRule {
            package_name: String::new(),
            cellular: true,
            wifi: true,
            filtered: true,
            screen_off: false,
            https: true,
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

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsState {
    /// Built-ins plus custom entries on the way out; only custom entries are
    /// written to disk, so a future build can add or fix a built-in.
    pub providers: Vec<DnsProviderRecord>,
    pub rewrites: Vec<DnsRewrite>,
}

impl Default for DnsState {
    fn default() -> Self {
        DnsState {
            providers: builtin_dns_providers(),
            rewrites: Vec::new(),
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
