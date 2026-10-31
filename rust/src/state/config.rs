//! One config path: persisted state in, engine knobs out.
//!
//! Kotlin used to map settings to `EngineConfig` on every change, which meant
//! two implementations of every default and a switch that could be shown but
//! never applied. Building the engine config here makes the persisted record
//! the only source of truth: the UI writes a record, the core applies it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use crate::engine::{Config, Core, StealthConfig};

use super::model::*;
use super::StateStore;

/// The per-app consequences of the firewall rules, computed once per apply.
#[derive(Debug, Default)]
pub struct PolicyPlan {
    /// Global defaults plus the per-app overrides the engine evaluates.
    pub network: crate::engine::AppNetworkPolicy,
    /// Apps whose TLS is spliced instead of decrypted.
    pub https_skip_apps: Vec<String>,
    /// Apps kept outside the tunnel entirely.
    pub excluded: Vec<String>,
}

pub struct Plan {
    pub config: Config,
    /// Plain UDP resolver; unused when `secure` is set.
    pub upstream: SocketAddr,
    /// DoT/DoH transport selected by the provider, if any.
    pub secure: Option<crate::dnssecure::SecureResolver>,
    /// Plain UDP resolver retried once when the selected one is silent.
    pub backup: Option<SocketAddr>,
    pub outcome: ConfigOutcome,
    pub resolver: ResolverSnapshot,
    pub policy: PolicyPlan,
    /// Parsed `host -> address` rows, ready for the engine.
    pub rewrites: Vec<crate::dnsrewrite::DnsRewriteRule>,
}

const DEFAULT_IP: Ipv4Addr = Ipv4Addr::new(94, 140, 14, 14);
const DEFAULT_PORT: u16 = 53;

/// DNS server advertised inside the tunnel when the upstream is encrypted.
/// The engine intercepts every UDP query on port 53, so this address never
/// needs a listener of its own; it only has to be routable through the TUN.
const TUNNEL_DNS: &str = "10.111.222.1";

fn default_upstream() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(DEFAULT_IP), DEFAULT_PORT)
}

/// The active network's resolver as Android reported it. The core cannot read
/// `LinkProperties`, and a VPN's `/etc/resolv.conf` is not the device's, so
/// Kotlin hands this over before every apply.
static SYSTEM_DNS: Mutex<Option<SocketAddr>> = Mutex::new(None);

/// Installs the servers Android sees for the active network. Only the first
/// IPv4 entry is kept: the fallback sends plain UDP from an IPv4 socket, and
/// one spare answer is already more than AdGuard's single fallback.
pub fn set_system_dns(servers: Vec<String>) {
    let parsed = servers
        .iter()
        .filter_map(|s| s.trim().parse::<Ipv4Addr>().ok())
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), 53))
        .next();
    if let Ok(mut slot) = SYSTEM_DNS.lock() {
        *slot = parsed;
    }
}

fn system_dns() -> Option<SocketAddr> {
    SYSTEM_DNS.lock().map(|slot| *slot).unwrap_or(None)
}

/// Applies the current state to the engine. Returns the warning Kotlin shows
/// (if any); the engine always ends up with a usable resolver, so a missing or
/// unusable provider never leaves the VPN down.
pub fn apply(state: &StateStore, core: &Core, private_dns_strict: bool) -> ConfigOutcome {
    let plan = build(&state.snapshot(), private_dns_strict);
    core.set_config(plan.config);
    core.set_dns_rewrites(plan.rewrites);
    core.set_app_network_policy(plan.policy.network);
    core.set_https_skip_apps(plan.policy.https_skip_apps);
    core.set_resolver(plan.upstream);
    core.set_secure_resolver(plan.secure);
    core.set_backup_resolver(plan.backup);
    plan.outcome
}

pub fn build(snapshot: &StateSnapshot, private_dns_strict: bool) -> Plan {
    let protection = &snapshot.protection;
    let policy = policy(snapshot);
    let (provider, provider_warning) = selected_provider(snapshot);
    let (upstream, secure, tunnel_dns, address_warning) = upstream(&provider);
    let backup = backup_resolver(&snapshot.dns);
    let (proxy, proxy_warning) = proxy(&protection.proxy);

    let warning = if provider_warning != ConfigWarning::None {
        provider_warning
    } else if address_warning != ConfigWarning::None {
        address_warning
    } else {
        proxy_warning
    };

    let resolver = ResolverSnapshot {
        tunnel_dns,
        provider_id: provider.id.clone(),
        warning,
    };

    let config = Config {
        mitm_enabled: protection.is_https_filtering_enabled,
        // Termination needs the CA and the decision layer HTTPS filtering
        // brings; the UI disables the switch, and the core refuses to arm it
        // on its own (a stored `true` must not survive turning HTTPS off).
        filter_http3: protection.filter_http3 && protection.is_https_filtering_enabled,
        // Blocking ECH is the inverse of letting it run end to end; AdGuard
        // ships its "Block ECH" switch off, so ECH is allowed by default.
        full_ech: !protection.is_ech_blocking_enabled,
        block_quic: protection.block_quic,
        block_doh: protection.block_doh,
        // With the system's Private DNS in strict mode the platform already
        // owns DoT; dropping it too would also kill the user's chosen server.
        block_dot: protection.block_dot && !private_dns_strict,
        ad_blocking: protection.is_ad_blocking_enabled,
        annoyances: protection.is_annoyances_enabled,
        browsing_security: protection.is_browsing_security_enabled,
        tracking_protection: protection.is_tracking_protection_enabled,
        dns_protection: protection.is_dns_protection_enabled,
        smart_filtering: protection.is_smart_filtering_enabled,
        block_mode: crate::dns::BlockMode::from_u8(protection.block_mode.code()),
        log_allowed: protection.log_allowed_requests,
        eco_mode: protection.is_eco_battery_mode_enabled,
        https_skip_hosts: protection.https_skip_hosts.clone(),
        https_only_hosts: protection.https_only_hosts.clone(),
        https_only_mode: protection.https_only_mode,
        proxy,
        stealth: StealthConfig {
            enabled: protection.is_stealth_mode_enabled,
            strip_utm: protection.strip_utm_tracking,
            block_web_rtc: protection.block_web_rtc_leaks,
            disguise_user_agent: protection.disguise_user_agent,
            block_third_party_cookies: protection.block_third_party_cookies,
        },
        cosmetic_filtering: protection.cosmetic_filtering,
        safe_search: protection.safe_search,
    };

    let rewrites = snapshot
        .dns
        .rewrites
        .iter()
        .filter_map(|row| crate::dnsrewrite::DnsRewriteRule::parse(&row.host, &row.answer))
        .collect();

    Plan {
        config,
        upstream,
        secure,
        backup,
        outcome: ConfigOutcome {
            ok: warning == ConfigWarning::None,
            warning,
        },
        resolver,
        policy,
        rewrites,
    }
}

/// The selected provider, or the AdGuard default with a warning. Never fails:
/// a resolver the user deleted must not take the tunnel down with it.
fn selected_provider(snapshot: &StateSnapshot) -> (DnsProviderRecord, ConfigWarning) {
    if let Some(provider) = snapshot
        .dns
        .provider(&snapshot.protection.selected_dns_provider_id)
    {
        return (provider.clone(), ConfigWarning::None);
    }
    crate::logbuf::push("state: selected resolver is missing, using the default");
    (default_provider(), ConfigWarning::ProviderMissing)
}

fn default_provider() -> DnsProviderRecord {
    builtin_dns_providers()
        .into_iter()
        .find(|p| p.id == "adguard_default")
        .expect("the built-in default always exists")
}

/// The resolver the engine should use.
///
/// UDP keeps the plain forwarder. DoT/DoH build a secure transport and leave
/// the tunnel advertising the AdGuard address, because `VpnService` only
/// accepts an IP there and apps inside the tunnel still speak plain DNS.
/// A provider the transport cannot parse falls back to the default with a
/// warning instead of silently keeping an unrelated resolver active.
fn upstream(
    provider: &DnsProviderRecord,
) -> (
    SocketAddr,
    Option<crate::dnssecure::SecureResolver>,
    String,
    ConfigWarning,
) {
    match provider.protocol {
        DnsProtocol::Udp => match provider.address.parse::<IpAddr>() {
            Ok(ip) => {
                let addr = SocketAddr::new(ip, provider.port);
                (addr, None, ip.to_string(), ConfigWarning::None)
            }
            Err(_) => {
                crate::logbuf::push(&format!(
                    "state: resolver {} has an unparsable address; using the default",
                    provider.id
                ));
                (
                    default_upstream(),
                    None,
                    DEFAULT_IP.to_string(),
                    ConfigWarning::AddressInvalid,
                )
            }
        },
        DnsProtocol::Dot | DnsProtocol::Doh => {
            match crate::dnssecure::SecureResolver::from_parts(
                provider.protocol,
                &provider.address,
                provider.port,
            ) {
                Some(resolver) => (
                    default_upstream(),
                    Some(resolver),
                    TUNNEL_DNS.to_string(),
                    ConfigWarning::None,
                ),
                None => {
                    crate::logbuf::push(&format!(
                        "state: resolver {} uses {:?} with an unusable address; using UDP",
                        provider.id, provider.protocol
                    ));
                    (
                        default_upstream(),
                        None,
                        DEFAULT_IP.to_string(),
                        ConfigWarning::AddressInvalid,
                    )
                }
            }
        }
    }
}

/// The fallback resolver, or `None` when it is off or unusable. A bad backup
/// must not produce a warning banner: the primary still works, and the user
/// only enabled the fallback as insurance.
fn backup_resolver(state: &DnsState) -> Option<SocketAddr> {
    match state.backup_mode {
        DnsBackupMode::Off => None,
        DnsBackupMode::System => system_dns(),
        DnsBackupMode::Fixed => {
            let backup = state.backup.as_ref()?;
            match backup.address.trim().parse::<IpAddr>() {
                Ok(ip) => Some(SocketAddr::new(
                    ip,
                    if backup.port == 0 { 53 } else { backup.port },
                )),
                Err(_) => {
                    crate::logbuf::push(
                        "state: backup resolver is not an IP literal; fallback disabled",
                    );
                    None
                }
            }
        }
    }
}

fn proxy(
    state: &ProxyState,
) -> (
    Option<std::sync::Arc<crate::socks5::ProxyEndpoint>>,
    ConfigWarning,
) {
    if !state.enabled {
        return (None, ConfigWarning::None);
    }
    let host = state.host.trim();
    let parsed = host
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .ok()
        .map(crate::packet::ip_key_from);
    match parsed {
        Some(addr) if state.port != 0 => (
            Some(std::sync::Arc::new(crate::socks5::ProxyEndpoint {
                addr,
                port: state.port,
                username: state.username.clone(),
                password: state.password.clone(),
                automatic: state.automatic,
            })),
            ConfigWarning::None,
        ),
        _ => {
            crate::logbuf::push(
                "state: proxy host must be an IPv4/IPv6 literal and the port non-zero",
            );
            (None, ConfigWarning::ProxyInvalid)
        }
    }
}

pub fn policy(snapshot: &StateSnapshot) -> PolicyPlan {
    let mut plan = PolicyPlan::default();
    for rule in &snapshot.firewall {
        if !rule.filtered {
            plan.excluded.push(rule.package_name.clone());
        }
        if !rule.https {
            plan.https_skip_apps.push(rule.package_name.clone());
        }
    }
    // The firewall switch owns the per-app restrictions only: tunnel routing
    // and HTTPS filtering are separate switches and keep working when it is
    // off. A disabled global or custom set contributes no restriction, which
    // is why the global defaults turn into "allow" instead of being ignored:
    // `Inherit` still has to resolve to something.
    let protection = &snapshot.protection;
    let network = &mut plan.network;
    network.active = protection.is_firewall_enabled;
    network.allow_wifi = !protection.firewall_global_rules || protection.firewall_allow_wifi;
    network.allow_wifi_screen_off =
        !protection.firewall_global_rules || protection.firewall_allow_wifi_screen_off;
    network.allow_cellular =
        !protection.firewall_global_rules || protection.firewall_allow_cellular;
    network.allow_cellular_screen_off =
        !protection.firewall_global_rules || protection.firewall_allow_cellular_screen_off;
    network.allow_roaming = !protection.firewall_global_rules || protection.firewall_allow_roaming;

    // Routing answers are a proxy feature, not a firewall dimension: they
    // keep applying while the firewall switch (or its custom-rule gate) is
    // off, so a user can pin one app to the proxy without enabling the rest.
    network.proxy_rules = std::sync::Arc::new(        snapshot
            .firewall
            .iter()
            .filter(|rule| rule.proxy != ProxyAccess::Inherit)
            .map(|rule| (rule.package_name.clone(), rule.proxy))
            .collect(),
    );

    if !protection.is_firewall_enabled || !protection.firewall_custom_rules {
        return plan;
    }
    let rules = snapshot
        .firewall
        .iter()
        .filter(|rule| {
            rule.wifi != FirewallAccess::Inherit
                || rule.wifi_screen_off != FirewallAccess::Inherit
                || rule.cellular != FirewallAccess::Inherit
                || rule.cellular_screen_off != FirewallAccess::Inherit
                || rule.roaming != FirewallAccess::Inherit
        })
        .map(|rule| {
            (
                rule.package_name.clone(),
                crate::engine::AppFirewallState {
                    wifi: rule.wifi,
                    wifi_screen_off: rule.wifi_screen_off,
                    cellular: rule.cellular,
                    cellular_screen_off: rule.cellular_screen_off,
                    roaming: rule.roaming,
                },
            )
        })
        .collect();
    network.rules = std::sync::Arc::new(rules);
    plan
}

/// Apps kept out of the tunnel (`filtered = false`), for `VpnService`.
pub fn excluded_packages(snapshot: &StateSnapshot) -> Vec<String> {
    policy(snapshot).excluded
}

/// What the tunnel should advertise as its DNS server, without touching the
/// engine (the VPN builder calls this before `establish`).
pub fn resolver_snapshot(snapshot: &StateSnapshot) -> ResolverSnapshot {
    let (provider, provider_warning) = selected_provider(snapshot);
    let (_, _, tunnel_dns, address_warning) = upstream(&provider);
    let warning = if provider_warning != ConfigWarning::None {
        provider_warning
    } else {
        address_warning
    };
    ResolverSnapshot {
        tunnel_dns,
        provider_id: provider.id.clone(),
        warning,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> StateSnapshot {
        StateSnapshot::default()
    }

    #[test]
    fn defaults_are_usable_without_any_warning() {
        let plan = build(&snapshot(), false);
        assert!(plan.outcome.ok);
        assert_eq!(plan.resolver.tunnel_dns, "94.140.14.14");
        assert!(plan.config.dns_protection);
        assert!(!plan.config.mitm_enabled);
    }

    #[test]
    fn encrypted_upstreams_advertise_the_tunnel_address() {
        let mut s = snapshot();
        s.dns.providers.push(DnsProviderRecord {
            id: "doh_test".to_string(),
            name: "DoH".to_string(),
            address: "https://dns.example/dns-query".to_string(),
            port: 443,
            protocol: DnsProtocol::Doh,
            description: String::new(),
            description_key: String::new(),
            is_custom: true,
        });
        s.protection.selected_dns_provider_id = "doh_test".to_string();
        let plan = build(&s, false);
        assert!(plan.secure.is_some());
        assert_eq!(plan.resolver.tunnel_dns, "10.111.222.1");
        assert_eq!(resolver_snapshot(&s).tunnel_dns, "10.111.222.1");
    }

    #[test]
    fn stealth_effects_need_the_master_switch() {
        let mut s = snapshot();
        s.protection.is_stealth_mode_enabled = false;
        s.protection.strip_utm_tracking = true;
        s.protection.block_web_rtc_leaks = true;
        let off = build(&s, false);
        assert!(!off.config.stealth.strips_utm());
        assert!(!off.config.stealth.blocks_web_rtc());

        s.protection.is_stealth_mode_enabled = true;
        let on = build(&s, false);
        assert!(on.config.stealth.strips_utm());
        assert!(on.config.stealth.blocks_web_rtc());
        assert!(on.config.stealth.blocks_third_party_cookies());
        assert!(!on.config.stealth.disguises_user_agent());
    }

    #[test]
    fn a_missing_provider_falls_back_and_warns() {
        let mut s = snapshot();
        s.protection.selected_dns_provider_id = "gone".to_string();
        let plan = build(&s, false);
        assert!(!plan.outcome.ok);
        assert_eq!(plan.outcome.warning, ConfigWarning::ProviderMissing);
        assert_eq!(plan.resolver.provider_id, "adguard_default");
        assert_eq!(plan.resolver.tunnel_dns, "94.140.14.14");
    }

    #[test]
    fn custom_udp_resolver_sets_the_tunnel_dns() {
        let mut s = snapshot();
        s.dns.providers.push(DnsProviderRecord {
            id: "mine".to_string(),
            name: "Mine".to_string(),
            address: "9.9.9.9".to_string(),
            port: 5353,
            protocol: DnsProtocol::Udp,
            is_custom: true,
            ..DnsProviderRecord::default()
        });
        s.protection.selected_dns_provider_id = "mine".to_string();
        let plan = build(&s, false);
        assert!(plan.outcome.ok);
        assert_eq!(plan.resolver.tunnel_dns, "9.9.9.9");
        assert_eq!(plan.upstream.port(), 5353);
    }

    #[test]
    fn the_backup_resolver_follows_the_selected_mode() {
        fn addr(a: [u8; 4]) -> Option<SocketAddr> {
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), 53))
        }

        let mut s = snapshot();
        // Default is the system resolver, like AdGuard. Nothing reported yet,
        // so there is nothing to fall back to until Android hands it over.
        assert_eq!(s.dns.backup_mode, DnsBackupMode::System);
        assert!(build(&s, false).backup.is_none());

        set_system_dns(vec!["1.1.1.1".to_string(), "2001:db8::1".to_string()]);
        assert_eq!(build(&s, false).backup, addr([1, 1, 1, 1]));

        s.dns.backup_mode = DnsBackupMode::Off;
        assert!(build(&s, false).backup.is_none());

        s.dns.backup_mode = DnsBackupMode::Fixed;
        assert!(build(&s, false).backup.is_none());
        s.dns.backup = Some(DnsBackup {
            address: "9.9.9.9".to_string(),
            port: 0,
        });
        assert_eq!(build(&s, false).backup, addr([9, 9, 9, 9]));

        // Plain DNS needs a literal; a hostname would need a resolver to
        // resolve, which is exactly what is broken when the fallback matters.
        s.dns.backup = Some(DnsBackup {
            address: "dns.example".to_string(),
            port: 53,
        });
        assert!(build(&s, false).backup.is_none());

        set_system_dns(Vec::new());
    }

    #[test]
    fn an_older_dns_blob_defaults_the_fallback_to_the_system() {
        let parsed: DnsState = serde_json::from_str(r#"{"providers":[],"rewrites":[]}"#).unwrap();
        assert_eq!(parsed.backup_mode, DnsBackupMode::System);
        assert!(parsed.backup.is_none());
    }

    #[test]
    fn ech_is_allowed_unless_the_user_blocks_it() {
        // AdGuard's "Block ECH" ships off, and the engine flag is its
        // inverse: ECHConfigs stay in the answers by default.
        let s = snapshot();
        assert!(!s.protection.is_ech_blocking_enabled);
        assert!(build(&s, false).config.full_ech);

        let mut s = snapshot();
        s.protection.is_ech_blocking_enabled = true;
        assert!(!build(&s, false).config.full_ech);
    }

    #[test]
    fn private_dns_strict_carves_dot_out_of_the_blocker() {
        let s = snapshot();
        assert!(build(&s, false).config.block_dot);
        assert!(!build(&s, true).config.block_dot);
    }

    #[test]
    fn firewall_switch_only_gates_network_rules() {
        let mut s = snapshot();
        s.firewall.push(AppFirewallRule {
            package_name: "com.example".to_string(),
            cellular: FirewallAccess::Block,
            wifi: FirewallAccess::Block,
            filtered: false,
            https: false,
            ..AppFirewallRule::default()
        });
        let on = policy(&s);
        assert!(on.network.active);
        assert!(on.network.allow_wifi, "the global default still allows");
        let rule = on.network.rules.get("com.example").expect("override kept");
        assert_eq!(rule.wifi, FirewallAccess::Block);
        assert_eq!(rule.cellular, FirewallAccess::Block);
        assert_eq!(on.excluded, vec!["com.example"]);
        assert_eq!(on.https_skip_apps, vec!["com.example"]);

        s.protection.is_firewall_enabled = false;
        let off = policy(&s);
        assert!(!off.network.active);
        assert!(off.network.rules.is_empty());
        // Routing and HTTPS exclusion survive the firewall switch.
        assert_eq!(off.excluded, vec!["com.example"]);
        assert_eq!(off.https_skip_apps, vec!["com.example"]);
    }

    #[test]
    fn proxy_routing_survives_the_firewall_switch() {
        let mut s = snapshot();
        s.firewall.push(AppFirewallRule {
            package_name: "com.example".to_string(),
            proxy: ProxyAccess::Through,
            ..AppFirewallRule::default()
        });
        let on = policy(&s);
        assert_eq!(
            on.network.proxy_rules.get("com.example"),
            Some(&ProxyAccess::Through)
        );

        // Routing is a proxy feature: turning the firewall off drops the
        // network dimensions but keeps the per-app proxy answers.
        s.protection.is_firewall_enabled = false;
        let off = policy(&s);
        assert!(off.network.rules.is_empty());
        assert_eq!(
            off.network.proxy_rules.get("com.example"),
            Some(&ProxyAccess::Through)
        );
    }

    #[test]
    fn global_defaults_apply_inherited_dimensions_and_drop_when_gated() {
        let mut s = snapshot();
        s.protection.firewall_allow_wifi = false;
        s.protection.firewall_allow_roaming = false;
        s.firewall.push(AppFirewallRule {
            package_name: "com.example".to_string(),
            wifi: FirewallAccess::Allow,
            ..AppFirewallRule::default()
        });

        let plan = policy(&s);
        assert!(!plan.network.allow_wifi);
        assert!(!plan.network.allow_roaming);
        let rule = plan.network.rules.get("com.example").expect("explicit allow");
        assert_eq!(rule.wifi, FirewallAccess::Allow);
        assert_eq!(
            rule.cellular,
            FirewallAccess::Inherit,
            "only the dimensions the user touched are overrides"
        );

        // Turning global rules off restores the allowed defaults without
        // discarding the per-app override.
        s.protection.firewall_global_rules = false;
        let plan = policy(&s);
        assert!(plan.network.allow_wifi);
        assert!(plan.network.allow_roaming);
        assert!(plan.network.rules.contains_key("com.example"));

        // Turning custom rules off drops the overrides; the globals decide.
        s.protection.firewall_global_rules = true;
        s.protection.firewall_custom_rules = false;
        let plan = policy(&s);
        assert!(plan.network.rules.is_empty());
        assert!(!plan.network.allow_wifi);
    }

    #[test]
    fn a_broken_proxy_leaves_a_warning_but_keeps_direct_connections() {
        let mut s = snapshot();
        s.protection.proxy = ProxyState {
            enabled: true,
            host: "proxy.example".to_string(),
            port: 1080,
            ..ProxyState::default()
        };
        let plan = build(&s, false);
        assert!(plan.config.proxy.is_none());
        assert_eq!(plan.outcome.warning, ConfigWarning::ProxyInvalid);
    }

    #[test]
    fn rewrites_are_parsed_and_bad_rows_are_skipped() {
        let mut s = snapshot();
        s.dns.rewrites.push(DnsRewrite {
            host: "*.lan".to_string(),
            answer: "10.0.0.2".to_string(),
        });
        s.dns.rewrites.push(DnsRewrite {
            host: "broken.lan".to_string(),
            answer: "not-an-address".to_string(),
        });
        let plan = build(&s, false);
        assert_eq!(plan.rewrites.len(), 1);
        assert_eq!(plan.rewrites[0].host, "lan");
        assert!(plan.rewrites[0].wildcard);
    }

    #[test]
    fn safe_search_reaches_the_engine() {
        let mut s = snapshot();
        assert!(!build(&s, false).config.safe_search);
        s.protection.safe_search = true;
        assert!(build(&s, false).config.safe_search);
    }

    #[test]
    fn encrypted_providers_select_the_secure_transport() {
        let mut s = snapshot();
        s.dns.providers.push(DnsProviderRecord {
            id: "dot".to_string(),
            address: "tls://dns.example".to_string(),
            port: 853,
            protocol: DnsProtocol::Dot,
            is_custom: true,
            ..DnsProviderRecord::default()
        });
        s.dns.providers.push(DnsProviderRecord {
            id: "doh".to_string(),
            address: "https://dns.example/dns-query".to_string(),
            port: 443,
            protocol: DnsProtocol::Doh,
            is_custom: true,
            ..DnsProviderRecord::default()
        });

        s.protection.selected_dns_provider_id = "dot".to_string();
        let dot = build(&s, false);
        assert!(dot.outcome.ok);
        let secure = dot.secure.as_ref().expect("DoT transport");
        assert_eq!(secure.protocol, DnsProtocol::Dot);
        assert_eq!(secure.host, "dns.example");
        assert_eq!(secure.port, 853);
        // The tunnel still needs an IP: apps inside it speak plain DNS, and
        // the engine answers this reserved one.
        assert_eq!(dot.resolver.tunnel_dns, "10.111.222.1");

        s.protection.selected_dns_provider_id = "doh".to_string();
        let doh = build(&s, false);
        assert!(doh.outcome.ok);
        let secure = doh.secure.as_ref().expect("DoH transport");
        assert_eq!(secure.protocol, DnsProtocol::Doh);
        assert_eq!(secure.path, "/dns-query");
        assert_eq!(secure.port, 443);
    }

    #[test]
    fn an_unusable_encrypted_provider_falls_back_and_warns() {
        let mut s = snapshot();
        s.dns.providers.push(DnsProviderRecord {
            id: "bad".to_string(),
            address: "dns.example".to_string(),
            port: 443,
            protocol: DnsProtocol::Doh,
            is_custom: true,
            ..DnsProviderRecord::default()
        });
        s.protection.selected_dns_provider_id = "bad".to_string();
        let plan = build(&s, false);
        assert!(plan.secure.is_none());
        assert_eq!(plan.outcome.warning, ConfigWarning::AddressInvalid);
        assert_eq!(plan.resolver.tunnel_dns, "94.140.14.14");
        assert_eq!(plan.upstream.port(), 53);
    }
}
