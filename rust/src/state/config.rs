//! One config path: persisted state in, engine knobs out.
//!
//! Kotlin used to map settings to `EngineConfig` on every change, which meant
//! two implementations of every default and a switch that could be shown but
//! never applied. Building the engine config here makes the persisted record
//! the only source of truth: the UI writes a record, the core applies it.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::engine::{Config, Core, StealthConfig};

use super::model::*;
use super::StateStore;

/// The per-app consequences of the firewall rules, computed once per apply.
#[derive(Debug, Default)]
pub struct PolicyPlan {
    pub cellular_blocked: Vec<String>,
    pub wifi_blocked: Vec<String>,
    pub screen_off_blocked: Vec<String>,
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

/// Applies the current state to the engine. Returns the warning Kotlin shows
/// (if any); the engine always ends up with a usable resolver, so a missing or
/// unusable provider never leaves the VPN down.
pub fn apply(state: &StateStore, core: &Core, private_dns_strict: bool) -> ConfigOutcome {
    let plan = build(&state.snapshot(), private_dns_strict);
    core.set_config(plan.config);
    core.set_dns_rewrites(plan.rewrites);
    core.set_app_network_policy(
        plan.policy.cellular_blocked,
        plan.policy.wifi_blocked,
        plan.policy.screen_off_blocked,
    );
    core.set_https_skip_apps(plan.policy.https_skip_apps);
    core.set_resolver(plan.upstream);
    core.set_secure_resolver(plan.secure);
    plan.outcome
}

pub fn build(snapshot: &StateSnapshot, private_dns_strict: bool) -> Plan {
    let protection = &snapshot.protection;
    let policy = policy(snapshot);
    let (provider, provider_warning) = selected_provider(snapshot);
    let (upstream, secure, tunnel_dns, address_warning) = upstream(&provider);
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
        full_ech: protection.is_full_ech_enabled,
        block_quic: protection.block_quic,
        block_doh: protection.block_doh,
        // With the system's Private DNS in strict mode the platform already
        // owns DoT; dropping it too would also kill the user's chosen server.
        block_dot: protection.block_dot && !private_dns_strict,
        ad_blocking: protection.is_ad_blocking_enabled,
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
    // off. The core treats empty lists as "no restriction".
    if snapshot.protection.is_firewall_enabled {
        for rule in &snapshot.firewall {
            if !rule.cellular {
                plan.cellular_blocked.push(rule.package_name.clone());
            }
            if !rule.wifi {
                plan.wifi_blocked.push(rule.package_name.clone());
            }
            if rule.screen_off {
                plan.screen_off_blocked.push(rule.package_name.clone());
            }
        }
    }
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
            cellular: false,
            wifi: false,
            filtered: false,
            screen_off: true,
            https: false,
        });
        let on = policy(&s);
        assert_eq!(on.cellular_blocked, vec!["com.example"]);
        assert_eq!(on.wifi_blocked, vec!["com.example"]);
        assert_eq!(on.screen_off_blocked, vec!["com.example"]);
        assert_eq!(on.excluded, vec!["com.example"]);
        assert_eq!(on.https_skip_apps, vec!["com.example"]);

        s.protection.is_firewall_enabled = false;
        let off = policy(&s);
        assert!(off.cellular_blocked.is_empty());
        assert!(off.wifi_blocked.is_empty());
        assert!(off.screen_off_blocked.is_empty());
        // Routing and HTTPS exclusion survive the firewall switch.
        assert_eq!(off.excluded, vec!["com.example"]);
        assert_eq!(off.https_skip_apps, vec!["com.example"]);
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
