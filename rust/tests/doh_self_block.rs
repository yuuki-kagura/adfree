//! Regression tests for the encrypted-DNS blocking rules.
//!
//! The platform resolver silently upgrades to DoT when the configured server
//! supports it. The point of "block encrypted DNS" is to force it back onto
//! plain UDP:53, which is the only transport we can filter and forward — so
//! DoT towards the encrypted-DNS providers is blocked *even when one of them is
//! also our upstream*. Our own forwarding is unaffected: it uses protected
//! sockets outside the tunnel.

use adfree_core::engine::{core, Config};
use adfree_core::packet::{ip_key_from, IpKey};

fn cloudflare() -> IpKey {
    ip_key_from("1.1.1.1".parse().unwrap())
}

#[test]
fn the_configured_upstream_is_blocked_too() {
    let core = core();
    // Our upstream is AdGuard DNS, which is in the encrypted-DNS list. Blocking
    // DoT to it is what pushes the resolver onto UDP:53, which we can forward.
    let upstream = ip_key_from(core.resolver_addr().ip());
    assert!(
        core.is_encrypted_dns_elsewhere(upstream),
        "DoT towards the upstream must be blocked so the resolver falls back to UDP"
    );
}

#[test]
fn other_providers_are_still_blocked() {
    let core = core();
    assert!(core.is_encrypted_dns_elsewhere(cloudflare()));
}

#[test]
fn the_upstream_filter_is_independent_of_the_config_switch() {
    // `is_encrypted_dns_elsewhere` answers one question: "is this an encrypted DNS
    // provider?". Whether to *act* on it is the caller's decision, so this test
    // only checks the answer stays stable regardless of the config switch.
    let core = core();
    core.set_config(Config {
        block_doh: false,
        ..Config::default()
    });
    assert!(core.is_encrypted_dns_elsewhere(cloudflare()));
    core.set_config(Config::default());
}
