//! Repro for the "0 active rules" bug: run the real rebuild path on the host
//! with the exact lists the app ships, and time it.

use adfree_core::filter::{FilterEngine, FilterListInfo, ListFormat};
use std::path::PathBuf;
use std::time::Instant;

fn lists(dir: &str) -> Vec<FilterListInfo> {
    let specs = [
        ("builtin_dns", "AdGuard DNS filter", ListFormat::Standard, 0u8),
        ("builtin_oisd", "OISD Big", ListFormat::Hosts, 0),
        ("builtin_stevenblack", "StevenBlack hosts", ListFormat::Hosts, 5),
    ];
    specs
        .iter()
        .map(|(id, name, format, category)| FilterListInfo {
            id: 1,
            name: format!("{name}-{id}"),
            url: String::new(),
            enabled: true,
            local_path: Some(PathBuf::from(format!("{dir}/{id}.txt"))),
            format: *format,
            category: *category,
            rule_count: 0,
            last_error: None,
        })
        .collect()
}

#[test]
fn rebuild_with_real_lists_reports_rules() {
    let dir = std::env::var("ADFREE_LIST_DIR").unwrap_or_else(|_| "/tmp/opencode/lists".into());
    if !PathBuf::from(&dir).join("builtin_dns.txt").exists() {
        eprintln!("skipped: {dir}/builtin_dns.txt missing");
        return;
    }
    // Pull the hosts lists too when possible.
    let specs = lists(&dir);
    let engine = FilterEngine::new();
    let started = Instant::now();
    engine.rebuild(&specs, &[]);
    let elapsed = started.elapsed();
    println!("build took {elapsed:?}");
    assert!(engine.active_rules() > 100_000, "expected a large rule count");
    assert!(engine.memory_bytes() > 1_000_000);
    // And the engine must actually block — including with all three lists
    // loaded, which is what shipped on the device.
    for host in [
        "doubleclick.net",
        "googleads.g.doubleclick.net",
        "app-measurement.com",
        "adservice.google.com",
        "sdk.appsflyer.com",
        "adnxs.com",
        "crashlytics.com",
        "graph.facebook.com",
    ] {
        let verdict = engine.check_host(host);
        println!("{host}: blocked={}", verdict.blocked);
        if host != "graph.facebook.com" {
            assert!(verdict.blocked, "{host} must be blocked by the real lists");
        }
    }
    let clean = engine.check_host("api.github.com");
    assert!(!clean.blocked, "api.github.com must not be blocked");
}
