//! Repro: does the real AdGuard DNS filter block the hosts that leaked?

use adblock::engine::Engine;
use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;

fn build(path: &str) -> Engine {
    let text = std::fs::read_to_string(path).expect("list");
    let mut set = FilterSet::new(true);
    set.add_filter_list(text, ParseOptions::default());
    Engine::new_with_filter_set(set)
}

fn blocked(engine: &Engine, host: &str) -> bool {
    let url = format!("https://{host}/");
    let req = Request::new(&url, "https://localhost/", "xmlhttprequest", "").expect("request");
    engine.check_network_request(&req).should_block()
}

#[test]
fn real_adguard_dns_list_blocks_known_hosts() {
    let path = std::env::var("ADFREE_LIST").unwrap_or_else(|_| "/tmp/opencode/lists/dns.txt".into());
    if !std::path::Path::new(&path).exists() {
        eprintln!("skipped: no list at {path}");
        return;
    }
    let engine = build(&path);
    let hosts = [
        "doubleclick.net",
        "zz1.adnxs.com",
        "zz2.adnxs.com",
        "uv.adnxs.com",
        "googleads.g.doubleclick.net",
        "app-measurement.com",
        "sdk.appsflyer.com",
        "adservice.google.com",
        "graph.facebook.com",
        "api.github.com",
        "wikipedia.org",
    ];
    let mut report = String::new();
    for host in hosts {
        report.push_str(&format!("{host}: {}\n", blocked(&engine, host)));
    }
    println!("{report}");
    assert!(blocked(&engine, "doubleclick.net"), "doubleclick.net must be blocked");
    // `crashlytics.com` is not in the AdGuard DNS list (OISD covers it instead),
    // and `graph.facebook.com` must stay reachable for facebook.com to work.
    assert!(blocked(&engine, "app-measurement.com"), "app-measurement.com must be blocked");
    assert!(blocked(&engine, "sdk.appsflyer.com"), "sdk.appsflyer.com must be blocked");
    assert!(blocked(&engine, "adservice.google.com"), "adservice.google.com must be blocked");
    assert!(blocked(&engine, "adservice.google.com"), "adservice.google.com must be blocked");
    assert!(!blocked(&engine, "api.github.com"), "api.github.com must be allowed");
}
