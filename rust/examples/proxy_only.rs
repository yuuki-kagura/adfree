//! Raises the transparent proxy listeners without touching the firewall.
//!
//! `core_start_proxy` binds the TCP and DNS listeners before any nft rule is
//! installed, so this binary can exercise the MITM/splice paths against real
//! hosts while the machine's own traffic is left alone:
//!
//! ```sh
//! cargo run --release --example proxy_only -- 3129 5300 /tmp/adfree-proxy-only
//! curl --proxy http://127.0.0.1:3129 https://example.com/
//! ```
use std::path::Path;

fn main() {
    let mut args = std::env::args().skip(1);
    let tcp: u16 = args.next().and_then(|v| v.parse().ok()).unwrap_or(3129);
    let dns: u16 = args.next().and_then(|v| v.parse().ok()).unwrap_or(5300);
    let root = args.next().unwrap_or_else(|| "/tmp/adfree-proxy-only".into());

    if std::fs::create_dir_all(&root).is_err() {
        eprintln!("cannot create {root}");
        std::process::exit(1);
    }
    if !adfree_core::api::core_set_data_root(root.clone()) {
        eprintln!("data root refused: {root}");
    }
    let _ = adfree_core::api::core_start(0);
    let status = adfree_core::api::core_start_proxy(tcp, dns, false);
    println!(
        "running={} tcp={} dns={} tcp_error={:?} dns_error={:?} root={}",
        status.running, status.tcp_port, status.dns_port, status.tcp_error, status.dns_error,
        Path::new(&root).display()
    );
    if !status.running {
        std::process::exit(1);
    }
    // The host relays the core's log ring to the journal; print it here so a
    // splice decision is visible while the listeners are being exercised.
    loop {
        for line in adfree_core::api::core_take_log_lines() {
            println!("[core] {line}");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
