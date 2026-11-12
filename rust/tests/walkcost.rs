//! How much of a forwarder pass is the tables' own shape.
//!
//! `epoll` took the kernel's scan out of the wait (`BENCHMARK.md`), and what is
//! left is two O(relays) walks: `poll_snapshot()` on the relay and NAT tables,
//! and `WaitSet::sync` over the snapshot it produced. Measured on the phone they
//! cost 0.255 ms and 0.253 ms per pass at 1497 descriptors — together now the
//! largest item in the pass. This asks which of their two shapes they are: bytes
//! moved per entry, or per-entry logic.
//!
//! The answer it gave, and the design decision resting on it: a `Relay` is 1056
//! bytes and a `UdpFlow` 176, and the relay walk is the *cheaper* of the two per
//! entry — 31 ns against 40 on the same machine, the same ratio the loaded run
//! showed. Nothing about the bytes moves, so grouping fields into one cache line
//! (`#[repr(C)]`) would buy exactly nothing, and the only way to make a pass
//! cheaper is to walk fewer entries or fewer times.
//!
//! `cargo test --release --test walkcost -- --ignored --nocapture`

// These tests drive the tun-side engine — epoll, raw descriptors, the
// `std::os::fd` types — so they are Unix tests by construction. Windows reaches
// the same filtering through the WinDivert redirect (`src/winnat.rs`), which has
// its own tests and never sees these packets.
#![cfg(unix)]

use std::os::fd::RawFd;
use std::time::Instant;

use adfree_core::mitm::relay::{Relay, RelayPoll, RelayTable};
use adfree_core::mitm::tcp::Flow;
use adfree_core::packet::IpKey;
use adfree_core::udpnat::{UdpFlow, UdpKey, UdpNat, UdpPoll};
use adfree_core::waitset::WaitSet;

/// The mix the phone's `nudge2048` window showed: 284 live TCP relays inside a
/// wait set of 1497 descriptors, so the rest are datagram mappings.
const RELAYS: usize = 284;
const MAPPINGS: usize = 1200;
const PASSES: usize = 512;

fn pair() -> (RawFd, RawFd) {
    let mut fds = [-1; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    assert_eq!(rc, 0, "socketpair failed: {}", std::io::Error::last_os_error());
    (fds[0], fds[1])
}

fn fill(relays: &mut RelayTable, nat: &mut UdpNat, peers: &mut Vec<RawFd>) {
    for i in 0..RELAYS {
        let (fd, peer) = pair();
        peers.push(peer);
        let flow = Flow::new(IpKey::V4(1), 40000 + i as u16, 80, 1000, 5000);
        relays.insert(Relay::new_plain(
            flow,
            fd,
            Vec::new(),
            1360,
            false,
        ));
    }
    for i in 0..MAPPINGS {
        let (fd, peer) = pair();
        peers.push(peer);
        let key = UdpKey {
            client: IpKey::V4(1),
            client_port: 41000 + i as u16,
            server: IpKey::V4(0x0808_0808),
            server_port: 443,
        };
        nat.insert(UdpFlow {
            fd,
            key,
            template: Vec::new(),
            last_ms: 0,
            app_packages: Vec::new(),
            retire: false,
            proxied: false,
            sent: 0,
            recv: 0,
            traffic: None,
            id: 0,
        });
    }
}

#[test]
#[ignore = "opens about three thousand descriptors and costs seconds of CPU"]
fn the_two_walks_priced_separately() {
    let mut relays = RelayTable::new();
    let mut nat = UdpNat::new();
    let mut peers = Vec::new();
    fill(&mut relays, &mut nat, &mut peers);
    let mut set = WaitSet::new();

    // Five trials of each, and the minimum is the number. The same machine under
    // load gave 66 ns a relay and unloaded 31 ns for the identical walk, so an
    // average over one run answers nothing about whether a change helped.
    const TRIALS: usize = 5;
    let best = |run: &mut dyn FnMut()| -> f64 {
        let mut min = f64::MAX;
        for _ in 0..TRIALS {
            let t = Instant::now();
            run();
            let ns = t.elapsed().as_nanos() as f64 / PASSES as f64;
            if ns < min {
                min = ns;
            }
        }
        min
    };

    let relay_walk = best(&mut || {
        for _ in 0..PASSES {
            let v = relays.poll_snapshot();
            std::hint::black_box(&v);
        }
    });

    let udp_walk = best(&mut || {
        for _ in 0..PASSES {
            let v = nat.poll_snapshot();
            std::hint::black_box(&v);
        }
    });

    // The two snapshots together, then the sync they feed, which is what the
    // pass actually pays.
    let both = best(&mut || {
        for _ in 0..PASSES {
            let r = relays.poll_snapshot();
            let u = nat.poll_snapshot();
            set.sync(-1, &[], &r, &u);
            std::hint::black_box(set.watched());
        }
    });

    let rows = RELAYS + MAPPINGS;
    let sync_alone = both - relay_walk - udp_walk;

    // What the two snapshots' allocator is worth on its own, because it is the
    // one part of the walk a caller could remove without changing what the walks
    // look at: `collect()` on a table iterator asks for the table's length up
    // front, so a pass buys both buffers and hands them back.
    let alloc = best(&mut || {
        for _ in 0..PASSES {
            let a: Vec<RelayPoll> = Vec::with_capacity(RELAYS);
            let b: Vec<UdpPoll> = Vec::with_capacity(MAPPINGS);
            std::hint::black_box(a);
            std::hint::black_box(b);
        }
    });

    println!(
        "{RELAYS} relays x {} B: snapshot {relay_walk:.0} ns/pass = {:.1} ns/relay",
        std::mem::size_of::<Relay>(),
        relay_walk / RELAYS as f64,
    );
    println!(
        "{MAPPINGS} mappings x {} B: snapshot {udp_walk:.0} ns/pass = {:.1} ns/mapping",
        std::mem::size_of::<UdpFlow>(),
        udp_walk / MAPPINGS as f64,
    );
    println!(
        "both snapshots + sync over {rows} rows: {both:.0} ns/pass, sync alone {sync_alone:.0} ns = {:.1} ns/row",
        sync_alone / rows as f64,
    );
    println!(
        "the two buffers alone, bought and handed back: {alloc:.0} ns/pass = {:.1} ns/row",
        alloc / rows as f64,
    );
    assert_eq!(set.watched(), rows, "the set lost track of rows");
}
