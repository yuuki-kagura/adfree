//! The forwarder's wait set, backed by `epoll`.
//!
//! `poll()` costs a walk of the whole descriptor array on every call, whether
//! anything is ready or not: measured on the Sony with 1729 descriptors in play,
//! it took 1.85 ms of CPU per pass and 82.5% of the forwarder's total.
//! `epoll_wait` costs what is ready instead, so the same pass spends its time on
//! the relays that actually moved bytes — 0.093 ms a pass at 1497 descriptors, the
//! same device, after this module went in — provided the interest set is kept
//! without re-asking the kernel for every descriptor on every pass, which is what
//! this module is about.
//!
//! The set is owned by the thread that waits on it. Registration is refreshed
//! once per pass, in [`WaitSet::sync`], from a fresh snapshot of the engine's
//! tables.

use std::collections::HashMap;
use crate::sys::fd::RawFd;

use crate::mitm::relay::RelayPoll;
use crate::udpnat::UdpPoll;
use crate::sys::libc;

/// Cap on how many descriptors one wait reports. Level-triggered, so whatever
/// is left over makes the next `epoll_wait` return at once; nothing is lost by
/// bounding one pass.
const MAX_READY: usize = 128;

/// What a registered descriptor is to the engine, carrying the snapshot the
/// dispatcher needs to service it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitEntry {
    /// The wake eventfd, poked by the encrypted-DNS and QUIC workers.
    Wake,
    /// An upstream DNS socket. Readiness only ends the wait; the reply is read
    /// by `Upstream::poll` at the top of the next pass.
    Dns,
    /// A relay's peer socket.
    Relay(RelayPoll),
    /// One NAT mapping's socket.
    Udp(UdpPoll),
}

impl WaitEntry {
    /// What the kernel is asked to watch for this descriptor, or 0 to leave it
    /// out of the set entirely.
    ///
    /// Zero happens for a paused relay with nothing queued towards its peer.
    /// Dropping it, rather than registering it with no events, matters:
    /// `EPOLLHUP` and `EPOLLERR` are reported whatever the mask says, so a peer
    /// that finished sending would wake the loop on every pass while its data
    /// sat unread in the kernel buffer.
    fn bits(&self) -> u32 {
        match *self {
            WaitEntry::Wake | WaitEntry::Dns | WaitEntry::Udp(_) => libc::EPOLLIN as u32,
            WaitEntry::Relay(p) => {
                let write = p.connecting || p.want_write;
                let listen = !p.paused;
                (if listen { libc::EPOLLIN } else { 0 }
                    | if write { libc::EPOLLOUT } else { 0 }) as u32
            }
        }
    }

    /// Which socket the engine thinks this descriptor is, when the engine can
    /// say.
    ///
    /// The relay and NAT tables stamp every socket with an instance token, and
    /// that token is the only proof that a registration still applies to the
    /// file behind a number: descriptors are recycled, and a `(descriptor,
    /// client port)` pair can come back describing a socket nobody has ever
    /// waited on. `None` covers the descriptors the engine does not stamp —
    /// the wake eventfd and the DNS sockets, which another thread may replace —
    /// and their registration is re-asserted on every pass instead.
    fn instance(&self) -> Option<u64> {
        match *self {
            WaitEntry::Wake | WaitEntry::Dns => None,
            WaitEntry::Relay(p) => Some(p.gen),
            WaitEntry::Udp(p) => Some(p.id),
        }
    }
}

/// A descriptor that answered the wait, and what the engine registered for it.
#[derive(Debug, Clone, Copy)]
pub struct Ready {
    pub entry: WaitEntry,
    /// `POLL*` bits, so the dispatchers need no translation of their own.
    pub revents: libc::c_short,
}

struct Slot {
    /// The snapshot this pass produced; readiness is dispatched from it, so it
    /// is refreshed even when the registration itself did not change.
    entry: WaitEntry,
    /// What the kernel is currently asked to watch for this descriptor.
    bits: u32,
    /// Instance token of the file the registration was made for.
    instance: Option<u64>,
    /// `WaitSet::stamp` at the pass this descriptor last appeared in a
    /// snapshot; anything older is unregistered.
    stamp: u32,
}

/// The interest table's hasher: one multiply, no SipHash.
///
/// The keys are descriptor numbers — 3, 4, 5, …, handed out in sequence and
/// reused as soon as a flow closes — and the table is looked up once per relay
/// on every pass, which is the cost this saves. `RawFd`'s own `Hash` goes to the
/// default hasher, which exists to survive an adversary choosing its keys;
/// nothing chooses these but the kernel. Dropping the hash to one multiply is
/// safe *and* better distributed: the bucket index reads the low bits and the
/// group tag the top seven, so descriptors left as themselves share a tag and
/// lengthen every probe chain, while a multiply by the golden ratio spreads
/// both ends.
#[derive(Default)]
struct FdHasher(u64);

const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

impl std::hash::Hasher for FdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ *byte as u64).wrapping_mul(GOLDEN);
        }
    }

    fn write_i32(&mut self, value: i32) {
        self.0 = (value as u32 as u64).wrapping_mul(GOLDEN);
    }
}

type FdTable<S> = HashMap<RawFd, S, std::hash::BuildHasherDefault<FdHasher>>;

pub struct WaitSet {
    /// The `epoll` instance: a real one on Unix, a wepoll (IOCP) one on
    /// Windows. Both are reached through `sys::fd`, so this file is the same
    /// code on either platform.
    ep: crate::sys::fd::Epoll,
    interest: FdTable<Slot>,
    /// Incremented per `sync`; a slot carrying the current stamp survived it.
    stamp: u32,
    /// Slots that carried the current stamp, counted as they got it. `sync` uses
    /// the count to decide whether a descriptor can have gone stale; see
    /// [`WaitSet::drop_gone`].
    stamped: usize,
    /// `epoll_ctl` calls issued so far. An unchanged pass issues none, which is
    /// the reason the set is cheaper than `poll()`; growth says the traffic is
    /// churning its relays, and then the saving is smaller.
    ops: u64,
    events: Vec<libc::epoll_event>,
    ready: Vec<Ready>,
}

/// `epoll`'s ready bits are the `poll` bits the engine's dispatchers read, but
/// the two constants come from different headers and some of them differ, so
/// the mapping is spelled out rather than assumed.
fn poll_revents(events: u32) -> libc::c_short {
    let mut bits: libc::c_int = 0;
    for (ep, poll) in [
        (libc::EPOLLIN, libc::POLLIN),
        (libc::EPOLLPRI, libc::POLLPRI),
        (libc::EPOLLOUT, libc::POLLOUT),
        (libc::EPOLLERR, libc::POLLERR),
        (libc::EPOLLHUP, libc::POLLHUP),
        (libc::EPOLLRDHUP, libc::POLLRDHUP),
    ] {
        if events & ep as u32 != 0 {
            bits |= poll as libc::c_int;
        }
    }
    bits as libc::c_short
}

impl Default for WaitSet {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitSet {
    pub fn new() -> Self {
        Self {
            ep: crate::sys::fd::epoll_create1(libc::EPOLL_CLOEXEC),
            interest: FdTable::default(),
            stamp: 0,
            stamped: 0,
            ops: 0,
            events: vec![
                libc::epoll_event { events: 0, u64: 0 };
                MAX_READY
            ],
            ready: Vec::with_capacity(MAX_READY),
        }
    }

    /// Descriptors the set is watching. Used by the forwarder's instrumentation
    /// and the tests; the engine itself never needs it.
    pub fn watched(&self) -> usize {
        self.interest.len()
    }

    /// How many `epoll_ctl` calls the set has issued.
    pub fn ops(&self) -> u64 {
        self.ops
    }

    /// Makes the set match one snapshot of the engine's tables.
    ///
    /// A descriptor whose instance token and interest mask are unchanged costs
    /// one hash lookup and no syscall, which is why the steady part of a busy
    /// tunnel is free here: relays that are only reading keep the registration
    /// they already have.
    ///
    /// What is left per row is that one lookup. A pass whose snapshot held every
    /// registration it already had has nothing to reap, and `stamped` says so
    /// without looking: see [`WaitSet::drop_gone`].
    pub fn sync(
        &mut self,
        wake_fd: RawFd,
        dns: &[RawFd],
        relays: &[RelayPoll],
        udp: &[UdpPoll],
    ) {
        self.stamp += 1;
        self.stamped = 0;
        if crate::sys::fd::fd_ok(wake_fd) {
            self.reconcile(wake_fd, WaitEntry::Wake);
        }
        for fd in dns {
            self.reconcile(*fd, WaitEntry::Dns);
        }
        for p in relays {
            self.reconcile(p.fd, WaitEntry::Relay(*p));
        }
        for p in udp {
            self.reconcile(p.fd, WaitEntry::Udp(*p));
        }
        if self.stamped != self.interest.len() {
            self.drop_gone();
        }
    }

    /// Blocks until something is ready or `timeout_ms` passes.
    ///
    /// The returned slice borrows the set, so the caller dispatches from it
    /// before syncing again.
    pub fn wait(&mut self, timeout_ms: libc::c_int) -> &[Ready] {
        self.ready.clear();
        if !crate::sys::fd::epoll_ok(self.ep) {
            // `epoll_create1` failed once, at startup (descriptor exhaustion is
            // the only error it can return here, and an engine that cannot
            // create an epoll fd cannot create flow sockets either). Nothing
            // can report readiness without one, so hold the pass for its
            // cadence rather than spinning the loop.
            if timeout_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(timeout_ms as u64));
            }
            return &self.ready;
        }
        let n = crate::sys::fd::epoll_wait(self.ep, &mut self.events, timeout_ms);
        if n <= 0 {
            return &self.ready;
        }
        for ev in &self.events[..n as usize] {
            // `epoll_event` is `repr(packed)` on x86_64 Linux: copy the fields
            // out rather than borrowing them. (`sys::fd` keeps the Windows
            // shape in step with wepoll's C struct.)
            let (bits, data) = (ev.events, ev.u64);
            let Some(slot) = self.interest.get(&(data as RawFd)) else {
                continue;
            };
            self.ready.push(Ready {
                entry: slot.entry,
                revents: poll_revents(bits),
            });
        }
        &self.ready
    }

    /// Brings one descriptor's registration in line with what the engine wants
    /// from it now.
    ///
    /// Counts the slot as seen for this pass the first time the pass touches it,
    /// which is what lets [`WaitSet::sync`] skip the reap when nothing went
    /// missing: two snapshot rows on one descriptor must not read as two.
    fn reconcile(&mut self, fd: RawFd, entry: WaitEntry) {
        let (ep, stamp) = (self.ep, self.stamp);
        let bits = entry.bits();
        if bits == 0 {
            // Left out of the set; `drop_gone` unregisters it if it was in.
            return;
        }
        let instance = entry.instance();
        let mut forget = false;
        let mut seen = false;
        if let Some(slot) = self.interest.get_mut(&fd) {
            seen = slot.stamp != stamp;
            slot.stamp = stamp;
            slot.entry = entry;
            if slot.instance.is_some() && slot.instance == instance {
                // The same socket, so the registration is still its own; only a
                // changed mask has to reach the kernel.
                if slot.bits != bits && ctl(ep, libc::EPOLL_CTL_MOD, fd, bits, &mut self.ops) != 0 {
                    forget = true;
                } else {
                    slot.bits = bits;
                }
            } else {
                // A different socket on this number, or one the engine cannot
                // identify. `EPOLL_CTL_MOD` is the wrong call: the registration
                // on file may belong to a socket that is already closed, and
                // modifying would either fail or change some other owner's
                // interest. Drop it, then register this file from scratch.
                // Descriptors with no instance token land here every pass, which
                // is the price of not being able to prove anything about them —
                // the engine's own two or three, not the thousands of relays.
                let _ = ctl(ep, libc::EPOLL_CTL_DEL, fd, 0, &mut self.ops);
                if ctl(ep, libc::EPOLL_CTL_ADD, fd, bits, &mut self.ops) == 0 {
                    slot.bits = bits;
                    slot.instance = instance;
                } else {
                    forget = true;
                }
            }
        } else if ctl(ep, libc::EPOLL_CTL_ADD, fd, bits, &mut self.ops) == 0 {
            seen = true;
            self.interest.insert(
                fd,
                Slot {
                    entry,
                    bits,
                    instance,
                    stamp,
                },
            );
        }
        if seen {
            self.stamped += 1;
        }
        if forget {
            self.interest.remove(&fd);
        }
    }

    /// Unregisters descriptors the snapshot no longer contains: closed relays,
    /// retired NAT mappings, replaced DNS sockets.
    ///
    /// This is a second walk of everything the set holds, so `sync` calls it only
    /// when the pass left a slot untouched: `stamped` counts the distinct slots
    /// that carry this pass's stamp, so a count short of the table's length names
    /// exactly the descriptors that have to go, and a count that matches it means
    /// the walk would delete nothing. A failed `epoll_ctl` can drop a slot it had
    /// already counted, which lands on the safe side of the test — the walk runs.
    fn drop_gone(&mut self) {
        let (ep, stamp) = (self.ep, self.stamp);
        let mut gone = 0u64;
        self.interest.retain(|fd, slot| {
            if slot.stamp == stamp {
                return true;
            }
            let _ = ctl(ep, libc::EPOLL_CTL_DEL, *fd, 0, &mut gone);
            false
        });
        self.ops += gone;
    }
}

/// One `epoll_ctl`, counted: a pass that issues none is a pass whose relays
/// kept the interest they already had.
fn ctl(
    ep: crate::sys::fd::Epoll,
    op: libc::c_int,
    fd: RawFd,
    bits: u32,
    ops: &mut u64,
) -> libc::c_int {
    *ops += 1;
    if !crate::sys::fd::epoll_ok(ep) {
        return -1;
    }
    let mut ev = libc::epoll_event {
        events: bits,
        // The payload is `u64` on both kernels: on Unix a descriptor is an
        // `i32` and widens, on Windows a `SOCKET` already is one.
        u64: fd as _,
    };
    crate::sys::fd::epoll_ctl(ep, op, fd, &mut ev)
}

impl Drop for WaitSet {
    fn drop(&mut self) {
        if crate::sys::fd::epoll_ok(self.ep) {
            crate::sys::fd::epoll_close(self.ep);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A descriptor pair the loop can register without any engine state behind
    /// it: readiness on the read end is a write to the write end. Both ends are
    /// closed on drop, the way the engine's one-descriptor-per-socket relays
    /// are, so nothing stays registered behind the test.
    struct Pipe {
        read: RawFd,
        write: RawFd,
    }

    impl Pipe {
        fn new() -> Self {
            let mut fds = [0 as RawFd; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            Self {
                read: fds[0],
                write: fds[1],
            }
        }

        fn poke(&self) {
            let buf = [0u8; 1];
            assert_eq!(
                unsafe { libc::write(self.write, buf.as_ptr() as *const libc::c_void, 1) },
                1
            );
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.read);
                libc::close(self.write);
            }
        }
    }

    fn relay(gen: u64, fd: RawFd) -> RelayPoll {
        RelayPoll {
            gen,
            client_port: 1234,
            fd,
            connecting: false,
            want_write: false,
            paused: false,
        }
    }

    fn udp(fd: RawFd) -> UdpPoll {
        use std::net::Ipv4Addr;
        UdpPoll {
            id: 7,
            key: crate::udpnat::UdpKey {
                client: crate::packet::IpKey::V4(u32::from(Ipv4Addr::new(10, 0, 0, 2))),
                client_port: 40000,
                server: crate::packet::IpKey::V4(u32::from(Ipv4Addr::new(9, 9, 9, 9))),
                server_port: 53,
            },
            fd,
        }
    }

    #[test]
    fn a_steady_descriptor_costs_no_syscall() {
        let pipe = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[], &[relay(1, pipe.read)], &[]);
        assert_eq!(set.watched(), 1);
        let ops = set.ops();
        set.sync(-1, &[], &[relay(1, pipe.read)], &[]);
        assert_eq!(set.ops(), ops, "unchanged registration was re-issued");
        assert_eq!(set.watched(), 1);
    }

    #[test]
    fn a_changed_mask_modifies_the_registration() {
        let pipe = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[], &[relay(1, pipe.read)], &[]);
        let ops = set.ops();
        let mut writing = relay(1, pipe.read);
        writing.want_write = true;
        set.sync(-1, &[], &[writing], &[]);
        assert_eq!(set.ops(), ops + 1, "a mask change should cost one EPOLL_CTL_MOD");
        assert_eq!(set.interest[&pipe.read].instance, Some(1));
    }

    #[test]
    fn the_same_descriptor_with_a_new_socket_is_re_registered() {
        // The hazard `EPOLL_CTL_MOD` would get wrong: the number survived, the
        // file behind it did not.
        let pipe = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[], &[relay(1, pipe.read)], &[]);
        let ops = set.ops();
        set.sync(-1, &[], &[relay(2, pipe.read)], &[]);
        assert_eq!(set.ops(), ops + 2, "expected one DEL and one ADD");
        assert_eq!(set.interest[&pipe.read].instance, Some(2));
        // And a new socket on the same number with the same mask is still
        // re-registered, which is what an unproven registration can never be.
        set.sync(-1, &[], &[relay(3, pipe.read)], &[]);
        assert_eq!(set.interest[&pipe.read].instance, Some(3));
    }

    #[test]
    fn a_descriptor_the_snapshot_dropped_is_unregistered() {
        let kept = Pipe::new();
        let gone = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[], &[relay(1, kept.read), relay(2, gone.read)], &[]);
        assert_eq!(set.watched(), 2);
        set.sync(-1, &[], &[relay(1, kept.read)], &[]);
        assert_eq!(set.watched(), 1);
        assert!(set.interest.contains_key(&kept.read));
    }

    #[test]
    fn one_descriptor_is_one_slot_however_many_rows_carry_it() {
        // The reap is skipped when the pass touched as many slots as the table
        // holds, so counting the same descriptor twice would hide the stale one.
        let kept = Pipe::new();
        let gone = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[], &[relay(1, kept.read), relay(2, gone.read)], &[]);
        assert_eq!(set.watched(), 2);
        set.sync(-1, &[], &[relay(1, kept.read), relay(1, kept.read)], &[]);
        assert_eq!(set.watched(), 1, "a double row defeated the reap");
    }

    #[test]
    fn a_paused_relay_leaves_the_set_entirely() {
        let pipe = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[], &[relay(1, pipe.read)], &[]);
        assert_eq!(set.watched(), 1);
        let mut paused = relay(1, pipe.read);
        paused.paused = true;
        set.sync(-1, &[], &[paused], &[]);
        assert_eq!(set.watched(), 0, "a paused relay must not be registered");
        // Write interest alone keeps it, with the read mask off: it is the
        // always-reported EPOLLHUP that has to be avoided, not the descriptor.
        paused.want_write = true;
        set.sync(-1, &[], &[paused], &[]);
        assert_eq!(set.watched(), 1);
    }

    #[test]
    fn an_unproven_registration_is_re_asserted_every_pass() {
        // The wake eventfd and the DNS sockets are the two the engine does not
        // stamp, and another thread may hand the number to a different file.
        let pipe = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[pipe.read], &[], &[]);
        let ops = set.ops();
        set.sync(-1, &[pipe.read], &[], &[]);
        assert!(set.ops() > ops, "a DNS socket was trusted without a token");
        assert_eq!(set.watched(), 1);
    }

    #[test]
    fn readiness_carries_the_registered_entry() {
        let pipe = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[], &[relay(1, pipe.read)], &[]);
        pipe.poke();
        let ready = set.wait(0);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].entry, WaitEntry::Relay(relay(1, pipe.read)));
        assert_eq!(ready[0].revents & libc::POLLIN, libc::POLLIN);
    }

    #[test]
    fn a_wait_with_nothing_ready_returns_the_timeout() {
        let mut set = WaitSet::new();
        let started = std::time::Instant::now();
        assert!(set.wait(40).is_empty());
        assert!(started.elapsed() >= std::time::Duration::from_millis(30));
    }

    #[test]
    fn epoll_bits_map_to_the_poll_bits_the_dispatchers_read() {
        assert_eq!(
            poll_revents(libc::EPOLLIN as u32),
            libc::POLLIN as libc::c_short
        );
        assert_eq!(
            poll_revents((libc::EPOLLOUT | libc::EPOLLHUP) as u32),
            (libc::POLLOUT | libc::POLLHUP) as libc::c_short
        );
        assert_eq!(poll_revents(0), 0);
    }

    #[test]
    fn a_reclosed_descriptor_leaves_no_registration_behind() {
        // The kernel drops the file from the interest list when its last
        // descriptor closes, which is what the engine relies on for every flow
        // it reaps between two snapshots. Whatever takes the number next is
        // registered afresh and reported for itself.
        let first = Pipe::new();
        let mut set = WaitSet::new();
        set.sync(-1, &[first.read], &[], &[]);
        assert_eq!(set.watched(), 1);
        drop(first);

        let second = Pipe::new();
        set.sync(-1, &[], &[], &[udp(second.read)]);
        assert_eq!(set.watched(), 1);
        assert_eq!(
            set.interest[&second.read].entry,
            WaitEntry::Udp(udp(second.read))
        );
        second.poke();
        let ready = set.wait(0);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].entry, WaitEntry::Udp(udp(second.read)));
    }

    /// CPU this thread spent, not the wall clock it slept — the same clock the
    /// forwarder's instrumentation used, kept here so the measurement below has
    /// no dependency on code that only exists to be measured.
    fn thread_cpu_ns() -> u64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }

    /// One pass of the forwarder's wait, with nothing ready: the `poll()` the
    /// loop used to run against the set that replaced it, same descriptors.
    ///
    /// Ignored because it opens a thousand descriptors and costs a second of
    /// CPU. Run it with
    /// `cargo test --release --lib waitset -- --ignored --nocapture`; the numbers
    /// it prints are the ones `BENCHMARK.md` quotes.
    #[test]
    #[ignore = "opens 1024 descriptors and costs about a second of CPU"]
    fn one_pass_of_the_wait_against_one_pass_of_the_poll() {
        const N: usize = 1024;
        const PASSES: usize = 4096;

        let fds: Vec<RawFd> = (0..N)
            .map(|_| unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) })
            .collect();
        assert!(
            fds.iter().all(|fd| crate::sys::fd::fd_ok(*fd)),
            "eventfd ran out of descriptors: {}",
            std::io::Error::last_os_error()
        );
        let relays: Vec<RelayPoll> = fds
            .iter()
            .enumerate()
            .map(|(i, fd)| relay(i as u64 + 1, *fd))
            .collect();

        let mut set = WaitSet::new();
        set.sync(-1, &[], &relays, &[]);
        assert_eq!(set.watched(), N);
        let base_ops = set.ops();

        // Split, because the halves answer different questions: the wait says
        // whether `epoll_wait` really costs what is ready rather than what is
        // registered, and the two walks say what the Rust side pays per entry,
        // with and without the scan for entries the snapshot stopped reporting.
        // The minimum of five trials, because the same machine under load priced
        // one of these walks at twice what it priced it at unloaded.
        const TRIALS: usize = 5;
        let trial = |run: &mut dyn FnMut()| -> u64 {
            let mut min = u64::MAX;
            for _ in 0..TRIALS {
                let t0 = thread_cpu_ns();
                run();
                let ns = thread_cpu_ns() - t0;
                if ns < min {
                    min = ns;
                }
            }
            min
        };

        let wait_ns = trial(&mut || {
            for _ in 0..PASSES {
                set.wait(0);
            }
        });
        // The walk as `sync` runs it on a steady pass: every entry looked at, and
        // no second sweep of the table to find what is missing, because the slot
        // count already said nothing is.
        let sync_ns = trial(&mut || {
            for _ in 0..PASSES {
                set.sync(-1, &[], &relays, &[]);
            }
        });
        // The same walk with that sweep forced back in, which is the shape
        // `sync` had before the count: the difference is the guard's saving, as a
        // measurement rather than as an argument about stamping.
        let reaped_ns = trial(&mut || {
            for _ in 0..PASSES {
                set.stamp += 1;
                set.stamped = 0;
                for p in &relays {
                    set.reconcile(p.fd, WaitEntry::Relay(*p));
                }
                set.drop_gone();
            }
        });
        // A steady set is a set that issues no syscalls: everything the pass
        // re-reads, it re-reads from its own table.
        assert_eq!(
            set.ops() - base_ops,
            0,
            "the steady passes issued epoll_ctl work"
        );

        // A steady set is a set that issues no syscalls: everything the pass
        // re-reads, it re-reads from its own table.
        assert_eq!(
            set.ops() - base_ops,
            0,
            "the steady passes issued epoll_ctl work"
        );

        let poll_ns = trial(&mut || {
            for _ in 0..PASSES {
                // The old loop rebuilt the array every pass, so the rebuild is
                // part of what is being compared — and left out here would
                // flatter it.
                let mut pfds: Vec<libc::pollfd> = relays
                    .iter()
                    .map(|r| libc::pollfd {
                        fd: r.fd,
                        events: libc::POLLIN as libc::c_short,
                        revents: 0,
                    })
                    .collect();
                let n = pfds.len() as libc::nfds_t;
                std::hint::black_box(unsafe { libc::poll(pfds.as_mut_ptr(), n, 0) });
            }
        });

        println!(
            "nfds={N} passes={PASSES}: poll {:.1} us/pass | wait {:.1} + sync {:.1} (with the forced reap {:.1}) = {:.1} us/pass ({:.2}x)",
            poll_ns as f64 / PASSES as f64 / 1000.0,
            wait_ns as f64 / PASSES as f64 / 1000.0,
            sync_ns as f64 / PASSES as f64 / 1000.0,
            reaped_ns as f64 / PASSES as f64 / 1000.0,
            (wait_ns + sync_ns) as f64 / PASSES as f64 / 1000.0,
            poll_ns as f64 / ((wait_ns + sync_ns).max(1) as f64),
        );

        for fd in fds {
            unsafe { libc::close(fd) };
        }
    }
}
