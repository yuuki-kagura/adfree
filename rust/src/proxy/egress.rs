//! What the proxy's own dials say this machine can carry on IPv6.
//!
//! A redirect does not ask the client which family it chose. An IPv6 flow
//! arrives at the dual-stack listener like any other (`tcp::bind_listener`),
//! `SO_ORIGINAL_DST` names a real global address, and the only way on is to
//! dial IPv6. When this machine's v6 default route is a black hole — a tunnel
//! interface that is up but carries nothing, which is what was measured here —
//! the SYN the client sent has already been answered *locally*, and that is
//! precisely what ends its happy-eyeballs race: having won the connection, the
//! client now waits while the proxy spends [`super::CONNECT_TIMEOUT`] on a
//! dial that cannot land, and gets a reset instead of a page. Without AdFree
//! the same client loses the v6 attempt in milliseconds and loads the site
//! over IPv4. Measured: 10 s and exit 35 with the rules installed, 0.59–1.19 s
//! and 200 without them.
//!
//! So the repair belongs in the lookup rather than the connection, because the
//! lookup is where the family gets chosen: once enough dials have failed in the
//! ways only the machine itself explains, the DNS half stops handing out AAAA
//! records, clients ask for A, and the black hole is never entered. The verdict
//! is held proxy-side on purpose — the tun path gets its addresses from the
//! platform's own network stack and has no part in this.
//!
//! Three things keep that honest, and each is the reason for a threshold:
//!
//! * only failures the machine owns (`Failure::Timeout`,
//!   `Failure::Unreachable`) count; a peer that refuses (`ECONNREFUSED`) says
//!   something about that peer, and acting on it would downgrade the whole
//!   machine to IPv4 because one CDN's v6 broke;
//! * [`FAILURE_THRESHOLD`] of them inside [`FAILURE_WINDOW_MS`] — one site's
//!   slow v6 is not a verdict about this host;
//! * the address has to be a global one to count at all
//!   ([`is_egress_evidence`]): a `fe80::` peer that answers while the tunnel is
//!   a black hole says nothing about egress and must not undo the verdict;
//! * the suppression *expires*, and the query that falls out of the expiry is
//!   answered normally, so a real dial gets to prove the tunnel back. A v6 dial
//!   that succeeds clears everything at once. The window doubles per failed
//!   re-probe up to [`MAX_SUPPRESS_MS`], which bounds the one bad request a
//!   probe costs a machine that genuinely has no IPv6.
//!
//! The same verdict also spares the connections it cannot help: while it is
//! held and no re-probe is outstanding, [`Egress::dial_worth_making`] refuses
//! the IPv6 dial instead of spending the connect budget on an answer that is
//! already known — the flows left are the ones holding a record cached before
//! the verdict, and they are better off reset and retried over IPv4.
//!
//! One way out is left alone: an `HTTPS` answer carrying an `ipv6hint` still
//! names an IPv6 address a client may try. Stripping the hint means parsing
//! SvcParams on the forward path, and a client that follows one gets the same
//! reset the record would have caused — the stall, not the filtering, is what
//! this verdict is for.

use std::sync::Mutex;

/// Machine-level IPv6 dial failures it takes to stop handing out AAAA records.
/// The proxy is the only witness here, and three in a row inside the window is
/// the machine talking rather than one host.
const FAILURE_THRESHOLD: u32 = 3;

/// Failures further apart than this are not one pattern about the current
/// network: a connection that dropped over an hour ago says nothing about
/// whether IPv6 works now.
const FAILURE_WINDOW_MS: u64 = 60_000;

/// How long the first suppression lasts. Short because the dial that follows
/// it is the evidence: the cost of being wrong in either direction is one
/// connection, not one browsing session.
const BASE_SUPPRESS_MS: u64 = 30_000;

/// The ceiling for the re-probe interval. Beyond this an outage would be
/// noticed too slowly to be called self-healing, and the traffic the proxy
/// would rather have filtered is the traffic a silent IPv6 keeps to itself.
const MAX_SUPPRESS_MS: u64 = 10 * 60_000;

/// Why a dial failed, as far as this verdict is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The packets left and nothing came back in time. On a machine whose v6
    /// route leads into a dead tunnel this is the only answer it can give.
    Timeout,
    /// The kernel refused before sending: no route, no address, no such family.
    Unreachable,
    /// The peer said no (`ECONNREFUSED`) or the reason is somebody else's.
    /// Deliberately not evidence about this machine.
    Elsewhere,
}

impl Failure {
    /// The split the verdict cares about, from the errno the dial carried.
    pub fn from_errno(errno: i32) -> Failure {
        match errno {
            libc::ETIMEDOUT => Failure::Timeout,
            libc::ENETUNREACH
            | libc::EHOSTUNREACH
            | libc::ENETDOWN
            | libc::ENODEV
            | libc::EADDRNOTAVAIL
            | libc::EAFNOSUPPORT
            | libc::EPERM => Failure::Unreachable,
            _ => Failure::Elsewhere,
        }
    }
}

/// What one dial changed, so the callers can log a verdict rather than a row
/// per connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum News {
    /// Nothing worth saying.
    None,
    /// AAAA answers have started being withheld: the machine cannot carry IPv6.
    Suppressed { window_ms: u64 },
    /// AAAA answers have stopped being withheld: it can.
    Restored,
    /// Still withheld, and the re-probe window moved.
    Extended { window_ms: u64 },
}

/// The verdict itself, as a function of a clock the tests get to choose.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Egress {
    /// Machine-level failures counted inside the window starting at
    /// `counted_ms`.
    failures: u32,
    counted_ms: u64,
    /// Epoch ms until which AAAA records are withheld.
    suppressed_until_ms: u64,
    /// Current suppression length; `0` until the first one sets the base.
    window_ms: u64,
    /// A suppression has ended and the verdict is waiting for the dial its
    /// re-probe produces: queries are answered normally until then.
    probing: bool,
}

/// The starting verdict: nothing seen, nothing believed. A `const` because the
/// static below cannot call `Default`.
const IDLE: Egress = Egress {
    failures: 0,
    counted_ms: 0,
    suppressed_until_ms: 0,
    window_ms: 0,
    probing: false,
};

impl Egress {
    /// The proxy reached an IPv6 address. Whatever was believed before, this
    /// machine can carry IPv6 right now.
    pub fn note_v6_success(&mut self, now_ms: u64) -> News {
        let was = self.suppressed(now_ms) || self.probing;
        *self = IDLE;
        if was {
            News::Restored
        } else {
            News::None
        }
    }

    /// The proxy could not reach an IPv6 address.
    pub fn note_v6_failure(&mut self, now_ms: u64, kind: Failure) -> News {
        if kind == Failure::Elsewhere {
            return News::None;
        }
        if self.suppressed(now_ms) || self.probing {
            // The re-probe answered — or a flow that already held the address
            // failed while the records were still being withheld, which is
            // what the suppression predicted. Either way the verdict stands and
            // the next chance comes later.
            self.probing = false;
            self.failures = FAILURE_THRESHOLD;
            self.window_ms = self.next_window();
            self.suppressed_until_ms = now_ms.saturating_add(self.window_ms);
            return News::Extended {
                window_ms: self.window_ms,
            };
        }
        if self.failures > 0 && now_ms.saturating_sub(self.counted_ms) > FAILURE_WINDOW_MS {
            self.failures = 0;
        }
        if self.failures == 0 {
            self.counted_ms = now_ms;
        }
        self.failures += 1;
        if self.failures < FAILURE_THRESHOLD {
            return News::None;
        }
        self.window_ms = self.next_window();
        self.suppressed_until_ms = now_ms.saturating_add(self.window_ms);
        News::Suppressed {
            window_ms: self.window_ms,
        }
    }

    /// Should this AAAA query be answered without records?
    ///
    /// False also once the suppression has expired, and the expiry is not a
    /// quiet return to normal: `probing` is armed here, so the queries that
    /// follow are the re-probe and the next dial's outcome decides the verdict.
    /// A machine that never had an outage has nothing to re-probe (`0` in
    /// `suppressed_until_ms`), so one early failure still has to be counted
    /// three times like any other.
    pub fn withhold_aaaa(&mut self, now_ms: u64) -> bool {
        if self.suppressed(now_ms) {
            return true;
        }
        if self.suppressed_until_ms != 0 {
            self.probing = true;
        }
        false
    }

    fn suppressed(&self, now_ms: u64) -> bool {
        self.suppressed_until_ms > now_ms
    }

    /// Should an IPv6 dial be made at all?
    ///
    /// While the verdict is held and no re-probe is outstanding the outcome is
    /// already known, and the flow asking for it is one the client should not
    /// have tried — a `AAAA` record cached before the verdict, or a literal
    /// address in a config. Making the dial costs the full connect budget on a
    /// connection thread for an answer nobody doubts; refusing it gives the
    /// client a reset it can move on from, which is the family the lookup has
    /// already steered it to. While probing the dial is exactly the point, so
    /// it is made.
    pub fn dial_worth_making(&self, now_ms: u64) -> bool {
        self.probing || !self.suppressed(now_ms)
    }

    fn next_window(&self) -> u64 {
        match self.window_ms {
            0 => BASE_SUPPRESS_MS,
            w => w.saturating_mul(2).min(MAX_SUPPRESS_MS),
        }
    }
}

static V6: Mutex<Egress> = Mutex::new(IDLE);

/// Does a dial of this address say anything about carrying IPv6 *off* the
/// machine? Loopback, link-local and unique-local answers are made without
/// the global route, so they prove nothing about it: a NAS on `fe80::` that
/// replies while the tunnel is a black hole must not hand every host its AAAA
/// record back, and a global address that times out is the evidence.
pub fn is_egress_evidence(addr: std::net::SocketAddr) -> bool {
    let std::net::IpAddr::V6(v6) = addr.ip() else {
        return false;
    };
    !(v6.is_loopback()
        || v6.is_unicast_link_local()
        || (v6.segments()[0] & 0xfe00) == 0xfc00)
}

/// Reports the outcome of one dial. Only global IPv6 targets feed the verdict
/// (see [`is_egress_evidence`]); an IPv4 failure is somebody's server, not this
/// machine's family.
pub(crate) fn note_dial(addr: std::net::SocketAddr, failure: Option<Failure>) {
    if !is_egress_evidence(addr) {
        return;
    }
    let now_ms = crate::util::now_ms();
    let news = match V6.lock() {
        Ok(mut state) => match failure {
            None => state.note_v6_success(now_ms),
            Some(kind) => state.note_v6_failure(now_ms, kind),
        },
        // A panic in here is the only way the lock poisons, and the dial must
        // not fail because the verdict did.
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            match failure {
                None => state.note_v6_success(now_ms),
                Some(kind) => state.note_v6_failure(now_ms, kind),
            }
        }
    };
    match news {
        News::None => {}
        News::Suppressed { window_ms } => crate::logbuf::push(&format!(
            "proxy: IPv6 dials are failing; withholding AAAA records for {}s",
            window_ms / 1000
        )),
        News::Restored => crate::logbuf::push("proxy: IPv6 works again; answering AAAA normally"),
        News::Extended { window_ms } => crate::logbuf::push(&format!(
            "proxy: IPv6 still cannot be carried; withholding AAAA records for {}s",
            window_ms / 1000
        )),
    }
}

/// True when AAAA answers should carry no records (see [`Egress::withhold_aaaa`]).
pub(crate) fn withhold_aaaa() -> bool {
    let now_ms = crate::util::now_ms();
    match V6.lock() {
        Ok(mut state) => state.withhold_aaaa(now_ms),
        Err(poisoned) => poisoned.into_inner().withhold_aaaa(now_ms),
    }
}

/// True when an IPv6 dial is worth attempting (see
/// [`Egress::dial_worth_making`]). Reading the verdict does not arm a probe —
/// only answering the query that would produce the flow does.
pub(crate) fn dial_worth_making() -> bool {
    let now_ms = crate::util::now_ms();
    match V6.lock() {
        Ok(state) => state.dial_worth_making(now_ms),
        Err(poisoned) => poisoned.into_inner().dial_worth_making(now_ms),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_000_000;

    /// Drives the state machine to a suppression whose window starts exactly at
    /// `at`, so the tests can speak about expiry without carrying the two
    /// failures that came before.
    fn suppress(egress: &mut Egress, at: u64) {
        egress.note_v6_failure(at - 2, Failure::Timeout);
        egress.note_v6_failure(at - 1, Failure::Timeout);
        assert_eq!(
            egress.note_v6_failure(at, Failure::Timeout),
            News::Suppressed {
                window_ms: BASE_SUPPRESS_MS
            }
        );
    }

    #[test]
    fn three_machine_failures_start_the_suppression() {
        let mut egress = Egress::default();
        assert_eq!(egress.note_v6_failure(T, Failure::Timeout), News::None);
        assert_eq!(egress.note_v6_failure(T + 100, Failure::Timeout), News::None);
        assert_eq!(
            egress.note_v6_failure(T + 200, Failure::Timeout),
            News::Suppressed {
                window_ms: BASE_SUPPRESS_MS
            },
            "the third failure is the verdict"
        );
        assert!(egress.withhold_aaaa(T + 300));
    }

    #[test]
    fn a_refused_peer_is_not_this_machines_problem() {
        let mut egress = Egress::default();
        for step in 0..10 {
            assert_eq!(
                egress.note_v6_failure(T + step * 10, Failure::Elsewhere),
                News::None,
                "a host whose own IPv6 is broken must not cost every host its AAAA records"
            );
        }
        assert!(!egress.withhold_aaaa(T + 1000));
    }

    #[test]
    fn failures_far_apart_are_not_one_pattern() {
        let mut egress = Egress::default();
        egress.note_v6_failure(T, Failure::Timeout);
        egress.note_v6_failure(T + FAILURE_WINDOW_MS + 1, Failure::Timeout);
        assert_eq!(
            egress.note_v6_failure(T + 2 * FAILURE_WINDOW_MS + 2, Failure::Timeout),
            News::None,
            "each is the first of its own window"
        );
        assert!(!egress.withhold_aaaa(T + 2 * FAILURE_WINDOW_MS + 3));
    }

    #[test]
    fn one_dial_that_lands_clears_everything() {
        let mut egress = Egress::default();
        suppress(&mut egress, T);
        assert!(egress.withhold_aaaa(T + 3));
        assert_eq!(egress.note_v6_success(T + 4), News::Restored, "the clearing is news");
        assert!(!egress.withhold_aaaa(T + 5));
        assert_eq!(egress.note_v6_success(T + 6), News::None, "and only said once");
    }

    #[test]
    fn the_suppression_expires_into_one_probe_and_doubles_on_failure() {
        let mut egress = Egress::default();
        suppress(&mut egress, T);

        assert!(egress.withhold_aaaa(T + BASE_SUPPRESS_MS - 1));
        assert!(
            !egress.withhold_aaaa(T + BASE_SUPPRESS_MS),
            "the query at the expiry is answered normally: that is the re-probe"
        );

        assert_eq!(
            egress.note_v6_failure(T + BASE_SUPPRESS_MS + 1, Failure::Timeout),
            News::Extended {
                window_ms: BASE_SUPPRESS_MS * 2
            }
        );
        assert!(egress.withhold_aaaa(T + BASE_SUPPRESS_MS + 2), "suppressed again");
        assert!(
            !egress.withhold_aaaa(T + BASE_SUPPRESS_MS * 3 + 1),
            "the second window is twice the first"
        );
    }

    #[test]
    fn the_reprobe_interval_is_capped() {
        let mut egress = Egress::default();
        suppress(&mut egress, T);
        for _ in 0..12 {
            let at = egress.suppressed_until_ms;
            assert!(!egress.withhold_aaaa(at), "the expiry hands the query back");
            egress.note_v6_failure(at + 1, Failure::Timeout);
        }
        assert_eq!(egress.window_ms, MAX_SUPPRESS_MS, "a long outage still re-probes");
        let until = egress.suppressed_until_ms;
        assert!(egress.withhold_aaaa(until - 1));
        assert!(!egress.withhold_aaaa(until));
    }

    #[test]
    fn a_probe_that_lands_ends_the_outage() {
        let mut egress = Egress::default();
        suppress(&mut egress, T);
        assert!(!egress.withhold_aaaa(T + BASE_SUPPRESS_MS), "the probe is on its way");
        assert_eq!(
            egress.note_v6_success(T + BASE_SUPPRESS_MS + 5_000),
            News::Restored,
            "the tunnel came back, and that is worth a line in the log"
        );
        assert!(!egress.withhold_aaaa(T + BASE_SUPPRESS_MS + 6_000));
        assert_eq!(egress.window_ms, 0, "the whole history is dropped, not paused");
    }

    #[test]
    fn the_errno_split_is_the_one_the_verdict_cares_about() {
        assert_eq!(Failure::from_errno(libc::ETIMEDOUT), Failure::Timeout);
        assert_eq!(Failure::from_errno(libc::ENETUNREACH), Failure::Unreachable);
        assert_eq!(Failure::from_errno(libc::EAFNOSUPPORT), Failure::Unreachable);
        assert_eq!(
            Failure::from_errno(libc::ECONNREFUSED),
            Failure::Elsewhere,
            "a refused v6 socket names a server that is not listening, not a machine with no route"
        );
    }

    #[test]
    fn a_dial_the_verdict_already_explains_is_not_made() {
        let mut egress = Egress::default();
        assert!(egress.dial_worth_making(T), "nothing is believed yet, so everything is tried");
        suppress(&mut egress, T);
        assert!(
            !egress.dial_worth_making(T + 1),
            "a stale record's dial would only cost the connect budget"
        );
        assert!(
            !egress.withhold_aaaa(T + BASE_SUPPRESS_MS),
            "the expiry hands the query back"
        );
        assert!(
            egress.dial_worth_making(T + BASE_SUPPRESS_MS + 1),
            "and the flow it produces is the probe: that dial is made"
        );
        egress.note_v6_failure(T + BASE_SUPPRESS_MS + 2, Failure::Timeout);
        assert!(
            !egress.dial_worth_making(T + BASE_SUPPRESS_MS + 3),
            "answered, so no more dials until the next window"
        );
    }

    #[test]
    fn only_a_global_address_is_evidence_about_egress() {
        let global: std::net::SocketAddr = "[2606:4700:4700::22c4]:443".parse().unwrap();
        assert!(is_egress_evidence(global));
        for text in ["[::1]:443", "[fe80::1]:443", "[fd00::5]:443", "93.184.216.34:443"] {
            let addr: std::net::SocketAddr = text.parse().unwrap();
            assert!(
                !is_egress_evidence(addr),
                "{text} is answered without the global route, so it says nothing about it"
            );
        }
    }
}
