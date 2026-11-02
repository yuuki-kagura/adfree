//! Anti-retry-loop handling.
//!
//! Some apps insist on a request a filter refuses: they retry it in a tight
//! loop, burning CPU (and battery) on connections that are reset every time.
//! When one app has the same host blocked again and again inside a short
//! window, the engine treats that app as requiring the request and lets it
//! through for a cooldown. The filter then resumes; a window only stays open
//! while the app keeps hammering, and turning the switch off clears them all.
//!
//! The cooldown is a hole in the blocking: a probe host that gets spare time
//! connects. So the switch is off by default, and the window is keyed per
//! (host, app) rather than per host — one app retrying must not open the host
//! for every other app on the device.

use crate::fxhash::FxHashMap;
use crate::util::now_ms;

/// Blocked attempts from one host in one app that count as a retry loop.
pub const RETRY_LIMIT: u32 = 7;
/// The attempts must fall inside this window to count as one loop.
pub const RETRY_WINDOW_MS: u64 = 10_000;
/// How long a host that tripped the limit is let through.
pub const ALLOW_MS: u64 = 60_000;
/// Cap on tracked windows; the table is pruned when it is reached.
const MAX_ENTRIES: usize = 1024;

/// Who a flow belongs to: the Linux uid owning the connection, which is what
/// flow attribution already resolves before it maps to package names. Keying on
/// uid instead of a package string keeps DNS and TCP decisions consistent for a
/// uid that owns several packages, and costs no clone. Traffic the engine cannot
/// attribute shares uid 0.
pub type FlowOwner = u32;

#[derive(Clone, Copy, Default)]
struct Entry {
    window_start_ms: u64,
    last_blocked_ms: u64,
    blocked: u32,
    allow_until_ms: u64,
}

pub struct SmartFilter {
    enabled: bool,
    hosts: FxHashMap<(Box<str>, FlowOwner), Entry>,
}

impl Default for SmartFilter {
    fn default() -> Self {
        Self {
            enabled: false,
            hosts: FxHashMap::default(),
        }
    }
}

impl SmartFilter {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            hosts: FxHashMap::default(),
        }
    }

    /// The switch is re-read on every decision, so turning it off takes effect
    /// immediately and forgets the windows opened while it was on.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.hosts.clear();
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Records one blocked attempt on `host` from `owner`.
    ///
    /// Returns true while that (host, app) pair is in a smart-allow window: the
    /// caller should forward the request instead of blocking it. Once the limit
    /// is reached the window opens, and remains open for [`ALLOW_MS`].
    pub fn note_blocked(&mut self, host: &str, owner: FlowOwner) -> bool {
        if !self.enabled {
            return false;
        }
        let now = now_ms();
        if self.hosts.len() >= MAX_ENTRIES {
            self.prune(now);
        }
        // A tuple key has no partial lookup, so the pair is built once here and
        // reused for the insert.
        let key = (host.into(), owner);
        let entry = match self.hosts.get_mut(&key) {
            Some(entry) => entry,
            None => self.hosts.entry(key).or_default(),
        };
        if entry.allow_until_ms > now {
            return true;
        }
        if now.saturating_sub(entry.window_start_ms) > RETRY_WINDOW_MS {
            entry.window_start_ms = now;
            entry.blocked = 0;
        }
        entry.last_blocked_ms = now;
        entry.blocked += 1;
        if entry.blocked < RETRY_LIMIT {
            return false;
        }
        entry.blocked = 0;
        entry.allow_until_ms = now + ALLOW_MS;
        crate::logbuf::push(&format!(
            "smart filter: {host} blocked {RETRY_LIMIT}x in {}s by one app, allowing it for {}s",
            RETRY_WINDOW_MS / 1000,
            ALLOW_MS / 1000
        ));
        true
    }

    fn prune(&mut self, now: u64) {
        self.hosts.retain(|_, entry| {
            entry.allow_until_ms > now
                || now.saturating_sub(entry.last_blocked_ms) <= RETRY_WINDOW_MS
        });
        if self.hosts.len() >= MAX_ENTRIES {
            // Pathological churn (thousands of distinct blocked hosts): start
            // over rather than grow without bound. Windows can be re-learned.
            self.hosts.clear();
        }
    }

    #[cfg(test)]
    fn window_open_for(&self, host: &str, owner: FlowOwner) -> bool {
        // A tuple key has no partial lookup: the pair is built to the stored
        // type here, which Borrow<T> for T allows.
        self.enabled
            && self
                .hosts
                .get(&(host.into(), owner))
                .is_some_and(|entry| entry.allow_until_ms > now_ms())
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.hosts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: FlowOwner = 10_123;
    const OTHER_APP: FlowOwner = 10_456;

    /// Blocked attempts from one app that should trip the limit.
    fn hammer(filter: &mut SmartFilter, host: &str, owner: FlowOwner) {
        for _ in 0..RETRY_LIMIT {
            filter.note_blocked(host, owner);
        }
    }

    #[test]
    fn a_fresh_install_ships_smart_filtering_off() {
        let mut filter = SmartFilter::default();
        assert!(!filter.enabled());
        // The default is what the benchmark measures: a probe host must not be
        // spared however hard any app retries it.
        for _ in 0..RETRY_LIMIT * 2 {
            assert!(!filter.note_blocked("zq8f8.adnxs.com", APP));
        }
        assert!(!filter.window_open_for("zq8f8.adnxs.com", APP));
        assert_eq!(filter.tracked(), 0);
    }

    #[test]
    fn disabled_never_allows() {
        let mut filter = SmartFilter::new(false);
        for _ in 0..RETRY_LIMIT * 2 {
            assert!(!filter.note_blocked("ads.example", APP));
        }
        assert!(!filter.window_open_for("ads.example", APP));
    }

    #[test]
    fn seven_blocks_from_one_app_open_a_window() {
        let mut filter = SmartFilter::new(true);
        for _ in 0..RETRY_LIMIT - 1 {
            assert!(!filter.note_blocked("ads.example", APP));
        }
        assert!(!filter.window_open_for("ads.example", APP));
        assert!(filter.note_blocked("ads.example", APP));
        assert!(filter.window_open_for("ads.example", APP));
    }

    #[test]
    fn a_different_app_on_the_same_host_keeps_being_blocked() {
        let mut filter = SmartFilter::new(true);
        hammer(&mut filter, "ads.example", APP);
        assert!(filter.window_open_for("ads.example", APP));
        // The retry loop belongs to one app; the spare window must not become a
        // free pass for a second app that never asked for the host.
        for _ in 0..RETRY_LIMIT - 1 {
            assert!(!filter.note_blocked("ads.example", OTHER_APP));
        }
        assert!(!filter.window_open_for("ads.example", OTHER_APP));
    }

    #[test]
    fn an_open_window_does_not_extend_itself() {
        let mut filter = SmartFilter::new(true);
        hammer(&mut filter, "ads.example", APP);
        let until = filter
            .hosts
            .get(&("ads.example".into(), APP))
            .unwrap()
            .allow_until_ms;
        for _ in 0..RETRY_LIMIT {
            assert!(filter.note_blocked("ads.example", APP));
        }
        let after = filter
            .hosts
            .get(&("ads.example".into(), APP))
            .unwrap()
            .allow_until_ms;
        assert_eq!(until, after);
    }

    #[test]
    fn attempts_outside_the_window_do_not_accumulate() {
        let mut filter = SmartFilter::new(true);
        for _ in 0..RETRY_LIMIT - 1 {
            assert!(!filter.note_blocked("slow.example", APP));
        }
        // The first attempts are old enough to be forgotten: the next one starts
        // a new window instead of tripping the limit.
        {
            let entry = filter.hosts.get_mut(&("slow.example".into(), APP)).unwrap();
            entry.window_start_ms = now_ms().saturating_sub(RETRY_WINDOW_MS + 1);
        }
        assert!(!filter.note_blocked("slow.example", APP));
        assert!(!filter.window_open_for("slow.example", APP));
    }

    #[test]
    fn turning_the_switch_off_forgets_open_windows() {
        let mut filter = SmartFilter::new(true);
        hammer(&mut filter, "ads.example", APP);
        assert!(filter.window_open_for("ads.example", APP));
        filter.set_enabled(false);
        assert!(!filter.window_open_for("ads.example", APP));
        assert_eq!(filter.tracked(), 0);
    }

    #[test]
    fn hosts_are_tracked_independently() {
        let mut filter = SmartFilter::new(true);
        hammer(&mut filter, "ads.example", APP);
        assert!(!filter.window_open_for("tracker.example", APP));
        assert!(!filter.note_blocked("tracker.example", APP));
    }

    #[test]
    fn unattributable_flows_share_one_owner() {
        let mut filter = SmartFilter::new(true);
        // Two apps the engine could not resolve both land in uid 0's bucket, so
        // their attempts add up into one window rather than two half-counted ones.
        for _ in 0..3 {
            assert!(!filter.note_blocked("ads.example", 0));
        }
        for _ in 0..RETRY_LIMIT - 4 {
            assert!(!filter.note_blocked("ads.example", 0));
        }
        assert!(filter.note_blocked("ads.example", 0));
        assert!(filter.window_open_for("ads.example", 0));
    }

    #[test]
    fn the_table_is_bounded() {
        let mut filter = SmartFilter::new(true);
        for i in 0..MAX_ENTRIES * 2 {
            filter.note_blocked(&format!("host{i}.example"), APP);
        }
        assert!(filter.tracked() <= MAX_ENTRIES);
    }

    #[test]
    fn a_tracked_window_carries_a_known_cost() {
        // The cap only bounds memory if a window is cheap: 1024 of these stay
        // well under the event ring's budget even when the switch is on.
        let per_window =
            std::mem::size_of::<(Box<str>, FlowOwner)>() + std::mem::size_of::<Entry>();
        assert!(per_window <= 64, "{per_window} bytes per window");
        assert!(MAX_ENTRIES * per_window <= 64 * 1024);
    }
}
