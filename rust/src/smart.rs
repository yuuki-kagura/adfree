//! Anti-retry-loop handling.
//!
//! Some apps insist on a request a filter refuses: they retry it in a tight
//! loop, burning CPU (and battery) on connections that are reset every time.
//! When the same host is blocked again and again inside a short window, the
//! engine treats the app as requiring that request and lets it through for a
//! cooldown. The filter then resumes; a host only stays allowed while it keeps
//! hammering, and turning the switch off clears every window at once.

use crate::fxhash::FxHashMap;
use crate::util::now_ms;

/// Blocked attempts from one host that count as a retry loop.
pub const RETRY_LIMIT: u32 = 5;
/// The attempts must fall inside this window to count as one loop.
pub const RETRY_WINDOW_MS: u64 = 10_000;
/// How long a host that tripped the limit is let through.
pub const ALLOW_MS: u64 = 60_000;
/// Cap on tracked hosts; the table is pruned when it is reached.
const MAX_ENTRIES: usize = 1024;

#[derive(Clone, Copy, Default)]
struct Entry {
    window_start_ms: u64,
    last_blocked_ms: u64,
    blocked: u32,
    allow_until_ms: u64,
}

pub struct SmartFilter {
    enabled: bool,
    hosts: FxHashMap<Box<str>, Entry>,
}

impl Default for SmartFilter {
    fn default() -> Self {
        Self {
            enabled: true,
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

    /// Read-only check used where a block was already decided elsewhere (the
    /// DNS answer learned into the connection tracker).
    pub fn allows(&self, host: &str) -> bool {
        if !self.enabled {
            return false;
        }
        self.hosts
            .get(host)
            .is_some_and(|entry| entry.allow_until_ms > now_ms())
    }

    /// Records one blocked attempt on `host`.
    ///
    /// Returns true while the host is in a smart-allow window: the caller
    /// should forward the request instead of blocking it. Once the limit is
    /// reached the window opens, and remains open for [`ALLOW_MS`].
    pub fn note_blocked(&mut self, host: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let now = now_ms();
        if self.hosts.len() >= MAX_ENTRIES {
            self.prune(now);
        }
        let entry = match self.hosts.get_mut(host) {
            Some(entry) => entry,
            None => self
                .hosts
                .entry(host.into())
                .or_insert_with(Entry::default),
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
            "smart filter: {host} blocked {}x in {}s, allowing it for {}s",
            RETRY_LIMIT,
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
    fn tracked(&self) -> usize {
        self.hosts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_never_allows() {
        let mut filter = SmartFilter::new(false);
        for _ in 0..RETRY_LIMIT * 2 {
            assert!(!filter.note_blocked("ads.example"));
        }
        assert!(!filter.allows("ads.example"));
    }

    #[test]
    fn a_retry_loop_opens_an_allow_window() {
        let mut filter = SmartFilter::new(true);
        for _ in 0..RETRY_LIMIT - 1 {
            assert!(!filter.note_blocked("ads.example"));
        }
        assert!(!filter.allows("ads.example"));
        assert!(filter.note_blocked("ads.example"));
        assert!(filter.allows("ads.example"));
    }

    #[test]
    fn attempts_outside_the_window_do_not_accumulate() {
        let mut filter = SmartFilter::new(true);
        for _ in 0..RETRY_LIMIT - 1 {
            assert!(!filter.note_blocked("slow.example"));
        }
        // The first four attempts are old enough to be forgotten: the fifth
        // one starts a new window instead of tripping the limit.
        {
            let entry = filter.hosts.get_mut("slow.example").unwrap();
            entry.window_start_ms = now_ms().saturating_sub(RETRY_WINDOW_MS + 1);
        }
        assert!(!filter.note_blocked("slow.example"));
        assert!(!filter.allows("slow.example"));
    }

    #[test]
    fn turning_the_switch_off_forgets_open_windows() {
        let mut filter = SmartFilter::new(true);
        for _ in 0..RETRY_LIMIT {
            filter.note_blocked("ads.example");
        }
        assert!(filter.allows("ads.example"));
        filter.set_enabled(false);
        assert!(!filter.allows("ads.example"));
        assert_eq!(filter.tracked(), 0);
    }

    #[test]
    fn hosts_are_tracked_independently() {
        let mut filter = SmartFilter::new(true);
        for _ in 0..RETRY_LIMIT {
            filter.note_blocked("ads.example");
        }
        assert!(!filter.allows("tracker.example"));
        assert!(!filter.note_blocked("tracker.example"));
    }

    #[test]
    fn the_table_is_bounded() {
        let mut filter = SmartFilter::new(true);
        for i in 0..MAX_ENTRIES * 2 {
            filter.note_blocked(&format!("host{i}.example"));
        }
        assert!(filter.tracked() <= MAX_ENTRIES);
    }
}
