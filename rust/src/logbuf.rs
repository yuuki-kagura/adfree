//! Bounded log ring that survives the trip from native code to the UI.
//!
//! The core must never talk to Android directly (no `logcat` from the packet
//! threads), so warnings are buffered here and read lazily by the app, which
//! forwards them to `logcat` on its own thread.
//!
//! Lines carry a severity, and one stored level says how much of that is
//! buffered. The ring is only 200 lines deep, so the level is not cosmetic: at
//! `DEBUG` a burst of per-request chatter evicts the warnings that came with it,
//! and at `OFF` a field report has nothing to quote. `WARN` is the shipped
//! default and is what this buffer did before levels existed.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

const MAX_LINES: usize = 200;
const MAX_LINE_BYTES: usize = 512;

/// Nothing is buffered.
pub const OFF: u8 = 0;
/// Only lines that name a failure.
pub const ERROR: u8 = 1;
/// Failures and the diagnostics that explain a fallback. The default.
pub const WARN: u8 = 2;
/// Everything, including the chatter that repeats per request.
pub const DEBUG: u8 = 3;

/// The level the ring falls back to before any config has been applied: the
/// behaviour every existing install already has.
pub const DEFAULT_LEVEL: u8 = WARN;

static LEVEL: AtomicU8 = AtomicU8::new(DEFAULT_LEVEL);
static LINES: Mutex<Option<VecDeque<String>>> = Mutex::new(None);

/// Sets the buffer level and returns what was stored. An out-of-range value is
/// clamped rather than refused: the level arrives from a stored setting written
/// by a possible future build, and a ring that cannot interpret it should be
/// loud, not silent.
pub fn set_level(level: u8) -> u8 {
    let stored = level.min(DEBUG);
    LEVEL.store(stored, Ordering::Relaxed);
    stored
}

pub fn level() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

/// True when a line of this severity is worth buffering right now. A severity
/// number is never below `OFF`, so the off level fails every comparison here.
#[inline]
fn kept(severity: u8) -> bool {
    severity <= LEVEL.load(Ordering::Relaxed)
}

fn with_queue<R>(f: impl FnOnce(&mut VecDeque<String>) -> R) -> R {
    let mut guard = LINES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(VecDeque::with_capacity(MAX_LINES));
    }
    let queue = guard.as_mut().expect("queue initialised above");
    f(queue)
}

/// Buffers one diagnostic: a fallback taken, a value repaired, a switch that
/// changed what the core does.
pub fn push(line: &str) {
    push_at(WARN, line)
}

/// Buffers one failure - the core could not do what it was asked.
pub fn push_error(line: &str) {
    push_at(ERROR, line)
}

/// Buffers one per-request line. Silent unless the level is `DEBUG`.
pub fn push_debug(line: &str) {
    push_at(DEBUG, line)
}

/// Buffers one line at a given severity, dropping it below that level and
/// dropping the oldest line when the ring is full.
fn push_at(severity: u8, line: &str) {
    if !kept(severity) {
        return;
    }
    with_queue(|queue| {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }
        if trimmed.len() > MAX_LINE_BYTES {
            let mut end = MAX_LINE_BYTES;
            while !trimmed.is_char_boundary(end) {
                end -= 1;
            }
            queue.push_back(format!("{}…", &trimmed[..end]));
        } else {
            queue.push_back(trimmed.to_string());
        }
        while queue.len() > MAX_LINES {
            queue.pop_front();
        }
    });
}

/// Drains everything buffered so far, oldest first.
pub fn take() -> Vec<String> {
    with_queue(|queue| queue.drain(..).collect())
}

/// Drops everything buffered.
pub fn clear() {
    with_queue(|queue| queue.clear());
}

/// The buffer and the level are process-wide statics, so any test that reads
/// them must hold this lock; two tests draining the same ring see each other's
/// lines.
#[cfg(test)]
pub(crate) fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_and_drains() {
        let _guard = lock();
        set_level(DEFAULT_LEVEL);
        clear();
        push("first");
        push("  ");
        push("second");
        assert_eq!(take(), vec!["first".to_string(), "second".to_string()]);
        assert!(take().is_empty());
        set_level(DEFAULT_LEVEL);
    }

    #[test]
    fn long_lines_are_truncated() {
        let _guard = lock();
        set_level(DEFAULT_LEVEL);
        clear();
        push(&"x".repeat(900));
        let lines = take();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].len() <= MAX_LINE_BYTES + 4, "{}", lines[0].len());
        set_level(DEFAULT_LEVEL);
    }

    #[test]
    fn ring_is_bounded() {
        let _guard = lock();
        set_level(DEFAULT_LEVEL);
        clear();
        for i in 0..(MAX_LINES + 50) {
            push(&format!("line {i}"));
        }
        let lines = take();
        assert_eq!(lines.len(), MAX_LINES);
        assert_eq!(lines.last().map(String::as_str), Some("line 249"));
        set_level(DEFAULT_LEVEL);
    }

    /// A fresh install must buffer exactly what it buffered before levels
    /// existed, or this stage would have changed the logs every user sees.
    #[test]
    fn a_fresh_install_buffers_normal_lines_and_stays_at_the_shipped_level() {
        let _guard = lock();
        set_level(DEFAULT_LEVEL);
        assert_eq!(level(), WARN);
        clear();
        push("normal");
        push_debug("chatter");
        assert_eq!(take(), vec!["normal".to_string()]);
        set_level(DEFAULT_LEVEL);
    }

    #[test]
    fn the_error_level_keeps_failures_and_drops_the_rest() {
        let _guard = lock();
        set_level(ERROR);
        clear();
        push_error("store: write failed");
        push("a fallback was taken");
        push_debug("per-request chatter");
        assert_eq!(take(), vec!["store: write failed".to_string()]);
        set_level(DEFAULT_LEVEL);
    }

    #[test]
    fn the_debug_level_admits_the_per_request_chatter() {
        let _guard = lock();
        set_level(DEBUG);
        clear();
        push_error("failed");
        push("normal");
        push_debug("cookies stripped");
        assert_eq!(
            take(),
            vec![
                "failed".to_string(),
                "normal".to_string(),
                "cookies stripped".to_string()
            ]
        );
        set_level(DEFAULT_LEVEL);
    }

    #[test]
    fn the_off_level_buffers_nothing() {
        let _guard = lock();
        clear();
        set_level(OFF);
        push_error("a failure nobody will read");
        push("normal");
        push_debug("chatter");
        assert!(take().is_empty());
        set_level(DEFAULT_LEVEL);
        clear();
    }

    /// The level arrives from a stored record that a newer build may have
    /// widened. Clamping keeps an unknown value loud instead of silent.
    #[test]
    fn an_unknown_level_clamps_to_the_loudest() {
        let _guard = lock();
        assert_eq!(set_level(99), DEBUG);
        clear();
        push_debug("still buffered");
        assert_eq!(take(), vec!["still buffered".to_string()]);
        set_level(DEFAULT_LEVEL);
    }
}
