//! Small helpers shared by the native core.

use std::sync::OnceLock;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();

/// Current wall clock in milliseconds.
#[inline]
pub fn now_ms() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(_) => 0,
    }
}

/// Monotonic nanoseconds since the first call (cheap: a relaxed atomic load).
#[inline]
pub fn now_ns() -> u64 {
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as u64
}

/// Turns `Some("1.2.3.4")` style `Option<&str>` into the byte offset of the last
/// dot, used for host suffix stripping.
#[inline]
pub fn last_dot(s: &str) -> Option<usize> {
    match s.rfind('.') {
        Some(i) if i > 0 && i + 1 < s.len() => Some(i),
        _ => None,
    }
}
