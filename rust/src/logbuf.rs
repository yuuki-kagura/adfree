//! Bounded log ring that survives the trip from native code to the UI.
//!
//! The core must never talk to Android directly (no `logcat` from the packet
//! threads), so warnings are buffered here and read lazily by the app, which
//! forwards them to `logcat` on its own thread.

use std::collections::VecDeque;
use std::sync::Mutex;

const MAX_LINES: usize = 200;
const MAX_LINE_BYTES: usize = 512;

static LINES: Mutex<Option<VecDeque<String>>> = Mutex::new(None);

fn with_queue<R>(f: impl FnOnce(&mut VecDeque<String>) -> R) -> R {
    let mut guard = LINES.lock().unwrap();
    if guard.is_none() {
        *guard = Some(VecDeque::with_capacity(MAX_LINES));
    }
    let queue = guard.as_mut().expect("queue initialised above");
    f(queue)
}

/// Buffers one line, dropping the oldest line when the ring is full.
pub fn push(line: &str) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The buffer is a process-wide static, so these tests must not run
    /// concurrently with each other.
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn buffers_and_drains() {
        let _guard = LOCK.lock().unwrap();
        clear();
        push("first");
        push("  ");
        push("second");
        assert_eq!(take(), vec!["first".to_string(), "second".to_string()]);
        assert!(take().is_empty());
    }

    #[test]
    fn long_lines_are_truncated() {
        let _guard = LOCK.lock().unwrap();
        clear();
        push(&"x".repeat(900));
        let lines = take();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].len() <= MAX_LINE_BYTES + 4, "{}", lines[0].len());
    }

    #[test]
    fn ring_is_bounded() {
        let _guard = LOCK.lock().unwrap();
        clear();
        for i in 0..(MAX_LINES + 50) {
            push(&format!("line {i}"));
        }
        let lines = take();
        assert_eq!(lines.len(), MAX_LINES);
        assert_eq!(lines.last().map(String::as_str), Some("line 249"));
    }
}
