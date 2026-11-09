//! Which hosts each page has had blocked, for the badge the page draws.
//!
//! AdGuard shows the count on the browser extension's own icon. An extension
//! cannot be asked to count what the *app* blocks — it never sees the decision
//! — so the number is kept here, where the decisions are made, and the page
//! runtime reads it back over the local origin.
//!
//! Two things decide what the number means:
//!
//! * **Hosts, not requests.** One ad host can be asked for twenty times and one
//!   tracker once; the badge says how much of the page was taken away, so a
//!   host counts once. It also makes the number stable while a page loads:
//!   browsers retry, and a retry is not news.
//! * **The page is the last document loaded.** Blocking happens on the DNS
//!   path and on bare connections as well as on requests, and neither of those
//!   carries the page that asked. The document the engine served last is the
//!   page the user is on, which is what a badge is for; a count that only
//!   covered requests the proxy could attribute would read zero on almost
//!   every site, because the DNS half blocks the ads first.
//!
//! The count starts again on every new document, so it reads "on this page"
//! rather than "since the app started".

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many hosts one page may remember. A page that asks for more than this
/// has nothing left to say with its badge.
const MAX_HOSTS_PER_PAGE: usize = 2000;

/// How many pages are remembered. A browsing session touches a few dozen; the
/// cap only exists so a machine left running for weeks cannot grow without end.
const MAX_PAGES: usize = 512;

/// How long after a document a block is still counted for it. Ads arrive while
/// the page loads and shortly after; past this the block is far more likely to
/// come from another tab, another app, or a retry nobody is watching.
const FRESH: Duration = Duration::from_secs(180);

#[derive(Default)]
struct State {
    pages: HashMap<String, HashSet<String>>,
    active: Option<(String, Instant)>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = guard.get_or_insert_with(State::default);
    if state.pages.len() > MAX_PAGES {
        state.pages.clear();
        state.active = None;
    }
    f(state)
}

/// A document for `host` has been served: the page is on screen now, and
/// whatever it had blocked before belongs to the page the user left.
pub fn enter(host: &str) {
    if host.is_empty() {
        return;
    }
    with(|state| {
        state.pages.insert(host.to_string(), HashSet::new());
        state.active = Some((host.to_string(), Instant::now()));
    });
}

/// One host was blocked. Counted for the page on screen, once.
pub fn block(host: &str) {
    if host.is_empty() {
        return;
    }
    with(|state| {
        let Some((page, at)) = state.active.as_ref() else {
            return;
        };
        if at.elapsed() > FRESH {
            return;
        }
        let page = page.clone();
        let Some(hosts) = state.pages.get_mut(&page) else {
            return;
        };
        if hosts.len() < MAX_HOSTS_PER_PAGE {
            hosts.insert(host.to_string());
        }
    });
}

/// What the badge reads.
pub fn read(host: &str) -> u64 {
    if host.is_empty() {
        return 0;
    }
    with(|state| state.pages.get(host).map_or(0, |hosts| hosts.len() as u64))
}

/// Forgets every page; the tests need it, and a protection restart means the
/// numbers no longer describe anything the user can see.
pub fn clear() {
    with(|state| {
        state.pages.clear();
        state.active = None;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_counts_the_hosts_it_lost_once_each() {
        clear();
        enter("news.example");
        block("ads.example");
        block("ads.example");
        block("tracker.example");
        assert_eq!(read("news.example"), 2, "a host counts once, however often");

        // Another page is nobody's business.
        assert_eq!(read("other.example"), 0);
    }

    #[test]
    fn a_new_document_starts_the_count_again() {
        clear();
        enter("news.example");
        block("ads.example");
        assert_eq!(read("news.example"), 1);

        enter("news.example");
        assert_eq!(read("news.example"), 0);
        block("tracker.example");
        assert_eq!(read("news.example"), 1);
    }

    #[test]
    fn a_block_before_any_page_is_counted_nowhere() {
        clear();
        block("ads.example");
        assert_eq!(read("news.example"), 0);
        assert_eq!(read("ads.example"), 0);
    }

    #[test]
    fn the_last_document_is_where_blocks_land() {
        clear();
        enter("first.example");
        enter("second.example");
        block("ads.example");
        assert_eq!(read("first.example"), 0);
        assert_eq!(read("second.example"), 1);
    }

    #[test]
    fn an_empty_host_is_never_counted() {
        clear();
        enter("");
        block("");
        assert_eq!(read(""), 0);
    }
}
