//! A page the user took out of filtering.
//!
//! `@@||site^$document` (the assistant's "turn filtering off here", the
//! extension popup's switch) is honoured by the request layer on its own: a
//! request whose page is excepted is let through before any rule is matched.
//! Two of the three places this app blocks do not carry a request at all — the
//! resolver, and the bare connection refused before the handshake — and those
//! are where most ads die. A page that was excepted therefore still came out
//! blocked: on a test page that asks "is this ad reachable?", the answer stayed
//! "no" and the score stayed high.
//!
//! Nothing in a DNS query or a TCP handshake names the page that asked, so the
//! exemption is remembered rather than looked up. Every request the rules let
//! through *because its page was excepted* refreshes it, and the next document
//! that is not excepted ends it. In between, the two stages above stand down.
//! [`Exemption::FRESH`] is what keeps a browser closed without navigating
//! anywhere from leaving the resolver unguarded forever.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long the resolver and the pre-handshake refusal stand down after the
/// last request seen from an excepted page. Long enough for a page that is
/// being read, short enough that a closed tab cannot keep filtering off.
pub const FRESH: Duration = Duration::from_secs(180);

/// The page whose requests were last let through as excepted, and when.
#[derive(Default)]
pub struct Exemption {
    since: Mutex<Option<(Instant, String)>>,
}

impl Exemption {
    fn with<R>(&self, f: impl FnOnce(&mut Option<(Instant, String)>) -> R) -> R {
        let mut guard = self
            .since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut guard)
    }

    /// A request from an excepted page just came through: the browser is still
    /// there, and the page is still the one the user excepted.
    pub fn note(&self, host: &str) {
        self.with(|since| {
            let same = since
                .as_ref()
                .is_some_and(|(at, named)| named == host && at.elapsed() <= FRESH);
            if !same {
                crate::logbuf::push(&format!(
                    "page_exception: {host} is out of filtering, early stages stand down"
                ));
            }
            *since = Some((Instant::now(), host.to_string()));
        });
    }

    /// A document that is *not* excepted: the browser moved on, and filtering
    /// is the whole machine's again.
    pub fn end(&self) {
        self.with(|since| {
            if since.is_some() {
                crate::logbuf::push("page_exception: left the excepted page");
            }
            *since = None;
        });
    }

    /// The excepted page, while the record of it is still fresh.
    ///
    /// The caller asks the rules whether that page is still excepted: a
    /// rebuild may have taken the exception away, and a rebuild happens for
    /// reasons that have nothing to do with it — the window alone is not
    /// evidence that the exception still stands.
    pub fn page(&self) -> Option<String> {
        self.with(|since| {
            since
                .as_ref()
                .filter(|(at, _)| at.elapsed() <= FRESH)
                .map(|(_, host)| host.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_excepted_page_stands_the_early_stages_down_until_it_is_left() {
        let exemption = Exemption::default();
        assert!(exemption.page().is_none(), "nothing is exempted before a page asks");

        exemption.note("ads.example");
        assert_eq!(
            exemption.page().as_deref(),
            Some("ads.example"),
            "a request from an excepted page keeps it open"
        );

        exemption.end();
        assert!(exemption.page().is_none(), "a page that is not excepted ends it");
    }

    #[test]
    fn the_exemption_belongs_to_the_engine_that_granted_it() {
        let one = Exemption::default();
        let other = Exemption::default();
        one.note("ads.example");
        assert_eq!(one.page().as_deref(), Some("ads.example"));
        assert!(
            other.page().is_none(),
            "another engine's rules never excepted that page"
        );
    }
}
