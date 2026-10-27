//! SafeSearch: which host a search query must really be sent to.
//!
//! The major engines expose a family-filtered host that returns the same
//! layout but only safe results. Rewriting the question before it is forwarded
//! is the only way that works for every record type: an engine that answers
//! with plain `A` records has no CNAME to edit, and the answer must still carry
//! the address of the filtered service.
//!
//! The mapping is deliberately a pure function so the list can be tested
//! without a socket.

/// The filtered host for `host`, or `None` when the host is not a search
/// engine with a known safe variant.
pub fn safe_host(host: &str) -> Option<&'static str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }

    // `google.<tld>` and every subdomain (`www.google.com`,
    // `images.google.co.uk`): the engine label sits right before the public
    // suffix, which is one label (`com`) or two (`co.uk`). Checking the
    // position rather than the label count keeps lookalikes such as
    // `google.com.evil.test` from matching.
    if engine_at(&host, "google") {
        return Some("forcesafesearch.google.com");
    }
    if engine_at(&host, "yandex") {
        return Some("familysearch.yandex.ru");
    }

    if matches_apex(&host, "bing.com") {
        return Some("strict.bing.com");
    }
    if matches_apex(&host, "duckduckgo.com") {
        return Some("safe.duckduckgo.com");
    }
    if matches_apex(&host, "pixabay.com") {
        return Some("safe.pixabay.com");
    }
    if matches_apex(&host, "youtube.com")
        || matches_apex(&host, "youtu.be")
        || matches_apex(&host, "youtubekids.com")
    {
        return Some("restrict.youtube.com");
    }
    None
}

/// Whether the last-but-one or last-but-two label of `host` is `engine`, i.e.
/// the host is `engine.<suffix>`, `engine.<sld>.<cc>` or a subdomain of one.
fn engine_at(host: &str, engine: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    let len = labels.len();
    if len < 2 || !labels[len - 1].chars().all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if labels[len - 2] == engine {
        return true;
    }
    // Country suffixes are two labels deep for a handful of second-level
    // names (`google.co.uk`, `google.com.au`, `yandex.com.tr`). Requiring a
    // known one keeps `google.evil.test` out.
    len >= 3
        && labels[len - 3] == engine
        && matches!(
            labels[len - 2],
            "co" | "com" | "net" | "org" | "gov" | "ac" | "edu" | "ne" | "or" | "go" | "gob"
        )
}

/// `example.com` itself or any subdomain of it.
fn matches_apex(host: &str, apex: &str) -> bool {
    host == apex || host.ends_with(&format!(".{apex}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_and_its_subdomains_use_the_forced_host() {
        for host in [
            "google.com",
            "www.google.com",
            "images.google.co.uk",
            "google.de",
        ] {
            assert_eq!(
                safe_host(host),
                Some("forcesafesearch.google.com"),
                "{host}"
            );
        }
    }

    #[test]
    fn the_other_engines_map_to_their_strict_hosts() {
        assert_eq!(safe_host("www.bing.com"), Some("strict.bing.com"));
        assert_eq!(safe_host("bing.com"), Some("strict.bing.com"));
        assert_eq!(safe_host("duckduckgo.com"), Some("safe.duckduckgo.com"));
        assert_eq!(safe_host("m.youtube.com"), Some("restrict.youtube.com"));
        assert_eq!(safe_host("youtu.be"), Some("restrict.youtube.com"));
        assert_eq!(safe_host("yandex.ru"), Some("familysearch.yandex.ru"));
        assert_eq!(safe_host("pixabay.com"), Some("safe.pixabay.com"));
    }

    #[test]
    fn unrelated_and_lookalike_hosts_are_left_alone() {
        assert_eq!(safe_host("example.com"), None);
        assert_eq!(safe_host("notgoogle.com"), None);
        assert_eq!(safe_host("google.com.evil.test"), None);
        assert_eq!(safe_host("bing.com.evil.test"), None);
        assert_eq!(safe_host(""), None);
    }
}
