//! Hostname patterns for the HTTPS website allow/block lists.
//!
//! AdGuard's "Filter HTTPS websites" section lets a user exclude sites from
//! decryption (banking, health, anything with client certificates) and,
//! optionally, invert the model so *only* listed sites are decrypted. The
//! matching happens before the ClientHello is fed to rustls: no pattern means
//! the connection is spliced through untouched, exactly like a non-TLS flow.
//!
//! A pattern is a hostname, optionally with `*`. `example.com` covers the
//! domain and its subdomains; `*.example.com` is accepted as the same thing
//! because that is how people write it. Entries pasted as URLs are reduced to
//! their host, so `https://Example.com/path` works.

/// A parsed, lowercase host list. Empty matches nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostPatterns {
    patterns: Vec<String>,
}

impl HostPatterns {
    pub fn new<I: IntoIterator<Item = String>>(patterns: I) -> Self {
        Self {
            patterns: patterns
                .into_iter()
                .filter_map(|raw| normalize(&raw))
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// True when `host` is covered by any entry.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        self.patterns
            .iter()
            .any(|pattern| host_matches(&host, pattern))
    }
}

/// One pattern against one already-lowercase host.
fn host_matches(host: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        if glob(pattern, host) {
            return true;
        }
        // `*.example.com` reads as "subdomains" to some users and as "the
        // domain too" to others; accepting both is the only unsurprising rule.
        return pattern
            .strip_prefix("*.")
            .is_some_and(|apex| host_matches(host, apex));
    }
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

/// Classic `*`-glob (any sequence, including dots).
fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            resume = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            resume += 1;
            ti = resume;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// `https://Example.com:443/path` → `example.com`. `None` for junk.
fn normalize(raw: &str) -> Option<String> {
    let mut value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    if let Some((_, rest)) = value.split_once("://") {
        value = rest.to_string();
    }
    value = value
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .to_string();
    // A port is noise on a host list; keep bracketed IPv6 literals intact.
    if !value.starts_with('[') {
        if let Some((host, port)) = value.rsplit_once(':') {
            if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                value = host.to_string();
            }
        }
    }
    value = value
        .trim_end_matches('.')
        .trim_start_matches('.')
        .to_string();
    if value.is_empty()
        || value.chars().any(|c| c.is_whitespace())
        || value.chars().any(|c| {
            !(c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '*' || c == ':')
        })
    {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> HostPatterns {
        HostPatterns::new(entries.iter().map(|s| s.to_string()))
    }

    #[test]
    fn a_domain_covers_its_subdomains_but_not_neighbours() {
        let hosts = list(&["example.com"]);
        assert!(hosts.matches("example.com"));
        assert!(hosts.matches("ads.example.com"));
        assert!(hosts.matches("EXAMPLE.com"));
        assert!(!hosts.matches("notexample.com"));
        assert!(!hosts.matches("example.com.evil.test"));
    }

    #[test]
    fn wildcard_apex_is_accepted_as_the_domain() {
        let hosts = list(&["*.example.com"]);
        assert!(hosts.matches("example.com"));
        assert!(hosts.matches("a.b.example.com"));
        assert!(!hosts.matches("example.org"));
    }

    #[test]
    fn urls_and_ports_are_reduced_to_the_host() {
        let hosts = list(&["https://Bank.Example:443/login", "http://other.test/"]);
        assert!(hosts.matches("bank.example"));
        assert!(hosts.matches("other.test"));
    }

    #[test]
    fn junk_entries_are_ignored() {
        let hosts = list(&["", "   ", "has space.test", "%%%", "http://"]);
        assert!(hosts.is_empty());
    }

    #[test]
    fn glob_matches_any_sequence() {
        assert!(glob("*.example.com", "a.example.com"));
        assert!(glob("ads.*.test", "ads.a.b.test"));
        assert!(!glob("ads.*.test", "cdn.a.test"));
    }
}
