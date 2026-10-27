//! User DNS rewrites: `host -> address` answers the core gives itself.
//!
//! A rewrite is the user's explicit intent, so it is checked before the filter
//! lists: an address the user mapped must not be sinkholed by a subscription
//! that happens to cover the host. The rules are kept parsed (an address, not
//! a string), so the packet path never parses anything.

use std::net::IpAddr;

/// One parsed `host -> address` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRewriteRule {
    /// Lowercased host, without the `*.` prefix on a wildcard rule.
    pub host: String,
    /// `*.example.com` matches `a.example.com`, never `example.com` itself.
    pub wildcard: bool,
    pub address: IpAddr,
}

impl DnsRewriteRule {
    /// Parses one persisted row. `None` for an empty host or an answer that is
    /// not an IP literal: the settings form validates the same way, so a bad
    /// row can only come from an older build or a hand-edited store.
    pub fn parse(host: &str, answer: &str) -> Option<DnsRewriteRule> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host == "*" {
            return None;
        }
        let (wildcard, host) = match host.strip_prefix("*.") {
            Some(rest) => (true, rest.to_string()),
            None => (false, host),
        };
        if host.is_empty() {
            return None;
        }
        let address = answer.trim().parse::<IpAddr>().ok()?;
        Some(DnsRewriteRule {
            host,
            wildcard,
            address,
        })
    }

    pub fn matches(&self, host: &str) -> bool {
        if self.wildcard {
            host.ends_with(&format!(".{}", self.host))
        } else {
            host == self.host
        }
    }
}

/// The address a host is rewritten to, if any. An exact rule wins over a
/// wildcard; between wildcards the most specific (longest) host wins.
pub fn lookup(rules: &[DnsRewriteRule], host: &str) -> Option<IpAddr> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rule) = rules.iter().find(|rule| !rule.wildcard && rule.host == host) {
        return Some(rule.address);
    }
    rules
        .iter()
        .filter(|rule| rule.wildcard && rule.matches(&host))
        .max_by_key(|rule| rule.host.len())
        .map(|rule| rule.address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn rule(host: &str, answer: &str) -> DnsRewriteRule {
        DnsRewriteRule::parse(host, answer).expect("valid rule")
    }

    #[test]
    fn an_exact_rule_answers_the_host_and_nothing_below_it() {
        let rules = vec![rule("nas.home", "192.168.1.10")];
        assert_eq!(
            lookup(&rules, "nas.home"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
        assert_eq!(lookup(&rules, "www.nas.home"), None);
    }

    #[test]
    fn a_wildcard_covers_subdomains_but_not_the_apex() {
        let rules = vec![rule("*.lan", "10.0.0.2")];
        assert_eq!(
            lookup(&rules, "printer.lan"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(lookup(&rules, "lan"), None);
        assert_eq!(lookup(&rules, "lan.evil.test"), None);
    }

    #[test]
    fn an_exact_rule_wins_over_a_wildcard() {
        let rules = vec![
            rule("*.home", "10.0.0.2"),
            rule("router.home", "10.0.0.1"),
        ];
        assert_eq!(
            lookup(&rules, "router.home"),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn names_are_normalised_and_bad_answers_are_dropped() {
        let rules = vec![rule(" NAS.Home. ", " 192.168.1.10 ")];
        assert_eq!(
            lookup(&rules, "nas.home"),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)))
        );
        assert!(DnsRewriteRule::parse("host", "not-an-address").is_none());
        assert!(DnsRewriteRule::parse("", "10.0.0.1").is_none());
        assert!(DnsRewriteRule::parse("*.", "10.0.0.1").is_none());
    }
}
