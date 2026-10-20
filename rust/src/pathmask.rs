//! `$path` / `$url` — the bracket modifiers AdGuard lists pin a non-basic
//! rule to a page location with.
//!
//! The knowledge base writes these rules `[$path=…]rest` or `[$url=…]rest`
//! (create-own-filters, modifiers for non-basic type of rules): the bracket
//! carries the modifiers, and `rest` is the rule itself. CoreLibs applies
//! such a rule only on the pages the mask covers. `$path` matches the page's
//! path and query; `$path` with no value means the site's main page. `$url`
//! matches the whole page URL. A value is either a basic-rule pattern —
//! case-insensitive, `*` for any run of characters, `^` for a separator, a
//! leading or trailing `|` anchoring the two ends, `||` meaningful only for
//! a `$url` — or, enclosed in `/…/`, a regular expression, `\/` and `\:`
//! unescaped first.
//!
//! This module parses the bracket and compiles the masks; where the rules go
//! and how they are served is [`crate::filter`]'s half. The bracket's other
//! modifiers are read too, but only `$domain` is honored — moved onto the
//! rule's ordinary domain position — and only where that cannot change what
//! the rule means: a regexp domain cannot be spelled on a cosmetic rule (the
//! crate discards the rule), `$app` cannot be honored at all, and mixing the
//! two ways of spelling domains is invalid per the knowledge base, so the
//! rule is dropped rather than applied wider than the list asked.
//!
//! The pattern-to-regexp translation mirrors the crate's own
//! (`regex_manager::compile_regex`), so a mask matches exactly what a network
//! rule pattern matches.

use regex::bytes::{Regex as BytesRegex, RegexBuilder as BytesRegexBuilder};
use std::sync::OnceLock;

/// A compiled `$path` value.
#[derive(Debug, Clone)]
pub enum PathMask {
    /// `[$path]` with no value: the site's main page, and only it.
    MainPage,
    /// A pattern or a `/regexp/`; the subject is matched whole.
    Regex(BytesRegex),
}

impl PathMask {
    /// Compiles a `$path` value the way AdGuard reads it: `/…/` is a regular
    /// expression, anything else is a basic-rule pattern. `None` when the
    /// value cannot be a mask — the rule it sits on is dropped rather than
    /// applied everywhere.
    pub fn parse(value: &str) -> Option<PathMask> {
        if value.is_empty() {
            return None;
        }
        if value.len() >= 2 && value.starts_with('/') && value.ends_with('/') {
            // A complete regexp; the crate unescapes the two sequences the
            // knowledge base uses to smuggle `/` and `:` in and passes the
            // rest as written.
            let body = value[1..value.len() - 1]
                .replace("\\/", "/")
                .replace("\\:", ":");
            return BytesRegexBuilder::new(&body)
                .unicode(false)
                .build()
                .ok()
                .map(PathMask::Regex);
        }
        if value.contains("||") {
            // Domain anchors say nothing about a path.
            return None;
        }
        let mut pattern = String::new();
        let body = value.strip_prefix('|').unwrap_or(value);
        let (body, right_anchor) = match body.strip_suffix('|') {
            Some(body) => (body, true),
            None => (body, false),
        };
        if value.starts_with('|') {
            pattern.push('^');
        }
        pattern.push_str(&pattern_to_regex(body));
        if right_anchor {
            pattern.push('$');
        }
        BytesRegexBuilder::new(&pattern)
            .unicode(false)
            .case_insensitive(true)
            .build()
            .ok()
            .map(PathMask::Regex)
    }

    /// Whether the mask covers `subject` — a page's path and query, the same
    /// string AdGuard's own `$path` sees.
    pub fn matches(&self, subject: &str) -> bool {
        match self {
            // A query string does not make the main page another page.
            PathMask::MainPage => subject == "/" || subject.starts_with("/?"),
            PathMask::Regex(regexp) => regexp.is_match(subject.as_bytes()),
        }
    }
}

/// A compiled `$url` value: the page's whole URL.
#[derive(Debug, Clone)]
pub enum UrlMask {
    /// A pattern or a `/regexp/`; the subject is the full URL.
    Regex(BytesRegex),
}

impl UrlMask {
    /// Compiles a `$url` value the way AdGuard reads it: `/…/` is a regular
    /// expression, anything else is a basic-rule pattern. `None` when the
    /// value cannot be a mask — the rule it sits on is dropped rather than
    /// applied everywhere.
    pub fn parse(value: &str) -> Option<UrlMask> {
        if value.is_empty() {
            return None;
        }
        if value.len() >= 2 && value.starts_with('/') && value.ends_with('/') {
            let body = value[1..value.len() - 1]
                .replace("\\/", "/")
                .replace("\\:", ":");
            return BytesRegexBuilder::new(&body)
                .unicode(false)
                .build()
                .ok()
                .map(UrlMask::Regex);
        }
        let mut pattern = String::new();
        if let Some(rest) = value.strip_prefix("||") {
            // A hostname anchor, the one meaning a path could not have: the
            // scheme, any subdomain, then the host. `||example.com` names the
            // host itself, never a host that merely starts with it, so a
            // value with no tail also requires a hostname boundary.
            let (rest, right_anchor) = match rest.strip_suffix('|') {
                Some(rest) => (rest, true),
                None => (rest, false),
            };
            let (host, tail) = split_url_host(rest);
            if host.is_empty() {
                return None;
            }
            pattern.push_str("^(?:https?|wss?)://(?:[^/]+\\.)?");
            pattern.push_str(&pattern_to_regex(host));
            if tail.is_empty() {
                if right_anchor {
                    pattern.push('$');
                } else {
                    pattern.push_str("(?:[^\\w\\d\\._%-]|$)");
                }
            } else {
                pattern.push_str(&pattern_to_regex(tail));
                if right_anchor {
                    pattern.push('$');
                }
            }
        } else {
            let body = value.strip_prefix('|').unwrap_or(value);
            let (body, right_anchor) = match body.strip_suffix('|') {
                Some(body) => (body, true),
                None => (body, false),
            };
            if value.starts_with('|') {
                pattern.push('^');
            }
            pattern.push_str(&pattern_to_regex(body));
            if right_anchor {
                pattern.push('$');
            }
        }
        BytesRegexBuilder::new(&pattern)
            .unicode(false)
            .case_insensitive(true)
            .build()
            .ok()
            .map(UrlMask::Regex)
    }

    /// Whether the mask covers `url` — the page's whole URL.
    pub fn matches(&self, url: &str) -> bool {
        match self {
            UrlMask::Regex(regexp) => regexp.is_match(url.as_bytes()),
        }
    }
}

/// The host part of a `||` value and the rest of the pattern.
///
/// The host ends at the first character that cannot be one: a path, a
/// separator, a query, a fragment or a port. A `*` stays in the host part so
/// a wildcard host keeps its basic-rule meaning.
fn split_url_host(rest: &str) -> (&str, &str) {
    let end = rest
        .find(['/', '^', '?', '#', ':'])
        .unwrap_or(rest.len());
    (&rest[..end], &rest[end..])
}

/// The location one bracket puts a rule on: a path, a URL, or both (the
/// bracket may spell both, and then both must match).
#[derive(Debug, Clone)]
pub struct Location {
    /// `path` / `path=value`.
    pub path: Option<PathMask>,
    /// `url=value`.
    pub url: Option<UrlMask>,
}

impl Location {
    /// Whether the location covers the page at `url`.
    pub fn matches(&self, url: &str) -> bool {
        if let Some(path) = &self.path {
            if !path.matches(path_and_query(url)) {
                return false;
            }
        }
        if let Some(mask) = &self.url {
            if !mask.matches(url) {
                return false;
            }
        }
        true
    }
}

/// The path and query of a full URL, the `$path` subject. A URL that carries
/// neither (a bare origin) reads as the main page.
pub fn path_and_query(url: &str) -> &str {
    let rest = match url.find("://") {
        Some(index) => &url[index + 3..],
        None => url,
    };
    match rest.find('/') {
        Some(index) => &rest[index..],
        None => "/",
    }
}

/// What a line beginning `[$…]` turned out to be.
pub enum BracketParse {
    /// Not a bracket rule (no `[$` prefix, or the bracket never closes):
    /// the line goes on untouched, for the engine to deal with.
    NotBracket,
    /// A bracket holding something this engine cannot honor. `rest` is the
    /// rule text after the closing bracket, so the caller can tell whether it
    /// was a cosmetic rule at all.
    Unsupported { rest: String },
    /// A bracket the app can turn into what the list meant.
    Parsed(Bracket),
}

/// The contents of a `[$…]` bracket that this engine can honor.
pub struct Bracket {
    /// `path` or `path=value`, compiled. `None` when the bracket spells none.
    pub path: Option<PathMask>,
    /// `url=value`, compiled. `None` when the bracket spells none.
    pub url: Option<UrlMask>,
    /// `domain=…`, negations and `|` separators kept, pipe separators turned
    /// into the commas a cosmetic rule's domain position takes.
    pub domain: Option<String>,
    /// The rule text after the closing bracket.
    pub rest: String,
}

impl Bracket {
    /// The location the bracket pins the rule to; `None` when it only names
    /// a domain.
    pub fn location(self) -> Option<Location> {
        (!(self.path.is_none() && self.url.is_none())).then_some(Location {
            path: self.path,
            url: self.url,
        })
    }
}

/// Parses a `[$…]` bracket and the rule text that follows it.
///
/// `\[`, `\]`, `\,` and `\\` are the escapes the syntax defines; they are
/// undone in the values, and an escaped `]` does not close the bracket. An
/// unescaped `[` opens a nested class (a `/regexp/` value's `[0-9a-z]`),
/// whose `]` does not close the bracket either.
pub fn parse_bracket(line: &str) -> BracketParse {
    let Some(body) = line.strip_prefix("[$") else {
        return BracketParse::NotBracket;
    };
    // A `]` inside a regular expression's character class (`[0-9a-z]`) is
    // part of the value, not the end of the bracket. Lists write those
    // classes without the syntax's `\]` escape, so the scanner counts
    // nesting: an unescaped `[` opens a class and its `]` closes it.
    let mut end = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (index, ch) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' => depth += 1,
            ']' if depth == 0 => {
                end = Some(index);
                break;
            }
            ']' => depth -= 1,
            _ => {}
        }
    }
    // Unterminated: the engine's own parse throws the line away, with its own
    // diagnostics; leave it alone.
    let Some(end) = end else {
        return BracketParse::NotBracket;
    };
    let rest = body[end + 1..].to_string();

    // Split the modifiers on unescaped commas. Only `[`, `]`, `,` and `\`
    // are the syntax's own escapes (KB §non-basic-rules-modifiers-syntax);
    // any other backslash belongs to the value — a `$url` regexp is full of
    // them — and stays exactly where the list wrote it.
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut chars = body[..end].chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.peek() {
                Some(&next) if matches!(next, '[' | ']' | ',' | '\\') => {
                    current.push(next);
                    chars.next();
                }
                _ => current.push('\\'),
            },
            ',' => parts.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    parts.push(current);

    let mut path: Option<PathMask> = None;
    let mut path_seen = false;
    let mut url: Option<UrlMask> = None;
    let mut url_seen = false;
    let mut domain: Option<String> = None;
    for part in &parts {
        let (name, value) = match part.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (part.as_str(), None),
        };
        match (name, value) {
            ("path", None) => {
                if path_seen {
                    return BracketParse::Unsupported { rest };
                }
                path_seen = true;
                path = Some(PathMask::MainPage);
            }
            ("path", Some(value)) => {
                if path_seen {
                    return BracketParse::Unsupported { rest };
                }
                path_seen = true;
                match PathMask::parse(value) {
                    Some(mask) => path = Some(mask),
                    None => return BracketParse::Unsupported { rest },
                }
            }
            ("url", Some(value)) => {
                if url_seen {
                    return BracketParse::Unsupported { rest };
                }
                url_seen = true;
                match UrlMask::parse(value) {
                    Some(mask) => url = Some(mask),
                    None => return BracketParse::Unsupported { rest },
                }
            }
            ("url", None) => {
                // `$url` has no valueless spelling.
                return BracketParse::Unsupported { rest };
            }
            ("domain", Some(value)) => {
                // A negated value is spelled `~domain`; its bare form is what
                // the regexp check has to see through.
                let bare = value.strip_prefix('~').unwrap_or(value);
                if domain.is_some() || bare.is_empty() || bare.starts_with('/') {
                    return BracketParse::Unsupported { rest };
                }
                domain = Some(value.replace('|', ","));
            }
            // `$app`, a `domain` without a value, an empty modifier: nothing
            // this engine can honor.
            _ => return BracketParse::Unsupported { rest },
        }
    }

    BracketParse::Parsed(Bracket {
        path,
        url,
        domain,
        rest,
    })
}

/// Translates a basic-rule pattern into the regexp body that matches it,
/// mirroring the crate's translator character for character.
fn pattern_to_regex(pattern: &str) -> String {
    static SPECIAL: OnceLock<regex::Regex> = OnceLock::new();
    static WILDCARD: OnceLock<regex::Regex> = OnceLock::new();
    static ANCHOR: OnceLock<regex::Regex> = OnceLock::new();
    static ANCHOR_EOL: OnceLock<regex::Regex> = OnceLock::new();

    let special = SPECIAL.get_or_init(|| regex::Regex::new(r"([\|\.\$\+\?\{\}\(\)\[\]])").unwrap());
    let wildcard = WILDCARD.get_or_init(|| regex::Regex::new(r"\*").unwrap());
    let anchor = ANCHOR.get_or_init(|| regex::Regex::new(r"\^(.)").unwrap());
    let anchor_eol = ANCHOR_EOL.get_or_init(|| regex::Regex::new(r"\^$").unwrap());

    let repl = special.replace_all(pattern, "\\$1");
    let repl = wildcard.replace_all(&repl, ".*");
    // `^` is a separator: anything but a letter, a digit or `_ - . %`.
    let repl = anchor.replace_all(&repl, "(?:[^\\w\\d\\._%-])$1");
    let repl = anchor_eol.replace_all(&repl, "(?:[^\\w\\d\\._%-]|$)");
    repl.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(value: &str) -> PathMask {
        PathMask::parse(value).expect("value should compile")
    }

    #[test]
    fn bare_path_is_the_main_page() {
        let main = PathMask::MainPage;
        assert!(main.matches("/"));
        assert!(main.matches("/?utm_source=x"));
        assert!(!main.matches("/tv"));
        assert!(!main.matches("/index.html"));
    }

    #[test]
    fn patterns_are_substrings_like_basic_rules() {
        let m = mask("page.html");
        assert!(m.matches("/page.html"));
        assert!(m.matches("/page.html?a=b"));
        assert!(m.matches("/sub/page.html"));
        assert!(m.matches("/another_page.html"));
        let m = mask("/page.html");
        assert!(m.matches("/page.html"));
        assert!(m.matches("/sub/page.html"));
        assert!(!m.matches("/another_page.html"));
    }

    #[test]
    fn patterns_honor_anchors_and_wildcards() {
        let m = mask("|/page.html");
        assert!(m.matches("/page.html"));
        assert!(!m.matches("/sub/page.html"));
        let m = mask("/page.html|");
        assert!(m.matches("/page.html"));
        assert!(m.matches("/sub/page.html"));
        assert!(!m.matches("/page.html?a=b"));
        let m = mask("/page*.html");
        assert!(m.matches("/page1.html"));
        assert!(m.matches("/page.html"));
    }

    #[test]
    fn caret_separator_matches_like_a_network_pattern() {
        let m = mask("/foo^bar");
        assert!(m.matches("/foo/bar"));
        assert!(m.matches("/foo?bar"));
        assert!(!m.matches("/fooxbar"));
    }

    #[test]
    fn regexp_values_match_as_written() {
        // The knowledge base example, with the escapes its syntax requires.
        let m = mask(r"/\/(sub1|sub2)\/page\.html/");
        assert!(m.matches("/sub1/page.html"));
        assert!(m.matches("/sub2/page.html"));
        assert!(!m.matches("/sub3/page.html"));
    }

    #[test]
    fn unusable_values_do_not_compile() {
        assert!(PathMask::parse("").is_none());
        assert!(PathMask::parse("||example.com").is_none());
        assert!(PathMask::parse("/(/").is_none());
    }

    #[test]
    fn url_patterns_anchor_on_the_whole_url() {
        let m = UrlMask::parse("||example.com/content/*").expect("mask");
        assert!(m.matches("https://example.com/content/a"));
        assert!(m.matches("https://sub.example.com/content/a"));
        assert!(m.matches("http://example.com/content/a"));
        assert!(!m.matches("https://evilexample.com/content/a"));

        // A bare host anchor names that host and its subdomains, never a
        // hostname that merely starts with the same letters.
        let m = UrlMask::parse("||example.com^").expect("mask");
        assert!(m.matches("https://example.com/"));
        assert!(m.matches("https://example.com:8443/x"));
        assert!(m.matches("https://sub.example.com/x"));
        assert!(!m.matches("https://example.com.evil/"));

        let m = UrlMask::parse("||example.com").expect("mask");
        assert!(m.matches("https://example.com/"));
        assert!(!m.matches("https://example.com.evil/"));

        // A trailing `|` anchors the end of the whole URL.
        let m = UrlMask::parse("||example.com/path|").expect("mask");
        assert!(m.matches("https://example.com/path"));
        assert!(!m.matches("https://example.com/path?q=1"));
    }

    #[test]
    fn url_regexp_values_keep_their_escapes() {
        let m = UrlMask::parse(r"/^https:\/\/shop\.test\/video\?ref=/").expect("mask");
        assert!(m.matches("https://shop.test/video?ref=x"));
        assert!(!m.matches("https://shop.test/video"));
        assert!(!m.matches("https://other.test/video?ref=x"));
    }

    #[test]
    fn bracket_keeps_regexp_character_classes_together() {
        // The live lines spell their classes without `\]`; the scanner must
        // not stop at the first one.
        let line = r"[$url=/^https:\/\/[0-9a-z]{5}[0-9a-z]?\.[a-z]{2}[a-z]?\/[0-9a-z-]+\/[0-9A-Za-z]{12}[0-9A-Za-z]*\?ref(erer)?=/]$$script";
        let BracketParse::Parsed(bracket) = parse_bracket(line) else {
            panic!("bracket should parse");
        };
        assert_eq!(bracket.rest, "$$script");
        let Some(UrlMask::Regex(mask)) = bracket.url else {
            panic!("url should compile");
        };
        assert!(mask.is_match(b"https://abcde.com/foo/abcdefghijkl?referer=x"));
    }

    #[test]
    fn the_live_url_regexp_matches() {
        let m = UrlMask::parse(
            r"/^https:\/\/[0-9a-z]{5}[0-9a-z]?[0-9a-z]?[0-9a-z]?\.[a-z]{2}[a-z]?[a-z]?[a-z]?\/[0-9a-z-]+\/[0-9A-Za-z]{12}[0-9A-Za-z]*\?ref(erer)?=/",
        )
        .expect("mask");
        assert!(m.matches("https://abcde.com/foo/abcdefghijkl?referer=x"));
    }

    #[test]
    fn unusable_url_values_do_not_compile() {
        assert!(UrlMask::parse("").is_none());
        assert!(UrlMask::parse("||").is_none());
        assert!(UrlMask::parse("||/path").is_none());
        assert!(UrlMask::parse("/(/").is_none());
    }

    #[test]
    fn bracket_carries_url_and_leaves_the_regexp_escapes_alone() {
        let BracketParse::Parsed(bracket) =
            parse_bracket(r"[$url=/^https:\/\/shop\.test\/video\?ref=/]##.x")
        else {
            panic!("bracket should parse");
        };
        let Some(UrlMask::Regex(mask)) = bracket.url else {
            panic!("url should compile");
        };
        assert!(mask.is_match(b"https://shop.test/video?ref=x"));
        assert_eq!(bracket.rest, "##.x");
    }

    #[test]
    fn bracket_carries_path_and_the_rest_of_the_rule() {
        let BracketParse::Parsed(bracket) = parse_bracket("[$path=/tv]yandex.*##.promo") else {
            panic!("bracket should parse");
        };
        assert!(matches!(bracket.path, Some(PathMask::Regex(_))));
        assert!(bracket.domain.is_none());
        assert_eq!(bracket.rest, "yandex.*##.promo");
        assert!(matches!(
            parse_bracket("[$path]f95zone.to##.node"),
            BracketParse::Parsed(_)
        ));
    }

    #[test]
    fn bracket_domain_keeps_negations_and_becomes_commas() {
        let BracketParse::Parsed(bracket) =
            parse_bracket("[$domain=facebook.com|~video.facebook.com,path=/gaming]#$#body > .AdBox")
        else {
            panic!("bracket should parse");
        };
        assert_eq!(
            bracket.domain.as_deref(),
            Some("facebook.com,~video.facebook.com")
        );
        assert_eq!(bracket.rest, "#$#body > .AdBox");
    }

    #[test]
    fn bracket_escapes_do_not_split_or_close() {
        let BracketParse::Parsed(bracket) = parse_bracket(r"[$path=/a\]b\,c]##.x") else {
            panic!("bracket should parse");
        };
        let Some(PathMask::Regex(mask)) = bracket.path else {
            panic!("path should compile");
        };
        assert!(mask.is_match(br"/a]b,c"));
        assert_eq!(bracket.rest, "##.x");
    }

    #[test]
    fn unsupported_brackets_report_their_rule_text() {
        for line in [
            "[$app=org.example.app]##.textad",
            "[$url]##.textad",
            "[$path=/a,path=/b]##.textad",
            "[$path=||example.com]##.textad",
            "[$domain=/re/]##.textad",
            "[$domain=~/re/]##.textad",
            "[$domain=]##.textad",
            "[$]##.textad",
        ] {
            match parse_bracket(line) {
                BracketParse::Unsupported { rest } => assert!(
                    rest.contains("##.textad"),
                    "{line}: rest should be the rule text, got {rest:?}"
                ),
                _ => panic!("{line} should be unsupported"),
            }
        }
    }

    #[test]
    fn non_brackets_stay_untouched() {
        assert!(matches!(
            parse_bracket("example.com##.textad"),
            BracketParse::NotBracket
        ));
        assert!(matches!(
            parse_bracket("[$path=/x"),
            BracketParse::NotBracket
        ));
    }

    #[test]
    fn path_and_query_reads_the_url() {
        assert_eq!(path_and_query("https://shop.test/a/b?c=d"), "/a/b?c=d");
        assert_eq!(path_and_query("https://shop.test/"), "/");
        assert_eq!(path_and_query("https://shop.test"), "/");
        assert_eq!(path_and_query("shop.test/tv"), "/tv");
    }
}
