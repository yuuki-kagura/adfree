//! `$app` values: the applications an AdGuard rule may be narrowed to.
//!
//! The basic `$app=` modifier and the non-basic bracket spelling share one
//! syntax (KB §`$app`): `|`-separated plain names, a trailing `*` wildcard,
//! and `/…/` regular expressions. A `~` negates the whole list, and the
//! knowledge base forbids mixing negated and plain entries.
//!
//! The network `$app=` layer keeps one engine per app ([`crate::filter`]);
//! the bracket layer asks [`AppMask::matches`] with the applications the
//! connection was attributed to.

use regex::Regex;

/// One entry of an `$app=` value list: a plain name, a name with a trailing
/// `*`, or a `/…/` regexp.
#[derive(Debug, Clone)]
pub enum AppEntry {
    /// A plain application name, matched lexicographically.
    Name(String),
    /// A wildcard entry: every application whose name starts with the prefix.
    Prefix(String),
    /// A regexp entry. It matches the way a basic URL regexp pattern does — a
    /// search, not an anchored match; the KB's own examples anchor with
    /// `^…$` where anchoring is meant.
    Regex(Regex),
}

impl AppEntry {
    pub(crate) fn matches(&self, app: &str) -> bool {
        match self {
            AppEntry::Name(name) => name == app,
            AppEntry::Prefix(prefix) => app.starts_with(prefix.as_str()),
            AppEntry::Regex(regex) => regex.is_match(app),
        }
    }
}

/// One parsed `$app=` value, ready to test the apps a flow belongs to.
#[derive(Debug, Clone)]
pub struct AppMask {
    entries: Vec<AppEntry>,
    /// The list was spelled with `~`: it covers every app its entries do not.
    negated: bool,
}

impl AppMask {
    /// Parses one `$app=` value. `None` when the value names nothing, mixes
    /// negated and plain entries, or carries an entry form the syntax does
    /// not have: the rule is dropped rather than applied wider than the list
    /// asked.
    pub fn parse(value: &str) -> Option<AppMask> {
        let values = [value.to_string()];
        let (entries, negated) = parse_app_entries(&values)?;
        Some(AppMask { entries, negated })
    }

    /// Whether any application of `apps` is covered. An unattributed flow
    /// (`apps` empty) matches nothing: the reference's `$app` names the app
    /// the request came from, and a rule with no such name cannot be shown to
    /// apply.
    pub fn matches(&self, apps: &[String]) -> bool {
        apps.iter().any(|app| {
            let hit = self.entries.iter().any(|entry| entry.matches(app));
            hit != self.negated
        })
    }
}

/// Parses the values of every `app=` token of one rule into entries, or `None`
/// when the rule cannot be run faithfully: an entry that names nothing, an
/// entry form the KB does not have, a regexp the regexp crate cannot run, or a
/// mix of negated and plain entries — the KB forbids one.
pub fn parse_app_entries(values: &[String]) -> Option<(Vec<AppEntry>, bool)> {
    let mut entries = Vec::new();
    let mut negated = None::<bool>;
    for value in values {
        for raw in split_app_value(value) {
            let raw = raw.trim();
            let (is_negated, body) = match raw.strip_prefix('~') {
                Some(body) => (true, body.trim()),
                None => (false, raw),
            };
            if body.is_empty() {
                return None;
            }
            if let Some(seen) = negated {
                if seen != is_negated {
                    return None;
                }
            } else {
                negated = Some(is_negated);
            }
            entries.push(parse_app_entry(body)?);
        }
    }
    (!entries.is_empty()).then(|| (entries, negated.unwrap_or(false)))
}

/// Splits the value of one `app=` token into entries: `|` separates them and a
/// backslash escapes it (as well as every character the entry parsers treat
/// specially inside a regexp).
fn split_app_value(value: &str) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 1 < bytes.len() {
            index += 2;
            continue;
        }
        if bytes[index] == b'|' {
            out.push(&value[start..index]);
            start = index + 1;
        }
        index += 1;
    }
    out.push(&value[start..]);
    out
}

/// One entry of an `app=` value: a `/…/` regexp, a trailing-`*` wildcard, or a
/// plain name. `None` for anything else — an entry this engine cannot name is
/// a rule it must not half-run.
fn parse_app_entry(body: &str) -> Option<AppEntry> {
    if body.starts_with('/') {
        let rest = body.strip_suffix('/')?;
        if rest.len() < 2 {
            return None;
        }
        let source = app_regex_unescape(&rest[1..]);
        return Regex::new(&source).ok().map(AppEntry::Regex);
    }
    if let Some(prefix) = body.strip_suffix('*') {
        // The wildcard is the last character and the only one; a bare `*`
        // names no application.
        if prefix.is_empty() || prefix.contains('*') {
            return None;
        }
        return Some(AppEntry::Prefix(prefix.to_string()));
    }
    if body.contains(['*', '|', '\\']) {
        return None;
    }
    Some(AppEntry::Name(body.to_string()))
}

/// Removes the rule-syntax escapes from a regexp entry (`/`, `$`, `,` and `|`
/// are escaped for the line parser, KB §`$app`); the regexp crate sees the
/// bare characters — `\$` is the end anchor there, not a literal dollar.
fn app_regex_unescape(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some(next) if matches!(next, '/' | '$' | ',' | '|') => out.push(next),
            Some(next) => {
                out.push('\\');
                out.push(next);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(value: &str) -> AppMask {
        AppMask::parse(value).expect("value should parse")
    }

    #[test]
    fn names_wildcards_and_regexps_match() {
        assert!(app("org.example.app").matches(&["org.example.app".to_string()]));
        assert!(!app("org.example.app").matches(&["org.example.other".to_string()]));
        assert!(app("org.example.*").matches(&["org.example.other".to_string()]));
        assert!(app(r#"/org\.example\.[a-z]+/"#).matches(&["org.example.app".to_string()]));
        assert!(!app(r#"/org\.example\.[a-z]+/"#).matches(&["com.example.app".to_string()]));
    }

    #[test]
    fn a_negated_list_covers_the_other_apps() {
        let mask = app("~org.example.app");
        assert!(!mask.matches(&["org.example.app".to_string()]));
        assert!(mask.matches(&["com.example.other".to_string()]));
    }

    #[test]
    fn an_unattributed_flow_matches_nothing() {
        assert!(!app("org.example.app").matches(&[]));
        assert!(!app("~org.example.app").matches(&[]));
    }

    #[test]
    fn impossible_lists_are_refused() {
        assert!(AppMask::parse("").is_none());
        assert!(AppMask::parse("org.example.app|~com.example.app").is_none());
        assert!(AppMask::parse("/[/").is_none());
        assert!(AppMask::parse("com.*.app").is_none());
    }
}
