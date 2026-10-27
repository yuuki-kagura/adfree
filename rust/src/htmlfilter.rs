//! HTML filtering rules: the `$$` selector of AdGuard and the `##^` selector
//! of uBlock Origin.
//!
//! Both syntaxes cut elements out of a response *document* before the browser
//! parses it. `[domains]$$selector` (exception `[domains]$@$selector`) is
//! AdGuard's own form; `[domains]##^selector` (exception `#@^`) is uBO's. The
//! crate this engine is built on has no action for either, so both the
//! matching (see [`crate::filter::FilterEngine::html_plan`]) and the edit
//! live here.
//!
//! The knowledge base's two implementations read the same text very
//! differently, and the lists are written for whichever one runs them. The
//! scanner keeps the two apart by syntax, not by pseudo name:
//!
//! - `$$` rules are read the way CoreLibs (AdGuard for Android, the product
//!   this engine aims at) reads them, and the way the AdGuard catalogue is
//!   written: `[attr="value"]` puts the value anywhere in the attribute's
//!   value (`attr*=` is the same predicate), an attribute with no value tests
//!   presence, `:contains()` / `:-abp-contains()` / `:has-text()` searches
//!   the element's inner markup case-sensitively (a `/regexp/flags` argument
//!   is a regexp), and the special attributes (`tag-content`, `wildcard`,
//!   `min-length`, `max-length`) are the reference's own. Anything a CoreLibs
//!   rule can hold beyond that — CSS operators (`^=`, `~=`, …), class and id
//!   sugar, selector lists, a content predicate left of a `>` — is dropped
//!   and counted rather than approximated.
//! - `##^` rules are read the way uBO reads them: a full-enough CSS selector
//!   (tag, classes, ids, attribute operators, `:has-text()` case-insensitively
//!   over the element's text, `/regexp/` or `/regexp/i` for the argument),
//!   with a hostname required on a blocking rule. uBO's procedural operators
//!   (`:has()`, `:xpath()`, …) and `##^responseheader(…)` are dropped and
//!   counted.
//!
//! The edit itself never re-serializes the document: the bytes between the
//! cut elements travel through exactly as they arrived. A round trip through
//! a DOM would rewrite the whole page — entities, quoting, implied tags — and
//! with it any nonce or hash a policy is pinned to. Where the reference walks
//! a SAX stream, this scanner walks the same bytes: tags, attributes,
//! comments, raw-text elements, void elements and the parser's own implied
//! end tags, with an element stack so a `>` chain can ask about a parent. A
//! rule with a content predicate reads the element's inner bytes (the
//! "innerHTML" the knowledge base measures); a uBO rule reads them with the
//! markup taken out, the closest a byte scanner gets to `textContent`.
//!
//! Rules that cannot run are dropped at load and counted, never guessed at:
//!
//! - the removal of `<html>`, `<head>` and `<body>` is refused (the reference
//!   cannot take `<body>` out either), and an element that never closes ends
//!   where the document ends, the way a parser reads it;
//! - the `max-length` default of the knowledge base (8192) applies to every
//!   rule carrying a content predicate, so a rule that means to look inside a
//!   larger script spells its own cap — which is why the converters always
//!   add one ([`DEFAULT_MAX_LENGTH`]);
//! - `regexp` patterns are compiled here and now; a pattern the `regex` crate
//!   cannot compile (a lookaround of another shape, a backreference) drops
//!   its rule. The knowledge base's own conversion table spells its length
//!   tests as `^(?=.{m,n}$).*/s`, which this scanner recognizes and answers
//!   natively.

use crate::appmask::AppMask;
use crate::pathmask::{self, BracketParse, Location};
use aho_corasick::AhoCorasick;
use regex::bytes::Regex;
use std::collections::{HashMap, HashSet};

/// The `max-length` a rule with a content predicate gets when it spells none.
///
/// The knowledge base gives the attribute that default, and the lists are
/// written around it: a rule that means to look inside a script larger than
/// this carries its own `[max-length=…]` (the uBO-to-AdGuard converters add
/// 262144 on principle), and no rule in the catalogue spells a `min-length`
/// above it without a matching `max-length`.
const DEFAULT_MAX_LENGTH: usize = 8192;

/// Elements whose removal is refused: they are the document itself, and the
/// reference cannot take them out either (CoreLibs refuses `<body>`).
const PROTECTED_ELEMENTS: &[&str] = &["html", "head", "body"];

/// Elements with no end tag: they are matched and removed on their own.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

/// Elements whose content holds no markup a parser reads: everything up to
/// the matching end tag is opaque. Rules never match inside them, and a
/// content predicate on the element itself reads the raw bytes — what the DOM
/// reports for `script` and `style`, and the safe reading for `noscript` and
/// `template` (their content is not part of the document's element tree).
const RAW_TEXT_ELEMENTS: &[&str] = &[
    "script", "style", "textarea", "title", "noscript", "template",
];

/// Block-level start tags that close an open `<p>` (the parser's own rule): a
/// rule naming a `<p>` must see the element end where the parser ends it.
const P_CLOSERS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "details",
    "div",
    "dl",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hgroup",
    "hr",
    "li",
    "main",
    "menu",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "ul",
];

/// The syntax family a rule was written in: the two spell the same feature
/// with different selectors and different defaults.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Syntax {
    /// `$$` / `$@$`: CoreLibs semantics.
    AdGuard,
    /// `##^` / `#@^`: uBO semantics.
    Ubo,
}

/// Which bytes a content predicate reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TextMode {
    /// The element's inner bytes, markup included (CoreLibs' stream, the
    /// knowledge base's "innerHTML").
    Inner,
    /// The inner bytes with the markup taken out (uBO's `textContent`, as
    /// close as a byte scanner gets).
    Text,
}

/// A parsed `$$` / `##^` rule.
#[derive(Clone, Debug)]
pub struct Rule {
    /// The domain position: what stands before the marker, or the bracket's
    /// `$domain=`. `None` applies to every host.
    domains: Option<DomainSpec>,
    /// The rule's location, matched against the page: the bracket's
    /// `$path=` / `$url=` or a path-in-domain target. `None` when the rule
    /// is not pinned to a page location.
    location: Option<Location>,
    /// `[$app=…]`: the applications the rule is narrowed to. `None` when the
    /// bracket spelled none.
    app: Option<AppMask>,
    /// The compound chain: `chain.last()` is the element itself, the ones
    /// before it its ancestors under `>`.
    chain: Vec<Compound>,
    /// The syntax family, for the content reading ([`TextMode`]).
    syntax: Syntax,
    /// The selector text as the list wrote it, for logs.
    text: String,
    /// The fingerprint two rules' selectors must share for an exception to
    /// cancel a rule (the reference compares selectors, not domains).
    canonical: String,
}

/// A rule's domain position, read once when the rule is parsed.
///
/// Splitting and lowercasing the list spelling per page would repeat the
/// same work for every rule and every request; the plan build now hands the
/// parsed position a host that is already normalized.
#[derive(Clone, Debug)]
struct DomainSpec {
    entries: Vec<DomainEntry>,
}

#[derive(Clone, Debug)]
struct DomainEntry {
    negated: bool,
    kind: DomainKind,
}

#[derive(Clone, Debug)]
enum DomainKind {
    /// `*`: every host.
    Any,
    /// `base.*`: the base label appears as a whole label of the host.
    WildTld(String),
    /// `example.com` / `*.example.com`: the host or one of its parents.
    Suffix(String),
}

impl DomainSpec {
    /// `None` for "no position written": the rule applies to every host.
    fn parse(position: Option<&str>) -> Option<DomainSpec> {
        let position = position?;
        let mut entries = Vec::new();
        for entry in position.split(',') {
            let entry = entry.trim().to_ascii_lowercase();
            if entry.is_empty() {
                continue;
            }
            let (negated, entry) = match entry.strip_prefix('~') {
                Some(rest) => (true, rest),
                None => (false, entry.as_str()),
            };
            let kind = if entry.is_empty() {
                continue;
            } else if entry == "*" {
                DomainKind::Any
            } else if let Some(base) = entry.strip_suffix(".*") {
                DomainKind::WildTld(base.to_string())
            } else {
                DomainKind::Suffix(entry.strip_prefix("*.").unwrap_or(entry).to_string())
            };
            entries.push(DomainEntry { negated, kind });
        }
        Some(DomainSpec { entries })
    }

    /// Whether `host` passes the position. `host` must already be trimmed of
    /// its trailing dot and lowercased.
    fn matches(&self, host: &str) -> bool {
        let mut positive = false;
        let mut matched = false;
        for entry in &self.entries {
            let hit = match &entry.kind {
                DomainKind::Any => true,
                DomainKind::WildTld(base) => wild_tld_matches(host, base),
                DomainKind::Suffix(domain) => suffix_matches(host, domain),
            };
            if entry.negated {
                if hit {
                    return false;
                }
            } else {
                positive = true;
                matched |= hit;
            }
        }
        !positive || matched
    }
}

/// `example.*` in the reference's reading: the base label has a dot after it,
/// at the start of the host or between two labels.
fn wild_tld_matches(host: &str, base: &str) -> bool {
    if base.is_empty() {
        return false;
    }
    let host = host.as_bytes();
    let base = base.as_bytes();
    if host.len() > base.len() && host.starts_with(base) && host[base.len()] == b'.' {
        return true;
    }
    host.windows(base.len() + 2).any(|window| {
        window[0] == b'.' && &window[1..base.len() + 1] == base && window[base.len() + 1] == b'.'
    })
}

/// `example.com`: the host itself or a subdomain of it.
fn suffix_matches(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

/// What one line turned out to be.
pub enum Parsed {
    /// A blocking rule.
    Rule(Rule),
    /// An exception rule (`$@$` / `#@^`).
    Exception(Rule),
    /// Several rules from one line: a path-in-domain domain position names
    /// one rule per target, each with its own domain and location.
    Many {
        blocking: Vec<Rule>,
        exceptions: Vec<Rule>,
    },
    /// HTML filtering the scanner cannot honour: dropped and counted.
    Unsupported,
    /// Not an HTML filtering rule.
    NotHtml,
}

/// How one attribute predicate matches.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AttrMatch {
    /// The attribute is there, whatever its value (`[attr]`).
    Present,
    /// Anywhere inside the value. Both `=` and `*=` are this in the CoreLibs
    /// reading, and `*=` is this in CSS too.
    Substring(String),
    /// The whole value (`[attr="value"]` in the CSS reading).
    Exact(String),
    Prefix(String),
    Suffix(String),
    /// One whitespace-separated token of the value is this (`~=`).
    Token(String),
    /// The value is this or starts with `this-` (`|=`).
    PrefixOrToken(String),
}

/// One content predicate: something the element's content must carry.
#[derive(Clone, Debug)]
enum Content {
    /// A literal searched in the element's content. The needle is stored
    /// lowercased when the search ignores case; `ci` is the same needle as a
    /// case-insensitive matcher, so the search never has to copy (and
    /// lowercase) the element's content per rule.
    Text {
        needle: String,
        case_insensitive: bool,
        ci: Option<AhoCorasick>,
    },
    /// A regular expression searched in the element's content.
    Regex(Regex),
    /// A `*`-glob the whole content must match.
    Glob(Glob),
    /// The content's length in bytes.
    MinLen(usize),
    MaxLen(usize),
}

impl Content {
    /// A literal content search. Callers pass the needle already lowercased
    /// for a case-insensitive one.
    fn text(needle: impl Into<String>, case_insensitive: bool) -> Content {
        let needle = needle.into();
        let ci = case_insensitive.then(|| {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build([needle.as_str()])
                .expect("a single literal always builds")
        });
        Content::Text {
            needle,
            case_insensitive,
            ci,
        }
    }
}

/// A `*`-wildcard pattern: literal pieces that must appear in order.
#[derive(Clone, Debug)]
struct Glob {
    parts: Vec<String>,
    lead: bool,
    trail: bool,
}

/// One compound selector: a tag, classes and ids, attributes, and the content
/// predicates that decide it.
#[derive(Clone, Debug, Default)]
struct Compound {
    tag: Option<String>,
    id: Option<String>,
    classes: Vec<String>,
    attrs: Vec<(String, AttrMatch)>,
    content: Vec<Content>,
}

impl Compound {
    /// Whether the element's own parts — tag, id, classes, attributes — let
    /// the compound through. Content predicates are asked separately: they
    /// need the element to have ended.
    fn matches_element(&self, name: &str, attrs: &[(String, Option<String>)]) -> bool {
        if let Some(tag) = &self.tag {
            if tag != name {
                return false;
            }
        }
        if let Some(id) = &self.id {
            match attribute(attrs, "id") {
                Some(Some(value)) if value == id => {}
                _ => return false,
            }
        }
        for class in &self.classes {
            match attribute(attrs, "class") {
                Some(Some(value)) if value.split_whitespace().any(|token| token == class) => {}
                _ => return false,
            }
        }
        for (name, matcher) in &self.attrs {
            if !attr_matches(attribute(attrs, name), matcher) {
                return false;
            }
        }
        true
    }
}

/// The first occurrence of an attribute, as the DOM keeps it.
fn attribute<'a>(attrs: &'a [(String, Option<String>)], name: &str) -> Option<&'a Option<String>> {
    attrs
        .iter()
        .find(|(attr, _)| attr == name)
        .map(|(_, value)| value)
}

/// Whether one attribute's value satisfies one predicate.
fn attr_matches(value: Option<&Option<String>>, matcher: &AttrMatch) -> bool {
    let Some(Some(text)) = value else {
        // An attribute with no value is presence (`[attr=""]` reads the same
        // way); an absent attribute matches nothing.
        return value.is_some() && matches!(matcher, AttrMatch::Present);
    };
    match matcher {
        AttrMatch::Present => true,
        AttrMatch::Substring(needle) => text.contains(needle.as_str()),
        AttrMatch::Exact(needle) => text == needle,
        AttrMatch::Prefix(needle) => text.starts_with(needle.as_str()),
        AttrMatch::Suffix(needle) => text.ends_with(needle.as_str()),
        AttrMatch::Token(needle) => text.split_whitespace().any(|token| token == needle),
        AttrMatch::PrefixOrToken(needle) => {
            text == needle
                || text.starts_with(&format!("{needle}-"))
                || text.split_whitespace().any(|token| token == needle)
        }
    }
}

/// Reads one line: the rule it is, HTML filtering the scanner cannot honour,
/// or neither.
pub fn parse_line(line: &str) -> Parsed {
    // A `[$…]` bracket names the rule's location (and may name the domain
    // position or the applications); the cosmetic scanner refuses the same
    // shapes, and so does this one.
    match pathmask::parse_bracket(line) {
        BracketParse::NotBracket => rule_line(None, None, None, line),
        BracketParse::Unsupported { rest } => {
            if marker(&rest).is_some() {
                Parsed::Unsupported
            } else {
                Parsed::NotHtml
            }
        }
        BracketParse::Parsed(bracket) => {
            let location = bracket.location();
            let app = bracket.app;
            rule_line(bracket.domain, location, app, &bracket.rest)
        }
    }
}

/// Finishes a rule once the marker is out of the way.
fn rule_line(
    bracket_domain: Option<String>,
    location: Option<Location>,
    app: Option<AppMask>,
    rest: &str,
) -> Parsed {
    let Some((index, marker)) = marker(rest) else {
        return Parsed::NotHtml;
    };
    let exception = matches!(marker, "$@$" | "#@^");
    let syntax = if marker.ends_with('$') {
        Syntax::AdGuard
    } else {
        Syntax::Ubo
    };
    let prefix = rest[..index].trim();
    // A bracket names the domain position; a prefix beside it is the "mixed
    // styles" the cosmetic scanner refuses too.
    if bracket_domain.is_some() && !prefix.is_empty() {
        return Parsed::Unsupported;
    }
    // `$url` is not compatible with a domain-specific rule (KB §`$url`
    // limitations); a rule's own domain position beside the URL mask is
    // refused, like the cosmetic scanner refuses it.
    if location
        .as_ref()
        .is_some_and(|location| location.url.is_some())
        && !prefix.is_empty()
    {
        return Parsed::Unsupported;
    }
    // A path-in-domain target and a bracket `$path` are two path scopes on
    // one rule; the reference does not define the pair, and honouring one
    // would apply the rule too wide.
    if location.is_some() && prefix.contains('/') && path_in_domain_candidate(prefix) {
        return Parsed::Unsupported;
    }
    let selector = rest[index + marker.len()..].trim();
    if selector.is_empty() {
        return Parsed::Unsupported;
    }
    if bracket_domain.is_none() && path_in_domain_candidate(prefix) && prefix.contains('/') {
        let targets = match pathmask::parse_targets(prefix) {
            pathmask::TargetsParse::NotTargets => None,
            pathmask::TargetsParse::Unsupported => return Parsed::Unsupported,
            pathmask::TargetsParse::Targets(targets) => Some(targets),
        };
        if let Some(targets) = targets {
            let Ok(chain) = parse_chain(selector, syntax) else {
                return Parsed::Unsupported;
            };
            let canonical = canonical(&chain, syntax);
            let mut blocking = Vec::new();
            let mut exceptions = Vec::new();
            for target in targets {
                let domains = target.domain.as_deref();
                let location = match (target.path, target.authority) {
                    (None, Some(authority)) => Some(Location {
                        path: None,
                        url: None,
                        authority: Some(authority),
                    }),
                    (path, None) => path.map(|path| Location {
                        path: Some(path),
                        url: None,
                        authority: None,
                    }),
                    (Some(_), Some(_)) => None,
                };
                // uBO writes a hostname on every blocking HTML filter; a
                // path-in-domain target is that hostname.
                if syntax == Syntax::Ubo && !exception && domains.is_none() && location.is_none() {
                    return Parsed::Unsupported;
                }
                let rule = Rule {
                    domains: DomainSpec::parse(domains),
                    location,
                    app: app.clone(),
                    chain: chain.clone(),
                    syntax,
                    text: selector.to_string(),
                    canonical: canonical.clone(),
                };
                if exception {
                    exceptions.push(rule);
                } else {
                    blocking.push(rule);
                }
            }
            // One target is the ordinary parse result; several targets can
            // only travel as a list.
            if exceptions.is_empty() && blocking.len() == 1 {
                return Parsed::Rule(blocking.pop().expect("one rule"));
            }
            if blocking.is_empty() && exceptions.len() == 1 {
                return Parsed::Exception(exceptions.pop().expect("one rule"));
            }
            return Parsed::Many {
                blocking,
                exceptions,
            };
        }
    }
    if !domain_position_ok(prefix) {
        return Parsed::NotHtml;
    }
    let domain_position: Option<&str> = if !prefix.is_empty() {
        Some(prefix)
    } else {
        bracket_domain.as_deref()
    };
    // uBO writes a hostname on every blocking HTML filter; a generic one is
    // refused by the reference itself.
    if syntax == Syntax::Ubo && !exception && domain_position.is_none() {
        return Parsed::Unsupported;
    }
    let Ok(chain) = parse_chain(selector, syntax) else {
        return Parsed::Unsupported;
    };
    let canonical = canonical(&chain, syntax);
    let rule = Rule {
        domains: DomainSpec::parse(domain_position),
        location,
        app,
        chain,
        syntax,
        text: selector.to_string(),
        canonical,
    };
    if exception {
        Parsed::Exception(rule)
    } else {
        Parsed::Rule(rule)
    }
}

/// The earliest HTML filtering marker in the rule text, with the marker.
fn marker(text: &str) -> Option<(usize, &'static str)> {
    const MARKERS: [&str; 4] = ["$$", "$@$", "##^", "#@^"];
    MARKERS
        .iter()
        .filter_map(|marker| text.find(marker).map(|index| (index, *marker)))
        .min_by_key(|(index, _)| *index)
}

/// Whether a text before a marker can be a path-in-domain domain position.
/// A whole-target regexp starts and ends with `/`; a plain target has a
/// domain-like part before its first `/`, while the path and query after it
/// may hold any URL text. Anything else (`#%#`, a selector fragment, a
/// modifier) is not a target, and the caller falls back to the ordinary
/// domain-position check.
fn path_in_domain_candidate(prefix: &str) -> bool {
    if prefix.starts_with('/') {
        return prefix.ends_with('/') && prefix.len() >= 2;
    }
    // Only the target domains (before the first `/`) have to be domain-like;
    // the path and query may hold `?`, `=`, `&`, `%`, `$`, … and must not make
    // the rule look like a selector or a network pattern.
    let Some(slash) = prefix.find('/') else {
        return false;
    };
    let domains = &prefix[..slash];
    !domains.is_empty()
        && domains.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '~' | '*' | ',' | ' ')
        })
}

/// Whether a text before a marker can be a domain position.
///
/// A rule marker is two characters that appear in all sorts of other rules
/// too: a scriptlet's argument may carry `$$`, a cosmetic selector may hold
/// `##^` inside an argument. A domain position holds nothing but domain-list
/// characters, which is what keeps those lines out.
fn domain_position_ok(prefix: &str) -> bool {
    prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '~' | ',' | '*' | ' '))
}

/// Splits a selector into its `>` chain of compounds and parses each.
///
/// A content predicate may only stand on the rightmost compound: the
/// reference cannot test a parent's content, and a rule that asks for one is
/// dropped rather than run half-way.
fn parse_chain(text: &str, syntax: Syntax) -> Result<Vec<Compound>, ()> {
    let mut chain = Vec::new();
    let mut rest = text.trim();
    loop {
        let (head, tail) = split_top_level(rest)?;
        chain.push(parse_compound(head.trim(), syntax)?);
        match tail {
            Some(tail) => rest = tail.trim(),
            None => break,
        }
    }
    for compound in &chain[..chain.len() - 1] {
        if !compound.content.is_empty() {
            return Err(());
        }
    }
    Ok(chain)
}

/// Splits at the first `>` outside parentheses and brackets.
///
/// The parentheses matter: `:contains(a > b)` holds a comparator, not a
/// combinator, and the same goes for an attribute value's `>` (always inside
/// a bracket). Quotes are *not* tracked: the corpus writes lone quotes inside
/// `:contains` arguments (`:contains({"zone_id":")`), and a `)` inside an
/// attribute value (`[wildcard="*.name)throw…"]`) closes nothing. The two
/// counters are counts, not nesting: a closer without a matching opener is
/// left to the compound parser, which refuses the shapes this scanner cannot
/// read.
fn split_top_level(text: &str) -> Result<(&str, Option<&str>), ()> {
    let mut parens = 0usize;
    let mut brackets = 0usize;
    for (index, c) in text.char_indices() {
        match c {
            '(' => parens += 1,
            ')' => parens = parens.saturating_sub(1),
            '[' => brackets += 1,
            ']' => brackets = brackets.saturating_sub(1),
            '>' if parens == 0 && brackets == 0 => {
                return Ok((&text[..index], Some(&text[index + 1..])))
            }
            _ => {}
        }
    }
    // Unbalanced parentheses are the corpus norm: `:contains` reads its
    // argument to the *last* `)` of the selector, so a rule missing one stays
    // one compound here and the pseudo reader takes care of it.
    Ok((text, None))
}

/// Parses one compound: `tag`, `.class`, `#id`, `[attribute]`, `:pseudo(…)`.
fn parse_compound(text: &str, syntax: Syntax) -> Result<Compound, ()> {
    if text.is_empty() {
        return Err(());
    }
    let bytes = text.as_bytes();
    let mut cursor = 0usize;
    let mut compound = Compound::default();
    if bytes[0].is_ascii_alphabetic() {
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'-' | b'_'))
        {
            cursor += 1;
        }
        compound.tag = Some(text[..cursor].to_ascii_lowercase());
    } else if bytes[0] == b'*' && syntax == Syntax::Ubo {
        // The universal selector: any tag.
        cursor = 1;
    }
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'#' if syntax == Syntax::Ubo => {
                let (name, next) = ident(text, cursor + 1)?;
                compound.id = Some(name);
                cursor = next;
            }
            b'.' if syntax == Syntax::Ubo => {
                let (name, next) = ident(text, cursor + 1)?;
                compound.classes.push(name);
                cursor = next;
            }
            b'[' => {
                let close = bracket_end(text, cursor)?;
                parse_attribute(text[cursor + 1..close].trim(), syntax, &mut compound)?;
                cursor = close + 1;
            }
            b':' => {
                let (name, after) = pseudo_name(text, cursor + 1)?;
                let (arg, next) = pseudo_arg(text, after)?;
                for predicate in pseudo_content(&name, arg, syntax)? {
                    compound.content.push(predicate);
                }
                cursor = next;
            }
            _ => return Err(()),
        }
    }
    if compound.tag.is_none()
        && compound.id.is_none()
        && compound.classes.is_empty()
        && compound.attrs.is_empty()
        && compound.content.is_empty()
    {
        return Err(());
    }
    if syntax == Syntax::AdGuard && !compound.content.is_empty() {
        // The knowledge base's default cap: a rule that means to read a
        // script larger than this spells its own `max-length`.
        if !compound
            .content
            .iter()
            .any(|predicate| matches!(predicate, Content::MaxLen(_)))
        {
            compound.content.push(Content::MaxLen(DEFAULT_MAX_LENGTH));
        }
    }
    // Cheap predicates first: a length test rules most elements out before
    // any byte search runs.
    compound.content.sort_by_key(content_cost);
    Ok(compound)
}

/// The order content predicates are asked in: lengths, then literals, then
/// regular expressions.
fn content_cost(predicate: &Content) -> u8 {
    match predicate {
        Content::MinLen(_) | Content::MaxLen(_) => 0,
        Content::Text { .. } | Content::Glob(_) => 1,
        Content::Regex(_) => 2,
    }
}

/// Reads an identifier after `.` or `#`.
fn ident(text: &str, start: usize) -> Result<(String, usize), ()> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len()
        && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'-' | b'_'))
    {
        cursor += 1;
    }
    if cursor == start {
        return Err(());
    }
    Ok((text[start..cursor].to_string(), cursor))
}

/// The index of the `]` that closes the bracket opening at `start`.
fn bracket_end(text: &str, start: usize) -> Result<usize, ()> {
    let bytes = text.as_bytes();
    let mut quote = 0u8;
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        if quote != 0 {
            if byte == quote {
                quote = 0;
            }
        } else if byte == b'"' || byte == b'\'' {
            quote = byte;
        } else if byte == b']' {
            return Ok(cursor);
        }
        cursor += 1;
    }
    Err(())
}

/// Reads one `[name]`, `[name="value"]`, `[name*="value"]`, … attribute, or
/// one of the CoreLibs special attributes, into the compound.
fn parse_attribute(inner: &str, syntax: Syntax, compound: &mut Compound) -> Result<(), ()> {
    let bytes = inner.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len()
        && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'-' | b'_' | b':'))
    {
        cursor += 1;
    }
    if cursor == 0 {
        return Err(());
    }
    let name = inner[..cursor].to_ascii_lowercase();
    let operator;
    if cursor < bytes.len() && matches!(bytes[cursor], b'=' | b'*' | b'^' | b'$' | b'~' | b'|') {
        if bytes[cursor] == b'=' {
            operator = "=";
            cursor += 1;
        } else if cursor + 1 < bytes.len() && bytes[cursor + 1] == b'=' {
            operator = &inner[cursor..cursor + 2];
            cursor += 2;
        } else {
            return Err(());
        }
    } else {
        operator = "";
    }
    let value = if cursor < bytes.len() {
        if operator.is_empty() {
            return Err(());
        }
        Some(unquote(inner[cursor..].trim(), syntax)?)
    } else {
        if !operator.is_empty() {
            return Err(());
        }
        None
    };
    match syntax {
        Syntax::AdGuard => match (name.as_str(), operator, value.as_deref()) {
            ("tag-content", "=" | "*=", Some(value)) => {
                if value.is_empty() {
                    return Err(());
                }
                compound
                    .content
                    .push(Content::text(value.to_string(), false));
                Ok(())
            }
            ("wildcard", "=" | "*=", Some(value)) => {
                if value.is_empty() {
                    return Err(());
                }
                compound.content.push(Content::Glob(Glob::parse(value)));
                Ok(())
            }
            ("min-length", "=" | "*=", Some(value)) => {
                let length: usize = value.parse().map_err(|_| ())?;
                compound.content.push(Content::MinLen(length));
                Ok(())
            }
            ("max-length", "=" | "*=", Some(value)) => {
                let length: usize = value.parse().map_err(|_| ())?;
                compound.content.push(Content::MaxLen(length));
                Ok(())
            }
            ("tag-content" | "wildcard" | "min-length" | "max-length", _, _) => Err(()),
            (_, "", None) => {
                compound.attrs.push((name, AttrMatch::Present));
                Ok(())
            }
            // The CoreLibs value match is "the value is somewhere in the
            // attribute": `=` and `*=` are one predicate there. An empty
            // value is presence, which is also what CSS `[attr=""]` means to
            // the lists that spell it.
            (_, "=" | "*=", Some(value)) => {
                let matcher = if value.is_empty() {
                    AttrMatch::Present
                } else {
                    AttrMatch::Substring(value.to_string())
                };
                compound.attrs.push((name, matcher));
                Ok(())
            }
            _ => Err(()),
        },
        Syntax::Ubo => {
            let matcher = match (operator, value) {
                ("", None) => AttrMatch::Present,
                ("=", Some(value)) => AttrMatch::Exact(value.to_string()),
                ("*=", Some(value)) if !value.is_empty() => AttrMatch::Substring(value.to_string()),
                ("^=", Some(value)) if !value.is_empty() => AttrMatch::Prefix(value.to_string()),
                ("$=", Some(value)) if !value.is_empty() => AttrMatch::Suffix(value.to_string()),
                ("~=", Some(value)) if !value.is_empty() => AttrMatch::Token(value.to_string()),
                ("|=", Some(value)) if !value.is_empty() => {
                    AttrMatch::PrefixOrToken(value.to_string())
                }
                _ => return Err(()),
            };
            compound.attrs.push((name, matcher));
            Ok(())
        }
    }
}

/// Unquotes an attribute value and undoes the CoreLibs quote escape (`""`
/// for a literal quote).
fn unquote(value: &str, syntax: Syntax) -> Result<String, ()> {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return Err(());
    }
    if bytes[0] == b'"' || bytes[0] == b'\'' {
        let quote = bytes[0];
        if bytes.len() < 2 || bytes[bytes.len() - 1] != quote {
            return Err(());
        }
        let inner = &value[1..value.len() - 1];
        if syntax == Syntax::AdGuard {
            Ok(inner.replace("\"\"", "\""))
        } else {
            Ok(inner.to_string())
        }
    } else {
        Ok(value.to_string())
    }
}

/// Reads a pseudo's name and returns the index just after its opening `(`.
fn pseudo_name(text: &str, start: usize) -> Result<(String, usize), ()> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'-') {
        cursor += 1;
    }
    if cursor == start || cursor >= bytes.len() || bytes[cursor] != b'(' {
        return Err(());
    }
    Ok((text[start..cursor].to_ascii_lowercase(), cursor + 1))
}

/// Reads a pseudo's argument.
///
/// The reference reads it to the *last* `)` of the selector: unbalanced
/// parentheses inside the argument are the norm
/// (`:contains(eval(function(p,a,c,k,e,d))` carries one). When the pseudo is
/// not the selector's tail — attributes may follow it — the argument is read
/// by balancing parentheses instead.
fn pseudo_arg(text: &str, start: usize) -> Result<(&str, usize), ()> {
    let rest = &text[start..];
    if let Some(close) = rest.rfind(')') {
        if rest[close + 1..].trim().is_empty() {
            return Ok((&rest[..close], text.len()));
        }
    }
    let bytes = text.as_bytes();
    let mut depth = 1usize;
    let mut cursor = start;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&text[start..cursor], cursor + 1));
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    Err(())
}

/// Reads a `:contains` / `:has-text` / `:-abp-contains` argument into the
/// predicates it means.
fn pseudo_content(name: &str, arg: &str, syntax: Syntax) -> Result<Vec<Content>, ()> {
    let known = match syntax {
        Syntax::AdGuard => matches!(name, "contains" | "-abp-contains" | "has-text"),
        Syntax::Ubo => matches!(name, "has-text" | "-abp-contains" | "contains"),
    };
    if !known {
        return Err(());
    }
    match syntax {
        Syntax::AdGuard => {
            if let Some(rest) = arg.strip_prefix('/') {
                if let Some(close) = rest.rfind('/') {
                    let body = &rest[..close];
                    let flags = &rest[close + 1..];
                    // A `/…/` form is a regexp; the flags are the regexp
                    // options, and one this engine cannot read drops the
                    // rule rather than run it differently.
                    return regex_content(body, flags);
                }
            }
            if arg.is_empty() {
                return Err(());
            }
            Ok(vec![Content::text(arg.to_string(), false)])
        }
        Syntax::Ubo => {
            if arg.len() > 3 && arg.starts_with('/') && arg.ends_with("/i") {
                return regex_content(&arg[1..arg.len() - 2], "i");
            }
            if arg.len() > 2 && arg.starts_with('/') && arg.ends_with('/') {
                return regex_content(&arg[1..arg.len() - 1], "");
            }
            if arg.is_empty() {
                return Err(());
            }
            // uBO's literal text search is case-insensitive by default.
            Ok(vec![Content::text(arg.to_ascii_lowercase(), true)])
        }
    }
}

/// Compiles a `:contains(/…/)` body, or reads the knowledge base's own
/// length-test shape natively.
fn regex_content(body: &str, flags: &str) -> Result<Vec<Content>, ()> {
    if flags == "s" {
        if let Some((min, max)) = length_pattern(body) {
            // The shape the knowledge base's conversion table writes for a
            // length test, answered here without a lookaround.
            let mut predicates = Vec::new();
            if let Some(min) = min {
                predicates.push(Content::MinLen(min));
            }
            if let Some(max) = max {
                predicates.push(Content::MaxLen(max));
            }
            if !predicates.is_empty() {
                return Ok(predicates);
            }
        }
    }
    let prefix = inline_flags(flags)?;
    let pattern = format!("{prefix}{}", normalize_braces(body));
    Regex::new(&pattern)
        .map(|regex| vec![Content::Regex(regex)])
        .map_err(|_| ())
}

/// Recognizes `^(?=.{m,n}$).*` (the `s` flag is read separately): the length
/// test the knowledge base's converter writes. `{m,n}` is both bounds, `{m,}`
/// a lower one, `{m}` an exact one.
fn length_pattern(body: &str) -> Option<(Option<usize>, Option<usize>)> {
    let rest = body.strip_prefix("^(?=.")?;
    let rest = rest.strip_suffix('$').unwrap_or(rest);
    let rest = rest.strip_suffix(".*")?;
    let rest = rest.strip_suffix(')')?;
    let rest = rest.strip_suffix('$')?;
    let rest = rest.strip_prefix('{')?.strip_suffix('}')?;
    let (min, max) = match rest.split_once(',') {
        Some((min, max)) => (
            if min.is_empty() { 0 } else { min.parse().ok()? },
            if max.is_empty() {
                None
            } else {
                Some(max.parse().ok()?)
            },
        ),
        None => {
            let exact: usize = rest.parse().ok()?;
            (exact, Some(exact))
        }
    };
    if max.is_some_and(|max| max < min) {
        return None;
    }
    Some((Some(min), max))
}

/// The inline-flag prefix a regexp's flags become, the way `$replace` reads
/// them: `g` changes nothing about one match and `_` is the list's own
/// spelling for "nothing", so both disappear; anything else this engine does
/// not know drops the rule.
fn inline_flags(flags: &str) -> Result<String, ()> {
    let mut out = String::new();
    for flag in flags.chars() {
        match flag {
            'g' | '_' => {}
            'i' | 'm' | 's' | 'x' => out.push(flag),
            _ => return Err(()),
        }
    }
    if out.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("(?{out})"))
    }
}

/// Escapes the `{` and `}` the Rust `regex` crate refuses where PCRE and
/// JavaScript read them literally (`{"zone_id":` is a literal there).
fn normalize_braces(pattern: &str) -> String {
    let bytes = pattern.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() + 8);
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => {
                out.push(bytes[cursor]);
                cursor += 1;
                if cursor < bytes.len() {
                    out.push(bytes[cursor]);
                    cursor += 1;
                }
            }
            b'{' => {
                let start = cursor + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end].is_ascii_digit() {
                    end += 1;
                }
                let digits = end > start;
                if digits && end < bytes.len() && bytes[end] == b',' {
                    end += 1;
                    while end < bytes.len() && bytes[end].is_ascii_digit() {
                        end += 1;
                    }
                }
                if digits && end < bytes.len() && bytes[end] == b'}' {
                    out.extend_from_slice(&bytes[cursor..=end]);
                    cursor = end + 1;
                } else {
                    out.extend_from_slice(b"\\{");
                    cursor += 1;
                }
            }
            b'}' => {
                out.extend_from_slice(b"\\}");
                cursor += 1;
            }
            byte => {
                out.push(byte);
                cursor += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl Glob {
    fn parse(pattern: &str) -> Glob {
        Glob {
            parts: pattern.split('*').map(str::to_string).collect(),
            lead: pattern.starts_with('*'),
            trail: pattern.ends_with('*'),
        }
    }

    fn matches(&self, hay: &[u8]) -> bool {
        let parts: Vec<&[u8]> = self
            .parts
            .iter()
            .map(|part| part.as_bytes())
            .filter(|part| !part.is_empty())
            .collect();
        if parts.is_empty() {
            // A pattern of nothing but `*` asks for any content; an element
            // with none never matches a content predicate.
            return !hay.is_empty();
        }
        if !self.lead && !self.trail && parts.len() == 1 {
            return hay == parts[0];
        }
        let mut low = 0usize;
        let mut first = 0usize;
        if !self.lead {
            if !hay.starts_with(parts[0]) {
                return false;
            }
            low = parts[0].len();
            first = 1;
        }
        let mut high = hay.len();
        let mut last = parts.len();
        if !self.trail {
            let part = parts[parts.len() - 1];
            if !hay.ends_with(part) {
                return false;
            }
            if hay.len() < part.len() || hay.len() - part.len() < low {
                return false;
            }
            high = hay.len() - part.len();
            last -= 1;
        }
        let mut cursor = low;
        for part in &parts[first..last] {
            match memchr::memmem::find(&hay[cursor..high], part) {
                Some(index) => cursor += index + part.len(),
                None => return false,
            }
        }
        true
    }
}

/// The fingerprint an exception's selector must share to cancel a rule. Tags
/// and attribute names are lowercased; values, arguments and regexps keep
/// their case, because they are matched that way.
fn canonical(chain: &[Compound], syntax: Syntax) -> String {
    let mut compounds = Vec::with_capacity(chain.len());
    for compound in chain {
        let mut out = String::new();
        out.push_str(compound.tag.as_deref().unwrap_or("*"));
        if let Some(id) = &compound.id {
            out.push('#');
            out.push_str(id);
        }
        let mut classes: Vec<&String> = compound.classes.iter().collect();
        classes.sort();
        for class in classes {
            out.push('.');
            out.push_str(class);
        }
        let mut attrs: Vec<String> = compound
            .attrs
            .iter()
            .map(|(name, matcher)| match matcher {
                AttrMatch::Present => name.to_string(),
                AttrMatch::Substring(value) => format!("{name}=v:{value}"),
                AttrMatch::Exact(value) => format!("{name}==v:{value}"),
                AttrMatch::Prefix(value) => format!("{name}^=v:{value}"),
                AttrMatch::Suffix(value) => format!("{name}$=v:{value}"),
                AttrMatch::Token(value) => format!("{name}~=v:{value}"),
                AttrMatch::PrefixOrToken(value) => format!("{name}|=v:{value}"),
            })
            .collect();
        attrs.sort();
        for attr in attrs {
            out.push('[');
            out.push_str(&attr);
            out.push(']');
        }
        let mut content: Vec<String> = compound
            .content
            .iter()
            .map(|predicate| match predicate {
                Content::Text {
                    needle,
                    case_insensitive,
                    ..
                } => {
                    if *case_insensitive {
                        format!("t:{needle}:i")
                    } else {
                        format!("t:{needle}")
                    }
                }
                Content::Regex(regex) => format!("r:{}", regex.as_str()),
                Content::Glob(glob) => format!("g:{}", glob.parts.join("*")),
                Content::MinLen(length) => format!("min:{length}"),
                Content::MaxLen(length) => format!("max:{length}"),
            })
            .collect();
        content.sort();
        for predicate in content {
            out.push('{');
            out.push_str(&predicate);
            out.push('}');
        }
        compounds.push(out);
    }
    let family = match syntax {
        Syntax::AdGuard => "adg",
        Syntax::Ubo => "ubo",
    };
    format!("{family}:{}", compounds.join(">"))
}

/// The rules that apply to one page, ready to run against a response body.
pub struct Plan {
    rules: Vec<Rule>,
    by_tag: HashMap<String, Vec<usize>>,
    any: Vec<usize>,
}

impl Plan {
    /// Resolves the rules that apply to a page: the blocking rules whose
    /// domains (and bracket) cover it, minus the ones an exception's selector
    /// cancels. The caller has no app attribution: `$app`-narrowed rules stay
    /// out.
    pub fn build(rules: &[Rule], exceptions: &[Rule], host: &str, url: &str) -> Option<Plan> {
        Self::build_for_apps(rules, exceptions, host, url, &[])
    }

    /// [`Self::build`] for a flow attributed to `apps`.
    pub fn build_for_apps(
        rules: &[Rule],
        exceptions: &[Rule],
        host: &str,
        url: &str,
        apps: &[String],
    ) -> Option<Plan> {
        // Every rule asks about the same host: normalize it once instead of
        // re-trimming and re-lowercasing it per rule.
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let cancelled: HashSet<&str> = exceptions
            .iter()
            .filter(|rule| rule.applies(&host, url, apps))
            .map(|rule| rule.canonical.as_str())
            .collect();
        let mut kept = Vec::new();
        for rule in rules {
            if !rule.applies(&host, url, apps) || cancelled.contains(rule.canonical.as_str()) {
                continue;
            }
            kept.push(rule.clone());
        }
        if kept.is_empty() {
            return None;
        }
        let mut by_tag: HashMap<String, Vec<usize>> = HashMap::new();
        let mut any = Vec::new();
        for (index, rule) in kept.iter().enumerate() {
            match rule
                .chain
                .last()
                .and_then(|compound| compound.tag.as_deref())
            {
                Some(tag) => by_tag.entry(tag.to_string()).or_default().push(index),
                None => any.push(index),
            }
        }
        Some(Plan {
            rules: kept,
            by_tag,
            any,
        })
    }

    /// Cuts the matching elements out of one response body. `None` when
    /// nothing matched: the body then travels with its own length and framing
    /// still in place.
    pub fn apply(&self, body: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
        let mut found = self.scan(body);
        if found.is_empty() {
            return None;
        }
        // Outermost first: a range inside another one was cut by cutting the
        // one around it.
        found.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        let mut out = Vec::with_capacity(body.len());
        let mut cursor = 0usize;
        let mut removed: Vec<usize> = Vec::new();
        for &(start, end, index) in &found {
            if start < cursor {
                continue;
            }
            out.extend_from_slice(&body[cursor..start]);
            cursor = end;
            if !removed.contains(&index) {
                removed.push(index);
            }
        }
        out.extend_from_slice(&body[cursor..]);
        let texts = removed
            .into_iter()
            .map(|index| self.rules[index].text.clone())
            .collect();
        Some((out, texts))
    }

    /// One walk over the document: every element is matched as it ends.
    fn scan(&self, body: &[u8]) -> Vec<(usize, usize, usize)> {
        let mut found: Vec<(usize, usize, usize)> = Vec::new();
        let mut stack: Vec<Open> = Vec::new();
        let mut pos = 0usize;
        while pos < body.len() {
            let Some(offset) = memchr::memchr(b'<', &body[pos..]) else {
                break;
            };
            let lt = pos + offset;
            pos = lt + 1;
            let rest = &body[lt..];
            if rest.starts_with(b"<!--") {
                match memchr::memmem::find(&body[lt + 4..], b"-->") {
                    Some(end) => pos = lt + 4 + end + 3,
                    None => break,
                }
                continue;
            }
            if rest.starts_with(b"<!") || rest.starts_with(b"<?") {
                match memchr::memchr(b'>', rest) {
                    Some(end) => pos = lt + end + 1,
                    None => break,
                }
                continue;
            }
            if rest.starts_with(b"</") {
                let Some((name, name_end)) = tag_name(body, lt + 2) else {
                    continue;
                };
                let Some(tag_end) = markup_end(body, name_end) else {
                    break;
                };
                self.close(&mut stack, body, &name, lt, tag_end + 1, &mut found);
                pos = tag_end + 1;
                continue;
            }
            let Some((name, name_end)) = tag_name(body, lt + 1) else {
                continue;
            };
            let Some(tag_end) = markup_end(body, name_end) else {
                break;
            };
            let after = tag_end + 1;
            let attrs = parse_attrs(body, name_end, tag_end);
            // The parser's implied ends: an open `<p>`, `<li>`, `<td>` … ends
            // where the next start tag says so, and a content predicate must
            // read the same bytes the parser would see.
            while let Some(top) = stack.last() {
                if !implicitly_closes(&top.name, &name) {
                    break;
                }
                let element = stack.pop().unwrap();
                self.finish(&element, body, lt, lt, &stack, &mut found);
            }
            let candidates = self.candidates(&name, attrs.as_deref());
            if is_void(&name) {
                let element = Open {
                    start: lt,
                    inner: after,
                    candidates,
                    attrs,
                    name,
                };
                self.finish(&element, body, after, after, &stack, &mut found);
                pos = after;
                continue;
            }
            let raw_text = is_raw_text(&name);
            let close_at = if raw_text {
                // Everything up to the matching end tag is opaque.
                find_close_tag(body, after, &name)
            } else {
                None
            };
            stack.push(Open {
                start: lt,
                inner: after,
                candidates,
                attrs,
                name,
            });
            pos = match (raw_text, close_at) {
                (true, Some(close)) => close,
                (true, None) => body.len(),
                _ => after,
            };
        }
        // An element that never closed ends where the document ends, the way
        // a parser reads it.
        while let Some(element) = stack.pop() {
            self.finish(&element, body, body.len(), body.len(), &stack, &mut found);
        }
        found
    }

    /// Ends one element: its content runs to `content_end`, its removal to
    /// `end` (past the end tag when there was one).
    fn finish(
        &self,
        element: &Open,
        body: &[u8],
        content_end: usize,
        end: usize,
        ancestors: &[Open],
        found: &mut Vec<(usize, usize, usize)>,
    ) {
        if element.candidates.is_empty() || PROTECTED_ELEMENTS.contains(&element.name.as_str()) {
            return;
        }
        let raw = &body[element.inner..content_end];
        let raw_text = is_raw_text(&element.name);
        let mut stripped: Option<Vec<u8>> = None;
        for &index in &element.candidates {
            if self.matches(index, raw, raw_text, &mut stripped, ancestors) {
                found.push((element.start, end, index));
            }
        }
    }

    /// The rules whose element-side parts match a start tag.
    fn candidates(&self, name: &str, attrs: Option<&[(String, Option<String>)]>) -> Vec<usize> {
        let Some(attrs) = attrs else {
            // A tag whose attributes could not be read matches nothing.
            return Vec::new();
        };
        let mut out: Vec<usize> = Vec::new();
        if let Some(list) = self.by_tag.get(name) {
            out.extend_from_slice(list);
        }
        out.extend_from_slice(&self.any);
        out.retain(|&index| {
            self.rules[index]
                .chain
                .last()
                .is_some_and(|compound| compound.matches_element(name, attrs))
        });
        out
    }

    /// The whole question for one rule and one ended element: its content
    /// predicates, and the ancestors a `>` chain asks about.
    fn matches(
        &self,
        index: usize,
        raw: &[u8],
        raw_text: bool,
        stripped: &mut Option<Vec<u8>>,
        ancestors: &[Open],
    ) -> bool {
        let rule = &self.rules[index];
        let element = rule
            .chain
            .last()
            .expect("a parsed rule carries at least one compound");
        if !element.content.is_empty() {
            let hay: &[u8] = match text_mode(rule.syntax) {
                TextMode::Inner => raw,
                TextMode::Text => {
                    if raw_text {
                        raw
                    } else {
                        stripped.get_or_insert_with(|| strip_markup(raw))
                    }
                }
            };
            for predicate in &element.content {
                if !content_matches(predicate, hay) {
                    return false;
                }
            }
        }
        if rule.chain.len() > 1 {
            let mut up = ancestors.iter().rev();
            for compound in rule.chain[..rule.chain.len() - 1].iter().rev() {
                let Some(ancestor) = up.next() else {
                    return false;
                };
                let Some(attrs) = ancestor.attrs.as_deref() else {
                    return false;
                };
                if !compound.matches_element(&ancestor.name, attrs) {
                    return false;
                }
            }
        }
        true
    }

    /// Ends one element the moment its end tag arrives.
    fn close(
        &self,
        stack: &mut Vec<Open>,
        body: &[u8],
        name: &str,
        lt: usize,
        end: usize,
        found: &mut Vec<(usize, usize, usize)>,
    ) {
        let Some(index) = stack.iter().rposition(|element| element.name == name) else {
            // A stray end tag: nothing to end.
            return;
        };
        // Everything the end tag closes implicitly ends here too.
        while stack.len() > index + 1 {
            let element = stack.pop().unwrap();
            self.finish(&element, body, lt, lt, stack, found);
        }
        let element = stack.pop().unwrap();
        self.finish(&element, body, lt, end, stack, found);
    }
}

impl Rule {
    /// Whether the rule's domain position, location and applications cover
    /// one page. `host` must already be trimmed of its trailing dot and
    /// lowercased ([`Plan::build_for_apps`] normalizes it once per build).
    fn applies(&self, host: &str, url: &str, apps: &[String]) -> bool {
        if let Some(domains) = &self.domains {
            if !domains.matches(host) {
                return false;
            }
        }
        if let Some(location) = &self.location {
            if !location.matches(url) {
                return false;
            }
        }
        if let Some(app) = &self.app {
            if !app.matches(apps) {
                return false;
            }
        }
        true
    }
}

/// Which bytes a rule's content predicates read.
fn text_mode(syntax: Syntax) -> TextMode {
    match syntax {
        Syntax::AdGuard => TextMode::Inner,
        Syntax::Ubo => TextMode::Text,
    }
}

/// One start tag seen and not yet ended.
struct Open {
    start: usize,
    /// The first byte of the content: just past the start tag's `>`.
    inner: usize,
    name: String,
    attrs: Option<Vec<(String, Option<String>)>>,
    /// The rule indices whose element-side parts match this tag.
    candidates: Vec<usize>,
}

/// Whether one content predicate holds for an element's content.
fn content_matches(predicate: &Content, hay: &[u8]) -> bool {
    match predicate {
        Content::MinLen(min) => hay.len() >= *min,
        Content::MaxLen(max) => hay.len() <= *max,
        Content::Text {
            needle,
            case_insensitive,
            ci,
        } => {
            if hay.is_empty() {
                return false;
            }
            if *case_insensitive {
                ci.as_ref().is_some_and(|ci| ci.is_match(hay))
            } else {
                memchr::memmem::find(hay, needle.as_bytes()).is_some()
            }
        }
        Content::Regex(regex) => !hay.is_empty() && regex.is_match(hay),
        Content::Glob(glob) => glob.matches(hay),
    }
}

/// Whether a start tag ends an open element on its own.
fn implicitly_closes(open: &str, next: &str) -> bool {
    match next {
        "li" => matches!(open, "li" | "p"),
        "dt" | "dd" => matches!(open, "dt" | "dd"),
        "option" => open == "option",
        "optgroup" => matches!(open, "option" | "optgroup"),
        "tr" => matches!(open, "tr" | "td" | "th"),
        "td" | "th" => matches!(open, "td" | "th"),
        "tbody" | "thead" | "tfoot" => {
            matches!(open, "tr" | "td" | "th" | "tbody" | "thead" | "tfoot")
        }
        "caption" | "colgroup" => matches!(
            open,
            "tr" | "td" | "th" | "tbody" | "thead" | "tfoot" | "caption" | "colgroup"
        ),
        "rt" | "rp" => matches!(open, "rt" | "rp"),
        other if P_CLOSERS.contains(&other) => open == "p",
        _ => false,
    }
}

fn is_void(name: &str) -> bool {
    VOID_ELEMENTS.contains(&name)
}

fn is_raw_text(name: &str) -> bool {
    RAW_TEXT_ELEMENTS.contains(&name)
}

/// Reads a tag name starting at `start`: lowercased, with the index just
/// past it.
fn tag_name(body: &[u8], start: usize) -> Option<(String, usize)> {
    if start >= body.len() || !body[start].is_ascii_alphabetic() {
        return None;
    }
    let mut cursor = start;
    while cursor < body.len()
        && (body[cursor].is_ascii_alphanumeric() || matches!(body[cursor], b'-' | b'_' | b':'))
    {
        cursor += 1;
    }
    let name = String::from_utf8_lossy(&body[start..cursor]).to_ascii_lowercase();
    Some((name, cursor))
}

/// The index of the `>` that ends the markup starting at `from`.
///
/// A quote only opens a value where a value can start (right after `=`), so
/// an apostrophe inside an unquoted value (`title=it's`) cannot swallow the
/// tag's `>`.
fn markup_end(body: &[u8], from: usize) -> Option<usize> {
    let mut quote = 0u8;
    let mut cursor = from;
    while cursor < body.len() {
        let byte = body[cursor];
        if quote != 0 {
            if byte == quote {
                quote = 0;
            }
        } else if (byte == b'"' || byte == b'\'') && cursor > 0 && body[cursor - 1] == b'=' {
            quote = byte;
        } else if byte == b'>' {
            return Some(cursor);
        }
        cursor += 1;
    }
    None
}

/// Reads a start tag's attributes. `None` when the tag cannot be read: an
/// element with unreadable attributes matches no rule.
fn parse_attrs(
    body: &[u8],
    mut cursor: usize,
    end: usize,
) -> Option<Vec<(String, Option<String>)>> {
    let mut attrs: Vec<(String, Option<String>)> = Vec::new();
    while cursor < end {
        while cursor < end && body[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= end {
            break;
        }
        if body[cursor] == b'/' {
            cursor += 1;
            continue;
        }
        let name_start = cursor;
        while cursor < end
            && !body[cursor].is_ascii_whitespace()
            && !matches!(body[cursor], b'=' | b'/' | b'>')
        {
            cursor += 1;
        }
        if cursor == name_start {
            return None;
        }
        let name = String::from_utf8_lossy(&body[name_start..cursor]).to_ascii_lowercase();
        while cursor < end && body[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let mut value = None;
        if cursor < end && body[cursor] == b'=' {
            cursor += 1;
            while cursor < end && body[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < end && (body[cursor] == b'"' || body[cursor] == b'\'') {
                let quote = body[cursor];
                cursor += 1;
                let value_start = cursor;
                while cursor < end && body[cursor] != quote {
                    cursor += 1;
                }
                if cursor >= end {
                    return None;
                }
                value = Some(String::from_utf8_lossy(&body[value_start..cursor]).to_string());
                cursor += 1;
            } else {
                let value_start = cursor;
                while cursor < end && !body[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if cursor == value_start {
                    return None;
                }
                value = Some(String::from_utf8_lossy(&body[value_start..cursor]).to_string());
            }
        }
        // The DOM keeps the first occurrence of an attribute.
        if !attrs.iter().any(|(seen, _)| *seen == name) {
            attrs.push((name, value));
        }
    }
    Some(attrs)
}

/// The next `</name` that closes a raw-text element.
fn find_close_tag(body: &[u8], from: usize, name: &str) -> Option<usize> {
    let mut cursor = from;
    while cursor + 2 <= body.len() {
        let offset = memchr::memmem::find(&body[cursor..], b"</")?;
        let at = cursor + offset;
        if let Some((found, _)) = tag_name(body, at + 2) {
            if found == name {
                return Some(at);
            }
        }
        cursor = at + 2;
    }
    None
}

/// The element's content with the markup taken out: what `textContent`
/// reports, as close as a byte scanner gets (character references are left as
/// they are written, which only ever under-matches).
fn strip_markup(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut pos = 0usize;
    while pos < raw.len() {
        let Some(offset) = memchr::memchr(b'<', &raw[pos..]) else {
            out.extend_from_slice(&raw[pos..]);
            break;
        };
        let lt = pos + offset;
        out.extend_from_slice(&raw[pos..lt]);
        let rest = &raw[lt..];
        if rest.starts_with(b"<!--") {
            match memchr::memmem::find(&raw[lt + 4..], b"-->") {
                Some(end) => pos = lt + 4 + end + 3,
                None => break,
            }
            continue;
        }
        let Some(end) = markup_end(raw, lt) else {
            break;
        };
        // A raw-text element's content is text, not markup: it stays whole.
        if let Some((name, _)) = tag_name(raw, lt + 1) {
            if is_raw_text(&name) {
                match find_close_tag(raw, end + 1, &name) {
                    Some(close) => {
                        out.extend_from_slice(&raw[end + 1..close]);
                        pos = close;
                        continue;
                    }
                    None => {
                        out.extend_from_slice(&raw[end + 1..]);
                        break;
                    }
                }
            }
        }
        pos = end + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_of(lines: &[&str]) -> Vec<Rule> {
        lines
            .iter()
            .filter_map(|line| match parse_line(line) {
                Parsed::Rule(rule) => Some(rule),
                _ => None,
            })
            .collect()
    }

    fn exceptions_of(lines: &[&str]) -> Vec<Rule> {
        lines
            .iter()
            .filter_map(|line| match parse_line(line) {
                Parsed::Exception(rule) => Some(rule),
                _ => None,
            })
            .collect()
    }

    fn plan_of(lines: &[&str]) -> Plan {
        let rules = rules_of(lines);
        assert_eq!(rules.len(), lines.len(), "every line must parse: {lines:?}");
        Plan::build(&rules, &[], "shop.test", "/").expect("a plan")
    }

    fn body_of(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    #[test]
    fn a_rule_is_only_html_filtering_when_its_prefix_is_a_domain_position() {
        assert!(matches!(
            parse_line("shop.test$$script[src]"),
            Parsed::Rule(_)
        ));
        assert!(matches!(parse_line("$$div[class=\"ad\"]"), Parsed::Rule(_)));
        assert!(matches!(parse_line("a.com,b.com$$div"), Parsed::Rule(_)));
        assert!(matches!(
            parse_line("example.org#%#//scriptlet('set-constant', '$$.analytics', 'emptyObj')"),
            Parsed::NotHtml
        ));
        assert!(matches!(
            parse_line("example.com##div[data-x=\"$$\"]"),
            Parsed::NotHtml
        ));
        assert!(matches!(parse_line("! shop.test$$div"), Parsed::NotHtml));
    }

    #[test]
    fn an_unsupported_selector_is_dropped_not_approximated() {
        // CSS operators CoreLibs does not have.
        assert!(matches!(
            parse_line("shop.test$$script[src^=\"cdn\"]"),
            Parsed::Unsupported
        ));
        assert!(matches!(
            parse_line("shop.test$$script[src~=\"cdn\"]"),
            Parsed::Unsupported
        ));
        // Class and id sugar are the CSS reading, not the CoreLibs one.
        assert!(matches!(
            parse_line("shop.test$$div.ad"),
            Parsed::Unsupported
        ));
        assert!(matches!(
            parse_line("shop.test$$div#slot"),
            Parsed::Unsupported
        ));
        // A selector list.
        assert!(matches!(
            parse_line("shop.test$$div, p"),
            Parsed::Unsupported
        ));
        // An unknown pseudo.
        assert!(matches!(
            parse_line("shop.test$$div:has(span)"),
            Parsed::Unsupported
        ));
        // A content predicate on the left of a combinator.
        assert!(matches!(
            parse_line("shop.test$$div:contains(ad) > p"),
            Parsed::Unsupported
        ));
        assert!(matches!(parse_line("shop.test$$"), Parsed::Unsupported));
    }

    #[test]
    fn the_adguard_value_match_is_a_substring() {
        let plan = plan_of(&["shop.test$$script[src=\"html-load.com\"]"]);
        let (body, rules) = plan
            .apply(&body_of(
                "<script src=\"//cdn.html-load.com/x.js\"></script>",
            ))
            .expect("a removal");
        assert!(body.is_empty(), "{}", String::from_utf8_lossy(&body));
        assert_eq!(rules, vec!["script[src=\"html-load.com\"]".to_string()]);

        // `*=` is the same predicate in this reading.
        let plan = plan_of(&["shop.test$$script[src*=\"html-load.com\"]"]);
        assert!(plan
            .apply(&body_of(
                "<script src=\"//cdn.html-load.com/x.js\"></script>"
            ))
            .is_some());
    }

    #[test]
    fn a_bare_attribute_tests_presence() {
        let plan = plan_of(&["shop.test$$meta[property]"]);
        assert!(plan
            .apply(&body_of("<meta property=\"og:title\">"))
            .is_some());
        assert!(plan.apply(&body_of("<meta name=\"x\">")).is_none());
    }

    #[test]
    fn a_contains_literal_reads_the_inner_markup_case_sensitively() {
        let plan = plan_of(&["shop.test$$div[class=\"box\"]:contains(<h2>Iklan</h2>)"]);
        assert!(plan
            .apply(&body_of("<div class=\"box\"><h2>Iklan</h2></div><p>x</p>"))
            .is_some());
        // Case matters: the reference's literal search is case-sensitive.
        assert!(plan
            .apply(&body_of("<div class=\"box\"><h2>IKLAN</h2></div>"))
            .is_none());
        // A class value only has to hold the needle.
        assert!(plan
            .apply(&body_of("<div class=\"ad-box\"><h2>Iklan</h2></div>"))
            .is_some());
        // An empty element never matches a content predicate.
        assert!(plan.apply(&body_of("<div class=\"box\"></div>")).is_none());
    }

    #[test]
    fn a_contains_regex_carries_its_flags() {
        let plan = plan_of(&["shop.test$$script:contains(/^.*window.*googleAd.*$/s)"]);
        assert!(plan
            .apply(&body_of("<script>\nvar x = window.googleAd;</script>"))
            .is_some());
        // Without the `s` flag the `.` does not cross the newline.
        let plan = plan_of(&["shop.test$$script:contains(/^.*window.*googleAd.*$/)"]);
        assert!(plan
            .apply(&body_of("<script>\nvar x = window.googleAd;</script>"))
            .is_none());
        // The corpus also spells the global flag, which changes nothing
        // about one match.
        let plan = plan_of(&["shop.test$$p:contains(/^AD$/g)"]);
        assert!(plan.apply(&body_of("<p>AD</p>")).is_some());
    }

    #[test]
    fn a_contains_argument_may_carry_unbalanced_parentheses() {
        let plan = plan_of(&["shop.test$$script:contains(eval(function(p,a,c,k,e,d))"]);
        assert!(plan
            .apply(&body_of("<script>eval(function(p,a,c,k,e,d){})</script>"))
            .is_some());
    }

    #[test]
    fn the_corpus_shapes_are_read_the_way_the_reference_reads_them() {
        // A lone quote inside a `:contains` argument, its parenthesis missing.
        assert!(matches!(
            parse_line("youporngay.com$$script:contains({\"zone_id\":\")"),
            Parsed::Rule(_)
        ));
        // A `(` inside the argument that never closes within it.
        assert!(matches!(
            parse_line("jkmk.net$$script:contains((function(){ var g=window;g[\"_)"),
            Parsed::Rule(_)
        ));
        // A `)` inside an attribute value closes nothing: the value runs to
        // its own closing bracket, and the `""` escapes are the list's quotes.
        let rule = match parse_line(
            "filmweb.pl$$script[tag-content=\".name)throw h=\"\"ABP\"\",\"][max-length=\"7000\"]",
        ) {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let plan =
            Plan::build(std::slice::from_ref(&rule), &[], "filmweb.pl", "/").expect("a plan");
        assert!(plan
            .apply(&body_of("<script>if(x.name)throw h=\"ABP\",y</script>"))
            .is_some());

        // A wildcard with the same shape.
        let rule = match parse_line(
            "x.test$$script[wildcard=\"*.name)throw *=\"\"ABP\"\",*\"][min-length=\"5\"][max-length=\"8000\"]",
        ) {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let plan = Plan::build(std::slice::from_ref(&rule), &[], "x.test", "/").expect("a plan");
        assert!(plan
            .apply(&body_of("<script>a.name)throw x=\"ABP\",b</script>"))
            .is_some());
    }

    #[test]
    fn the_special_attributes_are_the_references_own() {
        // tag-content, with the `""` escape the knowledge base defines.
        let plan = plan_of(&["shop.test$$li[tag-content=\"\"\"NativeAdItems\"\"\"]"]);
        let (body, _) = plan
            .apply(&body_of("<li><span>\"NativeAdItems\"</span></li>"))
            .expect("a removal");
        assert!(body.is_empty());

        // wildcard: `*` stands for anything.
        let plan = plan_of(&["shop.test$$script[wildcard=\"*eval*babasbmsgx*\"]"]);
        assert!(plan
            .apply(&body_of("<script>a=eval(\"babasbmsgx\")</script>"))
            .is_some());
        assert!(plan
            .apply(&body_of("<script>a=eval(\"other\")</script>"))
            .is_none());

        // min-length and max-length measure the inner bytes.
        let plan = plan_of(&["shop.test$$script[min-length=\"5\"][max-length=\"10\"]"]);
        assert!(plan.apply(&body_of("<script>12345</script>")).is_some());
        assert!(plan.apply(&body_of("<script>1234</script>")).is_none());
        assert!(plan
            .apply(&body_of("<script>12345678901</script>"))
            .is_none());

        // `[max-length="0"]` is the catalogue's way of naming empty scripts.
        let plan = plan_of(&["shop.test$$script[max-length=\"0\"]"]);
        assert!(plan
            .apply(&body_of("<script src=\"x.js\"></script><script>y</script>"))
            .is_some());
    }

    #[test]
    fn a_content_rule_without_max_length_gets_the_default() {
        let small = format!("<script>{}NEEDLE</script>", "a".repeat(10));
        let large = format!("<script>{}NEEDLE</script>", "a".repeat(DEFAULT_MAX_LENGTH));
        let plan = plan_of(&["shop.test$$script:contains(NEEDLE)"]);
        assert!(plan.apply(&body_of(&small)).is_some());
        assert!(plan.apply(&body_of(&large)).is_none());

        // An explicit cap overrides the default.
        let plan = plan_of(&["shop.test$$script:contains(NEEDLE)[max-length=\"100000\"]"]);
        assert!(plan.apply(&body_of(&large)).is_some());
    }

    #[test]
    fn the_knowledge_bases_length_pattern_is_answered_natively() {
        let plan = plan_of(&["shop.test$$script:contains(/^(?=.{10,20}$).*/s)"]);
        assert!(plan
            .apply(&body_of("<script>1234567890</script>"))
            .is_some());
        assert!(plan.apply(&body_of("<script>123</script>")).is_none());
        assert!(plan
            .apply(&body_of("<script>1234567890123456789012345</script>"))
            .is_none());
    }

    #[test]
    fn a_lookaround_the_engine_cannot_run_drops_its_rule() {
        // The `regex` crate has no lookarounds of that shape: the rule is
        // dropped, and the line is counted as unsupported.
        assert!(matches!(
            parse_line("shop.test$$script:contains(/^(?!ok).*$/s)"),
            Parsed::Unsupported
        ));
    }

    #[test]
    fn literal_braces_compile_the_way_pcre_reads_them() {
        let plan = plan_of(&["shop.test$$script:contains(/\\{\"zone_id\":/)"]);
        assert!(plan
            .apply(&body_of("<script>{\"zone_id\": 7}</script>"))
            .is_some());
    }

    #[test]
    fn removal_takes_the_whole_element_and_leaves_the_bytes_around_it() {
        let plan = plan_of(&["shop.test$$div[class=\"ad-box\"]"]);
        let body = "<p>keep</p><div class=\"ad-box\"><b>ad</b></div><p>keep2</p>";
        let (out, _) = plan.apply(&body_of(body)).expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "<p>keep</p><p>keep2</p>");
    }

    #[test]
    fn nesting_void_elements_and_comments_are_read_the_parsers_way() {
        // Nested same-name elements: the outer goes with its content.
        let plan = plan_of(&["shop.test$$div[class=\"ad\"]"]);
        let (out, _) = plan
            .apply(&body_of(
                "<div class=\"ad\">a<div class=\"ad\">b</div></div>keep",
            ))
            .expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "keep");

        // A void element is removed on its own.
        let plan = plan_of(&["shop.test$$meta[property=\"og:title\"]"]);
        let (out, _) = plan
            .apply(&body_of(
                "<head><meta property=\"og:title\"><title>x</title></head>",
            ))
            .expect("a removal");
        assert_eq!(
            String::from_utf8_lossy(&out),
            "<head><title>x</title></head>"
        );

        // A `</div>` inside a comment does not end the element.
        let plan = plan_of(&["shop.test$$div[class=\"ad\"]"]);
        let (out, _) = plan
            .apply(&body_of("<div class=\"ad\">x<!-- </div> -->y</div>keep"))
            .expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "keep");

        // A `</div>` inside a script does not end the element either.
        let (out, _) = plan
            .apply(&body_of(
                "<div class=\"ad\"><script>var s = \"</div>\";</script></div>keep",
            ))
            .expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "keep");
    }

    #[test]
    fn an_element_that_never_closes_ends_where_the_document_ends() {
        let plan = plan_of(&["shop.test$$div[class=\"ad\"]"]);
        let (out, _) = plan
            .apply(&body_of("<p>keep</p><div class=\"ad\">tail"))
            .expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "<p>keep</p>");
    }

    #[test]
    fn implied_end_tags_reach_the_same_bytes_the_parser_would() {
        // `<p>a<p>b`: the first `<p>`'s content is `a`.
        let plan = plan_of(&["shop.test$$p:contains(a)"]);
        let (out, _) = plan.apply(&body_of("<p>a<p>b")).expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "<p>b");

        // `<li>` starts close an open `<li>`.
        let plan = plan_of(&["shop.test$$li[class=\"ad\"]"]);
        let (out, _) = plan
            .apply(&body_of("<ul><li class=\"ad\">x<li>keep</ul>"))
            .expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "<ul><li>keep</ul>");
    }

    #[test]
    fn the_document_elements_are_never_removed() {
        for rule in ["shop.test$$html", "shop.test$$head", "shop.test$$body"] {
            let plan = plan_of(&[rule]);
            assert!(
                plan.apply(&body_of("<html><head></head><body>x</body></html>"))
                    .is_none(),
                "{rule}"
            );
        }
    }

    #[test]
    fn an_exception_cancels_a_rule_with_the_same_selector() {
        let rules = "shop.test$$script[tag-content=\"fbevents.js\"][max-length=\"500\"]";

        // An exception without the special attributes is another selector:
        // the reference compares them, so the rule stays.
        let built = Plan::build(
            &rules_of(&[rules]),
            &exceptions_of(&[
                "shop.test$@$script[max-length=\"500\"][tag-content=\"fbevents.js\"]",
            ]),
            "shop.test",
            "/",
        );
        assert!(
            built.is_none(),
            "attribute order is not part of the selector"
        );

        // A different selector does not cancel the rule.
        let built = Plan::build(
            &rules_of(&[rules]),
            &exceptions_of(&["shop.test$@$script:contains(fbevents.js)"]),
            "shop.test",
            "/",
        );
        assert!(built.is_some());

        // A global exception cancels everywhere.
        let built = Plan::build(
            &rules_of(&[rules]),
            &exceptions_of(&["$@$script[tag-content=\"fbevents.js\"][max-length=\"500\"]"]),
            "shop.test",
            "/",
        );
        assert!(built.is_none());

        // An exception for another host does not.
        let built = Plan::build(
            &rules_of(&[rules]),
            &exceptions_of(&[
                "other.test$@$script[tag-content=\"fbevents.js\"][max-length=\"500\"]",
            ]),
            "shop.test",
            "/",
        );
        assert!(built.is_some());
    }

    #[test]
    fn domains_decide_where_a_rule_applies() {
        let rules = rules_of(&["example.*$$div[class=\"ad\"]", "shop.test$$p"]);
        let plan = Plan::build(&rules, &[], "example.com", "/").expect("a plan");
        let (out, texts) = plan
            .apply(&body_of("<div class=\"ad\">x</div>"))
            .expect("a removal");
        assert!(out.is_empty());
        assert_eq!(texts, vec!["div[class=\"ad\"]".to_string()]);
        assert!(Plan::build(&rules, &[], "other.test", "/").is_none());
    }

    #[test]
    fn a_domain_position_is_read_once_and_matched_the_same_way() {
        // `.*` stands for any TLD: a whole label at the start or in the
        // middle of the host.
        let wild = DomainSpec::parse(Some("Example.*")).expect("spec");
        assert!(wild.matches("example.com"));
        assert!(wild.matches("www.example.co.uk"));
        assert!(!wild.matches("notexample.com"));
        // A leading `*.` and a bare parent both admit the host and its
        // subdomains.
        let suffix = DomainSpec::parse(Some("*.shop.test")).expect("spec");
        assert!(suffix.matches("shop.test"));
        assert!(suffix.matches("a.shop.test"));
        assert!(!suffix.matches("notshop.test"));
        // `~` excludes; a position with only negations applies elsewhere.
        let mixed = DomainSpec::parse(Some("~quiet.test, shop.test")).expect("spec");
        assert!(mixed.matches("shop.test"));
        assert!(mixed.matches("cdn.shop.test"));
        assert!(!mixed.matches("quiet.test"));
        assert!(!mixed.matches("other.test"));
        let negated_only = DomainSpec::parse(Some("~quiet.test")).expect("spec");
        assert!(negated_only.matches("any.test"));
        assert!(!negated_only.matches("quiet.test"));
        // `*` alone admits everything.
        assert!(DomainSpec::parse(Some("*"))
            .expect("spec")
            .matches("whatever.test"));
    }

    #[test]
    fn a_bracket_names_the_domain_position_or_the_path() {
        // `[$domain=…]` = the domain position, like the cosmetic scanner.
        let rule = match parse_line("[$domain=shop.test]$$div[class=\"ad\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let plan = Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/").expect("a plan");
        assert!(plan.apply(&body_of("<div class=\"ad\">x</div>")).is_some());
        assert!(Plan::build(std::slice::from_ref(&rule), &[], "other.test", "/").is_none());

        // `[$path=…]` matches the page's path and query.
        let rule = match parse_line("[$path=/video/]$$div[class=\"ad\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        assert!(Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/video/x").is_some());
        assert!(Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/other").is_none());

        // `[$url=…]` matches the whole page URL.
        let rule = match parse_line("[$url=/^https:\\/\\/shop\\.test\\/video/]$$div[class=\"ad\"]")
        {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/video/x"
        )
        .is_some());
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/other"
        )
        .is_none());
    }

    #[test]
    fn path_in_domain_scopes_html_rules() {
        let rule = match parse_line("shop.test/video$$div[class=\"ad\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/video/x"
        )
        .is_some());
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/other"
        )
        .is_none());

        // One target may carry a path while the others do not; the line
        // becomes one rule per target.
        let Parsed::Many { blocking, .. } =
            parse_line("alpha.test,beta.test/checkout$$div[class=\"ad\"]")
        else {
            panic!("a target list");
        };
        assert_eq!(blocking.len(), 2);
        assert!(Plan::build(&blocking, &[], "alpha.test", "https://alpha.test/other").is_some());
        assert!(Plan::build(&blocking, &[], "beta.test", "https://beta.test/other").is_none());
        assert!(Plan::build(&blocking, &[], "beta.test", "https://beta.test/checkout").is_some());

        // A whole-target regexp sees the host and the path together.
        let rule = match parse_line(r#"/shop\.test\/video[0-9]+/$$div[class="ad"]"#) {
            Parsed::Rule(rule) => rule,
            _ => panic!("a regexp rule"),
        };
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/video12"
        )
        .is_some());
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/other"
        )
        .is_none());
    }

    #[test]
    fn a_url_bracket_refuses_a_domain_position() {
        assert!(matches!(
            parse_line("[$url=/shop/]shop.test$$div[class=\"ad\"]"),
            Parsed::Unsupported
        ));
        assert!(matches!(
            parse_line("[$url=/shop/,path=/video]$$div[class=\"ad\"]"),
            Parsed::Unsupported
        ));
        assert!(matches!(
            parse_line("[$url=/shop/]$$div[class=\"ad\"]"),
            Parsed::Rule(_)
        ));
        // A bracket `$path` and a path-in-domain target are two path scopes
        // on one rule; the pair is refused rather than picking one.
        assert!(matches!(
            parse_line("[$path=/shop/]shop.test/video$$div[class=\"ad\"]"),
            Parsed::Unsupported
        ));
        assert!(matches!(
            parse_line("[$path=/shop/]shop.test$$div[class=\"ad\"]"),
            Parsed::Rule(_)
        ));
    }

    #[test]
    fn a_bracket_app_narrows_html_rules() {
        let rule = match parse_line("[$app=org.example.app]shop.test$$div[class=\"ad\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        assert!(Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/").is_none());
        let apps = vec!["org.example.app".to_string()];
        assert!(
            Plan::build_for_apps(std::slice::from_ref(&rule), &[], "shop.test", "/", &apps)
                .is_some()
        );
        let other = vec!["com.example.app".to_string()];
        assert!(
            Plan::build_for_apps(std::slice::from_ref(&rule), &[], "shop.test", "/", &other)
                .is_none()
        );
    }

    #[test]
    fn an_app_bracket_exception_only_cancels_for_its_app() {
        let rule = match parse_line("shop.test$$div[class=\"ad\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let exception = match parse_line("[$app=org.example.app]shop.test$@$div[class=\"ad\"]") {
            Parsed::Exception(rule) => rule,
            _ => panic!("an exception"),
        };
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            std::slice::from_ref(&exception),
            "shop.test",
            "/"
        )
        .is_some());
        let app = vec!["org.example.app".to_string()];
        assert!(Plan::build_for_apps(
            std::slice::from_ref(&rule),
            std::slice::from_ref(&exception),
            "shop.test",
            "/",
            &app
        )
        .is_none());
        let other = vec!["com.example.app".to_string()];
        assert!(Plan::build_for_apps(
            std::slice::from_ref(&rule),
            std::slice::from_ref(&exception),
            "shop.test",
            "/",
            &other
        )
        .is_some());
    }

    #[test]
    fn path_in_domain_html_keeps_its_query_text() {
        let rule = match parse_line("shop.test/search?q=1$$div[class=\"ad\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/search?q=1"
        )
        .is_some());
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/search?q=2"
        )
        .is_none());
    }

    #[test]
    fn path_in_domain_html_exceptions_cancel_only_on_their_path() {
        let rule = match parse_line("shop.test$$div[class=\"ad\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let exception = match parse_line("shop.test/video$@$div[class=\"ad\"]") {
            Parsed::Exception(rule) => rule,
            _ => panic!("an exception"),
        };
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            std::slice::from_ref(&exception),
            "shop.test",
            "https://shop.test/video"
        )
        .is_none());
        assert!(Plan::build(
            std::slice::from_ref(&rule),
            std::slice::from_ref(&exception),
            "shop.test",
            "https://shop.test/other"
        )
        .is_some());
    }

    #[test]
    fn an_app_bracket_narrows_path_in_domain_html_rules() {
        let rule = match parse_line("[$app=org.example.app]shop.test/video$$div[class=\"ad\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let app = vec!["org.example.app".to_string()];
        assert!(Plan::build_for_apps(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/video",
            &app
        )
        .is_some());
        assert!(Plan::build_for_apps(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/other",
            &app
        )
        .is_none());
        assert!(Plan::build_for_apps(
            std::slice::from_ref(&rule),
            &[],
            "shop.test",
            "https://shop.test/video",
            &["com.other.app".to_string()]
        )
        .is_none());
    }

    #[test]
    fn a_chain_asks_about_the_parent() {
        let plan = plan_of(&["shop.test$$div[class=\"ad\"] > iframe[src]"]);
        assert!(plan
            .apply(&body_of(
                "<div class=\"ad\"><iframe src=\"x\"></iframe></div>"
            ))
            .is_some());
        // The parent must be the direct one and match.
        assert!(plan
            .apply(&body_of(
                "<div class=\"ad\"><span><iframe src=\"x\"></iframe></span></div>"
            ))
            .is_none());
        assert!(plan
            .apply(&body_of(
                "<div class=\"other\"><iframe src=\"x\"></iframe></div>"
            ))
            .is_none());
    }

    #[test]
    fn the_ubo_profile_reads_css_selectors_and_case_insensitive_text() {
        // A blocking `##^` rule needs a hostname.
        assert!(matches!(
            parse_line("##^script:has-text(await eval)"),
            Parsed::Unsupported
        ));
        assert!(matches!(
            parse_line("#@^script:has-text(await eval)"),
            Parsed::Exception(_)
        ));

        let rule = match parse_line("shop.test##^script:has-text(await eval)") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let plan = Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/").expect("a plan");
        // uBO's literal search does not care about case.
        let (out, _) = plan
            .apply(&body_of("<script>await EVAL(async()=>{})</script>"))
            .expect("a removal");
        assert!(out.is_empty());

        // Moar CSS: classes, ids and operators.
        let rule = match parse_line("shop.test##^.ad#slot[data-x*=\"y\"]") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let plan = Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/").expect("a plan");
        assert!(plan
            .apply(&body_of(
                "<div class=\"x ad y\" id=\"slot\" data-x=\"ayb\">t</div>"
            ))
            .is_some());

        // The text search reads textContent, not the markup.
        let rule = match parse_line("shop.test##^div:has-text(hello world)") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let plan = Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/").expect("a plan");
        assert!(plan
            .apply(&body_of("<div>hello <b>world</b></div>"))
            .is_some());
        assert!(plan.apply(&body_of("<div>hello</div>")).is_none());
    }

    #[test]
    fn the_ubo_responseheader_form_is_not_this_feature() {
        assert!(matches!(
            parse_line("shop.test##^responseheader(refresh)"),
            Parsed::Unsupported
        ));
    }

    #[test]
    fn ubo_regexes_take_only_the_i_flag() {
        let rule = match parse_line("shop.test##^script:has-text(/await eval/)") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let plan = Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/").expect("a plan");
        // Without `i`, the regexp is case-sensitive.
        assert!(plan
            .apply(&body_of("<script>await eval</script>"))
            .is_some());
        assert!(plan
            .apply(&body_of("<script>await EVAL</script>"))
            .is_none());

        let rule = match parse_line("shop.test##^script:has-text(/await eval/i)") {
            Parsed::Rule(rule) => rule,
            _ => panic!("a rule"),
        };
        let plan = Plan::build(std::slice::from_ref(&rule), &[], "shop.test", "/").expect("a plan");
        assert!(plan
            .apply(&body_of("<script>await EVAL</script>"))
            .is_some());
    }

    #[test]
    fn one_walk_cuts_every_matching_element() {
        let plan = plan_of(&[
            "shop.test$$div[class=\"ad\"]",
            "shop.test$$p:contains(Sponsored)",
        ]);
        let (out, texts) = plan
            .apply(&body_of(
                "<div class=\"ad\">a</div><p>keep</p><p>Sponsored content</p>",
            ))
            .expect("removals");
        assert_eq!(String::from_utf8_lossy(&out), "<p>keep</p>");
        assert_eq!(texts.len(), 2);

        // An inner match inside a removed outer element is not counted twice.
        let plan = plan_of(&[
            "shop.test$$div[class=\"ad\"]",
            "shop.test$$span:contains(x)",
        ]);
        let (out, texts) = plan
            .apply(&body_of("<div class=\"ad\"><span>x</span></div>keep"))
            .expect("removals");
        assert_eq!(String::from_utf8_lossy(&out), "keep");
        assert_eq!(texts, vec!["div[class=\"ad\"]".to_string()]);
    }

    #[test]
    fn a_tagless_compound_matches_any_element() {
        let plan = plan_of(&["shop.test$$:contains(NativeAd)"]);
        let (out, _) = plan
            .apply(&body_of("<p>keep</p><div><span>NativeAd</span></div>"))
            .expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "<p>keep</p>");
    }

    #[test]
    fn uppercase_markup_matches_lowercase_rules() {
        let plan = plan_of(&["shop.test$$div[class=\"ad\"]"]);
        assert!(plan.apply(&body_of("<DIV CLASS=\"ad\">x</DIV>")).is_some());
    }

    #[test]
    fn a_stray_end_tag_changes_nothing() {
        let plan = plan_of(&["shop.test$$div[class=\"ad\"]"]);
        let (out, _) = plan
            .apply(&body_of("</div><div class=\"ad\">x</div></div>"))
            .expect("a removal");
        assert_eq!(String::from_utf8_lossy(&out), "</div></div>");
    }

    #[test]
    fn nothing_matched_means_no_rewrite_at_all() {
        let plan = plan_of(&["shop.test$$div[class=\"ad\"]"]);
        assert!(plan.apply(&body_of("<p>clean</p>")).is_none());
        assert!(plan.apply(b"not html at all").is_none());
    }
}
