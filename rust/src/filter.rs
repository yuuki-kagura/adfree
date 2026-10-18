//! Filter core: a thin, battery-aware wrapper around `adblock` (the AdGuard /
//! Brave adblock engine).
//!
//! Responsibilities:
//! * keep subscriptions as files on disk and only materialise their text while
//!   building an engine, so steady state memory is the compiled index and
//!   nothing else;
//! * build on a background thread and swap the compiled engine in atomically:
//!   the packet loop never waits for a rebuild;
//! * put a bounded per-host decision cache in front of the engine. Apps re-query
//!   the same handful of hosts constantly, and a cache hit is many times cheaper
//!   than a full rule evaluation, which is exactly the kind of win that shows
//!   up in the battery profile;
//! * translate a hostname into the engine's `Request` shape (DNS level matching
//!   = "request for `https://host/`"), which is what AdGuard's own DNS filtering
//!   does.
//!
//! The engine is compiled *without* the `single-thread` feature so it is
//! `Send + Sync`.

use crate::fxhash::hash_str;
use adblock::cosmetic_filter_cache::ProceduralOrActionFilter;
use adblock::engine::Engine;
use adblock::lists::{FilterFormat, FilterSet, ParseOptions, RuleTypes};
use adblock::request::Request;
use adblock::resources::{MimeType, Resource, ResourceType};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

/// Format of a subscription file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ListFormat {
    /// AdGuard / EasyList / Adblock Plus syntax.
    Standard,
    /// `0.0.0.0 host` hosts syntax (OISD, StevenBlack, HaGeZi, ...).
    Hosts,
}

impl ListFormat {
    pub fn as_u8(self) -> u8 {
        match self {
            ListFormat::Standard => 0,
            ListFormat::Hosts => 1,
        }
    }

    pub fn from_u8(v: u8) -> ListFormat {
        if v == 1 {
            ListFormat::Hosts
        } else {
            ListFormat::Standard
        }
    }
}

/// Categories are indices into the app's UI labels. Keep in sync with
/// `com.example.model.RequestCategory`.
pub const CAT_AD: u8 = 0;
pub const CAT_TRACKER: u8 = 1;
pub const CAT_ANALYTICS: u8 = 2;
pub const CAT_SOCIAL: u8 = 3;

/// Caps on one page's cosmetic payload. A page must never download megabytes
/// of rules because a subscription went wild; AdGuard caps the same way.
const MAX_HIDE_SELECTORS: usize = 6000;
const MAX_STYLE_RULES: usize = 400;
const MAX_PROCEDURAL: usize = 400;
const MAX_SCRIPTLET_BYTES: usize = 128 * 1024;
const MAX_GENERIC_SELECTORS: usize = 3000;

/// Scriptlet implementations (AdGuard's, compiled into the binary).
///
/// The `adblock` crate ships no scriptlets of its own: it assembles
/// `#%#//scriptlet(...)` rules only when the host provides the resource table.
/// The table is embedded at build time and parsed once, on the first rebuild.
fn scriptlet_resources() -> &'static Vec<Resource> {
    static RESOURCES: OnceLock<Vec<Resource>> = OnceLock::new();
    RESOURCES.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/scriptlets.json")).unwrap_or_else(|e| {
            crate::logbuf::push(&format!("scriptlets: bad embedded resource table: {e}"));
            Vec::new()
        })
    })
}

/// Redirect resources (`$redirect=noopjs` and friends) the engine can serve in
/// place of a blocked request.
///
/// A rule like `||imasdk.googleapis.com/js/sdkloader/ima3.js$redirect=noopjs`
/// exists to keep a page alive while a script is neutralised: without the
/// resource table the crate reports no redirect, the rule degrades to a hard
/// block, and the page breaks on the missing script. Names are AdGuard's first,
/// uBO's and EasyList's ride along as aliases, and the content is embedded in
/// the base64 form the engine stores.
///
/// Only tiny, dependency-free resources live here. Anything a list asks for
/// that is missing simply does not redirect — the request is blocked exactly
/// as it would have been before.
const REDIRECT_TABLE: &[(&str, &[&str], MimeType, &str)] = &[
    // `(function(){})();`
    (
        "noopjs",
        &["noop.js", "noopjs.js"],
        MimeType::ApplicationJavascript,
        "KGZ1bmN0aW9uKCl7fSkoKTs=",
    ),
    // An empty body: the classic "let the request through with nothing".
    ("nooptext", &["noop.txt"], MimeType::TextPlain, ""),
    (
        "noopjson",
        &["noop.json"],
        MimeType::ApplicationJson,
        "e30=",
    ),
    ("noopcss", &["noop.css"], MimeType::TextCss, ""),
    (
        "noopframe",
        &["noop.html"],
        MimeType::TextHtml,
        "PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PC9oZWFkPjxib2R5PjwvYm9keT48L2h0bWw+",
    ),
    // A 1x1 transparent GIF.
    (
        "1x1.gif",
        &["1x1-transparent.gif", "transparent.gif"],
        MimeType::ImageGif,
        "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
    ),
    (
        "noop-vast2.xml",
        &[],
        MimeType::TextXml,
        "PFZBU1QgdmVyc2lvbj0iMi4wIj48L1ZBU1Q+",
    ),
    (
        "noop-vast3.xml",
        &[],
        MimeType::TextXml,
        "PFZBU1QgdmVyc2lvbj0iMy4wIj48L1ZBU1Q+",
    ),
    (
        "noop-vast4.xml",
        &[],
        MimeType::TextXml,
        "PFZBU1QgdmVyc2lvbj0iNC4wIj48L1ZBU1Q+",
    ),
];

/// The redirect table as engine resources (built once, on the first rebuild).
fn redirect_resources() -> &'static Vec<Resource> {
    static RESOURCES: OnceLock<Vec<Resource>> = OnceLock::new();
    RESOURCES.get_or_init(|| {
        REDIRECT_TABLE
            .iter()
            .map(|(name, aliases, kind, content)| Resource {
                name: (*name).to_string(),
                aliases: aliases.iter().map(|alias| (*alias).to_string()).collect(),
                kind: ResourceType::Mime(kind.clone()),
                content: (*content).to_string(),
                dependencies: Vec::new(),
                permission: Default::default(),
            })
            .collect()
    })
}

/// Cosmetic filtering payload for one page, ready for the content script.
#[derive(Debug, Default)]
pub struct CosmeticResources {
    /// `##` selectors to hide (`display: none !important`).
    pub hide_selectors: Vec<String>,
    /// `#$#` style rules reducible to plain CSS: `(selector, declarations)`.
    pub style_rules: Vec<(String, String)>,
    /// `#?#` / action rules that need in-page JS, as JSON for the runtime.
    pub procedural: Vec<String>,
    /// `#%#//scriptlet(...)` invocations, assembled with their functions.
    pub scriptlets: String,
    /// A `$generichide` exception is in play: skip the class/id lookup.
    pub generichide: bool,
    /// Selectors excepted by `#@#`: pass to [`FilterEngine::generic_selectors`].
    pub exceptions: Vec<String>,
}

impl CosmeticResources {
    /// True when there is nothing to hand to a page.
    pub fn is_empty(&self) -> bool {
        self.hide_selectors.is_empty()
            && self.style_rules.is_empty()
            && self.procedural.is_empty()
            && self.scriptlets.is_empty()
    }
}
/// Page-level work the lists' exception rules switch off.
///
/// The engine itself knows `$generichide` only; the rest are scanned out of
/// the list text by [`scan_cosmetic_exceptions`] and applied when a page asks
/// for its cosmetic resources ([`FilterEngine::cosmetic_switches_for`]) or when
/// the MITM path decides about the page's own requests (`urlblock`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CosmeticSwitches {
    /// `$elemhide` (alias `$ehide`): no element hiding, specific or generic.
    pub elemhide: bool,
    /// `$specifichide` (alias `$shide`): no rules bound to the page's own
    /// domain. Generic rules stay.
    pub specifichide: bool,
    /// `$jsinject`: no scriptlets.
    pub jsinject: bool,
    /// `$urlblock` (and `$document`, which implies it): the page's own
    /// requests are not blocked by network rules. The page host is the source:
    /// the document that carries the exception, or the referrer of a
    /// subresource.
    pub urlblock: bool,
}

impl CosmeticSwitches {
    fn merge(&mut self, other: CosmeticSwitches) {
        self.elemhide |= other.elemhide;
        self.specifichide |= other.specifichide;
        self.jsinject |= other.jsinject;
        self.urlblock |= other.urlblock;
    }
}

/// One `$replace` rule's payload, ready to apply to a response body.
///
/// The crate drops every rule carrying a modifier it does not implement, so
/// `$replace` rules never reach the main engine. [`scan_replace_rules`] keeps
/// them aside — their patterns still matched by the crate, their payloads
/// compiled here — and the HTTPS path applies them after decoding a response
/// body, which is what AdGuard calls "the response is modified instead".
pub struct Replace {
    /// The payload exactly as the list wrote it: `/regexp/replacement/flags`.
    payload: String,
    /// `None` when the pattern is one the `regex` crate cannot compile
    /// (lookarounds, backreferences): the engine cannot run such a rule, so
    /// the response travels unmodified — the request is still not blocked,
    /// which is the part of the modifier that keeps a page alive.
    regex: Option<regex::bytes::Regex>,
    /// The right-hand side with AdGuard's escapes resolved.
    replacement: String,
}

impl Replace {
    /// Reads `/regexp/replacement/flags`, the only shape real lists use.
    ///
    /// The payload may contain escaped separators (`\/`, `\,`) and escaped
    /// dollars (`\$1`), and two of the three slashes close the regexp and the
    /// replacement before the flags follow, so a malformed value still yields
    /// a rule that simply never matches.
    pub fn parse(payload: &str) -> Replace {
        let mut replacement = String::new();
        let mut regex = None;
        if let Some(rest) = payload.strip_prefix('/') {
            if let Some((pattern, rest)) = split_unescaped(rest, '/') {
                if let Some((right, flags)) = split_unescaped(rest, '/') {
                    replacement = unescape_replacement(right);
                    regex = inline_flags(flags)
                        .map(|prefix| format!("{prefix}{}", unescape_pattern(pattern)))
                        .and_then(|pattern| regex::bytes::Regex::new(&pattern).ok());
                }
            }
        }
        Replace {
            payload: payload.to_string(),
            regex,
            replacement,
        }
    }

    /// The payload as the list wrote it, for logs.
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// True when the pattern compiled: a rule that cannot run rewrites
    /// nothing.
    pub fn runs(&self) -> bool {
        self.regex.is_some()
    }

    /// The body with every match replaced, or `None` when nothing matched.
    ///
    /// `None` leaves the caller free to hand the original bytes over with the
    /// origin's own length and framing still in place.
    pub fn apply(&self, body: &[u8]) -> Option<Vec<u8>> {
        let regex = self.regex.as_ref()?;
        match regex.replace_all(body, self.replacement.as_bytes()) {
            std::borrow::Cow::Owned(bytes) => Some(bytes),
            std::borrow::Cow::Borrowed(_) => None,
        }
    }
}

/// The `(?i)`-style prefix for a `$replace` payload's flags, or `None` when a
/// flag means something this engine does not implement.
///
/// `g` asks for every match, which `replace_all` does anyway.
fn inline_flags(flags: &str) -> Option<String> {
    let mut out = String::new();
    for flag in flags.chars() {
        match flag {
            'g' | '_' => {}
            'i' | 'm' | 's' | 'x' => out.push(flag),
            _ => return None,
        }
    }
    if out.is_empty() {
        Some(String::new())
    } else {
        Some(format!("(?{out})"))
    }
}

/// Resolves the escapes an AdGuard `$replace` regexp carries.
///
/// `\,` is what keeps a comma out of the option list; as a regexp it becomes
/// the character itself — the engine has no use for the backslash, and a
/// quantifier would not parse with it (`{280\,400}`). `\/` needs no resolving:
/// the list writes it as the separator's escape and the regexp engine reads an
/// escaped piece of punctuation as that piece. `\\` is a literal backslash, so
/// neither rule applies to whatever follows it.
fn unescape_pattern(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some(',') => {
                chars.next();
                out.push(',');
            }
            Some('\\') => {
                chars.next();
                out.push('\\');
                out.push('\\');
            }
            Some(_) => out.push('\\'),
            None => out.push('\\'),
        }
    }
    out
}

/// Splits at the first `sep` that is not escaped by a backslash.
fn split_unescaped(text: &str, sep: char) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (index, c) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            _ if c == sep => return Some((&text[..index], &text[index + c.len_utf8()..])),
            _ => {}
        }
    }
    None
}

/// Resolves the escapes AdGuard writes inside a `$replace` replacement.
///
/// `\/` is the separator, `\,` the comma the option list splits on and `\$1`
/// a capture reference — which the regex crate spells `$1`, so the backslash
/// has to go. Anything else keeps its backslash.
fn unescape_replacement(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(next) if matches!(next, '/' | '$' | ',') => out.push(next),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

pub const CAT_ANNOYANCE: u8 = 4;
pub const CAT_MALWARE: u8 = 5;
pub const CAT_CUSTOM: u8 = 6;

/// Everything needed to (re)build and identify one subscription.
#[derive(Clone, Debug)]
pub struct FilterListInfo {
    pub id: u16,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub local_path: Option<PathBuf>,
    pub format: ListFormat,
    pub category: u8,
    /// Filled in after a build attempt.
    pub rule_count: u64,
    pub last_error: Option<String>,
}

/// Result of a host lookup.
#[derive(Clone, Debug, Default)]
pub struct HostVerdict {
    pub blocked: bool,
    pub rule_text: Option<String>,
    pub list_name: Option<String>,
    pub category: u8,
    /// The matched rule carries a `$redirect`: the request is not refused, it
    /// is answered locally with a no-op resource. The DNS layer must leave such
    /// a host alone — the MITM path (which sees the whole URL, and can tell a
    /// `redirect-rule` that applies from one that does not) serves it.
    pub redirect: bool,
}

/// What the engine says about one full request URL.
///
/// The DNS layer only ever has a hostname; the MITM path has the request line
/// and headers, so it can evaluate the rules that need a URL (`$redirect`,
/// `$removeparam`, path-scoped blocks) and answer precisely.
#[derive(Clone, Debug, Default)]
pub struct UrlVerdict {
    /// The request must not reach the network. `redirect` may still be set:
    /// the block is then answered with that resource instead of nothing.
    pub blocked: bool,
    /// Body of a `$redirect` resource, as the crate hands it over: a `data:`
    /// URL carrying the MIME type and the bytes.
    pub redirect: Option<String>,
    /// The URL the request must be rewritten to before it is forwarded
    /// (`$removeparam` dropped something from the query).
    pub rewritten_url: Option<String>,
    pub rule_text: Option<String>,
    pub list_name: Option<String>,
    pub category: u8,
}

#[derive(Clone, Copy)]
struct CachedDecision {
    blocked: bool,
    redirect: bool,
    category: u8,
    generation: u64,
}

/// Open-addressed cache sized as a power of two, cleared wholesale once 90% full.
struct DecisionCache {
    keys: Vec<u64>,
    values: Vec<CachedDecision>,
    used: usize,
    hits: u64,
    misses: u64,
}

impl DecisionCache {
    fn new(capacity: usize) -> Self {
        DecisionCache {
            keys: vec![0; capacity],
            values: vec![
                CachedDecision {
                    blocked: false,
                    redirect: false,
                    category: 0,
                    generation: u64::MAX,
                };
                capacity
            ],
            used: 0,
            hits: 0,
            misses: 0,
        }
    }

    #[inline]
    fn get(&mut self, key: u64, generation: u64) -> Option<CachedDecision> {
        if self.used == 0 {
            self.misses += 1;
            return None;
        }
        let mask = self.keys.len() - 1;
        let mut idx = (key as usize) & mask;
        for _ in 0..8 {
            let k = self.keys[idx];
            if k == key {
                let v = self.values[idx];
                if v.generation == generation {
                    self.hits += 1;
                    return Some(v);
                }
                self.misses += 1;
                return None;
            }
            if k == 0 {
                self.misses += 1;
                return None;
            }
            idx = (idx + 1) & mask;
        }
        self.misses += 1;
        None
    }

    #[inline]
    fn insert(&mut self, key: u64, value: CachedDecision) {
        let mask = self.keys.len() - 1;
        let mut idx = (key as usize) & mask;
        for _ in 0..8 {
            if self.keys[idx] == key || self.keys[idx] == 0 {
                if self.keys[idx] == 0 {
                    self.used += 1;
                }
                self.keys[idx] = key;
                self.values[idx] = value;
                return;
            }
            idx = (idx + 1) & mask;
        }
    }

    fn maybe_clear(&mut self) {
        if self.used * 10 >= self.keys.len() * 9 {
            for k in self.keys.iter_mut() {
                *k = 0;
            }
            self.used = 0;
        }
    }

    fn clear(&mut self) {
        for k in self.keys.iter_mut() {
            *k = 0;
        }
        self.used = 0;
    }

    fn hits(&self) -> u64 {
        self.hits
    }

    fn misses(&self) -> u64 {
        self.misses
    }
}

/// Maps the engine's internal `source_index` back to the subscription it came
/// from, so the UI can show "matched by <list>".
#[derive(Clone)]
struct SourceMapEntry {
    source_index: u32,
    #[allow(dead_code)]
    list_id: u16,
    name: String,
    category: u8,
}

struct Compiled {
    engine: Engine,
    generation: u64,
    memory_bytes: usize,
    sources: Vec<SourceMapEntry>,
    rule_count: u64,
    /// Cosmetic switches from the loaded exceptions, by hostname (see
    /// [`scan_cosmetic_exceptions`]). Empty on a stock engine.
    cosmetic_switches: HashMap<String, CosmeticSwitches>,
    /// `$replace` rules, found by [`scan_replace_rules`]. `None` when no
    /// loaded list carries one.
    replace: Option<ReplaceEngine>,
}

/// The `$replace` rules of the loaded lists, with the engine that finds them.
///
/// The crate refuses the modifier, so a rule cannot go into the main engine
/// as it stands. It goes into a second one with `$replace` swapped for a
/// `$redirect` to a per-rule resource: the crate keeps matching the rule's
/// own pattern — `domain=`, type options, `important` and exceptions all mean
/// what the list meant — and hands the matched rule's identity back as the
/// redirect body.
struct ReplaceEngine {
    /// The probe engine. `None` when only content exceptions were found.
    probe: Option<Engine>,
    /// Payloads, index-matched with the probe engine's resources.
    rules: Vec<Arc<Replace>>,
    /// Rules that switch content modification off (`$content`, an empty
    /// `$replace`), kept as plain blocking rules: a match there means "do not
    /// modify the response".
    veto: Option<Engine>,
    /// How many content exceptions went into [`ReplaceEngine::veto`].
    veto_rules: u32,
    /// Rules left out because the crate cannot be told about them the way the
    /// list meant them (`app=`, `badfilter`, a payload on a page exception).
    dropped: u32,
}

pub struct FilterEngine {
    inner: RwLock<Arc<Compiled>>,
    cache: RwLock<DecisionCache>,
    /// Total time spent building engines (diagnostics).
    build_ns: AtomicU64,
    pending_builds: AtomicUsize,
    generation: AtomicU64,
}

impl Default for FilterEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterEngine {
    pub fn new() -> Self {
        FilterEngine {
            inner: RwLock::new(Arc::new(Compiled {
                engine: Engine::default(),
                generation: 0,
                memory_bytes: 0,
                sources: Vec::new(),
                rule_count: 0,
                cosmetic_switches: HashMap::new(),
                replace: None,
            })),
            cache: RwLock::new(DecisionCache::new(1 << 15)),
            build_ns: AtomicU64::new(0),
            pending_builds: AtomicUsize::new(0),
            generation: AtomicU64::new(0),
        }
    }

    /// Compiles `lists` (+ `user_rules`) into a new engine and swaps it in.
    /// Returns the new generation.
    pub fn rebuild(&self, lists: &[FilterListInfo], user_rules: &[String]) -> u64 {
        let build_started = std::time::Instant::now();
        let mut set = FilterSet::new(true);
        let mut sources: Vec<SourceMapEntry> = Vec::with_capacity(lists.len() + 1);
        let mut rule_count = 0u64;
        let mut errors: Vec<String> = Vec::new();
        let mut cosmetic_exceptions = CosmeticExceptionScan::default();
        let mut replace_scan = ReplaceScan::default();

        for list in lists.iter().filter(|l| l.enabled) {
            let Some(path) = &list.local_path else { continue };
            match std::fs::read(path) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => {
                        let format = match list.format {
                            ListFormat::Hosts => FilterFormat::Hosts,
                            ListFormat::Standard => FilterFormat::Standard,
                        };
                        let text = match list.format {
                            ListFormat::Standard => {
                                // Exception rules the engine drops, read here
                                // (conversion only rewrites cosmetic markers,
                                // network rules pass through untouched).
                                scan_cosmetic_exceptions(&text, &mut cosmetic_exceptions);
                                scan_replace_rules(&text, &mut replace_scan);
                                convert_adguard_cosmetics(text)
                            }
                            ListFormat::Hosts => text,
                        };
                        let counted = count_rules(&text);
                        let record = set.add_filter_list(
                            text,
                            ParseOptions {
                                format,
                                rule_types: RuleTypes::All,
                                ..Default::default()
                            },
                        );
                        let name = if list.name.trim().is_empty() {
                            record
                                .metadata
                                .title
                                .clone()
                                .unwrap_or_else(|| "Untitled list".to_string())
                        } else {
                            list.name.trim().to_string()
                        };
                        sources.push(SourceMapEntry {
                            source_index: record.source_index as u32,
                            list_id: list.id,
                            name,
                            category: list.category,
                        });
                        rule_count += counted;
                    }
                    Err(e) => errors.push(format!("{}: {}", path.display(), e)),
                },
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        errors.push(format!("{}: {}", path.display(), e));
                    }
                }
            }
        }

        // User rules go last: they must be able to win over any subscription.
        if !user_rules.is_empty() {
            let joined = user_rules
                .iter()
                .filter(|r| !r.trim().is_empty())
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            scan_cosmetic_exceptions(&joined, &mut cosmetic_exceptions);
            scan_replace_rules(&joined, &mut replace_scan);
            let record = set.add_filter_list(
                convert_adguard_cosmetics(joined),
                ParseOptions::default(),
            );
            sources.push(SourceMapEntry {
                source_index: record.source_index as u32,
                list_id: 0,
                name: "User Custom Filter".to_string(),
                category: CAT_CUSTOM,
            });
        }

        let mut engine = Engine::new_with_filter_set(set);
        // Scriptlets: `#%#//scriptlet(...)` rules are only assembled when the
        // engine knows the implementations, so the table goes in before any
        // page asks for its cosmetic resources. Redirects ride in the same
        // call — `use_resources` *replaces* the table, it does not add to it —
        // and an unresolved `$redirect` degrades to a hard block.
        engine.use_resources(
            scriptlet_resources()
                .iter()
                .chain(redirect_resources().iter())
                .cloned(),
        );
        let memory_bytes = engine.serialize().len();
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let replace = build_replace(replace_scan);
        if let Some(replace) = replace.as_ref() {
            // The count is what the docs quote: rules the lists carry that the
            // engine on its own would have thrown away.
            let unreadable = replace.rules.iter().filter(|rule| !rule.runs()).count();
            crate::logbuf::push(&format!(
                "filter: {} $replace rules ({unreadable} unreadable), {} content exceptions, {} rules dropped",
                replace.rules.len(),
                replace.veto_rules,
                replace.dropped,
            ));
        }
        let compiled = Arc::new(Compiled {
            engine,
            generation,
            memory_bytes,
            sources,
            rule_count,
            cosmetic_switches: cosmetic_exceptions.resolve(),
            replace,
        });
        *self.inner.write().unwrap() = compiled;
        self.cache.write().unwrap().clear();
        self.build_ns
            .fetch_add(build_started.elapsed().as_nanos() as u64, Ordering::SeqCst);
        self.pending_builds.fetch_sub(1, Ordering::SeqCst);
        generation
    }

    /// Same as [`rebuild`] but on a background thread: calls are processed in
    /// order, so only the newest snapshot ends up active.
    pub fn rebuild_async(self: &Arc<Self>, lists: Vec<FilterListInfo>, user_rules: Vec<String>) {
        self.pending_builds.fetch_add(1, Ordering::SeqCst);
        let engine = Arc::clone(self);
        std::thread::Builder::new()
            .name("adfree-filter-build".into())
            .spawn(move || {
                        engine.rebuild(&lists, &user_rules);
            })
            .ok();
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    pub fn memory_bytes(&self) -> usize {
        let compiled = self.inner.read().unwrap();
        compiled.memory_bytes
    }

    pub fn active_rules(&self) -> u64 {
        let compiled = self.inner.read().unwrap();
        compiled.rule_count
    }

    /// What the loaded exceptions switch off for `host`'s pages. `||host^`
    /// covers everything below the host, so the lookup walks the page host's
    /// domain suffixes. Also the switches are already folded into
    /// [`Self::cosmetic_resources`]; this is for callers that only want the
    /// flags (the injection snippet builds every tag itself).
    pub fn cosmetic_switches_for(&self, host: &str) -> CosmeticSwitches {
        switches_for(&self.compiled(), host)
    }

    /// Cosmetic rules that apply to `url`: element hiding, style actions,
    /// procedural rules and scriptlets.
    ///
    /// The caller passes the page URL (`https://host/` is enough: cosmetic
    /// matching is hostname-based, exactly like AdGuard's own engine). What
    /// the lists' exceptions switch off is already applied.
    pub fn cosmetic_resources(&self, url: &str) -> CosmeticResources {
        // Clone the Arc out of the lock: a rebuild can then swap engines
        // without this call holding the read guard.
        let compiled = self.inner.read().unwrap().clone();
        let switches = switches_for(&compiled, url_host(url));
        let raw = compiled.engine.url_cosmetic_resources(url);

        let mut hide_selectors: Vec<String> = raw.hide_selectors.into_iter().collect();
        let mut style_rules = Vec::new();
        let mut procedural = Vec::new();
        for entry in raw.procedural_actions {
            let Ok(parsed) = serde_json::from_str::<ProceduralOrActionFilter>(&entry) else {
                continue;
            };
            match parsed.as_css() {
                // `as_css` folds the default hide action back to plain CSS.
                Some((selector, style)) if style == "display: none !important" => {
                    hide_selectors.push(selector)
                }
                Some((selector, style)) => {
                    if style_rules.len() < MAX_STYLE_RULES {
                        style_rules.push((selector, style));
                    }
                }
                None => {
                    if procedural.len() < MAX_PROCEDURAL {
                        procedural.push(entry);
                    }
                }
            }
        }
        let mut scriptlets = raw.injected_script;

        if switches.elemhide {
            // `$elemhide`: no cosmetic rule at all, specific or generic.
            // Scriptlets stay — those are `$jsinject`'s business.
            hide_selectors.clear();
            style_rules.clear();
            procedural.clear();
        } else if switches.specifichide {
            // `$specifichide`: only what is bound to the page's own domain
            // goes away. Asked about a hostname no list targets, the engine
            // returns exactly the generic part, which the page keeps;
            // procedural and scriptlet rules are always hostname-bound, so
            // they simply go.
            let generic = compiled.engine.url_cosmetic_resources(GENERIC_ONLY_URL);
            let excepted: std::collections::HashSet<&str> =
                raw.exceptions.iter().map(String::as_str).collect();
            hide_selectors = generic
                .hide_selectors
                .into_iter()
                .filter(|selector| !excepted.contains(selector.as_str()))
                .collect();
            style_rules.clear();
            procedural.clear();
            scriptlets.clear();
        }
        if switches.jsinject {
            scriptlets.clear();
        }
        if scriptlets.len() > MAX_SCRIPTLET_BYTES {
            scriptlets.clear();
        }
        hide_selectors.truncate(MAX_HIDE_SELECTORS);

        CosmeticResources {
            hide_selectors,
            style_rules,
            procedural,
            scriptlets,
            // `$elemhide` covers the generic half too: nothing left to look up.
            generichide: raw.generichide || switches.elemhide,
            exceptions: raw.exceptions.into_iter().collect(),
        }
    }

    /// The element-hiding selectors that apply to `host`, in a stable order.
    ///
    /// The engine hands these out as a `HashSet`, so two calls for the same
    /// page need not agree on the order. The stylesheet they are served as is
    /// content-addressed (its URL carries a hash of the bytes), which makes a
    /// stable order mandatory: the hash written into the page has to match the
    /// bytes the stylesheet request comes back with.
    pub fn hide_selectors_for(&self, host: &str) -> Vec<String> {
        let url = format!("https://{host}/");
        let mut selectors = self.cosmetic_resources(&url).hide_selectors;
        selectors.sort_unstable();
        selectors.dedup();
        selectors
    }

    /// Generic `##.class` / `## #id` rules matching the tokens a page uses.
    ///
    /// These rules are not tied to a hostname, so the page's own classes and
    /// ids decide which ones apply; `exceptions` is the `#@#` list from
    /// [`Self::cosmetic_resources`].
    pub fn generic_selectors(
        &self,
        classes: &[String],
        ids: &[String],
        exceptions: &[String],
    ) -> Vec<String> {
        if classes.is_empty() && ids.is_empty() {
            return Vec::new();
        }
        let compiled = self.inner.read().unwrap().clone();
        let exceptions: std::collections::HashSet<String> = exceptions.iter().cloned().collect();
        let mut selectors = compiled
            .engine
            .hidden_class_id_selectors(classes, ids, &exceptions);
        selectors.truncate(MAX_GENERIC_SELECTORS);
        selectors
    }

    pub fn build_time_ms(&self) -> u64 {
        self.build_ns.load(Ordering::SeqCst) / 1_000_000
    }

    pub fn is_building(&self) -> bool {
        self.pending_builds.load(Ordering::SeqCst) > 0
    }

    pub fn is_ready(&self) -> bool {
        self.generation.load(Ordering::SeqCst) > 0
    }

    pub fn cache_hits(&self) -> u64 {
        self.cache.read().unwrap().hits()
    }

    pub fn cache_misses(&self) -> u64 {
        self.cache.read().unwrap().misses()
    }

    /// The hot path. Answers "block this host?" (cached).
    pub fn check_host(&self, host: &str) -> HostVerdict {
        let host = normalise_host(host);
        if host.is_empty() {
            return HostVerdict::default();
        }
        let key = hash_str(host);
        let compiled = self.compiled();
        let generation = compiled.generation;

        if let Some(hit) = self.cache.write().unwrap().get(key, generation) {
            if !hit.blocked {
                return HostVerdict::default();
            }
            return HostVerdict {
                blocked: true,
                rule_text: None,
                list_name: None,
                category: hit.category,
                redirect: hit.redirect,
            };
        }

        let verdict = evaluate(&compiled, host);
        self.cache.write().unwrap().insert(
            key,
            CachedDecision {
                blocked: verdict.blocked,
                redirect: verdict.redirect,
                category: verdict.category,
                generation,
            },
        );
        self.cache.write().unwrap().maybe_clear();
        verdict
    }

    /// Same as [`check_host`] but always reports the matched rule, bypassing the
    /// cache. Used by the UI (log details, threat lab).
    pub fn check_host_detailed(&self, host: &str) -> HostVerdict {
        let host = normalise_host(host);
        if host.is_empty() {
            return HostVerdict::default();
        }
        let compiled = self.compiled();
        evaluate(&compiled, host)
    }

    /// A full request URL, evaluated against every network rule.
    ///
    /// This is the MITM path's decision point: it is the only place that knows
    /// the request line, so it is where `$redirect`, `$removeparam` and the
    /// rules scoped to a path can be applied. `source` is the page the request
    /// belongs to — a document request is its own source, a subresource uses
    /// the `Referer` it carries, and an empty source counts as third-party
    /// exactly like the DNS layer does.
    ///
    /// `request_type` is one of the crate's names (`document`, `script`,
    /// `sub_frame`, `image`, `stylesheet`, `xmlhttprequest`, `media`, ...).
    pub fn check_url(
        &self,
        url: &str,
        source: &str,
        request_type: &str,
        method: &str,
    ) -> UrlVerdict {
        let compiled = self.compiled();
        let Ok(request) = Request::new(url, source, request_type, method) else {
            return UrlVerdict::default();
        };
        let result = compiled.engine.check_network_request(&request);
        let blocked = result.should_block();
        let (rule_text, list_name, category) = matched_details(&compiled, &result, url_host(url));
        UrlVerdict {
            blocked,
            // A redirect only ever stands in for a block: `$redirect-rule`
            // means "redirect instead, if something else blocks this".
            redirect: if blocked {
                result.redirect.clone()
            } else {
                None
            },
            rewritten_url: result.rewritten_url.clone(),
            rule_text,
            list_name,
            category,
        }
    }

    /// Whether any `$replace` rule is loaded: the HTTPS path only pays for the
    /// probe when one is.
    pub fn has_replace(&self) -> bool {
        self.compiled()
            .replace
            .as_ref()
            .is_some_and(|replace| replace.probe.is_some())
    }

    /// How many `$replace` rules the loaded lists carry (diagnostics).
    pub fn replace_rules(&self) -> u64 {
        self.compiled()
            .replace
            .as_ref()
            .map(|replace| replace.rules.len() as u64)
            .unwrap_or(0)
    }

    /// The `$replace` rule that applies to one request, if any.
    ///
    /// A match means the response body is rewritten *instead* of the request
    /// being blocked: AdGuard gives the modifier priority over every other
    /// basic rule, exceptions included. A page exception (`$content`, or an
    /// empty `$replace`) switches content modification off for the pages it
    /// matches, so those are asked first.
    pub fn replace_for(
        &self,
        url: &str,
        source: &str,
        request_type: &str,
        method: &str,
    ) -> Option<Arc<Replace>> {
        let compiled = self.compiled();
        let replace = compiled.replace.as_ref()?;
        let probe = replace.probe.as_ref()?;
        let request = Request::new(url, source, request_type, method).ok()?;
        let result = probe.check_network_request(&request);
        let rule = replace
            .rules
            .get(replace_redirect_index(result.redirect.as_deref()?)?)?
            .clone();
        if let Some(veto) = replace.veto.as_ref() {
            // The exceptions name *pages*, so a subresource is asked about the
            // document it came from. `other` keeps the crate from reading a
            // path-scoped pattern as "not a document": a page URL is the only
            // URL the rule is about, whatever the request type is.
            let page = if request_type == "document" || source.is_empty() {
                url
            } else {
                source
            };
            if let Ok(request) = Request::new(page, page, "other", "GET") {
                if veto.check_network_request(&request).should_block() {
                    return None;
                }
            }
        }
        Some(rule)
    }

    pub fn clear_cache(&self) {
        self.cache.write().unwrap().clear();
    }

    fn compiled(&self) -> Arc<Compiled> {
        let guard = self.inner.read().unwrap();
        guard.clone()
    }
}

#[inline]
fn normalise_host(host: &str) -> &str {
    host.trim().trim_end_matches('.')
}

/// A URL no filter list can target: asked about it, the engine answers with
/// exactly the rules that are not bound to a hostname, which is what
/// `$specifichide` keeps.
const GENERIC_ONLY_URL: &str = "https://adfree.invalid/";

/// The exception rules read out of the list text, before the engine's own
/// (host-only) parse throws them away.
///
/// `$badfilter` cancels the rule it mirrors, so additions and cancellations are
/// collected as exact `(host, switches)` pairs and matched at the end: a cancel
/// works whichever list the rule it cancels sits in, and whichever order the
/// two were read.
#[derive(Default)]
struct CosmeticExceptionScan {
    adds: HashSet<(String, CosmeticSwitches)>,
    cancels: HashSet<(String, CosmeticSwitches)>,
}

impl CosmeticExceptionScan {
    /// Folds the surviving rules into a host-keyed map.
    fn resolve(&self) -> HashMap<String, CosmeticSwitches> {
        let mut out: HashMap<String, CosmeticSwitches> = HashMap::new();
        for (host, switches) in &self.adds {
            if self.cancels.contains(&(host.clone(), *switches)) {
                continue;
            }
            out.entry(host.clone()).or_default().merge(*switches);
        }
        out
    }
}

/// Collects the exceptions that switch cosmetic work off, keyed by hostname.
///
/// The engine rejects rules carrying `$elemhide`, `$specifichide` or
/// `$jsinject` (it only implements `$generichide`), and a `$document`
/// exception implies those three — so a list asking for a site to be left
/// alone would otherwise keep getting it hidden.
///
/// Only `@@` rules with a plain `||host^` pattern count: rules with a path, a
/// wildcard or a `$domain=` constraint scope the exception more finely than a
/// hostname can express, and applying those too widely would hide *less* than
/// the list asked for — they are skipped instead.
fn scan_cosmetic_exceptions(text: &str, into: &mut CosmeticExceptionScan) {
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("@@") else {
            continue;
        };
        let Some((pattern, options)) = split_rule_options(rest) else {
            continue;
        };
        let mut switches = CosmeticSwitches::default();
        let mut scoped = false;
        let mut cancel = false;
        for option in options.split(',') {
            match option.trim() {
                "elemhide" | "ehide" => switches.elemhide = true,
                "specifichide" | "shide" => switches.specifichide = true,
                "jsinject" => switches.jsinject = true,
                // `$urlblock` stops the page's own requests from being blocked
                // by network rules; the MITM path reads it off the referrer.
                "urlblock" => switches.urlblock = true,
                // `$document` unblocks the whole site; AdGuard spells it out
                // as `$elemhide` + `$urlblock` + `$jsinject` (+ modifiers this
                // app applies elsewhere).
                "document" | "doc" => {
                    switches.elemhide = true;
                    switches.specifichide = true;
                    switches.jsinject = true;
                    switches.urlblock = true;
                }
                "badfilter" => cancel = true,
                option if option.starts_with("domain=") => scoped = true,
                // `~`-negations and every other modifier change nothing here.
                _ => {}
            }
        }
        if scoped || switches == CosmeticSwitches::default() {
            continue;
        }
        if let Some(host) = exception_host(pattern) {
            let pair = (host, switches);
            if cancel {
                into.cancels.insert(pair);
            } else {
                into.adds.insert(pair);
            }
        }
    }
}

/// Splits `pattern$opt,opt` at the first `$` that is not backslash-escaped.
fn split_rule_options(rule: &str) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (idx, ch) in rule.char_indices() {
        if ch == '$' && !escaped {
            return Some((&rule[..idx], &rule[idx + 1..]));
        }
        escaped = ch == '\\' && !escaped;
    }
    None
}

/// The hostname a `||host^` pattern names; `None` for anything else (regex,
/// wildcard, path, port), which a hostname-keyed switch cannot represent.
fn exception_host(pattern: &str) -> Option<String> {
    let rest = pattern.strip_prefix("||")?;
    let mut end = rest.len();
    for (idx, ch) in rest.char_indices() {
        match ch {
            '^' => {
                end = idx;
                break;
            }
            // A path makes the rule narrower than its hostname.
            '/' => return None,
            _ if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' => {}
            _ => return None,
        }
    }
    let host = rest[..end].trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// The host of a URL, without scheme, port or path.
pub(crate) fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let host = &rest[..end];
    host.split(':').next().unwrap_or(host)
}

/// The switches `host` inherits from the engine's exception rules. `||host^`
/// covers everything below the host, so the page host is walked suffix by
/// suffix and every hit folds in.
fn switches_for(compiled: &Compiled, host: &str) -> CosmeticSwitches {
    if compiled.cosmetic_switches.is_empty() {
        return CosmeticSwitches::default();
    }
    let host = normalise_host(host).to_ascii_lowercase();
    let mut switches = CosmeticSwitches::default();
    let mut rest = host.as_str();
    loop {
        if let Some(found) = compiled.cosmetic_switches.get(rest) {
            switches.merge(*found);
        }
        match rest.split_once('.') {
            Some((_, tail)) => rest = tail,
            None => break,
        }
    }
    switches
}

/// Rewrites AdGuard-only cosmetic syntax into the uBO/ABP forms the engine
/// understands, line for line (so source-map line numbers stay aligned):
///
/// * `#%#//scriptlet(args)` / `#@%#//scriptlet(args)` → `##+js(args)` / `#@#+js(args)`
/// * `#$#sel { css }` / `#@$#sel { css }` → `##sel { css }` / `#@#sel { css }`
/// * `#$?#` / `#@$?#` (extended style) → `#?#` / `#@?#`
///
/// Anything else (`#%#` raw JS, `##^`, `$$`) is left untouched: the engine
/// drops what it cannot parse, and a wrong rewrite would be worse than a
/// dropped rule.
fn convert_adguard_cosmetics(text: String) -> String {
    if !text.contains("#%#") && !text.contains("#$#") {
        return text;
    }
    let mut out = String::with_capacity(text.len() + 64);
    for line in text.lines() {
        convert_adguard_line(line, &mut out);
        out.push('\n');
    }
    out
}

fn convert_adguard_line(line: &str, out: &mut String) {
    // Scriptlets first: their args may contain `#$#`-looking text.
    for (from, to) in [("#@%#//scriptlet(", "#@#+js("), ("#%#//scriptlet(", "##+js(")] {
        if let Some(pos) = line.find(from) {
            out.push_str(&line[..pos]);
            out.push_str(to);
            out.push_str(&line[pos + from.len()..]);
            return;
        }
    }
    // Longer markers first: `#@$?#` must not be matched as `#@$#`.
    for (from, to) in [("#@$?#", "#@?#"), ("#$?#", "#?#"), ("#@$#", "#@#"), ("#$#", "##")] {
        if let Some(pos) = line.find(from) {
            out.push_str(&line[..pos]);
            out.push_str(to);
            out.push_str(&line[pos + from.len()..]);
            return;
        }
    }
    out.push_str(line);
}

/// Where a `$replace` rule's index rides.
///
/// The probe engine answers a match with a `$redirect` to
/// `adfree-replace-<index>`, whose resource body *is* that index: the crate
/// hands the body back in `BlockerResult::redirect`, which is how the payload
/// that matched is found again.
const REPLACE_RESOURCE_PREFIX: &str = "adfree-replace-";

/// Modifiers a `$replace` rule may carry and the crate implements exactly.
///
/// They go into the probe rule untouched, so the probe matches the rule the
/// way the list meant it. Everything else — `app=`, `badfilter`, another
/// modifier the crate refuses — sends the whole rule to
/// [`ReplaceEngine::dropped`]: matching it without that option would apply it
/// wider than the list asked for.
const KEPT_OPTIONS: &[&str] = &[
    "domain",
    "from",
    "to",
    "important",
    "match-case",
    "third-party",
    "3p",
    "first-party",
    "1p",
    "document",
    "doc",
    "image",
    "media",
    "object",
    "object-subrequest",
    "other",
    "ping",
    "beacon",
    "script",
    "stylesheet",
    "css",
    "subdocument",
    "frame",
    "xmlhttprequest",
    "xhr",
    "websocket",
    "font",
    "all",
    "method",
];

/// The `$replace` and content-exception rules one list carries.
#[derive(Default)]
struct ReplaceScan {
    /// Probe rules: the original rule with `$replace` swapped for a `$redirect`
    /// to the resource carrying the rule's index.
    probe: Vec<String>,
    /// Payloads, index-matched with `probe`.
    payloads: Vec<String>,
    /// Rules that switch content modification off, as plain blocking rules.
    veto: Vec<String>,
    /// Rules left out (see [`ReplaceEngine::dropped`]).
    dropped: u32,
}

/// Reads the rules the crate drops because of the modifiers it does not
/// implement: `$replace` (the response body is rewritten instead of the
/// request being blocked) and `$content` (a page exception switching such
/// rewrites off).
///
/// The pattern half of every `$replace` rule still goes to the crate's own
/// matcher — as a `$redirect` to a resource carrying the rule's index — so
/// `domain=`, the type options, `important` and the exceptions keep the
/// meaning the list gave them.
fn scan_replace_rules(text: &str, scan: &mut ReplaceScan) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['!', '[', '#']) {
            continue;
        }
        let exception = line.starts_with("@@");
        let rule = line.strip_prefix("@@").unwrap_or(line);
        let Some((pattern, tokens)) = split_rule(rule) else {
            continue;
        };
        let replace = tokens.iter().copied().find(|token| is_replace_token(token));
        let content = tokens.contains(&"content");

        let mut kept: Vec<&str> = Vec::new();
        let mut faithful = true;
        for token in &tokens {
            let bare = token.trim_start_matches('~');
            let name = bare.split('=').next().unwrap_or(bare);
            if name.is_empty() || matches!(name, "replace" | "content" | "_" | "__" | "___") {
                continue;
            }
            if KEPT_OPTIONS.contains(&name) {
                kept.push(token);
            } else {
                faithful = false;
            }
        }
        if !faithful {
            scan.dropped += 1;
            continue;
        }

        let payload = replace
            .map(|token| token.strip_prefix("replace=").unwrap_or(""))
            .unwrap_or_default();
        if content || (replace.is_some() && payload.is_empty()) {
            // Both say "do not modify the response here", and only an
            // exception can say it.
            if exception {
                scan.veto.push(probe_line(pattern, &kept, None));
            } else {
                scan.dropped += 1;
            }
            continue;
        }
        if exception {
            // `@@...$replace=/X/Y/` cancels the rules carrying that payload
            // only; no list in the catalogue writes the form.
            scan.dropped += 1;
            continue;
        }
        scan.probe
            .push(probe_line(pattern, &kept, Some(scan.probe.len())));
        scan.payloads.push(payload.to_string());
    }
}

/// Splits `pattern$option,option,...` at the `$` that starts the modifier
/// list.
///
/// The pattern itself may contain a `$`, so the split is the first `$` after
/// which a `$replace` or `$content` option shows up.
fn split_rule(text: &str) -> Option<(&str, Vec<&str>)> {
    let mut search = 0;
    while let Some(offset) = text[search..].find('$') {
        let index = search + offset;
        let pattern = &text[..index];
        let tokens = split_options(&text[index + 1..]);
        if !pattern.is_empty()
            && tokens
                .iter()
                .any(|token| is_replace_token(token) || *token == "content")
        {
            return Some((pattern, tokens));
        }
        search = index + 1;
    }
    None
}

/// Splits an option list on commas, keeping a `replace=` payload whole.
///
/// The payload is `/regexp/replacement/`, and a quarter of the real rules
/// contain commas of their own — while the option list around it is
/// comma-separated. The two unescaped slashes after the value's opening one
/// are what says where it ends, exactly like AdGuard's own parser.
fn split_options(options: &str) -> Vec<&str> {
    let bytes = options.as_bytes();
    let mut tokens = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    // Inside a `replace=/…` value: how many of its slashes have been seen.
    let mut payload_slashes: Option<u32> = None;
    while index < bytes.len() {
        if index == start && options[start..].starts_with("replace=/") {
            payload_slashes = Some(0);
            index = start + "replace=/".len();
            continue;
        }
        let byte = bytes[index];
        if byte == b'\\' && index + 1 < bytes.len() {
            index += 2;
            continue;
        }
        if let Some(slashes) = payload_slashes.as_mut() {
            if byte == b'/' {
                *slashes += 1;
                if *slashes == 2 {
                    payload_slashes = None;
                }
            }
            index += 1;
            continue;
        }
        if byte == b',' {
            tokens.push(&options[start..index]);
            start = index + 1;
            index = start;
            continue;
        }
        index += 1;
    }
    tokens.push(&options[start..]);
    tokens
}

fn is_replace_token(token: &str) -> bool {
    token == "replace" || token.starts_with("replace=")
}

/// The rule the crate is actually given: the pattern, the options the crate
/// understands, and — for the probe engine — the redirect that names the
/// rule's index.
fn probe_line(pattern: &str, options: &[&str], index: Option<usize>) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(options.len() + 1);
    if let Some(index) = index {
        parts.push(format!("{REPLACE_RESOURCE_PREFIX}{index}"));
        parts[0].insert_str(0, "redirect=");
    }
    parts.extend(options.iter().map(|option| (*option).to_string()));
    if parts.is_empty() {
        return pattern.to_string();
    }
    format!("{pattern}${}", parts.join(","))
}

/// Builds the engines a list's `$replace` rules need, or `None` when the
/// loaded lists carry none.
fn build_replace(scan: ReplaceScan) -> Option<ReplaceEngine> {
    let rules: Vec<Arc<Replace>> = scan
        .payloads
        .iter()
        .map(|payload| Arc::new(Replace::parse(payload)))
        .collect();
    let veto_rules = scan.veto.len() as u32;
    let probe = (!scan.probe.is_empty()).then(|| {
        let mut set = FilterSet::new(false);
        set.add_filter_list(scan.probe.join("\n"), ParseOptions::default());
        let mut engine = Engine::new_with_filter_set(set);
        // One resource per rule. The body is the rule's index: the only thing
        // that has to survive the crate's redirect handling.
        engine.use_resources((0..scan.probe.len()).map(|index| Resource {
            name: format!("{REPLACE_RESOURCE_PREFIX}{index}"),
            aliases: Vec::new(),
            kind: ResourceType::Mime(MimeType::TextPlain),
            content: BASE64.encode(index.to_string()),
            dependencies: Vec::new(),
            permission: Default::default(),
        }));
        engine
    });
    let veto = (!scan.veto.is_empty()).then(|| {
        let mut set = FilterSet::new(false);
        set.add_filter_list(scan.veto.join("\n"), ParseOptions::default());
        Engine::new_with_filter_set(set)
    });
    if probe.is_none() && veto.is_none() {
        return None;
    }
    Some(ReplaceEngine {
        probe,
        rules,
        veto,
        veto_rules,
        dropped: scan.dropped,
    })
}

/// The rule index a probe resource handed back, out of the `data:` URL the
/// crate wraps a redirect body in.
fn replace_redirect_index(data_url: &str) -> Option<usize> {
    let (_, encoded) = data_url.strip_prefix("data:")?.split_once(',')?;
    let bytes = BASE64.decode(encoded).ok()?;
    std::str::from_utf8(&bytes).ok()?.parse().ok()
}

/// Number of rule-looking lines in a list. The `adblock` engine does not expose
/// per-source counts, and counting real lines is both cheap and honest enough
/// for the UI ("rules loaded").
fn count_rules(text: &str) -> u64 {
    text.lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('!') && !t.starts_with('[') && !t.starts_with('#')
        })
        .count() as u64
}

/// Runs one host through the adblock engine.
fn evaluate(compiled: &Compiled, host: &str) -> HostVerdict {
    let url = format!("https://{}/", host);
    let request = match Request::new(&url, "https://localhost/", "xmlhttprequest", "") {
        Ok(r) => r,
        Err(_) => return HostVerdict::default(),
    };
    let result = compiled.engine.check_network_request(&request);
    if !result.should_block() {
        return HostVerdict::default();
    }

    let (rule_text, list_name, category) = matched_details(compiled, &result, host);
    HostVerdict {
        blocked: true,
        rule_text,
        list_name,
        category,
        // A `$redirect` rule blocks *and* answers: the DNS layer must step
        // aside for it, and only a registered resource counts.
        redirect: result.redirect.is_some(),
    }
}

/// The rule, list and category behind a match, for the log and the UI.
fn matched_details(
    compiled: &Compiled,
    result: &adblock::blocker::BlockerResult,
    host: &str,
) -> (Option<String>, Option<String>, u8) {
    let (rule_text, source) = match &result.filter {
        Some(info) => (
            info.raw_line.clone(),
            info.source_location.as_ref().map(|loc| loc.source_index),
        ),
        None => (None, None),
    };
    let list = source
        .and_then(|idx| compiled.sources.iter().find(|s| s.source_index == idx))
        .cloned();

    let category = list
        .as_ref()
        .map(|l| l.category)
        .unwrap_or_else(|| categorise(rule_text.as_deref(), host));
    (rule_text, list.map(|l| l.name), category)
}

/// Best-effort category for a block whose owning list has none.
fn categorise(rule: Option<&str>, host: &str) -> u8 {
    let haystack = format!(
        "{} {}",
        rule.unwrap_or_default().to_ascii_lowercase(),
        host.to_ascii_lowercase()
    );
    if haystack.contains("analytic")
        || haystack.contains("telemetry")
        || haystack.contains("metrics")
        || haystack.contains("measurement")
    {
        CAT_ANALYTICS
    } else if haystack.contains("track") || haystack.contains("pixel") || haystack.contains("beacon") {
        CAT_TRACKER
    } else if haystack.contains("social") || haystack.contains("facebook") || haystack.contains("twitter") {
        CAT_SOCIAL
    } else if haystack.contains("malware")
        || haystack.contains("phish")
        || haystack.contains("scam")
        || haystack.contains("spam")
    {
        CAT_MALWARE
    } else {
        CAT_AD
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    fn temp_list(name: &str, body: &str, format: ListFormat, id: u16) -> FilterListInfo {
        let dir = std::env::temp_dir().join("adfree-filter-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        FilterListInfo {
            id,
            name: name.to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format,
            category: CAT_AD,
            rule_count: 0,
            last_error: None,
        }
    }

    fn default_lists() -> Vec<FilterListInfo> {
        vec![
            temp_list(
                "base.txt",
                "! Title: AdFree test list\n\
                 [Adblock Plus 2.0]\n\
                 ||doubleclick.net^\n\
                 ||ads.example.com^\n\
                 @@||safe.example.com^\n\
                 ||tracker.test^\n",
                ListFormat::Standard,
                1,
            ),
            temp_list(
                "hosts.txt",
                "0.0.0.0 ha.ge.zi\n127.0.0.1 block.me\n",
                ListFormat::Hosts,
                2,
            ),
        ]
    }

    fn engine(lists: Vec<FilterListInfo>) -> FilterEngine {
        let fe = FilterEngine::new();
        fe.rebuild(&lists, &[]);
        fe
    }

    #[test]
    fn blocks_domain_and_subdomains() {
        let fe = engine(default_lists());
        assert!(fe.check_host("doubleclick.net").blocked);
        assert!(fe.check_host("googleads.g.doubleclick.net").blocked);
        assert!(fe.check_host("ads.example.com").blocked);
    }

    #[test]
    fn honours_exceptions() {
        let fe = engine(default_lists());
        assert!(!fe.check_host("safe.example.com").blocked);
        assert!(!fe.check_host("deep.sub.safe.example.com").blocked);
    }

    #[test]
    fn parses_hosts_syntax() {
        let fe = engine(default_lists());
        assert!(fe.check_host("block.me").blocked);
        assert!(fe.check_host("a.b.block.me").blocked);
        assert!(!fe.check_host("other.net").blocked);
    }

    #[test]
    fn detailed_lookup_reports_rule_and_list() {
        let fe = engine(default_lists());
        let v = fe.check_host_detailed("googleads.g.doubleclick.net");
        assert!(v.blocked);
        assert_eq!(v.rule_text.as_deref(), Some("||doubleclick.net^"));
        assert_eq!(v.list_name.as_deref(), Some("base.txt"));
    }

    #[test]
    fn regex_rules_match() {
        let fe = engine(vec![temp_list(
            "regex.txt",
            "/adserver-[0-9]+\\./\n",
            ListFormat::Standard,
            3,
        )]);
        assert!(fe.check_host("adserver-42.net").blocked);
        assert!(!fe.check_host("example.net").blocked);
    }

    #[test]
    fn user_rules_are_applied() {
        let fe = FilterEngine::new();
        fe.rebuild(&default_lists(), &["||my-block.test^".to_string()]);
        assert!(fe.check_host("my-block.test").blocked);
        assert!(fe.check_host("x.my-block.test").blocked);
    }

    #[test]
    fn url_scoped_rules_need_the_whole_request() {
        let fe = cosmetic_engine("||shop.test/ads/tracker.js$script\n");
        // The host itself is clean: the rule is narrower than a hostname, so
        // the DNS layer must not touch it.
        assert!(!fe.check_host("shop.test").blocked);
        let hit = fe.check_url(
            "https://shop.test/ads/tracker.js",
            "https://shop.test/",
            "script",
            "GET",
        );
        assert!(hit.blocked, "{hit:?}");
        assert_eq!(
            hit.rule_text.as_deref(),
            Some("||shop.test/ads/tracker.js$script")
        );
        // Same URL, another request type: `$script` must not match an image.
        assert!(
            !fe.check_url(
                "https://shop.test/ads/tracker.js",
                "https://shop.test/",
                "image",
                "GET"
            )
            .blocked
        );
        // Same host, another path.
        assert!(
            !fe.check_url("https://shop.test/app.js", "https://shop.test/", "script", "GET").blocked
        );
        // The source decides third-party rules, and it is the referrer.
        let fe = cosmetic_engine("||cdn.test^$third-party\n");
        assert!(
            fe.check_url("https://cdn.test/x.js", "https://shop.test/", "script", "GET")
                .blocked
        );
        assert!(
            !fe.check_url("https://cdn.test/x.js", "https://cdn.test/", "script", "GET").blocked
        );
    }

    #[test]
    fn removeparam_rewrites_the_forwarded_url() {
        let fe = cosmetic_engine("||shop.test/api$removeparam=secret\n");
        let v = fe.check_url(
            "https://shop.test/api?secret=1&keep=2",
            "https://shop.test/",
            "xmlhttprequest",
            "GET",
        );
        assert!(!v.blocked, "{v:?}");
        assert_eq!(
            v.rewritten_url.as_deref(),
            Some("https://shop.test/api?keep=2")
        );
        // Nothing to drop: the URL is left exactly as it was.
        let v = fe.check_url(
            "https://shop.test/api?keep=2",
            "https://shop.test/",
            "xmlhttprequest",
            "GET",
        );
        assert_eq!(v.rewritten_url, None);
    }

    /// Whether any `$replace` rule covers a request, the way the HTTPS path
    /// asks about it.
    fn rewrites(fe: &FilterEngine, url: &str, source: &str, kind: &str) -> bool {
        fe.replace_for(url, source, kind, "GET").is_some()
    }

    /// The `$replace` rule covering one of this file's script URLs.
    fn replace_rule(fe: &FilterEngine, url: &str) -> Arc<Replace> {
        fe.replace_for(url, "https://page.test/", "script", "GET")
            .unwrap_or_else(|| panic!("no rule covers {url}"))
    }

    #[test]
    fn replace_rules_rewrite_instead_of_blocking() {
        let fe = cosmetic_engine(
            "||shop.test/ad.js$replace=/banner/advert/\n\
             ||shop.test/other.js\n",
        );
        assert!(fe.has_replace());
        assert_eq!(fe.replace_rules(), 1);
        // The crate drops a rule it cannot implement, so nothing about the URL
        // looks blocked to the caller: the body is what gets edited.
        let v = fe.check_url(
            "https://shop.test/ad.js",
            "https://shop.test/",
            "script",
            "GET",
        );
        assert!(!v.blocked, "{v:?}");
        let rule = replace_rule(&fe, "https://shop.test/ad.js");
        assert_eq!(rule.payload(), "/banner/advert/");
        assert!(rule.runs());
        assert_eq!(
            rule.apply(b"a banner here").as_deref(),
            Some(&b"a advert here"[..])
        );
        // No match means no rewrite: the caller hands the origin's bytes over
        // with the length it declared.
        assert_eq!(rule.apply(b"nothing to see"), None);
        // A URL the rule does not name is left to the blocking rules.
        let v = fe.check_url(
            "https://shop.test/other.js",
            "https://shop.test/",
            "script",
            "GET",
        );
        assert!(v.blocked, "{v:?}");
        let (url, page) = ("https://shop.test/other.js", "https://shop.test/");
        assert!(!rewrites(&fe, url, page, "script"));
    }

    #[test]
    fn replace_payloads_survive_commas_and_escapes() {
        // A real payload is full of commas of its own — a quantifier, a
        // character class — inside an option list that is comma-separated.
        // The slashes after the value's opening one are what says where the
        // value ends, exactly like AdGuard's own parser.
        let fe = cosmetic_engine(
            r"||shop.test/a.js$script,replace=/\d{1,3}\.(\d+)/v$1/i
||shop.test/b.js$replace=/(a\,b)/[$1]/
||shop.test/c.js$replace=/(<item>){2\,3}/G/
||shop.test/d.js$replace=/a\/b/H/
",
        );
        assert_eq!(fe.replace_rules(), 4);
        let rule = replace_rule(&fe, "https://shop.test/a.js");
        assert_eq!(rule.payload(), r"/\d{1,3}\.(\d+)/v$1/i");
        assert_eq!(
            rule.apply(b"123.45 and 7.8").as_deref(),
            Some(&b"v45 and v8"[..])
        );
        // A `\,` keeps the comma from ending the option list and reads as a
        // plain comma to the regexp engine.
        let rule = replace_rule(&fe, "https://shop.test/b.js");
        assert_eq!(rule.payload(), r"/(a\,b)/[$1]/");
        assert_eq!(rule.apply(b"a,b").as_deref(), Some(&b"[a,b]"[..]));
        // `\,` inside a quantifier is the list's way of hiding the comma from
        // its own option list: the regexp wants a plain `{2,3}`.
        let rule = replace_rule(&fe, "https://shop.test/c.js");
        assert_eq!(rule.payload(), r"/(<item>){2\,3}/G/");
        assert_eq!(rule.apply(b"<item><item>Z").as_deref(), Some(&b"GZ"[..]));
        assert_eq!(rule.apply(b"<item>Z"), None);
        // `\/` is the separator's escape, and the regexp engine reads it as
        // the slash the list means.
        let rule = replace_rule(&fe, "https://shop.test/d.js");
        assert_eq!(rule.apply(b"a/ba/b").as_deref(), Some(&b"HH"[..]));
    }

    #[test]
    fn replace_rules_honour_their_scoping() {
        // `domain=` names the page the subresource was loaded from, and the
        // type option names the kind of subresource: both are the crate's own
        // matcher, kept whole by the probe line.
        let (url, page) = ("https://cdn.test/ad.js", "https://page.test/");
        let fe = cosmetic_engine("||cdn.test/ad.js$replace=/x/y/,domain=page.test\n");
        assert!(rewrites(&fe, url, page, "script"));
        assert!(!rewrites(&fe, url, "https://other.test/", "script"));

        let fe = cosmetic_engine("||cdn.test/ad.js$replace=/x/y/,script\n");
        assert!(rewrites(&fe, url, page, "script"));
        assert!(!rewrites(&fe, url, page, "xmlhttprequest"));

        // A rule the blocking engine would answer for a different URL is not
        // dragged in: the probe matches on the same pattern.
        let fe = cosmetic_engine("||cdn.test/ad.js$replace=/x/y/\n");
        assert!(!rewrites(&fe, "https://cdn.test/other.js", page, "script"));
    }

    #[test]
    fn page_exceptions_switch_replace_off() {
        // Both spellings say "do not modify the responses of this page", and
        // the question is asked about the page, not the subresource.
        let url = "https://cdn.test/ad.js";
        let quiet = "https://quiet.test/";
        let loud = "https://loud.test/";
        for exception in ["@@||quiet.test^$content\n", "@@||quiet.test^$replace\n"] {
            let fe = cosmetic_engine(&format!("||cdn.test/ad.js$replace=/x/y/\n{exception}"));
            assert!(!rewrites(&fe, url, quiet, "script"), "{exception}");
            assert!(rewrites(&fe, url, loud, "script"), "{exception}");
        }
        // A page named by a path pattern is the only page it covers.
        let fe = cosmetic_engine(
            "||cdn.test/ad.js$replace=/x/y/\n\
             @@||quiet.test/one^$content\n",
        );
        let one = "https://quiet.test/one/page.html";
        let two = "https://quiet.test/two/page.html";
        assert!(!rewrites(&fe, url, one, "script"));
        assert!(rewrites(&fe, url, two, "script"));
    }

    #[test]
    fn replace_rules_the_crate_cannot_keep_are_dropped() {
        // `@@…$replace=/…/…/` cancels the rules carrying that payload. Telling
        // which ones those are means reading every payload twice; no list in
        // the catalogue writes the form, so the exception is dropped instead —
        // which leaves the rule it names in place (a known deviation).
        let (url, page) = ("https://cdn.test/ad.js", "https://page.test/");
        let fe = cosmetic_engine(
            "||cdn.test/ad.js$replace=/x/y/\n\
             @@||cdn.test/ad.js$replace=/x/y/\n",
        );
        assert!(rewrites(&fe, url, page, "script"));

        // An option the crate does not implement changes what a rule means:
        // keeping the pattern anyway would over-apply it to every response.
        let fe = cosmetic_engine("||cdn.test/ad.js$replace=/x/y/,csp=script-src 'none'\n");
        assert!(!fe.has_replace());
        assert_eq!(fe.replace_rules(), 0);
        assert!(!rewrites(&fe, url, page, "script"));
        // A blocking `$content` rule is just as unreadable: the modifier only
        // means something on an exception.
        let fe = cosmetic_engine("||cdn.test/ad.js$content\n");
        assert!(!fe.has_replace());
    }

    #[test]
    fn unreadable_replace_payloads_never_rewrite() {
        // The regexp crate has no lookbehind. The rule is still counted — the
        // list asked for it — but its body passes through untouched.
        let fe = cosmetic_engine("||cdn.test/ad.js$replace=/(?<=x)y/z/\n");
        assert!(fe.has_replace());
        assert_eq!(fe.replace_rules(), 1);
        let rule = replace_rule(&fe, "https://cdn.test/ad.js");
        assert!(!rule.runs());
        assert_eq!(rule.apply(b"xy"), None);
        // A payload that is not `/regexp/replacement/` at all fares the same.
        let rule = Replace::parse("nonsense");
        assert!(!rule.runs());
        assert_eq!(rule.apply(b"nonsense"), None);
    }

    #[test]
    fn redirect_rules_are_answered_not_dropped() {
        let fe = cosmetic_engine("||shop.test/fake.js$redirect=noopjs\n");
        let v = fe.check_url(
            "https://shop.test/fake.js",
            "https://shop.test/",
            "script",
            "GET",
        );
        assert!(v.blocked, "a `$redirect` rule blocks as well: {v:?}");
        let body = v.redirect.expect("the resource is registered");
        assert!(
            body.starts_with("data:application/javascript;base64,"),
            "{body}"
        );

        // `$redirect-rule` redirects only when something else blocks, and the
        // crate reports the resource either way — the gate is ours.
        let fe = cosmetic_engine("||shop.test/fake.js$redirect-rule=noopjs\n");
        let v = fe.check_url(
            "https://shop.test/fake.js",
            "https://shop.test/",
            "script",
            "GET",
        );
        assert!(v.redirect.is_none(), "{v:?}");
        // Together with a block it fires, which is the whole point of the pair.
        let fe = cosmetic_engine(
            "||shop.test/fake.js\n\
             ||shop.test/fake.js$redirect-rule=noopjs\n",
        );
        let v = fe.check_url(
            "https://shop.test/fake.js",
            "https://shop.test/",
            "script",
            "GET",
        );
        assert!(v.blocked && v.redirect.is_some(), "{v:?}");

        // A resource this app does not carry degrades to a plain block.
        let fe = cosmetic_engine("||shop.test/fake.js$redirect=noopmp4-1s\n");
        let v = fe.check_url(
            "https://shop.test/fake.js",
            "https://shop.test/",
            "script",
            "GET",
        );
        assert!(v.blocked && v.redirect.is_none(), "{v:?}");
    }

    #[test]
    fn redirect_hosts_are_flagged_for_the_https_path() {
        let fe = cosmetic_engine("||tracker.test^$redirect=nooptext\n||plain.test^\n");
        let v = fe.check_host("tracker.test");
        assert!(v.blocked && v.redirect, "{v:?}");
        assert!(fe.check_host("sub.tracker.test").redirect);
        let v = fe.check_host("plain.test");
        assert!(v.blocked && !v.redirect, "{v:?}");
        // A resource we cannot serve is not a reason to step aside.
        let fe = cosmetic_engine("||tracker.test^$redirect=googlesyndication-adsbygoogle\n");
        assert!(!fe.check_host("tracker.test").redirect);
    }

    #[test]
    fn redirect_resources_decode_to_their_stated_shape() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let resources = redirect_resources();
        let named = |name: &str| {
            resources
                .iter()
                .find(|r| r.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"))
        };
        let decode = |name: &str| STANDARD.decode(&named(name).content).expect("base64");
        assert!(decode("noopjs").starts_with(b"(function"));
        assert_eq!(decode("noopjson"), b"{}");
        assert!(decode("noopframe").starts_with(b"<!DOCTYPE html>"));
        assert!(decode("1x1.gif").starts_with(b"GIF89a"));
        assert!(decode("nooptext").is_empty());
        // Every name and alias must be unique: the engine refuses duplicates,
        // and a resource that silently fails to load turns a redirect into a
        // hard block — exactly the breakage the table exists to avoid.
        let mut seen = std::collections::HashSet::new();
        for resource in resources {
            for ident in std::iter::once(&resource.name).chain(resource.aliases.iter()) {
                assert!(seen.insert(ident.clone()), "duplicate resource name {ident}");
            }
        }
    }

    #[test]
    fn disabled_lists_are_skipped() {
        let mut lists = default_lists();
        lists[0].enabled = false;
        let fe = engine(lists);
        assert!(!fe.check_host("doubleclick.net").blocked);
        assert!(fe.check_host("ha.ge.zi").blocked);
    }

    #[test]
    fn missing_files_do_not_panic() {
        let fe = FilterEngine::new();
        let lists = vec![FilterListInfo {
            id: 9,
            name: "Missing".into(),
            url: String::new(),
            enabled: true,
            local_path: Some(PathBuf::from("/nonexistent/list.txt")),
            format: ListFormat::Standard,
            category: CAT_AD,
            rule_count: 0,
            last_error: None,
        }];
        fe.rebuild(&lists, &[]);
        assert!(!fe.check_host("doubleclick.net").blocked);
    }

    #[test]
    fn rule_counting_ignores_metadata() {
        assert_eq!(
            count_rules("! Title: x\n[Adblock Plus 2.0]\n||a.com^\n#cosmetic\n\n||b.com^\n"),
            2
        );
    }

    #[test]
    fn cache_serves_repeat_queries() {
        let fe = engine(default_lists());
        assert!(fe.check_host("doubleclick.net").blocked);
        let t = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = fe.check_host("doubleclick.net");
        }
        let per_query = t.elapsed().as_nanos() as f64 / 10_000.0;
        // A debug build is ~20x slower than the release profile shipped in the
        // APK; the threshold below what a release build actually costs (a few
        // hundred nanoseconds) so this only catches real regressions.
        let limit = if cfg!(debug_assertions) { 30_000.0 } else { 2_000.0 };
        assert!(per_query < limit, "cached query cost {per_query}ns");
        assert!(fe.cache_hits() > 9_000);
    }

    #[test]
    fn rebuild_bumps_generation_and_memory() {
        let fe = engine(default_lists());
        let g1 = fe.generation();
        assert!(g1 > 0);
        assert!(fe.memory_bytes() > 64);
        fe.rebuild(&default_lists(), &[]);
        assert!(fe.generation() > g1);
    }

    fn cosmetic_engine(body: &str) -> FilterEngine {
        // One file per call: the tests run in parallel and each engine reads
        // the list at rebuild time.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let name = format!(
            "cosmetic-{}.txt",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        );
        let fe = FilterEngine::new();
        fe.rebuild(
            &[temp_list(&name, body, ListFormat::Standard, 3)],
            &[],
        );
        fe
    }

    #[test]
    fn embedded_scriptlet_table_is_well_formed() {
        let resources = scriptlet_resources();
        assert!(resources.len() >= 90, "only {} scriptlets", resources.len());
        assert!(resources.iter().all(|r| r.name.ends_with(".js")));
        assert!(resources.iter().all(|r| !r.content.is_empty()));
        // The AdGuard bundle names the implementation function after the rule.
        let by_name = |n: &str| resources.iter().find(|r| r.name == n);
        assert!(by_name("set-constant.js").is_some());
        assert!(by_name("abort-on-property-read.js").is_some());
    }

    #[test]
    fn cosmetic_rules_reach_the_page_payload() {
        let fe = cosmetic_engine(
            "! Title: cosmetic\n\
             example.com##.ad-box\n\
             example.com##.keep-me\n\
             example.com#@#.keep-me\n\
             example.com#$#.banner { margin: 0 }\n\
             ##.adsbygoogle\n\
             example.com#?#.late:has-text(Sponsored)\n",
        );
        let res = fe.cosmetic_resources("https://example.com/");
        assert!(
            res.hide_selectors.iter().any(|s| s == ".ad-box"),
            "{:?}",
            res.hide_selectors
        );
        assert!(
            !res.hide_selectors.iter().any(|s| s == ".keep-me"),
            "an #@# exception must win"
        );
        assert!(
            res.style_rules
                .iter()
                .any(|(s, css)| s == ".banner" && css.contains("margin")),
            "{:?}",
            res.style_rules
        );
        assert!(
            res.procedural.iter().any(|p| p.contains("has-text")),
            "{:?}",
            res.procedural
        );
        // Generic class/id rules only fire for tokens the page actually uses.
        let generic = fe.generic_selectors(&["adsbygoogle".to_string()], &[], &res.exceptions);
        assert!(generic.iter().any(|s| s == ".adsbygoogle"), "{generic:?}");
        let none = fe.generic_selectors(&["unused-token".to_string()], &[], &res.exceptions);
        assert!(none.is_empty(), "{none:?}");
    }

    #[test]
    fn hiding_selectors_come_back_in_a_stable_order() {
        // The engine stores them in a `HashSet`, so without the sort two calls
        // can differ — and the stylesheet URL hashes these bytes.
        let fe = cosmetic_engine(
            "example.com##.zebra\n\
             example.com##.alpha\n\
             example.com##.middle\n\
             other.test##.not-here\n\
             ##.adsbygoogle\n",
        );
        let first = fe.hide_selectors_for("example.com");
        let second = fe.hide_selectors_for("example.com");
        assert_eq!(first, second, "the same host must yield the same bytes");
        assert!(
            first.windows(2).all(|w| w[0] <= w[1]),
            "not sorted: {first:?}"
        );
        for selector in [".alpha", ".middle", ".zebra"] {
            assert!(first.iter().any(|s| s == selector), "{first:?}");
        }
        assert!(
            !first.iter().any(|s| s == ".not-here"),
            "another host's rule must not leak in: {first:?}"
        );
        assert!(
            fe.hide_selectors_for("nowhere.test").is_empty(),
            "a host with no hiding rules gets no stylesheet"
        );
    }

    #[test]
    fn scriptlet_rules_are_assembled_from_embedded_resources() {
        let fe = cosmetic_engine("example.com#%#//scriptlet('set-constant', 'foo', 'bar')\n");
        let res = fe.cosmetic_resources("https://example.com/");
        assert!(
            res.scriptlets.contains("setConstant(\"foo\", \"bar\")"),
            "{}",
            res.scriptlets
        );
        // The function definition is emitted alongside the invocation.
        assert!(
            res.scriptlets.contains("function setConstant()"),
            "{}",
            res.scriptlets
        );
        // A host the rule does not target gets nothing.
        assert!(fe.cosmetic_resources("https://other.test/").is_empty());
    }

    #[test]
    fn scanner_reads_only_the_host_wide_exceptions() {
        let mut scan = CosmeticExceptionScan::default();
        scan_cosmetic_exceptions(
            "! comment\n\
             @@||plain.test^$elemhide\n\
             @@||alias.test^$ehide\n\
             @@||shide.test^$shide\n\
             @@||both.test^$specifichide,ehide\n\
             @@||js.test^$jsinject\n\
             @@||doc.test^$document\n\
             @@||doc-alias.test^$doc\n\
             @@||bare.test$elemhide\n\
             @@||negated.test^$~elemhide\n\
             @@||scoped.test^$elemhide,domain=other.test\n\
             @@||path.test/some/page$elemhide\n\
             @@||wild.*^$elemhide\n\
             @@/rege?x/$elemhide\n\
             @@||cancel.test^$elemhide,badfilter\n\
             @@||ub.test^$urlblock\n\
             @@||ub.test^$urlblock,badfilter\n\
             ||block.test^$elemhide\n",
            &mut scan,
        );
        assert_eq!(
            scan.cancels.len(),
            2,
            "a `$badfilter` is a cancellation: {:?}",
            scan.cancels
        );
        let map = scan.resolve();
        let on = |host: &str| map.get(host).copied().unwrap_or_default();
        let elemhide = CosmeticSwitches {
            elemhide: true,
            ..Default::default()
        };
        assert_eq!(on("plain.test"), elemhide);
        assert_eq!(on("alias.test"), elemhide);
        assert_eq!(on("bare.test"), elemhide);
        assert_eq!(
            on("shide.test"),
            CosmeticSwitches {
                specifichide: true,
                ..Default::default()
            }
        );
        assert_eq!(
            on("both.test"),
            CosmeticSwitches {
                elemhide: true,
                specifichide: true,
                ..Default::default()
            }
        );
        assert_eq!(
            on("js.test"),
            CosmeticSwitches {
                jsinject: true,
                ..Default::default()
            }
        );
        let all = CosmeticSwitches {
            elemhide: true,
            specifichide: true,
            jsinject: true,
            urlblock: true,
        };
        assert_eq!(on("doc.test"), all);
        assert_eq!(on("doc-alias.test"), all);
        // `$urlblock` is network-side only: it stops the page's own requests
        // from being blocked without touching cosmetics.
        assert_eq!(
            on("ub.test"),
            CosmeticSwitches::default(),
            "cancelled by its own `$badfilter` pair"
        );
        // Negations, `$domain=` scoping, paths, wildcards and regexes are all
        // narrower than a hostname: skipped, never applied too widely.
        assert_eq!(map.len(), 8, "{map:?}");
    }

    #[test]
    fn elemhide_switches_every_cosmetic_rule_off() {
        let fe = cosmetic_engine(
            "shop.test##.ad-box\n\
             ##div[data-ad]\n\
             shop.test#%#//scriptlet('set-constant', 'foo', 'bar')\n\
             @@||shop.test^$elemhide\n",
        );
        let res = fe.cosmetic_resources("https://shop.test/");
        assert!(res.hide_selectors.is_empty(), "{:?}", res.hide_selectors);
        assert!(res.style_rules.is_empty(), "{:?}", res.style_rules);
        assert!(res.procedural.is_empty(), "{:?}", res.procedural);
        assert!(res.generichide, "the class/id lookup must be off too");
        assert!(
            res.scriptlets.contains("setConstant"),
            "`$elemhide` is not `$jsinject`: {}",
            res.scriptlets
        );
        // `||host^` covers subdomains...
        let sub = fe.cosmetic_resources("https://www.shop.test/");
        assert!(
            sub.hide_selectors.is_empty(),
            "a subdomain inherits the exception: {:?}",
            sub.hide_selectors
        );
        // ...and nothing else.
        let other = fe.cosmetic_resources("https://other.test/");
        assert!(
            other.hide_selectors.iter().any(|s| s == "div[data-ad]"),
            "generic rules must still reach other hosts: {:?}",
            other.hide_selectors
        );
    }

    #[test]
    fn specifichide_keeps_only_the_generic_half() {
        let body = "quiet.test##.banner\n\
                    ##div[data-ad]\n\
                    quiet.test#?#.late:has-text(Sponsored)\n\
                    quiet.test#%#//scriptlet('set-constant', 'foo', 'bar')\n";
        let before = cosmetic_engine(body);
        let res = before.cosmetic_resources("https://quiet.test/");
        assert!(
            res.hide_selectors.iter().any(|s| s == ".banner"),
            "the specific rule applies while nothing excepts it: {:?}",
            res.hide_selectors
        );
        assert!(!res.procedural.is_empty() && !res.scriptlets.is_empty());

        let after = cosmetic_engine(&format!("{body}@@||quiet.test^$specifichide\n"));
        let res = after.cosmetic_resources("https://quiet.test/");
        assert_eq!(
            res.hide_selectors,
            vec!["div[data-ad]".to_string()],
            "only the generic selector stays"
        );
        assert!(res.procedural.is_empty(), "procedural rules are hostname-bound");
        assert!(res.scriptlets.is_empty(), "scriptlets are hostname-bound");
        assert!(!res.generichide, "the class/id lookup still runs");
    }

    #[test]
    fn jsinject_and_document_exceptions_switch_their_own_parts() {
        let fe = cosmetic_engine(
            "passive.test##.banner\n\
             passive.test#%#//scriptlet('set-constant', 'foo', 'bar')\n\
             @@||passive.test^$jsinject\n\
             dead.test##.banner\n\
             dead.test#%#//scriptlet('set-constant', 'foo', 'bar')\n\
             @@||dead.test^$document\n",
        );
        let passive = fe.cosmetic_resources("https://passive.test/");
        assert!(
            passive.hide_selectors.iter().any(|s| s == ".banner"),
            "$jsinject must not touch hiding: {:?}",
            passive.hide_selectors
        );
        assert!(passive.scriptlets.is_empty(), "$jsinject must drop scriptlets");
        assert!(!passive.generichide);

        let dead = fe.cosmetic_resources("https://dead.test/");
        assert!(dead.is_empty(), "$document leaves nothing to inject: {dead:?}");
        assert!(dead.generichide, "$document covers the generic half too");
    }

    #[test]
    fn a_user_rule_can_switch_cosmetics_off() {
        let fe = FilterEngine::new();
        fe.rebuild(&[], &["@@||news.test^$elemhide".to_string()]);
        assert_eq!(
            fe.cosmetic_switches_for("sub.news.test"),
            CosmeticSwitches {
                elemhide: true,
                ..Default::default()
            }
        );
        assert_eq!(
            fe.cosmetic_switches_for("other.test"),
            CosmeticSwitches::default()
        );
    }

    #[test]
    fn badfilter_cancels_the_rule_it_mirrors() {
        let fe = cosmetic_engine(
            "cancel.test##.ad-box\n\
             @@||cancel.test^$elemhide\n\
             @@||cancel.test^$elemhide,badfilter\n",
        );
        let res = fe.cosmetic_resources("https://cancel.test/");
        assert!(
            res.hide_selectors.iter().any(|s| s == ".ad-box"),
            "`$badfilter` cancels the exception: {:?}",
            res.hide_selectors
        );
        assert!(!res.generichide);

        // A cancellation only matches the rule it mirrors.
        let fe = cosmetic_engine(
            "kept.test##.ad-box\n\
             @@||kept.test^$elemhide\n\
             @@||kept.test^$jsinject,badfilter\n",
        );
        let res = fe.cosmetic_resources("https://kept.test/");
        assert!(
            res.hide_selectors.is_empty(),
            "the `$elemhide` rule stands: {:?}",
            res.hide_selectors
        );
        assert!(res.generichide);
    }
}

