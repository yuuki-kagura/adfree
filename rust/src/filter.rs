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
use crate::jsonprune::{JsonPrune, JsonpruneRule};
use crate::pathmask;
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
use std::sync::{Arc, Mutex, OnceLock, RwLock};

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
/// How many `$path` subsets keep their side engine. A page usually matches
/// none, and the pages that match one are the ones their rules were written
/// for: a handful is every path a session realistically visits.
const PATH_ENGINE_CACHE: usize = 32;

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
    /// The modifiers the crate refuses (`$urltransform`, the `$removeparam`
    /// shapes it does not implement, and the response-header ones: `$csp`,
    /// `$permissions`, `$removeheader`), found by [`scan_modifier_rules`].
    /// `None` when no loaded list carries one.
    modifier_rules: Option<ModifierRules>,
    /// The `$cookie` rules, found by [`scan_modifier_rules`] too. `None` when
    /// no loaded list carries one.
    cookie_rules: Option<CookieRules>,
    /// The cosmetic rules pinned to page paths (`[$path=…]`), found by
    /// [`convert_adguard_cosmetics`]. `None` when no loaded list carries one.
    path_cosmetics: Option<PathCosmetics>,
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
                modifier_rules: None,
                cookie_rules: None,
                path_cosmetics: None,
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
        let mut url_scan = ModifierScan::default();
        let mut path_scan = PathScan::default();

        for list in lists.iter().filter(|l| l.enabled) {
            let Some(path) = &list.local_path else {
                continue;
            };
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
                                scan_modifier_rules(&text, &mut url_scan);
                                convert_adguard_cosmetics(text, &mut path_scan)
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
            scan_modifier_rules(&joined, &mut url_scan);
            let record = set.add_filter_list(
                convert_adguard_cosmetics(joined, &mut path_scan),
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
        let (modifier_rules, cookie_rules) = build_modifier_rules(url_scan);
        if let Some(rules) = modifier_rules.as_ref() {
            let url = rules
                .rules
                .iter()
                .filter(|rule| rule.family.is_url())
                .count();
            let jsonprune = rules
                .rules
                .iter()
                .filter(|rule| rule.family == ModifierFamily::Jsonprune)
                .count();
            let hls = rules
                .rules
                .iter()
                .filter(|rule| rule.family == ModifierFamily::Hls)
                .count();
            crate::logbuf::push(&format!(
                "filter: {url} URL modifier rules + {} header modifier rules + {jsonprune} $jsonprune rules + {hls} $hls rules ({} dropped)",
                rules.rules.len() - url - jsonprune - hls,
                rules.dropped,
            ));
        }
        if let Some(rules) = cookie_rules.as_ref() {
            crate::logbuf::push(&format!(
                "filter: {} $cookie rules ({} request-independent, {} dropped)",
                rules.rules.len(),
                rules.rules.iter().filter(|rule| rule.constant).count(),
                rules.dropped,
            ));
        }
        let path_cosmetics = path_scan.resolve();
        if let Some(path) = path_cosmetics.as_ref() {
            crate::logbuf::push(&format!(
                "filter: {} $path cosmetic rules ({} unsupported)",
                path.rules.len(),
                path.dropped,
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
            modifier_rules,
            cookie_rules,
            path_cosmetics,
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
    /// procedural rules and scriptlets. `url` must be the page the response
    /// will render — the `$path` rules are matched against its path.
    ///
    /// The caller may pass `https://host/` when the lists carry no `$path`
    /// rule: cosmetic matching is hostname-based, exactly like AdGuard's own
    /// engine. What the lists' exceptions switch off is already applied.
    pub fn cosmetic_resources(&self, url: &str) -> CosmeticResources {
        self.cosmetic_resources_impl(url, true)
    }

    /// The cosmetic rules bound to `host` itself, `$path` rules left out.
    ///
    /// For callers that ask about a hostname rather than a page — the hiding
    /// stylesheet, the generic class/id lookup: the `/` of the URL synthesized
    /// for them is nobody's real path, and evaluating a main-page `$path` rule
    /// against it would apply the rule on pages the list never asked about.
    pub fn cosmetic_resources_for_host(&self, host: &str) -> CosmeticResources {
        self.cosmetic_resources_impl(&format!("https://{host}/"), false)
    }

    fn cosmetic_resources_impl(&self, url: &str, with_paths: bool) -> CosmeticResources {
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

        // The `$path` rules pinned to this page's path, served from the side
        // engine. They ride the inline payload like procedural rules do — the
        // per-host hiding stylesheet cannot know the path, and the browser
        // keeps it cached across the site.
        if with_paths {
            if let Some(path_rules) = compiled.path_cosmetics.as_ref() {
                let subset = path_rules.subset(pathmask::path_and_query(url));
                if !subset.is_empty() {
                    let extra = path_rules.engine_for(&subset).url_cosmetic_resources(url);
                    for selector in extra.hide_selectors {
                        if style_rules.len() < MAX_STYLE_RULES {
                            style_rules.push((selector, "display: none !important".to_string()));
                        }
                    }
                    for entry in extra.procedural_actions {
                        let Ok(parsed) = serde_json::from_str::<ProceduralOrActionFilter>(&entry)
                        else {
                            continue;
                        };
                        match parsed.as_css() {
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
                    scriptlets.push_str(&extra.injected_script);
                }
            }
        }

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
        let mut selectors = self.cosmetic_resources_for_host(host).hide_selectors;
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
    /// `subdocument`, `image`, `stylesheet`, `xmlhttprequest`, `media`, ...).
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
        if page_vetoed(&compiled, url, source, request_type) {
            return None;
        }
        let request = Request::new(url, source, request_type, method).ok()?;
        let result = probe.check_network_request(&request);
        let rule = replace
            .rules
            .get(replace_redirect_index(result.redirect.as_deref()?)?)?
            .clone();
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

/// A cosmetic rule AdGuard pins to a page path (`[$path=…]`), with the side
/// engine that serves it.
///
/// The main engine has no notion of the bracket — it drops such a rule whole
/// — and its cosmetic matching is hostname-based: a page asks for its
/// cosmetics for a URL, and the rules pinned to some other path of the site
/// must not be part of the answer. So those rules stay out of the main engine
/// and a page whose path matches a rule's mask gets a small engine of its own
/// — just the rules that match, plus the lists' cosmetic exceptions, which
/// cancel a path rule exactly as they would cancel any other — asked for the
/// URL like any other engine would be.
struct PathCosmetics {
    /// The path-pinned rules, in list order.
    rules: Vec<PathRule>,
    /// The `#@#`-family lines of every loaded list, converted, newline-
    /// separated: what the side engine needs to cancel a path rule the lists
    /// except elsewhere. Lines with a `[$…]` bracket of their own are not
    /// here — they cancel only the rules sharing their path, and are carried
    /// by the side list itself.
    exceptions: String,
    /// How many bracket rules could not be honored (see [`PathScan`]).
    dropped: u32,
    /// One engine per matched subset of [`PathCosmetics::rules`]. A page
    /// usually matches none, and the ones that match are pages the rules were
    /// written for, so the cache only ever holds the paths a session visits.
    engines: Mutex<HashMap<Vec<usize>, Arc<Engine>>>,
}

/// One path-pinned cosmetic rule: the converted text the side engine parses,
/// and the mask that decides the pages it applies to.
struct PathRule {
    text: String,
    mask: pathmask::PathMask,
}

impl PathCosmetics {
    /// The indices of the rules whose mask covers `subject` — a page's path
    /// and query.
    fn subset(&self, subject: &str) -> Vec<usize> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.mask.matches(subject))
            .map(|(index, _)| index)
            .collect()
    }

    /// The engine for one matched subset, built on first use.
    fn engine_for(&self, subset: &[usize]) -> Arc<Engine> {
        let mut engines = self.engines.lock().unwrap();
        if let Some(engine) = engines.get(subset) {
            return engine.clone();
        }
        let mut set = FilterSet::new(false);
        let mut text = String::new();
        for &index in subset {
            text.push_str(&self.rules[index].text);
            text.push('\n');
        }
        text.push_str(&self.exceptions);
        set.add_filter_list(
            text,
            ParseOptions {
                format: FilterFormat::Standard,
                rule_types: RuleTypes::All,
                ..Default::default()
            },
        );
        let mut engine = Engine::new_with_filter_set(set);
        // Scriptlets only assemble when the engine knows the implementations,
        // and only the subsets carrying one need the (large) table.
        if subset
            .iter()
            .any(|&index| self.rules[index].text.contains("+js("))
        {
            engine.use_resources(scriptlet_resources().iter().cloned());
        }
        let engine = Arc::new(engine);
        if engines.len() >= PATH_ENGINE_CACHE {
            engines.clear();
        }
        engines.insert(subset.to_vec(), engine.clone());
        engine
    }
}

/// What the path-bracket scan of the loaded lists has collected, before the
/// count and the side engine are made of it.
#[derive(Default)]
struct PathScan {
    rules: Vec<PathRule>,
    /// Raw `#@#`-family lines; converted in [`PathScan::resolve`].
    exceptions: Vec<String>,
    /// Bracket rules that could not be honored: `$app` or `$url`, a regexp
    /// `$domain` (a cosmetic rule cannot spell one), a `$path` that does not
    /// compile, or domains spelled in both styles (invalid per the knowledge
    /// base). Dropped rather than applied to pages the list did not ask for.
    dropped: u32,
}

impl PathScan {
    /// The scan as [`Compiled`] holds it. Anything at all — a rule or a drop
    /// — makes it `Some`, so the build log can report both.
    fn resolve(self) -> Option<PathCosmetics> {
        if self.rules.is_empty() && self.dropped == 0 {
            return None;
        }
        let mut exceptions = String::new();
        if !self.rules.is_empty() {
            for line in &self.exceptions {
                convert_adguard_line(line, &mut exceptions);
                exceptions.push('\n');
            }
        }
        Some(PathCosmetics {
            rules: self.rules,
            exceptions,
            dropped: self.dropped,
            engines: Mutex::new(HashMap::new()),
        })
    }
}

/// A cosmetic marker and its position: the earliest of the markers the
/// conversion and the bracket scan know. No marker is a substring of another
/// at the same position, so the earliest one is also the right one.
fn cosmetic_marker(line: &str) -> Option<(usize, &'static str)> {
    COSMETIC_MARKERS
        .iter()
        .filter_map(|marker| line.find(marker).map(|index| (index, *marker)))
        .min_by_key(|(index, _)| *index)
}

/// Every cosmetic marker a rule can carry, [`convert_adguard_line`]'s table
/// included.
const COSMETIC_MARKERS: &[&str] = &[
    "#@$?#", "#@?#", "#@$#", "#@%#", "#@#", "#$?#", "#?#", "#$#", "#%#", "##",
];

/// The markers whose lines cancel a rule ([`PathCosmetics::exceptions`]).
const EXCEPTION_MARKERS: &[&str] = &["#@$?#", "#@?#", "#@$#", "#@%#", "#@#"];

/// Rewrites one `[$…]`-bracketed cosmetic line.
///
/// `Some` means the bracket was recognized and the returned text replaces the
/// line — empty when the bracket holds something unusable, the rewritten rule
/// otherwise. `None` leaves the line to the plain conversion: it is not a
/// bracket rule, its bracket could not be made sense of, or its rule text is
/// not a cosmetic rule (a network rule's `[$…]` is out of this scanner's
/// business and stays exactly as it was).
fn bracket_cosmetic_line(line: &str, path: &mut PathScan) -> Option<String> {
    let bracket = match pathmask::parse_bracket(line) {
        pathmask::BracketParse::NotBracket => return None,
        pathmask::BracketParse::Unsupported { rest } => {
            // Only cosmetic rules are this scanner's (and the engine's)
            // business; a network rule keeps its line.
            cosmetic_marker(&rest)?;
            path.dropped += 1;
            return Some(String::new());
        }
        pathmask::BracketParse::Parsed(bracket) => bracket,
    };
    let (marker, _) = cosmetic_marker(&bracket.rest)?;
    // The domain part of the rule text, before the marker. Mixed styles —
    // `$domain` in the bracket *and* domains on the rule — are invalid per
    // the knowledge base: the rule is ignored.
    let before = bracket.rest[..marker].trim();
    if bracket.domain.is_some() && !before.is_empty() {
        path.dropped += 1;
        return Some(String::new());
    }
    let domains = bracket.domain.as_deref().unwrap_or(before);
    let mut rewritten = String::new();
    convert_adguard_line(&format!("{domains}{}", &bracket.rest[marker..]), &mut rewritten);
    match bracket.path {
        // A path-pinned rule: out of the main text — a blank line keeps the
        // source map aligned — and into the side list.
        Some(mask) => {
            path.rules.push(PathRule {
                text: rewritten,
                mask,
            });
            Some(String::new())
        }
        // `$domain` alone: the rule goes back into the main text without its
        // bracket, in the domain position the bracket was standing in for.
        None => Some(rewritten),
    }
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
fn convert_adguard_cosmetics(text: String, path: &mut PathScan) -> String {
    if !text.contains("[$")
        && !text.contains("#%#")
        && !text.contains("#$#")
        && !text.contains("#@")
    {
        return text;
    }
    let mut out = String::with_capacity(text.len() + 64);
    for line in text.lines() {
        match bracket_cosmetic_line(line, path) {
            Some(rewritten) => out.push_str(&rewritten),
            None => {
                // `#@#`-family lines are the cancellations the path side
                // engine has to know: taken down as written, converted in
                // [`PathScan::resolve`].
                if line.contains("#@") {
                    if let Some((_, marker)) = cosmetic_marker(line) {
                        if EXCEPTION_MARKERS.contains(&marker) {
                            path.exceptions.push(line.to_string());
                        }
                    }
                }
                convert_adguard_line(line, &mut out);
            }
        }
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
        scan.probe.push(probe_line(
            pattern,
            &kept,
            Some(&format!("{REPLACE_RESOURCE_PREFIX}{}", scan.probe.len())),
        ));
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
    // Inside a `/…/`-bracketed modifier value: how many of its slashes have
    // been seen, and how many close the bracketed part of the value.
    // `replace`/`urltransform` values carry two or more slashes before the
    // unescaped commas are free to split again, `removeparam=/regexp/` and
    // `cookie=/regexp/` close at the first one. Escaped commas are handled for
    // every value.
    let mut payload_slashes: Option<(u32, u32)> = None;
    while index < bytes.len() {
        if index == start {
            let payload = ["replace=/", "urltransform=/"]
                .iter()
                .find_map(|prefix| {
                    options[start..]
                        .starts_with(prefix)
                        .then_some((prefix.len(), 2))
                })
                .or_else(|| {
                    ["removeparam=/", "queryprune=/", "cookie=/"]
                        .iter()
                        .find_map(|prefix| {
                            options[start..]
                                .starts_with(prefix)
                                .then_some((prefix.len(), 1))
                        })
                });
            if let Some((len, closes)) = payload {
                payload_slashes = Some((0, closes));
                index = start + len;
                continue;
            }
        }
        let byte = bytes[index];
        if byte == b'\\' && index + 1 < bytes.len() {
            index += 2;
            continue;
        }
        if let Some((slashes, closes)) = payload_slashes.as_mut() {
            if byte == b'/' {
                *slashes += 1;
                if slashes == closes {
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
/// understands, and — for the probe engines — the redirect that names where the
/// rule's identity comes back in.
fn probe_line(pattern: &str, options: &[impl AsRef<str>], redirect: Option<&str>) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(options.len() + 1);
    if let Some(name) = redirect {
        parts.push(format!("redirect={name}"));
    }
    parts.extend(options.iter().map(|option| option.as_ref().to_string()));
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

// ---------------------------------------------------------------------------
// Request-URL modifiers the crate does not implement
// ---------------------------------------------------------------------------

/// Where a URL rule's index redirect rides.
///
/// The per-rule probe engines answer with a `$redirect` to
/// `adfree-urledit-<index>` (the shared fast path uses `adfree-urledit-any`,
/// an exception line `adfree-urledit-ex`), and the resource body carries the
/// index back exactly the way [`REPLACE_RESOURCE_PREFIX`] does it.
const MODIFIER_RESOURCE_PREFIX: &str = "adfree-urledit-";

/// Which modifier a rule carries. Values are only comparable within one
/// family: `@@...$removeparam=param` cancels `$removeparam` rules, never a
/// `$urltransform` that happens to repeat the value. The last three are the
/// response-header modifiers: they change what the client reads back instead of
/// what the origin is asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ModifierFamily {
    Transform,
    RemoveParam,
    Csp,
    Permissions,
    RemoveHeader,
    Jsonprune,
    Hls,
}

impl ModifierFamily {
    /// Whether the family rewrites the request URL — the two the HTTPS path
    /// runs through [`FilterEngine::url_edit`].
    fn is_url(self) -> bool {
        matches!(self, ModifierFamily::Transform | ModifierFamily::RemoveParam)
    }

    /// Whether the family shapes the answer's headers — the three
    /// [`FilterEngine::header_edit`] carries.
    fn is_header(self) -> bool {
        matches!(
            self,
            ModifierFamily::Csp | ModifierFamily::Permissions | ModifierFamily::RemoveHeader
        )
    }
}

/// One request-header/response-header rule, with its payload compiled.
struct ModifierRule {
    family: ModifierFamily,
    kind: ModifierKind,
    /// The rule exactly as the list wrote it: the log shows it.
    text: String,
    /// The modifier value as written: what a valued exception cancels, and the
    /// order `$urltransform` rules apply in.
    value: String,
    /// The rule names an explicit `$method`: a whole-URL transform is then not
    /// held back to GET the way it is by default.
    has_method: bool,
    /// The rule names `$subdocument`: `$permissions` is the one family that
    /// reads this, because subframes may only be affected by a rule that asks
    /// for them.
    subdocument: bool,
}

enum ModifierKind {
    Transform(UrlTransform),
    RemoveParam(RemoveParam),
    /// The `Content-Security-Policy` value the response gains.
    Csp(String),
    /// The `Permissions-Policy` value the response gains.
    Permissions(String),
    RemoveHeader(HeaderName),
    /// The expression the response body loses its matches of.
    Jsonprune(JsonPrune),
    /// The matcher the response playlist loses its segments by.
    Hls(crate::hls::HlsMatcher),
}

/// One `$removeheader` payload: the header to take out, and the direction.
struct HeaderName {
    /// Lowercased: HTTP header names are case-insensitive, and so is the
    /// comparison an exception makes.
    name: String,
    /// `request:`-prefixed — the header is taken off the request the origin
    /// sees, not off the response the client sees.
    request: bool,
}

/// Headers `$removeheader` refuses to touch, the reference's own list: they
/// carry framing, CORS or security meaning, and a list taking one out is a
/// list that did not mean to. A value naming one is dropped with the rule.
const FORBIDDEN_HEADERS: &[&str] = &[
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-request-headers",
    "access-control-request-method",
    "origin",
    "timing-allow-origin",
    "allow",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "content-security-policy",
    "content-security-policy-report-only",
    "expect-ct",
    "feature-policy",
    "origin-isolation",
    "strict-transport-security",
    "upgrade-insecure-requests",
    "x-content-type-options",
    "x-download-options",
    "x-frame-options",
    "x-permitted-cross-domain-policies",
    "x-powered-by",
    "x-xss-protection",
    "public-key-pins",
    "public-key-pins-report-only",
    "sec-websocket-key",
    "sec-websocket-extensions",
    "sec-websocket-accept",
    "sec-websocket-protocol",
    "sec-websocket-version",
    "p3p",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "sec-fetch-site",
    "sec-fetch-user",
    "referrer-policy",
    "content-type",
    "content-length",
    "accept",
    "accept-encoding",
    "host",
    "connection",
    "transfer-encoding",
    "upgrade",
];

/// One `$urltransform` rule's pipeline, ready to run on a request URL.
///
/// The value is `|`-separated stages: `/regexp/replacement/flags` or `/`-
/// delimited substitutes, plus `pct` and `b64` decodes. Normally only the path
/// and query are the input — a value beginning with `/^http` hands over the
/// whole URL instead, which is how the list cleans an affiliate redirect down
/// to its destination.
struct UrlTransform {
    /// The whole URL is the pipeline's input, so the transformation may change
    /// the origin: the rule's first substitute reaches for it (`/^http…`),
    /// which is how the list cleans an affiliate redirect down to its
    /// destination. Such a rule only matches GET requests.
    full: bool,
    stages: Vec<Transform>,
}

enum Transform {
    Substitute(Substitute),
    /// Percent-decode what the pipeline has produced so far.
    Pct,
    /// Base64-decode it (either alphabet).
    B64,
}

/// One `name/regexp/replacement` stage of a `$urltransform`.
struct Substitute {
    regex: regex::Regex,
    replacement: String,
    /// This substitute's regexp was anchored at `^http`, so it can only mean
    /// anything when the pipeline sees the whole URL.
    whole_url: bool,
}

/// One `$removeparam` rule, compiled.
enum RemoveParam {
    /// Naked `$removeparam`: every parameter goes.
    All,
    /// `$removeparam=name`; `~` inverts the sense of both named forms.
    Name(String),
    NotName(String),
    /// `$removeparam=/regexp/[i]`, matched against `name=value`.
    Regex(regex::Regex),
    NotRegex(regex::Regex),
}

/// The modifier rules one list text carries.
#[derive(Default)]
struct ModifierScan {
    /// Rules held until the `$badfilter` pass has looked at them (it needs the
    /// whole set, lists and user rules alike, before a rule can be called).
    pending: Vec<PendingRule>,
    /// `$cookie` rules, held the same way but built differently: they are not
    /// one engine apiece but a single probe that answers every rule that
    /// matched (see [`CookieRules`]), and an exception among them is not a
    /// cancellation to fold but a rule of its own.
    cookies: Vec<PendingCookie>,
    /// Exceptions, waiting to be folded into the per-rule engines. An empty
    /// value cancels every rule of its family; a valued one cancels the rules
    /// repeating it. `$permissions` also compares whether the two are
    /// `$subdocument`-scoped.
    exceptions: Vec<ExceptionRule>,
    /// `$badfilter` rules: they never apply themselves, they take other rules
    /// off the set.
    badfilters: Vec<CancelMaterial>,
    dropped: u32,
    /// The `$cookie` share of [`ModifierScan::dropped`], counted apart for the
    /// build log.
    cookie_dropped: u32,
}

/// One rule the scan read, before `$badfilter` has had its say.
struct PendingRule {
    rule: ModifierRule,
    /// The pattern the probe matches on (`*` when the list wrote none: an
    /// empty pattern and `*` say the same thing).
    pattern: String,
    /// The options the probe line carries: the ones the crate implements, the
    /// family token gone, the default types spelled out.
    options: Vec<String>,
    /// What a `$badfilter` rule compares (see [`CancelMaterial`]).
    cancel: CancelMaterial,
}

/// One `$cookie` rule the scan read, held the same way.
struct PendingCookie {
    rule: CookieRule,
    /// The pattern the probe matches on (`*` when the list wrote none).
    pattern: String,
    /// The options the probe line carries: the crate options, without a
    /// default type — a `$csp` line cannot carry one, and a type-less cookie
    /// rule covers every request type anyway.
    options: Vec<String>,
    /// What a `$badfilter` rule compares.
    cancel: CancelMaterial,
}

/// One exception rule, ready to be folded into the probes it cancels.
struct ExceptionRule {
    family: ModifierFamily,
    value: String,
    /// The rule names `$subdocument` (or its alias).
    subdocument: bool,
    pattern: String,
    options: Vec<String>,
}

/// What `$badfilter` compares, following the reference's `negatesBadfilter`:
/// the two rules match when they are the same kind of rule (blocking against
/// blocking, exception against exception), match the same pattern, carry the
/// same option *names* — values are not part of it, so a `$csp` badfilter takes
/// out every `$csp` rule with that pattern, whichever directive it sets — the
/// same request types, and compatible domain lists.
struct CancelMaterial {
    exception: bool,
    pattern: String,
    /// Option names, values dropped, aliases canonical, `badfilter` gone,
    /// split by sense.
    options: (Vec<String>, Vec<String>),
    /// Type options, canonical, split by sense.
    types: (Vec<String>, Vec<String>),
    /// `domain=` as written; `None` when the rule names none. A permitted list
    /// cancels when the two intersect.
    domains: Option<Vec<String>>,
    /// `~domain=`, compared as written.
    denied: Option<Vec<String>>,
    /// `denyallow=`, compared as written.
    denyallow: Option<Vec<String>>,
}

impl CancelMaterial {
    /// Whether `self` (a `$badfilter` rule) takes `other` off the set.
    fn cancels(&self, other: &CancelMaterial) -> bool {
        self.exception == other.exception
            && self.pattern == other.pattern
            && self.options == other.options
            && self.types == other.types
            && match (&self.domains, &other.domains) {
                (None, None) => true,
                (Some(mine), Some(theirs)) => mine.iter().any(|domain| theirs.contains(domain)),
                _ => false,
            }
            && self.denied == other.denied
            && self.denyallow == other.denyallow
    }
}

/// How many modifier rules one build keeps. Each rule gets its own probe
/// engine, and no real list comes close; a list trying to push past this is
/// capped rather than allowed to build thousands of engines.
const URL_RULES_MAX: usize = 256;

/// The modifier rules of the loaded lists, with the engines that find them.
struct ModifierRules {
    rules: Vec<ModifierRule>,
    /// One engine per rule: the rule's own pattern with its exceptions folded
    /// in, so `should_block` here means "this rule applies to this request".
    probes: Vec<Engine>,
    /// Every rule in one engine, one shared resource: a miss means no rule of
    /// any family can possibly apply, whatever the exceptions say.
    any: Engine,
    dropped: u32,
}

/// What the URL-level modifiers do to one request, from
/// [`FilterEngine::url_edit`].
pub struct UrlEdit {
    /// The URL the request must go out as.
    pub url: String,
    /// The rules that fired, in application order (the log shows them).
    pub rules: Vec<String>,
}

/// What the response-header modifiers do to one request, from
/// [`FilterEngine::header_edit`].
///
/// This is the plan the HTTPS path holds for the answer: the headers the
/// response gains, and the ones it or the request going out lose.
#[derive(Default)]
pub struct HeaderEdit {
    /// `Content-Security-Policy` values to append, one header each, in the
    /// order the lists wrote them.
    pub csp: Vec<String>,
    /// `Permissions-Policy` values to append.
    pub permissions: Vec<String>,
    /// Response headers to take out (lowercased names).
    pub remove_response: Vec<String>,
    /// Request headers to take out before the request goes out (lowercased).
    pub remove_request: Vec<String>,
    /// The rules that fired, for the log line.
    pub rules: Vec<String>,
}

/// The `$jsonprune` rules that apply to one request, as a plan for the
/// response body.
///
/// The reference sorts the matching rules lexicographically and applies the
/// first to the original response, each next one to the result of the
/// previous; [`JsonprunePlan::apply`] reads the plan in exactly that order.
pub struct JsonprunePlan {
    rules: Vec<JsonpruneRule>,
}

impl JsonprunePlan {
    /// Applies the plan to one response body, returning the rewritten body
    /// and the rules that changed it. `None` when the body is not JSON, or no
    /// rule took anything out of it.
    pub fn apply(&self, body: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
        crate::jsonprune::prune_body(&self.rules, body)
    }
}

/// The `$hls` rules that apply to one request, as a plan for the response
/// body.
///
/// The reference calls the rules' effect cumulative — each removes segments
/// of the same playlist — so the plan carries them all, with the playlist's
/// own URL to resolve the segments against, and [`HlsPlan::apply`] unions
/// the removals in one pass.
pub struct HlsPlan {
    rules: Vec<crate::hls::HlsRule>,
    /// The URL the playlist was fetched from: segment URLs resolve against
    /// it, the way a player would read them.
    base: String,
}

impl HlsPlan {
    /// Applies the plan to one response body, returning the rewritten body
    /// and the rules that changed it. `None` when the body is not an HLS
    /// playlist, or no rule removed a segment from it.
    pub fn apply(&self, body: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
        crate::hls::apply_rules(&self.rules, &self.base, body)
    }
}

/// Reads the rules the crate refuses because of their modifier: `$urltransform`
/// and the `$removeparam` shapes it does not implement (bare, `~`, and
/// `/regexp/`; only `=name` ever reached the crate) rewrite the request URL,
/// while `$csp`, `$permissions` and `$removeheader` shape the answer. Their
/// `$badfilter` rules are read here too — these rules live outside the crate's
/// engine, so its own badfilter pass never sees them.
fn scan_modifier_rules(text: &str, scan: &mut ModifierScan) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['!', '[', '#']) {
            continue;
        }
        // A `#` before the `$` says the line is a cosmetic rule that mentions
        // a modifier name by accident (`##div:has-text($csp…)`), and a pattern
        // with a `#` in it is one no list writes.
        if let (Some(hash), Some(dollar)) = (line.find('#'), line.find('$')) {
            if hash < dollar {
                continue;
            }
        }
        let exception = line.starts_with("@@");
        let rule = line.strip_prefix("@@").unwrap_or(line);
        let Some((pattern, tokens)) = split_modifier_rule(rule) else {
            continue;
        };
        // An empty pattern and `*` say the same thing: every URL matches.
        let pattern = if pattern.is_empty() { "*" } else { pattern };
        // One rule, one modifier: two modifier families in the same rule have
        // no defined combination, and no list writes one.
        let families: Vec<&str> = tokens
            .iter()
            .copied()
            .filter(|token| is_modifier_token(token))
            .collect();
        if families.len() != 1 {
            scan.dropped += 1;
            continue;
        }
        let token = families[0];
        // `$cookie` is not one of the modifier families: it is matched by
        // machinery of its own (see [`CookieRules`]) and takes the branch below
        // before a family is read. `$jsonprune` and `$hls` are families like
        // the others — per-rule probes carry them — but the reference scopes
        // their type options.
        let cookie = token.split('=').next() == Some("cookie");
        let hls = token.split('=').next() == Some("hls");
        let body_family = hls || token.split('=').next() == Some("jsonprune");
        let value = token.split_once('=').map(|(_, value)| value).unwrap_or("");
        let badfilter = tokens.iter().any(|token| {
            let bare = token.trim_start_matches('~');
            bare.split('=').next().unwrap_or(bare) == "badfilter"
        });

        // The options the crate implements exactly, so the probe matches the
        // rule the way the list meant it; the family token is where the
        // redirect goes, and nothing else would parse.
        let mut kept: Vec<&str> = Vec::new();
        let mut faithful = true;
        // `$hls` names `$match-case`: remembered here because whether it can
        // be honored depends on the value's form (a pattern cannot, a regexp
        // answers for itself).
        let mut value_match_case = false;
        for token in &tokens {
            let bare = token.trim_start_matches('~');
            let name = bare.split('=').next().unwrap_or(bare);
            if name.is_empty() || is_modifier_token(token) {
                // The family token itself carries where its probe's answer
                // goes, so it is not kept as an option.
                continue;
            }
            if name == "badfilter" {
                // The cancellation marker is not an option a probe may carry;
                // its rule never applies itself. What it cancels is recorded
                // below, out of the same option list ([`CancelMaterial`]).
                continue;
            }
            if name == "to" {
                // The crate parses `$to` and then leaves the rule out of every
                // list, so pointing a probe at it would never match: the rule
                // is dropped instead of living on as a dead one.
                faithful = false;
                continue;
            }
            if name == "method" {
                // The crate knows GET, HEAD and POST; a rule asking for any
                // other method (or to exclude one) would come out wider than
                // the list wrote it.
                let methods_ok = !token.starts_with('~')
                    && bare
                        .split_once('=')
                        .map(|(_, value)| {
                            !value.is_empty()
                                && value.split('|').all(|method| {
                                    matches!(
                                        method.trim().to_ascii_lowercase().as_str(),
                                        "get" | "head" | "post"
                                    )
                                })
                        })
                        .unwrap_or(false);
                if !methods_ok {
                    faithful = false;
                    continue;
                }
            }
            if cookie && TYPE_OPTIONS.contains(&name) {
                // The cookie probe line is a `$csp`, and the crate refuses
                // `$csp` with a content type — so the line carries none, and
                // that is faithful to every real `$cookie` rule: a type-less
                // one covers every request type. `all` says exactly that and
                // reads as no option; any other type would make the probe
                // answer a different question than the list asked, and the
                // rule is dropped rather than half-run.
                if name == "all" && !token.starts_with('~') {
                    continue;
                }
                faithful = false;
                continue;
            }
            if body_family && TYPE_OPTIONS.contains(&name) {
                // The reference takes `$jsonprune` and `$hls` with
                // `$xmlhttprequest` only, and the live corpus also spells
                // `all` — every type by definition. Any other type, or a
                // negated one (which the compatibility list does not have),
                // would make the probe answer a question the list did not
                // ask: the rule is dropped rather than half-run.
                if !token.starts_with('~') && matches!(name, "xmlhttprequest" | "xhr" | "all") {
                    kept.push(token);
                    continue;
                }
                faithful = false;
                continue;
            }
            if hls && name == "match-case" {
                // The crate refuses `$match-case` on anything but a full-regex
                // rule, so a probe carrying it would never match. The option
                // is left off the probe; where it would have shaped a
                // pattern-form value it cannot be honored (see below), and a
                // regexp-form value carries its own case syntax.
                value_match_case = true;
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
            scan.cookie_dropped += u32::from(cookie);
            continue;
        }
        if cookie {
            // `$badfilter` never applies itself, and never reads its modifier
            // value either (the reference checks the marker first): one whose
            // value is unreadable still cancels the rules it matches.
            if badfilter {
                scan.badfilters.push(cancel_material(exception, pattern, &tokens));
                continue;
            }
            // The value is the cookie this rule is about, read into a matcher;
            // an unreadable one (`;maxAge`/`;sameSite` — a *modifying* rule
            // this engine does not modify with — an unknown `;` part, or a
            // regexp the regex crate cannot run) sends the rule to the dropped
            // counter, the way the reference refuses it.
            let Some(matcher) = cookie_payload(value) else {
                scan.dropped += 1;
                scan.cookie_dropped += 1;
                continue;
            };
            if scan.cookies.len() >= COOKIE_RULES_MAX {
                scan.dropped += 1;
                scan.cookie_dropped += 1;
                continue;
            }
            // An exception among cookie rules is a rule of its own, not a
            // cancellation: whether a cookie goes is answered per name, and an
            // allowlist rule that matches the name has the last word (see
            // [`CookiePlan::dropped`]).
            let text = if exception {
                format!("@@{rule}")
            } else {
                rule.to_string()
            };
            // The rules whose answer does not depend on the request — no
            // pattern, no `$domain=`/party/method option — are answered without
            // asking the engine at all; asking about them would mean
            // enumerating hundreds of hits per request for an answer that never
            // changes (the live corpus is 427 of them).
            let constant = pattern == "*"
                && !tokens.iter().any(|token| {
                    let bare = token.trim_start_matches('~');
                    matches!(
                        bare.split('=').next().unwrap_or(bare),
                        "domain" | "from" | "1p" | "first-party" | "3p" | "third-party" | "method"
                    )
                });
            scan.cookies.push(PendingCookie {
                rule: CookieRule {
                    text,
                    allow: exception,
                    matcher,
                    constant,
                },
                pattern: pattern.to_string(),
                options: kept.iter().map(|token| token.to_string()).collect(),
                cancel: cancel_material(exception, pattern, &tokens),
            });
            continue;
        }
        let family = modifier_family_of(token);
        let mut options: Vec<String> = kept.iter().map(|token| token.to_string()).collect();
        if !has_positive_type(&kept) {
            options.push(default_types(family).to_string());
        }
        let has_method = kept
            .iter()
            .any(|token| token.trim_start_matches('~').split('=').next() == Some("method"));
        let subdocument = kept.iter().any(|token| {
            !token.starts_with('~')
                && matches!(
                    token.split('=').next().unwrap_or(token),
                    "subdocument" | "frame"
                )
        });

        // The payload: a blocking rule whose modifier this engine cannot read
        // is a rule it must not half-run. An exception carries no payload — its
        // value only labels the rules it cancels — so for one this is a
        // validity question, and an empty value is always legal there.
        let kind = payload(family, value);
        if kind.is_none() && !(exception && value.trim().is_empty()) {
            scan.dropped += 1;
            continue;
        }
        if hls
            && !exception
            && value_match_case
            && matches!(
                kind,
                Some(ModifierKind::Hls(crate::hls::HlsMatcher::Pattern(_)))
            )
        {
            // The pattern engine can only match case-insensitively — the
            // crate's own basic-rule matching — so a pattern-form rule asking
            // for `$match-case` is dropped rather than run wider than the
            // list wrote it.
            scan.dropped += 1;
            continue;
        }
        if badfilter {
            // A `$badfilter` rule never applies itself: it waits until every
            // list has been read, then takes the rules it matches off the set.
            scan.badfilters.push(cancel_material(exception, pattern, &tokens));
            continue;
        }
        if exception {
            scan.exceptions.push(ExceptionRule {
                family,
                value: value.to_string(),
                subdocument,
                pattern: pattern.to_string(),
                options,
            });
            continue;
        }
        if scan.pending.len() >= URL_RULES_MAX {
            scan.dropped += 1;
            continue;
        }
        scan.pending.push(PendingRule {
            rule: ModifierRule {
                family,
                kind: kind.expect("a blocking rule has a payload"),
                text: rule.to_string(),
                value: value.to_string(),
                has_method,
                subdocument,
            },
            pattern: pattern.to_string(),
            options,
            cancel: cancel_material(exception, pattern, &tokens),
        });
    }
}

/// Splits `pattern$option,option,...` at the `$` that starts a modifier list.
/// The pattern itself may contain a `$`, so the split is the first `$` after
/// which one of the family tokens shows up. A rule that starts with the `$`
/// has no pattern at all — every URL matches it.
fn split_modifier_rule(text: &str) -> Option<(&str, Vec<&str>)> {
    let mut search = 0;
    while let Some(offset) = text[search..].find('$') {
        let index = search + offset;
        let pattern = &text[..index];
        let tokens = split_options(&text[index + 1..]);
        if tokens.iter().any(|token| is_modifier_token(token)) {
            return Some((pattern, tokens));
        }
        search = index + 1;
    }
    None
}

/// A token carrying one of the modifiers this engine reads itself: the crate
/// refuses every one of them, so they are matched here.
fn is_modifier_token(token: &str) -> bool {
    matches!(
        token.split('=').next().unwrap_or(token),
        "urltransform"
            | "removeparam"
            | "queryprune"
            | "csp"
            | "permissions"
            | "removeheader"
            | "cookie"
            | "jsonprune"
            | "hls"
    )
}

fn modifier_family_of(token: &str) -> ModifierFamily {
    match token.split('=').next() {
        Some("urltransform") => ModifierFamily::Transform,
        Some("csp") => ModifierFamily::Csp,
        Some("permissions") => ModifierFamily::Permissions,
        Some("removeheader") => ModifierFamily::RemoveHeader,
        Some("jsonprune") => ModifierFamily::Jsonprune,
        Some("hls") => ModifierFamily::Hls,
        _ => ModifierFamily::RemoveParam,
    }
}

/// The payload of one modifier rule, or `None` when the value means something
/// this engine will not run: a rule that cannot run is a rule that must not
/// half-run.
fn payload(family: ModifierFamily, value: &str) -> Option<ModifierKind> {
    match family {
        ModifierFamily::Transform => UrlTransform::parse(value).map(ModifierKind::Transform),
        ModifierFamily::RemoveParam => RemoveParam::parse(value).map(ModifierKind::RemoveParam),
        ModifierFamily::Csp => csp_payload(value).map(ModifierKind::Csp),
        ModifierFamily::Permissions => permissions_payload(value).map(ModifierKind::Permissions),
        ModifierFamily::RemoveHeader => removeheader_payload(value).map(ModifierKind::RemoveHeader),
        ModifierFamily::Jsonprune => JsonPrune::parse(value).map(ModifierKind::Jsonprune),
        ModifierFamily::Hls => crate::hls::parse(value).map(ModifierKind::Hls),
    }
}

/// Reads a `$csp` value: the policy the response gains.
///
/// A `report-*` directive turns the header into an observer rather than a
/// policy — the reference refuses the rule, and so does this — and an empty
/// value is no policy at all, so only an exception may leave it out.
fn csp_payload(value: &str) -> Option<String> {
    if value.trim().is_empty() || value.to_ascii_lowercase().contains("report-") {
        return None;
    }
    Some(value.to_string())
}

/// Reads a `$permissions` value. A rule may spell several policies with `|` or
/// an escaped comma, and both read as the separator the header itself uses.
fn permissions_payload(value: &str) -> Option<String> {
    let normalised = value.replace("\\,", ",").replace('|', ",");
    if normalised.trim().is_empty() {
        return None;
    }
    Some(normalised)
}

/// Reads a `$removeheader` value: `request:name` takes the header off the
/// request the origin sees, a bare name off the response the client sees.
/// A header the list may not touch, or a name carrying a `:` of its own, makes
/// the rule invalid — the reference refuses those, and so does this.
fn removeheader_payload(value: &str) -> Option<HeaderName> {
    let lower = value.trim().to_ascii_lowercase();
    let (request, name) = match lower.strip_prefix("request:") {
        Some(name) => (true, name),
        None => (false, lower.as_str()),
    };
    if name.is_empty() || name.contains(':') || FORBIDDEN_HEADERS.contains(&name) {
        return None;
    }
    Some(HeaderName {
        name: name.to_string(),
        request,
    })
}

/// Reads the option list the way `$badfilter` compares it (see
/// [`CancelMaterial`]).
fn cancel_material(exception: bool, pattern: &str, tokens: &[&str]) -> CancelMaterial {
    let mut options: (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut types: (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let mut domains = None;
    let mut denied = None;
    let mut denyallow = None;
    for token in tokens {
        let (name, negated) = canonical_option(token);
        if name.is_empty() || name == "badfilter" {
            continue;
        }
        let value = token.split_once('=').map(|(_, value)| value).unwrap_or("");
        match name.as_str() {
            "domain" => {
                let list: Vec<String> = value.split('|').map(str::to_string).collect();
                if negated {
                    denied = Some(list);
                } else {
                    domains = Some(list);
                }
            }
            "denyallow" => {
                denyallow = Some(value.split('|').map(str::to_string).collect());
            }
            _ => {
                let bucket = if is_type_name(&name) { &mut types } else { &mut options };
                let side = if negated { &mut bucket.1 } else { &mut bucket.0 };
                side.push(name);
            }
        }
    }
    for bucket in [&mut options, &mut types] {
        bucket.0.sort();
        bucket.0.dedup();
        bucket.1.sort();
        bucket.1.dedup();
    }
    CancelMaterial {
        exception,
        pattern: pattern.to_string(),
        options,
        types,
        domains,
        denied,
        denyallow,
    }
}

/// Canonical `(name, negated)` for the `$badfilter` compare: aliases collapse
/// onto the name they stand for, and the first-party spellings collapse onto
/// the third-party flag they set, the way the reference's parser reads them.
fn canonical_option(token: &str) -> (String, bool) {
    let negated = token.starts_with('~');
    let bare = token.trim_start_matches('~');
    let name = bare.split('=').next().unwrap_or(bare);
    let (name, negated) = match name {
        "1p" | "first-party" => ("third-party", !negated),
        "3p" => ("third-party", negated),
        "doc" => ("document", negated),
        "frame" => ("subdocument", negated),
        "css" => ("stylesheet", negated),
        "xhr" => ("xmlhttprequest", negated),
        "beacon" => ("ping", negated),
        "queryprune" => ("removeparam", negated),
        other => (other, negated),
    };
    (name.to_string(), negated)
}

/// The canonical names that set a request type rather than an option flag.
fn is_type_name(name: &str) -> bool {
    matches!(
        name,
        "document"
            | "subdocument"
            | "script"
            | "stylesheet"
            | "image"
            | "media"
            | "object"
            | "object-subrequest"
            | "other"
            | "ping"
            | "xmlhttprequest"
            | "websocket"
            | "font"
            | "all"
    )
}

/// The request-type options a rule may name.
const TYPE_OPTIONS: &[&str] = &[
    "document",
    "doc",
    "subdocument",
    "frame",
    "script",
    "stylesheet",
    "css",
    "image",
    "media",
    "object",
    "object-subrequest",
    "other",
    "ping",
    "beacon",
    "xmlhttprequest",
    "xhr",
    "websocket",
    "font",
    "all",
];

fn has_positive_type(tokens: &[&str]) -> bool {
    tokens.iter().any(|token| {
        if token.starts_with('~') {
            return false;
        }
        TYPE_OPTIONS.contains(&token.split('=').next().unwrap_or(token))
    })
}

/// The request types a modifier rule covers when the list names none.
///
/// AdGuard's own engine and its MV3 converter agree on the split: a
/// `$urltransform`, `$csp` or `$removeheader` without type options covers every
/// request type, document navigations included, while `$removeparam` and
/// `$permissions` cover only the documents — a `document`-typed request,
/// top-level or a frame. The crate would leave documents out of a line that
/// names no type, so the default has to be spelled out on the probe line.
fn default_types(family: ModifierFamily) -> &'static str {
    match family {
        ModifierFamily::Transform
        | ModifierFamily::Csp
        | ModifierFamily::RemoveHeader
        | ModifierFamily::Jsonprune
        | ModifierFamily::Hls => "all",
        ModifierFamily::RemoveParam | ModifierFamily::Permissions => "document,subdocument",
    }
}

impl UrlTransform {
    /// Reads a `$urltransform` value, or `None` when a stage means something
    /// this engine cannot run: a rule that cannot run is a rule that must not
    /// half-run.
    fn parse(value: &str) -> Option<UrlTransform> {
        // The whole URL is the pipeline's input when the first substitute
        // reaches for it (`/^http…`): a rule that starts by reading the tracker
        // URL is a rule about where the request really goes. Later substitutes
        // do not get to make that call — AdGuard decides it on the first one,
        // and the real rules are written for it.
        let mut full = false;
        let mut decided = false;
        let mut stages = Vec::new();
        for stage in split_transform_stages(value) {
            let stage = stage.trim();
            match stage {
                "" => {}
                "pct" => stages.push(Transform::Pct),
                "b64" => stages.push(Transform::B64),
                _ => {
                    let substitute = Substitute::parse(stage)?;
                    if !decided {
                        full = substitute.whole_url;
                        decided = true;
                    }
                    stages.push(Transform::Substitute(substitute));
                }
            }
        }
        if stages.is_empty() {
            return None;
        }
        Some(UrlTransform { full, stages })
    }

    /// The transformed URL, or `None` when the pipeline cannot produce one the
    /// request could legally go out as.
    fn apply(&self, url: &str) -> Option<String> {
        let mut current = if self.full {
            url.to_string()
        } else {
            path_and_query(url)?.to_string()
        };
        for stage in &self.stages {
            match stage {
                Transform::Pct => current = percent_decode(&current),
                Transform::B64 => {
                    if let Some(decoded) = base64_decode_any(&current) {
                        current = decoded;
                    }
                }
                Transform::Substitute(substitute) => {
                    // Every occurrence, the way `$replace` and CoreLibs do it:
                    // the real affiliate rules depend on it (`/%2F/\//` clears
                    // all three escapes an encoded destination carries).
                    current = substitute
                        .regex
                        .replace_all(&current, substitute.replacement.as_str())
                        .into_owned();
                }
            }
        }
        if self.full {
            // The rule reached for the whole URL, so it may move the request to
            // another origin — but only to a URL a request could go out as.
            // AdGuard accepts exactly the streaming-and-web schemes here.
            let scheme_ok = ["http://", "https://", "ws://", "wss://"]
                .iter()
                .any(|scheme| current.starts_with(scheme));
            (scheme_ok && !current.contains(char::is_whitespace)).then_some(current)
        } else if current.starts_with('/') {
            Some(format!("{}{current}", origin_of(url)?))
        } else {
            None
        }
    }
}

/// Splits a `$urltransform` value into its `|`-separated stages.
///
/// A pipe inside a `/regexp/replacement/flags` substitute is a regex
/// alternation, not a separator: a stage that opens with `/` runs until its
/// third unescaped slash, the way AdGuard's own splitter reads it.
fn split_transform_stages(value: &str) -> Vec<&str> {
    let mut stages = Vec::new();
    let mut start = 0usize;
    let mut slashes = 0u8;
    let mut in_substitute = false;
    let mut escaped = false;
    for (index, c) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '|' if !in_substitute => {
                stages.push(&value[start..index]);
                start = index + 1;
                slashes = 0;
                in_substitute = false;
            }
            '/' => {
                if !in_substitute && index == start {
                    in_substitute = true;
                    slashes = 0;
                }
                if in_substitute {
                    slashes += 1;
                    if slashes >= 3 {
                        in_substitute = false;
                    }
                }
            }
            _ => {}
        }
    }
    stages.push(&value[start..]);
    stages
}

impl Substitute {
    /// Reads `/regexp/replacement/flags`, the shape every real `$urltransform`
    /// stage uses.
    fn parse(stage: &str) -> Option<Substitute> {
        // `$` is the modifier separator in a rule, so a stage writes `\$` both
        // for a backreference and for the end-of-string anchor — and the
        // transform reads both as the `$` they stand for.
        let stage = stage.replace("\\$", "$");
        let rest = stage.strip_prefix('/')?;
        let (pattern, rest) = split_unescaped(rest, '/')?;
        let (replacement, flags) = split_unescaped(rest, '/')?;
        let prefix = inline_flags(flags)?;
        let regex = regex::Regex::new(&format!("{prefix}{}", unescape_pattern(pattern))).ok()?;
        Some(Substitute {
            regex,
            replacement: unescape_replacement(replacement),
            whole_url: pattern.starts_with("^http"),
        })
    }
}

impl RemoveParam {
    fn parse(value: &str) -> Option<RemoveParam> {
        if value.is_empty() {
            return Some(RemoveParam::All);
        }
        let (negated, rest) = match value.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, value),
        };
        if let Some(regex) = parse_slash_regex(rest) {
            return Some(if negated {
                RemoveParam::NotRegex(regex)
            } else {
                RemoveParam::Regex(regex)
            });
        }
        if rest.is_empty() {
            return None;
        }
        Some(if negated {
            RemoveParam::NotName(rest.to_string())
        } else {
            RemoveParam::Name(rest.to_string())
        })
    }

    /// The URL with the parameters this rule drops taken off, or `None` when
    /// it drops none.
    fn apply(&self, url: &str) -> Option<String> {
        let query_start = url.find('?')?;
        let (path, rest) = url.split_at(query_start);
        let rest = &rest[1..];
        let (query, fragment) = match rest.find('#') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        if query.is_empty() {
            return None;
        }
        if matches!(self, RemoveParam::All) {
            // AdGuard cuts everything after the path here, fragment included.
            return Some(path.to_string());
        }
        let mut kept: Vec<&str> = Vec::new();
        let mut removed = false;
        for pair in query.split('&') {
            // The parameter is judged as the `name=value` string the docs
            // describe — a bare name reads as `name=`. It is judged twice: as
            // written, and percent-decoded, so a regexp written for readable
            // parameters still finds them escaped in the URL.
            let test = if pair.contains('=') {
                pair.to_string()
            } else {
                format!("{pair}=")
            };
            let decoded = percent_decode(&test);
            let drop = match self {
                RemoveParam::All => unreachable!("handled above"),
                RemoveParam::Name(name) => named(&test, name) || named(&decoded, name),
                RemoveParam::NotName(name) => !named(&test, name) && !named(&decoded, name),
                RemoveParam::Regex(regex) => regex.is_match(&test) || regex.is_match(&decoded),
                RemoveParam::NotRegex(regex) => !regex.is_match(&test) && !regex.is_match(&decoded),
            };
            if drop {
                removed = true;
            } else {
                kept.push(pair);
            }
        }
        if !removed {
            return None;
        }
        // Removing parameters normalizes the query the way AdGuard does: the
        // holes and the empty `=value` leftovers go too.
        let kept: Vec<&str> = kept
            .into_iter()
            .filter(|pair| !pair.is_empty() && !pair.starts_with('='))
            .collect();
        let mut out = String::with_capacity(url.len());
        out.push_str(path);
        if !kept.is_empty() {
            out.push('?');
            out.push_str(&kept.join("&"));
        }
        out.push_str(fragment);
        Some(out)
    }
}

/// Whether a `name=value` string carries the named parameter: the comparison
/// AdGuard writes as `^name=`.
fn named(test: &str, name: &str) -> bool {
    test.len() > name.len() && test.starts_with(name) && test.as_bytes()[name.len()] == b'='
}

/// Reads `/regexp/` (optionally `/regexp/i`), the `$removeparam` regular
/// expression shape.
fn parse_slash_regex(text: &str) -> Option<regex::Regex> {
    let rest = text.strip_prefix('/')?;
    let mut end = None;
    let mut escaped = false;
    for (index, c) in rest.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '/' => end = Some(index),
            _ => {}
        }
    }
    let end = end?;
    let flags = &rest[end + 1..];
    if !flags.chars().all(|flag| flag == 'i') {
        return None;
    }
    let prefix = if flags.is_empty() { "" } else { "(?i)" };
    regex::Regex::new(&format!("{prefix}{}", unescape_pattern(&rest[..end]))).ok()
}

/// Percent-decodes a URL fragment. A `%` that does not start a valid escape is
/// left alone, and bytes that do not form UTF-8 are kept as they are.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    index += 3;
                    continue;
                }
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Base64-decodes text, trying the standard and URL-safe alphabets, padded or
/// not: the `b64` stage of `$urltransform` takes either.
fn base64_decode_any(text: &str) -> Option<String> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let text = text.trim();
    for engine in [BASE64, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(text) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                return Some(decoded);
            }
        }
    }
    None
}

/// The path-and-query half of an absolute URL: what a `$urltransform`
/// substitute works on unless the rule asks for the whole URL.
fn path_and_query(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let start = rest.find(['/', '?', '#'])?;
    Some(&rest[start..])
}

/// The `scheme://authority` head of an absolute URL.
fn origin_of(url: &str) -> Option<&str> {
    let scheme_end = url.find("://")? + 3;
    let rest = &url[scheme_end..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&url[..scheme_end + authority_end])
}

/// Whether two absolute URLs share scheme and authority. A `$urltransform`
/// that changes them moves the request to another origin, which is answered
/// with a redirect instead of a rewrite.
pub fn same_origin(a: &str, b: &str) -> bool {
    match (origin_of(a), origin_of(b)) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

/// Whether a page exception (`$content`, or an empty `$replace`) switches
/// content modification off for the page a request belongs to.
fn page_vetoed(compiled: &Compiled, url: &str, source: &str, request_type: &str) -> bool {
    let Some(veto) = compiled
        .replace
        .as_ref()
        .and_then(|replace| replace.veto.as_ref())
    else {
        return false;
    };
    // The exceptions name *pages*, so a subresource is asked about the document
    // it came from. `other` keeps the crate from reading a path-scoped pattern
    // as "not a document": a page URL is the only URL the rule is about,
    // whatever the request type is.
    let page = if request_type == "document" || source.is_empty() {
        url
    } else {
        source
    };
    Request::new(page, page, "other", "GET")
        .map(|request| veto.check_network_request(&request).should_block())
        .unwrap_or(false)
}

/// Builds the engines a list's modifier rules need, or `None`/`None` when the
/// loaded lists carry none: the request/response-header rules and the cookie
/// rules, which share the scan (and its `$badfilter` pass) but not the way
/// they are matched.
fn build_modifier_rules(scan: ModifierScan) -> (Option<ModifierRules>, Option<CookieRules>) {
    let ModifierScan {
        pending,
        cookies,
        exceptions,
        badfilters,
        dropped,
        cookie_dropped,
    } = scan;
    // `$badfilter` has the last word on which rules live: a rule one of them
    // matches never applies.
    let cookies: Vec<PendingCookie> = cookies
        .into_iter()
        .filter(|rule| !badfilters.iter().any(|filter| filter.cancels(&rule.cancel)))
        .collect();
    let cookie_rules = build_cookie_rules(cookies, cookie_dropped);
    let pending: Vec<PendingRule> = pending
        .into_iter()
        .filter(|rule| !badfilters.iter().any(|filter| filter.cancels(&rule.cancel)))
        .collect();
    if pending.is_empty() {
        return (None, cookie_rules);
    }
    let mut any_lines = Vec::with_capacity(pending.len());
    let mut probes = Vec::with_capacity(pending.len());
    let mut rules = Vec::with_capacity(pending.len());
    for (index, pending) in pending.into_iter().enumerate() {
        let PendingRule {
            rule,
            pattern,
            options,
            ..
        } = pending;
        let probe = probe_line(
            &pattern,
            &options,
            Some(&format!("{MODIFIER_RESOURCE_PREFIX}{index}")),
        );
        // An exception is folded into the engine of every rule it can cancel:
        // the crate has to see the rule cancelled by what the list cancelled
        // it with. An empty value cancels every rule of its family, a valued
        // one the rules repeating it. `$permissions` also compares whether the
        // two are `$subdocument`-scoped — a subframe may only be affected by a
        // rule that asks for it — so a document-scoped exception does not
        // touch a subframe rule, or the other way round.
        let mut lines = vec![probe];
        lines.extend(
            exceptions
                .iter()
                .filter(|exception| {
                    exception.family == rule.family
                        && (exception.value.is_empty() || exception.value == rule.value)
                        && (rule.family != ModifierFamily::Permissions
                            || exception.subdocument == rule.subdocument)
                })
                .map(|exception| {
                    let line = probe_line(
                        &exception.pattern,
                        &exception.options,
                        Some(&format!("{MODIFIER_RESOURCE_PREFIX}ex")),
                    );
                    format!("@@{line}")
                }),
        );
        let mut set = FilterSet::new(false);
        set.add_filter_list(lines.join("\n"), ParseOptions::default());
        let mut engine = Engine::new_with_filter_set(set);
        engine.use_resources([
            url_resource(
                &format!("{MODIFIER_RESOURCE_PREFIX}{index}"),
                &index.to_string(),
            ),
            url_resource(&format!("{MODIFIER_RESOURCE_PREFIX}ex"), "0"),
        ]);
        probes.push(engine);
        any_lines.push(probe_line(
            &pattern,
            &options,
            Some(&format!("{MODIFIER_RESOURCE_PREFIX}any")),
        ));
        rules.push(rule);
    }
    let mut any_set = FilterSet::new(false);
    any_set.add_filter_list(any_lines.join("\n"), ParseOptions::default());
    let mut any = Engine::new_with_filter_set(any_set);
    any.use_resources([url_resource(&format!("{MODIFIER_RESOURCE_PREFIX}any"), "0")]);

    (
        Some(ModifierRules {
            rules,
            probes,
            any,
            dropped,
        }),
        cookie_rules,
    )
}

// ---------------------------------------------------------------------------
// `$cookie` — the rules that keep a cookie from being sent or set
// ---------------------------------------------------------------------------

/// How many `$cookie` rules one build keeps.
///
/// Every request-dependent rule of the family shares one probe engine (see
/// [`CookieRules`]), so this is only a sanity bound, far above anything a list
/// carries — the live corpus reads 1127.
const COOKIE_RULES_MAX: usize = 4096;

/// The `$cookie` rules of the loaded lists, with the engine that finds them.
///
/// The crate refuses the modifier, so the rules are matched by an engine of
/// this engine's own. What makes it one engine instead of one per rule: a
/// rule's `$cookie` modifier is rewritten into a `$csp` carrying the rule's
/// index, and `get_csp_directives` hands back *every* directive that matched —
/// the whole matching set in one call. The crate dedupes directive values, so
/// one index per line is one hit per rule.
struct CookieRules {
    /// Every rule, in list order; the probe's `$csp` value is the rule's index
    /// into this vector.
    rules: Vec<Arc<CookieRule>>,
    /// The probe engine, holding one `$csp` line per request-dependent rule.
    /// `None` when every rule is [`CookieRule::constant`].
    probe: Option<Engine>,
    dropped: u32,
}

/// One `$cookie` rule, ready to match a cookie name.
struct CookieRule {
    /// The rule exactly as the list wrote it (an exception keeps its `@@`: it
    /// is a rule of its own here, not a cancellation folded into another).
    text: String,
    /// `@@`: the rule protects the cookies its matcher names.
    allow: bool,
    /// What the rule's value matches.
    matcher: CookieMatcher,
    /// The rule matches every request (no pattern, no `$domain=` or
    /// party/method option), so the probe engine is never asked about it.
    constant: bool,
}

/// What a `$cookie` value matches.
enum CookieMatcher {
    /// `$cookie=name`: that exact name.
    Name(String),
    /// `$cookie=/regexp/`: the reference compiles the value with `new RegExp`
    /// and tests the cookie name with it — a search, not a full match.
    Regex(regex::Regex),
    /// `$cookie` with no value: every cookie.
    All,
}

impl CookieMatcher {
    fn matches(&self, name: &str) -> bool {
        match self {
            CookieMatcher::Name(rule) => rule == name,
            CookieMatcher::Regex(regex) => regex.is_match(name),
            CookieMatcher::All => true,
        }
    }
}

/// What the `$cookie` rules do to the cookies of one exchange, from
/// [`CookiePlan::dropped`].
#[derive(Debug, Default)]
pub struct CookieEdit {
    /// The cookie names that must go, in the order they were asked about.
    pub drop: Vec<String>,
    /// The blocking rules behind the drops (the log shows the count).
    pub rules: Vec<String>,
}

/// The `$cookie` rules one request matched, from [`FilterEngine::cookie_plan`].
///
/// The plan is what the HTTPS path holds for the exchange: the request loses
/// the cookies it names from its `Cookie` header, and the response that comes
/// back may not set them. Both questions are answered per cookie name, because
/// the answers depend on the name.
pub struct CookiePlan {
    /// The rules that matched the request, in list order.
    matched: Vec<Arc<CookieRule>>,
}

impl CookiePlan {
    /// The names of `names` that must be taken off: a name goes when a
    /// blocking rule that matched the request matches it too, unless an
    /// allowlist rule that matched the request matches it — an allowlist rule
    /// has the last word whatever the rules' order or importance, the way the
    /// reference's per-cookie lookup reads them.
    pub fn dropped(&self, names: &[String]) -> Option<CookieEdit> {
        let mut edit = CookieEdit::default();
        for name in names {
            // An empty name is no cookie to name in a rule; the reference
            // never blocks one.
            if name.is_empty() || edit.drop.iter().any(|dropped| dropped == name) {
                continue;
            }
            let mut blocked: Option<&CookieRule> = None;
            let mut allowed = false;
            for rule in &self.matched {
                if !rule.matcher.matches(name) {
                    continue;
                }
                if rule.allow {
                    allowed = true;
                    break;
                }
                if blocked.is_none() {
                    blocked = Some(rule);
                }
            }
            let Some(rule) = blocked.filter(|_| !allowed) else {
                continue;
            };
            edit.drop.push(name.clone());
            if !edit.rules.iter().any(|text| text == &rule.text) {
                edit.rules.push(rule.text.clone());
            }
        }
        (!edit.drop.is_empty()).then_some(edit)
    }
}

/// Builds the one engine the cookie rules need, or `None` when there are none.
fn build_cookie_rules(cookies: Vec<PendingCookie>, dropped: u32) -> Option<CookieRules> {
    if cookies.is_empty() {
        return None;
    }
    let mut rules: Vec<Arc<CookieRule>> = Vec::with_capacity(cookies.len());
    let mut lines: Vec<String> = Vec::new();
    for pending in cookies {
        let index = rules.len();
        let PendingCookie {
            rule,
            pattern,
            options,
            ..
        } = pending;
        if !rule.constant {
            // The probe line the crate can read: the `$cookie` modifier
            // becomes a `$csp` naming the rule's index. A rule carries one
            // modifier, so the value is free to be the index.
            let mut probe_options = Vec::with_capacity(options.len() + 1);
            probe_options.push(format!("csp={index}"));
            probe_options.extend(options);
            lines.push(probe_line(&pattern, &probe_options, None));
        }
        rules.push(Arc::new(rule));
    }
    let probe = (!lines.is_empty()).then(|| {
        let mut set = FilterSet::new(false);
        set.add_filter_list(lines.join("\n"), ParseOptions::default());
        Engine::new_with_filter_set(set)
    });
    Some(CookieRules {
        rules,
        probe,
        dropped,
    })
}

/// Reads a `$cookie` value: the cookie the rule is about.
///
/// The value is a name, a `/regexp/` (the reference compiles it with
/// `new RegExp`, so a value that merely looks like one — `/foo/i`, say — is a
/// literal name), or empty, which matches every cookie. A `;`-separated part
/// names one of the two options the reference implements and this engine does
/// not: a `;maxAge` above zero or a `;sameSite` makes the rule *modify* the
/// cookie instead of removing it, and a rule this engine cannot modify is a
/// rule it must not half-run; an unknown part is a value the reference refuses
/// with it. Both drop the rule.
fn cookie_payload(value: &str) -> Option<CookieMatcher> {
    let mut parts = value.split(';');
    let name = parts.next().unwrap_or_default();
    for part in parts {
        let (option, argument) = match part.split_once('=') {
            Some((option, argument)) => (option, Some(argument)),
            None => (part, None),
        };
        match option {
            // `parseInt` reads the leading whole number and stops: `30`, `+30`
            // and `30x` are all thirty seconds of modification, while a
            // missing value, an empty one or `soon` read as none at all.
            "maxAge" => {
                let seconds = argument.and_then(leading_integer).unwrap_or(0);
                if seconds > 0 {
                    return None;
                }
            }
            // `sameSite` modifies whatever it carries, an absent value
            // included.
            "sameSite" => return None,
            _ => return None,
        }
    }
    if name.is_empty() {
        return Some(CookieMatcher::All);
    }
    if name.starts_with('/') && name.ends_with('/') {
        // `/` alone is the empty pattern, which matches everything — the way
        // the reference reads it.
        let pattern = if name.len() >= 2 {
            &name[1..name.len() - 1]
        } else {
            ""
        };
        return regex::Regex::new(pattern).ok().map(CookieMatcher::Regex);
    }
    Some(CookieMatcher::Name(name.to_string()))
}

/// The leading whole number of a string, the way JavaScript's `parseInt` reads
/// one: an optional sign, then digits, up to the first byte that is neither.
/// `None` when there is no number at all; a number too large to hold counts as
/// one.
fn leading_integer(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let mut end = 0usize;
    if matches!(bytes.first(), Some(&b'+') | Some(&b'-')) {
        end = 1;
    }
    let digits_start = end;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == digits_start {
        return None;
    }
    Some(text[..end].parse().unwrap_or_else(|_| {
        if text.starts_with('-') {
            i64::MIN
        } else {
            i64::MAX
        }
    }))
}

/// One probe resource: the body is what the crate hands back when the redirect
/// fires, the name is what the rule points at.
fn url_resource(name: &str, body: &str) -> Resource {
    Resource {
        name: name.to_string(),
        aliases: Vec::new(),
        kind: ResourceType::Mime(MimeType::TextPlain),
        content: BASE64.encode(body),
        dependencies: Vec::new(),
        permission: Default::default(),
    }
}

impl FilterEngine {
    /// Whether the loaded lists carry request-URL modifiers the HTTPS path
    /// runs.
    pub fn has_url_rules(&self) -> bool {
        self.compiled()
            .modifier_rules
            .as_ref()
            .is_some_and(|rules| rules.rules.iter().any(|rule| rule.family.is_url()))
    }

    /// Whether they carry response-header modifiers (`$csp`, `$permissions`,
    /// `$removeheader`).
    pub fn has_header_rules(&self) -> bool {
        self.compiled()
            .modifier_rules
            .as_ref()
            .is_some_and(|rules| rules.rules.iter().any(|rule| rule.family.is_header()))
    }

    /// Whether the loaded lists carry `$cookie` rules.
    pub fn has_cookie_rules(&self) -> bool {
        self.compiled().cookie_rules.is_some()
    }

    /// Whether the loaded lists carry cosmetic rules pinned to a page path
    /// (`[$path=…]`).
    pub fn has_path_rules(&self) -> bool {
        self.compiled()
            .path_cosmetics
            .as_ref()
            .is_some_and(|path| !path.rules.is_empty())
    }

    /// Whether the loaded lists carry `$jsonprune` rules.
    pub fn has_jsonprune_rules(&self) -> bool {
        self.compiled()
            .modifier_rules
            .as_ref()
            .is_some_and(|rules| {
                rules
                    .rules
                    .iter()
                    .any(|rule| rule.family == ModifierFamily::Jsonprune)
            })
    }

    /// Whether the loaded lists carry `$hls` rules.
    pub fn has_hls_rules(&self) -> bool {
        self.compiled()
            .modifier_rules
            .as_ref()
            .is_some_and(|rules| {
                rules
                    .rules
                    .iter()
                    .any(|rule| rule.family == ModifierFamily::Hls)
            })
    }

    /// The `$cookie` rules that apply to one request, matched once per exchange
    /// and held for both halves of it.
    ///
    /// The request type is not part of the question: the probe line is a `$csp`
    /// (which the crate only answers for document-like requests) and carries no
    /// type option, so the answer is the same for a request of any type — and a
    /// rule that names a type was dropped at build, because its answer could
    /// not be asked for.
    pub fn cookie_plan(&self, url: &str, source: &str, method: &str) -> Option<CookiePlan> {
        let compiled = self.compiled();
        let rules = compiled.cookie_rules.as_ref()?;
        // `document` is what the crate's enumeration demands; no probe line
        // carries a type option, so it does not decide anything.
        let request = Request::new(url, source, "document", method).ok()?;
        let mut hit: Vec<usize> = Vec::new();
        if let Some(probe) = rules.probe.as_ref() {
            if let Some(directives) = probe.get_csp_directives(&request) {
                for value in directives.split(',') {
                    if let Ok(index) = value.parse::<usize>() {
                        if index < rules.rules.len() {
                            hit.push(index);
                        }
                    }
                }
            }
        }
        let matched: Vec<Arc<CookieRule>> = rules
            .rules
            .iter()
            .enumerate()
            .filter(|(index, rule)| rule.constant || hit.contains(index))
            .map(|(_, rule)| Arc::clone(rule))
            .collect();
        (!matched.is_empty()).then_some(CookiePlan { matched })
    }

    /// How many `$cookie` rules they carry (diagnostics).
    pub fn cookie_rules_count(&self) -> u64 {
        self.compiled()
            .cookie_rules
            .as_ref()
            .map(|rules| rules.rules.len() as u64)
            .unwrap_or(0)
    }

    /// How many URL modifier rules the loaded lists carry (diagnostics).
    pub fn url_rules_count(&self) -> u64 {
        self.compiled()
            .modifier_rules
            .as_ref()
            .map(|rules| {
                rules
                    .rules
                    .iter()
                    .filter(|rule| rule.family.is_url())
                    .count() as u64
            })
            .unwrap_or(0)
    }

    /// How many header modifier rules they carry (diagnostics).
    pub fn header_rules_count(&self) -> u64 {
        self.compiled()
            .modifier_rules
            .as_ref()
            .map(|rules| {
                rules
                    .rules
                    .iter()
                    .filter(|rule| rule.family.is_header())
                    .count() as u64
            })
            .unwrap_or(0)
    }

    /// The request-URL modifiers that apply to one request, applied.
    ///
    /// `$urltransform` runs first, in the order AdGuard applies matching rules
    /// in: by the modifier value the rules carry, each rule on what the one
    /// before it left. A whole-URL transform then leaves `$removeparam` to work
    /// on the rewritten request — it is matched again, the way a rewritten
    /// request is matched against the rest of the rules — while a rule a page
    /// exception cancels — `@@` with the same value, or with none — never
    /// fires: the value comparison lives inside each probe engine, so the
    /// crate's own exception handling answers it.
    ///
    /// The methods hold two rules back, both AdGuard's own: a whole-URL
    /// transform only ever matches a GET, and `$removeparam` only reads the
    /// methods a parameter change cannot break.
    pub fn url_edit(
        &self,
        url: &str,
        source: &str,
        request_type: &str,
        method: &str,
    ) -> Option<UrlEdit> {
        let compiled = self.compiled();
        let rules = compiled.modifier_rules.as_ref()?;
        if page_vetoed(&compiled, url, source, request_type) {
            return None;
        }
        let request = Request::new(url, source, request_type, method).ok()?;
        // The fast path: no rule of any family can match, whatever the
        // exceptions say, so the per-rule engines are never asked. Every probe
        // line carries a `$redirect`, so a hit comes back as one.
        rules
            .any
            .check_network_request(&request)
            .redirect
            .as_ref()?;
        let matched = |request: &Request| -> Vec<&ModifierRule> {
            rules
                .rules
                .iter()
                .zip(rules.probes.iter())
                .filter(|(_, engine)| engine.check_network_request(request).should_block())
                .map(|(rule, _)| rule)
                .collect()
        };

        let mut current = url.to_string();
        let mut fired: Vec<String> = Vec::new();
        let mut transforms: Vec<&ModifierRule> = matched(&request)
            .into_iter()
            .filter(|rule| rule.family == ModifierFamily::Transform)
            .collect();
        transforms.sort_by(|a, b| a.value.cmp(&b.value));
        for rule in transforms {
            let ModifierKind::Transform(transform) = &rule.kind else {
                continue;
            };
            // A rule that may change the origin only ever matches a GET:
            // anything else cannot take the redirect it would have to answer
            // with, so it is not applied at all.
            if transform.full && !rule.has_method && !method.eq_ignore_ascii_case("GET") {
                continue;
            }
            if let Some(next) = transform.apply(&current) {
                if next != current {
                    current = next;
                    fired.push(rule.text.clone());
                }
            }
        }

        // AdGuard purges parameters of the requests a rewrite cannot break:
        // GETs and HEADs, and the bodies a form sends with them. A PUT or a
        // DELETE is left exactly as the client wrote it.
        let purging = matches!(
            method.to_ascii_uppercase().as_str(),
            "GET" | "HEAD" | "POST" | "OPTIONS"
        );
        if purging {
            let rewritten = (current != url)
                .then(|| Request::new(&current, source, request_type, method).ok())
                .flatten();
            let request = rewritten.as_ref().unwrap_or(&request);
            for rule in matched(request) {
                if rule.family != ModifierFamily::RemoveParam {
                    continue;
                }
                let ModifierKind::RemoveParam(remove) = &rule.kind else {
                    continue;
                };
                if let Some(next) = remove.apply(&current) {
                    if next != current {
                        current = next;
                        fired.push(rule.text.clone());
                    }
                }
            }
        }
        if fired.is_empty() {
            return None;
        }
        Some(UrlEdit {
            url: current,
            rules: fired,
        })
    }

    /// The response-header modifiers that apply to one request, as a plan for
    /// the answer.
    ///
    /// A rule that matches the request changes the response that request
    /// produces: `$csp` and `$permissions` values are appended as headers, and
    /// `$removeheader` names are taken out — of the response, or of the request
    /// itself when the value says `request:`. A value is appended once however
    /// many lists repeat it, the way the reference keeps one rule per directive,
    /// and `$permissions` only applies to a request of the same scope as the
    /// rule: a rule that does not name `$subdocument` speaks about documents, a
    /// frame is only affected by one that does.
    ///
    /// A page that switched content modification off (`$content`, an empty
    /// `$replace`) still gets its headers edited: those switches are about what
    /// the *page* runs, these modifiers are network filtering, and the reference
    /// keeps them in services of their own.
    pub fn header_edit(
        &self,
        url: &str,
        source: &str,
        request_type: &str,
        method: &str,
    ) -> Option<HeaderEdit> {
        let compiled = self.compiled();
        let rules = compiled.modifier_rules.as_ref()?;
        let request = Request::new(url, source, request_type, method).ok()?;
        // The same fast path as the URL edit: a miss means no rule of any
        // family can match, whatever the exceptions say.
        rules.any.check_network_request(&request).redirect.as_ref()?;
        let subdocument = request_type == "subdocument";
        let mut edit = HeaderEdit::default();
        for (rule, engine) in rules.rules.iter().zip(rules.probes.iter()) {
            if !rule.family.is_header() || !engine.check_network_request(&request).should_block() {
                continue;
            }
            match &rule.kind {
                ModifierKind::Csp(value) => {
                    if edit.csp.contains(value) {
                        continue;
                    }
                    edit.csp.push(value.clone());
                }
                ModifierKind::Permissions(value) => {
                    if rule.subdocument != subdocument || edit.permissions.contains(value) {
                        continue;
                    }
                    edit.permissions.push(value.clone());
                }
                ModifierKind::RemoveHeader(header) => {
                    let list = if header.request {
                        &mut edit.remove_request
                    } else {
                        &mut edit.remove_response
                    };
                    if list.contains(&header.name) {
                        continue;
                    }
                    list.push(header.name.clone());
                }
                ModifierKind::Transform(_)
                | ModifierKind::RemoveParam(_)
                | ModifierKind::Jsonprune(_)
                | ModifierKind::Hls(_) => continue,
            }
            edit.rules.push(rule.text.clone());
        }
        if edit.rules.is_empty() {
            return None;
        }
        Some(edit)
    }

    /// The `$jsonprune` rules that apply to one request, matched once per
    /// exchange and held for the response that request produces.
    ///
    /// A page exception (`$content`, an empty `$replace`) switches the family
    /// off, like it switches `$replace` off — `$jsonprune` is a content
    /// modifier, not network filtering. The rules themselves are sorted the
    /// way the reference applies them, lexicographically, and each one reads
    /// what the rules before it left (see [`JsonprunePlan::apply`]).
    pub fn jsonprune_plan(
        &self,
        url: &str,
        source: &str,
        request_type: &str,
        method: &str,
    ) -> Option<JsonprunePlan> {
        let compiled = self.compiled();
        let rules = compiled.modifier_rules.as_ref()?;
        if page_vetoed(&compiled, url, source, request_type) {
            return None;
        }
        let request = Request::new(url, source, request_type, method).ok()?;
        // The same fast path as the other edits: a miss on the shared engine
        // means no rule of any family can match, whatever the exceptions say.
        rules.any.check_network_request(&request).redirect.as_ref()?;
        let mut matched: Vec<&ModifierRule> = rules
            .rules
            .iter()
            .zip(rules.probes.iter())
            .filter(|(rule, engine)| {
                rule.family == ModifierFamily::Jsonprune
                    && engine.check_network_request(&request).should_block()
            })
            .map(|(rule, _)| rule)
            .collect();
        matched.sort_by(|a, b| a.text.cmp(&b.text));
        let rules: Vec<JsonpruneRule> = matched
            .into_iter()
            .filter_map(|rule| match &rule.kind {
                ModifierKind::Jsonprune(expression) => {
                    Some(JsonpruneRule::new(rule.text.clone(), expression.clone()))
                }
                _ => None,
            })
            .collect();
        (!rules.is_empty()).then_some(JsonprunePlan { rules })
    }

    /// The `$hls` rules that apply to one request, matched once per exchange
    /// and held for the response that request produces.
    ///
    /// A page exception (`$content`, an empty `$replace`) switches the family
    /// off, like it switches `$replace` off — `$hls` is a content modifier,
    /// not network filtering. Every matching rule rides on the plan in list
    /// order; their effect is cumulative and order-independent (see
    /// [`HlsPlan::apply`]).
    pub fn hls_plan(
        &self,
        url: &str,
        source: &str,
        request_type: &str,
        method: &str,
    ) -> Option<HlsPlan> {
        let compiled = self.compiled();
        let rules = compiled.modifier_rules.as_ref()?;
        if page_vetoed(&compiled, url, source, request_type) {
            return None;
        }
        let request = Request::new(url, source, request_type, method).ok()?;
        // The same fast path as the other edits: a miss on the shared engine
        // means no rule of any family can match, whatever the exceptions say.
        rules.any.check_network_request(&request).redirect.as_ref()?;
        let rules: Vec<crate::hls::HlsRule> = rules
            .rules
            .iter()
            .zip(rules.probes.iter())
            .filter(|(rule, engine)| {
                rule.family == ModifierFamily::Hls
                    && engine.check_network_request(&request).should_block()
            })
            .filter_map(|(rule, _)| match &rule.kind {
                ModifierKind::Hls(matcher) => {
                    Some(crate::hls::HlsRule::new(rule.text.clone(), matcher.clone()))
                }
                _ => None,
            })
            .collect();
        (!rules.is_empty()).then(|| HlsPlan {
            rules,
            base: url.to_string(),
        })
    }

    /// How many `$jsonprune` rules they carry (diagnostics).
    pub fn jsonprune_rules_count(&self) -> u64 {
        self.compiled()
            .modifier_rules
            .as_ref()
            .map(|rules| {
                rules
                    .rules
                    .iter()
                    .filter(|rule| rule.family == ModifierFamily::Jsonprune)
                    .count() as u64
            })
            .unwrap_or(0)
    }

    /// How many `$hls` rules they carry (diagnostics).
    pub fn hls_rules_count(&self) -> u64 {
        self.compiled()
            .modifier_rules
            .as_ref()
            .map(|rules| {
                rules
                    .rules
                    .iter()
                    .filter(|rule| rule.family == ModifierFamily::Hls)
                    .count() as u64
            })
            .unwrap_or(0)
    }
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

    /// One request through the URL modifiers, the way the HTTPS path runs
    /// them: what the request goes out as, or nothing when no rule fires.
    fn url_of(fe: &FilterEngine, url: &str, kind: &str) -> Option<String> {
        fe.url_edit(url, "https://page.test/", kind, "GET")
            .map(|edit| edit.url)
    }

    #[test]
    fn urltransform_reaches_the_destination_of_a_tracker_link() {
        // The tradedoubler shape: a decode, then the substitute that reads the
        // whole URL — the first substitute decides the mode — then a decode of
        // what it left behind.
        let fe = cosmetic_engine(
            "||clk.tradedoubler.com/click?*url=$urltransform=pct|/^https?:\\/\\/(?:[a-z0-9-]+\\.)*?.*\\.tradedoubler\\.com.*[?&]url=([^&]*).*/\\$1/|pct\n",
        );
        assert_eq!(fe.url_rules_count(), 1);
        let url = "https://clk.tradedoubler.com/click?p=1&url=https%3A%2F%2Fwww.store.test%2Fdeep%2F%3Fq%3D1&x=2";
        let edit = fe
            .url_edit(url, "https://page.test/", "document", "GET")
            .expect("the rule fires");
        assert_eq!(edit.url, "https://www.store.test/deep/?q=1");
        assert_eq!(edit.rules.len(), 1);
        // The transformation moved the request to another origin, which only
        // an answer the client can follow can do.
        assert!(!same_origin(url, &edit.url));
    }

    #[test]
    fn urltransform_stays_on_the_page_path_when_the_first_substitute_does() {
        // The effiliation trio: the two decodes are path-only stages and sort
        // first, so they leave the tracker URL readable; the third rule is its
        // own full-URL pipeline — its first substitute reaches for the whole
        // URL — and hands back the destination.
        let fe = cosmetic_engine(
            "||track.effiliation.com/servlet/effi.redir$urltransform=/%2F/\\//\n\
             ||track.effiliation.com/servlet/effi.redir$urltransform=/%3A/:/\n\
             ||track.effiliation.com/servlet/effi.redir$urltransform=/^https?:\\/\\/(?:[a-z0-9-]+\\.)*?track\\.effiliation\\.com.*[?&]url=(.+)$/\\$1/\n",
        );
        assert_eq!(fe.url_rules_count(), 3);
        let url = "https://track.effiliation.com/servlet/effi.redir?id=1&url=http%3A%2F%2Fshop.test%2Fdeep%2Fpage";
        let edit = fe
            .url_edit(url, "https://page.test/", "document", "GET")
            .expect("the rules fire");
        assert_eq!(edit.url, "http://shop.test/deep/page");
        assert_eq!(edit.rules.len(), 3, "{:?}", edit.rules);
        // The destination is another origin, so the HTTPS path answers a
        // redirect rather than rewriting the request in place.
        assert!(!same_origin(url, &edit.url));
    }

    #[test]
    fn a_path_only_transform_decodes_in_place() {
        // A rule whose first substitute is not anchored at `^http` works on
        // the path, and the origin stays whatever it was.
        let fe = cosmetic_engine("||shop.test/go$urltransform=/%2F/\\//\n");
        let url = "https://shop.test/go?next=%2Fdeep%2Fpage";
        let edit = fe
            .url_edit(url, "https://page.test/", "document", "GET")
            .expect("the rule fires");
        assert_eq!(edit.url, "https://shop.test/go?next=/deep/page");
        assert!(same_origin(url, &edit.url));
    }

    #[test]
    fn a_whole_url_transform_waits_for_a_get() {
        let fe = cosmetic_engine(
            "||shop.test/go$urltransform=/^http.*url=(https?:\\/\\/[^&]*)$/\\$1/\n",
        );
        let url = "https://shop.test/go?url=https://ok.test/x";
        let edit = fe
            .url_edit(url, "https://page.test/", "document", "GET")
            .expect("GET fires");
        assert_eq!(edit.url, "https://ok.test/x");
        assert!(fe
            .url_edit(url, "https://page.test/", "document", "POST")
            .is_none());
        // A path-only transform is not held back the same way.
        let fe = cosmetic_engine("||shop.test/go$urltransform=/-a/-b/\n");
        assert_eq!(
            url_of(&fe, "https://shop.test/go-a", "document").as_deref(),
            Some("https://shop.test/go-b")
        );
        // An explicit `$method` is the rule setting its own terms.
        let fe = cosmetic_engine(
            "||shop.test/go$method=POST,urltransform=/^http.*url=(https?:\\/\\/[^&]*)$/\\$1/\n",
        );
        assert!(fe
            .url_edit(url, "https://page.test/", "document", "POST")
            .is_some());
        assert!(fe
            .url_edit(url, "https://page.test/", "document", "GET")
            .is_none());
    }

    #[test]
    fn removeparam_shapes_the_crate_refuses_still_run() {
        // The bare shape takes every parameter off, and — with no type option —
        // only a document or a frame is offered to it.
        let fe = cosmetic_engine("&siteid=*&adid=$removeparam\n");
        assert_eq!(
            url_of(
                &fe,
                "https://shop.test/pixel?y=1&siteid=7&adid=3&x=1",
                "subdocument"
            )
            .as_deref(),
            Some("https://shop.test/pixel")
        );
        assert!(url_of(&fe, "https://shop.test/pixel?y=1&siteid=7&adid=3", "image").is_none());
        // The regexp shape reads the parameter normalized to `name=value`, as
        // written and percent-decoded.
        let fe = cosmetic_engine("||shop.test/api$removeparam=/^secret_.*$/\n");
        assert_eq!(
            url_of(
                &fe,
                "https://shop.test/api?secret_a=1&keep=2&secret_b=3",
                "document"
            )
            .as_deref(),
            Some("https://shop.test/api?keep=2")
        );
        assert_eq!(
            url_of(&fe, "https://shop.test/api?secret%5Fa=1", "document").as_deref(),
            Some("https://shop.test/api")
        );
        // Negation keeps exactly the parameter it names.
        let fe = cosmetic_engine("||shop.test/api$removeparam=~keep\n");
        assert_eq!(
            url_of(&fe, "https://shop.test/api?keep=1&a=2", "document").as_deref(),
            Some("https://shop.test/api?keep=1")
        );
        // `=name`, the shape the crate implements, runs here too: the family
        // keeps one order and one exception story.
        let fe = cosmetic_engine("||shop.test/api$removeparam=secret\n");
        assert_eq!(
            url_of(&fe, "https://shop.test/api?secret=1&keep=2", "document").as_deref(),
            Some("https://shop.test/api?keep=2")
        );
        // No parameter change on the methods a rewrite can break.
        assert!(fe
            .url_edit(
                "https://shop.test/api?secret=1",
                "https://page.test/",
                "document",
                "DELETE"
            )
            .is_none());
    }

    #[test]
    fn url_modifier_exceptions_cancel_rule_by_rule() {
        // An exception carrying a value cancels exactly the rule with that
        // value: the other removal still happens.
        let fe = cosmetic_engine(
            "||shop.test/api$removeparam=secret\n\
             ||shop.test/api$removeparam=track\n\
             @@||shop.test^$removeparam=secret\n",
        );
        assert_eq!(
            url_of(
                &fe,
                "https://shop.test/api?secret=1&track=2&keep=3",
                "document"
            )
            .as_deref(),
            Some("https://shop.test/api?secret=1&keep=3")
        );
        // An exception with no value cancels the whole family.
        let fe = cosmetic_engine(
            "||shop.test/api$removeparam=secret\n\
             @@||shop.test^$removeparam\n",
        );
        assert!(url_of(&fe, "https://shop.test/api?secret=1", "document").is_none());
        // The page the exception names is what scopes it.
        let fe = cosmetic_engine(
            "||shop.test/go$urltransform=/-a/-b/\n\
             @@||other.test^$urltransform\n",
        );
        assert_eq!(
            url_of(&fe, "https://shop.test/go-a", "document").as_deref(),
            Some("https://shop.test/go-b")
        );
        // A plain exception is about blocking, not about the URL modifiers.
        let fe = cosmetic_engine(
            "||shop.test/go$urltransform=/-a/-b/\n\
             @@||shop.test^\n",
        );
        assert!(url_of(&fe, "https://shop.test/go-a", "document").is_some());
    }

    #[test]
    fn urltransforms_run_before_the_parameter_removals() {
        // The transform writes the parameter the removal then drops: the other
        // order would leave it behind.
        let fe = cosmetic_engine(
            "||shop.test/api$urltransform=/keep=/gone=/\n\
             ||shop.test/api$removeparam=gone\n",
        );
        assert_eq!(
            url_of(&fe, "https://shop.test/api?keep=1", "document").as_deref(),
            Some("https://shop.test/api")
        );
        // The removal reads the request the transform left, so a rule whose
        // pattern only the rewritten URL matches still fires.
        let fe = cosmetic_engine(
            "||shop.test/api$urltransform=/-old/-new/\n\
             ||shop.test/api-new$removeparam=secret\n",
        );
        assert_eq!(
            url_of(&fe, "https://shop.test/api-old?secret=1", "document").as_deref(),
            Some("https://shop.test/api-new")
        );
    }

    #[test]
    fn url_modifier_rules_the_engine_cannot_run_are_dropped() {
        // A `$urltransform` with no value, one naming modifiers the crate
        // would ignore or widen, one carrying another family, a stage that
        // does not parse, and a removal value that means nothing: nothing
        // half-runs.
        let fe = cosmetic_engine(
            "||shop.test^$urltransform\n\
             ||shop.test^$urltransform=/-a/-b/,$to=other.test\n\
             ||shop.test^$urltransform=/-a/-b/,$method=PUT\n\
             ||shop.test^$urltransform=/-a/-b/,$replace=/x/y/\n\
             ||shop.test^$urltransform=bad-stage\n\
             ||shop.test^$removeparam=~\n",
        );
        assert_eq!(fe.url_rules_count(), 0);
        assert!(url_of(&fe, "https://shop.test/go-a", "document").is_none());
    }

    /// The header plan one request gets, the way the HTTPS path asks for it: a
    /// document is its own source, a subresource stands on the page that asked.
    fn header_of(fe: &FilterEngine, url: &str, kind: &str) -> Option<HeaderEdit> {
        let source = if kind == "document" {
            url
        } else {
            "https://page.test/"
        };
        fe.header_edit(url, source, kind, "GET")
    }

    #[test]
    fn csp_values_are_appended_and_domain_scoped() {
        // The real list shapes: one policy per rule, `domain=` scoping it to
        // the sites the lists meant, the value travelling as written.
        let fe = cosmetic_engine(
            "$csp=script-src 'self' 'unsafe-inline',domain=thumbs.pro\n\
             ||video.test^$csp=worker-src 'none'\n",
        );
        assert!(fe.has_header_rules());
        assert_eq!(fe.header_rules_count(), 2);
        assert_eq!(fe.url_rules_count(), 0);
        let edit =
            header_of(&fe, "https://thumbs.pro/watch", "document").expect("the rule fires");
        assert_eq!(
            edit.csp,
            vec!["script-src 'self' 'unsafe-inline'".to_string()]
        );
        assert_eq!(edit.rules.len(), 1);
        // The domain option scopes the rule to that page: another site is none
        // of its business.
        assert!(header_of(&fe, "https://other.test/watch", "document").is_none());
        let edit = header_of(&fe, "https://video.test/player", "script").expect("the rule fires");
        assert_eq!(edit.csp, vec!["worker-src 'none'".to_string()]);
        assert!(edit.permissions.is_empty() && edit.remove_response.is_empty());
    }

    #[test]
    fn csp_exceptions_cancel_by_value_and_by_family() {
        // A valued exception cancels exactly the rule whose value it repeats,
        // the way the ag-base and easylist pairs interact.
        let fe = cosmetic_engine(
            "||video.test^$csp=worker-src 'none'\n\
             ||video.test^$csp=frame-ancestors 'none'\n\
             @@||video.test^$csp=worker-src 'none'\n",
        );
        let edit =
            header_of(&fe, "https://video.test/player", "document").expect("one rule stands");
        assert_eq!(edit.csp, vec!["frame-ancestors 'none'".to_string()]);
        assert_eq!(edit.rules.len(), 1);
        // One with no value cancels the whole family for the page it names.
        let fe = cosmetic_engine(
            "||video.test^$csp=worker-src 'none'\n\
             @@||video.test^$csp\n",
        );
        assert!(header_of(&fe, "https://video.test/player", "document").is_none());
        // The page the exception names is what scopes it.
        let fe = cosmetic_engine(
            "||video.test^$csp=worker-src 'none'\n\
             @@||other.test^$csp\n",
        );
        assert!(header_of(&fe, "https://video.test/player", "document").is_some());
    }

    #[test]
    fn permissions_rules_speak_to_their_own_scope() {
        // The real tracking-protection shapes: every document loses the
        // interest-group APIs, and the shopify allowlist cancels one rule on
        // the pages it names, and only there.
        let fe = cosmetic_engine(
            "/.*/$permissions=join-ad-interest-group=(),document\n\
             /.*/$permissions=browsing-topics=(),document\n\
             @@||shop.test/authentication/$permissions=browsing-topics=()\n",
        );
        let edit = header_of(&fe, "https://shop.test/authentication/login", "document")
            .expect("the other rule fires");
        assert_eq!(
            edit.permissions,
            vec!["join-ad-interest-group=()".to_string()]
        );
        let edit = header_of(&fe, "https://other.test/", "document").expect("both fire here");
        assert_eq!(
            edit.permissions,
            vec![
                "join-ad-interest-group=()".to_string(),
                "browsing-topics=()".to_string()
            ]
        );
        // A frame is not a document: a rule that does not ask for frames never
        // reaches into one...
        assert!(header_of(&fe, "https://other.test/frame", "subdocument").is_none());
        // ...and a rule that asks for frames never reaches a document.
        let fe = cosmetic_engine("||frame.test^$permissions=geolocation=(),subdocument\n");
        assert!(header_of(&fe, "https://frame.test/frame", "subdocument").is_some());
        assert!(header_of(&fe, "https://frame.test/", "document").is_none());
    }

    #[test]
    fn permissions_separators_are_normalised_for_the_header() {
        // The lists write several policies with `|` or an escaped comma; the
        // header itself uses commas.
        let fe = cosmetic_engine(
            "$domain=news.test,permissions=geolocation=()|camera=()\n\
             ||news.test^$permissions=usb=()\\,serial=()\n",
        );
        let edit = header_of(&fe, "https://news.test/", "document").expect("both rules fire");
        assert_eq!(
            edit.permissions,
            vec![
                "geolocation=(),camera=()".to_string(),
                "usb=(),serial=()".to_string()
            ]
        );
    }

    #[test]
    fn removeheader_names_are_lowercased_and_keep_their_direction() {
        let fe = cosmetic_engine(
            "||go.xlivrdr.com^$removeheader=Location\n\
             ||api.test^$removeheader=request:X-Requested-With\n",
        );
        assert!(fe.has_header_rules());
        assert_eq!(fe.header_rules_count(), 2);
        assert!(!fe.has_url_rules());
        let edit = header_of(&fe, "https://go.xlivrdr.com/abc", "document").expect("fires");
        assert_eq!(edit.remove_response, vec!["location".to_string()]);
        assert!(edit.remove_request.is_empty());
        let edit = header_of(&fe, "https://api.test/v1", "xmlhttprequest").expect("fires");
        assert_eq!(edit.remove_request, vec!["x-requested-with".to_string()]);
        assert!(edit.remove_response.is_empty());
    }

    #[test]
    fn header_rules_the_engine_cannot_run_are_dropped() {
        // `report-*` turns a `$csp` value into an observer rather than a
        // policy, `$header` is a shape this engine does not implement,
        // forbidden or colon-carrying `$removeheader` names cannot be touched,
        // and a blocking rule with no value says nothing: nothing half-runs.
        let fe = cosmetic_engine(
            "||video.test^$csp=default-src 'self'; report-uri https://x.test/collect\n\
             ||video.test^$csp=worker-src 'none',$header=set-cookie:/x/\n\
             ||video.test^$removeheader=content-type\n\
             ||video.test^$removeheader=request:dnt:1\n\
             ||video.test^$permissions\n\
             ||video.test^$removeheader\n",
        );
        assert!(!fe.has_header_rules());
        assert_eq!(fe.header_rules_count(), 0);
        assert!(header_of(&fe, "https://video.test/", "document").is_none());
    }

    #[test]
    fn badfilter_cancels_modifier_rules_across_lists() {
        // The ag-base rule cancels the easylist copy: `$badfilter` compares
        // option names, not values, and the scan runs over every list before
        // any of them applies.
        let fe = engine(vec![
            temp_list(
                "cancel-a.txt",
                "||thegay.test^$csp=default-src 'self' *.ahcdn.com,badfilter\n",
                ListFormat::Standard,
                11,
            ),
            temp_list(
                "cancel-b.txt",
                "||thegay.test^$csp=default-src 'self' *.other.com\n",
                ListFormat::Standard,
                12,
            ),
        ]);
        assert!(!fe.has_header_rules());
        assert_eq!(fe.header_rules_count(), 0);
        assert!(header_of(&fe, "https://thegay.test/", "document").is_none());
        // A `$removeheader` badfilter only cancels its own family.
        let fe = cosmetic_engine(
            "||video.test^$removeheader=location\n\
             ||video.test^$csp=worker-src 'none'\n\
             ||video.test^$removeheader=location,badfilter\n",
        );
        let edit = header_of(&fe, "https://video.test/", "document").expect("the csp rule stands");
        assert!(edit.remove_response.is_empty());
        assert_eq!(edit.csp, vec!["worker-src 'none'".to_string()]);
    }

    #[test]
    fn repeated_header_values_are_appended_once() {
        // The lists repeat each other; each value reaches the header once, and
        // a repeated rule does not count twice.
        let fe = cosmetic_engine(
            "||video.test^$csp=worker-src 'none'\n\
             ||video.test^$csp=worker-src 'none'\n\
             ||video.test^$removeheader=Location\n\
             ||video.test^$removeheader=location\n",
        );
        let edit = header_of(&fe, "https://video.test/", "document").expect("fires");
        assert_eq!(edit.csp, vec!["worker-src 'none'".to_string()]);
        assert_eq!(edit.remove_response, vec!["location".to_string()]);
        assert_eq!(edit.rules.len(), 2, "one per distinct value");
    }

    /// The cookie names the rules take off one request, the way the HTTPS path
    /// asks about them.
    fn dropped(fe: &FilterEngine, url: &str, names: &[&str]) -> Vec<String> {
        let names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
        fe.cookie_plan(url, "https://page.test/", "GET")
            .and_then(|plan| plan.dropped(&names))
            .map(|edit| edit.drop)
            .unwrap_or_default()
    }

    #[test]
    fn cookie_values_match_by_name_regexp_or_everything() {
        // The three shapes the lists write: an exact name, a `/regexp/`
        // (compiled like the reference's `new RegExp`), and no value at all,
        // which is every cookie.
        let fe = cosmetic_engine("||shop.test^$cookie=dropme\n");
        assert!(fe.has_cookie_rules());
        assert_eq!(fe.cookie_rules_count(), 1);
        assert!(!fe.has_url_rules() && !fe.has_header_rules());
        assert_eq!(
            dropped(&fe, "https://shop.test/", &["dropme", "keepme"]),
            vec!["dropme"]
        );
        // The name is exact and case-sensitive: `$cookie=ID` never names `id`.
        let fe = cosmetic_engine("||shop.test^$cookie=ID\n");
        assert_eq!(dropped(&fe, "https://shop.test/", &["id", "ID"]), vec!["ID"]);

        let fe = cosmetic_engine("||shop.test^$cookie=/^trac/\n");
        assert_eq!(
            dropped(&fe, "https://shop.test/", &["tracker_1", "other"]),
            vec!["tracker_1"]
        );
        // The regexp is a search, the way `RegExp.test` reads one.
        let fe = cosmetic_engine("||shop.test^$cookie=/k$/\n");
        assert_eq!(
            dropped(&fe, "https://shop.test/", &["bk", "kb"]),
            vec!["bk"]
        );

        // No value: every cookie is named. No pattern either, so the rule is
        // answered without asking the probe engine at all.
        let fe = cosmetic_engine("$cookie\n");
        assert_eq!(fe.cookie_rules_count(), 1);
        assert_eq!(
            dropped(&fe, "https://any.test/x", &["a", "b"]),
            vec!["a", "b"]
        );
    }

    #[test]
    fn cookie_allowlist_has_the_last_word() {
        // An exception among cookie rules is a rule of its own, not a
        // cancellation folded into the blocking rule: it protects the cookies
        // its own matcher names, whatever the rules' order.
        for body in [
            "||shop.test^$cookie=/^trac/\n@@||shop.test^$cookie=tracker_1\n",
            "@@||shop.test^$cookie=tracker_1\n||shop.test^$cookie=/^trac/\n",
        ] {
            let fe = cosmetic_engine(body);
            assert_eq!(fe.cookie_rules_count(), 2);
            assert_eq!(
                dropped(&fe, "https://shop.test/", &["tracker_1", "tracker_2"]),
                vec!["tracker_2"],
                "{body:?}"
            );
        }
        // A page that does not match the exception keeps losing the cookie.
        let fe = cosmetic_engine(
            "||shop.test^$cookie=dropme\n@@||other.test^$cookie=dropme\n",
        );
        assert_eq!(
            dropped(&fe, "https://shop.test/", &["dropme"]),
            vec!["dropme"]
        );
    }

    #[test]
    fn cookie_rules_follow_their_request_options() {
        // A pattern scopes the rule to the requests it names; `$domain=`
        // scopes it to the pages ours stand on.
        let fe = cosmetic_engine("||shop.test/cart^$cookie=dropme\n");
        assert!(dropped(&fe, "https://shop.test/home", &["dropme"]).is_empty());
        assert_eq!(
            dropped(&fe, "https://shop.test/cart", &["dropme"]),
            vec!["dropme"]
        );
        let fe = cosmetic_engine("$cookie=dropme,domain=shop.test\n");
        let names = vec!["dropme".to_string()];
        let hits = |source: &str| {
            fe.cookie_plan("https://api.test/x", source, "GET")
                .and_then(|plan| plan.dropped(&names))
                .is_some()
        };
        assert!(hits("https://shop.test/"));
        assert!(!hits("https://other.test/"));
    }

    #[test]
    fn cookie_values_the_engine_cannot_run_are_dropped() {
        // A `;maxAge` above zero or a `;sameSite` turns the rule into a
        // *modifying* one this engine does not modify with, an unknown `;`
        // part is a value the reference refuses with it, and a regexp the
        // regex crate cannot run cannot name a cookie: nothing half-runs.
        let fe = cosmetic_engine(
            "||shop.test^$cookie=keep;maxAge=30\n\
             ||shop.test^$cookie=keep;sameSite=None\n\
             ||shop.test^$cookie=keep;part=value\n\
             ||shop.test^$cookie=/[/\n",
        );
        assert!(!fe.has_cookie_rules());
        assert_eq!(fe.cookie_rules_count(), 0);
        assert!(dropped(&fe, "https://shop.test/", &["keep"]).is_empty());
        // `maxAge` reads its leading whole number, and zero is no
        // modification at all — the rule stands.
        let fe = cosmetic_engine("||shop.test^$cookie=keep;maxAge=0\n");
        assert_eq!(fe.cookie_rules_count(), 1);
        assert_eq!(
            dropped(&fe, "https://shop.test/", &["keep"]),
            vec!["keep"]
        );
        // A value that merely looks like a regexp is a literal name: `/foo/i`
        // is not a flag-carrying regexp, it is a cookie named that way.
        let fe = cosmetic_engine("||shop.test^$cookie=/foo/i\n");
        assert_eq!(fe.cookie_rules_count(), 1);
        assert_eq!(
            dropped(&fe, "https://shop.test/", &["/foo/i", "foo"]),
            vec!["/foo/i"]
        );
        // A type makes the probe line impossible to write (a `$csp` carries
        // none) and no real rule names one: the rule is dropped.
        let fe = cosmetic_engine("||shop.test^$cookie=dropme,script\n");
        assert!(!fe.has_cookie_rules());
    }

    #[test]
    fn cookie_badfilter_cancels_cookie_rules_across_lists() {
        let fe = engine(vec![
            temp_list(
                "cancel-cookie-a.txt",
                "||shop.test^$cookie=dropme,badfilter\n",
                ListFormat::Standard,
                13,
            ),
            temp_list(
                "cancel-cookie-b.txt",
                "||shop.test^$cookie=dropme\n",
                ListFormat::Standard,
                14,
            ),
        ]);
        assert!(!fe.has_cookie_rules());
        assert!(dropped(&fe, "https://shop.test/", &["dropme"]).is_empty());
        // A badfilter whose own value is unreadable still cancels: the
        // reference checks the marker before it reads the modifier.
        let fe = cosmetic_engine(
            "||shop.test^$cookie=dropme\n\
             ||shop.test^$cookie=dropme;maxAge=30,badfilter\n",
        );
        assert!(!fe.has_cookie_rules());
    }

    /// The `$jsonprune` plan covering one request, the way the HTTPS path asks
    /// about it.
    fn prunes(fe: &FilterEngine, url: &str, source: &str, kind: &str) -> Option<JsonprunePlan> {
        fe.jsonprune_plan(url, source, kind, "GET")
    }

    #[test]
    fn jsonprune_rules_edit_the_json_bodies_they_cover() {
        let fe = cosmetic_engine("||api.test/graphql^$jsonprune=\\$.ads\n");
        assert!(fe.has_jsonprune_rules());
        assert_eq!(fe.jsonprune_rules_count(), 1);
        // A `$jsonprune` rule is not a URL, header or cookie rule, and it
        // edits instead of blocking.
        assert!(!fe.has_url_rules() && !fe.has_header_rules() && !fe.has_cookie_rules());
        let plan = prunes(&fe, "https://api.test/graphql", "https://page.test/", "xmlhttprequest")
            .expect("the rule covers the request");
        let (body, applied) = plan
            .apply(br#"{"ads": [1, 2], "keep": 3}"#)
            .expect("the item goes");
        assert_eq!(String::from_utf8(body).expect("utf8"), r#"{"keep":3}"#);
        assert_eq!(applied.join("; "), "||api.test/graphql^$jsonprune=\\$.ads");
        // Nothing selected, nothing written: the plan says so.
        let plan = prunes(&fe, "https://api.test/graphql", "https://page.test/", "xmlhttprequest")
            .expect("the rule covers the request");
        assert!(plan.apply(br#"{"keep": 3}"#).is_none());
        // The pattern scopes the rule to the requests it names.
        assert!(
            prunes(&fe, "https://api.test/other", "https://page.test/", "xmlhttprequest").is_none()
        );
    }

    #[test]
    fn jsonprune_applies_the_rules_in_the_reference_order() {
        // The reference sorts the matching rules lexicographically by text and
        // applies each to the last one's result; `$.a` runs before `$.z`.
        let fe = cosmetic_engine("||api.test^$jsonprune=\\$.z\n||api.test^$jsonprune=\\$.a\n");
        let plan = prunes(&fe, "https://api.test/x", "https://page.test/", "xmlhttprequest")
            .expect("both rules cover the request");
        let (body, applied) = plan
            .apply(br#"{"z": 1, "a": 2, "keep": 3}"#)
            .expect("both items go");
        assert_eq!(String::from_utf8(body).expect("utf8"), r#"{"keep":3}"#);
        assert_eq!(
            applied.join("; "),
            "||api.test^$jsonprune=\\$.a; ||api.test^$jsonprune=\\$.z"
        );
    }

    #[test]
    fn jsonprune_takes_the_request_types_the_reference_allows() {
        // The reference pairs `$jsonprune` with `$xmlhttprequest`; the live
        // lists also spell `all`, every type by definition.
        let fe = cosmetic_engine("||api.test^$jsonprune=\\$.ads,xmlhttprequest\n");
        assert!(prunes(&fe, "https://api.test/x", "https://page.test/", "xmlhttprequest").is_some());
        assert!(prunes(&fe, "https://api.test/x", "https://page.test/", "script").is_none());
        let fe = cosmetic_engine("||api.test^$jsonprune=\\$.ads,all\n");
        assert!(prunes(&fe, "https://api.test/x", "https://page.test/", "document").is_some());
        // Party and domain options are crate options and stay.
        let fe = cosmetic_engine("||api.test^$jsonprune=\\$.ads,~third-party\n");
        assert!(prunes(&fe, "https://api.test/x", "https://api.test/", "xmlhttprequest").is_some());
        assert!(prunes(&fe, "https://api.test/x", "https://other.test/", "xmlhttprequest").is_none());
        let fe = cosmetic_engine("||api.test^$jsonprune=\\$.ads,domain=page.test\n");
        assert!(prunes(&fe, "https://api.test/x", "https://page.test/", "xmlhttprequest").is_some());
        assert!(prunes(&fe, "https://api.test/x", "https://other.test/", "xmlhttprequest").is_none());
        // A type the compatibility list does not carry — negated or not —
        // would make the probe answer a question the list did not ask.
        for spec in ["\\$.ads,script", "\\$.ads,~xmlhttprequest", "\\$.ads,subdocument"] {
            let fe = cosmetic_engine(&format!("||api.test^$jsonprune={spec}\n"));
            assert!(!fe.has_jsonprune_rules(), "{spec} must be dropped");
        }
    }

    #[test]
    fn jsonprune_exceptions_fold_into_the_rules_they_cancel() {
        let url = "https://api.test/graphql";
        // A bare exception cancels every rule of the family for the responses
        // its pattern names.
        let fe = cosmetic_engine("||api.test^$jsonprune=\\$.ads\n@@||api.test^$jsonprune\n");
        assert!(fe.has_jsonprune_rules());
        assert!(prunes(&fe, url, "https://page.test/", "xmlhttprequest").is_none());
        // A rule the exception's pattern does not name still applies.
        let fe = cosmetic_engine("||api.test^$jsonprune=\\$.ads\n@@||other.test^$jsonprune\n");
        assert!(prunes(&fe, url, "https://page.test/", "xmlhttprequest").is_some());
        // A valued exception cancels the rules repeating its value, and only
        // them.
        let fe =
            cosmetic_engine("||api.test^$jsonprune=\\$.ads\n@@||api.test^$jsonprune=\\$.ads\n");
        assert!(prunes(&fe, url, "https://page.test/", "xmlhttprequest").is_none());
        let fe = cosmetic_engine(
            "||api.test^$jsonprune=\\$.ads\n@@||api.test^$jsonprune=\\$.trackers\n",
        );
        assert!(prunes(&fe, url, "https://page.test/", "xmlhttprequest").is_some());
    }

    #[test]
    fn jsonprune_badfilter_cancels_across_lists() {
        let fe = engine(vec![
            temp_list(
                "cancel-jsonprune-a.txt",
                "||api.test^$jsonprune=\\$.ads,badfilter\n",
                ListFormat::Standard,
                15,
            ),
            temp_list(
                "cancel-jsonprune-b.txt",
                "||api.test^$jsonprune=\\$.ads\n",
                ListFormat::Standard,
                16,
            ),
        ]);
        assert!(!fe.has_jsonprune_rules());
        assert_eq!(fe.jsonprune_rules_count(), 0);
        assert!(prunes(&fe, "https://api.test/x", "https://page.test/", "xmlhttprequest").is_none());
    }

    #[test]
    fn jsonprune_values_the_engine_cannot_run_are_dropped() {
        // Script expressions, a trailing `..`: the dialect has neither, and a
        // rule that cannot run does not run half-way.
        let fe = cosmetic_engine(
            "||api.test^$jsonprune=\\$[?(@.x == 1)]\n\
             ||api.test^$jsonprune=\\$.a..\n",
        );
        assert!(!fe.has_jsonprune_rules());
        assert_eq!(fe.jsonprune_rules_count(), 0);
    }

    #[test]
    fn page_exceptions_switch_jsonprune_off() {
        // `$jsonprune` is content modification: a page that switched it off
        // keeps its responses intact.
        let url = "https://api.test/graphql";
        for exception in ["@@||quiet.test^$content\n", "@@||quiet.test^$replace\n"] {
            let fe = cosmetic_engine(&format!("||api.test^$jsonprune=\\$.ads\n{exception}"));
            assert!(
                prunes(&fe, url, "https://quiet.test/", "xmlhttprequest").is_none(),
                "{exception}"
            );
            assert!(prunes(&fe, url, "https://loud.test/", "xmlhttprequest").is_some());
        }
    }

    /// The `$hls` plan covering one request, the way the HTTPS path asks
    /// about it.
    fn trims(fe: &FilterEngine, url: &str, source: &str, kind: &str) -> Option<HlsPlan> {
        fe.hls_plan(url, source, kind, "GET")
    }

    #[test]
    fn hls_rules_edit_the_playlists_they_cover() {
        let fe = cosmetic_engine("||stream.test^$hls=preroll\n");
        assert!(fe.has_hls_rules());
        assert_eq!(fe.hls_rules_count(), 1);
        // An `$hls` rule is not a URL, header or cookie rule, and it edits
        // instead of blocking.
        assert!(!fe.has_url_rules() && !fe.has_header_rules() && !fe.has_cookie_rules());
        let url = "https://stream.test/hls/index.m3u8";
        let plan = trims(&fe, url, "https://page.test/", "xmlhttprequest")
            .expect("the rule covers the request");
        let (body, applied) = plan
            .apply(b"#EXTM3U\n#EXTINF:10,\npreroll.ts\n#EXTINF:10,\n01.ts\n")
            .expect("the segment goes");
        assert_eq!(
            String::from_utf8(body).expect("utf8"),
            "#EXTM3U\n#EXTINF:10,\n01.ts\n"
        );
        assert_eq!(applied, vec!["||stream.test^$hls=preroll"]);
        // A URL the rule does not name has no plan.
        assert!(trims(
            &fe,
            "https://other.test/hls/index.m3u8",
            "https://page.test/",
            "xmlhttprequest"
        )
        .is_none());
    }

    #[test]
    fn hls_takes_the_request_types_the_reference_allows() {
        let url = "https://stream.test/hls/index.m3u8";
        // The reference pairs `$hls` with `$xmlhttprequest`; the live lists
        // also spell `all`, every type by definition.
        let fe = cosmetic_engine("||stream.test^$hls=preroll,xmlhttprequest\n");
        assert!(trims(&fe, url, "https://page.test/", "xmlhttprequest").is_some());
        assert!(trims(&fe, url, "https://page.test/", "script").is_none());
        let fe = cosmetic_engine("||stream.test^$hls=preroll,all\n");
        assert!(trims(&fe, url, "https://page.test/", "document").is_some());
        // Party and domain options are crate options and stay.
        let fe = cosmetic_engine("||stream.test^$hls=preroll,~third-party\n");
        assert!(trims(&fe, url, "https://stream.test/", "xmlhttprequest").is_some());
        assert!(trims(&fe, url, "https://other.test/", "xmlhttprequest").is_none());
        let fe = cosmetic_engine("||stream.test^$hls=preroll,domain=page.test\n");
        assert!(trims(&fe, url, "https://page.test/", "xmlhttprequest").is_some());
        assert!(trims(&fe, url, "https://other.test/", "xmlhttprequest").is_none());
        // A type the compatibility list does not carry — negated or not —
        // would make the probe answer a question the list did not ask.
        for spec in ["preroll,script", "preroll,~xmlhttprequest", "preroll,subdocument"] {
            let fe = cosmetic_engine(&format!("||stream.test^$hls={spec}\n"));
            assert!(!fe.has_hls_rules(), "{spec} must be dropped");
        }
    }

    #[test]
    fn hls_exceptions_fold_into_the_rules_they_cancel() {
        let url = "https://stream.test/hls/index.m3u8";
        // A bare exception cancels every rule of the family for the responses
        // its pattern names.
        let fe = cosmetic_engine("||stream.test^$hls=preroll\n@@||stream.test^$hls\n");
        assert!(fe.has_hls_rules());
        assert!(trims(&fe, url, "https://page.test/", "xmlhttprequest").is_none());
        // A rule the exception's pattern does not name still applies.
        let fe = cosmetic_engine("||stream.test^$hls=preroll\n@@||other.test^$hls\n");
        assert!(trims(&fe, url, "https://page.test/", "xmlhttprequest").is_some());
        // A valued exception cancels the rules repeating its value, and only
        // them.
        let fe = cosmetic_engine("||stream.test^$hls=preroll\n@@||stream.test^$hls=preroll\n");
        assert!(trims(&fe, url, "https://page.test/", "xmlhttprequest").is_none());
        let fe = cosmetic_engine("||stream.test^$hls=preroll\n@@||stream.test^$hls=midroll\n");
        assert!(trims(&fe, url, "https://page.test/", "xmlhttprequest").is_some());
    }

    #[test]
    fn hls_badfilter_cancels_across_lists() {
        let fe = engine(vec![
            temp_list(
                "cancel-hls-a.txt",
                "||stream.test^$hls=preroll,badfilter\n",
                ListFormat::Standard,
                17,
            ),
            temp_list(
                "cancel-hls-b.txt",
                "||stream.test^$hls=preroll\n",
                ListFormat::Standard,
                18,
            ),
        ]);
        assert!(!fe.has_hls_rules());
        assert_eq!(fe.hls_rules_count(), 0);
        assert!(trims(
            &fe,
            "https://stream.test/hls/index.m3u8",
            "https://page.test/",
            "xmlhttprequest"
        )
        .is_none());
    }

    #[test]
    fn hls_match_case_shapes_both_forms() {
        // A pattern-form value cannot run `$match-case` — the crate refuses
        // the option on anything but a full regex — so the rule is dropped
        // rather than run wider than the list wrote it.
        let fe = cosmetic_engine("||stream.test^$hls=preroll,match-case\n");
        assert!(!fe.has_hls_rules());
        assert_eq!(fe.hls_rules_count(), 0);
        // A regexp answers for its own case, so the option adds nothing and
        // the rule stays.
        let fe = cosmetic_engine("||stream.test^$hls=/preroll/,match-case\n");
        assert!(fe.has_hls_rules());
        let plan = trims(
            &fe,
            "https://stream.test/hls/index.m3u8",
            "https://page.test/",
            "xmlhttprequest",
        )
        .expect("the rule covers the request");
        assert!(plan
            .apply(b"#EXTM3U\n#EXTINF:10,\npreroll.ts\n")
            .is_some());
    }

    #[test]
    fn hls_values_the_engine_cannot_run_are_dropped() {
        // A regexp without its closing `/`, an unknown flag, a lookahead the
        // Rust regex crate cannot compile, a pattern holding a literal `$`:
        // a rule that cannot run does not run half-way.
        let fe = cosmetic_engine(
            "||stream.test^$hls=/preroll\n\
             ||stream.test^$hls=/preroll/q\n\
             ||stream.test^$hls=/\\.ts(?=x)/\n\
             ||stream.test^$hls=price\\$5\n",
        );
        assert!(!fe.has_hls_rules());
        assert_eq!(fe.hls_rules_count(), 0);
    }

    #[test]
    fn page_exceptions_switch_hls_off() {
        // `$hls` is content modification: a page that switched it off keeps
        // its playlists intact.
        let url = "https://stream.test/hls/index.m3u8";
        for exception in ["@@||quiet.test^$content\n", "@@||quiet.test^$replace\n"] {
            let fe = cosmetic_engine(&format!("||stream.test^$hls=preroll\n{exception}"));
            assert!(
                trims(&fe, url, "https://quiet.test/", "xmlhttprequest").is_none(),
                "{exception}"
            );
            assert!(trims(&fe, url, "https://loud.test/", "xmlhttprequest").is_some());
        }
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
    fn path_rules_wait_for_their_page() {
        let fe = cosmetic_engine(
            "! Title: paths\n\
             shop.test##.always\n\
             [$path=/tv]shop.test##.only-tv\n\
             [$path]shop.test##.only-main\n",
        );
        assert!(fe.has_path_rules());

        let tv = fe.cosmetic_resources("https://shop.test/tv");
        assert!(
            tv.style_rules
                .iter()
                .any(|(s, css)| s == ".only-tv" && css == "display: none !important"),
            "{:?}",
            tv.style_rules
        );
        // The path rule rides the inline payload; the per-host stylesheet is
        // for rules the whole site shares.
        assert!(!tv.hide_selectors.iter().any(|s| s == ".only-tv"));
        assert!(tv.hide_selectors.iter().any(|s| s == ".always"));

        // `$path` matches the query string as well.
        let query = fe.cosmetic_resources("https://shop.test/tv?video=1");
        assert!(query.style_rules.iter().any(|(s, _)| s == ".only-tv"));

        // Another path of the same site: neither path rule applies.
        let other = fe.cosmetic_resources("https://shop.test/other");
        assert!(other.style_rules.is_empty(), "{:?}", other.style_rules);
        assert!(other.hide_selectors.iter().any(|s| s == ".always"));

        // The main page: the bare `[$path]` rule, and only it.
        let main = fe.cosmetic_resources("https://shop.test/");
        assert!(main.style_rules.iter().any(|(s, _)| s == ".only-main"));
        assert!(!main.style_rules.iter().any(|(s, _)| s == ".only-tv"));
        // A query string does not make the main page another page.
        let main_query = fe.cosmetic_resources("https://shop.test/?utm_source=x");
        assert!(main_query.style_rules.iter().any(|(s, _)| s == ".only-main"));

        // The rule's own domain still has to match.
        let sibling = fe.cosmetic_resources("https://other.test/tv");
        assert!(!sibling.style_rules.iter().any(|(s, _)| s == ".only-tv"));

        // A hostname ask has no page behind it: no path rule may answer.
        let host = fe.cosmetic_resources_for_host("shop.test");
        assert!(host.style_rules.is_empty(), "{:?}", host.style_rules);
        assert!(host.hide_selectors.iter().any(|s| s == ".always"));
    }

    #[test]
    fn path_rules_carry_scriptlets_and_procedural_actions() {
        let fe = cosmetic_engine(
            "[$path=/tv]shop.test#%#//scriptlet('set-constant', 'adblock', 'false')\n\
             [$path=/tv]shop.test#?#.late:has-text(Sponsored)\n",
        );
        let tv = fe.cosmetic_resources("https://shop.test/tv");
        assert!(!tv.scriptlets.is_empty(), "{:?}", tv.scriptlets);
        assert!(
            tv.procedural.iter().any(|p| p.contains("has-text")),
            "{:?}",
            tv.procedural
        );
        let other = fe.cosmetic_resources("https://shop.test/other");
        assert!(other.scriptlets.is_empty());
        assert!(other.procedural.is_empty());
    }

    #[test]
    fn path_rule_exceptions_apply_inside_the_path_engine() {
        let fe = cosmetic_engine(
            "shop.test#@#.only-tv\n\
             [$path=/tv]shop.test##.only-tv\n\
             [$path=/tv]shop.test##.stays\n",
        );
        let tv = fe.cosmetic_resources("https://shop.test/tv");
        assert!(!tv.style_rules.iter().any(|(s, _)| s == ".only-tv"));
        assert!(tv.style_rules.iter().any(|(s, _)| s == ".stays"));
    }

    #[test]
    fn path_bracket_domains_apply_like_classic_domains() {
        let fe = cosmetic_engine("[$domain=alpha.test|beta.test]##.promo\n");
        // No `$path`: the bracket goes away and the rule is an ordinary one.
        assert!(!fe.has_path_rules());
        assert!(fe
            .cosmetic_resources("https://alpha.test/")
            .hide_selectors
            .iter()
            .any(|s| s == ".promo"));
        assert!(fe
            .cosmetic_resources("https://sub.beta.test/x")
            .hide_selectors
            .iter()
            .any(|s| s == ".promo"));
        assert!(!fe
            .cosmetic_resources("https://gamma.test/")
            .hide_selectors
            .iter()
            .any(|s| s == ".promo"));
    }

    #[test]
    fn path_bracket_domain_moves_onto_the_rule() {
        let fe = cosmetic_engine(
            "[$domain=facebook.com,path=/gaming]#$#body > .AdBox { height: 0 !important; }\n",
        );
        let gaming = fe.cosmetic_resources("https://facebook.com/gaming");
        assert!(
            gaming
                .style_rules
                .iter()
                .any(|(s, css)| s == "body > .AdBox" && css.contains("height")),
            "{:?}",
            gaming.style_rules
        );
        // The domain from the bracket still scopes the rule.
        let other_path = fe.cosmetic_resources("https://facebook.com/feed");
        assert!(other_path.style_rules.is_empty());
        let other_site = fe.cosmetic_resources("https://twitter.com/gaming");
        assert!(other_site.style_rules.is_empty());
    }

    #[test]
    fn path_brackets_that_cannot_be_honored_are_dropped() {
        let fe = cosmetic_engine(
            "[$app=org.example.app]##.a\n\
             [$url=/x]##.b\n\
             [$domain=/re/]##.c\n\
             [$domain=x.com,path=/y]y.com##.d\n\
             [$path=/x,path=/y]##.e\n\
             [$path=||x.com]##.f\n",
        );
        assert!(!fe.has_path_rules());
        let compiled = fe.compiled();
        let path = compiled.path_cosmetics.as_ref().expect("scan");
        assert_eq!(path.dropped, 6);
        assert!(path.rules.is_empty());
        // None of them may fall back to the engine as plain rules.
        let res = fe.cosmetic_resources("https://y.com/y");
        assert!(res.hide_selectors.is_empty(), "{:?}", res.hide_selectors);
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

