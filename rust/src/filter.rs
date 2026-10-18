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
use adblock::resources::Resource;
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
/// Cosmetic work a page's exception rules switch off.
///
/// The engine itself knows `$generichide` only; the rest are scanned out of
/// the list text by [`scan_cosmetic_exceptions`] and applied when a page asks
/// for its cosmetic resources. See [`FilterEngine::cosmetic_switches_for`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CosmeticSwitches {
    /// `$elemhide` (alias `$ehide`): no element hiding, specific or generic.
    pub elemhide: bool,
    /// `$specifichide` (alias `$shide`): no rules bound to the page's own
    /// domain. Generic rules stay.
    pub specifichide: bool,
    /// `$jsinject`: no scriptlets.
    pub jsinject: bool,
}

impl CosmeticSwitches {
    fn merge(&mut self, other: CosmeticSwitches) {
        self.elemhide |= other.elemhide;
        self.specifichide |= other.specifichide;
        self.jsinject |= other.jsinject;
    }
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
}

#[derive(Clone, Copy)]
struct CachedDecision {
    blocked: bool,
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
        // page asks for its cosmetic resources.
        engine.use_resources(scriptlet_resources().iter().cloned());
        let memory_bytes = engine.serialize().len();
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let compiled = Arc::new(Compiled {
            engine,
            generation,
            memory_bytes,
            sources,
            rule_count,
            cosmetic_switches: cosmetic_exceptions.resolve(),
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
            };
        }

        let verdict = evaluate(&compiled, host);
        self.cache.write().unwrap().insert(
            key,
            CachedDecision {
                blocked: verdict.blocked,
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
                // `$document` unblocks the whole site; AdGuard spells it out
                // as `$elemhide` + `$jsinject` (+ request-level modifiers this
                // app does not implement).
                "document" | "doc" => {
                    switches.elemhide = true;
                    switches.specifichide = true;
                    switches.jsinject = true;
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
fn url_host(url: &str) -> &str {
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

    let (rule_text, source) = match &result.filter {
        Some(info) => {
            let source = info
                .source_location
                .as_ref()
                .map(|loc| loc.source_index);
            (info.raw_line.clone(), source)
        }
        None => (None, None),
    };
    let list = source
        .and_then(|idx| compiled.sources.iter().find(|s| s.source_index == idx))
        .cloned();

    let category = list
        .as_ref()
        .map(|l| l.category)
        .unwrap_or(categorise(rule_text.as_deref(), host));

    HostVerdict {
        blocked: true,
        rule_text,
        list_name: list.map(|l| l.name),
        category,
    }
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
             ||block.test^$elemhide\n",
            &mut scan,
        );
        assert_eq!(
            scan.cancels.len(),
            1,
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
        };
        assert_eq!(on("doc.test"), all);
        assert_eq!(on("doc-alias.test"), all);
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

