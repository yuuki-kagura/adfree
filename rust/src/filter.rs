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
use adblock::engine::Engine;
use adblock::lists::{FilterFormat, FilterSet, ParseOptions, RuleTypes};
use adblock::request::Request;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

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

        for list in lists.iter().filter(|l| l.enabled) {
            let Some(path) = &list.local_path else { continue };
            match std::fs::read(path) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(text) => {
                        let format = match list.format {
                            ListFormat::Hosts => FilterFormat::Hosts,
                            ListFormat::Standard => FilterFormat::Standard,
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
            let record = set.add_filter_list(joined, ParseOptions::default());
            sources.push(SourceMapEntry {
                source_index: record.source_index as u32,
                list_id: 0,
                name: "User Custom Filter".to_string(),
                category: CAT_CUSTOM,
            });
        }

        let engine = Engine::new_with_filter_set(set);
        let memory_bytes = engine.serialize().len();
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let compiled = Arc::new(Compiled {
            engine,
            generation,
            memory_bytes,
            sources,
            rule_count,
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
}
