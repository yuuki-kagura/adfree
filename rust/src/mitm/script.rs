//! User-supplied scripts.
//!
//! The user writes JS and we keep the list; when serving `/adfree-user.js` (or
//! inlining), the scripts are stitched into one file. Keeping it separate means
//! one `<script src>` per response instead of full bodies inside the HTML.
//!
//! Tampermonkey metadata is honoured here, in the core, so every platform gets
//! the same `@match` / `@include` / `@exclude` / `@run-at` behaviour. The whole
//! list is still served as one file; a small guard at the start of each script
//! decides whether that script may run on the current page.

use regex::RegexBuilder;

/// Caps so a client never downloads too much. The byte cap has to fit real
/// userscripts (AdGuard Extra is ~560 KB), so it is generous; the combined
/// body is only rebuilt when the list changes, not per request.
pub const MAX_SCRIPTS: usize = 32;
pub const MAX_SCRIPT_BYTES: usize = 1024 * 1024;

/// Metadata limits: a broken header must not turn one download into thousands
/// of regexes. Real userscripts use a handful of patterns.
const MAX_META_PATTERNS: usize = 64;
const MAX_PATTERN_LEN: usize = 2048;
const MAX_REQUIRES: usize = 8;
const META_SCAN_LINES: usize = 256;

/// One user script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserScript {
    pub name: String,
    pub body: String,
    pub enabled: bool,
}

/// Script list plus serving state.
#[derive(Clone, Debug)]
pub struct ScriptSet {
    scripts: Vec<ScriptEntry>,
    /// Master switch for script injection.
    pub enabled: bool,
    /// URL mà ta dùng trong `<script src>`.
    pub serve_path: String,
    /// The stitched body, rebuilt when the list changes: serving a page must
    /// never pay for re-stitching the scripts on every request.
    combined: std::sync::Arc<str>,
}

/// A script with its metadata already parsed and compiled.
#[derive(Clone, Debug)]
pub(crate) struct ScriptEntry {
    name: String,
    body: String,
    enabled: bool,
    meta: ScriptMeta,
}

#[derive(Clone, Debug)]
struct ScriptMeta {
    run_at: RunAt,
    noframes: bool,
    /// `@match` + `@include` patterns, combined as OR.
    allow: Vec<CompiledPattern>,
    exclude: Vec<CompiledPattern>,
    /// At least one `@match` / `@include` line was present. If every line is
    /// invalid, the script must not fall back to running everywhere.
    restrict: bool,
    version: String,
    /// Dependencies we cannot execute; kept only to warn in the page console.
    requires: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunAt {
    Start,
    End,
    Idle,
}

#[derive(Clone, Debug)]
struct CompiledPattern {
    /// Rust `regex` source. JS receives it through `new RegExp(...)`.
    source: String,
}

impl CompiledPattern {
    fn new(source: String) -> Option<Self> {
        // Validate once here. The page gets the source and runs the same
        // expression; the Rust copy is only needed by the unit tests.
        RegexBuilder::new(&source)
            .case_insensitive(true)
            .build()
            .ok()?;
        Some(Self { source })
    }

    #[cfg(test)]
    fn matches(&self, url: &str) -> bool {
        RegexBuilder::new(&self.source)
            .case_insensitive(true)
            .build()
            .map(|regex| regex.is_match(url))
            .unwrap_or(false)
    }

    fn test_js(&self) -> String {
        format!(
            "new RegExp({}, 'i').test(__adfree_href)",
            js_string(&self.source)
        )
    }
}

impl ScriptMeta {
    fn parse(body: &str) -> Self {
        let mut meta = Self {
            run_at: RunAt::Start,
            noframes: false,
            allow: Vec::new(),
            exclude: Vec::new(),
            restrict: false,
            version: String::new(),
            requires: Vec::new(),
        };

        let mut in_header = false;
        let mut saw_header = false;
        let mut run_at = None;

        for line in body.lines().take(META_SCAN_LINES) {
            let line = line.trim_start_matches('\u{feff}').trim_start();
            if !in_header {
                if line.starts_with("// ==UserScript==") {
                    in_header = true;
                    saw_header = true;
                }
                continue;
            }
            if line.starts_with("// ==/UserScript==") {
                break;
            }
            let Some(rest) = line.strip_prefix("//") else {
                continue;
            };
            let Some((key, value)) = split_key_value(rest.trim_start()) else {
                continue;
            };
            let value = value.trim();
            match key {
                "@match" => {
                    meta.restrict = true;
                    if let Some(pattern) = compile_match(value) {
                        push_pattern(&mut meta.allow, pattern);
                    }
                }
                "@include" => {
                    meta.restrict = true;
                    if let Some(pattern) = compile_glob(value) {
                        push_pattern(&mut meta.allow, pattern);
                    }
                }
                "@exclude" => {
                    if let Some(pattern) = compile_glob(value) {
                        push_pattern(&mut meta.exclude, pattern);
                    }
                }
                "@run-at" => run_at = Some(match value {
                    "document-start" => RunAt::Start,
                    "document-end" => RunAt::End,
                    "document-idle" => RunAt::Idle,
                    _ => continue,
                }),
                "@noframes" => meta.noframes = true,
                "@version" if meta.version.is_empty() => meta.version = value.to_string(),
                "@require" if !value.is_empty() && meta.requires.len() < MAX_REQUIRES => {
                    meta.requires.push(value.to_string());
                }
                _ => {}
            }
        }

        meta.run_at = run_at.unwrap_or(if saw_header {
            // Tampermonkey's default; headerless AdFree scripts keep the old
            // document-start behaviour so the built-in Extra still wins races.
            RunAt::Idle
        } else {
            RunAt::Start
        });
        meta
    }

    /// Test hook for the Rust side; the page runs the same sources in JS.
    #[cfg(test)]
    fn matches(&self, url: &str) -> bool {
        if self.exclude.iter().any(|p| p.matches(url)) {
            return false;
        }
        if self.allow.is_empty() {
            return !self.restrict;
        }
        self.allow.iter().any(|p| p.matches(url))
    }

    fn predicate_js(&self) -> String {
        let allow = if self.allow.is_empty() {
            if self.restrict {
                "false".to_string()
            } else {
                "true".to_string()
            }
        } else {
            self.allow
                .iter()
                .map(CompiledPattern::test_js)
                .collect::<Vec<_>>()
                .join(" || ")
        };

        if self.exclude.is_empty() {
            allow
        } else {
            let exclude = self
                .exclude
                .iter()
                .map(CompiledPattern::test_js)
                .collect::<Vec<_>>()
                .join(" || ");
            format!("!({exclude}) && ({allow})")
        }
    }
}

fn push_pattern(patterns: &mut Vec<CompiledPattern>, pattern: CompiledPattern) {
    if patterns.len() < MAX_META_PATTERNS {
        patterns.push(pattern);
    }
}

/// Split `@key value` without allocating. Metadata keys never contain spaces.
fn split_key_value(line: &str) -> Option<(&str, &str)> {
    if !line.starts_with('@') {
        return None;
    }
    let end = line
        .char_indices()
        .find(|(_, c)| c.is_whitespace())
        .map(|(i, _)| i)
        .unwrap_or(line.len());
    Some((&line[..end], line[end..].trim()))
}

/// Compile a Tampermonkey `@match` pattern:
/// `<scheme>://<host><path>`, with `*` allowed for scheme, a leading `*.` in
/// the host, and anywhere in the path.
fn compile_match(pattern: &str) -> Option<CompiledPattern> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN {
        return None;
    }
    let (scheme, rest) = pattern.split_once("://")?;
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "*" => "https?",
        "http" => "http",
        "https" => "https",
        _ => return None,
    };
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/*"),
    };
    if host.is_empty() {
        return None;
    }

    let mut source = String::with_capacity(pattern.len() + 32);
    source.push('^');
    source.push_str(scheme);
    source.push_str("://");
    source.push_str(&host_regex(host)?);
    source.push_str(&path_regex(path));
    source.push('$');
    CompiledPattern::new(source)
}

/// Compile a Greasemonkey `@include` / `@exclude` glob against the full URL.
fn compile_glob(pattern: &str) -> Option<CompiledPattern> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN {
        return None;
    }
    let mut source = String::with_capacity(pattern.len() + 4);
    source.push('^');
    append_wildcard_regex(&mut source, pattern, ".*");
    source.push('$');
    CompiledPattern::new(source)
}

fn host_regex(host: &str) -> Option<String> {
    if host == "*" {
        return Some("[^/]+".to_string());
    }
    let (prefix, rest) = match host.strip_prefix("*.") {
        Some(rest) => ("(?:[^/]+\\.)*", rest),
        None => ("", host),
    };
    if rest.is_empty() || rest.contains('*') {
        // Match patterns only allow a wildcard for the whole host or as the
        // leading `*.` label. Anything else is invalid; treating it as a glob
        // would make `https://*example.com/*` match `evilexample.com`.
        return None;
    }
    let mut out = String::from(prefix);
    append_wildcard_regex(&mut out, rest, "[^/]*");
    Some(out)
}

fn path_regex(path: &str) -> String {
    let mut out = String::new();
    append_wildcard_regex(&mut out, path, ".*");
    // A `@match` path is matched without the query/fragment. Unless the user
    // ended it with `*`, allow either to follow the exact path.
    if !path.ends_with('*') {
        out.push_str("(?:[?#].*)?");
    }
    out
}

/// Append `pattern` to `out`, escaping literals and replacing `*` with
/// `wildcard`. Keeping one implementation means `@match` and `@include`
/// cannot disagree about dots, slashes or query characters.
fn append_wildcard_regex(out: &mut String, pattern: &str, wildcard: &str) {
    let mut literal = String::new();
    for ch in pattern.chars() {
        if ch == '*' {
            if !literal.is_empty() {
                out.push_str(&regex::escape(&literal));
                literal.clear();
            }
            out.push_str(wildcard);
        } else {
            literal.push(ch);
        }
    }
    if !literal.is_empty() {
        out.push_str(&regex::escape(&literal));
    }
}

/// A JS double-quoted string. Metadata is ASCII in practice, but escape
/// controls anyway so a weird pattern cannot break the served file.
fn js_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl ScriptEntry {
    fn new(script: UserScript) -> Self {
        let meta = ScriptMeta::parse(&script.body);
        Self {
            name: script.name,
            body: script.body,
            enabled: script.enabled,
            meta,
        }
    }

    /// One self-contained IIFE: match guard, runtime shims, try/catch, and the
    /// user's body. The guard means a page only pays for the bodies selected
    /// for it at execution time, even though the file is shared.
    fn wrapped_js(&self) -> String {
        let mut out = String::with_capacity(self.body.len() + 512);
        out.push_str("/* ");
        out.push_str(&comment_name(&self.name));
        out.push_str(" */\n");
        out.push_str("(function(){\n");
        out.push_str("var __adfree_href=location.href;\n");
        out.push_str("if(!(");
        out.push_str(&self.meta.predicate_js());
        out.push_str("))return;\n");
        if self.meta.noframes {
            out.push_str("if(window.top!==window)return;\n");
        }
        out.push_str("var __adfree_run=function(){\n");
        // GM shims that are safe to provide in page context. A script that
        // asked for GM_xmlhttpRequest/GM_setValue will still not find them;
        // those need a real browser-extension sandbox, not a page injection.
        out.push_str("var unsafeWindow=window;\n");
        out.push_str("var GM_info={scriptHandler:'AdFree',version:'1.0',script:{name:");
        out.push_str(&js_string(&self.name));
        out.push_str(",version:");
        out.push_str(&js_string(&self.meta.version));
        out.push_str("}};\n");
        out.push_str(
            "var GM_addStyle=function(css){var s=document.createElement('style');s.textContent=css;(document.head||document.documentElement).appendChild(s);return s;};\n",
        );
        out.push_str(
            "var GM_log=function(){try{console.log.apply(console,arguments);}catch(e){}};\n",
        );
        if !self.meta.requires.is_empty() {
            out.push_str("console.warn('AdFree: @require is not supported by this userscript host');\n");
        }
        out.push_str("try{\n");
        out.push_str(&self.body);
        out.push_str("\n}catch(e){console.warn('AdFree script failed: '+");
        out.push_str(&js_string(&self.name));
        out.push_str(",e);}\n");
        out.push_str("};\n");

        match self.meta.run_at {
            RunAt::Start => out.push_str("__adfree_run();\n"),
            RunAt::End => out.push_str(
                "if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',__adfree_run,{once:true});}else{__adfree_run();}\n",
            ),
            RunAt::Idle => out.push_str(
                "var __adfree_idle=function(){if(window.requestIdleCallback){window.requestIdleCallback(__adfree_run);}else{window.setTimeout(__adfree_run,1);}};if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',__adfree_idle,{once:true});}else{__adfree_idle();}\n",
            ),
        }
        out.push_str("})();\n");
        out
    }
}

fn comment_name(name: &str) -> String {
    let mut out = name.replace("*/", "* /").replace(['\n', '\r'], " ");
    if out.len() > 80 {
        let mut end = 80;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push('…');
    }
    out
}

impl Default for ScriptSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptSet {
    pub fn new() -> Self {
        ScriptSet {
            scripts: Vec::new(),
            enabled: false,
            serve_path: "/adfree-user.js".to_string(),
            combined: std::sync::Arc::from(""),
        }
    }

    /// Replace the whole list, dropping over-long or empty entries.
    pub fn replace_all(&mut self, scripts: Vec<UserScript>) -> usize {
        self.scripts = scripts
            .into_iter()
            .filter(|s| !s.name.is_empty() && !s.body.is_empty())
            .filter(|s| s.body.len() <= MAX_SCRIPT_BYTES)
            .take(MAX_SCRIPTS)
            .map(ScriptEntry::new)
            .collect();
        self.recompute();
        self.scripts.len()
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.recompute();
    }

    /// Rebuilds the served body; called after any state change.
    fn recompute(&mut self) {
        self.combined = if self.is_enabled() {
            std::sync::Arc::from(self.build_combined().as_str())
        } else {
            std::sync::Arc::from("")
        };
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.scripts.is_empty()
    }

    pub(crate) fn scripts(&self) -> &[ScriptEntry] {
        &self.scripts
    }

    /// Combined JS body (enabled scripts only).
    pub fn combined_js(&self) -> String {
        self.combined.to_string()
    }

    /// Cheap handle for the serving path: cloning an `Arc` beats copying a
    /// megabyte of JS for every intercepted connection.
    pub fn combined_arc(&self) -> std::sync::Arc<str> {
        std::sync::Arc::clone(&self.combined)
    }

    /// Stitches the enabled scripts into one body wrapped per script.
    fn build_combined(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("/* AdFree user scripts */\n");
        out.push_str("(function(){'use strict';\n");
        for script in self.scripts.iter().filter(|s| s.enabled) {
            out.push_str(&script.wrapped_js());
        }
        out.push_str("})();\n");
        out
    }

    /// The path we answer when a client requests it.
    pub fn serve_path(&self) -> &str {
        &self.serve_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(name: &str, body: &str) -> UserScript {
        UserScript {
            name: name.to_string(),
            body: body.to_string(),
            enabled: true,
        }
    }

    fn meta(body: &str) -> ScriptMeta {
        ScriptMeta::parse(body)
    }

    #[test]
    fn disabled_set_serves_nothing() {
        let mut set = ScriptSet::new();
        set.replace_all(vec![script("a", "console.log(1)")]);
        assert!(set.combined_js().is_empty());
        set.set_enabled(true);
        assert!(set.is_enabled());
        assert!(set.combined_js().contains("console.log(1)"));
    }

    #[test]
    fn replaces_the_whole_list() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script("one", "let a = 1;"), script("two", "let b = 2;")]);
        assert_eq!(set.scripts().len(), 2);
        set.replace_all(vec![script("only", "let c = 3;")]);
        assert_eq!(set.scripts().len(), 1);
        let js = set.combined_js();
        assert!(js.contains("let c = 3;"));
        assert!(!js.contains("let a = 1;"));
    }

    #[test]
    fn filters_empty_and_huge_scripts() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        let huge = "x".repeat(MAX_SCRIPT_BYTES + 1);
        set.replace_all(vec![
            UserScript { name: String::new(), body: "a".into(), enabled: true },
            UserScript { name: "empty".into(), body: String::new(), enabled: true },
            UserScript { name: "big".into(), body: huge, enabled: true },
            script("ok", "let ok = true;"),
        ]);
        assert_eq!(set.scripts().len(), 1);
        assert_eq!(set.scripts()[0].name, "ok");
    }

    #[test]
    fn caps_the_number_of_scripts() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        let many: Vec<UserScript> = (0..40)
            .map(|i| script(&format!("s{i}"), "console.log(1)"))
            .collect();
        set.replace_all(many);
        assert_eq!(set.scripts().len(), MAX_SCRIPTS);
    }

    #[test]
    fn only_enabled_scripts_are_combined() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![
            script("on", "let on = 1;"),
            UserScript {
                name: "off".into(),
                body: "let off = 1;".into(),
                enabled: false,
            },
        ]);
        let js = set.combined_js();
        assert!(js.contains("let on = 1;"));
        assert!(!js.contains("let off = 1;"));
    }

    #[test]
    fn combined_js_wraps_each_script_in_try_catch() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script("broken", "this is not javascript ((")]);
        let js = set.combined_js();
        assert!(js.contains("try{"), "every script must be isolated");
        assert!(js.contains("}catch(e)"));
        assert!(js.contains("'use strict'"));
    }

    #[test]
    fn serve_path_defaults_to_a_stable_url() {
        let set = ScriptSet::new();
        assert_eq!(set.serve_path(), "/adfree-user.js");
    }

    #[test]
    fn combined_arc_follows_state_changes() {
        let mut set = ScriptSet::new();
        assert!(set.combined_arc().is_empty());
        set.replace_all(vec![script("a", "let a = 1;")]);
        assert!(set.combined_arc().is_empty(), "master switch still off");
        set.set_enabled(true);
        assert!(set.combined_arc().contains("let a = 1;"));
        set.set_enabled(false);
        assert!(set.combined_arc().is_empty());
    }

    #[test]
    fn match_and_exclude_choose_pages() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://*.example.com/*\n\
             // @exclude https://ads.example.com/*\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://example.com/"));
        assert!(meta.matches("https://www.example.com/page"));
        assert!(!meta.matches("http://www.example.com/page"));
        assert!(!meta.matches("https://ads.example.com/banner"));
        assert!(!meta.matches("https://example.org/"));
    }

    #[test]
    fn match_all_covers_http_and_https_pages() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match *://*/*\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://example.com/"));
        assert!(meta.matches("http://example.com/path?q=1"));
        assert!(!meta.matches("ftp://example.com/"));
    }

    #[test]
    fn a_path_match_accepts_a_query_unless_it_ends_with_star() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://example.com/watch\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://example.com/watch"));
        assert!(meta.matches("https://example.com/watch?v=1"));
        assert!(!meta.matches("https://example.com/watch/extra"));
    }

    #[test]
    fn includes_are_or_with_matches() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://a.example/*\n\
             // @include https://b.example/*\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://a.example/page"));
        assert!(meta.matches("https://b.example/page"));
        assert!(!meta.matches("https://c.example/page"));
    }

    #[test]
    fn include_globs_can_name_a_fragment_of_the_url() {
        let meta = meta(
            "// ==UserScript==\n\
             // @include *wikipedia.org*\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://vi.wikipedia.org/wiki/Trang_ch%E1%BB%A7"));
        assert!(!meta.matches("https://example.org/"));
    }

    #[test]
    fn a_header_without_patterns_keeps_legacy_run_everywhere() {
        let meta = meta(
            "// ==UserScript==\n\
             // @name only-a-name\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://anything.example/"));
        assert_eq!(meta.run_at, RunAt::Idle);
    }

    #[test]
    fn no_header_keeps_document_start_and_runs_everywhere() {
        let meta = meta("console.log('plain')");
        assert!(meta.matches("https://anything.example/"));
        assert_eq!(meta.run_at, RunAt::Start);
    }

    #[test]
    fn run_at_and_noframes_are_parsed() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://example.com/*\n\
             // @run-at document-end\n\
             // @noframes\n\
             // ==/UserScript==\n",
        );
        assert_eq!(meta.run_at, RunAt::End);
        assert!(meta.noframes);
    }

    #[test]
    fn an_invalid_match_does_not_open_the_script_everywhere() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match not-a-match-pattern\n\
             // ==/UserScript==\n",
        );
        assert!(!meta.matches("https://example.com/"));
    }

    #[test]
    fn a_wildcard_inside_the_host_is_not_a_suffix_glob() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://*example.com/*\n\
             // ==/UserScript==\n",
        );
        assert!(!meta.matches("https://evilexample.com/"));
        assert!(!meta.matches("https://example.com/"));
    }

    #[test]
    fn match_guard_and_run_at_reach_the_served_body() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script(
            "scoped",
            "// ==UserScript==\n\
             // @match https://example.com/*\n\
             // @run-at document-end\n\
             // ==/UserScript==\n\
             window.__scoped = true;",
        )]);
        let js = set.combined_js();
        assert!(js.contains("new RegExp("), "the match source must reach the page");
        assert!(js.contains("document.readyState==='loading'"));
        assert!(js.contains("DOMContentLoaded"));
        assert!(js.contains("window.__scoped = true;"));
    }

    #[test]
    fn document_idle_uses_request_idle_callback() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script(
            "idle",
            "// ==UserScript==\n\
             // @match *://*/*\n\
             // ==/UserScript==\n\
             window.__idle = true;",
        )]);
        let js = set.combined_js();
        assert!(js.contains("requestIdleCallback"));
    }
}
