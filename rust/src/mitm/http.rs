//! Inject user scripts and cosmetic rules into HTML responses.
//!
//! The MITM stage only reads HTTP/1.1 bodies today, so this stays deliberately
//! simple: find the header/body boundary, check `content-type`, inject before
//! `</head>` or `</body>`, and **rewrite `content-length`** — without that the
//! client would hang or truncate the body.
//!
//! Injection also rewrites `content-security-policy` rather than dropping it:
//! the injected tags carry a fresh nonce per response and the policy learns
//! that nonce, so a strict `script-src` no longer blocks the hiding rules and
//! the page keeps the protection it asked for. AdGuard injects with a nonce
//! for the same reason; the difference is what happens to the rest of the
//! header, which stays as the origin wrote it.

/// Outcome of handling one response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Nothing to do (not HTML, or the body is too large).
    Skip,
    /// Script injected; a new body is returned.
    Injected,
    /// Response carries `content-encoding` (gzip/br), so injection is skipped.
    Compressed,
    /// No safe insertion point was found.
    NoInsertPoint,
}

/// Largest HTML body we are willing to rewrite, to bound memory use.
pub const MAX_INJECTABLE_BODY: usize = 512 * 1024;

/// Caps on the class/id tokens scanned out of one body, so the generic-rule
/// lookup stays bounded on pathological pages.
const MAX_CLASS_TOKENS: usize = 800;
const MAX_ID_TOKENS: usize = 400;
const MAX_TOKEN_LEN: usize = 64;

/// Random bytes behind one page's nonce. CSP wants at least 128 bits; 18 bytes
/// (144 bits) leaves room for the hex encoding to stay a single attribute.
const NONCE_BYTES: usize = 18;

/// A fresh nonce for one injected page.
///
/// Per response, not per session: a value that repeats would let a script that
/// learned it once run under another page's policy later. `ring`'s system RNG
/// is the one the TLS stack already builds on; the fallback exists only so a
/// broken OS RNG cannot take the hiding rules down with it.
pub fn new_nonce() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; NONCE_BYTES];
    match SystemRandom::new().fill(&mut bytes) {
        Ok(()) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        Err(_) => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("{nanos:036x}")
        }
    }
}

/// The `nonce="…"` attribute for an injected tag; empty when there is no nonce.
pub(crate) fn nonce_attr(nonce: &str) -> String {
    if nonce.is_empty() {
        String::new()
    } else {
        format!(" nonce=\"{}\"", escape_attr(nonce))
    }
}

/// Builds the `<script src=...>` tag for `src`, with the page's nonce so a
/// strict `script-src` lets it through.
pub fn script_tag(src: &str, defer: bool, nonce: &str) -> String {
    let escaped = escape_attr(src);
    let nonce = nonce_attr(nonce);
    if defer {
        format!("<script{nonce} src=\"{escaped}\" defer></script>")
    } else {
        format!("<script{nonce} src=\"{escaped}\"></script>")
    }
}

/// Builds the `<link rel="stylesheet">` tag for an injected stylesheet.
///
/// The id is what lets the page runtime notice the page dropping the element
/// and put it back; the browser then reuses its cached copy. Chromium honours
/// a nonce on `<link rel=stylesheet>` (checked in the JS test suite), so the
/// tag carries one when the policy asks for it.
pub fn style_link_tag(href: &str, id: &str, nonce: &str) -> String {
    format!(
        "<link rel=\"stylesheet\" id=\"{}\" href=\"{}\"{}>",
        escape_attr(id),
        escape_attr(href),
        nonce_attr(nonce)
    )
}

/// Chèn `snippet` (raw HTML: script tags, inline data) vào `body`.
///
/// The caller decides what goes in — the injector only finds the insertion
/// point and keeps the document well-formed.
pub fn inject_snippet(body: &[u8], snippet: &[u8]) -> (Vec<u8>, Decision) {
    if body.is_empty() || body.len() > MAX_INJECTABLE_BODY {
        return (body.to_vec(), Decision::Skip);
    }
    // Only inject when the body clearly looks like HTML.
    if !looks_like_html(body) {
        return (body.to_vec(), Decision::Skip);
    }
    let Some(pos) = injection_point(body) else {
        return (body.to_vec(), Decision::NoInsertPoint);
    };
    let mut out = Vec::with_capacity(body.len() + snippet.len());
    out.extend_from_slice(&body[..pos]);
    out.extend_from_slice(snippet);
    out.extend_from_slice(&body[pos..]);
    (out, Decision::Injected)
}

/// True when the bytes look like a document that is safe to edit: a real
/// `<!doctype`/`<html` somewhere in the head of the file.
fn looks_like_html(body: &[u8]) -> bool {
    let lower: Vec<u8> = body.iter().map(|b| b.to_ascii_lowercase()).collect();
    if find_ci(&lower, b"<!doc").is_some() {
        return true;
    }
    // `"<html>"` alone misses the common shape: the tag usually carries
    // attributes (`<html lang="en">`), and real pages have been seen with no
    // doctype at all (news.ycombinator.com).
    find_ci(&lower, b"<html").is_some_and(|at| {
        matches!(
            lower.get(at + 5),
            Some(b'>' | b' ' | b'\t' | b'\r' | b'\n' | b'/')
        )
    })
}

/// Where a snippet goes: as early inside `<head>` as the document allows,
/// else at `</head>`, else at `</body>`, else just past `<body ...>`.
///
/// The early spot mirrors what AdGuard does on real pages (measured on
/// vnexpress.net, dantri.com.vn and genk.vn: its script tags land right after
/// the head's metadata block and before the first element that can fetch or
/// render). Hiding rules arriving before the page's own resources is what
/// keeps ads from painting first.
///
/// Three guards keep the move safe:
///
/// * the anchor only moves ahead of a non-metadata element once a
///   `<meta charset>` (or `http-equiv` declaration) has been seen — a
///   multi-kilobyte payload must never push the document's encoding
///   declaration past the parser's 1024-byte prescan window;
/// * a `<meta http-equiv="content-security-policy">` anchors in its own right:
///   it governs everything parsed after it (measured: it is not retroactive),
///   so the snippet lands in front of it and stays outside the policy the page
///   set for itself. A *header* policy is answered in `csp_with_nonce`;
/// * an incomplete tag (`<link rel=...` cut by the buffer) decides nothing,
///   so the streaming injector waits instead of splitting it in half.
///
/// `None` means the document has not shown a home for it yet.
pub fn injection_point(body: &[u8]) -> Option<usize> {
    if let Some(pos) = head_snippet_point(body) {
        return Some(pos);
    }
    let lower: Vec<u8> = body.iter().map(|b| b.to_ascii_lowercase()).collect();
    // Prefer </head>, then </body>, then <body ...>.
    for needle in [b"</head>".as_slice(), b"</body>".as_slice()] {
        if let Some(pos) = find_ci(&lower, needle) {
            return Some(pos);
        }
    }
    let pos = find_ci(&lower, b"<body")?;
    // Insert right after the closing <body ...> tag — if it is complete.
    lower[pos..]
        .iter()
        .position(|b| *b == b'>')
        .map(|i| pos + i + 1)
}

/// The early-in-`<head>` anchor, when the buffer already answers for it.
///
/// Elements that cannot render or fetch (`<title>`, `<meta>`, `<base>`, and
/// comments) are stepped over; the anchor is the first element that can, or
/// `</head>` when the head holds nothing else. Until an encoding declaration
/// has been seen the scan only records it and keeps walking, so the anchor
/// can still move to the first element after it.
fn head_snippet_point(body: &[u8]) -> Option<usize> {
    let mut i = head_open_end(body)?;
    let mut charset_seen = false;
    while i < body.len() {
        if body[i] != b'<' {
            i += 1;
            continue;
        }
        let rest = &body[i..];
        if starts_with_ci(rest, b"<!--") {
            // Comments never anchor: AdGuard lands after them too.
            let end = find_ci_bytes(&rest[4..], b"-->")?;
            i += 4 + end + 3;
            continue;
        }
        if starts_with_ci(rest, b"<!") || starts_with_ci(rest, b"<?") {
            // A declaration or processing instruction runs to its `>`.
            let end = rest.iter().position(|b| *b == b'>')?;
            i += end + 1;
            continue;
        }
        let closing = starts_with_ci(rest, b"</");
        let at = if closing { 2 } else { 1 };
        let (name_len, name_done) = tag_name(&rest[at..]);
        if !name_done || name_len == 0 {
            // Cut mid-name, or a stray `<` in text: wait for more bytes.
            return None;
        }
        let end = rest.iter().position(|b| *b == b'>')?;
        let name = &rest[at..at + name_len];
        if closing {
            // `</head>` is the last chance: everything before it was metadata.
            if name.eq_ignore_ascii_case(b"head") {
                return Some(i);
            }
            i += end + 1;
            continue;
        }
        if name.eq_ignore_ascii_case(b"meta") {
            let tag = &rest[..end];
            if charset_seen && meta_is_csp(tag) {
                // The page's own policy starts here; the injected tags must not
                // be inside it. Before a charset declaration there is no room
                // to move (see the prescan rule above), so the walk keeps going.
                return Some(i);
            }
            if tag
                .windows(b"charset".len())
                .any(|w| w.eq_ignore_ascii_case(b"charset"))
            {
                charset_seen = true;
            }
            i += end + 1;
            continue;
        }
        if name.eq_ignore_ascii_case(b"title") || name.eq_ignore_ascii_case(b"base") {
            i += end + 1;
            continue;
        }
        if RAW_TEXT_ELEMENTS
            .iter()
            .any(|raw| name.eq_ignore_ascii_case(raw))
        {
            // Content of these may hold `<` bytes that are not tags; skipping
            // into it would anchor inside a script or a stylesheet.
            i = close_of_element(body, end + i, name)?;
            continue;
        }
        // The first element that can fetch or render. The payload may go in
        // front of it, but only once the encoding is spoken for.
        if charset_seen {
            return Some(i);
        }
        i += end + 1;
    }
    None
}

/// Elements whose content is not parsed as markup by the HTML parser (or is
/// treated as opaque for our purposes), so a `<` inside never starts a tag.
const RAW_TEXT_ELEMENTS: [&[u8]; 8] = [
    b"script",
    b"style",
    b"textarea",
    b"xmp",
    b"iframe",
    b"noframes",
    b"noscript",
    b"template",
];

/// The offset just past `</name>`, or `None` while it is still incoming.
fn close_of_element(body: &[u8], from: usize, name: &[u8]) -> Option<usize> {
    let mut search = from;
    while search < body.len() {
        let at = find_ci_bytes(&body[search..], b"</")? + search;
        let (name_len, name_done) = tag_name(&body[at + 2..]);
        if !name_done {
            return None;
        }
        if name_len == name.len() && body[at + 2..at + 2 + name_len].eq_ignore_ascii_case(name) {
            let end = body[at..].iter().position(|b| *b == b'>')? + at;
            return Some(end + 1);
        }
        search = at + 2;
    }
    None
}

/// The offset just past the opening `<head ...>` tag.
///
/// `<header>` is not a head: the name has to end at a delimiter.
fn head_open_end(body: &[u8]) -> Option<usize> {
    let mut search = 0;
    while search < body.len() {
        let at = find_ci_bytes(&body[search..], b"<head")? + search;
        let after = at + 5;
        match body.get(after) {
            Some(b) if b.is_ascii_whitespace() || *b == b'>' || *b == b'/' => {
                let end = body[after..].iter().position(|b| *b == b'>')?;
                return Some(after + end + 1);
            }
            Some(_) => search = after,
            None => return None,
        }
    }
    None
}

/// The element name right after `<` (or `</`), and whether the buffer held
/// its delimiter: an unfinished name decides nothing.
fn tag_name(bytes: &[u8]) -> (usize, bool) {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_alphanumeric() || b == b'-' {
            i += 1;
        } else {
            return (i, true);
        }
    }
    (i, false)
}

/// Case-insensitive byte search, for haystacks that arrive as they are.
fn find_ci_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn starts_with_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

/// Whether a `<meta …>` tag is a `http-equiv` CSP declaration.
///
/// Both attribute names are looked for anywhere in the tag, so attribute order
/// does not matter; a `content` value that merely mentions the string cannot
/// match, since `http-equiv` has to be there too.
fn meta_is_csp(tag: &[u8]) -> bool {
    find_ci_bytes(tag, b"http-equiv").is_some()
        && find_ci_bytes(tag, b"content-security-policy").is_some()
}

/// Offset just past the last complete tag: the fallback home for a snippet when
/// the document never shows a `</head>`/`</body>`/`<body`.
pub fn safe_injection_point(body: &[u8]) -> usize {
    match body.iter().rposition(|b| *b == b'>') {
        Some(i) => i + 1,
        None => 0,
    }
}

/// Injects a `<script src>` tag — the shape most callers and tests want.
pub fn inject_script(body: &[u8], src: &str) -> (Vec<u8>, Decision) {
    inject_snippet(body, script_tag(src, true, "").as_bytes())
}

/// Rewrites `content-security-policy` so everything we inject is allowed,
/// leaving the policy itself — and with it the page's own protection — in
/// place.
///
/// Three things have to get through, and not all of them take a nonce:
///
/// * the injected `<script>` and `<link rel="stylesheet">` tags, and the
///   `<style>` the runtime may build — these take `'nonce-…'`, which the page's
///   own scripts ignore;
/// * the runtime's `fetch` of the generic-rule lookup — `connect-src` has no
///   nonce-source, so there the origin (`host_source`) is the only way in.
///
/// Which shape a directive gets is decided per directive:
///
/// * a directive that does **not** lean on `'unsafe-inline'` gets
///   `'nonce-…'`, which our tags carry and the page's own scripts ignore;
/// * a directive that does lean on it gets `host_source` (our origin) instead.
///   Chromium ignores `'unsafe-inline'` as soon as the policy holds a nonce,
///   so adding one there would block the page's *own* inline scripts —
///   measured, not assumed. A directive that already carries a nonce or a
///   hash is past that point: its `'unsafe-inline'`, if any, is inert already,
///   and a nonce of ours changes nothing for the page.
///
/// `report-only` policies are diagnostics, not enforcement: they travel back
/// exactly as they came.
pub fn csp_with_nonce(headers: &[u8], nonce: &str, host_source: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(headers.len() + 64);
    for line in headers.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if !lower.starts_with(b"content-security-policy:") {
            out.extend_from_slice(line);
            continue;
        }
        let name_end = line.iter().position(|b| *b == b':').unwrap_or(0);
        let ending = line_ending(line);
        let value_end = line.len().saturating_sub(ending.len());
        if name_end >= value_end {
            out.extend_from_slice(line);
            continue;
        }
        let value = String::from_utf8_lossy(&line[name_end + 1..value_end]);
        out.extend_from_slice(&line[..name_end]);
        out.extend_from_slice(b": ");
        out.extend_from_slice(add_nonce_to_policy(value.trim(), nonce, host_source).as_bytes());
        out.extend_from_slice(ending.as_bytes());
    }
    out
}

/// One policy with the nonce (or the origin) added where it would block us.
fn add_nonce_to_policy(value: &str, nonce: &str, host_source: &str) -> String {
    let directives: Vec<&str> = value
        .split(';')
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .collect();
    if directives.is_empty() {
        return value.to_string();
    }
    let name_of = |d: &str| {
        d.split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let names: Vec<String> = directives.iter().map(|d| name_of(d)).collect();
    let has = |n: &str| names.iter().any(|x| x == n);
    // The specific directives win over `default-src`, and `-elem` wins over the
    // bare form: whichever of them is present is what a parser consults.
    let covered = |carrier: Carrier| match carrier {
        Carrier::Script => has("script-src") || has("script-src-elem"),
        Carrier::Style => has("style-src") || has("style-src-elem"),
        Carrier::Connect => has("connect-src"),
    };

    let mut out = String::with_capacity(value.len() + 64);
    for (i, directive) in directives.iter().enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        out.push_str(directive);
        let name = name_of(directive);
        let mut wanted: Vec<Carrier> = Vec::new();
        match name.as_str() {
            "script-src" | "script-src-elem" => wanted.push(Carrier::Script),
            "style-src" | "style-src-elem" => wanted.push(Carrier::Style),
            "connect-src" => wanted.push(Carrier::Connect),
            // Everything the specific directives leave uncovered falls back here.
            "default-src" => wanted.extend(CARRIERS.iter().copied().filter(|c| !covered(*c))),
            _ => {}
        }
        if wanted.is_empty() {
            continue;
        }
        let sources: Vec<&str> = directive.split_whitespace().skip(1).collect();
        let inline = sources
            .iter()
            .any(|s| s.eq_ignore_ascii_case("'unsafe-inline'"));
        let native_inline = sources
            .iter()
            .any(|s| s.eq_ignore_ascii_case("'strict-dynamic'") || is_nonce_or_hash(s));
        // A lone `default-src` carries several of our carriers at once: one
        // addition each, and never the same value twice.
        let mut additions: Vec<String> = Vec::new();
        for carrier in wanted {
            let addition = carrier.addition(inline && !native_inline, nonce, host_source);
            if !additions.contains(&addition) {
                additions.push(addition);
            }
        }
        for addition in additions {
            out.push_str(&addition);
        }
    }
    out
}

/// What the injected page needs the policy to allow.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Carrier {
    /// The inline payload, the runtime tag and the user-script tag.
    Script,
    /// The hiding stylesheet and the `<style>` element the runtime builds.
    Style,
    /// The runtime's `fetch` of the generic-rule lookup.
    Connect,
}

/// Every carrier, in the order their additions are written into a directive
/// that serves as the fallback for more than one of them.
const CARRIERS: [Carrier; 3] = [Carrier::Script, Carrier::Style, Carrier::Connect];

impl Carrier {
    /// The source expression that satisfies this carrier.
    ///
    /// `inline_only` is the page leaning on `'unsafe-inline'` with no nonce or
    /// hash of its own: a nonce of ours would silently switch that off, so the
    /// origin goes in instead — it satisfies our tags and leaves the page's own
    /// inline scripts alone.
    ///
    /// `Connect` has no element to hang a nonce on: `connect-src` has no
    /// nonce-source, so the origin is the only way in — and the runtime's
    /// lookup is a `fetch`, which nothing else reaches.
    fn addition(self, inline_only: bool, nonce: &str, host_source: &str) -> String {
        if inline_only || self == Carrier::Connect {
            format!(" {host_source}")
        } else {
            format!(" 'nonce-{nonce}'")
        }
    }
}

/// Whether a source expression is a nonce or a hash: a policy holding one of
/// these already ignores `'unsafe-inline'`, so a nonce of ours is free.
fn is_nonce_or_hash(source: &str) -> bool {
    let bare = source.trim_matches('\'').to_ascii_lowercase();
    ["nonce-", "sha256-", "sha384-", "sha512-"]
        .iter()
        .any(|prefix| bare.starts_with(prefix))
}

/// Class and id tokens used by an HTML body, for generic `##.class` rules.
///
/// A byte scan instead of a parser: one Aho-Corasick pass finds both
/// attribute names, then a value is recognised by name, `=`, and the same
/// quoting rules as before. False positives (a token inside a script or a
/// comment) are harmless: the lookup only ever returns rules that already
/// exist in the lists.
pub fn collect_class_id_tokens(body: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut classes = Vec::new();
    let mut ids = Vec::new();
    let mut seen_c = std::collections::HashSet::new();
    let mut seen_i = std::collections::HashSet::new();
    let matcher = class_id_matcher();
    let mut at = 0;
    while at < body.len() && (classes.len() < MAX_CLASS_TOKENS || ids.len() < MAX_ID_TOKENS) {
        let Some(hit) = matcher.find(aho_corasick::Input::new(body).span(at..body.len())) else {
            break;
        };
        let start = hit.start();
        // The name must start an attribute, not sit inside a word or another
        // attribute's name (`myid=`, `data-class=`).
        if start > 0 {
            let prev = body[start - 1];
            if prev.is_ascii_alphanumeric() || prev == b'-' || prev == b'_' {
                at = start + 1;
                continue;
            }
        }
        // Pattern order is what the matcher was built with: 0 = class, 1 = id.
        let (out, seen, cap) = if hit.pattern().as_usize() == 0 {
            (&mut classes, &mut seen_c, MAX_CLASS_TOKENS)
        } else {
            (&mut ids, &mut seen_i, MAX_ID_TOKENS)
        };
        at = match collect_attribute_value(body, hit.end(), out, seen, cap) {
            // Past the value: its bytes are text, not attribute names.
            Some(end) => end,
            None => start + 1,
        };
    }
    (classes, ids)
}

/// One `class`/`id` matcher for the whole process: ASCII-case-insensitive
/// and allocation-free per body.
fn class_id_matcher() -> &'static aho_corasick::AhoCorasick {
    static MATCHER: std::sync::OnceLock<aho_corasick::AhoCorasick> = std::sync::OnceLock::new();
    MATCHER.get_or_init(|| {
        aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(["class", "id"])
            .expect("a two-literal pattern set always builds")
    })
}

/// Reads the value of the attribute whose name just ended at `after_name`,
/// and returns the index just past it. `None` when there is no `=`: the
/// caller then resumes one byte in, as a plain scan would.
fn collect_attribute_value(
    body: &[u8],
    after_name: usize,
    out: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
    cap: usize,
) -> Option<usize> {
    let mut j = after_name;
    while j < body.len() && body[j] == b' ' {
        j += 1;
    }
    if j >= body.len() || body[j] != b'=' {
        return None;
    }
    j += 1;
    let mut quote = 0u8;
    if j < body.len() && (body[j] == b'"' || body[j] == b'\'') {
        quote = body[j];
        j += 1;
    }
    let start = j;
    while j < body.len() {
        let b = body[j];
        if (quote != 0 && b == quote) || (quote == 0 && (b == b' ' || b == b'>' || b == b'/')) {
            break;
        }
        if quote == 0 && (b == b'\n' || b == b'\r' || b == b'\t') {
            break;
        }
        if j - start > 256 {
            break;
        }
        j += 1;
    }
    if quote != 0 && j < body.len() {
        // Consume the closing quote.
        j += 1;
    }
    if out.len() >= cap {
        // The name's quota is full but (with two names in one scan) the
        // other's may not be: still resume past the value so its bytes are
        // not read as attribute names.
        return Some(j);
    }
    for token in body[start..j.min(body.len())]
        .split(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\''))
    {
        if token.is_empty() || token.len() > MAX_TOKEN_LEN {
            continue;
        }
        if let Ok(s) = std::str::from_utf8(token) {
            if seen.insert(s.to_string()) {
                out.push(s.to_string());
                if out.len() >= cap {
                    break;
                }
            }
        }
    }
    Some(j)
}

// ---------------------------------------------------------------- response shape

/// `content-encoding` of a response body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    Identity,
    Gzip,
    Deflate,
    /// `br`, `zstd`, ...: readable by the client but not by us.
    Other,
}

impl Encoding {
    /// The token for `content-encoding`, when the body is compressed at all.
    pub fn name(self) -> Option<&'static str> {
        match self {
            Encoding::Gzip => Some("gzip"),
            Encoding::Deflate => Some("deflate"),
            // An identity body has nothing to declare, and `Other` never
            // reaches a rewrite: a response is only edited when we can read it.
            Encoding::Identity | Encoding::Other => None,
        }
    }
}

/// The facts the proxy needs from one response head.
#[derive(Clone, Copy, Debug)]
pub struct ResponseHead {
    pub status: u16,
    pub html: bool,
    /// The body is text: the only kind a `$replace` rule ever looks at.
    pub text: bool,
    pub chunked: bool,
    pub encoding: Encoding,
    pub content_length: Option<usize>,
}

impl ResponseHead {
    /// 1xx, 204 and 304 carry no body: the head is the whole message even when
    /// a `content-length` is advertised.
    pub fn bodyless(&self) -> bool {
        (100..200).contains(&self.status) || self.status == 204 || self.status == 304
    }
}

/// Whether a media type names text a `$replace` rule may rewrite.
///
/// AdGuard modifies every text response and refuses media, images and objects;
/// the list here is that, minus the types no rule in the catalogue targets,
/// plus the HLS manifests some of them do.
fn content_type_is_text(mime: &str) -> bool {
    mime.starts_with("text/")
        || matches!(
            mime,
            "application/javascript"
                | "application/x-javascript"
                | "application/ecmascript"
                | "application/json"
                | "application/ld+json"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/rss+xml"
                | "application/atom+xml"
                | "application/x-mpegurl"
                | "application/vnd.apple.mpegurl"
                | "audio/mpegurl"
                | "audio/x-mpegurl"
        )
}

/// Parses a complete response head (up to and including the blank line).
pub fn parse_response_head(head: &[u8]) -> ResponseHead {
    let mut info = ResponseHead {
        status: 0,
        html: false,
        text: false,
        chunked: false,
        encoding: Encoding::Identity,
        content_length: None,
    };
    // `HTTP/1.1 200 OK`
    if let Some(line_end) = head.windows(2).position(|w| w == b"\r\n") {
        let status = String::from_utf8_lossy(&head[..line_end]);
        if let Some(code) = status.split(' ').nth(1) {
            info.status = code.parse().unwrap_or(0);
        }
    }
    for line in head.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"content-type:") {
            info.html = lower.windows(9).any(|w| w == b"text/html");
            let value = String::from_utf8_lossy(&lower);
            let mime = value
                .trim_start_matches("content-type:")
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            info.text = content_type_is_text(mime);
        } else if lower.starts_with(b"content-encoding:") {
            let value = String::from_utf8_lossy(&lower);
            let value = value.trim_start_matches("content-encoding:").trim();
            info.encoding = match value.split(',').next().map(str::trim).unwrap_or("") {
                "" | "identity" => Encoding::Identity,
                "gzip" | "x-gzip" => Encoding::Gzip,
                "deflate" => Encoding::Deflate,
                _ => Encoding::Other,
            };
        } else if lower.starts_with(b"transfer-encoding:") {
            info.chunked = lower.windows(7).any(|w| w == b"chunked");
        } else if lower.starts_with(b"content-length:") {
            let value = String::from_utf8_lossy(&lower);
            let value = value.trim_start_matches("content-length:").trim();
            info.content_length = value.parse().ok();
        }
    }
    info
}

/// Rewrites a request head that asks for HTML so the origin stops negotiating
/// encodings we cannot decode (`br`, `zstd`).
///
/// Keeps `gzip`/`deflate` in place: those are decoded, filtered and put back
/// compressed. `force` is for a request the lists matched with `$replace`:
/// the response is not a page, so the `accept` header says nothing, and the
/// body still has to be decodable — a header left with nothing to negotiate
/// asks for `gzip` rather than going away. Returns `None` when the buffer has
/// no complete head, no reason to drop anything, or nothing to drop.
pub fn drop_undecodable_encodings(buf: &[u8], force: bool) -> Option<Vec<u8>> {
    let end = head_end(buf)?;
    let head = &buf[..end];
    if !force && !head_accepts_html(head) {
        return None;
    }
    let mut changed = false;
    let mut out = Vec::with_capacity(head.len());
    for line in head.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"accept-encoding:") {
            let value = String::from_utf8_lossy(&lower);
            let value = value.trim_start_matches("accept-encoding:").trim();
            let kept: Vec<&str> = value
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty() && *t != "br" && *t != "zstd")
                .collect();
            if kept.len() == value.split(',').filter(|t| !t.trim().is_empty()).count() {
                continue; // nothing droppable
            }
            changed = true;
            if !kept.is_empty() {
                let name_end = line.iter().position(|b| *b == b':').unwrap_or(0);
                let name = String::from_utf8_lossy(&line[..name_end]).to_string();
                let ending = if line.ends_with(b"\r\n") {
                    "\r\n"
                } else {
                    "\n"
                };
                out.extend_from_slice(format!("{name}: {}{ending}", kept.join(", ")).as_bytes());
            } else if force {
                // Nothing left, and the header cannot simply go away: with no
                // `accept-encoding` at all the origin is free to pick anything,
                // including what could not be decoded. A `$replace` match is
                // usually not a page, so the browser never asked for gzip —
                // say it here.
                let name_end = line.iter().position(|b| *b == b':').unwrap_or(0);
                let name = String::from_utf8_lossy(&line[..name_end]).to_string();
                let ending = if line.ends_with(b"\r\n") {
                    "\r\n"
                } else {
                    "\n"
                };
                out.extend_from_slice(format!("{name}: gzip{ending}").as_bytes());
            }
            continue;
        }
        out.extend_from_slice(line);
    }
    if !changed {
        return None;
    }
    out.extend_from_slice(&buf[end..]);
    Some(out)
}

/// Takes the named headers out of a message head (`CRLFCRLF` included).
///
/// The name of a header is its part before the first `:`, compared
/// case-insensitively and whole (`x-frame-options` never matches
/// `x-frame-options-report`). A header line that folds onto the next line
/// (`obs-fold`) loses its continuation with it, so no orphan bytes are left
/// behind. Returns `None` when none of the names is there: the caller keeps
/// the head it had.
pub fn drop_headers(head: &[u8], names: &[String]) -> Option<Vec<u8>> {
    drop_header_lines(head, names).map(|(out, _)| out)
}

/// [`drop_headers`], also reporting the names it actually found (lowercased).
fn drop_header_lines(head: &[u8], names: &[String]) -> Option<(Vec<u8>, Vec<String>)> {
    if names.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(head.len());
    let mut dropped: Vec<String> = Vec::new();
    // Whether the previous line was dropped and a folded continuation of it
    // may still be coming.
    let mut in_folded = false;
    for line in head.split_inclusive(|b| *b == b'\n') {
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            if in_folded {
                continue;
            }
        } else if let Some(name) = header_line_name(line) {
            in_folded = names
                .iter()
                .any(|header| header.eq_ignore_ascii_case(name.as_str()));
            if in_folded {
                if !dropped.contains(&name) {
                    dropped.push(name);
                }
                continue;
            }
        } else {
            in_folded = false;
        }
        out.extend_from_slice(line);
    }
    if dropped.is_empty() {
        return None;
    }
    Some((out, dropped))
}

/// The lowercased name of a header line, or `None` when the line is not one —
/// a continuation line, the blank line that ends the head, or a line with
/// whitespace where a header name must be.
fn header_line_name(line: &[u8]) -> Option<String> {
    let end = line.iter().position(|b| *b == b':')?;
    if end == 0 || line[..end].contains(&b' ') || line[..end].contains(&b'\t') {
        return None;
    }
    Some(String::from_utf8_lossy(&line[..end]).to_ascii_lowercase())
}

/// The trimmed value of one header line, when the line is a header of that
/// (lowercased) name.
fn header_value<'a>(line: &'a [u8], name: &str) -> Option<&'a str> {
    let end = line.iter().position(|b| *b == b':')?;
    if end == 0 || !line[..end].eq_ignore_ascii_case(name.as_bytes()) {
        return None;
    }
    std::str::from_utf8(&line[end + 1..]).ok().map(str::trim)
}

/// The name of a `Cookie` pair (`name=value`), or `None` when the pair does
/// not parse as one — the reference skips those, and a pair it skips is a
/// cookie no rule can name.
fn cookie_pair_name(pair: &str) -> Option<&str> {
    let (name, _) = pair.split_once('=')?;
    let name = name.trim();
    (!name.is_empty()).then_some(name)
}

/// The cookie a `Set-Cookie` value names: its first non-empty `;`-part up to
/// the first `=`, or the whole part when it carries none. The reference reads
/// it that way, and trims nothing.
fn set_cookie_name(value: &str) -> Option<&str> {
    let first = value.split(';').find(|part| !part.is_empty())?;
    let name = first.split('=').next().unwrap_or(first);
    (!name.is_empty()).then_some(name)
}

/// The cookie names a request head carries, in the order its `Cookie` header
/// lists them.
///
/// A pair counts only when it parses as `name=value`, and repeats count once.
pub fn request_cookie_names(head: &[u8]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in head.split_inclusive(|b| *b == b'\n') {
        let Some(value) = header_value(line, "cookie") else {
            continue;
        };
        for pair in value.split(';') {
            let Some(name) = cookie_pair_name(pair.trim()) else {
                continue;
            };
            if !names.iter().any(|seen| seen == name) {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// Takes the cookies `dropped` names out of the `Cookie` header of a request
/// head, rebuilding the header the way the reference serialises one
/// (`name=value; name=value`, names and values trimmed) — a header is rewritten
/// only when one of the names really was on it, so a request the rules do not
/// touch goes over byte for byte. `None` when the head carries none of the
/// names: the caller keeps the head it had.
pub fn drop_request_cookies(head: &[u8], dropped: &[String]) -> Option<Vec<u8>> {
    if dropped.is_empty() {
        return None;
    }
    let mut changed = false;
    let mut out = Vec::with_capacity(head.len());
    for line in head.split_inclusive(|b| *b == b'\n') {
        let Some(value) = header_value(line, "cookie") else {
            out.extend_from_slice(line);
            continue;
        };
        let mut kept: Vec<String> = Vec::new();
        let mut line_changed = false;
        for pair in value.split(';') {
            // The reference reads a cookie as `name=value` and skips anything
            // else: a pair without an `=` is not a cookie, and a rebuild only
            // carries cookies.
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            let name = name.trim();
            if dropped.iter().any(|dropped| dropped == name) {
                line_changed = true;
                continue;
            }
            kept.push(format!("{name}={}", value.trim()));
        }
        if !line_changed {
            // None of the names is on this line: it goes over as it came.
            out.extend_from_slice(line);
            continue;
        }
        changed = true;
        if kept.is_empty() {
            // Every cookie went: the header goes with them.
            continue;
        }
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            out.extend_from_slice(line);
            continue;
        };
        let ending = if line.ends_with(b"\r\n") {
            "\r\n"
        } else {
            "\n"
        };
        out.extend_from_slice(&line[..colon]);
        out.extend_from_slice(format!(": {}{ending}", kept.join("; ")).as_bytes());
    }
    changed.then_some(out)
}

/// The cookie names a response head sets, in header order, each once.
pub fn set_cookie_names(head: &[u8]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for line in head.split_inclusive(|b| *b == b'\n') {
        let Some(value) = header_value(line, "set-cookie") else {
            continue;
        };
        let Some(name) = set_cookie_name(value) else {
            continue;
        };
        if !names.iter().any(|seen| seen == name) {
            names.push(name.to_string());
        }
    }
    names
}

/// Takes the `set-cookie` headers whose cookie name is in `dropped` out of a
/// response head. The names actually found and taken out come back with the
/// new head.
pub fn drop_set_cookie_headers(head: &[u8], dropped: &[String]) -> Option<(Vec<u8>, Vec<String>)> {
    if dropped.is_empty() {
        return None;
    }
    let mut taken: Vec<String> = Vec::new();
    let mut out = Vec::with_capacity(head.len());
    for line in head.split_inclusive(|b| *b == b'\n') {
        if let Some(value) = header_value(line, "set-cookie") {
            if let Some(name) = set_cookie_name(value) {
                if dropped.iter().any(|dropped| dropped == name) {
                    if !taken.iter().any(|seen| seen == name) {
                        taken.push(name.to_string());
                    }
                    continue;
                }
            }
        }
        out.extend_from_slice(line);
    }
    if taken.is_empty() {
        return None;
    }
    Some((out, taken))
}

/// What [`apply_response_headers`] did to one head, for the log line.
#[derive(Debug, Default)]
pub struct HeadEdits {
    /// Names actually taken out of the head (lowercased).
    pub dropped: Vec<String>,
    /// Canonical names appended to the head.
    pub added: Vec<String>,
}

/// Applies the response-header modifiers to a head: `$removeheader` names go
/// away, `$csp` and `$permissions` values are appended as header lines of
/// their own.
///
/// Everything stays inside the header block — its framing (`content-length`,
/// `transfer-encoding`) is off limits to `$removeheader` — so the new lines go
/// in just before the blank line that ends it. A head without that blank line
/// is not a head this can edit.
pub fn apply_response_headers(
    head: &mut Vec<u8>,
    drop: &[String],
    csp: &[String],
    permissions: &[String],
) -> HeadEdits {
    let mut edits = HeadEdits::default();
    if let Some((out, dropped)) = drop_header_lines(head, drop) {
        *head = out;
        edits.dropped = dropped;
    }
    if !(head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n")) {
        return edits;
    }
    let ending = if head.ends_with(b"\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut lines = String::new();
    for value in csp {
        lines.push_str("Content-Security-Policy: ");
        lines.push_str(value);
        lines.push_str(ending);
        edits.added.push("Content-Security-Policy".to_string());
    }
    for value in permissions {
        lines.push_str("Permissions-Policy: ");
        lines.push_str(value);
        lines.push_str(ending);
        edits.added.push("Permissions-Policy".to_string());
    }
    if !lines.is_empty() {
        let at = head.len() - ending.len();
        head.splice(at..at, lines.into_bytes());
    }
    edits
}

/// True when the head carries an `accept` header mentioning `text/html`.
pub fn head_accepts_html(head: &[u8]) -> bool {
    for line in head.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"accept:") {
            return lower.windows(9).any(|w| w == b"text/html");
        }
    }
    false
}

/// Offset just past the blank line that ends an HTTP head.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Outcome of decoding a chunked body.
pub enum Dechunk {
    /// The terminating chunk was seen; the payload and how many bytes of the
    /// stream it took are both returned.
    Complete { payload: Vec<u8>, consumed: usize },
    /// Framing is fine so far, more chunks are still coming.
    Incomplete,
    /// Not chunked framing at all.
    Malformed,
}

/// Decodes `transfer-encoding: chunked` framing.
pub fn dechunk(body: &[u8]) -> Dechunk {
    let mut state = DechunkState::new();
    let mut payload = Vec::new();
    match state.push(body, &mut payload) {
        Err(_) => Dechunk::Malformed,
        Ok(true) => Dechunk::Complete {
            payload,
            consumed: state.consumed(),
        },
        Ok(false) => Dechunk::Incomplete,
    }
}

/// Incremental chunked-framing decoder.
///
/// The whole-body path can wait for the terminating chunk before it does
/// anything; a body that has to reach the client *while it is still arriving*
/// cannot, so the framing is decoded a piece at a time here. Bytes that belong
/// to the next response stay in [`DechunkState::leftover`].
#[derive(Debug)]
pub struct DechunkState {
    buf: Vec<u8>,
    consumed: usize,
    done: bool,
    /// Payload bytes still expected for the chunk being read.
    chunk_left: usize,
    /// What the next bytes are: a size line, payload, the line break that
    /// closes a chunk, or trailers. Kept across calls so a chunk cut in half by
    /// the network is not mistaken for bad framing.
    stage: ChunkStage,
}

/// The four things the chunked framing asks for, in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ChunkStage {
    /// A chunk-size line is due.
    Size,
    /// Payload bytes of the current chunk.
    Payload,
    /// The line break that closes the current chunk's payload.
    Terminator,
    /// Trailers after the terminating chunk, up to the blank line.
    Trailer,
}

impl Default for DechunkState {
    fn default() -> Self {
        Self::new()
    }
}

impl DechunkState {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            consumed: 0,
            done: false,
            chunk_left: 0,
            stage: ChunkStage::Size,
        }
    }

    /// How many bytes of the stream have been decoded for good.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// True once the terminating chunk and its trailers have gone by.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Bytes past the end of the framing: the next response's, if any.
    pub fn leftover(&self) -> &[u8] {
        &self.buf
    }

    /// Decodes whatever `data` completes and appends the payload to `out`.
    ///
    /// Payload bytes go out as soon as they are here, even while the chunk
    /// that carries them is still arriving: chunks run to megabytes.
    ///
    /// `Ok(true)` once the terminating chunk has been seen. An `Err` means the
    /// bytes are not chunked framing at all.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<bool, String> {
        self.parse(data, Some(out))
    }

    /// Follows the framing without keeping the payload, for a body that goes
    /// to the client exactly as it came: only the end of the stream matters,
    /// because the next response's head is right behind it.
    ///
    /// `Ok(true)` once the terminating chunk has been seen; whatever followed
    /// it is in [`DechunkState::leftover`].
    pub fn walk(&mut self, data: &[u8]) -> Result<bool, String> {
        self.parse(data, None)
    }

    fn parse(&mut self, data: &[u8], mut out: Option<&mut Vec<u8>>) -> Result<bool, String> {
        if self.done {
            return Ok(true);
        }
        self.buf.extend_from_slice(data);
        let mut pos = 0usize;
        'parse: loop {
            match self.stage {
                ChunkStage::Payload => {
                    // Hand over whatever part of this chunk is here: chunks run
                    // into megabytes, and waiting for one whole is not an
                    // option for a body that has to keep moving.
                    let take = self.chunk_left.min(self.buf.len() - pos);
                    if let Some(sink) = out.as_mut() {
                        sink.extend_from_slice(&self.buf[pos..pos + take]);
                    }
                    pos += take;
                    self.chunk_left -= take;
                    if self.chunk_left > 0 {
                        break;
                    }
                    self.stage = ChunkStage::Terminator;
                }
                ChunkStage::Terminator => {
                    // CRLF, or bare LF from a server that does not care.
                    let Some(first) = self.buf.get(pos).copied() else {
                        break;
                    };
                    if first == b'\r' {
                        if self.buf.len() < pos + 2 {
                            break;
                        }
                        pos += 2;
                    } else {
                        pos += 1;
                    }
                    self.stage = ChunkStage::Size;
                }
                ChunkStage::Size | ChunkStage::Trailer => {
                    let Some(nl) = self.buf[pos..].iter().position(|b| *b == b'\n') else {
                        break;
                    };
                    let nl = pos + nl;
                    let line_end = if nl > pos && self.buf[nl - 1] == b'\r' {
                        nl - 1
                    } else {
                        nl
                    };
                    if self.stage == ChunkStage::Trailer {
                        let blank = line_end == pos;
                        pos = nl + 1;
                        if blank {
                            self.done = true;
                            break 'parse;
                        }
                        continue;
                    }
                    let size_part = self.buf[pos..line_end]
                        .split(|b| *b == b';')
                        .next()
                        .unwrap_or(&[]);
                    let size = chunk_size(size_part)?;
                    pos = nl + 1;
                    if size > 0 {
                        self.chunk_left = size;
                        self.stage = ChunkStage::Payload;
                    } else {
                        self.stage = ChunkStage::Trailer;
                    }
                }
            }
        }
        self.buf.drain(..pos);
        self.consumed += pos;
        Ok(self.done)
    }
}

/// Parses a chunk-size field: hex digits, surrounding blanks ignored.
fn chunk_size(text: &[u8]) -> Result<usize, String> {
    let text = std::str::from_utf8(text)
        .map_err(|_| "chunk size is not text".to_string())?
        .trim();
    if text.is_empty() {
        return Err("chunk size is missing".to_string());
    }
    usize::from_str_radix(text, 16).map_err(|_| format!("chunk size {text:?} is not hex"))
}

/// Head for a body that grew to `body_len` bytes and travels as identity (or as
/// `encoding` when given): `content-length` is set, `transfer-encoding` and
/// `trailer` go.
///
/// The head arrives as it should leave — a rewritten policy included — because
/// only the caller knows whether anything was injected and under which nonce.
pub fn head_for_new_body(head: &[u8], body_len: usize, encoding: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len() + 32);
    let mut have_length = false;
    for line in head.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"transfer-encoding:") || lower.starts_with(b"trailer:") {
            continue;
        }
        if lower.starts_with(b"content-encoding:") {
            if let Some(enc) = encoding {
                let name = header_name(line);
                out.extend_from_slice(format!("{name}: {enc}{}", line_ending(line)).as_bytes());
            }
            continue;
        }
        if lower.starts_with(b"content-length:") {
            have_length = true;
            let name = header_name(line);
            out.extend_from_slice(format!("{name}: {body_len}{}", line_ending(line)).as_bytes());
            continue;
        }
        out.extend_from_slice(line);
    }
    if !have_length {
        // `out` ends with the blank line that closes the head: the header has
        // to go *before* it, not after.
        let (body_of_head, tail) = if out.ends_with(b"\r\n\r\n") {
            (out.len() - 2, "\r\n")
        } else if out.ends_with(b"\n\n") {
            (out.len() - 1, "\n")
        } else {
            (out.len(), "\r\n")
        };
        out.truncate(body_of_head);
        out.extend_from_slice(format!("Content-Length: {body_len}{tail}{tail}").as_bytes());
    }
    out
}

/// Head for a body that only grew by `delta` bytes; framing is untouched.
pub fn head_for_bigger_body(head: &[u8], delta: usize) -> Vec<u8> {
    let current = parse_response_head(head).content_length;
    let mut out = Vec::with_capacity(head.len() + 16);
    for line in head.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        // A missing `content-length` is fine here: the body is length-framed by
        // definition, so the caller would not pick this helper.
        if lower.starts_with(b"content-length:") {
            if let Some(current) = current {
                let name = header_name(line);
                out.extend_from_slice(
                    format!("{name}: {}{}", current + delta, line_ending(line)).as_bytes(),
                );
                continue;
            }
        }
        out.extend_from_slice(line);
    }
    out
}

/// The header name of a line, with its original casing.
fn header_name(line: &[u8]) -> String {
    let end = line.iter().position(|b| *b == b':').unwrap_or(0);
    String::from_utf8_lossy(&line[..end]).to_string()
}

fn line_ending(line: &[u8]) -> &'static str {
    if line.ends_with(b"\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Empty when the buffer does not start a request line, otherwise whether the
/// request is a `HEAD` — responses to those advertise a `content-length` but
/// carry no body, which the rewriter must not wait for.
pub fn request_method_is_head(buf: &[u8]) -> Option<bool> {
    request_info(buf).map(|info| info.head)
}

/// What a request line says about the response that will follow it.
///
/// `Default` is the shape every response rewriter assumes when it cannot see
/// the request: not a HEAD, and a client that speaks HTTP/1.1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RequestInfo {
    /// A `HEAD`: the response advertises a length but carries no body.
    pub head: bool,
    /// HTTP/1.0: the client cannot read a chunked body.
    pub http10: bool,
}

/// Recognises a request line at the start of `buf`, plus the version it names.
///
/// The version matters to the response rewriter: switching a body to chunked
/// framing is only safe for clients that speak HTTP/1.1. An incomplete version
/// token counts as 1.1, which is what every client that matters here sends.
pub fn request_info(buf: &[u8]) -> Option<RequestInfo> {
    const METHODS: [&str; 9] = [
        "HEAD ", "GET ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
    ];
    let head = METHODS
        .iter()
        .find(|method| buf.starts_with(method.as_bytes()))
        .map(|method| *method == "HEAD ")?;
    let line_end = buf.iter().position(|b| *b == b'\n').unwrap_or(buf.len());
    let line = &buf[..line_end];
    let http10 = line.ends_with(b"HTTP/1.0\r") || line.ends_with(b"HTTP/1.0");
    Some(RequestInfo { head, http10 })
}

/// Decodes a `gzip` or `deflate` body. `None` when the bytes are not what the
/// header claims, in which case the caller forwards them untouched.
pub fn decode_body(body: &[u8], encoding: Encoding) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::with_capacity(body.len() * 3);
    match encoding {
        Encoding::Gzip => {
            // `MultiGzDecoder` also accepts concatenated members, which some
            // servers emit when they compress a stream in pieces.
            flate2::read::MultiGzDecoder::new(body)
                .read_to_end(&mut out)
                .ok()?;
        }
        Encoding::Deflate => {
            // "deflate" officially means a zlib stream, but plenty of servers
            // send raw DEFLATE; try both before giving up.
            if flate2::read::ZlibDecoder::new(body)
                .read_to_end(&mut out)
                .is_err()
            {
                out.clear();
                flate2::read::DeflateDecoder::new(body)
                    .read_to_end(&mut out)
                    .ok()?;
            }
        }
        Encoding::Identity | Encoding::Other => return None,
    }
    Some(out)
}

/// Compresses a body as gzip. Fast level: the phone re-downloads nothing, but
/// it should not burn cycles re-compressing either.
pub fn gzip_encode(body: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(body).ok()?;
    encoder.finish().ok()
}

// ---------------------------------------------------------------------------
// Streaming rewriting
// ---------------------------------------------------------------------------

/// How many body bytes a response may hold back before it switches to
/// streaming.
///
/// Bytes held are bytes the client cannot acknowledge, and a client that does
/// not acknowledge stops the relay: holding more than one TCP window of body
/// deadlocks the connection. A window is at least 64 KiB, so this leaves room.
pub const STREAM_AFTER: usize = 32 * 1024;

/// How big a text body may be before a `$replace` rule is given up on.
///
/// A rewrite needs the whole body at once, which streaming cannot do, so the
/// rule's own cap is the only bound there is. AdGuard draws the line at 10 MB;
/// that is memory a phone does not have to spare for one response, and the
/// bodies these rules target — player scripts, API answers, manifests — are
/// well under this one. What goes over travels untouched.
pub const REPLACE_AFTER: usize = 512 * 1024;

/// Decoded bytes kept while the injector looks for an insertion point.
pub const STREAM_PREFIX_LIMIT: usize = 16 * 1024;

/// Appends one `transfer-encoding: chunked` frame.
pub fn emit_chunk(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

/// Appends the terminating chunk.
pub fn emit_last_chunk(out: &mut Vec<u8>) {
    out.extend_from_slice(b"0\r\n\r\n");
}

/// Head for a body that will leave chunked: framing is replaced (the edited
/// length is unknowable up front), `content-encoding` follows `encoding`.
pub fn head_for_chunked_body(head: &[u8], encoding: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len() + 32);
    let mut have_framing = false;
    for line in head.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"content-length:") || lower.starts_with(b"trailer:") {
            continue;
        }
        if lower.starts_with(b"transfer-encoding:") {
            have_framing = true;
            let name = header_name(line);
            out.extend_from_slice(format!("{name}: chunked{}", line_ending(line)).as_bytes());
            continue;
        }
        if lower.starts_with(b"content-encoding:") {
            if let Some(enc) = encoding {
                let name = header_name(line);
                out.extend_from_slice(format!("{name}: {enc}{}", line_ending(line)).as_bytes());
            }
            continue;
        }
        out.extend_from_slice(line);
    }
    if !have_framing {
        // `out` ends with the blank line that closes the head: the header has
        // to go *before* it, not after.
        let (head_part, tail) = if out.ends_with(b"\r\n\r\n") {
            (out.len() - 2, "\r\n")
        } else if out.ends_with(b"\n\n") {
            (out.len() - 1, "\n")
        } else {
            (out.len(), "\r\n")
        };
        out.truncate(head_part);
        out.extend_from_slice(format!("Transfer-Encoding: chunked{tail}{tail}").as_bytes());
    }
    out
}

/// Incremental gzip decoder.
///
/// The pure-Rust flate2 backend has no gzip mode (`Decompress::new_gzip` is
/// zlib-only), so the header, its optional fields and the trailer are handled
/// here over a raw inflate stream — the same split flate2's own `GzDecoder`
/// uses.
pub struct GunzipState {
    header: Vec<u8>,
    /// Set once the gzip header is understood: where the deflate payload began.
    body_start: Option<usize>,
    dec: flate2::Decompress,
    /// Bytes of trailer (CRC32 + ISIZE) still to be skipped.
    trailer_left: usize,
    inflate_done: bool,
    done: bool,
}

impl Default for GunzipState {
    fn default() -> Self {
        Self::new()
    }
}

impl GunzipState {
    pub fn new() -> Self {
        Self {
            header: Vec::new(),
            body_start: None,
            dec: flate2::Decompress::new(false),
            trailer_left: 8,
            inflate_done: false,
            done: false,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Feeds compressed bytes, appending whatever they decode to `out`.
    ///
    /// A silent `Ok` with nothing decoded means "not enough bytes yet". An
    /// `Err` means the bytes are not a gzip stream.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        if self.done {
            return Ok(());
        }
        if self.body_start.is_none() {
            self.header.extend_from_slice(data);
            match gzip_body_start(&self.header) {
                GzipHeader::Incomplete => return Ok(()),
                GzipHeader::Bad => return Err("not a gzip stream".to_string()),
                GzipHeader::Ok(start) => {
                    self.body_start = Some(start);
                    let body: Vec<u8> = self.header[start..].to_vec();
                    self.header.clear();
                    self.decode(&body, out)?;
                }
            }
        } else {
            self.decode(data, out)?;
        }
        Ok(())
    }

    fn decode(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        let mut pos = 0usize;
        loop {
            if self.inflate_done {
                // The CRC32 and length that close a gzip member. Not verified:
                // a wrong one is the origin's problem, not the page's.
                let take = self.trailer_left.min(data.len() - pos);
                self.trailer_left -= take;
                if self.trailer_left == 0 {
                    self.done = true;
                }
                return Ok(());
            }
            let in_before = self.dec.total_in();
            let out_before = self.dec.total_out();
            let start = out.len();
            out.resize(start + DECODE_CHUNK, 0);
            let status = self
                .dec
                .decompress(
                    &data[pos..],
                    &mut out[start..],
                    flate2::FlushDecompress::None,
                )
                .map_err(|e| format!("gzip: {e}"))?;
            let read = (self.dec.total_in() - in_before) as usize;
            let written = (self.dec.total_out() - out_before) as usize;
            out.truncate(start + written);
            pos += read;
            match status {
                flate2::Status::StreamEnd => self.inflate_done = true,
                _ if pos >= data.len() && written == 0 => return Ok(()),
                _ => {}
            }
        }
    }
}

/// Scratch size for one inflate step.
const DECODE_CHUNK: usize = 64 * 1024;

/// What a gzip header looks like from the bytes seen so far.
enum GzipHeader {
    /// Not enough bytes yet.
    Incomplete,
    /// The magic number or method says this is not gzip.
    Bad,
    /// Payload starts at this offset.
    Ok(usize),
}

/// Walks the fixed and optional parts of a gzip header.
fn gzip_body_start(buf: &[u8]) -> GzipHeader {
    if buf.len() < 10 {
        return if buf.len() < 2 || &buf[..2] == b"\x1f\x8b" {
            GzipHeader::Incomplete
        } else {
            GzipHeader::Bad
        };
    }
    if &buf[..2] != b"\x1f\x8b" || buf[2] != 8 {
        return GzipHeader::Bad;
    }
    let flags = buf[3];
    let mut pos = 10usize;
    if flags & 0x04 != 0 {
        // FEXTRA: two-byte length, then that many bytes.
        if buf.len() < pos + 2 {
            return GzipHeader::Incomplete;
        }
        let extra = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
        pos += 2 + extra;
    }
    for flag in [0x08u8, 0x10u8] {
        // FNAME, FCOMMENT: NUL-terminated.
        if flags & flag == 0 {
            continue;
        }
        let scan = pos.min(buf.len());
        match buf[scan..].iter().position(|b| *b == 0) {
            Some(i) => pos = scan + i + 1,
            None => return GzipHeader::Incomplete,
        }
    }
    if flags & 0x02 != 0 {
        pos += 2; // FHCRC
    }
    if buf.len() < pos {
        return GzipHeader::Incomplete;
    }
    GzipHeader::Ok(pos)
}

/// True when the request's `Accept-Encoding` allows a gzipped answer.
///
/// Only gzip can be produced here (no brotli), and only gzip is checked for:
/// a client that did not ask for it gets the body plain.
pub fn accepts_gzip(request_head: &[u8]) -> bool {
    let lower: Vec<u8> = request_head
        .iter()
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let Some(pos) = find_ci(&lower, b"\r\naccept-encoding:") else {
        return false;
    };
    let rest = &lower[pos + 2..];
    let end = rest
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(rest.len());
    rest[..end].windows(4).any(|w| w == b"gzip")
}

/// Gzips a whole locally answered body.
///
/// `None` when the encoder refuses; the caller then sends the bytes plain
/// rather than not at all.
pub fn gzip_bytes(body: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(body).ok()?;
    encoder.finish().ok()
}

/// Incremental gzip encoder, so an edited body can leave compressed without
/// being held whole first.
pub struct GzipState {
    enc: Option<flate2::write::GzEncoder<Vec<u8>>>,
}

impl Default for GzipState {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipState {
    pub fn new() -> Self {
        Self {
            enc: Some(flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::fast(),
            )),
        }
    }

    /// Compresses `data` and appends the bytes the encoder produced.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
        use std::io::Write;
        let enc = self
            .enc
            .as_mut()
            .ok_or_else(|| "gzip stream already finished".to_string())?;
        enc.write_all(data).map_err(|e| format!("gzip: {e}"))?;
        let sink = enc.get_mut();
        out.extend_from_slice(sink);
        sink.clear();
        Ok(())
    }

    /// Appends whatever closes the stream (the CRC32 and length).
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), String> {
        let Some(enc) = self.enc.take() else {
            return Ok(());
        };
        let rest = enc.finish().map_err(|e| format!("gzip: {e}"))?;
        out.extend_from_slice(&rest);
        Ok(())
    }
}

/// Escape quotes and backslashes for an attribute value.
fn escape_attr(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
}

/// Case-insensitive substring search (over an already-lowercased slice).
fn find_ci(haystack_lower: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack_lower.len() {
        return None;
    }
    haystack_lower
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_before_head_close() {
        let body = b"<html><head><title>t</title></head><body>hi</body></html>";
        let (out, decision) = inject_script(body, "/adfree.js");
        assert_eq!(decision, Decision::Injected);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("<html><head><title>t</title><script"));
        assert!(text.contains("</head><body>hi</body></html>"));
    }

    #[test]
    fn falls_back_to_body_close_then_body_open() {
        let (out, d) = inject_script(b"<html><body>x</body></html>", "/a.js");
        assert_eq!(d, Decision::Injected);
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("<script src=\"/a.js\""));

        let (out, d) = inject_script(b"<html><body><p>x</p></html>", "/a.js");
        assert_eq!(d, Decision::Injected);
        assert!(String::from_utf8(out)
            .unwrap()
            .starts_with("<html><body><script"));
    }

    #[test]
    fn skips_non_html_and_huge_bodies() {
        assert_eq!(inject_script(b"{\"json\":true}", "/a.js").1, Decision::Skip);
        assert_eq!(inject_script(b"", "/a.js").1, Decision::Skip);
        let big = vec![b'x'; MAX_INJECTABLE_BODY + 1];
        assert_eq!(inject_script(&big, "/a.js").1, Decision::Skip);
        // Neither a `<!doctype` nor an `<html` tag: a fragment, not a page.
        assert_eq!(inject_script(b"just text", "/a.js").1, Decision::Skip);
        assert_eq!(
            inject_script(b"<div>fragment</div>", "/a.js").1,
            Decision::Skip
        );
    }

    #[test]
    fn a_page_without_a_doctype_is_still_a_page() {
        // news.ycombinator.com ships exactly this shape: no doctype at all and
        // an `<html>` tag that carries attributes, so `"<html>"` never occurs.
        let body =
            b"<html lang=\"en\" op=\"news\"><head><title>t</title></head><body>x</body></html>";
        let (out, d) = inject_script(body, "/a.js");
        assert_eq!(d, Decision::Injected);
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("<script src=\"/a.js\""));
    }

    #[test]
    fn no_insert_point_is_reported() {
        assert_eq!(
            inject_script(b"<!doctype html><p>hi", "/a.js").1,
            Decision::NoInsertPoint
        );
    }

    #[test]
    fn injects_into_doctype_pages() {
        let (out, d) = inject_script(b"<!doctype html><html><head></head></html>", "/a.js");
        assert_eq!(d, Decision::Injected);
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("<script src=\"/a.js\""));
    }

    #[test]
    fn response_heads_are_parsed() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 42\r\n\r\n";
        let info = parse_response_head(head);
        assert_eq!(info.status, 200);
        assert!(info.html);
        assert!(!info.chunked);
        assert_eq!(info.content_length, Some(42));
        assert_eq!(info.encoding, Encoding::Identity);
        assert!(!info.bodyless());

        // Header names are case-insensitive.
        let upper = b"HTTP/1.1 200 OK\r\nCONTENT-TYPE: TEXT/HTML\r\nCONTENT-ENCODING: GZIP\r\n\r\n";
        let info = parse_response_head(upper);
        assert!(info.html);
        assert_eq!(info.encoding, Encoding::Gzip);

        let js = b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n";
        assert!(!parse_response_head(js).html);

        // What a `$replace` rule may look at: text bodies, not media. A
        // response without a content-type is not one of them.
        assert!(parse_response_head(js).text);
        assert!(parse_response_head(head).text);
        let manifest = b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\n\r\n";
        assert!(parse_response_head(manifest).text);
        let png = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n";
        assert!(!parse_response_head(png).text);
        let none = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n";
        assert!(!parse_response_head(none).text);

        let chunked =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_response_head(chunked).chunked);

        // 304 advertises a length but never carries a body.
        let n304 = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\n\r\n";
        assert!(parse_response_head(n304).bodyless());
        let n204 = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert!(parse_response_head(n204).bodyless());
        let n100 = b"HTTP/1.1 100 Continue\r\n\r\n";
        assert!(parse_response_head(n100).bodyless());
    }

    #[test]
    fn growing_bodies_bump_the_declared_length() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        let out = head_for_bigger_body(head, 58);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Content-Length: 100\r\n"), "{text}");
        assert!(text.contains("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn growing_bodies_leave_the_policy_alone() {
        // The policy is the caller's business now: it is rewritten (with the
        // nonce) or not, and framing passes do not second-guess that.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Security-Policy: script-src 'self'\r\n\r\n";
        let text = String::from_utf8(head_for_bigger_body(head, 9)).unwrap();
        assert!(
            text.contains("Content-Security-Policy: script-src 'self'\r\n"),
            "{text}"
        );
    }

    #[test]
    fn new_bodies_set_length_and_drop_chunking() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X\r\nContent-Type: text/html\r\n\r\n";
        let text = String::from_utf8(head_for_new_body(head, 12, None)).unwrap();
        assert!(!text.contains("Transfer-Encoding"), "{text}");
        assert!(!text.contains("Trailer"), "{text}");
        assert!(text.contains("Content-Length: 12\r\n"), "{text}");
        // The header must land inside the head, before the blank line.
        assert!(text.ends_with("\r\n\r\n"), "{text}");
    }

    #[test]
    fn new_bodies_replace_the_encoding() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\nContent-Length: 5\r\n\r\n";
        let text = String::from_utf8(head_for_new_body(head, 21, Some("gzip"))).unwrap();
        assert!(text.contains("Content-Encoding: gzip\r\n"), "{text}");
        assert!(text.contains("Content-Length: 21\r\n"), "{text}");
        // Identity bodies lose the header entirely.
        let text = String::from_utf8(head_for_new_body(head, 21, None)).unwrap();
        assert!(!text.contains("Content-Encoding"), "{text}");
    }

    #[test]
    fn chunked_bodies_are_decoded() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        match dechunk(body) {
            Dechunk::Complete { payload, consumed } => {
                assert_eq!(payload, b"Wikipedia");
                assert_eq!(consumed, body.len());
            }
            _ => panic!("expected a complete body"),
        }
    }

    #[test]
    fn chunked_bodies_accept_extensions_and_trailers() {
        let body = b"4;name=value\r\nWiki\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT";
        match dechunk(body) {
            Dechunk::Complete { payload, consumed } => {
                assert_eq!(payload, b"Wiki");
                // The connection stays in sync: what follows is the next response.
                assert_eq!(&body[consumed..], b"NEXT");
            }
            _ => panic!("expected a complete body"),
        }
    }

    #[test]
    fn partial_chunked_bodies_are_incomplete() {
        assert!(matches!(dechunk(b"4\r\nWi"), Dechunk::Incomplete));
        assert!(matches!(dechunk(b"4\r\nWiki\r\n"), Dechunk::Incomplete));
        assert!(matches!(dechunk(b"zz\r\n"), Dechunk::Malformed));
    }

    #[test]
    fn walking_a_chunked_stream_keeps_nothing_but_the_position() {
        // A body that goes over untouched still has to be followed to its
        // end: the head behind it is the next response's, and the walker is
        // how that boundary is found. What it takes in, it counts; what it
        // consumes, nobody sees.
        let mut state = DechunkState::new();
        assert!(!state.walk(b"5\r\nhe").expect("framing so far"));
        assert!(!state.walk(b"llo\r\n0\r\n").expect("framing so far"));
        assert!(!state.is_done(), "the trailers are still to come");
        assert!(state.walk(b"\r\n").expect("the terminating chunk"));
        assert!(state.is_done());
        assert_eq!(state.consumed(), b"5\r\nhello\r\n0\r\n\r\n".len());
        assert!(state.leftover().is_empty());

        // Bytes after the terminator are left exactly where they are: they
        // belong to the next response.
        let mut state = DechunkState::new();
        assert!(state.walk(b"1\r\na\r\n0\r\n\r\nNEXT").expect("the stream"));
        assert_eq!(state.leftover(), b"NEXT");

        // Framing that is not chunked framing at all is refused, not
        // guessed at.
        let mut state = DechunkState::new();
        assert!(state.walk(b"zz\r\n").is_err());
    }

    #[test]
    fn html_requests_stop_asking_for_brotli() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n\r\n";
        let out = drop_undecodable_encodings(req, false).expect("rewritten");
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("Accept-Encoding: gzip, deflate\r\n"),
            "{text}"
        );
        assert!(!text.contains("br"), "{text}");
        assert!(!text.contains("zstd"), "{text}");

        // Requests that do not ask for HTML keep their negotiation.
        let js = b"GET /a.js HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: br, zstd\r\n\r\n";
        assert!(drop_undecodable_encodings(js, false).is_none());

        // Nothing droppable: no rewrite at all, so the bytes stay identical.
        let gz = b"GET / HTTP/1.1\r\nAccept: text/html\r\nAccept-Encoding: gzip\r\n\r\n";
        assert!(drop_undecodable_encodings(gz, false).is_none());

        // A `$replace` match is reason enough on its own: the response is not
        // a page, so nothing in the request says its body is text.
        let out = drop_undecodable_encodings(js, true).expect("rewritten");
        assert!(String::from_utf8(out)
            .unwrap()
            .contains("Accept-Encoding: gzip\r\n"));

        // Only undecodable tokens: the header goes away entirely.
        let only_br = b"GET / HTTP/1.1\r\nAccept: text/html\r\nAccept-Encoding: br\r\n\r\n";
        let out = drop_undecodable_encodings(only_br, false).expect("rewritten");
        assert!(!String::from_utf8(out).unwrap().contains("Accept-Encoding"));

        // Head still arriving: not our business yet.
        assert!(drop_undecodable_encodings(b"GET / HTTP/1.1\r\nAccept: text/htm", false).is_none());
    }

    #[test]
    fn head_requests_are_recognised() {
        assert_eq!(request_method_is_head(b"HEAD /x HTTP/1.1\r\n"), Some(true));
        assert_eq!(request_method_is_head(b"GET /x HTTP/1.1\r\n"), Some(false));
        assert_eq!(request_method_is_head(b"POST /x HTTP/1.1\r\n"), Some(false));
        assert_eq!(request_method_is_head(b"body bytes"), None);
    }

    #[test]
    fn gzip_bodies_round_trip() {
        let plain = b"<html><head></head><body>hello</body></html>".to_vec();
        let gz = gzip_encode(&plain).expect("encode");
        assert_eq!(gz[..2], [0x1f, 0x8b]);
        assert_eq!(decode_body(&gz, Encoding::Gzip).expect("decode"), plain);
        // Not gzip: reported, not guessed.
        assert!(decode_body(b"\x1f\x8b\x08\x00", Encoding::Gzip).is_none());
        assert!(decode_body(&plain, Encoding::Identity).is_none());
    }

    #[test]
    fn deflate_bodies_round_trip_both_flavours() {
        use std::io::Write;
        let plain = b"<html><head></head><body>x</body></html>".to_vec();
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        zlib.write_all(&plain).unwrap();
        let zlib = zlib.finish().unwrap();
        assert_eq!(decode_body(&zlib, Encoding::Deflate).expect("zlib"), plain);

        let mut raw = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        raw.write_all(&plain).unwrap();
        let raw = raw.finish().unwrap();
        assert_eq!(decode_body(&raw, Encoding::Deflate).expect("raw"), plain);
    }

    #[test]
    fn head_end_finds_the_blank_line() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn escapes_script_src() {
        // XSS hole in the injection point itself: always escape the value.
        let (out, _) = inject_script(b"<html><head></head></html>", "/a\" onload=\"x");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("onload=\"x"), "the value must be escaped");
        assert!(text.contains("&quot;"));
    }

    #[test]
    fn teaches_the_policy_our_nonce() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: script-src 'self'; style-src 'self'\r\nContent-Security-Policy-Report-Only: default-src 'none'\r\nX-Kept: yes\r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(
            out.contains(
                "Content-Security-Policy: script-src 'self' 'nonce-abc123'; style-src 'self' 'nonce-abc123'"
            ),
            "{out}"
        );
        // A report-only policy is a diagnostic, not enforcement: untouched.
        assert!(
            out.contains("Content-Security-Policy-Report-Only: default-src 'none'"),
            "{out}"
        );
        assert!(out.contains("X-Kept: yes"), "{out}");
        assert!(out.contains("Content-Type: text/html"), "{out}");
    }

    #[test]
    fn a_fallback_policy_is_taught_case_insensitively() {
        let head = b"HTTP/1.1 200 OK\r\nCONTENT-SECURITY-POLICY: default-src 'self'\r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(
            out.contains("CONTENT-SECURITY-POLICY: default-src 'self' 'nonce-abc123'"),
            "{out}"
        );
    }

    #[test]
    fn unsafe_inline_gets_our_origin_instead_of_a_nonce() {
        // Chromium stops honouring `'unsafe-inline'` the moment the policy
        // holds a nonce, so a nonce here would block the page's own inline
        // scripts. The origin satisfies our tags without touching that.
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'unsafe-inline' https://cdn.test; style-src 'unsafe-inline'\r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(out.contains("'unsafe-inline'"), "{out}");
        assert!(!out.contains("nonce-"), "{out}");
        assert!(
            out.contains("script-src 'unsafe-inline' https://cdn.test https://192.0.2.1"),
            "{out}"
        );
        assert!(
            out.contains("style-src 'unsafe-inline' https://192.0.2.1"),
            "{out}"
        );
    }

    #[test]
    fn a_policy_that_already_holds_a_nonce_can_take_ours() {
        // `'unsafe-inline'` is inert there already, so our nonce changes
        // nothing for the page and both our tags are covered by it.
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'unsafe-inline' 'nonce-page'\r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(
            out.contains("script-src 'unsafe-inline' 'nonce-page' 'nonce-abc123'"),
            "{out}"
        );
    }

    #[test]
    fn a_policy_that_never_governs_our_tags_is_left_alone() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: img-src 'self'; frame-ancestors 'none'\r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(
            out.contains("Content-Security-Policy: img-src 'self'; frame-ancestors 'none'"),
            "{out}"
        );
    }

    #[test]
    fn the_lookup_fetch_is_allowed_by_connect_src() {
        // `connect-src` has no nonce-source: the runtime's lookup is a fetch,
        // and a policy that pins connect to 'self' would block it silently.
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: script-src 'self'; connect-src 'self'\r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(
            out.contains("connect-src 'self' https://192.0.2.1"),
            "{out}"
        );
    }

    #[test]
    fn a_policy_shaped_like_a_real_one_gets_all_three_carriers() {
        // The measured shape of www.reddit.com: scripts locked to a nonce,
        // styles leaning on 'unsafe-inline', and `default-src 'none'` behind
        // everything else — which is where the lookup's fetch lands.
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'none'; script-src 'nonce-page'; style-src 'unsafe-inline'\r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(
            out.contains("default-src 'none' https://192.0.2.1"),
            "{out}"
        );
        assert!(
            out.contains("script-src 'nonce-page' 'nonce-abc123'"),
            "{out}"
        );
        assert!(
            out.contains("style-src 'unsafe-inline' https://192.0.2.1"),
            "{out}"
        );
    }

    #[test]
    fn a_lone_default_src_gets_each_addition_once() {
        // No specific directive: the fallback carries all three carriers, and
        // the same source expression is never written twice.
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(
            out.contains("default-src 'self' 'nonce-abc123' https://192.0.2.1"),
            "{out}"
        );
        assert_eq!(out.matches("'nonce-abc123'").count(), 1, "{out}");
    }

    #[test]
    fn an_empty_policy_is_not_invented_into_something() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: \r\n\r\n";
        let out = String::from_utf8(csp_with_nonce(head, "abc123", "https://192.0.2.1")).unwrap();
        assert!(out.contains("Content-Security-Policy: \r\n"), "{out}");
    }

    #[test]
    fn nonces_do_not_repeat() {
        let first = new_nonce();
        let second = new_nonce();
        assert_eq!(first.len(), 36, "18 bytes in hex: {first}");
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()), "{first}");
        assert_ne!(first, second, "a repeated nonce would be reusable");
    }

    #[test]
    fn injects_multiple_tags_in_order() {
        let body = b"<html><head></head><body>x</body></html>";
        let snippet = b"<script>window.__d=1;</script><script src=\"/p.js\"></script><script src=\"/u.js\" defer></script>";
        let (out, d) = inject_snippet(body, snippet);
        assert_eq!(d, Decision::Injected);
        let text = String::from_utf8(out).unwrap();
        let inline = text.find("window.__d=1").unwrap();
        let page = text.find("/p.js").unwrap();
        let user = text.find("/u.js").unwrap();
        assert!(inline < page && page < user, "{text}");
        assert!(text.contains("</head><body>"), "{text}");
    }

    #[test]
    fn script_tag_escapes_defers_and_carries_the_nonce() {
        assert_eq!(
            script_tag("/a.js", true, ""),
            "<script src=\"/a.js\" defer></script>"
        );
        assert_eq!(
            script_tag("/a.js", false, ""),
            "<script src=\"/a.js\"></script>"
        );
        assert_eq!(
            script_tag("/a.js", false, "n0nce"),
            "<script nonce=\"n0nce\" src=\"/a.js\"></script>"
        );
        let escaped = script_tag("/a\"<b>", false, "");
        assert!(!escaped.contains("/a\"<b>"), "{escaped}");
        assert!(
            escaped.contains("&quot;") && escaped.contains("&lt;"),
            "{escaped}"
        );
    }

    #[test]
    fn style_link_escapes_keeps_an_id_and_carries_the_nonce() {
        assert_eq!(
            style_link_tag("/adfree-hide.css?h=abc", "adfree-hide", ""),
            "<link rel=\"stylesheet\" id=\"adfree-hide\" href=\"/adfree-hide.css?h=abc\">"
        );
        assert_eq!(
            style_link_tag("/h.css", "adfree-hide", "n0nce"),
            "<link rel=\"stylesheet\" id=\"adfree-hide\" href=\"/h.css\" nonce=\"n0nce\">"
        );
        let escaped = style_link_tag("/a\"<b>", "x\"", "");
        assert!(!escaped.contains("/a\"<b>"), "{escaped}");
        assert!(escaped.contains("&quot;"), "{escaped}");
    }

    #[test]
    fn accept_encoding_decides_whether_a_local_body_is_gzipped() {
        assert!(accepts_gzip(
            b"GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n"
        ));
        assert!(accepts_gzip(
            b"GET / HTTP/1.1\r\naccept-encoding: GZIP\r\n\r\n"
        ));
        assert!(!accepts_gzip(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(!accepts_gzip(
            b"GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: deflate, br\r\n\r\n"
        ));
        // A path or header value that merely mentions the word is not a yes.
        assert!(!accepts_gzip(b"GET /gzip HTTP/1.1\r\nHost: x\r\n\r\n"));
    }

    #[test]
    fn gzipped_local_bodies_decode_back() {
        let body = b"body".repeat(300);
        let gz = gzip_bytes(&body).expect("gzip");
        assert!(gz.len() < body.len(), "the point is to shrink page data");
        let mut out = Vec::new();
        let mut gunzip = GunzipState::new();
        gunzip.push(&gz, &mut out).expect("decode");
        assert!(gunzip.is_done(), "the stream must end");
        assert_eq!(out, body);
    }

    #[test]
    fn collects_class_and_id_tokens() {
        let body = br#"<html><body><div class="ad-box promo" id="main">x</div>
            <span class='solo  spaced' id=raw>y</span><p class="ad-box">z</p></body></html>"#;
        let (classes, ids) = collect_class_id_tokens(body);
        assert!(classes.contains(&"ad-box".to_string()), "{classes:?}");
        assert!(classes.contains(&"promo".to_string()), "{classes:?}");
        assert!(classes.contains(&"solo".to_string()), "{classes:?}");
        assert!(classes.contains(&"spaced".to_string()), "{classes:?}");
        assert_eq!(classes.iter().filter(|c| *c == "ad-box").count(), 1);
        assert!(ids.contains(&"main".to_string()), "{ids:?}");
        assert!(ids.contains(&"raw".to_string()), "{ids:?}");
    }

    #[test]
    fn token_scan_is_bounded() {
        let mut body = String::from("<html><body>");
        for i in 0..(MAX_CLASS_TOKENS + 50) {
            body.push_str(&format!("<div class=\"c{i}\"></div>"));
        }
        body.push_str("</body></html>");
        let (classes, _) = collect_class_id_tokens(body.as_bytes());
        assert_eq!(classes.len(), MAX_CLASS_TOKENS);
    }

    #[test]
    fn token_scan_ignores_non_attributes() {
        let body =
            b"<html><body><script>var classy = 1; var myid=2;</script><div>t</div></body></html>";
        let (classes, ids) = collect_class_id_tokens(body);
        assert!(classes.is_empty(), "{classes:?}");
        assert!(ids.is_empty(), "{ids:?}");
    }

    #[test]
    fn dechunk_state_hands_over_pieces_as_they_complete() {
        let mut state = DechunkState::new();
        let mut out = Vec::new();
        // Payload bytes go out as they arrive: the chunk is not complete yet.
        assert!(!state.push(b"5\r\nWi", &mut out).expect("chunks"));
        assert_eq!(out, b"Wikip"[..2].to_vec());
        assert!(!state.is_done());
        // The rest of that chunk, then the terminator.
        assert!(state.push(b"kip\r\n0\r\n\r\n", &mut out).expect("chunks"));
        assert_eq!(out, b"Wikip");
        assert!(state.is_done());
        assert_eq!(state.consumed(), 15);
    }

    #[test]
    fn dechunk_state_survives_a_split_at_any_boundary() {
        // Every byte boundary of the same stream must decode identically: a
        // chunk cut between its payload and its CRLF used to look like bad
        // framing, and a real origin (Wikipedia) does exactly that.
        let stream = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        let terminator = stream.len() - b"NEXT".len();
        for split in 0..=stream.len() {
            let mut state = DechunkState::new();
            let mut out = Vec::new();
            let first = state
                .push(&stream[..split], &mut out)
                .unwrap_or_else(|e| panic!("split {split}: {e}"));
            // The first half may already hold the terminator: what matters is
            // that no split is mistaken for bad framing.
            let _ = first;
            let done = state
                .push(&stream[split..], &mut out)
                .unwrap_or_else(|e| panic!("split {split}: {e}"));
            assert!(done, "split {split}: the terminator must be seen");
            assert_eq!(out, b"Wikipedia", "split {split}");
            if split < terminator {
                // The bytes that follow the body came in the second push, so
                // they stay in the buffer for the next response to find.
                assert_eq!(state.leftover(), b"NEXT", "split {split}");
            }
        }
    }

    #[test]
    fn dechunk_state_keeps_what_follows_the_body() {
        let mut state = DechunkState::new();
        let mut out = Vec::new();
        let stream = b"4\r\nWiki\r\n0\r\n\r\nHTTP/1.1 200 OK\r\n";
        assert!(state.push(stream, &mut out).expect("chunks"));
        assert_eq!(out, b"Wiki");
        assert_eq!(state.leftover(), b"HTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn gunzip_state_decodes_across_reads() {
        let plain: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let gz = gzip_encode(&plain).expect("gzip");
        let mut state = GunzipState::new();
        let mut out = Vec::new();
        for piece in gz.chunks(7) {
            state.push(piece, &mut out).expect("gzip");
        }
        assert!(state.is_done(), "the trailer must have gone by");
        assert_eq!(out, plain);
    }

    #[test]
    fn gunzip_state_skips_an_optional_name() {
        // Hand-built gzip member with FNAME set: the header grows past the
        // fixed ten bytes and the payload only starts after the NUL.
        let mut deflated = Vec::new();
        {
            use std::io::Write;
            let mut enc =
                flate2::write::DeflateEncoder::new(&mut deflated, flate2::Compression::fast());
            enc.write_all(b"<html><head></head></html>")
                .expect("deflate");
            enc.finish().expect("deflate");
        }
        let mut member = vec![0x1f, 0x8b, 8, 0x08, 0, 0, 0, 0, 0, 3];
        member.extend_from_slice(b"page.html\0");
        member.extend_from_slice(&deflated);
        member.extend_from_slice(&[0u8; 8]); // CRC32 + ISIZE, unchecked
        let mut state = GunzipState::new();
        let mut out = Vec::new();
        state.push(&member, &mut out).expect("gzip");
        assert!(state.is_done());
        assert_eq!(out, b"<html><head></head></html>");
    }

    #[test]
    fn gunzip_state_rejects_what_is_not_gzip() {
        let mut state = GunzipState::new();
        let mut out = Vec::new();
        assert!(state.push(b"not gzip at all", &mut out).is_err());
    }

    #[test]
    fn gzip_state_round_trips_with_the_streaming_encoder() {
        let plain: Vec<u8> = (0..30_000u32).map(|i| (i % 97) as u8).collect();
        let mut state = GzipState::new();
        let mut out = Vec::new();
        for piece in plain.chunks(1024) {
            state.push(piece, &mut out).expect("gzip");
        }
        state.finish(&mut out).expect("gzip");
        assert_eq!(decode_body(&out, Encoding::Gzip).expect("decodes"), plain);
    }

    #[test]
    fn chunk_frames_wrap_the_body() {
        let mut out = Vec::new();
        emit_chunk(&mut out, b"Wiki");
        emit_chunk(&mut out, b"");
        emit_chunk(&mut out, b"pedia");
        emit_last_chunk(&mut out);
        assert_eq!(out, b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
    }

    #[test]
    fn chunked_heads_replace_the_framing() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4242\r\nContent-Encoding: gzip\r\nContent-Security-Policy: script-src 'none'\r\n\r\n";
        let out = head_for_chunked_body(head, Some("gzip"));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Transfer-Encoding: chunked\r\n"), "{text}");
        assert!(text.contains("Content-Encoding: gzip\r\n"), "{text}");
        assert!(!text.to_lowercase().contains("content-length"), "{text}");
        // The policy is untouched here; the caller adds the nonce before this.
        assert!(
            text.contains("Content-Security-Policy: script-src 'none'\r\n"),
            "{text}"
        );
        assert!(text.ends_with("\r\n\r\n"), "{text}");
    }

    #[test]
    fn chunked_heads_are_dropped_when_the_body_is_not_compressed() {
        let head =
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n";
        let out = head_for_chunked_body(head, None);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.to_lowercase().contains("content-encoding"), "{text}");
        assert_eq!(
            text.matches("Transfer-Encoding: chunked").count(),
            1,
            "{text}"
        );
    }

    #[test]
    fn the_injection_point_prefers_head_close() {
        let body = b"<html><head><title>t</title></head><body>x</body></html>";
        let pos = injection_point(body).expect("a point");
        assert_eq!(&body[pos..pos + 7], b"</head>");
        assert_eq!(safe_injection_point(b"<html><head>"), b"<html><head>".len());
        assert_eq!(safe_injection_point(b"<html"), b"<html".len() - 5);
        assert_eq!(injection_point(b"<html><head>"), None);
    }

    #[test]
    fn injection_moves_before_the_first_resource_like_adguard() {
        // The measured AdGuard shape: after the metadata block, before the
        // first element that can fetch or render.
        let body = b"<html><head><meta charset=\"utf-8\"><title>t</title><!-- c --><link rel=\"icon\" href=\"/i.ico\"><style>x</style></head><body>";
        let pos = injection_point(body).expect("a point");
        assert_eq!(&body[pos..pos + 5], b"<link");
    }

    #[test]
    fn injection_waits_for_the_encoding_declaration() {
        // A script precedes the charset declaration: the anchor must not jump
        // in front of it, or a multi-kilobyte payload would push the
        // declaration past the parser's 1024-byte prescan window.
        let body = b"<head><script src=\"/a.js\"></script><meta charset=\"utf-8\"><link rel=\"icon\" href=\"/i.ico\"></head>";
        let pos = injection_point(body).expect("a point");
        assert_eq!(&body[pos..pos + 5], b"<link");
    }

    #[test]
    fn injection_lands_before_a_meta_policy() {
        // A `<meta http-equiv="content-security-policy">` governs everything
        // parsed after it and cannot be reached by the header rewrite: the
        // anchor is the policy meta itself, so the snippet stays outside it.
        let body = b"<html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\"><link rel=\"icon\" href=\"/i.ico\"></head>";
        let pos = injection_point(body).expect("a point");
        assert!(
            body[pos..].starts_with(b"<meta http-equiv="),
            "the anchor must be the policy meta: {:?}",
            String::from_utf8_lossy(&body[pos..])
        );
    }

    #[test]
    fn a_meta_policy_before_the_charset_does_not_jump_the_queue() {
        // Moving the payload in front of the policy meta would also move it in
        // front of the charset declaration that follows it, and a multi-
        // kilobyte payload would push that past the prescan window. The
        // encoding rule wins; such pages keep the anchor they had.
        let body = b"<head><meta http-equiv=\"content-security-policy\" content=\"script-src 'none'\"><meta charset=\"utf-8\"><link rel=\"icon\"></head>";
        let pos = injection_point(body).expect("a point");
        assert_eq!(&body[pos..pos + 5], b"<link");
    }

    #[test]
    fn injection_falls_back_to_head_close_without_a_charset_declaration() {
        let body = b"<head><link rel=\"icon\" href=\"/i.ico\"><style>x</style></head>";
        let pos = injection_point(body).expect("a point");
        assert_eq!(&body[pos..pos + 7], b"</head>");
    }

    #[test]
    fn injection_survives_an_unfinished_buffer() {
        assert_eq!(injection_point(b"<html><hea"), None);
        assert_eq!(injection_point(b"<html>"), None);
        assert_eq!(
            injection_point(b"<html><head><meta charset=\"utf-8\"><lin"),
            None
        );
        assert_eq!(
            injection_point(b"<html><head><script>var a = 1;</scr"),
            None
        );
        assert_eq!(
            injection_point(b"<html><head><meta charset=\"utf-8\"><!-- still open"),
            None
        );
    }

    #[test]
    fn a_charset_lookalike_inside_a_script_does_not_count() {
        // `<` bytes inside a raw-text element are not tags, and a string that
        // looks like a meta declaration is not one: a naive byte scan would
        // anchor inside the script.
        let body = b"<head><script>var m = '<meta charset=utf-8>'; if (a<b) {}</script><meta charset=utf-8><link rel=\"icon\"></head>";
        let pos = injection_point(body).expect("a point");
        assert_eq!(&body[pos..pos + 5], b"<link");
        let only_script =
            b"<head><script>document.write('<meta charset=x>')</script><link rel=\"icon\"></head>";
        let pos = injection_point(only_script).expect("a point");
        assert_eq!(&only_script[pos..pos + 7], b"</head>");
    }

    #[test]
    fn injection_falls_back_to_body_when_the_head_never_shows() {
        let body = b"<html><body><p>x</p></body></html>";
        let pos = injection_point(body).expect("a point");
        assert_eq!(&body[pos..pos + 7], b"</body>");
        let no_close = b"<html><body class=\"x\">t";
        let pos = injection_point(no_close).expect("a point");
        assert_eq!(pos, b"<html><body class=\"x\">".len());
    }

    #[test]
    fn a_header_is_not_a_head() {
        let body = b"<html><body><header>x</header><p>y";
        let pos = injection_point(body).expect("a point");
        assert_eq!(pos, b"<html><body>".len());
    }

    #[test]
    fn drop_headers_takes_the_line_and_its_continuations() {
        let head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nX-Drop: one\r\n folded onto it\r\nX-Keep: 3\r\n\r\n";
        let out = drop_headers(head, &["x-drop".to_string()]).expect("the line is there");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nX-Keep: 3\r\n\r\n"
        );
    }

    #[test]
    fn drop_headers_matches_whole_names_case_insensitively() {
        let head = b"HTTP/1.1 200 OK\r\nX-Frame-Options-Report: 1\r\nX-Frame-Options: DENY\r\n\r\n";
        let out = drop_headers(head, &["X-Frame-Options".to_string()]).expect("one line matches");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nX-Frame-Options-Report: 1\r\n\r\n"
        );
        assert!(drop_headers(head, &["missing".to_string()]).is_none());
        assert!(drop_headers(head, &[]).is_none());
    }

    #[test]
    fn apply_response_headers_appends_before_the_blank_line() {
        let mut head = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Drop: 1\r\n\r\n".to_vec();
        let edits = apply_response_headers(
            &mut head,
            &["x-drop".to_string()],
            &["worker-src 'none'".to_string()],
            &["browsing-topics=()".to_string(), "usb=()".to_string()],
        );
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\
             Content-Security-Policy: worker-src 'none'\r\n\
             Permissions-Policy: browsing-topics=()\r\n\
             Permissions-Policy: usb=()\r\n\r\n"
        );
        assert_eq!(edits.dropped, vec!["x-drop".to_string()]);
        assert_eq!(
            edits.added,
            vec![
                "Content-Security-Policy".to_string(),
                "Permissions-Policy".to_string(),
                "Permissions-Policy".to_string()
            ]
        );
    }

    #[test]
    fn apply_response_headers_leaves_an_unframed_head_alone() {
        // No blank line, no place to put a header: nothing is appended.
        let mut head = b"HTTP/1.1 200 OK\r\nX-Drop: 1".to_vec();
        let edits = apply_response_headers(&mut head, &[], &["worker-src 'none'".to_string()], &[]);
        assert!(edits.added.is_empty());
        assert_eq!(
            String::from_utf8(head).unwrap(),
            "HTTP/1.1 200 OK\r\nX-Drop: 1"
        );
    }

    #[test]
    fn cookie_helpers_read_the_headers_the_way_the_reference_does() {
        // A pair is a cookie only when it looks like `name=value` (the
        // reference skips the others), the name is trimmed of surrounding
        // spaces, and a name repeats once.
        let head = b"GET / HTTP/1.1\r\nCookie: a=1; b=2; a=1; nope; =x; c=\r\n\r\n";
        assert_eq!(
            request_cookie_names(head),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert!(request_cookie_names(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_empty());
        // A `set-cookie` names its cookie in the first non-empty `;`-part,
        // before the first `=`; the parts after it are options, not names.
        let head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2\r\nSet-Cookie: a=9\r\n\r\n";
        assert_eq!(
            set_cookie_names(head),
            vec!["a".to_string(), "b".to_string()]
        );
        // A `set-cookie` with no name cannot be parsed: it is none of the
        // rules' business, and it stays whatever they say.
        let head = b"HTTP/1.1 200 OK\r\nSet-Cookie: =novalue; a=b\r\n\r\n";
        assert!(set_cookie_names(head).is_empty());
        assert!(drop_set_cookie_headers(head, &["a".to_string()]).is_none());
    }

    #[test]
    fn drop_request_cookies_rebuilds_only_when_a_cookie_went() {
        let names = vec!["a".to_string()];
        // The header is re-serialised the way the reference writes one —
        // `name=value; name=value`, names and values trimmed — and only when
        // one of the names really went.
        let head = b"GET / HTTP/1.1\r\nCookie: a = 1 ; b=2 ; c =\r\n\r\n";
        let out = drop_request_cookies(head, &names).expect("a went");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET / HTTP/1.1\r\nCookie: b=2; c=\r\n\r\n"
        );
        // Every cookie gone: the header goes with them.
        let head = b"GET / HTTP/1.1\r\nCookie: a=1\r\nHost: x\r\n\r\n";
        let out = drop_request_cookies(head, &names).expect("a went");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        );
        // A pair the reference cannot read as a cookie is dropped with the
        // rebuild — the reference re-serialises cookies, not raw pairs.
        let head = b"GET / HTTP/1.1\r\nCookie: nope; a=1; b=2\r\n\r\n";
        let out = drop_request_cookies(head, &names).expect("a went");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET / HTTP/1.1\r\nCookie: b=2\r\n\r\n"
        );
        // A header the rules do not touch is no reason to rewrite anything.
        let head = b"GET / HTTP/1.1\r\nCookie: b=2; nope\r\n\r\n";
        assert!(drop_request_cookies(head, &names).is_none());
        assert!(drop_request_cookies(head, &["missing".to_string()]).is_none());
        assert!(drop_request_cookies(head, &[]).is_none());
    }

    #[test]
    fn drop_set_cookie_headers_takes_whole_lines_off() {
        let head = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2\r\nSet-Cookie: a=9\r\n\r\n";
        let (out, taken) = drop_set_cookie_headers(head, &["a".to_string(), "missing".to_string()])
            .expect("one went");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nSet-Cookie: b=2\r\n\r\n"
        );
        assert_eq!(taken, vec!["a".to_string()]);
        assert!(drop_set_cookie_headers(head, &["missing".to_string()]).is_none());
        assert!(drop_set_cookie_headers(head, &[]).is_none());
    }
}
