//! `$hls` — the HLS playlist edits AdGuard filter lists ask for.
//!
//! CoreLibs implements `$hls`; the crate this engine is built on has never
//! seen the modifier, so both the matching (see
//! [`crate::filter::FilterEngine::hls_plan`]) and the edit itself live here.
//! This module is the edit half: the two matcher forms, the playlist model
//! and the rewrite.
//!
//! A `$hls` rule removes segments — media segment URLs, or the variant
//! playlist URLs of a master playlist; the reference draws no line between
//! the two — from the responses of the requests the rule matches:
//!
//! - `$hls=urlpattern` — the segment's URL, resolved against the playlist's
//!   own URL, matched by the engine's basic-rule matcher. The characters
//!   `/`, `$` and `,` arrive escaped (`\/`, `\$`, `\,`) and are unescaped
//!   here; a pattern still holding a `$` cannot be spelled on a network rule
//!   line, and such a rule is dropped rather than half-run.
//! - `$hls=/regexp/` — the segment's URL, resolved the same way, is searched
//!   by `regexp`. The knowledge base writes these in JavaScript regexp
//!   syntax; this engine compiles them with the Rust `regex` crate, and a
//!   regexp it cannot compile (a lookaround, a backreference) drops the rule.
//! - `$hls=/regexp/t` — the same search, but against each tag that applies
//!   to the segment: a segment holding a matching tag is removed. `i` makes
//!   the search case-insensitive, and may be combined with `t`.
//!
//! The playlist model is the knowledge base's (create-own-filters, `$hls`):
//! a line is empty, a URL, or a `#` line; the `#` lines that are recognized
//! tags are matched and removed positionally, everything else passes through
//! untouched and is never matched. A tag either applies to the first URL
//! line after it (single), to every URL line after it until the next tag of
//! the same name (multi), or to the whole playlist — playlist tags are never
//! removed and never matched. When a segment goes, its single tags go with
//! it; a multi tag goes when every segment it covered is gone. Multiple
//! matching rules are cumulative — the reference says so — and this module
//! reads every rule against the original playlist and unions the removals,
//! so the rules' order does not matter.
//!
//! Where this deviates from the reference, on purpose:
//!
//! - The body-size cap is [`crate::mitm::http::REPLACE_AFTER`] (512 KB),
//!   where the reference edits playlists up to 10 MB — this engine holds
//!   every edited body to the same cap, and playlists are small.
//! - The tag table holds the RFC 8216 tags and the two UPLYNK tags the
//!   knowledge base's example uses; a `t` rule naming any other `#` line
//!   finds it unrecognized, and the line is passed through untouched.
//! - The reference matches pattern-form values with basic-URL-rule semantics
//!   of its own; here they ride the crate, the same matcher every basic rule
//!   in this engine goes through.

use adblock::engine::Engine;
use adblock::filters::network::NetworkFilter;
use adblock::lists::{FilterSet, ParseOptions};
use adblock::request::Request;
use std::sync::Arc;

/// What a `$hls` value matches.
#[derive(Clone)]
pub enum HlsMatcher {
    /// `$hls=urlpattern`: the crate's own basic-rule matcher, holding the
    /// one converted pattern. `Arc` because a request's plan copies the
    /// matcher out of the engine build it borrowed from.
    Pattern(Arc<Engine>),
    /// `$hls=/regexp/`: the regexp, tested against the segment's URL.
    UrlRegex(regex::Regex),
    /// `$hls=/regexp/t`: the regexp, tested against the segment's tags.
    TagRegex(regex::Regex),
}

/// One parsed `$hls` rule, with the text it came from.
///
/// What a request's [`crate::filter::HlsPlan`] holds: the plan is built per
/// request and outlives the engine build it borrowed from, so the text and
/// the matcher are copied out of it.
#[derive(Clone)]
pub struct HlsRule {
    /// The rule exactly as the list wrote it: the log shows it.
    pub text: String,
    matcher: HlsMatcher,
}

impl HlsRule {
    pub fn new(text: String, matcher: HlsMatcher) -> HlsRule {
        HlsRule { text, matcher }
    }
}

/// Parses a `$hls` value. `None` when the value means something this engine
/// will not run — a rule that cannot run is a rule that must not half-run.
pub fn parse(value: &str) -> Option<HlsMatcher> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    match value.strip_prefix('/') {
        Some(rest) => regexp_matcher(rest),
        None => pattern_matcher(value),
    }
}

/// `$hls=/regexp/options`: the text between the opening `/` and `rest`.
fn regexp_matcher(value: &str) -> Option<HlsMatcher> {
    // The closing `/` is the first one not escaped as `\/` — the knowledge
    // base says a literal `/` inside the regexp must be escaped.
    let mut escaped = false;
    let mut close = None;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '/' => {
                close = Some(index);
                break;
            }
            _ => {}
        }
    }
    let close = close?;
    let (regexp, rest) = value.split_at(close);
    let flags = &rest[1..];
    let tags = flags.contains('t');
    let insensitive = flags.contains('i');
    if flags.len() != usize::from(tags) + usize::from(insensitive)
        || flags.chars().any(|flag| !matches!(flag, 'i' | 't'))
    {
        // The two options the knowledge base documents; anything else — an
        // unknown letter, the same letter twice — is a value the reference
        // would not read either, and no guess is made.
        return None;
    }
    let mut source = String::with_capacity(regexp.len() + 4);
    if insensitive {
        source.push_str("(?i)");
    }
    source.push_str(&unescape(regexp));
    let regex = regex::Regex::new(&source).ok()?;
    Some(if tags {
        HlsMatcher::TagRegex(regex)
    } else {
        HlsMatcher::UrlRegex(regex)
    })
}

/// `$hls=urlpattern`: the pattern half of a basic URL rule.
fn pattern_matcher(value: &str) -> Option<HlsMatcher> {
    let pattern = unescape(value);
    if pattern.is_empty() || pattern.contains('$') {
        // A `$` starts the option list of a network rule line: a literal one
        // cannot be spelled there, and the rule is dropped rather than run
        // as something else.
        return None;
    }
    // The crate validates the whole pattern the way it validates a basic
    // rule's: what it refuses there is refused here.
    NetworkFilter::parse(&pattern, false, ParseOptions::default()).ok()?;
    let mut set = FilterSet::new(false);
    set.add_filter_list(pattern, ParseOptions::default());
    Some(HlsMatcher::Pattern(Arc::new(Engine::new_with_filter_set(
        set,
    ))))
}

/// Undoes the rule-level escapes the knowledge base asks for: `\/`, `\$`
/// and `\,`. Every other `\x` pair belongs to the regexp or pattern language
/// and is kept as written.
fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some(next) if matches!(next, '/' | '$' | ',') => out.push(next),
            Some(next) => {
                out.push('\\');
                out.push(next);
            }
            None => out.push('\\'),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The playlist model
// ---------------------------------------------------------------------------

/// One line's role in the playlist.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    /// A URL line: the segment itself.
    Segment,
    /// A tag applying to the first URL line after it.
    Single,
    /// A tag applying to every URL line after it, until the next tag of the
    /// same name.
    Multi,
    /// A tag applying to the whole playlist: never matched, never removed.
    Playlist,
    /// An empty line, a comment, or a `#` line that is not a recognized
    /// tag: carried through untouched.
    Other,
}

/// The tags that apply to the whole playlist (RFC 8216): never matched by a
/// rule, never removed. The knowledge base: "`$hls` rules are intended for
/// segment removals".
const PLAYLIST_TAGS: &[&str] = &[
    "#EXTM3U",
    "#EXT-X-VERSION",
    "#EXT-X-TARGETDURATION",
    "#EXT-X-MEDIA-SEQUENCE",
    "#EXT-X-DISCONTINUITY-SEQUENCE",
    "#EXT-X-ENDLIST",
    "#EXT-X-PLAYLIST-TYPE",
    "#EXT-X-I-FRAMES-ONLY",
    "#EXT-X-START",
    "#EXT-X-INDEPENDENT-SEGMENTS",
    "#EXT-X-MEDIA",
    "#EXT-X-I-FRAME-STREAM-INF",
    "#EXT-X-SESSION-DATA",
    "#EXT-X-SESSION-KEY",
];

/// The tags that apply to every segment after them, until the tag with the
/// same name: RFC 8216's key/map tags, plus the UPLYNK pair the knowledge
/// base's example pins down.
const MULTI_TAGS: &[&str] = &[
    "#EXT-X-KEY",
    "#EXT-X-MAP",
    "#EXT-X-DATERANGE",
    "#UPLYNK-SEGMENT",
    "#UPLYNK-KEY",
];

/// The tags that apply to the first segment after them and to nothing else.
const SINGLE_TAGS: &[&str] = &[
    "#EXTINF",
    "#EXT-X-BYTERANGE",
    "#EXT-X-DISCONTINUITY",
    "#EXT-X-PROGRAM-DATE-TIME",
    "#EXT-X-STREAM-INF",
];

/// The name of a tag line: what comes before its first `:` or `,`, the way a
/// tag's name can be told from its attributes. `#EXTINF,5` and
/// `#EXT-X-TARGETDURATION:10` both name their tag.
fn tag_name(line: &str) -> &str {
    let end = line.find([':', ',']).unwrap_or(line.len());
    &line[..end]
}

/// What one line of a playlist is.
fn role_of(content: &str) -> Role {
    let content = content.trim();
    if content.is_empty() {
        return Role::Other;
    }
    if !content.starts_with('#') {
        return Role::Segment;
    }
    let name = tag_name(content);
    if PLAYLIST_TAGS.contains(&name) {
        Role::Playlist
    } else if SINGLE_TAGS.contains(&name) {
        Role::Single
    } else if MULTI_TAGS.contains(&name) {
        Role::Multi
    } else {
        Role::Other
    }
}

/// One URL line of the playlist.
struct Segment<'a> {
    /// The line index of the URL itself.
    line: usize,
    /// The URL as the line wrote it (terminators and surrounding whitespace
    /// trimmed).
    url: &'a str,
    /// The tags that apply to this segment, in playlist order: what a `t`
    /// rule reads.
    tags: Vec<&'a str>,
}

/// One tag line, with the segments it applies to.
struct Tag {
    /// The line index of the tag itself.
    line: usize,
    /// Whether the tag reaches past its first segment.
    multi: bool,
    /// The segment indexes it applies to, in playlist order.
    covered: Vec<usize>,
}

/// A parsed playlist: the segments and the tags that apply to them.
struct Playlist<'a> {
    segments: Vec<Segment<'a>>,
    tags: Vec<Tag>,
}

impl<'a> Playlist<'a> {
    fn parse(lines: &[&'a str]) -> Playlist<'a> {
        let mut segments: Vec<Segment<'a>> = Vec::new();
        let mut tags: Vec<Tag> = Vec::new();
        // Single tags waiting for the URL line they apply to.
        let mut pending: Vec<usize> = Vec::new();
        // Multi tags still open: `(name, tag index)`, one per name.
        let mut active: Vec<(String, usize)> = Vec::new();
        for (line, raw) in lines.iter().enumerate() {
            let content = raw.trim_end_matches(['\r', '\n']);
            match role_of(content) {
                Role::Segment => {
                    let mut attached: Vec<usize> = std::mem::take(&mut pending);
                    attached.extend(active.iter().map(|(_, tag)| *tag));
                    attached.sort_unstable();
                    let segment = segments.len();
                    for &tag in &attached {
                        tags[tag].covered.push(segment);
                    }
                    segments.push(Segment {
                        line,
                        url: content.trim(),
                        tags: attached
                            .iter()
                            .map(|&tag| lines[tags[tag].line].trim_end_matches(['\r', '\n']))
                            .collect(),
                    });
                }
                Role::Single => {
                    let tag = tags.len();
                    tags.push(Tag {
                        line,
                        multi: false,
                        covered: Vec::new(),
                    });
                    pending.push(tag);
                }
                Role::Multi => {
                    let name = tag_name(content.trim()).to_string();
                    if let Some(open) = active.iter().position(|(open, _)| *open == name) {
                        active.remove(open);
                    }
                    let tag = tags.len();
                    tags.push(Tag {
                        line,
                        multi: true,
                        covered: Vec::new(),
                    });
                    active.push((name, tag));
                }
                Role::Playlist | Role::Other => {}
            }
        }
        Playlist { segments, tags }
    }
}

// ---------------------------------------------------------------------------
// The rewrite
// ---------------------------------------------------------------------------

/// Applies the rules to one response body. `None` when no rule changed
/// anything: a body that is not an HLS playlist, and a playlist no rule
/// removes a segment from, go over untouched.
///
/// Every rule reads the original playlist — the reference calls the rules'
/// effect cumulative, and a removal cannot make a later rule match less —
/// and a rule counts as applied when it removes a segment no rule before it
/// had removed.
pub fn apply_rules(rules: &[HlsRule], base: &str, body: &[u8]) -> Option<(Vec<u8>, Vec<String>)> {
    let text = std::str::from_utf8(body).ok()?;
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    // An HLS playlist is UTF-8 text starting with the line `#EXTM3U`; any
    // other response is none of these rules' business.
    if lines.first()?.trim_end_matches(['\r', '\n']) != "#EXTM3U" {
        return None;
    }
    let playlist = Playlist::parse(&lines);
    if playlist.segments.is_empty() {
        return None;
    }
    // Segment URLs are matched as the player would read them: resolved
    // against the URL the playlist itself was fetched from.
    let urls: Vec<String> = playlist
        .segments
        .iter()
        .map(|segment| resolve(base, segment.url))
        .collect();
    let requests: Vec<Option<Request>> = urls
        .iter()
        .map(|url| Request::new(url, url, "other", "GET").ok())
        .collect();

    let mut removed = vec![false; playlist.segments.len()];
    let mut applied: Vec<String> = Vec::new();
    for rule in rules {
        let mut contributed = false;
        for (index, segment) in playlist.segments.iter().enumerate() {
            if removed[index] {
                continue;
            }
            if rule_matches(
                &rule.matcher,
                &urls[index],
                requests[index].as_ref(),
                &segment.tags,
            ) {
                removed[index] = true;
                contributed = true;
            }
        }
        if contributed {
            applied.push(rule.text.clone());
        }
    }
    if applied.is_empty() {
        return None;
    }

    // Removal propagation: a removed segment takes its single tags with it,
    // and a multi tag goes when every segment it covered is gone.
    let mut dropped = vec![false; lines.len()];
    for (segment, gone) in removed.iter().enumerate() {
        if *gone {
            dropped[playlist.segments[segment].line] = true;
        }
    }
    for tag in &playlist.tags {
        let gone = if tag.multi {
            !tag.covered.is_empty() && tag.covered.iter().all(|segment| removed[*segment])
        } else {
            tag.covered
                .first()
                .is_some_and(|segment| removed[*segment])
        };
        if gone {
            dropped[tag.line] = true;
        }
    }

    let mut out = Vec::with_capacity(body.len());
    for (line, raw) in lines.iter().enumerate() {
        if !dropped[line] {
            out.extend_from_slice(raw.as_bytes());
        }
    }
    Some((out, applied))
}

/// Whether one rule removes one segment.
fn rule_matches(
    matcher: &HlsMatcher,
    url: &str,
    request: Option<&Request>,
    tags: &[&str],
) -> bool {
    match matcher {
        HlsMatcher::Pattern(engine) => request
            .map(|request| engine.check_network_request(request).should_block())
            .unwrap_or(false),
        HlsMatcher::UrlRegex(regex) => regex.is_match(url),
        HlsMatcher::TagRegex(regex) => tags.iter().any(|tag| regex.is_match(tag)),
    }
}

/// Resolves a segment URL against the URL the playlist was fetched from —
/// the URL a player would resolve it to. Absolute URLs come back as they
/// are; a protocol-relative one takes the playlist's scheme; a relative one
/// is merged with the playlist's base path, dot segments and all (RFC 3986,
/// §5.2).
fn resolve(base: &str, url: &str) -> String {
    let url = url.trim();
    if let Some(scheme) = url.find("://") {
        if scheme > 0
            && url[..scheme]
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
        {
            return url.to_string();
        }
    }
    let (scheme, authority, base_path) = split_base(base);
    if let Some(rest) = url.strip_prefix("//") {
        return format!("{scheme}://{rest}");
    }
    if url.starts_with('/') {
        return format!("{scheme}://{authority}{}", normalize_path(url));
    }
    let directory = match base_path.rfind('/') {
        Some(index) => &base_path[..=index],
        None => "/",
    };
    format!(
        "{scheme}://{authority}{}",
        normalize_path(&format!("{directory}{url}"))
    )
}

/// Splits `scheme://authority/path…` into its three parts. A base with no
/// scheme is read as the path alone (the caller builds URLs from it).
fn split_base(base: &str) -> (&str, &str, &str) {
    let (scheme, rest) = match base.find("://") {
        Some(index) => (&base[..index], &base[index + 3..]),
        None => ("https", base),
    };
    match rest.find('/') {
        Some(index) => (scheme, &rest[..index], &rest[index..]),
        None => (scheme, rest, "/"),
    }
}

/// Removes the dot segments of a path (RFC 3986, §5.2.4), keeping the query
/// and fragment as they are. Close enough for matching: an empty path
/// component collapses with the next `/`, which no segment URL relies on.
fn normalize_path(path: &str) -> String {
    let (path, suffix) = match path.find(['?', '#']) {
        Some(index) => path.split_at(index),
        None => (path, ""),
    };
    let absolute = path.starts_with('/');
    let trailing =
        path.ends_with('/') || path.ends_with("/.") || path.ends_with("/..");
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let mut out = parts.join("/");
    if absolute {
        out.insert(0, '/');
    }
    if trailing && !out.ends_with('/') {
        out.push('/');
    }
    out.push_str(suffix);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(value: &str) -> HlsRule {
        HlsRule::new(
            format!("||stream.test^$hls={value}"),
            parse(value).expect("the value must parse"),
        )
    }

    const BASE: &str = "https://stream.test/hls/index.m3u8";

    /// The transformation the knowledge base's `$hls` section shows, rule for
    /// rule and byte for byte: the URL-pattern rule removes the preroll
    /// segment, the tag rule the segments the `,ad` marker covers, and the
    /// tags that applied only to the removed segments go with them.
    #[test]
    fn the_knowledge_base_transformation_is_reproduced() {
        let playlist = "\
#EXTM3U
#EXT-X-TARGETDURATION:10
#EXTINF,5
preroll.ts
#UPLYNK-SEGMENT:abc123,ad
#UPLYNK-KEY:aabb1122
#EXT-X-DISCONTINUITY
#EXTINF,10
01.ts
#EXTINF,10
02.ts
#UPLYNK-SEGMENT:abc123,segment
#UPLYNK-KEY:ccdd2233
#EXT-X-DISCONTINUITY
#EXTINF,10
01.ts
#EXTINF,10
02.ts
#EXT-X-ENDLIST
";
        let modified = "\
#EXTM3U
#EXT-X-TARGETDURATION:10
#UPLYNK-SEGMENT:abc123,segment
#UPLYNK-KEY:ccdd2233
#EXT-X-DISCONTINUITY
#EXTINF,10
01.ts
#EXTINF,10
02.ts
#EXT-X-ENDLIST
";
        let rules = [
            rule("preroll"),
            rule("/#UPLYNK-SEGMENT:.*\\,ad/t"),
        ];
        let (out, applied) = apply_rules(&rules, "https://example.org/master.m3u8", playlist.as_bytes())
            .expect("the rules remove segments");
        assert_eq!(String::from_utf8(out).expect("utf8"), modified);
        assert_eq!(applied, vec![rules[0].text.clone(), rules[1].text.clone()]);
    }

    /// A tag rule removes the segments the tag applies to: a single tag
    /// covers only the URL line after it, a multi tag every line until the
    /// next tag of the same name.
    #[test]
    fn tag_rules_read_the_tags_that_apply_to_each_segment() {
        let playlist = "\
#EXTM3U
#EXT-X-CUE-OUT:DURATION=30
#EXTINF:10,
01.ts
#EXTINF:10,
02.ts
#EXT-X-CUE-IN
#EXTINF:10,
03.ts
";
        // `#EXT-X-CUE-OUT` is not a recognized tag: the rule finds nothing.
        let rules = [rule("/CUE-OUT/t")];
        assert!(
            apply_rules(&rules, BASE, playlist.as_bytes()).is_none(),
            "an unrecognized tag must not be matched"
        );
        // A recognized multi tag reaching both 01.ts and 02.ts: both go, and
        // the segments' own `#EXTINF` lines go with them.
        let playlist = playlist.replace("#EXT-X-CUE-OUT:DURATION=30", "#EXT-X-KEY:METHOD=NONE");
        let rules = [rule("/METHOD=NONE/t")];
        let (out, applied) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(applied.len(), 1);
        assert!(
            !text.contains("01.ts") && !text.contains("02.ts") && !text.contains("03.ts"),
            "every segment the key covers must go: {text}"
        );
        assert!(
            !text.contains("#EXT-X-KEY"),
            "the key goes with its segments: {text}"
        );
        assert!(
            text.contains("#EXT-X-CUE-IN"),
            "the unrecognized tag is carried through: {text}"
        );
    }

    /// When a multi tag covers several segments and only some of them are
    /// removed, the tag stays.
    #[test]
    fn a_multi_tag_survives_while_one_covered_segment_remains() {
        let playlist = "\
#EXTM3U
#EXT-X-KEY:METHOD=NONE
#EXTINF:10,
01.ts
#EXTINF:10,
02.ts
";
        // One segment goes (the pattern names it), the key still covers the
        // other: both stay.
        let rules = [rule("01.ts")];
        let (out, _) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("#EXT-X-KEY"), "{text}");
        assert!(!text.contains("01.ts"), "{text}");
        assert!(text.contains("02.ts"), "{text}");
    }

    /// Playlist-level tags are never matched and never removed — the
    /// knowledge base keeps `$replace` for those.
    #[test]
    fn playlist_tags_are_left_in_place() {
        let playlist = "\
#EXTM3U
#EXT-X-TARGETDURATION:10
#EXTINF:10,
01.ts
#EXT-X-ENDLIST
";
        let rules = [rule("/TARGETDURATION/t")];
        assert!(
            apply_rules(&rules, BASE, playlist.as_bytes()).is_none(),
            "a playlist tag is not a removal candidate"
        );
    }

    /// A body that is not an HLS playlist is left alone: no `#EXTM3U` first
    /// line, not UTF-8, or no segment for the rules to remove.
    #[test]
    fn only_playlists_are_edited() {
        let rules = [rule("01.ts")];
        assert!(apply_rules(&rules, BASE, b"{\"a\": 1}").is_none());
        assert!(apply_rules(&rules, BASE, b"").is_none());
        assert!(apply_rules(&rules, BASE, &[0xff, 0xfe, 0x00]).is_none());
        assert!(
            apply_rules(&rules, BASE, b"#EXTM3U\n#EXT-X-ENDLIST\n").is_none(),
            "a playlist without segments cannot change"
        );
        assert!(
            apply_rules(&rules, BASE, b" #EXTM3U\n01.ts\n").is_none(),
            "the signature must be the first line"
        );
    }

    /// Segment URLs are matched as the player would read them: resolved
    /// against the playlist's own URL.
    #[test]
    fn segments_match_through_their_resolved_urls() {
        let playlist = "\
#EXTM3U
#EXTINF:10,
../ads/preroll.ts
#EXTINF:10,
01.ts
#EXTINF:10,
//cdn.other.test/x/02.ts
";
        let rules = [rule("||stream.test/ads/")];
        let (out, _) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains("preroll.ts"), "{text}");
        assert!(text.contains("01.ts"), "a sibling stays: {text}");
        assert!(text.contains("02.ts"), "another host stays: {text}");

        let rules = [rule("||cdn.other.test/x/")];
        let (out, _) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains("02.ts"), "the protocol-relative URL resolves: {text}");
    }

    /// The regexp forms: `\/` `\$` `\,` arrive escaped, `i` decides case,
    /// `t` reads tags.
    #[test]
    fn the_regexp_forms_read_their_escapes_and_flags() {
        // The shape the live corpus ships, verbatim.
        let playlist = "\
#EXTM3U
#EXTINF:10,
https://redirector.googlevideo.com/videoplayback?dur=1&source=dclk_video_ads
#EXTINF:10,
https://redirector.googlevideo.com/videoplayback?dur=1&source=clean
";
        let rules = [rule("/redirector\\.googlevideo\\.com\\/videoplayback[\\s\\S]*?dclk_video_ads/")];
        let (out, _) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains("dclk_video_ads"), "{text}");
        assert!(text.contains("source=clean"), "{text}");

        let playlist = "#EXTM3U\n#EXTINF:10,\nhttps://cdn.test/AD/spot.ts\n";
        let rules = [rule("/ad\\/spot\\.ts/i")];
        assert!(
            apply_rules(&rules, BASE, playlist.as_bytes()).is_some(),
            "the i flag makes the search case-insensitive"
        );

        let playlist = "#EXTM3U\n#UPLYNK-SEGMENT:abc,AD\n#EXTINF:10,\n01.ts\n";
        let rules = [rule("/uplynk-segment:.*,ad/ti")];
        assert!(
            apply_rules(&rules, BASE, playlist.as_bytes()).is_some(),
            "t and i combine"
        );
    }

    /// Pattern-form values ride the engine's basic-rule matcher: `||`
    /// anchors, `*` wildcards and the escaped leading `/`.
    #[test]
    fn pattern_values_match_like_basic_url_rules() {
        let playlist = "\
#EXTM3U
#EXTINF:10,
/preroll.ts
#EXTINF:10,
https://cdn.ads.test/x/spot.ts
#EXTINF:10,
01.ts
";
        let rules = [rule("\\/preroll.ts")];
        let (out, _) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains("preroll.ts"), "{text}");

        let rules = [rule("||cdn.ads.test^")];
        let (out, _) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert!(!text.contains("spot.ts"), "{text}");
        assert!(text.contains("01.ts"), "{text}");
    }

    /// CRLF playlists keep their line endings, removals included.
    #[test]
    fn crlf_playlists_keep_their_line_endings() {
        let playlist = "#EXTM3U\r\n#EXTINF:10,\r\nad.ts\r\n#EXTINF:10,\r\n01.ts\r\n";
        let rules = [rule("ad.ts")];
        let (out, _) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        assert_eq!(
            String::from_utf8(out).expect("utf8"),
            "#EXTM3U\r\n#EXTINF:10,\r\n01.ts\r\n"
        );
    }

    /// Every matching rule is cumulative, and the order they are read in does
    /// not change the removals.
    #[test]
    fn the_rules_are_cumulative() {
        let playlist = "\
#EXTM3U
#EXTINF:10,
ad.ts
#EXTINF:10,
01.ts
#EXTINF:10,
02.ts
";
        let rules = [rule("ad.ts"), rule("02.ts")];
        let (out, applied) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert_eq!(applied.len(), 2);
        assert!(!text.contains("ad.ts") && !text.contains("02.ts"), "{text}");
        assert!(text.contains("01.ts"), "{text}");
        // Reversed, the same playlist comes out the same.
        let reversed = [rule("02.ts"), rule("ad.ts")];
        let (out, _) = apply_rules(&reversed, BASE, playlist.as_bytes()).expect("removal");
        assert_eq!(String::from_utf8(out).expect("utf8"), text);
    }

    /// A rule that removes only segments an earlier rule had already removed
    /// is not reported as applied.
    #[test]
    fn a_rule_with_nothing_left_to_remove_is_not_applied() {
        let playlist = "#EXTM3U\n#EXTINF:10,\nad.ts\n#EXTINF:10,\n01.ts\n";
        let rules = [rule("/ad\\.ts/"), rule("ad.ts")];
        let (_, applied) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        assert_eq!(applied, vec![rules[0].text.clone()]);
    }

    /// Tags left dangling — no segment after them — are carried through.
    #[test]
    fn dangling_tags_are_left_alone() {
        let playlist = "#EXTM3U\n#EXTINF:10,\nad.ts\n#EXT-X-KEY:METHOD=NONE\n#EXTINF:10,\n";
        let rules = [rule("/METHOD=NONE/t")];
        assert!(
            apply_rules(&rules, BASE, playlist.as_bytes()).is_none(),
            "a tag covering no segment is not a removal candidate"
        );
        let rules = [rule("ad.ts")];
        let (out, _) = apply_rules(&rules, BASE, playlist.as_bytes()).expect("removal");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("#EXT-X-KEY"), "{text}");
    }

    /// Everything the live corpus carries parses; the values the engine
    /// cannot run are dropped.
    #[test]
    fn the_live_corpus_values_all_parse() {
        let values = [
            "/redirector\\.googlevideo\\.com\\/videoplayback[\\s\\S]*?dclk_video_ads/",
            "/https:\\/\\/prism-ads-cdn\\.a2d\\.tv\\//",
            "/#UPLYNK-SEGMENT:.*\\,ad/t",
        ];
        for value in values {
            assert!(parse(value).is_some(), "{value} must parse");
        }
    }

    /// Values this engine will not run are dropped rather than half-run.
    #[test]
    fn values_the_engine_cannot_run_are_dropped() {
        for value in [
            "",
            "/no closing slash",
            "/re/x",
            "/re/tt",
            // A lookahead the Rust regex crate cannot compile.
            "/ad(?=\\.ts)/",
            // A literal `$` cannot be spelled on a network rule line.
            "cost\\$1",
        ] {
            assert!(parse(value).is_none(), "{value:?} must be dropped");
        }
        // A pattern with an escaped comma is fine.
        assert!(parse("a\\,b").is_some());
    }

    /// The §5.2 resolution the segment matching rides.
    #[test]
    fn segment_urls_resolve_against_the_playlist() {
        let base = "https://h.test/a/b/c.m3u8";
        assert_eq!(resolve(base, "d.ts"), "https://h.test/a/b/d.ts");
        assert_eq!(resolve(base, "../x/d.ts"), "https://h.test/a/x/d.ts");
        assert_eq!(resolve(base, "./d.ts?v=1"), "https://h.test/a/b/d.ts?v=1");
        assert_eq!(resolve(base, "/x.ts"), "https://h.test/x.ts");
        assert_eq!(resolve(base, "../"), "https://h.test/a/");
        assert_eq!(resolve(base, "//other.test/x.ts"), "https://other.test/x.ts");
        assert_eq!(resolve(base, "http://other.test/x.ts"), "http://other.test/x.ts");
        assert_eq!(resolve(base, "https://h.test/x.ts"), "https://h.test/x.ts");
    }
}
