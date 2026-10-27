//! Filter-list and userscript bodies: downloads, atomic writes, state.
//!
//! The files live under the store root (`filters/<id>.txt`,
//! `scripts/<id>.js`) so the platform never opens them: it asks for an
//! outcome, a small state snapshot, or the text itself. Downloads land in a
//! temp file and are renamed into place, so a killed process never leaves a
//! half-written list behind.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

/// AdFree's own request header, the same one the Kotlin client used.
const USER_AGENT: &str = "AdFree/1.0 (Android)";
/// Anything longer than this is not a filter list or script.
const MAX_BODY_BYTES: u64 = 32 * 1024 * 1024;

/// Filenames come from list/script ids; keep them to one safe path segment.
/// Mirrors the id sanitizer the platform used before this moved here.
pub fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .take(64)
        .collect()
}

pub fn asset_path(dir: &Path, id: &str, ext: &str) -> PathBuf {
    dir.join(format!("{}.{ext}", sanitize_id(id)))
}

/// Everything the UI wants to know about one downloaded file.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// Absolute path of the body on disk.
    pub path: PathBuf,
    /// Rule lines (filters only; 0 for scripts).
    pub line_count: i64,
    pub version: Option<String>,
    pub updated_text: Option<String>,
    pub detected_format: Option<String>,
    pub size_bytes: i64,
    pub modified_ms: i64,
}

/// Fetches a text body with a hard size cap and timeout. Used by the normal
/// list/script download and by `@require` resolution at install time.
pub fn fetch_text(url: &str, max_bytes: u64, timeout: Duration) -> Result<String, String> {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("the list has no URL".to_string());
    }
    let response = ureq::get(url)
        .set("User-Agent", USER_AGENT)
        .timeout(timeout)
        .call()
        .map_err(|e| e.to_string())?;
    if response.status() != 200 {
        return Err(format!("HTTP {}", response.status()));
    }
    let mut body = String::new();
    response
        .into_reader()
        .take(max_bytes)
        .read_to_string(&mut body)
        .map_err(|e| e.to_string())?;
    if body.trim().is_empty() {
        return Err("empty response".to_string());
    }
    Ok(body)
}

/// Downloads `url` into `dir/<id>.<ext>` through a temp file + rename.
/// `with_meta` also parses filter headers and counts rules; scripts only
/// need size and date.
pub fn fetch(
    dir: &Path,
    id: &str,
    ext: &str,
    url: &str,
    with_meta: bool,
) -> Result<Outcome, String> {
    let body = fetch_text(url, MAX_BODY_BYTES, Duration::from_secs(60))?;
    let path = save(dir, id, ext, &body)?;
    Ok(state_of(&path, &body, with_meta))
}

/// Writes `text` exactly like [`fetch`] would: temp file, then rename. Used
/// for lists the user imported from a file, and pasted rules.
pub fn save(dir: &Path, id: &str, ext: &str, text: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = asset_path(dir, id, ext);
    let tmp = path.with_extension(format!("{ext}.tmp"));
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    Ok(path)
}

/// The state of a file already on disk, or `None` when it was never saved.
/// Counting rules needs the body, so filters read it back; scripts do not.
pub fn state(dir: &Path, id: &str, ext: &str, with_meta: bool) -> Option<Outcome> {
    let path = asset_path(dir, id, ext);
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let mut out = Outcome {
        path: path.clone(),
        size_bytes: meta.len() as i64,
        modified_ms: modified_ms(&meta),
        ..Outcome::default()
    };
    if with_meta {
        if let Ok(text) = std::fs::read_to_string(&path) {
            fill_meta(&mut out, &text);
        }
    }
    Some(out)
}

/// Deletes the body (and any temp file left by an interrupted write).
pub fn remove(dir: &Path, id: &str, ext: &str) -> bool {
    let path = asset_path(dir, id, ext);
    let removed = std::fs::remove_file(&path).is_ok();
    let _ = std::fs::remove_file(path.with_extension(format!("{ext}.tmp")));
    removed
}

pub fn read_text(dir: &Path, id: &str, ext: &str) -> Option<String> {
    std::fs::read_to_string(asset_path(dir, id, ext)).ok()
}

/// Scripts the core ships itself, keyed by the id the platform's catalogue
/// uses. The body is written into the store like any downloaded one, so the
/// script list, its enable/disable state and the push path all work
/// unchanged; [`install_builtin`] only keeps the file in step with the body
/// this build ships.
pub const BUILTIN_SCRIPTS: &[(&str, &str)] = &[("adfree-extra", crate::filter::EXTRA_JS)];

/// Writes the built-in scripts into `dir`, skipping the ones whose body is
/// already the shipped one. Returns how many files were written.
pub fn install_builtin(dir: &Path) -> usize {
    let mut written = 0;
    for &(id, body) in BUILTIN_SCRIPTS {
        if read_text(dir, id, "js").as_deref() == Some(body) {
            continue;
        }
        if save(dir, id, "js", body).is_ok() {
            written += 1;
        }
    }
    written
}

fn state_of(path: &Path, body: &str, with_meta: bool) -> Outcome {
    let (size, modified) = std::fs::metadata(path)
        .map(|m| (m.len(), modified_ms(&m)))
        .unwrap_or((body.len() as u64, 0));
    let mut out = Outcome {
        path: path.to_path_buf(),
        size_bytes: size as i64,
        modified_ms: modified,
        ..Outcome::default()
    };
    if with_meta {
        fill_meta(&mut out, body);
    }
    out
}

fn fill_meta(out: &mut Outcome, body: &str) {
    let parsed = parse_meta(body);
    out.line_count = count_rules(body.lines());
    out.version = parsed.version;
    out.updated_text = parsed.updated_text;
    out.detected_format = parsed.format;
}

fn modified_ms(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Rule lines: the same filter the platform used before (headers, comments
/// and blanks are not rules).
fn count_rules<'a>(lines: impl Iterator<Item = &'a str>) -> i64 {
    lines
        .filter(|line| {
            let t = line.trim();
            !t.is_empty() && !t.starts_with('!') && !t.starts_with('[') && !t.starts_with('#')
        })
        .count() as i64
}

struct ParsedMeta {
    version: Option<String>,
    updated_text: Option<String>,
    format: Option<String>,
}

/// Header metadata AdGuard-style comments carry, plus a guess at the syntax.
/// Hosts lists look like `0.0.0.0 domain` lines instead of `||domain^`, and
/// the two formats are parsed differently, so this matters.
fn parse_meta(body: &str) -> ParsedMeta {
    let mut version = None;
    let mut updated = None;
    let mut hosts_like = 0usize;
    let mut adblock_like = 0usize;
    for line in body.lines().take(400) {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("! Version:") {
            version = Some(rest.trim().chars().take(40).collect());
        } else if let Some(rest) = t.strip_prefix("! TimeUpdated:") {
            updated = format_iso_date(rest).or(updated);
        } else if t.len() >= 3 && !t.starts_with('!') && !t.starts_with('#') && !t.starts_with('[')
        {
            if hosts_line(t) {
                hosts_like += 1;
            } else {
                adblock_like += 1;
            }
        }
    }
    let format = if hosts_like == 0 && adblock_like == 0 {
        None
    } else if hosts_like > adblock_like {
        Some("hosts".to_string())
    } else {
        Some("standard".to_string())
    };
    ParsedMeta {
        version,
        updated_text: updated,
        format,
    }
}

/// `0.0.0.0 example.com`, `::1 host`, ... — the hosts-file shape.
fn hosts_line(line: &str) -> bool {
    let mut parts = line.split_whitespace();
    let Some(addr) = parts.next() else {
        return false;
    };
    parts.next().is_some() && matches!(addr, "0.0.0.0" | "127.0.0.1" | "::1" | "::")
}

/// `2025-05-15T23:04:39+00:00` -> `15/05/2025 23:04`, what the rows show.
fn format_iso_date(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.len() < 19 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    Some(format!(
        "{}/{}/{} {}:{}",
        &s[8..10],
        &s[5..7],
        &s[0..4],
        &s[11..13],
        &s[14..16]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("adfree-assets-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn ids_become_one_safe_path_segment() {
        assert_eq!(sanitize_id("adguard-base"), "adguard_base");
        assert_eq!(sanitize_id("a/b c.d"), "a_b_c_d");
        assert_eq!(sanitize_id(&"x".repeat(80)).len(), 64);
    }

    #[test]
    fn builtin_scripts_are_written_once_and_kept_in_step() {
        let dir = temp_dir("builtin");
        // First run writes the shipped bodies.
        assert_eq!(install_builtin(&dir), BUILTIN_SCRIPTS.len());
        let (id, body) = BUILTIN_SCRIPTS[0];
        assert_eq!(read_text(&dir, id, "js").as_deref(), Some(body));
        // Second run has nothing to do.
        assert_eq!(install_builtin(&dir), 0);
        // A body that drifted (an app update ships a new stub) is refreshed.
        save(&dir, id, "js", "// stale").unwrap();
        assert_eq!(install_builtin(&dir), 1);
        assert_eq!(read_text(&dir, id, "js").as_deref(), Some(body));
    }

    #[test]
    fn save_state_remove_roundtrip() {
        let dir = temp_dir("roundtrip");
        let body = "\
! Title: Test list
! Version: 2.5.30
! TimeUpdated: 2025-05-15T23:04:39+00:00
||ads.example.com^
||track.example.net^
! a comment
";
        let path = save(&dir, "test-list", "txt", body).unwrap();
        assert!(path.exists());

        let info = state(&dir, "test-list", "txt", true).unwrap();
        assert_eq!(info.line_count, 2);
        assert_eq!(info.version.as_deref(), Some("2.5.30"));
        assert_eq!(info.updated_text.as_deref(), Some("15/05/2025 23:04"));
        assert_eq!(info.detected_format.as_deref(), Some("standard"));
        assert_eq!(info.size_bytes, body.len() as i64);
        assert!(info.modified_ms > 0);
        assert_eq!(info.path, path);

        assert_eq!(read_text(&dir, "test-list", "txt").as_deref(), Some(body));
        assert!(remove(&dir, "test-list", "txt"));
        assert!(state(&dir, "test-list", "txt", true).is_none());
        assert!(!remove(&dir, "test-list", "txt"));
    }

    #[test]
    fn hosts_lists_are_detected() {
        let dir = temp_dir("hosts");
        let body = "0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.net\n::1 v6.example.org\n";
        save(&dir, "hosts-list", "txt", body).unwrap();
        let info = state(&dir, "hosts-list", "txt", true).unwrap();
        assert_eq!(info.line_count, 3);
        assert_eq!(info.detected_format.as_deref(), Some("hosts"));
    }

    #[test]
    fn scripts_skip_filter_metadata() {
        let dir = temp_dir("scripts");
        save(&dir, "script_1", "js", "// ==UserScript==\ngetHost();\n").unwrap();
        let info = state(&dir, "script_1", "js", false).unwrap();
        assert_eq!(info.line_count, 0);
        assert_eq!(info.detected_format, None);
        assert!(info.size_bytes > 0);
    }

    #[test]
    fn interrupted_writes_leave_no_temp_behind() {
        let dir = temp_dir("temp");
        save(&dir, "plain", "txt", "||a.com^\n").unwrap();
        remove(&dir, "plain", "txt");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp files left: {leftovers:?}");
    }

    #[test]
    fn bad_urls_and_dates_are_rejected() {
        let dir = temp_dir("bad");
        assert!(fetch(&dir, "x", "txt", "ftp://example.com/list.txt", true).is_err());
        assert!(fetch_text("ftp://example.com/req.js", 1024, Duration::from_secs(1)).is_err());
        assert_eq!(format_iso_date("not a date"), None);
        assert_eq!(format_iso_date("short"), None);
    }
}
