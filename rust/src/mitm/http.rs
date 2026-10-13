//! Inject user scripts into HTML responses.
//!
//! The MITM stage only reads HTTP/1.1 bodies today, so this stays deliberately
//! simple: find the header/body boundary, check `content-type`, inject before
//! `</head>` or `</body>`, and **rewrite `content-length`** — without that the
//! client would hang or truncate the body.

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

/// Chèn `snippet` vào `body`.
///
/// `snippet` is a script URL the client fetches (e.g. `/adfree-user.js`); we
/// only emit one `<script src=...>` tag instead of bloating every response.
pub fn inject_script(body: &[u8], src: &str) -> (Vec<u8>, Decision) {
    if body.is_empty() || body.len() > MAX_INJECTABLE_BODY {
        return (body.to_vec(), Decision::Skip);
    }
    // Only inject when the body clearly looks like HTML.
    let lower: Vec<u8> = body.iter().map(|b| b.to_ascii_lowercase()).collect();
    if !lower.windows(6).any(|w| w == b"<html>") && !lower.windows(5).any(|w| w == b"<!doc") {
        return (body.to_vec(), Decision::Skip);
    }
    let escaped = escape_attr(src);
    let tag = format!("<script src=\"{escaped}\" defer></script>").into_bytes();

    // Prefer </head>, then </body>, then <body ...>.
    for needle in [b"</head>".as_slice(), b"</body>".as_slice()] {
        if let Some(pos) = find_ci(&lower, needle) {
            let mut out = Vec::with_capacity(body.len() + tag.len());
            out.extend_from_slice(&body[..pos]);
            out.extend_from_slice(&tag);
            out.extend_from_slice(&body[pos..]);
            return (out, Decision::Injected);
        }
    }
    if let Some(pos) = find_ci(&lower, b"<body") {
        // Insert right after the closing <body ...> tag.
        let end = match lower[pos..].iter().position(|b| *b == b'>') {
            Some(i) => pos + i + 1,
            None => return (body.to_vec(), Decision::NoInsertPoint),
        };
        let mut out = Vec::with_capacity(body.len() + tag.len());
        out.extend_from_slice(&body[..end]);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&body[end..]);
        return (out, Decision::Injected);
    }
    (body.to_vec(), Decision::NoInsertPoint)
}

/// Rewrite `content-length` after the body changed size.
///
/// Takes the whole header block and returns it with the length fixed.
pub fn fix_content_length(headers: &[u8], body_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(headers.len() + 16);
    for line in headers.split_inclusive(|b| *b == b'\n') {
        let mut line = line.to_vec();
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"content-length:") {
            // Keep the original header name's case: some clients are picky.
            let name_end = line
                .iter()
                .position(|b| *b == b':')
                .unwrap_or(line.len());
            let name = String::from_utf8_lossy(&line[..name_end]).to_string();
            let ending = if line.ends_with(b"\r\n") { "\r\n" } else { "\n" };
            line = format!("{name}: {body_len}{ending}").into_bytes();
        }
        out.append(&mut line);
    }
    out
}

/// Per-response decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Injectable {
    /// Uncompressed HTML: safe to inject.
    Html,
    /// Not HTML.
    Skip,
    /// Has `content-encoding` (gzip/br/zstd): decompression unsupported.
    Compressed,
    /// `transfer-encoding: chunked`: the length is unknown up front.
    Chunked,
}

/// Có nên chèn script cho response này không?
///
/// Only inject for HTML. Compressed responses are skipped: decoding and
/// re-encoding is a stage of its own, and doing it halfway breaks pages.
pub fn should_inject(headers: &[u8]) -> Injectable {
    let mut content_type_html = false;
    let mut chunked = false;
    let mut compressed = false;
    for line in headers.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"content-type:") {
            content_type_html = lower.windows(9).any(|w| w == b"text/html");
        } else if lower.starts_with(b"content-encoding:") {
            compressed = true;
        } else if lower.starts_with(b"transfer-encoding:") {
            chunked = lower.windows(7).any(|w| w == b"chunked");
        }
    }
    if compressed {
        Injectable::Compressed
    } else if !content_type_html {
        Injectable::Skip
    } else if chunked {
        Injectable::Chunked
    } else {
        Injectable::Html
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
        assert!(String::from_utf8(out).unwrap().contains("<script src=\"/a.js\""));

        let (out, d) = inject_script(b"<html><body><p>x</p></html>", "/a.js");
        assert_eq!(d, Decision::Injected);
        assert!(String::from_utf8(out).unwrap().starts_with("<html><body><script"));
    }

    #[test]
    fn skips_non_html_and_huge_bodies() {
        assert_eq!(inject_script(b"{\"json\":true}", "/a.js").1, Decision::Skip);
        assert_eq!(inject_script(b"", "/a.js").1, Decision::Skip);
        let big = vec![b'x'; MAX_INJECTABLE_BODY + 1];
        assert_eq!(inject_script(&big, "/a.js").1, Decision::Skip);
        // Không có tag html nào.
        assert_eq!(inject_script(b"just text", "/a.js").1, Decision::Skip);
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
        assert!(String::from_utf8(out).unwrap().contains("<script src=\"/a.js\""));
    }

    #[test]
    fn content_length_is_rewritten_case_insensitively() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        let out = fix_content_length(head, 7);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Content-Length: 7\r\n"), "{text}");
        assert!(text.contains("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn content_length_absent_is_left_alone() {
        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(fix_content_length(head, 3), head.to_vec());
    }

    #[test]
    fn only_html_responses_are_injected() {
        let html = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n";
        assert_eq!(should_inject(html), Injectable::Html);
        let js = b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n";
        assert_eq!(should_inject(js), Injectable::Skip);
        let gz = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n";
        assert_eq!(should_inject(gz), Injectable::Compressed);
        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(should_inject(chunked), Injectable::Chunked);
    }

    #[test]
    fn uppercase_html_is_detected() {
        let head = b"HTTP/1.1 200 OK\r\nCONTENT-TYPE: TEXT/HTML\r\n\r\n";
        assert_eq!(should_inject(head), Injectable::Html);
    }

    #[test]
    fn escapes_script_src() {
        // XSS hole in the injection point itself: always escape the value.
        let (out, _) = inject_script(b"<html><head></head></html>", "/a\" onload=\"x");
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("onload=\"x"), "the value must be escaped");
        assert!(text.contains("&quot;"));
    }
}
