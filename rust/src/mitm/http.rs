//! Inject user scripts and cosmetic rules into HTML responses.
//!
//! The MITM stage only reads HTTP/1.1 bodies today, so this stays deliberately
//! simple: find the header/body boundary, check `content-type`, inject before
//! `</head>` or `</body>`, and **rewrite `content-length`** — without that the
//! client would hang or truncate the body.
//!
//! Injection also strips `content-security-policy` from the response: the
//! injected scripts are same-origin, but a strict `script-src` would still
//! block them (AdGuard relaxes CSP the same way).

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

/// Builds the `<script src=...>` tag for `src`.
pub fn script_tag(src: &str, defer: bool) -> String {
    let escaped = escape_attr(src);
    if defer {
        format!("<script src=\"{escaped}\" defer></script>")
    } else {
        format!("<script src=\"{escaped}\"></script>")
    }
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

/// True when the bytes start like a document that is safe to edit: a real
/// `<!doctype`/`<html` somewhere in the head of the file.
fn looks_like_html(body: &[u8]) -> bool {
    let lower: Vec<u8> = body.iter().map(|b| b.to_ascii_lowercase()).collect();
    find_ci(&lower, b"<html>").is_some() || find_ci(&lower, b"<!doc").is_some()
}

/// Where a snippet goes: at `</head>`, else at `</body>`, else just past the
/// opening `<body ...>` tag.
///
/// `None` means the document has not shown a home for it — the streaming
/// injector waits for more bytes rather than splitting a tag in half.
pub fn injection_point(body: &[u8]) -> Option<usize> {
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

/// Offset just past the last complete tag: the fallback home for a snippet when
/// the document never shows a `</head>`/`</body>`/`<body`.
pub fn safe_injection_point(body: &[u8]) -> usize {
    match body.iter().rposition(|b| *b == b'>') {
        Some(i) => i + 1,
        None => 0,
    }
}

/// Chèn một `<script src>` — the shape most callers and tests want.
pub fn inject_script(body: &[u8], src: &str) -> (Vec<u8>, Decision) {
    inject_snippet(body, script_tag(src, true).as_bytes())
}

/// Removes `content-security-policy` headers from a rewritten response.
///
/// Both the enforcing and report-only headers go: our scripts are injected
/// inline and from the page's own origin, and leaving a strict `script-src`
/// in place would silently drop every cosmetic rule on hardened sites.
pub fn strip_csp(headers: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(headers.len());
    for line in headers.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"content-security-policy:") {
            continue;
        }
        if lower.starts_with(b"content-security-policy-report-only:") {
            continue;
        }
        out.extend_from_slice(line);
    }
    out
}

/// Class and id tokens used by an HTML body, for generic `##.class` rules.
///
/// A byte scan instead of a parser: attributes are recognised by name
/// (`class`/`id`) followed by `=`, values split on whitespace and deduped.
/// False positives (a token inside a script or a comment) are harmless: the
/// lookup only ever returns rules that already exist in the lists.
pub fn collect_class_id_tokens(body: &[u8]) -> (Vec<String>, Vec<String>) {
    let mut classes = Vec::new();
    let mut ids = Vec::new();
    let mut seen_c = std::collections::HashSet::new();
    let mut seen_i = std::collections::HashSet::new();
    collect_tokens(body, b"class", &mut classes, &mut seen_c, MAX_CLASS_TOKENS);
    collect_tokens(body, b"id", &mut ids, &mut seen_i, MAX_ID_TOKENS);
    (classes, ids)
}

fn collect_tokens(
    body: &[u8],
    name: &[u8],
    out: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
    cap: usize,
) {
    let mut i = 0;
    while i < body.len() && out.len() < cap {
        if !body[i].eq_ignore_ascii_case(&name[0]) {
            i += 1;
            continue;
        }
        // The name must start an attribute, not sit inside a word or another
        // attribute's name (`myid=`, `data-class=`).
        if i > 0 {
            let prev = body[i - 1];
            if prev.is_ascii_alphanumeric() || prev == b'-' || prev == b'_' {
                i += 1;
                continue;
            }
        }
        if i + name.len() > body.len() || !body[i..i + name.len()].eq_ignore_ascii_case(name) {
            i += 1;
            continue;
        }
        let mut j = i + name.len();
        while j < body.len() && body[j] == b' ' {
            j += 1;
        }
        if j >= body.len() || body[j] != b'=' {
            i += 1;
            continue;
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
        for token in body[start..j.min(body.len())].split(|b| {
            matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'')
        }) {
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
        i = j;
    }
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

/// The facts the proxy needs from one response head.
#[derive(Clone, Copy, Debug)]
pub struct ResponseHead {
    pub status: u16,
    pub html: bool,
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

/// Parses a complete response head (up to and including the blank line).
pub fn parse_response_head(head: &[u8]) -> ResponseHead {
    let mut info = ResponseHead {
        status: 0,
        html: false,
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
/// compressed. Returns `None` when the buffer has no complete head, no
/// `accept: text/html`, or nothing to drop.
pub fn drop_undecodable_encodings(buf: &[u8]) -> Option<Vec<u8>> {
    let end = head_end(buf)?;
    let head = &buf[..end];
    if !head_accepts_html(head) {
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
                let ending = if line.ends_with(b"\r\n") { "\r\n" } else { "\n" };
                out.extend_from_slice(format!("{name}: {}{ending}", kept.join(", ")).as_bytes());
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
                    out.extend_from_slice(&self.buf[pos..pos + take]);
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
/// `trailer` go, CSP goes.
pub fn head_for_new_body(head: &[u8], body_len: usize, encoding: Option<&str>) -> Vec<u8> {
    let stripped = strip_csp(head);
    let mut out = Vec::with_capacity(stripped.len() + 32);
    let mut have_length = false;
    for line in stripped.split_inclusive(|b| *b == b'\n') {
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        if lower.starts_with(b"transfer-encoding:") || lower.starts_with(b"trailer:") {
            continue;
        }
        if lower.starts_with(b"content-encoding:") {
            if let Some(enc) = encoding {
                let name = header_name(line);
                out.extend_from_slice(
                    format!("{name}: {enc}{}", line_ending(line)).as_bytes(),
                );
            }
            continue;
        }
        if lower.starts_with(b"content-length:") {
            have_length = true;
            let name = header_name(line);
            out.extend_from_slice(
                format!("{name}: {body_len}{}", line_ending(line)).as_bytes(),
            );
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
    let stripped = strip_csp(head);
    let mut out = Vec::with_capacity(stripped.len() + 16);
    for line in stripped.split_inclusive(|b| *b == b'\n') {
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
/// length is unknowable up front), `content-encoding` follows `encoding`, CSP
/// goes.
pub fn head_for_chunked_body(head: &[u8], encoding: Option<&str>) -> Vec<u8> {
    let stripped = strip_csp(head);
    let mut out = Vec::with_capacity(stripped.len() + 32);
    let mut have_framing = false;
    for line in stripped.split_inclusive(|b| *b == b'\n') {
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
                .decompress(&data[pos..], &mut out[start..], flate2::FlushDecompress::None)
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

        let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n";
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
    fn growing_bodies_drop_any_csp() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Security-Policy: script-src 'self'\r\n\r\n";
        let text = String::from_utf8(head_for_bigger_body(head, 9)).unwrap();
        assert!(!text.contains("Content-Security-Policy"), "{text}");
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
    fn html_requests_stop_asking_for_brotli() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate, br, zstd\r\n\r\n";
        let out = drop_undecodable_encodings(req).expect("rewritten");
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Accept-Encoding: gzip, deflate\r\n"), "{text}");
        assert!(!text.contains("br"), "{text}");
        assert!(!text.contains("zstd"), "{text}");

        // Requests that do not ask for HTML keep their negotiation.
        let js = b"GET /a.js HTTP/1.1\r\nAccept: */*\r\nAccept-Encoding: br, zstd\r\n\r\n";
        assert!(drop_undecodable_encodings(js).is_none());

        // Nothing droppable: no rewrite at all, so the bytes stay identical.
        let gz = b"GET / HTTP/1.1\r\nAccept: text/html\r\nAccept-Encoding: gzip\r\n\r\n";
        assert!(drop_undecodable_encodings(gz).is_none());

        // Only undecodable tokens: the header goes away entirely.
        let only_br = b"GET / HTTP/1.1\r\nAccept: text/html\r\nAccept-Encoding: br\r\n\r\n";
        let out = drop_undecodable_encodings(only_br).expect("rewritten");
        assert!(!String::from_utf8(out).unwrap().contains("Accept-Encoding"));

        // Head still arriving: not our business yet.
        assert!(drop_undecodable_encodings(b"GET / HTTP/1.1\r\nAccept: text/htm").is_none());
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
    fn strips_both_csp_headers() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: script-src 'self'\r\nContent-Security-Policy-Report-Only: default-src 'none'\r\nX-Kept: yes\r\n\r\n";
        let out = String::from_utf8(strip_csp(head)).unwrap();
        assert!(!out.contains("Content-Security-Policy"), "{out}");
        assert!(out.contains("X-Kept: yes"), "{out}");
        assert!(out.contains("Content-Type: text/html"), "{out}");
    }

    #[test]
    fn strips_csp_case_insensitively() {
        let head = b"HTTP/1.1 200 OK\r\nCONTENT-SECURITY-POLICY: default-src 'self'\r\n\r\n";
        let out = String::from_utf8(strip_csp(head)).unwrap();
        assert!(!out.contains("CONTENT-SECURITY-POLICY"), "{out}");
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
    fn script_tag_escapes_and_defers() {
        assert_eq!(
            script_tag("/a.js", true),
            "<script src=\"/a.js\" defer></script>"
        );
        assert_eq!(script_tag("/a.js", false), "<script src=\"/a.js\"></script>");
        let escaped = script_tag("/a\"<b>", false);
        assert!(!escaped.contains("/a\"<b>"), "{escaped}");
        assert!(escaped.contains("&quot;") && escaped.contains("&lt;"), "{escaped}");
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
        let body = b"<html><body><script>var classy = 1; var myid=2;</script><div>t</div></body></html>";
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
            enc.write_all(b"<html><head></head></html>").expect("deflate");
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
        assert!(!text.to_lowercase().contains("content-security-policy"), "{text}");
        assert!(text.ends_with("\r\n\r\n"), "{text}");
    }

    #[test]
    fn chunked_heads_are_dropped_when_the_body_is_not_compressed() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n";
        let out = head_for_chunked_body(head, None);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.to_lowercase().contains("content-encoding"), "{text}");
        assert_eq!(text.matches("Transfer-Encoding: chunked").count(), 1, "{text}");
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
}
