//! Bounded event log produced by the packet engine.
//!
//! The design goal is that the NATIVE hot path must never allocate and must
//! never block: entries are written into a preallocated ring of fixed-size
//! records with inline strings, and the JNI layer copies them into a direct
//! `ByteBuffer` for the UI. Nothing is created per packet, so the log costs the
//! packet path a few stores.
//!
//! ## Wire format (what `drain_into` writes)
//!
//! ```text
//! 0..8    ts_ms          u64
//! 8       action         u8   0=allow 1=block 2=tcp-reset 3=udp-drop 4=quic-drop 5=hosts-block
//! 9       category       u8
//! 10      flags          u8   bit0=ipv6 bit1=has-rule bits2..3=transport bit4=roaming bits5..7=protocol
//! 11      domain_len     u8
//! 12      ip_len         u8
//! 13      rule_len       u8
//! 14      list_len       u8
//! 15      app_len        u8
//! 16..20  latency_ns     u32
//! 20..24  bytes_saved    u32
//! 24      req_type       u8   one of req_type::*
//! 25      tls_ver        u8   one of tls_ver::*
//! 26..    domain[domain_len] ip[ip_len] rule[rule_len] list[list_len]
//!         app[app_len]
//!         flow_id u32, bytes_sent u32, bytes_recv u32,
//!         url_len u8, answer_len u8, source_len u8, cipher_len u8, ctype_len u8,
//!         status u16,
//!         url[url_len], answer[answer_len], source[source_len],
//!         cipher[cipher_len], ctype[ctype_len]
//! ```
//!
//! `req_type` and `tls_ver` sit at the end of the header and the lengths of the
//! strings at the end of the trailer, so a reader written against the older
//! layout keeps every offset it already computes.

pub const ACTION_ALLOW: u8 = 0;
pub const ACTION_BLOCK: u8 = 1;
pub const ACTION_TCP_RESET: u8 = 2;
pub const ACTION_UDP_DROP: u8 = 3;
pub const ACTION_QUIC_DROP: u8 = 4;

/// Transport the flow travelled on, packed into `flags`.
pub const TRANSPORT_UNKNOWN: u8 = 0;
pub const TRANSPORT_WIFI: u8 = 1;
pub const TRANSPORT_CELLULAR: u8 = 2;

const FLAG_IPV6: u8 = 0b0000_0001;
const FLAG_HAS_RULE: u8 = 0b0000_0010;
const FLAG_TRANSPORT_MASK: u8 = 0b0000_1100;
const FLAG_ROAMING: u8 = 0b0001_0000;
/// Which protocol the decision was made on, in the three bits above roaming.
/// Zero means the row never said: the reader falls back on what the action
/// implies, which is how the rows written before this byte exists still read.
const FLAG_PROTOCOL_MASK: u8 = 0b1110_0000;
const FLAG_PROTOCOL_SHIFT: u32 = 5;

/// The transports a log row can name, in the order the UI's own enum lists
/// them. `NONE` is zero so an event built without one stays unread.
pub mod protocol {
    pub const NONE: u8 = 0;
    pub const DNS_UDP: u8 = 1;
    pub const DNS_DOT: u8 = 2;
    pub const DNS_DOH: u8 = 3;
    pub const HTTPS: u8 = 4;
    pub const QUIC: u8 = 5;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 7;
}

pub const MAX_DOMAIN: usize = 96;
pub const MAX_IP: usize = 40;
pub const MAX_RULE: usize = 72;
pub const MAX_LIST: usize = 24;
/// Package name of the app that owned the flow. A uid can resolve to several
/// packages; the log keeps the first, which is what attribution reports.
pub const MAX_APP: usize = 96;
/// Request URL for HTTPS decisions made after TLS termination. Capped so the
/// ring stays small; callers that only know the host leave it empty.
pub const MAX_URL: usize = 128;
/// First address(es) of a DNS answer, when the engine produced it itself.
pub const MAX_ANSWER: usize = 64;
/// The referrer a request carried. AdGuard's log shows it as `Source`, and it
/// is what tells a user which page — or which app — asked for this one.
pub const MAX_SOURCE: usize = 96;
/// The cipher suite the upstream TLS session negotiated, in the IANA name
/// rustls reports (`TLS13_AES_256_GCM_SHA384`). Longest real name is 39 bytes.
pub const MAX_CIPHER: usize = 40;
/// The MIME type the response declared, without its parameters. AdGuard names
/// this `Content-Type`, and a truncated one still tells the user what arrived.
pub const MAX_CTYPE: usize = 32;
/// Who the server a session talked to said it was, and who signed the proof.
/// A full distinguished name runs past 200 bytes and says nothing more than
/// the attribute that names the party, so the writers store that one (see
/// [`crate::mitm::tls::peer_cert`]).
pub const MAX_CERT_NAME: usize = 96;
const RECORD_HEADER: usize = 26;
/// Fixed bytes appended after the variable-name tail (flow id, traffic, the
/// seven length bytes, the response status, the certificate's validity window).
const RECORD_TRAILER: usize = 37;

/// What kind of thing a decision was about, in the words the log's tabs use.
///
/// The filter speaks in rule modifiers (`$script`, `$image`), the log speaks in
/// request kinds, and the two only agree at one edge: [`req_type::of`]. The
/// names below are stable because the database row, the exported file and the
/// UI's tabs all key on them.
pub mod req_type {
    pub const OTHER: u8 = 0;
    pub const DOCUMENT: u8 = 1;
    pub const STYLESHEET: u8 = 2;
    pub const SCRIPT: u8 = 3;
    pub const XHR: u8 = 4;
    pub const IMAGE: u8 = 5;
    pub const FONT: u8 = 6;
    pub const MEDIA: u8 = 7;
    pub const WEBSOCKET: u8 = 8;
    pub const DNS: u8 = 9;
    pub const CONNECTION: u8 = 10;

    pub fn name(code: u8) -> &'static str {
        match code {
            DOCUMENT => "document",
            STYLESHEET => "stylesheet",
            SCRIPT => "script",
            XHR => "xhr",
            IMAGE => "image",
            FONT => "font",
            MEDIA => "media",
            WEBSOCKET => "websocket",
            DNS => "dns",
            CONNECTION => "connection",
            _ => "other",
        }
    }

    /// Maps a resource name onto a code. A `$document` request and an iframe
    /// are the same tab, and anything without a tab of its own — a CSP report,
    /// a ping, an oddball modifier — is the `other` the last tab collects.
    pub fn of(text: &str) -> u8 {
        match text {
            "document" | "subdocument" => DOCUMENT,
            "stylesheet" => STYLESHEET,
            "script" => SCRIPT,
            "xmlhttprequest" => XHR,
            "image" => IMAGE,
            "font" => FONT,
            "media" => MEDIA,
            "websocket" => WEBSOCKET,
            "dns" => DNS,
            "connection" => CONNECTION,
            _ => OTHER,
        }
    }
}

/// The TLS version a session actually negotiated, named the way the log shows
/// it. The core chooses the spelling once so the database row, the exported
/// file and the UI agree, exactly like [`req_type`].
pub mod tls_ver {
    /// Nothing was encrypted: a plaintext request, or a connection refused
    /// before its handshake.
    pub const NONE: u8 = 0;
    pub const TLS12: u8 = 1;
    pub const TLS13: u8 = 2;

    pub fn name(code: u8) -> &'static str {
        match code {
            TLS12 => "TLS 1.2",
            TLS13 => "TLS 1.3",
            _ => "",
        }
    }
}

/// Events kept in the live ring. The durable log is the database the store
/// writes first ([`crate::store`]); this ring only feeds the in-process tail,
/// and an `Event` is past 700 bytes now that the TLS version, the cipher
/// suite and the HTTP answer ride with it, so the previous 4 096 slots would
/// have held ~3 MB of anonymous memory for a buffer a poll of the tail drains
/// in one go.
const CAPACITY: usize = 512;

#[derive(Clone, Copy)]
pub struct Event {
    pub ts_ms: u64,
    pub action: u8,
    pub category: u8,
    pub flags: u8,
    pub latency_ns: u32,
    pub bytes_saved: u32,
    /// Monotonic id the core assigns to every logged decision; stable across
    /// the ring and the database row.
    pub flow_id: u32,
    pub bytes_sent: u32,
    pub bytes_recv: u32,
    /// One of [`req_type`]: what the decision was about, not which rule made
    /// it. `OTHER` is the zero, so an event built without a type reads as the
    /// tab AdGuard puts everything unclassified in.
    pub req_type: u8,
    /// One of [`tls_ver`]: what the upstream session negotiated, `NONE` when
    /// nothing was encrypted or the row's decision never reached a handshake.
    pub tls_ver: u8,
    /// The HTTP status the origin answered with, 0 when the request never got
    /// an HTTP answer (a block, a DNS row, a refused connection).
    pub status: u16,
    pub domain: [u8; MAX_DOMAIN],
    pub domain_len: u8,
    pub ip: [u8; MAX_IP],
    pub ip_len: u8,
    pub rule: [u8; MAX_RULE],
    pub rule_len: u8,
    pub list: [u8; MAX_LIST],
    pub list_len: u8,
    pub app: [u8; MAX_APP],
    pub app_len: u8,
    pub url: [u8; MAX_URL],
    pub url_len: u8,
    pub answer: [u8; MAX_ANSWER],
    pub answer_len: u8,
    pub source: [u8; MAX_SOURCE],
    pub source_len: u8,
    pub cipher: [u8; MAX_CIPHER],
    pub cipher_len: u8,
    pub ctype: [u8; MAX_CTYPE],
    pub ctype_len: u8,
    /// The subject and issuer of the certificate the upstream TLS session
    /// presented, empty when the row never saw one.
    pub cert_subj: [u8; MAX_CERT_NAME],
    pub cert_subj_len: u8,
    pub cert_iss: [u8; MAX_CERT_NAME],
    pub cert_iss_len: u8,
    /// That certificate's validity window in epoch milliseconds, 0 when there
    /// was no certificate. A day is all the log shows, so seconds would do,
    /// but the platform's date helpers already speak milliseconds.
    pub cert_from: i64,
    pub cert_to: i64,
}

impl Event {
    pub const fn zeroed() -> Self {
        Event {
            ts_ms: 0,
            action: 0,
            category: 0,
            flags: 0,
            latency_ns: 0,
            bytes_saved: 0,
            flow_id: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            req_type: req_type::OTHER,
            tls_ver: tls_ver::NONE,
            status: 0,
            domain: [0; MAX_DOMAIN],
            domain_len: 0,
            ip: [0; MAX_IP],
            ip_len: 0,
            rule: [0; MAX_RULE],
            rule_len: 0,
            list: [0; MAX_LIST],
            list_len: 0,
            app: [0; MAX_APP],
            app_len: 0,
            url: [0; MAX_URL],
            url_len: 0,
            answer: [0; MAX_ANSWER],
            answer_len: 0,
            source: [0; MAX_SOURCE],
            source_len: 0,
            cipher: [0; MAX_CIPHER],
            cipher_len: 0,
            ctype: [0; MAX_CTYPE],
            ctype_len: 0,
            cert_subj: [0; MAX_CERT_NAME],
            cert_subj_len: 0,
            cert_iss: [0; MAX_CERT_NAME],
            cert_iss_len: 0,
            cert_from: 0,
            cert_to: 0,
        }
    }

    /// Records the network the decision was made on. Called in one place
    /// (`Core::log_event`) so no call site has to thread it through.
    pub fn set_network(&mut self, transport: u8, roaming: bool) {
        let bits = (transport & 0b11) << 2;
        self.flags = (self.flags & !(FLAG_TRANSPORT_MASK | FLAG_ROAMING))
            | bits
            | if roaming { FLAG_ROAMING } else { 0 };
    }

    pub fn transport(&self) -> u8 {
        (self.flags & FLAG_TRANSPORT_MASK) >> 2
    }

    pub fn roaming(&self) -> bool {
        self.flags & FLAG_ROAMING != 0
    }

    /// Which protocol the row belongs to, as a [`protocol`] code. `NONE` when
    /// the writer did not say, which is every row stored before this existed.
    pub fn set_protocol(&mut self, code: u8) {
        self.flags =
            (self.flags & !FLAG_PROTOCOL_MASK) | ((code & 0b111) << FLAG_PROTOCOL_SHIFT);
    }

    pub fn protocol(&self) -> u8 {
        (self.flags & FLAG_PROTOCOL_MASK) >> FLAG_PROTOCOL_SHIFT
    }

    pub fn domain(&self) -> &str {
        std::str::from_utf8(&self.domain[..self.domain_len as usize]).unwrap_or("")
    }

    pub fn ip(&self) -> &str {
        std::str::from_utf8(&self.ip[..self.ip_len as usize]).unwrap_or("")
    }

    pub fn rule(&self) -> &str {
        std::str::from_utf8(&self.rule[..self.rule_len as usize]).unwrap_or("")
    }

    pub fn list(&self) -> &str {
        std::str::from_utf8(&self.list[..self.list_len as usize]).unwrap_or("")
    }

    pub fn app(&self) -> &str {
        std::str::from_utf8(&self.app[..self.app_len as usize]).unwrap_or("")
    }

    pub fn url(&self) -> &str {
        std::str::from_utf8(&self.url[..self.url_len as usize]).unwrap_or("")
    }

    pub fn answer(&self) -> &str {
        std::str::from_utf8(&self.answer[..self.answer_len as usize]).unwrap_or("")
    }

    /// The referrer the request carried, when the decision had one.
    pub fn source(&self) -> &str {
        std::str::from_utf8(&self.source[..self.source_len as usize]).unwrap_or("")
    }

    /// The kind of request, named the way the log's tabs name it.
    pub fn req_type_name(&self) -> &'static str {
        req_type::name(self.req_type)
    }

    /// The TLS version named the way the log shows it, empty when nothing was
    /// encrypted or the row never reached a handshake.
    pub fn tls_name(&self) -> &'static str {
        tls_ver::name(self.tls_ver)
    }

    /// The cipher suite the upstream session negotiated.
    pub fn cipher(&self) -> &str {
        std::str::from_utf8(&self.cipher[..self.cipher_len as usize]).unwrap_or("")
    }

    /// The MIME type the response declared, empty when there was no HTTP
    /// answer to declare one in.
    pub fn content_type(&self) -> &str {
        std::str::from_utf8(&self.ctype[..self.ctype_len as usize]).unwrap_or("")
    }

    /// The name the server's certificate carried, empty for a row that never
    /// completed a handshake.
    pub fn cert_subject(&self) -> &str {
        std::str::from_utf8(&self.cert_subj[..self.cert_subj_len as usize]).unwrap_or("")
    }

    /// Who signed that certificate — the party the user is really trusting.
    pub fn cert_issuer(&self) -> &str {
        std::str::from_utf8(&self.cert_iss[..self.cert_iss_len as usize]).unwrap_or("")
    }
}

/// Fixed-size ring of [`Event`]s.
pub struct EventLog {
    ring: Vec<Event>,
    next: usize,
    len: usize,
    /// Total events ever produced (before dropping).
    produced: u64,
    dropped: u64,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new(CAPACITY)
    }
}

impl EventLog {
    pub fn new(capacity: usize) -> Self {
        EventLog {
            ring: vec![Event::zeroed(); capacity.max(1)],
            next: 0,
            len: 0,
            produced: 0,
            dropped: 0,
        }
    }

    /// Pushes one event. Never blocks (the mutex is only ever held for a few
    /// stores) and never allocates.
    pub fn push(&mut self, event: Event) {
        self.ring[self.next] = event;
        self.next = (self.next + 1) % self.ring.len();
        if self.len < self.ring.len() {
            self.len += 1;
        } else {
            self.dropped += 1;
        }
        self.produced += 1;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn produced(&self) -> u64 {
        self.produced
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Serialises up to `max` events, newest last, into `out`.
    /// Returns the number of events written.
    pub fn drain_into(&mut self, out: &mut Vec<u8>, max: usize) -> usize {
        let count = self.len.min(max);
        let start = (self.next + self.ring.len() - self.len) % self.ring.len();
        let mut written = 0;
        for i in 0..count {
            let idx = (start + (self.len - count) + i) % self.ring.len();
            let ev = self.ring[idx];
            if !encode(&ev, out) {
                break;
            }
            written += 1;
        }
        written
    }

    /// Takes up to `max` events out of the ring (oldest first among the taken),
    /// leaving the rest untouched.
    pub fn drain_events(&mut self, max: usize) -> Vec<Event> {
        let count = self.len.min(max);
        let start = (self.next + self.ring.len() - self.len) % self.ring.len();
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let idx = (start + (self.len - count) + i) % self.ring.len();
            out.push(self.ring[idx]);
        }
        self.len -= count;
        self.next = (start + count) % self.ring.len();
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = &Event> {
        let len = self.len;
        let start = (self.next + self.ring.len() - len) % self.ring.len();
        (0..len).map(move |i| &self.ring[(start + i) % self.ring.len()])
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.next = 0;
    }
}

fn encode(ev: &Event, out: &mut Vec<u8>) -> bool {
    let start = out.len();
    let dlen = ev.domain_len as usize;
    let ilen = ev.ip_len as usize;
    let rlen = ev.rule_len as usize;
    let llen = ev.list_len as usize;
    let alen = ev.app_len as usize;
    let ulen = ev.url_len as usize;
    let qlen = ev.answer_len as usize;
    let slen = ev.source_len as usize;
    let clen = ev.cipher_len as usize;
    let tlen = ev.ctype_len as usize;
    let subjlen = ev.cert_subj_len as usize;
    let isslen = ev.cert_iss_len as usize;
    if dlen > MAX_DOMAIN
        || ilen > MAX_IP
        || rlen > MAX_RULE
        || llen > MAX_LIST
        || alen > MAX_APP
        || ulen > MAX_URL
        || qlen > MAX_ANSWER
        || slen > MAX_SOURCE
        || clen > MAX_CIPHER
        || tlen > MAX_CTYPE
        || subjlen > MAX_CERT_NAME
        || isslen > MAX_CERT_NAME
    {
        return false;
    }
    out.extend_from_slice(&ev.ts_ms.to_le_bytes());
    out.push(ev.action);
    out.push(ev.category);
    out.push(ev.flags);
    out.push(dlen as u8);
    out.push(ilen as u8);
    out.push(rlen as u8);
    out.push(llen as u8);
    out.push(alen as u8);
    out.extend_from_slice(&ev.latency_ns.to_le_bytes());
    out.extend_from_slice(&ev.bytes_saved.to_le_bytes());
    // Last of the header, so every offset a reader of the older fields
    // already computes stays where it was.
    out.push(ev.req_type);
    out.push(ev.tls_ver);
    out.extend_from_slice(&ev.domain[..dlen]);
    out.extend_from_slice(&ev.ip[..ilen]);
    out.extend_from_slice(&ev.rule[..rlen]);
    out.extend_from_slice(&ev.list[..llen]);
    out.extend_from_slice(&ev.app[..alen]);
    out.extend_from_slice(&ev.flow_id.to_le_bytes());
    out.extend_from_slice(&ev.bytes_sent.to_le_bytes());
    out.extend_from_slice(&ev.bytes_recv.to_le_bytes());
    out.push(ulen as u8);
    out.push(qlen as u8);
    out.push(slen as u8);
    out.push(clen as u8);
    out.push(tlen as u8);
    out.extend_from_slice(&ev.status.to_le_bytes());
    // Last of the trailer, so every offset a reader of the older fields
    // already computes still points at the same thing.
    out.push(subjlen as u8);
    out.push(isslen as u8);
    out.extend_from_slice(&ev.cert_from.to_le_bytes());
    out.extend_from_slice(&ev.cert_to.to_le_bytes());
    out.extend_from_slice(&ev.url[..ulen]);
    out.extend_from_slice(&ev.answer[..qlen]);
    out.extend_from_slice(&ev.source[..slen]);
    out.extend_from_slice(&ev.cipher[..clen]);
    out.extend_from_slice(&ev.ctype[..tlen]);
    out.extend_from_slice(&ev.cert_subj[..subjlen]);
    out.extend_from_slice(&ev.cert_iss[..isslen]);
    debug_assert_eq!(
        out.len() - start,
        RECORD_HEADER
            + RECORD_TRAILER
            + dlen
            + ilen
            + rlen
            + llen
            + alen
            + ulen
            + qlen
            + slen
            + clen
            + tlen
            + subjlen
            + isslen
    );
    true
}

/// Names the app a decision belongs to. Kept separate from the constructors so
/// call sites that already resolved the flow's packages just attach the result.
pub fn with_app(mut event: Event, app: &str) -> Event {
    put_str(&mut event.app[..], &mut event.app_len, app);
    event
}

/// Attaches the request URL the HTTPS path decided on.
pub fn with_url(mut event: Event, url: &str) -> Event {
    put_str(&mut event.url[..], &mut event.url_len, url);
    event
}

/// Attaches the address(es) a DNS answer carried, when the engine produced
/// the reply itself.
pub fn with_answer(mut event: Event, answer: &str) -> Event {
    put_str(&mut event.answer[..], &mut event.answer_len, answer);
    event
}

/// Records how many bytes crossed the flow, when known at log time.
pub fn with_traffic(mut event: Event, sent: u32, recv: u32) -> Event {
    event.bytes_sent = sent;
    event.bytes_recv = recv;
    event
}

/// Attaches the referrer a request carried, so the log can name what asked for
/// it rather than only what answered.
pub fn with_source(mut event: Event, source: &str) -> Event {
    put_str(&mut event.source[..], &mut event.source_len, source);
    event
}

/// Says what kind of thing the decision was about. Call sites that hold the
/// filter's word for it map it with [`req_type::of`]; the DNS and TCP paths
/// pass their own code.
pub fn with_type(mut event: Event, code: u8) -> Event {
    event.req_type = code;
    event
}

/// Says which protocol the decision was made on, so a row's transport is a
/// fact the engine recorded rather than a guess from the action.
pub fn with_protocol(mut event: Event, code: u8) -> Event {
    event.set_protocol(code);
    event
}

/// Says how the connection upstream was encrypted, with [`tls_ver::NONE`] for
/// a row that never had an encrypted half to speak of.
pub fn with_tls(mut event: Event, code: u8) -> Event {
    event.tls_ver = code;
    event
}

/// Says what the cipher suite of that session was, in rustls' own name.
pub fn with_cipher(mut event: Event, cipher: &str) -> Event {
    put_str(&mut event.cipher[..], &mut event.cipher_len, cipher);
    event
}

/// Attaches the HTTP status the origin answered with. A request that never
/// reached an origin has no status, which is why the field is 0 rather than a
/// guess.
pub fn with_status(mut event: Event, status: u16) -> Event {
    event.status = status;
    event
}

/// Attaches the MIME type the response declared, the fact that tells a user
/// whether a request brought back a page, a script or a video.
pub fn with_content_type(mut event: Event, mime: &str) -> Event {
    put_str(&mut event.ctype[..], &mut event.ctype_len, mime);
    event
}

/// Attaches the certificate the upstream TLS session presented: who it named,
/// who signed it, and the window it claimed to be good for. A row whose
/// handshake never completed — or never happened — has no certificate, and
/// stays as it was built.
pub fn with_cert(
    mut event: Event,
    subject: &str,
    issuer: &str,
    not_before_ms: i64,
    not_after_ms: i64,
) -> Event {
    put_str(&mut event.cert_subj[..], &mut event.cert_subj_len, subject);
    put_str(&mut event.cert_iss[..], &mut event.cert_iss_len, issuer);
    event.cert_from = not_before_ms;
    event.cert_to = not_after_ms;
    event
}

/// Factory helpers so callers never build an `Event` by hand.
pub fn allow_event(domain: &str, ip: &str, latency_ns: u32) -> Event {
    build(ACTION_ALLOW, domain, ip, "", "", latency_ns, 0, 0, false)
}

/// A request the lists refused and the smart filter let through. The action
/// stays ALLOW so the row never inflates a block counter, while the rule and
/// list columns say which switch spared it and why — without that row a
/// connection that the lists forbid looks unexplained.
pub fn spared_event(domain: &str, ip: &str, latency_ns: u32) -> Event {
    let rule = format!(
        "blocked {}x in {}s by the same app",
        crate::smart::RETRY_LIMIT,
        crate::smart::RETRY_WINDOW_MS / 1000
    );
    build(
        ACTION_ALLOW,
        domain,
        ip,
        &rule,
        "Smart filtering",
        latency_ns,
        0,
        0,
        false,
    )
}

pub fn block_event(
    action: u8,
    domain: &str,
    ip: &str,
    rule: &str,
    list: &str,
    category: u8,
    latency_ns: u32,
    bytes_saved: u32,
    ipv6: bool,
) -> Event {
    build(
        action,
        domain,
        ip,
        rule,
        list,
        latency_ns,
        bytes_saved,
        category,
        ipv6,
    )
}

#[allow(clippy::too_many_arguments)]
fn build(
    action: u8,
    domain: &str,
    ip: &str,
    rule: &str,
    list: &str,
    latency_ns: u32,
    bytes_saved: u32,
    category: u8,
    ipv6: bool,
) -> Event {
    let mut ev = Event::zeroed();
    ev.ts_ms = crate::util::now_ms();
    ev.action = action;
    ev.category = category;
    ev.flags = (if ipv6 { FLAG_IPV6 } else { 0 }) | (if rule.is_empty() { 0 } else { FLAG_HAS_RULE });
    ev.latency_ns = latency_ns;
    ev.bytes_saved = bytes_saved;
    put_str(&mut ev.domain[..], &mut ev.domain_len, domain);
    put_str(&mut ev.ip[..], &mut ev.ip_len, ip);
    put_str(&mut ev.rule[..], &mut ev.rule_len, rule);
    put_str(&mut ev.list[..], &mut ev.list_len, list);
    ev
}

fn put_str(dst: &mut [u8], dst_len: &mut u8, value: &str) {
    let bytes = value.as_bytes();
    let n = bytes.len().min(dst.len());
    dst[..n].copy_from_slice(&bytes[..n]);
    *dst_len = n as u8;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_live_ring_stays_within_its_memory_budget() {
        let record = std::mem::size_of::<Event>();
        // Naming the bound per record, not only per ring, is what tells a
        // future field how much room it took and how much is left. The peer
        // certificate's two names and their window cost ~210 bytes; the ring
        // still sits well inside its total budget.
        assert!(record <= 1152, "one event is {record} bytes");
        let ring_bytes = record * CAPACITY;
        // Phase 6 enrichment (url, dns answer, flow id, per-flow sizes) may
        // not push the ring past the ~3 MB budget the plan set for it.
        assert!(
            ring_bytes <= 3 * 1024 * 1024,
            "live ring is {ring_bytes} bytes for {CAPACITY} slots"
        );
    }

    #[test]
    fn push_and_drain_newest_last() {
        let mut log = EventLog::new(8);
        for i in 0..5u64 {
            let ev = allow_event(&format!("host{i}.test"), "1.2.3.4", i as u32);
            log.push(ev);
        }
        let mut out = Vec::new();
        let n = log.drain_into(&mut out, 10);
        assert_eq!(n, 5);
        // decode
        let mut idx = 0;
        let mut domains = Vec::new();
        while idx < out.len() {
            let dlen = out[idx + 11] as usize;
            let ilen = out[idx + 12] as usize;
            let rlen = out[idx + 13] as usize;
            let llen = out[idx + 14] as usize;
            let alen = out[idx + 15] as usize;
            let ts = u64::from_le_bytes(out[idx..idx + 8].try_into().unwrap());
            let latency = u32::from_le_bytes(out[idx + 16..idx + 20].try_into().unwrap());
            let d_start = idx + RECORD_HEADER;
            let domain = std::str::from_utf8(&out[d_start..d_start + dlen])
                .unwrap()
                .to_string();
            let saved = u32::from_le_bytes(out[idx + 20..idx + 24].try_into().unwrap());
            assert_eq!(saved, 0);
            assert_eq!(rlen + llen + alen, 0);
            domains.push((domain, ts, latency));
            // allow_event carries no rule/list/app/url/answer, so the record is
            // the header, the two strings and the fixed trailer.
            idx += RECORD_HEADER + RECORD_TRAILER + dlen + ilen;
        }
        assert_eq!(domains[0].0, "host0.test");
        assert_eq!(domains[4].0, "host4.test");
    }

    #[test]
    fn ring_overwrites_oldest() {
        let mut log = EventLog::new(4);
        for i in 0..10u64 {
            log.push(allow_event(&format!("h{i}.test"), "1.1.1.1", 0));
        }
        assert_eq!(log.len(), 4);
        assert_eq!(log.dropped(), 6);
        let mut out = Vec::new();
        let n = log.drain_into(&mut out, 4);
        assert_eq!(n, 4);
        let first_domain = {
            let dlen = out[11] as usize;
            std::str::from_utf8(&out[RECORD_HEADER..RECORD_HEADER + dlen])
                .unwrap()
                .to_string()
        };
        assert_eq!(first_domain, "h6.test");
    }

    #[test]
    fn long_strings_are_truncated_not_panicking() {
        let long = "a".repeat(200);
        let ev = block_event(ACTION_BLOCK, &long, &long, &long, &long, 0, 1, 2, false);
        assert_eq!(ev.domain_len, MAX_DOMAIN as u8);
        assert_eq!(ev.rule_len, MAX_RULE as u8);
        assert_eq!(ev.list_len, MAX_LIST as u8);
    }

    #[test]
    fn the_app_travels_with_the_event() {
        let ev = with_app(
            allow_event("host.test", "1.2.3.4", 7),
            "com.example.browser",
        );
        assert_eq!(ev.app(), "com.example.browser");
        assert_eq!(ev.domain(), "host.test");

        // The wire format carries it after the list name, so a reader that
        // already parses the older fields keeps the same offsets.
        let mut log = EventLog::new(4);
        log.push(ev);
        let mut out = Vec::new();
        assert_eq!(log.drain_into(&mut out, 4), 1);
        let dlen = out[11] as usize;
        let ilen = out[12] as usize;
        let rlen = out[13] as usize;
        let llen = out[14] as usize;
        let alen = out[15] as usize;
        let start = RECORD_HEADER + dlen + ilen + rlen + llen;
        assert_eq!(&out[start..start + alen], b"com.example.browser");
        assert_eq!(out.len(), start + alen + RECORD_TRAILER);
    }

    #[test]
    fn a_long_app_name_is_truncated_like_the_other_fields() {
        let long = "a".repeat(200);
        let ev = with_app(allow_event("host.test", "", 0), &long);
        assert_eq!(ev.app_len, MAX_APP as u8);
        assert_eq!(ev.app(), &long[..MAX_APP]);
    }

    #[test]
    fn the_filter_words_map_onto_the_tabs_the_log_shows() {
        // The names are what the database row, the exported file and the UI's
        // tabs all key on, so the mapping is the one place they are decided.
        assert_eq!(req_type::name(req_type::of("script")), "script");
        assert_eq!(req_type::name(req_type::of("stylesheet")), "stylesheet");
        assert_eq!(req_type::name(req_type::of("xmlhttprequest")), "xhr");
        assert_eq!(req_type::name(req_type::of("image")), "image");
        assert_eq!(req_type::name(req_type::of("media")), "media");
        assert_eq!(req_type::name(req_type::of("font")), "font");
        assert_eq!(
            req_type::name(req_type::of("subdocument")),
            "document",
            "an iframe is the HTML tab, not a tab of its own"
        );
        assert_eq!(
            req_type::name(req_type::of("csp_report")),
            "other",
            "a modifier with no tab of its own lands in the last one"
        );
        assert_eq!(req_type::name(req_type::of("")), "other");
        assert_eq!(req_type::name(req_type::DNS), "dns");
        assert_eq!(req_type::name(req_type::CONNECTION), "connection");
    }

    #[test]
    fn the_type_and_the_referrer_travel_with_the_event() {
        let ev = with_source(
            with_type(
                block_event(ACTION_BLOCK, "host.test", "", "||banner", "Ads", 1, 0, 10, false),
                req_type::SCRIPT,
            ),
            "https://host.test/page",
        );
        assert_eq!(ev.req_type_name(), "script");
        assert_eq!(ev.source(), "https://host.test/page");

        let mut log = EventLog::new(4);
        log.push(ev);
        let mut out = Vec::new();
        assert_eq!(log.drain_into(&mut out, 4), 1);
        // The type rides at the end of the header, where a reader of the older
        // fields never looked, so nothing that parsed the record before shifts.
        assert_eq!(out[24], req_type::SCRIPT);
        let tail = out.len() - ev.source_len as usize;
        assert_eq!(&out[tail..], b"https://host.test/page");
    }

    #[test]
    fn a_long_referrer_is_truncated_like_the_other_fields() {
        let ev = with_source(allow_event("host.test", "", 0), &"b".repeat(300));
        assert_eq!(ev.source_len, MAX_SOURCE as u8);
        assert_eq!(ev.source(), &"b".repeat(MAX_SOURCE));
    }

    #[test]
    fn the_tls_facts_and_the_answer_travel_with_the_event() {
        let ev = with_cert(
            with_content_type(
                with_status(
                    with_cipher(
                        with_tls(allow_event("host.test", "", 0), tls_ver::TLS13),
                        "TLS13_AES_256_GCM_SHA384",
                    ),
                    200,
                ),
                "text/html",
            ),
            "cdn.example",
            "Example Root CA",
            1_700_000_000_000,
            1_800_000_000_000,
        );
        assert_eq!(ev.tls_name(), "TLS 1.3");
        assert_eq!(ev.cipher(), "TLS13_AES_256_GCM_SHA384");
        assert_eq!(ev.status, 200);
        assert_eq!(ev.content_type(), "text/html");
        assert_eq!(ev.cert_subject(), "cdn.example");
        assert_eq!(ev.cert_issuer(), "Example Root CA");
        assert_eq!(ev.cert_from, 1_700_000_000_000);
        assert_eq!(ev.cert_to, 1_800_000_000_000);

        let mut log = EventLog::new(4);
        log.push(ev);
        let mut out = Vec::new();
        assert_eq!(log.drain_into(&mut out, 4), 1);
        // The version rides at the end of the header, after the request type,
        // where a reader of the older fields never looked.
        assert_eq!(out[25], tls_ver::TLS13);
        let dlen = out[11] as usize;
        let ilen = out[12] as usize;
        let tail = RECORD_HEADER + dlen + ilen;
        // The trailer's fixed part still ends with the status, and the
        // certificate's own facts follow it: the strings the lengths count are
        // pushed back, nothing before them moved.
        assert_eq!(out[tail + 17], 200);
        assert_eq!(out[tail + 19], 11);
        assert_eq!(out[tail + 20], 15);
        assert_eq!(
            i64::from_le_bytes(out[tail + 21..tail + 29].try_into().unwrap()),
            1_700_000_000_000
        );
        assert_eq!(
            &out[tail + RECORD_TRAILER..],
            b"TLS13_AES_256_GCM_SHA384text/htmlcdn.exampleExample Root CA"
        );
        assert_eq!(
            out.len(),
            RECORD_HEADER + RECORD_TRAILER + dlen + ilen + ev.cipher_len as usize
                + ev.ctype_len as usize
                + ev.cert_subj_len as usize
                + ev.cert_iss_len as usize
        );
    }

    #[test]
    fn an_unencrypted_row_names_no_tls_version() {
        // A plaintext request or a connection refused before its handshake has
        // no encryption to report, and the UI leaves the row out rather than
        // inventing one.
        assert_eq!(tls_ver::name(tls_ver::NONE), "");
        assert_eq!(Event::zeroed().tls_name(), "");
        assert_eq!(Event::zeroed().status, 0);
        assert!(Event::zeroed().cipher().is_empty());
        assert!(Event::zeroed().content_type().is_empty());
        assert!(Event::zeroed().cert_subject().is_empty());
        assert!(Event::zeroed().cert_issuer().is_empty());
        assert_eq!(Event::zeroed().cert_from, 0);
        assert_eq!(Event::zeroed().cert_to, 0);
        let long = "c".repeat(200);
        let ev = with_cipher(allow_event("host.test", "", 0), &long);
        assert_eq!(ev.cipher_len, MAX_CIPHER as u8);
        let mime = with_content_type(allow_event("host.test", "", 0), &"m".repeat(100));
        assert_eq!(mime.ctype_len, MAX_CTYPE as u8);
        let named = with_cert(
            allow_event("host.test", "", 0),
            &"s".repeat(200),
            &"i".repeat(200),
            1,
            2,
        );
        assert_eq!(named.cert_subj_len, MAX_CERT_NAME as u8);
        assert_eq!(named.cert_iss_len, MAX_CERT_NAME as u8);
    }

    #[test]
    fn the_protocol_a_decision_made_on_is_recorded_separately() {
        // The action says blocked or allowed; only the writer knows whether the
        // decision was a DNS answer or a request torn out of an HTTPS session.
        let mut ev = allow_event("host.test", "", 0);
        assert_eq!(ev.protocol(), protocol::NONE);
        ev.set_protocol(protocol::HTTPS);
        assert_eq!(ev.protocol(), protocol::HTTPS);
        // An unrelated update leaves both the protocol and the other bits.
        ev.set_network(TRANSPORT_CELLULAR, true);
        assert_eq!(ev.protocol(), protocol::HTTPS);
        assert_eq!(ev.transport(), TRANSPORT_CELLULAR);
        assert!(ev.roaming());
        let mut v6 = block_event(ACTION_BLOCK, "host.test", "", "r", "l", 0, 0, 0, true);
        v6.set_protocol(protocol::QUIC);
        assert!(v6.flags & FLAG_IPV6 != 0);
        assert_eq!(v6.protocol(), protocol::QUIC);
        assert_eq!(v6.transport(), TRANSPORT_UNKNOWN);
    }

    #[test]
    fn the_network_rides_in_the_flags_byte() {
        let mut ev = allow_event("host.test", "", 0);
        assert_eq!(ev.transport(), TRANSPORT_UNKNOWN);
        assert!(!ev.roaming());
        ev.set_network(TRANSPORT_CELLULAR, true);
        assert_eq!(ev.transport(), TRANSPORT_CELLULAR);
        assert!(ev.roaming());
        // The ipv6 bit survives an unrelated update.
        let mut v6 = block_event(ACTION_BLOCK, "host.test", "", "r", "l", 0, 0, 0, true);
        v6.set_network(TRANSPORT_WIFI, false);
        assert!(v6.flags & FLAG_IPV6 != 0);
        assert!(v6.flags & FLAG_HAS_RULE != 0);
        assert_eq!(v6.transport(), TRANSPORT_WIFI);
        assert!(!v6.roaming());
    }

    #[test]
    fn url_answer_and_traffic_travel_with_the_event() {
        let ev = with_traffic(
            with_answer(
                with_url(allow_event("host.test", "", 0), "/path?q=1"),
                "203.0.113.9",
            ),
            12,
            3456,
        );
        assert_eq!(ev.url(), "/path?q=1");
        assert_eq!(ev.answer(), "203.0.113.9");
        assert_eq!(ev.bytes_sent, 12);
        assert_eq!(ev.bytes_recv, 3456);
        let long = "u".repeat(400);
        let truncated = with_url(allow_event("host.test", "", 0), &long);
        assert_eq!(truncated.url_len, MAX_URL as u8);
        assert_eq!(truncated.url(), &long[..MAX_URL]);
    }
}
