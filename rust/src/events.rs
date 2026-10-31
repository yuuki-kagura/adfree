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
//! 10      flags          u8   bit0=ipv6 bit1=has-rule bits2..3=transport bit4=roaming
//! 11      domain_len     u8
//! 12      ip_len         u8
//! 13      rule_len       u8
//! 14      list_len       u8
//! 15      app_len        u8
//! 16..20  latency_ns     u32
//! 20..24  bytes_saved    u32
//! 24..    domain[domain_len] ip[ip_len] rule[rule_len] list[list_len]
//!         app[app_len]
//!         flow_id u32, bytes_sent u32, bytes_recv u32,
//!         url_len u8, answer_len u8, url[url_len], answer[answer_len]
//! ```

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
const RECORD_HEADER: usize = 24;
/// Fixed bytes appended after the variable-name tail (flow id, traffic, the
/// two length bytes).
const RECORD_TRAILER: usize = 14;
/// Events kept in the live ring. The durable log is the database the store
/// writes first ([`crate::store`]); this ring only feeds the in-process tail,
/// and an `Event` is ~360 bytes, so the previous 4 096 slots held ~1.5 MB of
/// anonymous memory for a buffer a poll of the tail drains in one go.
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
    if dlen > MAX_DOMAIN
        || ilen > MAX_IP
        || rlen > MAX_RULE
        || llen > MAX_LIST
        || alen > MAX_APP
        || ulen > MAX_URL
        || qlen > MAX_ANSWER
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
    out.extend_from_slice(&ev.url[..ulen]);
    out.extend_from_slice(&ev.answer[..qlen]);
    debug_assert_eq!(
        out.len() - start,
        RECORD_HEADER + RECORD_TRAILER + dlen + ilen + rlen + llen + alen + ulen + qlen
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

/// Factory helpers so callers never build an `Event` by hand.
pub fn allow_event(domain: &str, ip: &str, latency_ns: u32) -> Event {
    build(ACTION_ALLOW, domain, ip, "", "", latency_ns, 0, 0, false)
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
            std::str::from_utf8(&out[24..24 + dlen])
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
