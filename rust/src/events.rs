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
//! 10      flags          u8   bit0=ipv6 bit1=has-rule
//! 11      domain_len     u8
//! 12      ip_len         u8
//! 13      rule_len       u8
//! 14      list_len       u8
//! 15      app_len        u8
//! 16..20  latency_ns     u32
//! 20..24  bytes_saved    u32
//! 24..    domain[domain_len] ip[ip_len] rule[rule_len] list[list_len]
//!         app[app_len]
//! ```

pub const ACTION_ALLOW: u8 = 0;
pub const ACTION_BLOCK: u8 = 1;
pub const ACTION_TCP_RESET: u8 = 2;
pub const ACTION_UDP_DROP: u8 = 3;
pub const ACTION_QUIC_DROP: u8 = 4;

pub const MAX_DOMAIN: usize = 96;
pub const MAX_IP: usize = 40;
pub const MAX_RULE: usize = 72;
pub const MAX_LIST: usize = 24;
/// Package name of the app that owned the flow. A uid can resolve to several
/// packages; the log keeps the first, which is what attribution reports.
pub const MAX_APP: usize = 96;
const RECORD_HEADER: usize = 24;
const CAPACITY: usize = 4_096;

#[derive(Clone, Copy)]
pub struct Event {
    pub ts_ms: u64,
    pub action: u8,
    pub category: u8,
    pub flags: u8,
    pub latency_ns: u32,
    pub bytes_saved: u32,
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
        }
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
    if dlen > MAX_DOMAIN || ilen > MAX_IP || rlen > MAX_RULE || llen > MAX_LIST || alen > MAX_APP {
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
    debug_assert_eq!(
        out.len() - start,
        RECORD_HEADER + dlen + ilen + rlen + llen + alen
    );
    true
}

/// Names the app a decision belongs to. Kept separate from the constructors so
/// call sites that already resolved the flow's packages just attach the result.
pub fn with_app(mut event: Event, app: &str) -> Event {
    put_str(&mut event.app[..], &mut event.app_len, app);
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
    ev.flags = (if ipv6 { 0b01 } else { 0 }) | (if rule.is_empty() { 0 } else { 0b10 });
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
            idx += RECORD_HEADER + dlen + ilen + rlen + llen + alen;
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
        assert_eq!(out.len(), start + alen);
    }

    #[test]
    fn a_long_app_name_is_truncated_like_the_other_fields() {
        let long = "a".repeat(200);
        let ev = with_app(allow_event("host.test", "", 0), &long);
        assert_eq!(ev.app_len, MAX_APP as u8);
        assert_eq!(ev.app(), &long[..MAX_APP]);
    }
}
