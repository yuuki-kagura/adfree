//! DNS message decoding, synthetic reply synthesis and answer learning.
//!
//! The VPN intercepts every outgoing query, asks the filter core about the
//! QNAME and either answers straight from the TUN (no radio wakeup, no upstream
//! round trip) or forwards it to a protected upstream socket.
//!
//! All decoding is done into fixed stack buffers: there is no heap allocation
//! per query on the packet path.

use crate::packet::{self, Packet};
use std::net::IpAddr;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const TYPE_ANY: u16 = 255;
pub const TYPE_SOA: u16 = 6;

pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NXDOMAIN: u16 = 3;
pub const RCODE_REFUSED: u16 = 5;

/// What to answer for a blocked domain.
///
/// * `NxDomain`  — name does not exist (what AdGuard uses by default).
/// * `ZeroIp`    — answer A with `0.0.0.0` / AAAA with `::`.
/// * `Refused`   — refuse the query.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockMode {
    NxDomain,
    ZeroIp,
    Refused,
}

impl BlockMode {
    pub fn from_u8(v: u8) -> BlockMode {
        match v {
            1 => BlockMode::ZeroIp,
            2 => BlockMode::Refused,
            _ => BlockMode::NxDomain,
        }
    }
}

/// Decoded QNAME, stored inline.
#[derive(Clone)]
pub struct QName {
    buf: [u8; 255],
    len: u16,
}

impl QName {
    pub const EMPTY: QName = QName {
        buf: [0u8; 255],
        len: 0,
    };

    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: only ASCII lower-case letters, digits, dots and hyphens are
        // ever written into the buffer.
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len as usize]) }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A DNS query as it appears on the wire.
pub struct Query<'a> {
    pub body: &'a [u8],
    pub id: u16,
    pub flags: u16,
    pub qd_count: u16,
    pub qtype: u16,
    pub qclass: u16,
    pub qname: QName,
    /// Offset just past the question section.
    pub q_end: usize,
    pub has_question: bool,
}

impl<'a> Query<'a> {
    #[inline]
    pub fn is_query(&self) -> bool {
        self.flags & 0x8000 == 0
    }

    #[inline]
    pub fn rcode(&self) -> u16 {
        self.flags & 0x000f
    }
}

/// Decodes a DNS message from `body` (the UDP payload).
///
/// Returns `None` for malformed messages: those are simply forwarded upstream
/// rather than risking a broken answer.
pub fn parse_query<'a>(body: &'a [u8]) -> Option<Query<'a>> {
    if body.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([body[0], body[1]]);
    let flags = u16::from_be_bytes([body[2], body[3]]);
    let qd_count = u16::from_be_bytes([body[4], body[5]]);
    if qd_count != 1 {
        return Some(Query {
            body,
            id,
            flags,
            qd_count,
            qtype: 0,
            qclass: 0,
            qname: QName::EMPTY,
            q_end: 12,
            has_question: false,
        });
    }

    let mut buf = [0u8; 255];
    let mut len = 0usize;
    let mut off = 12usize;
    let mut label_len_total = 0usize;
    loop {
        let label_len = *body.get(off)? as usize;
        off += 1;
        if label_len == 0 {
            break;
        }
        // 0xC0 = compression pointer, which must never appear in a question.
        if label_len & 0xc0 != 0 {
            return None;
        }
        label_len_total += label_len;
        if label_len_total > 253 {
            return None; // name too long
        }
        if off + label_len > body.len() {
            return None;
        }
        if len != 0 {
            buf[len] = b'.';
            len += 1;
        }
        for i in 0..label_len {
            let b = body[off + i];
            buf[len] = b.to_ascii_lowercase();
            len += 1;
        }
        off += label_len;
    }
    let qtype = u16::from_be_bytes([*body.get(off)?, *body.get(off + 1)?]);
    let qclass = u16::from_be_bytes([*body.get(off + 2)?, *body.get(off + 3)?]);
    off += 4;

    Some(Query {
        body,
        id,
        flags,
        qd_count,
        qtype,
        qclass,
        qname: QName {
            buf,
            len: len as u16,
        },
        q_end: off,
        has_question: true,
    })
}

/// Rewrites a query transaction id in place, so every forwarded query carries
/// a locally unique id and replies can be matched without ambiguity.
#[inline]
pub fn patch_txid(body: &mut [u8], txid: u16) {
    body[0] = (txid >> 8) as u8;
    body[1] = (txid & 0xff) as u8;
}

/// Answers a query we could not forward with the given rcode (SERVFAIL etc.).
/// Answers immediately instead of letting the client wait for a timeout.
pub fn synthesize_error(
    packet: &Packet<'_>,
    query: Option<&Query<'_>>,
    rcode: u16,
) -> Option<Vec<u8>> {
    let parsed;
    let query = match query {
        Some(q) => q,
        None => {
            parsed = parse_query(packet.l4_payload())?;
            &parsed
        }
    };
    if !query.has_question || query.q_end > query.body.len() {
        return None;
    }
    let question = &query.body[12..query.q_end];
    let mut body = Vec::with_capacity(12 + question.len());
    let flags: u16 = 0x8000 | (query.flags & 0x0100) | (rcode & 0x000f);
    body.extend_from_slice(&query.id.to_be_bytes());
    body.extend_from_slice(&flags.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(question);
    Some(packet.rewrite_udp(&body))
}

/// Builds a synthetic answer for `q` and wraps it into a complete IP packet
/// addressed back to the querying client.
pub fn synthesize_reply(packet: &Packet<'_>, q: &Query<'_>, mode: BlockMode) -> Option<Vec<u8>> {
    if !q.has_question || q.q_end > q.body.len() {
        return None;
    }
    let question = &q.body[12..q.q_end];
    let mut body: Vec<u8> = Vec::with_capacity(q_end_len(q, mode));
    let rcode = match mode {
        BlockMode::NxDomain => RCODE_NXDOMAIN,
        BlockMode::Refused => RCODE_REFUSED,
        BlockMode::ZeroIp => RCODE_NOERROR,
    };
    let flags: u16 = 0x8000 // QR
        | (q.flags & 0x0100) // copy opcode
        | 0x0080 // recursion available
        | rcode;
    body.extend_from_slice(&q.id.to_be_bytes());
    body.extend_from_slice(&flags.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    let ancount: u16 = if mode == BlockMode::ZeroIp { 1 } else { 0 };
    body.extend_from_slice(&ancount.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // nscount
    body.extend_from_slice(&0u16.to_be_bytes()); // arcount
    body.extend_from_slice(question);

    if ancount == 1 {
        let rdlen: u16 = if q.qtype == TYPE_AAAA { 16 } else { 4 };
        body.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to the question
        body.extend_from_slice(&q.qtype.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes()); // class IN
        body.extend_from_slice(&60u32.to_be_bytes()); // TTL
        body.extend_from_slice(&rdlen.to_be_bytes());
        if q.qtype == TYPE_AAAA {
            body.extend_from_slice(&[0u8; 16]);
        } else {
            body.extend_from_slice(&[0, 0, 0, 0]); // 0.0.0.0
        }
    }

    Some(packet.rewrite_udp(&body))
}

fn q_end_len(q: &Query<'_>, mode: BlockMode) -> usize {
    let mut len = q.q_end;
    if mode == BlockMode::ZeroIp {
        len += 16;
    }
    len
}

/// Writes one domain name in wire format (labels, then the root label).
///
/// `None` for a name that is empty, has a label over 63 bytes or is longer
/// than DNS allows: a query carrying one would be dropped by the resolver
/// anyway.
fn write_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(())
}

/// Builds one DNS query, with an EDNS0 OPT record asking for a 1232-byte
/// answer (the tunnel MTU fits it without fragmentation).
///
/// Used for the queries the engine originates: SafeSearch's second lookup and
/// the resolver probe. The transaction id is the caller's, so the reply can be
/// matched on the same path as a forwarded client query.
pub fn build_query(qname: &str, qtype: u16, txid: u16) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(64);
    body.extend_from_slice(&txid.to_be_bytes());
    body.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    body.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    body.extend_from_slice(&0u16.to_be_bytes()); // ancount
    body.extend_from_slice(&0u16.to_be_bytes()); // nscount
    body.extend_from_slice(&1u16.to_be_bytes()); // arcount (OPT)
    write_name(&mut body, qname)?;
    body.extend_from_slice(&qtype.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes()); // class IN

    // OPT: root name, type 41, UDP payload size, extended rcode/version/flags,
    // empty rdata.
    body.push(0);
    body.extend_from_slice(&41u16.to_be_bytes());
    body.extend_from_slice(&1232u16.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    Some(body)
}

/// Builds the answer body for `query` from a set of addresses.
///
/// Only the address family the question asked for is used (`A` gets IPv4,
/// `AAAA` gets IPv6); every other type, or a set with no matching family,
/// returns `None` so the caller forwards the query instead of answering it
/// with an empty record set.
pub fn answer_message(query: &Query<'_>, answers: &[IpAddr], ttl: u32) -> Option<Vec<u8>> {
    if !query.has_question || query.q_end > query.body.len() {
        return None;
    }
    let records: Vec<&IpAddr> = answers
        .iter()
        .filter(|ip| {
            matches!(
                (query.qtype, ip),
                (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_))
            )
        })
        .collect();
    if records.is_empty() {
        return None;
    }
    let question = &query.body[12..query.q_end];
    let mut body = Vec::with_capacity(12 + question.len() + records.len() * 32);
    let flags: u16 = 0x8000 // QR
        | (query.flags & 0x7800) // opcode, echoed
        | (query.flags & 0x0100) // RD, echoed
        | 0x0080 // RA
        | RCODE_NOERROR;
    body.extend_from_slice(&query.id.to_be_bytes());
    body.extend_from_slice(&flags.to_be_bytes());
    body.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    body.extend_from_slice(&(records.len() as u16).to_be_bytes()); // ancount
    body.extend_from_slice(&0u16.to_be_bytes()); // nscount
    body.extend_from_slice(&0u16.to_be_bytes()); // arcount
    body.extend_from_slice(question);
    for ip in records {
        body.extend_from_slice(&[0xc0, 0x0c]); // owner: the question name
        body.extend_from_slice(&query.qtype.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes()); // class IN
        body.extend_from_slice(&ttl.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                body.extend_from_slice(&4u16.to_be_bytes());
                body.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                body.extend_from_slice(&16u16.to_be_bytes());
                body.extend_from_slice(&v6.octets());
            }
        }
    }
    Some(body)
}

/// [`answer_message`] wrapped into a complete IP packet back to the client.
pub fn synthesize_answer(
    packet: &Packet<'_>,
    query: &Query<'_>,
    answers: &[IpAddr],
    ttl: u32,
) -> Option<Vec<u8>> {
    answer_message(query, answers, ttl).map(|body| packet.rewrite_udp(&body))
}

/// The A/AAAA addresses in one upstream answer, each with its own TTL.
///
/// Unlike [`parse_answers`] this keeps the address value (SafeSearch caches
/// the safe resolver's addresses, it does not learn a connection mapping).
pub fn answer_addresses(body: &[u8]) -> Vec<(IpAddr, u32)> {
    let mut out = Vec::new();
    for record in parse_answers(body) {
        out.push((record.ip.as_ip(), record.ttl));
    }
    out
}

/// One learned `IP -> host` mapping taken from an upstream answer.
#[derive(Clone, Copy)]
pub struct LearnedRecord {
    pub ip: crate::packet::IpKey,
    pub ttl: u32,
}

/// Extracts A/AAAA records from a DNS response for conntrack learning.
pub fn parse_answers(body: &[u8]) -> Vec<LearnedRecord> {
    let mut out = Vec::new();
    if body.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([body[4], body[5]]) as usize;
    let an = u16::from_be_bytes([body[6], body[7]]) as usize;
    if qd > 4 || an == 0 || an > 64 {
        return out;
    }
    let mut off = 12usize;
    // Skip the questions.
    for _ in 0..qd {
        if !skip_name(body, &mut off) {
            return out;
        }
        off += 4;
        if off > body.len() {
            return out;
        }
    }
    for _ in 0..an {
        if !skip_name(body, &mut off) {
            return out;
        }
        if off + 10 > body.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([body[off], body[off + 1]]);
        let ttl = u32::from_be_bytes([body[off + 4], body[off + 5], body[off + 6], body[off + 7]]);
        let rdlen = u16::from_be_bytes([body[off + 8], body[off + 9]]) as usize;
        off += 10;
        if off + rdlen > body.len() {
            return out;
        }
        match (rtype, rdlen) {
            (TYPE_A, 4) => {
                if let Some(key) = packet::ip_key_from_bytes(&body[off..off + 4]) {
                    out.push(LearnedRecord { ip: key, ttl });
                }
            }
            (TYPE_AAAA, 16) => {
                if let Some(key) = packet::ip_key_from_bytes(&body[off..off + 16]) {
                    out.push(LearnedRecord { ip: key, ttl });
                }
            }
            _ => {}
        }
        off += rdlen;
    }
    out
}

/// SvcParamKey 5, held for Encrypted Client Hello (RFC 9460, Table 1): the
/// ECHConfigList a client needs to attempt ECH (RFC 9849).
const SVC_PARAM_KEY_ECH: u16 = 5;

/// Key 65535, reserved as "Invalid key" (RFC 9460, Table 1). Clients ignore
/// SvcParams they do not recognise (RFC 9460 §2.4.3), which is what makes the
/// rewrite below a safe way of taking `ech` away.
const SVC_PARAM_KEY_RESERVED: u16 = 0xffff;

/// Neutralises the `ech` SvcParam of every SVCB/HTTPS record in `message`.
///
/// A client that learns an ECHConfig wraps its next ClientHello around it, and
/// that handshake cannot negotiate ECH through the TLS terminator: the outer
/// name is the only one the ClientHello exposes. The client then either
/// rejects the forged certificate and retries without ECH a second later (a
/// wasted round trip per origin, seen as `CertificateUnknown`), or — on hosts
/// in ECH-required mode — refuses to continue at all (`ech_required`), and the
/// connection, hence the page, fails. ECH exists to keep *this* proxy out of
/// the connection, and the user asked for it to be in, so an HTTPS filter has
/// to strip the parameter before the client sees it.
///
/// The key is rewritten to the reserved value instead of removing the
/// parameter: the record keeps its length, so nothing after it (another
/// SvcParam, a resource record, a compression pointer) can shift. Returns
/// whether anything was rewritten.
pub fn strip_ech(message: &mut [u8]) -> bool {
    if message.len() < 12 {
        return false;
    }
    let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
    let an = u16::from_be_bytes([message[6], message[7]]) as usize;
    if qd > 4 || an == 0 || an > 64 {
        return false;
    }
    let mut off = 12usize;
    for _ in 0..qd {
        if !skip_name(message, &mut off) {
            return false;
        }
        off += 4;
        if off > message.len() {
            return false;
        }
    }
    let mut stripped = false;
    for _ in 0..an {
        if !skip_name(message, &mut off) || off + 10 > message.len() {
            break;
        }
        let rtype = u16::from_be_bytes([message[off], message[off + 1]]);
        let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
        off += 10;
        if off + rdlen > message.len() {
            break;
        }
        if rtype == TYPE_SVCB || rtype == TYPE_HTTPS {
            stripped |= strip_ech_param(message, off, off + rdlen);
        }
        off += rdlen;
    }
    stripped
}

/// Lowers the TTL of every answer record in `message` to at most `max`.
///
/// Called on the answers whose `ech` parameter was just rewritten away: an
/// answer the proxy changed is not the answer the origin published, so it must
/// not be cached as if it were. It also bounds how long a host that turns out
/// to require ECH stays broken — the browser re-reads the record, and can only
/// then pick the ECHConfig back up, when what it holds expires. Returns how
/// many records were lowered.
pub fn clamp_answer_ttl(message: &mut [u8], max: u32) -> usize {
    if message.len() < 12 {
        return 0;
    }
    let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
    let an = u16::from_be_bytes([message[6], message[7]]) as usize;
    if qd > 4 || an == 0 || an > 64 {
        return 0;
    }
    let mut off = 12usize;
    for _ in 0..qd {
        if !skip_name(message, &mut off) {
            return 0;
        }
        off += 4;
        if off > message.len() {
            return 0;
        }
    }
    let mut clamped = 0;
    for _ in 0..an {
        if !skip_name(message, &mut off) || off + 10 > message.len() {
            break;
        }
        let ttl = u32::from_be_bytes([
            message[off + 4],
            message[off + 5],
            message[off + 6],
            message[off + 7],
        ]);
        if ttl > max {
            message[off + 4..off + 8].copy_from_slice(&max.to_be_bytes());
            clamped += 1;
        }
        let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
        off += 10;
        if off + rdlen > message.len() {
            break;
        }
        off += rdlen;
    }
    clamped
}

/// One resource record located inside a message.
#[derive(Clone, Copy)]
struct RecordSpan {
    rtype: u16,
    ttl: u32,
    /// Offset of the TTL field, for in-place aging.
    ttl_at: usize,
    /// RDATA bounds.
    rdata: (usize, usize),
}

/// Reads the record at `*off`, advancing past it.
fn read_record(message: &[u8], off: &mut usize) -> Option<RecordSpan> {
    if !skip_name(message, off) || *off + 10 > message.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([message[*off], message[*off + 1]]);
    let ttl_at = *off + 4;
    let ttl = u32::from_be_bytes([
        message[*off + 4],
        message[*off + 5],
        message[*off + 6],
        message[*off + 7],
    ]);
    let rdlen = u16::from_be_bytes([message[*off + 8], message[*off + 9]]) as usize;
    *off += 10;
    let end = *off + rdlen;
    if end > message.len() {
        return None;
    }
    let span = RecordSpan {
        rtype,
        ttl,
        ttl_at,
        rdata: (*off, end),
    };
    *off = end;
    Some(span)
}

/// The SOA `minimum` field of one SOA record's RDATA (RFC 2308 §4).
fn soa_minimum(message: &[u8], (start, end): (usize, usize)) -> Option<u32> {
    let mut off = start;
    // MNAME, RNAME, then serial/refresh/retry/expire/minimum.
    if !skip_name(message, &mut off) || !skip_name(message, &mut off) || off + 20 > end {
        return None;
    }
    Some(u32::from_be_bytes([
        message[off + 16],
        message[off + 17],
        message[off + 18],
        message[off + 19],
    ]))
}

/// How long an answer may be reused, in seconds.
///
/// Only a NOERROR or NXDOMAIN answer is cacheable: SERVFAIL and the rest
/// describe a moment of the resolver, not the record. A positive answer lives
/// as long as its shortest record, a negative one as long as its SOA allows
/// (RFC 2308 §5) — without that SOA a negative answer is not cached, because
/// nothing says how long the resolver will stand by it. A zero TTL is the
/// server saying "do not reuse this"; the rest is capped so a long-lived
/// record still expires within the hour.
pub fn cache_ttl(message: &[u8]) -> Option<u32> {
    const MAX_TTL: u32 = 3_600;
    let cacheable = |ttl: u32| (ttl > 0).then(|| ttl.min(MAX_TTL));
    if message.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let rcode = flags & 0x000f;
    if flags & 0x8000 == 0 || flags & 0x0200 != 0 || (flags >> 11) & 0x000f != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
    let an = u16::from_be_bytes([message[6], message[7]]) as usize;
    let ns = u16::from_be_bytes([message[8], message[9]]) as usize;
    if qd != 1 || an > 64 || ns > 16 {
        return None;
    }
    let mut off = 12usize;
    if !skip_name(message, &mut off) {
        return None;
    }
    off += 4;
    if off > message.len() {
        return None;
    }
    match rcode {
        RCODE_NOERROR if an > 0 => {
            let mut ttl = u32::MAX;
            for _ in 0..an {
                ttl = ttl.min(read_record(message, &mut off)?.ttl);
            }
            cacheable(ttl)
        }
        RCODE_NOERROR | RCODE_NXDOMAIN => {
            for _ in 0..an {
                read_record(message, &mut off)?;
            }
            for _ in 0..ns {
                let record = read_record(message, &mut off)?;
                if record.rtype == TYPE_SOA {
                    let minimum = soa_minimum(message, record.rdata)?;
                    return cacheable(record.ttl.min(minimum));
                }
            }
            None
        }
        _ => None,
    }
}

/// Subtracts `elapsed_secs` from every answer and authority record TTL.
///
/// A cached answer must leave the client at the origin's deadline, not restart
/// it: without this the client would hold the record for the full TTL again
/// from the moment it was served. The additional section is left alone — its
/// TTL field is OPT flags, not a lifetime. Returns how many records were aged.
pub fn age_ttls(message: &mut [u8], elapsed_secs: u32) -> usize {
    if elapsed_secs == 0 || message.len() < 12 {
        return 0;
    }
    let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
    let an = u16::from_be_bytes([message[6], message[7]]) as usize;
    let ns = u16::from_be_bytes([message[8], message[9]]) as usize;
    if qd != 1 || an > 64 || ns > 16 {
        return 0;
    }
    let mut off = 12usize;
    if !skip_name(message, &mut off) {
        return 0;
    }
    off += 4;
    if off > message.len() {
        return 0;
    }
    let mut aged = 0;
    for _ in 0..(an + ns) {
        let Some(record) = read_record(message, &mut off) else {
            break;
        };
        let ttl = record.ttl.saturating_sub(elapsed_secs);
        message[record.ttl_at..record.ttl_at + 4].copy_from_slice(&ttl.to_be_bytes());
        aged += 1;
    }
    aged
}

/// Copies the client's spelling of the question into a cached answer.
///
/// Clients that randomize the case of the QNAME (0x20 encoding) check that the
/// reply echoes it; an answer cached for one spelling must not be served to a
/// client that asked with another. Returns `false` when the two questions do
/// not line up, in which case the caller forwards instead.
pub fn adopt_question(message: &mut [u8], query: &Query<'_>) -> bool {
    let (own_end, own_has_question) = match parse_query(message) {
        Some(own) => (own.q_end, own.has_question),
        None => return false,
    };
    if !own_has_question || !query.has_question || own_end != query.q_end {
        return false;
    }
    message[12..own_end].copy_from_slice(&query.body[12..query.q_end]);
    true
}

/// Rewrites the `ech` key inside one record's RDATA, if it carries one.
fn strip_ech_param(message: &mut [u8], start: usize, end: usize) -> bool {
    // SvcPriority (2 bytes), then the target name (never compressed in
    // practice, but skip_name reads either form).
    let mut off = start + 2;
    if off > end || !skip_name(message, &mut off) {
        return false;
    }
    let mut stripped = false;
    while off + 4 <= end {
        let key = u16::from_be_bytes([message[off], message[off + 1]]);
        let len = u16::from_be_bytes([message[off + 2], message[off + 3]]) as usize;
        if off + 4 + len > end {
            break;
        }
        if key == SVC_PARAM_KEY_ECH {
            message[off..off + 2].copy_from_slice(&SVC_PARAM_KEY_RESERVED.to_be_bytes());
            stripped = true;
        }
        off += 4 + len;
    }
    stripped
}

/// The `public_name` of the first ECHConfig in the first `ech` SvcParam of
/// `message`, when the answer carries a readable one.
///
/// The ECHConfigList is public data — it is what the resolver hands every
/// client — and its `public_name` is the name a real ECH connection exposes on
/// the wire (RFC 9849 §4). It is also the only way to tell such a connection
/// from the GREASE extension browsers attach to ordinary ones: a GREASE hello
/// still carries the real host as its SNI, while a real ECH hello carries the
/// public name. The transport half splices the former and terminates the
/// latter, so it has to know the names (`mitm::ech`). Lowercased, like every
/// other name the core compares.
pub fn ech_public_name(message: &[u8]) -> Option<String> {
    if message.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
    let an = u16::from_be_bytes([message[6], message[7]]) as usize;
    if qd > 4 || an == 0 || an > 64 {
        return None;
    }
    let mut off = 12usize;
    for _ in 0..qd {
        if !skip_name(message, &mut off) {
            return None;
        }
        off += 4;
        if off > message.len() {
            return None;
        }
    }
    for _ in 0..an {
        if !skip_name(message, &mut off) || off + 10 > message.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([message[off], message[off + 1]]);
        let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
        off += 10;
        if off + rdlen > message.len() {
            return None;
        }
        if rtype == TYPE_SVCB || rtype == TYPE_HTTPS {
            if let Some(name) = ech_param_public_name(message, off, off + rdlen) {
                return Some(name);
            }
        }
        off += rdlen;
    }
    None
}

/// The raw ECHConfigList of the first `ech` SvcParam of `message`, with its
/// 2-byte length prefix, when the answer carries a usable one.
///
/// This is exactly the value `rustls::client::EchConfig::new` expects. The
/// client half never sees it — [`strip_ech`] rewrites the parameter away — but
/// the proxy's own upstream connection can offer it, which is what lets a host
/// that requires ECH still be filtered (see `mitm::ech`). Only lists that name
/// a readable `public_name` are kept: rustls needs that name for the outer
/// hello, and a config it cannot use would only cost a rejected handshake.
pub fn ech_config_list(message: &[u8]) -> Option<Vec<u8>> {
    if message.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
    let an = u16::from_be_bytes([message[6], message[7]]) as usize;
    if qd > 4 || an == 0 || an > 64 {
        return None;
    }
    let mut off = 12usize;
    for _ in 0..qd {
        if !skip_name(message, &mut off) {
            return None;
        }
        off += 4;
        if off > message.len() {
            return None;
        }
    }
    for _ in 0..an {
        if !skip_name(message, &mut off) || off + 10 > message.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([message[off], message[off + 1]]);
        let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
        off += 10;
        if off + rdlen > message.len() {
            return None;
        }
        if rtype == TYPE_SVCB || rtype == TYPE_HTTPS {
            if let Some(value) = ech_param_value(message, off, off + rdlen) {
                if ech_config_public_name(value).is_some() {
                    return Some(value.to_vec());
                }
            }
        }
        off += rdlen;
    }
    None
}

/// The value of the `ech` SvcParam of one SVCB/HTTPS record, still prefixed by
/// its 2-byte length.
fn ech_param_value(message: &[u8], start: usize, end: usize) -> Option<&[u8]> {
    let mut off = start + 2;
    if off > end || !skip_name(message, &mut off) {
        return None;
    }
    while off + 4 <= end {
        let key = u16::from_be_bytes([message[off], message[off + 1]]);
        let len = u16::from_be_bytes([message[off + 2], message[off + 3]]) as usize;
        let value_end = off.checked_add(4 + len)?;
        if value_end > end {
            return None;
        }
        if key == SVC_PARAM_KEY_ECH {
            return Some(&message[off + 4..value_end]);
        }
        off = value_end;
    }
    None
}

/// The `public_name` inside the `ech` SvcParam of one SVCB/HTTPS record.
fn ech_param_public_name(message: &[u8], start: usize, end: usize) -> Option<String> {
    ech_config_public_name(ech_param_value(message, start, end)?)
}

/// The `public_name` of the first 0xfe0d ECHConfig in an ECHConfigList.
///
/// ```text
/// ECHConfigList: uint16 length, then ECHConfig { uint16 version,
///   uint16 length, ECHConfigContents { HpkeKeyConfig key_config,
///   uint8 maximum_name_length, opaque public_name<1..255>,
///   ECHConfigExtension extensions<0..2^16-1> } }
/// HpkeKeyConfig: uint8 config_id, uint16 kem_id,
///   opaque public_key<0..2^16-1>,
///   HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>
/// ```
fn ech_config_public_name(list: &[u8]) -> Option<String> {
    let list_len = u16::from_be_bytes([*list.first()?, *list.get(1)?]) as usize;
    let list_end = (2 + list_len).min(list.len());
    let mut off = 2usize;
    while off + 4 <= list_end {
        let version = u16::from_be_bytes([list[off], list[off + 1]]);
        let len = u16::from_be_bytes([list[off + 2], list[off + 3]]) as usize;
        let body_end = off.checked_add(4 + len)?;
        if body_end > list_end {
            return None;
        }
        if version == 0xfe0d {
            return ech_config_contents_public_name(&list[off + 4..body_end]);
        }
        off = body_end;
    }
    None
}

/// The `public_name` field of one `ECHConfigContents`.
fn ech_config_contents_public_name(contents: &[u8]) -> Option<String> {
    // config_id, kem_id, then the HPKE public key (a 2-byte length plus key).
    let key_len = u16::from_be_bytes([*contents.get(3)?, *contents.get(4)?]) as usize;
    let mut off = 1 + 4 + key_len;
    // cipher_suites: a 2-byte length, then 4-byte suites.
    let suites_len = u16::from_be_bytes([*contents.get(off)?, *contents.get(off + 1)?]) as usize;
    off += 2 + suites_len;
    // maximum_name_length, then public_name (a 1-byte length plus name).
    let name_len = *contents.get(off + 1)? as usize;
    let name = contents.get(off + 2..off + 2 + name_len)?;
    let name = std::str::from_utf8(name).ok()?;
    if name.is_empty() {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

/// Length of the name field at `off`, following compression pointers only to
/// find the end of the *field* (never the position after the target name).
fn name_field_len(body: &[u8], start: usize) -> Option<usize> {
    let mut cur = start;
    let mut jumps = 0;
    let mut field_end: Option<usize> = None;
    loop {
        let len = *body.get(cur)?;
        match len {
            0 => return Some(field_end.unwrap_or(cur + 1) - start),
            n if n & 0xc0 == 0xc0 => {
                let pointer = ((n as usize & 0x3f) << 8) | *body.get(cur + 1)? as usize;
                // The field in *this* buffer ends right after the two bytes.
                field_end = field_end.or(Some(cur + 2));
                if pointer >= body.len() || jumps > 8 {
                    return None;
                }
                jumps += 1;
                cur = pointer;
            }
            n if n & 0xc0 != 0 => return None,
            n => {
                cur += 1 + n as usize;
                if cur >= body.len() {
                    return None;
                }
            }
        }
    }
}

/// Advances `off` past a (possibly compressed) name. Returns false on garbage.
fn skip_name(body: &[u8], off: &mut usize) -> bool {
    match name_field_len(body, *off) {
        Some(len) => {
            *off += len;
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{self, Packet};

    fn make_query(qname: &[u8], qtype: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x12, 0x34, 0x01, 0x00]);
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        v.extend_from_slice(qname);
        v.extend_from_slice(&[0x00]);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v
    }

    #[test]
    fn decodes_qname_lowercased() {
        let mut qname = Vec::new();
        qname.push(7u8);
        qname.extend_from_slice(b"example");
        qname.push(3u8);
        qname.extend_from_slice(b"COM");
        let body = make_query(&qname, TYPE_A);
        let q = parse_query(&body).expect("q");
        assert!(q.is_query());
        assert_eq!(q.qname.as_str(), "example.com");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, 1);
        assert_eq!(q.q_end, 12 + qname.len() + 1 + 4);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_query(&[0u8; 11]).is_none());
        // A question with a compression pointer.
        let mut qname = Vec::new();
        qname.extend_from_slice(&[0xc0, 0x0c, 0, 0, 1, 0, 1]);
        let body = make_query(&qname, TYPE_A);
        assert!(parse_query(&body).is_none());
    }

    #[test]
    fn synthesizes_nxdomain_reply() {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x45, 0x00]);
        let dns_len = 12 + 1 + 7 + 4 + 1 + 4;
        let total = 20 + 8 + dns_len;
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0, 0]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&[8, 8, 8, 8]);
        pkt.extend_from_slice(&51234u16.to_be_bytes());
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(&((8 + dns_len) as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        let mut qname = Vec::new();
        qname.push(7u8);
        qname.extend_from_slice(b"example");
        qname.push(3u8);
        qname.extend_from_slice(b"com");
        pkt.extend_from_slice(&[0xab, 0xcd, 0x01, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&qname);
        pkt.extend_from_slice(&[0]);
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        packet::fix_ipv4_checksum(&mut pkt);

        let packet = Packet::parse(&pkt).unwrap();
        let q = parse_query(packet.l4_payload()).unwrap();
        let reply = synthesize_reply(&packet, &q, BlockMode::NxDomain).expect("reply");
        let rp = Packet::parse(&reply).expect("parse reply");
        assert_eq!(rp.src_ip_text(), "8.8.8.8");
        assert_eq!(rp.dst_ip_text(), "10.0.0.2");
        assert_eq!(rp.src_port, 53);
        assert_eq!(rp.dst_port, 51234);
        let rq = parse_query(rp.l4_payload()).expect("decode reply");
        assert!(!rq.is_query());
        assert_eq!(rq.id, 0xabcd);
        assert_eq!(rq.rcode(), RCODE_NXDOMAIN);
        assert_eq!(rq.qd_count, 1);
        assert_eq!(rq.qname.as_str(), "example.com");
    }

    #[test]
    fn synthesizes_zero_ip_answer() {
        let mut qname = Vec::new();
        qname.push(3u8);
        qname.extend_from_slice(b"ads");
        let mut dns = make_query(&qname, TYPE_A);
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x45, 0x00]);
        let total = 20 + 8 + dns.len();
        pkt.extend_from_slice(&(total as u16).to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0, 0]);
        pkt.extend_from_slice(&[10, 0, 0, 2]);
        pkt.extend_from_slice(&[8, 8, 8, 8]);
        pkt.extend_from_slice(&51234u16.to_be_bytes());
        pkt.extend_from_slice(&53u16.to_be_bytes());
        pkt.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&[0, 0]);
        pkt.append(&mut dns);
        packet::fix_ipv4_checksum(&mut pkt);
        let packet = Packet::parse(&pkt).unwrap();
        let q = parse_query(packet.l4_payload()).unwrap();
        let reply = synthesize_reply(&packet, &q, BlockMode::ZeroIp).expect("reply");
        let rp = Packet::parse(&reply).unwrap();
        let body = rp.l4_payload();
        let ancount = u16::from_be_bytes([body[6], body[7]]);
        assert_eq!(ancount, 1);
        assert_eq!(rp.total_len - rp.l4_payload_offset(), q.q_end + 16);
    }

    #[test]
    fn learns_a_records() {
        // header: qd=1 an=1
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0, 0x80, 0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0]);
        let mut qname = Vec::new();
        qname.push(3u8);
        qname.extend_from_slice(b"ads");
        b.extend_from_slice(&qname);
        b.extend_from_slice(&[0]);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // answer
        b.extend_from_slice(&[0xc0, 0x0c]);
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&300u32.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&[1, 2, 3, 4]);
        let recs = parse_answers(&b);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].ip.as_ip().to_string(), "1.2.3.4");
        assert_eq!(recs[0].ttl, 300);
    }

    /// SVCB/HTTPS RDATA: priority, root target, then the given parameters.
    fn svcb_rdata(params: &[(u16, &[u8])]) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(0);
        for (key, value) in params {
            rdata.extend_from_slice(&key.to_be_bytes());
            rdata.extend_from_slice(&(value.len() as u16).to_be_bytes());
            rdata.extend_from_slice(value);
        }
        rdata
    }

    /// A response for `example.com` with `answers` answer slots to fill.
    fn response_skeleton(answers: usize) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x12, 0x34, 0x84, 0x80]);
        b.extend_from_slice(&[0x00, 0x01]);
        b.extend_from_slice(&(answers as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        let mut qname = Vec::new();
        qname.push(7u8);
        qname.extend_from_slice(b"example");
        qname.push(3u8);
        qname.extend_from_slice(b"com");
        b.extend_from_slice(&qname);
        b.extend_from_slice(&[0]);
        b.extend_from_slice(&[0x00, 0x41, 0x00, 0x01]);
        b
    }

    fn add_answer(b: &mut Vec<u8>, rtype: u16, rdata: &[u8]) {
        add_answer_ttl(b, rtype, 300, rdata);
    }

    fn add_answer_ttl(b: &mut Vec<u8>, rtype: u16, ttl: u32, rdata: &[u8]) {
        b.extend_from_slice(&[0xc0, 0x0c]);
        b.extend_from_slice(&rtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&ttl.to_be_bytes());
        b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        b.extend_from_slice(rdata);
    }

    #[test]
    fn a_cacheable_answer_lives_as_long_as_its_shortest_record() {
        let mut msg = response_skeleton(2);
        add_answer_ttl(&mut msg, TYPE_A, 300, &[1, 2, 3, 4]);
        add_answer_ttl(&mut msg, TYPE_A, 60, &[5, 6, 7, 8]);
        assert_eq!(cache_ttl(&msg), Some(60));
        // A zero TTL asks for the answer to be used once, not kept.
        let mut zero = response_skeleton(1);
        add_answer_ttl(&mut zero, TYPE_A, 0, &[1, 2, 3, 4]);
        assert_eq!(cache_ttl(&zero), None);
        // A truncated answer stops at the records it carried: the client's
        // retry must reach a resolver, not this cache.
        let mut tc = response_skeleton(1);
        add_answer(&mut tc, TYPE_A, &[1, 2, 3, 4]);
        tc[2] |= 0x02;
        assert_eq!(cache_ttl(&tc), None);
        // SERVFAIL describes a moment of the resolver, not the record.
        let mut servfail = response_skeleton(0);
        servfail[3] = (servfail[3] & 0xf0) | RCODE_SERVFAIL as u8;
        assert_eq!(cache_ttl(&servfail), None);
        // Nothing says how long an empty answer without an SOA holds.
        assert_eq!(cache_ttl(&response_skeleton(0)), None);
    }

    #[test]
    fn a_negative_answer_lives_as_long_as_its_soa_allows() {
        let mut msg = response_skeleton(0);
        msg[3] = (msg[3] & 0xf0) | RCODE_NXDOMAIN as u8;
        msg[9] = 1; // one authority record
        add_answer_ttl(&mut msg, TYPE_SOA, 900, &soa_rdata(120));
        assert_eq!(cache_ttl(&msg), Some(120));
    }

    fn soa_rdata(minimum: u32) -> Vec<u8> {
        let mut r = Vec::new();
        for label in [&b"ns"[..], &b"example"[..], &b"com"[..]] {
            r.push(label.len() as u8);
            r.extend_from_slice(label);
        }
        r.push(0);
        for label in [&b"hostmaster"[..], &b"example"[..], &b"com"[..]] {
            r.push(label.len() as u8);
            r.extend_from_slice(label);
        }
        r.push(0);
        r.extend_from_slice(&1u32.to_be_bytes()); // serial
        r.extend_from_slice(&3_600u32.to_be_bytes()); // refresh
        r.extend_from_slice(&600u32.to_be_bytes()); // retry
        r.extend_from_slice(&86_400u32.to_be_bytes()); // expire
        r.extend_from_slice(&minimum.to_be_bytes());
        r
    }

    #[test]
    fn a_cached_answer_ages_instead_of_restarting_its_clock() {
        let mut msg = response_skeleton(1);
        add_answer(&mut msg, TYPE_A, &[1, 2, 3, 4]);
        assert_eq!(age_ttls(&mut msg, 0), 0);
        assert_eq!(age_ttls(&mut msg, 90), 1);
        assert_eq!(u32::from_be_bytes([msg[35], msg[36], msg[37], msg[38]]), 210);
        // Never underflows into a huge lifetime.
        assert_eq!(age_ttls(&mut msg, 9_999), 1);
        assert_eq!(u32::from_be_bytes([msg[35], msg[36], msg[37], msg[38]]), 0);
    }

    #[test]
    fn a_cached_answer_echoes_the_clients_own_spelling() {
        let mut msg = response_skeleton(1);
        add_answer(&mut msg, TYPE_A, &[1, 2, 3, 4]);
        // The client randomized the case (0x20 encoding) and checks that the
        // reply echoes it.
        let mut qname = Vec::new();
        qname.push(7u8);
        qname.extend_from_slice(b"ExAmPlE");
        qname.push(3u8);
        qname.extend_from_slice(b"CoM");
        let client = make_query(&qname, TYPE_A);
        let query = parse_query(&client).expect("q");
        assert!(adopt_question(&mut msg, &query));
        assert_eq!(&msg[12..29], &client[12..29]);
        // A question of a different length does not line up.
        let other = make_query(&[3u8, b'w', b'w', b'w'], TYPE_A);
        assert!(!adopt_question(&mut msg, &parse_query(&other).expect("q")));
    }

    /// The parameter list of the first SVCB/HTTPS answer, parsed the way a
    /// client would: independently of `strip_ech`.
    fn svcb_params(message: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let qd = u16::from_be_bytes([message[4], message[5]]) as usize;
        let an = u16::from_be_bytes([message[6], message[7]]) as usize;
        let mut off = 12usize;
        for _ in 0..qd {
            assert!(skip_name(message, &mut off));
            off += 4;
        }
        for _ in 0..an {
            assert!(skip_name(message, &mut off));
            let rtype = u16::from_be_bytes([message[off], message[off + 1]]);
            let rdlen = u16::from_be_bytes([message[off + 8], message[off + 9]]) as usize;
            off += 10;
            let end = off + rdlen;
            if rtype == TYPE_HTTPS {
                let mut p = off + 2;
                assert!(skip_name(message, &mut p));
                let mut out = Vec::new();
                while p + 4 <= end {
                    let key = u16::from_be_bytes([message[p], message[p + 1]]);
                    let len = u16::from_be_bytes([message[p + 2], message[p + 3]]) as usize;
                    out.push((key, message[p + 4..p + 4 + len].to_vec()));
                    p += 4 + len;
                }
                return out;
            }
            off = end;
        }
        Vec::new()
    }

    #[test]
    fn strips_the_ech_param_without_moving_a_byte() {
        const ALPN: &[u8] = &[0x02, b'h', b'2'];
        const ECM: &[u8] = &[0xab; 6];
        const HINT: &[u8] = &[93, 184, 216, 34];
        let mut msg = response_skeleton(2);
        add_answer(
            &mut msg,
            TYPE_HTTPS,
            &svcb_rdata(&[(1, ALPN), (5, ECM), (4, HINT)]),
        );
        // An answer *after* the rewritten one must survive untouched.
        add_answer(&mut msg, TYPE_A, &[1, 2, 3, 4]);
        let before = svcb_params(&msg);
        assert!(before.iter().any(|(key, _)| *key == SVC_PARAM_KEY_ECH));
        let len = msg.len();

        assert!(strip_ech(&mut msg));
        assert_eq!(msg.len(), len, "the rewrite may not shift a byte");
        let after = svcb_params(&msg);
        assert_eq!(
            after,
            vec![
                (1, ALPN.to_vec()),
                (SVC_PARAM_KEY_RESERVED, ECM.to_vec()),
                (4, HINT.to_vec()),
            ]
        );
        // The record after it still parses, too.
        let learned = parse_answers(&msg);
        assert_eq!(learned.len(), 1);
        assert_eq!(learned[0].ip.as_ip().to_string(), "1.2.3.4");
        // Nothing left for a second pass.
        assert!(!strip_ech(&mut msg));
    }

    #[test]
    fn leaves_a_record_without_ech_alone() {
        let mut msg = response_skeleton(2);
        add_answer(
            &mut msg,
            TYPE_HTTPS,
            &svcb_rdata(&[(1, &[0x02, b'h', b'2'])]),
        );
        add_answer(&mut msg, TYPE_A, &[1, 2, 3, 4]);
        let before = msg.clone();
        assert!(!strip_ech(&mut msg));
        assert_eq!(msg, before, "no ech means no rewrite at all");
    }

    #[test]
    fn a_truncated_answer_is_left_alone() {
        assert!(!strip_ech(&mut []));
        assert!(!strip_ech(&mut [0u8; 3]));
        // An answer count that promises records the message does not carry.
        let mut msg = response_skeleton(1);
        assert!(!strip_ech(&mut msg));
        // An HTTPS record whose RDATA claims an `ech` value it does not carry:
        // the parameter must be left alone, not patched over the record end.
        let mut msg = response_skeleton(1);
        add_answer(
            &mut msg,
            TYPE_HTTPS,
            &[0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x40],
        );
        let before = msg.clone();
        assert!(!strip_ech(&mut msg));
        assert_eq!(msg, before);
    }

    #[test]
    fn a_rewritten_answer_is_not_cached_as_published() {
        let mut msg = response_skeleton(2);
        add_answer(&mut msg, TYPE_HTTPS, &svcb_rdata(&[(5, &[0xab; 6])]));
        add_answer(&mut msg, TYPE_A, &[1, 2, 3, 4]);
        assert_eq!(
            clamp_answer_ttl(&mut msg, 60),
            2,
            "both records carried 300"
        );
        // Header (12) + question (17) + name pointer (2) + type/class (4):
        // the first record's TTL.
        assert_eq!(u32::from_be_bytes([msg[35], msg[36], msg[37], msg[38]]), 60);
        assert_eq!(parse_answers(&msg).len(), 1);
        // Nothing to lower once every record fits.
        assert_eq!(clamp_answer_ttl(&mut msg, 60), 0);
    }

    /// The ECHConfigList `crypto.cloudflare.com` served on 19/10/2026 (from
    /// `dig +short HTTPS crypto.cloudflare.com`, base64 `AEX+DQBBPwAgACCY…`):
    /// a real 0xfe0d config, public name `cloudflare-ech.com`, no extensions.
    const CF_ECH_CONFIG: &[u8] = &[
        0x00, 0x45, 0xfe, 0x0d, 0x00, 0x41, 0x3f, 0x00, 0x20, 0x00, 0x20, 0x98, 0x25, 0xe1, 0xdb,
        0x0b, 0xf9, 0x5a, 0x81, 0x67, 0x61, 0x6c, 0x83, 0x39, 0x10, 0x9a, 0x22, 0xfd, 0x35, 0x47,
        0x20, 0xa6, 0x37, 0xd2, 0x66, 0x16, 0xa6, 0xa3, 0xc2, 0xaf, 0x8d, 0x88, 0x29, 0x00, 0x04,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x6c, 0x61, 0x72,
        0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
    ];

    #[test]
    fn the_public_name_comes_out_of_a_real_ech_config() {
        let mut msg = response_skeleton(1);
        add_answer(&mut msg, TYPE_HTTPS, &svcb_rdata(&[(5, CF_ECH_CONFIG)]));
        assert_eq!(
            ech_public_name(&msg),
            Some("cloudflare-ech.com".to_string())
        );
        // A record without ech carries no name.
        let mut plain = response_skeleton(1);
        add_answer(
            &mut plain,
            TYPE_HTTPS,
            &svcb_rdata(&[(1, &[0x02, b'h', b'2'])]),
        );
        assert_eq!(ech_public_name(&plain), None);
        // A value that is not an ECHConfigList is ignored, not guessed at.
        let mut junk = response_skeleton(1);
        add_answer(&mut junk, TYPE_HTTPS, &svcb_rdata(&[(5, &[0xab; 6])]));
        assert_eq!(ech_public_name(&junk), None);
    }

    /// `ech_config_list` hands the upstream half exactly the bytes `dig` shows:
    /// the SvcParam value, length prefix included.
    #[test]
    fn the_raw_ech_config_list_survives_the_round_trip() {
        let mut msg = response_skeleton(1);
        add_answer(&mut msg, TYPE_HTTPS, &svcb_rdata(&[(5, CF_ECH_CONFIG)]));
        assert_eq!(ech_config_list(&msg), Some(CF_ECH_CONFIG.to_vec()));
        // Stripping rewrites the key, so the list must be taken before it.
        assert!(strip_ech(&mut msg));
        assert_eq!(ech_config_list(&msg), None);
        // A record without ech, and an unreadable value, carry no list.
        let mut plain = response_skeleton(1);
        add_answer(
            &mut plain,
            TYPE_HTTPS,
            &svcb_rdata(&[(1, &[0x02, b'h', b'2'])]),
        );
        assert_eq!(ech_config_list(&plain), None);
        let mut junk = response_skeleton(1);
        add_answer(&mut junk, TYPE_HTTPS, &svcb_rdata(&[(5, &[0xab; 6])]));
        assert_eq!(ech_config_list(&junk), None);
    }
}
