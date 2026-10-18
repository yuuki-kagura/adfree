//! DNS message decoding, synthetic reply synthesis and answer learning.
//!
//! The VPN intercepts every outgoing query, asks the filter core about the
//! QNAME and either answers straight from the TUN (no radio wakeup, no upstream
//! round trip) or forwards it to a protected upstream socket.
//!
//! All decoding is done into fixed stack buffers: there is no heap allocation
//! per query on the packet path.

use crate::packet::{self, Packet};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const TYPE_ANY: u16 = 255;

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
    let _qclass = u16::from_be_bytes([*body.get(off + 2)?, *body.get(off + 3)?]);
    off += 4;

    Some(Query {
        body,
        id,
        flags,
        qd_count,
        qtype,
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
pub fn synthesize_error(packet: &Packet<'_>, query: Option<&Query<'_>>, rcode: u16) -> Option<Vec<u8>> {
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
        b.extend_from_slice(&[0xc0, 0x0c]);
        b.extend_from_slice(&rtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&300u32.to_be_bytes());
        b.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        b.extend_from_slice(rdata);
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
}
