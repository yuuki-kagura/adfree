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
}
