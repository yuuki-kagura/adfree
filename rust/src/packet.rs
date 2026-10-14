//! Zero-copy parsing of the IPv4/IPv6 + TCP/UDP headers coming out of the TUN
//! file descriptor, plus synthesis of reply packets (DNS answers and TCP RSTs).
//!
//! Everything here is `#[inline]` and allocation free on the decode path: the
//! hot loop reads one packet, classifies it and either writes a synthesized
//! reply or hands the packet back to the kernel.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const FIN: u8 = 0x01;
pub const PSH: u8 = 0x08;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

/// A decoded packet. Borrows the original buffer; nothing is copied until a
/// reply actually needs to be built.
#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    pub raw: &'a [u8],
    pub version: u8,
    pub proto: u8,
    /// Length of the IP header (4 for IPv6).
    pub ip_hdr_len: usize,
    pub total_len: usize,
    pub src_port: u16,
    pub dst_port: u16,
    pub is_syn: bool,
    pub is_ack: bool,
    pub is_rst: bool,
    pub is_fin: bool,
    pub seq: u32,
    pub ack_seq: u32,
    /// Payload length of the L4 datagram (L3 payload minus the L4 header).
    pub l4_payload_len: usize,
    ip_hdr: &'a [u8],
    l4_hdr: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpKey {
    V4(u32),
    V6(u128),
}

impl IpKey {
    #[inline]
    pub fn as_ip(&self) -> std::net::IpAddr {
        match *self {
            IpKey::V4(v) => std::net::IpAddr::V4(Ipv4Addr::from(v)),
            IpKey::V6(v) => std::net::IpAddr::V6(Ipv6Addr::from(v)),
        }
    }
}

/// Converts a `std` address into the packed key used by the tables.
pub fn ip_key_from(addr: std::net::IpAddr) -> IpKey {
    match addr {
        std::net::IpAddr::V4(v4) => IpKey::V4(u32::from_be_bytes(v4.octets())),
        std::net::IpAddr::V6(v6) => IpKey::V6(u128::from_be_bytes(v6.octets())),
    }
}

pub fn ip_key_from_bytes(bytes: &[u8]) -> Option<IpKey> {
    match bytes.len() {
        4 => {
            let mut b = [0u8; 4];
            b.copy_from_slice(bytes);
            Some(IpKey::V4(u32::from_be_bytes(b)))
        }
        16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(bytes);
            Some(IpKey::V6(u128::from_be_bytes(b)))
        }
        _ => None,
    }
}

impl<'a> Packet<'a> {
    pub fn src_ip(&self) -> Option<IpKey> {
        self.src_ip_bytes().and_then(ip_key_from_bytes)
    }

    pub fn dst_ip(&self) -> Option<IpKey> {
        self.dst_ip_bytes().and_then(ip_key_from_bytes)
    }

    #[inline]
    fn src_ip_bytes(&self) -> Option<&'a [u8]> {
        if self.version == 4 {
            self.ip_hdr.get(12..16)
        } else {
            self.ip_hdr.get(8..24)
        }
    }

    #[inline]
    fn dst_ip_bytes(&self) -> Option<&'a [u8]> {
        if self.version == 4 {
            self.ip_hdr.get(16..20)
        } else {
            self.ip_hdr.get(24..40)
        }
    }

    /// Source address as dotted-quad / hextet text. Borrows the packet buffer.
    pub fn src_ip_text(&self) -> String {
        self.src_ip().map(|k| k.as_ip().to_string()).unwrap_or_default()
    }

    pub fn dst_ip_text(&self) -> String {
        self.dst_ip().map(|k| k.as_ip().to_string()).unwrap_or_default()
    }

    pub fn l4_payload(&self) -> &'a [u8] {
        let start = self.ip_hdr_len + self.l4_hdr_len();
        if start <= self.raw.len() {
            &self.raw[start..]
        } else {
            &[]
        }
    }

    #[inline]
    fn l4_hdr_len(&self) -> usize {
        match self.proto {
            PROTO_UDP => 8,
            PROTO_TCP => {
                let data_off = self
                    .l4_hdr
                    .get(12)
                    .map(|b| (b >> 4) as usize * 4)
                    .unwrap_or(20);
                if data_off < 20 {
                    20
                } else {
                    data_off
                }
            }
            _ => 0,
        }
    }

    /// Decodes a packet. Returns `None` for anything that is not plain
    /// IPv4/IPv6 TCP or UDP (fragments, extension headers, truncated).
    pub fn parse(raw: &'a [u8]) -> Option<Packet<'a>> {
        if raw.len() < 20 {
            return None;
        }
        let version = raw[0] >> 4;
        let (proto, ip_hdr_len, total_len, l4_offset) = match version {
            4 => {
                let ihl = (raw[0] & 0x0f) as usize * 4;
                if ihl < 20 || raw.len() < ihl {
                    return None;
                }
                let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
                // Fragments other than the first cannot be classified and the
                // DNS payload would be incomplete.
                if flags_frag & 0x1fff != 0 {
                    return None;
                }
                let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
                if total_len < ihl || total_len > raw.len() {
                    return None;
                }
                (
                    raw[9],
                    ihl,
                    total_len,
                    ihl,
                )
            }
            6 => {
                if raw.len() < 40 {
                    return None;
                }
                let payload_len = u16::from_be_bytes([raw[4], raw[5]]) as usize;
                let total_len = 40 + payload_len;
                if total_len > raw.len() {
                    return None;
                }
                // Skip the common extension header chain; we only care about the
                // packet if it lands on TCP or UDP eventually.
                let mut next = raw[6];
                let mut off = 40usize;
                loop {
                    match next {
                        6 | 17 | 58 | 136 => break,
                        0 => {
                            // Hop-by-hop
                            if off + 2 > raw.len() {
                                return None;
                            }
                            let ext_len = (raw[off + 1] as usize + 1) * 8;
                            next = raw[off];
                            off += ext_len;
                        }
                        43 | 60 => {
                            if off + 2 > raw.len() {
                                return None;
                            }
                            let ext_len = (raw[off + 1] as usize + 1) * 8;
                            next = raw[off];
                            off += ext_len;
                        }
                        _ => return None,
                    }
                    if off >= raw.len() {
                        return None;
                    }
                }
                (next, 40, total_len, off)
            }
            _ => return None,
        };

        if l4_offset + 4 > raw.len() {
            return None;
        }
        let l4_hdr = &raw[l4_offset..];
        let ip_hdr = &raw[..ip_hdr_len];
        let (
            src_port,
            dst_port,
            flags,
            seq,
            ack_seq,
            is_syn,
            is_ack,
            is_rst,
            is_fin,
            l4_payload_len,
        ) = match proto {
            PROTO_UDP => {
                if l4_hdr.len() < 8 {
                    return None;
                }
                let sp = u16::from_be_bytes([l4_hdr[0], l4_hdr[1]]);
                let dp = u16::from_be_bytes([l4_hdr[2], l4_hdr[3]]);
                let len = u16::from_be_bytes([l4_hdr[4], l4_hdr[5]]) as usize;
                if len < 8 || l4_offset + len > total_len {
                    return None;
                }
                // UDP has no sequence numbers; the placeholders are only there to
                // keep the struct shape uniform between the two protocols.
                (sp, dp, 0u8, 0, 0, false, false, false, false, len - 8)
            }
            PROTO_TCP => {
                if l4_hdr.len() < 20 {
                    return None;
                }
                let sp = u16::from_be_bytes([l4_hdr[0], l4_hdr[1]]);
                let dp = u16::from_be_bytes([l4_hdr[2], l4_hdr[3]]);
                let f = l4_hdr[13];
                let seq = u32::from_be_bytes([l4_hdr[4], l4_hdr[5], l4_hdr[6], l4_hdr[7]]);
                let ack =
                    u32::from_be_bytes([l4_hdr[8], l4_hdr[9], l4_hdr[10], l4_hdr[11]]);
                let data_off = (f >> 4) as usize * 4;
                let l4_payload_len = l4_hdr.len().saturating_sub(data_off.max(20));
                (
                    sp,
                    dp,
                    f,
                    seq,
                    ack,
                    f & SYN != 0,
                    f & ACK != 0,
                    f & RST != 0,
                    f & FIN != 0,
                    l4_payload_len,
                )
            }
            _ => return None,
        };

        let _ = flags; // TCP-only field; UDP keeps zero
        Some(Packet {
            raw,
            version,
            proto,
            ip_hdr_len,
            total_len,
            src_port,
            dst_port,
            is_syn,
            is_ack,
            is_rst,
            is_fin,
            seq,
            ack_seq,
            l4_payload_len,
            ip_hdr,
            l4_hdr,
        })
    }

    /// Byte offset where the L4 payload starts.
    #[inline]
    pub fn l4_payload_offset(&self) -> usize {
        self.ip_hdr_len + self.l4_hdr_len()
    }

    /// Builds a DNS reply packet by rewriting the query in place.
    ///
    /// `payload` is the new DNS message (possibly a different length than the
    /// query), addresses and ports are swapped and every checksum/length field
    /// is recomputed.
    pub fn rewrite_udp(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = self.raw[..self.total_len.min(self.raw.len())].to_vec();
        let l4 = self.ip_hdr_len;
        // Swap addresses.
        if self.version == 4 {
            for i in 12..16 {
                out.swap(i, i + 4);
            }
        } else {
            for i in 8..24 {
                out.swap(i, i + 16);
            }
        }
        // Swap ports.
        out[l4] = self.dst_port_hi();
        out[l4 + 1] = self.dst_port_lo();
        out[l4 + 2] = self.src_port_hi();
        out[l4 + 3] = self.src_port_lo();
        // New UDP length.
        let new_l4_len = (8 + payload.len()) as u16;
        out[l4 + 4] = (new_l4_len >> 8) as u8;
        out[l4 + 5] = (new_l4_len & 0xff) as u8;
        // The UDP checksum of an IPv4 datagram is optional; for IPv6 it is
        // mandatory and must be recomputed after the swap.
        out[l4 + 6] = 0;
        out[l4 + 7] = 0;
        if self.version == 6 && out.len() >= l4 + 8 {
            let checksum = udp_checksum_v6(&out[..l4], &out[l4..l4 + 8], payload);
            let sum = if checksum == 0 { 0xffff } else { checksum };
            out[l4 + 6..l4 + 8].copy_from_slice(&sum.to_be_bytes());
        }
        // Replace the L4 payload.
        out.truncate(l4 + 8);
        out.extend_from_slice(payload);
        let total = out.len();
        if self.version == 4 {
            out[2] = (total >> 8) as u8;
            out[3] = (total & 0xff) as u8;
            fix_ipv4_checksum(&mut out);
        } else {
            out[4] = ((total - 40) >> 8) as u8;
            out[5] = ((total - 40) & 0xff) as u8;
        }
        out
    }
}

impl<'a> Packet<'a> {
    #[inline]
    fn dst_port_hi(&self) -> u8 {
        (self.dst_port >> 8) as u8
    }
    #[inline]
    fn dst_port_lo(&self) -> u8 {
        (self.dst_port & 0xff) as u8
    }
    #[inline]
    fn src_port_hi(&self) -> u8 {
        (self.src_port >> 8) as u8
    }
    #[inline]
    fn src_port_lo(&self) -> u8 {
        (self.src_port & 0xff) as u8
    }
}

/// Builds a TCP RST (+ACK) answer for a SYN, terminating the connection
/// locally instead of letting the app wait for a timeout.
pub fn build_rst(packet: &Packet<'_>) -> Option<Vec<u8>> {
    if packet.raw.len() < packet.ip_hdr_len + 20 {
        return None;
    }
    let mut out = packet.raw[..packet.total_len.min(packet.raw.len())].to_vec();
    let l4 = packet.ip_hdr_len;

    if packet.version == 4 {
        for i in 12..16 {
            out.swap(i, i + 4);
        }
    } else {
        for i in 8..24 {
            out.swap(i, i + 16);
        }
    }
    // Swap ports.
    out[l4] = (packet.dst_port >> 8) as u8;
    out[l4 + 1] = (packet.dst_port & 0xff) as u8;
    out[l4 + 2] = (packet.src_port >> 8) as u8;
    out[l4 + 3] = (packet.src_port & 0xff) as u8;
    // A reset for a packet that was UDP (a DNS flow, say) still has to look
    // like TCP, otherwise the kernel classifies the reply as UDP and drops it.
    if packet.proto == PROTO_UDP {
        out[9] = 6;
    }
    // The RST acknowledges everything already seen: seq = ack,
    // ack = seq + payload + the SYN/FIN that was consumed.
    let mut ack = packet.seq.wrapping_add(1);
    if packet.is_fin {
        ack = ack.wrapping_add(1);
    }
    ack = ack.wrapping_add(packet.l4_payload_len as u32);
    out[l4 + 4..l4 + 8].copy_from_slice(&packet.ack_seq.to_be_bytes());
    out[l4 + 8..l4 + 12].copy_from_slice(&ack.to_be_bytes());
    // data offset 5, flags RST|ACK, window 0
    out[l4 + 12] = 5 << 4;
    out[l4 + 13] = RST | ACK;
    out[l4 + 14] = 0;
    out[l4 + 15] = 0;
    let total = l4 + 20;
    out.truncate(total);
    if packet.version == 4 {
        out[2] = (total >> 8) as u8;
        out[3] = (total & 0xff) as u8;
        fix_ipv4_checksum(&mut out);
    } else {
        out[4] = ((total - 40) >> 8) as u8;
        out[5] = ((total - 40) & 0xff) as u8;
        let checksum = tcp_checksum_v6(&out[..l4], &out[l4..l4 + 20]);
        out[l4 + 16..l4 + 18].copy_from_slice(&checksum.to_be_bytes());
        out[l4 + 18..l4 + 20].copy_from_slice(&0u16.to_be_bytes());
    }
    Some(out)
}

/// Build a TCP reply (ACK or SYN-ACK) for a packet, using caller-supplied
/// seq/ack. Used by the MITM stage when we answer instead of the OS.
pub fn build_ack_response(pkt: &Packet<'_>, seq: u32, ack: u32) -> Option<Vec<u8>> {
    if pkt.raw.len() < pkt.ip_hdr_len + 20 {
        return None;
    }
    let mut out = pkt.raw[..pkt.total_len.min(pkt.raw.len())].to_vec();
    let l4 = pkt.ip_hdr_len;

    if pkt.version == 4 {
        for i in 12..16 {
            out.swap(i, i + 4);
        }
        // A UDP (DNS) packet has no TCP flags: switch the protocol so it parses.
        if pkt.proto == PROTO_UDP {
            out[9] = 6;
        }
    } else {
        for i in 8..24 {
            out.swap(i, i + 16);
        }
    }

    out[l4] = (pkt.dst_port >> 8) as u8;
    out[l4 + 1] = (pkt.dst_port & 0xff) as u8;
    out[l4 + 2] = (pkt.src_port >> 8) as u8;
    out[l4 + 3] = (pkt.src_port & 0xff) as u8;
    out[l4 + 4..l4 + 8].copy_from_slice(&seq.to_be_bytes());
    out[l4 + 8..l4 + 12].copy_from_slice(&ack.to_be_bytes());
    out[l4 + 12] = 5 << 4; // data offset 5, no options
    // SYN-ACK when replying to a SYN.
    out[l4 + 13] = if pkt.is_syn { ACK | SYN } else { ACK };
    out[l4 + 14] = 0xff; // window
    out[l4 + 15] = 0xff;
    let total = l4 + 20;
    out.truncate(total);

    if pkt.version == 4 {
        out[2] = (total >> 8) as u8;
        out[3] = (total & 0xff) as u8;
        fix_ipv4_checksum(&mut out);
        // TCP checksum set to 0; not required for the packets we synthesise.
        out[l4 + 16] = 0;
        out[l4 + 17] = 0;
        out[l4 + 18] = 0;
        out[l4 + 19] = 0;
    } else {
        out[4] = ((total - 40) >> 8) as u8;
        out[5] = ((total - 40) & 0xff) as u8;
        let checksum = tcp_checksum_v6(&out[..l4], &out[l4..total]);
        out[l4 + 16..l4 + 18].copy_from_slice(&checksum.to_be_bytes());
        out[l4 + 18..l4 + 20].copy_from_slice(&0u16.to_be_bytes());
    }
    Some(out)
}

/// Recomputes the IPv4 header checksum of a mutable packet buffer.
pub fn fix_ipv4_checksum(buf: &mut [u8]) {
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < ihl {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    buf[10] = (csum >> 8) as u8;
    buf[11] = (csum & 0xff) as u8;
}

/// IPv6 pseudo header: src(16) dst(16) len(32) zeros(24) next_header(8).
fn v6_pseudo(ip_hdr: &[u8], len: u32, next_header: u8) -> [u8; 40] {
    let mut pseudo = [0u8; 40];
    if ip_hdr.len() < 40 {
        return pseudo;
    }
    pseudo[0..16].copy_from_slice(&ip_hdr[8..24]);
    pseudo[16..32].copy_from_slice(&ip_hdr[24..40]);
    pseudo[32..36].copy_from_slice(&len.to_be_bytes());
    pseudo[39] = next_header;
    pseudo
}

pub fn tcp_checksum_v6(ip_hdr: &[u8], tcp: &[u8]) -> u16 {
    internet_checksum(&v6_pseudo(ip_hdr, tcp.len() as u32, PROTO_TCP), tcp, &[])
}

pub fn udp_checksum_v6(ip_hdr: &[u8], udp_hdr: &[u8], payload: &[u8]) -> u16 {
    let len = (udp_hdr.len() + payload.len()) as u32;
    internet_checksum(&v6_pseudo(ip_hdr, len, PROTO_UDP), udp_hdr, payload)
}

/// Standard RFC 1071 internet checksum.
pub fn internet_checksum(pseudo: &[u8], a: &[u8], b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let acc = |bytes: &[u8], sum: &mut u32| {
        let mut i = 0;
        while i + 1 < bytes.len() {
            *sum += u16::from_be_bytes([bytes[i], bytes[i + 1]]) as u32;
            i += 2;
        }
        if i < bytes.len() {
            *sum += u16::from_be_bytes([bytes[i], 0]) as u32;
        }
    };
    acc(pseudo, &mut sum);
    acc(a, &mut sum);
    acc(b, &mut sum);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp_dns_query(qname: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        // IPv4 header
        p.extend_from_slice(&[0x45, 0x00]);
        let total = 20 + 8 + 12 + qname.len() + 4;
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00]);
        p.extend_from_slice(&[192, 168, 1, 5]);
        p.extend_from_slice(&[9, 9, 9, 9]);
        // UDP
        p.extend_from_slice(&43210u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&((8 + 12 + qname.len() + 4) as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]);
        // DNS
        p.extend_from_slice(&[0x12, 0x34]);
        p.extend_from_slice(&[0x01, 0x00]);
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        p.extend_from_slice(qname);
        p.extend_from_slice(&[0x00]);
        p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        fix_ipv4_checksum(&mut p);
        p
    }

    #[test]
    fn parses_ipv4_udp_dns() {
        let q = ipv4_udp_dns_query(b"\x07example\x03com");
        let p = Packet::parse(&q).expect("parse");
        assert_eq!(p.version, 4);
        assert_eq!(p.proto, PROTO_UDP);
        assert_eq!(p.src_port, 43210);
        assert_eq!(p.dst_port, 53);
        assert_eq!(p.dst_ip_text(), "9.9.9.9");
        assert_eq!(p.src_ip_text(), "192.168.1.5");
        assert_eq!(p.l4_payload()[..4], [0x12, 0x34, 0x01, 0x00]);
    }

    #[test]
    fn rst_swaps_addresses_and_acks() {
        let q = ipv4_udp_dns_query(b"\x07example\x03com");
        let p = Packet::parse(&q).unwrap();
        let rst = build_rst(&p).expect("rst");
        let rp = Packet::parse(&rst).expect("parse rst");
        assert_eq!(rp.src_ip_text(), "9.9.9.9");
        assert_eq!(rp.dst_ip_text(), "192.168.1.5");
        assert_eq!(rp.src_port, 53);
        assert_eq!(rp.dst_port, 43210);
        assert!(rp.is_rst);
        assert!(rp.is_ack);
        assert_eq!(rp.total_len, 20 + 20);
    }

    #[test]
    fn ipv6_is_parsed() {
        // 40 byte header + UDP + 12 bytes DNS
        let mut p = Vec::new();
        p.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        let len = 8 + 12;
        p.extend_from_slice(&(len as u16).to_be_bytes());
        p.extend_from_slice(&[17, 64]);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&(len as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]);
        p.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        let parsed = Packet::parse(&p).expect("parse v6");
        assert_eq!(parsed.version, 6);
        assert_eq!(parsed.dst_ip_text(), "2001:db8::2");
        assert_eq!(parsed.dst_port, 53);
    }

    #[test]
    fn ipv4_checksum_roundtrip() {
        let mut p = vec![0x45u8, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 40, 17];
        p.extend_from_slice(&[0, 0, 1, 2, 3, 4]);
        // Fill the rest of the 20 byte header so the checksum walk is valid.
        p.extend_from_slice(&[0u8; 4]);
        fix_ipv4_checksum(&mut p);
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < 20 {
            sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32;
            i += 2;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff, "checksum must verify");
    }
}
