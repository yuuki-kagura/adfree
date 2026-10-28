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
    /// Receive window the sender advertises (TCP only; zero for UDP).
    pub window: u16,
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
        self.src_ip()
            .map(|k| k.as_ip().to_string())
            .unwrap_or_default()
    }

    pub fn dst_ip_text(&self) -> String {
        self.dst_ip()
            .map(|k| k.as_ip().to_string())
            .unwrap_or_default()
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
                // MF or a non-zero offset means the datagram is fragmented:
                // the payload alone cannot be classified, and relaying the
                // first fragment would deliver a truncated datagram instead
                // of the ones the upper layer expects. Both are dropped.
                if flags_frag & 0x3fff != 0 {
                    return None;
                }
                let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
                if total_len < ihl || total_len > raw.len() {
                    return None;
                }
                (raw[9], ihl, total_len, ihl)
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
            window,
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
                (sp, dp, 0u8, 0, 0, 0u16, false, false, false, false, len - 8)
            }
            PROTO_TCP => {
                if l4_hdr.len() < 20 {
                    return None;
                }
                let sp = u16::from_be_bytes([l4_hdr[0], l4_hdr[1]]);
                let dp = u16::from_be_bytes([l4_hdr[2], l4_hdr[3]]);
                let f = l4_hdr[13];
                let seq = u32::from_be_bytes([l4_hdr[4], l4_hdr[5], l4_hdr[6], l4_hdr[7]]);
                let ack = u32::from_be_bytes([l4_hdr[8], l4_hdr[9], l4_hdr[10], l4_hdr[11]]);
                // The window is what funds every byte we send back: without it
                // a big response (the stitched userscript) overruns the client's
                // receive buffer and the excess is dropped, never retransmitted.
                let window = u16::from_be_bytes([l4_hdr[14], l4_hdr[15]]);
                let data_off = (f >> 4) as usize * 4;
                let l4_payload_len = l4_hdr.len().saturating_sub(data_off.max(20));
                (
                    sp,
                    dp,
                    f,
                    seq,
                    ack,
                    window,
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
            window,
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

    /// The MSS advertised in a TCP SYN's options, if present.
    ///
    /// Our segments must fit inside it or the client's stack will drop what
    /// does not: replying to a SYN without ever sending more than the peer's
    /// own declared size is the only way to be sure.
    pub fn tcp_mss(&self) -> Option<u16> {
        if self.proto != PROTO_TCP {
            return None;
        }
        let options = self
            .raw
            .get(self.ip_hdr_len + 20..self.ip_hdr_len + self.l4_hdr_len())?;
        let mut i = 0;
        while i < options.len() {
            match options[i] {
                0 => break,  // End of options
                1 => i += 1, // NOP
                kind => {
                    let len = *options.get(i + 1)? as usize;
                    if len < 2 {
                        break;
                    }
                    if kind == 2 && len == 4 {
                        let value = u16::from_be_bytes([options[i + 2], options[i + 3]]);
                        return Some(value);
                    }
                    i += len;
                }
            }
        }
        None
    }

    /// The receive-window scale the sender advertised in its SYN.
    ///
    /// A window field of 65535 with scale 8 means a 16 MB window: ignoring the
    /// scale would hold every reply down to a few hundred bytes per burst.
    pub fn tcp_window_scale(&self) -> Option<u8> {
        if self.proto != PROTO_TCP {
            return None;
        }
        let options = self
            .raw
            .get(self.ip_hdr_len + 20..self.ip_hdr_len + self.l4_hdr_len())?;
        let mut i = 0;
        while i < options.len() {
            match options[i] {
                0 => break,  // End of options
                1 => i += 1, // NOP
                kind => {
                    let len = *options.get(i + 1)? as usize;
                    if len < 2 {
                        break;
                    }
                    if kind == 3 && len == 3 {
                        // The option caps at 14 per RFC 7323.
                        return Some(options[i + 2].min(14));
                    }
                    i += len;
                }
            }
        }
        None
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

/// Builds a whole UDP packet from its four endpoints and payload.
///
/// The QUIC bridge only ever holds datagrams, not packets: quinn reports where
/// a datagram goes, and the engine has to turn it into something the TUN
/// device accepts. Addresses and ports are taken as-is (no swap), so the caller
/// decides the direction.
pub fn build_udp(
    src: IpKey,
    src_port: u16,
    dst: IpKey,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    if udp_len > u16::MAX as usize {
        return None;
    }
    match (src, dst) {
        (IpKey::V4(s), IpKey::V4(d)) => {
            let total = 20usize.checked_add(udp_len)?;
            if total > u16::MAX as usize {
                return None;
            }
            let mut out = vec![0u8; total];
            out[0] = 0x45;
            out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            // Don't fragment: a QUIC datagram is never fragmented by the path
            // above us either, and the DF bit keeps that contract.
            out[6] = 0x40;
            out[8] = 64;
            out[9] = PROTO_UDP;
            out[12..16].copy_from_slice(&s.to_be_bytes());
            out[16..20].copy_from_slice(&d.to_be_bytes());
            fix_ipv4_checksum(&mut out);
            write_udp_header(&mut out[20..28], src_port, dst_port, udp_len);
            out[28..].copy_from_slice(payload);
            let checksum = internet_checksum(
                &v4_pseudo(&out[..20], udp_len as u32, PROTO_UDP),
                &out[20..28],
                payload,
            );
            // A computed zero is transmitted as all ones (RFC 768): zero means
            // "no checksum", which would make a v6 receiver drop the datagram.
            let checksum = if checksum == 0 { 0xffff } else { checksum };
            out[26..28].copy_from_slice(&checksum.to_be_bytes());
            Some(out)
        }
        (IpKey::V6(s), IpKey::V6(d)) => {
            let mut out = vec![0u8; 40 + udp_len];
            out[0] = 0x60;
            out[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            out[6] = PROTO_UDP;
            out[7] = 64;
            out[8..24].copy_from_slice(&s.to_be_bytes());
            out[24..40].copy_from_slice(&d.to_be_bytes());
            write_udp_header(&mut out[40..48], src_port, dst_port, udp_len);
            out[48..].copy_from_slice(payload);
            let checksum = udp_checksum_v6(&out[..40], &out[40..48], payload);
            let checksum = if checksum == 0 { 0xffff } else { checksum };
            out[46..48].copy_from_slice(&checksum.to_be_bytes());
            Some(out)
        }
        _ => None,
    }
}

fn write_udp_header(header: &mut [u8], src_port: u16, dst_port: u16, len: usize) {
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    header[6..8].copy_from_slice(&[0, 0]);
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
        // The seq/ack/flags just changed: the carried checksum is the client's,
        // it cannot survive. Recompute over the real pseudo header.
        let checksum = tcp_checksum_v4(&out[..l4], &out[l4..l4 + 20]);
        out[l4 + 16..l4 + 18].copy_from_slice(&checksum.to_be_bytes());
        out[l4 + 18..l4 + 20].copy_from_slice(&0u16.to_be_bytes());
    } else {
        out[4] = ((total - 40) >> 8) as u8;
        out[5] = ((total - 40) & 0xff) as u8;
        let checksum = tcp_checksum_v6(&out[..l4], &out[l4..l4 + 20]);
        out[l4 + 16..l4 + 18].copy_from_slice(&checksum.to_be_bytes());
        out[l4 + 18..l4 + 20].copy_from_slice(&0u16.to_be_bytes());
    }
    Some(out)
}

/// An ICMP "port unreachable" for a datagram the engine drops.
///
/// A silent drop leaves the sender waiting out the whole UDP/QUIC handshake
/// timeout. Chrome's Secure DNS is HTTP/3 first, so a quiet drop there never
/// falls back to TCP and the browser loses DNS entirely; the error is the
/// definite failure that triggers the fallback, and it is what a real NAT
/// would have sent. The error quotes the original IP header and the first
/// eight bytes of its payload, as RFC 792/4443 prescribe.
pub fn build_unreachable(packet: &Packet<'_>) -> Option<Vec<u8>> {
    let quote = packet.raw.get(..packet.ip_hdr_len + 8)?;
    if packet.version == 4 {
        Some(unreachable_v4(packet, quote))
    } else {
        Some(unreachable_v6(packet, quote))
    }
}

fn unreachable_v4(packet: &Packet<'_>, quote: &[u8]) -> Vec<u8> {
    let icmp_len = 8 + quote.len();
    let total = 20 + icmp_len;
    let mut out = vec![0u8; total];
    out[0] = 0x45;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[8] = 64;
    out[9] = 1; // ICMP
    let (Some(src), Some(dst)) = (packet.src_ip_bytes(), packet.dst_ip_bytes()) else {
        return out;
    };
    // The error is addressed from the host that was dialed to the client.
    out[12..16].copy_from_slice(dst);
    out[16..20].copy_from_slice(src);
    fix_ipv4_checksum(&mut out[..20]);
    out[20] = 3; // destination unreachable
    out[21] = 3; // port unreachable
    out[28..].copy_from_slice(quote);
    let checksum = internet_checksum(&[], &out[20..], &[]);
    out[22..24].copy_from_slice(&checksum.to_be_bytes());
    out
}

fn unreachable_v6(packet: &Packet<'_>, quote: &[u8]) -> Vec<u8> {
    let icmp_len = 8 + quote.len();
    let total = 40 + icmp_len;
    let mut out = vec![0u8; total];
    out[0] = 0x60;
    out[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    out[6] = 58; // ICMPv6
    out[7] = 64;
    let (Some(src), Some(dst)) = (packet.src_ip_bytes(), packet.dst_ip_bytes()) else {
        return out;
    };
    out[8..24].copy_from_slice(dst);
    out[24..40].copy_from_slice(src);
    out[40] = 1; // destination unreachable
    out[41] = 4; // port unreachable
    out[48..].copy_from_slice(quote);
    let pseudo = v6_pseudo(&out[..40], icmp_len as u32, 58);
    let checksum = internet_checksum(&pseudo, &out[40..], &[]);
    out[42..44].copy_from_slice(&checksum.to_be_bytes());
    out
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
        // A zero TCP checksum is not a "no checksum" marker the way it is for
        // UDP: the receiving stack validates it and drops the segment, so the
        // reply would never arrive. Compute the real one.
        let checksum = tcp_checksum_v4(&out[..l4], &out[l4..total]);
        out[l4 + 16..l4 + 18].copy_from_slice(&checksum.to_be_bytes());
        out[l4 + 18..l4 + 20].copy_from_slice(&0u16.to_be_bytes());
    } else {
        out[4] = ((total - 40) >> 8) as u8;
        out[5] = ((total - 40) & 0xff) as u8;
        let checksum = tcp_checksum_v6(&out[..l4], &out[l4..total]);
        out[l4 + 16..l4 + 18].copy_from_slice(&checksum.to_be_bytes());
        out[l4 + 18..l4 + 20].copy_from_slice(&0u16.to_be_bytes());
    }
    Some(out)
}

/// The IPv4 header checksum; `0` means the header is correct.
pub fn ipv4_checksum(buf: &[u8]) -> u16 {
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    internet_checksum(&[], &buf[..ihl], &[])
}

/// Recomputes the IPv4 header checksum of a mutable packet buffer.
pub fn fix_ipv4_checksum(buf: &mut [u8]) {
    // The checksum field must read zero while it is being computed, or the
    // previous value is folded into the result.
    buf[10] = 0;
    buf[11] = 0;
    let csum = ipv4_checksum(buf);
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

/// IPv4 pseudo header: src(4) dst(4) zero(1) proto(1) len(2).
fn v4_pseudo(ip_hdr: &[u8], len: u32, next_header: u8) -> [u8; 12] {
    let mut pseudo = [0u8; 12];
    if ip_hdr.len() < 20 {
        return pseudo;
    }
    pseudo[0..4].copy_from_slice(&ip_hdr[12..16]);
    pseudo[4..8].copy_from_slice(&ip_hdr[16..20]);
    pseudo[9] = next_header;
    pseudo[10..12].copy_from_slice(&(len as u16).to_be_bytes());
    pseudo
}

pub fn tcp_checksum_v4(ip_hdr: &[u8], tcp: &[u8]) -> u16 {
    internet_checksum(&v4_pseudo(ip_hdr, tcp.len() as u32, PROTO_TCP), tcp, &[])
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
    fn fragmented_packets_are_rejected() {
        // First fragment (MF): the payload is incomplete, so relaying it would
        // hand a truncated datagram to the peer.
        let mut q = ipv4_udp_dns_query(b"\x03one\x03one\x03one");
        q[6] |= 0x20;
        assert!(Packet::parse(&q).is_none());
        // Later fragments carry no ports at all.
        let mut q = ipv4_udp_dns_query(b"\x03one\x03one\x03one");
        q[7] |= 0x08;
        assert!(Packet::parse(&q).is_none());
        // DF is an ordinary flag and must keep parsing.
        let mut q = ipv4_udp_dns_query(b"\x03one\x03one\x03one");
        q[6] |= 0x40;
        assert!(Packet::parse(&q).is_some());
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
    fn an_unreachable_quotes_the_dropped_datagram() {
        let v4 = build_udp(
            IpKey::V4(u32::from_be_bytes([192, 0, 2, 10])),
            50000,
            IpKey::V4(u32::from_be_bytes([203, 0, 113, 7])),
            443,
            b"quic",
        )
        .expect("v4 packet");
        let parsed = Packet::parse(&v4).expect("parse v4");
        let err = build_unreachable(&parsed).expect("icmp");
        assert_eq!(err[0], 0x45);
        assert_eq!(err[9], 1, "ICMP");
        assert_eq!(&err[12..16], &[203, 0, 113, 7], "sent by the dialed host");
        assert_eq!(&err[16..20], &[192, 0, 2, 10], "addressed to the client");
        assert_eq!(ipv4_checksum(&err[..20]), 0, "the header must verify");
        assert_eq!(&err[20..22], &[3, 3], "destination unreachable, port");
        assert_eq!(&err[28..], &v4[..28], "the header and eight bytes quoted");
        assert_eq!(
            internet_checksum(&[], &err[20..], &[]),
            0,
            "the ICMP checksum must verify"
        );

        let v6 = build_udp(
            IpKey::V6(u128::from(
                "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap(),
            )),
            50000,
            IpKey::V6(u128::from(
                "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap(),
            )),
            443,
            b"h3",
        )
        .expect("v6 packet");
        let parsed = Packet::parse(&v6).expect("parse v6");
        let err = build_unreachable(&parsed).expect("icmpv6");
        assert_eq!(err[0], 0x60);
        assert_eq!(err[6], 58, "ICMPv6");
        assert_eq!(
            u16::from_be_bytes([err[4], err[5]]) as usize,
            err.len() - 40
        );
        assert_eq!(&err[8..24], &v6[24..40], "sent by the dialed host");
        assert_eq!(&err[24..40], &v6[8..24], "addressed to the client");
        assert_eq!(&err[40..42], &[1, 4], "destination unreachable, port");
        assert_eq!(&err[48..], &v6[..48], "the header and eight bytes quoted");
        assert_eq!(
            internet_checksum(
                &v6_pseudo(&err[..40], (err.len() - 40) as u32, 58),
                &err[40..],
                &[]
            ),
            0,
            "the ICMPv6 checksum must verify"
        );
    }

    #[test]
    fn build_udp_round_trips_both_families() {
        let v4 = build_udp(
            IpKey::V4(u32::from_be_bytes([192, 0, 2, 10])),
            443,
            IpKey::V4(u32::from_be_bytes([203, 0, 113, 7])),
            50000,
            b"quic",
        )
        .expect("v4 packet");
        let parsed = Packet::parse(&v4).expect("parse v4");
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.src_ip_text(), "192.0.2.10");
        assert_eq!(parsed.dst_ip_text(), "203.0.113.7");
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 50000);
        assert_eq!(parsed.l4_payload(), b"quic");
        assert_eq!(
            internet_checksum(&v4_pseudo(&v4[..20], 12, PROTO_UDP), &v4[20..], &[]),
            0,
            "the UDP checksum must verify"
        );

        let v6 = build_udp(
            IpKey::V6(u128::from(
                "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap(),
            )),
            443,
            IpKey::V6(u128::from(
                "2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap(),
            )),
            444,
            b"h3",
        )
        .expect("v6 packet");
        let parsed = Packet::parse(&v6).expect("parse v6");
        assert_eq!(parsed.version, 6);
        assert_eq!(parsed.src_ip_text(), "2001:db8::1");
        assert_eq!(parsed.dst_ip_text(), "2001:db8::2");
        assert_eq!(parsed.src_port, 443);
        assert_eq!(parsed.dst_port, 444);
        assert_eq!(parsed.l4_payload(), b"h3");
        assert_eq!(
            internet_checksum(
                &v6_pseudo(&v6[..40], (v6.len() - 40) as u32, PROTO_UDP),
                &v6[40..],
                &[]
            ),
            0,
            "the UDP checksum must verify"
        );

        // A four-tuple cannot cross address families.
        assert!(build_udp(IpKey::V4(1), 1, IpKey::V6(1), 2, b"x").is_none());
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
