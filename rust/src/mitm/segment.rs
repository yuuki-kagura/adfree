//! TCP segment builders for the relay.
//!
//! Once we answer a client's SYN ourselves, every byte we send back must be a
//! well-formed TCP segment: correct sequence/acknowledgement numbers, data
//! offset, and flags. Getting ACK wrong is the classic way to make a client
//! stall forever, so each builder is exercised by a test that reads the segment
//! back through the packet parser.

use crate::packet::{self, Packet, ACK, FIN, PSH, RST, SYN};

/// Finalises a segment: length fields, IPv4 header checksum, then the TCP
/// checksum over the real pseudo header.
///
/// Both checksum fields must read zero while they are being computed — the
/// buffers we build start as a copy of the client's packet, so the stale
/// values would otherwise be folded into the result and every segment would be
/// discarded by the receiving stack.
fn finish(pkt: &Packet<'_>, out: &mut [u8]) {
    let l4 = pkt.ip_hdr_len;
    let total = out.len();
    if pkt.version == 4 {
        out[2] = (total >> 8) as u8;
        out[3] = (total & 0xff) as u8;
        packet::fix_ipv4_checksum(out);
    } else {
        out[4] = ((total - 40) >> 8) as u8;
        out[5] = ((total - 40) & 0xff) as u8;
    }
    out[l4 + 16..l4 + 20].copy_from_slice(&[0, 0, 0, 0]);
    let checksum = {
        let (ip, tcp) = out.split_at(l4);
        let tcp = &tcp[..total - l4];
        if pkt.version == 4 {
            packet::tcp_checksum_v4(ip, tcp)
        } else {
            packet::tcp_checksum_v6(ip, tcp)
        }
    };
    out[l4 + 16..l4 + 18].copy_from_slice(&checksum.to_be_bytes());
}

/// Builds an ACK (or SYN-ACK) for `pkt` with explicit seq/ack.
pub fn build_ack(pkt: &Packet<'_>, seq: u32, ack: u32, syn: bool) -> Option<Vec<u8>> {
    let mut out = pkt.raw[..pkt.total_len.min(pkt.raw.len())].to_vec();
    let l4 = pkt.ip_hdr_len;

    if pkt.version == 4 {
        for i in 12..16 {
            out.swap(i, i + 4);
        }
        // A packet that arrived as UDP (a DNS flow, say) has no TCP flags.
        if pkt.proto != packet::PROTO_TCP {
            out[9] = packet::PROTO_TCP;
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
    out[l4 + 13] = if syn { ACK | SYN } else { ACK };
    out[l4 + 14] = 0xff; // window
    out[l4 + 15] = 0xff;
    let total = l4 + 20;
    out.truncate(total);

    finish(pkt, &mut out);
    Some(out)
}

/// Builds a data segment carrying `payload` for the client.
pub fn build_data_segment(pkt: &Packet<'_>, seq: u32, ack: u32, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() {
        return None;
    }
    let ack_seg = build_ack(pkt, seq, ack, false)?;
    let mut out = ack_seg;
    let l4 = pkt.ip_hdr_len;
    out[l4 + 13] = ACK | PSH;
    out.extend_from_slice(payload);
    finish(pkt, &mut out);
    Some(out)
}

/// Builds a FIN+ACK carrying no payload.
pub fn build_fin(pkt: &Packet<'_>, seq: u32, ack: u32) -> Option<Vec<u8>> {
    let mut out = build_ack(pkt, seq, ack, false)?;
    let l4 = pkt.ip_hdr_len;
    out[l4 + 13] = ACK | FIN;
    finish(pkt, &mut out);
    Some(out)
}

/// Builds a RST for a flow (used when we bail out of a relay).
pub fn build_rst(pkt: &Packet<'_>, seq: u32) -> Option<Vec<u8>> {
    let mut out = build_ack(pkt, seq, 0, false)?;
    let l4 = pkt.ip_hdr_len;
    out[l4 + 13] = RST;
    finish(pkt, &mut out);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn(seq: u32) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x45, 0x00, 0x00, 40, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0]);
        p.extend_from_slice(&[10, 111, 42, 1]);
        p.extend_from_slice(&[142, 250, 185, 194]);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        packet::fix_ipv4_checksum(&mut p);
        p
    }

    #[test]
    fn syn_ack_is_a_valid_tcp_reply() {
        let raw = syn(1000);
        let pkt = Packet::parse(&raw).expect("parse");
        let seg = build_ack(&pkt, 5000, 1001, true).expect("syn ack");
        let rp = Packet::parse(&seg).expect("parse reply");
        assert!(rp.is_syn && rp.is_ack);
        assert_eq!(rp.seq, 5000);
        assert_eq!(rp.ack_seq, 1001);
        assert_eq!(rp.src_ip_text(), "142.250.185.194");
        assert_eq!(rp.dst_ip_text(), "10.111.42.1");
        assert_eq!(rp.total_len, 40);
    }

    #[test]
    fn data_segment_carries_the_payload() {
        let raw = syn(1000);
        let pkt = Packet::parse(&raw).expect("parse");
        let payload = b"HTTP/1.1 200 OK\r\n\r\n";
        let seg = build_data_segment(&pkt, 5000, 1001, payload).expect("segment");
        let rp = Packet::parse(&seg).expect("parse reply");
        assert_eq!(rp.l4_payload(), payload);
        assert!(rp.is_ack && !rp.is_syn);
        // The IP total length must cover the payload.
        assert_eq!(rp.total_len, 40 + payload.len());
        assert_eq!(rp.seq, 5000);
    }

    #[test]
    fn empty_payload_is_rejected() {
        let raw = syn(1000);
        let pkt = Packet::parse(&raw).expect("parse");
        assert!(build_data_segment(&pkt, 5000, 1001, &[]).is_none());
    }

    #[test]
    fn fin_and_rst_are_well_formed() {
        let raw = syn(1000);
        let pkt = Packet::parse(&raw).expect("parse");
        for (seg, want_fin, want_rst) in [
            (build_fin(&pkt, 5000, 1001).expect("fin"), true, false),
            (build_rst(&pkt, 5000).expect("rst"), false, true),
        ] {
            let rp = Packet::parse(&seg).expect("parse");
            assert_eq!(rp.is_fin, want_fin);
            assert_eq!(rp.is_rst, want_rst);
            assert!(rp.is_ack || want_rst);
            assert!(rp.l4_payload().is_empty());
        }
    }

    #[test]
    fn every_v4_segment_verifies_both_checksums() {
        // The receiving stack validates these: a stale or zero checksum means
        // the segment is discarded before the socket ever sees a byte.
        let raw = syn(1000);
        let pkt = Packet::parse(&raw).expect("parse");
        let segs = [
            build_ack(&pkt, 5000, 1001, true).expect("ack"),
            build_data_segment(&pkt, 5000, 1001, b"payload").expect("data"),
            build_fin(&pkt, 5000, 1001).expect("fin"),
            build_rst(&pkt, 5000).expect("rst"),
        ];
        for seg in &segs {
            let rp = Packet::parse(seg).expect("parse");
            let l4 = rp.ip_hdr_len;
            assert_eq!(packet::ipv4_checksum(&seg[..l4]), 0, "ip header checksum");
            assert_eq!(
                packet::tcp_checksum_v4(&seg[..l4], &seg[l4..]),
                0,
                "tcp checksum"
            );
        }
    }

    #[test]
    fn ipv6_segments_carry_a_checksum() {
        // A minimal IPv6/TCP packet: 40 byte header + 20 byte TCP.
        let mut p = Vec::new();
        p.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        p.extend_from_slice(&20u16.to_be_bytes());
        p.extend_from_slice(&[6, 64]);
        let src: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        let pkt = Packet::parse(&p).expect("parse v6");
        let seg = build_data_segment(&pkt, 7000, 1001, b"hi").expect("segment");
        let rp = Packet::parse(&seg).expect("parse reply");
        assert_eq!(rp.l4_payload(), b"hi");
        // A zero TCP checksum is illegal on IPv6.
        let checksum = u16::from_be_bytes([seg[rp.ip_hdr_len + 16], seg[rp.ip_hdr_len + 17]]);
        assert_ne!(checksum, 0, "IPv6 TCP checksum must be non-zero");
    }
}
