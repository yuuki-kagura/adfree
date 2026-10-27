//! Minimal SOCKS5 client handshake (RFC 1928, plus RFC 1929 credentials).
//!
//! The tunnel's forwarder thread owns every flow descriptor, so this module
//! never makes a syscall: the caller writes [`Socks5Handshake::take_output`]
//! and feeds socket reads back through [`Socks5Handshake::on_bytes`]. A flow's
//! application bytes stay queued until the handshake completes, so a SOCKS
//! reply can never be mistaken for origin data.

use crate::packet::IpKey;

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME: u8 = 0x02;
const COMMAND_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// A reply is at most a header, a 255-byte domain and a port. Anything past
/// this is not a SOCKS5 reply and must not grow the queue.
const MAX_REPLY_BYTES: usize = 512;

/// The SOCKS5 proxy a TCP flow must be sent through.
#[derive(Clone, Debug)]
pub struct ProxyEndpoint {
    pub addr: IpKey,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl ProxyEndpoint {
    /// RFC 1929 credentials are sent only when both halves are present.
    pub fn credentials(&self) -> Option<(String, String)> {
        if self.username.is_empty() || self.password.is_empty() {
            None
        } else {
            Some((self.username.clone(), self.password.clone()))
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Method,
    Auth,
    Reply,
    Done,
    Failed,
}

/// One in-flight SOCKS5 negotiation.
pub struct Socks5Handshake {
    dest: IpKey,
    dest_port: u16,
    auth: Option<(String, String)>,
    phase: Phase,
    /// Handshake bytes the proxy has not accepted yet.
    out: Vec<u8>,
    /// Proxy bytes not yet consumed by the current phase.
    rx: Vec<u8>,
}

impl Socks5Handshake {
    pub fn new(
        dest: IpKey,
        dest_port: u16,
        auth: Option<(String, String)>,
    ) -> Result<Self, &'static str> {
        if let Some((user, pass)) = &auth {
            if user.len() > 255 || pass.len() > 255 {
                return Err("proxy credentials are longer than 255 bytes");
            }
        }
        let mut out = Vec::with_capacity(8);
        out.push(VERSION);
        if auth.is_some() {
            out.push(2);
            out.push(METHOD_NO_AUTH);
            out.push(METHOD_USERNAME);
        } else {
            out.push(1);
            out.push(METHOD_NO_AUTH);
        }
        Ok(Self {
            dest,
            dest_port,
            auth,
            phase: Phase::Method,
            out,
            rx: Vec::new(),
        })
    }

    /// True when the caller has handshake bytes to write to the proxy.
    pub fn wants_write(&self) -> bool {
        !self.out.is_empty()
    }

    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done
    }

    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Restores the unwritten tail of a short write, ahead of anything queued
    /// while the write was in progress.
    pub fn requeue_output(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut merged = Vec::with_capacity(bytes.len() + self.out.len());
        merged.extend_from_slice(bytes);
        merged.extend_from_slice(&self.out);
        self.out = merged;
    }

    /// Consumes proxy bytes. Returns whatever followed the final reply (origin
    /// data coalesced into the same read), or the reason the flow must die.
    pub fn on_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.phase == Phase::Failed {
            return Err("proxy handshake already failed");
        }
        if self.phase == Phase::Done {
            return Ok(bytes.to_vec());
        }
        self.rx.extend_from_slice(bytes);
        if self.rx.len() > MAX_REPLY_BYTES {
            self.phase = Phase::Failed;
            return Err("proxy reply is too long");
        }
        loop {
            match self.phase {
                Phase::Method => {
                    if self.rx.len() < 2 {
                        return Ok(Vec::new());
                    }
                    if self.rx[0] != VERSION {
                        self.phase = Phase::Failed;
                        return Err("proxy is not speaking SOCKS5");
                    }
                    let method = self.rx[1];
                    self.rx.drain(..2);
                    match method {
                        METHOD_NO_AUTH => {
                            self.queue_connect();
                            self.phase = Phase::Reply;
                        }
                        METHOD_USERNAME if self.auth.is_some() => {
                            self.queue_auth();
                            self.phase = Phase::Auth;
                        }
                        0xff => {
                            self.phase = Phase::Failed;
                            return Err("proxy accepted none of the offered auth methods");
                        }
                        _ => {
                            self.phase = Phase::Failed;
                            return Err("proxy chose an unsupported auth method");
                        }
                    }
                }
                Phase::Auth => {
                    if self.rx.len() < 2 {
                        return Ok(Vec::new());
                    }
                    let status = self.rx[1];
                    self.rx.drain(..2);
                    if status != 0 {
                        self.phase = Phase::Failed;
                        return Err("proxy rejected the credentials");
                    }
                    self.queue_connect();
                    self.phase = Phase::Reply;
                }
                Phase::Reply => {
                    if self.rx.len() < 4 {
                        return Ok(Vec::new());
                    }
                    if self.rx[0] != VERSION {
                        self.phase = Phase::Failed;
                        return Err("proxy replied with a malformed status");
                    }
                    let rep = self.rx[1];
                    let atyp = self.rx[3];
                    let addr_len = match atyp {
                        ATYP_IPV4 => 4,
                        ATYP_IPV6 => 16,
                        ATYP_DOMAIN => {
                            if self.rx.len() < 5 {
                                return Ok(Vec::new());
                            }
                            self.rx[4] as usize
                        }
                        _ => {
                            self.phase = Phase::Failed;
                            return Err("proxy replied with an unknown address type");
                        }
                    };
                    let total = 4 + addr_len + if atyp == ATYP_DOMAIN { 1 } else { 0 } + 2;
                    if self.rx.len() < total {
                        return Ok(Vec::new());
                    }
                    if rep != 0 {
                        self.phase = Phase::Failed;
                        return Err(reply_reason(rep));
                    }
                    self.rx.drain(..total);
                    self.phase = Phase::Done;
                    return Ok(std::mem::take(&mut self.rx));
                }
                Phase::Done => return Ok(std::mem::take(&mut self.rx)),
                Phase::Failed => return Err("proxy handshake failed"),
            }
        }
    }

    fn queue_auth(&mut self) {
        let Some((user, pass)) = &self.auth else {
            return;
        };
        self.out.push(0x01);
        self.out.push(user.len() as u8);
        self.out.extend_from_slice(user.as_bytes());
        self.out.push(pass.len() as u8);
        self.out.extend_from_slice(pass.as_bytes());
    }

    fn queue_connect(&mut self) {
        self.out.push(VERSION);
        self.out.push(COMMAND_CONNECT);
        self.out.push(0);
        match self.dest {
            IpKey::V4(v) => {
                self.out.push(ATYP_IPV4);
                self.out.extend_from_slice(&v.to_be_bytes());
            }
            IpKey::V6(v) => {
                self.out.push(ATYP_IPV6);
                self.out.extend_from_slice(&v.to_be_bytes());
            }
        }
        self.out.extend_from_slice(&self.dest_port.to_be_bytes());
    }
}

fn reply_reason(rep: u8) -> &'static str {
    match rep {
        1 => "proxy failed to connect to the destination",
        2 => "proxy policy forbids the destination",
        3 => "proxy reports the network unreachable",
        4 => "proxy reports the host unreachable",
        5 => "proxy reports the connection refused",
        6 => "proxy reports the TTL expired",
        7 => "proxy does not support CONNECT",
        8 => "proxy does not support the destination address type",
        _ => "proxy refused the connection",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest() -> IpKey {
        // 93.184.216.34
        IpKey::V4(0x5db8_d822)
    }

    fn connect_request() -> Vec<u8> {
        vec![5, 1, 0, 1, 93, 184, 216, 34, 0x01, 0xbb]
    }

    fn success_reply() -> Vec<u8> {
        vec![5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34]
    }

    #[test]
    fn no_auth_negotiation_sends_greeting_then_connect() {
        let mut hs = Socks5Handshake::new(dest(), 443, None).expect("handshake");
        assert_eq!(hs.take_output(), vec![5, 1, 0]);

        assert_eq!(hs.on_bytes(&[5, 0]).expect("method"), Vec::<u8>::new());
        assert_eq!(hs.take_output(), connect_request());
        assert!(!hs.is_done());

        assert_eq!(
            hs.on_bytes(&success_reply()).expect("reply"),
            Vec::<u8>::new()
        );
        assert!(hs.is_done());
    }

    #[test]
    fn credentials_go_through_rfc1929() {
        let auth = Some(("user".to_string(), "pass".to_string()));
        let mut hs = Socks5Handshake::new(dest(), 443, auth).expect("handshake");
        assert_eq!(hs.take_output(), vec![5, 2, 0, 2]);

        hs.on_bytes(&[5, 2]).expect("method");
        assert_eq!(
            hs.take_output(),
            vec![1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's']
        );

        hs.on_bytes(&[1, 0]).expect("auth");
        assert_eq!(hs.take_output(), connect_request());
    }

    #[test]
    fn a_rejected_destination_names_the_reason() {
        let mut hs = Socks5Handshake::new(dest(), 443, None).expect("handshake");
        hs.on_bytes(&[5, 0]).expect("method");
        let mut reply = success_reply();
        reply[1] = 5;
        assert_eq!(
            hs.on_bytes(&reply).expect_err("refusal"),
            "proxy reports the connection refused"
        );
    }

    #[test]
    fn a_reply_split_across_reads_waits_for_the_rest() {
        let mut hs = Socks5Handshake::new(dest(), 443, None).expect("handshake");
        hs.on_bytes(&[5, 0]).expect("method");
        hs.take_output();

        assert!(hs.on_bytes(&[5, 0, 0]).expect("partial").is_empty());
        assert!(!hs.is_done());
        assert!(hs.on_bytes(&[1, 10, 0]).expect("partial").is_empty());
        assert!(!hs.is_done());
        assert!(hs.on_bytes(&[0, 1, 0x12, 0x34]).expect("tail").is_empty());
        assert!(hs.is_done());
    }

    #[test]
    fn origin_bytes_coalesced_with_the_reply_are_returned() {
        let mut hs = Socks5Handshake::new(dest(), 443, None).expect("handshake");
        hs.on_bytes(&[5, 0]).expect("method");
        hs.take_output();

        let mut reply = success_reply();
        reply.extend_from_slice(b"HTTP/1.1");
        assert_eq!(hs.on_bytes(&reply).expect("reply"), b"HTTP/1.1".to_vec());
        assert!(hs.is_done());
    }

    #[test]
    fn ipv6_destinations_use_the_16_byte_form() {
        let v6 = IpKey::V6(0x2001_0db8_0000_0000_0000_0000_0000_0001);
        let mut hs = Socks5Handshake::new(v6, 80, None).expect("handshake");
        hs.take_output();
        hs.on_bytes(&[5, 0]).expect("method");
        let request = hs.take_output();
        assert_eq!(&request[..4], &[5, 1, 0, 4]);
        assert_eq!(
            &request[4..20],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(&request[20..], &[0x00, 0x50]);
    }

    #[test]
    fn a_proxy_that_offers_no_supported_method_fails() {
        let mut hs = Socks5Handshake::new(dest(), 443, None).expect("handshake");
        assert!(hs.on_bytes(&[5, 0xff]).is_err());
        assert!(hs.on_bytes(&[5, 0]).is_err());
    }

    #[test]
    fn oversized_credentials_are_refused_before_any_byte_is_sent() {
        let auth = Some(("u".repeat(256), "p".to_string()));
        assert!(Socks5Handshake::new(dest(), 443, auth).is_err());
    }
}
