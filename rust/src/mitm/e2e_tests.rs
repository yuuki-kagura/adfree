//! Engine end-to-end test: synthetic TCP packets → `Core::handle_packet` →
//! real TLS handshake → real HTTP → injected cosmetic payload.
//!
//! Nothing in the middle is mocked. The client side is a hand-rolled TCP stack
//! driving rustls; the origin is a loopback rustls server; between them run the
//! real relay, the MITM splice, the injector and the local script endpoints.
//! This is the only test that would catch a break in how the pieces line up —
//! a wrong sequence number, a handshake byte stuck behind the window, an
//! injection that never reaches the client.

use crate::engine::{Config, Core, StealthConfig};
use crate::filter::{FilterListInfo, ListFormat};
use crate::mitm::ca::CertificateAuthority;
use crate::mitm::proxy::local_asset;
use crate::mitm::script::UserScript;
use crate::mitm::tls;
use crate::packet::{self, Packet, ACK, PSH, SYN};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The "device" address synthetic client packets come from.
const CLIENT_IP: [u8; 4] = [10, 0, 2, 15];
/// The origin's address; loopback, so the relay's connect() finds it.
const ORIGIN_IP: [u8; 4] = [127, 0, 0, 1];
const CLIENT_PORT: u16 = 40_000;
/// The client's advertised receive window: large enough that every ACK funds
/// the next burst.
const WINDOW: u16 = 0xffff;
/// Payload bytes of one segment towards the origin.
const MSS: usize = 1460;

struct AllowAll;

impl crate::api::SocketProtector for AllowAll {
    fn protect(&self, _fd: i32) -> bool {
        true
    }
}

/// Builds one IPv4+TCP packet from the "device" to `dst`.
fn tcp_packet(
    dst: [u8; 4],
    flags: u8,
    seq: u32,
    ack: u32,
    dst_port: u16,
    payload: &[u8],
    options: &[u8],
) -> Vec<u8> {
    let tcp_hdr = 20 + options.len();
    let total = 20 + tcp_hdr + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 6, 0x00, 0x00]);
    p.extend_from_slice(&CLIENT_IP);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&CLIENT_PORT.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ack.to_be_bytes());
    p.push(((tcp_hdr / 4) as u8) << 4);
    p.push(flags);
    p.extend_from_slice(&WINDOW.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // checksum, urgent
    p.extend_from_slice(options);
    p.extend_from_slice(payload);
    crate::packet::fix_ipv4_checksum(&mut p);
    let checksum = packet::tcp_checksum_v4(&p[..20], &p[20..]);
    p[36] = (checksum >> 8) as u8;
    p[37] = checksum as u8;
    p
}

/// A TCP client that talks to the engine through `handle_packet` and the
/// forwarder pump, exactly like the device's stack would.
struct Client {
    core: Arc<Core>,
    /// Where the synthetic packets are addressed.
    dst_ip: [u8; 4],
    dst_port: u16,
    /// Next byte we send.
    seq: u32,
    /// Next byte we expect.
    their_seq: u32,
    /// Out-of-order payloads waiting for their turn.
    pending: BTreeMap<u32, Vec<u8>>,
    /// Received bytes not yet consumed by the caller.
    buf: Vec<u8>,
}

impl Client {
    fn connect(core: Arc<Core>, dst_port: u16) -> Client {
        Client::connect_to(core, ORIGIN_IP, dst_port)
    }

    fn connect_to(core: Arc<Core>, dst_ip: [u8; 4], dst_port: u16) -> Client {
        let mut c = Client {
            core,
            dst_ip,
            dst_port,
            seq: 1000,
            their_seq: 0,
            pending: BTreeMap::new(),
            buf: Vec::new(),
        };
        // MSS option so the relay's segmentation matches a real client's.
        let syn = tcp_packet(c.dst_ip, SYN, c.seq, 0, dst_port, &[], &[2, 4, 0x05, 0xb4]);
        let out = c.core.handle_packet(&syn);
        let syn_ack = out
            .iter()
            .find_map(|raw| Packet::parse(raw))
            .filter(|p| p.is_syn && p.is_ack)
            .expect("the engine must answer the SYN");
        c.their_seq = syn_ack.seq.wrapping_add(1);
        c.seq = c.seq.wrapping_add(1);
        let ack = tcp_packet(c.dst_ip, ACK, c.seq, c.their_seq, dst_port, &[], &[]);
        let out = c.core.handle_packet(&ack);
        c.absorb(out);
        // The upstream half is built by the setup worker on a device; the
        // tests have no threads, so the pump that follows every exchange is
        // asked to do it before any bytes are sent.
        c.pump(0);
        c
    }

    /// Feeds `data` as segments, exactly what a socket write produces.
    fn send(&mut self, data: &[u8]) {
        for chunk in data.chunks(MSS) {
            let pkt = tcp_packet(
                self.dst_ip,
                ACK | PSH,
                self.seq,
                self.their_seq,
                self.dst_port,
                chunk,
                &[],
            );
            self.seq = self.seq.wrapping_add(chunk.len() as u32);
            let out = self.core.handle_packet(&pkt);
            self.absorb(out);
        }
    }

    /// A bare ACK: acknowledges everything received and funds the next burst.
    fn ack(&mut self) {
        let pkt = tcp_packet(
            self.dst_ip,
            ACK,
            self.seq,
            self.their_seq,
            self.dst_port,
            &[],
            &[],
        );
        let out = self.core.handle_packet(&pkt);
        self.absorb(out);
    }

    /// One pass of the forwarder loop plus the packets it wrote to the tun.
    fn pump(&mut self, ms: i32) {
        self.core.pump_once(ms);
        let out = self.core.take_outbox();
        self.absorb(out);
    }

    fn absorb(&mut self, packets: Vec<Vec<u8>>) {
        for raw in packets {
            let Some(p) = Packet::parse(&raw) else {
                continue;
            };
            if p.src_port != self.dst_port || p.dst_port != CLIENT_PORT {
                continue;
            }
            assert!(!p.is_rst, "the engine reset the flow");
            let payload = p.l4_payload();
            if payload.is_empty() {
                continue;
            }
            self.pending.insert(p.seq, payload.to_vec());
            while let Some((&seq, _)) = self.pending.iter().next() {
                if seq != self.their_seq {
                    break;
                }
                let (_, data) = self.pending.pop_first().expect("just peeked");
                self.their_seq = self.their_seq.wrapping_add(data.len() as u32);
                self.buf.extend_from_slice(&data);
            }
        }
    }

    /// Bytes that arrived, pumping until there are some or `timeout` passes.
    fn read_some(&mut self, timeout: Duration) -> Vec<u8> {
        let deadline = Instant::now() + timeout;
        loop {
            if !self.buf.is_empty() {
                return std::mem::take(&mut self.buf);
            }
            if Instant::now() > deadline {
                return Vec::new();
            }
            self.ack();
            self.pump(20);
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Best-effort close: FIN towards the origin, so its thread can finish.
    fn close(&mut self) {
        let fin = tcp_packet(
            self.dst_ip,
            ACK | 0x01,
            self.seq,
            self.their_seq,
            self.dst_port,
            &[],
            &[],
        );
        self.seq = self.seq.wrapping_add(1);
        let out = self.core.handle_packet(&fin);
        self.absorb(out);
    }
}

/// How the origin frames and encodes the page it serves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OriginBody {
    /// Plain HTML with a `content-length`.
    Plain,
    /// gzip-compressed HTML with a `content-length`.
    Gzip,
    /// The same HTML cut into HTTP chunks.
    Chunked,
    /// gzip-compressed HTML cut into HTTP chunks — what news.ycombinator.com
    /// and many other origins serve.
    ChunkedGzip,
    /// Chunked and *declared* gzip, but the body is not gzip at all: the proxy
    /// cannot decode it and has to hand it over untouched.
    ChunkedBadGzip,
}

/// A loopback HTTPS origin serving `html` for `GET /`.
struct Origin {
    port: u16,
    ca_der: Vec<u8>,
    /// Every request head the origin saw, in order.
    requests: Arc<std::sync::Mutex<Vec<String>>>,
}

fn start_origin(html: &'static str) -> Origin {
    start_origin_mode(html, OriginBody::Plain)
}

fn start_origin_mode(html: &'static str, mode: OriginBody) -> Origin {
    let ca = CertificateAuthority::generate().expect("origin ca");
    let issued = ca.issue("shop.test").expect("origin leaf");
    let chain: Vec<CertificateDer<'static>> = ca
        .chain_for(&issued)
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.key.clone()));
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .expect("origin server config");
    cfg.alpn_protocols = vec![tls::ALPN_H1.to_vec()];
    let cfg = Arc::new(cfg);

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind origin");
    let port = listener.local_addr().expect("addr").port();
    let requests: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return;
        };
        let conn = ServerConnection::new(cfg).expect("origin connection");
        let mut tls = rustls::StreamOwned::new(conn, stream);
        let mut buf = [0u8; 8192];
        loop {
            // Read one full request head.
            let mut request = Vec::new();
            loop {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let line = String::from_utf8_lossy(&request);
            seen.lock().expect("requests").push(line.to_string());
            // A subresource the lists may want to rewrite: text, but not HTML,
            // so it takes a different road through the rewriter. A HEAD asks
            // for the head alone, and a real origin sends no body with it; the
            // `-gz` path arrives compressed, which is how Chrome usually gets
            // its scripts.
            let response: Vec<u8> = if line.starts_with("GET /ad.js ")
                || line.starts_with("HEAD /ad.js ")
            {
                let body = if line.starts_with("HEAD") { "" } else { SCRIPT };
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\
                     Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                    SCRIPT.len()
                )
                .into_bytes()
            } else if line.starts_with("GET /ad-gz.js ") {
                let gz = crate::mitm::http::gzip_encode(SCRIPT.as_bytes()).expect("gzip");
                let mut out = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\
                     Content-Encoding: gzip\r\nContent-Length: {}\r\n\
                     Connection: keep-alive\r\n\r\n",
                    gz.len()
                )
                .into_bytes();
                out.extend_from_slice(&gz);
                out
            } else if line.starts_with("GET /go ") {
                // A redirect a `$removeheader=location` rule is about to
                // disarm: the client must see it without the target.
                b"HTTP/1.1 302 Found\r\nLocation: https://track.test/next\r\n\
                  Content-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                    .to_vec()
            } else if line.starts_with("GET /cookies ")
                || line.starts_with("HEAD /cookies ")
                || line.starts_with("GET /cookies?")
            {
                // The cookies a `$cookie` rule may take off both halves of the
                // exchange: the request carries some, the answer sets some. The
                // `?` form is the same resource with a query the stealth edits
                // are asked to keep or drop.
                let body = if line.starts_with("HEAD") { "" } else { "ok" };
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                     Set-Cookie: dropme=5; Path=/\r\nSet-Cookie: keepme=3; Path=/\r\n\
                     Set-Cookie: other=5; Path=/\r\n\
                     Content-Length: 2\r\nConnection: keep-alive\r\n\r\n{body}"
                )
                .into_bytes()
            } else if line.starts_with("GET /etag ") {
                // A cached resource: the answer carries the tag and a
                // revalidation asks with it, which is the pair the stealth
                // switch separates.
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                  ETag: \"abc123\"\r\nContent-Length: 2\r\n\
                  Connection: keep-alive\r\n\r\nok"
                    .to_vec()
            } else if line.starts_with("GET /jsonprune ") || line.starts_with("POST /jsonprune ") {
                // A JSON API answer a `$jsonprune` rule takes items out of.
                let body = r#"{"ads": [1, 2], "keep": 3}"#;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes()
            } else if line.starts_with("GET /hls ") {
                // An HLS playlist a `$hls` rule takes segments out of: the
                // URL-pattern rule removes `01.ts`, the tag rule the segment
                // its `#EXT-X-BYTERANGE` marker covers.
                let body = "#EXTM3U\n#EXTINF:10,\n#EXT-X-BYTERANGE:1000@0\nad.ts\n\
                            #EXTINF:10,\n01.ts\n#EXT-X-ENDLIST\n";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\n\
                     Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes()
            } else if line.starts_with("GET /ech-required ") {
                // What an ECH-required origin sends to a plain connection:
                // a bare 502 with no `Server` header at all (measured on
                // Cloudflare's own ECH-required host).
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\
                  Connection: keep-alive\r\n\r\n"
                    .to_vec()
            } else if line.starts_with("GET /unlucky ") {
                // An ordinary 502, the kind any proxy or downed origin sends:
                // it names itself, so there is nothing to learn from it.
                b"HTTP/1.1 502 Bad Gateway\r\nServer: nginx\r\nContent-Length: 0\r\n\
                  Connection: keep-alive\r\n\r\n"
                    .to_vec()
            } else if line.starts_with("GET /misdirected ") {
                // The same story told by the status: `421 Misdirected
                // Request` is what a server that cannot serve this name says.
                b"HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\n\
                  Connection: keep-alive\r\n\r\n"
                    .to_vec()
            } else if line.starts_with("GET /missing ") {
                // A page that never arrived: a status apart from 200 is not
                // one HTML filtering reads.
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                    html.len(),
                    html
                )
                .into_bytes()
            } else if line.starts_with("GET /pathpage ") {
                // The same page under another path: the `$path` rules have to
                // tell the two apart.
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                     Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                    html.len(),
                    html
                )
                .into_bytes()
            } else if line.starts_with("GET / ") {
                match mode {
                    OriginBody::Plain => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                         Content-Security-Policy: script-src 'none'\r\n\
                         Content-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
                        html.len(),
                        html
                    )
                    .into_bytes(),
                    OriginBody::Gzip => {
                        let gz = crate::mitm::http::gzip_encode(html.as_bytes()).expect("gzip");
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                             Content-Encoding: gzip\r\n\
                             Content-Security-Policy: script-src 'none'\r\n\
                             Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                            gz.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(&gz);
                        out
                    }
                    OriginBody::Chunked => {
                        let mut out = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                             Content-Security-Policy: script-src 'none'\r\n\
                             Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
                            .to_vec();
                        out.extend_from_slice(format!("{:x}\r\n", html.len()).as_bytes());
                        out.extend_from_slice(html.as_bytes());
                        out.extend_from_slice(b"\r\n0\r\n\r\n");
                        out
                    }
                    OriginBody::ChunkedGzip => {
                        let gz = crate::mitm::http::gzip_encode(html.as_bytes()).expect("gzip");
                        let mut out = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                             Content-Encoding: gzip\r\n\
                             Content-Security-Policy: script-src 'none'\r\n\
                             Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
                            .to_vec();
                        out.extend_from_slice(format!("{:x}\r\n", gz.len()).as_bytes());
                        out.extend_from_slice(&gz);
                        out.extend_from_slice(b"\r\n0\r\n\r\n");
                        out
                    }
                    OriginBody::ChunkedBadGzip => {
                        let garbage = b"not gzip at all";
                        let mut out = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                             Content-Encoding: gzip\r\n\
                             Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
                            .to_vec();
                        out.extend_from_slice(format!("{:x}\r\n", garbage.len()).as_bytes());
                        out.extend_from_slice(garbage);
                        out.extend_from_slice(b"\r\n0\r\n\r\n");
                        out
                    }
                }
            } else {
                let body = "not found";
                format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
                    body.len()
                )
                .into_bytes()
            };
            if tls.write_all(&response).is_err() {
                return;
            }
            let _ = tls.flush();
        }
    });

    Origin {
        port,
        ca_der: ca.cert_der(),
        requests,
    }
}

/// The client's TLS half, trusting the MITM CA the engine signs leaves with.
fn client_config(mitm_ca_der: Vec<u8>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(mitm_ca_der))
        .expect("mitm ca as a trust anchor");
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![tls::ALPN_H1.to_vec()];
    Arc::new(cfg)
}

/// Pushes everything rustls wants to send into the packet path.
fn flush_tls(tcp: &mut Client, conn: &mut ClientConnection) {
    let mut wire = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut wire).expect("write_tls") == 0 {
            break;
        }
    }
    if !wire.is_empty() {
        tcp.send(&wire);
    }
}

/// Feeds TCP bytes into rustls and returns the plaintext that came out.
///
/// `process_new_packets` must run between reads: the deframer's buffer is
/// bounded, so shovelling a whole burst in first fails with "message buffer
/// full". Draining plaintext in the same loop also keeps rustls's receive
/// buffer from filling up. The read loop must stop as soon as the slice is
/// exhausted — `read_tls` returning `Ok(0)` is how rustls learns of an EOF.
fn feed_tls(conn: &mut ClientConnection, wire: Vec<u8>) -> Vec<u8> {
    let mut plain = Vec::new();
    let mut rd: &[u8] = &wire;
    while !rd.is_empty() {
        let n = match conn.read_tls(&mut rd) {
            Ok(n) => n,
            Err(e) => panic!("read_tls: {e}\nengine log:\n{}", engine_log()),
        };
        if n == 0 {
            break;
        }
        conn.process_new_packets().expect("process packets");
        let mut buf = [0u8; 64 * 1024];
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => plain.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("plaintext read: {e}\nengine log:\n{}", engine_log()),
            }
        }
    }
    plain
}

/// Everything the engine logged so far; printed when an assertion trips.
fn engine_log() -> String {
    crate::logbuf::take().join("\n")
}

/// Substring search over bytes.
fn contains_bytes(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Drives the handshake until rustls says it is done.
fn handshake(tcp: &mut Client, cfg: Arc<ClientConfig>) -> ClientConnection {
    handshake_with(
        tcp,
        cfg,
        ServerName::try_from("shop.test").expect("server name"),
    )
}

/// Same, for a connection whose name is not a hostname: the injection origin
/// is an address literal, and rustls then puts no SNI on the wire at all.
fn handshake_with(
    tcp: &mut Client,
    cfg: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> ClientConnection {
    let mut conn = ClientConnection::new(cfg, name).expect("client connection");
    let deadline = Instant::now() + Duration::from_secs(15);
    while conn.is_handshaking() {
        assert!(
            Instant::now() < deadline,
            "handshake stuck: {} bytes buffered",
            tcp.buf.len()
        );
        flush_tls(tcp, &mut conn);
        let wire = tcp.read_some(Duration::from_millis(50));
        let _ = feed_tls(&mut conn, wire);
    }
    flush_tls(tcp, &mut conn);
    conn
}

/// True when `raw` holds a complete response (head plus declared body).
fn complete_response(raw: &[u8]) -> bool {
    let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..head_end]).to_lowercase();
    if head
        .lines()
        .any(|l| l.trim() == "transfer-encoding: chunked")
    {
        // No length to count: the terminator is the only end there is.
        return raw[head_end..].ends_with(b"0\r\n\r\n");
    }
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    raw.len() >= head_end + len
}

/// The length a response head declares, to hold against the body it framed.
fn declared_length(head: &str) -> usize {
    head.to_lowercase()
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length:")
                .and_then(|v| v.trim().parse().ok())
        })
        .expect("a length-framed response")
}

/// One HTTP/1.1 round trip through the splice. Returns `(head, body)`.
fn request(tcp: &mut Client, conn: &mut ClientConnection, path: &str) -> (String, Vec<u8>) {
    request_with(tcp, conn, path, "")
}

/// The href of the hiding stylesheet the injector wrote into a page.
fn hide_href(page: &str) -> String {
    let start = page
        .find("/adfree-hide.css")
        .expect("the stylesheet link must be injected");
    let rest = &page[start..];
    let end = rest.find('"').expect("the href must be quoted");
    rest[..end].to_string()
}

/// The nonce the injected tags carry, out of the policy that learned it.
///
/// Also asserts the shape that matters: the policy is still there (that is the
/// point of the rewrite) and it says `'nonce-…'` — the same value every
/// injected tag must carry.
fn nonce_of(head: &str) -> String {
    let lower = head.to_lowercase();
    assert!(
        lower.contains("content-security-policy"),
        "the page's policy must survive the injection: {head}"
    );
    let at = head
        .find("'nonce-")
        .expect("the policy must be taught our nonce")
        + "'nonce-".len();
    let rest = &head[at..];
    let end = rest.find('\'').expect("the nonce must be quoted");
    rest[..end].to_string()
}

/// The page as the client can read it: gunzipped when the head says so.
fn page_text(head: &str, body: &[u8]) -> String {
    if head.to_lowercase().contains("content-encoding: gzip") {
        let decoded = crate::mitm::http::decode_body(body, crate::mitm::http::Encoding::Gzip)
            .expect("the body must decode as gzip");
        String::from_utf8_lossy(&decoded).to_string()
    } else {
        String::from_utf8_lossy(body).to_string()
    }
}

/// Same, with extra request headers (each line already ending in CRLF).
fn request_with(
    tcp: &mut Client,
    conn: &mut ClientConnection,
    path: &str,
    extra: &str,
) -> (String, Vec<u8>) {
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\nConnection: keep-alive\r\n{extra}\r\n");
    send_and_read(tcp, conn, &req.into_bytes())
}

/// A request with a body, the way an API client sends one: the head counts
/// the bytes, and they follow it.
fn post_with(
    tcp: &mut Client,
    conn: &mut ClientConnection,
    path: &str,
    body: &[u8],
    extra: &str,
) -> (String, Vec<u8>) {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: shop.test\r\nConnection: keep-alive\r\n\
         Content-Length: {}\r\n{extra}\r\n",
        body.len()
    );
    let mut req = head.into_bytes();
    req.extend_from_slice(body);
    send_and_read(tcp, conn, &req)
}

/// Writes one raw request and reads one response back.
fn send_and_read(tcp: &mut Client, conn: &mut ClientConnection, req: &[u8]) -> (String, Vec<u8>) {
    conn.writer().write_all(req).expect("write request");
    flush_tls(tcp, conn);

    let mut raw = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if complete_response(&raw) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "response timeout: {} bytes so far",
            raw.len()
        );
        flush_tls(tcp, conn);
        let wire = tcp.read_some(Duration::from_millis(50));
        raw.extend_from_slice(&feed_tls(conn, wire));
    }
    let head_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
    let mut body = raw[head_end..].to_vec();
    // Only one response is in flight at a time; anything after the declared
    // body belongs to the next one (there is none here).
    let declared: usize = head
        .to_lowercase()
        .lines()
        .find_map(|l| {
            l.strip_prefix("content-length:")
                .map(|v| v.trim().to_string())
        })
        .and_then(|v| v.parse().ok())
        .unwrap_or(body.len());
    body.truncate(declared);
    (head, body)
}

/// A HEAD through the splice. The answer is headers only, so this cannot wait
/// for a body: it reads until the head is complete, then listens a little
/// longer to prove nothing follows it.
fn head_request(tcp: &mut Client, conn: &mut ClientConnection, path: &str, extra: &str) -> Vec<u8> {
    let req =
        format!("HEAD {path} HTTP/1.1\r\nHost: shop.test\r\nConnection: keep-alive\r\n{extra}\r\n");
    conn.writer()
        .write_all(req.as_bytes())
        .expect("write request");
    flush_tls(tcp, conn);

    let mut raw = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let wire = tcp.read_some(Duration::from_millis(50));
        raw.extend_from_slice(&feed_tls(conn, wire));
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no head for {path}: {:?}",
            raw.len()
        );
    }
    // Anything arriving after the head would be a body on a HEAD — the one
    // thing a client is not allowed to be sent.
    let quiet = Instant::now() + Duration::from_millis(300);
    while Instant::now() < quiet {
        let wire = tcp.read_some(Duration::from_millis(50));
        raw.extend_from_slice(&feed_tls(conn, wire));
    }
    raw
}

/// The list the engine is given: every cosmetic rule shape in one place.
const LIST: &str = "! Title: e2e cosmetic\n\
                    shop.test##.ad-box\n\
                    shop.test#$#.banner { margin: 0 }\n\
                    shop.test#?#.sponsored:has-text(Sponsored)\n\
                    shop.test#%#//scriptlet('set-constant', 'adBlocked', 'true')\n\
                    shop.test#%#window.__adfree_raw = 1;\n\
                    ##.adsbygoogle\n\
                    ###slot-1\n";

/// The page the origin serves: tokens for generic rules, and a matching
/// element for the procedural one.
const HTML: &str = "<!doctype html><html><head><title>e2e</title></head>\
                    <body><div class=\"ad-box\">ad</div>\
                    <div class=\"adsbygoogle\" id=\"slot-1\">ad</div>\
                    <p class=\"sponsored\">Sponsored content</p></body></html>";

/// The same shapes, plus the exception the engine drops: the page must come
/// out with nothing to hide and nothing to look up, but scriptlets stay.
const ELEMHIDE_LIST: &str = "! Title: e2e elemhide\n\
                             shop.test##.ad-box\n\
                             ##.adsbygoogle\n\
                             shop.test#?#.sponsored:has-text(Sponsored)\n\
                             shop.test#%#//scriptlet('set-constant', 'adBlocked', 'true')\n\
                             @@||shop.test^$elemhide\n";

/// A site-wide unblock: no cosmetic tag may go out at all, not even the
/// runtime — there is nothing for it to find.
const DOCUMENT_LIST: &str = "! Title: e2e document\n\
                             shop.test##.ad-box\n\
                             shop.test#%#//scriptlet('set-constant', 'adBlocked', 'true')\n\
                             @@||shop.test^$document\n";

fn setup_core(origin: &Origin) -> (Arc<Core>, Vec<u8>) {
    setup_core_with_list(origin, "e2e", LIST)
}

fn setup_core_named(origin: &Origin, tag: &str) -> (Arc<Core>, Vec<u8>) {
    setup_core_with_list(origin, tag, LIST)
}

fn setup_core_with_list(origin: &Origin, tag: &str, list: &str) -> (Arc<Core>, Vec<u8>) {
    let core = Arc::new(Core::new());
    core.set_socket_protector(Arc::new(AllowAll));
    core.set_config(Config {
        mitm_enabled: true,
        ..Config::default()
    });
    core.mitm_port
        .store(origin.port, std::sync::atomic::Ordering::SeqCst);

    // The CA the client will trust, and the engine signs leaves with.
    let ca = Arc::new(CertificateAuthority::generate().expect("mitm ca"));
    let ca_der = ca.cert_der();
    core.set_mitm_ca(ca);

    // The origin's CA is the only upstream anchor that matters here.
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(origin.ca_der.clone()))
        .expect("origin ca");
    core.set_upstream_tls_config(tls::UpstreamTls::with_roots(roots));

    // Filter list from disk, exactly like the app ships them.
    let dir = std::env::temp_dir().join("adfree-e2e");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(format!("{tag}-list.txt"));
    std::fs::write(&path, list).expect("write list");
    core.set_lists(
        vec![FilterListInfo {
            id: 1,
            name: "e2e".to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format: ListFormat::Standard,
            category: 0,
            trusted: true,
            rule_count: 0,
            last_error: None,
            dns_only: false,
        }],
        Vec::new(),
    );

    // A user script large enough to force window-limited bursts.
    let body = format!(
        "/* e2e-marker */window.__adfree_e2e=\"{}\";",
        "x".repeat(300_000)
    );
    {
        let mut scripts = core.mitm_scripts.write().unwrap();
        scripts.replace_all(vec![UserScript {
            id: "e2e".to_string(),
            name: "e2e.js".to_string(),
            body,
            enabled: true,
        }]);
        scripts.set_enabled(true);
    }
    (core, ca_der)
}

#[test]
fn cosmetic_filtering_rides_the_packet_path() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core(&origin);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // 1. The user script is served locally: same-origin path, whole body,
    //    delivered in window-sized bursts.
    let (head, body) = request(&mut tcp, &mut conn, "/adfree-user.js");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        body.len() > 300_000,
        "the whole script must arrive, got {} bytes",
        body.len()
    );
    assert!(
        contains_bytes(&body, b"window.__adfree_e2e"),
        "the script body must be the one that was installed"
    );

    // 2. The page comes back with the cosmetic payload and both tags, and a
    //    strict CSP is gone (otherwise the injected scripts never run). The
    //    request negotiates encodings exactly like Chrome does; the origin must
    //    never see brotli/zstd, because the rewriter cannot decode those.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Accept: text/html,application/xhtml+xml\r\n\
         Accept-Encoding: gzip, deflate, br, zstd\r\n",
    );
    let seen = origin.requests.lock().expect("requests");
    let encoding_line = seen
        .last()
        .expect("the page request reached the origin")
        .lines()
        .find(|l| l.to_lowercase().starts_with("accept-encoding:"))
        .expect("the origin saw an accept-encoding header")
        .trim()
        .to_string();
    assert_eq!(
        encoding_line, "Accept-Encoding: gzip, deflate",
        "br/zstd must be dropped before the request goes upstream"
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let nonce = nonce_of(&head);
    assert!(
        head.to_lowercase()
            .contains(&format!("script-src 'none' 'nonce-{nonce}'")),
        "the page's policy must stay, with our nonce added: {head}"
    );
    let page = String::from_utf8_lossy(&body);
    assert!(
        page.contains(&format!("<script nonce=\"{nonce}\">window.__adfree_page=")),
        "payload injected with the nonce: {page}"
    );
    assert!(
        page.contains(&format!(
            "<script nonce=\"{nonce}\" src=\"{}?dmn=shop.test&h=",
            local_asset("/adfree-page.js")
        )),
        "runtime tag injected with the nonce"
    );
    assert!(
        page.contains(&format!(
            "<script nonce=\"{nonce}\" src=\"{}?h=",
            local_asset("/adfree-user.js")
        )),
        "user script tag injected with the nonce"
    );
    let href = hide_href(&page);
    assert!(
        page.contains(&format!(
            "<link rel=\"stylesheet\" id=\"adfree-hide\" href=\"{}\" nonce=\"{nonce}\">",
            local_asset(&href)
        )),
        "the stylesheet link carries the nonce: {page}"
    );
    // Element hiding left the payload: it travels as a stylesheet the browser
    // fetches once per site, and its URL hashes exactly what it serves.
    assert!(
        href.starts_with("/adfree-hide.css?dmn=shop.test&h="),
        "{href}"
    );
    assert!(
        !page.contains("\"hide\""),
        "hiding left the payload: {page}"
    );
    assert!(
        !page.contains("display:none"),
        "no CSS belongs inline any more: {page}"
    );
    // Style action, scriptlet and the hostname rules.
    assert!(page.contains("\".banner\""), "style rule missing: {page}");
    assert!(page.contains("setConstant"), "scriptlet missing: {page}");
    assert!(page.contains("adBlocked"), "scriptlet args missing: {page}");
    assert!(
        page.contains("\"jsrules\":[\"window.__adfree_raw = 1;\"]"),
        "the raw JavaScript rule rides the payload: {page}"
    );
    assert!(page.contains("has-text"), "procedural rule missing: {page}");
    // Generic class/id rules, matched from the HTML the proxy scanned.
    assert!(
        page.contains("\".adsbygoogle\""),
        "class rule missing: {page}"
    );
    assert!(page.contains("\"#slot-1\""), "id rule missing: {page}");
    // The origin's own content survived the rewrite.
    assert!(
        page.contains("Sponsored content"),
        "the page itself is intact"
    );

    // 3. The page runtime is served locally.
    let (head, body) = request(&mut tcp, &mut conn, "/adfree-page.js");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let runtime = String::from_utf8_lossy(&body);
    assert!(
        runtime.contains("window.__adfree_page"),
        "the runtime must consume the inline payload"
    );
    assert!(
        runtime.contains("MutationObserver"),
        "the runtime must watch the DOM"
    );
    assert!(
        runtime.contains("adfree-hide"),
        "the runtime must keep the hiding stylesheet alive"
    );

    // 4. The dynamic lookup answers for tokens the HTML scan never saw.
    let (head, body) = request(
        &mut tcp,
        &mut conn,
        "/adfree-generic.js?c=adsbygoogle%20never-used&i=slot-1",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let json = String::from_utf8_lossy(&body);
    assert!(json.contains("\".adsbygoogle\""), "{json}");
    assert!(json.contains("\"#slot-1\""), "{json}");
    assert!(!json.contains("never-used"), "{json}");

    // 5. The hiding stylesheet the page was told to fetch: cacheable forever,
    //    and the bytes are the ones its URL hashed (so the cached copy can
    //    never be stale).
    let (head, body) = request(&mut tcp, &mut conn, &href);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.contains("Content-Type: text/css"), "{head}");
    assert!(
        head.contains("Cache-Control: max-age=31536000, immutable"),
        "{head}"
    );
    let css = String::from_utf8(body).expect("utf8");
    assert!(css.contains(".ad-box"), "{css}");
    assert_eq!(css, ".ad-box{display:none!important}\n", "{css}");
    let advertised = u64::from_str_radix(href.split("h=").nth(1).expect("hash"), 16).expect("hex");
    assert_eq!(
        advertised,
        super::proxy::content_hash(css.as_bytes()),
        "the URL must hash the bytes that are served"
    );

    tcp.close();
}

/// Cosmetic filtering is a real switch, not a persisted flag with no reader:
/// off ships the page without the hiding stylesheet, the payload or the
/// runtime, while the user's own script keeps its tag.
#[test]
fn turning_cosmetics_off_leaves_the_page_without_them() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core(&origin);
    core.set_config(Config {
        cosmetic_filtering: false,
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request(&mut tcp, &mut conn, "/");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        !page.contains("adfree-hide"),
        "no hiding stylesheet: {page}"
    );
    assert!(!page.contains("adfree-page.js"), "no runtime: {page}");
    assert!(
        !page.contains("window.__adfree_page="),
        "no payload: {page}"
    );
    assert!(
        page.contains("/adfree-user.js"),
        "user scripts are not cosmetic rules: {page}"
    );
    assert!(page.contains("Sponsored content"), "the page is intact");
    tcp.close();
}

/// A generic style injection (`#$#sel { css }`, no domain — how the lists undo
/// a bait hiding) rides the page payload from our own scan: the crate reads
/// these rules as plain hides and drops the action, so nothing else would carry
/// them. Its `#@$#` exception, naming a host, takes the rule back there.
const STYLE_LIST: &str = "! Title: e2e generic style\n\
                          #$#.pub_300x250.text-ad { display: block !important; }\n";
const STYLE_EXCEPTION_LIST: &str = "! Title: e2e generic style exception\n\
                                    #$#.pub_300x250.text-ad { display: block !important; }\n\
                                    shop.test#@$#.pub_300x250.text-ad { display: block !important; }\n";

#[test]
fn generic_style_injections_ride_the_page_payload() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "generic-style", STYLE_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request(&mut tcp, &mut conn, "/");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        page.contains("\".pub_300x250.text-ad\"") && page.contains("display: block !important"),
        "the generic style rule must ride the payload: {page}"
    );
    tcp.close();

    // The same rule, with the host named in an exception: nothing goes out.
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "generic-style-exc", STYLE_EXCEPTION_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request(&mut tcp, &mut conn, "/");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        !page.contains("pub_300x250"),
        "the exception is read on its host: {page}"
    );
    tcp.close();
}

/// An `@@||host^$elemhide` exception is one the engine rejects, so the app
/// reads it out of the list itself: the page gets no hiding stylesheet, no
/// style/procedural/generic payload and an empty lookup, while the scriptlet —
/// `$elemhide` is not `$jsinject` — still goes out.
#[test]
fn an_elemhide_exception_clears_the_page() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "elemhide", ELEMHIDE_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Accept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        !page.contains("adfree-hide"),
        "no hiding stylesheet may be linked: {page}"
    );
    assert!(
        !page.contains("display:none"),
        "no CSS may travel inline instead: {page}"
    );
    assert!(
        page.contains("adfree-page.js"),
        "the runtime tag is still injected: {page}"
    );
    assert!(
        page.contains("\"dynamic\":false"),
        "the lookup must be declared off: {page}"
    );
    for key in ["\"style\"", "\"generic\"", "\"procedural\""] {
        assert!(!page.contains(key), "{key} must be gone: {page}");
    }
    assert!(
        page.contains("setConstant"),
        "`$elemhide` is not `$jsinject`, the scriptlet stays: {page}"
    );
    assert!(
        page.contains("Sponsored content"),
        "the page itself is intact"
    );

    // The lookup endpoint answers empty: `$elemhide` covers generic rules too.
    let (head, body) = request(
        &mut tcp,
        &mut conn,
        "/adfree-generic.js?c=adsbygoogle%20sponsored&i=slot-1",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        String::from_utf8_lossy(&body),
        "[]",
        "generic tokens must come back empty"
    );

    tcp.close();
}

/// `@@||host^$document` unblocks the whole site: no cosmetic tag goes out at
/// all — not even the runtime, which would find nothing — while the user's own
/// script is not the lists' to switch off.
#[test]
fn a_document_exception_takes_every_cosmetic_tag_out() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "document", DOCUMENT_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Accept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = page_text(&head, &body);
    for tag in ["adfree-hide", "adfree-page.js", "window.__adfree_page"] {
        assert!(!page.contains(tag), "{tag} must not be injected: {page}");
    }
    assert!(
        page.contains("adfree-user.js"),
        "the user script still goes out: {page}"
    );
    assert!(
        page.contains("Sponsored content"),
        "the page itself is intact"
    );

    tcp.close();
}

/// The `[$path=…]` bracket: cosmetic rules pinned to one page of a site.
/// The page's own URL decides — the rules must reach the page they name and
/// stay away from every other one, and the per-host stylesheet must never
/// carry them.
const PATH_LIST: &str = "! Title: e2e path\n\
                         [$path=/pathpage]shop.test##.path-only\n\
                         [$path]shop.test##.path-main\n\
                         shop.test##.ad-box\n";

#[test]
fn path_rules_apply_to_their_page_only() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "path", PATH_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // The page the rule names: the selector rides the inline payload, since
    // the stylesheet is asked for by host alone and cannot know the path.
    let (head, body) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        page.contains("\".path-only\""),
        "the path rule must reach its page: {page}"
    );
    assert!(
        !page.contains("\".path-main\""),
        "the main-page rule must stay on the main page: {page}"
    );

    // The host stylesheet carries the host rules only.
    if let Some(start) = page.find("/adfree-hide.css") {
        let rest = &page[start..];
        let end = rest.find('"').expect("the href must be quoted");
        let href = rest[..end].to_string();
        let (_, css_body) = request(&mut tcp, &mut conn, &href);
        let css = String::from_utf8_lossy(&css_body).to_string();
        assert!(
            css.contains(".ad-box"),
            "the host rule is in the stylesheet: {css}"
        );
        assert!(
            !css.contains(".path-only"),
            "a path rule must not travel in the per-host stylesheet: {css}"
        );
    }

    // The main page: its own rule, and not the other page's.
    let (head, body) = request(&mut tcp, &mut conn, "/");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        page.contains("\".path-main\""),
        "the bare `$path` rule is for the main page: {page}"
    );
    assert!(
        !page.contains("\".path-only\""),
        "the /pathpage rule must stay there: {page}"
    );

    tcp.close();
}

/// A page-scoped `#@#` exception: the host stylesheet cannot know which page
/// it is answering for, so the page that carries the exception must receive
/// the remaining hiding selectors inline instead.
const SCOPED_HIDE_EXCEPTION_LIST: &str = "! Title: e2e scoped hide exception\n\
                                         shop.test##.ad-box\n\
                                         shop.test##.adsbygoogle\n\
                                         shop.test#$#.ad-box { color: red }\n\
                                         shop.test#%#//scriptlet('set-constant', 'adblock', 'false')\n\
                                         [$path=/pathpage]shop.test#@#.ad-box\n\
                                         [$path=/pathpage]shop.test#@$#.ad-box { color: red }\n\
                                         [$path=/pathpage]shop.test#@%#//scriptlet('set-constant', 'adblock', 'false')\n";

#[test]
fn a_path_scoped_hide_exception_rides_the_page_payload() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "scoped-hide", SCOPED_HIDE_EXCEPTION_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // The page the exception names: no host stylesheet, and only the
    // selectors that survive the exception in the inline payload.
    let (head, body) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        !page.contains("/adfree-hide.css"),
        "the per-host stylesheet cannot express a page-scoped exception: {page}"
    );
    let payload = page
        .split("window.__adfree_page=")
        .nth(1)
        .expect("the cosmetic payload must stay inline")
        .split(";</script>")
        .next()
        .unwrap();
    assert!(
        payload.contains("\"hide\":"),
        "the surviving hides must travel inline: {payload}"
    );
    assert!(
        payload.contains("\".adsbygoogle\""),
        "the non-excepted hide must stay: {payload}"
    );
    assert!(
        !payload.contains("\"hide\":[\".ad-box\""),
        "the excepted hide must not come back inline: {payload}"
    );
    assert!(
        !payload.contains("\"style\":"),
        "the excepted style rule must not come back: {payload}"
    );
    assert!(
        !payload.contains("\"scriptlets\":"),
        "the excepted scriptlet must not come back: {payload}"
    );
    assert!(
        payload.contains("\"exceptions\":"),
        "the runtime needs the page exceptions for later generic tokens: {payload}"
    );
    assert!(
        payload.contains("\".ad-box\""),
        "the exception itself must reach the runtime: {payload}"
    );

    // Every other page keeps the cacheable stylesheet.
    let (head, body) = request(&mut tcp, &mut conn, "/");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let other = page_text(&head, &body);
    assert!(
        other.contains("/adfree-hide.css"),
        "a page without the exception keeps the stylesheet: {other}"
    );
    let href = hide_href(&other);
    let (_, css_body) = request(&mut tcp, &mut conn, &href);
    let css = String::from_utf8_lossy(&css_body).to_string();
    assert!(css.contains(".ad-box"), "{css}");
    assert!(css.contains(".adsbygoogle"), "{css}");
    assert!(
        other.contains("\"style\":"),
        "another page keeps the host style rule: {other}"
    );
    assert!(
        other.contains("adblock"),
        "another page keeps the host scriptlet: {other}"
    );

    tcp.close();
}

/// The network rules that need a URL: path-scoped blocks, `$redirect` and
/// `$removeparam`. The DNS layer only ever sees a hostname, so these can only
/// fire on the HTTPS path — and the removal names the request kind, because
/// without a type option the modifier only covers documents and frames.
const URL_LIST: &str = "! Title: e2e url rules\n\
                        ||shop.test/ads/tracker.js$script\n\
                        ||shop.test/fake.js$redirect=noopjs\n\
                        ||shop.test/api^$removeparam=secret,xmlhttprequest\n";

/// The same block, but the page holds a `$urlblock`: its own requests are the
/// site's business, not the lists'. AdGuard's coverage is spelled out as
/// blocking, redirects *and* `$removeparam`, so the rule carrying it stands
/// down for such a page as well.
const URLBLOCK_LIST: &str = "! Title: e2e urlblock\n\
                             ||shop.test/ads/tracker.js$script\n\
                             ||shop.test/api^$removeparam=secret,xmlhttprequest\n\
                             @@||shop.test^$urlblock\n";

/// The rules that need a whole URL fire on the HTTPS path: a path-scoped block
/// is answered locally (the origin never sees it), a `$redirect` resource is
/// served in the blocked request's place, and `$removeparam` rewrites the
/// request line the origin receives. All of it over one kept-alive connection,
/// which also proves the locally answered responses frame cleanly.
#[test]
fn url_rules_are_applied_on_the_https_path() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "url", URL_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // 1. A path-scoped block: an empty answer, and nothing left the machine.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/ads/tracker.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 204"), "{head}");
    assert!(body.is_empty(), "{body:?}");
    {
        let seen = origin.requests.lock().expect("requests");
        assert!(
            !seen.iter().any(|r| r.contains("tracker.js")),
            "a blocked URL must not reach the origin: {seen:?}"
        );
    }

    // 2. `$redirect`: the no-op resource is served in its place.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/fake.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.to_lowercase()
            .contains("content-type: application/javascript"),
        "{head}"
    );
    assert_eq!(body, b"(function(){})();", "the registered noop body");

    // 3. `$removeparam`: the request goes out, one parameter lighter than the
    //    page asked for.
    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/api?secret=1&keep=2",
        "Sec-Fetch-Dest: empty\r\nReferer: https://shop.test/\r\n",
    );
    assert!(
        head.starts_with("HTTP/1.1 404"),
        "the origin answers what it has, so the request reached it: {head}"
    );
    let seen = origin.requests.lock().expect("requests");
    let api = seen
        .iter()
        .find(|r| r.contains("/api"))
        .expect("the rewritten request reached the origin");
    assert!(
        api.starts_with("GET /api?keep=2 "),
        "the dropped parameter must be gone: {api:?}"
    );
    drop(seen);

    // 4. The same redirect through a HEAD: the head it would have sent, and
    //    not one byte of body — that is how a connection desyncs.
    let raw = head_request(
        &mut tcp,
        &mut conn,
        "/fake.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://shop.test/\r\n",
    );
    let head = String::from_utf8_lossy(&raw).to_string();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    // The length of the body the GET above received, still declared.
    assert!(
        head.to_lowercase()
            .contains(&format!("content-length: {}", b"(function(){})();".len())),
        "{head}"
    );
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .expect("the head must be complete");
    assert_eq!(raw.len(), end, "a HEAD answer must carry no body: {head}");

    // 5. The same `$removeparam` on a POST: the request carries a body, and
    //    the parameter still goes — a POST is a method the modifier reaches.
    let (head, _) = post_with(
        &mut tcp,
        &mut conn,
        "/api?secret=1&keep=2",
        br#"{"x": 1}"#,
        "Content-Type: application/json\r\nSec-Fetch-Dest: empty\r\n\
         Referer: https://shop.test/\r\n",
    );
    assert!(
        head.starts_with("HTTP/1.1 404"),
        "the origin answers what it has, so the request reached it: {head}"
    );
    let seen = origin.requests.lock().expect("requests");
    let post = seen
        .iter()
        .find(|r| r.starts_with("POST /api"))
        .expect("the POST reached the origin");
    assert!(
        post.starts_with("POST /api?keep=2 "),
        "the dropped parameter must be gone from a POST too: {post:?}"
    );
    drop(seen);

    tcp.close();
}

/// The response-header rules: the policies the answer gains, the headers it
/// loses, and the request-header half of `$removeheader`.
const HEADER_LIST: &str = "! Title: e2e header rules\n\
                           ||shop.test/ad.js$csp=worker-src 'none'\n\
                           ||shop.test/ad.js$permissions=browsing-topics=(),document\n\
                           ||shop.test/ad.js$removeheader=request:accept-language\n\
                           ||shop.test/go$removeheader=location\n";

/// `$csp`, `$permissions` and `$removeheader` shape the exchange itself: the
/// policies are appended to the response head, the named request header never
/// reaches the origin, and a redirect arrives without the target a client
/// would follow. None of it touches the body.
#[test]
fn header_rules_shape_the_https_exchange() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "header", HEADER_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // 1. The request goes out one header lighter, and the response comes back
    //    two policies richer — the values ride the same request.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/ad.js",
        "Sec-Fetch-Dest: document\r\nAccept-Language: en-US\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        body,
        SCRIPT.as_bytes(),
        "the body must come through untouched"
    );
    let lower = head.to_lowercase();
    assert!(
        lower.contains("content-security-policy: worker-src 'none'"),
        "the $csp value must be appended: {head}"
    );
    assert!(
        lower.contains("permissions-policy: browsing-topics=()"),
        "the $permissions value must be appended: {head}"
    );
    assert!(
        lower.contains("content-type: application/javascript"),
        "the origin's own headers stay: {head}"
    );
    {
        let seen = origin.requests.lock().expect("requests");
        let ad = seen.last().expect("the request reached the origin");
        assert!(
            !ad.to_lowercase().contains("accept-language"),
            "the dropped request header must be gone: {ad:?}"
        );
    }

    // 2. `$removeheader=location`: the redirect arrives without its target, so
    //    a client that would have followed it stays where it is.
    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/go",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 302"), "{head}");
    assert!(
        !head.to_lowercase().contains("location:"),
        "the header must be gone: {head}"
    );

    tcp.close();
}

/// The `$cookie` rules: what the request carries and what the answer sets, both
/// trimmed to the same allowlist.
const COOKIE_LIST: &str = "! Title: e2e cookie rules\n\
                           ||shop.test/cookies$cookie=dropme\n\
                           @@||shop.test/cookies$cookie=keepme\n\
                           ||shop.test/cookies$cookie\n";

/// `$cookie` names cookies on both halves of the exchange: the request loses
/// them before it is forwarded, and the response may not set them again. The
/// allowlist protects the cookie it names, on both halves alike.
#[test]
fn cookie_rules_trim_the_https_exchange() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "cookie", COOKIE_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/cookies",
        "Sec-Fetch-Dest: document\r\nCookie: dropme=1; keepme=2; other=5\r\n\
         Referer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ok", "the body is none of the rules' business");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        assert!(
            sent.contains("Cookie: keepme=2"),
            "the allowlisted cookie must still go out: {sent:?}"
        );
        assert!(
            !sent.contains("dropme") && !sent.contains("other"),
            "a dropped cookie must not reach the origin: {sent:?}"
        );
    }
    // The answer sets the same three cookies; the same rules decide. The
    // blocking ones name `dropme` and, with no value, every cookie; the
    // allowlist keeps `keepme` whatever they say.
    let lower = head.to_lowercase();
    assert!(
        lower.contains("set-cookie: keepme=3"),
        "the allowlisted cookie must still be set: {head}"
    );
    assert!(
        !lower.contains("set-cookie: dropme") && !lower.contains("set-cookie: other"),
        "a dropped cookie must not come back in a set-cookie: {head}"
    );

    tcp.close();
}

/// A `$removeparam` rule rewrites a URL the `$cookie` rules read too: the
/// request line that goes out is shorter than the one that was matched, and
/// the cookie plan still has to see the head that actually goes out. The stale
/// length used to slice the buffer past its end — a panic on a real device.
const COOKIE_REWRITE_LIST: &str = "! Title: e2e cookie+removeparam rules\n\
                                   ||shop.test/cookies$cookie=dropme\n\
                                   ||shop.test/cookies$removeparam=gone\n";

/// One request, two rules: `$removeparam` takes the query off the line, and the
/// `$cookie` plan trims the cookies on the head it rewrote — no panic, and the
/// rewrite still reaches the response that request brings back.
#[test]
fn cookie_rules_read_the_head_a_url_rewrite_installed() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "cookie-rewrite", COOKIE_REWRITE_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/cookies?gone=1",
        "Sec-Fetch-Dest: document\r\nCookie: dropme=1; keepme=2\r\n\
         Referer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ok", "the body is none of the rules' business");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        assert!(
            sent.starts_with("GET /cookies HTTP/1.1"),
            "the rewritten target goes out: {sent:?}"
        );
        assert!(
            sent.contains("Cookie: keepme=2") && !sent.contains("dropme"),
            "the cookie plan still trims the rewritten head: {sent:?}"
        );
    }
    let lower = head.to_lowercase();
    assert!(
        lower.contains("set-cookie: keepme=3") && !lower.contains("set-cookie: dropme"),
        "the plan still reaches the answer: {head}"
    );

    tcp.close();
}

/// Stealth mode edits the request and its answer: the tracking parameters go,
/// a cross-site request loses its cookies, the user agent is replaced, and the
/// answer may not set a third-party cookie either.
#[test]
fn stealth_edits_both_halves_of_the_https_exchange() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "stealth", "");
    core.set_config(Config {
        mitm_enabled: true,
        stealth: StealthConfig {
            enabled: true,
            strip_utm: true,
            block_web_rtc: false,
            disguise_user_agent: true,
            block_third_party_cookies: true,
            ..StealthConfig::default()
        },
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/cookies?utm_source=news&fbclid=abc",
        "Sec-Fetch-Dest: document\r\nSec-Fetch-Site: cross-site\r\n\
         Referer: https://other.test/\r\nCookie: sid=1\r\n\
         User-Agent: real-browser\r\nSec-CH-UA: \"Chromium\";v=\"124\"\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ok", "the body must come through untouched");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        assert!(
            sent.starts_with("GET /cookies HTTP/1.1"),
            "the tracking parameters must be gone: {sent:?}"
        );
        assert!(
            !sent.to_lowercase().contains("cookie:"),
            "a cross-site request must not carry cookies: {sent:?}"
        );
        assert!(
            sent.contains(crate::mitm::stealth::DISGUISED_USER_AGENT),
            "the disguised user agent must go out: {sent:?}"
        );
        assert!(
            !sent.to_lowercase().contains("sec-ch-ua"),
            "the client hints must go with the real user agent: {sent:?}"
        );
    }
    assert!(
        !head.to_lowercase().contains("set-cookie:"),
        "a cross-site answer may not set cookies: {head}"
    );

    tcp.close();
}

/// The identifying headers a cross-site request has no business carrying: the
/// bearer token, the referring page, and the entity tag the last answer stored
/// for this client's cache.
#[test]
fn stealth_takes_the_identifying_headers_off_a_cross_site_request() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "stealth-headers", "");
    core.set_config(Config {
        mitm_enabled: true,
        stealth: StealthConfig {
            enabled: true,
            strip_third_party_authorization: true,
            hide_third_party_referer: true,
            strip_etag: true,
            ..StealthConfig::default()
        },
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/etag",
        "Sec-Fetch-Dest: empty\r\nSec-Fetch-Site: cross-site\r\n\
         Authorization: Bearer secret-token\r\n\
         Referer: https://shop.test/page\r\n\
         If-None-Match: \"abc123\"\r\nCookie: sid=1\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ok", "the body is none of the headers' business");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        let lower = sent.to_lowercase();
        assert!(
            !lower.contains("authorization:"),
            "a token must not travel to another site: {sent:?}"
        );
        assert!(
            !lower.contains("referer:"),
            "the referring page must not travel either: {sent:?}"
        );
        assert!(
            !lower.contains("if-none-match"),
            "the stored tag must not be handed back: {sent:?}"
        );
        assert!(
            lower.contains("cookie: sid=1"),
            "the cookie jar is a different switch: {sent:?}"
        );
    }
    assert!(
        !head.to_lowercase().contains("etag:"),
        "and no new tag may be stored for this client: {head}"
    );

    tcp.close();
}

/// The first-party half of the cookie switch: it does not ask who the request
/// is for, so the site's own jar is closed on both halves of the exchange.
#[test]
fn blocking_every_cookie_closes_the_sites_own_jar() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "stealth-all-cookies", "");
    core.set_config(Config {
        mitm_enabled: true,
        stealth: StealthConfig {
            enabled: true,
            block_all_cookies: true,
            ..StealthConfig::default()
        },
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/cookies",
        "Sec-Fetch-Dest: document\r\nCookie: sid=1\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ok");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        assert!(
            !sent.to_lowercase().contains("cookie:"),
            "a first-party request loses its cookies too: {sent:?}"
        );
    }
    let lower = head.to_lowercase();
    assert!(
        !lower.contains("set-cookie:"),
        "and the answer may not open the jar again: {head}"
    );

    tcp.close();
}

/// `Yêu cầu các trang web không theo dõi tôi` and `Ẩn truy vấn tìm kiếm`: the
/// signals go out, and the words the user typed stay on the results page.
#[test]
fn the_privacy_signals_go_out_and_the_search_query_stays_home() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "stealth-signals", "");
    core.set_config(Config {
        mitm_enabled: true,
        stealth: StealthConfig {
            enabled: true,
            inject_gpc_dnt: true,
            hide_search_query: true,
            ..StealthConfig::default()
        },
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/cookies",
        "Sec-Fetch-Dest: document\r\n\
         Referer: https://www.google.com/search?q=cats&num=10\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        assert!(sent.contains("Sec-GPC: 1"), "GPC must go out: {sent:?}");
        assert!(sent.contains("DNT: 1"), "and DNT with it: {sent:?}");
        assert!(
            sent.contains("Referer: https://www.google.com/search?num=10"),
            "the referer keeps its page and loses the words: {sent:?}"
        );
        assert!(
            !sent.contains("q=cats"),
            "the query must not leave the results page: {sent:?}"
        );
    }

    tcp.close();
}

/// The address the user typed is the address the origin reads: whatever the app
/// claimed for itself is overwritten, because the point is that the page sees
/// one address and no other.
#[test]
fn a_masked_address_replaces_the_one_the_client_claims() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "stealth-mask", "");
    core.set_config(Config {
        mitm_enabled: true,
        stealth: StealthConfig {
            enabled: true,
            mask_ip: Some("203.0.113.9".parse().expect("an address")),
            ..StealthConfig::default()
        },
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "X-Forwarded-For: 198.51.100.7\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        assert!(
            sent.contains("X-Forwarded-For: 203.0.113.9"),
            "the masked address must go out: {sent:?}"
        );
        assert!(
            !sent.contains("198.51.100.7"),
            "and not the address the app claimed: {sent:?}"
        );
    }
    tcp.close();
}

/// The address survives being switched off in the stored text, but the master
/// switch decides whether a byte is written: an off mode leaves the head of the
/// request exactly as the app composed it.
#[test]
fn a_masked_address_is_not_added_when_stealth_is_off() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "stealth-mask-off", "");
    core.set_config(Config {
        mitm_enabled: true,
        stealth: StealthConfig {
            enabled: false,
            mask_ip: Some("203.0.113.9".parse().expect("an address")),
            ..StealthConfig::default()
        },
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "X-Forwarded-For: 198.51.100.7\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        assert!(
            !sent.contains("203.0.113.9"),
            "a mode that is off must add nothing: {sent:?}"
        );
        assert!(
            sent.contains("X-Forwarded-For: 198.51.100.7"),
            "the client's own head goes out as it came: {sent:?}"
        );
    }
    tcp.close();
}

/// A page gets the scriptlets the browser-API switches ask for, inline and with
/// the nonce the policy was taught: the guard has to run before the page's own
/// scripts do.
#[test]
fn an_injected_guard_silences_the_push_and_geolocation_apis() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "stealth-guards", "");
    core.set_config(Config {
        mitm_enabled: true,
        stealth: StealthConfig {
            enabled: true,
            block_push_api: true,
            block_geolocation_api: true,
            ..StealthConfig::default()
        },
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(&mut tcp, &mut conn, "/", "Accept: text/html\r\n");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let nonce = nonce_of(&head);
    let page = String::from_utf8_lossy(&body);
    assert!(
        page.contains(&format!("<script nonce=\"{nonce}\">")),
        "the guards are inline and carry the nonce: {page}"
    );
    assert!(
        page.contains("PushManager"),
        "the push API must be closed in the page: {page}"
    );
    assert!(
        page.contains("getCurrentPosition"),
        "and the geolocation API with it: {page}"
    );

    tcp.close();
}

/// With nothing switched on, the stealth path must not touch a request at all:
/// the head the origin sees is the head the client wrote.
#[test]
fn stealth_leaves_a_request_it_has_no_edit_for_alone() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "stealth-off", "");
    core.set_config(Config {
        mitm_enabled: true,
        // The master is on and every sub-switch is off: nothing applies.
        stealth: StealthConfig {
            enabled: true,
            ..StealthConfig::default()
        },
        ..core.config()
    });

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/cookies?utm_source=news",
        "Sec-Fetch-Site: cross-site\r\nAuthorization: Bearer keep-me\r\n\
         Referer: https://www.google.com/search?q=cats\r\nCookie: sid=1\r\n\
         If-None-Match: \"abc123\"\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, b"ok");
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.last().expect("the request reached the origin");
        assert!(
            sent.contains("GET /cookies?utm_source=news HTTP/1.1"),
            "the URL keeps every parameter: {sent:?}"
        );
        assert!(sent.contains("Cookie: sid=1"), "{sent:?}");
        assert!(sent.contains("Authorization: Bearer keep-me"), "{sent:?}");
        assert!(sent.contains("q=cats"), "{sent:?}");
        assert!(sent.contains("If-None-Match"), "{sent:?}");
    }
    assert!(
        head.to_lowercase().contains("set-cookie:"),
        "the jar stays open: {head}"
    );

    tcp.close();
}

/// The `$jsonprune` rule: the answer's JSON loses the item it names.
const JSONPRUNE_LIST: &str = "! Title: e2e jsonprune rules\n\
                              ||shop.test/jsonprune$jsonprune=\\$.ads\n";

/// `$jsonprune` takes the items the expression names out of a JSON response
/// body — and the head the client reads is told the truth about the length.
#[test]
fn jsonprune_rules_trim_the_https_body() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "jsonprune", JSONPRUNE_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/jsonprune",
        "Sec-Fetch-Dest: empty\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, br#"{"keep":3}"#, "the ad item must be gone: {head}");
    assert!(
        head.to_lowercase().contains("content-length: 10"),
        "the head must tell the length the client reads: {head}"
    );

    tcp.close();
}

/// The same rule on a request that carries a body: `$jsonprune` trims the
/// answer to a POST like it trims the answer to a GET, and the request itself
/// still goes to the origin whole.
#[test]
fn jsonprune_rules_reach_a_request_with_a_body() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "jsonprune-post", JSONPRUNE_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = post_with(
        &mut tcp,
        &mut conn,
        "/jsonprune",
        br#"{"q": 1}"#,
        "Content-Type: application/json\r\nSec-Fetch-Dest: empty\r\n\
         Referer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, br#"{"keep":3}"#, "the ad item must be gone: {head}");
    assert!(
        head.to_lowercase().contains("content-length: 10"),
        "the head must tell the length the client reads: {head}"
    );
    {
        let seen = origin.requests.lock().expect("requests");
        let sent = seen.first().expect("the request reached the origin");
        assert!(
            sent.starts_with("POST /jsonprune HTTP/1.1"),
            "the request goes out as it was sent: {sent:?}"
        );
    }

    tcp.close();
}

/// A blocked URL on a request that carries a body.
const POST_BLOCK_LIST: &str = "! Title: e2e post blocks\n\
                               ||shop.test/blockme^\n";

/// The block on a request with a body: the answer goes out at the head, and
/// the body bytes that follow are swallowed before anything is parsed again —
/// the next request on the connection is read where it really starts.
#[test]
fn a_blocked_request_body_is_swallowed_and_the_connection_goes_on() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "post-block", POST_BLOCK_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // A declared length first.
    let (head, body) = post_with(&mut tcp, &mut conn, "/blockme", b"{\"track\": true}", "");
    assert!(head.starts_with("HTTP/1.1 204 No Content"), "{head}");
    assert!(body.is_empty(), "{body:?}");

    // Then a chunked body: the swallow has to follow its framing.
    let chunked = b"POST /blockme HTTP/1.1\r\nHost: shop.test\r\nConnection: keep-alive\r\n\
                    Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let (head, body) = send_and_read(&mut tcp, &mut conn, chunked);
    assert!(head.starts_with("HTTP/1.1 204 No Content"), "{head}");
    assert!(body.is_empty(), "{body:?}");

    // The next request on the same connection is read as a request, not as
    // body bytes: had one byte of either body been read as a head, this would
    // not be a page, and the origin would have heard it.
    let (head, body) = request(&mut tcp, &mut conn, "/");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        contains_bytes(&body, local_asset("/adfree-user.js").as_bytes()),
        "the page must come back with its tags injected"
    );
    let seen = origin.requests.lock().expect("requests");
    assert_eq!(
        seen.len(),
        1,
        "only the page may reach the origin: {seen:?}"
    );

    tcp.close();
}

/// The `$hls` rules: the tag rule removes the segment its marker covers, the
/// URL-pattern rule the segment it names.
const HLS_LIST: &str = "! Title: e2e hls rules\n\
                        ||shop.test/hls$hls=/#EXT-X-BYTERANGE/t\n\
                        ||shop.test/hls$hls=01.ts\n";

/// `$hls` takes the segments the rules name out of an HLS playlist, the tags
/// that applied only to them with them — and the head the client reads is
/// told the truth about the length.
#[test]
fn hls_rules_trim_the_https_body() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "hls", HLS_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/hls",
        "Sec-Fetch-Dest: empty\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let expected = "#EXTM3U\n#EXT-X-ENDLIST\n";
    assert_eq!(
        String::from_utf8(body).expect("utf8"),
        expected,
        "the named segments and their tag must be gone: {head}"
    );
    assert!(
        head.to_lowercase()
            .contains(&format!("content-length: {}", expected.len())),
        "the head must tell the length the client reads: {head}"
    );

    tcp.close();
}

/// `@@||host^$urlblock`: the page vouches for itself, so the URL rules stand
/// down for requests it makes — the third-party referrer case still fires.
#[test]
fn a_urlblock_exception_lets_the_pages_own_requests_through() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "urlblock", URLBLOCK_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // The page's own subresource: the exception covers it.
    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/ads/tracker.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://shop.test/\r\n",
    );
    assert!(
        head.starts_with("HTTP/1.1 404"),
        "the exception must let the request through: {head}"
    );
    // The same request with a third-party page behind it: no exception covers
    // *that* page, so the rule fires.
    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/ads/tracker.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://other.test/\r\n",
    );
    assert!(
        head.starts_with("HTTP/1.1 204"),
        "a page without the exception must still be covered: {head}"
    );

    // AdGuard spells the exception's coverage out: blocking, redirects and
    // `$removeparam` all stand down for such a page, so the query survives.
    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/api?secret=1&keep=2",
        "Sec-Fetch-Dest: empty\r\nReferer: https://shop.test/\r\n",
    );
    assert!(
        head.starts_with("HTTP/1.1 404"),
        "the page's own request reaches the origin: {head}"
    );
    let seen = origin.requests.lock().expect("requests");
    let api = seen
        .iter()
        .find(|r| r.contains("/api"))
        .expect("the request reached the origin");
    assert!(
        api.starts_with("GET /api?secret=1&keep=2 "),
        "a $urlblock page keeps its query: {api:?}"
    );
    drop(seen);
    tcp.close();
}

/// `$urltransform`: a rule whose first substitute reaches for the whole URL
/// hands the request to the destination it extracted — another origin, so the
/// request is answered a redirect and the tracker never sees it — while a rule
/// that stays on the path rewrites the request line the origin receives. Both
/// over one kept-alive connection, which proves the redirect frames cleanly.
const URLTRANSFORM_LIST: &str = "! Title: e2e urltransform\n\
                                 ||shop.test/go$urltransform=pct|/^http.*[?&]url=(https?:\\/\\/[^&]*)$/\\$1/|pct\n\
                                 ||shop.test/local$urltransform=/-old/-new/\n";

/// `$urltransform` on the HTTPS path: a same-origin transform is a rewrite,
/// an origin-changing one a redirect, and each is applied by the rule that
/// carried it (see [`URLTRANSFORM_LIST`]).
#[test]
fn urltransform_rules_rewrite_and_redirect_on_the_https_path() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "urltransform", URLTRANSFORM_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // 1. The destination is another origin: the one answer that can take the
    //    request there is a redirect, and the tracker never sees it.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/go?url=https%3A%2F%2Fok.test%2Fdeep",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 302"), "{head}");
    assert!(head.contains("Location: https://ok.test/deep"), "{head}");
    assert!(body.is_empty(), "{body:?}");
    {
        let seen = origin.requests.lock().expect("requests");
        assert!(
            !seen.iter().any(|r| r.contains("/go")),
            "a redirected request must not reach the origin: {seen:?}"
        );
    }

    // 2. A transform that stays on the path is a rewrite of the request line
    //    the origin receives.
    let (head, _) = request_with(
        &mut tcp,
        &mut conn,
        "/local-old",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(
        head.starts_with("HTTP/1.1 404"),
        "the origin answers what it has, so the request reached it: {head}"
    );
    let seen = origin.requests.lock().expect("requests");
    let local = seen
        .iter()
        .find(|r| r.contains("/local"))
        .expect("the rewritten request reached the origin");
    assert!(
        local.starts_with("GET /local-new "),
        "the rewritten path must be what the origin sees: {local:?}"
    );
    drop(seen);

    tcp.close();
}

/// `$replace` rules: one names the page, one a script it loads, so both roads
/// through the rewriter are walked — HTML, which is injected into as well, and
/// plain text, which is not.
const REPLACE_LIST: &str = "! Title: e2e replace\n\
                            ||shop.test^$document,replace=/<title>e2e<\\/title>/<title>clean<\\/title>/\n\
                            ||shop.test/ad.js$script,replace=/banner\\((\\d)\\)/safe($1)/\n\
                            ||shop.test/ad-gz.js$script,replace=/banner\\((\\d)\\)/safe($1)/\n";

/// The same, for a page far larger than a rewrite may hold.
const REPLACE_CAP_LIST: &str = "! Title: e2e replace cap\n\
                                ||shop.test^$replace=/<title>big<\\/title>/<title>small<\\/title>/\n";

/// `$replace`: the matched response body is rewritten, the request is *not*
/// blocked, and the injection that follows an HTML rewrite still lands — all
/// over one kept-alive connection, which also proves the rewritten responses
/// frame cleanly.
#[test]
fn replace_rules_rewrite_bodies_on_the_https_path() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "replace", REPLACE_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    // 1. The page itself: the list's own text lands in the body, and the
    //    injector then runs on the result — one nonce in the policy, the tags
    //    carrying it, and a length that counts both edits.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let nonce = nonce_of(&head);
    let page = page_text(&head, &body);
    assert!(page.contains("<title>clean</title>"), "{page}");
    assert!(!page.contains("<title>e2e</title>"), "{page}");
    assert!(page.contains(&format!(" nonce=\"{nonce}\"")), "{page}");
    assert!(
        page.ends_with("</html>"),
        "the body must be complete: {page}"
    );
    assert_eq!(declared_length(&head), body.len());

    // 2. A script the page loads: rewritten in place, served by the origin
    //    rather than answered by the filter.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/ad.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(
        head.to_lowercase()
            .contains("content-type: application/javascript"),
        "{head}"
    );
    assert_eq!(String::from_utf8_lossy(&body), "/* ads */ safe(1);");
    assert_eq!(declared_length(&head), body.len());
    {
        let seen = origin.requests.lock().expect("requests");
        assert!(
            seen.iter().any(|r| r.starts_with("GET /ad.js ")),
            "a `$replace` rule must not block the request: {seen:?}"
        );
    }

    // 3. The same rewrite on a compressed response: decoded, rewritten, and
    //    put back compressed — a `$replace` match is also reason enough to
    //    stop the client negotiating an encoding the rewriter cannot read.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/ad-gz.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://shop.test/\r\n\
         Accept-Encoding: gzip, deflate, br, zstd\r\n",
    );
    assert!(
        head.to_lowercase().contains("content-encoding: gzip"),
        "{head}"
    );
    assert_eq!(page_text(&head, &body), "/* ads */ safe(1);");
    assert_eq!(declared_length(&head), body.len());
    {
        let seen = origin.requests.lock().expect("requests");
        let asked = seen
            .iter()
            .find(|r| r.starts_with("GET /ad-gz.js "))
            .expect("the request reached the origin");
        assert!(
            asked.contains("Accept-Encoding: gzip, deflate\r\n"),
            "the encodings we cannot decode must be gone: {asked:?}"
        );
    }

    // 4. The same connection, one more round: a rewritten response is framed
    //    like any other, and the splice stays in sync.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/ad.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert_eq!(String::from_utf8_lossy(&body), "/* ads */ safe(1);");

    // 5. A HEAD exists to advertise a body, not to carry one: there is nothing
    //    to rewrite, so the origin's own head goes through untouched and
    //    nothing follows it.
    let raw = head_request(
        &mut tcp,
        &mut conn,
        "/ad.js",
        "Sec-Fetch-Dest: script\r\nReferer: https://shop.test/\r\n",
    );
    let head = String::from_utf8_lossy(&raw).to_string();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");

    tcp.close();
}

/// The cap: a rewrite holds the whole body, so a text body already known to be
/// larger travels as it is — and a page among those still gets its injection,
/// streamed exactly as before.
#[test]
fn a_body_over_the_replace_cap_keeps_its_bytes() {
    let origin = start_origin(noisy_page(600 * 1024));
    let (core, ca_der) = setup_core_with_list(&origin, "replace-cap", REPLACE_CAP_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_streamed(&mut tcp, &mut conn, "/");
    let nonce = nonce_of(&head);
    let page = page_text(&head, &body);
    assert!(
        page.contains("<title>big</title>"),
        "unrewritten: {page:.200}"
    );
    assert!(!page.contains("<title>small</title>"), "{page:.200}");
    assert!(
        page.contains(&format!(" nonce=\"{nonce}\"")),
        "and still injected: {page:.200}"
    );
    assert!(
        page.ends_with("</body></html>"),
        "the body must be complete"
    );

    tcp.close();
}

/// The `$$` rules: the answer loses the elements they name, the bytes around
/// them untouched, and the injection that follows still lands on the cut
/// body.
const HTML_LIST: &str = "! Title: e2e html filtering\n\
                         shop.test$$div[class=\"adsbygoogle\"]\n\
                         shop.test$$p[class=\"sponsored\"]\n";

/// The same rules with the `$@$` exception that cancels one of them.
const HTML_EXCEPTION_LIST: &str = "! Title: e2e html filtering exception\n\
                                   shop.test$$div[class=\"adsbygoogle\"]\n\
                                   shop.test$$p[class=\"sponsored\"]\n\
                                   shop.test$@$p[class=\"sponsored\"]\n";

/// The `$content` exception: it switches the whole family off, the way the
/// knowledge base says it switches content modification off.
const HTML_CONTENT_LIST: &str = "! Title: e2e html filtering veto\n\
                                 shop.test$$div[class=\"adsbygoogle\"]\n\
                                 @@||shop.test^$content\n";

/// One rule for the `ad-box` element every noisy page carries.
const HTML_BIG_LIST: &str = "! Title: e2e html filtering big\n\
                             shop.test$$div[class=\"ad-box\"]\n";

/// The same response edited by two families in one pass: HTML filtering
/// first, `$replace` on what it left.
const HTML_REPLACE_LIST: &str = "! Title: e2e html filtering replace\n\
                                 shop.test$$div[class=\"adsbygoogle\"]\n\
                                 ||shop.test^$document,replace=/<title>e2e<\\/title>/<title>clean<\\/title>/\n";

/// `$$`: the elements the rules name are cut out of the page, everything
/// around them travels as it came, and the injection the page's own handling
/// adds still lands — one pass, one nonce, one length.
#[test]
fn html_rules_cut_elements_on_the_https_path() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "html", HTML_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let nonce = nonce_of(&head);
    let page = page_text(&head, &body);
    assert!(
        !page.contains("adsbygoogle"),
        "the attribute rule's element must be gone: {page}"
    );
    assert!(
        !page.contains("sponsored"),
        "the class rule's element must be gone: {page}"
    );
    assert!(
        page.contains("<div class=\"ad-box\">ad</div>"),
        "nothing else may move: {page}"
    );
    assert!(
        page.contains(&format!(" nonce=\"{nonce}\"")),
        "the injection must land on the cut body: {page}"
    );
    assert!(
        page.ends_with("</html>"),
        "the body must be complete: {page}"
    );
    assert_eq!(declared_length(&head), body.len());

    // The same connection, one more round: a cut response is framed like any
    // other, and the splice stays in sync.
    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(!page_text(&head, &body).contains("adsbygoogle"));

    tcp.close();
}

/// `$@$`: the exception cancels the rule whose selector it repeats, and only
/// that one.
#[test]
fn an_html_exception_saves_the_element_it_names() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "html-exception", HTML_EXCEPTION_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    let page = page_text(&head, &body);
    assert!(
        !page.contains("adsbygoogle"),
        "the rule without an exception still runs: {page}"
    );
    assert!(
        page.contains("Sponsored content"),
        "the exception's element must stay: {page}"
    );
    assert_eq!(declared_length(&head), body.len());

    tcp.close();
}

/// `$content`: the page exception switches HTML filtering off, like it
/// switches `$replace` off.
#[test]
fn a_content_exception_switches_html_filtering_off() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "html-content", HTML_CONTENT_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    let page = page_text(&head, &body);
    assert!(
        page.contains("adsbygoogle"),
        "`$content` must leave the page whole: {page}"
    );
    assert_eq!(declared_length(&head), body.len());

    tcp.close();
}

/// A page past the streaming threshold (32 KiB) is still held: an HTML rule
/// reads the whole document, and the cap that lets an edit hold one is the
/// `$replace` one.
#[test]
fn html_rules_reach_a_page_over_the_streaming_threshold() {
    let origin = start_origin(noisy_page(96 * 1024));
    let (core, ca_der) = setup_core_with_list(&origin, "html-big", HTML_BIG_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        !page.contains("ad-box"),
        "the rule's element must be gone from a big page: {page:.200}"
    );
    assert!(page.ends_with("</body></html>"), "complete body");
    assert_eq!(declared_length(&head), body.len());

    tcp.close();
}

/// Past the edit cap (512 KiB) the bytes travel as they are — and a page among
/// those still gets its injection, streamed exactly as before.
#[test]
fn an_html_rule_over_the_cap_leaves_the_bytes_alone() {
    let origin = start_origin(noisy_page(600 * 1024));
    let (core, ca_der) = setup_core_with_list(&origin, "html-cap", HTML_BIG_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_streamed(&mut tcp, &mut conn, "/");
    let nonce = nonce_of(&head);
    let page = page_text(&head, &body);
    assert!(
        page.contains("ad-box"),
        "over the cap the bytes travel untouched: {page:.200}"
    );
    assert!(
        page.contains(&format!(" nonce=\"{nonce}\"")),
        "and still injected: {page:.200}"
    );
    assert!(
        page.ends_with("</body></html>"),
        "the body must be complete"
    );

    tcp.close();
}

/// A page that never arrived with a 200 is not HTML filtering's to read: the
/// element stays where the origin put it.
#[test]
fn html_rules_skip_a_response_that_is_not_a_200() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "html-status", HTML_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/missing",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        page.contains("adsbygoogle"),
        "a 404 is not the page the rules were written for: {page}"
    );

    tcp.close();
}

/// HTML filtering and `$replace` edit one response in one pass: the cut comes
/// first, and what `$replace` reads is what the client will get.
#[test]
fn html_filtering_and_replace_edit_the_same_pass() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "html-replace", HTML_REPLACE_LIST);

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    assert!(!conn.is_handshaking(), "the MITM handshake must complete");

    let (head, body) = request_with(
        &mut tcp,
        &mut conn,
        "/",
        "Sec-Fetch-Dest: document\r\nReferer: https://shop.test/\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let page = page_text(&head, &body);
    assert!(
        page.contains("<title>clean</title>"),
        "the rewrite must land: {page}"
    );
    assert!(
        !page.contains("adsbygoogle"),
        "and the cut must too: {page}"
    );
    assert_eq!(declared_length(&head), body.len());

    tcp.close();
}

/// The script the origin serves for `/ad.js`: a text body that is not a page.
const SCRIPT: &str = "/* ads */ banner(1);";

/// The injection origin: the reserved address is answered by the app itself.
///
/// This is what keeps the injected tags out of the page's reach — a service
/// worker only intercepts its own origin, so it can never answer (or break)
/// a request for the runtime, the stylesheet or a rule lookup. It must work
/// with no peer socket at all: the leaf is minted for the address (an IP
/// literal puts no SNI on the wire), and every asset comes back over the
/// connection the page itself arrived through.
#[test]
fn the_injection_origin_is_answered_without_a_peer() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core(&origin);

    let mut tcp = Client::connect_to(
        core.clone(),
        crate::mitm::proxy::LOCAL_ORIGIN_V4,
        origin.port,
    );
    let mut conn = handshake_with(
        &mut tcp,
        client_config(ca_der),
        ServerName::try_from("192.0.2.1").expect("address literal"),
    );
    assert!(
        !conn.is_handshaking(),
        "the local origin must complete a handshake"
    );

    // 1. The runtime, for the host its tag named (`dmn=`, like AdGuard's
    //    content script carries). A `<script src>` needs no CORS, only CORP;
    //    the page must not be able to *read* our assets.
    let (head, body) = request(&mut tcp, &mut conn, "/adfree-page.js?dmn=shop.test&h=0");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.contains("Cross-Origin-Resource-Policy: cross-origin"),
        "the runtime is embedded cross-origin: {head}"
    );
    assert!(
        !head.contains("Access-Control-Allow-Origin"),
        "a page must not be able to fetch the runtime: {head}"
    );
    assert!(
        contains_bytes(&body, b"window.__adfree_page"),
        "the runtime must arrive whole"
    );

    // 2. The user script, in window-sized bursts like a real origin's answer.
    //    The user's own code: not readable from a page.
    let (head, body) = request(&mut tcp, &mut conn, "/adfree-user.js");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        !head.contains("Access-Control-Allow-Origin"),
        "the user script must stay unreadable: {head}"
    );
    assert!(
        contains_bytes(&body, b"window.__adfree_e2e"),
        "the script body must arrive, got {} bytes",
        body.len()
    );

    // 3. The host whose rules the answer carries comes from the URL alone.
    let (head, body) = request(&mut tcp, &mut conn, "/adfree-hide.css?dmn=shop.test&h=0");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let css = String::from_utf8_lossy(&body);
    assert!(css.contains(".ad-box"), "{css}");
    let (head, body) = request(
        &mut tcp,
        &mut conn,
        "/adfree-generic.js?dmn=shop.test&c=adsbygoogle&i=slot-1",
    );
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.contains("Access-Control-Allow-Origin: *"),
        "the rule lookup is what a page reads cross-origin: {head}"
    );
    let json = String::from_utf8_lossy(&body);
    assert!(json.contains("\".adsbygoogle\""), "{json}");

    // 4. Anything else is a dead end: there is no peer to forward to.
    let (head, _) = request(&mut tcp, &mut conn, "/etc/passwd");
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");

    // 5. And nothing was ever dialed for the reserved address.
    let seen = origin.requests.lock().expect("requests");
    assert!(
        seen.is_empty(),
        "the local origin must never reach upstream: {seen:?}"
    );
    drop(seen);
    tcp.close();
}

#[test]
fn compressed_and_chunked_pages_are_still_filtered() {
    for mode in [OriginBody::Gzip, OriginBody::Chunked] {
        let origin = start_origin_mode(HTML, mode);
        let (core, ca_der) = setup_core_named(&origin, "e2e-framing");

        let mut tcp = Client::connect(core.clone(), origin.port);
        let mut conn = handshake(&mut tcp, client_config(ca_der));

        let (head, body) = request(&mut tcp, &mut conn, "/");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let nonce = nonce_of(&head);
        let lower = head.to_lowercase();
        assert!(
            lower.contains(&format!("script-src 'none' 'nonce-{nonce}'")),
            "the policy must survive the framing rewrite: {head}"
        );

        let page = match mode {
            OriginBody::Gzip => {
                assert!(
                    lower.contains("content-encoding: gzip"),
                    "the page must still travel compressed: {head}"
                );
                let decoded =
                    crate::mitm::http::decode_body(&body, crate::mitm::http::Encoding::Gzip)
                        .expect("the body must decode as gzip");
                String::from_utf8_lossy(&decoded).to_string()
            }
            _ => {
                assert!(
                    !lower.contains("transfer-encoding"),
                    "chunking must be gone, the body has a length now: {head}"
                );
                String::from_utf8_lossy(&body).to_string()
            }
        };
        assert!(
            page.contains(&format!("<script nonce=\"{nonce}\">window.__adfree_page=")),
            "the payload must be injected into a {mode:?} page with the nonce: {page}"
        );
        let href = hide_href(&page);
        assert!(
            href.starts_with("/adfree-hide.css?dmn=shop.test&h="),
            "hiding travels as a stylesheet into a {mode:?} page: {href}"
        );
        assert!(
            page.contains("\"#slot-1\""),
            "generic rules must be scanned: {page}"
        );
        assert!(
            page.contains("Sponsored content"),
            "the page itself is intact: {page}"
        );
        tcp.close();
    }
}

/// The shape news.ycombinator.com serves: no doctype, and the `<html>` tag
/// carries attributes so the bare `"<html>"` never occurs.
const HTML_NO_DOCTYPE: &str = "<html lang=\"en\" op=\"news\"><head><title>e2e</title></head>\
                               <body><div class=\"adsbygoogle\" id=\"slot-1\">ad</div></body></html>";

#[test]
fn a_page_without_a_doctype_is_injected_like_any_other() {
    // Until the document check learned this shape the body fell through
    // unedited — and under chunked framing that also broke the page.
    for mode in [OriginBody::Plain, OriginBody::ChunkedGzip] {
        let origin = start_origin_mode(HTML_NO_DOCTYPE, mode);
        let (core, ca_der) = setup_core_named(&origin, "e2e-no-doctype");

        let mut tcp = Client::connect(core.clone(), origin.port);
        let mut conn = handshake(&mut tcp, client_config(ca_der));

        let (head, body) = request(&mut tcp, &mut conn, "/");
        let nonce = nonce_of(&head);
        assert!(
            !head.to_lowercase().contains("transfer-encoding"),
            "chunking must be gone, the body has a length now: {head}"
        );
        let page = page_text(&head, &body);
        assert!(
            page.contains(&format!("<script nonce=\"{nonce}\">window.__adfree_page=")),
            "the payload must be injected into a {mode:?} page with the nonce: {page}"
        );
        assert!(
            page.contains(&format!(
                "<script nonce=\"{nonce}\" src=\"https://192.0.2.1/adfree-page.js"
            )),
            "the runtime must travel with the same nonce into a {mode:?} page: {page}"
        );
        assert!(
            page.contains("\"#slot-1\""),
            "generic rules must be scanned: {page}"
        );
        tcp.close();
    }
}

#[test]
fn a_chunked_body_that_is_not_ours_to_edit_keeps_its_chunking() {
    // `text/html` that never looks like a document: the injector leaves it
    // alone, and the framing has to survive that — a dechunked body under the
    // origin's `transfer-encoding: chunked` head is exactly what Chrome
    // reports as ERR_INVALID_CHUNKED_ENCODING.
    let fragment = "<div class=\"adsbygoogle\">ad</div>";
    for mode in [OriginBody::Chunked, OriginBody::ChunkedGzip] {
        let origin = start_origin_mode(fragment, mode);
        let (core, ca_der) = setup_core_named(&origin, "e2e-passthrough");

        let mut tcp = Client::connect(core.clone(), origin.port);
        let mut conn = handshake(&mut tcp, client_config(ca_der));

        let (head, body) = request(&mut tcp, &mut conn, "/");
        assert!(
            head.to_lowercase().contains("transfer-encoding: chunked"),
            "the framing the origin chose must survive: {head}"
        );
        let payload = match crate::mitm::http::dechunk(&body) {
            crate::mitm::http::Dechunk::Complete { payload, .. } => payload,
            _ => panic!("the client must receive a well-framed chunked body: {body:?}"),
        };
        let plain = if mode == OriginBody::ChunkedGzip {
            crate::mitm::http::decode_body(&payload, crate::mitm::http::Encoding::Gzip)
                .expect("the gzip payload must survive")
        } else {
            payload
        };
        assert_eq!(String::from_utf8_lossy(&plain), fragment);
        tcp.close();
    }
}

#[test]
fn a_chunked_body_we_cannot_decode_keeps_its_chunking() {
    // Declared gzip, but the bytes are not: the injector cannot read the body,
    // so it hands it over byte for byte. Framing included — this is the other
    // branch that leaves a body alone.
    let garbage = "not gzip at all";
    let origin = start_origin_mode(garbage, OriginBody::ChunkedBadGzip);
    let (core, ca_der) = setup_core_named(&origin, "e2e-bad-gzip");

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));

    let (head, body) = request(&mut tcp, &mut conn, "/");
    assert!(
        head.to_lowercase().contains("transfer-encoding: chunked"),
        "the framing the origin chose must survive: {head}"
    );
    let payload = match crate::mitm::http::dechunk(&body) {
        crate::mitm::http::Dechunk::Complete { payload, .. } => payload,
        _ => panic!("the client must receive a well-framed chunked body: {body:?}"),
    };
    assert_eq!(String::from_utf8_lossy(&payload), garbage);
    tcp.close();
}

/// A page that does not compress away: a repeated character would shrink to
/// nothing and never exercise the streaming path.
fn noisy_page(len: usize) -> &'static str {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut page = String::from(
        "<!doctype html><html><head><title>big</title></head>\
         <body><div class=\"ad-box\">ad</div>",
    );
    while page.len() < len {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        page.push((b'a' + ((seed >> 33) % 26) as u8) as char);
    }
    page.push_str("</body></html>");
    Box::leak(page.into_boxed_str())
}

/// Reads a response that has been switched to chunked framing, until the
/// terminating chunk arrives. Returns `(head, decoded_body)`.
fn request_streamed(
    tcp: &mut Client,
    conn: &mut ClientConnection,
    path: &str,
) -> (String, Vec<u8>) {
    let req = format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\nConnection: keep-alive\r\n\r\n");
    conn.writer()
        .write_all(req.as_bytes())
        .expect("write request");
    flush_tls(tcp, conn);

    let mut raw = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            Instant::now() < deadline,
            "streamed response never finished: {} bytes so far",
            raw.len()
        );
        if let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
            let mut body = Vec::new();
            let mut framing = crate::mitm::http::DechunkState::new();
            let done = framing
                .push(&raw[split..], &mut body)
                .expect("the body must be chunked");
            if done {
                assert!(framing.leftover().is_empty(), "no trailing bytes");
                let head = String::from_utf8_lossy(&raw[..split]).to_string();
                let plain = if head.to_lowercase().contains("content-encoding: gzip") {
                    crate::mitm::http::decode_body(&body, crate::mitm::http::Encoding::Gzip)
                        .expect("the streamed body must be valid gzip")
                } else {
                    body
                };
                return (head, plain);
            }
        }
        flush_tls(tcp, conn);
        let wire = tcp.read_some(Duration::from_millis(50));
        raw.extend_from_slice(&feed_tls(conn, wire));
    }
}

/// The regression this stage exists for: a body bigger than one receive window
/// cannot be held whole. Unacknowledged bytes stall the relay, the origin's
/// remaining bytes are never handed over, and the page hangs forever — which is
/// what a plain `content-length` response over the window used to do.
#[test]
fn a_page_larger_than_one_window_streams_to_the_client() {
    let origin = start_origin_mode(noisy_page(200 * 1024), OriginBody::Gzip);
    let (core, ca_der) = setup_core_named(&origin, "e2e-stream");

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));

    let (head, body) = request_streamed(&mut tcp, &mut conn, "/");
    let lower = head.to_lowercase();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        lower.contains("transfer-encoding: chunked"),
        "a body too long to hold must stream: {head}"
    );
    assert!(
        lower.contains("content-encoding: gzip"),
        "and it must still travel compressed: {head}"
    );
    assert!(!lower.contains("content-length"), "{head}");
    let nonce = nonce_of(&head);

    let page = String::from_utf8(body).expect("utf8");
    assert!(
        page.contains(&format!(
            "<script nonce=\"{nonce}\" src=\"{}?dmn=shop.test&h=",
            local_asset("/adfree-page.js")
        )),
        "the runtime tag must be injected with the nonce"
    );
    assert!(
        page.contains(&format!(
            "<script nonce=\"{nonce}\" src=\"{}?h=",
            local_asset("/adfree-user.js")
        )),
        "the user script tag must be injected with the nonce"
    );
    assert!(
        page.contains(&format!("<script nonce=\"{nonce}\">window.__adfree_page=")),
        "the payload must be injected with the nonce"
    );
    // Hostname rules come from the URL, so they are there even though the scan
    // only saw the head of the document — as the stylesheet the browser caches.
    let href = hide_href(&page);
    assert!(
        href.starts_with("/adfree-hide.css?dmn=shop.test&h="),
        "{href}"
    );
    assert!(
        !page.contains("\"hide\""),
        "hiding left the payload: {page}"
    );
    // The tag has to land before the body renders, and nothing may be lost.
    let tag = page.find("/adfree-user.js").expect("tag");
    let head_close = page.find("</head>").expect("</head>");
    assert!(tag < head_close, "the tag must land inside the head");
    assert_eq!(page.matches("</head>").count(), 1, "no duplicated parts");
    assert!(
        page.ends_with("</body></html>"),
        "the page must be complete"
    );
    assert!(page.contains("ad-box"), "the origin's own content survived");

    tcp.close();
}

// ------------------------------------------------------------------ `$app=`

/// The app rules of the e2e: a generic block an app exception lifts, and an
/// app-scoped block no generic rule carries.
///
/// Each test owns one connection: the flow is the app attribution surface, and
/// a client port recycled between two connections would keep the older flow's
/// attribution — the harness always starts a fresh origin and core instead.
const APP_EXCEPTION_LIST: &str = "! Title: e2e app exception\n\
                                  ||shop.test/pathpage\n\
                                  @@||shop.test/pathpage$app=com.test.allowed\n";

const APP_BLOCK_LIST: &str = "! Title: e2e app block\n\
                              ||shop.test/pathpage$app=com.test.blocked\n";

#[test]
fn an_app_exception_does_not_lift_a_generic_block_for_other_apps() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "app-exception-thaw", APP_EXCEPTION_LIST);

    // Nobody owns this flow: the generic block decides, and the app exception
    // is not allowed to stand in for every app on the device.
    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, body) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(head.starts_with("HTTP/1.1 204"), "{head}");
    assert!(body.is_empty(), "{body:?}");
    assert!(
        origin.requests.lock().expect("requests").is_empty(),
        "a blocked request must not reach the origin"
    );
}

#[test]
fn an_app_exception_lifts_a_generic_block_for_its_app() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "app-exception-keep", APP_EXCEPTION_LIST);

    // The flow the kernel tables would name: the exception lives in the app
    // shard, the block in the main engine, and the merge is what cancels it.
    core.set_uid_apps(vec![(42_424, vec!["com.test.allowed".to_string()])]);
    core.pin_uid_for_port(CLIENT_PORT, 42_424);
    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, body) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "the app exception must let it through: {head}"
    );
    assert!(contains_bytes(&body, b"e2e"), "the page arrives whole");
    let seen = origin.requests.lock().expect("requests");
    assert!(
        seen.iter().any(|r| r.contains("/pathpage")),
        "the request must reach the origin: {seen:?}"
    );
}

#[test]
fn an_app_scoped_block_spares_the_apps_it_does_not_name() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "app-block-spare", APP_BLOCK_LIST);

    // An unattributed flow is nobody's app rule: the page comes through.
    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, _) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "no app is named, no app rule fires: {head}"
    );
}

#[test]
fn an_app_scoped_block_applies_to_its_app() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "app-block", APP_BLOCK_LIST);

    core.set_uid_apps(vec![(42_425, vec!["com.test.blocked".to_string()])]);
    core.pin_uid_for_port(CLIENT_PORT, 42_425);
    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, body) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(
        head.starts_with("HTTP/1.1 204"),
        "the named app is blocked: {head}"
    );
    assert!(body.is_empty(), "{body:?}");
}

// ------------------------------------------- `$app=` (the platform lookup)

/// A list with no `$app=` rule at all: the platform must not be asked.
const PLAIN_LIST: &str = "! Title: e2e plain\n||shop.test/ads/tracker.js$script\n";

/// The Android path: no kernel table is involved, the platform callback
/// answers — and it has to be asked about exactly the connection the tunnel
/// opened, or the flow would be attributed to the wrong app.
struct PlatformLookup {
    /// uid the "framework" reports; `None` for an unattributable connection.
    uid: Option<u32>,
    /// The origin this test dials, asserted on every call.
    origin_port: u16,
    calls: AtomicUsize,
}

impl crate::api::ConnectionUidLookup for PlatformLookup {
    fn owner_uid(
        &self,
        protocol: u8,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
    ) -> Option<u32> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(protocol, 6, "the tunnel's TCP flows are what is asked");
        assert_eq!(local_ip, "10.0.2.15");
        assert_eq!(local_port, CLIENT_PORT);
        assert_eq!(remote_ip, "127.0.0.1");
        assert_eq!(remote_port, self.origin_port);
        self.uid
    }
}

#[test]
fn a_platform_lookup_drives_the_app_shard() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "app-platform-block", APP_BLOCK_LIST);
    core.set_uid_apps(vec![(42_426, vec!["com.test.blocked".to_string()])]);
    let lookup = Arc::new(PlatformLookup {
        uid: Some(42_426),
        origin_port: origin.port,
        calls: AtomicUsize::new(0),
    });
    core.set_uid_lookup(lookup.clone());

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, body) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(
        head.starts_with("HTTP/1.1 204"),
        "the app the platform named is blocked: {head}"
    );
    assert!(body.is_empty(), "{body:?}");
    assert_eq!(
        lookup.calls.load(Ordering::SeqCst),
        1,
        "one connection asks the platform once"
    );
}

#[test]
fn a_platform_lookup_that_cannot_answer_leaves_the_flow_unattributed() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "app-platform-unknown", APP_BLOCK_LIST);
    // The table has the uid; the platform just cannot name the connection, so
    // no app is ever attached to it.
    core.set_uid_apps(vec![(42_427, vec!["com.test.blocked".to_string()])]);
    let lookup = Arc::new(PlatformLookup {
        uid: None,
        origin_port: origin.port,
        calls: AtomicUsize::new(0),
    });
    core.set_uid_lookup(lookup.clone());

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, _) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "an unknown app matches no app rule: {head}"
    );
    assert_eq!(lookup.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn an_intercepted_flow_is_attributed_without_app_rules() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "app-platform-idle", PLAIN_LIST);
    let lookup = Arc::new(PlatformLookup {
        uid: Some(42_428),
        origin_port: origin.port,
        calls: AtomicUsize::new(0),
    });
    core.set_uid_lookup(lookup.clone());

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, _) = request(&mut tcp, &mut conn, "/pathpage");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        lookup.calls.load(Ordering::SeqCst),
        1,
        "the HTTPS path logs the app on a blocked request, so an intercepted \
         flow is attributed even with no `$app=` rule loaded"
    );
}

/// A client's first flight: the bytes the proxy sniffs a ClientHello out of.
fn client_first_flight(host: &str) -> Vec<u8> {
    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = vec![tls::ALPN_H1.to_vec()];
    let name = ServerName::try_from(host.to_string()).expect("server name");
    let mut client = ClientConnection::new(Arc::new(config), name).expect("client connection");
    tls::take_client_outbound(&mut client)
}

/// A listener that records the first bytes a connection brings it.
fn recording_listener() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
    let port = listener.local_addr().expect("listener addr").port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 16 * 1024];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = tx.send(buf[..n].to_vec());
        }
    });
    (port, rx)
}

/// An `Origin` stand-in whose side of the setup is a bare listener: nothing
/// TLS answers there, and the only thing that matters is which bytes arrive.
fn raw_origin(port: u16) -> Origin {
    Origin {
        port,
        ca_der: CertificateAuthority::generate()
            .expect("origin ca")
            .cert_der(),
        requests: Arc::new(std::sync::Mutex::new(Vec::new())),
    }
}

/// Pumps the engine until the listener reports the bytes it received.
fn await_listener(tcp: &mut Client, seen: &std::sync::mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        tcp.pump(20);
        match seen.try_recv() {
            Ok(bytes) => return bytes,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                assert!(Instant::now() < deadline, "the origin must be reached");
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("the listener thread is gone")
            }
        }
    }
}

/// A client that offers ECH is handed to the origin untouched: the host it is
/// reaching for is inside the encrypted half of the hello, so no certificate
/// the proxy could forge would be for the right name. What lands on the origin
/// is the client's own hello — the parser here says so on the raw bytes.
/// A GREASE `encrypted_client_hello` — what browsers put on ordinary
/// connections — is not an ECH connection: the proxy terminates it as before.
/// That is the difference between filtering the web and not filtering it.
#[test]
fn a_grease_hello_is_still_terminated() {
    let (port, seen) = recording_listener();
    let origin = raw_origin(port);
    let (core, _) = setup_core_named(&origin, "e2e-ech-grease");

    let mut tcp = Client::connect(core.clone(), port);
    let hello = tls::with_fake_ech(&client_first_flight("shop.test")).expect("patchable hello");
    tcp.send(&hello);

    // The proxy answers with a handshake record of its own: the connection is
    // being terminated, not relayed.
    let answer = tcp.read_some(Duration::from_secs(10));
    assert!(!answer.is_empty(), "the proxy must answer the hello");
    assert_eq!(answer[0], 0x16, "a TLS handshake record");
    // And the client's hello is never spliced: the origin has nothing yet.
    assert!(
        seen.try_recv().is_err(),
        "a GREASE hello must not reach the origin byte for byte"
    );
}

/// A host learned to require ECH keeps its config: the browser comes back with
/// a real ECH hello, whose SNI is the config's public name. That connection has
/// to go through untouched — the proxy cannot serve a certificate for a host it
/// cannot see.
#[test]
fn an_exempt_hosts_public_name_is_spliced_verbatim() {
    let (port, seen) = recording_listener();
    let origin = raw_origin(port);
    let (core, _) = setup_core_named(&origin, "e2e-ech-splice");
    core.ech_hosts
        .note_public_name("shop.test", "cloudflare-ech.test");
    core.ech_hosts
        .note_refusal("shop.test", crate::util::now_ms());

    let mut tcp = Client::connect(core.clone(), port);
    let hello =
        tls::with_fake_ech(&client_first_flight("cloudflare-ech.test")).expect("patchable hello");
    tcp.send(&hello);

    let forwarded = await_listener(&mut tcp, &seen);
    assert_eq!(
        forwarded, hello,
        "the exempt host's public name must reach the origin byte for byte"
    );
}

/// The same exemption does not splice a plain hello that names the host
/// itself: terminating it lets the upstream half offer ECH, which keeps the
/// page filterable.
#[test]
fn a_plain_hello_to_an_exempt_host_is_still_terminated() {
    let (port, seen) = recording_listener();
    let origin = raw_origin(port);
    let (core, _) = setup_core_named(&origin, "e2e-ech-exempt-plain");
    core.ech_hosts
        .note_public_name("shop.test", "cloudflare-ech.test");
    core.ech_hosts
        .note_refusal("shop.test", crate::util::now_ms());

    let mut tcp = Client::connect(core.clone(), port);
    let hello = tls::with_fake_ech(&client_first_flight("shop.test")).expect("patchable hello");
    tcp.send(&hello);

    let answer = tcp.read_some(Duration::from_secs(10));
    assert!(!answer.is_empty(), "the proxy must answer the hello");
    assert_eq!(answer[0], 0x16, "a TLS handshake record, not a splice");
    assert!(
        seen.try_recv().is_err(),
        "a plain hello is not spliced by the exemption"
    );
}

/// A real ECH hello names the ECHConfig's public name, not the host it is
/// reaching for. Without full ECH or an exemption for a host behind that name,
/// the client's cached config is not followed through to a splice: the hello is
/// terminated (and fails once), so the browser retries in the clear and the
/// page stays filterable.
#[test]
fn an_ech_public_name_is_terminated_without_full_ech() {
    let (port, seen) = recording_listener();
    let origin = raw_origin(port);
    let (core, _) = setup_core_named(&origin, "e2e-ech-public-name-off");
    core.ech_hosts
        .note_public_name("shop.test", "cloudflare-ech.test");

    let mut tcp = Client::connect(core.clone(), port);
    let hello =
        tls::with_fake_ech(&client_first_flight("cloudflare-ech.test")).expect("patchable hello");
    tcp.send(&hello);

    let answer = tcp.read_some(Duration::from_secs(10));
    assert!(!answer.is_empty(), "the proxy must answer the hello");
    assert_eq!(answer[0], 0x16, "a TLS handshake record, not a splice");
    assert!(
        seen.try_recv().is_err(),
        "without full ECH the origin must not receive the wrapped hello"
    );
}

/// The same hello with full ECH on is the user's opt-in to lose filtering for
/// ECH: it goes to the origin byte for byte.
#[test]
fn full_ech_splices_an_ech_public_name_verbatim() {
    let (port, seen) = recording_listener();
    let origin = raw_origin(port);
    let (core, _) = setup_core_named(&origin, "e2e-ech-public-name-on");
    let mut cfg = core.config();
    cfg.full_ech = true;
    core.set_config(cfg);
    core.ech_hosts
        .note_public_name("shop.test", "cloudflare-ech.test");

    let mut tcp = Client::connect(core.clone(), port);
    let hello =
        tls::with_fake_ech(&client_first_flight("cloudflare-ech.test")).expect("patchable hello");
    tcp.send(&hello);

    let forwarded = await_listener(&mut tcp, &seen);
    assert_eq!(
        forwarded, hello,
        "full ECH must splice the public name byte for byte"
    );
}

/// The same flow without ECH is terminated exactly as before: the origin sees
/// the proxy's own hello, which never offers ECH.
#[test]
fn a_client_without_ech_is_still_terminated() {
    let (port, seen) = recording_listener();
    let origin = raw_origin(port);
    let (core, ca_der) = setup_core_named(&origin, "e2e-ech-terminated");

    let mut tcp = Client::connect(core.clone(), port);
    // The client talks TLS to the proxy, which then dials the origin itself —
    // the hello that lands there is the proxy's.
    let _conn = handshake(&mut tcp, client_config(ca_der));

    let forwarded = await_listener(&mut tcp, &seen);
    match tls::first_flight(&forwarded) {
        tls::Flight::Hello {
            ech_len,
            server_name,
            alpn_http1,
            ..
        } => {
            assert_eq!(None, ech_len, "the proxy's hello must not offer ECH");
            assert_eq!(Some("shop.test".to_string()), server_name);
            assert_eq!(Some(true), alpn_http1);
        }
        other => panic!("the proxy's own hello must come back: {other:?}"),
    }
}

/// A host that advertises ECH needs two bare refusals within the window before
/// it is exempted; an ordinary 502 — one that names its server — teaches
/// nothing, and neither does a single bare one. Once confirmed, the public
/// name its browser will wrap in ECH is what gets spliced.
#[test]
fn an_ech_required_refusal_needs_two_bare_502s() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_named(&origin, "e2e-ech-refusal");
    // The DNS half has already told this client the host advertises ECH, and
    // what public name its config exposes.
    core.ech_hosts.note_advertised("shop.test");
    core.ech_hosts
        .note_public_name("shop.test", "cloudflare-ech.test");

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));

    let (head, _) = request(&mut tcp, &mut conn, "/unlucky");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    let (head, _) = request(&mut tcp, &mut conn, "/ech-required");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    let now = crate::util::now_ms();
    assert!(
        !core.ech_hosts.exempt("shop.test", now),
        "a 502 that names its server is an ordinary failure, and one bare 502 is not proof"
    );

    let (head, _) = request(&mut tcp, &mut conn, "/ech-required");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert!(
        core.ech_hosts.exempt("shop.test", now),
        "the second bare refusal must confirm the host"
    );
    assert!(
        core.ech_hosts.splices("cloudflare-ech.test", false, now),
        "and the public name its config exposes is what gets spliced"
    );
}

/// `421 Misdirected Request` is the same refusal told by the status, and one of
/// them is definitive.
#[test]
fn a_misdirected_request_is_a_refusal_too() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_named(&origin, "e2e-ech-misdirected");
    core.ech_hosts.note_advertised("shop.test");

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, _) = request(&mut tcp, &mut conn, "/misdirected");
    assert!(head.starts_with("HTTP/1.1 421"), "{head}");
    assert!(core.ech_hosts.exempt("shop.test", crate::util::now_ms()));
}

/// Only a host whose ECHConfig was rewritten away can be learned from: a bare
/// 502 from anywhere else teaches nothing.
#[test]
fn a_bare_502_from_a_host_without_ech_teaches_nothing() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_named(&origin, "e2e-ech-nolearn");

    let mut tcp = Client::connect(core.clone(), origin.port);
    let mut conn = handshake(&mut tcp, client_config(ca_der));
    let (head, _) = request(&mut tcp, &mut conn, "/ech-required");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    let (head, _) = request(&mut tcp, &mut conn, "/ech-required");
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert!(
        !core.ech_hosts.exempt("shop.test", crate::util::now_ms()),
        "a host that never advertised ECH must not be exempted"
    );
}

/// A flow whose ClientHello names a host the lists block is reset before the
/// handshake. Such a flow exists only because the client resolved the name
/// without the engine's resolver (Secure DNS, a cached answer); answering its
/// requests would let them count as delivered, while a reset fails them the
/// way the resolver's NXDOMAIN would have.
#[test]
fn a_blocked_sni_resets_the_flow() {
    let origin = start_origin(HTML);
    let (core, ca_der) = setup_core_with_list(&origin, "blocked-sni", "||shop.test^\n");

    let tcp = Client::connect(core.clone(), origin.port);
    let mut browser = ClientConnection::new(
        client_config(ca_der),
        ServerName::try_from("shop.test").expect("server name"),
    )
    .expect("client connection");
    let hello = tls::take_client_outbound(&mut browser);
    assert!(!hello.is_empty(), "the browser has a first flight");

    let pkt = tcp_packet(
        ORIGIN_IP,
        ACK | PSH,
        tcp.seq,
        tcp.their_seq,
        origin.port,
        &hello,
        &[],
    );
    let out = core.handle_packet(&pkt);
    let reset = out
        .iter()
        .any(|raw| Packet::parse(raw).is_some_and(|p| p.is_rst && p.src_port == origin.port));
    assert!(reset, "the blocked flow must be reset, not answered");
}
