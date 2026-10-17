//! Engine end-to-end test: synthetic TCP packets → `Core::handle_packet` →
//! real TLS handshake → real HTTP → injected cosmetic payload.
//!
//! Nothing in the middle is mocked. The client side is a hand-rolled TCP stack
//! driving rustls; the origin is a loopback rustls server; between them run the
//! real relay, the MITM splice, the injector and the local script endpoints.
//! This is the only test that would catch a break in how the pieces line up —
//! a wrong sequence number, a handshake byte stuck behind the window, an
//! injection that never reaches the client.

use crate::engine::{Config, Core};
use crate::filter::{FilterListInfo, ListFormat};
use crate::mitm::ca::CertificateAuthority;
use crate::mitm::script::UserScript;
use crate::mitm::tls;
use crate::packet::{self, Packet, ACK, PSH, SYN};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
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

/// Builds one IPv4+TCP packet from the "device" to the origin.
fn tcp_packet(flags: u8, seq: u32, ack: u32, dst_port: u16, payload: &[u8], options: &[u8]) -> Vec<u8> {
    let tcp_hdr = 20 + options.len();
    let total = 20 + tcp_hdr + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 6, 0x00, 0x00]);
    p.extend_from_slice(&CLIENT_IP);
    p.extend_from_slice(&ORIGIN_IP);
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
        let mut c = Client {
            core,
            dst_port,
            seq: 1000,
            their_seq: 0,
            pending: BTreeMap::new(),
            buf: Vec::new(),
        };
        // MSS option so the relay's segmentation matches a real client's.
        let syn = tcp_packet(SYN, c.seq, 0, dst_port, &[], &[2, 4, 0x05, 0xb4]);
        let out = c.core.handle_packet(&syn);
        let syn_ack = out
            .iter()
            .find_map(|raw| Packet::parse(raw))
            .filter(|p| p.is_syn && p.is_ack)
            .expect("the engine must answer the SYN");
        c.their_seq = syn_ack.seq.wrapping_add(1);
        c.seq = c.seq.wrapping_add(1);
        let ack = tcp_packet(ACK, c.seq, c.their_seq, dst_port, &[], &[]);
        let out = c.core.handle_packet(&ack);
        c.absorb(out);
        c
    }

    /// Feeds `data` as segments, exactly what a socket write produces.
    fn send(&mut self, data: &[u8]) {
        for chunk in data.chunks(MSS) {
            let pkt = tcp_packet(ACK | PSH, self.seq, self.their_seq, self.dst_port, chunk, &[]);
            self.seq = self.seq.wrapping_add(chunk.len() as u32);
            let out = self.core.handle_packet(&pkt);
            self.absorb(out);
        }
    }

    /// A bare ACK: acknowledges everything received and funds the next burst.
    fn ack(&mut self) {
        let pkt = tcp_packet(ACK, self.seq, self.their_seq, self.dst_port, &[], &[]);
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
        let fin = tcp_packet(ACK | 0x01, self.seq, self.their_seq, self.dst_port, &[], &[]);
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
            let response: Vec<u8> = if line.starts_with("GET / ") {
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
    let name = ServerName::try_from("shop.test").expect("server name");
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
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    raw.len() >= head_end + len
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

/// Same, with extra request headers (each line already ending in CRLF).
fn request_with(
    tcp: &mut Client,
    conn: &mut ClientConnection,
    path: &str,
    extra: &str,
) -> (String, Vec<u8>) {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: shop.test\r\nConnection: keep-alive\r\n{extra}\r\n"
    );
    conn.writer().write_all(req.as_bytes()).expect("write request");
    flush_tls(tcp, conn);

    let mut raw = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if complete_response(&raw) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "response timeout for {path}: {} bytes so far",
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
        .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().to_string()))
        .and_then(|v| v.parse().ok())
        .unwrap_or(body.len());
    body.truncate(declared);
    (head, body)
}

/// The list the engine is given: every cosmetic rule shape in one place.
const LIST: &str = "! Title: e2e cosmetic\n\
                    shop.test##.ad-box\n\
                    shop.test#$#.banner { margin: 0 }\n\
                    shop.test#?#.sponsored:has-text(Sponsored)\n\
                    shop.test#%#//scriptlet('set-constant', 'adBlocked', 'true')\n\
                    ##.adsbygoogle\n\
                    ###slot-1\n";

/// The page the origin serves: tokens for generic rules, and a matching
/// element for the procedural one.
const HTML: &str = "<!doctype html><html><head><title>e2e</title></head>\
                    <body><div class=\"ad-box\">ad</div>\
                    <div class=\"adsbygoogle\" id=\"slot-1\">ad</div>\
                    <p class=\"sponsored\">Sponsored content</p></body></html>";

fn setup_core(origin: &Origin) -> (Arc<Core>, Vec<u8>) {
    setup_core_named(origin, "e2e")
}

fn setup_core_named(origin: &Origin, tag: &str) -> (Arc<Core>, Vec<u8>) {
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
    core.set_upstream_tls_config(tls::client_config_with(roots));

    // Filter list from disk, exactly like the app ships them.
    let dir = std::env::temp_dir().join("adfree-e2e");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join(format!("{tag}-list.txt"));
    std::fs::write(&path, LIST).expect("write list");
    core.set_lists(
        vec![FilterListInfo {
            id: 1,
            name: "e2e".to_string(),
            url: String::new(),
            enabled: true,
            local_path: Some(path),
            format: ListFormat::Standard,
            category: 0,
            rule_count: 0,
            last_error: None,
        }],
        Vec::new(),
    );

    // A user script large enough to force window-limited bursts.
    let body = format!("/* e2e-marker */window.__adfree_e2e=\"{}\";", "x".repeat(300_000));
    {
        let mut scripts = core.mitm_scripts.write().unwrap();
        scripts.replace_all(vec![UserScript {
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
    assert!(
        !head.to_lowercase().contains("content-security-policy"),
        "CSP must be stripped: {head}"
    );
    let page = String::from_utf8_lossy(&body);
    assert!(page.contains("window.__adfree_page="), "payload injected");
    assert!(
        page.contains("<script src=\"/adfree-page.js?h="),
        "runtime tag injected"
    );
    assert!(
        page.contains("<script src=\"/adfree-user.js?h="),
        "user script tag injected"
    );
    // Element hiding left the payload: it travels as a stylesheet the browser
    // fetches once per site, and its URL hashes exactly what it serves.
    let href = hide_href(&page);
    assert!(href.starts_with("/adfree-hide.css?h="), "{href}");
    assert!(!page.contains("\"hide\""), "hiding left the payload: {page}");
    assert!(
        !page.contains("display:none"),
        "no CSS belongs inline any more: {page}"
    );
    // Style action, scriptlet and the hostname rules.
    assert!(page.contains("\".banner\""), "style rule missing: {page}");
    assert!(page.contains("setConstant"), "scriptlet missing: {page}");
    assert!(page.contains("adBlocked"), "scriptlet args missing: {page}");
    assert!(page.contains("has-text"), "procedural rule missing: {page}");
    // Generic class/id rules, matched from the HTML the proxy scanned.
    assert!(page.contains("\".adsbygoogle\""), "class rule missing: {page}");
    assert!(page.contains("\"#slot-1\""), "id rule missing: {page}");
    // The origin's own content survived the rewrite.
    assert!(page.contains("Sponsored content"), "the page itself is intact");

    // 3. The page runtime is served locally.
    let (head, body) = request(&mut tcp, &mut conn, "/adfree-page.js");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let runtime = String::from_utf8_lossy(&body);
    assert!(
        runtime.contains("window.__adfree_page"),
        "the runtime must consume the inline payload"
    );
    assert!(runtime.contains("MutationObserver"), "the runtime must watch the DOM");
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

#[test]
fn compressed_and_chunked_pages_are_still_filtered() {
    for mode in [OriginBody::Gzip, OriginBody::Chunked] {
        let origin = start_origin_mode(HTML, mode);
        let (core, ca_der) = setup_core_named(&origin, "e2e-framing");

        let mut tcp = Client::connect(core.clone(), origin.port);
        let mut conn = handshake(&mut tcp, client_config(ca_der));

        let (head, body) = request(&mut tcp, &mut conn, "/");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        let lower = head.to_lowercase();
        assert!(
            !lower.contains("content-security-policy"),
            "CSP must be stripped whatever the framing: {head}"
        );

        let page = match mode {
            OriginBody::Gzip => {
                assert!(
                    lower.contains("content-encoding: gzip"),
                    "the page must still travel compressed: {head}"
                );
                let decoded = crate::mitm::http::decode_body(&body, crate::mitm::http::Encoding::Gzip)
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
            page.contains("window.__adfree_page="),
            "the payload must be injected into a {mode:?} page: {page}"
        );
        let href = hide_href(&page);
        assert!(
            href.starts_with("/adfree-hide.css?h="),
            "hiding travels as a stylesheet into a {mode:?} page: {href}"
        );
        assert!(page.contains("\"#slot-1\""), "generic rules must be scanned: {page}");
        assert!(page.contains("Sponsored content"), "the page itself is intact: {page}");
        tcp.close();
    }
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
    conn.writer().write_all(req.as_bytes()).expect("write request");
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
    assert!(!lower.contains("content-security-policy"), "{head}");

    let page = String::from_utf8(body).expect("utf8");
    assert!(
        page.contains("<script src=\"/adfree-page.js?h="),
        "the runtime tag must be injected"
    );
    assert!(
        page.contains("<script src=\"/adfree-user.js?h="),
        "the user script tag must be injected"
    );
    assert!(
        page.contains("window.__adfree_page="),
        "the payload must be injected"
    );
    // Hostname rules come from the URL, so they are there even though the scan
    // only saw the head of the document — as the stylesheet the browser caches.
    let href = hide_href(&page);
    assert!(href.starts_with("/adfree-hide.css?h="), "{href}");
    assert!(!page.contains("\"hide\""), "hiding left the payload: {page}");
    // The tag has to land before the body renders, and nothing may be lost.
    let tag = page.find("/adfree-user.js").expect("tag");
    let head_close = page.find("</head>").expect("</head>");
    assert!(tag < head_close, "the tag must land inside the head");
    assert_eq!(page.matches("</head>").count(), 1, "no duplicated parts");
    assert!(page.ends_with("</body></html>"), "the page must be complete");
    assert!(page.contains("ad-box"), "the origin's own content survived");

    tcp.close();
}
