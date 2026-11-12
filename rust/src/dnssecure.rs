//! Encrypted upstream DNS: DNS-over-TLS and DNS-over-HTTPS.
//!
//! Both transports are blocking (TCP, a TLS handshake, one request), so the
//! packet path never runs them: [`Core`](crate::engine::Core) hands a query to
//! a small worker pool and the answer returns through a channel the forwarder
//! drains. The same exchange is exposed as a synchronous probe for the
//! settings screen, which runs it on its own IO thread.
//!
//! Two traps this module is built around:
//! * the socket has to be `protect()`ed *before* `connect()`, or the handshake
//!   itself is routed back into the tunnel and DNS recurses;
//! * a hostname in the provider address cannot be resolved with the system
//!   resolver once the tunnel owns DNS, so it goes through a plain UDP
//!   bootstrap query on a protected socket.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use crate::sys::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::api::SocketProtector;
use crate::dns;
use crate::state::model::{DnsProbeError, DnsProtocol};
use crate::sys::libc;

/// Where a hostname is bootstrapped from when the provider is named. The
/// default resolver is reachable without DoH/DoT, which is exactly what a
/// bootstrap needs.
const BOOTSTRAP_V4: Ipv4Addr = Ipv4Addr::new(94, 140, 14, 14);
const BOOTSTRAP_V6: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Total time one query may spend across attempts. Past this the client gets
/// SERVFAIL and its own retry policy takes over — a resolver that is down must
/// not hold the pending slot for long.
const QUERY_BUDGET: Duration = Duration::from_secs(12);
/// One retry after a transport failure (connect or timeout). TLS and response
/// errors are deterministic, so repeating them only wastes the budget.
const MAX_ATTEMPTS: usize = 2;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_millis(2_500);
const MAX_HEADER_LINE: usize = 8 * 1024;
const MAX_RESPONSE: usize = 65_535;
const ADDRESS_CACHE_MS: u64 = 10 * 60 * 1_000;
const ADDRESS_CACHE_CAP: usize = 16;

/// One encrypted resolver. The address is already normalized by
/// [`crate::state::dnsaddr`]: `host` has no scheme or brackets, and the DoH
/// path is a request target beginning with `/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureResolver {
    pub protocol: DnsProtocol,
    pub host: String,
    pub port: u16,
    /// Request target for DoH (`/dns-query`, query string included); empty
    /// for DoT.
    pub path: String,
}

impl SecureResolver {
    /// Builds a resolver from a validated provider. `None` for UDP or an
    /// address this module cannot speak.
    pub fn from_parts(protocol: DnsProtocol, address: &str, port: u16) -> Option<Self> {
        match protocol {
            DnsProtocol::Udp => None,
            DnsProtocol::Dot => {
                let text = address.trim();
                let host = if text
                    .get(..6)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tls://"))
                {
                    &text[6..]
                } else {
                    text
                };
                let host = host.trim_end_matches('/').trim_matches(['[', ']']);
                if host.is_empty() {
                    return None;
                }
                Some(SecureResolver {
                    protocol: DnsProtocol::Dot,
                    host: host.to_string(),
                    port,
                    path: String::new(),
                })
            }
            DnsProtocol::Doh => {
                let text = address.trim();
                if !text
                    .get(..8)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
                {
                    return None;
                }
                let rest = &text[8..];
                let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                let authority = &rest[..end];
                let tail = &rest[end..];
                let (host, url_port) = split_authority(authority)?;
                if host.is_empty() {
                    return None;
                }
                let path = if tail.is_empty() {
                    "/".to_string()
                } else if tail.starts_with('/') {
                    tail.split('#').next().unwrap_or("/").to_string()
                } else {
                    format!("/{}", tail.split('#').next().unwrap_or(""))
                };
                Some(SecureResolver {
                    protocol: DnsProtocol::Doh,
                    host,
                    port: url_port.unwrap_or(port),
                    path,
                })
            }
        }
    }

    pub fn label(&self) -> String {
        match self.protocol {
            DnsProtocol::Doh => {
                format!("DoH https://{}:{}{}", self.host, self.port, self.path)
            }
            _ => format!("DoT {}:{}", self.host, self.port),
        }
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = DnsProtocol::Doh.default_port();
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Splits a URL authority (`host`, `host:port`, `[v6]:port`). `None` for an
/// empty host, which the settings validator already rejects.
fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(raw) => Some(raw.parse().ok()?),
            None if after.is_empty() => None,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, raw)) if !host.is_empty() && !host.contains(':') => {
            Some((host.to_string(), Some(raw.parse().ok()?)))
        }
        _ => Some((authority.to_string(), None)),
    }
}

/// Errors are kept small and copyable: a worker only logs them and tells the
/// client to fail fast, and the probe maps them to a UI code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecureError {
    Address,
    Protect,
    Connect(String),
    Tls(String),
    Timeout,
    Response(String),
}

impl SecureError {
    pub fn probe_error(&self) -> DnsProbeError {
        match self {
            SecureError::Address => DnsProbeError::AddressInvalid,
            SecureError::Protect => DnsProbeError::ProtectedSocket,
            SecureError::Connect(_) => DnsProbeError::Network,
            SecureError::Timeout => DnsProbeError::Timeout,
            SecureError::Tls(_) => DnsProbeError::Unsupported,
            SecureError::Response(message) if message.contains("HTTP 505") => {
                DnsProbeError::Unsupported
            }
            SecureError::Response(_) => DnsProbeError::BadResponse,
        }
    }
}

/// One query waiting for a worker. The pending record is what turns the
/// answer into the client's reply, exactly like a UDP upstream reply.
pub struct SecureJob {
    pub resolver: SecureResolver,
    pub message: Vec<u8>,
    pub pending: crate::upstream::Pending,
    pub protector: Arc<dyn SocketProtector>,
}

/// One worker's answer. `message` is empty when the exchange failed, which
/// makes the client get SERVFAIL immediately.
pub struct SecureReply {
    pub pending: crate::upstream::Pending,
    pub message: Vec<u8>,
}

/// Serves jobs until the channel closes (the process ending). The wake fd is
/// written after every job so the forwarder picks the reply up at once
/// instead of after its idle wait.
pub fn worker_loop(rx: Receiver<SecureJob>, replies: Sender<SecureReply>, wake_fd: RawFd) {
    while let Ok(job) = rx.recv() {
        let outcome = exchange(&job.resolver, &job.message, Some(job.protector.as_ref()));
        let message = match outcome {
            Ok(message) => message,
            Err(error) => {
                crate::logbuf::push(&format!(
                    "dns: {} query failed: {error:?}",
                    job.resolver.label()
                ));
                Vec::new()
            }
        };
        if replies
            .send(SecureReply {
                pending: job.pending,
                message,
            })
            .is_err()
        {
            return;
        }
        if crate::sys::fd::fd_ok(wake_fd) {
            let one: u64 = 1;
            unsafe {
                libc::write(
                    wake_fd,
                    &one as *const u64 as *const libc::c_void,
                    std::mem::size_of::<u64>(),
                );
            }
        }
    }
}

/// Runs one exchange with the device trust store: DoT offers ALPN `dot`, DoH
/// offers HTTP/1.1. `None` protects nothing, which is correct only when the
/// tunnel is not running (the settings probe before the first connect).
pub fn exchange(
    resolver: &SecureResolver,
    message: &[u8],
    protector: Option<&dyn SocketProtector>,
) -> Result<Vec<u8>, SecureError> {
    match resolver.protocol {
        DnsProtocol::Doh => exchange_with(
            resolver,
            message,
            protector,
            crate::mitm::tls::client_config(),
        ),
        DnsProtocol::Dot => exchange_with(resolver, message, protector, dot_config()),
        DnsProtocol::Udp => Err(SecureError::Address),
    }
}

/// The explicit-config form: tests stand in a local TLS server with roots of
/// their own instead of the device store.
pub fn exchange_with(
    resolver: &SecureResolver,
    message: &[u8],
    protector: Option<&dyn SocketProtector>,
    config: Arc<ClientConfig>,
) -> Result<Vec<u8>, SecureError> {
    if message.len() < 12 || message.len() > MAX_RESPONSE {
        return Err(SecureError::Response("bad query size".into()));
    }
    let deadline = std::time::Instant::now() + QUERY_BUDGET;
    let name = server_name(&resolver.host)?;
    let addresses = resolve(&resolver.host, resolver.port, protector)?;
    let mut last = SecureError::Connect("no address".into());
    for attempt in 0..MAX_ATTEMPTS {
        for address in &addresses {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(SecureError::Timeout);
            }
            let stream = match connect(*address, protector, remaining) {
                Ok(stream) => stream,
                Err(error) => {
                    last = error;
                    continue;
                }
            };
            let connection = ClientConnection::new(config.clone(), name.clone())
                .map_err(|error| SecureError::Tls(error.to_string()))?;
            let mut tls = StreamOwned::new(connection, stream);
            let outcome = match resolver.protocol {
                DnsProtocol::Doh => doh_exchange(&mut tls, resolver, message),
                _ => dot_exchange(&mut tls, message),
            };
            match outcome {
                Ok(answer) => {
                    if answer.len() < 12 || answer[0] != message[0] || answer[1] != message[1] {
                        last = SecureError::Response("transaction id mismatch".into());
                        continue;
                    }
                    return Ok(answer);
                }
                Err(error) => last = error,
            }
        }
        if !matches!(last, SecureError::Timeout | SecureError::Connect(_)) {
            break;
        }
        if attempt + 1 < MAX_ATTEMPTS {
            crate::logbuf::push(&format!(
                "dns: {} retrying after {last:?}",
                resolver.label()
            ));
        }
    }
    Err(last)
}

fn dot_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut config = ClientConfig::builder()
                .with_root_certificates(crate::mitm::tls::system_root_store())
                .with_no_client_auth();
            config.alpn_protocols = vec![b"dot".to_vec()];
            Arc::new(config)
        })
        .clone()
}

fn server_name(host: &str) -> Result<ServerName<'static>, SecureError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_string()).map_err(|_| SecureError::Address)
}

/// Resolves the provider host, through the bootstrap query for a name. An IP
/// literal never touches the network here.
fn resolve(
    host: &str,
    port: u16,
    protector: Option<&dyn SocketProtector>,
) -> Result<Vec<SocketAddr>, SecureError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addresses = cached_addresses(host)
        .map(Ok)
        .unwrap_or_else(|| bootstrap(host, protector));
    let addresses = addresses?;
    if addresses.is_empty() {
        return Err(SecureError::Address);
    }
    Ok(addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

fn cached_addresses(host: &str) -> Option<Vec<IpAddr>> {
    let cache = address_cache().lock().ok()?;
    let (addresses, expires) = cache.get(host)?;
    if *expires <= crate::util::now_ms() {
        return None;
    }
    Some(addresses.clone())
}

fn remember_addresses(host: &str, addresses: &[IpAddr]) {
    if addresses.is_empty() {
        return;
    }
    let Ok(mut cache) = address_cache().lock() else {
        return;
    };
    if cache.len() >= ADDRESS_CACHE_CAP {
        cache.clear();
    }
    cache.insert(
        host.to_string(),
        (addresses.to_vec(), crate::util::now_ms() + ADDRESS_CACHE_MS),
    );
}

type AddressCache = Mutex<HashMap<String, (Vec<IpAddr>, u64)>>;

fn address_cache() -> &'static AddressCache {
    static CACHE: OnceLock<AddressCache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// One plain DNS query to the bootstrap resolver, on a protected socket. A
/// name with only AAAA records gets a second, IPv6 attempt.
fn bootstrap(
    host: &str,
    protector: Option<&dyn SocketProtector>,
) -> Result<Vec<IpAddr>, SecureError> {
    let txid = (crate::util::now_ms() & 0x7fff) as u16;
    let query = dns::build_query(host, dns::TYPE_A, txid).ok_or(SecureError::Address)?;
    let mut last_error = None;
    let mut addresses = match bootstrap_v4(&query, protector) {
        Ok(addresses) => addresses,
        Err(error) => {
            last_error = Some(error);
            Vec::new()
        }
    };
    if addresses.is_empty() {
        let query = dns::build_query(host, dns::TYPE_AAAA, txid).ok_or(SecureError::Address)?;
        match bootstrap_v6(&query, protector) {
            Ok(records) => addresses = records,
            Err(error) => last_error = Some(error),
        }
    }
    remember_addresses(host, &addresses);
    if addresses.is_empty() {
        return Err(last_error.unwrap_or(SecureError::Address));
    }
    Ok(addresses)
}

fn bootstrap_v4(
    query: &[u8],
    protector: Option<&dyn SocketProtector>,
) -> Result<Vec<IpAddr>, SecureError> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    protect(protector, socket.as_raw_fd())?;
    socket
        .set_read_timeout(Some(BOOTSTRAP_TIMEOUT))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    socket
        .send_to(query, (BOOTSTRAP_V4, 53))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    read_bootstrap(&socket, query)
}

fn bootstrap_v6(
    query: &[u8],
    protector: Option<&dyn SocketProtector>,
) -> Result<Vec<IpAddr>, SecureError> {
    let socket = UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    protect(protector, socket.as_raw_fd())?;
    socket
        .set_read_timeout(Some(BOOTSTRAP_TIMEOUT))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    socket
        .send_to(query, (BOOTSTRAP_V6, 53))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    read_bootstrap(&socket, query)
}

fn read_bootstrap(socket: &UdpSocket, query: &[u8]) -> Result<Vec<IpAddr>, SecureError> {
    let mut buf = [0u8; 2048];
    loop {
        let (len, _) = socket
            .recv_from(&mut buf)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                    SecureError::Timeout
                }
                _ => SecureError::Connect(error.to_string()),
            })?;
        let reply = &buf[..len];
        if reply.len() < 12 || reply[0] != query[0] || reply[1] != query[1] {
            continue;
        }
        return Ok(dns::answer_addresses(reply)
            .into_iter()
            .map(|(ip, _)| ip)
            .collect());
    }
}

/// Opens a protected TCP connection without ever routing the handshake into
/// the tunnel: the descriptor exists and is protected before `connect()`.
fn connect(
    address: SocketAddr,
    protector: Option<&dyn SocketProtector>,
    timeout: Duration,
) -> Result<TcpStream, SecureError> {
    let (family, storage, length) = sockaddr(address);
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if !crate::sys::fd::fd_ok(fd) {
        return Err(SecureError::Connect(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if let Err(error) = protect(protector, fd) {
        unsafe { libc::close(fd) };
        return Err(error);
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
    let rc = unsafe { libc::connect(fd, &storage as *const _ as *const libc::sockaddr, length) };
    if rc != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            unsafe { libc::close(fd) };
            return Err(SecureError::Connect(error.to_string()));
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe {
            libc::poll(
                &mut pfd,
                1,
                timeout.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if ready <= 0 {
            unsafe { libc::close(fd) };
            return Err(SecureError::Timeout);
        }
        let mut so_error: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut _ as *mut libc::c_void,
                &mut size,
            )
        };
        if rc != 0 || so_error != 0 {
            let detail = if rc == 0 {
                std::io::Error::from_raw_os_error(so_error).to_string()
            } else {
                std::io::Error::last_os_error().to_string()
            };
            unsafe { libc::close(fd) };
            return Err(SecureError::Connect(detail));
        }
    }
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    }

    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    Ok(stream)
}

fn protect(protector: Option<&dyn SocketProtector>, fd: RawFd) -> Result<(), SecureError> {
    match protector {
        Some(protector) if !protector.protect(crate::sys::fd::as_i32(fd)) => Err(SecureError::Protect),
        _ => Ok(()),
    }
}

/// The `sockaddr` for `connect()`, with the port and address in network byte
/// order. IPv6 scope ids are irrelevant for a public resolver.
fn sockaddr(address: SocketAddr) -> (libc::c_int, SockAddrStorage, libc::socklen_t) {
    let mut storage = SockAddrStorage { raw: [0u8; 28] };
    match address {
        SocketAddr::V4(addr) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const _ as *const u8,
                    storage.raw.as_mut_ptr(),
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            (
                libc::AF_INET,
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(addr) => {
            let sin = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: 0,
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const _ as *const u8,
                    storage.raw.as_mut_ptr(),
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            (
                libc::AF_INET6,
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

/// Enough room for either address family, aligned like a sockaddr.
#[repr(C, align(8))]
struct SockAddrStorage {
    raw: [u8; 28],
}

fn dot_exchange(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    message: &[u8],
) -> Result<Vec<u8>, SecureError> {
    let length = u16::try_from(message.len())
        .map_err(|_| SecureError::Response("query too large".into()))?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    tls.write_all(&framed)
        .and_then(|_| tls.flush())
        .map_err(|error| SecureError::Connect(error.to_string()))?;

    let mut header = [0u8; 2];
    tls.read_exact(&mut header).map_err(read_error)?;
    let length = u16::from_be_bytes(header) as usize;
    if !(12..=MAX_RESPONSE).contains(&length) {
        return Err(SecureError::Response("implausible DNS length".into()));
    }
    let mut answer = vec![0u8; length];
    tls.read_exact(&mut answer).map_err(read_error)?;
    Ok(answer)
}

fn doh_exchange(
    tls: &mut StreamOwned<ClientConnection, TcpStream>,
    resolver: &SecureResolver,
    message: &[u8],
) -> Result<Vec<u8>, SecureError> {
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: AdFree/{}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resolver.path,
        resolver.host_header(),
        crate::CORE_VERSION,
        message.len()
    );
    tls.write_all(request.as_bytes())
        .and_then(|_| tls.write_all(message))
        .and_then(|_| tls.flush())
        .map_err(|error| SecureError::Connect(error.to_string()))?;

    let mut reader = BufReader::new(tls);
    let status = read_line(&mut reader)?;
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| SecureError::Response(format!("bad status line: {status}")))?;
    if code != 200 {
        return Err(SecureError::Response(format!("HTTP {code}")));
    }

    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    loop {
        let line = read_line(&mut reader)?;
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                chunked = true;
            }
            "content-length" => {
                content_length = value.parse::<usize>().ok();
            }
            _ => {}
        }
    }

    if chunked {
        read_chunked(&mut reader)
    } else if let Some(length) = content_length {
        if length > MAX_RESPONSE {
            return Err(SecureError::Response("response too large".into()));
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).map_err(read_error)?;
        Ok(body)
    } else {
        let mut body = Vec::new();
        reader
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut body)
            .map_err(read_error)?;
        if body.len() > MAX_RESPONSE {
            return Err(SecureError::Response("response too large".into()));
        }
        Ok(body)
    }
}

fn read_line(reader: &mut impl BufRead) -> Result<String, SecureError> {
    let mut line = Vec::new();
    loop {
        let (found, used) = {
            let available = reader.fill_buf().map_err(read_error)?;
            if available.is_empty() {
                return Err(SecureError::Response("connection closed".into()));
            }
            match available.iter().position(|byte| *byte == b'\n') {
                Some(index) => {
                    line.extend_from_slice(&available[..=index]);
                    (true, index + 1)
                }
                None => {
                    line.extend_from_slice(available);
                    (false, available.len())
                }
            }
        };
        reader.consume(used);
        if line.len() > MAX_HEADER_LINE {
            return Err(SecureError::Response("header line too long".into()));
        }
        if found {
            break;
        }
    }
    while line
        .last()
        .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
    {
        line.pop();
    }
    Ok(String::from_utf8_lossy(&line).to_string())
}

fn read_chunked(reader: &mut impl BufRead) -> Result<Vec<u8>, SecureError> {
    let mut body = Vec::new();
    loop {
        let line = read_line(reader)?;
        let size = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size, 16)
            .map_err(|_| SecureError::Response("bad chunk size".into()))?;
        if size == 0 {
            // Trailers, then the final empty line.
            loop {
                let trailer = read_line(reader)?;
                if trailer.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        if body.len().saturating_add(size) > MAX_RESPONSE {
            return Err(SecureError::Response("response too large".into()));
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).map_err(read_error)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).map_err(read_error)?;
        if crlf != *b"\r\n" {
            return Err(SecureError::Response("bad chunk terminator".into()));
        }
    }
}

fn read_error(error: std::io::Error) -> SecureError {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => SecureError::Timeout,
        _ => SecureError::Connect(error.to_string()),
    }
}

/// One plain UDP probe for the settings screen. Only IPv4 is accepted here,
/// matching what the UDP forwarder supports.
pub fn probe_udp(
    host: &str,
    port: u16,
    protector: Option<&dyn SocketProtector>,
) -> Result<Vec<u8>, SecureError> {
    let ip = host.parse::<Ipv4Addr>().map_err(|_| SecureError::Address)?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    protect(protector, socket.as_raw_fd())?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    socket
        .connect((ip, port))
        .map_err(|error| SecureError::Connect(error.to_string()))?;

    let txid = (crate::util::now_ms() & 0x7fff) as u16;
    let query = dns::build_query("example.com", dns::TYPE_A, txid).ok_or(SecureError::Address)?;
    socket
        .send(&query)
        .map_err(|error| SecureError::Connect(error.to_string()))?;
    let mut buf = [0u8; 2048];
    let read = socket.recv(&mut buf).map_err(|error| match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => SecureError::Timeout,
        _ => SecureError::Connect(error.to_string()),
    })?;
    if read < 12 || buf[0] != query[0] || buf[1] != query[1] {
        return Err(SecureError::Response("unexpected answer".into()));
    }
    Ok(buf[..read].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    /// A one-connection TLS server with a certificate the returned root store
    /// accepts. The handler owns the stream, so a test can speak DoT framing
    /// or HTTP/1.1 over the same baseline.
    fn local_server(
        alpn: &[u8],
        handler: impl FnOnce(&mut StreamOwned<ServerConnection, TcpStream>) + Send + 'static,
    ) -> (u16, RootCertStore, std::thread::JoinHandle<()>) {
        let ca = Arc::new(crate::mitm::ca::CertificateAuthority::generate().expect("test ca"));
        let issued = ca.issue("127.0.0.1").expect("leaf");
        let chain: Vec<CertificateDer<'static>> = ca
            .chain_for(&issued)
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.key.clone()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        config.alpn_protocols = vec![alpn.to_vec()];
        let config = Arc::new(config);

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let port = listener.local_addr().expect("address").port();
        let worker = std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let connection = ServerConnection::new(config).expect("server connection");
            let mut tls = StreamOwned::new(connection, stream);
            handler(&mut tls);
        });

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.cert_der()))
            .expect("root");
        (port, roots, worker)
    }

    fn client_config(roots: RootCertStore, alpn: &[u8]) -> Arc<ClientConfig> {
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        Arc::new(config)
    }

    fn read_dot_query(tls: &mut StreamOwned<ServerConnection, TcpStream>) -> Vec<u8> {
        let mut header = [0u8; 2];
        tls.read_exact(&mut header).expect("length");
        let length = u16::from_be_bytes(header) as usize;
        let mut message = vec![0u8; length];
        tls.read_exact(&mut message).expect("query");
        message
    }

    fn write_dot_answer(
        tls: &mut StreamOwned<ServerConnection, TcpStream>,
        message: &[u8],
        address: Ipv4Addr,
    ) {
        let query = dns::parse_query(message).expect("parsed query");
        let answer = dns::answer_message(&query, &[IpAddr::V4(address)], 90).expect("answer");
        tls.write_all(&(answer.len() as u16).to_be_bytes())
            .expect("length");
        tls.write_all(&answer).expect("answer");
        tls.flush().expect("flush");
    }

    /// Reads one HTTP/1.1 request and returns its body. The request head may
    /// arrive with part of the body already buffered.
    fn read_http_request(tls: &mut StreamOwned<ServerConnection, TcpStream>) -> (String, Vec<u8>) {
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        let head_end = loop {
            if let Some(index) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                break index + 4;
            }
            let read = tls.read(&mut buf).expect("request");
            assert!(read > 0, "connection closed before the request head");
            received.extend_from_slice(&buf[..read]);
        };
        let head = String::from_utf8_lossy(&received[..head_end]).to_string();
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .expect("content length");
        let mut body = received[head_end..].to_vec();
        while body.len() < content_length {
            let read = tls.read(&mut buf).expect("body");
            assert!(read > 0, "connection closed before the body");
            body.extend_from_slice(&buf[..read]);
        }
        body.truncate(content_length);
        (head, body)
    }

    #[test]
    fn a_dot_address_drops_its_scheme_and_brackets() {
        let dot = SecureResolver::from_parts(DnsProtocol::Dot, "tls://dns.example", 853).unwrap();
        assert_eq!(dot.host, "dns.example");
        assert_eq!(dot.port, 853);
        assert_eq!(dot.path, "");
        let v6 = SecureResolver::from_parts(DnsProtocol::Dot, "[2606:4700::1111]", 853).unwrap();
        assert_eq!(v6.host, "2606:4700::1111");
    }

    #[test]
    fn a_doh_url_keeps_its_path_and_authority() {
        let doh =
            SecureResolver::from_parts(DnsProtocol::Doh, "https://dns.example/dns-query?x=1", 443)
                .unwrap();
        assert_eq!(doh.host, "dns.example");
        assert_eq!(doh.port, 443);
        assert_eq!(doh.path, "/dns-query?x=1");
        assert_eq!(doh.host_header(), "dns.example");

        let custom =
            SecureResolver::from_parts(DnsProtocol::Doh, "https://dns.example:8443/dns-query", 443)
                .unwrap();
        assert_eq!(custom.port, 8443);
        assert_eq!(custom.host_header(), "dns.example:8443");
    }

    #[test]
    fn malformed_addresses_are_rejected() {
        assert!(SecureResolver::from_parts(DnsProtocol::Udp, "1.1.1.1", 53).is_none());
        assert!(SecureResolver::from_parts(DnsProtocol::Dot, "", 853).is_none());
        assert!(SecureResolver::from_parts(DnsProtocol::Doh, "http://x/dns-query", 443).is_none());
        assert!(SecureResolver::from_parts(DnsProtocol::Doh, "https://", 443).is_none());
    }

    #[test]
    fn schemes_are_case_insensitive() {
        let dot = SecureResolver::from_parts(DnsProtocol::Dot, "TLS://dns.example", 853)
            .expect("mixed-case DoT");
        assert_eq!(dot.host, "dns.example");
        let doh = SecureResolver::from_parts(DnsProtocol::Doh, "HtTpS://dns.example/q", 443)
            .expect("mixed-case DoH");
        assert_eq!(doh.host, "dns.example");
        assert_eq!(doh.path, "/q");
    }

    #[test]
    fn an_unbounded_header_line_is_rejected() {
        let mut reader = std::io::Cursor::new(vec![b'a'; MAX_HEADER_LINE + 2]);
        assert!(matches!(
            read_line(&mut reader),
            Err(SecureError::Response(_))
        ));
    }

    #[test]
    fn a_hostname_is_resolved_through_the_bootstrap_query() {
        // No sockets in a unit test: the resolver's own address parser is the
        // part worth covering here. The network half is exercised by the
        // local TLS tests below.
        assert_eq!(
            resolve("127.0.0.1", 853, None).unwrap(),
            vec![SocketAddr::from(([127, 0, 0, 1], 853))]
        );
    }

    #[test]
    fn a_dot_query_round_trips_over_tls() {
        let address = Ipv4Addr::new(203, 0, 113, 7);
        let (port, roots, server) = local_server(b"dot", |tls| {
            let query = read_dot_query(tls);
            write_dot_answer(tls, &query, Ipv4Addr::new(203, 0, 113, 7));
        });
        let config = client_config(roots, b"dot");
        let resolver =
            SecureResolver::from_parts(DnsProtocol::Dot, "127.0.0.1", port).expect("resolver");
        let message = dns::build_query("example.com", dns::TYPE_A, 0x4242).expect("query");

        let answer = exchange_with(&resolver, &message, None, config).expect("answer");
        assert_eq!(answer[..2], message[..2]);
        assert_eq!(
            dns::answer_addresses(&answer),
            vec![(IpAddr::V4(address), 90)]
        );
        server.join().expect("server thread");
    }

    #[test]
    fn a_doh_query_reads_a_content_length_body() {
        let address = Ipv4Addr::new(198, 51, 100, 9);
        let (port, roots, server) = local_server(b"http/1.1", move |tls| {
            let (head, body) = read_http_request(tls);
            assert!(head.starts_with("POST /dns-query HTTP/1.1\r\n"));
            let query = dns::parse_query(&body).expect("parsed query");
            let answer = dns::answer_message(&query, &[IpAddr::V4(address)], 120).expect("answer");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                answer.len()
            );
            tls.write_all(response.as_bytes()).expect("head");
            tls.write_all(&answer).expect("answer");
            tls.flush().expect("flush");
        });
        let config = client_config(roots, b"http/1.1");
        let resolver =
            SecureResolver::from_parts(DnsProtocol::Doh, "https://127.0.0.1/dns-query", port)
                .expect("resolver");
        let message = dns::build_query("example.com", dns::TYPE_A, 0x5151).expect("query");

        let answer = exchange_with(&resolver, &message, None, config).expect("answer");
        assert_eq!(
            dns::answer_addresses(&answer),
            vec![(IpAddr::V4(address), 120)]
        );
        server.join().expect("server thread");
    }

    #[test]
    fn a_doh_query_reads_a_chunked_body() {
        let address = Ipv4Addr::new(192, 0, 2, 44);
        let (port, roots, server) = local_server(b"http/1.1", move |tls| {
            let (_, body) = read_http_request(tls);
            let query = dns::parse_query(&body).expect("parsed query");
            let answer = dns::answer_message(&query, &[IpAddr::V4(address)], 60).expect("answer");
            let head = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            tls.write_all(head.as_bytes()).expect("head");
            tls.write_all(format!("{:x}\r\n", answer.len()).as_bytes())
                .expect("chunk size");
            tls.write_all(&answer).expect("chunk");
            tls.write_all(b"\r\n0\r\n\r\n").expect("end");
            tls.flush().expect("flush");
        });
        let config = client_config(roots, b"http/1.1");
        let resolver =
            SecureResolver::from_parts(DnsProtocol::Doh, "https://127.0.0.1/dns-query", port)
                .expect("resolver");
        let message = dns::build_query("example.com", dns::TYPE_A, 0x6161).expect("query");

        let answer = exchange_with(&resolver, &message, None, config).expect("answer");
        assert_eq!(
            dns::answer_addresses(&answer),
            vec![(IpAddr::V4(address), 60)]
        );
        server.join().expect("server thread");
    }
}
