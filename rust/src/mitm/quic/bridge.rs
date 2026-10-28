//! The seam between the packet engine and quinn.
//!
//! The engine is single-threaded and poll-based; quinn needs a tokio runtime.
//! One `adfree-quic` thread owns that runtime and every QUIC endpoint:
//!
//! ```text
//!   tun-thread ──handle_quic──► Bridge::open ──job──► endpoint per 5-tuple
//!        ▲                         │                      │
//!        └── drain() ◄── OutDatagram ── TunUdpSocket ◄────┘
//! ```
//!
//! The bridge never touches the engine's tables directly. Decisions that need
//! them (is this host excluded? did the app reject our certificate?) go through
//! [`Host`], which the engine implements on its own thread, so the packet path
//! keeps owning its locks and the QUIC thread never blocks on the tun.
//!
//! Hosts are keyed by the client's five-tuple. Everything above the transport
//! (HTTP/3 framing, request editing, response rewriting) lives in [`super::hub`]
//! and is shared with the tests that drive it over in-memory sockets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use quinn::{Endpoint, EndpointConfig, TokioRuntime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::engine::StealthConfig;
use crate::filter::FilterEngine;
use crate::mitm::proxy::MitmSink;
use crate::mitm::quic::hub::{self, HubConfig};
use crate::mitm::quic::socket::{OutDatagram, TunUdpSocket};
use crate::mitm::tls::{self, SniCertResolver, UpstreamTls};
use crate::udpnat::UdpKey;

/// Terminated QUIC flows one engine may hold at once. A browser opens one
/// connection per origin and a page rarely spans dozens of origins; past this
/// the flow is dropped like a congested NAT box would, and the client falls
/// back to TCP.
pub const MAX_FLOWS: usize = 64;

/// Datagrams queued towards the packet thread before `try_send` starts
/// counting drops. QUIC retransmits, so a full queue costs a round trip.
const OUTBOX_CAP: usize = 1024;

/// How long a terminated flow may sit without a datagram. QUIC connections
/// are long-lived (one per origin), so this only reaps the abandoned ones.
const IDLE: Duration = Duration::from_secs(60);

/// Bidirectional and unidirectional streams one connection may open. Browsers
/// keep a handful per origin; the cap is what stops one page from pinning the
/// whole runtime.
const MAX_STREAMS: u32 = 64;

/// Largest QUIC datagram that fits the tunnel's 1500-byte MTU over IPv6
/// (1500 − 40 IP − 8 UDP).
const TUNNEL_MAX_UDP: u16 = 1452;

/// What the hub needs to answer a request. Built on the packet path from the
/// same inputs the HTTP/1.1 splice uses, so the two paths filter identically.
pub struct FlowInfo {
    /// The original destination (the server address the client dialed).
    pub local: SocketAddr,
    pub apps: Vec<String>,
    pub filter: Arc<FilterEngine>,
    pub resolver: Arc<SniCertResolver>,
    pub cosmetic: Option<Arc<FilterEngine>>,
    pub stealth: StealthConfig,
    pub upstream: Arc<UpstreamTls>,
    pub serve_path: String,
    pub script_body: Arc<str>,
    pub script_tag_src: String,
    pub sink: Option<MitmSink>,
}

/// What the QUIC thread asks the engine, always from that thread.
pub trait Host: Send + Sync {
    /// The ClientHello named an excluded host (or one whose ECH requirement
    /// only a raw splice can honour). The engine has already moved the flow to
    /// the plain NAT path; `true` tells the resolver to refuse the handshake,
    /// which is what makes the client retry (and land on the NAT mapping).
    fn should_splice(&self, key: UdpKey, host: &str, apps: &[String]) -> bool;

    /// No transport could be built for this flow (no protected socket, runtime
    /// failure). The engine splices it instead of leaving the client hanging.
    fn abandon(&self, key: UdpKey);

    /// The client refused the forged certificate mid-handshake (`alert` is the
    /// TLS alert rustls received). The engine learns the app so its next
    /// connection is spliced, like the TCP path does.
    fn cert_rejected(&self, key: UdpKey, host: &str, apps: &[String], alert: u8);

    /// A protected, unconnected UDP socket for a shared upstream endpoint.
    fn upstream_socket(&self, ipv6: bool) -> Option<std::net::UdpSocket>;

    /// Poke the forwarder; a datagram is waiting to be drained.
    fn wake(&self);
}

/// [`Host`] on top of the process-wide engine.
pub struct CoreHost {
    core: &'static crate::engine::Core,
}

impl CoreHost {
    pub fn new(core: &'static crate::engine::Core) -> Arc<Self> {
        Arc::new(CoreHost { core })
    }
}

impl Host for CoreHost {
    fn should_splice(&self, key: UdpKey, host: &str, apps: &[String]) -> bool {
        self.core.h3_should_splice(key, host, apps)
    }

    fn abandon(&self, key: UdpKey) {
        self.core.h3_abandon(key);
    }

    fn cert_rejected(&self, key: UdpKey, host: &str, apps: &[String], alert: u8) {
        self.core.h3_cert_rejected(key, host, apps, alert);
    }

    fn upstream_socket(&self, ipv6: bool) -> Option<std::net::UdpSocket> {
        self.core.open_upstream_quic_socket(ipv6)
    }

    fn wake(&self) {
        self.core.wake();
    }
}

enum Job {
    Open {
        key: UdpKey,
        info: FlowInfo,
        socket: Arc<TunUdpSocket>,
    },
    Close {
        key: UdpKey,
    },
    CloseAll,
    Shutdown,
}

/// The engine-side handle: opens and closes flows, and hands out the datagrams
/// quinn produced. Everything is lock-free with respect to the packet path
/// except the outbound receiver, which only the forwarder drains.
pub struct Bridge {
    jobs: UnboundedSender<Job>,
    out_tx: SyncSender<OutDatagram>,
    out_rx: Mutex<Receiver<OutDatagram>>,
    waker: Arc<dyn Fn() + Send + Sync>,
}

impl Bridge {
    /// Spawns the QUIC thread. `None` when the thread cannot be created; the
    /// engine then keeps the old drop/relay behavior.
    pub fn start(host: Arc<dyn Host>) -> Option<(Arc<Self>, std::thread::JoinHandle<()>)> {
        let (out_tx, out_rx) = sync_channel(OUTBOX_CAP);
        let (jobs, job_rx) = unbounded_channel();
        let weak: Weak<dyn Host> = Arc::downgrade(&host);
        let waker: Arc<dyn Fn() + Send + Sync> = {
            let weak = weak.clone();
            Arc::new(move || {
                if let Some(host) = weak.upgrade() {
                    host.wake();
                }
            })
        };
        let bridge = Arc::new(Bridge {
            jobs,
            out_tx,
            out_rx: Mutex::new(out_rx),
            waker,
        });
        let worker = std::thread::Builder::new()
            .name("adfree-quic".into())
            .stack_size(1024 * 1024)
            .spawn(move || run(job_rx, host))
            .ok()?;
        Some((bridge, worker))
    }

    /// Starts terminating one client flow. The returned socket is where the
    /// engine feeds the client's datagrams from now on.
    pub fn open(&self, key: UdpKey, info: FlowInfo) -> Option<Arc<TunUdpSocket>> {
        let socket = TunUdpSocket::with_wake(
            info.local,
            self.out_tx.clone(),
            Some(Arc::clone(&self.waker)),
        );
        let job = Job::Open {
            key,
            info,
            socket: Arc::clone(&socket),
        };
        self.jobs.send(job).ok()?;
        Some(socket)
    }

    pub fn close(&self, key: UdpKey) {
        let _ = self.jobs.send(Job::Close { key });
    }

    pub fn close_all(&self) {
        let _ = self.jobs.send(Job::CloseAll);
    }

    pub fn shutdown(&self) {
        let _ = self.jobs.send(Job::Shutdown);
    }

    /// Moves up to `max` datagrams into `out` without blocking.
    pub fn drain(&self, out: &mut Vec<OutDatagram>, max: usize) {
        let Ok(rx) = self.out_rx.lock() else {
            return;
        };
        while out.len() < max {
            match rx.try_recv() {
                Ok(datagram) => out.push(datagram),
                Err(_) => break,
            }
        }
    }
}

/// The QUIC thread: one endpoint per flow, one shared endpoint per address
/// family for the upstream halves.
fn run(mut jobs: UnboundedReceiver<Job>, host: Arc<dyn Host>) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            crate::logbuf::push(&format!("quic bridge: no async runtime: {e}"));
            return;
        }
    };
    runtime.block_on(async move {
        let upstreams = Arc::new(Upstreams::new(Arc::clone(&host)));
        let mut flows: HashMap<UdpKey, Endpoint> = HashMap::new();
        while let Some(job) = jobs.recv().await {
            match job {
                Job::Open { key, info, socket } => {
                    if flows.len() >= MAX_FLOWS {
                        host.abandon(key);
                        continue;
                    }
                    match open_flow(key, info, socket, &host, &upstreams) {
                        Some(endpoint) => {
                            flows.insert(key, endpoint);
                        }
                        None => host.abandon(key),
                    }
                }
                Job::Close { key } => {
                    if let Some(endpoint) = flows.remove(&key) {
                        endpoint.close(quinn::VarInt::from_u32(0), b"flow closed");
                    }
                }
                Job::CloseAll => {
                    for (_, endpoint) in flows.drain() {
                        endpoint.close(quinn::VarInt::from_u32(0), b"flows closed");
                    }
                }
                Job::Shutdown => break,
            }
        }
        for (_, endpoint) in flows.drain() {
            endpoint.close(quinn::VarInt::from_u32(0), b"stopping");
        }
    });
    // Give the endpoints a moment to send their CONNECTION_CLOSE frames; the
    // thread is about to be joined by `Core::stop` callers.
    runtime.shutdown_timeout(Duration::from_millis(200));
}

fn open_flow(
    key: UdpKey,
    info: FlowInfo,
    socket: Arc<TunUdpSocket>,
    host: &Arc<dyn Host>,
    upstreams: &Arc<Upstreams>,
) -> Option<Endpoint> {
    let resolver = Arc::new(HubResolver {
        inner: Arc::clone(&info.resolver),
        captured: Mutex::new(None),
        key,
        apps: info.apps.clone(),
        host: Arc::clone(host),
        spliced: AtomicBool::new(false),
    });
    let tls = tls::server_config_h3(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);
    let mut server = match hub::quinn_server_config(tls) {
        Ok(server) => server,
        Err(e) => {
            crate::logbuf::push(&format!("quic: server config failed: {e}"));
            return None;
        }
    };
    server.transport_config(transport());
    let endpoint = match Endpoint::new_with_abstract_socket(
        endpoint_config(),
        Some(server),
        socket,
        Arc::new(TokioRuntime),
    ) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            crate::logbuf::push(&format!("quic: endpoint failed: {e}"));
            return None;
        }
    };
    tokio::spawn(accept_loop(
        endpoint.clone(),
        resolver,
        Arc::new(info),
        Arc::clone(upstreams),
    ));
    Some(endpoint)
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    if let Ok(idle) = quinn::IdleTimeout::try_from(IDLE) {
        transport.max_idle_timeout(Some(idle));
    }
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_STREAMS));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_STREAMS));
    Arc::new(transport)
}

/// The tunnel forwards 1500-byte IP packets, so a QUIC datagram may carry at
/// most 1452 bytes once IPv6's 48-byte header is added. quinn's default is
/// 1472 (the IPv4 limit); advertising it would let an IPv6 peer send packets
/// the tun cannot carry.
fn endpoint_config() -> EndpointConfig {
    let mut config = EndpointConfig::default();
    config
        .max_udp_payload_size(TUNNEL_MAX_UDP)
        .expect("1452 is within quinn's bounds");
    config
}

async fn accept_loop(
    endpoint: Endpoint,
    resolver: Arc<HubResolver>,
    info: Arc<FlowInfo>,
    upstreams: Arc<Upstreams>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let resolver = Arc::clone(&resolver);
        let info = Arc::clone(&info);
        let upstreams = Arc::clone(&upstreams);
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => serve(connection, resolver, info, upstreams).await,
                Err(error) => {
                    // The resolver refused the hello on purpose (the engine
                    // already spliced the flow); that close is not a failure.
                    if resolver.spliced() {
                        return;
                    }
                    if let Some(alert) = cert_alert(&error) {
                        if let Some(host) = resolver.captured() {
                            resolver
                                .host
                                .cert_rejected(resolver.key, &host, &info.apps, alert);
                        }
                    } else {
                        crate::logbuf::push(&format!(
                            "quic {}: handshake failed: {error}",
                            resolver.display_host()
                        ));
                    }
                }
            }
        });
    }
}

async fn serve(
    connection: quinn::Connection,
    resolver: Arc<HubResolver>,
    info: Arc<FlowInfo>,
    upstreams: Arc<Upstreams>,
) {
    let Some(server_name) = resolver.captured() else {
        // No SNI: an address literal, which this path cannot filter. The
        // client falls back to TCP, where the same flow is spliced.
        connection.close(quinn::VarInt::from_u32(0), b"no sni");
        return;
    };
    let Some(endpoint) = upstreams.endpoint(info.local.is_ipv6()) else {
        crate::logbuf::push(&format!("quic {server_name}: no upstream transport"));
        connection.close(quinn::VarInt::from_u32(0), b"upstream unavailable");
        return;
    };
    let config = Arc::new(HubConfig {
        filter: Arc::clone(&info.filter),
        apps: info.apps.clone(),
        server_name: server_name.clone(),
        origin: info.local,
        local: false,
        serve_path: info.serve_path.clone(),
        script_body: Arc::clone(&info.script_body),
        script_tag_src: info.script_tag_src.clone(),
        cosmetic: info.cosmetic.clone(),
        stealth: info.stealth,
        upstream: Arc::clone(&info.upstream),
        endpoint,
        sink: info.sink,
    });
    hub::serve_connection(connection.clone(), config).await;
    // A client that rejects the leaf closes the connection with the TLS alert
    // in its CONNECTION_CLOSE; that is the only place the alert surfaces once
    // the handshake was reported as complete.
    if !resolver.spliced() {
        if let Some(error) = connection.close_reason() {
            if let Some(alert) = cert_alert(&error) {
                resolver
                    .host
                    .cert_rejected(resolver.key, &server_name, &info.apps, alert);
            }
        }
    }
}

/// The per-flow certificate resolver: captures the SNI rustls parsed, and asks
/// the engine whether the flow belongs on the raw path before signing a leaf.
struct HubResolver {
    inner: Arc<SniCertResolver>,
    captured: Mutex<Option<String>>,
    key: UdpKey,
    apps: Vec<String>,
    host: Arc<dyn Host>,
    spliced: AtomicBool,
}

impl HubResolver {
    fn captured(&self) -> Option<String> {
        self.captured.lock().ok().and_then(|slot| slot.clone())
    }

    fn spliced(&self) -> bool {
        self.spliced.load(Ordering::Relaxed)
    }

    fn display_host(&self) -> String {
        self.captured().unwrap_or_else(|| "?".to_string())
    }
}

impl std::fmt::Debug for HubResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HubResolver")
    }
}

impl ResolvesServerCert for HubResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?.to_string();
        if let Ok(mut slot) = self.captured.lock() {
            *slot = Some(name.clone());
        }
        if self.host.should_splice(self.key, &name, &self.apps) {
            self.spliced.store(true, Ordering::Relaxed);
            // No leaf: rustls aborts the handshake and the client retries.
            return None;
        }
        self.inner.resolve(client_hello)
    }
}

/// Shared upstream endpoints: one per address family, connecting over sockets
/// the app protected (so the engine's own QUIC never loops back into the VPN).
struct Upstreams {
    host: Arc<dyn Host>,
    v4: Mutex<Option<Endpoint>>,
    v6: Mutex<Option<Endpoint>>,
}

impl Upstreams {
    fn new(host: Arc<dyn Host>) -> Self {
        Upstreams {
            host,
            v4: Mutex::new(None),
            v6: Mutex::new(None),
        }
    }

    fn endpoint(&self, ipv6: bool) -> Option<Endpoint> {
        let slot = if ipv6 { &self.v6 } else { &self.v4 };
        let mut guard = slot.lock().unwrap();
        if let Some(endpoint) = guard.as_ref() {
            return Some(endpoint.clone());
        }
        let socket = self.host.upstream_socket(ipv6)?;
        match Endpoint::new(endpoint_config(), None, socket, Arc::new(TokioRuntime)) {
            Ok(endpoint) => {
                *guard = Some(endpoint.clone());
                Some(endpoint)
            }
            Err(e) => {
                crate::logbuf::push(&format!("quic: upstream endpoint failed: {e}"));
                None
            }
        }
    }
}

/// The TLS alert inside a QUIC close, when it is one a client sends after
/// refusing our certificate.
fn cert_alert(error: &quinn::ConnectionError) -> Option<u8> {
    let code = match error {
        quinn::ConnectionError::TransportError(error) => u64::from(error.code),
        quinn::ConnectionError::ConnectionClosed(close) => u64::from(close.error_code),
        _ => return None,
    };
    // TLS alerts travel as CRYPTO_ERROR (0x100 | alert) in QUIC.
    let alert = u8::try_from(code.checked_sub(0x100)?).ok()?;
    crate::engine::cert_alert_is_rejection(alert).then_some(alert)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The advertised receive limit must fit an IPv6 packet inside the
    /// tunnel's 1500-byte MTU, unlike quinn's IPv4-only default.
    #[test]
    fn the_advertised_datagram_size_fits_the_tunnel_mtu() {
        assert_eq!(
            endpoint_config().get_max_udp_payload_size(),
            u64::from(TUNNEL_MAX_UDP)
        );
        assert!(usize::from(TUNNEL_MAX_UDP) + 48 <= 1500);
    }
}
