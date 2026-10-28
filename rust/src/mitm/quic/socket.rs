//! An `AsyncUdpSocket` backed by the packet engine instead of a file
//! descriptor.
//!
//! quinn wants a socket it can poll; the engine already owns the only network
//! path (the TUN device). This adapter is the seam: `recv` feeds the endpoint
//! with datagrams the engine decoded, and everything quinn sends arrives on an
//! `OutDatagram` channel that the forwarder turns into UDP packets.

use std::collections::VecDeque;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

/// Upper bound on datagrams held for a connection between two polls.
///
/// A stalled runtime must not grow the heap through the TUN side; QUIC
/// retransmits, so dropping here costs a round trip, not correctness.
const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;

/// One datagram leaving the QUIC endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutDatagram {
    /// The local address of the socket that produced it: the original
    /// destination server for the client-facing endpoint, the upstream server
    /// for the shared upstream endpoint.
    pub source: SocketAddr,
    /// Where the datagram must be sent.
    pub destination: SocketAddr,
    pub payload: Vec<u8>,
}

/// One datagram entering the QUIC endpoint.
#[derive(Debug)]
pub struct Datagram {
    /// The peer that sent it.
    pub peer: SocketAddr,
    /// The address it was sent to. QUIC uses it as the local address, so the
    /// client-facing endpoint sees the original server IP rather than the
    /// synthetic one.
    pub dst_ip: Option<IpAddr>,
    pub payload: Vec<u8>,
}

struct Inbound {
    queue: VecDeque<Datagram>,
    bytes: usize,
    waker: Option<Waker>,
}

/// In-memory UDP transport for one QUIC endpoint.
pub struct TunUdpSocket {
    local: SocketAddr,
    inbound: Mutex<Inbound>,
    outbound: SyncSender<OutDatagram>,
    dropped: AtomicU64,
    truncated: AtomicU64,
}

impl TunUdpSocket {
    pub fn new(local: SocketAddr, outbound: SyncSender<OutDatagram>) -> Arc<Self> {
        Arc::new(Self {
            local,
            inbound: Mutex::new(Inbound {
                queue: VecDeque::new(),
                bytes: 0,
                waker: None,
            }),
            outbound,
            dropped: AtomicU64::new(0),
            truncated: AtomicU64::new(0),
        })
    }

    /// Hands a datagram to the endpoint, waking quinn if it was waiting.
    ///
    /// Returns false when the queue is full; the caller (the forwarder) then
    /// drops the packet like any congested UDP path would.
    pub fn recv(&self, datagram: Datagram) -> bool {
        let mut state = self.inbound.lock().unwrap();
        if state.bytes + datagram.payload.len() > MAX_QUEUED_BYTES {
            drop(state);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        state.bytes += datagram.payload.len();
        state.queue.push_back(datagram);
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
        true
    }

    /// Datagrams the endpoint could not hand over (queue full, buffer too
    /// small).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed) + self.truncated.load(Ordering::Relaxed)
    }

    pub fn local(&self) -> SocketAddr {
        self.local
    }
}

impl fmt::Debug for TunUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunUdpSocket")
            .field("local", &self.local)
            .field("dropped", &self.dropped())
            .finish()
    }
}

impl AsyncUdpSocket for TunUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // quinn may pack several datagrams per call when segmentation is on.
        // Each becomes one packet through the engine, so split them here and
        // let the channel bound (rather than a `WouldBlock` loop) apply
        // backpressure: UDP drops are normal, stalls are not.
        let segments = transmit.segment_size.unwrap_or(transmit.contents.len());
        let mut sent = 0usize;
        while sent < transmit.contents.len() {
            let end = (sent + segments).min(transmit.contents.len());
            let out = OutDatagram {
                source: self.local,
                destination: transmit.destination,
                payload: transmit.contents[sent..end].to_vec(),
            };
            match self.outbound.try_send(out) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "QUIC output closed",
                    ));
                }
            }
            sent = end;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no receive buffer",
            )));
        }
        let mut state = self.inbound.lock().unwrap();
        loop {
            let Some(datagram) = state.queue.pop_front() else {
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            };
            state.bytes -= datagram.payload.len();
            if datagram.payload.len() > bufs[0].len() {
                self.truncated.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let len = datagram.payload.len();
            bufs[0][..len].copy_from_slice(&datagram.payload);
            meta[0] = RecvMeta {
                addr: datagram.peer,
                len,
                stride: len,
                ecn: None,
                dst_ip: datagram.dst_ip,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        // The TUN path can fragment at the IP layer; keep path-MTU discovery
        // conservative until the MTU survey lands.
        true
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
    use std::time::Duration;

    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    const ALPN: &[u8] = b"h3";
    const CHANNEL: usize = 4096;

    fn endpoint_socket(local: SocketAddr) -> (Arc<TunUdpSocket>, Receiver<OutDatagram>) {
        let (tx, rx): (SyncSender<OutDatagram>, Receiver<OutDatagram>) = sync_channel(CHANNEL);
        (TunUdpSocket::new(local, tx), rx)
    }

    fn pump(to: Arc<TunUdpSocket>, rx: Receiver<OutDatagram>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            while let Ok(out) = rx.recv() {
                let dst_ip = Some(to.local.ip());
                to.recv(Datagram {
                    peer: out.source,
                    dst_ip,
                    payload: out.payload,
                });
            }
        })
    }

    fn configs() -> (ServerConfig, ClientConfig) {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self-signed certificate");
        let cert = CertificateDer::from(generated.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));

        let mut server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .expect("server config");
        server.alpn_protocols = vec![ALPN.to_vec()];
        let server = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server).expect("QUIC server config"),
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).expect("trust anchor");
        let mut client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![ALPN.to_vec()];
        let client = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client).expect("QUIC client config"),
        ));
        (server, client)
    }

    #[test]
    fn echo_round_trip_through_in_memory_sockets() {
        let (server_socket, server_rx) = endpoint_socket("127.0.0.1:4433".parse().unwrap());
        let (client_socket, client_rx) = endpoint_socket("127.0.0.1:5555".parse().unwrap());
        let _server_pump = pump(client_socket.clone(), server_rx);
        let _client_pump = pump(server_socket.clone(), client_rx);
        let (server_config, client_config) = configs();
        let server_errors = server_socket.clone();
        let client_errors = client_socket.clone();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let result = rt.block_on(async move {
            let runtime = Arc::new(TokioRuntime);
            let server_endpoint = Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                Some(server_config),
                server_socket,
                runtime.clone(),
            )
            .expect("server endpoint");
            let client_endpoint = Endpoint::new_with_abstract_socket(
                EndpointConfig::default(),
                None,
                client_socket,
                runtime,
            )
            .expect("client endpoint");
            let server = tokio::spawn(async move {
                let incoming = server_endpoint.accept().await.expect("incoming");
                let connection = incoming.await.expect("server handshake");
                let (mut send, mut recv) = connection.accept_bi().await.expect("stream");
                let request = recv.read_to_end(1024).await.expect("request");
                send.write_all(&request).await.expect("echo");
                send.finish().expect("finish");
                connection.closed().await;
            });

            let connection = tokio::time::timeout(
                Duration::from_secs(5),
                client_endpoint
                    .connect_with(
                        client_config,
                        "127.0.0.1:4433".parse().unwrap(),
                        "localhost",
                    )
                    .expect("connect"),
            )
            .await
            .expect("handshake timeout")
            .expect("handshake");
            let (mut send, mut recv) = connection.open_bi().await.expect("open");
            send.write_all(b"hello over h3").await.expect("write");
            send.finish().expect("finish");
            let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64))
                .await
                .expect("reply timeout")
                .expect("reply");
            connection.close(0u32.into(), b"done");
            server.abort();
            reply
        });

        assert_eq!(result, b"hello over h3");
        assert_eq!(server_errors.dropped(), 0);
        assert_eq!(client_errors.dropped(), 0);
    }

    #[test]
    fn oversized_datagram_is_dropped_not_truncated() {
        let (tx, _rx) = sync_channel(1);
        let socket = TunUdpSocket::new("127.0.0.1:1".parse().unwrap(), tx);
        let peer = "127.0.0.1:2".parse().unwrap();
        assert!(socket.recv(Datagram {
            peer,
            dst_ip: None,
            payload: vec![0u8; 32],
        }));
        assert!(socket.recv(Datagram {
            peer,
            dst_ip: None,
            payload: vec![7u8; 8],
        }));

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut buf = [0u8; 16];
        let mut bufs = [IoSliceMut::new(&mut buf)];
        let mut meta = [RecvMeta {
            addr: peer,
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];
        match socket.poll_recv(&mut cx, &mut bufs, &mut meta) {
            Poll::Ready(Ok(1)) => {
                assert_eq!(meta[0].len, 8);
                assert_eq!(&buf[..8], &[7u8; 8]);
            }
            other => panic!("expected the second datagram, got {other:?}"),
        }
        assert_eq!(socket.dropped(), 1);
    }
}
