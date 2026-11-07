//! The relay: one intercepted connection, end to end.
//!
//! ```text
//!   TUN ──▶ client TCP ──▶ ServerConnection ─▶ plaintext ─▶ ClientConnection ──▶ peer socket
//!   TUN ◀── client TCP ◀── ServerConnection ◀── plaintext ◀── ClientConnection ◀── peer socket
//! ```
//!
//! Every step returns the payloads to write back, so the packet loop stays in
//! charge of TCP segmentation and no syscall ever blocks.

use crate::mitm::proxy::ProxySession;
use crate::mitm::tcp::{Flow, FlowState};
use crate::socks5::{ProxyEndpoint, Socks5Handshake};
use crate::util::now_ms;
use std::collections::VecDeque;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Port we intercept for TLS termination. Everything else keeps flowing.
pub const MITM_PORT: u16 = 443;

/// Where a retired relay reports the bytes that crossed it: the package that
/// owned the flow, device-to-server and server-to-device totals.
///
/// A plain function pointer, like [`crate::mitm::proxy::MitmSink`]: production
/// points at the process-wide engine and tests run without one, so the relay
/// never has to know how the log is stored.
pub type TrafficSink = fn(app: &str, sent: u64, recv: u64);

/// Fallback payload cap when the client's SYN carried no MSS option.
pub const DEFAULT_MSS: usize = 1460;

/// Bytes a relay may hold for a client that is not acknowledging fast enough.
/// At the cap the peer socket stops being read, so the kernel's receive
/// buffer (and then TCP backpressure) slows the server down instead of this
/// queue growing with the whole response.
pub const MAX_PENDING_TO_CLIENT: usize = 4 * 1024 * 1024;

/// Reading the peer resumes once the backlog fell to this much: the gap
/// between the two marks keeps an ACK from re-arming the read on every flush
/// while the client sits at the cap.
pub const CLIENT_RESUME_AT: usize = MAX_PENDING_TO_CLIENT / 2;

/// A TLS handshake record, by its content type.
const RECORD_HANDSHAKE: u8 = 0x16;

/// How many bytes anti-DPI lets the peer see before the rest of the hello
/// follows in its own segment.
///
/// The hello's opening is record header (5) + handshake header (4) + legacy
/// version (2) + the client random (32), so a cut at 24 bytes lands inside the
/// random and leaves everything an inspector is looking for — cipher list,
/// extensions, `server_name` — behind it. TCP reassembles whatever the segments
/// say, so a real server cannot tell the difference.
const ANTI_DPI_HEAD: usize = 24;

/// Instance token for peer sockets.
///
/// The forwarder keeps an `epoll` registration across passes, and a
/// registration is about a *file*, not about a number: when a relay's socket
/// closes, its descriptor number goes back into the pool and the next socket
/// the engine opens usually gets it. Handing every peer socket a fresh token is
/// what lets the wait set see that `(descriptor, client port)` is a different
/// socket than the one it registered, and re-register instead of assuming the
/// old interest still stands.
static NEXT_PEER_SOCKET: AtomicU64 = AtomicU64::new(1);

fn next_peer_gen() -> u64 {
    NEXT_PEER_SOCKET.fetch_add(1, Ordering::Relaxed)
}

/// One relayed connection.
///
/// `session` is `Some` only for TLS-terminated flows (HTTPS filtering): with
/// `None` the relay is a transparent splice that just moves bytes between the
/// client and the peer socket.
pub struct Relay {
    pub flow: Flow,
    pub session: Option<ProxySession>,
    /// Protected socket to the real server; the relay owns it and closes it on
    /// drop (-1 in tests). Install it with [`Self::attach_peer`].
    pub peer_fd: RawFd,
    /// Instance token of [`Self::peer_fd`], from [`NEXT_PEER_SOCKET`].
    pub peer_gen: u64,
    /// The client's SYN, kept as the template for every reply we build.
    pub syn_packet: Vec<u8>,
    /// Set once either side is done.
    pub closed: bool,
    /// Largest TCP payload we may put in one segment towards the client.
    /// Anything above the client's MSS is dropped by its stack, and anything
    /// above the tunnel MTU cannot even be written to the descriptor.
    pub mss: usize,
    /// Last time either side moved bytes; the engine expires idle relays.
    pub last_ms: u64,
    /// The client already sent its FIN.
    pub client_fin: bool,
    /// The peer `connect()` has not completed yet: `send()` would fail with
    /// EAGAIN until the socket is writable, so bytes wait in `pending_to_peer`.
    pub connecting: bool,
    /// Peer connect attempts already spent; one retry is allowed after a
    /// failure, because a fresh socket picks a fresh source port.
    pub connect_retries: u8,
    /// Client bytes not yet accepted by the peer socket (it is connecting, or
    /// its send buffer is full). Flushed by the engine on the next writable.
    pub pending_to_peer: Vec<u8>,
    /// Wire bytes for the client the receive window could not take yet.
    /// Flushed as the client's ACKs open the window further. A deque, not a
    /// vec: the flush takes from the front on every ACK, and shifting a
    /// multi-megabyte backlog per segment would dwarf the filtering work.
    pub pending_to_client: VecDeque<u8>,
    /// The client-facing backlog hit [`MAX_PENDING_TO_CLIENT`]: the engine
    /// leaves the peer socket out of its read set until the queue drains to
    /// [`CLIENT_RESUME_AT`]. Without this a stalled client turns the queue
    /// into a copy of whatever the server is willing to send.
    pub client_paused: bool,
    /// The peer closed while bytes were still pending: the FIN must wait for
    /// them, or it would carry a sequence number ahead of data the client has
    /// not seen (and the relay would drop that data on retirement).
    pub fin_after_flush: bool,
    /// Set while some thread is inside `send()` for this relay, so two threads
    /// never interleave writes and scramble the byte order.
    pub flushing: bool,
    /// The client sent its FIN while bytes were still queued for the peer: the
    /// half-close waits until the queue is empty (writes are refused after).
    pub shutdown_after_flush: bool,
    /// Packages owning this flow, resolved once at SYN time. The app firewall
    /// reevaluates them when the network or screen state changes.
    pub app_packages: Vec<String>,
    /// The SOCKS5 proxy this flow dials instead of the destination, fixed when
    /// the flow opens so a settings change never rewrites a live connection.
    pub proxy: Option<Arc<ProxyEndpoint>>,
    /// SOCKS5 negotiation for this flow; `None` on direct connections.
    pub handshake: Option<Socks5Handshake>,
    /// The SYN was answered, but the upstream half — app attribution, the
    /// protected socket, the TLS session — is still being built by the setup
    /// worker. The packet reader never runs that machinery inline, or every
    /// connection would wait for the previous one's setup.
    pub setup_pending: bool,
    /// Client segments that arrived before the upstream half existed, with
    /// their sequence numbers: replayed through the session once it lands,
    /// which is also when they are acknowledged.
    pub pending_client: Vec<(u32, Vec<u8>)>,
    /// Bytes buffered in [`Self::pending_client`]. Capped so a client that
    /// keeps sending during a slow setup cannot grow it without bound.
    pub pending_client_bytes: usize,
    /// Payload bytes put on the wire towards the client. `flow.up_bytes` also
    /// counts the SYN-ACK and the FIN, which are sequence numbers, not traffic,
    /// so the statistics cannot read the total from it.
    pub payload_to_client: u64,
    /// Whether the connection's opening has begun crossing to the peer.
    ///
    /// Anti-DPI has one thing to say about a flow, and it is worth exactly one
    /// write. SOCKS5 negotiation is not that opening — those bytes go to the
    /// proxy and carry no server name — so the engine sets this only for bytes
    /// the origin asked for, and a proxied flow still splits its ClientHello.
    pub opening_sent: bool,
    /// Reports what crossed this connection when it retires; `None` in tests.
    pub traffic: Option<TrafficSink>,
    /// The address pair the client's SYN named, or `None` for a relay built
    /// without one. See [`Relay::serves`].
    pub flow_key: Option<FlowKey>,
}

/// The half of a relay's identity that its client port cannot carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowKey {
    client: crate::packet::IpKey,
    peer: crate::packet::IpKey,
    peer_port: u16,
}

impl FlowKey {
    fn of(pkt: &crate::packet::Packet<'_>) -> Option<FlowKey> {
        Some(FlowKey {
            client: pkt.src_ip()?,
            peer: pkt.dst_ip()?,
            peer_port: pkt.dst_port,
        })
    }
}

impl Relay {
    /// A relay that TLS-terminates: the client's HTTPS traffic is decrypted,
    /// filtered and re-encrypted towards the real server.
    pub fn new_tls(
        flow: Flow,
        peer_fd: RawFd,
        session: ProxySession,
        syn_packet: Vec<u8>,
        mss: usize,
        connecting: bool,
    ) -> Self {
        let flow_key = crate::packet::Packet::parse(&syn_packet).and_then(|pkt| FlowKey::of(&pkt));
        Relay {
            flow,
            session: Some(session),
            peer_fd,
            peer_gen: next_peer_gen(),
            syn_packet,
            flow_key,
            closed: false,
            mss,
            last_ms: now_ms(),
            client_fin: false,
            connecting,
            connect_retries: 0,
            pending_to_peer: Vec::new(),
            pending_to_client: VecDeque::new(),
            client_paused: false,
            fin_after_flush: false,
            flushing: false,
            shutdown_after_flush: false,
            app_packages: Vec::new(),
            proxy: None,
            handshake: None,
            setup_pending: false,
            pending_client: Vec::new(),
            pending_client_bytes: 0,
            payload_to_client: 0,
            opening_sent: false,
            traffic: None,
        }
    }

    /// A relay that only splices bytes: no TLS, no filtering, used for every
    /// TCP flow that is not an HTTPS connection we intercept.
    pub fn new_plain(
        flow: Flow,
        peer_fd: RawFd,
        syn_packet: Vec<u8>,
        mss: usize,
        connecting: bool,
    ) -> Self {
        let flow_key = crate::packet::Packet::parse(&syn_packet).and_then(|pkt| FlowKey::of(&pkt));
        Relay {
            flow,
            session: None,
            peer_fd,
            peer_gen: next_peer_gen(),
            syn_packet,
            flow_key,
            closed: false,
            mss,
            last_ms: now_ms(),
            client_fin: false,
            connecting,
            connect_retries: 0,
            pending_to_peer: Vec::new(),
            pending_to_client: VecDeque::new(),
            client_paused: false,
            fin_after_flush: false,
            flushing: false,
            shutdown_after_flush: false,
            app_packages: Vec::new(),
            proxy: None,
            handshake: None,
            setup_pending: false,
            pending_client: Vec::new(),
            pending_client_bytes: 0,
            payload_to_client: 0,
            opening_sent: false,
            traffic: None,
        }
    }

    /// Points the relay at a peer socket.
    ///
    /// Replacing `peer_fd` without this call would leave the new socket wearing
    /// the old one's `peer_gen`, and the forwarder's wait set would read the
    /// unchanged `(descriptor, generation)` pair as proof that its `epoll`
    /// registration still covers the file behind it. It would not: the closed
    /// socket's registration went with it, and the flow would never be woken.
    pub fn attach_peer(&mut self, fd: RawFd) {
        self.peer_fd = fd;
        self.peer_gen = next_peer_gen();
    }

    /// The client's SYN, and with it the identity every reply is built from.
    pub fn set_syn(&mut self, syn: Vec<u8>) {
        self.flow_key = crate::packet::Packet::parse(&syn).and_then(|pkt| FlowKey::of(&pkt));
        self.syn_packet = syn;
    }

    /// Whether a packet coming from the client belongs to this relay.
    ///
    /// The engine's table is keyed by the client port alone, and the kernel
    /// happily gives that port to a new socket bound for another address while
    /// this flow is still live — the tuple only has to differ somewhere. So a
    /// port hit names this flow only when the address pair matches too. Without
    /// the check, the other flow's SYN-ACK would be built from this relay's
    /// template, land on an address pair its client cannot use, and leave the
    /// new socket waiting for an answer that never arrives.
    pub fn serves(&self, pkt: &crate::packet::Packet<'_>) -> bool {
        match self.flow_key {
            Some(stored) => FlowKey::of(pkt) == Some(stored),
            None => false,
        }
    }

    /// True while SOCKS5 negotiation still owns the peer socket: application
    /// bytes must wait, and a writable peer means handshake output, not data.
    pub fn proxy_handshaking(&self) -> bool {
        self.handshake.as_ref().is_some_and(|h| !h.is_done())
    }

    /// Buffers client bytes until the peer connection is writable.
    pub fn queue_to_peer(&mut self, bytes: &[u8]) {
        self.pending_to_peer.extend_from_slice(bytes);
    }

    /// Where the first flight to the peer is cut, or `None` when it goes out as
    /// one piece.
    ///
    /// Only the opening of a connection matters: a middlebox that reads the
    /// server name straight out of the first segment never reaches the rest of
    /// the hello once it is split. Everything after that, and every byte that
    /// is not a handshake record, is written exactly as it came — fragmenting a
    /// download would cost packets for nothing.
    pub fn anti_dpi_head(&self, chunk: &[u8], enabled: bool) -> Option<usize> {
        if !enabled || self.opening_sent {
            return None;
        }
        if chunk.first() != Some(&RECORD_HANDSHAKE) || chunk.len() <= ANTI_DPI_HEAD {
            return None;
        }
        Some(ANTI_DPI_HEAD)
    }

    /// Turns a payload into the TCP segments addressed to the client.
    ///
    /// The relay owns the flow, so it is the right place to advance the
    /// client-facing sequence number; the engine just writes the result out.
    pub fn segments_for_client(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        self.queue_to_client(payload);
        self.flush_to_client()
    }

    /// Buffers wire bytes for the client until its window takes them.
    pub fn queue_to_client(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.pending_to_client.extend(bytes.iter().copied());
            if self.pending_to_client.len() >= MAX_PENDING_TO_CLIENT {
                self.client_paused = true;
            }
        }
    }

    /// Whether the engine must stop reading this relay's peer socket.
    pub fn client_paused(&self) -> bool {
        self.client_paused
    }

    /// Records the ACK and window carried by any packet from the client.
    pub fn on_client_ack(&mut self, ack_seq: u32, window: u16) {
        // Only ever move the ACK forward: retransmissions carry stale values.
        if ack_seq.wrapping_sub(self.flow.client_ack) < 0x8000_0000 {
            self.flow.client_ack = ack_seq;
        }
        self.flow.client_window = (window as u32) << self.flow.client_window_scale;
    }

    /// Emits as many client-bound segments as the receive window allows.
    ///
    /// A receiver drops anything past its advertised window and this relay has
    /// no retransmission, so staying inside the window is what keeps a large
    /// body flowing (the stitched userscript is ~600 KB): each ACK opens the
    /// window further and the engine calls back in to flush the rest.
    pub fn flush_to_client(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        // Parsing the SYN template once is enough: the loop only swaps the
        // sequence numbers and copies the payload in.
        let Some(pkt) = crate::packet::Packet::parse(&self.syn_packet) else {
            return out;
        };
        while !self.pending_to_client.is_empty() {
            let in_flight = self.flow.next_send_seq().wrapping_sub(self.flow.client_ack) as u64;
            let window = self.flow.client_window as u64;
            if in_flight >= window {
                break;
            }
            let room = (window - in_flight) as usize;
            let take = room.min(self.mss).min(self.pending_to_client.len());
            // A segment has to come out as one slice; the rotation only runs
            // when the used region wrapped, and it is amortized over the
            // bytes it moves.
            let pending = self.pending_to_client.make_contiguous();
            let seq = self.flow.next_send_seq();
            let Some(segment) = crate::mitm::segment::build_data_segment(
                &pkt,
                seq,
                self.flow.acked_seq,
                &pending[..take],
            ) else {
                break;
            };
            self.pending_to_client.drain(..take);
            self.flow.up_bytes += take as u64;
            self.payload_to_client += take as u64;
            out.push(segment);
        }
        // Below the low-water mark the peer may be read again; the engine is
        // woken from here because only it owns the read set.
        if self.client_paused && self.pending_to_client.len() <= CLIENT_RESUME_AT {
            self.client_paused = false;
        }
        // A deferred FIN rides out once the last byte is on its way and the
        // window has room for its sequence number.
        if self.pending_to_client.is_empty() && self.fin_after_flush && !self.closed {
            let in_flight = self.flow.next_send_seq().wrapping_sub(self.flow.client_ack) as u64;
            if in_flight < self.flow.client_window as u64 {
                self.fin_after_flush = false;
                if let Some(fin) = self.fin_now() {
                    out.push(fin);
                }
            }
        }
        out
    }

    /// Is the client-facing half ready to carry application data?
    pub fn is_established(&self) -> bool {
        !self.closed
            && match &self.session {
                // A plain splice is always ready; the TLS half is only ready
                // once the handshake finished.
                Some(s) => !s.server_handshaking(),
                None => true,
            }
    }

    /// A segment arrived from the client.
    ///
    /// `seq` is the segment's own sequence number. Until our ACK reaches the
    /// client it retransmits, so duplicates and overlaps are routine and each
    /// byte may only be handed forward once: a second copy of a POST would hit
    /// the server twice, and a second copy of a TLS record would corrupt the
    /// rustls stream.
    ///
    /// Returns `(to_peer, to_client)`: both directions can produce bytes, because
    /// during the handshake our own answers count towards the client.
    pub fn on_client_segment(
        &mut self,
        seq: u32,
        payload: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        if payload.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let expected = self.flow.acked_seq;
        let fresh = if seq == expected {
            payload
        } else if seq.wrapping_sub(expected) & 0x8000_0000 != 0 {
            // An older segment: the head was already forwarded, at best.
            let skipped = expected.wrapping_sub(seq) as usize;
            if skipped >= payload.len() {
                return Ok((Vec::new(), Vec::new())); // a pure retransmission
            }
            &payload[skipped..]
        } else {
            // A gap. Client packets are read straight off the tun device and
            // cannot be dropped by us, so this is a retransmission that raced
            // ahead of our ACK; stay quiet and the caller's ACK pulls the
            // missing hole back.
            return Ok((Vec::new(), Vec::new()));
        };
        // Every client byte must be acknowledged exactly once: the ACK the
        // caller sends after this call carries `acked_seq`, and without it the
        // client retransmits everything forever.
        self.flow.acked_seq = self.flow.acked_seq.wrapping_add(fresh.len() as u32);
        self.flow.down_bytes += fresh.len() as u64;
        self.last_ms = now_ms();
        let Some(session) = self.session.as_mut() else {
            // Plain splice: forward the bytes untouched.
            return Ok((fresh.to_vec(), Vec::new()));
        };
        let out = session.on_client_payload(fresh)?;
        if out.closed {
            self.closed = true;
        }
        Ok((out.to_peer, out.to_client))
    }

    /// Data arrived from the real server.
    ///
    /// Returns `(to_peer, to_client, restart_peer)`: the peer direction carries
    /// wire bytes the upstream half produced while processing server data (its
    /// protocol handshake finishing, plus a request that waited for it).
    /// Dropping those silently deadlocks the flow: the real server never sees
    /// the client's Finished and never answers. `restart_peer` asks the caller
    /// to reopen the peer socket first — the upstream half rebuilt itself
    /// after an ECH rejection, and its new hello belongs on a fresh
    /// connection.
    pub fn on_peer_data(&mut self, bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, bool), String> {
        if bytes.is_empty() {
            return Ok((Vec::new(), Vec::new(), false));
        }
        self.last_ms = now_ms();
        let Some(session) = self.session.as_mut() else {
            // Plain splice: forward the bytes untouched.
            return Ok((Vec::new(), bytes.to_vec(), false));
        };
        let out = session.on_peer_payload(bytes)?;
        if out.closed {
            self.closed = true;
        }
        Ok((out.to_peer, out.to_client, out.restart_peer))
    }

    /// The client sent a FIN. Shut our write side to the peer down and
    /// acknowledge: a FIN consumes one sequence number.
    pub fn on_client_fin(&mut self) -> Option<Vec<u8>> {
        // A client that never sent a request before its FIN refused the
        // certificate (see `ProxySession::on_client_eof`).
        if let Some(session) = self.session.as_mut() {
            // No process name reaches this path: the session falls back to the
            // `(host, client fingerprint)` pair it remembers itself.
            session.on_client_eof();
        }
        self.client_fin = true;
        self.last_ms = now_ms();
        self.flow.acked_seq = self.flow.acked_seq.wrapping_add(1);
        let pkt = crate::packet::Packet::parse(&self.syn_packet)?;
        let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
        crate::mitm::segment::build_ack(&pkt, seq, self.flow.acked_seq, false)
    }

    /// A pure ACK for every client byte received so far.
    ///
    /// A plain splice has nothing to piggyback on, so this segment is the only
    /// thing that stops the client from retransmitting its request.
    pub fn ack_to_client(&mut self) -> Option<Vec<u8>> {
        let pkt = crate::packet::Packet::parse(&self.syn_packet)?;
        let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
        crate::mitm::segment::build_ack(&pkt, seq, self.flow.acked_seq, false)
    }

    /// The peer closed its side: send the client a FIN and retire the relay.
    ///
    /// When bytes are still waiting for window space the FIN is deferred; the
    /// flush that empties the queue sends it.
    pub fn on_peer_eof(&mut self) -> Option<Vec<u8>> {
        if !self.pending_to_client.is_empty() {
            self.fin_after_flush = true;
            return None;
        }
        self.fin_now()
    }

    /// Emits the FIN immediately and retires the relay.
    fn fin_now(&mut self) -> Option<Vec<u8>> {
        let pkt = crate::packet::Packet::parse(&self.syn_packet)?;
        let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
        self.flow.up_bytes += 1; // the FIN we send consumes one sequence number
        self.closed = true;
        self.flow.state = FlowState::Closed;
        crate::mitm::segment::build_fin(&pkt, seq, self.flow.acked_seq)
    }

    /// A hard reset towards the client (peer refused the connection, idle
    /// timeout...): better than leaving the app waiting on a dead flow.
    pub fn rst_to_client(&mut self) -> Option<Vec<u8>> {
        let pkt = crate::packet::Packet::parse(&self.syn_packet)?;
        let seq = self.flow.my_seq.wrapping_add(self.flow.up_bytes as u32);
        crate::mitm::segment::build_rst(&pkt, seq)
    }

    /// Bytes the peer-facing TLS half wants to put on the wire.
    pub fn client_outbound(&mut self) -> Vec<u8> {
        match self.session.as_mut() {
            Some(s) => s.take_upstream_outbound(),
            None => Vec::new(),
        }
    }

    /// Marks the relay as finished when either side goes away.
    pub fn close(&mut self) {
        self.closed = true;
        self.flow.state = FlowState::Closed;
    }

    /// Chunks a payload into segments the client can understand.
    pub fn split_segments(payload: Vec<u8>, max: usize) -> Vec<Vec<u8>> {
        let max = max.max(1);
        if payload.len() <= max {
            return if payload.is_empty() {
                Vec::new()
            } else {
                vec![payload]
            };
        }
        payload.chunks(max).map(<[u8]>::to_vec).collect()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // A connection that moved nothing is not worth a row: a probe or a
        // relay retired during setup would otherwise flood the table.
        if self.flow.down_bytes != 0 || self.payload_to_client != 0 {
            if let Some(sink) = self.traffic {
                let app = self.app_packages.first().map(String::as_str).unwrap_or("");
                sink(app, self.flow.down_bytes, self.payload_to_client);
            }
        }
        // The engine created this descriptor for us (and had the app protect
        // it), so retiring the relay must close it. -1 is the test sentinel.
        if self.peer_fd >= 0 {
            unsafe {
                libc::close(self.peer_fd);
            }
        }
    }
}

/// One relay's peer socket, as the forwarder's wait set needs it.
///
/// A struct rather than a tuple because there are six fields and the engine
/// dispatches from all of them: `gen` says which socket the descriptor *is*,
/// which is what lets a persistent `epoll` registration be reused, and the
/// three flags say what to ask of it and what to do when it answers. A relay
/// whose peer socket is not open yet (`fd` would be -1) is left out: there is
/// nothing to wait on, and the engine learns the descriptor when setup
/// installs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPoll {
    /// Instance token of `fd`; see [`NEXT_PEER_SOCKET`].
    pub gen: u64,
    pub client_port: u16,
    pub fd: RawFd,
    pub connecting: bool,
    pub want_write: bool,
    pub paused: bool,
}

/// Every live relay, keyed by the client's port.
pub struct RelayTable {
    relays: std::collections::HashMap<u16, Relay>,
}

impl Default for RelayTable {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayTable {
    pub fn new() -> Self {
        RelayTable {
            relays: std::collections::HashMap::new(),
        }
    }

    pub fn insert(&mut self, relay: Relay) {
        self.relays.insert(relay.flow.client_port, relay);
    }

    pub fn get(&self, port: u16) -> Option<&Relay> {
        self.relays.get(&port)
    }

    /// Mutable walk over the live relays (housekeeping).
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u16, &mut Relay)> {
        self.relays.iter_mut().map(|(p, r)| (*p, r))
    }

    pub fn get_mut(&mut self, port: u16) -> Option<&mut Relay> {
        self.relays.get_mut(&port)
    }

    pub fn remove(&mut self, port: u16) -> Option<Relay> {
        self.relays.remove(&port)
    }

    /// Drops every relay (and closes its peer descriptor). Used on shutdown:
    /// a restart must not inherit half-dead flows whose client ports are about
    /// to be reused by fresh sessions.
    pub fn clear(&mut self) {
        self.relays.clear();
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Every peer socket in play, so the engine can wait on them. See
    /// [`RelayPoll`] for what each field says and why the wait set needs all of
    /// them.
    pub fn poll_snapshot(&self) -> Vec<RelayPoll> {
        self.relays
            .values()
            .filter(|r| !r.closed && r.peer_fd >= 0)
            .map(|r| {
                // During SOCKS5 negotiation only handshake output deserves a
                // writable wake: asking for POLLOUT because app bytes are
                // queued would spin until the proxy has answered.
                let want_write = if r.proxy_handshaking() {
                    r.handshake.as_ref().is_some_and(|h| h.wants_write())
                } else {
                    !r.pending_to_peer.is_empty()
                };
                RelayPoll {
                    gen: r.peer_gen,
                    client_port: r.flow.client_port,
                    fd: r.peer_fd,
                    connecting: r.connecting,
                    // A socket that is still connecting is writable when the
                    // connect finished; a connected one is writable when the
                    // client's queued bytes need draining.
                    want_write: !r.connecting && want_write,
                    paused: r.client_paused,
                }
            })
            .collect()
    }

    /// Drops relays that already finished. The engine calls this from its
    /// housekeeping pass so finished flows do not pile up.
    pub fn drop_closed(&mut self) -> usize {
        let before = self.relays.len();
        self.relays.retain(|_, r| !r.closed);
        before - self.relays.len()
    }
}

/// Decides whether a destination port is worth terminating TLS for.
pub fn is_mitm_port(port: u16) -> bool {
    port == MITM_PORT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::ca::CertificateAuthority;
    use crate::mitm::proxy::ProxySession;
    use crate::mitm::tls::{open_session, SniCertResolver};
    use std::sync::Arc;

    fn syn_packet() -> Vec<u8> {
        // Minimal IPv4/TCP SYN: enough for the segment builders, which parse
        // the template to swap addresses and ports.
        let mut p = Vec::new();
        p.extend_from_slice(&[0x45, 0x00, 0x00, 40, 0x00, 0x00, 0x00, 0x00, 64, 6, 0, 0]);
        p.extend_from_slice(&[10, 111, 42, 1]);
        p.extend_from_slice(&[142, 250, 185, 194]);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&1000u32.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        crate::packet::fix_ipv4_checksum(&mut p);
        p
    }

    fn relay() -> Relay {
        let ca = CertificateAuthority::generate().expect("ca");
        let resolver = Arc::new(SniCertResolver::new(Arc::new(
            CertificateAuthority::from_pem(&ca.cert_pem(), &ca.key_pem()).expect("restore"),
        )));
        let session = open_session(&resolver, "x.example.com").expect("session");
        let proxy = ProxySession::new(session, "/adfree-user.js".into(), Arc::from(""));
        Relay::new_tls(
            crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 443, 1000, 5000),
            -1,
            proxy,
            Vec::new(),
            DEFAULT_MSS,
            false,
        )
    }

    fn relay_with_syn() -> Relay {
        let mut r = relay();
        r.set_syn(syn_packet());
        // The engine sets this right after it answers the SYN: the SYN-ACK
        // consumed one client-facing sequence number.
        r.flow.up_bytes = 1;
        r
    }

    fn plain_relay_with_syn() -> Relay {
        let flow = crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 80, 1000, 5000);
        let mut r = Relay::new_plain(flow, -1, syn_packet(), DEFAULT_MSS, false);
        r.flow.up_bytes = 1;
        r
    }

    #[test]
    fn a_fresh_relay_is_not_yet_established() {
        // The client half is still handshaking, so no application data flows.
        let r = relay();
        assert!(!r.is_established());
        assert!(!r.closed);
    }

    #[test]
    fn a_plain_relay_moves_bytes_untouched() {
        let flow = crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 80, 1000, 5000);
        let mut r = Relay::new_plain(flow, -1, syn_packet(), DEFAULT_MSS, false);
        // No handshake to complete: bytes can flow immediately.
        assert!(r.is_established());
        let (to_peer, to_client) = r
            .on_client_segment(1001, b"GET / HTTP/1.1\r\n\r\n")
            .expect("step");
        assert_eq!(to_peer, b"GET / HTTP/1.1\r\n\r\n");
        assert!(to_client.is_empty());
        // The request must be acknowledged (client seq + 1 from the SYN).
        assert_eq!(r.flow.acked_seq, 1001 + 18);
        assert_eq!(r.flow.down_bytes, 18);
        let back = r
            .on_peer_data(b"HTTP/1.1 200 OK\r\n\r\n")
            .expect("peer step");
        assert_eq!(
            back,
            (Vec::new(), b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), false)
        );
    }

    /// What the last retired relay reported.
    static REPORTED: std::sync::Mutex<(String, u64, u64)> =
        std::sync::Mutex::new((String::new(), 0, 0));

    fn record(app: &str, sent: u64, recv: u64) {
        let mut slot = REPORTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = (app.to_string(), sent, recv);
    }

    fn reported() -> (String, u64, u64) {
        REPORTED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// A connection reports its payload once, when it retires: the SYN-ACK and
    /// the FIN are sequence numbers, not traffic, so they must not show up.
    #[test]
    fn a_retired_relay_reports_what_crossed_it() {
        let mut r = plain_relay_with_syn();
        r.traffic = Some(record);
        r.app_packages = vec!["com.example.app".to_string()];
        r.on_client_segment(1001, b"hello").expect("step");
        r.segments_for_client(b"1234567");
        assert_eq!(r.flow.up_bytes, 8, "up_bytes also counts the SYN-ACK");
        drop(r);
        assert_eq!(reported(), ("com.example.app".to_string(), 5, 7));

        // A relay that moved nothing is not a row.
        let mut quiet = plain_relay_with_syn();
        quiet.traffic = Some(record);
        drop(quiet);
        assert_eq!(
            reported(),
            ("com.example.app".to_string(), 5, 7),
            "the previous report is still there: nothing new was written"
        );
    }

    #[test]
    fn a_full_client_backlog_stops_peer_reads_until_acks_drain_it() {
        let mut r = plain_relay_with_syn();
        // A relay with no peer socket is not in the snapshot at all, so this
        // test needs a real descriptor to talk about.
        let peer = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(peer >= 0, "socket: {}", std::io::Error::last_os_error());
        r.attach_peer(peer);
        r.queue_to_client(&vec![0u8; MAX_PENDING_TO_CLIENT - 1]);
        assert!(!r.client_paused(), "the cap itself has not been reached");

        // A client that stops opening its window: the backlog reaches the cap
        // and the engine must leave the peer socket unread.
        r.flow.client_window = 0;
        r.queue_to_client(&[0u8]);
        assert!(r.client_paused());
        assert!(
            r.flush_to_client().is_empty(),
            "a zero window takes nothing"
        );
        assert!(r.client_paused());
        let mut table = RelayTable::new();
        table.insert(r);
        assert!(
            table.poll_snapshot()[0].paused,
            "the snapshot must tell the engine not to read the peer"
        );

        // ACKs open the window: the queue drains and the peer may be read
        // again.
        let mut r = table.remove(40000).expect("relay");
        r.flow.client_window = u32::MAX;
        let segments = r.flush_to_client();
        assert!(!segments.is_empty());
        assert!(r.pending_to_client.is_empty());
        assert!(!r.client_paused());
    }

    #[test]
    fn a_relay_that_has_no_peer_socket_yet_is_not_waited_on() {
        let mut table = RelayTable::new();
        table.insert(plain_relay_with_syn());
        assert!(
            table.poll_snapshot().is_empty(),
            "a descriptor of -1 would make the wait fail on a socket that does not exist"
        );
    }

    #[test]
    fn a_retransmission_is_forwarded_only_once() {
        let mut r = plain_relay_with_syn();
        let request = b"POST /x HTTP/1.1\r\n\r\nAB";
        let (first, _) = r.on_client_segment(1001, request).expect("step");
        assert_eq!(first, request);
        assert_eq!(r.flow.acked_seq, 1001 + 22);
        // The client retransmits while our ACK is in flight: a second copy of a
        // POST must never reach the peer.
        let (again, _) = r.on_client_segment(1001, request).expect("dup");
        assert!(again.is_empty());
        assert_eq!(
            r.flow.acked_seq,
            1001 + 22,
            "a duplicate must not advance the ack"
        );
        assert_eq!(r.flow.down_bytes, 22);
    }

    #[test]
    fn a_partial_overlap_forwards_only_the_new_tail() {
        let mut r = plain_relay_with_syn();
        let _ = r.on_client_segment(1001, b"abcdef").expect("step");
        // A retransmission that starts mid-way and carries new bytes at the
        // end (the client packeted ahead before our ACK arrived).
        let (tail, _) = r.on_client_segment(1004, b"defghi").expect("overlap");
        assert_eq!(tail, b"ghi");
        // 1004..1007 was already delivered ("def"); only the tail is new.
        assert_eq!(r.flow.acked_seq, 1010);
    }

    #[test]
    fn an_ack_to_the_client_carries_the_running_sequence() {
        let mut r = plain_relay_with_syn();
        let _ = r.on_client_segment(1001, b"GET /").expect("step");
        let ack = r.ack_to_client().expect("ack");
        let pkt = crate::packet::Packet::parse(&ack).expect("parse");
        assert!(pkt.is_ack && !pkt.is_fin);
        assert_eq!(
            pkt.seq, 5001,
            "no data sent yet: seq stays after the SYN-ACK"
        );
        assert_eq!(pkt.ack_seq, 1001 + 5);
    }

    #[test]
    fn an_invalid_tls_record_is_rejected() {
        let mut r = relay();
        // Record type 0 does not exist: rustls must fail loudly instead of
        // buffering noise forever.
        let bogus = [0x00, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00];
        let out = r.on_client_segment(1001, &bogus);
        assert!(out.is_err(), "an invalid record must be rejected: {out:?}");
    }

    #[test]
    fn a_partial_record_is_buffered_not_rejected() {
        let mut r = relay();
        // Only the first 4 bytes of a 5 byte record header: nothing to judge yet.
        let out = r.on_client_segment(1001, &[0x16, 0x03, 0x01, 0x00]);
        assert!(out.is_ok(), "a partial record is not an error: {out:?}");
        assert!(out.unwrap() == (Vec::new(), Vec::new()));
    }

    #[test]
    fn invalid_peer_records_never_become_plaintext() {
        let mut r = relay();
        // rustls is free to buffer or reject this; what must never happen is
        // junk surfacing as application data.
        let out = r.on_peer_data(&[0x00, 0x03, 0x01, 0x00, 0x02, 0x00, 0x00]);
        match out {
            Err(_) => {}
            Ok((to_peer, to_client, restart)) => {
                assert!(to_peer.is_empty(), "junk must not reach the peer");
                assert!(to_client.is_empty(), "junk must not become plaintext");
                assert!(!restart, "junk does not ask for a new peer socket");
            }
        }
    }

    #[test]
    fn close_marks_the_flow_closed() {
        let mut r = relay();
        r.close();
        assert!(r.closed);
        assert_eq!(r.flow.state, FlowState::Closed);
    }

    #[test]
    fn segments_are_bounded() {
        assert!(Relay::split_segments(Vec::new(), 100).is_empty());
        let small = Relay::split_segments(vec![1, 2, 3], 100);
        assert_eq!(small, vec![vec![1, 2, 3]]);

        let big = vec![7u8; 100 * 2 + 5];
        let chunks = Relay::split_segments(big.clone(), 100);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.len() <= 100));
        assert_eq!(chunks.iter().map(|c| c.len()).sum::<usize>(), big.len());
    }

    #[test]
    fn segments_never_exceed_the_client_mss() {
        // The tunnel MTU is 1500: a 1460 byte payload plus headers is the most
        // that can be written to the descriptor at once.
        let mut r = relay_with_syn();
        let payload = vec![1u8; 10_000];
        let segs = r.segments_for_client(&payload);
        assert!(segs.len() >= 7, "10k must split into MSS-sized pieces");
        for seg in &segs {
            let pkt = crate::packet::Packet::parse(seg).expect("parse");
            assert!(
                pkt.l4_payload_len <= DEFAULT_MSS,
                "segment payload {} above the MSS",
                pkt.l4_payload_len
            );
        }
    }

    #[test]
    fn client_data_advances_the_acknowledgement() {
        let mut r = relay_with_syn();
        let before = r.flow.acked_seq;
        // A bogus TLS record still counts as bytes the peer must be acked for:
        // the sequence bookkeeping must not depend on handshake state.
        let _ = r.on_client_segment(1001, &[0x16, 0x03, 0x01, 0x00]);
        assert_eq!(r.flow.acked_seq, before + 4);
    }

    #[test]
    fn peer_data_does_not_double_count_the_sequence() {
        let mut r = relay_with_syn();
        // Whatever the session returns, the client-facing sequence is advanced
        // exactly once, by `segments_for_client`.
        let payload = b"hello".to_vec();
        let segs = r.segments_for_client(&payload);
        assert_eq!(segs.len(), 1);
        let first = crate::packet::Packet::parse(&segs[0]).expect("parse");
        assert_eq!(first.seq, 5001); // my_seq + the SYN's sequence
        assert_eq!(r.flow.up_bytes, 6); // 1 (SYN) + 5
        let segs = r.segments_for_client(b"world");
        let second = crate::packet::Packet::parse(&segs[0]).expect("parse");
        assert_eq!(second.seq, 5006, "consecutive segments must not skip");
    }

    #[test]
    fn client_fin_is_acked_once() {
        let mut r = relay_with_syn();
        let before = r.flow.acked_seq;
        let ack = r.on_client_fin().expect("ack");
        let pkt = crate::packet::Packet::parse(&ack).expect("parse");
        assert!(pkt.is_ack && !pkt.is_fin);
        assert_eq!(r.flow.acked_seq, before + 1);
        assert!(r.client_fin);
    }

    #[test]
    fn peer_eof_sends_a_fin_and_closes() {
        let mut r = relay_with_syn();
        let fin = r.on_peer_eof().expect("fin");
        let pkt = crate::packet::Packet::parse(&fin).expect("parse");
        assert!(pkt.is_fin && pkt.is_ack);
        assert!(r.closed);
        assert_eq!(r.flow.up_bytes, 2, "the FIN consumes one sequence number");
    }

    #[test]
    fn closed_relays_are_pruned() {
        let mut table = RelayTable::new();
        table.insert(relay());
        assert_eq!(table.len(), 1);
        table.get_mut(40000).unwrap().close();
        assert_eq!(table.drop_closed(), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn only_https_is_terminated() {
        assert!(is_mitm_port(443));
        assert!(!is_mitm_port(80));
        assert!(!is_mitm_port(53));
    }

    #[test]
    fn empty_payloads_are_no_ops() {
        let mut r = relay();
        assert_eq!(
            r.on_client_segment(1001, &[]).unwrap(),
            (Vec::new(), Vec::new())
        );
        assert_eq!(
            r.on_peer_data(&[]).unwrap(),
            (Vec::new(), Vec::new(), false)
        );
    }

    /// The engine's own path: a browser, a `Relay`, and an origin, with the
    /// relay in the middle exactly as the engine drives it.
    ///
    /// Regression: `on_peer_data` used to return only the client-bound bytes,
    /// dropping what the upstream half produced while processing server data
    /// (its protocol Finished and the request buffered behind it). The origin
    /// then never completed its handshake, and every HTTPS page died with an
    /// empty response.
    #[test]
    fn on_peer_data_carries_the_upstreams_own_bytes() {
        use crate::mitm::proxy_tests::{feed_browser, feed_origin};
        use rustls::pki_types::ServerName;
        use rustls::{ClientConnection, ServerConnection};
        use std::io::Write;

        // The origin's CA: the certificate the upstream half must trust.
        let origin_ca = CertificateAuthority::generate().expect("origin ca");
        let mut origin_roots = rustls::RootCertStore::empty();
        origin_roots
            .add(rustls::pki_types::CertificateDer::from(
                origin_ca.cert_der(),
            ))
            .expect("origin root");

        // The CA the browser trusts: the one we present to it.
        let mitm_ca = CertificateAuthority::generate().expect("mitm ca");
        let resolver = Arc::new(SniCertResolver::new(Arc::new(
            CertificateAuthority::from_pem(&mitm_ca.cert_pem(), &mitm_ca.key_pem())
                .expect("restore"),
        )));
        let session = crate::mitm::tls::open_session_with(
            &resolver,
            "origin.example.com",
            crate::mitm::tls::UpstreamTls::with_roots(origin_roots),
        )
        .expect("session");
        let proxy = ProxySession::new(session, String::new(), Arc::from(""));
        let mut relay = Relay::new_tls(
            crate::mitm::tcp::Flow::new(crate::packet::IpKey::V4(1), 40000, 443, 1000, 5000),
            -1,
            proxy,
            Vec::new(),
            DEFAULT_MSS,
            false,
        );

        // The origin, minting leaves from its own CA.
        let origin_resolver = Arc::new(SniCertResolver::new(Arc::new(origin_ca)));
        let mut origin = ServerConnection::new(crate::mitm::tls::server_config(origin_resolver))
            .expect("origin");

        // The fake browser.
        let mut browser_roots = rustls::RootCertStore::empty();
        browser_roots
            .add(rustls::pki_types::CertificateDer::from(mitm_ca.cert_der()))
            .expect("browser root");
        let name = ServerName::try_from("origin.example.com".to_string()).expect("server name");
        let mut browser =
            ClientConnection::new(crate::mitm::tls::client_config_with(browser_roots), name)
                .expect("browser");

        let request = b"GET / HTTP/1.1\r\nHost: origin.example.com\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        browser
            .writer()
            .write_all(request)
            .expect("browser writes the request");

        let mut to_origin: Vec<u8> = Vec::new();
        let mut origin_request: Vec<u8> = Vec::new();
        let mut browser_plain: Vec<u8> = Vec::new();
        let mut origin_answered = false;

        for _round in 0..64 {
            // browser -> relay -> origin
            let wire = crate::mitm::tls::take_client_outbound(&mut browser);
            if !wire.is_empty() {
                let seq = relay.flow.acked_seq;
                let (to_peer, to_client) =
                    relay.on_client_segment(seq, &wire).expect("client step");
                to_origin.extend_from_slice(&to_peer);
                feed_browser(&mut browser, &to_client, &mut browser_plain);
            }
            if !to_origin.is_empty() {
                feed_origin(&mut origin, &to_origin, &mut origin_request);
                to_origin.clear();
                if !origin_answered && !origin_request.is_empty() {
                    origin
                        .writer()
                        .write_all(response)
                        .expect("origin writes the response");
                    origin_answered = true;
                }
            }
            // origin -> relay -> browser
            let wire = crate::mitm::tls::take_server_outbound(&mut origin);
            if !wire.is_empty() {
                let (to_peer, to_client, _restart) = relay.on_peer_data(&wire).expect("peer step");
                to_origin.extend_from_slice(&to_peer);
                feed_browser(&mut browser, &to_client, &mut browser_plain);
            }
            if browser_plain.windows(12).any(|w| w == b"HTTP/1.1 200") {
                break;
            }
        }

        assert_eq!(
            origin_request, request,
            "the origin must receive the request byte for byte"
        );
        assert!(
            browser_plain.starts_with(b"HTTP/1.1 200 OK"),
            "the browser must receive the response"
        );
    }

    /// Anti-DPI has one job: keep the server name out of the first segment of a
    /// connection. Anything else — a switch flipped off, bytes that already
    /// followed the hello, plain HTTP — must go out exactly as it came, because
    /// splitting a download would cost packets and prove nothing.
    #[test]
    fn anti_dpi_splits_only_the_first_handshake_record() {
        let hello: Vec<u8> = std::iter::once(0x16u8)
            .chain((0..1_400u32).map(|i| (i % 250) as u8))
            .collect();
        let http = b"GET / HTTP/1.1\r\n\r\n".to_vec();

        let mut relay = plain_relay_with_syn();
        assert_eq!(None, relay.anti_dpi_head(&hello, false));
        assert_eq!(Some(ANTI_DPI_HEAD), relay.anti_dpi_head(&hello, true));
        // Not a handshake record.
        assert_eq!(None, relay.anti_dpi_head(&http, true));
        // Nothing to hide in a fragment shorter than the cut.
        assert_eq!(None, relay.anti_dpi_head(&hello[..20], true));
        // The opening has been sent, so this is no longer the first flight.
        relay.opening_sent = true;
        assert_eq!(None, relay.anti_dpi_head(&hello, true));
    }

    /// The cut has to land before the extension area, or the server name stays
    /// in the segment a matcher reads.
    #[test]
    fn the_anti_dpi_cut_leaves_the_extensions_for_the_next_segment() {
        // A hello laid out the way TLS lays one out: record header 5, handshake
        // header 4, legacy version 2, random 32. The body — where the server
        // name lives — starts at byte 43.
        let mut hello: Vec<u8> = vec![
            RECORD_HANDSHAKE,
            0x03,
            0x03,
            0x01,
            0x00,
            0x01,
            0x00,
            0x00,
            0xc0,
            0x03,
            0x03,
        ];
        hello.extend_from_slice(&[0xa5; 32]);
        let body = b"server-name-in-the-extensions".to_vec();
        hello.extend_from_slice(&body);

        let relay = plain_relay_with_syn();
        let cut = relay
            .anti_dpi_head(&hello, true)
            .expect("the opening flight of a handshake is what gets split");

        // Everything before the body, counted from the bytes rather than taken
        // from the comment above: the cut may never reach it.
        let header_len = hello.len() - body.len();
        assert!(
            cut < header_len,
            "the split must stay inside header and random: {cut} of {header_len}"
        );
    }
}
