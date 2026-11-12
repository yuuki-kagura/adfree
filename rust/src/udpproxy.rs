//! UDP ASSOCIATE for one NAT mapping.
//!
//! SOCKS5 relays UDP only through a TCP control connection: the client asks
//! for an association, the proxy names a relay endpoint, and every datagram
//! travels inside a small header. The packet loop is non-blocking, so a
//! dedicated thread owns the control and relay sockets for one mapping and
//! shuttles payloads over a `socketpair` the forwarder already polls. When the
//! mapping is retired, closing the engine end ends the thread.
//!
//! One association per mapping keeps the reply demultiplexing trivial: a
//! relay datagram can only belong to the flow that opened it.

use crate::api::SocketProtector;
use crate::packet::IpKey;
use crate::socks5::{ProxyEndpoint, Socks5Handshake};
use crate::sys::fd::RawFd;
use std::sync::Arc;
use crate::sys::libc;

const CONNECT_TIMEOUT_MS: i32 = 8_000;
const CONTROL_TIMEOUT: libc::timeval = libc::timeval {
    tv_sec: 10,
    tv_usec: 0,
};
const MAX_DATAGRAM: usize = 65_507;

/// Starts the association for one mapping. The thread creates, protects and
/// owns its control and relay sockets; the caller keeps (and later closes) the
/// other end of the `bridge_fd` pair, which is what ends the thread.
pub fn spawn(
    bridge_fd: RawFd,
    proxy: Arc<ProxyEndpoint>,
    protector: Arc<dyn SocketProtector>,
    server: IpKey,
    server_port: u16,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("adfree-udp-proxy".into())
        .spawn(move || run(bridge_fd, proxy, protector, server, server_port))
}

fn run(
    bridge_fd: RawFd,
    proxy: Arc<ProxyEndpoint>,
    protector: Arc<dyn SocketProtector>,
    server: IpKey,
    server_port: u16,
) {
    let bridge = OwnedFd(bridge_fd);
    let (control, relay) = match associate(&proxy, protector.as_ref()) {
        Ok(sockets) => sockets,
        Err(reason) => {
            crate::logbuf::push(&format!("udp proxy: {reason}"));
            return;
        }
    };
    set_blocking(bridge.0);
    shuttle(&control, &relay, &bridge, server, server_port);
}

/// Opens a socket towards `address`, asks the app to route it around the VPN
/// and leaves it non-blocking so `connect` can bound the wait.
fn peer_socket(
    address: IpKey,
    kind: libc::c_int,
    protector: &dyn SocketProtector,
) -> Option<OwnedFd> {
    let family = match address {
        IpKey::V4(_) => libc::AF_INET,
        IpKey::V6(_) => libc::AF_INET6,
    };
    let fd = unsafe { libc::socket(family, kind | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0) };
    if !crate::sys::fd::fd_ok(fd) {
        return None;
    }
    if !protector.protect(fd as i32) {
        unsafe { libc::close(fd) };
        return None;
    }
    Some(OwnedFd(fd))
}

/// Runs the handshake and dials the relay address the proxy returned. The
/// control connection must stay open for as long as the association lives, so
/// it is returned with the relay.
fn associate(
    proxy: &ProxyEndpoint,
    protector: &dyn SocketProtector,
) -> Result<(OwnedFd, OwnedFd), String> {
    let control = peer_socket(proxy.addr, libc::SOCK_STREAM, protector)
        .ok_or("cannot open a protected control socket")?;
    set_timeout(control.0);
    if !connect(control.0, proxy.addr, proxy.port) {
        return Err("connect to the proxy failed".into());
    }
    set_blocking(control.0);
    let mut handshake =
        Socks5Handshake::new_udp_associate(proxy.credentials()).map_err(str::to_string)?;
    let mut buffer = [0u8; 1024];
    loop {
        if handshake.wants_write() {
            write_all(control.0, &handshake.take_output())?;
        }
        if handshake.is_done() {
            break;
        }
        let read = read_some(control.0, &mut buffer)?;
        if read == 0 {
            return Err("proxy closed the control connection".into());
        }
        handshake
            .on_bytes(&buffer[..read])
            .map_err(str::to_string)?;
    }
    let (address, port) = handshake
        .bound()
        .ok_or_else(|| "proxy returned no UDP relay endpoint".to_string())?;
    // 0.0.0.0 / :: means "the address you reached me on".
    let address = if is_unspecified(address) {
        proxy.addr
    } else {
        address
    };
    let relay = peer_socket(address, libc::SOCK_DGRAM, protector)
        .ok_or("cannot open a protected relay socket")?;
    if !connect(relay.0, address, port) {
        return Err("connect to the UDP relay failed".into());
    }
    set_blocking(relay.0);
    Ok((control, relay))
}

fn shuttle(control: &OwnedFd, relay: &OwnedFd, bridge: &OwnedFd, server: IpKey, server_port: u16) {
    let mut buffer = [0u8; MAX_DATAGRAM];
    loop {
        let mut fds = [
            libc::pollfd {
                fd: bridge.0,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: relay.0,
                events: libc::POLLIN,
                revents: 0,
            },
            // The proxy announces the end of the association on the control
            // connection; nothing can be relayed after that.
            libc::pollfd {
                fd: control.0,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 3, 1_000) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                crate::logbuf::push(&format!("udp proxy: poll failed: {error}"));
                return;
            }
            continue;
        }
        if fds[0].revents != 0 {
            let read = unsafe {
                libc::recv(
                    bridge.0,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            if read <= 0 {
                return;
            }
            let mut packet = Vec::with_capacity(read as usize + 22);
            packet.extend_from_slice(&[0, 0, 0]);
            push_address(&mut packet, server);
            packet.extend_from_slice(&server_port.to_be_bytes());
            packet.extend_from_slice(&buffer[..read as usize]);
            send_to(relay.0, &packet);
        }
        if fds[1].revents != 0 {
            let read = unsafe {
                libc::recv(
                    relay.0,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            if read <= 0 {
                if fds[1].revents & libc::POLLIN == 0 {
                    return;
                }
                continue;
            }
            let Some(payload) = decapsulate(&buffer[..read as usize]) else {
                continue;
            };
            unsafe {
                libc::send(
                    bridge.0,
                    payload.as_ptr() as *const libc::c_void,
                    payload.len(),
                    libc::MSG_NOSIGNAL,
                );
            }
        }
        // The engine closed its end: the mapping is gone.
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return;
        }
        if fds[2].revents != 0 {
            return;
        }
    }
}

/// `[RSV RSV FRAG ATYP ADDR PORT]` in front of every relayed datagram.
fn push_address(out: &mut Vec<u8>, address: IpKey) {
    match address {
        IpKey::V4(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_be_bytes());
        }
        IpKey::V6(value) => {
            out.push(4);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decapsulate(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 4 || packet[2] != 0 {
        // Fragments are not supported; asking the sender to stop fragmenting
        // is cheaper than reassembling without a reassembly timer.
        return None;
    }
    let start = match packet[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        3 => {
            let length = *packet.get(4)? as usize;
            4 + 1 + length + 2
        }
        _ => return None,
    };
    packet.get(start..)
}

fn is_unspecified(address: IpKey) -> bool {
    match address {
        IpKey::V4(value) => value == 0,
        IpKey::V6(value) => value == 0,
    }
}

fn set_blocking(fd: RawFd) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    }
}

fn set_timeout(fd: RawFd) {
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &CONTROL_TIMEOUT as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &CONTROL_TIMEOUT as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

fn connect(fd: RawFd, address: IpKey, port: u16) -> bool {
    let (_, storage, length) = sockaddr(address, port);
    let ready = unsafe { libc::connect(fd, &storage as *const _ as *const libc::sockaddr, length) };
    if ready == 0 {
        return true;
    }
    // A non-blocking socket reports EINPROGRESS; the caller handed us a
    // blocking one, but the engine may have created it non-blocking.
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EINPROGRESS) {
        return false;
    }
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut poll, 1, CONNECT_TIMEOUT_MS) };
    if ready <= 0 {
        return false;
    }
    let mut status: libc::c_int = -1;
    let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            &mut status as *mut libc::c_int as *mut libc::c_void,
            &mut size,
        )
    };
    ok == 0 && status == 0
}

fn sockaddr(address: IpKey, port: u16) -> (libc::c_int, libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match address {
        IpKey::V4(value) => {
            let sin = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in;
            unsafe {
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_port = port.to_be();
                // `s_addr` holds the octets in memory order, so reverse the
                // host-order value before storing it.
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(value.to_be_bytes());
            }
            (
                libc::AF_INET,
                storage,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        IpKey::V6(value) => {
            let sin6 = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6;
            unsafe {
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = port.to_be();
                (*sin6).sin6_addr.s6_addr = value.to_be_bytes();
            }
            (
                libc::AF_INET6,
                storage,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn read_some(fd: RawFd, buffer: &mut [u8]) -> Result<usize, String> {
    let read = unsafe {
        libc::recv(
            fd,
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
            0,
        )
    };
    if read < 0 {
        return Err(format!(
            "control read failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(read as usize)
}

fn write_all(fd: RawFd, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let written = unsafe {
            libc::send(
                fd,
                bytes.as_ptr() as *const libc::c_void,
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if written <= 0 {
            return Err(format!(
                "control write failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn send_to(fd: RawFd, bytes: &[u8]) {
    unsafe {
        libc::send(
            fd,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
            libc::MSG_NOSIGNAL,
        );
    }
}

/// Closes its descriptor when the thread ends, on every exit path.
struct OwnedFd(RawFd);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if crate::sys::fd::fd_ok(self.0) {
            unsafe { libc::close(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};

    struct AllowAll;

    impl SocketProtector for AllowAll {
        fn protect(&self, _fd: i32) -> bool {
            true
        }
    }

    fn bridge_pair() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        // SEQPACKET keeps datagram boundaries and reports the peer closing,
        // unlike DGRAM where a closed peer never wakes a poll.
        let ok =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };
        assert_eq!(ok, 0, "socketpair() failed");
        fds.into()
    }

    #[test]
    fn a_relayed_datagram_comes_back_over_the_bridge() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let proxy_port = listener.local_addr().unwrap().port();
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay");
        relay
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let relay_port = relay.local_addr().unwrap().port();

        let mock = std::thread::spawn(move || {
            let (mut control, _) = listener.accept().expect("accept");
            control
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut greeting = [0u8; 3];
            control.read_exact(&mut greeting).expect("greeting");
            assert_eq!(greeting, [5, 1, 0]);
            control.write_all(&[5, 0]).expect("method");
            let mut request = [0u8; 10];
            control.read_exact(&mut request).expect("associate");
            assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
            let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
            reply.extend_from_slice(&relay_port.to_be_bytes());
            control.write_all(&reply).expect("bound");
            let mut datagram = [0u8; 2048];
            let (read, from) = relay.recv_from(&mut datagram).expect("relay recv");
            decapsulate(&datagram[..read]).expect("relay header");
            // Echo the whole encapsulated datagram back, like a real proxy.
            relay.send_to(&datagram[..read], from).expect("relay send");
            // Keep the control connection open until the client leaves.
            let mut sink = [0u8; 1];
            let _ = control.read(&mut sink);
        });

        let (engine_end, thread_end) = bridge_pair();
        let server = crate::packet::ip_key_from("1.1.1.1".parse().unwrap());
        let proxy = Arc::new(crate::socks5::ProxyEndpoint {
            addr: crate::packet::ip_key_from("127.0.0.1".parse().unwrap()),
            port: proxy_port,
            username: String::new(),
            password: String::new(),
            automatic: true,
        });
        spawn(thread_end, proxy, Arc::new(AllowAll), server, 53).expect("spawn");

        let payload = b"hello over socks";
        unsafe {
            libc::send(
                engine_end,
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                libc::MSG_NOSIGNAL,
            );
        }
        let mut received = [0u8; 64];
        let read = unsafe {
            libc::recv(
                engine_end,
                received.as_mut_ptr() as *mut libc::c_void,
                received.len(),
                0,
            )
        };
        assert!(read > 0, "no relayed payload");
        assert_eq!(&received[..read as usize], payload);
        unsafe { libc::close(engine_end) };
        mock.join().expect("mock");
    }
}
