//! The wire the browser extension's helper process talks to.
//!
//! The buck used to stop here: the window process listened on a Unix socket and
//! answered, which meant the extension was served by whichever process happened
//! to own the window. Two things are wrong with that. The extension's helper is
//! a pipe (`adfree-native-host`) that forwards Chrome's frames, so the *wire* —
//! framing, endpoint, lifecycle — belongs to the process that owns the filtering
//! engine, not to a window that can be closed while the engine keeps working.
//! And Windows has no Unix socket to hand a user: it has named pipes with an
//! ACL, or loopback with a token. That is a platform difference, and this crate
//! already has a place for those.
//!
//! What is *not* here is what to answer. A request asks about tabs, settings,
//! the window and the user's rules; that state lives on the app side, so the
//! core calls back into it through [`crate::api::AssistantHost`]. The split is
//! the same one the redirect uses: mechanics here, decisions where the state is.
//!
//! Chrome's framing is a 4-byte little-endian length followed by JSON, and it is
//! implemented once, here, for the listener *and* for the helper binary — the
//! two used to spell the same bytes in two languages.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::api::AssistantHost;

/// The socket's file name on Unix, beside the app's other runtime files.
pub const SOCKET_NAME: &str = "adfree-assistant.sock";
/// Where Windows publishes `host:port` and the token that proves a caller is
/// the user's own helper rather than anything else on the machine.
pub const ENDPOINT_FILE: &str = "assistant.endpoint";

/// One native-messaging frame. `None` means the peer hung up cleanly.
pub fn read_frame(input: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        match input.read(&mut header[got..]) {
            Ok(0) => return Ok(None),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let length = u32::from_le_bytes(header) as usize;
    // A length read the other way round is a nonsense size; the ceiling keeps a
    // misread header from asking for a gigabyte.
    if length == 0 || length > 64 * 1024 * 1024 {
        return Ok(None);
    }
    let mut body = vec![0u8; length];
    let mut have = 0;
    while have < length {
        match input.read(&mut body[have..]) {
            Ok(0) => return Ok(None),
            Ok(n) => have += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Some(body))
}

pub fn write_frame(output: &mut impl Write, message: &[u8]) -> std::io::Result<()> {
    output.write_all(&(message.len() as u32).to_le_bytes())?;
    output.write_all(message)?;
    output.flush()
}

/// Where an answer to this connection is written.
///
/// The reader and the writer are separate handles to the same socket, so a push
/// can be written while a request is still being read or answered. One mutex per
/// connection: Chrome may read slowly, and everything written has to stay in
/// whole frames.
type Sink = Arc<Mutex<Box<dyn Write + Send>>>;

static SINKS: Mutex<Vec<(u64, Sink)>> = Mutex::new(Vec::new());
static NEXT_SINK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn register(writer: Box<dyn Write + Send>) -> u64 {
    let id = NEXT_SINK.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut sinks) = SINKS.lock() {
        sinks.push((id, Arc::new(Mutex::new(writer))));
    }
    id
}

fn unregister(id: u64) {
    if let Ok(mut sinks) = SINKS.lock() {
        sinks.retain(|(other, _)| *other != id);
    }
}

/// Writes one frame to every connected popup.
///
/// The extension only hands an unsolicited message to its own listeners when
/// `requestId` starts with `ADG` (`background/api` drops the rest as a reply
/// nothing asked for), so the app builds the message; this only carries it.
/// A connection whose write fails is dropped: it is a popup that closed.
pub fn push(message: &[u8]) {
    let sinks: Vec<(u64, Sink)> = match SINKS.lock() {
        Ok(sinks) => sinks.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    for (id, sink) in sinks {
        let sent = match sink.lock() {
            Ok(mut writer) => write_frame(&mut *writer, message).is_ok(),
            Err(_) => false,
        };
        if !sent {
            unregister(id);
        }
    }
}

struct Running {
    address: String,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    /// Removed when the listener goes away: a socket file, or the endpoint file
    /// naming a port and a token.
    cleanup: Option<std::path::PathBuf>,
}

static RUNNING: Mutex<Option<Running>> = Mutex::new(None);

/// Starts listening and returns the address the helper connects to.
///
/// Idempotent in the way the caller expects: the bridge is started when the
/// window appears and again after a hand-over, and the second start is not an
/// error.
pub fn start(dir: &str, host: Arc<dyn AssistantHost>) -> Result<String, String> {
    let mut slot = RUNNING.lock().map_err(|_| "assistant lock poisoned")?;
    if let Some(running) = slot.as_ref() {
        return Ok(running.address.clone());
    }
    let directory = std::path::Path::new(dir);
    std::fs::create_dir_all(directory)
        .map_err(|e| format!("cannot create {}: {e}", directory.display()))?;
    let stop = Arc::new(AtomicBool::new(false));
    let started = listen(directory, host, Arc::clone(&stop))?;
    *slot = Some(Running {
        address: started.address.clone(),
        stop,
        thread: Some(started.thread),
        cleanup: started.cleanup,
    });
    Ok(started.address)
}

pub fn stop() {
    let running = {
        let mut slot = match RUNNING.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        slot.take()
    };
    let Some(mut running) = running else { return };
    running.stop.store(true, Ordering::SeqCst);
    // The accept loop wakes because the address is closed under it; the reader
    // below is the simpler half of that: closing the listener is what unblocks
    // `accept`, and the thread is joined so a restart cannot race the old one.
    close_listener(&running.address);
    // Live popups belong to the listener that is going away; their next frame
    // would be answered by nobody, and a socket the process no longer tracks is
    // worse than a closed one.
    if let Ok(mut sinks) = SINKS.lock() {
        sinks.clear();
    }
    if let Some(path) = running.cleanup.as_ref() {
        let _ = std::fs::remove_file(path);
    }
    if let Some(thread) = running.thread.take() {
        let _ = thread.join();
    }
}

pub fn address() -> Option<String> {
    RUNNING
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(|r| r.address.clone()))
}

struct Started {
    address: String,
    thread: JoinHandle<()>,
    cleanup: Option<std::path::PathBuf>,
}

/// Closes whatever the listener is bound to, so `accept` returns.
fn close_listener(address: &str) {
    // Connecting to our own endpoint is enough: the loop notices the stop flag
    // on the next iteration. Nothing is sent — the connection is dropped.
    #[cfg(unix)]
    {
        let _ = std::os::unix::net::UnixStream::connect(address);
    }
    #[cfg(windows)]
    {
        if let Ok(addr) = address.parse::<std::net::SocketAddr>() {
            let _ = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(200));
        }
    }
}

/// One client, start to finish. `token` is the Windows handshake: the helper
/// introduces itself before its first request.
fn serve<R: Read, W: Write + Send + 'static>(
    mut reader: R,
    writer: W,
    host: &dyn AssistantHost,
    token: Option<&str>,
) {
    if let Some(expected) = token {
        let Ok(Some(first)) = read_frame(&mut reader) else { return };
        let presented = std::str::from_utf8(&first)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
            .and_then(|value| value.get("token").and_then(|t| t.as_str()).map(str::to_string))
            .unwrap_or_default();
        if presented != expected {
            return;
        }
    }
    let id = register(Box::new(writer));
    let sink = match SINKS.lock() {
        Ok(sinks) => sinks.iter().find(|(other, _)| *other == id).map(|(_, sink)| Arc::clone(sink)),
        Err(_) => None,
    };
    let Some(sink) = sink else {
        unregister(id);
        return;
    };
    loop {
        match read_frame(&mut reader) {
            Ok(Some(request)) => {
                let Some(answer) = host.respond(request) else { break };
                let sent = match sink.lock() {
                    Ok(mut writer) => write_frame(&mut *writer, &answer).is_ok(),
                    Err(_) => false,
                };
                if !sent {
                    break;
                }
            }
            // A popup that closes mid-answer is normal, not a fault.
            Ok(None) | Err(_) => break,
        }
    }
    unregister(id);
}

#[cfg(unix)]
fn listen(dir: &std::path::Path, host: Arc<dyn AssistantHost>, stop: Arc<AtomicBool>) -> Result<Started, String> {
    use std::os::unix::net::UnixListener;

    let path = dir.join(SOCKET_NAME);
    // A Unix socket is a *file*: a killed app leaves it behind and the next
    // start cannot take the name. Deleting it blindly would be wrong in the one
    // case that matters — a second instance of the window — so it is probed
    // first: a live listener accepts, a corpse refuses, and only a corpse is
    // removed.
    if path.exists() {
        let alive = std::os::unix::net::UnixStream::connect(&path).is_ok();
        if alive {
            return Err(format!("another AdFree window owns {}", path.display()));
        }
        let _ = std::fs::remove_file(&path);
    }
    let listener = UnixListener::bind(&path).map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
    // A socket file is created with the umask's permissions — usually world
    // readable — and whoever can connect can switch protection off. The
    // directory is the app's own; the mode makes that explicit rather than
    // inherited from whatever launched the app.
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    let address = path.to_string_lossy().to_string();
    let thread = {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("adfree-assistant".to_string())
            .spawn(move || {
                for incoming in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = incoming else { continue };
                    // Two handles on one socket: reading must not hold the
                    // write side while a push is being delivered.
                    let Ok(writer) = stream.try_clone() else { continue };
                    let host = Arc::clone(&host);
                    std::thread::spawn(move || serve(stream, writer, host.as_ref(), None));
                }
            })
            .map_err(|e| format!("cannot start the assistant thread: {e}"))?
    };
    Ok(Started {
        address,
        thread,
        cleanup: Some(path),
    })
}

#[cfg(windows)]
fn listen(dir: &std::path::Path, host: Arc<dyn AssistantHost>, stop: Arc<AtomicBool>) -> Result<Started, String> {
    use std::net::TcpListener;

    // Loopback only, and a token the endpoint file carries: Windows has no
    // Unix socket to give a user, and an unauthenticated local port would let
    // any process on the machine drive the filtering engine.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("cannot listen on loopback: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let token = random_token();
    let file = dir.join(ENDPOINT_FILE);
    std::fs::write(&file, format!("127.0.0.1:{port}\n{token}\n"))
        .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    let address = format!("127.0.0.1:{port}");
    let thread = {
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("adfree-assistant".to_string())
            .spawn(move || {
                for incoming in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = incoming else { continue };
                    let Ok(writer) = stream.try_clone() else { continue };
                    let host = Arc::clone(&host);
                    let token = token.clone();
                    std::thread::spawn(move || serve(stream, writer, host.as_ref(), Some(&token)));
                }
            })
            .map_err(|e| format!("cannot start the assistant thread: {e}"))?
    };
    Ok(Started {
        address,
        thread,
        cleanup: Some(file),
    })
}

/// A token no other local process can guess.
///
/// The endpoint file is readable only by the user, so the token is the second
/// lock: a process that ignores file permissions — or one running as another
/// user on the same machine — cannot forge it.
#[cfg(windows)]
fn random_token() -> String {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut bytes = [0u8; 32];
    let rng = SystemRandom::new();
    if rng.fill(&mut bytes).is_err() {
        // A machine whose entropy source is dead still gets a token that is not
        // shared with anything else on it; the clock and the pid are enough for
        // the length of one session.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        bytes[..16].copy_from_slice(&now.to_le_bytes());
        bytes[16..].copy_from_slice(&pid.to_le_bytes());
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
