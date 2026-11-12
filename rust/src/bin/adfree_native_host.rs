//! The native-messaging host AdGuard's browser extension talks to.
//!
//! AdGuard's Browser Assistant is a Chrome extension that cannot touch a
//! filtering engine by itself: it opens a **native messaging** port to a host
//! named `com.adguard.browser_extension_host.nm` and asks *that* process for
//! everything — is the app installed, is protection on, add this rule, open
//! the filtering log. On Windows and macOS that host is shipped by AdGuard.
//! This is the Linux half.
//!
//! The host is deliberately dumb. Chrome starts it with a pair of pipes and a
//! 4-byte little-endian length in front of every JSON message; the filtering
//! core inside AdFree owns the state and the tunnel, and the core is the side
//! that listens (see `src/assistant.rs`). So this process is a pipe: a message
//! from Chrome goes to the core over the endpoint the core publishes, and the
//! answer goes back, frame for frame. Nothing here decides anything.
//!
//! The endpoint is a Unix socket on Linux — the directory it lives in is the
//! authorization, because only this user may open it — and loopback plus a
//! token on Windows, which has no Unix socket to give. Both are found through
//! the same published address, so the rest of this file does not branch.
//!
//! Chrome also passes the calling extension's origin as `argv[1]`; it is not
//! used: the endpoint already answers only its owner.


/// The host itself: the same code on every platform, because the endpoint
/// already hides the difference.
mod host {
use std::io::{self, Read, Write};
use std::time::Duration;

use adfree_core::assistant::{read_frame, write_frame};

/// Where the app listens: its data directory, the same one the window and the
/// privileged unit share.
fn socket_candidates() -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;
    let mut paths = Vec::new();
    #[cfg(unix)]
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        // An older window listens in the runtime directory; a socket that is
        // there is still the app, and refusing it would answer "not running"
        // to a popup on a machine that is filtering just fine.
        paths.push(dir.join("adfree").join(adfree_core::assistant::SOCKET_NAME));
        paths.push(dir.join(adfree_core::assistant::SOCKET_NAME));
    }
    if let Some(dir) = std::env::var_os("ADFREE_DATA_DIR") {
        paths.push(PathBuf::from(dir).join(adfree_core::assistant::SOCKET_NAME));
    }
    #[cfg(windows)]
    if let Some(dir) = std::env::var_os("LOCALAPPDATA") {
        paths.push(
            std::path::Path::new(&dir)
                .join("adfree")
                .join(adfree_core::assistant::ENDPOINT_FILE),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(
            std::path::Path::new(&home)
                .join(".local/share/adfree")
                .join(adfree_core::assistant::SOCKET_NAME),
        );
    }
    #[cfg(windows)]
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        paths.push(
            std::path::Path::new(&profile)
                .join(".local/share/adfree")
                .join(adfree_core::assistant::ENDPOINT_FILE),
        );
    }
    paths
}

/// A live connection to the core, however that platform reaches it.
trait Wire: Read + Write + Send {}
impl<T: Read + Write + Send> Wire for T {}

/// Connects, or `None` when nothing is listening.
#[cfg(unix)]
fn connect() -> Option<Box<dyn Wire>> {
    use std::os::unix::net::UnixStream;
    socket_candidates()
        .into_iter()
        .find_map(|path| UnixStream::connect(path).ok())
        .map(|stream| {
            // A socket whose peer is alive but busy — rebuilding a filter
            // engine, starting listeners — must not hold a message for
            // minutes. The timeout turns a stall into an answer the popup can
            // show and the user can retry.
            let _ = stream.set_read_timeout(Some(ANSWER_TIMEOUT));
            Box::new(stream) as Box<dyn Wire>
        })
}

/// Windows reaches the same core over loopback, with the token the core wrote
/// beside its port: the file's permissions are the first lock, this is the
/// second.
#[cfg(windows)]
fn connect() -> Option<Box<dyn Wire>> {
    use std::net::TcpStream;
    for path in socket_candidates() {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let mut lines = text.lines();
        let (Some(address), Some(token)) = (lines.next(), lines.next()) else { continue };
        let Ok(stream) = address.parse::<std::net::SocketAddr>() else { continue };
        let Ok(mut stream) = TcpStream::connect_timeout(&stream, Duration::from_secs(2)) else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(ANSWER_TIMEOUT));
        let hello = serde_json::json!({ "token": token }).to_string();
        if write_frame(&mut stream, hello.as_bytes()).is_err() {
            continue;
        }
        return Some(Box::new(stream));
    }
    None
}

/// The `id` a request carries, so its answer can be told apart from a push.
fn request_id(message: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(message)
        .ok()
        .and_then(|value| value.get("id").and_then(|id| id.as_str()).map(str::to_string))
        .unwrap_or_default()
}

/// The `requestId` a reply or push carries.
fn response_id(message: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(message)
        .ok()
        .and_then(|value| {
            value
                .get("requestId")
                .and_then(|id| id.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

/// Forwards frames from the app until the one answering `request` has gone by.
///
/// Pushes are forwarded too: the extension's popup is fed by them. Without the
/// id check the *first* frame was taken as the answer, and a push arriving in
/// that window made every following answer land one message late — which is
/// exactly how a popup ends up waiting forever on a reply that had already
/// been sent.
fn forward_until_answer(
    stream: &mut impl Read,
    output: &mut impl Write,
    request: &[u8],
) -> io::Result<()> {
    let wanted = request_id(request);
    for _ in 0..MAX_FRAMES_WHILE_WAITING {
        let frame = match read_frame(stream)? {
            Some(frame) => frame,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the app closed the socket",
                ))
            }
        };
        let answers = !wanted.is_empty() && response_id(&frame) == wanted;
        write_frame(output, &frame)?;
        if answers {
            return Ok(());
        }
    }
    Err(io::Error::other("the app did not answer"))
}

/// How long the app may take before the extension is told it did not answer.
///
/// Chrome's own timeout for a native request is five minutes, and until it
/// fires the popup shows a loading state — which is what "it just sits there
/// saying AdGuard is starting" looks like from the outside. A window that is
/// restarting (protection asked the system for the privilege and is handing
/// over) will not answer on *this* socket at all, so the wait has to end here.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// How many frames the host will forward while waiting for one answer.
///
/// The app also *pushes* — an open popup is told whenever protection changes —
/// so the frame that arrives first is not necessarily the answer. Each push is
/// forwarded as it comes (that is how a popup stays current) and the wait ends
/// at the frame carrying the id that was asked about. The bound is what keeps
/// a misbehaving socket from spinning here forever.
const MAX_FRAMES_WHILE_WAITING: usize = 64;

/// The error a Chrome extension can read when the app is not running.
///
/// The extension looks for `result === "error"` and shows `data`; a bare
/// disconnect would only say "native host has exited" and no reason.
fn unavailable_with(request: &[u8], reason: &str) -> Vec<u8> {
    let request_id = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|value| value.get("id").and_then(|id| id.as_str()).map(str::to_string))
        .unwrap_or_default();
    let body = serde_json::json!({
        "requestId": request_id,
        "result": "error",
        "data": reason,
    });
    body.to_string().into_bytes()
}

fn unavailable(request: &[u8]) -> Vec<u8> {
    unavailable_with(request, "AdFree is not running")
}

    pub fn main() {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();

    let mut connection: Option<Box<dyn Wire>> = None;
    loop {
        let Some(message) = read_frame(&mut input).unwrap_or(None) else {
            return;
        };
        if connection.is_none() {
            connection = connect();
        }
        let outcome = match connection.as_mut() {
            Some(stream) => write_frame(stream, &message)
                .and_then(|()| forward_until_answer(stream, &mut output, &message)),
            None => Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the app is not running",
            )),
        };
        if let Err(error) = outcome {
            // The app closed the socket or did not answer in time: drop it and
            // let the next message try a fresh one.
            connection = None;
            let timed_out = matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            );
            let reply = if timed_out {
                unavailable_with(&message, "AdFree did not answer in time")
            } else {
                unavailable(&message)
            };
            if write_frame(&mut output, &reply).is_err() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frame Chrome writes is a little-endian length and then the bytes.
    #[test]
    fn frames_round_trip() {
        let payload = br#"{"id":"ADG_1","type":"init"}"#;
        let mut wire = Vec::new();
        write_frame(&mut wire, payload).expect("written");
        assert_eq!(&wire[..4], &(payload.len() as u32).to_le_bytes());
        let mut cursor = &wire[..];
        let read = read_frame(&mut cursor).expect("read").expect("one message");
        assert_eq!(read, payload);
        assert!(read_frame(&mut cursor).expect("end").is_none());
    }

    /// A push that arrives while a request is in flight must not be taken for
    /// the answer: the answer is the frame that carries the id asked about,
    /// and everything before it is forwarded as it comes.
    #[cfg(unix)]
    #[test]
    fn a_push_is_forwarded_and_the_answer_is_matched_by_id() {
        use std::os::unix::net::UnixStream;
        let (mut app_side, mut host_side) = UnixStream::pair().expect("pair");
        let worker = std::thread::spawn(move || {
            write_frame(&mut app_side, br#"{"requestId":"ADG_STATE","appState":{}}"#).expect("push");
            write_frame(&mut app_side, br#"{"requestId":"ADG_1","result":"ok"}"#).expect("answer");
        });
        let mut output = Vec::new();
        forward_until_answer(&mut host_side, &mut output, br#"{"id":"ADG_1"}"#).expect("answered");
        worker.join().expect("worker");
        let mut cursor = &output[..];
        let first = read_frame(&mut cursor).expect("read").expect("push");
        let second = read_frame(&mut cursor).expect("read").expect("answer");
        assert_eq!(response_id(&first), "ADG_STATE");
        assert_eq!(response_id(&second), "ADG_1");
    }

    /// A stall is answered too, with a reason a person can act on.
    #[test]
    fn a_stalled_app_answers_with_a_timeout_reason() {
        let reply = unavailable_with(br#"{"id":"ADG_CUSTOM_9"}"#, "AdFree did not answer in time");
        let parsed: serde_json::Value = serde_json::from_slice(&reply).expect("json");
        assert_eq!(parsed["requestId"], "ADG_CUSTOM_9");
        assert_eq!(parsed["result"], "error");
        assert!(parsed["data"].as_str().unwrap_or_default().contains("in time"));
    }

    /// An unanswerable request still has to answer in the shape the extension
    /// parses, and keep the id it sent so it can match the reply.
    #[test]
    fn an_unavailable_app_still_answers_with_the_same_id() {
        let reply = unavailable(br#"{"id":"ADG_CUSTOM_7","type":"getCurrentAppState"}"#);
        let parsed: serde_json::Value = serde_json::from_slice(&reply).expect("json");
        assert_eq!(parsed["requestId"], "ADG_CUSTOM_7");
        assert_eq!(parsed["result"], "error");
        assert!(parsed["data"].as_str().unwrap_or_default().contains("not running"));
    }
}

}

fn main() {
    host::main()
}