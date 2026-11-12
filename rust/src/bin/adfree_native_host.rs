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
//! 4-byte little-endian length in front of every JSON message; the running
//! AdFree window owns the state and the tunnel. So this process is a pipe:
//! a message from Chrome goes to the app over a Unix socket and the answer
//! goes back, frame for frame. Nothing here decides anything, which is why the
//! protocol lives in `AssistantBridge.kt` beside the state it reports.
//!
//! Chrome also passes the calling extension's origin as `argv[1]`; it is not
//! used, because the socket is the authorization: only a process that can read
//! this user's runtime directory can connect to it.


/// The host itself. Unix only: it reaches the app over a Unix socket, which is
/// the authorization as much as the transport, and Windows will need a named
/// pipe with its own ACL when that build lands.
#[cfg(unix)]
mod host {
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Where the app listens. `$XDG_RUNTIME_DIR` is per-user and private, which is
/// what makes the socket safe to trust; the fallback is for a login without
/// one (a bare tty, some containers).
const SOCKET_NAME: &str = "adfree-assistant.sock";

fn socket_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let dir = PathBuf::from(dir);
        // The app creates the directory it listens in.
        paths.push(dir.join("adfree").join(SOCKET_NAME));
        paths.push(dir.join(SOCKET_NAME));
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home).join(".local/share/adfree").join(SOCKET_NAME));
    }
    paths
}

/// Reads one length-prefixed message; `None` at a clean end of input.
fn read_frame(input: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match input.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated message length",
                ))
            }
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let len = u32::from_le_bytes(header) as usize;
    // Chrome caps a message from the extension at 64 MiB; anything larger is
    // not this protocol.
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too long"));
    }
    let mut message = vec![0u8; len];
    input.read_exact(&mut message)?;
    Ok(Some(message))
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
    stream: &mut UnixStream,
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

fn write_frame(output: &mut impl Write, message: &[u8]) -> io::Result<()> {
    output.write_all(&(message.len() as u32).to_le_bytes())?;
    output.write_all(message)?;
    output.flush()
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

    let mut connection: Option<UnixStream> = None;
    loop {
        let Some(message) = read_frame(&mut input).unwrap_or(None) else {
            return;
        };
        if connection.is_none() {
            connection = socket_candidates()
                .into_iter()
                .find_map(|path| UnixStream::connect(path).ok());
            // A socket whose peer is alive but busy — rebuilding a filter
            // engine, starting listeners — must not hold this message for
            // minutes. The timeout turns a stall into an answer the popup can
            // show and the user can retry.
            if let Some(stream) = connection.as_ref() {
                let _ = stream.set_read_timeout(Some(ANSWER_TIMEOUT));
            }
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

#[cfg(unix)]
fn main() {
    host::main()
}

#[cfg(not(unix))]
fn main() {
    // Chrome would have to be told a host exists before it can call one, so a
    // build without the host is a build that never gets here.
    eprintln!("adfree-native-host: not implemented on this platform");
    std::process::exit(1);
}