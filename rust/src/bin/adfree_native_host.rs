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

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

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

fn write_frame(output: &mut impl Write, message: &[u8]) -> io::Result<()> {
    output.write_all(&(message.len() as u32).to_le_bytes())?;
    output.write_all(message)?;
    output.flush()
}

/// The error a Chrome extension can read when the app is not running.
///
/// The extension looks for `result === "error"` and shows `data`; a bare
/// disconnect would only say "native host has exited" and no reason.
fn unavailable(request: &[u8]) -> Vec<u8> {
    let request_id = serde_json::from_slice::<serde_json::Value>(request)
        .ok()
        .and_then(|value| value.get("id").and_then(|id| id.as_str()).map(str::to_string))
        .unwrap_or_default();
    let body = serde_json::json!({
        "requestId": request_id,
        "result": "error",
        "data": "AdFree is not running",
    });
    body.to_string().into_bytes()
}

fn main() {
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
        }
        let reply = match connection.as_mut() {
            Some(stream) => match write_frame(stream, &message) {
                Ok(()) => match read_frame(stream) {
                    Ok(Some(reply)) => reply,
                    // The app closed the socket: drop it and let the next
                    // message try a fresh one.
                    Ok(None) | Err(_) => {
                        connection = None;
                        unavailable(&message)
                    }
                },
                Err(_) => {
                    connection = None;
                    unavailable(&message)
                }
            },
            None => unavailable(&message),
        };
        if write_frame(&mut output, &reply).is_err() {
            return;
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
