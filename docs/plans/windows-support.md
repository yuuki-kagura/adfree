# Windows support

Status: **not implemented.** This is the plan, sized against the code as it is,
so the work starts with a real inventory rather than a guess.

The measured starting point (`cargo check --target x86_64-pc-windows-gnu --lib`
on this tree): **475 errors across 12 files**, all of them the same fact — the
core is built on Unix file descriptors and `poll`.

| File | Errors | What is Unix-only |
| --- | --- | --- |
| `src/engine.rs` | 105 | raw-fd DNS socket, `poll`, `FromRawFd`, `OpenOptionsExt` |
| `src/proxy/mod.rs` | 79 | `SO_MARK`, `poll`, `sockaddr_storage`, `socklen_t` |
| `src/proxy/dns.rs` | 77 | raw-fd UDP socket, `poll`, ancillary data |
| `src/udpproxy.rs` | 66 | raw-fd UDP relay, `poll` |
| `src/dnssecure.rs` | 43 | fd plumbing for DoT/DoH connections |
| `src/upstream.rs` | 39 | `sockaddr` construction, `poll` |
| `src/proxy/tcp.rs` | 34 | `SO_ORIGINAL_DST`, `AsRawFd`, `poll` |
| `src/waitset.rs` | 28 | `poll` on N fds with deadline arithmetic |
| `src/trust.rs`, `src/filter.rs`, `src/api.rs`, `src/udpnat.rs` | 7 | `FileExt`, `setenv`, fd types |

None of it is the filtering engine: `filter.rs` (11 050 lines of AdGuard rule
matching, cosmetic injection, TLS rewrite) is already portable. What has to move
is the socket layer underneath it.

## Decision 1 — how traffic reaches the proxy (needs an answer before porting)

Linux redirects packets with `nft` (`table inet adfree`) and recovers the
original destination with `SO_ORIGINAL_DST`; nothing on the machine can avoid
the proxy. Windows has no user-space equivalent, so there are two paths:

**A. System proxy + own DNS (recommended first).**
The app sets the WinINET/WinHTTP proxy to `127.0.0.1:3129` and the adapter DNS
to `127.0.0.1` (listener moves to port 53, which needs elevation), then blocks
QUIC outbound with a firewall rule so browsers cannot bypass filtering.
- Covers: every browser (they all honour the system proxy), Electron apps,
  WinHTTP clients, and any app that resolves through the system resolver.
- Does not cover: apps with a hardcoded DoH server or their own proxy stack,
  and games that ignore the system proxy.
- No driver, no kernel component, installable as a plain MSI.

**B. WinDivert/WFP.**
Full coverage, matching AdGuard for Windows, at the cost of shipping and signing
a kernel driver, an install/uninstall service, and a much larger verification
burden. This is a separate project, not a step in this one.

Recommendation: ship **A**, say plainly in the UI that Windows filtering is
proxy-based, and keep `nft`/`SO_ORIGINAL_DST` as the Linux path unchanged.

## Decision 2 — where the portable socket layer lives

Introduce `rust/src/sys/` with two implementations behind `cfg`:

```rust
pub struct Socket(/* fd on unix, SOCKET on windows */);
impl Socket {
    pub fn udp(bind: SocketAddr) -> io::Result<Self>;
    pub fn tcp_connect(addr: SocketAddr) -> io::Result<Self>;
    pub fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    pub fn send_to(&mut self, buf: &[u8], to: SocketAddr) -> io::Result<usize>;
    pub fn set_mark(&self, mark: u32) -> io::Result<()>;  // no-op on Windows
    pub fn original_dst(&self) -> Option<SocketAddr>;     // None on Windows
}
pub fn wait(readable: &[&Socket], timeout: Duration) -> Vec<usize>;
```

`wait` is `poll(2)` on Unix and `WSAPoll` on Windows; `set_mark` and
`original_dst` disappear on Windows because the system-proxy path needs neither.
Everything above `sys` — the engine, the rule matcher, the MITM — keeps calling
the same API it calls today.

The alternative (rewriting the proxy on `mio`/`tokio`) is a larger change that
would touch the engine's packet loop as well; `sys` is the smaller diff and
keeps the existing measured behaviour on Linux.

## Milestones

1. **`sys` lands on Unix with no behaviour change.** Move `waitset`, the fd
   helpers in `proxy/mod.rs`, `original_dst`, `try_mark` behind it; `cargo test`
   and the 40-curl pause test must stay green. This is the step that proves the
   abstraction is right before it has a second implementation.
2. **`sys` gets a Windows implementation.** `cargo check --target
   x86_64-pc-windows-gnu --lib` goes to zero. No runtime claims yet.
3. **Core runtime on Windows.** Explicit-proxy mode: client sends `CONNECT` or
   absolute-form URLs, so `original_dst` is never needed; DNS listener on `:53`.
   Verify on a Windows VM: `curl -x 127.0.0.1:3129 https://example.com/` → 200,
   `dig @127.0.0.1 example.com` → answer, a blocked domain → refused.
4. **Desktop shell.** `DesktopOs` seam with a Windows implementation of:
   autostart (`HKCU\…\Run`), native-messaging manifests (registry), the core
   library name (`adfree_core.dll`), elevation (UAC: one `Start-Process -Verb
   RunAs` for the netsh/registry commands instead of sudo/polkit), and the tray
   (Compose `Tray`, not SNI/DBus).
5. **Packaging.** `TargetFormat.Msi` (jpackage) with a per-user install, a
   `windows-latest` CI job that builds the core with MSVC and the MSI, and the
   same "verify the core is complete" step the Linux packages have
   (`dumpbin /exports adfree_core.dll`).

## What must not regress on Linux

- `nft` rules stay the interception path; `SO_MARK` keeps the proxy's own
  traffic out of them.
- The `DRAIN` window on a stop, the connection-slot accounting, and the totals
  table in sqlite are all upstream of this work and must not move.
- Keep `cargo clippy -D warnings` and all 931 Rust tests green at every step.

## Verification harness

`scripts/windows-check.sh` reproduces the CI check locally (needs
`rustup target add x86_64-pc-windows-gnu` and `mingw-w64-gcc`, both installed on
this machine already):

```sh
scripts/windows-check.sh        # prints the error count and the first failures
```

It exists so the port has a red/green line from the first commit, instead of
"should work on Windows" being untested prose.
