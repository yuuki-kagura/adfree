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

**B. A kernel driver (WinDivert, WFP callout, or our own socket filter).**
Full coverage, matching AdGuard for Windows, at the cost of shipping and signing
a kernel driver, an install/uninstall service, and a much larger verification
burden. This is a separate project, not a step in this one.

What signing costs, from Microsoft's own policy page: since **Windows 10 1607**
the OS "will not load any new kernel-mode drivers which are not signed by the Dev
Portal", and an **EV code-signing certificate is required** to even create the
dashboard account. Attestation signing (no HLK run) is enough for Windows 10
client systems; production drivers should submit HLK/HCK logs. Every driver
update is another submission, and a crash in it is a machine-wide BSOD rather
than an app crash — which is exactly why AdGuard says it "regularly updates
drivers to steadily reduce the number of BSODs".

Source: <https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later->

Recommendation: ship **A**, say plainly in the UI that Windows filtering is
proxy-based, and keep `nft`/`SO_ORIGINAL_DST` as the Linux path unchanged.

## What AdGuard for Windows actually ships (verified, not remembered)

AdGuard's own knowledge base is explicit: "In AdGuard for Windows, this
interception is implemented through **network drivers**", and the app lets the
user pick which one (`Settings → App settings → Network`):

- **WFP** — a Windows Filtering Platform callout, i.e. packet-level filtering
  inside the NETIO pipeline. This is the one whose callout bugs turn into
  NETIO-related BSODs.
- **TDI** — the legacy transport driver interface; kept for old systems.
- **SockFilter** (first appeared in 7.22.4, still called experimental) — a
  "lightweight **kernel-mode** network driver that works at the socket level
  (TCP/UDP)", intercepting `connect`/`send`/`receive`/`bind` instead of raw
  packets. AdGuard lists its advantages as less complexity than WFP, no
  filter-ordering conflicts with VPN/firewall/AV, and "greatly reduced risk of
  NETIO-related BSODs" — and its cost as not seeing traffic that bypasses
  Winsock (other kernel drivers).

Their release notes agree and show the operational cost: "AdGuard uses a special
network driver that handles the actual sending and receiving of data, allowing
us to filter traffic from every app on your device" (v8.0.0), and "We regularly
update drivers to steadily reduce the number of BSODs users experience" (v8.0.4).

So: **every AdGuard Windows path is a kernel driver, and all three are signed.**
An earlier draft of this plan said AdGuard uses WinDivert; that is wrong and is
corrected here. WinDivert would still be a kernel driver (`WinDivert.sys`,
"installed below the Windows network stack", LGPLv3/GPLv2) — bundled, but signed
by us.

Sources:
- <https://adguard.com/kb/adguard-for-windows/features/network/>
- <https://github.com/AdguardTeam/AdGuardForWindows/releases> (v8.0.0, v8.0.4, v8.0.0-beta-5)
- <https://github.com/basil00/WinDivert> (driver, license)

## Is there a whole-system path that does not cost a signing certificate?

AdGuard pays the EV-certificate + Dev Portal price; the question worth asking is
whether we have to. Four options, with what was actually verified:

**1. Bundle WinDivert and use its already-signed driver — no certificate needed.**
WinDivert's own documentation (§2.1 *Driver Signing*): "If you built your own
`WinDivert32.sys` / `WinDivert64.sys` drivers, they must be digitally signed…
Note that the **pre-built drivers from the official WinDivert distribution are
already digitally signed**." Checked on `WinDivert64.sys` from release v2.2.2-A
(94 144 bytes): one signer,
`C=CN, O=成都密思听科技有限公司`, chained to `Sectigo Public Code Signing CA EV R36`,
carrying an RFC 3161 timestamp (Sectigo time-stamping signer #3). The signature
is therefore in place and timestamped; no EV certificate of our own is involved.
Costs: the driver installs and runs only for an Administrator process, it is
LGPLv3 (redistribute the `.dll`/`.sys` unmodified with the licence, which is
allowed), the trust prompt names WinDivert rather than AdFree, and security
software does flag it — open issues #401 and #411 in the WinDivert tracker are
exactly that ("blocked from loading by some security software", "Defender
quarantines official WinDivert 2.2.2-A ZIP"). Not verified here: whether a given
Secure Boot machine loads it, since that can only be answered on Windows.

**2. No driver at all: system proxy + own DNS + hosts file + QUIC firewall rule.**
Free, ships as an MSI, and covers every browser and every app that resolves
through the system resolver. Misses apps with their own DoH/proxy stack.

**3. User-mode Winsock injection (the Proxifier approach).** A DLL hooked into
each process redirecting `connect`/`WSASocket`. No kernel driver, so only
ordinary code signing applies (SignPath Foundation issues free certificates to
open-source projects). Fragile by nature: AV flags injection, protected and
64-bit-only processes are missed, and anything not using Winsock bypasses it.

**4. Test-signing mode.** Free and useless for distribution: the user has to
disable driver signature enforcement, which on modern Windows means disabling
Secure Boot.

Recommended order stays: (2) first, because it is days of work and covers the
browsers; then (1) if whole-system coverage is wanted, since it is the only
free path to it, with the AV-false-positive risk accepted and documented.

## Decision taken — WinDivert, and the app runs elevated

The user chose the WinDivert route and stated the operating assumption we build
on: **AdFree for Windows runs with Administrator rights, always.** That removes
option (2) from the table above as the primary mechanism — a system proxy cannot
see an app that ignores it — and it removes the "which app is talking" question
from the redirector, because the filter can be told the whole machine.

What that changes in the core, concretely:

* the redirector is a userspace NAT: it rewrites the destination of outbound
  SYN to `127.0.0.1:3129`, records `(client ip:port → original ip:port)` and
  rewrites the replies back, which is exactly what `nft` + conntrack does for us
  on Linux. WinDivert supplies the packet surgery and checksum fixing;
* because the redirector is ours, `SO_ORIGINAL_DST` has no counterpart and
  `sys::original_destination` correctly answers `None` on Windows (see `af8c2e3`);
* DNS moves the same way: UDP 53 is redirected to the local resolver, and QUIC
  (UDP 443) is dropped so TCP+TLS is the only path out;
* the proxy's own sockets need no firewall mark: the filter excludes them by
  process id and port.

### Autostart without a UAC prompt

A `requireAdministrator` manifest launched from a `Run` key prompts at **every**
logon — the prompt is on the secure desktop and needs a click, so a `Run` entry
is not an autostart, it is a reminder. Two mechanisms do start elevated silently,
both installed once by the installer:

| Mechanism | Prompt at logon | Notes |
| --- | --- | --- |
| Task Scheduler task, `/RL HIGHEST`, trigger `ONLOGON` | none | Runs in the user's session, so the tray icon and window work; the task must be created by an elevated installer |
| Service as `LocalSystem` | none | Session 0, no UI: needs an unelevated UI talking over a pipe (the AdGuard model), and ownership of a named-pipe ACL |

Chosen for the first port: the **scheduled task**, because the app is one
process that draws the tray and holds the driver handle; a service split buys
nothing until the app needs to keep filtering while nobody is logged in. The
service split is the shape to move to if that requirement appears, and it is the
only shape that survives a user logging out.

## Where the port stands

The measurement this plan started with was 475 compile errors, all of them
"something Unix". It is now **zero**: `cargo build --release --target
x86_64-pc-windows-gnu --lib` produces `adfree_core.dll`, and `scripts/windows-check.sh`
exits 0.

What that took, in the order it happened:

| Commit | What it did |
| --- | --- |
| `af8c2e3` | the two kernel questions (`SO_ORIGINAL_DST`, `SO_MARK`) move into `sys`, Windows answers them honestly (475 → 460) |
| `1a05349` | `sys::libc` — the Winsock namesake: constants, `sockaddr_*`, `poll` over `WSAPoll`, WSA errno numbers; `sys::fd` for the descriptor vocabulary (460 → 187) |
| `9e796de` | the wait set becomes `epoll` over IOCP on Windows (wepoll), one implementation for all three platforms |
| `8935655` | `winnat`: the redirect decisions as pure functions, tested on Linux |
| `5303b9b` | `sys::windivert`: the driver loop — `WinDivert.dll` loaded at run time, two filters, `winnat` applied to each packet; `wredirect` is the start/stop/counters the app holds |
| `40c70c2` | the four redirect calls exist on every platform (`core_redirect_start/stop/running/packets_seen/live_flows`), so the switch is one switch |
| `a615155` | the CA is trusted on Windows through the machine's `Root` store (`certutil`), SHA-1 for thumbprints included |
| `06044d5` | the desktop answers the privilege questions for Windows: no mark, no `nft`, no `pkexec`, no systemd — protection is starting the redirect; autostart becomes a logon task with `HIGHEST` |
| `2b20b81` | the core is found as `adfree_core.dll`, the signed WinDivert pair travels in the jar and is unpacked for the loader, the MSI is declared |
| `9a8cda9`, `336bb78` | the MSI packages on a real Windows runner: WiX's version shape reduced from the release name, and the package built with `packageMsi` (no ProGuard) the way the Linux packages are |
| *this one* | the facilities that have no Winsock equivalent — `eventfd` and `socketpair` as a self-connected loopback datagram socket, a `poll`-backed `WaitSet`, the packet-info types as compile-only shells |

Two things changed shape rather than gained a shim, and they are the ones worth
reviewing:

* **`waitset`**: the Windows analogue of `epoll` is not `poll`. `WSAPoll` is a
  userland loop over `select`, and before Windows 10 1809 it does not report a
  failed connection — the one event a proxy's connect path is waiting for. The
  real counterpart is **IOCP**, so the tree vendors **wepoll 1.5.8** (BSD-2,
  IOCP + `\Device\Afd`, compiled by `build.rs`) and `sys::fd` names
  `epoll_create1`/`epoll_ctl`/`epoll_wait`/`epoll_close` for both kernels. The
  wait set stays one implementation with one set of semantics, and **Android and
  Linux keep the real `epoll` untouched**, `ops()` instrumentation included.
* **wake channels**: `eventfd` and `socketpair` are a UDP socket bound to
  `127.0.0.1:0` and connected to itself, duplicated for the pair. A write is
  immediately a readable event on the handle the loop polls, which is the whole
  contract the loop relies on.

Still Unix-only, deliberately, and named so they are not mistaken for ported:
the TUN forwarder's tests, the assistant's native-messaging host (a Unix socket
is the authorization as well as the transport — Windows needs a named pipe with
an ACL), and every path that expects `IP_PKTINFO` to name a redirected
destination, because on Windows the component that redirects will name it.

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

`wait` is `epoll` on Unix and `epoll`-over-IOCP on Windows (see Decision 1:
`WSAPoll` is not equivalent for a failed connect, which is what the tree needs);
`set_mark` and `original_dst` disappear on Windows because the redirect names the
destination itself.
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
4. **Desktop shell.** One class per platform difference, chosen inside the
   existing classes rather than forked beside them (the same seam `sys` is in
   Rust): autostart becomes a Scheduled Task with `/RL HIGHEST` + `ONLOGON`
   (done — a `Run` key re-prompts UAC at every logon), the "privilege" answers
   become the token the app already holds (done — `nft`/`polkit`/`systemctl`
   are skipped, and protection means starting the redirect), the core library is
   `adfree_core.dll`, and the tray needs a Windows implementation (Compose
   `Tray`, not SNI/DBus) — still open. Native-messaging manifests go to the
   registry instead of a `~/.config` JSON file.
5. **Packaging.** `TargetFormat.Msi` (jpackage), a machine-wide install (the
   driver and the certificate store need the administrator token, which a
   per-user MSI cannot grant), a fixed `upgradeUuid`, and a `windows-latest`
   workflow that builds the core with MSVC and the MSI and refuses to publish a
   core without the redirect's entry points. Still open: signing the MSI, and
   the tray, which still speaks KDE's D-Bus — on Windows the app currently runs
   from the window alone.

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

## Where the port stands, verified

The core compiles for `x86_64-pc-windows-gnu` (`scripts/windows-check.sh`, no
errors, no warnings) and for MSVC, and an **MSI now builds and uploads on a real
`windows-latest` runner** — 106 MB, artifact `adfree-msi`, run `43174550259`. That
run is the first end-to-end proof of the parts that only exist on Windows: the
C build of wepoll, `cargo build --release --lib` for `adfree_core.dll`, the
`uniffi_…core_redirect_start` symbol surviving into the DLL, and jpackage's WiX
toolchain.

What is still open, in the order it would bite a user:

1. **The tray.** `TraySni` is KDE's D-Bus SNI. On Windows there is no tray icon
   yet: the app runs from its window, and closing the window with the app
   filtering is a window nobody can bring back. Compose's `Tray` is the answer,
   and the pause/state logic it would drive is already written.
2. **Nothing has run on a Windows desktop.** The redirect, the driver, the
   certificate store and the logon task are all reasoned and unit-tested, but the
   first real machine is still ahead. The order to try it in: install the MSI as
   Administrator, confirm `WinDivert.dll` and `WinDivert64.sys` were unpacked
   next to the cache core, start the app, expect `certutil` to add the CA, then
   `curl -x 127.0.0.1:3129 https://example.com` and a blocked domain.
3. **MSI signing.** Unsigned, so SmartScreen warns; the WinDivert pair's own
   signature is what the kernel checks.
4. **The native-messaging host** for the browser extension is a Unix socket (the
   socket *is* the authorization). Windows needs a named pipe with an ACL.

