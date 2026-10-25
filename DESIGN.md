# AdFree — design

AdFree blocks ads and trackers entirely on the device. A Rust core owns packet
handling, rule matching and persistent state; Kotlin/Compose only draws the UI.
There is no backend, no API key and no telemetry.

```
┌──────────────────────────────────────────────────────────────────────┐
│  Kotlin / Compose UI (6 tabs)                                        │
│    ViewModel (MVI) ─ Repository ─ CoreEngine                         │
│         │ uniffi (generated bindings, type-checked on both ends)     │
├─────────┴────────────────────────────────────────────────────────────┤
│  Rust core  (libadfree_core.so)                                      │
│    packet.rs     IPv4/IPv6 + TCP/UDP parse and checksums             │
│    dns.rs        wire decode, NXDOMAIN/0.0.0.0 synth, TTL learning   │
│    upstream.rs   forward DNS over protect()ed sockets                │
│    filter.rs     adblock-rust (the engine behind AdGuard and Brave)  │
│    htmlfilter.rs `$$` / `##^` response-document edits                │
│    pathmask.rs   `$path` / `$url` page masks                         │
│    appmask.rs    `$app` rule narrowing                               │
│    jsonprune.rs  `$jsonprune` body edits                             │
│    hls.rs        `$hls` playlist edits                               │
│    conntrack.rs  IP→host→decision so blocked flows can be reset      │
│    uidmap.rs     /proc port→uid attribution for per-app rules        │
│    udpnat.rs     userspace UDP NAT for non-DNS datagrams             │
│    smart.rs      retry-loop cooldown for hosts an app insists on     │
│    store/        filter bodies, userscripts, CA and SQLite           │
│    engine.rs     packet loop, TCP relay on every port, DNS, stats    │
│    mitm/         CA, rustls, ECH, script injection, TLS splice       │
└──────────────────────────────────────────────────────────────────────┘
```

## Why this architecture

**1. Blocking at DNS is the cheapest layer.** For one DNS query the engine
answers inside the TUN device with a single `write`: no radio time, no network
round trip. That is why DNS filtering needs no root, no CA certificate and
almost no battery, and why it is always on.

**2. DNS alone is not enough, so the VPN routes all of `0.0.0.0/0` like
AdGuard.**
- TCP on **every port** is relayed transparently in userspace: the client
  connects to the engine, and the engine connects out through a `protect()`ed
  socket.
- UDP that is not DNS (QUIC, games, NTP…) goes through a **userspace NAT**:
  one mapping per session, with replies written back into the TUN device.
- QUIC/UDP 443 and DoT/853 are dropped on purpose so clients fall back to TCP
  and cannot bypass the filter; every other flow is left intact.

**3. HTTPS can be decrypted when the user asks for it.** With "Filter HTTPS"
enabled, port 443 is terminated with a locally generated CA, a script is
injected into HTML responses, and the request is re-originated upstream over
real TLS. Enabling it is **gated on the CA actually being installed** (see
[HTTPS filtering](#https-filtering-mitm)).

**4. Two packet-path threads, both sleeping on descriptors — no clock polling.**
- `tun-thread`: `poll(fd, 250ms)` → `read()` → parse → decide.
- `forward-thread`: **one** `poll()` covering an eventfd wakeup, every DNS
  socket and every relay/NAT flow; the 1-second timeout only drives periodic
  cleanup. Anything that creates work (a DNS query, a new relay, a socket
  refusing bytes, `stop()`) writes the eventfd, so a long timeout costs no
  latency.
There is no `Timer`, no `Handler.postDelayed`, no periodic wakeup.

**5. A per-host decision cache sits *in front of* the rule engine.** Apps ask
for the same host over and over; one hash lookup (a few hundred nanoseconds) is
much cheaper than evaluating the whole ruleset. See `filter.rs`.

**6. Use AdGuard's engine instead of writing another parser.** The `adblock`
crate (adblock-rust, the core of AdGuard DNS and Brave) parses and matches
AdGuard/EasyList/uBO/hosts syntax, including `||domain^`, `@@` exceptions,
`$important`, `$third-party`, `/regex/` and `##` cosmetic rules. It is built
with `default-features = false` plus `full-regex-handling`, and **without**
`single-thread` (which would make the engine `!Send`/`!Sync`).

## Packet path

1. The TUN thread reads one IP packet and the core classifies it.
2. DNS (UDP or TCP port 53, and DoH seen on 443 by IP) is decoded, checked
   against the filter, and either answered locally (NXDOMAIN or `0.0.0.0`) or
   forwarded through a protected upstream socket.
3. TCP is tracked by `conntrack.rs`. A blocked destination is reset
   immediately; everything else is relayed. The relay asks `uidmap.rs` who owns
   the source port, which makes per-app routing and `$app` rules real.
4. Port 443 enters a *pending* state until the ClientHello SNI is known. If
   HTTPS filtering is armed and the host is not excluded, TLS is terminated;
   otherwise the bytes are spliced through untouched.
5. Non-DNS UDP is mapped in `udpnat.rs` and written back when the reply
   arrives. QUIC and DoT are dropped before a mapping exists.

## Filtering capabilities

- **Network rules** — AdGuard/EasyList/uBO syntax via adblock-rust, with
  exception, `$important`, `$third-party`, regex and hosts-file forms.
- **Response-body rules** — the modifiers the upstream crate does not
  implement are handled locally: HTML filtering (`$$`, `##^`),
  `$jsonprune`, `$hls`, and the bracket form of `$path` / `$url`.
- **Per-app rules** — `$app` values match against the uid attribution above;
  the UI also routes or excludes whole apps from the tunnel.
- **Cosmetic filtering and userscripts** — a script is injected into filtered
  pages; user scripts may use `@require` and a safe subset of the GM APIs.
- **Smart filtering** — if one host is blocked five times within ten seconds,
  the app is assumed to require it and the host is allowed for a minute.
  A host keeps its pass only while it keeps hammering, and the switch clears
  every window at once. On by default.
- **Request log** — decisions and statistics are written to SQLite in the
  store, and the UI reads them lazily; the packet threads never talk to
  Android.

## Module layout

```
rust/                     core crate (cdylib + rlib)
  src/api.rs              uniffi API for Kotlin
  src/{packet,dns,upstream,conntrack,engine,udpnat,stats,events,filter}.rs
  src/{htmlfilter,jsonprune,hls,pathmask,appmask,smart}.rs
  src/{assets,store,uidmap,logbuf,fxhash,util}.rs
  src/mitm/               ca, tls, proxy, relay, http, tcp, script, segment,
                          ech, hpke, hosts, page_runtime.js
  tests/                  integration tests (DNS round trip, filter, …)
  uniffi.toml             Kotlin binding configuration
app/src/main/kotlin/
  git/shin/adfree/core/   CoreEngine + adfree.kt (generated by uniffi)
  git/shin/adfree/security/  ThreatAnalyzer (offline analysis)
  git/shin/adfree/ui/     ViewModel/MVI + 6 tabs (Compose)
  git/shin/adfree/vpn/    VpnService + controller
tools/install-emulator-ca.sh   install the CA into a rooted emulator (dev)
app/src/test/kotlin/      JVM unit tests
package.json              JS tests (Vitest + Playwright, run with bun)
rust/src/mitm/page_runtime.test.mjs   tests for the injected page runtime
```

## State and ownership

The platform hands the core one writable directory and never writes inside it
again:

```
<root>/filters/<id>.txt   filter list bodies
<root>/scripts/<id>.js    userscript bodies
<root>/core/ca.pem        local CA certificate (PEM)
<root>/core/ca-key.pem    local CA private key (PEM)
<root>/adfree.db          SQLite: request log, settings, registries
```

Downloads land in a temporary file and are renamed into place, so a killed
process never leaves a half-written list behind. The file names predate the
move from Kotlin, so installed apps keep their data without a migration.

Protection settings and the HTTPS toggle persist across restarts; the selected
filter lists, custom rules, userscripts and per-app choices do too.

## HTTPS filtering (MITM)

| Piece | File | What it does |
|---|---|---|
| Local CA (ECDSA P-256), leaf certificates per SNI, PEM persistence | `mitm/ca.rs` | issues and restores the chain |
| TLS termination with rustls (ALPN h1) | `mitm/tls.rs` | terminates the client handshake |
| Client-side TCP: SYN-ACK, sequence/ack translation, RST/FIN | `mitm/tcp.rs`, `mitm/segment.rs` | speaks TCP to the client from userspace |
| HTTP response rewrite and script injection | `mitm/http.rs` | fixes `content-length` after injecting |
| User scripts, `@require`, safe GM APIs | `mitm/script.rs` | builds one bundle with per-script guards |
| Byte splice browser ↔ proxy ↔ origin | `mitm/proxy.rs` | moves bytes in both directions |
| Relay integration in the engine | `mitm/relay.rs` | wires the splice into the packet loop |
| ECH handling | `mitm/ech.rs`, `mitm/hpke.rs` | strips ECH from DNS by default, offers the origin's config upstream |
| HTTPS allow/block host patterns | `mitm/hosts.rs` | excludes sites from decryption before TLS starts |

The decision now comes from the **ClientHello SNI**, not from the DNS map: a
port-443 relay enters *pending*, and upstream is only opened once rustls has
parsed the SNI. A missing or unusable hello is spliced straight through, and a
non-TLS flow is spliced intact. A `connect()` that is reset (NAT or `TIME_WAIT`
when a port is reused on the emulator) is retried **once on a fresh socket**
before the flow is dropped, so the client sees no interruption.

ECH exists to keep this proxy out of the connection, which is the opposite of
what HTTPS filtering needs. By default the DNS half rewrites the `ech` SvcParam
away, so no client can wrap a hello in a config the proxy cannot read, while
the original ECHConfigList is kept for the upstream half. When full ECH is
requested, the config reaches the client instead; hosts that use it end-to-end
are spliced rather than filtered.

`page_runtime.js` is the script injected into pages. Its tests run it in a real
Chromium; setting `ADFREE_CDP` adds one more check against the emulator's
Chrome behind the running VPN.

### Installing the certificate

The toggle is gated: while the CA is not in the trust store, turning it on only
opens instructions, and the toggle stays OFF (`isCaTrusted()` compares DER
against `AndroidCAStore`). The dialog exports `AdFree-CA.crt` to Downloads
(through MediaStore) and opens Settings, because:

- the inline install intent (`KeyChain.createInstallIntent`) only answers
  *"Install CA certificates in Settings"* — Android does not install a CA
  directly;
- the Settings file picker cannot read the app's private storage.

Verified flow on the emulator: toggle → dialog → *Open Settings* → the file is
in Downloads → Settings: Security & privacy → More security settings →
Encryption & credentials → Install a certificate → CA certificate → pick the
file (screen lock required) → return to the app: "Certificate: installed", and
the toggle turns itself ON.

**Trust store on Android 14+:** certificates are **no longer** read from
`/system/etc/security/cacerts`; the system store is the
`com.android.conscrypt` APEX (read-only, and a tmpfs overlay does not convince
Chrome). The correct path is the **user store**:
`/data/misc/user/0/cacerts-added/<hash>.0` (system:system, 644, label
`misc_user_data_file`) — exactly where the dialog installs it. On a rooted
emulator, `tools/install-emulator-ca.sh` can replace the Settings steps.

## Threading and resource use

The forwarder was rewritten to **sleep on descriptors instead of polling on a
clock**: it used to poll every flow every 50 ms and wait for DNS on a 250 ms
condvar, which meant dozens of wakeups per second for a single open connection.
Now there is one `poll()` (eventfd + DNS + flows + NAT, 1-second timeout) that
does work only when there is data, and every "there is new work" event writes
the eventfd.

Measured on the emulator while idle (background traffic subtracted): about
**16 context switches per second** for the whole process (tun thread 4/s,
forwarder 1/s, system threads), versus an old floor of ≥ 24/s for the forwarder
alone.

## Verified on the emulator (API 37, x86_64)

```
$ adb shell ping -c1 api.github.com      → PING 140.82.121.6        (forward)
$ adb shell ping -c1 a.doubleclick.net   → unknown host             (blocked in 2 µs)
$ adb shell ping -c1 fresh.adnxs.com     → unknown host             (blocked)
```

| Check | Result |
|---|---|
| Real rules compiled | **421,687** (AdGuard DNS 184,178 + OISD + StevenBlack + 3 user rules) |
| Decision latency (cache hit) | **2 µs** |
| Subdomain blocking (`a.doubleclick.net`) | ✅ NXDOMAIN |
| DoH by IP (`94.140.14.14:443`) | ✅ TCP reset, "connection dropped" rule |
| TCP relay on every port + UDP NAT | ✅ every socket `protect()`ed, internet unchanged while on |
| HTTPS MITM | ✅ Chrome reports *"AdFree Personal CA issued this website's certificate"* |
| Stack | uniffi 0.32 + JNA, no hand-written JNI |

That work also locked down four bugs with regression tests (see `git log`):

1. `sockaddr_in.s_addr` was byte-swapped → `sendto()` returned `EINVAL` and
   every valid DNS query timed out (`upstream_roundtrip.rs`,
   `sockaddr_uses_network_byte_order`).
2. A file descriptor was closed before Rust received it (`protect()` + `dup()`
   followed by closing the wrong copy) → `sendto()` returned `EBADF`.
3. The old forwarder busy-looped: `setBlocking(false)` without `poll()`.
4. The MITM path was dead because of three splice bugs: the proxy never took
   the ClientHello out of rustls, the plaintext request was discarded while the
   upstream handshake ran, and `Relay::on_peer_data` swallowed upstream bytes.
   All three have regression tests, and the relay test
   `on_peer_data_carries_the_upstreams_own_bytes` covers the last one.

## Build and test

Requirements: JDK 21 (source/target 17), Android SDK, **Android NDK r28c**
(`ANDROID_NDK_HOME`), `cargo-ndk` (`cargo install cargo-ndk`) and
`uniffi-bindgen` 0.32 (`cargo install uniffi --features cli`).

```bash
./gradlew :app:assembleDebug          # build the core + APK
./gradlew :app:verifyBindings         # regenerate Kotlin bindings after Rust API changes
./gradlew :app:assembleDebug -PskipNative   # skip native code (fast, UI only)

cd rust
cargo test                            # 576 library tests (2 ignored) + integration tests
cargo clippy --all-targets            # 0 warnings

cd ..
./gradlew :app:assembleDebug :app:testDebugUnitTest
bun install && bun run test           # 15 browser tests for page_runtime.js
```

The JS tests run `page_runtime.js` in a real Chromium; `bun` is the package
manager (Playwright uses the installed Chrome, it does not download a browser).

CI (`.github/workflows/android-ci.yml`) runs Vitest, `cargo test --lib`,
`cargo clippy --all-targets -- -D warnings`, Android Lint and a debug build.
Pushes to `main` additionally run `android-release.yml`, which signs the APK
and AAB with the release keystore and publishes them through semantic-release.

uniffi calls native code through JNA, so the APK needs the JNA dependency
(already listed in `libs.versions.toml`).

## Current limitations

- HTTPS filtering is OFF by default and requires installing the CA and a
  screen lock before it can be enabled.
- Android only (VpnService); there is no iOS or desktop build.
- Full ECH routing is available, but hosts that use it are spliced rather than
  filtered by design.
