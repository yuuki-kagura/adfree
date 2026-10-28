# AdFree

An on-device ad and tracker blocker for Android, built on a Rust core.
Filtering happens entirely on the phone: there is no backend, no API key and no
telemetry.

[Design and architecture →](DESIGN.md)

## What it does

- **DNS blocking** — queries answered inside the TUN device (NXDOMAIN or
  `0.0.0.0`), so blocking costs no radio time.
- **Full-tunnel VPN** — TCP on every port is relayed transparently and
  non-DNS UDP goes through a userspace NAT; QUIC and DoT are dropped so apps
  fall back to filterable TCP (QUIC can instead be terminated when HTTP/3
  filtering is on).
- **Optional HTTPS filtering** — port 443 can be terminated with a local CA,
  HTML responses rewritten and scripts injected. Off by default and gated on
  the CA being installed.
- **Optional HTTP/3 filtering** — with HTTPS filtering on, QUIC (UDP/443) is
  terminated and filtered like HTTPS instead of dropped. Chrome/Cronet still
  refuse user CAs for QUIC and fall back to TCP; SOCKS5 proxy mode drops QUIC
  so the browser uses the proxied TCP path.
- **AdGuard/EasyList/uBO rules** — via adblock-rust, plus the response-body
  modifiers the crate lacks: `$$`/`##^` HTML filtering, `$jsonprune`, `$hls`,
  and `$path`/`$url` masks.
- **Per-app control** — rules can be narrowed to apps (`$app`), and whole apps
  can be routed or excluded in the UI.
- **Cosmetic filtering and userscripts** — injected page runtime with
  `@require` and a safe subset of the GM APIs.
- **Smart filtering** — an app that hammers a blocked host five times in ten
  seconds gets a one-minute pass, so retry loops stop burning CPU.
- **Request log** — decisions and statistics persist in SQLite and feed the
  Activity view.
- **Security Lab** — offline threat analysis, no network calls.

The UI is five Compose tabs (Home, Protection, Activity, Apps, Settings) over
a uniffi bridge to `libadfree_core.so`. Home is a dashboard — one power switch,
one tap per module, then the counters. Protection lists every module with its
own switch; opening a row shows that module's options (filter lists, resolver,
certificate, stealth, per-app firewall rules). The Security Lab is reachable
from Settings.

## Build

Requirements:

- JDK 21 (the app targets Java 17 bytecode)
- Android SDK
- Android NDK **r28c** (`ANDROID_NDK_HOME`)
- `cargo-ndk` (`cargo install cargo-ndk`)
- `uniffi-bindgen` 0.32 (`cargo install uniffi --features cli`)

```bash
./gradlew :app:assembleDebug                # build the Rust core + APK
./gradlew :app:verifyBindings               # regenerate Kotlin bindings after Rust API changes
./gradlew :app:assembleDebug -PskipNative   # UI only, no native build
```

## Test

```bash
cd rust
cargo test                      # unit + integration tests
cargo clippy --all-targets      # must stay warning-free

cd ..
./gradlew :app:testDebugUnitTest
bun install && bun run test     # 32 Chromium tests (1 needs ADFREE_CDP)
```

CI runs Vitest, the Rust tests, clippy, Android Lint and a debug build on every
pull request. Pushes to `main` sign the release APK/AAB and publish them with
semantic-release; see `.github/workflows/`.

## Enabling HTTPS filtering

HTTPS filtering stays off until the local CA is installed. The toggle explains
the steps and exports `AdFree-CA.crt` to Downloads; after installing it through
Settings (screen lock required) the toggle turns on by itself. While protection
runs without the certificate, a low-priority notification keeps pointing at the
HTTPS module until the store contains the CA. The full flow, including the
Android 14+ user trust store path, is documented in
[DESIGN.md](DESIGN.md#installing-the-certificate).

## Limitations

- Android is the only shipping shell today; Linux, Windows, macOS and iOS are
  the planned targets — see the
  [platform roadmap](DESIGN.md#platform-roadmap).
- HTTPS filtering requires installing the CA.
- With full ECH on, flows that negotiate ECH are spliced rather than
  filtered; flows that do not use ECH stay filtered.
