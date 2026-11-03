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
- **Tracking protection** — one master switch over fourteen edits: the header
  and cookie rewrites a site sees, the browser-API guards a page sees, the split
  of a connection's first handshake write so a deep-inspection device cannot
  read the site name out of one packet (anti-DPI), and the address a site is told
  made the request (mask IP — a header, not an exit, and the row says so). Three
  privacy levels write twelve of them in one tap; the last two are not a level's
  business and survive whichever level is picked.
- **Smart filtering** — off by default. When switched on, a host the same app
  has been blocked on seven times in ten seconds gets a one-minute pass, so a
  retry loop stops burning CPU. It is opt-in because the pass makes that host
  reachable for a minute.
- **Website exceptions** — the ad-blocking module opens its own allowlist
  screen: the `@@` rules as domains, with search, add, delete, and a switch per
  rule. Switching one off writes AdGuard's `!` mark onto the rule text instead of
  deleting it, so the exception comes back with its text intact.
- **Company breakdown** — the Statistics view groups blocked traffic by domain
  and labels each with the company, service and category recorded in a
  `services.tsv` built from AdGuard's own tracker dataset plus Ghostery
  TrackerDB, updatable from a URL or a file like any filter list. Off by
  default: the grouping is a second query over the whole window.
- **Proactive security notice** — when a security list blocks a domain, one
  localized notification per domain per hour opens the log filtered to it.
- **Request log** — decisions and statistics persist in SQLite and feed the
  Activity view. The core's own diagnostics have a level (off, errors, warnings,
  debug) that decides what reaches logcat.
- **Automation** — Tasker and friends can switch protection through an exported
  receiver, but only after the user turns the gate on in Settings and the
  broadcast carries that install's token. Off by default, and the token is kept
  out of every backup.
- **Security Lab** — offline threat analysis, no network calls.

The UI is six Compose tabs (Home, Protection, Apps, Activity, Statistics,
Settings) over a uniffi bridge to `libadfree_core.so`. Home is a dashboard — one
power switch, one tap per module, then the counters. Protection lists every
module with its own switch; opening a row shows that module's options (filter
lists, website exceptions, resolver, certificate, stealth, per-app firewall
rules). The Security Lab is reachable from Settings, along with the backup pair,
the diagnostics level and the automation gate.

If the system drops the tunnel while protection is still expected — a revoke, an
OEM battery saver, another app taking the VPN — AdFree reopens it, three attempts
on a doubling delay, without asking. What it cannot do silently is obtain VPN
consent: when Android wants the confirmation again, or the attempts run out, one
notification you can hear taps back into enable. Where the system has been told
to keep this VPN up (always-on), AdFree posts nothing and starts nothing — the
platform is already rebuilding that tunnel, and a second owner competing with it
is the fault rather than the fix.

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

The company table ships at `rust/assets/services.tsv`. To rebuild it from
tracker datasets — AdGuard's `trackers.json`, Ghostery TrackerDB, DuckDuckGo
Tracker Radar, or an existing TSV for the rows to merge over — in precedence
order:

```bash
cd rust && cargo run --example services_dataset -- <body> <body> … [--out <path>]
```

A user can update the table without a rebuild: subscribe to a URL from the
Filters screen, or import a file there. The core converts either to the shipped
format before it keeps it, and leaves the previous table in place when the body
is not a sorted domain list. DuckDuckGo publishes its radar as one JSON file per
region, so it comes in through the file picker, joined first.

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
