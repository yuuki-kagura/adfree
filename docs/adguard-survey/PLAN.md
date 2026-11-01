# Follow-up plan — notification actions and Protection parity

Companion to `SURVEY.md`. Scope for the next session, ordered by value and
risk. Each step starts with the GitNexus impact check required by `AGENTS.md`.

## Phase 0 — baseline

1. Re-run `node .gitnexus/run.cjs analyze --index-only --repo .` if the graph
   is stale, then `impact` on every symbol before editing it.
2. Build and install the current HEAD on the test device so the notification
   and module changes are compared against a known baseline.

## Phase 1 — notification parity (highest value, lowest risk)

Goal: title + live stats + two actions, and a disabled state that keeps a
tap-to-enable reminder, matching AdGuard 4.14.

Files:

- `app/src/main/kotlin/git/shin/adfree/vpn/AdGuardVpnService.kt`
  - `buildStatusNotification` (~444–510): switch to
    `NotificationCompat.BigTextStyle`, content title `Đang chặn quảng cáo và
    công cụ theo dõi`, body two lines:
    `Bị chặn: N` / `Dữ liệu đã lưu: X MB` (localized format, no hard-coded
    separators outside `strings.xml`).
  - Actions: keep the stop/disable action but relabel it to AdGuard's wording
    (`Vô hiệu`/`Vô hiệu hóa`), and add `Trợ lý` as the second action; move
    pause/resume to the assistant or to a third action only if the row stays
    readable (AdGuard ships exactly two).
  - Disabled state: instead of `stopForeground(STOP_FOREGROUND_REMOVE)` +
    `stopSelf()` on disable, keep the foreground service but paused (VPN on,
    filtering off) and post `Bảo vệ bị vô hiệu hóa` /
    `Quảng cáo và trình theo dõi không bị chặn. Nhấn để bật`, whose
    `contentIntent` re-enables protection. Verify this does not keep wakeups
    alive: the Rust side already has `setProtectionPaused`/screen-off fast
    paths.
  - Stats source: `AdGuardRepository.stats` (`ProtectionStats`) and/or
    `engine.logStatusCounts()`; format bytes the same way Home does so the
    numbers agree across screens.
- `app/src/main/res/values/strings.xml` and `values-vi/strings.xml`:
  new title/body/action/disabled strings; follow the existing terse style from
  commit 529cf16.
- Notification channel stays `IMPORTANCE_LOW` unless testing shows the two
  action buttons need DEFAULT to be visible; AdGuard uses DEFAULT but AdFree
  should avoid noisy channel changes.

Assistant (start minimal, grow later):

- New `AssistantActivity` or a Compose modal bottom sheet launched from the
  `Trợ lý` action via a `PendingIntent` (`startActivity`) that carries an
  extra the app reads in `MainActivity`/nav host.
- Sheet skeleton: title `Trợ lý AdFree`, tabs `Ứng dụng` / `Trang Web`.
  - Apps tab: recent apps from `repository.logs` attribution, newest first,
    relative `Được sử dụng ... trước` style text.
  - App shortcuts: `Hoạt động gần đây` (log filtered by package),
    `Thống kê ứng dụng` (existing per-app stats if present),
    `Quản lý ứng dụng` (Apps tab), `Cài đặt tường lửa` (existing per-app
    firewall sheet).
  - Web tab: recent domains from the log; empty state copy mirrors AdGuard's
    `Chưa có hoạt động nào`.

Verification: `dumpsys notification` must show two actions and the stats
lines; expand/collapse both states, toggle disable/enable, confirm AdFree VPN
re-registers and the assistant opens over any app.

## Phase 2 — Protection rows: annoyances and browsing security

Goal: two new rows on the landing, backed by real gates rather than reusing
the ad-blocking flag.

1. Annoyances module:
   - Rust: add a module flag in `ProtectionConfig` (`rust/src/engine.rs`,
     near `ad_blocking` ~237), include it in `set_module_flags` (~848–858,
     ~1021–1034), and gate `FilterGroup.ANNOYANCES` on it instead of
     `AD_BLOCKING` (`FilterCatalog.moduleGate` ~60–65).
   - Kotlin: settings field, repository toggle, MVI intent, landing row
     (icon from `Icons.Default.*` or a new vector), detail screen reusing the
     switch list from `15-annoyances.png`.
   - uniffi: regenerated bindings via `./gradlew :app:verifyBindings` with
     `ADFREE_RUST_TARGET_DIR` and `ANDROID_NDK_HOME` as before.
2. Browsing security module:
   - The security lists already exist in `FilterCatalog` (URLhaus, Phishing
     URL Blocklist, Dandelion anti-malware, ~240–266). Either add a module
     gate for `FilterGroup.SECURITY` or create one grouped filter set.
   - Detail screen mirrors `10-browsing-security.png`: master switch plus a
     short privacy note (hash/domain check, no URLs leave the device).
   - Decide whether a warning UI is needed when a malicious domain is hit; if
     yes, reuse the log/blocked path and add a localized notification on the
     existing alert channel rather than a new channel.
   - AdGuard keeps two separate groups (`47`, `49`): `Bộ lọc bảo mật` is
     tracking-gated (spyware, URL tracking, EasyPrivacy, ...) while
     `Bộ lọc bảo vệ` holds the malware/phishing lists and is **not** gated by
     the tracking switch. AdFree's single `FilterGroup.SECURITY` is currently
     ungated and mixes both. Split it (or add a subgroup flag) so the
     browsing-security gate covers malware lists without switching off the
     tracking lists, and show the inactive warning when the owning module is
     off.

## Phase 3 — Firewall parity

Goal: global five-rule grid, per-app overrides, quick actions, notifications.

1. Model and core:
   - `AppFirewallRule` (~329–338) gains per-network screen-off/roaming
     dimensions or a shared `NetworkRule` value; `ProtectionSettings`
     (~465) gains the five global defaults.
   - Rust firewall evaluation currently understands Wi-Fi/cellular and
     screen-off; add roaming detection (TelephonyManager/ConnectivityManager
     signal in Kotlin, or pass a roaming flag into the core) and separate
     screen-off policies per transport. This is the largest change; keep the
     hot path allocation-free and add engine tests mirroring
     `rust/src/store/mod.rs` test style.
   - Persist via the same settings store and bump the schema version if the
     format changes; include a migration test.
2. UI:
   - Firewall detail (`ProtectionScreen.kt` ~581–621) gains
     `Quy tắc tường lửa toàn cầu`, `Quy tắc tường lửa tùy chỉnh`,
     `Hành động nhanh`, `Thông báo` rows like `04-firewall.png`.
   - Global rules screen: master + five switches (`05`).
   - Custom rules screen: app list with overrides (`06`), app picker sheet
     with search and grouped system apps (`07`), per-app override screen
     (`08`).
   - Quick actions (`09`, `62`): recent log entries grouped by app, `Chặn truy
     cập` button mapping to the same per-app rule update; reuse the
     infinite-log data already loaded by the repository. Per-card overflow
     offers recent app activity, app firewall rule, app management and a
     one-tap `Tắt tiếng thông báo`; the first three are navigation shortcuts,
     the last flips the per-app notification toggle.
   - Firewall overflow (`60`, `61`): a single `Đặt lại mặc định` action with a
     confirmation sheet. If added, reset only the firewall section (global
     defaults, per-app overrides, quick-action mutes), not other modules.
   - Notifications toggle: only notify for apps the user selected; post on
     the first blocked attempt per app/window to avoid spam.
3. Keep the existing Apps-tab sheet working; the new screens should call
   `updateAppFirewall` rather than duplicate state.

## Phase 4 — assistant depth and leftovers

- Assistant app stats/activity tabs wired to the existing log filters.
- Optional: `Cách chặn quảng cáo trên YouTube` help row and private-browser
  link, if the user wants them; both are navigation-only in AdGuard.

## Phase 5 — app management, settings and remaining screens

### Filter catalog parity (`43`–`51`)

AdFree already has `FiltersScreen`/`FiltersExtensions` and
`FilterCatalog` groups. Bring the UI to parity:

- Category landing: show `Đã bật: X trên Y` per group.
- Inactive warning: when the gate module is off, grey the affected category
  and offer `Kích hoạt` (AdGuard does this for tracking-gated security
  filters; AdFree needs it once annoyances/security have their own gates).
- Filter detail: description, last update, rule count, homepage, source URL
  and feature bullets. `FilterCatalog` already stores URL and description;
  rule count comes from the downloaded list metadata.
- Custom filters: `Thêm bộ lọc tuỳ chỉnh` plus the empty state; the add sheet
  takes a URL/local path with `Tiếp theo` and a file `Duyệt` picker (`66`).
- Language filters: the existing language group already matches AdGuard's
  list (ABPVN for Vietnamese); add version/update rows if the store has them.
- Allowlist add sheet (`67`): single `Địa chỉ trang web` field and `Thêm`.
- DNS add sheet (`69`) mirrors the custom-filter sheet with DNS-specific hint
  text; user-rule sheet (`68`) takes a raw rule with a syntax help link.

### Per-app screen (`25-app-detail.png`)

The current Apps tab sheet has filtering/HTTPS/firewall switches. Add routing
(`Định tuyến qua AdGuard`), proxy routing, per-app firewall shortcut and a
stats row. The firewall shortcut should open the new per-app rule screen from
Phase 3 instead of a second sheet.

### Settings (`34`–`40`)

- `Mạng`: AdFree's HTTPS filter switch already exists as a Protection module;
  expose a `Chế độ định tuyến` row that names the active mode (local VPN
  today, SOCKS5 endpoint when the proxy is configured).
- General: verify AdFree already covers auto-start, theme, language, update
  schedule and notification settings; add missing rows only where they change
  engine behavior.
- `Thông báo ứng dụng` is only a deep link to the OS channel settings in
  AdGuard (`70`–`72`); AdFree can add the same shortcut
  (`Settings.ACTION_APP_NOTIFICATION_SETTINGS`) instead of building an
  options screen, and should register separate channels per feature
  (protection, firewall, updates) like AdGuard's six OS channels.

### Allowlist, statistics, log

- Allowlist: give the website allowlist a dedicated screen (search + add) or
  document that HTTPS website rules cover it. AdGuard keeps it separate from
  user rules.
- Log detail (`73`–`79`): a request-detail screen with status, event type,
  domain/URL/address, DNS answer, timings, connection id and sizes, plus the
  applied rule. From an allowed request offer `Thêm quy tắc chặn`, from a
  blocked one `Thêm quy tắc cho phép`; the sheet pre-fills the rule from the
  request and scopes it to the app (block rules also get a priority option).
  AdFree's Log tab already has the needed fields in `log_events` (action,
  host, app, protocol, time) except sizes/connection id; store those if the
  detail screen is built. Log overflow (`77`) adds export and clear.
- Statistics (`52`–`59`): AdFree can build most of this from `log_events`:
  - data-type filter (all / mobile / Wi-Fi) and four time-range presets
    (24 h / 7 d / 30 d / all time);
  - all-apps list with ads/trackers/total counts, search and sort by
    ads/trackers/requests;
  - per-app screen with request/data counts, `Hoạt động gần đây` and an
    `App management` shortcut.
  The `Các dịch vụ` company breakdown has no direct AdFree equivalent: it
  needs a domain→company mapping that AdFree does not ship. Either skip that
  section or derive a minimal "top domains contacted" list until a company
  database is added (out of scope for now).
- `log_events` stores per-app attribution, so these aggregates are a new
  `GROUP BY app` query; add the matching index if the planner does not reuse
  `log_events_action`.
- Statistics/log wording: AdGuard advertises "newest 10k requests stored";
  AdFree already shows `log_window_capped` at 10k in RAM, but the SQLite store
  keeps 200k rows for 7 days. Keep the UI honest about the difference.

### Screens still missing from the survey

These do not block Phase 1–4, but capture them before implementing the
matching feature:

| Screen | Status | Use for |
| --- | --- | --- |
| Per-app statistics and `Xem tất cả ứng dụng` | captured (`55`–`59`) | implement from `log_events` as described above |
| Log entry detail + "create rule from request" | captured (`73`–`78`) | request detail, applied rule, block/allow rule creation |
| Settings → General → `Thông báo ứng dụng` | captured (`70`–`72`) | OS deep link; six AdGuard channels |
| `Thêm trang` (allowlist), `Quy tắc người dùng mới`, `Thêm bộ lọc DNS`, `Thêm bộ lọc tuỳ chỉnh` dialogs | captured (`66`–`69`) | add-flow parity |
| Quick actions / firewall overflow menus | captured (`60`–`62`) | navigation shortcuts, per-app mute, firewall reset |
| Social and annoyances filter categories | captured (`63`–`65`) | same row template; annoyances has 11 filters, social 2 |
| YouTube how-to page, private browser link | out of scope | navigation only |

## Phase 6 — data-model gaps from Phase 5

Goal: close everything Phase 5 could not build because the log, firewall or
filter stores do not carry the fields. Every step starts with the GitNexus
impact check required by `AGENTS.md`; the Rust schema change lands with its
migration test in the same commit.

Order matters: 6.1 unblocks 6.2 and 6.3, so do it first.

### 6.1 Log storage: transport, flow id, URL, DNS answer, sizes

Screens `52`–`59` and `73`–`79` need fields the log does not store today.

- Schema v6 (`rust/src/store/mod.rs`, `migrate()` after the v5 index at
  ~412): add `transport INTEGER NOT NULL DEFAULT 0`, `flow_id INTEGER NOT
  NULL DEFAULT 0`, `url TEXT NOT NULL DEFAULT ''`, `dns_answer TEXT NOT NULL
  DEFAULT ''`, `bytes_sent INTEGER NOT NULL DEFAULT 0`, `bytes_recv INTEGER
  NOT NULL DEFAULT 0`; index `log_events_transport_action ON
  log_events(transport, action)` for the statistics tabs. Keep the
  `INSERT INTO log_events` column list at ~513 and every test fixture in sync.
- `rust/src/events.rs` `Event` (~48): transport (unknown/wifi/cellular) and
  roaming ride in spare `flags` bits next to `ipv6`; add a `flow_id` field.
  `MAX_URL` needs a byte budget decision: 256 B × 10k ring events is ~2.5 MB
  on top of the current ring, so cap at 128 B and store only the path when
  MITM knows it. Builders at ~245 (`with_app`, `allow_event`, `block_event`)
  and the ring/persist path take the new fields.
- Fill transport from the existing `Core.network_type` / `roaming` atomics
  (`rust/src/engine.rs` ~705–707, setter ~1027) at event construction; the
  packet loop already reads these for firewall decisions, so this is a
  snapshot, not new connectivity plumbing.
- URL: `mitm::proxy::MitmBlock` (`rust/src/mitm/proxy.rs` ~141) gains
  `url: &str` (or path) filled by the decryptor; `log_mitm_block`
  (`rust/src/engine.rs` ~729) writes it. Non-MITM events keep `url` empty.
- DNS answer: when the packet path answers a query from upstream, attach the
  first A/AAAA answers to the event; otherwise leave empty.
- Sizes: events are logged at decision time, so add `Store::finish_flow(id,
  sent, recv)` called when a relay closes; blocked flows that moved no bytes
  stay zero. Batch the update with the next insert if a write per close
  shows up in benchmarks.
- uniffi: extend `LogEvent` (`rust/src/api.rs` ~189) and both `From` impls;
  regenerate bindings (`app/src/main/kotlin/git/shin/adfree/core/adfree.kt`,
  `CoreEngine.kt`) with `./gradlew :app:verifyBindings`.
- Kotlin: `NetworkRequestLog` (`model/Models.kt` ~40) gains transport,
  flowId, url, dnsAnswer, bytesSent, bytesRecv; `from(event)` maps them; the
  log detail rows in `FilteringLogScreen.kt` render URL, DNS answer,
  connection id and sizes; `AdGuardRepository.exportLogs` adds the columns to
  the CSV header.

### 6.2 Statistics parity (`52`–`59`)

- Data-type filter (all / mobile / Wi-Fi) chips on the statistics header,
  backed by `transport`; this is the piece missing from Phase 5.
- Ads vs trackers: `RequestCategory` already separates ad and tracking
  categories, so extend the per-app aggregate instead of inventing a field.
  Either widen `AppUsage` (`rust/src/api.rs` ~687) with ads/trackers counts
  or add `core_app_usage_detail_since`; the Kotlin list in
  `AppsManagementScreen.kt` gains a two-number row and the sort enum a third
  key if AdGuard's column is kept.
- Keep the existing time ranges, search and sort; they already cover `53`,
  `57`.
- Company breakdown (`59`) stays out of scope: it needs a domain→company
  database AdFree does not ship. If a fallback is wanted, show "top domains
  contacted" from the same `GROUP BY domain` instead and label it as such.

### 6.3 Per-app proxy routing

Phase 5 shipped the per-app screen without this row because the flag does not
exist; `isFilterRouted` only controls VPN inclusion.

- Model: `AppFirewallRule` gains `proxyAccess` (INHERIT / THROUGH / DIRECT,
  reusing the tri-state pattern from `FirewallAccess`); Rust mirror in
  `AppFirewallRule` + wire struct (`rust/src/state/model.rs` ~309–395) and
  `AppFirewallState` (`rust/src/engine.rs` ~327). State is JSON, so no SQL
  migration — add a serde default so old profiles load.
- Core: the TCP and UDP dial paths already resolve `cfg.proxy` (~2640) and
  the firewall lookup already has the per-flow package list. Add one lookup
  of `proxyAccess` there: THROUGH forces the SOCKS5 endpoint even when the
  global proxy is off, DIRECT bypasses it. Keep it allocation-free and reuse
  the firewall attribution map.
- Kotlin: repository `updateAppFirewall(proxyAccess = …)`, MVI intent field,
  `StateMapping` round-trip, a `Định tuyến proxy` row in the per-app sheet
  (`AppsManagementScreen.kt`) disabled while no usable global proxy is
  configured, plus strings in both locales.
- Tests: override beats the global routing mode in both directions; a
  DIRECT app is unaffected when the proxy is off.

### 6.4 DNS filters (`69`)

AdGuard keeps DNS-only lists apart from the website lists; AdFree applies
every catalog list to DNS and has no separate store, which is why the add
sheet was skipped.

- Core: add a `dns_filters` collection to `FilterState`
  (`rust/src/state/model.rs` ~602) and a second matcher consulted only in
  the DNS path; keep the existing lists on the current path unchanged so
  block counts do not shift.
- UI: a `Bộ lọc DNS` section in `FiltersScreen`/`FiltersExtensions` with the
  `Thêm bộ lọc DNS` sheet from `69` (URL or local file, reuse the custom
  filter flow and error copy).
- Alternative if the separate store is rejected: document in the UI that
  regular lists already filter DNS and delete the screenshot's flow from the
  plan. Decide before coding; the recommendation is the separate collection.

### 6.5 Carry-over and verification

- Phase 4 leftovers are navigation-only and may ride along: `Cách chặn quảng
  cáo trên YouTube` help row and the private-browser link.
- Allowlist (`67`): keep the current HTTPS website rules as the answer. If a
  dedicated search + add screen is still wanted, reuse the user-rule list
  path; it is cosmetic parity, not engine behavior.
- Rust tests: v5→v6 migration keeps row counts and old rows read with
  defaults; `flags` transport/roaming round-trip; `GROUP BY app, category`
  counts; per-app routing override; DNS-only lists do not match HTTP rules.
- Kotlin tests: `NetworkRequestLog` mapping, CSV columns, data-type filter.
- Bindings: `./gradlew :app:verifyBindings` with `ADFREE_RUST_TARGET_DIR`
  and `ANDROID_NDK_HOME`, rebuild the four ABIs with `cargo ndk`, then
  `./gradlew :app:testDebugUnitTest :app:assembleRelease -PskipNative`.
- Device (deferred from Phases 3–5): install on the Redmi, verify roaming
  with Wi-Fi off/mobile on, screen-off per transport, log detail fields,
  mobile/Wi-Fi statistics, per-app proxy routing and the DNS filter sheet;
  capture screenshots at 800×1340 for `52`–`59`, `69`, `73`–`79`.
- Device verification record (2026-11-01, Sony 802SO / Android 10, the
  connected device in place of the unavailable Redmi; VPN up on Wi-Fi,
  per-app evidence read from the on-device `adfree.db`):
  - Screen-off per-app firewall: verified. With the target app's
    Wi-Fi-screen-off access set to block, turning the screen off produced
    "App firewall" block rows for its DNS traffic (reason "app not allowed
    on Wi-Fi while the screen is off") and the block lifted on screen-on
    after the rule was reset. Caveat: with eco mode ON (the default)
    `log_event` intentionally drops every event written while the screen is
    off, so the enforcement is invisible in the log — the 333-row evidence
    above only appeared after eco mode was turned off for the test.
  - Per-app proxy routing: verified earlier in the same effort. A local
    SOCKS5 witness (`adb reverse tcp:1080`) logged the device's upstream
    CONNECTs: the baseline window with rules at INHERIT and the global
    proxy OFF produced no traffic for ~7 minutes, and once proxy routing
    was enabled the witness recorded the proxied connections (153 CONNECT
    records) — the override drives the dial path in both directions.
  - Roaming: negative path verified; positive enforcement not reachable on
    this device. Cellular is out of service (active network is the Wi-Fi
    VPN, `roaming=false` on every interface), so no SIM-roaming traffic can
    be produced without root to spoof the capability. Setting the roaming
    rule to block on an app while on Wi-Fi produced zero roaming blocks and
    normal traffic, which shows the `network == CELLULAR && roaming` gate is
    enforced; the decision function and flow-drop machinery are the same
    ones the screen-off test exercised end to end.
  - Device restored after the test: firewall table back to `[]`, eco mode
    back ON, VPN running with the default config.
- Benchmarks: the event enrichment sits on the packet hot path; run
  `BENCHMARK.md` and confirm ring memory growth stays under ~3 MB and
  per-flow cost is unchanged within noise.

### Risks

- The log table grows wider on disk; the retention window (200k rows / 7
  days) may need to shrink or the URL column to stay empty outside MITM.
- A write per closed relay doubles SQLite traffic if not batched.
- Per-app proxy lookup adds a map probe on the dial path; reuse the firewall
  map and measure before shipping.
- Splitting DNS lists can change existing block counts; run the full filter
  suite and compare against a real page set, like the Phase 2 risk note.

## Out of scope

- AdGuard VPN and private browser (separate products).
- Switching AdFree to a DEFAULT-importance channel.
- Any network/telemetry feature.

## Testing checklist

- Rust: `cargo test` for engine/firewall/new gates; persistence migration.
- Kotlin: unit tests for stats formatting, relative-time text, module gates.
- Device: `./gradlew :app:verifyBindings`, rebuild the four ABIs with
  `cargo ndk`, copy the `.so` files manually (cargo-ndk hardlinks), then
  `./gradlew :app:assembleRelease -PskipNative`.
- Manual: notification in both states and both languages; assistant opens
  over a third-party app; each new toggle survives process death; per-app
  override beats global rules; roaming and screen-off behavior verified with
  Wi-Fi off/mobile on if a SIM is available.
- Visual: screenshot each new screen at the same 800×1340 viewport for a
  side-by-side table against the AdGuard captures.

## Risks

- The disabled-but-running notification changes AdFree's service lifetime;
  verify no battery regression and that `onRevoke` still stops everything.
- Roaming/screen-off rules touch the packet hot path; benchmark with
  `BENCHMARK.md` before shipping.
- Annoyances/security modules change which filter rules are active; run the
  full filter test suite and compare blocked counts on a real page set.
- Only one VPN slot: the test device must stop AdGuard before validating
  AdFree, and vice versa.
