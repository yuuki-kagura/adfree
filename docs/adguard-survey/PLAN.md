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
re-registers and the assistant opens over any app. Done on the Sony 2026-11-02
— see the group-2 device verification record in §6.5. The open item it listed —
the assistant's per-app panel could not be scrolled back out — is fixed by
`b0101c8`; the panel is now a scrolling column, and the on-device re-check is
recorded with the other outstanding checks in §6.5.

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
   - Decided and shipped: a malicious block has to be visible without opening a
     screen. `974cfed` posts one localized notice per domain per hour on the
     existing alert channel, gated by the browsing-security switch, and the tap
     opens the log filtered to that domain. No new channel, no core change —
     the security lists already tag their blocks with the malware category, and
     the Kotlin mapping of that number is pinned by a test because a drift
     would silently stop the notice firing.
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

- Category landing: show `Đã bật: X trên Y` per group. Done — `FilterGroupCard`
  puts the sentence under the group name (`filters_group_enabled`) instead of
  the bare `2/3` ratio it used to show on the right of the row.
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
  user rules. **Reversed** — the earlier "no dedicated screen" decision is
  dropped. `1b34e10` adds one: the ad-blocking module opens the `@@` rules as a
  list of domains with search, add by typed host and delete, all through the
  existing incremental rule intents so the raw rules sheet stays in sync. What
  it deliberately does not have is a per-rule on/off switch — lines starting
  with `!` are stripped before the rules reach the core, so a disabled
  exception would be deleted rather than parked.
- Log detail (`73`–`79`): **done.** The request-detail sheet shows status, event
  type, domain/URL, DNS server and protocol, timings, connection id, size, the
  applied rule and its filter list. `Chặn tên miền` / `Danh sách trắng` no longer
  write a rule straight away; they open the rule-from-log sheet
  (`ui/screens/RuleFromLogSheet.kt`), which pre-fills the rule from the request,
  offers the exact-host and parent-domain candidates, lets the text be edited,
  and for block rules offers a priority tick and an app-scope tick.
  Composition lives in `model/RuleFromLog.kt` (`ruleCandidates`,
  `composeRuleText`, `appScopeSupported`) and is unit-tested.
  - "Priority" maps to the existing `$important` option — the engine has no
    numeric priority; `app_merge` resolves it as
    `blocked = important || (block && !exception)` (`rust/src/filter.rs:6663`),
    so the combined form is `||host^$app=<pkg>,important`.
  - App scope is offered only where the engine can honour it. `$app=` is
    enforced on the HTTPS/MITM and cosmetic paths (`check_url(..., apps)`), but
    `check_host()` (`rust/src/filter.rs:2216`) takes no apps and the decision
    cache is keyed by host alone, so a DNS-time rule cannot be per-app. DNS
    entries therefore show a note instead of the checkbox; no Rust change.
  - Allow rules get no options section, matching the AdGuard capture (`79`).
  - Sizes and connection id were already stored by Phase 6.1; log overflow
    (`77`) export and clear already existed.
  - Device verification record (2026-11-01, Sony 802SO / Android 10, release
    build): the sheet renders like the AdGuard capture (`75`) — title
    `Thêm quy tắc chặn`, prefilled `||<host>^` with a clear button, host and
    parent-domain radios, and the `Tuỳ chọn` ticks. Ticking priority + app scope
    on a UDP/Instagram entry produced
    `||test-gateway.instagram.com^$app=com.instagram.android,important`, stored
    once in `Quy tắc của bạn` and listed as a block rule. A DNS_UDP entry
    showed no app checkbox, the DNS note instead, and stored
    `||device-api.urbanairship.com^` with no `$app=`. Re-submitting that rule
    showed `Quy tắc đã có trong danh sách` and left the list at the same count.
    Both test rules were deleted afterwards.
- Statistics (`52`–`59`): AdFree can build most of this from `log_events`:
  - data-type filter (all / mobile / Wi-Fi) and four time-range presets
    (24 h / 7 d / 30 d / all time);
  - all-apps list with ads/trackers/total counts, search and sort by
    ads/trackers/requests;
  - per-app screen with request/data counts, `Hoạt động gần đây` and an
    `App management` shortcut.
  The `Các dịch vụ` company breakdown: **shipped**, reversing the earlier
  "out of scope". `f153ee0` adds a domain breakdown to the Statistics screen,
  labelled with the company that owns each registrable domain and falling back
  to the plain domain when the table has no row. The labels come from
  `rust/assets/services.tsv` (126 rows authored for this project — DuckDuckGo
  Tracker Radar and Ghostery were rejected because both are CC BY-NC-SA 4.0 and
  an app we distribute cannot carry NonCommercial). The table is compiled in
  with `include_str!`, looked up by suffix walk plus binary search over
  byte-sorted line offsets, and a downloaded override in `filters_dir` wins.
  `show_services_breakdown` defaults off because the second `GROUP BY` costs a
  query per refresh; the refresh piggybacks on the existing filter-update loop.
- `log_events` stores per-app attribution, so these aggregates are a new
  `GROUP BY app` query; add the matching index if the planner does not reuse
  `log_events_action`.
- Statistics/log wording: AdGuard advertises "newest 10k requests stored";
  AdFree already shows `log_window_capped` at 10k in RAM, but the SQLite store
  keeps 200k rows for 7 days. Keep the UI honest about the difference. Done —
  `log_retention_note` sits under the log's subtitle (testTag
  `log_retention_note`), not in the capped footer, because that footer only
  renders once 10k rows are loaded and would hide the window from every shorter
  log. It reads the store's own numbers (`LOG_DB_MAX_ROWS`/`LOG_DB_KEEP_DAYS`
  in `AdGuardRepository`, kept in step with `MAX_ROWS`/`KEEP_MS` in
  `rust/src/store/log.rs`).

### Screens still missing from the survey

These do not block Phase 1–4, but capture them before implementing the
matching feature:

| Screen | Status | Use for |
| --- | --- | --- |
| Per-app statistics and `Xem tất cả ứng dụng` | captured (`55`–`59`); `59` shipped by `f153ee0` | implement from `log_events` as described above, plus `services.tsv` for the company labels |
| Log entry detail + "create rule from request" | implemented | request detail, applied rule, block/allow rule creation |
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
- Sizes: implemented as a separate per-connection table, not an update of the
  decision row. `flow_id` in `log_events` is the id the core gives each *row*
  (`engine.rs`, `next_flow_id`), so no row can be "finished" at close, and a
  host the app opened a dozen connections to still has one DNS row — a
  decision row cannot carry a truthful size. Schema v7 adds `flow_traffic
  (ts_ms, app, transport, roaming, sent, recv)` with `ts_ms` and `(app, ts_ms)`
  indexes; `Relay` reports `flow.down_bytes` (device → server) and a new
  `payload_to_client` counter (server → device, because `flow.up_bytes` also
  counts the SYN-ACK and FIN sequence numbers) through a `TrafficSink` function
  pointer in `Drop` — the one hook that fires on every retirement path. The
  engine supplies the sink at the relay's single construction site
  (`begin_tcp_relay`) and stamps the network there, exactly like `log_event`
  does. Blocked flows that moved nothing report nothing. `usage_by_app` LEFT
  JOINs the per-app traffic sums, `window_totals` adds them to the small DNS
  answer bytes the log rows already carry, and `clear`/`prune_db` cover the new
  table with the log.
  The two datagram paths ride the same sink. `UdpFlow` carries `sent`/`recv`
  plus the sink: `relay_udp` counts each client datagram after a successful
  send, `handle_udp_reply` counts each rewritten reply, and the mapping's
  `Drop` reports, so idle expiry, a policy retire and the shutdown clear all
  account for themselves. A terminated QUIC flow does the same through
  `H3Flow`: `feed_h3` counts what the client pushed into quinn, `drain_quic`
  attributes each datagram quinn produced back to its flow by the client's
  five-tuple, and reaping, splicing or abandoning reports. Quinn's upstream
  half is deliberately not counted — the client-facing side is what the app
  actually put on and took off the wire.
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
- Company breakdown (`59`): no longer out of scope — see the `Các dịch vụ`
  entry under the statistics section, closed by `f153ee0` with a project-owned
  `services.tsv`. The "top domains contacted" fallback this line proposed is
  what the screen shows when the table has no row for a domain.

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

- Phase 4 leftovers are navigation-only. Decided against the
  `Cách chặn quảng cáo trên YouTube` row: AdFree has exactly one help target
  (`HELP_URL`, the project README, already surfaced in Settings) and no docs
  page for this how-to, so a second navigation row on the Protection list would
  either duplicate it or point at a third party's site. The private-browser
  link stays out of scope with the rest of that product.
- Allowlist (`67`): closed by `1b34e10` with the dedicated screen this section
  called cosmetic parity. The HTTPS website rules stay what they are — the
  per-module skip/only lists — and the new screen owns the `@@` exceptions.
- Rust tests: v5→v6 migration keeps row counts and old rows read with
  defaults; `flags` transport/roaming round-trip; `GROUP BY app, category`
  counts; per-app routing override; DNS-only lists do not match HTTP rules.
  For the v7 traffic table, seven checks:
  `store::tests::traffic_rows_follow_the_log` (the rows age out and clear with
  the log), the extended `app_usage_counts_blocked_rows_and_bytes` (per-app
  sums and the header totals),
  `mitm::relay::tests::a_retired_relay_reports_what_crossed_it` (payload only,
  once, with the owning package),
  `engine::tests::a_reaped_udp_mapping_lands_in_the_store` (the engine's own
  sink really reaches the database: two datagrams reaped on idle expiry, read
  back through the per-app join),
  `udpnat::tests::a_retired_mapping_reports_its_datagrams` and
  `a_retired_flag_reports_before_the_mapping_goes` (both UDP retirement
  paths), and `engine::tests::a_reaped_quic_flow_reports_its_datagrams` (a fed
  datagram is counted and a reaped QUIC flow reports it).
- Fixed, was a known flake:
  `filter::tests::detailed_lookup_reports_rule_and_list` failed about one full
  suite run in three, and failed every run filtered to `filter::tests` alone.
  Every filter test wrote its list bodies to the same `/tmp/adfree-filter-test`
  path, and the engine reads rule text back from the file when a lookup
  resolves, so a parallel test could replace the body another one was reading
  (`temp_list("base.txt", "! empty", …)` at the head of that path). `temp_list`
  now writes under a per-test subdirectory named after the test thread. The
  filtered run, which used to fail every time, passed three times in a row.
- Two ECH path tests had been failing silently since the DNS cache landed
  (`e4dc75c`, 29 Oct): `ech_configs_are_stripped_only_while_https_filtering_is_on`
  and `a_host_that_requires_ech_keeps_its_config` each asked the same name twice
  and their fake resolver expected to see both queries. The second is now a
  cache hit, so the resolver timed out and the binary reported a product
  failure that was a stale expectation. Bisected 74c6f66 (green) → e4dc75c
  (red); `handle_reply` is on the hit path (`serve_cached_answer`) and the cache
  stores the origin's unstripped answer, so the policy assertions still hold —
  the tests now count forwarded queries and assert exactly one, which is the
  stronger claim.
- Same investigation found `Core::clear_dns_cache` never cleared the answer
  cache it is named for: it dropped the rule cache, the connection tracker and
  the in-flight queries, but not `dns_cache`, which only `set_resolver` clears.
  It is exposed through uniffi (`core_clear_dns_cache`) and wrapped by
  `CoreEngine.clearDnsCache`, neither of which has a caller yet, so nothing
  broke in practice. The line is in, pinned by
  `clearing_the_dns_cache_sends_the_next_query_upstream`, which fails without
  it.
- Kotlin tests: `NetworkRequestLog` mapping, CSV columns, data-type filter.
- Bindings: `./gradlew :app:verifyBindings` with `ADFREE_RUST_TARGET_DIR`
  and `ANDROID_NDK_HOME`, rebuild the four ABIs with `cargo ndk`, then
  `./gradlew :app:testDebugUnitTest :app:assembleRelease -PskipNative`.
- Device (deferred from Phases 3–5): most of it was verified on the connected
  Sony instead of the Redmi — see the two records below. What still needs the
  Redmi: roaming with Wi-Fi off and mobile on (positive enforcement, not
  reachable without root on the Sony), and the per-flow memory probe in
  `BENCHMARK.md`. Screenshots `52`–`58`, `69`, `73`–`79` are captured. `59`
  (AdGuard's all-companies list) still needs an AdFree-side capture: the
  company breakdown it shows shipped in `f153ee0`, but no side-by-side
  screenshot of our version exists yet.
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
- Device verification record (2026-11-02, Sony 802SO / Android 10, release
  build versionName 1.1.1):
  - Numbering: the `adfree/` captures carry the AdGuard screen id they
    correspond to. The three below show AdFree behaviour with no AdGuard
    screen behind them, so they continue the sequence at `80`–`82` rather than
    reuse `77`–`79`, which already name the log overflow, blocked-request
    detail and allow-rule dialog.
  - Statistics range and data-type chips: `Hôm nay / 7 ngày / 30 ngày / Mọi
    lúc` over `Mọi mạng / Dữ liệu di động / Wi-Fi` — the §6.2 transport filter
    and the existing ranges in one frame (`adfree/adfree-53-stats-time-range.png`).
  - Rule-from-log sheet: opening a blocked row's whitelist action raises
    "Thêm quy tắc chặn" with `||msdk.shopee.vn^` pre-filled, the `||shopee.vn^`
    wider alternative and the priority option; cancelled without writing, so
    the custom list is unchanged (`adfree/adfree-75-dialog-rule-from-log.png`).
  - Log retention line: renders where §6.1 put it — under "Truy vấn mạng gần
    đây" the header reads "Cơ sở dữ liệu giữ 200000 dòng gần nhất trong 7
    ngày" with 15048 rows loaded, so a short visible list no longer reads as
    a short history (`adfree/adfree-80-log-retention.png`).
  - Statistics byte totals: "Dữ liệu sử dụng 126,2 MB đã lưu / 21,6 MB đã tải
    lên / 118,4 MB đã tải xuống" with the segmented bar, from
    `log_window_totals` (`adfree/adfree-81-stats-byte-totals.png`).
  - Filter group enabled count: "Đã bật: 1 trên 4" on the Riêng tư group
    (`adfree/adfree-82-filters-group-enabled.png`).
  - Per-app statistics and the tracker-sorted list, captured once the mask app
    was closed. AdFree has no per-app statistics page: the figures live in each
    card on the Ứng dụng screen — "161 chặn • 7 MB" over "0 quảng cáo • 158
    trình theo dõi • 167 yêu cầu" (`adfree/adfree-55-per-app-stats.png`).
    Sorting the same list by `Trình theo dõi` puts the tracker-heavy apps first
    (AccuWeather 158, Viettel Tammi 46 of 524 requests) — the per-app view
    AdGuard reaches through `Xem tất cả ứng dụng`
    (`adfree/adfree-58-stats-all-apps-scrolled.png`). The sheet applies the
    sort live and the header label tracks it; both were restored to `Tên`
    afterwards.
  - Datagram counting: corroborated, not proved. Switching "Chặn QUIC /
    UDP 443" off and browsing Chrome, Facebook and Messenger for ~75 s made
    UDP rows appear (b-graph.facebook.com · Facebook, www.messenger.com ·
    Chrome, protocol UDP), the tunnel stayed up, blocking kept counting
    (2,1K→2,3K ads, 6,4K→6,8K requests) and the byte totals rose (113,6→126,2
    MB saved, 109,4→118,4 MB down). Chrome's per-app figure reached 1 MB /
    184 requests. No surface separates datagram bytes from TCP bytes: the log
    detail's transfer row only fills for rows whose size is known at log time
    (cache-served DNS answers) and none occurred in the sampled window, so
    per-transport attribution rests on
    `a_reaped_udp_mapping_lands_in_the_store`,
    `a_retired_mapping_reports_its_datagrams` and
    `a_reaped_quic_flow_reports_its_datagrams`. The toggle was restored to
    blocked afterwards.
  - Caveat for later captures on this device: a third-party
    `com.aistudio.screenmask.overlay` window covered [176,445][624,787] and a
    Messenger chat head sits at the top right, so both intercept taps and hide
    content. Scrolling the region of interest clear of them, and tapping at
    x<176 or x>624, is what made the earlier reads possible. The user closed
    the mask app for the `55`/`58` captures; the chat head is still up at
    roughly [593,159][800,276] over the search field, and it does not cover any
    app card.
  - Gesture caveat for repeat captures: `adb shell input swipe` only scrolls
    this list when it starts inside it (y≳420). A swipe begun over the sticky
    header does nothing, which first read as the sort chips not applying —
    they do.
- Benchmarks: done host-side. The event enrichment sits on the packet hot path;
  the ring grew 352 B → 560 B per event (176 KB → 280 KB for 512 slots) against
  the ~3 MB budget, and each flow owner grew by the three words the traffic
  counters cost (Relay 928 B, `UdpFlow` 176 B, `H3Flow` 96 B; 94 KB worst case
  across both datagram tables). Both are pinned by tests —
  `the_live_ring_stays_within_its_memory_budget` and
  `a_live_flow_carries_a_known_cost`. The on-device probe half still needs the
  Redmi; see the two dated sections in `BENCHMARK.md`.
- Device verification record (2026-11-02, group 2 — Sony 802SO / Android 10,
  release build versionName 1.1.1). This is the Phase 1 `Verification:` line,
  the Phase 2/3 toggle persistence and the Phase 3 per-app-vs-global
  precedence, in one pass. Captures live under `/tmp/sony` and are not
  committed.
  - Notification: `dumpsys notification` shows id 1001 on channel
    `adfree_status` (IMPORTANCE_LOW) with `flags=0x62 actions=2` while
    running — `Vô hiệu` and `Trợ lý` — and the BigText body `Đang chặn quảng
    cáo và công cụ theo dõi` / `Bị chặn: N` / `Dữ liệu đã lưu: X MB`.
    Expand and collapse both redraw correctly; the 10 s ticker only reposts
    when a counter moved. The disabled state is a separate record
    (`flags=0x2`, `groupKey=silent`, `Bảo vệ bị vô hiệu hóa`), and disable →
    re-enable keeps the counter series continuous while AdFree VPN
    re-registers as the active tunnel. The PAUSED variant is reachable only
    from the assistant's `Tạm dừng bảo vệ` (or the QS tile), because the
    active notification's action is DISABLE — verified through the assistant.
  - Assistant over any app: opened from the `Trợ lý` action with Chrome
    foreground, per-app panel included. `AssistantActivity` is
    `exported="false"`, so a shell `am start` is refused with a
    SecurityException; the notification action is the only entry, as intended.
    Outstanding: the per-app panel does emit the `assistant_app_back` row but
    it is not visible and the sheet does not scroll (content bottom y=1293
    inside the sheet bounds [0,386][800,1316]), so a per-app panel is a dead
    end on this viewport.
  - Toggle persistence: `Chặn làm phiền`, `Bảo vệ Duyệt web` and `Tường lửa`
    were switched off, then `am force-stop` + relaunch; all three came back
    off, so the Rust-side `state` rows survive process death. They are
    restored to ON.
  - Firewall precedence: per-app `Chặn` beats the global allow (Chrome
    `Sử dụng Wi-Fi` = Chặn under global "Tất cả các kết nối được phép" →
    Chrome `ERR_TIMED_OUT`, every other app unaffected), per-app `Cho phép`
    beats a global block, `Kế thừa` follows the global rule, and the rule
    survives process death. The rule was removed and Chrome verified loading
    normally again.
  - Method caveat for every future capture here: the release build excludes
    `com.android.shell` from the tunnel (`AdGuardVpnService.kt:331`), so adb
    DNS and ping traffic bypasses filtering entirely and proves nothing.
    Traffic evidence has to come from an ordinary app; counter evidence from
    the app's own screens.
  - Two defects came out of this pass and both are fixed.
    1. `record_tcp_reset` counted *every* refused flow as a blocked request,
       including the resets sent because a relay could not be built — port
       reuse before the poller reaped the previous flow, a failed
       `connect()`, a session that would not start, data for a dead flow.
       Those paths pass `reason: None` and `None` fell back to
       `"connection dropped"`, so transport failures were added to
       `stats.tcp_reset` and `bytes_saved` and logged as BLOCKED rows; and
       because no filter gate stands between them and the wire, they kept
       arriving while protection was paused. Before/after on this device: the
       old core logged 40 TCP rows as `connection dropped` / `Protection` in
       the 28.5-minute window 21:24:48→21:53:22, for hosts no list names
       (`youtubei.googleapis.com` ×9, `play.googleapis.com` ×7,
       `vpn-api.proton.me` ×5, bare Google and Facebook IPs); the fixed core
       logged 0 TCP BLOCKED rows in 21:53:34→22:00:40 under much denser
       traffic, and every blocked row named a real rule
       (`||la3.vnecdn.net^`, `||cm.g.doubleclick.net^`, `||eclick.vn^`,
       `$third-party script`). `None` now returns before counting; the
       genuine-block half is pinned by
       `a_reset_of_a_learned_blocked_ip_counts_as_a_block` and the transport
       half by `a_refused_reused_port_is_not_counted_as_a_block`.
    2. The blocked-app notification could never fire. The notifier compared
       `row.matchedRule` to `"App firewall"`, which is a *list* name, and the
       TCP half of the firewall filed its rows under `"Protection"` while the
       DNS half used `"App firewall"` — so fixing only one of the two would
       still notify nobody. The notifier now reads `row.filterListName` and
       `record_tcp_reset` files `app not allowed …` reasons under
       `"App firewall"`. After the rebuild, blocking Chrome's Wi-Fi posted id
       16081 on channel `adfree_firewall`: `Đã chặn Chrome` / `Tường lửa đã
       chặn ứng dụng này truy cập Internet`.
  - Impact check on `record_tcp_reset` came back HIGH risk (2 direct callers,
    8 impacted symbols, 1 execution flow) and is reported rather than waived,
    per `AGENTS.md`. `node .gitnexus/run.cjs analyze --index-only` failed on
    this tree ("Worker pool exhausted all slots during idle-timeout retry",
    gitnexus 1.6.12) and the index is ~10 commits behind, so the call sites
    were confirmed by reading source instead: `refuse_setup`,
    `refuse_answered_flow`, `reset_tcp` and `reset_tcp_inner` all take
    `Option<&'static str>`, the only `Some` site is the `tcp_blocked` verdict
    at `engine.rs:2732`, and every other site is a transport failure.
  - Suites: `cargo test --lib` 776 passed / 0 failed / 2 ignored, and
    `:app:testDebugUnitTest` 105 passed / 0 failed.
  - Observed, not fixed: `Xuất hoạt động` writes `_logs.value` — the window
    already loaded — rather than a fresh query (`AdGuardRepository.kt:1581`),
    so an export taken without scrolling the log list off the top and back
    exports a stale snapshot. The blocked and saved-data counters are
    runtime-only and restart near zero with the process. And the screenshot
    space is not the dump space: `screencap` returns 800×1340 here while
    uiautomator bounds stop at 1316 (the bottom gesture area), and any crop
    that was resized for reading multiplies the error again — taps must use the
    dump coordinates.
  - English locale, the last open item of the group-2 set, done through the
    app's own `Ngôn ngữ ứng dụng` → English switch, so no system locale change
    and no reboot. The status notification reposted in English and was read
    from the shade: `Blocking ads and trackers` / `Blocked: 190 Data saved:
    5 MB`, with `Disable` and `Assistant` as its two actions, and its channel
    renamed to `AdFree protection status`. The firewall notification needed a
    re-trigger: the dedupe window is one notice per app per hour
    (`FIREWALL_NOTICE_WINDOW_MS`, `AdGuardRepository.kt:97`), so blocking
    Chrome again produced the `ERR_NAME_NOT_RESOLVED` page but no new record
    until AdFree was force-stopped and the in-memory `firewallNoticeAt` map
    cleared. It then posted `Chrome blocked` / `The firewall stopped this app
    from using the Internet` with the channel renamed to `Firewall blocks`.
  - Two consequences of that, both accepted rather than fixed. A notification
    keeps the language it was posted in: after the app went back to Vietnamese
    the English firewall row stayed in the shade, because only a new post
    re-renders it. And a channel name only refreshes when that channel next
    posts, so `adfree_firewall` still read `Firewall blocks` in the system
    settings until the notifier ran again — the status channel had already
    reverted to `Trạng thái bảo vệ AdFree`.
  - Capture note for the status row: pulled down over another app, the
    foreground-service row is not in the list at all (the silent section
    showed only the firewall row); opened from the home screen it is the first
    row. Also, the device does re-lock to the PIN keyguard after its timeout
    and `wm dismiss-keyguard` does not clear it — the PIN the user supplied is
    what unlocked it this pass.
  - Device left restored: Chrome's `Sử dụng Wi-Fi` back to `Kế thừa` (page
    verified loading again), app language back to `Tiếng Việt`, status
    notification reposting with `Vô hiệu` / `Trợ lý`.

- Device verification record (2026-11-03, Sony 802SO / Android 10, debug build
  versionName 1.1.1 at `e7430ef`, reinstalled once more after the action-namespace
  rename). Debug rather than release on purpose: the `files/capture-shell` marker
  that routes the shell's probes through the tunnel is only writable through
  `run-as`, and this pass is a measurement pass. Captures live under `/tmp` and
  are not committed.
  - Smart filtering default, the claim the 2026-10-29 and 2026-11-02 benchmark
    notes could not make: **48/48 blocked probes returned NXDOMAIN, 0 connected,
    60/60 allowed probes OK** — see `Re-run — smart filtering off by default` in
    BENCHMARK.md. The same harness that leaked four `zq8f8.adnxs.com` connects
    now leaks none.
  - Upgrade caveat found while setting that up: this install had
    `smartFiltering: true` persisted from before the default changed, and the
    stored value wins over the new default — which is correct behaviour for a
    user's choice, but it means the leak does not disappear by itself on an
    updated device. The switch was turned off here by hand before the pass, and
    the row's subtitle now states the window's consequence in both locales.
  - One-tap activation (Phase 5 gate pinning): the Home button takes the tunnel
    down (`tun0` gone) and up again (`tun0` = `10.111.42.1`) with no dialog,
    because consent was already granted; the QS tile and the notification action
    were left as verified on 2026-11-02.
  - The automation gate, end to end through `am broadcast` against
    `.automation.AutomationReceiver` with `tun0` as the observable, every case in
    its own `logcat -c` window. On the renamed actions: gate off + correct token
    → `ignored git.shin.adfree.automation.DISABLE_PROTECTION from an unauthorised
    broadcast`, tunnel untouched; gate on + wrong token → the same refusal; gate
    on + correct token → `automation: disabling protection` and `tun0` gone, then
    `automation: enabling protection` and it back; force-stop + correct token → a
    fresh process (pid 6011) answered the broadcast and raised `tun0` without a
    "tap to open", because Android 10 does not restrict this background start;
    after `Đổi mã khác` the retired token was refused, the switch had returned to
    off by itself, and neither the retired nor the live value appeared anywhere
    in `logcat -d`. The same matrix had been run earlier the same day against
    the pre-rename strings and every result carried over; the rename added the one
    case the collision left ambiguous — `git.shin.adfree.action.DISABLE_PROTECTION`
    with the gate on and a valid token now produces no log line and no state
    change, because that action no longer addresses this receiver.
    The Settings row was checked visually in Vietnamese: switch, hint naming both
    actions, warning line, the 32-hex token, copy and rotate buttons; `aapt2 dump
    strings` on the installed APK shows the `automation.*` names in the resources
    and no `git.shin.adfree.action.ENABLE_PROTECTION` resource string at all.
  - Device left as found: `files/capture-shell` absent, the tunnel up (last
    authorised ENABLE, the retired token then refused), the app sent to the
    home screen, automation switch off with a rotated token that was never
    transmitted, and the on-device `protection` record read back through `run-as`
    at the shipped defaults — `is_smart_filtering_enabled: false`,
    `show_services_breakdown: false`, `log_level: "warn"`. App language
    `Tiếng Việt`. The two DB copies pulled for that read were deleted after it.
  - Still owed on this device, none of it claimed above: the assistant panel
    scroll re-check (`b0101c8`), a full-store log export line count vs the store
    (`023b835`), add/remove on the allowlist screen (`1b34e10`), a real
    malicious-list hit posting the notice (`974cfed`, whose one-per-hour dedupe
    needs a force-stop to re-arm), the stealth switches and privacy-level radio
    taking effect on live requests (`91dc2dd`, `5858a75`), the services breakdown
    switch showing no `GROUP BY` and no RSS growth while off (`f153ee0`), the
    log-level rows actually changing what reaches logcat (`61dcccd`), and a
    system-initiated revoke posting the dropped-protection alert (`fa79e84`).
    The two Redmi-only items (positive roaming enforcement, the per-flow memory
    probe) stay blocked until that device is back.

### Risks

- The log table grows wider on disk; the retention window (200k rows / 7
  days) may need to shrink or the URL column to stay empty outside MITM.
- A write per closed relay doubles SQLite traffic if not batched. It is
  batched: `flow_traffic` rows ride the log writer's channel and commit in the
  same transaction as the decision rows, and a relay that moved zero bytes
  writes nothing. Datagram mappings retire on a 60 s idle clock and QUIC flows
  on their own, so a chatty app adds roughly one row per live mapping, capped by
  `UDP_MAX_FLOWS` (512) and `bridge::MAX_FLOWS`.
- Per-app proxy lookup adds a map probe on the dial path; reuse the firewall
  map and measure before shipping.
- Splitting DNS lists can change existing block counts; run the full filter
  suite and compare against a real page set, like the Phase 2 risk note.

## Out of scope

- AdGuard VPN and private browser (separate products), the high-contrast theme,
  and the `Cách chặn quảng cáo trên YouTube` how-to row.
- Tracker Radar / Ghostery as the company database: both are CC BY-NC-SA 4.0,
  so NonCommercial plus ShareAlike cannot be carried by an app we distribute.
  `rust/assets/services.tsv` is authored for this project instead; the scale-up
  its header names is a build-time Wikidata P856 (official website) query, CC0,
  merged into the same file.
- Mask-IP and any DPI-resistant transport: both are network-egress features, and
  this app's rule is no telemetry and no new outbound service.
- Silent VPN restart. Android 10+ requires the user's `prepareVpn` confirmation,
  so a dropped tunnel is reported (`fa79e84`), never re-established behind the
  user's back.
- Per-rule enable/disable on the allowlist screen: `!`-prefixed lines are
  stripped before rules reach the core, so a "disabled" exception would be
  deleted rather than parked.
- Switching AdFree to a DEFAULT-importance channel.
- Any network/telemetry feature. The automation receiver (`e7430ef`) is the only
  externally reachable surface added, and it is default-off, token-gated, and
  excluded from OS backup along with its token.

## Testing checklist

- Rust: `cargo test` for engine/firewall/new gates; persistence migration.
- Kotlin: unit tests for stats formatting, relative-time text, module gates, and
  `AutomationGateTest` for the gate itself — off by default, one token minted and
  kept stable, only the exact token authorised, off stops everything, rotation
  invalidates the old value and closes the switch.
- Exported surface: `aapt2 dump xmltree --file AndroidManifest.xml <apk>` must
  keep exactly four of our own exported components — the launcher activity,
  `BootReceiver`, `.automation.AutomationReceiver`, the QS tile — beside the
  androidx WorkManager/Room/profileinstaller ones those libraries bring (the
  exported androidx ones are guarded by `BIND_JOB_SERVICE` or `DUMP`). Nothing
  new may join the first list. The receiver's two actions must also stay in the
  `git.shin.adfree.automation.*` namespace:
  `git.shin.adfree.action.ENABLE_PROTECTION` is the *activity* action the
  notification and tile use, and the two must not be merged. Checked on the
  2026-11-03 debug and release APKs — the packaged resource strings name only
  `git.shin.adfree.automation.*`, and no `git.shin.adfree.action.ENABLE_PROTECTION`
  resource string exists at all.
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
