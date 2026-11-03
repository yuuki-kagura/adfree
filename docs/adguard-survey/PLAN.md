# Follow-up plan — notification actions and Protection parity

Companion to `SURVEY.md`. Phases 0–6 are all shipped: what is written below in
the imperative is the design each stage settled on, now marked with the commit
that landed it. What is left is verification — the dated device records, the
AdFree-side captures still owed and the Redmi-only checks are all listed in
§6.5, and the benchmark notes live in `BENCHMARK.md`. Each step still starts
with the GitNexus impact check required by `AGENTS.md`.

## Phase 0 — baseline

Standing rule for every phase below, not a one-off task:

1. Re-run `node .gitnexus/run.cjs analyze --index-only --repo .` if the graph
   is stale, then `impact` on every symbol before editing it.
2. Build and install the current HEAD on the test device so the notification
   and module changes are compared against a known baseline.

## Phase 1 — notification parity (highest value, lowest risk)

Goal: title + live stats + two actions, and a disabled state that keeps a
tap-to-enable reminder, matching AdGuard 4.14. **Shipped** in `80f1f61`.

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
`b0101c8`; the panel is now a scrolling column, and the on-device re-check ran on
2026-11-03 — see that pass in §6.5.

## Phase 2 — Protection rows: annoyances and browsing security

Goal: two new rows on the landing, backed by real gates rather than reusing
the ad-blocking flag. **Shipped**: the gates and rows in `06cf503`, the
malicious-block notice in `974cfed`, the gate-to-toggle assertion in `162f6d9`.

1. Annoyances module (`06cf503`):
   - Rust: the engine carries five module bits — `MODULE_ADS`,
     `MODULE_TRACKING`, `MODULE_DNS`, `MODULE_ANNOYANCES`, `MODULE_SECURITY`
     (`rust/src/filter.rs` ~712–723). `category_enabled_by` (~728) decides
     `CAT_ANNOYANCE` against the annoyances bit instead of the ad one,
     `set_module_flags` (~1388) writes all five from the config, and four of
     them — everything except DNS, which is a runtime gate over the same engine
     and must not throw a 35 MB cache away — are folded into the build cache key
     (~1031), so a switched-off module's lists leave the engine rather than keep
     matching from the cache.
   - Kotlin: `isAnnoyancesEnabled` on `ProtectionSettings` (~582), the
     repository toggle, the MVI intent, the landing row and its detail screen
     in `ProtectionScreen.kt` reusing the switch list from
     `15-annoyances.png`.
   - uniffi: regenerated bindings via `./gradlew :app:verifyBindings` with
     `ADFREE_RUST_TARGET_DIR` and `ANDROID_NDK_HOME` as before.
2. Browsing security module (`06cf503`, `974cfed`):
   - The security lists already existed in `FilterCatalog` (URLhaus, Phishing
     URL Blocklist, Dandelion anti-malware); `FilterGroup.SECURITY ->
     ModuleGate.BROWSING_SECURITY` now has a real `MODULE_SECURITY` bit behind
     it, so `CAT_MALWARE` is excluded at build time and gated at request time
     like every other module.
   - Detail screen mirrors `10-browsing-security.png`: master switch plus the
     privacy note (`protection_browsing_security_body`) — every page domain is
     checked against the lists on this device, and which sites you visit never
     leaves the phone.
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
     the tracking switch. Covered by the group layout rather than a new
     subgroup flag: `Bộ lọc bảo mật`'s tracking lists are
     `FilterGroup.PRIVACY`/`SOCIAL` → `ModuleGate.TRACKING`, and `Bộ lọc bảo vệ`'s
     malware lists are `FilterGroup.SECURITY` → `ModuleGate.BROWSING_SECURITY`
     alone, so neither switch can silence the other's lists. The
     inactive-group card (`FiltersScreen.kt` ~744–815, from `6174356`) names the
     owning module and offers its one-tap enable; `162f6d9` pins each card's
     button to the toggle that gate actually reads, next to the group-to-gate
     mapping it comes from.

## Phase 3 — Firewall parity

Goal: global five-rule grid, per-app overrides, quick actions, notifications.
**Shipped** in `22b64fa` (`FirewallScreens.kt`, `FirewallCommon.kt`,
`FirewallNotifier.kt`, the five `firewall_allow_*` dimensions in
`rust/src/state/config.rs` ~344–351 and the `NetworkRules` decision path in
`rust/src/engine.rs` ~409–528); the two defects the device pass found —
transport failures counted as blocks, and the blocked-app notification that
could never fire — were fixed in `5a1c9d9`.

1. Model and core — `22b64fa`:
   - `AppFirewallRule` carries one `FirewallAccess` per dimension, so
     screen-off and roaming are per-app answers alongside Wi-Fi and cellular
     rather than new fields bolted on; `ProtectionSettings` carries the five
     global defaults (`firewallAllowWifi`, `firewallAllowWifiScreenOff`,
     `firewallAllowCellular`, `firewallAllowCellularScreenOff`,
     `firewallAllowRoaming`) behind two master gates
     (`firewallGlobalRules`, `firewallCustomRules`).
   - Roaming is a Kotlin flag, not core plumbing: `AdGuardVpnService.kt`
     ~143–147 reads `NET_CAPABILITY_NOT_ROAMING` from the active cellular
     network and calls `CoreEngine.setRoaming` → `coreSetRoaming`, and the
     engine snapshots network type, screen state and roaming into one
     `NetworkRules` value rebuilt when any of them changes, so the hot path is
     still a single map lookup per flow. Screen-off policy is per transport
     (`allow_wifi_screen_off` / `allow_cellular_screen_off`), and an
     app barred from roaming stays offline on a visited network.
   - Persistence: the rules ride `ProtectionState` JSON, so no SQL migration
     was needed; `rust/src/state/legacy.rs` keeps the old blob byte-compatible
     (`app_firewall`, `is_firewall_enabled` read at ~192 and ~250) and the
     engine tests pin the decisions — `a_roaming_rule_only_applies_while_roaming`
     and `screen_off_cuts_open_flows_of_restricted_apps`.
2. UI — `22b64fa`:
   - Firewall detail (`ProtectionScreen.kt`) carries the `Quy tắc tường lửa
     toàn cầu`, `Quy tắc tường lửa tùy chỉnh`, `Hành động nhanh` and `Thông báo`
     rows like `04-firewall.png`, opening `FirewallGlobalDetail`,
     `FirewallCustomDetail`, `FirewallAppRuleDetail`,
     `FirewallQuickActionsDetail` and `FirewallNotificationsDetail`.
   - Global rules: master + five switches (`05`).
   - Custom rules: app list with overrides (`06`), app picker sheet with search
     and grouped system apps (`07`), per-app override screen (`08`) over the
     shared `FirewallNetworkStrip`.
   - Quick actions (`09`, `62`): recent log entries grouped by app, `Chặn truy
     cập` mapping to the same per-app rule update, reusing the infinite-log data
     already loaded by the repository. Per-card overflow offers recent app
     activity, app firewall rule, app management and a one-tap `Tắt tiếng thông
     báo`; the first three are navigation shortcuts, the last flips the per-app
     notification toggle.
   - Firewall overflow (`60`, `61`): a single `Đặt lại mặc định` action with a
     confirmation sheet, resetting only the firewall section (global defaults,
     per-app overrides, quick-action mutes) through
     `AdGuardRepository.resetFirewall`.
   - Notifications toggle: `firewallNotifications` plus the per-app
     `notifyBlocked`; the repository poller (`AdGuardRepository.kt` ~411–428)
     reads new `"App firewall"` rows and raises `FirewallNotifier` at most once
     per app per hour (`FIREWALL_NOTICE_WINDOW_MS`), on the `adfree_firewall`
     channel, and `5a1c9d9` made the TCP half of the firewall file its rows
     under `"App firewall"` so the notifier can actually see them.
3. The Apps-tab sheet calls `updateAppFirewall`, the same entry point the new
   screens use; no second copy of the state exists.

## Phase 4 — assistant depth and leftovers

**Shipped.** `AssistantActivity` carries both tabs over the existing log
filters — `Ứng dụng` and `Trang web` (`assistant_tab_apps`/`assistant_tab_websites`,
~290/~298) — and the per-app panel shows requests, blocked and saved bytes with
`Hoạt động gần đây`, app management and a back row (~471–508). The panel not
scrolling was a defect on that viewport, not a missing feature: `b0101c8` made
it scroll, re-checked on the device 2026-11-03 (§6.5). The
`Cách chặn quảng cáo trên YouTube` row and the private-browser link are decided
against — see §6.5.

## Phase 5 — app management, settings and remaining screens

**Shipped** across `22b64fa` (firewall, assistant, logging), `86c4098`
(Statistics tab), `c988623` (per-app proxy, DNS filters, log fields),
`1b34e10` (website allowlist) and `f153ee0` (company breakdown). The bullets
below stay as the record of what each screen had to cover; the wording that
changed since they were written is marked.

### Filter catalog parity (`43`–`51`)

AdFree already has `FiltersScreen`/`FiltersExtensions` and
`FilterCatalog` groups. Bring the UI to parity:

- Category landing: show `Đã bật: X trên Y` per group. Done — `FilterGroupCard`
  puts the sentence under the group name (`filters_group_enabled`) instead of
  the bare `2/3` ratio it used to show on the right of the row.
- Inactive warning: when the gate module is off, grey the affected category
  and offer `Kích hoạt`. Done in `6174356`, with a real gate behind it since
  `06cf503` — see Phase 2.
- Filter detail: description, last update, rule count, homepage, source URL
  and feature bullets. Done — `FiltersScreen.kt` ~883/~1747 render the last
  update (`filter_not_updated` when the metadata has none), the version row
  only once the list's own metadata provides one, and the homepage button
  (~1833).
- Custom filters: `Thêm bộ lọc tuỳ chỉnh` plus the empty state; the add sheet
  takes a URL/local path with `Tiếp theo` and a file `Duyệt` picker (`66`).
  Done.
- Language filters: the existing language group already matches AdGuard's
  list (ABPVN for Vietnamese); the version/update rows are the same
  metadata-driven rows as the filter detail above.
- Allowlist add sheet (`67`): single `Địa chỉ trang web` field and `Thêm`.
  Done in `1b34e10`.
- DNS add sheet (`69`) mirrors the custom-filter sheet with DNS-specific hint
  text; the user-rule flow (`68`) went further than the capture —
  `CustomRulesEditor.kt` offers a visual card manager (search, badges, delete)
  and a raw multi-line editor with syntax chips, both saving the whole list
  because the core recompiles from the complete set.

### Per-app screen (`25-app-detail.png`)

Done. The Apps-tab sheet (`AppsManagementScreen.kt` ~1003–1100) carries the
filtering/HTTPS switches, the SOCKS5 routing section (`btn_apply_app_routing`,
~914), the per-app firewall dimensions — Wi-Fi, Wi-Fi screen-off, cellular,
cellular screen-off, roaming — and the stats row, and the firewall shortcut
opens the Phase 3 `FirewallAppRuleDetail` rather than a second sheet.

### Settings (`34`–`40`)

- `Mạng`: done — `settings_routing_mode_title` (`Chế độ định tuyến`) names the
  active mode, `VPN cục bộ` or `SOCKS5 thượng nguồn`
  (`settings_routing_local_vpn`/`settings_routing_socks5`).
- General: verified against `35` — `settings_autostart_title` (~195), theme
  chips (~410), language chips (~368), the app-notification deep link and the
  periodic filter refresh (`work/FilterUpdateScheduler.kt`, driven by the
  user's chosen interval) are all present, so no row had to be added.
- `Thông báo ứng dụng`: done as the deep link
  (`AndroidSettings.ACTION_APP_NOTIFICATION_SETTINGS` in `SettingsScreen.kt`
  ~229 and `HomeScreen.kt` ~376), and the notifier objects register their own
  channels per feature rather than one shared channel: `adfree_status`,
  `adfree_firewall` (the block alert the firewall and the security notice both
  raise), `adfree_updates` (filter lists), `adfree_https_reminder` and
  `adfree_conflicts` — five against AdGuard's six (`SURVEY.md` ~310), because
  AdFree has nothing to put in a per-app-store or media-license channel.

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
  `rust/assets/services.tsv`, regenerated from the tracker datasets the survey
  covered: AdGuard's own `assets/preset/trackers.json` (the shape its APK ships,
  4552 domains) merged over Ghostery TrackerDB, plus the rows this project
  authored first. 5,409 rows, every one with a company. DuckDuckGo Tracker Radar
  is a supported import shape too, but it is published as a directory of
  per-region JSON files, so it arrives through the file picker rather than a
  URL. A row is tab-separated in AdGuard's own order — domain, company, service,
  category — and the last two fields are optional, so the two-column rows this
  project wrote before the datasets arrived still load. The table is compiled in
  with `include_str!`, looked up by suffix walk plus binary search over
  byte-sorted line offsets, and a downloaded override in `filters_dir` wins.
  `core_services_fetch` and `core_services_save` convert any of those shapes to
  the canonical table before they keep it, so subscribing to a raw
  `trackers.json` URL works, and the shipped table and an imported file go
  through the same Rust code (`cargo run --example services_dataset`).
  Licensing is the maintainer's call — the app is open source and the dataset
  terms are theirs to settle, so CC BY-NC-SA is no longer a reason to reject a
  source.
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

**Shipped** — 6.1 in `c988623`/`01ec9e5`/`a36dd7f`/`868c5fd`/`f153ee0`, 6.2 in
`c988623`/`86c4098`/`f153ee0`, 6.3 and 6.4 in `c988623`. What is left of this
phase is verification, not code: §6.5 keeps the dated device records and the
checks still owed.

### 6.1 Log storage: transport, flow id, URL, DNS answer, sizes

Screens `52`–`59` and `73`–`79` need fields the log does not store today.
**Shipped**: the v6 columns and event enrichment in `c988623`, the v7
per-connection traffic table in `01ec9e5`, the datagram half of it in
`a36dd7f`, the read-back on device in `868c5fd`, and the v8 `(ts_ms, domain)`
index that feeds the company breakdown in `f153ee0`.

- Schema v6 (`rust/src/store/mod.rs`, `migrate()` after the v5 index):
  `transport INTEGER NOT NULL DEFAULT 0`, `flow_id INTEGER NOT
  NULL DEFAULT 0`, `url TEXT NOT NULL DEFAULT ''`, `dns_answer TEXT NOT NULL
  DEFAULT ''`, `bytes_sent INTEGER NOT NULL DEFAULT 0`, `bytes_recv INTEGER
  NOT NULL DEFAULT 0`; index `log_events_transport_action ON
  log_events(transport, action)` for the statistics tabs. The
  `INSERT INTO log_events` column list and every test fixture are in sync.
- `rust/src/events.rs` `Event`: transport (unknown/wifi/cellular) and
  roaming ride in spare `flags` bits next to `ipv6`, and the record carries a
  `flow_id`. `MAX_URL` is capped at 128 B and only the path is stored when
  MITM knows it: 256 B × 10k ring events would have been ~2.5 MB on top of the
  current ring. The builders (`with_app`, `allow_event`, `block_event`,
  `with_url`) and the ring/persist path take the new fields.
- Fill transport from the existing `Core.network_type` / `roaming` atomics at
  event construction; the packet loop already reads these for firewall
  decisions, so this is a snapshot, not new connectivity plumbing.
- URL: `mitm::proxy::MitmBlock` carries `url: Option<&str>` (`rust/src/mitm/proxy.rs`
  ~145) filled by the decryptor, and `log_mitm_block` writes it through
  `events::with_url` (`rust/src/engine.rs` ~883). Non-MITM events keep `url`
  empty.
- DNS answer: when the packet path answers a query from upstream, the first
  A/AAAA answers ride on the event; otherwise the column stays empty.
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
- uniffi: `LogEvent` (`rust/src/api.rs`) and both `From` impls carry the new
  fields, and the bindings (`app/src/main/kotlin/git/shin/adfree/core/adfree.kt`,
  `CoreEngine.kt`) were regenerated with `./gradlew :app:verifyBindings`.
- Kotlin: `NetworkRequestLog` (`model/Models.kt` ~74) carries transport,
  flowId, url, dnsAnswer, bytesSent, bytesRecv; `from(event)` maps them; the
  log detail rows in `FilteringLogScreen.kt` render URL (`~886`), DNS answer
  (`~889`), connection id and sizes; `writeLogCsv` (`data/LogExport.kt` ~13)
  ends its header with `transport,roaming,flow_id,url,dns_answer,bytes_sent,bytes_recv`.

### 6.2 Statistics parity (`52`–`59`)

**Shipped**: the `transport` column and its filter in `c988623`, the Statistics
tab, the per-app ads/trackers/requests aggregate and the sort keys in
`86c4098`, the company breakdown in `f153ee0`.

- Data-type filter (all / mobile / Wi-Fi) chips on the statistics header,
  backed by `transport`: `AppUsageTransport` in the repository selects the
  transport code passed to `engine.appUsageSince` and `logWindowTotalsSince`
  (`AdGuardRepository.kt` ~1897), and the header renders the three
  `stats_transport_*` labels.
- Ads vs trackers: the aggregate was widened rather than a field invented —
  `AppUsage` (`rust/src/api.rs` ~719) carries `ads`, `trackers` and `requests`
  beside `blocked`, from `GROUP BY app, category`, the app cards in
  `AppsManagementScreen.kt` show the three numbers, and `AppSort` gained the
  matching keys (`86c4098`, headers tidied in `cf6461a`).
- The existing time ranges, search and sort cover `53` and `57`; they were kept.
- Company breakdown (`59`): no longer out of scope — see the `Các dịch vụ`
  entry under the statistics section, closed by `f153ee0`. Its project-owned
  `services.tsv` has since been regenerated from AdGuard's own `trackers.json`
  and Ghostery TrackerDB, so the breakdown now names the company, the service
  and its category. The "top domains contacted" fallback this line proposed is
  what the screen shows when the table has no row for a domain.

### 6.3 Per-app proxy routing

Phase 5 shipped the per-app screen without this row because the flag does not
exist; `isFilterRouted` only controls VPN inclusion. **Shipped** in `c988623`,
verified on the Sony with a SOCKS5 witness (`§6.5`, 2026-11-01 record).

- Model: `AppFirewallRule.proxyAccess` (INHERIT / THROUGH / DIRECT, `Models.kt`
  ~413, reusing the tri-state pattern from `FirewallAccess`), mirrored by
  `AppFirewallRule.proxy: ProxyAccess` (`rust/src/state/model.rs` ~437) with a
  serde default so an old profile loads as INHERIT — the state is JSON, so no
  SQL migration was needed.
- Core: the per-app answers live in `NetworkRules.proxy_rules` beside the
  firewall rules (`rust/src/engine.rs` ~436) and `proxy_through(packages,
  global)` (~473) decides each new TCP and UDP flow: THROUGH takes the SOCKS5
  endpoint even when the global proxy is off, DIRECT never does, and the
  strictest answer among a flow's packages wins. Routing is deliberately a
  proxy feature, not a firewall dimension, so it keeps applying when the
  firewall switch is off (`rust/src/state/config.rs` ~353).
- Kotlin: repository `updateAppFirewall(proxyAccess = …)`, the MVI intent
  field, the `StateMapping` round-trip, and the `Định tuyến proxy` row in the
  per-app sheet (`AppsManagementScreen.kt`) disabled while no usable global
  proxy is configured, in both locales.
- Tests: `proxy_routing_prefers_the_strictest_per_app_answer` and
  `proxy_rules_keep_the_policy_live_without_a_firewall` (engine.rs ~5661/~5691),
  `proxy_routing_survives_the_firewall_switch` (config.rs ~595).

### 6.4 DNS filters (`69`)

AdGuard keeps DNS-only lists apart from the website lists; AdFree applied
every catalog list to DNS and had no separate store, which is why the add
sheet was skipped. **Shipped** in `c988623` as the separate collection this
section recommended.

- Core: `FilterState.dns_filters` (`rust/src/state/model.rs` ~736) is a second
  list store consulted only on the hostname path, so the website lists keep
  answering HTTP rules and the DNS-only lists never enter them —
  `dns_filters_decide_lookups_only` (`rust/src/filter.rs` ~7133) pins that, and
  `dns_filters_persist_apart_from_the_custom_lists` (`rust/src/state/mod.rs`
  ~550) pins the store side, including that a blank id never persists.
- UI: a `Bộ lọc DNS` section in `FiltersScreen` (`~478`) with the
  `Thêm bộ lọc DNS` sheet from `69` (`AddDnsFilterDialog`, `~533`): URL or local
  file, reusing the custom filter flow and error copy.
- The alternative (document that regular lists already filter DNS and drop the
  screenshot's flow) was not taken; the separate store shipped instead.

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
- The four rows this file parked as out of scope are shipped, and the fifth is
  scoped instead of dropped:
  - `Bảo vệ chống lại DPI` splits the first ClientHello flight into two writes on
    the relay's origin-bound path (`Relay::anti_dpi_head`, 24 bytes then the
    rest), behind the stealth master switch. One extra `send()` per new
    connection; nothing is hidden from the site, only from whatever reads the
    wire. The opening is counted from the bytes the origin was asked for, not
    from every write on the peer socket: a proxied flow greets SOCKS5 first, and
    `engine::tests::the_socks5_greeting_leaves_the_anti_dpi_opening_for_the_hello`
    fails if that greeting is allowed to spend it. Peer sockets carry
    `TCP_NODELAY` from dial time — `open_peer_socket` sets it, and
    `engine::tests::a_peer_socket_is_not_nagle_delayed` reads it back — because
    the 24-byte opening otherwise leaves the rest of the hello to Nagle, which
    costs a round trip on every new connection and would make the switch a
    latency regression rather than a privacy one.
  - `Địa chỉ IP mặt nạ` sets `X-Forwarded-For` to the address the user typed on
    every filtered request, and its subtitle says what AdGuard's own knowledge
    base says: the address a page is shown is not the address the traffic
    leaves from. A real mask needs an exit through somebody else's machine,
    which stays out of scope.
  - Silent VPN restart: `scheduleTunnelRetry` retries three times on a doubling
    backoff, and only falls back to the alert when Android actually wants
    consent again (`VpnService.prepare` non-null) or the retries run out. The
    service declares `SUPPORTS_ALWAYS_ON`, so on a device told to keep the
    tunnel the platform rebuilds it and AdFree stays quiet rather than
    reporting a loss it did not cause.
  - Per-rule enable on the allowlist screen parks an exception as `!@@…`
    instead of deleting it. The mark survives in the user-rule text and every
    reader already treats a `!` line as inert — the compiled engine, the
    cosmetic and `$` side scanners, and the screen's own list — so a switched-off
    rule costs nothing and comes back with its text intact.
  - The audible alert moved to its own DEFAULT channel (`adfree_protection`).
    The ongoing status notification stays on the LOW channel it has always
    used: it redraws every ten seconds, and a DEFAULT channel would make that
    a sound.
  Owed on device: the services table accepting a tracker dataset over both
  update paths — a `trackers.json` URL and a DuckDuckGo region file through the
  picker — and refusing a body that is neither. The other five were settled by
  the 2026-11-03 passes in §6.5: the consent-lost alert fires and sounds on the
  DEFAULT channel after a system revoke, a witness origin read the mask
  header, a parked `!@@` rule was proven against live traffic and across a
  process death, an armed always-on VPN came back after a reboot with no tap
  and no alert while an unarmed revoke alerted and stayed down, and the
  anti-DPI handshake split measured +1.2 ms against a ~130 ms first byte in
  `BENCHMARK.md`.
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
  Sony instead of the Redmi — see the dated records below. What still needs
  the Redmi: roaming with Wi-Fi off and mobile on (positive enforcement, not
  reachable without root on the Sony), and the per-flow memory probe in
  `BENCHMARK.md`. Screenshots `52`–`58`, `69`, `73`–`79` and `59` are
  captured: `adfree-59-stats-all-companies.png` closed the last gap of the
  stage 5–12 set on 2026-11-03, so every AdGuard frame in that range now has
  our version beside it.
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
    end on this viewport. (Closed by the 2026-11-03 pass below.)
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
  - Native libraries: the pass above ran a build whose `libadfree_core.so` was
    older than its own Kotlin side. `rust/src/mitm/proxy.rs` was last written at
    06:41 and the arm64-v8a library in `jniLibs/` was linked at 06:39, so
    everything packaged after that — including the `-PskipNative` releases —
    carried a core without the last diagnostics edit. `x86_64` and `x86` were
    fine (linked at 06:45/06:47, after every source edit), and smart filtering,
    the company breakdown and the log fields all predate 06:39, so the 48/48
    probe result and the automation matrix stand. `:app:buildRust` relinked
    arm64-v8a (10:43) and armeabi-v7a (10:47) and left the other two at their
    06:45/06:47 timestamps — consistent with those two targets already holding
    the current sources. `:app:verifyBindings` after it changed two doc comments
    in `core/adfree.kt` and nothing else, so the committed bindings had drifted
    from `rust/src/state/model.rs` in prose only.
  - Log levels against live traffic (`61dcccd`), on a build from after that
    relink: the debug APK packaged at 11:31, whose arm64 library is the 10:43
    one and with no `rust/src` file newer than it, installed over the running
    app with the data and the `tun0` that was already up. `Gỡ lỗi` selected,
    then Chrome traffic. Nothing reached logcat while AdFree stayed hidden; the
    lines
    arrived as one batch at 11:38:48 when it came back to the foreground, and
    the batch carried the DEBUG-only `mitm <host>: privacy signals added` and
    `mitm www.wikipedia.org: third-party cookies stripped` next to the warn
    lines. Selecting `Cảnh báo` and reloading took exactly those two away: the
    11:39 window has `mitm www.wikipedia.org: third-party set-cookie dropped`
    (WARN, `rust/src/mitm/proxy.rs:1908`) and the `splicing verbatim` fallbacks
    with zero `privacy signals added`. The request half of that same stealth
    action kept happening while its line was suppressed, so what changed between
    the two windows is the level and not the traffic.
    Two things this settled alongside it. The drain rides the stats poller,
    which parks while the UI is hidden (`AdGuardRepository.kt:350`), so a field
    report only picks core lines up while the app is open, and they arrive
    batched after it returns rather than as they happen. And one stealth row
    was proven on live requests by the same run: `inject_gpc_dnt` was turned on
    for the test, every decrypted request gained `Sec-GPC`/`DNT`, and its
    DEBUG line was what made that visible.
    Left as found after it: stealth master and `inject_gpc_dnt` off, the
    `Tiêu chuẩn` preset radio untouched (its two switches,
    `strip_utm_tracking` and `block_third_party_cookies`, still read true),
    `log_level: "warn"`, `is_smart_filtering_enabled: false`,
    `show_services_breakdown: false` and `allow_external_control: false` read
    back through `run-as`, the tunnel up, the app sent home, and both DB copies
    pulled for that read deleted after it.
  - The seven checks the list above left owed, all run on the same device in one
    pass on 2026-11-03 (16:20–18:10 local), on the debug `1.1.1` installed at
    16:38:03 from HEAD `51b3eb5`.
  - Assistant panel scroll (`b0101c8`): the sheet was opened with
    `run-as git.shin.adfree am start --user 0 -n git.shin.adfree/.AssistantActivity`
    — a plain shell `am start` is still refused for `exported="false"`, and the
    run-as start only lands when the app is already in the foreground
    (`Displayed … +156ms`). The `AccuWeather` row (10 requests, 10 blocked,
    480 KB) showed `Hoạt động gần đây` at `[84,1042][314,1087]` and
    `Quản lý ứng dụng` at `[84,1129][295,1174]` with nothing below them; one
    `input swipe 400 1150 400 800` moved those to `[84,972]` and `[84,1059]` and
    revealed `Quay lại danh sách` at `[84,1146][314,1191]`. The two pinned
    shortcut buttons stay anchored outside the scrolling column, which is the
    layout the fix intends. This closes the `assistant_app_back` dead-end note in
    the 2026-11-02 record.
  - Full-store export (`023b835`): `Xuất hoạt động` wrote
    `/sdcard/Download/adfree-activity (4).csv`, 3,616,843 bytes — 1 header line
    plus 24,899 data lines over the 17 columns. The store copy taken at the same
    moment held 24,905 rows (`MIN(id)=3324`, `MAX(id)=28228`). The newest
    exported line is the `ns-global-dual.rtc.vietteltammi.vn` query carrying
    `flow_id` 1283, whose row is `id=28222`, and
    `COUNT(*) … WHERE id <= 28222` = 24,899: the export is the whole store, row
    for row, and the six rows that arrived while the file was being written are
    the only gap.
  - Allowlist add / park / restore / delete (`1b34e10`): `@@||adb-check.local^`
    added → snackbar `Đã thêm quy tắc @@||adb-check.local^`, header
    `2 domain bỏ qua mọi bộ lọc`; switched off → the `state.filters` row becomes
    `!@@||adb-check.local^`, the screen shows the `Tắt` badge with the parked
    text `!@@||adb-check.local^` under the host, header
    `1 domain bỏ qua mọi bộ lọc · 1 đang tắt`; switched back on → `2 domain bỏ
    qua mọi bộ lọc` with both rows `CHO PHÉP`; deleted → `state.filters` exactly
    the three-rule baseline it started from. Two halves of this row are still
    not proven on the device: the parked rule was never reloaded through the
    engine against live traffic, and it was not carried across an app restart.
    (Both settled by the pass at the end of this record.)
  - Real malicious-list hit posting the notice (`974cfed`): catalog `scamblock`
    downloaded 950 rules into `files/filters/cat_scamblock.txt`, which contains
    `||1stireland.com^`. `ping 1stireland.com` from the shell resolved to
    52.10.27.176, lost both packets and wrote no log row at all — the tunnel
    excludes `com.android.shell` (`AdGuardVpnService.kt:347`), so shell traffic
    never reaches the engine and the hit had to come from a real app. Chrome
    loading `http://1stireland.com/` posted id 66968 on `adfree_firewall`
    (`2000 + (domain.hashCode() and 0xFFFF)`) with
    `1stireland.com là trang độc hại` / `Bị chặn theo danh sách bảo mật Scam
    Blocklist`, and the log carried the blocked rows 28320, 28321–28326,
    28332–28337 and 28342–28347 with `action=1, category=5`, rule
    `1stireland.com^`, list `Scam Blocklist`. The one-hour dedupe did not need a
    force-stop this time: the 16:38 reinstall started a fresh process, so
    `securityNoticeAt` was already empty.
  - Stealth switches and the privacy-level radio on live requests (`91dc2dd`,
    `5858a75`), each against a real request Chrome made through the tunnel:
    `strip_utm_tracking` (query parameters gone on both an `Ultimate` fetch and a
    `High` navigation, intact with the master off), `disguise_user_agent`
    (`Chrome/156` → `Chrome/124` plus `sec-ch-ua` removed, A/B on one host),
    `block_third_party_cookies` (first-party `adfree=…` present, absent on a
    top-level cross-site navigation whose `Sec-Fetch-Site: cross-site` proves the
    direction), `block_all_cookies` (no `Cookie` header at all on a fresh
    connection under `Ultimate`, present under `High`),
    `strip_third_party_authorization` (`Authorization: Bearer …` when off, gone
    when on), `hide_third_party_referer` (referer `https://example.net/` when
    off, absent when on), `hide_search_query` (seven engine lines for the
    rewritten query links), `strip_etag` (engine line only — nothing at app level
    shows it), `inject_gpc_dnt` (`Sec-GPC` is the differentiator, because Chrome
    sends its own `DNT: 1` with that toggle and stealth off),
    `block_push_api` (`PushManager.subscribe` rejects with `NotAllowedError:
    Blocked by AdFree` and `Notification.permission` reads `denied`, against
    native/`default` when off), `block_geolocation_api` (`getCurrentPosition`
    errors `1:User denied Geolocation` and `permissions.query` reports `denied`),
    `mask_ip` (a witness origin echoed `X-Forwarded-For` `203.0.113.77` ahead of
    the real address, and only the real address with the field cleared), the
    master switch, and the `Cao`/`Cực đại` radios, whose writes were read back
    from `state.protection`.
  - Two things that method had to work around, both worth keeping. `StealthConfig`
    is a `Copy` snapshot taken once per TLS connection
    (`rust/src/mitm/proxy.rs:671-672`), and Chrome keeps sockets and pages:
    `example.com` answers with `Cache-Control: max-age=604800`, so a reload after
    a preset change can serve a cached body with the previous guards and look
    like a failure. Every verdict above therefore used a URL never fetched
    before (a unique query on a known-good host), or a `force-stop` of Chrome to
    reset the socket pool. And a guard replaces prototype methods, not the
    constructor, so `RTCPeerConnection.prototype.toString()` still reads
    `[native code]` while it is armed — the probes had to be functional.
  - The WebRTC row has a limitation and a control, both measured. With
    `block_web_rtc_leaks` on, the page's own `icecandidate` handler receives
    `candidates: []`; with it off the same probe on the same host receives
    `candidate:3925871770 1 udp 2113937151 10.111.42.1 36206 typ host` through
    both `onicecandidate` and `addEventListener`, with
    `setLocalDescription` native — so the empty list is AdFree's doing, not
    Chrome's. What the guard does not hide is the stored description: while it is
    armed, `pc.localDescription.sdp` still carries
    `a=candidate:… 10.111.42.1 51626 typ host`, because Chrome patches candidates
    it gathered after `setLocalDescription` into that object. A page that reads
    the local description instead of listening for events still sees the tunnel
    address.
  - `StealthPreset.of()` (`app/src/main/kotlin/git/shin/adfree/model/StealthPreset.kt:83`)
    reads the level from the twelve switches only and ignores
    `isStealthModeEnabled`, so with the master off and `Cực đại`'s twelve flags
    still stored the radio reports `Cực đại` while nothing is applied. Accepted
    for now: the row labels say what the level means, not what is running, and
    the disabled switch list under it is visibly greyed.
  - Services breakdown switch (`f153ee0`): the `GROUP BY domain` really is behind
    the switch — `engine.domainUsageSince` is called only inside
    `if (_settings.value.showServicesBreakdown)` at
    `app/src/main/kotlin/git/shin/adfree/data/AdGuardRepository.kt:1957`, while
    the per-app and window-total calls stay unconditional — and the `Dịch vụ`
    section appears on the Statistics screen only when the switch is on. Cost
    measured by `/proc/<pid>/stat` ticks at 100 Hz over identical 41 s windows of
    tap-driven refreshes on a 25,306-row store: off +1,014 ticks (10.14 s CPU),
    on +1,151 (11.51 s), i.e. roughly 23 ms of CPU per extra refresh. On the
    `Hôm nay` window (3,036 rows, 40 refreshes) the two are indistinguishable
    (+598 off against +596 on), so the price scales with the rows scanned, not
    with the switch. RSS did not grow in either run — total PSS fell in both
    (174.7→167.4 MB off, 171.8→165.9 MB on) — which is what the claim was about.
  - System-initiated revoke posting the dropped alert (`fa79e84`): the tunnel was
    dropped from Settings, and logcat shows
    `11-03 17:34:40.295 D/Vpn: setting state=DISCONNECTED, reason=agentDisconnect`
    → `17:34:40.354 I/AdGuardVpnService(5939): VPN revoked by user/system` →
    `17:34:40.623 D/NotificationService: 0|git.shin.adfree|70000|null|10344:
    granting content://settings/system/notification_sound`. The record is
    `id=70000 channel=adfree_protection importance=3 category=err` with
    `Hệ thống đã dừng bảo vệ` / `Đường hầm VPN đã đóng trong khi AdFree vẫn cần
    chặn quảng cáo. Android cần bạn xác nhận để mở lại - nhấn để bật lại bảo vệ`
    and a `ACTION_ENABLE_PROTECTION` content intent; the ongoing 1001 row was
    taken down by `stopForeground`, `is_protection_active` read false, and no
    retry ran because `VpnService.prepare` still wanted consent (this device has
    no always-on VPN — `settings get secure always_on_vpn_app` is `null`, so the
    silent-restart branch was not in play; the always-on pass at the end of this
    record is what reached it).
    Two properties of the alert this pass exposed. Nothing cancels
    `DROPPED_ALERT_ID` — `AdGuardVpnService.kt:764` is the only reference besides
    the constant — so re-enabling protection leaves the row behind until the user
    swipes it. And the row looked hard to reach: this device has
    rate-limited AdFree's posts (`post_frequency{pkg=git.shin.adfree, …
    muted=3378/3378}`), so the alert appeared to keep only its status-bar icon
    while the older security row joined the shade list. The always-on pass at the
    end of this record corrected that reading: with the same counters still
    reading every post muted, the alert rendered in full in the shade and swiped
    away normally, so `muted` costs the alerting effects, not the row.
  - Device left as found, read back through `run-as` against the copy taken
    before any of this: `filters` byte-identical (catalog
    `ag-base, ag-mobile-ads, ag-tracking, ag-dns, oisd, abpvn` with `scamblock`
    off again, three user rules, no custom or DNS lists), `protection` identical
    except that `anti_dpi` and `mask_ip` are now written as `false` and `""`
    instead of being absent from the JSON — same values, the preset write
    serialised them. Stealth master off with the `Tiêu chuẩn` flags, tracking
    protection on, `log_level: "warn"`, `show_services_breakdown: false`, the
    tunnel back up (`tun0`, 10.111.42.1/32, DNS 94.140.14.14), the screen-density
    override (240) untouched, the malware notice dismissed, the three probe tabs
    closed, `adb forward tcp:9333` removed, and today's 128 `/sdcard/*.xml` dumps
    deleted. The dropped-protection row itself stays posted, for the reason above.
  - The CPU/RAM comparison `BENCHMARK.md` said it did not measure, run on the
    same device 18:31–19:25. AdFree is the release APK built at 18:30 from the
    `ad874fe` code tree, installed over the debug build at 18:31:55 — both
    variants carry the SDK debug key, so `install -r` kept the store, and the
    `filters` row read back byte-identical with the `protection` row
    value-identical. AdGuard is the 4.14.0 release already on the device. Two
    interleaved passes, `tun0` asserted per app (`10.111.42.1` / `172.18.11.218`),
    screen pinned on.
    - Background idle CPU (60 s ×4): AdFree 0.70–1.07 %, median 0.83; AdGuard
      0.63–3.75 %, median 0.74 — parity, AdGuard noisier.
    - Foreground idle CPU (20 s ×4): 5.55–10.55 % median 7.10 against
      22.95–24.25 % median 23.27.
    - RAM: background PSS 85.8–108.6 MB median 94.9 against 254.6–289.2 MB median
      264.9; foreground 101.3–105.1 MB median 101.7 against 278.0–286.2 MB median
      281.2 — **AdFree 64 % lighter in both states**, repeating the 2026-11-02
      68 %/63 % at a dozen stages of features later.
    - Composition at rest (`App Summary`): AdFree Java 7.9 / native 61.2 / System
      3.5 MB against AdGuard Java 68.1 / native 131.3 / System 37.4 MB.
  - The workload had to change. A release AdFree never routes the shell into its
    tunnel (`AdGuardVpnService.kt:344` gates `capture-shell` on
    `BuildConfig.DEBUG`), while AdGuard does — `adb shell ping
    pagead2.googlesyndication.com` answers `unknown host` through AdGuard's
    tunnel — so the old probe would have measured AdGuard's filtering against
    AdFree's idleness. Twelve real pages loaded in Chrome 10 s apart with
    `?adfreebench=<pass>` to defeat the cache replaced it, and AdFree costs
    2.77 s / 2.65 s of CPU where AdGuard costs 12.96 s / 7.70 s for the same
    pages, with Chrome's own tick delta (1096/1062 against 1017/1062) as the
    control that both apps were handed a comparable page set. Both really
    filtered it: AdFree's counters moved 136→199 ads and 257→474 trackers over
    one sweep, AdGuard's card 488→2,363 blocked and 34→141 MB saved over two.
    The helpers are committed as `bench/win.sh` and `bench/sweep.sh`.
  - The device kernel-panicked mid-pass at 18:43:21 (`ro.boot.bootreason =
    kernel_panic,sysrq`, and `persist.sys.boot.reason.history` shows an earlier
    entry at 2026-11-02 11:53:38, so this is the hardware, not the measurement;
    `/sys/fs/pstore` needs root to read). The four windows taken before it were
    thrown away and the pass restarted from the cold boot, so every row above
    shares one device state and each carries its uptime stamp. A second lesson
    went into the harness: a pid held across a VPN handover can be recycled by
    another process and reads as negative CPU, so `win.sh` refuses a window whose
    pid changed.
  - Device left as found: AdGuard toggled off and force-stopped, the debug APK
    reinstalled at 19:23, protection re-enabled from the home power button
    (`tun0` 10.111.42.1/32, no `capture-shell` marker), store re-read through
    `run-as` and identical to the copy taken before the pass,
    `stay_on_while_plugged_in` back to 0, Chrome force-stopped, screen left
    unlocked on the launcher.
  - Still owed on this device: the services table accepting a tracker dataset
    over both update paths — a `trackers.json` URL and a DuckDuckGo region file
    through the picker — and refusing a body that is neither. The parked
    allowlist rule, the always-on restart and the anti-DPI cost are no longer on
    this list; the passes below settled them, the last one as +1.2 ms on the TLS
    handshake against ~130 ms to first byte in `BENCHMARK.md`.
    The two Redmi-only items (positive roaming enforcement, the per-flow memory
    probe) stay blocked until that device is back.
  - The Manual and Visual checklist lines at the end of this file, run on the
    same debug build after the CPU/RAM pass, every capture at 800×1340.
    - Notification in both states and both languages — all four combinations
      are now on disk: `adfree-84-notification-active-vi.png`
      (`Đang chặn quảng cáo và công cụ theo dõi` / `Bị chặn: N`, bigText
      adding `Dữ liệu đã lưu: X MB`, actions `Vô hiệu` and `Trợ lý`),
      `adfree-85-notification-paused-vi.png` (`Đã tạm dừng bảo vệ` /
      `VPN vẫn bật; quảng cáo & tracker chưa bị lọc`, actions `Tiếp tục` and
      `Trợ lý`), `adfree-86-notification-active-en.png` and
      `adfree-92-notification-paused-en.png` (`Protection paused` /
      `The VPN is on; ads and trackers are not filtered`, `Resume` and
      `Assistant`). The paused variant only ever comes from the assistant's
      pause control, so each paused row was made by opening the sheet, tapping
      it, then reading `dumpsys notification --noredact` extras next to the
      screenshot rather than trusting the pixels.
    - Two harness facts that cost time. The status row has no fixed rank: the
      10 s counter re-post moves it down the list, so a shade opened into the
      QS panel shows no AdFree row at all. That also casts doubt on the
      explanation given for the invisible dropped-protection alert earlier in
      this record — `post_frequency{pkg=git.shin.adfree, muted=3914/3914}`
      mutes alerting, not visibility, so that row was probably below the fold
      too rather than suppressed. And the action buttons only exist once the
      `Mở rộng` chevron is tapped; tapping the row body fires `contentIntent`
      and brings MainActivity forward, which is what three of the assistant
      attempts below actually did.
    - Assistant over a third-party app (`adfree-83-assistant-over-app.png`) —
      passes, and the reason it intermittently looks like it does not is now
      pinned. `AssistantActivity` declares no `taskAffinity`
      (`app/src/main/AndroidManifest.xml:43-49`) and the notification's
      PendingIntent carries only `FLAG_ACTIVITY_NEW_TASK`, so while the app's
      own task is alive the new-task match resolves to that task and the sheet
      draws over MainActivity instead of over the foreground app. With the
      task finished — BACK until `mCurrentFocus` is the launcher, process and
      `tun0` unaffected — the same tap opened its own task over Chrome, and
      the sheet's X returned to Chrome. The English paused capture needed
      exactly that detour: three taps surfaced the Settings screen, and only a
      force-stop plus the one-tap re-enable let the sheet float free.
    - Each new toggle survives process death: stealth master, the four `Cao`
      sub-switches, `anti_dpi`, `mask_ip` set to `203.0.113.7` and
      `show_services_breakdown` were written, then `am force-stop` and a
      relaunch (pid 20533 → 8900). All came back as set, the tunnel rebuilt
      itself at 10.111.42.1/32, the Stealth screen and the Statistics
      breakdown re-rendered from the persisted values, and no other key in any
      `state` row moved. Everything was reverted through the UI afterwards.
    - Per-app override beats the global rule, re-run on this build with two
      signals in the same window so the shell's own path could not be mistaken
      for the app's: under the global Wi-Fi block the shell TCP probes failed
      (`rc=-110` at ~2 s, `gai=7` for uncached names) while Chrome showed
      `ERR_NAME_NOT_RESOLVED`; a per-app `wifi: "allow"` for Chrome let Chrome
      render example.com with the shell still failing, and deleting the rule
      blocked Chrome again. `state.firewall` is back to `[]` and
      `state.protection` has zero diffs against the as-found copy.
    - Visual: nine captures join the set — `adfree-59-stats-all-companies.png`
      (the last open stage 5–12 frame), `adfree-87-stealth-presets.png`,
      `adfree-88-stealth-antidpi-maskip.png`,
      `adfree-89-stealth-maskip-editor.png`,
      `adfree-90-filters-services-table.png`,
      `adfree-91-allowlist-parked-rule.png`, and the four notification rows.
    - Device left as found: language back to `Tiếng Việt` through the app's
      own `App language` chips (no system locale change, no reboot),
      protection active and unpaused with `tun0` 10.111.42.1/32, every `state`
      row and `settings` byte-identical to the copy taken before the pass,
      `stay_on_while_plugged_in` 0, the density override untouched, screen sent
      HOME.
    - What this pass did not touch: the four items in the "Still owed" bullet
      above, and roaming, which needs the SIM the Sony does not have.
  - The parked allowlist rule against live traffic and across a process death —
    the two halves `1b34e10` left unproven. `pagead2.googlesyndication.com` was
    picked because the enabled lists already block it and a browser can be
    pointed straight at it, so the verdict is a rendered page rather than a
    counter. Adding `@@||pagead2.googlesyndication.com^` through
    `Ngoại lệ trang web` let Chrome render the favicon at
    `…/favicon.ico?af=allowon`. The row switch then parked it as
    `!@@||pagead2.googlesyndication.com^` — badge `Tắt`, header
    `1 domain bỏ qua mọi bộ lọc · 1 đang tắt` — and the same host on a fresh
    query answered `DNS_PROBE_FINISHED_NXDOMAIN`. `am force-stop` + relaunch
    (pid 26433 → 5085) kept the rule parked, rebuilt `tun0` by itself, and kept
    blocking: 12 more BLOCKED rows inside the window after the restart, which
    is the engine-reload half nothing had yet exercised. Switching the row back
    on rendered the favicon again and logged `action=0` (id 33521) with no
    block, and deleting the rule returned `state.filters` to its exact
    three-rule baseline with the block following it (id 33530).
    - What the rows say about where the exception applies: the engine files
      these as DNS decisions — rule `||pagead2.googlesyndication.com^`, list
      `AdGuard DNS filter`, `category=6`, `app=com.android.chrome` — so the
      `@@` rule has to win at the resolver, and the A/B shows it does in both
      directions.
    - Harness note: the row's switch is the unlabelled clickable View at
      x=620, while the control at x=698 is delete and carries the
      `Xoá ngoại lệ` description. Tapping the row body does nothing, and
      `Ngoại lệ trang web` is reached through Bảo vệ → Chặn quảng cáo, not from
      the module list itself.
    - Device left as found: rule deleted, every `state` row and `settings`
      byte-identical to the copy taken before the pass, Chrome force-stopped,
      tunnel up at 10.111.42.1/32, `stay_on_while_plugged_in` 0, screen on the
      launcher.
  - The always-on restart, run 2026-11-03 (22:05–22:40) — the last of the four
    parked rows, and the one §6.5 had kept open because no earlier lever could
    drop a live tunnel. Five levers were tried, and what they produced is the
    record.
    - Which key arms it. On this Android 10 build the authoritative one is
      `secure/always_on_vpn_app`, written by the per-app page Settings → VPN →
      AdFree → `VPN luôn bật`. `settings put secure always_on_vpn_packages` is
      accepted and ignored: the switch still read `TẮT` while that key named the
      package, and the framework never treated the session as always-on. The
      list row is the readable proof — an armed row says
      `Đã kết nối, Luôn bật đang hoạt động`, an unarmed one only `Đã kết nối`.
    - Armed, rebooted, no tap. With always-on armed and the tunnel up, a reboot
      brought the VPN back by itself: `ActivityManager: Start proc
      4240:git.shin.adfree/u0a344 for service
      {git.shin.adfree/git.shin.adfree.vpn.AdGuardVpnService}` — a service start
      with no activity and no intent from the shell — `tun0` at
      10.111.42.1/32 within the first 6 s poll after `sys.boot_completed=1`, zero
      `tunnel retry` lines, zero `VPN revoked` lines, and the ongoing 1001 on
      `adfree_status` as the only AdFree record in `dumpsys notification`. That
      is the promise `scheduleTunnelRetry`'s early return rests on
      (`AdGuardVpnService.kt:421-424`): the platform is the rebuilder, so a
      second one here really would only race it.
    - Unarmed, revoked, told. Settings → VPN → AdFree → row → `NGẮT KẾT NỐI`
      gives `Vpn: Switched from git.shin.adfree to [Legacy VPN]`, then
      `SettingsProvider: Notifying …/always_on_vpn_app` — the disconnect clears
      the arming as it revokes — and our own `VPN revoked by user/system`. The
      alert fired: active `NotificationRecord … id=70000
      channel=adfree_protection importance=3 category=err`, with
      `NotificationService: granting content://settings/system/notification_sound`
      for it, reading `Hệ thống đã dừng bảo vệ` / `Đường hầm VPN đã đóng trong
      khi AdFree vẫn cần chặn quảng cáo…` (`adfree-93-dropped-alert-vi.png`, a
      shade crop rather than a table frame, because the full shade carries other
      apps' content). `tun0` stayed down through 24 s of polling. Correct on
      both halves: nothing was rebuilding, so the user was told.
    - Un-arming a live session is itself a system revoke. Tapping `VPN luôn bật`
      back to `TẮT` while connected ran `onRevoke` in a living process — the
      closest thing to the guarded combination this device will produce — and
      again the alert fired and `toggleProtection(false)` took the remembered
      switch off. The ordering the branch depends on is visible in that result:
      `isSystemKeepingVpn()` is read after the key is already gone, so it
      answers false and says so out loud.
    - Force-stop while armed does not rebuild. `ActivityManager` logged
      `Scheduling restart of crashed service … in 1000ms` and then
      `Force stopping service ServiceRecord{…}`; `always_on_vpn_app` kept
      `git.shin.adfree`, and neither 60 s of polling nor a Wi-Fi flap brought
      `tun0` back. No alert either — nothing was left running to post one.
      Reopening `MainActivity` restarted the tunnel from the persisted switch,
      which is the recovery path a user actually has. `am kill` is not a lever
      at all: the foreground service is untouched (pid 4240 unchanged over 48 s).
    - So the honest scope of this pass: the exact combination the guard protects
      — a revoke delivered to a live process while the platform still holds
      AdFree as always-on — cannot be produced here, because every lever that
      revokes a live session also clears `always_on_vpn_app` first, and every
      lever that leaves it armed takes the process down with the tunnel, so no
      decision is ever made. What the device did answer is the behaviour the
      branch exists to produce: with a rebuilder the tunnel returns unasked and
      silent, without one the loss is announced and sounded. The guard's own
      true-branch stays covered by the JVM test on
      `shouldReportDroppedProtection(systemKeepsVpn = true)`.
    - Harness notes from the same pass: `cmd notification dismiss_all` does not
      exist on this build (`Unknown command`), so clearing the alert row means
      expanding the shade and swiping it — the row is at y≈355 in a two-row
      list, and after the swipe it survives only under `mArchive` in
      `dumpsys notification`, which is the tell that it is gone rather than
      hidden. `uiautomator dump` refuses to run while the shade is settling
      (`ERROR: could not get idle state`), so a `screencap` is the read for shade
      state.
    - Device left as found: `always_on_vpn`, `always_on_vpn_app` and
      `always_on_vpn_packages` all back to null, both switches on the per-app
      page at `TẮT`, the 70000 alert swiped out of the shade (only 1001 active,
      the alert left in `mArchive`), protection re-enabled from the home switch
      (`Đang lọc`), the whole `state` + `settings` set re-read through `run-as`
      and byte-identical to the copy taken before the pass, tunnel up at
      10.111.42.1/32, Wi-Fi enabled, `stay_on_while_plugged_in` back to 0,
      Chrome untouched, screen on the launcher.
  - The anti-DPI split against a measured first byte, run 2026-11-03
    (22:40–22:52) — the last number this device owed. `BENCHMARK.md` carries the
    table; what belongs here is how it was produced and what the harness could
    not rule out.
    - Getting the request inside the tunnel at all. The VPN builder calls
      `addDisallowedApplication(packageName)` for AdFree itself and, unless the
      debug marker `files/capture-shell` exists, for `com.android.shell` too
      (`AdGuardVpnService.kt:333-348`), so a plain `run-as … curl` was bypassing
      the engine. The marker was written and the tunnel rebuilt; the proof is in
      `dumpsys connectivity` — `Uids: <{0-1999, 2001-10343, 10345-99999}>` with
      shell excluded, `Uids: <{0-10343, 10345-99999}>` with it routed. The
      marker only takes effect on the next tunnel build, so the exclude cannot be
      changed under a live session.
    - What the tunnel then did to the flow. Shell traffic is relayed but not
      decrypted — the log rows for these rounds read `app=com.android.shell` with
      an empty `url` — which is exactly what the measurement needs: TLS ends at
      google.com, so `time_appconnect − time_connect` is the genuine handshake
      the split acts on, not a local re-encryption.
    - A/B/A/B, twelve rounds per block, 0.4 s apart, `generate_204`, every round
      `204`. Stealth master ON in both arms so `anti_dpi` is the only field that
      differs. Handshake came back +1.2 ms and held across both repeats (10.6 /
      10.5 off, 11.6 / 11.7 on); TTFB did not move, because the 7.8 ms pooled
      gap is smaller than the 11.2 ms between the two identical off blocks.
    - The sub-RTT size is not luck: every peer socket sets `TCP_NODELAY`
      (`rust/src/engine.rs:3188-3202`), so the 24-byte head is sent immediately
      rather than waiting on an acknowledgement — without it this measurement
      would have been an RTT, not a millisecond and a half.
    - Harness notes. `/system/bin/curl` is the binary that exists on this build;
      `/usr/bin/curl` is not reachable under `run-as`. `svc wifi disable` does
      not tear down an established `tun0`, so it is not a lever here either. The
      keyguard kept stealing focus mid-pass and silently ate a whole toggle
      cycle (netId stayed 102, so nothing had actually changed), which is why
      `stay_on_while_plugged_in` was set to 7 for the pass and every tap was
      preceded by WAKEUP, `wm dismiss-keyguard`, a re-`am start` and a focus
      read.
    - Device left as found: `capture-shell` removed and the tunnel rebuilt
      without it (netId 104, shell excluded again), stealth master and
      `anti_dpi` back to off with `mask_ip` empty, `stay_on_while_plugged_in`
      back to 0, the whole `state` + `settings` set re-read through `run-as` and
      byte-identical to the copy taken before the pass, screen on the launcher.

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
- Wikidata as a company-name source: the datasets below already name every
  domain, so the build-time P856 (official website) merge this file used to
  propose for scaling `rust/assets/services.tsv` is no longer needed.
- A real IP mask, as opposed to the advertised one. AdGuard's own knowledge base
  says tracking protection cannot hide the address, and its `Địa chỉ IP mặt nạ`
  only writes one into `X-Forwarded-For`, which AdFree now does too (stealth
  section). Hiding the address means the traffic leaves through somebody else's
  machine, and this app makes no outbound connection the user did not ask for.
- Any network/telemetry feature. The automation receiver (`e7430ef`) is the only
  externally reachable surface added, and it is default-off, token-gated, and
  excluded from OS backup along with its token.

## Testing checklist

The first three bullets are run and recorded (suites green, the exported surface
checked on the 2026-11-03 debug and release APKs); the device, manual and visual
lines are the ones §6.5 still lists as owed.

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
  `cargo ndk`, then `./gradlew :app:assembleRelease -PskipNative`. The manual
  `.so` copy the first pass here prescribed is not needed with cargo-ndk 4.1.2:
  it writes a separate file into `jniLibs/` (different inode, identical
  `sha256` to the target-dir library), so nothing has to be de-hardlinked.
  `buildRust` itself is never considered up-to-date, which is what keeps an APK
  from packaging a stale core.
- Device: the services table over both update paths. Point the URL at a raw
  `trackers.json` and at a canonical TSV, and import a DuckDuckGo region file
  through the picker; each must leave `filters/services.tsv` sorted and
  four-column, and the Statistics breakdown must show the company plus the
  category instead of the bare domain. A body that is neither a dataset nor a
  sorted table must be refused with the previous copy intact.
- Manual (run 2026-11-03, see the dated record): notification in both states
  and both languages, assistant over a third-party app, each new toggle
  surviving process death, and the per-app override beating the global rule
  are all done. The only leg left is roaming with Wi-Fi off and mobile on —
  this Sony has no SIM, so it waits for the Redmi. Screen-off per-app
  firewall was already verified on 2026-11-01.
- Visual (done 2026-11-03): every new screen is captured at the same
  800×1340 viewport for the side-by-side table against the AdGuard captures,
  through `adfree-92`.

## Risks

- The disabled-but-running notification changes AdFree's service lifetime;
  verify no battery regression and that `onRevoke` still stops everything.
- Roaming/screen-off rules touch the packet hot path; benchmark with
  `BENCHMARK.md` before shipping.
- Annoyances/security modules change which filter rules are active; run the
  full filter test suite and compare blocked counts on a real page set.
- Only one VPN slot: the test device must stop AdGuard before validating
  AdFree, and vice versa.
