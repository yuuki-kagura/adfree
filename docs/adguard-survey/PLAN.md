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
   - Quick actions (`09`): recent log entries grouped by app, `Chặn truy cập`
     button mapping to the same per-app rule update; reuse the infinite-log
     data already loaded by the repository.
   - Notifications toggle: only notify for apps the user selected; post on
     the first blocked attempt per app/window to avoid spam.
3. Keep the existing Apps-tab sheet working; the new screens should call
   `updateAppFirewall` rather than duplicate state.

## Phase 4 — assistant depth and leftovers

- Assistant app stats/activity tabs wired to the existing log filters.
- Optional: `Cách chặn quảng cáo trên YouTube` help row and private-browser
  link, if the user wants them; both are navigation-only in AdGuard.

## Phase 5 — app management and settings (second-pass additions)

- Per-app parity (`25-app-detail.png`): the current Apps tab sheet has
  filtering/HTTPS/firewall switches. Add routing (`Định tuyến qua AdGuard`),
  proxy routing, per-app firewall shortcut and a stats row. The firewall
  shortcut should open the new per-app rule screen from Phase 3 instead of a
  second sheet.
- Settings → `Mạng` (`39`, `40`): AdFree's HTTPS filter switch already exists
  as a Protection module; expose a `Chế độ định tuyến` row that names the
  active mode (local VPN today, SOCKS5 endpoint when the proxy is configured)
  so the settings map matches AdGuard's vocabulary.
- Settings → General (`35`): verify AdFree already covers auto-start, theme,
  language, update schedule and notification settings; add missing rows only
  where they change engine behavior.
- Allowlist: give the website allowlist a dedicated screen (search + add) or
  document that HTTPS website rules cover it. AdGuard keeps it separate from
  user rules.
- Statistics/log wording: AdGuard advertises "newest 10k requests stored";
  AdFree already shows `log_window_capped` at 10k in RAM, but the SQLite store
  keeps 200k rows for 7 days. Keep the UI honest about the difference.

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
