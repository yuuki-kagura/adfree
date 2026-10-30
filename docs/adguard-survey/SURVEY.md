# AdGuard survey — notification and Protection tab

Captured on 2026-10-30 from the reference client, to guide AdFree parity work.

- Device: Redmi Pad SE 8.7 (`flare`), Android 16, MIUI V816, no root.
- AdGuard nightly `4.14.68` (`com.adguard.android`, launcher `SplashActivity`).
- AdGuard VPN `com.adguard.vpn` also installed; only one VPN slot exists, so
  AdGuard and AdFree cannot protect at the same time.
- Raw notification record: `notification-dump.txt`
  (`adb shell dumpsys notification --noredact`).

## 1. Persistent notification

AdGuard posts one ongoing notification, channel `Protection`
(importance DEFAULT), id 2305, flags
`ONGOING_EVENT | NO_CLEAR | FOREGROUND_SERVICE | SILENT`, timeout 72 h,
`BigTextStyle`, `contentIntent` opens the app.

### While protecting

- Title: `Đang chặn quảng cáo và công cụ theo dõi`
- Text: two lines
  - `Bị chặn: 31`
  - `Dữ liệu đã lưu: 3 MB`
- Two actions, both plain text buttons without icons, left aligned under the
  text:
  - `Vô hiệu` → `startService` (turns protection off)
  - `Trợ lý` → `startActivity` (`AssistantActivity`, modal bottom sheet)
- Collapsed form already shows title plus both stats lines.

### After "Vô hiệu"

The notification becomes a tap-to-enable reminder (no actions):

- Title: `Bảo vệ bị vô hiệu hóa`
- Text: `Quảng cáo và trình theo dõi không bị chặn. Nhấn để bật`
- Tapping the content re-enables protection.

The VPN slot is released when protection is disabled; AdFree was able to
start again immediately afterwards.

### Assistant (Trợ lý)

Bottom sheet opened over whatever app is in front (it appeared over AdFree):

- Title `Trợ lý AdGuard`
- Subtitle `Nhanh chóng thay đổi cài đặt lọc cho ứng dụng hoặc trang web gần đây`
- Tabs `Ứng dụng` / `Trang Web`
- Apps tab: recently used apps, newest first, each with a relative timestamp
  (`Được sử dụng 7 phút trước`).
- Tapping an app opens a second sheet with shortcuts:
  - `Hoạt động gần đây`
  - `Thống kê ứng dụng`
  - `Quản lý ứng dụng`
  - `Cài đặt tường lửa` (per-app firewall rule screen)
  - `Back`
- Web tab: list of recent websites; empty state `Chưa có hoạt động nào`.

Screenshots: `17-notification-shade.png`, `18-notification-expanded.png`,
`19-assistant.png`, `20-assistant-app.png`, `21-assistant-web.png`,
`23-disable-action.png`.

## 2. Protection tab

Landing list (screenshot `03-protection.png`), each row a module switch plus a
detail screen:

1. Chặn quảng cáo và popup
2. Bảo vệ chống theo dõi
3. Chặn làm phiền
4. Bảo vệ hệ thống (DNS-level)
5. Tường lửa
6. Bảo vệ Duyệt web
7. AdGuard VPN (navigation row)
8. Cách chặn quảng cáo trên YouTube (navigation row)
9. Trình duyệt riêng tư (external link)

### Chặn quảng cáo và popup (`11-ad-blocking.png`)

- Master switch
- `Bảo vệ cơ bản` (basic protection)
- `Chặn quảng cáo theo ngôn ngữ cụ thể`
- `Danh sách cho phép của trang web` (shows count, here 0 sites)
- `Bộ lọc của Người dùng` (manual rules plus rules created from recent activity)

### Bảo vệ chống theo dõi (`12`–`14`)

- Master switch
- Privacy levels, radio list:
  - `Tiêu chuẩn` — blocks trackers and analytics systems
  - `High` — strips tracking parameters from URLs, limits third-party cookie
    lifetime (warning about re-login)
  - `Cực` — also limits first-party cookie lifetime, blocks browser APIs
    (worse warning)
  - `Tuỳ chọn` — manual settings
- `General` (fully captured in `27-tracking-general.png`):
  - `Chặn trình theo dõi` — blocks trackers/analytics through the AdGuard
    Tracking Protection filter
  - `Xóa tham số theo dõi khỏi URL` — strips UTM-style parameters using the
    AdGuard URL Tracking filter
  - `Ẩn truy vấn tìm kiếm` — opens search results directly, hiding the query
  - `Yêu cầu các trang web không theo dõi tôi` — sends Global Privacy Control
    and Do Not Track
- `Tuỳ chọn` level (`26-tracking-custom-level.png`) unlocks the manual
  General section; choosing it selected the radio in place.
- `Cách theo dõi`:
  - `Xóa cookie của bên thứ ba` (current lifetime 180 min)
  - `Xóa cookie của bên thứ nhất (không khuyến khích)` (4320 min)
  - `Chặn tiêu đề ETag và If-None-Match`
  - `Chặn tiêu đề ủy quyền của bên thứ ba`
- `API Trình duyệt`: `Chặn WebRTC`, `Chặn API Push của trình duyệt`,
  `Chặn API định vị của trình duyệt`
- `Khác`: `Ẩn người giới thiệu khối bên thứ ba` (Referer default),
  `Ẩn Đại lý người dùng` (user agent default), `Địa chỉ IP mặt nạ`,
  `Xóa tiêu đề về dữ liệu của khách hàng` (on),
  `Bảo vệ chống lại DPI`

### Chặn làm phiền (`15-annoyances.png`)

Master plus: social media buttons, cookie notices, popups, mobile app banners,
widgets, other annoyances (each a switch).

### Bảo vệ hệ thống / DNS (`16-dns-protection.png`)

- Master switch
- `Máy chủ` → DNS server picker (`Hiện tại: DNS tự động`)
- `Các bộ lọc` → DNS filters and user rules at hostname level

### Bảo vệ Duyệt web (`10-browsing-security.png`)

- Master switch only, plus explanation:
  - Checks each visited page against a live-updated malicious/phishing domain
    database; warns on dangerous pages.
  - "The app checks a hash prefix, not the URL, so it does not know which page
    you visit" (privacy note).
- `Tìm hiểu thêm` link.

## 3. Firewall (the deepest difference)

### Firewall screen (`04-firewall.png`)

- Master switch `Tường lửa`
- `Quy tắc tường lửa toàn cầu` — `Tất cả các kết nối được phép`, with five
  network icons (Wi-Fi, Wi-Fi screen-off, mobile, mobile screen-off, roaming)
- `Quy tắc tường lửa tùy chỉnh` — per-app rules that override global rules
- `Hành động nhanh` — quick actions from recent Internet activity
- `Thông báo` — notify when a selected app tries to use the Internet

### Global rules (`05-firewall-global.png`)

Master plus five switches:

1. `Sử dụng Wi-Fi`
2. `Sử dụng Wi-Fi khi tắt màn hình`
3. `Sử dụng dữ liệu di động`
4. `Sử dụng dữ liệu di động khi tắt màn hình`
5. `Sử dụng dữ liệu chuyển vùng`

### Custom rules (`06-firewall-custom.png`, `07`, `08`)

- Master switch
- `Ứng dụng có quy tắc tùy chỉnh` + `Thêm ứng dụng`
- App picker is a bottom sheet with search; system apps are grouped with
  expand arrows; each row opens the per-app rule screen.
- Per-app screen: app icon/name, the same five network icons
  (`Quyền tường lửa cho ứng dụng này dựa trên quy tắc toàn cầu và tùy chỉnh`),
  `Đã áp dụng quy tắc tùy chỉnh`, and `Quy tắc tùy chỉnh có sẵn` with one `+`
  row per network type (adding an override; global rules stay the default).

### Quick actions (`09-firewall-quick-actions.png`, `62`)

- Search field
- Cards per recent app: age (`3 phút trước`), icon/name, network icon with
  `Có quyền truy cập Wi-Fi`, `Được phép bởi quy tắc tường lửa toàn cầu`, and a
  large orange `Chặn truy cập` button; per-card overflow menu.
- Per-card overflow (`62-quick-actions-overflow.png`) is a four-item popup:
  `Hoạt động gần đây của ứng dụng`, `Quy tắc tường lửa ứng dụng`,
  `Quản lý ứng dụng`, `Tắt tiếng thông báo`. Left of the quick actions there is
  a shortcut to the recent activity, the app firewall rule, the app management
  screen, and a one-tap mute for that app's firewall notifications.

### Firewall overflow (`60`, `61`)

The top-right overflow has no dropdown; it adds a single orange toolbar action
`Đặt lại mặc định` (`60-firewall-overflow.png`). Tapping it opens a bottom
sheet (`61-firewall-reset-dialog.png`):

- `Đặt lại về mặc định?`
- `Tất cả các cài đặt trong phần này sẽ được đặt lại về giá trị mặc định của
  chúng`
- `Đặt lại` (orange confirm), dismissed with Back without resetting.

## 3b. Apps, settings, statistics, log

Captured on the second pass, after the module screens above.

### Quản lý ứng dụng (`24-apps-management.png`, `25-app-detail.png`)

- Search plus a list grouped by shared system process (Bluetooth, telephony,
  Google services, Mi Cloud, tethering, ...); each group expands and shows a
  warning `Không được định tuyến qua AdGuard` when it bypasses the VPN.
- Per-app (or per-group) screen:
  - `Định tuyến lưu lượng truy cập qua AdGuard`
  - `Lọc nội dung ứng dụng` (unencrypted traffic)
  - `Lọc lưu lượng HTTPS` (encrypted traffic; warns that apps can misbehave
    without a trusted CA)
  - `Định tuyến ứng dụng thông qua proxy`
  - `Cài đặt tường lửa ứng dụng` — the same five network icons as the firewall
    screens
  - App stats row (`0/0/0`) linking to per-app statistics

### Firewall notifications (`32-firewall-notifications.png`)

Master switch plus per-app notification toggles, grouped the same way as app
management (`Thông báo cho bạn khi các ứng dụng được chọn cố gắng sử dụng
Internet`).

### Ad blocking sub-screens

- `33-allowlist.png`: `Danh sách cho phép của trang web` — master, search,
  `Thêm trang`.
- `31-user-rules.png`: `Bộ lọc của Người dùng` — master, search,
  `Quy tắc người dùng mới`; header explains it holds allowlist rules, rules
  created from the log, and manually added rules.

### DNS sub-screens

- `28-dns-servers.png`: `DNS tự động` (currently active, resolves through a
  chosen provider), `AdGuard DNS`, `AdGuard DNS Family Protection`,
  `AdGuard DNS Không lọc`, then public servers (Google, Cloudflare, ...).
- `29-dns-filters.png`: `Các bộ lọc` master, `Thêm bộ lọc DNS`,
  `Bộ lọc của Người dùng` (DNS syntax), `Bộ lọc tên miền đơn giản`
  v2.1.39.80 with update timestamp.

### Filter catalog (`43`–`51`)

Reached from Settings → Đang lọc → `Bộ lọc`.

- Landing (`43`, `44`): search plus eight categories, each with
  `Đã bật: X trên Y`:
  - `Bộ lọc quảng cáo` — 2/3
  - `Bộ lọc bảo mật` — 1/7, with the warning
    `Các bộ lọc này không hoạt động vì Bảo vệ theo dõi bị tắt`
  - `Bộ lọc xã hội` — 1/2
  - `Bộ lọc phiền toái` — 5/11
  - `Bộ lọc bảo vệ` — 1/5
  - `Ngôn ngữ hỗ trợ` — 2/55
  - `Các bộ lọc khác` — 0/4
  - `Bộ lọc tuỳ chỉnh` — 0/0
- Category screen (`45`): rows show the filter name, version and last-update
  timestamp, with a switch on the right (the description appears only inside
  the filter).
- Filter detail (`46`): description, switch, `Cập nhật lần cuối`, `Quy tắc`
  (45,735 rules for the English filter), `Trang chủ` link, `Nguồn` URL and a
  `Tính năng` list (`Đề xuất AdGuard`, `Chặn quảng cáo`, ...).
- Security category (`47`): `Bộ lọc gián điệp`, `Bộ lọc URL Theo Dõi Của
  AdGuard`, `AdGuard Mail Tracking Protection filter`, `EasyPrivacy`,
  `Legitimate URL Shortener`, `Peter Lowe's Blocklist`; a snackbar offers
  `Kích hoạt` next to the "does not work while tracking protection is off"
  message.
- Protection filters (`49`): `Online Malicious URL Blocklist` (on),
  `Phishing URL Blocklist`, `Scam Blocklist by DurableNapkin`,
  `uBlock Origin – Badware risks`, `Dandelion Sprout's Anti-Malware List`.
  This is a separate group from `Bộ lọc bảo mật`; AdGuard uses it for the
  browsing-security/malware coverage.
- Social filters (`63-filter-social.png`): `Bộ lọc phương tiện mạng xã hội`
  v2.1.34.54 (on, updated 30 Oct 2026 07:21) and `Fanboy's Social Blocking
  List` v2.1.41.43 (off, updated 15 May 2025 19:44). Description: hide social
  widgets such as Like and Share buttons.
- Annoyances filters (`64`, `65`): 11 rows, 5 enabled. On: `Bộ lọc Thông báo
  Cookie AdGuard` 2.0.98.4, `Bộ lọc Quảng cáo AdGuard` 2.0.86.47, `Bộ lọc
  AdGuard Mobile App Banners` 2.0.33.56, `Bộ lọc Những phiền toái khác của
  AdGuard` 2.0.49.81, `Bộ lọc Tiện ích con AdGuard` 2.0.15.31. Off: `Bộ lọc
  phiền toái` 2.2.30.49, `Adblock Warning Removal List` 2.1.69.94, `Fanboy's
  Annoyances` 2.1.47.24, `EasyList Cookie List` 2.1.52.96, `Stevo's AI
  Blocklist` 2.0.1.78, `Web Annoyances Ultralist` 2.0.0.38. The category
  screen uses the same row template (name, version, update time, switch) as
  the other categories; no description text at this level.
- Other filters (`48`): `Bộ lọc quảng cáo hữu ích`, `Bộ lọc tên miền đơn giản`,
  `Bộ lọc thử nghiệm`, `Fanboy's Anti-thirdparty Fonts`.
- Custom filters (`50`): `Thêm bộ lọc tuỳ chỉnh`, empty state
  `Chưa có bộ lọc nào`.
- Language filters (`51`): Japanese, `ABPVN List` (Vietnamese, enabled),
  Russian, German, Dutch, Spanish/Portuguese, Turkish, ... Each row shows
  version and update time.

### Settings (`34`–`40`)

- Landing: `General`, `Đang lọc`, `Bản quyền`, `Hỗ trợ`, `Thông tin`,
  `Thoát`.
- General (`35`): auto-start with the system, theme, high contrast, app
  language, update app and filters, app notifications, technical data,
  automatic error reports, `Nâng cao`.
- Advanced (`36`): tasker automation, watchdog, log level, export log,
  low-level settings.
- `Đang lọc` (`37`): `Bộ lọc`, `Tiện ích mở rộng`, `Mạng`.
- Extensions (`38`): master, add extension, `AdGuard Extra`.
- `Mạng` (`39`): `HTTPS filtering` toggle, `Proxy` toggle, routing mode row
  (currently `VPN cục bộ`).
- Routing mode (`40`): `VPN cục bộ`, `Proxy tự động` (root),
  `Proxy thủ công` (root, port 8080).

### Statistics and log (`41`, `42`, `52`–`59`)

- Statistics landing: requests split into ads / trackers / total with a share
  bar, data saved / uploaded / downloaded, per-app top list, `Xem tất cả ứng
  dụng`.
- Data-type filter (`52`), opened from `Tất cả dữ liệu` next to `Yêu cầu`:
  `Tất cả dữ liệu`, `Chỉ dữ liệu di động`, `Chỉ Wi-Fi`.
- Time range (`53`), opened from the calendar icon in the top bar:
  `24 tiếng`, `7 ngày`, `30 ngày`, `Mọi lúc` (currently selected). Each row
  shows a calendar glyph; tapping the glyph does not open a custom date
  picker — the four presets are the whole control.
- All apps (`56`, `58`): search, sort menu (`57`: sort by `Quảng cáo`,
  `Trình theo dõi` or `Yêu cầu`), same `Mọi lúc` time range, rows with app
  icon, name and `ads / trackers / total` (e.g. `2,2K / 0 / 2,6K`). Some rows
  show tracker counts (e.g. Google Play Services `2 / 87 / 517`).
- Per-app statistics (`55`, Chrome variant): header with the app icon, name
  and its own `Mọi lúc` range, request counts, data counts, `Hoạt động gần
  đây` row, then `Các dịch vụ` — companies the app talked to (Facebook
  Audience Network `0/0/5`, Amazon Advertising `3/0/3`, Google `0/0/3`),
  `Xem tất cả các công ty` (`59`: Media.net, AdGuard, adguardcdn.com,
  Bugsnag, CloudFlare, Google, googleanalytics.com, Google APIs, ...), and an
  `App management` section with the five firewall network icons.
- Log: `Hoạt động gần đây` with the subtitle
  `Từ 10 nghìn yêu cầu được lưu trữ gần đây nhất`, search, rows showing app
  icon, host or IP:port, protocol scheme (`udp://`, `tcp://`, `https://`,
  `iquic://`) and time.

## 4. AdFree gaps observed

| Area | AdGuard | AdFree today |
| --- | --- | --- |
| Notification | title + blocked/saved stats + `Vô hiệu` + `Trợ lý` | title + status text + `Tạm dừng`/`Tiếp tục` + `Dừng`, no stats, no assistant |
| Disabled state | notification stays as tap-to-enable (`Bảo vệ bị vô hiệu hóa`) | `Dừng` removes the notification and the service |
| Protection rows | 6 modules + 3 navigation rows | 6 modules (ads, tracking, DNS, HTTPS, firewall, eco); no browsing security, no annoyances row, no assistant |
| Tracking options | privacy levels + cookie/header/API/DPI options | filter-list based tracking module |
| Annoyances | own module | annoyances live inside the ad-blocking module gate |
| Firewall | global 5-rule grid, per-app overrides, quick actions, notifications | master switch + per-app sheet (cellular/Wi-Fi/screen-off), no roaming, no quick actions, no notifications |
| Browsing security | phishing/malware warning module | security filter group exists in the catalog (URLhaus, phishing, anti-malware) but no module/UI |
| HTTPS filtering | Settings → Đang lọc → Mạng | own Protection row |
| Per-app controls | routing, content filtering, HTTPS filtering, proxy, firewall, stats in one screen | Apps tab sheet with filtering/HTTPS/firewall toggles, no routing/proxy/stat row grouping |
| Allowlist | dedicated `Danh sách cho phép của trang web` screen (search + add) | allowlist lives in custom rules and HTTPS website rules; no dedicated screen |
| Statistics | dedicated tab: data-type filter, four time-range presets, all-apps list sortable by ads/trackers/requests, per-app stats with service/company breakdown | summary cards on Home |
| Log | `Hoạt động gần đây`, newest 10k requests, search | Log tab with whole-log counts, cursor paging, filters (10k in-memory cap) |
| Routing | local VPN / automatic proxy / manual proxy (root) | local VPN plus SOCKS5 proxy support |
| Extensions | userstyles/userscripts manager | Extensions screen exists |
| Filter catalog | eight categories with `X/Y` counts, inactive-module warning, per-filter version, rule count, source and features, custom and language filters | filter store with similar groups but no counts, no inactive warning, no per-filter rule count/source |
| Security vs protection filters | `Bộ lọc bảo mật` (tracking-gated) and `Bộ lọc bảo vệ` (malware/phishing) are separate groups | one `SECURITY` group, currently ungated |

Existing AdFree code references for the follow-up:

- Notification: `app/src/main/kotlin/git/shin/adfree/vpn/AdGuardVpnService.kt`
  (`buildStatusNotification` ~444–510, `createNotificationChannel` ~429–442,
  `setPaused` ~513).
- Notification strings: `app/src/main/res/values{,-vi}/strings.xml`
  (`vpn_notification_*`).
- Protection routes/landing/firewall detail:
  `app/src/main/kotlin/git/shin/adfree/ui/screens/ProtectionScreen.kt`
  (routes 91–104, landing 210–334, firewall detail 581–621).
- Filter groups/gates and security lists:
  `app/src/main/kotlin/git/shin/adfree/data/FilterCatalog.kt` (groups 27–65,
  malware/phishing entries ~240–266).
- Firewall model: `app/src/main/kotlin/git/shin/adfree/model/Models.kt`
  (`AppFirewallRule` ~329–338, `isFirewallEnabled` ~465) and
  `AdGuardRepository.updateAppFirewall` ~1630.
- Engine module flags: `rust/src/engine.rs` (`ad_blocking` ~237,
  `set_module_flags` ~848–858 and ~1021–1034).

## 5. Screenshot index

| File | Content |
| --- | --- |
| `01-launch.png` | Home "Kích hoạt bảo vệ..." plus AdGuard VPN upsell sheet |
| `02-home-activating.png` | Home while activation was blocked by AdFree's VPN |
| `02-home-active.png` | Home, protection active (module icon row, check toggle) |
| `03-protection.png` | Protection landing list |
| `04-firewall.png` | Firewall screen |
| `05-firewall-global.png` | Global firewall rules |
| `06-firewall-custom.png` | Custom firewall rules landing |
| `07-firewall-add-app.png` | App picker sheet (grouped system apps) |
| `08-firewall-app-rule.png` | Per-app firewall rule screen |
| `09-firewall-quick-actions.png` | Quick actions |
| `10-browsing-security.png` | Browsing security detail |
| `11-ad-blocking.png` | Ad blocking detail |
| `12`–`14-tracking-protection*.png` | Tracking protection detail, scrolled |
| `15-annoyances.png` | Annoyances detail |
| `16-dns-protection.png` | DNS protection detail |
| `17-notification-shade.png` | Notification shade, collapsed |
| `18-notification-expanded.png` | Notification expanded with both actions |
| `19-assistant.png` | Assistant sheet, Apps tab |
| `20-assistant-app.png` | Assistant shortcuts for one app |
| `21-assistant-web.png` | Assistant Web tab (empty state) |
| `23-disable-action.png` | Tap-to-enable state after "Vô hiệu" |
| `24-apps-management.png` | Apps management, grouped by shared process |
| `25-app-detail.png` | Per-app screen: routing, filtering, HTTPS, proxy, firewall, stats |
| `26-tracking-custom-level.png` | Tracking protection with the `Tuỳ chọn` level selected |
| `27-tracking-general.png` | Tracking `General` section |
| `28-dns-servers.png` | DNS server picker |
| `29-dns-filters.png` | DNS filters and user rules |
| `31-user-rules.png` | User filter editor |
| `32-firewall-notifications.png` | Firewall notifications, per-app toggles |
| `33-allowlist.png` | Website allowlist |
| `34-settings.png` | Settings landing |
| `35-settings-general.png` | Settings → General |
| `36-settings-advanced.png` | Settings → General → Advanced |
| `37-settings-filtering.png` | Settings → Đang lọc |
| `38-settings-extensions.png` | Settings → Đang lọc → Tiện ích mở rộng |
| `39-settings-network.png` | Settings → Đang lọc → Mạng |
| `40-routing-mode.png` | Routing mode (local VPN / proxies) |
| `41-statistics.png` | Statistics tab |
| `42-filtering-log.png` | `Hoạt động gần đây` log |
| `43-filter-catalog.png` | Filter catalog landing (categories with X/Y counts) |
| `44-filter-catalog-bottom.png` | Filter catalog scrolled to custom filters |
| `45-filter-ads-category.png` | Ads filter category |
| `46-filter-detail.png` | One filter's detail (rules, source, features) |
| `47-filter-security-category.png` | Security category with the inactive warning |
| `48-other-filters.png` | Other filters category |
| `49-protection-filters.png` | Protection (malware/phishing) filter category |
| `50-custom-filters.png` | Custom filters empty state |
| `51-filter-languages.png` | Language filters (ABPVN enabled) |
| `52-stats-data-type.png` | Statistics data-type filter (all / mobile / Wi-Fi) |
| `53-stats-time-range.png` | Statistics time range (24 h / 7 d / 30 d / all time) |
| `55-per-app-stats.png` | Per-app statistics (Parallel Space) |
| `56-stats-all-apps.png` | All apps list with per-app counts |
| `57-stats-sort.png` | All apps sort menu |
| `58-stats-all-apps-scrolled.png` | All apps list, scrolled to tracker-heavy apps |
| `59-stats-all-companies.png` | All services/companies list |
| `60-firewall-overflow.png` | Firewall top bar with the `Đặt lại mặc định` action |
| `61-firewall-reset-dialog.png` | Firewall reset confirmation sheet |
| `62-quick-actions-overflow.png` | Quick action card overflow (activity, rule, app, mute) |
| `63-filter-social.png` | Social filter category |
| `64-filter-annoyances.png` | Annoyances filter category |
| `65-filter-annoyances-scrolled.png` | Annoyances list scrolled to the disabled filters |

Still not captured (relevant only if we implement the matching screen):

- Log entry detail and the "create rule from this request" flow.
- Settings → General → `Thông báo ứng dụng` (per-channel notification
  settings).
- Add dialogs: allowlist `Thêm trang`, user rule `Quy tắc người dùng mới`,
  DNS `Thêm bộ lọc DNS`, custom filter `Thêm bộ lọc tuỳ chỉnh`.
- YouTube how-to page and the private-browser external link (navigation only).
