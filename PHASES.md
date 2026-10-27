# AdFree — 8 phase còn lại

Ghi chú tạm từ phiên Qoder trước (danh sách `#39`–`#46`). Đây là việc đang làm
tiếp, không phải kế hoạch parity mạng trong `plan.md`.

| # | Phase | Trạng thái |
|---|-------|------------|
| 39 | Phase 1: Rust-owned typed state + Kotlin cutover | ✅ xong (`094d737`) |
| 40 | Phase 2: Rust config application + settings sanity | ✅ xong |
| 41 | Phase 3: Localize UI strings | ✅ xong (`707f79e` → `85fb29b`) |
| 42 | Phase 4: Stealth features end-to-end | ✅ xong (`f1cbdfb`) |
| 43 | Phase 5: Advanced DNS (DoH/DoT, rewrites, SafeSearch, probe) | ✅ xong (`e622cb0` + `fb82872`) |
| 44 | Phase 6: Background updates, notification, tile, autostart | ✅ xong (`2cfd659`) |
| 45 | Phase 7: Theme, language selector, cosmetic filtering | ◐ language xong (`7f2f203`), còn theme + cosmetic |
| 46 | Phase 8: Full verification and commits | ⏳ chưa |

## Phase 4 — Stealth end-to-end

Hiện trạng trước khi làm:

- UI có ba công tắc UTM / WebRTC / cookie, nhưng **không có công tắc bật
  Stealth**, cũng chưa có công tắc giả User-Agent.
- `isStealthModeEnabled`, `stripUtmTracking`, `blockWebRtcLeaks`,
  `disguiseUserAgent`, `blockThirdPartyCookies` chỉ được lưu trong state;
  `Config` của engine không nhận các cờ này, nên bật/tắt không có tác dụng.

Việc cần làm:

1. `StealthConfig` trong Rust + map từ `ProtectionState` sang `Config`.
2. WebRTC: chặn STUN/TURN ở tầng packet (UDP + TCP).
3. UTM: bỏ tham số tracking khỏi request HTTPS khi MITM bật.
4. Cookie bên thứ ba: bỏ `Cookie` của request cross-site và `Set-Cookie` của
   response tương ứng.
5. Giả User-Agent: thay `User-Agent`, bỏ các header `Sec-CH-UA-*`.
6. UI: công tắc Stealth tổng, công tắc giả UA, khoá các công tắc con khi
   Stealth tắt; chuỗi EN + VI.
7. Test Rust cho từng helper, chạy `cargo test`, `:app:testDebugUnitTest`,
   `:app:lintDebug`, `:app:assembleDebug`.

## Phase 5 — Advanced DNS

Đã xong:

- **DoT/DoH** (`rust/src/dnssecure.rs`): TCP mở qua socket protector, ALPN
  `dot` hoặc `http/1.1`, DoH POST tối giản. Resolver dạng hostname lấy địa chỉ
  qua UDP bootstrap được bảo vệ, cache địa chỉ 10 phút.
- **Rewrites**: chạy trước filter list; luật A chỉ trả A, AAAA chỉ trả AAAA;
  exact thắng wildcard. Hostname được Rust validate chặt
  (`DnsRewriteValidation`), UI chỉ map mã lỗi sang chuỗi.
- **SafeSearch**: gửi truy vấn tới host đã lọc rồi trả địa chỉ cho tên gốc,
  có cache ngắn; công tắc riêng trong tab Network.
- **Probe + UI**: chọn UDP/DoT/DoH khi thêm resolver, nút Test chạy nền và báo
  latency hoặc lý do lỗi qua snackbar; thêm/xoá rewrite; chuỗi EN + VI
  (716 key mỗi ngôn ngữ).

Giới hạn:

- DoH mới hỗ trợ HTTP/1.1; endpoint chỉ có HTTP/2 (ví dụ Quad9) báo
  `Unsupported`.
- Chưa kiểm tra trên thiết bị vì không có emulator/adb; đã chạy 676 test Rust,
  unit test Kotlin, `lintDebug` và `assembleDebug`.

## Phase 6 — Nền, thông báo, tile, tự khởi động

Đã xong (`2cfd659`):

- **Cập nhật nền**: `FilterUpdateScheduler` giữ một PeriodicWork duy nhất
  (WorkManager) với ràng buộc có mạng và pin không yếu; đổi khoảng thời gian
  hoặc tắt tự cập nhật sẽ đồng bộ lại lịch. Worker chỉ tải list đã quá hạn,
  dùng chung đường tải với foreground và trả về số list đã làm mới.
- **Thông báo**: thông báo bảo vệ có content intent mở app và action "Tạm
  dừng" (lưu trạng thái tắt, khác với stop khi khởi động lại tunnel). Khi
  worker làm mới được ít nhất một list, nó đăng một thông báo ưu tiên thấp
  mở thẳng tab Filters.
- **Quick Settings tile**: bật/tắt tunnel ngay từ khay; nếu chưa có consent
  VPN thì mở `MainActivity` với `ACTION_ENABLE_PROTECTION` để hệ thống hỏi.
- **Tự khởi động**: công tắc trong Settings, `BootReceiver` nhận
  `BOOT_COMPLETED`/`MY_PACKAGE_REPLACED` và chỉ bật lại khi người dùng đã bật
  `autoStart` và bảo vệ đang bật trước đó.
- **Quyền thông báo**: Android 13+ hỏi `POST_NOTIFICATIONS` một lần, có lưu
  cờ để không hỏi lại.

Giới hạn:

- Chưa kiểm tra trên thiết bị vì không có emulator/adb; đã chạy unit test
  Kotlin, `lintDebug` và `assembleDebug`.

## Ghi chú

- Chỉ bật các hiệu ứng khi `isStealthModeEnabled` bật; các cờ con vẫn được lưu
  riêng để người dùng chọn cái nào muốn dùng.
- UTM / cookie / UA chỉ chạy khi HTTPS filtering bật (luồng 443 được MITM).
  WebRTC chặn ở tầng packet nên chạy cả khi không MITM.
