# AdFree — 8 phase còn lại

Ghi chú tạm từ phiên Qoder trước (danh sách `#39`–`#46`). Đây là việc đang làm
tiếp, không phải kế hoạch parity mạng trong `plan.md`.

| # | Phase | Trạng thái |
|---|-------|------------|
| 39 | Phase 1: Rust-owned typed state + Kotlin cutover | ✅ xong (`094d737`) |
| 40 | Phase 2: Rust config application + settings sanity | ✅ xong |
| 41 | Phase 3: Localize UI strings | ✅ xong (`707f79e` → `85fb29b`) |
| 42 | Phase 4: Stealth features end-to-end | 🚧 đang làm |
| 43 | Phase 5: Advanced DNS (DoH/DoT, rewrites, SafeSearch, probe) | ⏳ chưa |
| 44 | Phase 6: Background updates, notification, tile, autostart | ⏳ chưa |
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

## Ghi chú

- Chỉ bật các hiệu ứng khi `isStealthModeEnabled` bật; các cờ con vẫn được lưu
  riêng để người dùng chọn cái nào muốn dùng.
- UTM / cookie / UA chỉ chạy khi HTTPS filtering bật (luồng 443 được MITM).
  WebRTC chặn ở tầng packet nên chạy cả khi không MITM.
