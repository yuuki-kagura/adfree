# AdFree vs AdGuard — performance benchmark

Living document. Numbers here are measured on real hardware, not estimates, so
later runs can be compared against them. Every result is followed by the exact
commit it was measured on.

## Environment

| | |
| --- | --- |
| Device | Redmi 24075RP89G (`flare`) |
| OS | Android 16 (SDK 36), HyperOS 3.0.303.0.WHXMIXM |
| Transport | Wi-Fi 5 GHz |
| AdFree | debug build from this repo, VPN active, default settings (AdGuard DNS `94.140.14.14`, 7 filter lists, HTTPS filtering per device CA) |
| AdGuard | nightly 4.14.68, protection on, default settings |

Both apps were measured alone: the other one was disabled and its tunnel torn
down before each run. The app under measurement was backgrounded (Home pressed)
unless stated otherwise.

## What is measured

| Metric | How |
| --- | --- |
| Blocked-host latency | median wall time of `nc -z -w 3 host 443` (DNS + TCP handshake through the tunnel) over known ad hosts |
| Allowed-host latency | same probe over ordinary hosts, with the failure count |
| Filtering decision cost | `stats.record_decision` counters inside the engine (DNS match time) |
| CPU | `utime + stime` from `/proc/<pid>/stat` of the measured app, sampled before/after the probe burst |
| Background idle CPU | same counters over a settled 60 s window with the app in the background and no probes |
| Foreground idle CPU | same counters with the app open and untouched |
| RAM | `dumpsys meminfo <pkg>` → `TOTAL PSS` |
| Battery | `dumpsys batterystats --charged`, UID mAh delta |

The probe harness (`/data/local/tmp/bench.sh`) runs 6 rounds × (10 allowed +
8 blocked hosts), timing each probe with `date +%s%3N`. AdFree's shell capture
marker (`files/capture-shell`, debug builds only) routes adb's `nc` through
the tunnel so the probe measures the app, not the host network.

## Baseline — 2026-10-28

AdFree `be011e7` (before the performance fixes below).

| Metric | AdFree | AdGuard | Verdict |
| --- | --- | --- | --- |
| Blocked-host latency (median) | ~60 ms | ~60 ms | parity |
| Allowed-host latency (median) | 68 ms (11/60 failures, 2 outliers 2–3 s) | 61 ms (60/60 OK) | AdFree worse |
| DNS decision time | 3.7–184 µs (avg 21.8 µs; recent p50 6.4 µs) | not readable from logs | n/a |
| CPU for the same 108 probes | 4.19 s (wall 21.2 s) | 2.02 s (wall 10.9 s) | AdFree ~2× |
| Background idle CPU | ~8.5–10.7 % of one core | ~0.1 % | **AdFree ~100×** |
| Foreground idle CPU | ~98 % before the animation fix, 8.7 % after | 11.3 % | parity after fix |
| RAM (TOTAL PSS) | 236–267 MB | 313–350 MB | AdFree ~25–35 % lighter |
| Battery | charging, 0–1 mAh delta → not separable | same | inconclusive, CPU used as proxy |

Filter coverage spot check: `zq8f8.adnxs.com` was reported here as not blocked
by the seven enabled lists. Follow-up runs show `||adnxs.com^` in the AdGuard
DNS list and the name blocked in every settled run; the earlier "still up"
results were the smart filter's retry-loop allow window, not a coverage gap.

## Root causes found

1. **Infinite hero animation.** The pulsing rings on Home ran a 60 fps
   `rememberInfiniteTransition` for decoration and kept a core at ~98 % while
   the app was open. Replaced with static rings in `7c58efa`.
2. **Stats poller never slept.** `AdGuardRepository.startStatsPoller` looped
   every 500 ms (2 s screen-off) for the lifetime of the process, whether or
   not any screen was visible. That is the ~10 % background CPU: the process
   and its threads were woken twice a second for a UI nobody could see.
3. **IPv6 routed without an IPv6 upstream.** The tunnel always added
   `2000::/3`, so every AAAA-capable client tried IPv6 first, the engine opened
   a peer socket, and the connect died with `ENETUNREACH` (errno 101). The
   engine then retried once on a fresh socket (also IPv6, also dead) before
   resetting the client. AdGuard's tunnel installs `::/0 unreachable` when the
   carrier has no global IPv6, so its clients fail the IPv6 attempt instantly
   without touching the tunnel.
4. **Per-connection retry noise.** The relay logs one failed peer connect and
   retry for every new flow — the same IPv6 path as above. Fixing (3) removes
   the trigger; the retry itself stays for its original purpose (stale NAT
   state).
5. **URL rules decided hostnames.** The DNS stage built `https://host/` and
   asked the engine whether that URL was blocked, so a rule written for URLs
   decided a bare hostname. ABPVN ships
   `/^https:\/\/[a-z]{3,}\.com\/$/$xmlhttprequest,third-party`, which blocked
   every `.com` host at the DNS stage — `github.com`, `google.com`,
   `facebook.com` — and the smart filter then logged "blocked 5x, allowing it
   for 60s" for each. AdGuard's DNS stage matches the hostname itself, which is
   what the request object now does.
6. **Cold lookups paid a two-second fallback.** A silent primary was retried
   through the backup only after 2 s, and the forwarder checked that deadline
   once per second, so the first lookup of a new name took 0.5–3 s. The retry
   is now hedged at 100 ms and the forwarder's wait is capped by the earliest
   deadline, which is what makes the retry fire when it is due.

## Fixes applied

| Fix | Where | Commit |
| --- | --- | --- |
| Static hero rings (foreground CPU 98 % → 8.7 %) | `ui/screens/HomeScreen.kt` | `7c58efa` |
| Poller parks while the UI is not visible | `data/AdGuardRepository.kt`, `MainActivity.kt` | this change |
| IPv6 routed only when the underlying network has a global IPv6 address; otherwise `::/0` unreachable | `vpn/AdGuardVpnService.kt` | this change |
| Retry log line now carries the errno | `rust/src/engine.rs` | this change |
| DNS-stage rules match the bare hostname, not a fabricated URL | `rust/src/filter.rs` | this change |
| Fallback retry hedged at 100 ms (2 s for DoT/DoH, where a handshake is expected) | `rust/src/upstream.rs` | this change |
| Forwarder wait capped by the first DNS deadline instead of a fixed 1 s | `rust/src/engine.rs` | this change |

## Re-run — after fixes (2026-10-29)

AdFree from this working tree, AdGuard nightly 4.14.68, both measured back to
back on the same Wi-Fi, app backgrounded unless stated.

| Metric | AdFree | AdGuard | Verdict |
| --- | --- | --- | --- |
| Blocked-host latency (median over 48 probes) | **57 ms** (48/48 blocked) | 66 ms (48/48 blocked) | AdFree lower |
| Allowed-host latency (median over 60 probes) | **69 ms** (60/60 OK, max 235 ms) | 70 ms (60/60 OK, max 273 ms) | AdFree lower |
| Allowed-host mean / max | **81 / 235 ms** | 87 / 273 ms | AdFree lower |
| CPU for the same 108 probes | **1.19 s** (119 ticks) | 2.27 s (227 ticks) | AdFree ~2× lower |
| Background idle CPU (60 s, settled) | **0.33 %** (20 ticks) | 3.2–4.2 % (194–254 ticks) | AdFree ~10× lower |
| Foreground idle CPU (60 s, app open) | **10.2 %** (613 ticks) | 12.3 % (736 ticks) | AdFree lower |
| RAM (TOTAL PSS) | **230 MB** background / 264 MB foreground | 292 MB background / 311 MB foreground | AdFree ~20 % lighter |

Battery remains unseparable on a charging device; CPU at matched work is the
proxy, and it is now below AdGuard's in every window measured.

### Cold lookups (first query of a never-seen name)

`nc -z -w 5 <unique>.127.0.0.1.nip.io 443` × 8, so every probe is a genuine
cache miss that must reach an upstream resolver.

| | AdFree | AdGuard |
| --- | --- | --- |
| Range | 253–611 ms | 166–527 ms |
| Median | 295 ms | 236 ms |

Before the fixes the same test produced 544 / 1023 / 2444 ms: the two-second
fallback plus the one-second wake. The remaining gap is the resolver itself —
`94.140.14.14` answers warm names in ~70 ms but takes 350 ms or more (and
sometimes never answers) for a cold one, while the system resolver
(`8.8.8.8`, the configured backup) answers in ~150 ms. The hedge at 100 ms
keeps warm lookups untouched; lowering it further would abandon the primary's
answer for names it can still answer quickly.

### Notes

- The blocked-host probes are repeated identical names, which is exactly the
  pattern AdFree's smart filter (5 blocks in 10 s → allow for 60 s) treats as a
  retry loop. One earlier run showed `adnxs.com` allowed after such a window;
  the settled runs above block all 48. AdGuard has no equivalent allow window.
- AdGuard's background CPU is spent with no probes in flight; the idle window
  was taken twice (254 then 194 ticks) after two minutes of settling.

## Re-running

```
# 1. Build and install (arm64 device)
cd rust && ANDROID_NDK_HOME=/srv/android-sdk/ndk/28.2.13676358 \
  cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build --lib --release
./gradlew :app:assembleDebug -PskipNative
adb install -r app/build/outputs/apk/debug/app-debug.apk

# 2. Let the shell's probes reach the tunnel (debug build only)
adb shell run-as git.shin.adfree touch files/capture-shell
# restart protection in the app, then background it

# 3. Run the harness (script below)
adb push bench.sh /data/local/tmp/ && adb shell 'sh /data/local/tmp/bench.sh adfree'
```

`bench.sh` (the `$1` tag names the CSV):

```sh
#!/system/bin/sh
tag="$1"
out="/data/local/tmp/bench_${tag}.csv"
echo "round,host,kind,rc,ms" > "$out"
ok="google.com facebook.com youtube.com shopee.vn vnexpress.net github.com wikipedia.org cloudflare.com apple.com microsoft.com"
bad="zq8f1.doubleclick.net zq8f2.googlesyndication.com zq8f3.google-analytics.com zq8f4.scorecardresearch.com zq8f5.criteo.com zq8f6.taboola.com zq8f7.outbrain.com zq8f8.adnxs.com"
r=1
while [ $r -le 6 ]; do
  for h in $ok; do
    t0=$(date +%s%3N); nc -z -w 3 "$h" 443 >/dev/null 2>&1; rc=$?
    t1=$(date +%s%3N); echo "$r,$h,allow,$rc,$((t1-t0))" >> "$out"
  done
  for h in $bad; do
    t0=$(date +%s%3N); nc -z -w 3 "$h" 443 >/dev/null 2>&1; rc=$?
    t1=$(date +%s%3N); echo "$r,$h,block,$rc,$((t1-t0))" >> "$out"
  done
  r=$((r+1))
done
```

CPU is read from `/proc/<pid>/stat` (`utime` + `stime`, 100 ticks/s), RAM from
`dumpsys meminfo <pkg> | grep 'TOTAL PSS'`, battery from
`dumpsys batterystats --charged | grep '^  UID (<uid>):'`.

Remove the marker and restart protection when the measurement is done: with it
in place, adb's own traffic goes through the tunnel.

## Caveats

- Wall times include the probe host's scheduling and Wi-Fi, so run all rounds
  of both apps back to back on the same network.
- AdGuard's filter decision time is not exported anywhere readable, so that
  row is informational only.
- Battery deltas need the device off the charger for at least 30 minutes per
  app; on a charging device they are noise.
- `stats.record_decision` covers DNS matching only; HTTPS request filtering has
  its own timing counters in the stats snapshot.