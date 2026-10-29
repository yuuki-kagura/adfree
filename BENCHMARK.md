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
| Blocked-host latency | median of `bench/probe.c` over known ad hosts: in-process `getaddrinfo` + non-blocking connect through the tunnel, DNS and TCP halves reported separately |
| Allowed-host latency | same probe over ordinary hosts, with the failure count |
| Filtering decision cost | `stats.record_decision` counters inside the engine (DNS match time) |
| CPU | `utime + stime` from `/proc/<pid>/stat` of the measured app, sampled before/after the probe burst |
| Background idle CPU | same counters over a settled 60 s window with the app in the background and no probes |
| Foreground idle CPU | same counters with the app open and untouched |
| RAM | `dumpsys meminfo <pkg>` → `TOTAL PSS` |
| Battery | `dumpsys batterystats --charged`, UID mAh delta |

The probe harness (`bench/probe.c`) runs 6 rounds × (10 allowed + 8 blocked
hosts) inside one process: `getaddrinfo` and a non-blocking connect are timed
separately and printed as CSV. It replaced the earlier `date`+`nc` loop, whose
fork/exec cost ~50 ms per sample and swamped the tunnel's own cost. The binary
must stay dynamically linked so lookups reach netd (a static build answers
EAI_NODATA), and AdFree's shell capture marker (`files/capture-shell`, debug
builds only) routes adb's traffic through the tunnel so the probe measures the
app, not the host network.

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
| Poller parks while the UI is not visible | `data/AdGuardRepository.kt`, `MainActivity.kt` | `c8ca524` |
| IPv6 routed only when the underlying network has a global IPv6 address; otherwise `::/0` unreachable | `vpn/AdGuardVpnService.kt` | `c8ca524` |
| Retry log line now carries the errno | `rust/src/engine.rs` | `c8ca524` |
| DNS-stage rules match the bare hostname, not a fabricated URL | `rust/src/filter.rs` | `c8ca524` |
| Fallback retry hedged at 100 ms (2 s for DoT/DoH, where a handshake is expected) | `rust/src/upstream.rs` | `c8ca524` |
| Forwarder wait capped by the first DNS deadline instead of a fixed 1 s | `rust/src/engine.rs` | `c8ca524` |

## Re-run — after fixes (2026-10-29)

AdFree `c8ca524`, AdGuard nightly 4.14.68, both measured back to back on the
same Wi-Fi, app backgrounded unless stated.

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

## Re-run — after the cache and idle work (2026-10-29, evening)

AdFree `813c87d`, AdGuard nightly 4.14.68, measured back to back in alternating
order on the same Wi-Fi (AdFree, AdGuard, AdGuard, AdFree, AdFree, AdGuard), so
network drift is shared by both. Each app was backgrounded and left to settle;
the probe harness is unchanged (6 rounds × 18 hostnames). Round medians are
listed rather than one combined figure, because the Wi-Fi moved during the
session and the spread is the honest result.

| Metric | AdFree | AdGuard | Verdict |
| --- | --- | --- | --- |
| Blocked-host latency (per round) | 61 / 65.5 / 57.5 ms | 57.5 / 62.5 ms | parity |
| Allowed-host latency (per round) | 72.5 / 70 / 71 ms | 58.5 / 61 ms | AdFree ~11 ms slower |
| Allowed-host mean (per round) | 86 / 87.5 / 184 ms | 82 / 91 ms | AdFree equal except one congested round (2 timeouts) |
| CPU for the same 108 probes | 1.33 / 1.57 / 1.93 s | 2.09 / 1.99 s | AdFree 20–35 % lower |
| Background idle CPU (60 s windows) | 0.18 / 0.13 / 0.62 % | 1.53 % | AdFree 3–10× lower |
| Foreground idle CPU (60 s, app open) | 9.9 % | 10.3 % | parity |
| RAM background PSS (settled) | ~247 MB (239–253 across processes) | 288 MB | AdFree ~14 % lighter |
| RAM foreground PSS | 263 MB | 350 MB | AdFree ~25 % lighter |

The idle figures are the point of this run: with nothing in flight the
forwarder now wakes once every 10 s instead of once a second, and the fresh
process that still had startup work to settle spent 37 ticks in its first
measured minute against 8–11 in the settled ones. AdGuard's background cost
measured lower this session (92 ticks) than in the previous one (194–254); it
is still an order of magnitude above AdFree's.

### Cold lookups (first query of a never-seen name)

`nc -z -w 5 <unique>.127.0.0.1.nip.io 443`, eight probes per round.

| | AdFree | AdGuard |
| --- | --- | --- |
| Median per round | 220.5 / 223 / 230.5 / 226 ms | 145.5 / 144.5 / 138.5 ms |
| Range | 209–241 ms (one congested round: 306–676) | 109–342 ms |

The ~80 ms gap is the hedge, not the forwarding: `94.140.14.14` takes 350 ms or
more (sometimes never answers) for a name it has not seen, the hedge hands the
query to the system resolver (`8.8.8.8`) at 100 ms, and that answers in another
~110 ms. AdGuard reaches a cold name through an upstream that answers in
~140 ms here. Lowering the hedge would shrink the gap but hand more warm
lookups to the system resolver, whose answers carry no DNS-level blocking — the
hedge stays where it is.

### DNS cache, verified on the device

- First lookup after a restart (the cache is empty): 143–257 ms.
- The same host 30 s later: 56–84 ms — local, no upstream round trip.
- Two minutes on, past the record's TTL, one probe cost 235 ms again and the
  following ones dropped back to 62–84 ms: expiry and refill both behave.
- `ping` from adb printed `MicRoSOft.COm`: the mixed-case QNAME its resolver
  had invented came back intact, so a hit re-adopts the caller's spelling
  instead of replaying the one that happened to be cached.
- The engine's forwarded-query counter is not readable from adb; the hit path
  is asserted in `a_repeated_query_is_answered_from_the_cache`, and the
  miss-then-hit timings above are that path running on the device.

### Fixes applied in this run

| Fix | Where | Commit |
| --- | --- | --- |
| Repeated DNS lookups answered from a bounded, TTL-respecting cache | `rust/src/dnscache.rs`, `rust/src/dns.rs`, `rust/src/engine.rs` | `813c87d` |
| Forwarder sleeps 10 s when no query, relay, NAT mapping or QUIC flow exists | `rust/src/engine.rs` | `813c87d` |
| Rule-size metric no longer serializes the whole engine just to read its length | `rust/src/filter.rs` | `813c87d` |
| Live event ring 4 096 → 512 slots (~1.5 MB of anonymous memory) | `rust/src/events.rs` | `813c87d` |

### Notes

- Two rounds had `zq8f8.adnxs.com` allowed for the whole round (6 of 48 blocked
  probes connected): the smart filter's 60 s allow window after a burst of
  identical blocks, described above. AdGuard has no equivalent window.
- The allowed-host gap tracks the Wi-Fi, not the code: connects to a fixed set
  of public IPs measured 66 ms on both apps in one pair of runs and 69 vs 57 ms
  in another, and the DNS step on AdFree — same destination IP, name versus
  address — is 0–5 ms once warm. No forwarding-path change was made in this
  run.
- PSS includes swapped pages. AdFree keeps ~70 MB of its total in swap;
  AdGuard's background total is 288 MB of which 244 MB is swap (RSS 115 MB).
  The numbers above are the `TOTAL PSS` the system reports, as in the previous
  sections.
- The filter rebuild still materializes the list text (~26 MB on this device)
  for the duration of a rebuild; the compiled engine drops it afterwards. That
  peak is unchanged and is not part of the settled figures.

## Re-run — after moving flow setup off the reader (2026-10-29, night)

AdFree `6617ea9`, AdGuard nightly 4.14.68, measured back to back on the same
Wi-Fi in alternating order (AdFree, AdGuard, AdFree, AdGuard). Each app was
backgrounded; the probe is the in-process `bench/probe.c`, so the numbers are
the tunnel's cost rather than the shell's fork/exec. Filter state is the same
seven lists as the runs above.

| Metric | AdFree | AdGuard | Verdict |
| --- | --- | --- | --- |
| Allowed-host total (median, 60 probes per run) | **4.6 / 4.8 ms** | 8.3 / 8.4 ms | AdFree ~45 % lower |
| Allowed DNS half (median) | 3.0 / 3.1 ms | 3.0 ms | parity |
| Allowed TCP half (median) | **1.4 / 1.4 ms** | 5.2 / 5.2 ms | AdFree ~3.7× lower |
| Blocked-host total (median, 48 probes per run) | **4.5 / 4.8 ms** | 9.6 / 10.6 ms | AdFree ~2× lower |
| CPU for the same 108 probes | **1.08 / 1.12 s** | 1.19 / 1.25 s | AdFree ~10 % lower |

### What changed

The reader used to build the whole upstream half of every intercepted flow
inline: app attribution (`ConnectivityManager.getConnectionOwnerUid`, ~4 ms),
`protect()` (1.3–3.6 ms) and the rustls session (2.3–6.4 ms) ran on the same
thread that reads the tun. Back-to-back SYNs queued behind the previous flow's
setup, which is why the handshake floor was 1.2 ms but its median stayed at
5.9 ms under load.

Now the reader answers the SYN-ACK immediately, parks the flow as pending and
buffers whatever the client sends, and a dedicated `adfree-setup` worker
builds the peer socket and TLS session off the packet path. The buffered
segments are replayed with their sequence numbers once the upstream half is
installed; a failed setup resets the answered flow with our sequence. The
allowed-host TCP median fell from 5.9 ms to 1.4 ms, which is the reader no
longer waiting on platform calls between SYNs.

| Fix | Where | Commit |
| --- | --- | --- |
| Upstream half built on a setup worker; client bytes buffered and replayed | `rust/src/engine.rs`, `rust/src/mitm/relay.rs` | `6617ea9` |
| In-process latency probe replacing the `date`+`nc` loop | `bench/probe.c` | `67c0a68` |

### Notes

- Blocked probes: AdFree answers NXDOMAIN in ~3 ms (AdGuard 9.6–10.6 ms).
  After the smart filter's 60 s allow window, four of the eight probe names
  were served `0.0.0.0` (the client still fails fast with ECONNREFUSED) and
  `zq8f8.adnxs.com` reconnected in every round — the documented retry-loop
  window, unchanged by this work. AdGuard has no such window and blocked
  48/48.
- The earlier ~60–70 ms totals in this document were dominated by the old
  harness: `date`+`nc` cost ~50 ms of fork/exec per sample on this device.
  The per-probe figures from this run and earlier ones are not directly
  comparable; the AdFree/AdGuard pairs within each run are.

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

# 3. Build and run the probe
"$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" \
  -O2 -o bench/probe bench/probe.c
adb push bench/probe /data/local/tmp/
adb shell '/data/local/tmp/probe 6 google.com facebook.com youtube.com shopee.vn \
  vnexpress.net github.com wikipedia.org cloudflare.com apple.com microsoft.com \
  zq8f1.doubleclick.net zq8f2.googlesyndication.com zq8f3.google-analytics.com \
  zq8f4.scorecardresearch.com zq8f5.criteo.com zq8f6.taboola.com \
  zq8f7.outbrain.com zq8f8.adnxs.com' > probe.csv
```

The probe prints `round,host,gai,rc,addr,dns_ms,connect_ms,total_ms`: `gai` is
`getaddrinfo`'s code (`0` = resolved, `7` = NXDOMAIN from the tunnel), `rc`
the connect result (`0` or an errno), and the DNS and connect halves are timed
separately. Read medians per host class from the CSV, and sample
`/proc/<pid>/stat` (`utime`+`stime`, 100 ticks/s) around a burst for CPU.
RAM comes from `dumpsys meminfo <pkg> | grep 'TOTAL PSS'`, battery from
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