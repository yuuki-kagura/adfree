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
app, not the host network. The marker is read when the tunnel is built, so it
only takes effect on the *next* protection start — `dumpsys connectivity` shows
which of the two states the live tunnel is in. On the Sony 802SO the marker in
place reads `Uids: <{0-10343, 10345-99999}>`, with uid 2000 inside, and the
marker absent reads `Uids: <{0-1999, 2001-10343, 10345-99999}>`, with a hole at
2000; the surrounding numbers are that device's app uids and only the hole
matters. Measuring in the second state measures the Wi-Fi path, not the tunnel.

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
  Closed on 2026-11-03 — the filter is off by default now and the same harness
  blocked 48/48; see `Re-run — smart filtering off by default`.
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
# restart protection in the app — the marker is only read when the tunnel is
# built — then background it, and assert it took:
adb shell dumpsys connectivity | grep -o 'Uids: [^}]*'   # must contain 2000

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

Two things this harness does not control, learned the hard way (see
`Re-run — on the Sony 802SO`): idle-CPU and RAM rows must be taken with the
release APK, since a debug build of AdFree nearly doubles its own resident set,
and with `Display Power: state=ON` plus `svc power stayon true` pinned before
the foreground window, otherwise screen state and launch transitions dominate
the sample. Only one VPN can run, so each app's pass has to assert its own
`tun0` address before trusting any number.

A third thing to assert before counting blocks: **the smart filter's state**. Its
60 s allow window turns a repeated-name harness into a leak, and the setting is
persisted per device, so an install that had it on keeps it on after the shipped
default changed. The Protection → Ad blocking screen shows the switch; a pass
that reports fewer than 48/48 blocked probes should check it before anything
else.

For the CPU and RAM rows the probe is the wrong tool on a release AdFree, because
release never routes the shell into the tunnel. Use the two helpers instead:
`bench/win.sh <package> <seconds> <label>` samples one quiet window (ticks from
`/proc/<pid>/stat`, PSS from `dumpsys meminfo`, and it refuses the window if the
pid changed under it), and `bench/sweep.sh <pass>` drives the 12-page Chrome
workload and reports both blockers' ticks plus Chrome's own as the control. Both
were written for `Re-run — CPU and RAM on HEAD`, which has the URL list and the
numbers.

## Caveats

- Wall times include the probe host's scheduling and Wi-Fi, so run all rounds
  of both apps back to back on the same network.
- AdGuard's filter decision time is not exported anywhere readable, so that
  row is informational only.
- Battery deltas need the device off the charger for at least 30 minutes per
  app; on a charging device they are noise.
- `stats.record_decision` covers DNS matching only; HTTPS request filtering has
  its own timing counters in the stats snapshot.
## Engine memory — slim debug info and dnsmasq lists (2026-10-29, night)

The filter engine was carrying more than the rules. Two changes, measured on
the host over the exact seven lists the device has enabled (876 k lines, 25 MB
of text; release build, `FilterEngine::rebuild`):

| Metric | adblock 0.13.3 | fork + dnsmasq fix |
| --- | --- | --- |
| Engine flatbuffer | 75 MB | 46 MB |
| RSS after build | 150 MB | 121 MB |
| Peak RSS while building (`VmHWM`) | 277 MB | 184 MB |
| Debug-info cost per rule | 8 B + the rule's text | 8 B |

- **Fork**: `/home/shin/adblock-rust`, branch `adfree-slim-debug`, two signed
  commits on top of tag `v0.13.3`, wired in through `[patch.crates-io]`:
  - debug builds keep each rule's source location (list index + line) but no
    longer its text. A matched rule's text is read back from the list file on
    demand (`pread` at the recorded line, fed by a 4-byte-per-line offset
    index); user rules keep their text inline.
  - rejected lines no longer ship their text either. Only the count is
    serialized. A list whose syntax is not parsed (a dnsmasq list read as
    standard) used to cost one stored string per line.
- **dnsmasq rules**: `local=/domain/` and `address=/domain/` are rewritten to
  `||domain^` line for line during the rebuild. OISD ships dnsmasq2 and was
  loaded as a standard list, so its 234 k lines became patterns that could
  never match — 14 MB of the engine that blocked nothing. They now block the
  domain and its subdomains (175 k of them are not in the AdGuard DNS filter
  either), for about the memory the dead patterns already took.
- The device PSS rows above are from the earlier runs and stay as history.
  With the release build installed again (same seven lists as the host run),
  `dumpsys meminfo` reported **239.4 MB** foreground `TOTAL PSS` (native heap
  121.8 MB) and **155.6 MB** after 90 s in the background (RSS 131.6 MB, swap
  PSS 97.0 MB, native heap PSS 26.6 MB with 88.4 MB of it swapped). The
  pre-change device baselines were 263 MB foreground and 230–247 MB
  background, so the shrink is visible on the device too.
- **Log attribution after the change**: the per-host decision cache keeps the
  verdict and not the rule text, so a repeated block was logged with an empty
  rule and list — visible on the device as a row whose detail named no rule.
  The DNS path now asks for the detailed verdict only when a row is actually
  being written (`logging_live()`), so the write pays for the lookup, not
  every query. `a_cached_block_still_logs_its_rule` pins the behaviour, and a
  host replay of the device's own failure against the two real lists
  (`builtin_dns`, `cat_ag_mobile_ads`, three queries for `api.dollphoin.site`)
  names the rule and list on the first answer and on both cache hits. Those
  blank device rows were written by the pre-update process: MIUI kept the
  service alive across the install, so it kept running the old code until a
  real force-stop.

## Rejected: moving `||x^` rules into a domain set (2026-10-30)

The next memory cut considered was to move the hostname-only `||x^` rules out
of the engine into a compact set/trie: a rule costs on the order of 50 B
today and a domain perhaps 10 B, for an estimated 20–30 MB. The idea was
rejected. Those rules are not just a domain string — the engine attaches
semantics to them that a domain-keyed set does not carry — and the RAM target
is already met (239.4 MB foreground / 155.6 MB background against AdGuard's
311–350 / 288 MB).

Why the representation cannot be swapped 1:1:

- **Options are evaluated per context.** DNS evaluates
  `Request::preparsed(host, host, "", "other", false, "")`
  (`rust/src/filter.rs:6243`): source equals the request host and there is no
  URL, so `$third-party`, request type and method behave differently than on
  the MITM path (`src/filters/network_matchers.rs:406-418`). One set cannot
  hold one answer for both callers.
- **`$redirect-rule` and exceptions attach to a block.** A redirect rule only
  fires when another filter blocks (`src/blocker.rs:52-55`), and exceptions,
  `$important` precedence and the forced exception-only queries
  (`rust/src/filter.rs:6340-6366`) are resolved inside `Blocker::check`
  (`src/blocker.rs:188-223`). Removing the blocking rule from the engine
  leaves those passes with nothing to attach to.
- **Attribution and category live on the rule.** The log names the rule via
  `source_index` + line (read back through `ListLines`), and the category is
  gated after the engine answer (`rust/src/filter.rs:1959-1987`). A
  deduplicated set entry loses both, and which list a row names would change.
- **Hostname matching is more than an exact key.** It has to reproduce
  label-boundary suffix matching, IDN/punycode decoding and hosts-form
  normalisation (`src/filters/network.rs:475`, `:917-954`); any mismatch
  silently changes what is blocked or allowed.
- **The saving was a guess.** The flatbuffer is already 46 MB for the seven
  lists, and no per-class byte census was taken, so 20–30 MB was never
  verified.

If RAM becomes a target again, the safe order is to measure the composition
first (network flatbuffer vs cosmetic cache vs decision caches), then dedupe
rules that appear in more than one list — same verdict, category union and a
deterministic source for the log — which keeps the engine's semantics intact.

## Response rewriting vs TLS cost (2026-10-30)

The proposal was to prune response handling further — skip `m3u8`/`ts` and
image responses entirely unless a filter could use them. The engine's own
counters answer whether that is where the cost is: `tls_ns` (decrypt +
re-encrypt), `rewrite_ns` (the response path, holding, injecting and copying
bodies) and `busy_ns` (the packet loop), all in `rust/src/stats.rs`. They were
logged from a debug APK that packaged the release native library; counters
start at process start, so the table is deltas between two reads. The log line
was removed and the release APK reinstalled after the run.

| Workload | TLS ms | rewrite ms | busy ms | packets |
| --- | --- | --- | --- | --- |
| Idle, app foreground, 20 s | 2.0 | 0 | 115.7 | 72 |
| Chrome on `vnexpress.net`, scrolls, 47 s | 423.4 | 76.4 | 553.4 | 2588 |
| Same page again, 35 s | 189.7 | 58.2 | 299.2 | 1377 |
| YouTube video, 96 s (QUIC) | 12.9 | 0 | 384.4 | 5314 |

- Rewriting is **14–19 % of the packet loop** and 18–31 % of TLS on
  image-heavy page loads. Over the whole 6.5-minute session it is 135 ms
  against 2.84 s busy (4.7 %) and 393 s uptime (0.03 % of one core).
- The video watch added almost no TLS work and **zero rewriting**: YouTube
  carries the stream over QUIC, which the TLS path never sees, and the bodies
  that did arrive were not held.
- The code already prunes the rest by class and content type: a response is
  inspected only when its URL matched a `$replace`/`$jsonprune`/`$hls`/`$$`
  plan, and only when the content type is text
  (`rust/src/mitm/proxy.rs:1852-1867`); images, `video/mp2t` segments and
  media never are. `m3u8` counts as text only because `$hls` needs it, and
  only when a rule matched that manifest.

So skipping image and segment bodies saves nothing — they are already
untouched — and further pruning has little headroom. TLS termination and the
packet loop dominate; the fixed cost left is HTML injection on page loads
when cosmetic filtering is on, which is what hiding needs.

## Persisted compiled engine (2026-10-30)

`FilterEngine::rebuild` now loads and stores the compiled engine under the
data root (`files/engine/engine.dat`). The file is a 16-byte header (magic,
cache version, build key) followed by the adblock-Rust DAT payload from
`Engine::serialize`. The key covers every compiled input — list id, format,
trusted bit and raw text in build order, the user rules, the ad and tracking
switches, and the crate version — so a match is byte-for-byte what this build
would produce. DNS protection stays out of the key: it only gates lookups,
never which rules compile, and flipping it must not discard the file. Source
attribution survives the round trip because the fork keeps each rule's
`(source index, line)` in the engine and `sources` re-reads the text from the
list file on demand.

Measured on the 24075RP89G with the release APK, VPN off (so no MITM traffic
inflates the high-water mark), 7 lists / 866,085 rules, each figure after a
`force-stop` and a fresh launch, `build_ms` from Settings, VmHWM from
`/proc/<pid>/status` 30 s after start:

| Cold start | build_ms | Engine load | VmHWM |
| --- | --- | --- | --- |
| Before the cache | 6152 | compiled | 620,388 kB |
| After, cache miss | 5892 | compiled (35 MB written in 97 ms) | 663,856 kB |
| After, cache hit | 4673 | 244 ms | 615,772 kB |

- A hit saves about **1.5 s of 6.2 s (24 %)**. The rest of the build is not
  the engine's: the list texts are still read and scanned every launch, since
  the `$replace`/modifier/cookie/HTML/app/scriptlet/path structures and the
  canonical line-number index are built from them, and
  `FilterSet::add_filter_list` only stores text — parsing happens inside
  `new_with_filter_set`, which the cache replaces.
- The 35 MB write is outside the reported build time (97–153 ms), and the
  miss row's higher VmHWM is consistent with that serialization buffer: the
  parse peak itself is smaller than the app's existing high-water mark, so the
  hit and the old builds land within noise of each other. The host figures
  earlier in this file (277 MB → 184 MB peak while building) remain the
  separation measured without the UI in the same process.
- Two device findings fixed while measuring: the platform pushes lists through
  `core_set_lists_async`, so the cache is now armed when the store opens
  (pinned by `the_async_list_push_persists_the_engine_cache`) rather than in
  the sync rebuild; and a DNS-protection flip was initially in the key and
  threw the cache away, now covered by the DNS case in
  `a_changed_key_rebuilds_instead_of_reusing`.
- A hit still serves attribution: on the cache-hit process the Security Lab
  reports `doubleclick.net` blocked by `||doubleclick.net^` from *AdGuard DNS
  filter*, and the cached-block path re-reads the rule text.

## Phase 6 ring-memory check (2026-11-01)

PLAN.md asked that the event enrichment (transport/roaming bits, flow id, the
128 B-capped URL, the 64 B DNS answer, per-flow byte counters) keep the live
ring under ~3 MB. Measured on the host as `size_of::<Event>() × CAPACITY` —
the ring's actual footprint, not an estimate — on HEAD and on the pre-Phase 6
tree (`9c130b8`, checked out in a temporary worktree):

| | Event | Ring (512 slots) |
| --- | --- | --- |
| Before Phase 6 (`9c130b8`) | 352 B | 176 KB |
| After Phase 6 (`086ae01`) | 560 B | 280 KB |

- The growth is ~104 KB, two orders of magnitude under the ~3 MB budget. The
  plan's 2.5 MB figure assumed 10k events in RAM; the live ring is 512 slots
  since `813c87d`, and the durable history lives in SQLite rows, not ring
  memory.
- The budget is pinned by `the_live_ring_stays_within_its_memory_budget` in
  `rust/src/events.rs`.
- The per-flow cost half of that benchmark note is closed on the Sony by the
  on-device staircase below: ~1.2 KB of heap per live TCP relay, against the
  928 B the host-side `size_of` predicts.


## Flow traffic counters — per-flow memory (2026-11-02)

The v7 traffic table added a byte counter pair and a sink pointer to every
structure that owns a connection, so the plan's "per-flow cost" note now has a
host-side half. Measured as `size_of` on the current tree (a temporary worktree
would have been needed for the pre-v7 numbers; the delta is exactly the three
words added, so it is stated as arithmetic):

| Flow | Size | Added |
| --- | --- | --- |
| `mitm::relay::Relay` (TCP) | 928 B | `payload_to_client` + `traffic` = 16 B |
| `udpnat::UdpFlow` (datagram mapping) | 176 B | `sent` + `recv` + `traffic` = 24 B |
| `engine::H3Flow` (terminated QUIC) | 96 B | `sent` + `recv` + `traffic` = 24 B |

- Worst case for both datagram tables at the caps the engine enforces:
  `176 × UDP_MAX_FLOWS (512) + 96 × bridge::MAX_FLOWS (64)` = 94 KB, before this
  change 81 KB. The relay table has no cap constant, but its 16 B is the same
  order as the `template: Vec<u8>` each mapping already carried.
- The budget is pinned by `a_live_flow_carries_a_known_cost` in
  `rust/src/engine.rs`, next to the ring budget test.
- Write cost is one `try_send` per retired flow and one extra row in a batch the
  writer already commits: traffic rows ride the log writer's channel and share
  its transaction, so the number of fsyncs per second does not change. A flow
  that moved no bytes sends nothing.
- The on-device half of the note is the next section. The traffic totals
  themselves are non-zero on the Sony (160 KB up / 29.1 MB down after a browser
  download, 151 KB on one app).

## On-device per-flow memory (2026-11-04, Sony 802SO)

`bench/flows.c` holds a staircase of concurrent TCP flows inside the tunnel and
`bench/flowmem.sh` samples `dumpsys meminfo git.shin.adfree` on each tread, so
the cost of a live flow is read off the slope instead of inferred from
`size_of`. Run 2026-11-04 11:29-11:37 on the Sony 802SO (debug APK, AdFree
`439cb4a`-era tree, tunnel up, screen pinned on, charger): step 512, four
treads, 60 s hold each, `http` mode (a real `HEAD /` with `Connection:
keep-alive` on port 80, re-poked every 10 s), eight Google hostnames.

| Live relays | `heap_alloc` (KB) | Δ vs baseline | per flow | `native_pss` (KB) |
| --- | --- | --- | --- | --- |
| 0 (baseline ×3) | 79,296–79,434 | — | — | 23,058–23,178 |
| 512 | 79,327–79,569 | +64 | 0.13 KB | 22,966–23,230 |
| 1,024 | 79,707–79,963 | +439 | 0.43 KB | 23,210–23,442 |
| 1,536 | 80,597–80,814 | +1,362 | 0.89 KB | 24,046–24,175 |
| 2,048 | 81,804–81,998 | +2,549 | 1.24 KB | 25,179–25,623 |
| 0 (after release ×3) | 78,867–78,902 | −460 | — | 23,311–25,475 |

- **~1.2 KB per live TCP relay**, against `size_of::<Relay>() = 928 B` on the
  host. The remainder is the per-flow heap the struct points at: the raw SYN it
  keeps as its segment template and the payload staging buffers. A separate
  768-flow run (`bench/netflow.sh 768 120 80`) put the same figure at 0.90 KB
  (heap_alloc 78,581 → 79,275 KB across the samples taken at 768 live relays),
  so the two runs agree to within 40 %.
- **It is capacity, not a leak.** With the flows closed `heap_alloc` sits 460 KB
  *below* the pre-run baseline and `heap_size` returns to 86.2 MB from 88.9 MB —
  the allocator gave pages back. Nothing accumulates across treads.
- The first two treads are under the noise floor and should not be read as
  slopes. The process had been up 13 h with 123 MB of itself swapped, and
  `heap_alloc` drifts ~1.2 MB per 17 min at zero relays, which is larger than
  the 512-flow step. The marginal cost of the last tread (1,536 → 2,048) is
  2.32 KB/flow; the aggregate over 2,048 is 1.24 KB/flow.
- **The relay table tracks the client 1:1**: `client_flows` and `relay_flows`
  (established sockets on the harness uid and on the engine uid for that port,
  from `/proc/net/tcp`) were equal at every sample on every tread — 512/512,
  1,024/1,024, 1,536/1,536, 2,048/2,048. An earlier run held 2,020/2,018.
- Why that earlier run read 3.2 KB per flow over the 1,024 → 2,048 span: its
  baseline already carried 207 relays still retiring from the pass before it,
  and its 1,024-flow samples were taken against 1,217 live relays, so a
  half-loaded tread was differenced against a fully loaded one. Its liveness
  check was the broken one too, which is why that run timed out at stage 3.
  Re-measured with both fixed, the same span costs 2.32 KB/flow at the top
  tread and 1.24 KB/flow across the whole staircase.
- Extrapolated: 10,000 concurrent relays cost ~12 MB of heap. There is no relay
  cap in the engine (`rust/src/engine.rs`), only idle retirement at
  `RELAY_IDLE_MS = 300_000`, so the practical bound is the fd limit (32,768 here).
- Harness facts worth keeping: the flows must come from a uid the tunnel
  captures, and the live tunnel decides that list. `adb shell` (uid 2000) was
  outside it at the start of this pass because `files/capture-shell` had been
  written *after* the tunnel was built; rebuilding protection put 2000 inside
  (`Uids: <{0-10343, 10345-99999}>`, and the shell's `probe` then answered
  `gai=7` for blocked names). The measurement used a captured debuggable app uid
  regardless — `git.shin.komorei` — pushed with `run-as` and executed from that
  app's own data directory, because `/data/local/tmp` is not executable under
  `run-as`. A keep-alive socket always
  has an unread answer in its buffer, and a socket with data pending never
  reports the FIN behind it, so the harness drains before judging a socket dead
  (`alive()` in `bench/flows.c`); without that, stages read full while the
  tunnel had already retired the relays.

## Re-run — on the Sony 802SO, release against release (2026-11-02, evening)

Every table above this one was measured on the Redmi `flare`, which is not
connected. This run is on the Sony 802SO (Android 10, `msmnile`, 8 cores,
5,492 MB RAM, Wi-Fi "Tachibana Shin (ZTE)" at −64 dBm, on the charger). **None
of its absolute figures are comparable with the rows above** — different SoC,
different Android, different radio. Only the AdFree/AdGuard pairs within this
section mean anything.

- AdFree `8ea0c8c`. The latency and probe-CPU rows use the debug APK, because
  routing adb's traffic into the tunnel needs the debug-only
  `files/capture-shell` marker; the idle-CPU and RAM rows use the release APK,
  because AdGuard is a release app. Both were measured, and the difference is
  large enough that mixing them would have been a mistake — see Memory below.
- AdGuard **4.14.0** release, not the nightly 4.14.68 the Redmi rows used.
- No battery rows. The device sat at 100% on AC, which `Caveats` already calls
  noise.
- Two passes per app, interleaved (AdFree, AdGuard, AdFree, AdGuard), same
  network throughout.

| Metric | AdFree | AdGuard | Verdict |
| --- | --- | --- | --- |
| Blocked-host latency (per round, warm) | 1.6–11.4 ms (NXDOMAIN 6–16 ms, then cached) | 10.0–20.0 ms | AdFree 3–8× faster, but see *Blocking* below |
| Allowed-host latency (per round, warm) | 1.9–5.0 ms | 6.3–11.7 ms | AdFree ~2–4× faster |
| Allowed-host first round (cold cache) | 177.3 / 182.1 ms | 90.3 / 181.1 ms | parity |
| Allowed-host mean (per round) | 2.1–3.5 ms (outliers 118.6 / 205.7 / 279.2) | 6.5–11.8 ms | AdFree lower, no timeouts |
| CPU for the same 108 probes | 0.81 / 0.79 s | 1.82 / 1.68 s | AdFree ~2.2× lower |
| Background idle CPU (60 s windows) | 0.98 / 0.90 % | 0.52 / 1.97 % | parity on this device |
| Foreground idle CPU (20 s, screen on, app open) | 6.60 / 5.90 % | 24.40 / 25.05 % | AdFree ~4× lower |
| RAM background PSS (release, settled) | 89.1 MB (+0.1 MB swap) | 274.6 MB (+31.3 MB swap) | AdFree ~68 % lighter |
| RAM foreground PSS (release, app open) | 101.2 MB (+0.05 MB swap) | 275.9 MB (+31.3 MB swap) | AdFree ~63 % lighter |
| Cold lookups (median of 8 per round) | 81.5 / 97.5 ms | 84.5 / 88.5 ms | parity |

### Latency per round (probe totals, ms, 6 rounds × 18 names)

| Pass | Allowed median | Allowed mean | Blocked median | Blocked mean |
| --- | --- | --- | --- | --- |
| AdFree 1 | 182.1 / 2.2 / 2.9 / 3.3 / 2.3 / 2.5 | 195.5 / 2.5 / 3.0 / 3.5 / 2.7 / 2.6 | 16.1 / 6.9 / 204.5 / 1.8 / 1.9 / 1.6 | 74.4 / 6.1 / 279.2 / 1.8 / 2.0 / 1.8 |
| AdFree 2 | 177.3 / 2.2 / 1.9 / 5.0 / 2.3 / 2.0 | 197.5 / 2.4 / 2.1 / 205.7 / 2.1 / 2.1 | 11.4 / 6.3 / 6.2 / 1.9 / 1.9 / 1.8 | 33.6 / 5.3 / 118.6 / 1.9 / 1.7 / 1.6 |
| AdGuard 1 | 181.1 / 6.3 / 9.6 / 11.5 / 11.2 / 11.4 | 177.9 / 6.6 / 9.1 / 11.8 / 11.1 / 11.4 | 16.1 / 12.0 / 15.4 / 15.8 / 15.6 / 15.3 | 36.0 / 10.6 / 13.0 / 14.3 / 15.4 / 14.7 |
| AdGuard 2 | 90.3 / 10.4 / 10.1 / 11.7 / 6.3 / 6.8 | 105.3 / 10.4 / 10.2 / 11.8 / 6.5 / 6.6 | 20.0 / 10.8 / 15.8 / 16.4 / 7.2 / 10.0 | 25.1 / 9.1 / 14.5 / 14.9 / 6.7 / 9.2 |

Round 1 is the cold cache for both apps and both settle to steady values by
round 3. AdFree's warm figures are 2–3 ms because the answer comes from its DNS
cache; AdGuard's are 6–12 ms, which is a per-query round trip through its own
stack rather than a cache hit. AdFree's blocked-host rounds 3–5 are ~1.8 ms for
the same reason — those are cached `0.0.0.0` answers, not the 6–16 ms NXDOMAIN
path.

### Blocking under a repeated-name burst

Of the 48 blocked probes, AdGuard returned NXDOMAIN for **48/48**. AdFree
returned NXDOMAIN for 24/48, `0.0.0.0`/`::` for 20/48 (the client fails with
`ECONNREFUSED`, so the request still dies), and let **4/48 connect** — all four
`zq8f8.adnxs.com`, the same retry-loop name the 2026-10-29 notes describe. This
is the smart filter (5 blocks in 10 s → allow for 60 s) doing what it is
configured to do against a harness that asks for the identical name twelve times
in a minute; `smartFiltering` is on in the settings that produced these rows.
AdGuard has no equivalent window, so on a repeated-name probe it blocks more
consistently than AdFree. Latency comparisons above should be read with that:
AdFree's fastest blocked rounds are the ones where it had stopped answering
NXDOMAIN.

That asymmetry is gone in the shipped configuration: with smart filtering off by
default the same harness returns 48/48 NXDOMAIN on the same device, so AdFree
blocks as consistently as AdGuard here. See
`Re-run — smart filtering off by default (2026-11-03, Sony 802SO)`.

### Memory, and why the build type mattered

| Build | Background PSS | swap PSS | Foreground PSS | swap PSS |
| --- | --- | --- | --- | --- |
| AdFree release | 89.1 MB | 0.1 MB | 101.2 MB | 0.05 MB |
| AdFree debug | 155.7–157.3 MB | 0–94.6 MB | 166.2–170.3 MB | 0.05–94.6 MB |
| AdGuard 4.14.0 | 254.8–289.1 MB | 0.01–31.3 MB | 264.8–292.8 MB | 0.01–31.3 MB |

The debug build nearly doubles AdFree's resident set (`.dex`/`.oat` `Code` alone
is 74.2 MB against AdGuard's 49.5 MB) and gets 83–97 MB of itself swapped out on
this device, which would have made the release-versus-release comparison a coin
flip. Composition at rest with protection on, release AdFree against AdGuard:

| | AdFree | AdGuard |
| --- | --- | --- |
| Native heap | 14.7 MB PSS (69.6 MB heap) | 164.1 MB PSS (178.0 MB heap) |
| Java/Dalvik heap | 6.4–8.2 MB | 63.3–69.1 MB |
| Code (dex + so mmap) | 68.5–74.2 MB | 38.0–49.5 MB |
| Graphics | 1.9–16.0 MB | 2.5–17.0 MB |

AdFree's engine holds the same seven lists (ag-base, ag-mobile-ads, ag-tracking,
ag-dns, oisd, abpvn plus user rules) on the same resolver
(`dnsProvider: adguard_default`, backup `8.8.8.8`, `blockMode: NXDOMAIN`,
`https: true`) as the Redmi runs, so the difference is the app, not the setup.

AdGuard with its protection switched off still sits at 145.0 MB PSS plus 63.3 MB
swapped — its at-rest footprint alone is close to AdFree's footprint with the
tunnel running.

### Cold lookups

`nc -z -w 5 <unique>.127.0.0.1.nip.io 443`, eight fresh names per round, three
rounds per pass. The method still carries the ~50 ms fork/exec cost `Notes`
describes, so subtract it before reading these as resolver latency.

| | AdFree | AdGuard |
| --- | --- | --- |
| Median (pass 1 / pass 2) | 81.5 / 97.5 ms | 84.5 / 88.5 ms |
| Range | 68–179 ms | 74–121 ms |

The 2026-10-29 Redmi run had AdFree at ~220 ms against AdGuard's ~140 ms, which
it attributed to the 100 ms hedge firing because `94.140.14.14` took 350 ms+ on
a cold name. From this network the primary answers inside the hedge window, so
the hedge never fires and the two apps are at parity. The Redmi observation about
the hedge stands; it is a property of that uplink, not of the code.

### What this run changes

- **Foreground idle CPU is a UI cost, not an engine cost.** With the screen
  pinned on, AdFree's home screen uses ~6 % of one core and AdGuard's ~25 %.
  On the Redmi both apps measured ~10 %. The figure ranks the toolkits on this
  device and should not be quoted as a protection-engine number.
- **Background idle is parity here**, 0.9–1.0 % against 0.5–2.0 %, whereas the
  Redmi rows had AdFree 3–10× below AdGuard. AdGuard's background cost varies
  more between windows than AdFree's does, so the honest read is "same order"
  rather than a win for either side.
- **The probe latency rows now measure the cache**, which they did not on the
  Redmi. Warm allowed lookups cost 2–3 ms in AdFree and 6–12 ms in AdGuard
  because AdFree answers from its DNS cache inside one round trip.
- Battery remains unmeasured on a charging device. The per-flow on-device memory
  probe that used to be listed with it is done — see *On-device per-flow memory*
  above; it needed a captured uid, not the Redmi.

### Measurement traps found while doing this

- **Pin the screen state for foreground idle.** The first three foreground
  windows in this session read 43.9 %, 89.8 % and 213.9 % of a core, which is
  not what either app does: the display had been turned off by a
  `KEYCODE_SLEEP` left in a helper, and `monkey` launch transitions were being
  sampled as "idle". Re-measured with `Display Power: state=ON` and
  `svc power stayon true`, the same window gives 6 % and 25 %.
- **Verify the tunnel, then verify it again after every handover.** Only one
  VPN can run, so switching apps silently leaves the second app's protection
  off. Each pass starts by asserting `tun0` carries that app's address
  (AdFree `10.111.42.1`, AdGuard `172.18.11.218`) and that a real, publicly
  resolvable ad host (`pagead2.googlesyndication.com`) comes back `gai=7` in
  11–18 ms. One AdGuard idle pass was thrown away because its switch tap did
  nothing and it measured the app at rest.
- **`/proc/<pid>/stat` needs the comm prefix stripped** (`sed 's/.*) //'`)
  before picking fields 12 and 13 — AdGuard's comm is `adguard.android` and a
  quoted path with an unquoted pid expands to `cat /proc/24660 /stat`, which
  reads as zero ticks and looks like an idle app rather than a broken parser.
- **Android 10 has no `TOTAL PSS:` label.** `dumpsys meminfo <pkg>` prints the
  per-process details table row `TOTAL <pss> <privateDirty> <privateClean>
  <swapPssDirty>`; the `App Summary` row is `TOTAL:` with a colon. Grepping the
  historical `TOTAL PSS` string silently returns nothing.


## Re-run — smart filtering off by default (2026-11-03, Sony 802SO)

AdFree `e7430ef` (debug APK), AdGuard not re-measured in this pass. Same device,
same network and the same harness as the 2026-11-02 release-vs-release section:
`bench/probe.c` rebuilt with
`aarch64-linux-android26-clang -O2`, 6 rounds × (10 allowed + 8 blocked) = 108
probes, `files/capture-shell` marker in place so the shell's traffic goes
through the tunnel, protection restarted after the marker, app backgrounded.

The one thing this pass exists to answer is the leak the 2026-10-29 and
2026-11-02 notes both recorded: `zq8f8.adnxs.com` connecting because the smart
filter had opened its 60 s allow window. The filter is now off by default and
its trigger is per `(host, uid)` at 7 blocks in 10 s, so the shipped
configuration was measured, not a tuned one.

| | This pass | 2026-11-02 pass (smart filtering on) |
| --- | --- | --- |
| Blocked probes | **48/48 NXDOMAIN, 0 connected** | 44/48 (4 `zq8f8.adnxs.com` connected) |
| Allowed probes | 60/60 OK | 60/60 OK |
| Blocked-host median total | 8.6 ms (max 197.7 in round 1) | 11.4–204.5 ms across rounds |
| Allowed-host median total | 2.6 ms (max 225.1 in round 1) | 2.0–5.0 ms across rounds |

Every one of the eight names — `doubleclick`, `googlesyndication`,
`google-analytics`, `scorecardresearch`, `criteo`, `taboola`, `outbrain`,
`adnxs` — returned `gai=7` in all six rounds, so the tunnel answered NXDOMAIN
and the connect never started. That is the same consistency AdGuard showed in
the section above (48/48), which is the parity claim the earlier notes could not
make.

Round 1 carries the cold cache on both classes, which is why the maxima sit near
200 ms while rounds 3–6 are the 2–3 ms cache-hit path the previous section
describes. One pass, no repeat: the blocking count is the result being recorded,
the latency figures are informational.

Two things this pass does not measure, and why:

- **CPU and RAM.** The rows in the earlier sections are release-APK figures, and
  the marker file that lets the shell's probes reach the tunnel only exists in a
  debug build. Re-running the RAM comparison would mean giving up the marker, so
  this section deliberately quotes neither. It has since been measured, on the
  same device the same evening, against a release AdFree and with a real-traffic
  workload that needs no marker at all:
  see `Re-run — CPU and RAM on HEAD, release against release (2026-11-03)`.
- **The upgrade path.** `smartFiltering` is persisted per device, so an install
  that had it on keeps it on after the default changes — this very device had
  `true` stored and needed the switch turned off by hand before the pass. A fresh
  install gets off, and only a pre-schema legacy profile is forced off at
  migration (`rust/src/state/legacy.rs`); a blob already on the current schema
  keeps exactly what it stored. The row's subtitle states the shipped default in
  both locales.


## Re-run — CPU and RAM on HEAD, release against release (2026-11-03, Sony 802SO)

The CPU and RAM rows in `Re-run — on the Sony 802SO` were measured at `8ea0c8c`
with smart filtering **on**, and everything shipped since then has a footprint:
MITM stealth edits, the services breakdown query, the tunnel rebuild, the mask-IP
header. The parity claim is about the app as shipped now, so it was re-measured
at HEAD (`ffb2d43`; the last commit that touched code is `ad874fe`, and the debug
build the device was already running had been installed from that same tree)
against the same AdGuard **4.14.0** release APK already on the device.

- AdFree: `app-release.apk` built 18:30, installed over the debug build at
  18:31:55. Both variants are signed with the SDK debug key, so `install -r`
  kept the store: the `filters` row is byte-identical to the copy taken before
  the switch and the `protection` row is value-identical. Release because
  AdGuard is a release app and the debug build nearly doubles AdFree's resident
  set (the table in *Memory, and why the build type mattered*).
- Settings during the pass, read back from the store afterwards:
  `is_smart_filtering_enabled = false`, `is_https_filtering_enabled = true`,
  `is_dns_protection_enabled = true`, `is_eco_battery_mode_enabled = true`,
  `log_allowed_requests = true`, `log_level = warn`, stealth master off,
  `show_services_breakdown = false`, six catalog lists on.
- AdGuard: protection toggled from its own main screen, `tun0` asserted at
  `172.18.11.218` per pass; AdFree's asserted at `10.111.42.1` per pass.
  `svc power stayon true` and `Display Power: state=ON` pinned before any
  window, as the traps section demands.
- Two interleaved passes per app: AdFree, AdGuard, AdFree, AdGuard.

### The workload is Chrome, not the probe

The old CPU row was "CPU for the same 108 probes", and a probe cannot be used
against a release AdFree: `capture-shell` is gated on `BuildConfig.DEBUG`
(`AdGuardVpnService.kt:344`), so in release the shell is always excluded from
the tunnel and the probe's traffic never reaches the engine. AdGuard has no such
exclusion — `adb shell ping pagead2.googlesyndication.com` returns
`unknown host` through its tunnel — so a probe pass would compare AdGuard's
tunnel against AdFree's idle one.

The workload is therefore twelve real pages loaded in Chrome, which is inside
every VPN: `vnexpress.net`, `cafef.vn`, `kenh14.vn`, `24h.com.vn`, `soha.vn`,
`genk.vn`, `youtube.com`, `github.com/adblockplus`, one Wikipedia article,
`cloudflare.com`, `apple.com/vn`, `microsoft.com/en-vn`, each with
`?adfreebench=<pass>` to defeat the HTTP cache, 10 s apart, Chrome force-stopped
before each sweep so no socket pool carries over. Chrome's own tick delta is the
control that both apps were handed a comparable page set: 1096 / 1062 on the
AdFree passes, 1017 / 1062 on the AdGuard passes — within 8 %.

### Results

| Metric | AdFree | AdGuard | Verdict |
| --- | --- | --- | --- |
| Background idle CPU (60 s windows ×4) | 0.70–1.07 %, median **0.83** | 0.63–3.75 %, median **0.74** | parity, AdGuard noisier |
| Foreground idle CPU (20 s windows ×4) | 5.55–10.55 %, median **7.10** | 22.95–24.25 %, median **23.27** | AdFree ~3.3× lower |
| CPU over the 12-page sweep | 2.77 s / 2.65 s | 12.96 s / 7.70 s | AdFree 2.9–4.7× lower |
| Sweep cost as % of one core | 2.50 % / 2.39 % | 11.57 % / 6.88 % | |
| Background PSS (settled) | 85.8–108.6 MB, median **94.9** | 254.6–289.2 MB, median **264.9** | AdFree **64 % lighter** |
| Foreground PSS | 101.3–105.1 MB, median **101.7** | 278.0–286.2 MB, median **281.2** | AdFree **64 % lighter** |

Every window, in order, with the device uptime stamped on it:

| Pass | Window | Ticks | % of a core | TOTAL PSS | Swap PSS | Uptime |
| --- | --- | --- | --- | --- | --- | --- |
| AdFree 1 | bg 60 s | 49 | 0.82 | 100.8 MB | 60.6 MB | 533 s |
| AdFree 1 | bg 60 s | 42 | 0.70 | 85.8 MB | 53.8 MB | 593 s |
| AdFree 1 | fg 20 s | 211 | 10.55 | 102.0 MB | 46.8 MB | 637 s |
| AdFree 1 | fg 20 s | 142 | 7.10 | 105.1 MB | 46.6 MB | 658 s |
| AdFree 1 | sweep 111 s | 277 | 2.50 | — | — | 788 s |
| AdGuard 1 | bg 60 s | 41 | 0.68 | 289.2 MB | 0.005 MB | 1217 s |
| AdGuard 1 | bg 60 s | 48 | 0.80 | 262.8 MB | 0.004 MB | 1277 s |
| AdGuard 1 | fg 20 s | 460 | 23.00 | 283.2 MB | 0.004 MB | 1322 s |
| AdGuard 1 | fg 20 s | 485 | 24.25 | 278.0 MB | 0.004 MB | 1343 s |
| AdGuard 1 | sweep 112 s | 1296 | 11.57 | — | — | 1478 s |
| AdFree 2 | bg 60 s | 64 | 1.07 | 108.6 MB | 0.005 MB | 1689 s |
| AdFree 2 | bg 60 s | 51 | 0.85 | 88.9 MB | 0.003 MB | 1750 s |
| AdFree 2 | fg 20 s | 142 | 7.10 | 101.4 MB | 0.003 MB | 1783 s |
| AdFree 2 | fg 20 s | 111 | 5.55 | 101.3 MB | 0.003 MB | 1804 s |
| AdFree 2 | sweep 111 s | 265 | 2.39 | — | — | 1935 s |
| AdGuard 2 | bg 60 s | 38 | 0.63 | 266.9 MB | 24.9 MB | 2089 s |
| AdGuard 2 | bg 60 s | 225 | 3.75 | 254.6 MB | 34.6 MB | 2150 s |
| AdGuard 2 | fg 20 s | 459 | 22.95 | 286.2 MB | 34.6 MB | 2193 s |
| AdGuard 2 | fg 20 s | 471 | 23.55 | 279.1 MB | 34.6 MB | 2214 s |
| AdGuard 2 | sweep 111 s | 770 | 6.94 | — | — | 2337 s |

Both apps really filtered the sweep, which is the assertion that makes the CPU
row mean anything: AdFree's home counters went 136 → 199 ads and 257 → 474
trackers across its pass-1 sweep, and AdGuard's own card went 488 → 2,363
blocked and 34 MB → 141 MB saved across its two.

### Composition at rest, from the `App Summary` block

| | AdFree bg | AdFree fg | AdGuard bg | AdGuard fg |
| --- | --- | --- | --- | --- |
| Java heap | 7.9 MB | 8.2 MB | 68.1 MB | 65.6 MB |
| Native heap | 61.2 MB | 61.2 MB | 131.3 MB | 132.4 MB |
| Code | 9.6 MB | 8.1 MB | 10.2 MB | 22.0 MB |
| Graphics | 2.8 MB | 16.2 MB | 3.4 MB | 17.1 MB |
| System | 3.5 MB | 3.6 MB | 37.4 MB | 37.6 MB |
| **TOTAL PSS** | **88.9 MB** | **101.3 MB** | **254.6 MB** | **279.1 MB** |

The shape is the same as the 2026-11-02 run: AdFree's entire background footprint
(88.9 MB) is only 21 MB more than AdGuard's Java heap alone (68.1 MB), and
AdGuard carries 37 MB of `System` that AdFree does not. AdFree's native heap is
61 MB here against the 14.7 MB PSS that run recorded at the same heap size
(69.6 MB) — pages freshly touched by the engine, not a growth in what it holds.

### What this run changes

- The RAM claim now belongs to HEAD and to the shipped configuration: AdFree is
  **64 % lighter than AdGuard in both states**, at 95 MB against 265 MB in the
  background and 102 MB against 281 MB in the foreground. It repeats the
  2026-11-02 result (68 % / 63 %) rather than contradicting it, which is the
  point: a dozen stages of features did not move the ratio.
- Foreground idle CPU is still a UI cost, not an engine cost, and the gap is
  narrower than the 2026-11-02 run measured: 7.1 % against 23.3 % here (3.3×)
  where that run had 5.90 % against 25.05 % (4.3×). AdFree's first foreground
  window reads high in both passes (10.55 % then 7.10 %, against 7.10 % and 5.55 %
  for the windows after them); the cause was not isolated, so the second window
  is the number to quote.
- The sweep row is the closest thing this harness has to an engine cost under
  real traffic, and it is the one row that moved: AdGuard's two sweeps differ by
  1.7× (12.96 s against 7.70 s) while AdFree's differ by 4 %. Read AdFree as
  ~2.5 % of a core for twelve page loads, AdGuard as 7–12 %.
- AdGuard's 3.75 % background window is the noisiest single reading in either
  series and the pass that produced it also shows its swap PSS climbing from
  0.004 MB to 34 MB. What ran inside it was not identified; the honest read of
  the background row is "same order, AdGuard occasionally does something".

### Two new traps found doing this

- **A reboot in the middle of a pass invalidates every window before it.** The
  device kernel-panicked at 18:43:21, during the first sweep attempt:
  `ro.boot.bootreason = kernel_panic,sysrq`, and
  `persist.sys.boot.reason.history` shows a second entry at 2026-11-02 11:53:38,
  so this is the device, not the measurement — `/sys/fs/pstore` is not readable
  without root, so the panic itself cannot be attributed to anything. The four
  windows taken before it (0.55 %/1.68 % background, 5.55 %/4.40 % foreground,
  90.1/83.8 MB and 96.4/96.0 MB PSS) are quoted nowhere above: the pass was
  restarted from the cold boot so that every row shares one device state, and
  each window now carries its uptime stamp so a reboot cannot pass unnoticed.
- **A pid captured before a handover can be recycled.** During the AdGuard pass
  the harness still held AdFree's old pid, and by then that number belonged to a
  different process, so its "CPU" came back as −2,565 ticks. A negative delta is
  pid reuse, not an idle app. `win.sh` now refuses a window whose pid changed
  under it instead of reporting a number.

## Anti-DPI hello splitting — cost per connection (2026-11-03, Sony 802SO)

The stealth feature that had no number was `anti_dpi`: it writes the TLS
ClientHello into two segments (24 bytes, then the rest) so a DPI box cannot see
a handshake in one packet. The split is `rust/src/mitm/relay.rs:55,241-249` and
the two-send flush is `rust/src/engine.rs:3310-3345`; the gate is
`StealthFlags::fragments_hello()` (`rust/src/engine.rs:288-290`), published per
config apply at `rust/src/engine.rs:1181-1182`. It was switched on and off on the
device with the rest of stealth left identical, and each state measured through
the tunnel.

Harness: the debug `capture-shell` marker (`app/src/main/kotlin/git/shin/
adfree/vpn/AdGuardVpnService.kt:343-348`) routes the shell uid through the VPN so
`curl` runs inside a relay, and the flow is a passthrough — TLS ends at
google.com, so `time_appconnect − time_connect` is the real handshake, not a
local re-encryption. Command per round:
`curl -k -s -o /dev/null -w '%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{http_code}\n' https://www.google.com/generate_204`,
12 rounds per block, 0.4 s apart, run A/B/A/B so a drift in the radio or the
upstream cannot masquerade as a feature effect. All rows returned `204`.
Medians, milliseconds:

| Block | anti-DPI | n | DNS | connect | TLS done | handshake | TTFB |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A | off | 12 | 7.3 | 9.3 | 21.2 | 10.6 | 126.6 |
| B | on | 12 | 5.4 | 7.0 | 19.0 | 11.6 | 136.3 |
| A2 | off | 12 | 8.0 | 9.9 | 20.6 | 10.5 | 137.8 |
| B2 | on | 12 | 5.4 | 7.0 | 18.8 | 11.7 | 138.5 |
| pooled | off | 24 | 7.8 | 9.8 | 20.9 | **10.5** | **130.5** |
| pooled | on | 24 | 5.4 | 7.0 | 18.9 | **11.7** | **138.3** |

- The handshake column is the only one this feature can move, and it moves by
  **+1.2 ms**. That is reproducible rather than a fluke: the two off blocks agree
  to 0.1 ms (10.6 / 10.5) and the two on blocks agree to 0.1 ms (11.6 / 11.7),
  so the gap holds across both repeats.
- End-to-end TTFB is **not** a cost. The pooled on−off difference is 7.8 ms,
  which is smaller than the 11.2 ms difference between the two identical off
  blocks (126.6 vs 137.8) and far inside the per-round spread (108 ms to
  604 ms across 48 rounds). Read the TTFB row as unchanged.
- The reason it is 1.2 ms and not a retransmit or a full RTT is that every peer
  socket gets `TCP_NODELAY` (`rust/src/engine.rs:3188-3202`), so the 24-byte
  head leaves immediately and the two segments are one small packet of extra
  work, not a Nagle wait.
- DNS and connect are lower in both on-blocks (5.4 / 7.0 vs 7.3–8.0 / 9.3–9.9).
  anti-DPI cannot make DNS faster — it only touches a ClientHello — so that pair
  is block ordering, not an effect, and it is the honest counter-evidence to
  reading a 12-round median as a precision instrument. It is why the conclusion
  rests on the two repeats agreeing, not on the pooled direction.

So: 1.2 ms per connection, once per connection, invisible against a 130 ms first
byte. Nothing here argues either way about the default — `anti_dpi` ships off
(`ProtectionSettings().antiDpi` is false, asserted at
`app/src/test/kotlin/git/shin/adfree/data/ProtectionStateMappingTest.kt:44`) and
no privacy level writes it, by design
(`app/src/main/kotlin/git/shin/adfree/model/StealthPreset.kt:107-110`: a level
promises what a site sees, and splitting the handshake changes only what a
middlebox sees). A user who turns it on pays 1.2 ms to look at and nothing
measurable to wait for.

Device restored: marker removed and the tunnel rebuilt without it (`Uids:` range
excludes uid 2000 again), stealth master and `anti_dpi` back to off, store
byte-identical to the pre-pass snapshot, `stay_on_while_plugged_in` back to 0.

## Client-port collisions and the refusal nobody receives (2026-11-04, Sony 802SO)

`flowcpu.sh` priced a relay that already exists. This is the other half: the cost
of *reaching* N live relays, which turned out to grow faster than N and to be
caused by the relay table's key rather than by any per-flow work.

The relay table is `HashMap<u16, Relay>` keyed by the client's source port alone
(`rust/src/mitm/relay.rs:581-583`), and `relay_tcp` treats a port hit on a
live relay as a SYN retransmission (`rust/src/engine.rs:2571-2606`) — so it answers
the new SYN from the *stored* `syn_packet` template. A port is not a flow: the
kernel hands the same source port to a socket bound for another address as soon as
the 4-tuple differs, and on a ramp opening 2048 flows over six destinations that
landed on 5.1% of the attempts it made (110 refused or timed out against 2158) —
not a tail event. The answer then goes to the other flow's address
pair, the new socket never sees its SYN-ACK, and it waits out its own timeout.

Harness: `bench/flows` (`bench/flows.c`) in `nudge` mode under the helper uid
(`git.shin.komorei`, 10309) inside the tunnel, six destinations, staged 512 → 2048
with a 20 s hold per stage; both halves of every flow counted from
`/proc/net/tcp` (uid 10344 = the origin half the engine dials, uid 10309 = the
client half). `missed` counts connects that returned anything but success.

| Run | wall at stage lines 1/2/3/4 | missed at those lines |
| --- | --- | --- |
| before | 14 / 85 / 185 / 284 s | 6 / 31 / 71 / 110 |
| tuple check only | 1 / 20 / 41 / 61 s | 0 / 0 / 0 / 0 |
| both refusal fixes | hold-bound (~60 s) | 3 / 32 / 83 / 159 |

The before-row is the superlinearity: 110 misses × the harness' 2 s connect timeout
≈ 220 s of the 284 s wall, and the shape is exactly a sum of timeouts. The 61 s row
is the four 20 s holds plus ~1 s of real fill, so the tuple check removed the
stalls — and its `missed 0` needed explaining, because the model predicted refusals,
not silence.

Three alternatives were refuted rather than assumed:

- **tun queue overflow.** Across the whole 284 s burst `tun0` read
  `rx_drop=0 tx_drop=0` (`/proc/net/dev`, fields 5 and 13), so nothing was being
  discarded for a full queue. A non-blocking `write()` returning `EAGAIN` would be
  invisible there, which is why the collision probe below was built.
- **the engine's own load.** Run from the app's own uid (10344, which the VPN's
  `Uids: <{0-1999, 2001-10343, 10345-99999}>` range excludes, so the tunnel is out
  of the path entirely) the same ramp showed `missed 0` and pure RTT pacing.
- **one destination.** Six hosts in-tunnel stalls, one host in-tunnel does not —
  which is what a *port* collision predicts and what a queue or a CPU limit does
  not.

### Making the collision deliberate

`bench/dport.c` (`bench/dportrun.sh` watches `/proc/net/tcp` on both uids while it
runs) binds one socket per destination to the *same* local port, so the collision
is asked for rather than waited for. Four sockets, port 80, four Google hosts:

| Build | refused flow's `connect()` | its state at t+2/4/6 s | engine→origin sockets |
| --- | --- | --- | --- |
| before | 1 ms, success | ESTABLISHED, silent (`again`) | 1 of 4 |
| after | 1 ms, `ECONNRESET` (104) | gone | 1 of 4 |

Same with a byte written on each socket: before, all four stayed ESTABLISHED and
silent for the whole 6 s; after, the port owner keeps its relay and the other three
are dead by t+2 s. The one engine socket across four client sockets is the point —
the table carries one flow per port, and the rest are answered and then refused.

### The two bugs, and why the second hid the first

The tuple check (`Relay::serves`, `rust/src/mitm/relay.rs:248-270`, and the three
lookups in `relay_tcp`) makes the colliding SYN fall through to
`begin_tcp_relay` (`rust/src/engine.rs:2783-2840`), which answers it from *its own*
packet — correct address pair, so `connect()` succeeds — and then refuses it through
`refuse_answered_flow` because the port is taken. That refusal was never received:

- `refuse_answered_flow` (`rust/src/engine.rs:3532-3540`) built the reset with
  `seq = my_seq`. The SYN-ACK it follows *is* `my_seq` and consumes that number, so
  the client's `rcv_nxt` is `my_seq + 1` and the reset sits one below the window:
  discarded. `Relay::rst_to_client` (`rust/src/mitm/relay.rs:526-530`) already got
  this right through `flow.up_bytes`; this is the same rule stated a second time,
  in the one place it was missing.
- `packet::build_rst` (`rust/src/packet.rs:529-572`) acknowledged
  `seq + 1 + payload`: the `+1` is the SYN's number, added to data and FIN segments
  too, so its ack landed one past the sender's `snd_nxt`. A stack validates the
  acknowledgement before it reads the reset, so every reset this builder sent *in
  answer to data* was dropped as a bogus ACK (and drew a challenge ACK back).
  Resets in answer to a SYN were always fine, which is why the blocked-host path —
  the refusal the UI reports — never looked broken.

Together these are the reason "answered, then refused" looked identical to
"served": the client's stack is left holding an ESTABLISHED socket with nothing
behind it. That is not a slow path, it is the whole of `refuse_setup` — the
per-app firewall cutting a flow, a `connect()` that failed, a TLS session that
would not open (`rust/src/engine.rs:2865-2959`) — so every one of those decisions
was recorded in the UI while the app kept waiting. Both fixes are one number each;
`a_refused_flow_resets_with_the_answered_sequence`
(`rust/src/engine.rs:7401-7437`) had been asserting the first one *wrong*, which is
the cost of writing a sequence rule from prose instead of from a client that reads
it. The tests now pin the numbers: `rust/src/engine.rs:7448` (collision: SYN-ACK on
the right pair, then a reset naming `syn_ack.seq + 1`, one relay kept) and
`rust/src/packet.rs:885` (ack for a SYN, a data segment, a FIN, data+FIN).

### What the limit now costs

Single-stage ramp, same six destinations:

| target | wall | missed | missed / attempts |
| --- | --- | --- | --- |
| 256 | 1 s | 0 | 0% |
| 512 | 1 s | 4 | 0.8% |
| 1024 | 2 s | 39 | 3.7% |
| 2048 | 2 s | 224 | 9.9% |

and the `http`-mode staircase to 4096 (`flowmem.sh 1024 4 30`) shows 137 / 307 /
515 / 814 misses at 1024 / 2048 / 3072 / 4096 — ~12–17% of attempts, each retried
into a fresh port and each stage still reaching its live target. A miss now costs
~1 ms rather than 2 s, which is why 2048 opens in 2 s: 2272 attempts at 2 s each
could not fit in it.

The table is still keyed by client port, so two flows that share a port cannot both
be carried — this fixes the *failure mode*, not the ceiling. Keying by tuple is the
ceiling's fix and `client_port` appears in 47 places in `engine.rs` (poll snapshot,
`push_to_peer`, `half_close_peer`, the reap path all address a relay by port), so it
is a separate change with its own measurement, not something to fold into a bug fix.

Two side observations, both from the same staircase:

- A relay is 1040 B now, and `flow_key` is what pushed it over the old bound:
  `Option<FlowKey>` measures 80 B (`client` and `peer` are `IpKey`, which is 32 B
  because of its `V6(u128)`), so `a_live_flow_carries_a_known_cost` moved its bound
  1024 → 1040 to keep the number pinned. Against the 1.2 KB/flow measured on device
  that is a few percent of a flow's cost, paid to stop a stall that measured 2 s
  per hit.
- Idle relays are not the leak it looked like. A run of 1024 leftover origin
  sockets was visible 90 s after its harness was killed (`RELAY_IDLE_MS` is 300 s,
  `rust/src/engine.rs:5538`), but at every stage transition — clients 4096 → 0 —
  `relay_flows` went 249 → 0 inside 15 s: the FIN path retires relays promptly and
  the idle timer is the backstop, not the routine.

Impact before editing: `refuse_answered_flow` is **CRITICAL** (6 symbols, 6
execution flows, 3 modules — it is the tail of every refusal the engine makes);
`packet::build_rst` and `segment::build_rst` are LOW (5 and 8 symbols). 827 unit
tests plus the integration suites pass; `cargo clippy` shows the same six
pre-existing warnings and nothing at the edited sites.

Device restored: `stay_on_while_plugged_in` back to 0, the helper's `files/` down
to `profileInstalled`, the app's harness copies (`flows_direct`, its log) removed,
protection left running with the tunnel up, density override left at the as-found
240. No setting was written this pass — the `protection` row still reads
`is_stealth_mode_enabled:false, anti_dpi:false`. The store's durable log does carry
the rows the harness traffic wrote.

## What a pass over the relay table is worth, and what a packet copy is worth (2026-11-04, host release build + Sony 802SO)

The collision pass named four hot-path candidates and fixed none of them for want
of a number. Three now have one, and they did not all come out the same way: one
was a real cost and is fixed, one was predicted by the shape of the loop and is
refuted, one is real but too small to be worth its call sites.

### The config every packet copied — fixed

`handle_packet` opened with `let cfg = self.cfg.read().unwrap().clone()`
(`rust/src/engine.rs:1889`, which now reads `self.config_ref()`): a deep copy of `Config`, made on
the path every tun packet takes — DNS, relay, STUN alike — to read about thirty
switches. Measured on the host in the release profile, 300k iterations of the
read-and-clone itself:

| config | copied per packet | `Arc` per packet |
| --- | --- | --- |
| shipped defaults (`Config` is 112 B, empty host lists) | 116.4 ns | 99.0 ns |
| 64 skip hosts + 64 only hosts | 17474.8 ns | 58.7 ns |

The first row is noise: a 112-byte copy is not worth talking about, and most of
both numbers is the `RwLock` read. The second is not, because `Vec<String>` clones
element by element — one buffer plus one `String` per host, 130 allocations — so a
phone whose owner filled in the HTTPS allowlist was paying 17.5 µs on every packet,
including the packets that never consult the lists. The store is now
`RwLock<Arc<Config>>` (`rust/src/engine.rs:730-734`) and the packet path takes the
`Arc` through `Core::config_ref`; `config()` still hands out a copy, which is what
its twelve callers — all of them tests that edit one — need.
`the_packet_path_shares_one_config_snapshot` pins the identity: two reads must be
the same allocation, and a `set_config` must produce a different one.

What this does *not* remove is the ~99 ns lock read, and going below it is where
this pass stopped deliberately: holding the guard across the dispatch instead of
cloning would nest the same read lock in `relay_udp` (`:2017`), `h3_info` (`:2324`)
and `log_event` (`:4427`), and `std::RwLock` deadlocks on a nested read as soon as
a writer queues between the two — a `set_config` from the UI thread is exactly that
writer.

### The per-pass sweep — refuted

`forwarder_loop` calls `prune_relays` on every pass (`rust/src/engine.rs:5081`),
and `prune_relays` walks the whole relay table (`:5558`), so the upkeep work is
quadratic in the number of relays if the passes themselves grow with the table.
That is a shape, not a measurement, so the shape was tested by switching it off:
a build with `prune_relays` returning immediately, against the committed build,
`bench/flowcpu.sh` at the same specs, 40 s windows, the forwarder identified by its
system-time bulk (it is the thread named `adfree-dns`, which runs
`forwarder_loop` — `rust/src/engine.rs:1758-1762`).

| run | live relays | tun0 packets in the window | forwarder | of which sys |
| --- | --- | --- | --- | --- |
| sweep on, 1024 opened | 357 | 2763 in / 3204 out | 2290 ms | 1980 ms |
| sweep off, 1024 opened | 460 | 2625 in / 3123 out | 2010 ms | 1840 ms |
| sweep on, 2048 opened | 603 | 4670 in / 5266 out | 5640 ms | 4970 ms |
| sweep off, 2048 opened | 724 | 4444 in / 4714 out | 5790 ms | 5180 ms |

Removing the sweep entirely moves the forwarder by less than the gap between two
runs of the same build, and the no-sweep runs are the ones with *more* entries in
the table — closed relays are only reaped inside the sweep, so they stayed counted
(724 against 603). The app's fd ceiling is 32768 (`/proc/<pid>/limits`), so the
no-sweep run was not being throttled by descriptors instead. The sweep is not the
cost.

Two things fall out of the same table. The first is a correction to
`bench/flowcpu.sh`, whose header says a `nudge` hold is quiet: it is not. The bare
`\n` the harness writes is a request the origins answer — with the clients silent
for the whole window, 2763 packets still arrived through the tunnel at 1024 and
4670 at 2048 — so 150-250 packets a second cross during a "quiet" window, and
`per_relay` is a hold-plus-answer number. The script now samples `tun0` across the
window so the assumption is checked rather than claimed. The second is where the
time actually is: 5180 of the 5790 ms is *system* time on that thread, and its
per-pass kernel work is `poll()` over one entry per live relay —
`wait_for_events` rebuilds the fd set from `poll_snapshot()` on every pass
(`rust/src/engine.rs:4888-4905`). That is the superlinear shape the loop's
structure predicts, in the wait rather than in the Rust sweeps, and the fix is
`epoll` — a persistent interest set owned by the one thread that is allowed to
close a descriptor under a concurrent poll. It is not a change to make in the
middle of this pass, and nothing here pretends the cost is gone.

### The debug line — measured, declined

`logbuf::push_debug` gates on the level (`rust/src/logbuf.rs:78`), but its fourteen
callers build the line first: `push_debug(&format!("mitm {host}: cookies stripped"))`
(`rust/src/mitm/proxy.rs:1323-1419`, `:1929`, `rust/src/mitm/quic/hub.rs:716-722`).
At the shipped level 2 those lines are thrown away. Measured on the host, release
profile, 500k iterations: 109.3 ns to build one and drop it, 1.5 ns to ask the gate
first. A request that trips several privacy rewrites pays a few hundred
nanoseconds, against the 1.2 ms a filtered connection costs in
`Anti-DPI hello splitting — cost per connection` above — two orders of magnitude
below the thing it would be measured against. Passing a closure would fix it and
touch fourteen sites
whose graph impact is HIGH (41 symbols), so the number is recorded and the code is
left alone.

Impact before editing: `handle_packet` **CRITICAL** (23 symbols, 11 execution
flows), `set_config` **CRITICAL** (22 symbols, 9 flows), `config()` reported
UNKNOWN and its callers were confirmed by search instead (twelve, all tests).
828 lib tests plus the integration suites pass, `cargo clippy` still six
pre-existing warnings and nothing at the edited sites.

Device restored: the measurement build with the sweep switched off was overwritten
by the committed library and reinstalled, protection left running with the tunnel
up, `stay_on_while_plugged_in` back to 0, the helper's `files/` back to
`profileInstalled` alone.

One loose end, recorded rather than chased: the enable-protection shortcut did not
bring the tunnel up in three attempts made from `adb shell am start` — once with
the screen locked, where the refusal surfaced as the `AdFree không thể khởi động`
notification (`notifyStartRefused`, reachable now because of `36b0412`, and the
refusal itself is the defect that commit records without fixing), and twice with
the screen on and the app warm, where nothing was logged and no consent dialog
appeared while the same action from the home button started the tunnel in seconds.
The second shape is not explained by the refused-start path and wants its own
pass.

