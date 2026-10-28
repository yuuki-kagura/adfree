# AdFree — design

AdFree blocks ads and trackers entirely on the device. A Rust core owns packet
handling, rule matching and persistent state; Kotlin/Compose only draws the UI.
There is no backend, no API key and no telemetry.

```
┌──────────────────────────────────────────────────────────────────────┐
│  Kotlin / Compose UI (6 tabs)                                        │
│    ViewModel (MVI) ─ Repository ─ CoreEngine                         │
│         │ uniffi (generated bindings, type-checked on both ends)     │
├─────────┴────────────────────────────────────────────────────────────┤
│  Rust core  (libadfree_core.so)                                      │
│    packet.rs     IPv4/IPv6 + TCP/UDP parse and checksums             │
│    dns.rs        wire decode, NXDOMAIN/0.0.0.0 synth, TTL learning   │
│    upstream.rs   forward DNS over protect()ed sockets                │
│    filter.rs     adblock-rust (the engine behind AdGuard and Brave)  │
│    htmlfilter.rs `$$` / `##^` response-document edits                │
│    pathmask.rs   `$path` / `$url` page masks                         │
│    appmask.rs    `$app` rule narrowing                               │
│    jsonprune.rs  `$jsonprune` body edits                             │
│    hls.rs        `$hls` playlist edits                               │
│    conntrack.rs  IP→host→decision so blocked flows can be reset      │
│    uidmap.rs     /proc port→uid attribution for per-app rules        │
│    udpnat.rs     userspace UDP NAT for non-DNS datagrams             │
│    smart.rs      retry-loop cooldown for hosts an app insists on     │
│    store/        filter bodies, userscripts, CA and SQLite           │
│    engine.rs     packet loop, TCP relay on every port, DNS, stats    │
│    mitm/         CA, rustls, ECH, script injection, TLS splice       │
└──────────────────────────────────────────────────────────────────────┘
```

## Why this architecture

**1. Blocking at DNS is the cheapest layer.** For one DNS query the engine
answers inside the TUN device with a single `write`: no radio time, no network
round trip. That is why DNS filtering needs no root, no CA certificate and
almost no battery, and why it is always on.

**2. DNS alone is not enough, so the VPN routes all of `0.0.0.0/0` like
AdGuard.**
- TCP on **every port** is relayed transparently in userspace: the client
  connects to the engine, and the engine connects out through a `protect()`ed
  socket.
- UDP that is not DNS (QUIC, games, NTP…) goes through a **userspace NAT**:
  one mapping per session, with replies written back into the TUN device.
- QUIC/UDP 443 and DoT/853 are dropped on purpose so clients fall back to TCP
  and cannot bypass the filter; every other flow is left intact. With HTTPS
  filtering on, the opt-in **Filter HTTP/3** switch terminates QUIC instead
  (see [HTTP/3 (QUIC) filtering](#http3-quic-filtering)).

**3. HTTPS can be decrypted when the user asks for it.** With "Filter HTTPS"
enabled, port 443 is terminated with a locally generated CA, a script is
injected into HTML responses, and the request is re-originated upstream over
real TLS. Enabling it is **gated on the CA actually being installed** (see
[HTTPS filtering](#https-filtering-mitm)).

**4. Two packet-path threads, both sleeping on descriptors — no clock polling.**
- `tun-thread`: `poll(fd, 250ms)` → `read()` → parse → decide.
- `forward-thread`: **one** `poll()` covering an eventfd wakeup, every DNS
  socket and every relay/NAT flow; the 1-second timeout only drives periodic
  cleanup. Anything that creates work (a DNS query, a new relay, a socket
  refusing bytes, `stop()`) writes the eventfd, so a long timeout costs no
  latency.
There is no `Timer`, no `Handler.postDelayed`, no periodic wakeup.

**5. A per-host decision cache sits *in front of* the rule engine.** Apps ask
for the same host over and over; one hash lookup (a few hundred nanoseconds) is
much cheaper than evaluating the whole ruleset. See `filter.rs`.

**6. Use AdGuard's engine instead of writing another parser.** The `adblock`
crate (adblock-rust, the core of AdGuard DNS and Brave) parses and matches
AdGuard/EasyList/uBO/hosts syntax, including `||domain^`, `@@` exceptions,
`$important`, `$third-party`, `/regex/` and `##` cosmetic rules. It is built
with `default-features = false` plus `full-regex-handling`, and **without**
`single-thread` (which would make the engine `!Send`/`!Sync`).

## Packet path

1. The TUN thread reads one IP packet and the core classifies it.
2. DNS (UDP or TCP port 53, and DoH seen on 443 by IP) is decoded, checked
   against the filter, and either answered locally (NXDOMAIN or `0.0.0.0`) or
   forwarded through a protected upstream socket.
3. TCP is tracked by `conntrack.rs`. A blocked destination is reset
   immediately; everything else is relayed. The relay asks `uidmap.rs` who owns
   the source port, which makes per-app routing and `$app` rules real.
4. Port 443 enters a *pending* state until the ClientHello SNI is known. If
   HTTPS filtering is armed and the host is not excluded, TLS is terminated;
   otherwise the bytes are spliced through untouched.
5. Non-DNS UDP is mapped in `udpnat.rs` and written back when the reply
   arrives. QUIC and DoT are dropped before a mapping exists; with HTTP/3
   filtering armed, UDP/443 goes to the QUIC hub instead.

## Filtering capabilities

- **Network rules** — AdGuard/EasyList/uBO syntax via adblock-rust, with
  exception, `$important`, `$third-party`, regex and hosts-file forms.
- **Response-body rules** — the modifiers the upstream crate does not
  implement are handled locally: HTML filtering (`$$`, `##^`),
  `$jsonprune`, `$hls`, and the bracket form of `$path` / `$url`.
- **Redirect resources** — `$redirect` / `$redirect-rule` names resolve to
  resources embedded in the binary: no-op script/text/CSS/JSON/HTML,
  transparent image, silent MP4/MP3, VAST/VMAP stubs, the anti-adblock
  shims (AdSense, GPT, APS, FuckAdBlock) and inert analytics/fingerprint
  stubs. A name the build cannot serve degrades to the plain block the rule
  would have produced, and the build-time audit names it in the log.
- **Per-app rules** — `$app` values match against the uid attribution above;
  the UI also routes or excludes whole apps from the tunnel.
- **Cosmetic filtering and userscripts** — a script is injected into filtered
  pages; user scripts may use `@require` and a safe subset of the GM APIs.
- **Smart filtering** — if one host is blocked five times within ten seconds,
  the app is assumed to require it and the host is allowed for a minute.
  A host keeps its pass only while it keeps hammering, and the switch clears
  every window at once. On by default.
- **Module switches** — ad blocking (ads + annoyances), tracking protection
  (trackers + analytics + social) and DNS protection are read on every
  decision, so toggling one takes effect without a rebuild. Cosmetics of a
  module-off list are dropped at build time and a rebuild is ordered when the
  flags change; a build sequence number stops a stale build from overwriting
  the newer result.
- **Request log** — decisions and statistics are written to SQLite in the
  store, and the UI reads them lazily; the packet threads never talk to
  Android.

### HTML filtering

One engine, two syntax profiles chosen by syntax rather than pseudo-class:
`$$`/`$@$` follows the AdGuard reference (CoreLibs, the engine behind AdGuard
Android and the syntax AdGuard lists are written for), `##^`/`#@^` follows
uBO/ABE.

- **AdGuard profile** — `[a="v"]` and `[a*="v"]` are both substring
  (CoreLibs #2063), `[a]` is presence; only `>` chains; no selector lists;
  `^=`, `$=`, `~=`, `|=` and the `.x`/`#x` sugar are dropped and counted, not
  approximated.
- **uBO profile** — a blocking rule must name a hostname, a generic exception
  is allowed; `:has-text` is case-insensitive over `textContent`;
  `##^responseheader(...)` and procedural operators are dropped and counted;
  regex is only `/re/` or `/re/i`.
- **Text predicates** — `:contains`, `:-abp-contains` and `:has-text` all mean
  innerHTML; the argument is raw text to the last `)` of the selector (so
  unbalanced parentheses in the corpus work), literals are case-sensitive in
  the AdGuard profile, and an element with empty inner content never matches.
- **Legacy specials** — `tag-content` is a substring with `""` as the escaped
  quote, `wildcard` is a glob on `*`, `min-length`/`max-length` measure bytes
  of innerHTML, and a rule with a content predicate but no maximum gets
  `max-length = 8192` (the catalogue never writes min-without-max; the
  KB's uBO conversion adds 262144). Constraints are ANDed.
- **Cut by bytes, never by DOM re-serialization** — a linear scanner handles
  tags, attributes, comments, doctype/PI, void elements, raw-text elements and
  HTML auto-close rules, with a stack for `>` chains. A cut covers the exact
  open→close range; `<html>` is never cut; a missing close is EOF; bytes
  outside the cut stay byte-identical, so nonces and CSP hashes survive (the
  failure ABE hit in #1720). An unknown shape fails closed.
- **Regex** — `regex::bytes` keeps matching linear (no ReDoS); the canonical
  `^(?=.{m,n}$)` length patterns are answered by a length check; a pattern
  that does not compile is dropped and counted.
- **Exceptions** — `$@$` cancels by canonical equality: lowercase tag/attr
  names, preserve value/argument case, fold equivalent predicates
  (`tag-content` ↔ `:contains` literal, `*=` ↔ `=`). It can never widen the
  filter. `#@^` does not cancel `$$` (different syntax family).
- **Page exceptions** — only `$content` switches HTML filtering off.
  `$document` already switches the whole exchange off through `$urlblock`
  before a plan is built; `$elemhide`, `$generichide`, `$specifichide` and
  `$jsinject` keep their cosmetic/JS scope. AdGuard draws the same boundary:
  CoreLibs #1337 records the old behavior — an
  `$elemhide,jsinject,extension` exception disabling `$$` — as the bug that
  was fixed in 2021, and #1222 reproduces it. `filter::content_vetoed` and
  `page_exceptions_switch_html_filtering_off` lock this in.
- **Body path** — the same Buffer as `$replace`, 512 KiB compressed cap, and
  a page over the 32 KiB stream threshold is still buffered when an HTML rule
  exists. Order: `$hls → $jsonprune → HTML → $replace → snippet`. Gates:
  `text/html`, status 200, not HEAD; byte-level cutting makes UTF-16 fail
  closed. Rule brackets reuse the `$path`/`$url`/`$app` masks.
- **Trust** — not gated: the trusted-list catalogue does not name `$$`/`##^`.
- AdGuard ships this on Windows/Mac/Android/Linux (and ABE in Firefox); the
  crate has no action for it, so the rewrite stage owns it.

### Userscripts

- **Metadata** — `@match`, `@include`, `@exclude`, `@run-at`, `@noframes`,
  `@version`, `@grant` and `@require`. A script without a header keeps the old
  behavior: every page, document-start. A script with a header defaults to
  document-idle; if every `@match`/`@include` is invalid the script stays
  off — it never falls back to every URL. Host wildcards accept `*` or a `*.`
  prefix only (`*example.com` does not become a suffix glob). Patterns become
  regexes once in Rust; caps are 64 patterns/script, 2048 characters/pattern
  and 256 header lines.
- **Run timing** — the `<script src>` tag carries no `defer`. `defer` used to
  move document-start scripts to `interactive`; now a document-start script
  runs while `readyState === 'loading'`, and end/idle waits inside the
  wrapper.
- **Page-context shims** — `unsafeWindow`, `GM_addStyle`, `GM_log`,
  `GM_info`, `GM_xmlhttpRequest`, `GM_download`, `GM_openInTab`,
  `GM_notification`, `GM_setClipboard`, `GM_addElement`, the
  `GM_*Value`/listener family and `GM_registerMenuCommand`/
  `GM_unregisterMenuCommand`. Network calls use the page's own `fetch`, so
  CORS and CSP still apply: this is a compatibility shim, not a bypass.
  Storage is the page origin's `localStorage`, namespaced per script id, so
  values do not cross origins the way an extension's storage would. Menu
  commands render in a closed shadow-root panel on the page.
- **Deliberately unsupported** — `@resource`, `@connect`, `@sandbox` and a
  real CORS bypass. Missing grants are named in the console and in the UI.
- **`@require`** — fetched at install/refresh, at most 8 URLs (deduplicated,
  order kept), 2 MiB each, 30 s timeout, embedded after the header inside a
  guard; a failure leaves a console warning. Body plus dependencies stays
  under 1 MiB.
- **Store** — the Greasy Fork sheet uses the public API, with paging and
  sort; 50 rows per page, non-http(s) rows dropped, and an installed script
  stays disabled until its body actually downloads. Scripts can also be
  imported from a file, created and edited in-app; `@require` is only fetched
  when installing from a URL.
- **Built-in AdFree Extra** — a userscript stub for BlockAdBlock/FuckAdBlock
  (written locally) ships seeded, on by default under the scripts master
  switch and only runs with HTTPS filtering. It is the equivalent of
  AdGuard Extra's anti-adblock shim, not a copy of its code.

### Filter-list lifecycle

A list or script is enabled only after its body downloads; a failure keeps
the row off with the real message instead of a silent no-op. Enabled lists
are refreshed when the app opens or resumes (default 24 h, 0 = off, 30 min
throttle), one engine push after the pass. The catalogue seeds the built-in
lists; custom lists can be added, edited and deleted with confirmation, user
rules can be imported/exported, and a master switch disables every userscript
at once. Filter detail metadata (size, version, source, last error) comes
from the core, not from placeholders.

## Module layout

```
rust/                     core crate (cdylib + rlib)
  src/api.rs              uniffi API for Kotlin
  src/{packet,dns,upstream,conntrack,engine,udpnat,stats,events,filter}.rs
  src/{htmlfilter,jsonprune,hls,pathmask,appmask,smart}.rs
  src/{assets,store,uidmap,logbuf,fxhash,util}.rs
  src/mitm/               ca, tls, proxy, relay, http, tcp, script, segment,
                          ech, hpke, hosts, decide, page_runtime.js,
  src/mitm/quic/          socket (in-memory AsyncUdpSocket), bridge (engine
                          side + thread), hub (h3 termination and filtering)
  tests/                  integration tests (DNS round trip, filter, …)
  uniffi.toml             Kotlin binding configuration
app/src/main/kotlin/
  git/shin/adfree/core/   CoreEngine + adfree.kt (generated by uniffi)
  git/shin/adfree/security/  ThreatAnalyzer (offline analysis)
  git/shin/adfree/ui/     ViewModel/MVI + 6 tabs (Compose)
  git/shin/adfree/vpn/    VpnService + controller
tools/install-emulator-ca.sh   install the CA into a rooted emulator (dev)
app/src/test/kotlin/      JVM unit tests
package.json              JS tests (Vitest + Playwright, run with bun)
rust/src/mitm/page_runtime.test.mjs   tests for the injected page runtime
```

## State and ownership

**Rust owns all data; the platform owns the lifecycle.** The app hands the core
one writable directory and one TUN descriptor at startup, then asks for
outcomes. Nothing in Kotlin parses a filter list, writes a userscript body or
opens the SQLite database.

| Component | Owner | Notes |
|---|---|---|
| Packet loop, DNS loop, filter engine | **Rust** | `core_start(tun_fd)`; the fd is handed over once |
| Data directory and its layout | **Rust** | the platform passes `data_root` once at init |
| Filter bodies + metadata | **Rust** | bodies stay `.txt`; metadata lives in SQLite |
| Userscript bodies + metadata | **Rust** | bodies stay `.js`; metadata lives in SQLite |
| CA certificate and key | **Rust** | `core/ca.pem`, `core/ca-key.pem`; Kotlin only asks for the PEM to install |
| Settings | **Rust** | one JSON blob in SQLite; Kotlin keeps a snapshot for the UI |
| Request log | **Rust** | SQLite, retention 7 days / 200k rows |
| VpnService lifecycle, notification, consent, screen-off, connectivity | Kotlin | the parts that cannot move |
| *When* to download lists (Wi-Fi/charging/battery), WorkManager | Kotlin | Rust offers a "download now" call |
| UI / Compose | Kotlin | reads state through uniffi |

The principle: **the platform decides "when" and hands over the fd/root; Rust
decides "what, how and where inside the root".**

```
<root>/filters/<id>.txt   filter list bodies
<root>/scripts/<id>.js    userscript bodies
<root>/core/ca.pem        local CA certificate (PEM)
<root>/core/ca-key.pem    local CA private key (PEM, 0600)
<root>/adfree.db          SQLite: settings blob, request log, registries
```

Downloads land in a temporary file and are renamed into place, so a killed
process never leaves a half-written list behind. The file names predate the
move from Kotlin, so installed apps keep their data without a migration.

SQLite schema v3 (`PRAGMA user_version`; migrations are additive):

```sql
CREATE TABLE settings(
  id INTEGER PRIMARY KEY CHECK (id = 1),
  json TEXT NOT NULL, updated_ms INTEGER NOT NULL);

CREATE TABLE log_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms INTEGER NOT NULL, action INTEGER NOT NULL, category INTEGER NOT NULL,
  domain TEXT NOT NULL, ip TEXT NOT NULL, rule TEXT NOT NULL, list_name TEXT NOT NULL,
  app TEXT NOT NULL DEFAULT '',
  latency_ns INTEGER NOT NULL DEFAULT 0, bytes_saved INTEGER NOT NULL DEFAULT 0,
  ipv6 INTEGER NOT NULL DEFAULT 0);
CREATE INDEX log_events_ts ON log_events(ts_ms);

CREATE TABLE filter_lists(id INTEGER PRIMARY KEY, name TEXT, url TEXT, enabled INTEGER,
  format INTEGER, category INTEGER, rule_count INTEGER, last_error TEXT,
  updated_ms INTEGER, etag TEXT, last_modified TEXT);
CREATE TABLE scripts(id TEXT PRIMARY KEY, name TEXT, url TEXT, enabled INTEGER, updated_ms INTEGER);
```

- WAL + `synchronous=NORMAL`; one writer thread (`adfree-db`) batches 500 ms or
  256 events; the packet thread only `try_send`s and never blocks.
- Retention prunes rows older than 7 days or beyond 200k entries every 5
  minutes.
- **`rusqlite` (bundled), not sqlx/tokio**: the core is synchronous and
  threaded; pulling in an async runtime to read a local database would invert
  the design and bloat the binary.
- Settings are stored as opaque JSON: the app owns the shape today, and a
  future platform port can lift the schema into Rust with a migration.
- Schema v3 adds `log_events.app`; rows written before it keep an empty app
  rather than a guess. The app is resolved from the uid table on DNS, the
  firewall and MITM flows (resolved at SYN), so a MITM connection costs one
  platform binder lookup for its log row.
- Backup is a versioned JSON envelope (`adfree-backup`) holding the settings
  and filter blobs, capped at 4 MB; if writing filters fails, settings roll
  back. Userscript bodies are not part of the backup.

The migration ran in five phases, all complete: (A) store + SQLite + log +
counters + shared leaf key, (B) the Activity screen reads the database,
(C) settings move into Rust, (D) filters/scripts/CA move into Rust with atomic
writes and FFI calls, (E) measurement on a real device. Phase E found no reason
for a worker pool: handshakes dominate, and the work is already split across
two threads.

Protection settings and the HTTPS toggle persist across restarts; the selected
filter lists, custom rules, userscripts, custom DNS providers and per-app
firewall choices do too.

## HTML injection and the local asset origin

How an HTML response is rewritten, and where the injected bytes are served
from. Two decisions live here: the **anchor** (where the snippet lands) and the
**channel** (the origin the injected tags point at).

### What is injected

Up to four things, in this order:

```html
<link rel="stylesheet" id="adfree-hide" href="https://192.0.2.1/adfree-hide.css?dmn=<host>&h=<hash>" nonce="<n>">
<script nonce="<n>">window.__adfree_page={…rules for this page…};</script>
<script nonce="<n>" src="https://192.0.2.1/adfree-page.js?dmn=<host>&h=<hash>"></script>
<script nonce="<n>" src="https://192.0.2.1/adfree-user.js?h=<hash>"></script>
```

- the host's hiding stylesheet (skipped when nothing is hidden, and also when a
  page-scoped `#@#` exception makes the host sheet wrong for this page),
- the cosmetic payload (skipped when the HTML scan found nothing): page-local
  hiding selectors (`hide`) and page exceptions (`exceptions`) when the host
  stylesheet was skipped, style actions, procedural rules, scriptlets and raw
  JavaScript rules for this page,
- the page runtime (when cosmetic filtering runs at all — a host unblocked with
  `$document` gets none of these three),
- the combined user scripts (only when at least one is installed).

The stylesheet is per host, the payload per page, the runtime per app version
and the user script per script set. Each URL carries the hash of the bytes it
serves, so the browser caches every one until it actually changes.

A `[$path=…]`, `[$url=…]`, `[$app=…]` or path-in-domain `#@#` exception can
cancel only some of a host's hiding selectors. The host stylesheet cannot
express that, so a matching page leaves the `<link>` out and carries the
filtered selectors in the payload's `hide` array; every other page of the host
keeps the cacheable stylesheet. The style (`#@$#`), procedural (`#@$?#`) and
scriptlet (`#@%#`) exceptions cancel their matching entry directly in Rust, so
those payload fields simply omit the rule.

`<n>` is a fresh nonce per response (`http::new_nonce`, 18 random bytes from
ring's CSPRNG), and the same value is taught to the page's own
`Content-Security-Policy`.

### What the lists can switch off

The adblock engine implements `$generichide` and nothing else: a rule carrying
`$elemhide`, `$specifichide` or `$jsinject` is rejected when the list is
parsed, and a `$document` exception is honoured for blocking but not for
cosmetics. The app therefore reads those out of the list text itself
(`filter::scan_cosmetic_exceptions`) and keys them by the `||host^` part of the
rule. Without that, a list asking for a site to be left alone would keep
getting its page hidden — the very thing the exception exists to stop.

What each modifier switches off for pages at the host (and, like any `||` rule,
at everything below it):

| rule | hiding | style/procedural | scriptlets, JS rules | class/id lookup |
| --- | --- | --- | --- | --- |
| `$elemhide` / `$ehide` | off | off | kept | off |
| `$specifichide` / `$shide` | generic half only | off | kept | on |
| `$jsinject` | — | — | off | — |
| `$document` / `$doc` | off | off | off | off |

- `$elemhide` is **not** `$jsinject`: scriptlets survive an `$elemhide`
  exception, and only `$jsinject` or `$document` removes them.
- `$specifichide` drops what is bound to the page's own domain. The engine has
  no flag for it, so the generic half is fetched by asking about a hostname no
  list can target (`https://adfree.invalid/`) and the page's own `#@#`
  exceptions are applied on top.
- `$document` also carries the request-level half (`$urlblock`): the page host
  is read off the exception (the `Referer` of a subresource, or the document
  request itself), and URL-level rules are skipped for it. The DNS layer cannot
  join in because it never sees a page.
- Only plain `||host^` patterns match. A rule with a path, wildcard, regex or
  `$domain=` constraint is narrower than a hostname can express, so it is
  skipped rather than applied too broadly.
- `$badfilter` cancels the rule it mirrors: additions and cancellations are
  collected as exact `(host, switches)` pairs and matched at the end, so list
  order does not matter.
- When `$document` is in play, the snippet builder injects nothing at all: no
  stylesheet, payload or runtime. The user's own script is not the lists' to
  switch off and still goes out.
- The table covers cosmetics and scriptlets. Response-body filtering has its
  own veto: only `$content` disables HTML filtering (`$$`/`##^`), while the
  `$elemhide` family keeps its cosmetic scope (see
  [HTML filtering](#html-filtering)).

### What only trusted lists may run

AdGuard has a second axis on top of what the lists ask for: *trust*. Only a
list installed as trusted may carry rules that execute code or reach the
network stack:

| what | who may run it |
| --- | --- |
| JavaScript rules (`#%#script`), scriptlets (`#%#//scriptlet(…)`, `##+js(…)`) | trusted lists |
| `$hls`, `$removeheader`, `$removeparam`, `$replace`, `$urltransform` | trusted lists |
| everything else | any enabled list |

The catalogue is the pre-approved set and is trusted by construction; the
user's own rules are trusted by definition. A list the user added — URL or file
— starts **untrusted** and gets a "Trusted filter" switch in its detail sheet;
the choice rides the filter-choices blob (`StoredFilter.trusted`) into
`FilterListInfo.trusted`.

An untrusted list's text is scrubbed (`filter::scrub_untrusted`) before any
reader or the engine sees it: JavaScript and scriptlet lines are blanked, and
so are network rules carrying a gated modifier. Line count is preserved so
source-map line numbers stay aligned, and nothing is half-run.

Raw `#%#` rules are the one shape the engine cannot assemble (AdGuard syntax,
no crate action), so trusted rules are read by `filter::scan_js_rules` and
served per page in the payload's `jsrules` array. Each runs in its own
`<script>` at document start, right after the scriptlets, so one syntax error
cannot take the others down. A rule naming no domains runs everywhere;
`~domains` and `.*` read like cosmetic domains; a `#@%#` exception cancels the
rules with the same script text.

### Where it lands: the anchor

AdGuard inserts early in `<head>`: right after the metadata block and before
the first external resource. Measured on the Chrome-received HTML of
2025-08/2025-09 builds of the largest Vietnamese news sites (AdGuard 4.14.68,
`Network.getResponseBody` through CDP):

| page | injected at | first `<link>` | `</head>` |
| --- | --- | --- | --- |
| vnexpress.net | 4731 | 5176 | 166385 |
| dantri.com.vn | 3931 | 4376 | — |
| genk.vn | 2199 | 2636 | — |

`injection_point` (`rust/src/mitm/http.rs`) reproduces that: inside `<head>`,
step over comments, whitespace and `<meta>` declarations, and anchor at the
first byte that is a complete non-meta tag — on these pages, the first
`<link>`. A charset declaration must have been seen before the anchor moves
that early, or the browser may decode the snippet with the wrong encoding
before reaching the page's own `<meta charset>`. The 1024-byte prescan depends
on it.

A `<meta http-equiv="content-security-policy">` applies to everything the
parser meets **after** it, and no header rewrite can reach it. Once the charset
is known, the anchor moves in front of such a meta. If the meta arrives before
any charset declaration, the encoding rule wins and the anchor stays where it
was: a multi-kilobyte payload would push the declaration past the prescan
window, and a page with a policy meta ahead of its charset is rare enough to
prefer the safe order.

Fallbacks keep pages that never match the early shape working: `</head>`,
`</body>`, after the `<body …>` tag, after the last complete tag. Byte 0 is
never used: it would land before `<!doctype html>` and put the page into quirks
mode.

### The policy

A `Content-Security-Policy` used to be **removed**: a strict `script-src`
blocks injected inline scripts and nothing else can run them. Removing it
weakens the page for everyone, so the policy now stays and the injected tags
are handed a way through it:

- every directive that governs what is injected — `script-src`, `style-src`
  and their `-elem` variants, or `default-src` when neither covers the role —
  gets `'nonce-<n>'` appended;
- a directive holding `'unsafe-inline'` and no nonce/hash is the exception:
  adding a nonce makes Chrome stop honouring `'unsafe-inline'`, which would
  break the page's own inline scripts. Our origin (`https://192.0.2.1`) is
  added as a host-source instead — enough for our tags, invisible to the rest;
- the runtime's rule lookup is a `fetch`, and `connect-src` has no nonce-source
  at all: that directive (or `default-src`, when it is the fallback) always
  gets our origin;
- `Content-Security-Policy-Report-Only` is not enforcement and is left alone,
  as is a policy that never mentions scripts, styles or connections
  (`img-src`, `frame-ancestors`, …).

A policy arriving as a `<meta http-equiv="content-security-policy">` cannot be
rewritten, so the anchor guard keeps the snippet in front of it instead. The
runtime reads its own nonce back off its tag and puts it on a `<style>` it may
have to build when constructable stylesheets are unavailable; the `<link>` the
proxy writes carries the nonce directly.

### Why the tags do not point at the page's own origin

A same-origin path (`/adfree-page.js`) is fetched **through the page's service
worker**, if it has one. A worker intercepts every same-origin fetch and may
answer with anything — a shell document, a cache entry, a 404, a wrong type. On
a site that registers one (most large news sites do) this silently disables
cosmetic filtering: the runtime never runs, the stylesheet never applies, the
dynamic lookups never answer. The same holds for assets the runtime fetches.

A different origin has no such interception point: a worker only sees its own
origin's requests. AdGuard does exactly this from `local.adguard.org`. A name
would need a resolver we control, and a private-zone name is at the mercy of
Android Private DNS and Chrome's secure DNS. So the origin is an **address
literal**: `https://192.0.2.1`, inside TEST-NET-1 (RFC 5737), an address that
can never be a real host. No DNS is involved, and Chrome treats it as a public
address, so there is no private-network preflight.

### The local session

The engine special-cases that address in `start_tcp_relay`: no peer socket is
opened (`peer_fd = -1`), no dial happens, and the connection is answered by a
`ProxySession` in `ProxyState::Local`. `192.0.2.1:443` with HTTPS filtering off
has nothing to answer with, so it is reset like a blocked flow, and a stray UDP
datagram to the address is dropped rather than relayed.

Everything the app owns is answered (the injected paths plus the `dmn`
lookups); anything else is a 404 with `Connection: close`, because there is no
upstream. Every response carries `Cross-Origin-Resource-Policy: cross-origin`
so pages under COEP keep working. `Access-Control-Allow-Origin: *` is on the
`dmn` lookup answer alone — the one a page reads with `fetch`. Scripts and
stylesheets are loaded by their tags and need no CORS, and the user script is
the user's own code: a page must not be able to fetch it behind their back. The
body is gzipped when the client asked for it.

The origin is an address literal, so the browser sends **no SNI**.
`SniCertResolver` cannot key a leaf off the hello, so the local session uses
`FixedCertResolver`: the leaf is minted for `192.0.2.1` and rcgen puts the
address in the certificate's IP SAN. A handshake with no SNI and an IP-SAN leaf
is covered by `the_injection_origin_is_answered_without_a_peer`.

### The parameters on the URLs

- `dmn=<host>` — the host whose rules the answer is about. The local origin
  never saw a ClientHello for the page, so the host travels in the URL, the
  same way AdGuard's content script carries it. Requests without it (a page
  cached before an app update) fall back to the session's SNI.
- `h=<hash>` — the content hash, for caching.

### The runtime

`page_runtime.js` reads `window.__adfree_page` (the payload), applies the
rules, watches the DOM, and asks for generic selectors through
`/adfree-generic.js`. It derives the origin and the host from its own
`<script src>` (`dmn=`), falling back to `location.origin` and
`location.hostname` for the legacy same-origin case. The lookup endpoint only
knows the host; on a page with a scoped `#@#` exception the payload also
carries `exceptions`, and the runtime filters matching selectors out of the
answer.

It is modern JavaScript — `const`/`let`, arrow functions, `Set`,
`async`/`await`, optional chaining — like AdGuard's content script. Its CSS
goes into `document.adoptedStyleSheets` where available, so a page sanitizer
has no `<style>` node to remove; a `<style data-adfree="css">` fallback is
re-attached by the observer if the page drops it. Scriptlets travel as an
inline `<script>` carrying the runtime's nonce — `new Function` needs
`'unsafe-eval'`, which a strict policy does not grant. Raw JavaScript rules
(`jsrules`) run the same way, each in its own tag.

### Testing and invariants

`rust/src/mitm/page_runtime.test.mjs` runs the real file in a real Chromium
through Playwright, with Vitest as the runner and bun as the package manager.
`page.route` answers for both origins, so a test can hand the runtime any
payload and lookup answer and assert on computed styles, the
`adoptedStyleSheets` path, the `<style>` fallback, XPath rules and a failing
lookup. The `ADFREE_CDP` test runs against the emulator's Chrome behind the
real VPN:

```sh
adb forward tcp:9333 localabstract:chrome_devtools_remote
ADFREE_CDP=http://localhost:9333 bun run test
```

When this changes, keep these agreements:

- `LOCAL_ORIGIN` / `LOCAL_ORIGIN_HOST` / `LOCAL_ORIGIN_V4` in
  `rust/src/mitm/proxy.rs` (URL, certificate name, packet match) must change
  together; breaking one fails silently — the tags render, nothing answers.
- The payload stays inline: it must land with the document, so it carries the
  nonce directly.
- The nonce has to reach every carrier: the payload, the runtime tag, the user
  script tag, the stylesheet `<link>`, and anything the runtime builds
  (the fallback `<style>`, the scriptlet `<script>`). A strict policy silently
  drops a carrier that lacks it.
- The stylesheet stays a stylesheet: 11 KB of all-site selectors per page would
  cost more than the one fetch it saves. The only exception is a page-scoped
  `#@#` exception, which uses the payload's `hide` array instead.


## HTTPS filtering (MITM)

| Piece | File | What it does |
|---|---|---|
| Local CA (ECDSA P-256), leaf certificates per SNI, PEM persistence | `mitm/ca.rs` | issues and restores the chain |
| TLS termination with rustls (ALPN h1) | `mitm/tls.rs` | terminates the client handshake |
| Client-side TCP: SYN-ACK, sequence/ack translation, RST/FIN | `mitm/tcp.rs`, `mitm/segment.rs` | speaks TCP to the client from userspace |
| HTTP response rewrite and script injection | `mitm/http.rs` | fixes `content-length` after injecting |
| User scripts, `@require`, safe GM APIs | `mitm/script.rs` | builds one bundle with per-script guards |
| Byte splice browser ↔ proxy ↔ origin | `mitm/proxy.rs` | moves bytes in both directions |
| Relay integration in the engine | `mitm/relay.rs` | wires the splice into the packet loop |
| ECH handling | `mitm/ech.rs`, `mitm/hpke.rs` | strips ECH from DNS by default, offers the origin's config upstream |
| HTTPS allow/block host patterns | `mitm/hosts.rs` | excludes sites from decryption before TLS starts |

The decision now comes from the **ClientHello SNI**, not from the DNS map: a
port-443 relay enters *pending*, and upstream is only opened once rustls has
parsed the SNI. A missing or unusable hello is spliced straight through, and a
non-TLS flow is spliced intact. A `connect()` that is reset (NAT or `TIME_WAIT`
when a port is reused on the emulator) is retried **once on a fresh socket**
before the flow is dropped, so the client sees no interruption.

### Encrypted ClientHello (ECH)

ECH aims at the opposite of HTTPS filtering: it hides the inner name. The two
legs are handled separately, and the default covers only the upstream half.

- **Default: upstream ECH.** The DNS half strips the `ech` SvcParam (key 5)
  from HTTPS/SVCB answers and clamps the answer TTL to 60 s, so a client
  cannot wrap a hello in a config the proxy cannot read. The raw
  ECHConfigList is read *before* the strip and kept for the proxy's own
  connection; rustls offers it upstream, so an ECH-required origin still
  accepts the handshake and the plaintext stays filterable. A refused offer is
  retried once in the clear on a fresh peer socket, and the host sits ECH out
  for 10 minutes.
- **Required-host exemption.** One `421`, or two bare `502`s (no `Server`
  header) within 10 minutes, mark a host as requiring ECH for 6 hours. Its DNS
  answer keeps the config (still clamped), the browser can run ECH end to
  end, and a hello whose SNI is that config's public name is spliced by name.
  A plain hello to the same host is still terminated and filtered — the proxy
  offers ECH upstream instead.
- **Public-name hello with full ECH off.** A cached ECHConfig can make Chrome
  send a real ECH hello long after the switch is off. If the SNI is a known
  public name and no exempt host publishes it, the hello is terminated (one
  failed handshake); Chrome retries in the clear, that retry is MITM'd with
  upstream ECH, and the page stays filtered. Splicing instead would silently
  drop filtering for a host that merely shares `cloudflare-ech.com` with an
  exempt one. A name the proxy never learned falls through as GREASE and is
  terminated anyway, with the same outcome.
- **Full ECH (`Config::full_ech`, off by default).** The DNS half keeps the
  config, the client may run ECH end to end, and that host is spliced and
  unfiltered for flows that actually negotiate ECH. Non-ECH clients (GREASE,
  older stacks) are still terminated, filtered and offered ECH upstream; the
  config is still kept for that half, and the refusal fallback still works.
  No TTL clamp is applied because the answer is the origin's again.
- **AdGuard parity.** Public evidence shows AdGuard's ECH is likewise the
  proxy↔origin leg: opt-in (`network.https.ech.enabled`), requiring DNS
  filtering, and documented as needing support on both sides. Its
  client↔proxy leg stays plain under HTTPS filtering — ECH checkers behind
  AdGuard report GREASE/plain (AdguardForAndroid #6249, still open in October
  2026). AdGuard documents no full-ECH/splice mode. AdFree matches that
  architecture and adds `full_ech` as an explicit per-host trade; omitting
  client↔proxy ECH by default is therefore not a parity gap.
  Evidence: [Mac 2.10 blog](https://adguard.com/en/blog/adguard-v2-10-for-mac.html),
  [ECH obstacles blog](https://adguard.com/en/blog/encrypted-client-hello-misconceptions-future.html),
  [AdguardForAndroid #6249](https://github.com/AdguardTeam/AdguardForAndroid/issues/6249),
  [CoreLibs #1751](https://github.com/AdguardTeam/CoreLibs/issues/1751).

`page_runtime.js` is the script injected into pages. Its tests run it in a real
Chromium; setting `ADFREE_CDP` adds one more check against the emulator's
Chrome behind the running VPN.

### HTTP/3 (QUIC) filtering

AdGuard's "Filter HTTP/3" switch has a direct counterpart here. QUIC cannot be
inspected without terminating it, so the default stays *drop UDP/443* and the
feature is opt-in (`filter_http3`, effective only with HTTPS filtering on).

- **Client side.** Each client five-tuple gets a quinn server endpoint whose
  UDP socket lives in memory: `handle_packet` pushes datagrams into it and the
  forwarder drains quinn's output back into the TUN. No extra fd, no loopback.
  The endpoint advertises a 1452-byte datagram limit, which fits the tunnel's
  1500-byte MTU over IPv6 (quinn's IPv4-only default of 1472 does not).
- **Upstream.** Terminated connections are re-originated over real QUIC from
  shared, `protect()`ed endpoints (one per address family) to the original
  destination IP with the SNI as the server name.
- **Decisions.** Requests reuse `mitm/decide.rs` and the same response rewriter
  as HTTP/1.1, so block rules, `$removeparam`, `$replace`, injection, cosmetic
  filtering and `$app` behave identically. Requests blocked inside a
  terminated flow count in `quic_blocked`.
- **Splicing.** Hosts excluded from HTTPS filtering, apps that reject the CA
  and ECH-required hosts are spliced verbatim: the pre-SNI client flight is
  buffered (16 KiB cap) and replayed into a plain NAT mapping, and the
  five-tuple is remembered for a minute so a retry does not handshake again.
- **Failure is clean.** No 0-RTT, no migration, no client ECH termination: an
  ALPN mismatch, a full flow table (64) or a missing upstream closes the QUIC
  connection and the client falls back to TCP, which is filtered anyway.
  Chrome/Cronet reject user CAs for QUIC, so they always take that path.
- **Not with SOCKS5.** A configured proxy carries TCP and non-DNS UDP, but
  QUIC is dropped so the browser uses the proxied, filtered transport.

### Outbound proxy (SOCKS5)

An opt-in routing mode for the whole tunnel. TCP flows use `CONNECT`;
non-DNS UDP mappings use `UDP ASSOCIATE`, one bridge thread per mapping
(`udpproxy.rs`). The handshake is a syscall-free state machine (`socks5.rs`,
RFC 1928 plus RFC 1929 credentials): the caller writes `take_output()` and
feeds reads through `on_bytes()`, application bytes stay queued until the
reply, and bytes beyond the reply are handed back to the relay. Credentials
are sent only when both halves exist, each capped at 255 bytes. Host and port
must be an IP literal — the packet loop never resolves names.

Automatic routing is the default: loopback, private, link-local, CGNAT,
198.18/15, documentation, multicast, 240/4, ULA and other non-internet
destinations stay direct, because a remote proxy cannot reach them and a
private destination must not be handed to a third party. Manual mode sends
every flow through the proxy. The proxy carries TCP and non-DNS UDP, but QUIC
is still dropped in proxy mode so the browser falls back to TCP, which the
proxy filters end to end. DNS has its own forwarder and is not proxied. Open
flows keep the path they started with; only a new flow reads the current
configuration. The password lives in the app-private SQLite blob, unencrypted
beyond the OS sandbox.

### Per-app network policy

Three package sets — cellular, Wi-Fi and screen-off — are enforced in Rust
(`AppNetworkPolicy`). A TCP SYN resolves the uid to packages before any socket
is opened and is refused with a RST and a reason; a UDP mapping checks at
creation; DNS is refused before the filter lists and answers in the configured
block mode. Changing the policy, the transport or screen state also cuts
flows already open (`drop_restricted_flows`), always from the forwarder
thread. Flows opened while the policy was still empty are the one gap: they
are not re-evaluated until they close, while every later change is applied
live.

### Installing the certificate

The toggle is gated: while the CA is not in the trust store, turning it on only
opens instructions, and the toggle stays OFF (`isCaTrusted()` compares DER
against `AndroidCAStore`). The dialog exports `AdFree-CA.crt` to Downloads
(through MediaStore) and opens Settings, because:

- the inline install intent (`KeyChain.createInstallIntent`) only answers
  *"Install CA certificates in Settings"* — Android does not install a CA
  directly;
- the Settings file picker cannot read the app's private storage.

Verified flow on the emulator: toggle → dialog → *Open Settings* → the file is
in Downloads → Settings: Security & privacy → More security settings →
Encryption & credentials → Install a certificate → CA certificate → pick the
file (screen lock required) → return to the app: "Certificate: installed", and
the toggle turns itself ON.

The CA card also reads `notAfter` from the PEM and warns in amber under 30
days, in red once expired; an empty or malformed PEM reports no date instead
of a fake one.

**Trust store on Android 14+:** certificates are **no longer** read from
`/system/etc/security/cacerts`; the system store is the
`com.android.conscrypt` APEX (read-only, and a tmpfs overlay does not convince
Chrome). The correct path is the **user store**:
`/data/misc/user/0/cacerts-added/<hash>.0` (system:system, 644, label
`misc_user_data_file`) — exactly where the dialog installs it. On a rooted
emulator, `tools/install-emulator-ca.sh` can replace the Settings steps.

**Apps that reject the CA.** Apps targeting API 24+ ignore user-store CAs;
Cronet in Google apps is the visible case. The engine learns such an app from
the client's `CertificateUnknown`/`UnknownCA`/`BadCertificate`/
`CertificateExpired`/`CertificateRevoked` alert (an alert from the origin side
never counts), splices that app's HTTPS verbatim from then on, logs once per
app, and keeps DNS filtering and `$app` rules active. A real CA change (not a
UI refresh) or a successful root install clears the learned set so those apps
are tried again.

**Root mode.** Where `su` is available, `trust.rs` installs the same CA into
the system store: a Magisk module on Android (a bind mount over the Conscrypt
APEX on 14+), a live mount in init's namespace without Magisk, or
`update-ca-certificates`/`update-ca-trust` on Linux. `su` runs only when the
user presses the button; status probes never elevate. With the CA in the
system store, Cronet apps are filtered instead of spliced. The root install
path is covered by automated tests only — the test device has no root.

## Threading and resource use

The forwarder was rewritten to **sleep on descriptors instead of polling on a
clock**: it used to poll every flow every 50 ms and wait for DNS on a 250 ms
condvar, which meant dozens of wakeups per second for a single open connection.
Now there is one `poll()` (eventfd + DNS + flows + NAT, 1-second timeout) that
does work only when there is data, and every "there is new work" event writes
the eventfd.

Measured on the emulator while idle (background traffic subtracted): about
**16 context switches per second** for the whole process (tun thread 4/s,
forwarder 1/s, system threads), versus an old floor of ≥ 24/s for the forwarder
alone.

## Verified on the emulator (API 37, x86_64)

```
$ adb shell ping -c1 api.github.com      → PING 140.82.121.6        (forward)
$ adb shell ping -c1 a.doubleclick.net   → unknown host             (blocked in 2 µs)
$ adb shell ping -c1 fresh.adnxs.com     → unknown host             (blocked)
```

| Check | Result |
|---|---|
| Real rules compiled | **421,687** (AdGuard DNS 184,178 + OISD + StevenBlack + 3 user rules) |
| Decision latency (cache hit) | **2 µs** |
| Subdomain blocking (`a.doubleclick.net`) | ✅ NXDOMAIN |
| DoH by IP (`94.140.14.14:443`) | ✅ TCP reset, "connection dropped" rule |
| TCP relay on every port + UDP NAT | ✅ every socket `protect()`ed, internet unchanged while on |
| HTTPS MITM | ✅ Chrome reports *"AdFree Personal CA issued this website's certificate"* |
| Stack | uniffi 0.32 + JNA, no hand-written JNI |

That work also locked down four bugs with regression tests (see `git log`):

1. `sockaddr_in.s_addr` was byte-swapped → `sendto()` returned `EINVAL` and
   every valid DNS query timed out (`upstream_roundtrip.rs`,
   `sockaddr_uses_network_byte_order`).
2. A file descriptor was closed before Rust received it (`protect()` + `dup()`
   followed by closing the wrong copy) → `sendto()` returned `EBADF`.
3. The old forwarder busy-looped: `setBlocking(false)` without `poll()`.
4. The MITM path was dead because of three splice bugs: the proxy never took
   the ClientHello out of rustls, the plaintext request was discarded while the
   upstream handshake ran, and `Relay::on_peer_data` swallowed upstream bytes.
   All three have regression tests, and the relay test
   `on_peer_data_carries_the_upstreams_own_bytes` covers the last one.

## Build and test

Requirements: JDK 21 (source/target 17), Android SDK, **Android NDK r28c**
(`ANDROID_NDK_HOME`), `cargo-ndk` (`cargo install cargo-ndk`) and
`uniffi-bindgen` 0.32 (`cargo install uniffi --features cli`).

```bash
./gradlew :app:assembleDebug          # build the core + APK
./gradlew :app:verifyBindings         # regenerate Kotlin bindings after Rust API changes
./gradlew :app:assembleDebug -PskipNative   # skip native code (fast, UI only)

cd rust
cargo test                            # 708 library tests (2 ignored) + integration tests
cargo clippy --all-targets            # 0 warnings

cd ..
./gradlew :app:assembleDebug :app:testDebugUnitTest
bun install && bun run test           # 32 browser tests (1 skips without ADFREE_CDP)
```

The JS tests run `page_runtime.js` in a real Chromium; `bun` is the package
manager (Playwright uses the installed Chrome, it does not download a browser).

CI (`.github/workflows/android-ci.yml`) runs Vitest, `cargo test --lib`,
`cargo clippy --all-targets -- -D warnings`, Android Lint and a debug build.
Pushes to `main` additionally run `android-release.yml`, which signs the APK
and AAB with the release keystore and publishes them through semantic-release.

uniffi calls native code through JNA, so the APK needs the JNA dependency
(already listed in `libs.versions.toml`).

## Platform roadmap

The core is written to be portable, and Android is the first shell rather than
the only one. The target order is **Android → Linux → Windows → macOS → iOS**.

The platform boundary is deliberately narrow. A port supplies only these
seams; everything else in `rust/` is shared:

| seam | Android today | What another platform must provide |
|---|---|---|
| TUN descriptor | `VpnService` fd handed to `core_start` | Linux `/dev/net/tun`; Windows Wintun; macOS `utun`; iOS `NEPacketTunnelProvider` |
| Socket protection | `SocketProtector` → `VpnService.protect()` | a no-op or routing-mark call that keeps upstream sockets outside the tunnel |
| App attribution | `ConnectionUidLookup` → `ConnectivityManager.getConnectionOwnerUid` (API 34+), `/proc/net/*` fallback | UID lookup from the kernel/API, or `None` where the OS does not expose it |
| Data root | app `filesDir` | any writable per-user directory |
| Settings UI | Compose over the uniffi snapshot | a platform shell over the same uniffi API |
| CA trust | user store install + screen lock | OS-specific trust store (system keychain, certificate manager, configuration profile) |

Practical consequences per platform:

- **Linux** — the packet engine works unchanged over a TUN fd; the shell needs
  root or `CAP_NET_ADMIN`, route/DNS setup and a systemd service. UID
  attribution is available from `/proc`, so `$app` rules keep working.
- **Windows** — Wintun supplies the adapter; a signed driver/service and the IP
  Helper API replace VpnService and `/proc`. The core needs a Windows
  implementation of the fd/socket layer, not a new filtering engine.
- **macOS** — `utun` works either as root or through NetworkExtension, which
  adds entitlements and App Store constraints; CA trust uses the Keychain.
- **iOS** — `NEPacketTunnelProvider` is the only tunnel API, and per-app
  attribution is not available to it, so `$app`/per-app routing degrade to a
  documented no-op. The CA must be installed as a configuration profile.

The filtering, DNS, MITM, store and state layers are platform-neutral by
design: `store/mod.rs` already says the platform hands down one directory, and
the engine already reaches the platform only through the protector and UID
callbacks. What changes per platform is the shell (tunnel plumbing, trust
store, lifecycle), not the rules.

## Parity notes (AdGuard)

AdGuard's filter engine source is not public (its CoreLibs repository ships
only a README), so parity questions are settled from the knowledge base, the
issue tracker, release notes and measured behavior rather than from code.

- **HTML filtering and page exceptions.** AdGuard does not let `$elemhide`,
  `$generichide`, `$specifichide` or `$jsinject` disable HTML filtering; they
  keep their cosmetic/JS scope. Only `$content` (and `$document`, through the
  `$content` part of its expansion) does. CoreLibs
  [#1337](https://github.com/AdguardTeam/CoreLibs/issues/1337) records the old
  behavior — a `$elemhide,jsinject,extension` exception disabling `$$` — as
  the bug that was fixed in 2021, and
  [#1222](https://github.com/AdguardTeam/CoreLibs/issues/1222) reproduces it.
  `filter::content_vetoed` matches the fixed behavior.
- **`$path` is not a network modifier.** It exists only in the bracket
  (cosmetic/HTML/raw-JS) form. The AdGuard knowledge base's basic-modifier
  table, AGTree and tsurlfilter have no network `path`, so a network rule
  carrying `$path=` is dropped by both stacks — parity, not a gap. The live
  corpus has zero such rows; the bracket form is implemented.
- **ECH.** AdGuard's ECH is also the proxy↔origin leg, opt-in and dependent
  on DNS filtering; its client↔proxy leg remains plain under HTTPS filtering
  (issue #6249 above), and no full-ECH mode is documented. The detailed
  comparison is in "Encrypted ClientHello (ECH)".

## Current limitations

- Android is the only shipping shell today; the platform roadmap above is the
  plan for Linux, Windows, macOS and iOS.
- HTTPS filtering is OFF by default and requires installing the CA and a
  screen lock before it can be enabled. Apps targeting API 24+ ignore
  user-store CAs: they are either learned and spliced verbatim, or covered by
  the root system-store install (automated tests only so far).
- ECH: by default only the proxy↔origin leg uses ECH. With `full_ech` on, a
  flow that negotiates ECH is spliced and unfiltered by design; non-ECH flows
  to the same host stay filtered. A public-name hello without `full_ech` or an
  exemption for a host behind it costs one failed handshake so the retry is
  filtered.
- HTTP/3 filtering is opt-in, needs HTTPS filtering, and Chrome/Cronet still
  reject user CAs for QUIC, so they fall back to TCP. QUIC is dropped in
  SOCKS5 proxy mode.
- SOCKS5: the proxy host must be an IP literal; automatic routing keeps
  private and other non-internet destinations direct; DNS is not proxied;
  open flows keep their original path; the password is stored unencrypted in
  the app-private database.
- Per-app firewall does not retroactively evaluate flows opened before the
  first policy arrived.
- HTML filtering is byte-level: unsupported operators are dropped and
  counted, UTF-16 documents fail closed, and `<html>` is never cut. The uBO
  profile approximates `:has-text` without entity decoding.
- Redirect resources the build cannot serve degrade to the plain block the
  rule would have produced. `.js` aliases that duplicate a scriptlet ident are
  not registered, because the engine would drop the duplicate silently and
  turn the rule into a hard block.
- Userscripts run in the page's main world. There is no `@resource`,
  `@connect`, `@sandbox` or CORS bypass; GM storage is page-origin
  `localStorage`, namespaced per script, and does not cross origins. The
  Greasy Fork sheet uses a public endpoint and loads one page of 50 rows at a
  time.

