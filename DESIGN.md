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
  and cannot bypass the filter; every other flow is left intact.

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
   arrives. QUIC and DoT are dropped before a mapping exists.

## Filtering capabilities

- **Network rules** — AdGuard/EasyList/uBO syntax via adblock-rust, with
  exception, `$important`, `$third-party`, regex and hosts-file forms.
- **Response-body rules** — the modifiers the upstream crate does not
  implement are handled locally: HTML filtering (`$$`, `##^`),
  `$jsonprune`, `$hls`, and the bracket form of `$path` / `$url`.
- **Per-app rules** — `$app` values match against the uid attribution above;
  the UI also routes or excludes whole apps from the tunnel.
- **Cosmetic filtering and userscripts** — a script is injected into filtered
  pages; user scripts may use `@require` and a safe subset of the GM APIs.
- **Smart filtering** — if one host is blocked five times within ten seconds,
  the app is assumed to require it and the host is allowed for a minute.
  A host keeps its pass only while it keeps hammering, and the switch clears
  every window at once. On by default.
- **Request log** — decisions and statistics are written to SQLite in the
  store, and the UI reads them lazily; the packet threads never talk to
  Android.

## Module layout

```
rust/                     core crate (cdylib + rlib)
  src/api.rs              uniffi API for Kotlin
  src/{packet,dns,upstream,conntrack,engine,udpnat,stats,events,filter}.rs
  src/{htmlfilter,jsonprune,hls,pathmask,appmask,smart}.rs
  src/{assets,store,uidmap,logbuf,fxhash,util}.rs
  src/mitm/               ca, tls, proxy, relay, http, tcp, script, segment,
                          ech, hpke, hosts, page_runtime.js
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

SQLite schema v1 (`PRAGMA user_version`):

```sql
CREATE TABLE settings(
  id INTEGER PRIMARY KEY CHECK (id = 1),
  json TEXT NOT NULL, updated_ms INTEGER NOT NULL);

CREATE TABLE log_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts_ms INTEGER NOT NULL, action INTEGER NOT NULL, category INTEGER NOT NULL,
  domain TEXT NOT NULL, ip TEXT NOT NULL, rule TEXT NOT NULL, list_name TEXT NOT NULL,
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

The migration ran in five phases, all complete: (A) store + SQLite + log +
counters + shared leaf key, (B) the Activity screen reads the database,
(C) settings move into Rust, (D) filters/scripts/CA move into Rust with atomic
writes and FFI calls, (E) measurement on a real device. Phase E found no reason
for a worker pool: handshakes dominate, and the work is already split across
two threads.

Protection settings and the HTTPS toggle persist across restarts; the selected
filter lists, custom rules, userscripts and per-app choices do too.

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

ECH exists to keep this proxy out of the connection, which is the opposite of
what HTTPS filtering needs. By default the DNS half rewrites the `ech` SvcParam
away, so no client can wrap a hello in a config the proxy cannot read, while
the original ECHConfigList is kept for the upstream half. When full ECH is
requested, the config reaches the client instead; hosts that use it end-to-end
are spliced rather than filtered.

`page_runtime.js` is the script injected into pages. Its tests run it in a real
Chromium; setting `ADFREE_CDP` adds one more check against the emulator's
Chrome behind the running VPN.

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

**Trust store on Android 14+:** certificates are **no longer** read from
`/system/etc/security/cacerts`; the system store is the
`com.android.conscrypt` APEX (read-only, and a tmpfs overlay does not convince
Chrome). The correct path is the **user store**:
`/data/misc/user/0/cacerts-added/<hash>.0` (system:system, 644, label
`misc_user_data_file`) — exactly where the dialog installs it. On a rooted
emulator, `tools/install-emulator-ca.sh` can replace the Settings steps.

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
cargo test                            # 576 library tests (2 ignored) + integration tests
cargo clippy --all-targets            # 0 warnings

cd ..
./gradlew :app:assembleDebug :app:testDebugUnitTest
bun install && bun run test           # 22 browser tests (1 skips without ADFREE_CDP)
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

## Current limitations

- Android is the only shipping shell today; the platform roadmap above is the
  plan for Linux, Windows, macOS and iOS.
- HTTPS filtering is OFF by default and requires installing the CA and a
  screen lock before it can be enabled.
- Full ECH routing is available, but hosts that use it are spliced rather than
  filtered by design.

