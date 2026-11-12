# Why YouTube still showed ads, and what AdGuard for Windows has that AdFree did not

A sponsored card on the YouTube home feed while AdFree was filtering — the
"Được tài trợ · …" card with "Xem" / "Truy cập trang web" buttons. The rule-based
filters were on and working; the card still rendered.

## The two halves of ad blocking, and which half was missing

| Kind of ad | Where it lives | What removes it |
| --- | --- | --- |
| banner, sidebar, player overlay | in the document | cosmetic rules (`##`, CSS hide) |
| **in-feed sponsored card** | **not in the document** — the home page's HTML contains no ad at all | the ad arrives as JSON from `youtubei/v1/browse`, and the page builds the card afterwards |
| pre-roll / mid-roll in the player | `ytInitialPlayerResponse`, served inside the page's own inline script | data-level removal before the player reads it |

Measured: `curl https://www.youtube.com/` returns a 974 KB document with **zero**
occurrences of `adSlotRenderer`, `inFeedAdLayoutRenderer`, `adPlacements` or
`displayAdRenderer`. A cosmetic match on that document has nothing to match —
which is why the card appeared even though AdGuard Base's rules for it are
present and delivered to the page:

```
###contents > ytd-rich-item-renderer:has(> ytd-ad-slot-renderer)
youtube.com##ytd-rich-item-renderer:has(> #content > ytd-ad-slot-renderer)
youtube.com#?#ytd-rich-grid-renderer ytd-rich-item-renderer div > ytd-display-ad-renderer:upward(2)
```

Those are all in the downloaded `ag-base` list and all come back from the
engine for `www.youtube.com` (probe: 15 hide selectors, 1 procedural action).
They hide an ad that exists. YouTube serves the card after the first paint,
often inside a wrapper the selectors do not name, so they miss it.

## What AdGuard ships for exactly this

**AdGuard Extra** — a userscript that AdGuard's own README says "comes
pre-installed with all premium AdGuard apps … for AdGuard for Windows, Mac and
Android you won't need to do anything to use it", and whose stated purpose is
"to fight ad blocking circumvention attempts". On YouTube it works one level
earlier than the CSS: it intercepts the page's data (initial payload plus the
`youtubei/v1/*` replies) and drops the ad entries.

AdFree had **no equivalent running**:

- `adfree-extra` (built in, on by default) is a different thing: it keeps
  BlockAdBlock/FuckAdBlock from noticing that ads are hidden.
- `adguard-extra` is in the Extensions catalogue as a *download* (GPL-3.0, so
  fetched from AdGuard's own endpoint rather than vendored) and was off by
  default. It is **on by default now**, like AdGuard's own apps: the download
  happens on the first start that finds it missing, and it is only that
  bootstrap that ignores a saved "off" — a switch that is off with no body
  behind it is the old default, not a decision the user made.

So the gap for this screenshot was not a filter list — it was the data-level
module.

## Filters: AdFree's defaults vs AdGuard for Windows

| AdGuard for Windows (default on) | AdFree desktop (this machine) |
| --- | --- |
| AdGuard Base filter | ✅ `ag-base` |
| AdGuard Mobile Ads filter | ✅ `ag-mobile-ads` |
| AdGuard Tracking Protection | ✅ `ag-tracking` |
| AdGuard Social Media filter | ⛔ off by default (`ag-social`, available) |
| AdGuard Annoyances (14 + 18/19/20/21/22) | ⛔ off by default (all available) |
| AdGuard URL Tracking filter | ⛔ off by default (`ag-url-tracking`, available) |
| AdGuard DNS filter | ✅ `ag-dns` |
| language filter picked from the system locale | ✅ (`cat_abpvn` for `vi`) |
| **AdGuard Extra (userscript)** | ✅ downloaded on first start, on by default |
| uBlock Origin Quick fixes (daily YouTube/DOM repairs) | ⛔ not in the catalogue |

The modules (`is_ad_blocking_enabled`, `is_annoyances_enabled`, …) are all on;
the difference is which *lists* the defaults turn on, not whether the engine can
run them.

## What was added

1. **`adfree-youtube`** — a built-in userscript (ours, Apache-2.0) that does what
   AdGuard Extra does for YouTube, without downloading anything or shipping
   GPL code:
   - `ytInitialData` / `ytInitialPlayerResponse` are taken over with accessor
     pairs at `document-start`, so the very first render is already scrubbed;
   - `fetch` and `XMLHttpRequest` are wrapped for `/youtubei/v1/` bodies: the
     JSON is parsed, ad renderers (`adSlotRenderer`, `inFeedAdLayoutRenderer`,
     `adPlacements`, `playerAds`, …) are dropped, and the page gets the cleaned
     body;
   - an array entry that exists only to carry an ad is dropped whole, so no
     empty card is left in the grid;
   - a stylesheet hides what still slips through (new renderer shapes).
   Scoped by `@match` to `*://*.youtube.com/*` and `*://youtube.com/*`; it is on
   by default like `adfree-extra`.
2. **`AdGuard Extra` is now on out of the box** (`defaultEnabled`), fetched once
   and kept in the store; `adfree-youtube` stays the offline, Apache-2.0 half so
   a machine without network still gets the data-level scrub.
3. **`uBlock Origin – Quick fixes`** in the Ads group (off by default). This is
   where uBlock Origin ships its YouTube repairs within days of a DOM change;
   AdGuard Base lags there, and it is the list most likely to be needed next
   time YouTube shuffles its markup.
4. Parity documented in `docs/plans/windows-support.md`'s table.

## How to check it worked

With protection on and the browser going through the proxy:

```sh
# the page is being filtered at all
curl -x http://127.0.0.1:3129 -sI https://www.youtube.com/ | head -3
# the module is in the injected script for that host
curl -x http://127.0.0.1:3129 -s https://www.youtube.com/ | grep -o '/adfree-user.js'
```

Then hard-reload YouTube (Ctrl+Shift+R) with the filtering log open: the
`youtubei/v1/browse` rows should still appear (the request is not blocked — its
*answer* is cleaned), and the home feed should show videos where the sponsored
card used to be.

If a card survives that, the module's CSS list is what to extend: add the
renderer name that wraps it to the `AD_KEYS` array in
`rust/assets/youtube.js`, which drops it at the data level as well.
