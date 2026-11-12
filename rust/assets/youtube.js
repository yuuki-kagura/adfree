// AdFree YouTube: removes the ads YouTube sends as data, not as markup.
//
// The rule-based filters (AdGuard Base, EasyList) hide ads that are already in
// the document. YouTube's in-feed sponsored cards and every ad in the player are
// not in the document: they arrive later, as JSON from `youtubei/v1/*` — or,
// for the first paint, as `ytInitialData` / `ytInitialPlayerResponse` assigned by
// an inline script. That is why a page can be fully cosmetic-filtered and still
// show "Được tài trợ · …" cards at the top of the home feed: the element that
// carries them is created after our stylesheet has done its work, and it is not
// a `ytd-ad-slot-renderer` at all in every experiment.
//
// So this script works one level earlier: it takes the ad entries out of the
// data before the app renders them.
//
//   * `ytInitialData` / `ytInitialPlayerResponse` are intercepted at
//     document-start, before the page's own scripts read them, by replacing the
//     property with an accessor pair. That is the same trick AdGuard Extra uses
//     and it is the only one that works for the very first render.
//   * `fetch` and `XMLHttpRequest` are wrapped for `/youtubei/v1/` responses:
//     the body is parsed, the ad renderers are dropped, and the page gets the
//     cleaned body as if it had always been that.
//   * A stylesheet hides what still slips through (an ad whose renderer shape
//     is new, a card already in the DOM before the first scrub).
//
// Nothing here is site-specific guesswork beyond the renderer names, which are
// part of YouTube's public Innertube schema and have been stable for years.
//
// ==UserScript==
// @name         AdFree YouTube
// @namespace    adfree
// @version      1.0.0
// @description  Removes in-feed and in-player ads from YouTube before they render
// @match        *://*.youtube.com/*
// @match        *://youtube.com/*
// @run-at       document-start
// @grant        none
// ==/UserScript==
(function () {
  'use strict';

  if (window.__adfreeYoutube) return;
  window.__adfreeYoutube = true;

  // Renderer keys that only ever carry an ad. A node holding one of these is
  // dropped whole; the names come from the Innertube schema (`adPlacements`,
  // `adSlots`, `playerAds` are the containers, the rest are the leaves).
  var AD_KEYS = [
    'adPlacements',
    'adSlots',
    'playerAds',
    'adBreakHeartbeatParams',
    'adBreakServiceRenderer',
    'adSlotRenderer',
    'inFeedAdLayoutRenderer',
    'displayAdRenderer',
    'promotedSparklesWebRenderer',
    'promotedSparklesTextSearchRenderer',
    'promotedVideoRenderer',
    'compactPromotedVideoRenderer',
    'statementBannerRenderer',
    'brandVideoShelfRenderer',
    'brandVideoSingletonRenderer',
    'adDurationRemaining',
    'playerLegacyDesktopWatchAdsRenderer'
  ];

  // Wrappers a feed entry can hide an ad inside. A `richItemRenderer` whose
  // `content` is an ad slot is an ad card: the entry has to go whole, because
  // emptying the content leaves an empty card in the grid.
  var WRAPPERS = ['richItemRenderer', 'richSectionRenderer', 'itemSectionRenderer', 'shelfRenderer', 'gridRenderer'];

  // `{ [key]: value }` where the key is an ad renderer: the whole node is an ad.
  function isAdLeaf(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    for (var i = 0; i < AD_KEYS.length; i++) {
      if (Object.prototype.hasOwnProperty.call(value, AD_KEYS[i])) return true;
    }
    return false;
  }

  // An array entry that exists only to carry an ad: an ad leaf, or a wrapper
  // whose `content` is one.
  function isAdEntry(value) {
    if (isAdLeaf(value)) return true;
    if (!value || typeof value !== 'object') return false;
    for (var i = 0; i < WRAPPERS.length; i++) {
      var wrapped = value[WRAPPERS[i]];
      if (wrapped && typeof wrapped === 'object' && isAdLeaf(wrapped.content)) return true;
    }
    return false;
  }

  // Drops ad entries from arrays in place and ad keys from objects, recursively.
  // Returns `true` when anything changed, so callers can skip re-serialising a
  // body that held no ads (the common case on every other request).
  function scrub(node, depth) {
    if (depth > 40 || !node || typeof node !== 'object') return false;
    var changed = false;
    if (Array.isArray(node)) {
      for (var i = node.length - 1; i >= 0; i--) {
        if (isAdEntry(node[i])) {
          node.splice(i, 1);
          changed = true;
        } else if (scrub(node[i], depth + 1)) {
          changed = true;
        }
      }
      return changed;
    }
    for (var key in node) {
      if (!Object.prototype.hasOwnProperty.call(node, key)) continue;
      if (AD_KEYS.indexOf(key) >= 0) {
        delete node[key];
        changed = true;
        continue;
      }
      if (scrub(node[key], depth + 1)) changed = true;
    }
    return changed;
  }

  // The first paint: the page assigns these from an inline script, so the window
  // property is replaced by an accessor that scrubs on the way in. A page that
  // re-assigns later (the SPA does not, but an extension could) still lands
  // here.
  ['ytInitialData', 'ytInitialPlayerResponse'].forEach(function (name) {
    var stored;
    try {
      Object.defineProperty(window, name, {
        configurable: true,
        enumerable: false,
        get: function () {
          return stored;
        },
        set: function (value) {
          try {
            scrub(value, 0);
          } catch (e) {
            /* a shape we do not recognise is left exactly as it came */
          }
          stored = value;
        }
      });
    } catch (e) {
      /* a browser that refuses the accessor still gets the fetch and XHR paths */
    }
  });

  function isInnertube(url) {
    if (!url) return false;
    var text = String(url);
    return text.indexOf('/youtubei/v1/') >= 0 || text.indexOf('/youtubei/v1?') >= 0;
  }

  function cleanText(text) {
    if (!text || text.charAt(0) !== '{') return null;
    var data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      return null;
    }
    if (!scrub(data, 0)) return null;
    return JSON.stringify(data);
  }

  // `fetch`: the body is read once, cleaned, and handed on as a fresh response
  // with the original status and headers. A response that is not JSON, or holds
  // no ads, is passed through untouched.
  var nativeFetch = window.fetch;
  if (typeof nativeFetch === 'function') {
    window.fetch = function (input, init) {
      var url = typeof input === 'string' ? input : input && input.url;
      var answer = nativeFetch.apply(this, arguments);
      if (!isInnertube(url)) return answer;
      return answer.then(function (response) {
        return response
          .clone()
          .text()
          .then(function (text) {
            var cleaned = cleanText(text);
            if (cleaned === null) return response;
            return new Response(cleaned, {
              status: response.status,
              statusText: response.statusText,
              headers: response.headers
            });
          })
          .catch(function () {
            return response;
          });
      });
    };
  }

  // `XMLHttpRequest`: the page reads `responseText` or `response`, so both are
  // shadowed on the instance once the body has arrived. The instance property
  // wins over the prototype getter, which is what makes this work.
  var nativeOpen = XMLHttpRequest.prototype.open;
  var nativeSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this.__adfreeUrl = url;
    return nativeOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    var xhr = this;
    if (isInnertube(this.__adfreeUrl)) {
      xhr.addEventListener('readystatechange', function () {
        if (xhr.readyState !== 4) return;
        var cleaned = null;
        try {
          if (xhr.responseType === 'json') {
            cleaned = xhr.response;
            if (scrub(cleaned, 0)) {
              Object.defineProperty(xhr, 'response', { configurable: true, get: function () { return cleaned; } });
            }
            return;
          }
          cleaned = cleanText(xhr.responseText);
        } catch (e) {
          return;
        }
        if (cleaned === null) return;
        Object.defineProperty(xhr, 'responseText', { configurable: true, get: function () { return cleaned; } });
        Object.defineProperty(xhr, 'response', {
          configurable: true,
          get: function () {
            return xhr.responseType === '' || xhr.responseType === 'text' ? cleaned : null;
          }
        });
      });
    }
    return nativeSend.apply(this, arguments);
  };

  // What the data scrub missed: the DOM shapes the filter lists already know,
  // plus the newer in-feed wrapper, kept here so the script stands alone even
  // when the cosmetic lists are stale.
  var CSS = [
    'ytd-rich-item-renderer:has(ytd-ad-slot-renderer)',
    'ytd-rich-item-renderer:has(ytd-in-feed-ad-layout-renderer)',
    'ytd-rich-section-renderer:has(ytd-ad-slot-renderer)',
    'ytd-rich-section-renderer:has(ytd-in-feed-ad-layout-renderer)',
    'ytm-rich-item-renderer:has(ad-slot-renderer)',
    'ytd-display-ad-renderer',
    'ytd-promoted-sparkles-web-renderer',
    'ytd-promoted-video-renderer',
    'ytd-compact-promoted-video-renderer',
    'ytd-search-pyv-renderer',
    'ytd-ad-slot-renderer',
    '#masthead-ad',
    '#player-ads',
    '#panels ytd-ads-engagement-panel-content-renderer',
    '.ytp-ad-overlay-slot',
    '.ytp-ad-module',
    'ytmusic-mealbar-promo-renderer'
  ].join(',\n') + ' { display: none !important; }';

  function injectStyle() {
    if (document.getElementById('adfree-youtube-style')) return;
    var style = document.createElement('style');
    style.id = 'adfree-youtube-style';
    style.textContent = CSS;
    (document.head || document.documentElement).appendChild(style);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectStyle, { once: true });
  } else {
    injectStyle();
  }
})();
