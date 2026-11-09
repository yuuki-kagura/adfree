// AdFree page runtime: applies the cosmetic rules the proxy computed for
// this page. Served from the app's own origin (the `https://192.0.2.1` address
// the tunnel answers locally), injected early in `<head>` so the hiding
// stylesheet lands before the page's own resources.
//
// The rules arrive inline as `window.__adfree_page` (written by the proxy):
//
// ```text
// { hide: [selector], exceptions: [selector], style: [[selector, css]],
//   generic: [selector],
//   procedural: [{selector: [{type, arg}], action: {type, arg}|null}],
//   scriptlets: "js source", jsrules: ["js source", ...], dynamic: true }
// ```
//
// Element hiding normally travels as a stylesheet (`<link rel="stylesheet"
// id="adfree-hide">`) served from that same origin, which the browser fetches
// once per site and keeps until the rules change. `hide` is the page-local
// form: the proxy uses it only when a `[$path=…]` / `[$app=…]` exception makes
// the per-host stylesheet unable to answer for this page alone.
//
// Modern syntax throughout (`const`/`let`, arrow functions, template literals,
// `Set`, `async`/`await`, optional chaining): AdGuard's content script is
// written the same way, the browsers that lack any of it are long gone, and
// this file is injected as a classic script, never as a module.
//
// Everything is defensive: a broken rule must never take a page down, so
// every step is guarded and failures are swallowed.

(() => {
  'use strict';

  // Where this runtime was served from, and the host whose rules it applies:
  // both travel in its own tag (`<script src="https://192.0.2.1/…?dmn=…">`),
  // the same way AdGuard's content script carries `dmn`. The fallbacks keep a
  // legacy same-origin tag (a page cached before an app update) working.
  let base = location.origin;
  let dmn = location.hostname;
  let nonce = '';
  try {
    const self = document.currentScript;
    const selfSrc = self?.src;
    if (selfSrc) {
      const selfUrl = new URL(selfSrc);
      base = selfUrl.origin;
      dmn = selfUrl.searchParams.get('dmn') || dmn;
    }
    // The nonce our tags carry — the proxy taught it to the page's policy, and
    // anything this runtime creates has to carry it too, or a strict
    // `style-src` drops it. A nonce is hidden from `getAttribute` and readable
    // through the property, which is what lets a script pass it on.
    nonce = self?.nonce || self?.getAttribute?.('nonce') || '';
  } catch {
    /* keep the fallbacks */
  }

  // No payload for this page: the proxy only sends one when its scan of the
  // HTML found something. The runtime still has work to do — the dynamic
  // class/id lookup is what covers a page whose body the proxy never saw.
  const payload = window.__adfree_page;
  const data = payload && typeof payload === 'object' ? payload : {};
  // The payload has been consumed; do not leave it for the page to read.
  try {
    delete window.__adfree_page;
  } catch {
    window.__adfree_page = undefined;
  }

  // The payload is JSON the engine wrote, but a runtime that dies on a shape
  // it did not expect would take the page's own scripts down with it (this
  // one runs first), so every list is checked before it is walked.
  const hideSelectors = Array.isArray(data.hide) ? data.hide : [];
  const exceptions = new Set(Array.isArray(data.exceptions) ? data.exceptions : []);
  const generic = Array.isArray(data.generic) ? data.generic : [];
  const stylePairs = Array.isArray(data.style) ? data.style : [];
  const procedural = Array.isArray(data.procedural) ? data.procedural : [];

  // --- the stylesheet -------------------------------------------------------

  const stylesHost = () => document.head || document.documentElement;

  // Selectors discovered at runtime (the dynamic class/id lookup).
  let dynamicCss = '';
  // A constructable stylesheet where the browser has one, which is what
  // AdGuard uses too: it has no DOM node for a page sanitizer to remove and
  // no text node to re-parse on every append. Everything else falls back to a
  // `<style>` element, which the observer below keeps re-attached.
  let sheet = null;
  let sheetAttempted = false;
  let styleEl = null;

  const cssText = () => {
    const rules = [];
    if (hideSelectors.length) {
      rules.push(`${hideSelectors.join(',')}{display:none!important}`);
    }
    if (generic.length) {
      rules.push(`${generic.join(',')}{display:none!important}`);
    }
    for (const pair of stylePairs) {
      if (pair?.length === 2) {
        rules.push(`${pair[0]}{${pair[1]}}`);
      }
    }
    if (dynamicCss) {
      rules.push(dynamicCss);
    }
    return rules.join('\n');
  };

  // Creates the page's stylesheet carrier once; null when the browser has
  // neither constructable stylesheets nor a writable document.
  const adoptSheet = (css) => {
    try {
      if (typeof CSSStyleSheet !== 'function' || !('adoptedStyleSheets' in document)) {
        return null;
      }
      const created = new CSSStyleSheet();
      created.replaceSync(css);
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, created];
      return created;
    } catch {
      return null;
    }
  };

  // Tags this runtime creates carry the nonce the proxy put on its own: a
  // `<style>` or a `<script>` built from JS is subject to `style-src` /
  // `script-src` like any other, and a strict policy drops an un-nonced one.
  const withNonce = (el) => {
    if (nonce) {
      try {
        if ('nonce' in el) {
          el.nonce = nonce;
        } else {
          el.setAttribute('nonce', nonce);
        }
      } catch {
        /* an element that refuses the attribute is still better than none */
      }
    }
    return el;
  };

  // Writes the whole rule set again, wherever it lives: `dynamicCss` grows as
  // lookups come back, so a rewrite is one call instead of an append path.
  const installStyles = () => {
    const css = cssText();
    if (!css) {
      return false;
    }
    if (!sheet && !sheetAttempted) {
      sheetAttempted = true;
      sheet = adoptSheet(css);
      if (sheet) {
        return true;
      }
    }
    if (sheet) {
      try {
        sheet.replaceSync(css);
        return true;
      } catch {
        sheet = null;
      }
    }
    try {
      const el = withNonce(styleEl ?? document.createElement('style'));
      el.setAttribute('data-adfree', 'css');
      el.textContent = css;
      if (!el.isConnected) {
        stylesHost().appendChild(el);
      }
      styleEl = el;
      return true;
    } catch {
      return false;
    }
  };

  installStyles();

  // Scriptlets run immediately: they install property traps and must beat the
  // page's own scripts. They go in as an inline `<script>` carrying our nonce
  // rather than through `new Function`: a strict policy has no `'unsafe-eval'`,
  // and eval would be dropped silently — the nonce is what `script-src`
  // already accepts. The wrapper keeps the isolation the function constructor
  // gave them: one broken scriptlet must not take the page down with it.
  if (data.scriptlets) {
    try {
      const el = withNonce(document.createElement('script'));
      el.textContent = `try {\n${data.scriptlets}\n} catch { /* a broken scriptlet stays inside */ }`;
      (document.head || document.documentElement).appendChild(el);
      el.remove();
    } catch {
      /* a scriptlet that cannot even be inserted must not break the page */
    }
  }

  // Raw JavaScript rules (`#%#`) run for the same reason and at the same
  // moment as the scriptlets: they install property traps the page's own
  // scripts must meet. Each rule gets a tag of its own — one rule with a
  // syntax error must not take the others down with it.
  if (Array.isArray(data.jsrules)) {
    for (const script of data.jsrules) {
      try {
        const el = withNonce(document.createElement('script'));
        el.textContent = `try {\n${script}\n} catch { /* a broken rule stays inside */ }`;
        (document.head || document.documentElement).appendChild(el);
        el.remove();
      } catch {
        /* a rule that cannot even be inserted must not break the page */
      }
    }
  }

  // --- procedural rules -----------------------------------------------------

  const matchesAttr = (el, arg) => {
    const eq = arg.indexOf('=');
    const name = (eq === -1 ? arg : arg.slice(0, eq)).trim();
    if (!name || !el.hasAttribute(name)) {
      return false;
    }
    if (eq === -1) {
      return true;
    }
    const want = arg.slice(eq + 1).trim();
    const value = el.getAttribute(name);
    if (/^\/.*\/$/.test(want)) {
      try {
        return new RegExp(want.slice(1, -1)).test(value);
      } catch {
        return false;
      }
    }
    return value === want;
  };

  const matchesCss = (el, pseudo, arg) => {
    const colon = arg.indexOf(':');
    if (colon === -1) {
      return false;
    }
    const prop = arg.slice(0, colon).trim();
    const want = arg.slice(colon + 1).trim();
    let actual;
    try {
      const computed = window.getComputedStyle(el, pseudo);
      if (!computed) {
        return false;
      }
      actual = computed.getPropertyValue(prop) || computed[prop];
    } catch {
      return false;
    }
    if (actual === undefined || actual === null) {
      return false;
    }
    if (/^\/.*\/$/.test(want)) {
      try {
        return new RegExp(want.slice(1, -1)).test(String(actual));
      } catch {
        return false;
      }
    }
    return String(actual).trim() === want;
  };

  const pathMatches = (arg) => {
    try {
      return new RegExp(arg).test(location.pathname);
    } catch {
      return true;
    }
  };

  const queryAll = (root, selector) => {
    try {
      return root.querySelectorAll(selector);
    } catch {
      return [];
    }
  };

  // A leading combinator only makes sense relative to the previous match.
  const scoped = (selector) => (/^\s*[>+~]/.test(selector) ? `:scope ${selector}` : selector);

  const applyAction = (elements, action) => {
    const { type, arg } = action ?? {};
    for (const el of elements) {
      try {
        if (!type) {
          el.style.setProperty('display', 'none', 'important');
        } else if (type === 'style') {
          el.style.cssText += `;${arg}`;
        } else if (type === 'remove') {
          el.remove();
        } else if (type === 'remove-attr') {
          el.removeAttribute(arg);
        } else if (type === 'remove-class') {
          el.classList.remove(arg);
        }
      } catch {
        /* skip this element */
      }
    }
  };

  const filter = (elements, test) => {
    const kept = new Set();
    for (const el of elements) {
      if (test(el)) {
        kept.add(el);
      }
    }
    return kept;
  };

  const applyProcedural = (rule) => {
    // The payload carries these as JSON strings (the engine serializes the
    // crate's structure); accept an object too so both shapes work.
    let entry = rule;
    if (typeof entry === 'string') {
      try {
        entry = JSON.parse(entry);
      } catch {
        return;
      }
    }
    // Every step narrows the same set; `null` means "not started yet", which
    // the element-wide steps treat as "everything".
    let current = null;
    for (const op of entry?.selector ?? []) {
      const { type, arg } = op;
      if (type === 'css-selector') {
        if (current === null) {
          current = new Set(queryAll(document, arg));
        } else {
          const next = new Set();
          for (const el of current) {
            for (const found of queryAll(el, scoped(arg))) {
              next.add(found);
            }
          }
          current = next;
        }
      } else if (type === 'matches-path') {
        if (!pathMatches(arg)) {
          return;
        }
      } else if (type === 'upward') {
        current ??= new Set(queryAll(document, '*'));
        const raised = new Set();
        for (const el of current) {
          const levels = /^\d+$/.test(arg) ? parseInt(arg, 10) || 1 : 0;
          let parent = el;
          if (levels) {
            for (let i = 0; i < levels && parent; i++) {
              parent = parent.parentElement;
            }
          } else if (el.closest) {
            parent = el.closest(arg);
          }
          if (parent) {
            raised.add(parent);
          }
        }
        current = raised;
      } else if (type === 'xpath') {
        const nodes = new Set();
        try {
          const result = document.evaluate(
            arg,
            document,
            null,
            XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
            null
          );
          for (let i = 0; i < result.snapshotLength; i++) {
            nodes.add(result.snapshotItem(i));
          }
        } catch {
          /* unsupported xpath */
        }
        current = nodes;
      } else {
        current ??= new Set(queryAll(document, '*'));
        if (type === 'has-text') {
          current = filter(current, (el) => (el.textContent || '').includes(arg));
        } else if (type === 'min-text-length') {
          const min = parseInt(arg, 10) || 0;
          current = filter(current, (el) => (el.textContent || '').length >= min);
        } else if (type === 'matches-attr') {
          current = filter(current, (el) => matchesAttr(el, arg));
        } else if (type === 'matches-css') {
          current = filter(current, (el) => matchesCss(el, null, arg));
        } else if (type === 'matches-css-before') {
          current = filter(current, (el) => matchesCss(el, ':before', arg));
        } else if (type === 'matches-css-after') {
          current = filter(current, (el) => matchesCss(el, ':after', arg));
        }
      }
      if (current !== null && current.size === 0) {
        return;
      }
    }
    if (current?.size) {
      applyAction(current, entry.action);
    }
  };

  const runProcedural = () => {
    for (const rule of procedural) {
      try {
        applyProcedural(rule);
      } catch {
        /* skip this rule */
      }
    }
  };

  if (procedural.length) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', runProcedural);
    } else {
      runProcedural();
    }
  }

  // --- dynamic generic lookup ----------------------------------------------
  //
  // The proxy scanned the initial HTML, so those tokens are already covered;
  // classes and ids the page adds later are batched to the local endpoint the
  // proxy answers.

  // Tokens the proxy already looked up (its scan found a selector for them).
  const seenTokens = new Set();
  for (const sel of generic) {
    if (sel.length > 1 && !/[ .#\[:]/.test(sel.slice(1))) {
      if (sel.startsWith('.')) {
        seenTokens.add(`c${sel.slice(1)}`);
      } else if (sel.startsWith('#')) {
        seenTokens.add(`i${sel.slice(1)}`);
      }
    }
  }

  // The dynamic lookup is on unless the payload says otherwise ($generichide):
  // without it nothing would ever ask for the tokens the proxy never scanned.
  const dynamic = data.dynamic !== false;
  let pendingClasses = [];
  let pendingIds = [];
  let timer = null;

  const flushGeneric = async () => {
    timer = null;
    if (!pendingClasses.length && !pendingIds.length) {
      return;
    }
    const classes = pendingClasses.slice(0, 500);
    const ids = pendingIds.slice(0, 300);
    pendingClasses = [];
    pendingIds = [];
    const url =
      `${base}/adfree-generic.js` +
      `?dmn=${encodeURIComponent(dmn)}` +
      `&c=${encodeURIComponent(classes.join(' '))}` +
      `&i=${encodeURIComponent(ids.join(' '))}`;
    try {
      const response = await fetch(url);
      const answer = response.ok ? await response.json() : [];
      // The endpoint answers for the host alone. A page-scoped `#@#`
      // exception is in the payload; drop the selectors it names here.
      const selectors = Array.isArray(answer)
        ? answer.filter((selector) => !exceptions.has(selector))
        : [];
      if (!selectors.length) {
        return;
      }
      dynamicCss += `${dynamicCss ? '\n' : ''}${selectors.join(',')}{display:none!important}`;
      installStyles();
    } catch {
      /* fetch unavailable: dynamic rules are simply skipped */
    }
  };

  // --- AdGuard Assistant bridge --------------------------------------------
  //
  // The assistant is a userscript (or the browser extension of the same name)
  // that draws its own panel on the page and then asks the *host* to do the
  // work through five globals. Nothing in a plain browser defines them, which
  // is why the assistant only ever worked inside AdGuard's own builds: they
  // inject the missing half. This is that half.
  //
  // The five names and their callback shapes are AdGuard's, not ours, so the
  // assistant published by AdGuard runs unmodified against this engine.
  const assistantUrl = (action, params) => {
    const query = Object.entries(params || {})
      .map(([key, value]) => `&${key}=${encodeURIComponent(value)}`)
      .join('');
    return `${base}/adfree-assistant.json?act=${action}${query}`;
  };

  const assistantCall = async (action, params) => {
    try {
      const response = await fetch(assistantUrl(action, params), {
        credentials: 'omit',
      });
      return response.ok ? await response.json() : null;
    } catch {
      return null;
    }
  };

  // `ADG_addRule(rule, callback)`: the element the user picked became a rule.
  const addRule = (rule, callback) => {
    if (typeof rule !== 'string' || !rule.trim()) {
      if (callback) callback();
      return;
    }
    const done = (ok) => {
      if (callback) callback(ok);
    };
    // The engine applies the rule before it answers, so one more ask of the
    // live rules covers the element the user picked — the page itself never
    // has to be reloaded for the rule to take effect.
    assistantCall('rule', { rule, dmn }).then((answer) => {
      const accepted = Boolean(answer && answer.ok);
      if (accepted) {
        refreshSoon();
      }
      done(accepted);
    });
  };

  // `ADG_temporaryDontBlock(timeout, callback)`: suspend filtering for this
  // page for `timeout` seconds. AdGuard implements it by disabling the matching
  // rules for the window; here the page gets a document exception that is
  // removed again when the window closes.
  const temporaryDontBlock = (timeout, callback) => {
    const seconds = Math.max(1, Math.min(600, Number(timeout) || 30));
    const rule = `@@||${dmn}^$document`;
    const finish = (ok) => {
      if (callback) callback(ok);
    };
    assistantCall('rule', { rule, dmn }).then((answer) => {
      const ok = Boolean(answer && answer.ok);
      finish(ok);
      // The exception is a document rule: it only takes effect on the next
      // load, which is also what AdGuard's assistant does here. A harness
      // driving this without a document to lose sets the flag to opt out.
      if (ok && host.__adfreeNoAssistantReload !== true) {
        try {
          location.reload();
        } catch {
          /* nothing to reload */
        }
      }
      setTimeout(() => {
        assistantCall('unrule', { rule, dmn });
      }, seconds * 1000);
    });
  };

  // `ADG_isFiltered(callback)`: is this page filtered at all (the assistant
  // shows "protection is off" instead of its usual panel).
  const isFiltered = (callback) => {
    assistantCall('filtered', { dmn }).then((answer) => {
      const filtered = Boolean(answer && answer.filtered);
      if (callback) callback(filtered);
      return filtered;
    });
  };

  // `ADG_changeFilteringState(state, callback)`: the panel's own switch.
  const changeFilteringState = (state, callback) => {
    assistantCall('switch', { on: state ? 1 : 0, dmn }).then((answer) => {
      if (callback) callback(Boolean(answer && answer.ok));
    });
  };

  // `ADG_sendAbuse(url, callback)`: "report this page". AdFree has nobody to
  // report to and does not phone home; the call is acknowledged so the panel
  // can close.
  const sendAbuse = (url, callback) => {
    assistantCall('abuse', { url: String(url || ''), dmn }).then(() => {
      if (callback) callback();
    });
  };

  const host = typeof unsafeWindow !== 'undefined' ? unsafeWindow : window;

  // The embedded build of the assistant (`@adguard/assistant`, the
  // `self.assistant.js` bundle) is a userscript that has to be *started*: it
  // draws its panel and hands the rule the user built to
  // `start(null, callback)` instead of going through `ADG_*`. The app injects
  // the bundle when the user installs it from Extensions; this runtime is what
  // offers the way in, because a page has no toolbar to put a button on.
  //
  // The panel is opened on a tap, never on load: the assistant's selector menu
  // covers a corner of the page, and a panel that appears on every page is a
  // panel everybody learns to close.
  const ASSISTANT_BUTTON_ID = '__adfree_assistant_button';

  const openAssistant = () => {
    if (typeof host.adguardAssistant !== 'function') return false;
    try {
      host.adguardAssistant().start(null, (rule) => addRule(rule));
      return true;
    } catch {
      return false;
    }
  };

  const drawAssistantButton = () => {
    if (document.getElementById(ASSISTANT_BUTTON_ID)) return;
    if (typeof host.adguardAssistant !== 'function') return;
    const button = document.createElement('div');
    button.id = ASSISTANT_BUTTON_ID;
    button.setAttribute('role', 'button');
    button.setAttribute('tabindex', '0');
    button.title = 'AdGuard Assistant';
    button.setAttribute('aria-label', 'AdGuard Assistant');
    button.textContent = '\u25C6';
    button.style.cssText = [
      'position:fixed', 'right:16px', 'bottom:16px', 'width:40px', 'height:40px',
      'border-radius:20px', 'display:flex', 'align-items:center',
      'justify-content:center', 'font-size:18px', 'line-height:1',
      'color:#fff', 'background:linear-gradient(140deg,#3fbf6f,#2b8a4b)',
      'box-shadow:0 4px 12px rgba(0,0,0,.35)', 'cursor:pointer',
      'z-index:2147483000', 'user-select:none', 'opacity:.92',
    ].join(';');
    const open = (event) => {
      event.preventDefault();
      event.stopPropagation();
      openAssistant();
    };
    button.addEventListener('click', open);
    button.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') open(event);
    });
    try {
      document.body.appendChild(button);
    } catch {
      /* no body yet: the retry below runs after it exists */
    }
  };

  // The userscript is injected at document-end and may land after this
  // runtime, so both steps repeat for a few seconds before giving up.
  let assistantTries = 0;
  const tryAssistant = () => {
    drawAssistantButton();
    if (document.getElementById(ASSISTANT_BUTTON_ID)) return;
    if (++assistantTries < 40) setTimeout(tryAssistant, 250);
  };
  tryAssistant();

  // --- live rules -----------------------------------------------------------
  //
  // Everything above came out of the document itself: `__adfree_page` and the
  // `adfree-hide` stylesheet were written into the response when it was
  // produced. A browser reuses that response for a later load — and a rule the
  // user added since then (the assistant's picker, the browser extension) is
  // in none of it. That is why a blocked element used to come back on reload:
  // the page was the same bytes, so it hid the same things.
  //
  // The app knows the current rules; this asks it again on every load, and
  // again after a rule is added, so what is hidden is what the engine holds
  // rather than what it held when the page was cached.
  let live = null;
  const applyLive = (answer) => {
    if (!answer || typeof answer !== 'object') {
      return false;
    }
    let changed = false;
    const swap = (target, next) => {
      if (!Array.isArray(next)) {
        return;
      }
      const before = JSON.stringify(target);
      target.length = 0;
      for (const item of next) {
        target.push(item);
      }
      if (JSON.stringify(target) !== before) {
        changed = true;
      }
    };
    swap(hideSelectors, answer.hide);
    swap(stylePairs, answer.style);
    swap(procedural, answer.procedural);
    if (changed) {
      installStyles();
      runProcedural();
    }
    return changed;
  };
  const refreshRules = async () => {
    try {
      const answer = await fetch(
        `${base}/adfree-cosmetics.json?dmn=${encodeURIComponent(dmn)}`,
        { credentials: 'omit', cache: 'no-store' },
      );
      if (!answer.ok) {
        return false;
      }
      live = await answer.json();
    } catch {
      return false;
    }
    return applyLive(live);
  };
  // The engine rebuilds its rule set on a worker, so a rule the assistant just
  // added is only in the answer a moment later: ask again a few times instead
  // of trusting the first answer. Every ask is a local round trip.
  const refreshSoon = () => {
    // The rebuild of a large rule set is not instant, and the page must not be
    // reloaded for the pick to show: keep asking for a few seconds.
    for (const wait of [0, 700, 1500, 2500, 4000, 6000, 9000]) {
      setTimeout(refreshRules, wait);
    }
  };
  // Once the document is parsed: the first paint is already covered by the
  // inline rules, and the fetch must not hold up parsing.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      refreshRules();
    });
  } else {
    refreshRules();
  }

  try {
    host.ADG_addRule = addRule;
    host.ADG_temporaryDontBlock = temporaryDontBlock;
    host.ADG_isFiltered = isFiltered;
    host.ADG_changeFilteringState = changeFilteringState;
    host.ADG_sendAbuse = sendAbuse;
  } catch {
    /* a page that froze its globals simply gets no assistant */
  }

  const note = (kind, token) => {
    if (!token || token.length > 64) {
      return;
    }
    const key = kind + token;
    if (seenTokens.has(key)) {
      return;
    }
    seenTokens.add(key);
    (kind === 'c' ? pendingClasses : pendingIds).push(token);
    if (timer === null) {
      timer = setTimeout(flushGeneric, 300);
    }
  };

  const collect = (root) => {
    if (!root || root.nodeType !== 1) {
      return;
    }
    const stack = [root];
    while (stack.length) {
      const el = stack.pop();
      if (el.nodeType !== 1) {
        continue;
      }
      if (el.classList) {
        for (const token of el.classList) {
          note('c', token);
        }
      }
      if (el.id) {
        note('i', el.id);
      }
      for (const child of el.children ?? []) {
        stack.push(child);
      }
    }
  };

  // --- stylesheet link ------------------------------------------------------
  //
  // The proxy writes the hiding stylesheet into the head as a `<link>` before
  // this script. The page is free to remove it (DOM sanitizers do), and the
  // browser then has to be told again — the same element re-attaches with the
  // bytes it already has cached.

  let hideLink = null;
  try {
    hideLink = document.getElementById('adfree-hide');
  } catch {
    hideLink = null;
  }

  // --- observers ------------------------------------------------------------

  if (
    (procedural.length || dynamic || hideLink || hideSelectors.length) &&
    document.documentElement
  ) {
    let pendingRun = false;
    try {
      const observer = new MutationObserver((records) => {
        // Keep our stylesheet alive if the page removes it. A constructable
        // stylesheet has no node to remove, so only the element path needs it.
        if (styleEl && !styleEl.isConnected) {
          installStyles();
        }
        if (hideLink && !hideLink.isConnected) {
          try {
            stylesHost().appendChild(hideLink);
          } catch {
            /* the link stays detached: static hiding is lost, nothing else */
          }
        }
        if (dynamic) {
          for (const record of records) {
            for (const node of record.addedNodes) {
              collect(node);
            }
          }
        }
        if (procedural.length && !pendingRun) {
          pendingRun = true;
          setTimeout(() => {
            pendingRun = false;
            runProcedural();
          }, 250);
        }
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
    } catch {
      /* no observer: static rules still applied */
    }
  }
})();
