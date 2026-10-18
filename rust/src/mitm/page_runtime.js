// AdFree page runtime: applies the cosmetic rules the proxy computed for
// this page. Served from the app's own origin (the `https://192.0.2.1` address
// the tunnel answers locally), injected early in `<head>` so the hiding
// stylesheet lands before the page's own resources.
//
// The rules arrive inline as `window.__adfree_page` (written by the proxy):
//
// ```text
// { style: [[selector, css]], generic: [selector],
//   procedural: [{selector: [{type, arg}], action: {type, arg}|null}],
//   scriptlets: "js source", dynamic: true }
// ```
//
// Element hiding is not in there: the proxy writes it as a stylesheet
// (`<link rel="stylesheet" id="adfree-hide">`) served from that same origin,
// which the browser fetches once per site and keeps until the rules change.
//
// Everything is defensive: a broken rule must never take a page down, so
// every step is guarded and failures are swallowed.

(function () {
  'use strict';

  // Where this runtime was served from, and the host whose rules it applies:
  // both travel in its own tag (`<script src="https://192.0.2.1/…?dmn=…">`),
  // the same way AdGuard's content script carries `dmn`. The fallbacks keep a
  // legacy same-origin tag (a page cached before an app update) working.
  var base = location.origin;
  var dmn = location.hostname;
  try {
    var selfSrc = document.currentScript && document.currentScript.src;
    if (selfSrc) {
      var selfUrl = new URL(selfSrc);
      base = selfUrl.origin;
      var param = selfUrl.searchParams.get('dmn');
      if (param) {
        dmn = param;
      }
    }
  } catch (e) {
    /* keep the fallbacks */
  }

  var data = window.__adfree_page;
  if (!data || typeof data !== 'object') {
    // No payload for this page: the proxy only sends one when its scan of the
    // HTML found something. The runtime still has work to do — the dynamic
    // class/id lookup is what covers a page whose body the proxy never saw.
    data = {};
  }
  // The payload has been consumed; do not leave it for the page to read.
  try {
    delete window.__adfree_page;
  } catch (e) {
    window.__adfree_page = undefined;
  }

  var styleEl = null;
  // Selectors discovered at runtime (the dynamic class/id lookup).
  var dynamicCss = '';

  function cssText() {
    var rules = [];
    if (data.generic && data.generic.length) {
      rules.push(data.generic.join(',') + '{display:none!important}');
    }
    var styles = data.style || [];
    for (var i = 0; i < styles.length; i++) {
      var pair = styles[i];
      if (pair && pair.length === 2) {
        rules.push(pair[0] + '{' + pair[1] + '}');
      }
    }
    if (dynamicCss) {
      rules.push(dynamicCss);
    }
    return rules.join('\n');
  }

  function installStyles() {
    var css = cssText();
    if (!css) {
      return false;
    }
    try {
      var el = document.createElement('style');
      el.setAttribute('data-adfree', 'css');
      el.textContent = css;
      (document.head || document.documentElement).appendChild(el);
      styleEl = el;
      return true;
    } catch (e) {
      return false;
    }
  }

  installStyles();

  // Scriptlets run immediately: they install property traps and must beat the
  // page's own scripts.
  if (data.scriptlets) {
    try {
      (new Function(data.scriptlets))();
    } catch (e) {
      /* a broken scriptlet must not break the page */
    }
  }

  // --- procedural rules -----------------------------------------------------

  function matchesAttr(el, arg) {
    var eq = arg.indexOf('=');
    var name = eq === -1 ? arg : arg.slice(0, eq);
    name = name.trim();
    if (!name || !el.hasAttribute(name)) {
      return false;
    }
    if (eq === -1) {
      return true;
    }
    var want = arg.slice(eq + 1).trim();
    var value = el.getAttribute(name);
    if (want.length > 1 && want.charAt(0) === '/' && want.charAt(want.length - 1) === '/') {
      try {
        return new RegExp(want.slice(1, -1)).test(value);
      } catch (e) {
        return false;
      }
    }
    return value === want;
  }

  function matchesCss(el, pseudo, arg) {
    var colon = arg.indexOf(':');
    if (colon === -1) {
      return false;
    }
    var prop = arg.slice(0, colon).trim();
    var want = arg.slice(colon + 1).trim();
    var actual;
    try {
      var computed = window.getComputedStyle(el, pseudo);
      if (!computed) {
        return false;
      }
      actual = computed.getPropertyValue(prop);
      if (!actual) {
        actual = computed[prop];
      }
    } catch (e) {
      return false;
    }
    if (actual === undefined || actual === null) {
      return false;
    }
    if (want.length > 1 && want.charAt(0) === '/' && want.charAt(want.length - 1) === '/') {
      try {
        return new RegExp(want.slice(1, -1)).test(String(actual));
      } catch (e) {
        return false;
      }
    }
    return String(actual).trim() === want;
  }

  function pathMatches(arg) {
    var re;
    try {
      re = new RegExp(arg);
    } catch (e) {
      return true;
    }
    return re.test(location.pathname);
  }

  function queryAll(root, selector) {
    try {
      return root.querySelectorAll(selector);
    } catch (e) {
      return [];
    }
  }

  function scoped(selector) {
    // A leading combinator only makes sense relative to the previous match.
    return /^\s*[>+~]/.test(selector) ? ':scope ' + selector : selector;
  }

  function applyAction(elements, action) {
    var type = action && action.type;
    for (var i = 0; i < elements.length; i++) {
      var el = elements[i];
      try {
        if (!type) {
          el.style.setProperty('display', 'none', 'important');
        } else if (type === 'style') {
          el.style.cssText += ';' + action.arg;
        } else if (type === 'remove') {
          el.remove();
        } else if (type === 'remove-attr') {
          el.removeAttribute(action.arg);
        } else if (type === 'remove-class') {
          el.classList.remove(action.arg);
        }
      } catch (e) {
        /* skip this element */
      }
    }
  }

  function applyProcedural(entry) {
    // The payload carries these as JSON strings (the engine serializes the
    // crate's structure); accept an object too so both shapes work.
    if (typeof entry === 'string') {
      try {
        entry = JSON.parse(entry);
      } catch (e) {
        return;
      }
    }
    var ops = (entry && entry.selector) || [];
    var current = null;
    for (var i = 0; i < ops.length; i++) {
      var op = ops[i];
      var type = op.type;
      if (type === 'css-selector') {
        if (current === null) {
          current = queryAll(document, op.arg);
        } else {
          var next = [];
          var seen = [];
          for (var j = 0; j < current.length; j++) {
            var found = queryAll(current[j], scoped(op.arg));
            for (var k = 0; k < found.length; k++) {
              if (seen.indexOf(found[k]) === -1) {
                seen.push(found[k]);
                next.push(found[k]);
              }
            }
          }
          current = next;
        }
      } else if (type === 'matches-path') {
        if (!pathMatches(op.arg)) {
          return;
        }
      } else if (type === 'upward') {
        if (current === null) {
          current = queryAll(document, '*');
        }
        var raised = [];
        for (var u = 0; u < current.length; u++) {
          var el = current[u];
          var parent = el;
          if (/^\d+$/.test(op.arg)) {
            var levels = parseInt(op.arg, 10) || 1;
            for (var l = 0; l < levels && parent; l++) {
              parent = parent.parentElement;
            }
          } else if (el.closest) {
            parent = el.closest(op.arg);
          }
          if (parent && raised.indexOf(parent) === -1) {
            raised.push(parent);
          }
        }
        current = raised;
      } else if (type === 'xpath') {
        var nodes = [];
        try {
          var result = document.evaluate(
            op.arg,
            document,
            null,
            XPathResult.ORDERED_NODE_SNAPSHOT_TYPE,
            null
          );
          for (var x = 0; x < result.snapshotLength; x++) {
            nodes.push(result.snapshotItem(x));
          }
        } catch (e) {
          /* unsupported xpath */
        }
        current = nodes;
      } else {
        if (current === null) {
          current = queryAll(document, '*');
        }
        var kept = [];
        for (var m = 0; m < current.length; m++) {
          var node = current[m];
          var ok = false;
          if (type === 'has-text') {
            ok = (node.textContent || '').indexOf(op.arg) !== -1;
          } else if (type === 'min-text-length') {
            ok = (node.textContent || '').length >= (parseInt(op.arg, 10) || 0);
          } else if (type === 'matches-attr') {
            ok = matchesAttr(node, op.arg);
          } else if (type === 'matches-css') {
            ok = matchesCss(node, null, op.arg);
          } else if (type === 'matches-css-before') {
            ok = matchesCss(node, ':before', op.arg);
          } else if (type === 'matches-css-after') {
            ok = matchesCss(node, ':after', op.arg);
          }
          if (ok) {
            kept.push(node);
          }
        }
        current = kept;
      }
      if (current !== null && current.length === 0) {
        return;
      }
    }
    if (current && current.length) {
      applyAction(current, entry.action);
    }
  }

  var procedural = data.procedural || [];

  function runProcedural() {
    for (var i = 0; i < procedural.length; i++) {
      try {
        applyProcedural(procedural[i]);
      } catch (e) {
        /* skip this rule */
      }
    }
  }

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

  var seenTokens = Object.create(null);

  // Tokens the proxy already looked up (its scan found a selector for them).
  var generic = data.generic || [];
  for (var g = 0; g < generic.length; g++) {
    var sel = generic[g];
    if (sel.length > 1 && sel.indexOf(' ', 1) === -1 && sel.indexOf('.', 1) === -1 &&
        sel.indexOf('#', 1) === -1 && sel.indexOf('[') === -1 && sel.indexOf(':') === -1) {
      if (sel.charAt(0) === '.') {
        seenTokens['c' + sel.slice(1)] = true;
      } else if (sel.charAt(0) === '#') {
        seenTokens['i' + sel.slice(1)] = true;
      }
    }
  }

  // The dynamic lookup is on unless the payload says otherwise ($generichide):
  // without it nothing would ever ask for the tokens the proxy never scanned.
  var dynamic = data.dynamic !== false;
  var pendingClasses = [];
  var pendingIds = [];
  var timer = null;

  function note(kind, token) {
    if (!token || token.length > 64) {
      return;
    }
    var key = kind + token;
    if (seenTokens[key]) {
      return;
    }
    seenTokens[key] = true;
    (kind === 'c' ? pendingClasses : pendingIds).push(token);
    if (timer === null) {
      timer = setTimeout(flushGeneric, 300);
    }
  }

  function collect(root) {
    if (!root || root.nodeType !== 1) {
      return;
    }
    var stack = [root];
    while (stack.length) {
      var el = stack.pop();
      if (el.nodeType !== 1) {
        continue;
      }
      if (el.classList) {
        for (var i = 0; i < el.classList.length; i++) {
          note('c', el.classList[i]);
        }
      }
      if (el.id) {
        note('i', el.id);
      }
      var child = el.firstElementChild;
      while (child) {
        stack.push(child);
        child = child.nextElementSibling;
      }
    }
  }

  function flushGeneric() {
    timer = null;
    if (!pendingClasses.length && !pendingIds.length) {
      return;
    }
    var classes = pendingClasses;
    var ids = pendingIds;
    pendingClasses = [];
    pendingIds = [];
    if (classes.length > 500) {
      classes = classes.slice(0, 500);
    }
    if (ids.length > 300) {
      ids = ids.slice(0, 300);
    }
    var url =
      base +
      '/adfree-generic.js?dmn=' +
      encodeURIComponent(dmn) +
      '&c=' +
      encodeURIComponent(classes.join(' ')) +
      '&i=' +
      encodeURIComponent(ids.join(' '));
    try {
      fetch(url)
        .then(function (r) {
          return r.ok ? r.json() : [];
        })
        .then(function (selectors) {
          if (!selectors || !selectors.length) {
            return;
          }
          var css = selectors.join(',') + '{display:none!important}';
          dynamicCss += (dynamicCss ? '\n' : '') + css;
          if (styleEl && styleEl.isConnected) {
            styleEl.textContent += '\n' + css;
          } else {
            installStyles();
          }
        })
        .catch(function () {});
    } catch (e) {
      /* fetch unavailable: dynamic rules are simply skipped */
    }
  }

  // --- stylesheet link ------------------------------------------------------
  //
  // The proxy writes the hiding stylesheet into the head as a `<link>` before
  // this script. The page is free to remove it (DOM sanitizers do), and the
  // browser then has to be told again — the same element re-attaches with the
  // bytes it already has cached.

  var hideLink = null;
  try {
    hideLink = document.getElementById('adfree-hide');
  } catch (e) {
    hideLink = null;
  }

  // --- observers ------------------------------------------------------------

  if ((procedural.length || dynamic || hideLink) && document.documentElement) {
    var pendingRun = false;
    try {
      var observer = new MutationObserver(function (records) {
        // Keep our stylesheet alive if the page removes it.
        if (styleEl && !styleEl.isConnected) {
          installStyles();
        }
        if (hideLink && !hideLink.isConnected) {
          try {
            (document.head || document.documentElement).appendChild(hideLink);
          } catch (e) {
            /* the link stays detached: static hiding is lost, nothing else */
          }
        }
        if (dynamic) {
          for (var i = 0; i < records.length; i++) {
            var added = records[i].addedNodes;
            for (var j = 0; j < added.length; j++) {
              collect(added[j]);
            }
          }
        }
        if (procedural.length && !pendingRun) {
          pendingRun = true;
          setTimeout(function () {
            pendingRun = false;
            runProcedural();
          }, 250);
        }
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
    } catch (e) {
      /* no observer: static rules still applied */
    }
  }
})();
