// Yandex.Metrika, replaced: `ym()` keeps the counter API (hit, reachGoal,
// click callbacks, client ids) and publishes `yaCounter<id>` plus the
// `yacounter<id>inited` event the page waits for.
(function () {
  'use strict';

  function noop() {}

  function later(options) {
    if (!options || typeof options !== 'object') {
      return;
    }
    var callback = options.callback;
    if (typeof callback === 'function') {
      var ctx = options.ctx;
      setTimeout(ctx === undefined ? callback : callback.bind(ctx), 0);
    }
  }

  function callbackFrom(id, param, options) {
    later(options);
  }

  var api = {
    addFileExtension: noop,
    extLink: callbackFrom,
    file: callbackFrom,
    getClientID: function (id, callback) {
      if (typeof callback === 'function') {
        setTimeout(function () {
          callback(null);
        }, 0);
      }
    },
    hit: callbackFrom,
    notBounce: callbackFrom,
    params: noop,
    reachGoal: function (id, target, params, callback, ctx) {
      later({ callback: callback, ctx: ctx });
    },
    setUserID: noop,
    userParams: noop,
    destruct: noop,
  };

  function init(id) {
    window['yaCounter' + id] = api;
    if (typeof document !== 'undefined' && typeof document.dispatchEvent === 'function') {
      try {
        document.dispatchEvent(new Event('yacounter' + id + 'inited'));
      } catch (error) {
        // An environment without Event constructors still gets the counter.
      }
    }
  }

  function ym(id, method) {
    if (method === 'init') {
      init(id);
      return undefined;
    }
    var fn = api[method];
    if (typeof fn !== 'function') {
      return undefined;
    }
    var rest = Array.prototype.slice.call(arguments, 2);
    return fn.apply(null, [id].concat(rest));
  }

  var pending = window.ym && Array.isArray(window.ym.a) ? window.ym.a : null;
  if (typeof window.ym === 'undefined' || pending) {
    window.ym = ym;
    ym.a = pending || [];
    if (pending) {
      pending.forEach(function (params) {
        if (Array.isArray(params) && params.length > 0) {
          init(params[0]);
        }
      });
    }
  }
})();
