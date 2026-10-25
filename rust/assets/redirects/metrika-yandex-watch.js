// The old Yandex.Metrika `watch.js`, replaced: `Ya.Metrika` counters accept
// the page's calls and the queued `yandex_metrika_callbacks` run, so a page
// waiting for its counter does not stall.
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

  function Metrika() {}
  Metrika.counters = function () {
    return [];
  };
  Metrika.prototype.addFileExtension = noop;
  Metrika.prototype.getClientID = noop;
  Metrika.prototype.setUserID = noop;
  Metrika.prototype.userParams = noop;
  Metrika.prototype.params = noop;
  Metrika.prototype.counters = function () {
    return [];
  };
  Metrika.prototype.extLink = function (url, options) {
    later(options);
  };
  Metrika.prototype.file = function (url, options) {
    later(options);
  };
  Metrika.prototype.hit = function (url, options) {
    later(options);
  };
  Metrika.prototype.reachGoal = function (target, params, callback, ctx) {
    later({ callback: callback, ctx: ctx });
  };
  Metrika.prototype.notBounce = later;

  if (window.Ya) {
    window.Ya.Metrika = Metrika;
  } else {
    window.Ya = { Metrika: Metrika };
  }

  if (Array.isArray(window.yandex_metrika_callbacks)) {
    window.yandex_metrika_callbacks.forEach(function (callback) {
      if (typeof callback === 'function') {
        callback();
      }
    });
  }
})();
