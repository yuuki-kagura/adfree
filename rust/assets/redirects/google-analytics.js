// Google Analytics / Tag Manager, replaced: the page's tracking calls run
// their callbacks and report success, while no hit leaves the page. The
// `ga` queue snippet, the optional `GoogleAnalyticsObject` name and the
// `dataLayer` used by gtag all see the interface they expect.
(function () {
  'use strict';

  var name = window.GoogleAnalyticsObject || 'ga';
  if (window[name] && window[name].loaded) {
    return;
  }

  function noop() {}

  function Tracker() {}
  Tracker.prototype.get = noop;
  Tracker.prototype.set = noop;
  Tracker.prototype.send = noop;

  function ga() {
    var args = Array.prototype.slice.call(arguments);
    if (args.length === 0) {
      return undefined;
    }
    var last = args[args.length - 1];
    if (last && typeof last === 'object' && typeof last.hitCallback === 'function') {
      setTimeout(last.hitCallback, 0);
    } else if (typeof last === 'function') {
      setTimeout(function () {
        last(ga.create());
      }, 0);
    }
    return undefined;
  }

  ga.create = function () {
    return new Tracker();
  };
  ga.getByName = function () {
    return new Tracker();
  };
  ga.getAll = function () {
    return [new Tracker()];
  };
  ga.remove = noop;
  ga.loaded = true;

  var pending = window[name] && window[name].q;
  window[name] = ga;
  // The snippet's queue keeps accepting calls: replay what the page already
  // pushed, then let later pushes run through the stub as well.
  if (Array.isArray(pending)) {
    pending.push = function (args) {
      ga.apply(null, args);
    };
    pending.forEach(function (args) {
      ga.apply(null, args);
    });
  }

  if (window.dataLayer && typeof window.dataLayer.push === 'function') {
    var push = window.dataLayer.push;
    window.dataLayer.push = function () {
      var args = Array.prototype.slice.call(arguments);
      args.forEach(function (item) {
        if (typeof item === 'function') {
          setTimeout(item, 0);
          return;
        }
        if (!item || typeof item !== 'object') {
          return;
        }
        if (typeof item.eventCallback === 'function') {
          setTimeout(item.eventCallback, 0);
        }
        Object.keys(item).forEach(function (key) {
          var value = item[key];
          if (value && typeof value.event_callback === 'function') {
            setTimeout(value.event_callback, 0);
          }
        });
      });
      return push.apply(window.dataLayer, args);
    };
  }

  if (window.google_optimize && typeof window.google_optimize.get === 'function') {
    window.google_optimize = { get: noop };
  }
})();
