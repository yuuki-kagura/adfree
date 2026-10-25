// FingerprintJS v3, replaced: `load()` resolves to an instance whose `get()`
// yields a random-looking visitor id, so a page that awaits the library
// continues without the probe ever running.
(function () {
  'use strict';

  if (window.FingerprintJS) {
    return;
  }

  var visitorId = '';
  for (var i = 0; i < 8; i += 1) {
    visitorId += (Math.random() * 0x10000 + 0x1000).toString(16).slice(-4);
  }

  function FingerprintJS() {}
  FingerprintJS.prototype = {
    load: function () {
      return Promise.resolve(new FingerprintJS());
    },
    get: function () {
      return Promise.resolve({ visitorId: visitorId });
    },
    hashComponents: function () {
      return '';
    },
  };

  window.FingerprintJS = new FingerprintJS();
})();
