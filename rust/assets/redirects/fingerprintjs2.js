// FingerprintJS v2, replaced: the page gets a stable-looking visitor id and
// an empty component list through the callbacks the library documents, and
// no fingerprinting code runs.
(function () {
  'use strict';

  if (window.Fingerprint2) {
    return;
  }

  var visitorId = '';
  for (var i = 0; i < 8; i += 1) {
    visitorId += (Math.random() * 0x10000 + 0x1000).toString(16).slice(-4);
  }

  function Fingerprint2() {}
  Fingerprint2.get = function (options, callback) {
    if (typeof options === 'function') {
      callback = options;
    }
    setTimeout(function () {
      if (typeof callback === 'function') {
        callback(visitorId, []);
      }
    }, 0);
  };
  Fingerprint2.getPromise = function () {
    return Promise.resolve([]);
  };
  Fingerprint2.getSync = function () {
    return [];
  };
  Fingerprint2.prototype = {
    get: Fingerprint2.get,
  };

  window.Fingerprint2 = Fingerprint2;
  // Some bundles publish the constructor under the shorter name.
  window.Fingerprint = Fingerprint2;
})();
