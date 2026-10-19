// Amazon's header bidding (APS), replaced: `init` and `fetchBids` answer like
// the library would when no demand came back, so a page that waits on them
// moves on, and the `apstag` global the page and its detection code look for
// is there.
(function () {
  'use strict';
  if (typeof window.apstag !== 'undefined') {
    return;
  }

  function noop() {}

  window.apstag = {
    init: function (config) {
      if (config && typeof config.cb === 'function') {
        setTimeout(config.cb, 0);
      }
      return true;
    },
    fetchBids: function (slots, done) {
      if (typeof done === 'function') {
        setTimeout(function () {
          done([]);
        }, 0);
      }
    },
    setDisplayBids: function () {
      return [];
    },
    targetingKeys: function () {
      return [];
    },
    renderAd: noop,
    version: '1.0',
  };
})();
