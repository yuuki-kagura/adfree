// comScore Scorecard Research, replaced: `COMSCORE.beacon` never sends and
// `purge` clears the page's `_comscore` queue, matching the interface sites
// call after loading the beacon script.
(function () {
  'use strict';

  if (window.COMSCORE) {
    return;
  }

  window.COMSCORE = {
    purge: function () {
      window._comscore = [];
    },
    beacon: function () {},
  };
})();
