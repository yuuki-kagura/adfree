// The AdSense loader, replaced: the page — and the anti-adblock code that
// watches for it — sees the `adsbygoogle` global the loader leaves behind, and
// the slot pushes the page queues go nowhere.
//
// `loaded` is the flag the real loader sets once its bootstrap ran, which is
// what detection scripts look at; `push` is the queue interface the page's own
// snippet calls. The object never grows, so nothing here can render an ad.
(function () {
  'use strict';
  if (typeof window.adsbygoogle === 'object' && window.adsbygoogle !== null) {
    return;
  }
  window.adsbygoogle = {
    loaded: true,
    push: function () {
      return 0;
    },
  };
})();
