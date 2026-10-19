// Google Publisher Tag, replaced: the page's `googletag.cmd` queue runs (that
// is what the real library does the moment it loads), the slot and service
// calls hand back chainable stubs, and the calls that would wait for an ad
// answer return straight away.
//
// A page (or an anti-adblock check) that only asks whether the library is
// there — `typeof googletag`, `googletag.apiReady` — sees a library that is
// there. A page that queued calls before the library loaded still gets them
// run, in order, against the stubs.
(function () {
  'use strict';
  var existing = window.googletag;
  if (existing && (existing.apiReady === true || typeof existing.defineSlot === 'function')) {
    return;
  }

  function noop() {}

  function slotStub() {
    var id = {
      getId: function () {
        return '';
      },
      getAdUnitPath: function () {
        return '';
      },
    };
    var slot = {
      addEventListener: noop,
      addService: function () {
        return slot;
      },
      clearTargeting: function () {
        return slot;
      },
      defineSizeMapping: function () {
        return slot;
      },
      getAdUnitPath: function () {
        return '';
      },
      getSlotElementId: function () {
        return '';
      },
      getSlotId: function () {
        return id;
      },
      getTargeting: function () {
        return [];
      },
      getTargetingKeys: function () {
        return [];
      },
      setCategoryExclusion: function () {
        return slot;
      },
      setClickUrl: function () {
        return slot;
      },
      setCollapseEmptyDiv: function () {
        return slot;
      },
      setTargeting: function () {
        return slot;
      },
      updateTargetingFromMap: function () {
        return slot;
      },
    };
    return slot;
  }

  var pubads = {
    addEventListener: noop,
    clearTargeting: function () {
      return pubads;
    },
    collapseEmptyDivs: noop,
    disableInitialLoad: noop,
    enableSingleRequest: noop,
    getSlots: function () {
      return [];
    },
    refresh: noop,
    setCategoryExclusion: function () {
      return pubads;
    },
    setCentering: noop,
    setPrivacySettings: noop,
    setRequestNonPersonalizedAds: noop,
    setTargeting: function () {
      return pubads;
    },
  };

  // The page's own snippet leaves `googletag.cmd` as an array; the real
  // library turns it into a queue that runs as it loads. An array with a
  // running `push` is both.
  var cmd = [];
  cmd.push = function (fn) {
    if (typeof fn === 'function') {
      try {
        fn();
      } catch (error) {
        // The page's callback threw: the real queue would swallow it the same
        // way, and the page must not see a different failure here.
      }
    }
    return 0;
  };

  window.googletag = {
    apiReady: true,
    pubadsReady: true,
    cmd: cmd,
    companionAds: function () {
      return { setRefreshUnfilledSlots: noop };
    },
    defineOutOfPageSlot: function () {
      return slotStub();
    },
    defineSlot: function () {
      return slotStub();
    },
    destroySlots: noop,
    display: noop,
    enableServices: noop,
    getVersion: function () {
      return '0';
    },
    pubads: function () {
      return pubads;
    },
    setAdIframeTitle: noop,
    sizeMapping: function () {
      return {
        addSize: function () {
          return this;
        },
        build: function () {
          return [];
        },
      };
    },
  };

  if (existing && Array.isArray(existing.cmd)) {
    for (var i = 0; i < existing.cmd.length; i++) {
      cmd.push(existing.cmd[i]);
    }
  }
})();
