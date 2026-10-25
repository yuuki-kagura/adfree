// The Gemius player plugin, replaced: video players call it to report
// playback events, and the stub accepts every event without sending it.
(function () {
  'use strict';

  if (window.GemiusPlayer) {
    return;
  }

  function noop() {}

  function GemiusPlayer() {}
  GemiusPlayer.prototype = {
    setVideoObject: noop,
    newProgram: noop,
    programEvent: noop,
    newAd: noop,
    adEvent: noop,
  };

  window.GemiusPlayer = GemiusPlayer;
})();
