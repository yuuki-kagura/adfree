// The Google IMA SDK, replaced by a small neutral API. A page that loads
// ima3.js to schedule ads still finds the constructors and events it calls;
// the ad request completes with an empty manager, which immediately reports
// that content may resume. No ad markup, VAST request or player control is
// created here.
//
// This is an independent stub written for AdFree (not a copy of the AdGuard
// redirect): every method is deliberately a no-op and the only state is the
// listener list and volume.
(function () {
  'use strict';

  if (window.google && window.google.ima && window.google.ima.VERSION) {
    return;
  }

  function noop() {}

  function EventTarget() {
    this._listeners = {};
  }

  EventTarget.prototype.addEventListener = function (type, listener) {
    if (typeof listener !== 'function') {
      return;
    }
    if (!this._listeners[type]) {
      this._listeners[type] = [];
    }
    this._listeners[type].push(listener);
  };

  EventTarget.prototype.removeEventListener = function (type, listener) {
    var list = this._listeners[type];
    if (!list) {
      return;
    }
    var at = list.indexOf(listener);
    if (at !== -1) {
      list.splice(at, 1);
    }
  };

  EventTarget.prototype._dispatch = function (event) {
    var list = this._listeners[event.type];
    if (!list) {
      return;
    }
    list = list.slice();
    for (var i = 0; i < list.length; i += 1) {
      try {
        list[i](event);
      } catch (error) {
        // The real event target also isolates one listener's exception from
        // the others; the page must not lose the rest of its callbacks.
        setTimeout(function () {
          throw error;
        }, 0);
      }
    }
  };

  function inherit(child, parent) {
    child.prototype = Object.create(parent.prototype);
    child.prototype.constructor = child;
  }

  function AdDisplayContainer(container, video) {
    this._container = container || null;
    this._video = video || null;
  }
  AdDisplayContainer.prototype.initialize = noop;
  AdDisplayContainer.prototype.destroy = noop;
  AdDisplayContainer.prototype.getVideoElement = function () {
    return this._video;
  };

  function AdEvent(type) {
    this.type = type;
  }
  AdEvent.prototype.getAd = function () {
    return null;
  };
  AdEvent.prototype.getAdData = function () {
    return {};
  };
  AdEvent.Type = {
    AD_BREAK_READY: 'adBreakReady',
    AD_BUFFERING: 'adBuffering',
    AD_CAN_PLAY: 'adCanPlay',
    AD_METADATA: 'adMetadata',
    AD_PROGRESS: 'adProgress',
    ALL_ADS_COMPLETED: 'allAdsCompleted',
    CLICK: 'click',
    COMPLETE: 'complete',
    CONTENT_PAUSE_REQUESTED: 'contentPauseRequested',
    CONTENT_RESUME_REQUESTED: 'contentResumeRequested',
    DURATION_CHANGE: 'durationChange',
    EXPANDED_CHANGED: 'expandedChanged',
    FIRST_QUARTILE: 'firstQuartile',
    IMPRESSION: 'impression',
    INTERACTION: 'interaction',
    LINEAR_CHANGE: 'linearChange',
    LINEAR_CHANGED: 'linearChanged',
    LOADED: 'loaded',
    LOG: 'log',
    MIDPOINT: 'midpoint',
    PAUSED: 'pause',
    RESUMED: 'resume',
    SKIPPABLE_STATE_CHANGED: 'skippableStateChanged',
    SKIPPED: 'skip',
    STARTED: 'start',
    THIRD_QUARTILE: 'thirdQuartile',
    USER_CLOSE: 'userClose',
    VIDEO_CLICKED: 'videoClicked',
    VIDEO_ICON_CLICKED: 'videoIconClicked',
    VIEWABLE_IMPRESSION: 'viewable_impression',
    VOLUME_CHANGED: 'volumeChange',
    VOLUME_MUTED: 'mute',
  };

  function AdError(message, code, type) {
    this.message = message || '';
    this.code = code || 0;
    this.type = type || 'adError';
  }
  AdError.prototype.getMessage = function () {
    return this.message;
  };
  AdError.prototype.getErrorCode = function () {
    return this.code;
  };
  AdError.prototype.getType = function () {
    return this.type;
  };
  AdError.prototype.toString = function () {
    return this.message;
  };

  function AdErrorEvent(error) {
    this.type = 'adError';
    this._error = error || new AdError();
  }
  AdErrorEvent.prototype.getError = function () {
    return this._error;
  };
  AdErrorEvent.prototype.getUserRequestContext = function () {
    return {};
  };
  AdErrorEvent.Type = { AD_ERROR: 'adError' };

  function AdsManagerLoadedEvent(type, manager) {
    this.type = type || AdsManagerLoadedEvent.Type.ADS_MANAGER_LOADED;
    this._manager = manager || null;
  }
  AdsManagerLoadedEvent.prototype.getAdsManager = function () {
    return this._manager;
  };
  AdsManagerLoadedEvent.prototype.getUserRequestContext = function () {
    return {};
  };
  AdsManagerLoadedEvent.Type = { ADS_MANAGER_LOADED: 'adsManagerLoaded' };

  function AdsManager() {
    EventTarget.call(this);
    this._volume = 1;
    this._started = false;
  }
  inherit(AdsManager, EventTarget);
  AdsManager.prototype.collapse = noop;
  AdsManager.prototype.configureAdsManager = noop;
  AdsManager.prototype.destroy = noop;
  AdsManager.prototype.discardAdBreak = noop;
  AdsManager.prototype.expand = noop;
  AdsManager.prototype.focus = noop;
  AdsManager.prototype.getAdSkippableState = function () {
    return false;
  };
  AdsManager.prototype.getCuePoints = function () {
    return [];
  };
  AdsManager.prototype.getCurrentAd = function () {
    return null;
  };
  AdsManager.prototype.getCurrentAdCuePoints = function () {
    return [];
  };
  AdsManager.prototype.getRemainingTime = function () {
    return 0;
  };
  AdsManager.prototype.getVolume = function () {
    return this._volume;
  };
  AdsManager.prototype.init = noop;
  AdsManager.prototype.isCustomClickTrackingUsed = function () {
    return false;
  };
  AdsManager.prototype.isCustomPlaybackUsed = function () {
    return false;
  };
  AdsManager.prototype.pause = noop;
  AdsManager.prototype.requestNextAdBreak = noop;
  AdsManager.prototype.resize = noop;
  AdsManager.prototype.resume = noop;
  AdsManager.prototype.setVolume = function (volume) {
    this._volume = volume;
  };
  AdsManager.prototype.skip = noop;
  AdsManager.prototype.stop = noop;
  AdsManager.prototype.updateAdsRenderingSettings = noop;
  AdsManager.prototype.start = function () {
    var self = this;
    if (this._started) {
      return;
    }
    this._started = true;
    // Resume while the click that called `start()` still has user activation,
    // so a player's `video.play()` is not rejected by the autoplay policy.
    // No fake ad events are sent because their handlers expect an ad object,
    // not `null`.
    self._dispatch(new AdEvent(AdEvent.Type.CONTENT_RESUME_REQUESTED));
    // The completion event can wait a turn; nothing in the player depends on
    // it to start the content.
    setTimeout(function () {
      self._dispatch(new AdEvent(AdEvent.Type.ALL_ADS_COMPLETED));
    }, 0);
  };

  function AdsRenderingSettings() {}
  AdsRenderingSettings.prototype.restoreCustomPlaybackStateOnAdBreakComplete = false;

  function AdsRequest() {}
  AdsRequest.prototype.setAdWillAutoPlay = noop;
  AdsRequest.prototype.setAdWillPlayMuted = noop;
  AdsRequest.prototype.setContinuousPlayback = noop;

  function ImaSdkSettings() {
    this._cookies = true;
    this._features = {};
    this._locale = '';
    this._ppid = '';
    this._redirects = 0;
    this._playerType = '';
    this._playerVersion = '';
  }
  ImaSdkSettings.prototype.getCompanionBackfill = function () {
    return '';
  };
  ImaSdkSettings.prototype.getDisableCustomPlaybackForIOS10Plus = function () {
    return false;
  };
  ImaSdkSettings.prototype.getFeatureFlags = function () {
    return this._features;
  };
  ImaSdkSettings.prototype.getLocale = function () {
    return this._locale;
  };
  ImaSdkSettings.prototype.getNumRedirects = function () {
    return this._redirects;
  };
  ImaSdkSettings.prototype.getPlayerType = function () {
    return this._playerType;
  };
  ImaSdkSettings.prototype.getPlayerVersion = function () {
    return this._playerVersion;
  };
  ImaSdkSettings.prototype.getPpid = function () {
    return this._ppid;
  };
  ImaSdkSettings.prototype.isCookiesEnabled = function () {
    return this._cookies;
  };
  ImaSdkSettings.prototype.setAutoPlayAdBreaks = noop;
  ImaSdkSettings.prototype.setCompanionBackfill = noop;
  ImaSdkSettings.prototype.setCookiesEnabled = function (enabled) {
    this._cookies = !!enabled;
  };
  ImaSdkSettings.prototype.setDisableCustomPlaybackForIOS10Plus = noop;
  ImaSdkSettings.prototype.setFeatureFlags = function (flags) {
    this._features = flags || {};
  };
  ImaSdkSettings.prototype.setLocale = function (locale) {
    this._locale = locale || '';
  };
  ImaSdkSettings.prototype.setNumRedirects = function (count) {
    this._redirects = count || 0;
  };
  ImaSdkSettings.prototype.setPlayerType = function (type) {
    this._playerType = type || '';
  };
  ImaSdkSettings.prototype.setPlayerVersion = function (version) {
    this._playerVersion = version || '';
  };
  ImaSdkSettings.prototype.setPpid = function (ppid) {
    this._ppid = ppid || '';
  };
  ImaSdkSettings.prototype.setSessionId = noop;
  ImaSdkSettings.prototype.setVpaidAllowed = noop;
  ImaSdkSettings.prototype.setVpaidMode = noop;
  ImaSdkSettings.CompanionBackfillMode = {
    ALWAYS: 'always',
    ON_MASTER_AD: 'on_master_ad',
  };
  ImaSdkSettings.VpaidMode = {
    DISABLED: 0,
    ENABLED: 1,
    INSECURE: 2,
  };

  function AdsLoader(container) {
    EventTarget.call(this);
    this._container = container || null;
    this._settings = new ImaSdkSettings();
    this._manager = new AdsManager();
  }
  inherit(AdsLoader, EventTarget);
  AdsLoader.prototype.contentComplete = noop;
  AdsLoader.prototype.destroy = noop;
  AdsLoader.prototype.getSettings = function () {
    return this._settings;
  };
  AdsLoader.prototype.getVersion = function () {
    return '3.517.2-adfree';
  };
  AdsLoader.prototype.requestAds = function () {
    var self = this;
    setTimeout(function () {
      self._dispatch(
        new AdsManagerLoadedEvent(
          AdsManagerLoadedEvent.Type.ADS_MANAGER_LOADED,
          self._manager
        )
      );
    }, 0);
  };

  var ima = {
    VERSION: '3.517.2-adfree',
    AdDisplayContainer: AdDisplayContainer,
    AdError: AdError,
    AdErrorEvent: AdErrorEvent,
    AdEvent: AdEvent,
    AdsLoader: AdsLoader,
    AdsManager: AdsManager,
    AdsManagerLoadedEvent: AdsManagerLoadedEvent,
    AdsRenderingSettings: AdsRenderingSettings,
    AdsRequest: AdsRequest,
    ImaSdkSettings: ImaSdkSettings,
    settings: new ImaSdkSettings(),
    UiElements: {
      AD_ATTRIBUTION: 'adAttribution',
      COUNTDOWN: 'countdown',
    },
    OmidAccessMode: {
      DOMAIN: 'domain',
      FULL: 'full',
      LIMITED: 'limited',
    },
    ViewMode: {
      FULLSCREEN: 'fullscreen',
      NORMAL: 'normal',
    },
  };

  window.google = window.google || {};
  window.google.ima = ima;
})();
