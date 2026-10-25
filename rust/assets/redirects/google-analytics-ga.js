// The old ga.js tracker, replaced: `_gaq` accepts and executes the page's
// commands (including the hit callbacks some flows wait on) and `_gat`
// hands out inert trackers, so nothing is sent and nothing stalls.
(function () {
  'use strict';

  if (window._gat) {
    return;
  }

  function noop() {}

  function Gaq() {}
  Gaq.prototype.push = function (item) {
    if (typeof item === 'function') {
      item();
      return;
    }
    if (!Array.isArray(item)) {
      return;
    }
    // The `_link` command is the one gaq call with a visible effect: it
    // navigates the page. Keep it so outbound-link handlers still work.
    if (
      typeof item[0] === 'string' &&
      /(^|\.)_link$/.test(item[0]) &&
      typeof item[1] === 'string'
    ) {
      try {
        window.location.assign(item[1]);
      } catch (error) {
        // A sandboxed frame may refuse the navigation; the tracker is inert
        // either way.
      }
    }
    if (item[0] === '_set' && item[1] === 'hitCallback' && typeof item[2] === 'function') {
      item[2]();
    }
  };

  var gaq = new Gaq();
  var pending = Array.isArray(window._gaq) ? window._gaq.slice() : [];
  window._gaq = gaq;
  window._gaq.qf = gaq;
  pending.forEach(function (item) {
    gaq.push(item);
  });

  var trackerMethods = [
    '_addIgnoredOrganic', '_addIgnoredRef', '_addItem', '_addOrganic',
    '_addTrans', '_clearIgnoredOrganic', '_clearIgnoredRef', '_clearOrganic',
    '_cookiePathCopy', '_deleteCustomVar', '_getName', '_setAccount',
    '_getAccount', '_getClientInfo', '_getDetectFlash', '_getDetectTitle',
    '_getLinkerUrl', '_getLocalGifPath', '_getServiceMode', '_getVersion',
    '_getVisitorCustomVar', '_initData', '_link', '_linkByPost',
    '_setAllowAnchor', '_setAllowHash', '_setAllowLinker', '_setCampContentKey',
    '_setCampMediumKey', '_setCampNameKey', '_setCampNOKey', '_setCampSourceKey',
    '_setCampTermKey', '_setCampaignCookieTimeout', '_setCampaignTrack',
    '_setClientInfo', '_setCookiePath', '_setCookiePersistence',
    '_setCookieTimeout', '_setCustomVar', '_setDetectFlash', '_setDetectTitle',
    '_setDomainName', '_setLocalGifPath', '_setLocalRemoteServerMode',
    '_setLocalServerMode', '_setReferrerOverride', '_setRemoteServerMode',
    '_setSampleRate', '_setSessionTimeout', '_setSiteSpeedSampleRate',
    '_setSessionCookieTimeout', '_setVar', '_setVisitorCookieTimeout',
    '_trackEvent', '_trackPageLoadTime', '_trackPageview', '_trackSocial',
    '_trackTiming', '_trackTrans', '_visitCode',
  ];
  var tracker = {};
  trackerMethods.forEach(function (method) {
    tracker[method] = noop;
  });
  tracker._getLinkerUrl = function (url) {
    return url;
  };
  tracker._link = function (url) {
    if (typeof url !== 'string') {
      return;
    }
    try {
      window.location.assign(url);
    } catch (error) {
      // Same as above: navigation is best effort.
    }
  };

  function Gat() {}
  Gat.prototype._anonymizeIP = noop;
  Gat.prototype._createTracker = noop;
  Gat.prototype._forceSSL = noop;
  Gat.prototype._getPlugin = noop;
  Gat.prototype._getTracker = function () {
    return tracker;
  };
  Gat.prototype._getTrackerByName = function () {
    return tracker;
  };
  Gat.prototype._getTrackers = function () {
    return [tracker];
  };
  Gat.prototype.aa = noop;
  Gat.prototype.ab = noop;
  Gat.prototype.hb = noop;
  Gat.prototype.la = noop;
  Gat.prototype.oa = noop;
  Gat.prototype.pa = noop;
  Gat.prototype.u = noop;

  window._gat = new Gat();
})();
