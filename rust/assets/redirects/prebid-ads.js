// The anti-adblock probe some pages load as `prebid-ads.js`: it answers the
// two constants the page checks, so the page keeps running its content
// instead of withholding it.
window.canRunAds = true;
window.isAdBlockActive = false;
