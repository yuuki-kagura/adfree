// AT Internet SmartTag, replaced: `ATInternet.Tracker.Tag` accepts the
// configuration, page, click and ecommerce calls sites make, and none of
// them reaches the tracker endpoint.
(function () {
  'use strict';

  if (window.ATInternet) {
    return;
  }

  function noop() {}
  function setter() {
    return { set: noop };
  }
  function sender() {
    return { send: noop };
  }

  function Tag() {}
  Tag.prototype = {
    setConfig: noop,
    setParam: noop,
    dispatch: noop,

    customVars: setter(),
    publisher: setter(),
    order: setter(),

    click: sender(),
    clickListener: sender(),
    internalSearch: {
      set: noop,
      send: noop,
    },

    ecommerce: {
      displayCart: { products: setter(), cart: setter() },
      updateCart: { cart: setter() },
      displayProduct: { products: setter() },
      displayPageProduct: { products: setter() },
      addProduct: { products: setter() },
      removeProduct: { products: setter() },
    },

    identifiedVisitor: { unset: noop },
    page: {
      set: noop,
      send: noop,
    },
    selfPromotion: {
      add: noop,
      send: noop,
    },
    privacy: {
      setVisitorMode: noop,
      getVisitorMode: noop,
      hit: noop,
    },
    richMedia: {
      add: noop,
      send: noop,
      remove: noop,
      removeAll: noop,
    },
  };

  window.ATInternet = {
    Tracker: {
      Tag: Tag,
    },
  };
})();
