// AdFree Extra: keeps the classic ad-block detection libraries blind.
//
// Two ways in, one body:
//   * an AdGuard list rule such as `/blockadblock.$script,redirect=prevent-fab-3.2.0`
//     serves this file in place of the library, so what the page loads is a
//     library that behaves;
//   * the built-in "AdFree Extra" userscript runs it on every filtered page
//     before the page's own scripts, so a copy of the library bundled inline
//     finds the names already taken.
//
// The public shape follows BlockAdBlock and FuckAdBlock 3.2.1 by Valentin
// Allaire (MIT — https://github.com/sitexw/BlockAdBlock and
// https://github.com/sitexw/FuckAdBlock): `_options`, `_var`, `_bait`,
// `setOption`, `on`/`onDetected`/`onNotDetected`, `check`, `emitEvent`,
// `clearEvent` and the `_creatBait`/`_destroyBait`/`_checkBait`/`_stopLoop`
// internals, so a page that pokes at any of them sees what it expects. The one
// difference is inside `_checkBait`: the bait is still created and dropped
// exactly as before, and the verdict is always the same — nothing was
// detected.
(function () {
  'use strict';

  var BAIT_CLASS =
    'pub_300x250 pub_300x250m pub_728x90 text-ad textAd ' +
    'text_ad text_ads text-ads text-ad-links';
  var BAIT_STYLE =
    'width: 1px !important; height: 1px !important; ' +
    'position: absolute !important; left: -10000px !important; ' +
    'top: -1000px !important;';

  function makeLib(name) {
    var Lib = function (options) {
      this._options = {
        checkOnLoad: false,
        resetOnEnd: false,
        loopCheckTime: 50,
        loopMaxNumber: 5,
        baitClass: BAIT_CLASS,
        baitStyle: BAIT_STYLE,
        debug: false,
      };
      this._var = {
        version: '3.2.1',
        bait: null,
        checking: false,
        loop: null,
        loopNumber: 0,
        event: { detected: [], notDetected: [] },
      };
      if (options !== undefined) {
        this.setOption(options);
      }
      var self = this;
      var onLoad = function () {
        setTimeout(function () {
          if (self._options.checkOnLoad !== true) {
            return;
          }
          if (self._var.bait === null) {
            self._creatBait();
          }
          setTimeout(function () {
            self.check();
          }, 1);
        }, 1);
      };
      if (window.addEventListener !== undefined) {
        window.addEventListener('load', onLoad, false);
      } else if (window.attachEvent !== undefined) {
        window.attachEvent('onload', onLoad);
      }
    };

    Lib.prototype._options = null;
    Lib.prototype._var = null;
    Lib.prototype._bait = null;

    Lib.prototype._log = function (method, message) {
      console.log('[' + name + '][' + method + '] ' + message);
    };

    Lib.prototype.setOption = function (options, value) {
      if (value !== undefined) {
        var key = options;
        options = {};
        options[key] = value;
      }
      for (var option in options) {
        this._options[option] = options[option];
        if (this._options.debug === true) {
          this._log(
            'setOption',
            'The option "' + option + '" he was assigned to "' + options[option] + '"',
          );
        }
      }
      return this;
    };

    Lib.prototype._creatBait = function () {
      if (window.document.body === null) {
        return;
      }
      var bait = document.createElement('div');
      bait.setAttribute('class', this._options.baitClass);
      bait.setAttribute('style', this._options.baitStyle);
      this._var.bait = window.document.body.appendChild(bait);
      if (this._options.debug === true) {
        this._log('_creatBait', 'Bait has been created');
      }
    };

    Lib.prototype._destroyBait = function () {
      if (this._var.bait !== null && window.document.body !== null) {
        window.document.body.removeChild(this._var.bait);
      }
      this._var.bait = null;
      if (this._options.debug === true) {
        this._log('_destroyBait', 'Bait has been removed');
      }
    };

    Lib.prototype.check = function (loop) {
      if (loop === undefined) {
        loop = true;
      }
      if (this._var.checking === true) {
        return false;
      }
      this._var.checking = true;
      if (this._var.bait === null) {
        this._creatBait();
      }
      var self = this;
      this._var.loopNumber = 0;
      if (loop === true) {
        this._var.loop = setInterval(function () {
          self._checkBait(loop);
        }, this._options.loopCheckTime);
      }
      setTimeout(function () {
        self._checkBait(loop);
      }, 1);
      if (this._options.debug === true) {
        this._log('check', 'A check is in progress ...');
      }
      return true;
    };

    // The library's reading of the world, with the reading taken out. The real
    // one looks at `body[abp]`, the bait's offsets and its computed style; the
    // shape of the flow around it (the loop count, the bait's lifetime, the
    // notDetected event) is the library's own.
    Lib.prototype._checkBait = function (loop) {
      if (this._var.bait === null) {
        this._creatBait();
      }
      if (loop === true) {
        this._var.loopNumber++;
        if (this._var.loopNumber >= this._options.loopMaxNumber) {
          this._stopLoop();
        }
      }
      if (this._var.loop === null || loop === false) {
        this._destroyBait();
        this.emitEvent(false);
        if (loop === true) {
          this._var.checking = false;
        }
      }
    };

    Lib.prototype._stopLoop = function () {
      clearInterval(this._var.loop);
      this._var.loop = null;
      this._var.loopNumber = 0;
      if (this._options.debug === true) {
        this._log('_stopLoop', 'A loop has been stopped');
      }
    };

    Lib.prototype.emitEvent = function (detected) {
      var fns = this._var.event[detected === true ? 'detected' : 'notDetected'];
      for (var i in fns) {
        if (fns.hasOwnProperty(i)) {
          fns[i]();
        }
      }
      if (this._options.resetOnEnd === true) {
        this.clearEvent();
      }
      return this;
    };

    Lib.prototype.clearEvent = function () {
      this._var.event.detected = [];
      this._var.event.notDetected = [];
    };

    Lib.prototype.on = function (detected, fn) {
      this._var.event[detected === true ? 'detected' : 'notDetected'].push(fn);
      return this;
    };

    Lib.prototype.onDetected = function (fn) {
      return this.on(true, fn);
    };

    Lib.prototype.onNotDetected = function (fn) {
      return this.on(false, fn);
    };

    return Lib;
  }

  function install(name) {
    if (typeof window[name] === 'function') {
      return;
    }
    var Lib = makeLib(name);
    window[name] = Lib;
    var instance = name.charAt(0).toLowerCase() + name.slice(1);
    if (window[instance] === undefined) {
      window[instance] = new Lib({ checkOnLoad: true, resetOnEnd: true });
    }
  }

  install('BlockAdBlock');
  install('FuckAdBlock');
})();
