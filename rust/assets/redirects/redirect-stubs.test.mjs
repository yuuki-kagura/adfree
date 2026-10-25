import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';

function load(file, extraWindow = {}) {
  const source = readFileSync(new URL(`./${file}`, import.meta.url), 'utf8');
  const dispatched = [];
  class FakeEvent {
    constructor(type) {
      this.type = type;
    }
  }
  const context = {
    window: { ...extraWindow },
    setTimeout,
    clearTimeout,
    Promise,
    Event: FakeEvent,
    document: {
      dispatchEvent(event) {
        dispatched.push(event);
      },
    },
    console,
  };
  vm.runInNewContext(source, context, { filename: file });
  return { window: context.window, dispatched };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 10));

describe('analytics and fingerprinting redirect stubs', () => {
  it('google-analytics answers the ga queue and gtag callbacks', async () => {
    const dataLayer = {
      items: [],
      push(item) {
        this.items.push(item);
        return 0;
      },
    };
    const { window } = load('google-analytics.js', { dataLayer });
    let called = 0;
    window.ga('send', 'pageview', () => {
      called += 1;
    });
    window.dataLayer.push({ event: 'view', eventCallback: () => (called += 1) });
    await tick();
    expect(typeof window.ga).toBe('function');
    expect(window.ga.loaded).toBe(true);
    expect(window.ga.getAll()).toHaveLength(1);
    expect(called).toBe(2);
    expect(window.dataLayer.items[0].event).toBe('view');
  });

  it('google-analytics-ga executes _gaq commands and returns inert trackers', () => {
    const { window } = load('google-analytics-ga.js', { _gaq: [] });
    let called = 0;
    window._gaq.push(['_set', 'hitCallback', () => (called += 1)]);
    window._gaq.push(() => (called += 1));
    expect(called).toBe(2);
    const tracker = window._gat._getTracker('UA-1');
    expect(tracker._getLinkerUrl('https://a.test/')).toBe('https://a.test/');
    expect(() => tracker._trackPageview('/')).not.toThrow();
  });

  it('gemius exposes the player events the plugin reports', () => {
    const { window } = load('gemius.js');
    const player = new window.GemiusPlayer();
    expect(() => {
      player.setVideoObject({});
      player.newProgram({});
      player.programEvent('play');
      player.newAd({});
      player.adEvent('start');
    }).not.toThrow();
  });

  it('prebid-ads answers the anti-adblock probe', () => {
    const { window } = load('prebid-ads.js');
    expect(window.canRunAds).toBe(true);
    expect(window.isAdBlockActive).toBe(false);
  });

  it('fingerprintjs2 hands out an id through the callback API', async () => {
    const { window } = load('fingerprintjs2.js');
    const result = await new Promise((resolve) => {
      window.Fingerprint2.get((id, components) => resolve({ id, components }));
    });
    expect(result.id).toHaveLength(32);
    expect(result.components).toEqual([]);
    expect(window.Fingerprint).toBe(window.Fingerprint2);
  });

  it('fingerprintjs3 resolves load() and get()', async () => {
    const { window } = load('fingerprintjs3.js');
    const instance = await window.FingerprintJS.load();
    const result = await instance.get();
    expect(result.visitorId).toHaveLength(32);
    expect(window.FingerprintJS.hashComponents([])).toBe('');
  });

  it('ati-smarttag accepts tracker configuration and ecommerce calls', () => {
    const { window } = load('ati-smarttag.js');
    const tag = new window.ATInternet.Tracker.Tag();
    expect(() => {
      tag.setConfig({ site: 1 });
      tag.setParam({ page: 'home' });
      tag.dispatch();
      tag.ecommerce.addProduct.products.set({});
      tag.page.send({});
      tag.click.send({});
    }).not.toThrow();
  });

  it('metrika-yandex-tag initialises counters and runs callbacks', async () => {
    const { window, dispatched } = load('metrika-yandex-tag.js');
    window.ym(42, 'init');
    expect(window.yaCounter42).toBeDefined();
    expect(dispatched.map((event) => event.type)).toContain('yacounter42inited');
    let called = 0;
    window.ym(42, 'hit', '/page', {
      callback: () => {
        called += 1;
      },
    });
    await tick();
    expect(called).toBe(1);
  });

  it('metrika-yandex-watch exposes Ya.Metrika and drains the callback queue', async () => {
    let called = 0;
    const { window } = load('metrika-yandex-watch.js', {
      yandex_metrika_callbacks: [() => (called += 1)],
    });
    const counter = new window.Ya.Metrika();
    counter.hit('/', {
      callback: () => {
        called += 1;
      },
    });
    await tick();
    expect(called).toBe(2);
    expect(counter.counters()).toEqual([]);
  });

  it('scorecardresearch-beacon purges the queue and swallows beacons', () => {
    const { window } = load('scorecardresearch-beacon.js', {
      _comscore: [{ c1: '2', c2: '1' }],
    });
    window.COMSCORE.beacon({ c1: '2', c2: '1' });
    window.COMSCORE.purge();
    expect(window._comscore).toEqual([]);
  });
});
