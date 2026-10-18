// Tests for `page_runtime.js`, the script the app injects into every page it
// filters. They run the real file in a real Chromium (Playwright): a stub DOM
// cannot speak for computed styles, `MutationObserver` timing, constructable
// stylesheets or XPath, and the runtime lives or dies on exactly those.
//
//   bun install && bun run test        (bun is the package manager here)
//
// The system Chrome is used; `PLAYWRIGHT_CHANNEL=chromium` switches to the
// browser `bunx playwright install chromium` fetched.
//
// The proxy is not part of these tests: `page.route` answers for both origins
// instead — the site, and the app's own `https://192.0.2.1` — so a test can
// hand the runtime any payload and any lookup answer it likes. The end-to-end
// path through the real VPN is checked on the emulator (docs/injection.md);
// a Chrome already running behind it can be driven from here by setting
// `ADFREE_CDP`, see the last describe block.

import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';
import { afterAll, afterEach, beforeAll, describe, expect, test } from 'vitest';

const RUNTIME = readFileSync(new URL('./page_runtime.js', import.meta.url), 'utf8');

// The address the tunnel answers itself: see docs/injection.md.
const ORIGIN = 'https://192.0.2.1';
const SITE = 'https://shop.test';
const PAGE_URL = `${SITE}/tin-tuc/`;

let browser = null;
const contexts = [];

beforeAll(async () => {
  // The system Chrome by default; `PLAYWRIGHT_CHANNEL=chromium` uses the
  // browser `npx playwright install chromium` fetched.
  browser = await chromium.launch({
    channel: process.env.PLAYWRIGHT_CHANNEL ?? 'chrome',
  });
});

afterEach(async () => {
  for (const context of contexts.splice(0)) {
    await context.close();
  }
});

afterAll(async () => {
  await browser?.close();
});

const page1 = (html) => `<!doctype html><html><head>${html.head ?? ''}</head><body>${html.body ?? ''}</body></html>`;

const hideLink = (query = 'dmn=shop.test&h=hide') =>
  `<link rel="stylesheet" id="adfree-hide" href="${ORIGIN}/adfree-hide.css?${query}">`;

// One page, both origins answered by routes: the site serves the document and
// the app's origin serves the runtime and the lookup answers, exactly the way
// the proxy would (including the CORS header the cross-origin fetch needs).
const openPage = async (options = {}) => {
  const context = await browser.newContext();
  contexts.push(context);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(String(error)));
  const lookups = [];
  const hides = [];

  await page.route(`${ORIGIN}/**`, async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/adfree-page.js') {
      return route.fulfill({
        status: 200,
        contentType: 'application/javascript; charset=utf-8',
        body: RUNTIME,
      });
    }
    if (url.pathname === '/adfree-hide.css') {
      hides.push(url);
      return route.fulfill({
        status: 200,
        contentType: 'text/css; charset=utf-8',
        body: options.hideCss ?? '',
      });
    }
    if (url.pathname === '/adfree-generic.js') {
      lookups.push(url);
      if (options.lookupFails) {
        return route.fulfill({ status: 500, contentType: 'text/plain', body: 'no' });
      }
      const answer = typeof options.answer === 'function' ? options.answer(url) : options.answer;
      return route.fulfill({
        status: 200,
        contentType: 'application/json; charset=utf-8',
        headers: { 'access-control-allow-origin': '*' },
        body: JSON.stringify(answer ?? []),
      });
    }
    return route.fulfill({ status: 404, contentType: 'text/plain', body: 'not the app’s' });
  });

  await page.route(`${SITE}/**`, async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/adfree-page.js') {
      // A page cached before the channel moved: the tag is same-origin.
      return route.fulfill({
        status: 200,
        contentType: 'application/javascript; charset=utf-8',
        body: RUNTIME,
      });
    }
    if (url.pathname === '/adfree-generic.js') {
      // The runtime asks its own origin in that same legacy case.
      lookups.push(url);
      const answer = typeof options.answer === 'function' ? options.answer(url) : options.answer;
      return route.fulfill({
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify(answer ?? []),
      });
    }
    if (route.request().resourceType() === 'document') {
      return route.fulfill({
        status: 200,
        contentType: 'text/html; charset=utf-8',
        body: page1(options.html ?? {}),
      });
    }
    return route.fulfill({ status: 200, contentType: 'text/css; charset=utf-8', body: '' });
  });

  if (options.initScript) {
    await page.addInitScript(options.initScript);
  }
  await page.goto(PAGE_URL);
  if (options.before) {
    await options.before(page);
  }
  // The proxy writes the payload inline before the runtime tag.
  await page.evaluate((payload) => {
    if (payload !== undefined) {
      window.__adfree_page = payload;
    }
  }, options.payload);
  await page.addScriptTag({
    url: options.scriptUrl ?? `${ORIGIN}/adfree-page.js?dmn=shop.test&h=test`,
  });

  return {
    page,
    errors,
    lookups,
    hides,
    display: (selector) =>
      page.evaluate((sel) => {
        const el = document.querySelector(sel);
        return el ? getComputedStyle(el).display : null;
      }, selector),
  };
};

test('the payload hides what it names and is not left behind', async () => {
  const page = await openPage({
    html: {
      head: hideLink(),
      body: '<div class="banner">banner</div><div class="ad-slot">slot</div>',
    },
    hideCss: '.banner{display:none!important}',
    payload: { generic: ['.ad-slot'] },
  });

  // The linker stylesheet the proxy writes, then the runtime's own rules.
  await expect.poll(() => page.display('.banner')).toBe('none');
  await expect.poll(() => page.display('.ad-slot')).toBe('none');

  expect(await page.page.evaluate(() => window.__adfree_page)).toBeUndefined();
  expect(page.errors).toEqual([]);
});

test('the rules go into a constructable stylesheet, with no node to remove', async () => {
  const page = await openPage({
    payload: { generic: ['.banner'], style: [['.ad-slot', 'visibility:hidden']] },
    html: { body: '<div class="banner">banner</div><div class="ad-slot">slot</div>' },
  });

  expect(await page.page.evaluate(() => document.adoptedStyleSheets.length)).toBe(1);
  expect(await page.page.evaluate(() => document.querySelectorAll('style[data-adfree]').length)).toBe(0);
  expect(
    await page.page.evaluate(() =>
      [...document.adoptedStyleSheets[0].cssRules].map((rule) => rule.selectorText)
    )
  ).toEqual(['.banner', '.ad-slot']);
  expect(await page.page.evaluate(() => getComputedStyle(document.querySelector('.ad-slot')).visibility)).toBe('hidden');
  expect(page.errors).toEqual([]);
});

test('without constructable stylesheets a style element carries the rules, and survives removal', async () => {
  const page = await openPage({
    html: { body: '<div class="ad-slot">slot</div>' },
    payload: { generic: ['.ad-slot'] },
    initScript: () => {
      // The way an older WebView looks to the runtime.
      delete Document.prototype.adoptedStyleSheets;
      delete window.CSSStyleSheet;
    },
  });

  await expect.poll(() => page.display('.ad-slot')).toBe('none');
  expect(await page.page.evaluate(() => document.querySelectorAll('style[data-adfree]').length)).toBe(1);

  // A DOM sanitizer removing the node must not lose the hiding.
  await page.page.evaluate(() => document.querySelector('style[data-adfree]').remove());
  await expect
    .poll(() => page.page.evaluate(() => document.querySelectorAll('style[data-adfree]').length))
    .toBe(1);
  await expect.poll(() => page.display('.ad-slot')).toBe('none');
  expect(page.errors).toEqual([]);
});

test('the hiding stylesheet link is re-attached when the page removes it', async () => {
  const page = await openPage({
    html: { head: hideLink(), body: '<div class="banner">banner</div>' },
    hideCss: '.banner{display:none!important}',
    payload: {},
  });

  await expect.poll(() => page.display('.banner')).toBe('none');
  await page.page.evaluate(() => document.getElementById('adfree-hide').remove());
  await expect
    .poll(() => page.page.evaluate(() => !!document.getElementById('adfree-hide')))
    .toBe(true);
  await expect.poll(() => page.display('.banner')).toBe('none');
  expect(page.errors).toEqual([]);
});

test('tokens the page adds later are looked up once, and the answer hides them', async () => {
  const page = await openPage({
    payload: {},
    answer: ['.sponsored'],
  });

  await page.page.evaluate(() => {
    const el = document.createElement('div');
    el.className = 'sponsored lazily-added';
    el.id = 'sponsored-1';
    el.textContent = 'sponsored';
    document.body.appendChild(el);
  });

  await expect.poll(() => page.lookups.length).toBe(1);
  const url = page.lookups[0];
  expect(url.origin).toBe(ORIGIN);
  expect(url.pathname).toBe('/adfree-generic.js');
  expect(url.searchParams.get('dmn')).toBe('shop.test');
  expect(url.searchParams.get('c')).toBe('sponsored lazily-added');
  expect(url.searchParams.get('i')).toBe('sponsored-1');
  await expect.poll(() => page.display('.sponsored')).toBe('none');

  // The same token is never asked about twice.
  await page.page.evaluate(() => {
    const el = document.createElement('div');
    el.className = 'sponsored';
    document.body.appendChild(el);
  });
  await page.page.waitForTimeout(700);
  expect(page.lookups.length).toBe(1);
  expect(page.errors).toEqual([]);
});

test('$generichide keeps the runtime from asking anything', async () => {
  const page = await openPage({ payload: { dynamic: false } });
  await page.page.evaluate(() => {
    const el = document.createElement('div');
    el.className = 'sponsored';
    document.body.appendChild(el);
  });
  await page.page.waitForTimeout(700);
  expect(page.lookups.length).toBe(0);
  expect(page.errors).toEqual([]);
});

test('a lookup that fails is swallowed', async () => {
  const page = await openPage({ payload: {}, lookupFails: true });
  await page.page.evaluate(() => {
    const el = document.createElement('div');
    el.className = 'sponsored';
    document.body.appendChild(el);
  });
  await expect.poll(() => page.lookups.length).toBe(1);
  expect(await page.page.evaluate(() => document.adoptedStyleSheets.length)).toBe(0);
  expect(page.errors).toEqual([]);
});

test('scriptlets run while the runtime is injected', async () => {
  const page = await openPage({
    payload: { scriptlets: 'window.__adfree_scriptlet_ran = true;' },
  });
  expect(await page.page.evaluate(() => window.__adfree_scriptlet_ran)).toBe(true);
  expect(page.errors).toEqual([]);
});

test('a payload of the wrong shape does not take the page down', async () => {
  const page = await openPage({
    html: { body: '<div class="ad-slot">slot</div>' },
    payload: {
      generic: 'not a list',
      style: 42,
      procedural: [{ selector: [{ type: 'css-selector', arg: '>>>' }], action: { type: 'remove' } }],
      scriptlets: 'throw new Error("this scriptlet is broken on purpose");',
    },
    answer: 'not a list either',
  });

  await page.page.evaluate(() => {
    const el = document.createElement('div');
    el.className = 'late';
    document.body.appendChild(el);
  });
  await expect.poll(() => page.lookups.length).toBe(1);
  expect(await page.page.evaluate(() => document.querySelector('.ad-slot') !== null)).toBe(true);
  expect(page.errors).toEqual([]);
});

describe('procedural rules', () => {
  test('a rule can remove an element it reaches through an upward step', async () => {
    const page = await openPage({
      html: {
        body: '<div class="ad-wrapper"><span class="ad-child">Quảng cáo</span></div><div id="keep">Nội dung</div>',
      },
      payload: {
        procedural: [
          // The engine writes these as JSON strings; both shapes must work.
          JSON.stringify({
            selector: [
              { type: 'css-selector', arg: '.ad-child' },
              { type: 'upward', arg: '.ad-wrapper' },
            ],
            action: { type: 'remove' },
          }),
        ],
      },
    });
    await expect.poll(() => page.page.evaluate(() => document.querySelectorAll('.ad-wrapper').length)).toBe(0);
    expect(await page.page.evaluate(() => document.getElementById('keep') !== null)).toBe(true);
    expect(page.errors).toEqual([]);
  });

  test('has-text and matches-attr narrow the match', async () => {
    const page = await openPage({
      html: {
        body:
          '<div class="box" data-ad="1">Quảng cáo</div>' +
          '<div class="box" data-ad="1">Nội dung</div>' +
          '<div class="box" data-ad="0">Quảng cáo</div>',
      },
      payload: {
        procedural: [
          {
            selector: [
              { type: 'css-selector', arg: '.box' },
              { type: 'has-text', arg: 'Quảng cáo' },
              { type: 'matches-attr', arg: 'data-ad=1' },
            ],
            action: { type: 'remove-class', arg: 'box' },
          },
        ],
      },
    });
    await expect.poll(() => page.page.evaluate(() => document.querySelectorAll('.box').length)).toBe(2);
    expect(await page.page.evaluate(() => document.body.textContent)).toBe('Quảng cáoNội dungQuảng cáo');
    expect(page.errors).toEqual([]);
  });

  test('an xpath step works', async () => {
    const page = await openPage({
      html: { body: '<div class="ad-slot">one</div><div class="ad-slot">two</div>' },
      payload: {
        procedural: [
          {
            selector: [{ type: 'xpath', arg: '//div[@class="ad-slot"][1]' }],
            action: { type: 'remove' },
          },
        ],
      },
    });
    await expect.poll(() => page.page.evaluate(() => document.querySelectorAll('.ad-slot').length)).toBe(1);
    expect(await page.page.evaluate(() => document.querySelector('.ad-slot').textContent)).toBe('two');
    expect(page.errors).toEqual([]);
  });

  test('matches-path skips the rule on another path', async () => {
    const page = await openPage({
      html: { body: '<div class="ad-slot">slot</div>' },
      payload: {
        procedural: [
          {
            selector: [
              { type: 'matches-path', arg: '^/khac/' },
              { type: 'css-selector', arg: '.ad-slot' },
            ],
            action: { type: 'remove' },
          },
        ],
      },
    });
    await page.page.waitForTimeout(300);
    expect(await page.page.evaluate(() => document.querySelectorAll('.ad-slot').length)).toBe(1);
    expect(page.errors).toEqual([]);
  });

  test('a rule added to the DOM later is applied', async () => {
    const page = await openPage({
      payload: {
        procedural: [{ selector: [{ type: 'css-selector', arg: '.late-ad' }], action: { type: 'remove' } }],
      },
    });
    await page.page.evaluate(() => {
      const el = document.createElement('div');
      el.className = 'late-ad';
      document.body.appendChild(el);
    });
    await expect.poll(() => page.page.evaluate(() => document.querySelectorAll('.late-ad').length)).toBe(0);
    expect(page.errors).toEqual([]);
  });
});

test('a legacy same-origin tag still finds the host and origin', async () => {
  const page = await openPage({
    payload: {},
    scriptUrl: `${SITE}/adfree-page.js?h=old`,
    answer: ['.sponsored'],
  });
  await page.page.evaluate(() => {
    const el = document.createElement('div');
    el.className = 'sponsored';
    document.body.appendChild(el);
  });
  await expect.poll(() => page.lookups.length).toBe(1);
  const url = page.lookups[0];
  expect(url.origin).toBe(SITE);
  expect(url.searchParams.get('dmn')).toBe('shop.test');
  await expect.poll(() => page.display('.sponsored')).toBe('none');
  expect(page.errors).toEqual([]);
});

// The one check that is not simulated: a Chrome running on the emulator with
// the app's VPN up, driven over CDP. Off unless ADFREE_CDP is set, e.g.
//
//   adb forward tcp:9333 localabstract:chrome_devtools_remote
//   ADFREE_CDP=http://localhost:9333 bun run test
describe.skipIf(!process.env.ADFREE_CDP)('behind the running VPN', () => {
  test('a real page carries the injected tags and the runtime answers', async () => {
    const connected = await chromium.connectOverCDP(process.env.ADFREE_CDP);
    const context = connected.contexts()[0];
    const page = context.pages()[0];
    await page.goto(process.env.ADFREE_PAGE ?? 'https://dantri.com.vn/', { waitUntil: 'load' });
    await page.waitForTimeout(3000);

    const tags = await page.evaluate(() =>
      [...document.querySelectorAll('script[src], link[href]')]
        .map((el) => el.src || el.href)
        .filter((url) => url.includes('192.0.2.1'))
    );
    expect(tags.some((url) => url.includes('/adfree-page.js'))).toBe(true);
    expect(tags.some((url) => url.includes('/adfree-hide.css'))).toBe(true);

    // Both assets come back cross-origin: the certificate for the address
    // literal was accepted and the CORS header is there.
    const runtime = await page.evaluate(() =>
      fetch('https://192.0.2.1/adfree-page.js?dmn=dantri.com.vn', { cache: 'no-store' }).then((r) => r.text())
    );
    expect(runtime).toContain('adoptedStyleSheets');

    const answer = await page.evaluate(() =>
      fetch('https://192.0.2.1/adfree-generic.js?dmn=dantri.com.vn&c=adfree-canary&i=adfree-canary', {
        cache: 'no-store',
      }).then((r) => r.json())
    );
    expect(Array.isArray(answer)).toBe(true);
    await connected.close();
  });
});
