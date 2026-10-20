import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';

const source = readFileSync(new URL('./google-ima3.js', import.meta.url), 'utf8');

function loadIma() {
  const context = {
    window: {},
    setTimeout,
    clearTimeout,
    console,
  };
  vm.runInNewContext(source, context, { filename: 'google-ima3.js' });
  return context.window.google.ima;
}

describe('google-ima3 redirect stub', () => {
  it('exposes the API the SDK consumer reaches for', () => {
    const ima = loadIma();
    expect(ima.VERSION).toContain('adfree');
    expect(typeof ima.AdDisplayContainer).toBe('function');
    expect(typeof ima.AdsLoader).toBe('function');
    expect(typeof ima.AdsManager).toBe('function');
    expect(ima.AdsManagerLoadedEvent.Type.ADS_MANAGER_LOADED).toBe(
      'adsManagerLoaded'
    );
    expect(ima.AdEvent.Type.CONTENT_RESUME_REQUESTED).toBe(
      'contentResumeRequested'
    );
  });

  it('completes a request with no ad and lets the page resume content', async () => {
    const ima = loadIma();
    const loader = new ima.AdsLoader({});
    const events = [];
    let manager = null;

    loader.addEventListener(
      ima.AdsManagerLoadedEvent.Type.ADS_MANAGER_LOADED,
      (event) => {
        events.push('loaded');
        manager = event.getAdsManager({});
        manager.addEventListener(ima.AdEvent.Type.CONTENT_RESUME_REQUESTED, () => {
          events.push('resume');
        });
        manager.addEventListener(ima.AdEvent.Type.ALL_ADS_COMPLETED, () => {
          events.push('complete');
        });
        manager.init(640, 360, ima.ViewMode.NORMAL);
        manager.start();
      }
    );

    loader.requestAds(new ima.AdsRequest());
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(manager).not.toBeNull();
    expect(events).toContain('resume');
    expect(events).toContain('complete');
    expect(manager.getCuePoints()).toEqual([]);
    expect(manager.getRemainingTime()).toBe(0);
  });

  it('does not replace an SDK that is already present', () => {
    const context = {
      window: {
        google: {
          ima: { VERSION: 'real-sdk', marker: 'keep-me' },
        },
      },
      setTimeout,
      clearTimeout,
      console,
    };
    vm.runInNewContext(source, context, { filename: 'google-ima3.js' });
    expect(context.window.google.ima.VERSION).toBe('real-sdk');
    expect(context.window.google.ima.marker).toBe('keep-me');
  });
});
