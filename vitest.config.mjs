import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Only the JavaScript the app injects into pages is tested from here;
    // `rust/src/mitm/page_runtime.js` is the one such file.
    include: ['rust/src/mitm/*.test.mjs'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
