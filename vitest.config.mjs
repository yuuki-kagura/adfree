import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // The JavaScript served to pages: the injected runtime and the redirect
    // stubs embedded into the Rust engine.
    include: ['rust/src/mitm/*.test.mjs', 'rust/assets/redirects/*.test.mjs'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
