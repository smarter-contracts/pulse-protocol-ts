import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      '@pulse-protocol/types': new URL('../types/src/index.ts', import.meta.url).pathname,
      '@pulse-protocol/ipfs': new URL('../ipfs/src/index.ts', import.meta.url).pathname,
    },
  },
  test: {
    environment: 'node',
  },
});
