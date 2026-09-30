import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/__tests__/**'],
      // Coverage floor (#264): measured on 2026-09-29 at 100% on every metric (the
      // package has a single runtime statement), seeded ~2 points below as the Go
      // modules are in /coverage-thresholds. Ratchet upwards only — never lower.
      thresholds: {
        statements: 98,
        branches: 98,
        functions: 98,
        lines: 98,
      },
    },
  },
});
