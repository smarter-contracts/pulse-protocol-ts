import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/**/__tests__/**'],
      // Coverage floor (#264): measured on 2026-09-29 at 98.57% statements, 97.77%
      // branches, 100% functions and lines, seeded ~2 points below as the Go modules
      // are in /coverage-thresholds. The one uncovered statement/branch is scope.ts's
      // defensive empty-segments guard, unreachable after String.split. Ratchet
      // upwards only — never lower.
      thresholds: {
        statements: 96,
        branches: 95,
        functions: 98,
        lines: 98,
      },
    },
  },
});
