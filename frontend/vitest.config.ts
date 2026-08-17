import { defineConfig, mergeConfig } from 'vitest/config';
import viteConfig from './vite.config';

/**
 * Kept apart from `vite.config.ts` so each file keeps its own type. Merged, so the test run
 * resolves modules exactly as the app does — a component that only passes under a different
 * resolver has not been tested.
 */
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      globals: true,
      environment: 'jsdom',
      setupFiles: ['./src/test-setup.ts'],
      css: true,
      include: ['src/**/*.test.{ts,tsx}'],
    },
  }),
);
