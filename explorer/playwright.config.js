// Playwright configuration (explorer contract §10): the browser suites run
// against the production build served beneath a repository-style subpath,
// across the three major engines.
import { defineConfig, devices } from '@playwright/test';

const PORT = 4173;
const SUBPATH = '/liveness-primer/explorer/';

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}${SUBPATH}`,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `node build.mjs && node tests/browser/serve.mjs --port ${PORT}`,
    url: `http://127.0.0.1:${PORT}${SUBPATH}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
