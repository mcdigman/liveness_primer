// Playwright configuration (explorer contract §10): the browser suites run
// against the production build served beneath a repository-style subpath,
// across the three major engines.
import { defineConfig, devices } from '@playwright/test';

import { baseUrl, PORT } from './tests/browser/serve.mjs';

// One endpoint for both the server and the clients, resolved from the
// environment by serve.mjs (EXPLORER_TEST_HOST / EXPLORER_TEST_PORT).
const BASE_URL = baseUrl();

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `node build.mjs && node tests/browser/serve.mjs --port ${PORT}`,
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
