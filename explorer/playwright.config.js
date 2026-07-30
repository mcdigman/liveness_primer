// Playwright configuration (explorer contract §17.2): the browser suites
// run against current Chromium, Firefox, and WebKit engines over a plain
// static server serving the production build beneath a repository-style
// subpath.
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: 'tests/browser',
  fullyParallel: true,
  forbidOnly: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:8930/liveness_primer/explorer/',
    trace: 'on-first-retry',
  },
  webServer: {
    // The build output is mounted beneath a GitHub Pages-style repository
    // subpath so navigation and asset loading are exercised there.
    command: 'node tests/browser/serve.mjs',
    url: 'http://127.0.0.1:8930/liveness_primer/explorer/',
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
