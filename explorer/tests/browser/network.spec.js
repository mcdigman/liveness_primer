// Network discipline (explorer contract §7, §8, §10): report loading and
// review never trigger network requests; the optional complete-file load
// contacts only the raw GitHub origin, only after an explicit action, and
// falls back to the embedded excerpt on failure.
import { expect, test } from '@playwright/test';

import { goldenReport, openReportAndWait } from './fixtures.mjs';

test.beforeEach(async ({ page }) => {
  await page.goto('./');
});

test('no report load or row interaction causes an unexpected network request', async ({ page }) => {
  /** @type {string[]} */
  const external = [];
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.hostname !== '127.0.0.1') {
      external.push(request.url());
    }
  });
  await openReportAndWait(page, goldenReport());
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('mover');
  await page
    .locator('.tabulator-row:not(.tabulator-group) input[aria-label^="Select for export"]')
    .first()
    .check();
  await page.locator('.tabulator-row:not(.tabulator-group)').first().click();
  await expect(page.locator('.context-panel')).toBeVisible();
  await page.getByRole('button', { name: 'Close finding context' }).click();
  expect(external).toEqual([]);
});

test('Load complete file fetches only after the explicit action and renders text', async ({ page }) => {
  /** @type {string[]} */
  const rawRequests = [];
  await page.route('https://raw.githubusercontent.com/**', async (route) => {
    rawRequests.push(route.request().url());
    const lines = Array.from({ length: 40 }, (_line, index) => `line ${index + 1}`).join('\n');
    await route.fulfill({ status: 200, contentType: 'text/plain', body: lines });
  });
  await openReportAndWait(page, goldenReport());
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('mover');
  await page.locator('.tabulator-row:not(.tabulator-group)').first().click();
  const loadButton = page.getByRole('button', { name: 'Load complete file' });
  await expect(loadButton).toBeVisible();
  expect(rawRequests).toEqual([]);
  await loadButton.click();
  await expect(page.locator('.source-lines')).toContainText('line 10');
  expect(rawRequests).toHaveLength(1);
  expect(rawRequests[0]).toMatch(
    /^https:\/\/raw\.githubusercontent\.com\/example\/alpha\/3{40}\/pkg\/a\.py$/,
  );
});

test('a failed complete-file load falls back to the embedded excerpt', async ({ page }) => {
  await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
  const report = goldenReport();
  const diff = report.projects[0].diffs.find((entry) => entry.symbol === 'mover');
  diff.base_occurrence.source_excerpt = {
    start_line: 10,
    lines: ['def moved():', '    return 1'],
    omitted_lines: 0,
  };
  await openReportAndWait(page, report);
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('mover');
  await page.locator('.tabulator-row:not(.tabulator-group)').first().click();
  await page.getByRole('button', { name: 'Load complete file' }).click();
  await expect(page.locator('.source-error')).toContainText('the embedded excerpt remains the evidence');
  await expect(page.locator('.source-lines')).toContainText('def moved():');
});

test('storage failure keeps the workspace usable with immediate exports', async ({ page }) => {
  await page.addInitScript(() => {
    const broken = () => {
      throw new Error('storage unavailable');
    };
    Storage.prototype.setItem = broken;
    Storage.prototype.getItem = broken;
  });
  await page.goto('./');
  await openReportAndWait(page, goldenReport());
  await expect(page.locator('.storage-warning')).toContainText('Local storage is unavailable');
  await expect(
    page.locator('.storage-warning').getByRole('button', { name: 'Export selected findings (.json)' }),
  ).toBeVisible();
  await page
    .locator('.tabulator-row:not(.tabulator-group) input[aria-label^="Select for export"]')
    .first()
    .check();
  await expect(page.locator('.export-count')).toContainText('1');
});
