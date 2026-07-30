// Browser behavior: import, filtering, review, export, keyboard access,
// themes, and responsive layout (explorer contract §17.2).
import { expect, test } from '@playwright/test';

import { goldenReport, reportFile, truncatedReport } from './fixtures.mjs';

async function loadReport(page, report = goldenReport()) {
  await page.goto('.');
  await page.setInputFiles('#report-input', reportFile(report));
  await expect(page.locator('#summary-region')).toBeVisible();
}

test('the empty state explains local processing and imports by keyboard', async ({ page }) => {
  await page.goto('.');
  await expect(page.getByText('not uploaded anywhere')).toBeVisible();
  await expect(page.locator('#report-input')).toBeVisible();
  // The skip link is the first focusable control and appears on focus.
  await page.keyboard.press('Tab');
  await expect(page.locator('.skip-link')).toBeFocused();
});

test('loading a valid report shows digest, schema, totals, and rollups without network', async ({ page }) => {
  const requests = [];
  page.on('request', (request) => {
    requests.push(request.url());
  });
  await loadReport(page);
  await expect(page.locator('#report-digest-abbrev')).toHaveText(/^[0-9a-f]{12}$/);
  await expect(page.locator('#summary-facts')).toContainText('1.1.0');
  await expect(page.locator('#summary-facts')).toContainText('5 new, 4 dropped, 9 changed');
  await expect(page.locator('#summary-rollups')).toContainText('changed SKY-U001: 1');
  await expect(page.locator('#findings-count')).toContainText('18 of 18');
  // No request beyond the application shell assets was made (§3.2).
  const external = requests.filter((url) => !url.startsWith('http://127.0.0.1:8930/'));
  expect(external).toEqual([]);
});

test('malformed and invalid reports fail with an alert and keep prior state', async ({ page }) => {
  await loadReport(page);
  await page.setInputFiles('#report-input', {
    name: 'broken.json',
    mimeType: 'application/json',
    buffer: Buffer.from('{"not": "a report"'),
  });
  await expect(page.locator('#import-errors')).toBeVisible();
  // The previously loaded report stays active (§5.5).
  await expect(page.locator('#findings-count')).toContainText('18 of 18');
  const invalid = goldenReport();
  invalid.projects[0].diffs[0].identity = 'f'.repeat(64);
  await page.setInputFiles('#report-input', reportFile(invalid, 'tampered.json'));
  await expect(page.locator('#import-errors')).toContainText('identity');
  await expect(page.locator('#findings-count')).toContainText('18 of 18');
});

test('filters compose, announce counts, and reset to canonical order', async ({ page }) => {
  await loadReport(page);
  await page.getByLabel('new', { exact: true }).check();
  await expect(page.locator('#findings-count')).toContainText('5 of 18');
  // OR within the class dimension...
  await page.getByLabel('changed', { exact: true }).check();
  await expect(page.locator('#findings-count')).toContainText('14 of 18');
  // ...AND across dimensions: only the changed `ruled` diff carries SKY-U001.
  await page.getByLabel('SKY-U001').check();
  await expect(page.locator('#findings-count')).toContainText('1 of 18');
  await page.getByLabel('SKY-U001').uncheck();
  await page.getByLabel('changed', { exact: true }).uncheck();
  await page.getByLabel('Search path, symbol, message, rule, kind').fill('lib/b.py');
  await expect(page.locator('#findings-count')).toContainText('1 of 18');
  await page.getByRole('button', { name: 'Reset filters' }).click();
  await expect(page.locator('#findings-count')).toContainText('18 of 18');
  const firstRow = page.locator('#findings-body tr').first();
  await expect(firstRow).toContainText('pkg/a.py');
});

test('review dispositions persist across a reload under the same digest', async ({ page }) => {
  await loadReport(page);
  await page.locator('#findings-body tr', { hasText: 'L10->L20' }).getByRole('button').click();
  await expect(page.locator('#details-region')).toBeVisible();
  await page.locator('#details-region').getByLabel('unexpected', { exact: true }).check();
  await page.getByLabel(/Review note/).fill('worth a second look');
  await page.getByLabel(/Review note/).blur();
  await expect(page.locator('#review-progress')).toContainText('1 unexpected');
  await page.reload();
  await page.setInputFiles('#report-input', reportFile(goldenReport()));
  await expect(page.locator('#review-progress')).toContainText('1 unexpected');
  const row = page.locator('#findings-body tr', { hasText: 'L10->L20' });
  await expect(row).toContainText('unexpected');
});

test('the JSON review export round-trips through import', async ({ page }) => {
  await loadReport(page);
  await page.locator('#findings-body tr').first().getByRole('button', { name: /Details/ }).click();
  await page.locator('#details-region').getByLabel('expected', { exact: true }).check();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download review JSON' }).click();
  const download = await downloadPromise;
  const path = await download.path();
  const { readFileSync } = await import('node:fs');
  const exported = readFileSync(path, 'utf8');
  expect(JSON.parse(exported).entries).toHaveLength(1);
  // Clear, then import the exported session back.
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Clear local review' }).click();
  await expect(page.locator('#review-progress')).toContainText('0 expected');
  await page.setInputFiles('#session-import', {
    name: 'review.json',
    mimeType: 'application/json',
    buffer: Buffer.from(exported),
  });
  await expect(page.locator('#review-progress')).toContainText('1 expected');
});

test('markdown copy falls back to the labelled textarea when the clipboard is denied', async ({ page, context, browserName }) => {
  await loadReport(page);
  await page.getByRole('button', { name: 'Copy Markdown summary' }).click();
  const fallback = page.locator('#markdown-fallback');
  await expect(fallback).toHaveValue(/liveness primer review summary/);
  await expect(page.locator('#status')).toContainText(/copied|shown below/);
  test.skip(browserName !== 'chromium', 'clipboard permission control is chromium-specific');
  await context.clearPermissions();
});

test('a truncated report shows the persistent incompleteness banner and export warning', async ({ page }) => {
  await loadReport(page, truncatedReport());
  await expect(page.locator('#banners')).toContainText('Incomplete finding detail');
  await page.getByRole('button', { name: 'Download Markdown summary' }).click();
  await expect(page.locator('#markdown-fallback')).toHaveValue(/not the complete blast radius/);
});

test('non-comparable and unenforced-isolation reports stay prominent', async ({ page }) => {
  const report = goldenReport();
  report.manifest.isolation_enforced = false;
  await loadReport(page, report);
  await expect(page.locator('#banners')).toContainText('not comparable');
  await expect(page.locator('#banners')).toContainText('NOT ENFORCED');
});

test('the details pane shows labelled base and head evidence and pinned links', async ({ page }) => {
  await loadReport(page);
  await page.locator('#findings-body tr', { hasText: 'L10->L20' }).getByRole('button').click();
  const details = page.locator('#details-content');
  await expect(details).toContainText('base span');
  await expect(details).toContainText('head span');
  await expect(details).toContainText('occurrence 0');
  // Complete-file loading is offered for the GitHub-hosted project only.
  await expect(details.getByRole('button', { name: /Load complete pinned file/ })).toHaveCount(2);
  await page.getByRole('button', { name: 'Close details' }).click();
  await expect(page.locator('#details-region')).toBeHidden();
  await page.locator('#findings-body tr', { hasText: 'lib/b.py' }).getByRole('button').click();
  await expect(details.getByRole('button', { name: /Load complete pinned file/ })).toHaveCount(0);
  await expect(details.locator('a')).toHaveCount(0);
});

test('complete-file loading falls back safely on network failure', async ({ page }) => {
  await page.route('https://raw.githubusercontent.com/**', (route) => route.abort());
  await loadReport(page);
  await page.locator('#findings-body tr', { hasText: 'L10->L20' }).getByRole('button').click();
  await page.getByRole('button', { name: /Load complete pinned file \(base/ }).click();
  await expect(page.locator('#details-content')).toContainText('Complete file unavailable');
  await expect(page.locator('#details-content')).toContainText('embedded excerpt above remains');
});

test('theme selection persists and applies data-theme', async ({ page }) => {
  await page.goto('.');
  await page.getByLabel('Theme').selectOption('dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.getByLabel('Theme').selectOption('system');
  await expect(page.locator('html')).not.toHaveAttribute('data-theme', /./);
});

test('the interface reflows at 320 CSS pixels without horizontal page scroll', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 900 });
  await loadReport(page);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});

test('keyboard-only review: filter, inspect, disposition, and export', async ({ page }) => {
  await loadReport(page);
  const detailsButton = page.locator('#findings-body tr').first().getByRole('button');
  await detailsButton.focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#details-region')).toBeVisible();
  await expect(page.locator('#details-region')).toBeFocused();
  await page.locator('#details-region').getByLabel('expected', { exact: true }).focus();
  await page.keyboard.press('Space');
  await expect(page.locator('#review-progress')).toContainText('1 expected');
  await page.getByRole('button', { name: 'Close details' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#findings-region')).toBeFocused();
});
