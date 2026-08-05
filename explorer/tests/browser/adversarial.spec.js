// Untrusted report content stays inert in the DOM and in exports
// (explorer contract §8, §10).
import { expect, test } from '@playwright/test';

import {
  HOSTILE_MESSAGE,
  HOSTILE_SYMBOL,
  adversarialReport,
  goldenReport,
  openReport,
  openReportAndWait,
} from './fixtures.mjs';

test.beforeEach(async ({ page }) => {
  await page.goto('./');
});

test('hostile strings render as literal text without executing or injecting', async ({ page }) => {
  let dialogs = 0;
  page.on('dialog', (dialog) => {
    dialogs += 1;
    void dialog.dismiss();
  });
  await openReportAndWait(page, adversarialReport());
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('onerror');
  const row = page.locator('.tabulator-row:not(.tabulator-group)').first();
  await expect(row).toContainText('<img src=x onerror');
  expect(await page.locator('img').count()).toBe(0);
  expect(await page.locator('.tabulator-row:not(.tabulator-group) style').count()).toBe(0);
  await row.click();
  await expect(page.locator('.context-panel .context-message')).toHaveText(
    new RegExp(HOSTILE_MESSAGE.slice(0, 20).replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')),
  );
  await expect(page.locator('.context-facts')).toContainText(HOSTILE_SYMBOL);
  expect(dialogs).toBe(0);
});

test('a hostile repository string never fabricates a source link', async ({ page }) => {
  await openReportAndWait(page, adversarialReport());
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('onerror');
  await page.locator('.tabulator-row:not(.tabulator-group)').first().click();
  const panel = page.locator('.context-panel');
  await expect(panel).toBeVisible();
  await expect(panel.getByRole('link', { name: 'Open pinned source' })).toHaveCount(0);
  await expect(panel.getByRole('button', { name: /Load complete file/ })).toHaveCount(0);
  const hrefs = await panel.locator('a').evaluateAll((anchors) => anchors.map((a) => a.href));
  for (const href of hrefs) {
    expect(href.startsWith('https://github.com/')).toBe(true);
  }
});

test('the Markdown export escapes hostile values and creates no hostile link targets', async ({
  page,
  browserName,
}) => {
  test.skip(browserName !== 'chromium', 'download content inspection runs once, on chromium');
  await openReportAndWait(page, adversarialReport());
  await page.getByLabel('Select all visible findings for export').check();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Save export markdown' }).click();
  const download = await downloadPromise;
  const path = await download.path();
  const { readFileSync } = await import('node:fs');
  const markdown = readFileSync(path, 'utf8');
  expect(markdown).not.toContain('](javascript:');
  expect(markdown).not.toContain('<script>');
  expect(markdown).toContain('\\<script\\>');
  expect(markdown).toContain('selected findings:');
});

test('the report JSON export is a report the explorer reimports', async ({ page, browserName }) => {
  // Explorer contract §6: the export is the input format, so the workbench
  // takes its own output back with the subset it wrote.
  test.skip(browserName !== 'chromium', 'download content inspection runs once, on chromium');
  await openReportAndWait(page, goldenReport());
  await page
    .locator('.tabulator-row:not(.tabulator-group) input[aria-label^="Select for export"]')
    .first()
    .check();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export selected findings (.json)' }).click();
  const download = await downloadPromise;
  const { readFileSync } = await import('node:fs');
  const text = readFileSync(await download.path(), 'utf8');
  const document = JSON.parse(text);
  expect(document.schema_version).toBe('1.2.0');
  expect(document.document_kind).toBe('explorer-export');
  expect(document.source_report_sha256).toMatch(/^[0-9a-f]{64}$/);
  expect(document.projects.flatMap((project) => project.diffs)).toHaveLength(1);
  // Aggregates still describe the run the export came from.
  expect(document.totals).toEqual(goldenReport().totals);
  expect(document.truncated).toBe(true);
  await openReport(page, text, 'export.json');
  await expect(page.locator('.tabulator-row:not(.tabulator-group)')).toHaveCount(1);
  await expect(page.locator('.import-errors')).toHaveCount(0);
});
