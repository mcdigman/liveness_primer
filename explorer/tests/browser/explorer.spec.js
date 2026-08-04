// Core workbench workflow (explorer contract §10): search, facets,
// grouping, sorting, hiding, selection, persistence, and exports operate
// on serialized report values and locators.
import { expect, test } from '@playwright/test';

import { goldenReport, goldenRowCount, openReport, openReportAndWait } from './fixtures.mjs';

test.beforeEach(async ({ page }) => {
  await page.goto('./');
});

test('a valid local report loads without upload and shows the workbench', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  const total = goldenRowCount();
  await expect(page.locator('.findings-counts')).toContainText(`${total} total`);
  await expect(page.locator('.report-digest code')).toHaveText(/^[0-9a-f]{12}$/);
  await expect(page.locator('.tabulator-group').first()).toContainText('alpha');
  await expect(page.locator('.tabulator-group').first()).toContainText('example/alpha @ 33333333');
  await expect(page.locator('.tabulator-row')).toHaveCount(total);
});

test('an invalid replacement leaves the current report intact', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  const total = goldenRowCount();
  await openReport(page, '{"schema_version": "0.0.1"}', 'broken.json');
  await expect(page.locator('.import-errors')).toContainText('Unsupported schema version');
  await expect(page.locator('.tabulator-row')).toHaveCount(total);
});

test('facets, search, and reset filter without touching workspace state', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  const total = goldenRowCount();
  // Select one row for export first, so reset provably keeps it.
  await page.locator('.tabulator-row input[aria-label^="Select for export"]').first().check();
  await expect(page.locator('.export-count')).toContainText('1');
  await page.locator('.facet', { hasText: 'Diff class' }).getByLabel('+ New').check();
  const shown = await page.locator('.tabulator-row').count();
  expect(shown).toBeLessThan(total);
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('ruleless');
  await expect(page.locator('.tabulator-row')).toHaveCount(1);
  await page.getByRole('button', { name: 'Reset all' }).click();
  await expect(page.locator('.tabulator-row')).toHaveCount(total);
  await expect(page.locator('.export-count')).toContainText('1');
});

test('hiding removes a row from the default view; show hidden reveals it dimmed', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  const total = goldenRowCount();
  const firstLocation = await page.locator('.tabulator-row .cell-location').first().textContent();
  await page.locator('.tabulator-row input[aria-label^="Hide"]').first().check();
  await expect(page.locator('.tabulator-row')).toHaveCount(total - 1);
  await page.getByLabel('Show hidden findings').check();
  await expect(page.locator('.tabulator-row')).toHaveCount(total);
  const hiddenRow = page.locator('.tabulator-row.row-hidden');
  await expect(hiddenRow).toHaveCount(1);
  await expect(hiddenRow).toContainText(String(firstLocation));
});

test('sorting restores exact report order after other sorts', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  const original = await page.locator('.tabulator-row .cell-location').allTextContents();
  await page.getByLabel('Sort').selectOption('confidence');
  await expect(page.locator('.tabulator-row .cell-location')).not.toHaveText(original);
  await page.getByLabel('Sort').selectOption('report');
  await expect(page.locator('.tabulator-row .cell-location')).toHaveText(original);
});

test('paired changed values show base and head in the row', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('mover');
  await expect(page.locator('.tabulator-row .cell-location').first()).toHaveText('pkg/a.py:10 → 20');
});

test('selecting a row opens context without resetting filters or scroll', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('mover');
  await expect(page.locator('.tabulator-row')).toHaveCount(1);
  await page.locator('.tabulator-row button[aria-label^="Open finding context"]').first().click();
  const panel = page.locator('.context-panel');
  await expect(panel.locator('.context-location')).toHaveText('pkg/a.py:10 → 20');
  await expect(panel).toContainText('Analyzer output');
  await expect(panel).toContainText('occurrence 0');
  // Filters survived.
  await expect(page.locator('.tabulator-row')).toHaveCount(1);
  // Closing returns to the export summary and restores focus.
  await panel.getByRole('button', { name: 'Close finding context' }).click();
  await expect(page.locator('.export-panel')).toBeVisible();
  await expect(page.locator('.tabulator-row button[aria-label^="Open finding context"]').first()).toBeFocused();
});

test('base and head analyzer values are labelled for a new finding', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('ruleless');
  await page.locator('.tabulator-row').first().click();
  const cards = page.locator('.analyzer-card');
  await expect(cards).toHaveCount(2);
  await expect(cards.nth(0)).toContainText('No finding reported for this identity.');
  await expect(cards.nth(1)).toContainText('Finding reported');
  await expect(cards.nth(1)).toContainText('Reported span');
});

test('source excerpt shows real line numbers with the reported span highlighted', async ({ page }) => {
  const report = goldenReport();
  const diff = report.projects[0].diffs.find((entry) => entry.symbol === 'mover');
  diff.base_occurrence.source_excerpt = {
    start_line: 10,
    lines: ['def moved():', '    return 1'],
    omitted_lines: 0,
  };
  await openReportAndWait(page, report);
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('mover');
  await page.locator('.tabulator-row').first().click();
  const source = page.locator('.source-lines');
  await expect(source.locator('.source-number').first()).toHaveText('10');
  await expect(source.locator('.source-line-highlight')).toHaveCount(2);
  await expect(source).toContainText('def moved():');
});

test('selection and hidden state persist for the same bytes and never cross digests', async ({ page }) => {
  const text = JSON.stringify(goldenReport());
  await openReport(page, text);
  await page.locator('.tabulator-row').first().waitFor();
  await page.locator('.tabulator-row input[aria-label^="Select for export"]').first().check();
  await page.locator('.tabulator-row input[aria-label^="Hide"]').nth(1).check();
  await expect(page.locator('.export-count')).toContainText('1');
  await page.reload();
  await openReport(page, text);
  await page.locator('.tabulator-row').first().waitFor();
  await expect(page.locator('.export-count')).toContainText('1');
  await expect(page.locator('.tabulator-row input[aria-label^="Select for export"]').first()).toBeChecked();
  // Byte-different report: same semantics, different digest, no inheritance.
  await page.reload();
  await openReport(page, `${text} `);
  await page.locator('.tabulator-row').first().waitFor();
  await expect(page.locator('.export-count')).toContainText('0');
});

test('the export summary counts selected findings per project', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  const selects = page.locator('.tabulator-row input[aria-label^="Select for export"]');
  await selects.first().check();
  await selects.last().check();
  await expect(page.locator('.export-projects li')).toHaveCount(2);
  await expect(page.locator('.export-panel')).toContainText('Across 2 projects');
  await page.getByRole('button', { name: /Clear selection/ }).click();
  await expect(page.locator('.export-count')).toContainText('0');
});

test('select-all applies to visible rows only and shows the affected count', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('pkg/a.py');
  const visible = await page.locator('.tabulator-row').count();
  await page.getByLabel('Select all visible findings for export').check();
  await expect(page.locator('.export-count strong')).toHaveText(String(visible));
  await expect(page.getByRole('button', { name: `Clear selection (${visible})` })).toBeVisible();
});

test('grouping by rule and ungrouped views are offered', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  await page.getByLabel('Group by').selectOption('rule');
  await expect(page.locator('.tabulator-group').first()).toContainText(/SKY-|\(no rule\)/);
  await page.getByLabel('Group by').selectOption('none');
  await expect(page.locator('.tabulator-group')).toHaveCount(0);
});
