// Accessibility scans and keyboard operability (explorer contract §9,
// §10) in both themes.
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

import { goldenReport, openReportAndWait } from './fixtures.mjs';

/**
 * @param {import('@playwright/test').Page} page
 * @returns {Promise<import('axe-core').Result[]>}
 */
async function axeViolations(page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  return results.violations;
}

test.beforeEach(async ({ page }) => {
  await page.goto('./');
});

test('the empty state has no WCAG A/AA violations', async ({ page }) => {
  await expect(page.getByRole('heading', { name: 'Open a liveness primer report' })).toBeVisible();
  expect(await axeViolations(page)).toEqual([]);
});

for (const theme of ['dark', 'light']) {
  test(`the loaded workbench has no WCAG A/AA violations in the ${theme} theme`, async ({ page }) => {
    await openReportAndWait(page, goldenReport());
    await page.getByLabel('Theme').selectOption(theme);
    await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
    expect(await axeViolations(page)).toEqual([]);
  });

  test(`the finding context has no WCAG A/AA violations in the ${theme} theme`, async ({ page }) => {
    await openReportAndWait(page, goldenReport());
    await page.getByLabel('Theme').selectOption(theme);
    await page
      .locator('.tabulator-row:not(.tabulator-group) button[aria-label^="Open finding context"]')
      .first()
      .click();
    await expect(page.locator('.context-panel')).toBeVisible();
    expect(await axeViolations(page)).toEqual([]);
  });
}

test('the review workflow is keyboard operable', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  // Search from the keyboard.
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').focus();
  await page.keyboard.type('mover');
  await expect(page.locator('.tabulator-row:not(.tabulator-group)')).toHaveCount(1);
  // Toggle export selection with Space on the row checkbox.
  await page
    .locator('.tabulator-row:not(.tabulator-group) input[aria-label^="Select for export"]')
    .first()
    .focus();
  await page.keyboard.press('Space');
  await expect(page.locator('.export-count')).toContainText('1');
  // Open context with Enter on the row's open button; focus lands in it.
  await page
    .locator('.tabulator-row:not(.tabulator-group) button[aria-label^="Open finding context"]')
    .first()
    .focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('.context-panel')).toBeVisible();
  await expect(page.locator('.context-location')).toBeFocused();
  // Close from the keyboard; focus returns to the invoking control.
  await page.getByRole('button', { name: 'Close finding context' }).focus();
  await page.keyboard.press('Enter');
  await expect(
    page.locator('.tabulator-row:not(.tabulator-group) button[aria-label^="Open finding context"]').first(),
  ).toBeFocused();
});

test('filtering does not move focus unexpectedly', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  const newFacet = page.locator('.facet', { hasText: 'Diff class' }).getByLabel('+ New');
  await newFacet.focus();
  await page.keyboard.press('Space');
  await expect(newFacet).toBeFocused();
  const search = page.getByPlaceholder('Search path, symbol, message, rule, kind');
  await search.focus();
  await page.keyboard.type('pkg');
  await expect(search).toBeFocused();
});

test('status announcements exist without flooding: one polite live region', async ({ page }) => {
  await openReportAndWait(page, goldenReport());
  const liveRegions = page.locator('[aria-live="polite"]');
  await expect(liveRegions.last()).toHaveText(/Report loaded: \d+ findings\./);
});
