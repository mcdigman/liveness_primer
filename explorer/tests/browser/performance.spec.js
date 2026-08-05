// Performance evidence (explorer contract §10): import/validation time is
// reported separately from grid rendering time for a representative large
// generated report. No portable millisecond threshold is asserted — CI
// runners are not a documented reference machine — so this suite reports
// measurements and asserts only that the surface stays bounded and
// responsive enough to interact with.
import { expect, test } from '@playwright/test';

import { largeReport, openReport } from './fixtures.mjs';

test('large-report import and render times are measured separately', async ({ page }) => {
  await page.goto('./');
  const report = largeReport(1500, 3);
  const text = JSON.stringify(report);
  const importStart = Date.now();
  await openReport(page, text, 'large.json');
  // The polite announcement fires when validation and projection finish.
  await page.locator('[aria-live="polite"]').last().filter({ hasText: 'Report loaded' }).waitFor({
    timeout: 60_000,
  });
  const importMs = Date.now() - importStart;
  const renderStart = Date.now();
  await page
    .locator('.tabulator-row:not(.tabulator-group)')
    .first()
    .waitFor({ state: 'visible', timeout: 60_000 });
  const renderMs = Date.now() - renderStart;
  console.log(
    `[performance] rows=4500 bytes=${text.length} import+validate=${importMs}ms grid-first-render=${renderMs}ms`,
  );
  // Responsive filtering: typing narrows the surface without hanging.
  const filterStart = Date.now();
  await page.getByPlaceholder('Search path, symbol, message, rule, kind').fill('unused_symbol_77');
  await expect(page.locator('.findings-counts')).toContainText('of 4500', { timeout: 30_000 });
  console.log(`[performance] filter-apply=${Date.now() - filterStart}ms`);
  const rendered = await page.locator('.tabulator-row:not(.tabulator-group)').count();
  expect(rendered).toBeLessThan(400);
});
