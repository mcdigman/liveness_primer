// Automated accessibility scans over every principal surface and both
// themes (explorer contract §17.3). Automated results are necessary but
// not sufficient; the release process additionally records the manual
// pass required by §17.3.
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

import { goldenReport, reportFile } from './fixtures.mjs';

async function scan(page) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag22aa']).analyze();
  return results.violations;
}

for (const theme of ['light', 'dark']) {
  test(`the empty state passes axe in the ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    await page.getByLabel('Theme').selectOption(theme);
    expect(await scan(page)).toEqual([]);
  });

  test(`the loaded review surface passes axe in the ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    await page.getByLabel('Theme').selectOption(theme);
    await page.setInputFiles('#report-input', reportFile(goldenReport()));
    await expect(page.locator('#summary-region')).toBeVisible();
    expect(await scan(page)).toEqual([]);
  });

  test(`open details and source comparison pass axe in the ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    await page.getByLabel('Theme').selectOption(theme);
    await page.setInputFiles('#report-input', reportFile(goldenReport()));
    await page.locator('#findings-body tr', { hasText: 'L10->L20' }).getByRole('button').click();
    await expect(page.locator('#details-region')).toBeVisible();
    expect(await scan(page)).toEqual([]);
  });
}

test('filtered findings and the export region pass axe', async ({ page }) => {
  await page.goto('.');
  await page.setInputFiles('#report-input', reportFile(goldenReport()));
  await page.getByLabel('new', { exact: true }).check();
  await page.getByRole('button', { name: 'Download Markdown summary' }).click();
  expect(await scan(page)).toEqual([]);
});

test('reduced motion and forced colors keep the surface operable', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce', forcedColors: 'active' });
  await page.goto('.');
  await page.setInputFiles('#report-input', reportFile(goldenReport()));
  await expect(page.locator('#summary-region')).toBeVisible();
  await page.locator('#findings-body tr').first().getByRole('button', { name: /Details/ }).click();
  await expect(page.locator('#details-region')).toBeVisible();
  // Class and review badges keep visible text without custom colors.
  await expect(page.locator('#findings-body .class-badge').first()).toContainText(/new|dropped|changed/);
});

test('200 percent zoom keeps the workflow reachable', async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 500 });
  await page.goto('.');
  await page.evaluate(() => {
    document.documentElement.style.fontSize = '200%';
  });
  await page.setInputFiles('#report-input', reportFile(goldenReport()));
  await expect(page.locator('#summary-region')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Download review JSON' })).toBeVisible();
});
