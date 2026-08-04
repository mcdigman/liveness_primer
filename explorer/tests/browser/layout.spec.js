// Workbench layout (explorer contract §2, §10): stationary header and side
// regions, a single scrolling findings surface, bounded rendering, and the
// intermediate and narrow behaviors, at the two required laptop viewports.
import { expect, test } from '@playwright/test';

import { goldenReport, largeReport, openReportAndWait } from './fixtures.mjs';

for (const viewport of [
  { width: 1440, height: 900 },
  { width: 1280, height: 800 },
]) {
  test.describe(`desktop workbench at ${viewport.width}x${viewport.height}`, () => {
    test.use({ viewport });

    test('the document body does not scroll and only the findings region scrolls', async ({ page }) => {
      await page.goto('./');
      await openReportAndWait(page, largeReport(400, 3));
      const bodyScrollable = await page.evaluate(
        () => document.documentElement.scrollHeight > document.documentElement.clientHeight,
      );
      expect(bodyScrollable).toBe(false);
      await expect(page.locator('.filter-rail')).toBeVisible();
      await expect(page.locator('.side-region')).toBeVisible();
      const holder = page.locator('.tabulator-tableholder');
      const scrollable = await holder.evaluate((element) => element.scrollHeight > element.clientHeight);
      expect(scrollable).toBe(true);
    });

    test('opening finding context preserves the central scroll position', async ({ page }) => {
      await page.goto('./');
      await openReportAndWait(page, largeReport(400, 3));
      const holder = page.locator('.tabulator-tableholder');
      await holder.evaluate((element) => element.scrollTo(0, 2200));
      await page.waitForTimeout(150);
      const before = await holder.evaluate((element) => element.scrollTop);
      expect(before).toBeGreaterThan(1000);
      await page.locator('.tabulator-row button[aria-label^="Open finding context"]').first().click();
      await expect(page.locator('.context-panel')).toBeVisible();
      const after = await holder.evaluate((element) => element.scrollTop);
      expect(Math.abs(after - before)).toBeLessThan(4);
    });

    test('large reports render a bounded number of rows', async ({ page }) => {
      await page.goto('./');
      await openReportAndWait(page, largeReport(1500, 3));
      await expect(page.locator('.findings-counts')).toContainText('4500 total');
      const rendered = await page.locator('.tabulator-row').count();
      expect(rendered).toBeLessThan(400);
    });
  });
}

test.describe('intermediate width', () => {
  test.use({ viewport: { width: 1024, height: 768 } });

  test('the finding context overlays while filters and table stay visible', async ({ page }) => {
    await page.goto('./');
    await openReportAndWait(page, goldenReport());
    await expect(page.locator('.side-region')).toBeHidden();
    await expect(page.locator('.filter-rail')).toBeVisible();
    await page.locator('.tabulator-row button[aria-label^="Open finding context"]').first().click();
    await expect(page.locator('.side-region')).toBeVisible();
    await expect(page.locator('.context-panel')).toBeVisible();
    await expect(page.locator('.filter-rail')).toBeVisible();
    await expect(page.locator('[data-testid="findings-table"]')).toBeVisible();
    await page.getByRole('button', { name: 'Close finding context' }).click();
    await expect(page.locator('.side-region')).toBeHidden();
    // The export summary opens on demand.
    await page.getByRole('button', { name: /Export \(/ }).click();
    await expect(page.locator('.export-panel')).toBeVisible();
  });
});

test.describe('narrow width', () => {
  test.use({ viewport: { width: 700, height: 900 } });

  test('filters become a drawer and the findings surface stays primary', async ({ page }) => {
    await page.goto('./');
    await openReportAndWait(page, goldenReport());
    await expect(page.locator('.filter-rail')).toBeHidden();
    await page.getByRole('button', { name: 'Filters' }).click();
    await expect(page.locator('.filter-rail')).toBeVisible();
    await page.getByRole('button', { name: 'Filters' }).click();
    await expect(page.locator('.filter-rail')).toBeHidden();
    await expect(page.locator('.tabulator-row').first()).toBeVisible();
  });
});

test.describe('200% zoom equivalent', () => {
  // 1280x800 at 200% browser zoom presents ~640x400 CSS pixels.
  test.use({ viewport: { width: 640, height: 400 } });

  test('controls remain operable and findings remain primary', async ({ page }) => {
    await page.goto('./');
    await openReportAndWait(page, goldenReport());
    await expect(page.locator('.tabulator-row').first()).toBeVisible();
    await page.getByRole('button', { name: 'Filters' }).click();
    await page.locator('.facet', { hasText: 'Diff class' }).getByLabel('+ New').check();
    await page.getByRole('button', { name: 'Reset all' }).click();
    await page.getByRole('button', { name: 'Filters' }).click();
    await page.locator('.tabulator-row button[aria-label^="Open finding context"]').first().click();
    await expect(page.locator('.context-panel')).toBeVisible();
  });
});

test.describe('themes', () => {
  test('light and dark themes both render the workbench', async ({ page }) => {
    await page.goto('./');
    await openReportAndWait(page, goldenReport());
    for (const theme of ['light', 'dark', 'system']) {
      await page.getByLabel('Theme').selectOption(theme);
      if (theme !== 'system') {
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
      }
      await expect(page.locator('.tabulator-row').first()).toBeVisible();
    }
  });
});
