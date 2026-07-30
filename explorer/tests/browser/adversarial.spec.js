// Adversarial fixtures: inert DOM structure, no unexpected network, no
// CSP violations, and structurally valid exports (explorer contract §17.4).
import { expect, test } from '@playwright/test';

import { hostileReport, reportFile } from './fixtures.mjs';

test('hostile report values stay text: no injected elements, requests, or CSP hits', async ({ page }) => {
  const violations = [];
  const dialogs = [];
  page.on('console', (message) => {
    if (message.text().includes('Content Security Policy')) violations.push(message.text());
  });
  page.on('dialog', (dialog) => {
    dialogs.push(dialog.message());
    void dialog.dismiss();
  });
  const requests = [];
  page.on('request', (request) => requests.push(request.url()));
  await page.goto('.');
  await page.setInputFiles('#report-input', reportFile(hostileReport(), 'hostile.json'));
  await expect(page.locator('#summary-region')).toBeVisible();
  // Open the finding whose message and source carry every payload family.
  await page.locator('#findings-body tr', { hasText: 'lib/b.py' }).getByRole('button').click();
  await expect(page.locator('#details-region')).toBeVisible();
  // The hostile markup is rendered as literal text, never as elements.
  expect(await page.locator('#details-content img').count()).toBe(0);
  expect(await page.locator('#details-content svg').count()).toBe(0);
  expect(await page.locator('iframe').count()).toBe(0);
  expect(await page.locator('#escaped').count()).toBe(0);
  await expect(page.locator('#details-content')).toContainText('<script>alert(2)</script>');
  // No dialog fired, no external request was made, no CSP violation logged.
  expect(dialogs).toEqual([]);
  const external = requests.filter((url) => !url.startsWith('http://127.0.0.1:8930/'));
  expect(external).toEqual([]);
  expect(violations).toEqual([]);
});

test('hostile values cannot break the markdown export structure', async ({ page }) => {
  await page.goto('.');
  await page.setInputFiles('#report-input', reportFile(hostileReport(), 'hostile.json'));
  await expect(page.locator('#summary-region')).toBeVisible();
  await page.locator('#findings-body tr', { hasText: 'lib/b.py' }).getByRole('button').click();
  await page.locator('#details-region').getByLabel('unexpected', { exact: true }).check();
  await page.getByLabel(/Review note/).fill('note with\n# heading\n[link](https://evil.invalid)');
  await page.getByLabel(/Review note/).blur();
  await page.getByRole('button', { name: 'Download Markdown summary' }).click();
  const markdown = await page.locator('#markdown-fallback').inputValue();
  // The hostile link brackets arrive escaped, so no Markdown link is
  // formed: every `](` before a javascript: or evil target is `\](`.
  expect(markdown).not.toMatch(/[^\\]\]\(javascript:/);
  expect(markdown).toContain('\\[x\\](javascript:alert(3))');
  expect(markdown).not.toMatch(/[^\\]\]\(https:\/\/evil\.invalid/);
  expect(markdown).toContain('\\[link\\](https://evil.invalid)');
  expect(markdown).not.toContain('\n# heading');
  const headings = markdown.split('\n').filter((line) => line.startsWith('#'));
  expect(headings[0]).toBe('# liveness primer review summary');
});

test('the review export validates and the digest scopes storage', async ({ page }) => {
  await page.goto('.');
  await page.setInputFiles('#report-input', reportFile(hostileReport(), 'hostile.json'));
  await expect(page.locator('#summary-region')).toBeVisible();
  await page.locator('#findings-body tr').first().getByRole('button', { name: /Details/ }).click();
  await page.locator('#details-region').getByLabel('expected', { exact: true }).check();
  const keys = await page.evaluate(() => Object.keys(localStorage));
  const reviewKeys = keys.filter((key) => key.startsWith('liveness-primer-review:'));
  expect(reviewKeys).toHaveLength(1);
  expect(reviewKeys[0]).toMatch(/^liveness-primer-review:[0-9a-f]{64}$/);
});

test('storage failure keeps in-memory review usable and warns', async ({ page }) => {
  await page.goto('.');
  await page.addInitScript(() => {
    const broken = {
      getItem: () => null,
      setItem: () => {
        throw new Error('QuotaExceededError');
      },
      removeItem: () => {},
    };
    Object.defineProperty(window, 'localStorage', { value: broken });
  });
  await page.goto('.');
  await page.setInputFiles('#report-input', reportFile(hostileReport(), 'hostile.json'));
  await expect(page.locator('#summary-region')).toBeVisible();
  await page.locator('#findings-body tr').first().getByRole('button', { name: /Details/ }).click();
  await page.locator('#details-region').getByLabel('expected', { exact: true }).check();
  await expect(page.locator('#review-progress')).toContainText('1 expected');
  await expect(page.locator('#storage-banner')).toBeVisible();
});
