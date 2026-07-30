// Computed-style contrast verification for every semantic token pairing in
// both themes (explorer contract §17.3). Visual snapshots are not accepted
// as contrast evidence; the ratios are computed from the resolved values.
import { expect, test } from '@playwright/test';

/** Token pairings: [foreground, background, minimum ratio]. */
const TEXT_PAIRINGS = [
  ['--text', '--canvas', 4.5],
  ['--text', '--surface', 4.5],
  ['--text', '--elevated-surface', 4.5],
  ['--muted-text', '--surface', 4.5],
  ['--link', '--surface', 4.5],
  ['--new-foreground', '--new-background', 4.5],
  ['--dropped-foreground', '--dropped-background', 4.5],
  ['--changed-foreground', '--changed-background', 4.5],
  ['--expected-foreground', '--expected-background', 4.5],
  ['--unexpected-foreground', '--unexpected-background', 4.5],
  ['--unreviewed-foreground', '--unreviewed-background', 4.5],
  ['--warning-foreground', '--warning-background', 4.5],
  ['--error-foreground', '--error-background', 4.5],
  ['--text', '--code-background', 4.5],
  ['--text', '--selection-background', 4.5],
  ['--text', '--code-highlight', 4.5],
];

/** Non-text pairings (borders, focus) need 3:1 (explorer contract §13.1). */
const NON_TEXT_PAIRINGS = [
  ['--border', '--surface', 3],
  ['--focus', '--canvas', 3],
  ['--focus', '--surface', 3],
  ['--new-border', '--new-background', 3],
  ['--dropped-border', '--dropped-background', 3],
  ['--changed-border', '--changed-background', 3],
  ['--expected-border', '--expected-background', 3],
  ['--unexpected-border', '--unexpected-background', 3],
  ['--unreviewed-border', '--unreviewed-background', 3],
  ['--warning-border', '--warning-background', 3],
  ['--error-border', '--error-background', 3],
];

async function contrastRatios(page, pairings) {
  return page.evaluate((pairs) => {
    const styles = getComputedStyle(document.documentElement);
    const probe = document.createElement('div');
    document.body.append(probe);
    const channel = (value) => {
      const scaled = value / 255;
      return scaled <= 0.04045 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
    };
    const luminance = (token) => {
      probe.style.color = styles.getPropertyValue(token);
      const rgb = getComputedStyle(probe).color.match(/\d+(\.\d+)?/g).map(Number);
      return 0.2126 * channel(rgb[0]) + 0.7152 * channel(rgb[1]) + 0.0722 * channel(rgb[2]);
    };
    const results = pairs.map(([foreground, background, minimum]) => {
      const lighter = Math.max(luminance(foreground), luminance(background));
      const darker = Math.min(luminance(foreground), luminance(background));
      const ratio = (lighter + 0.05) / (darker + 0.05);
      return { foreground, background, minimum, ratio };
    });
    probe.remove();
    return results;
  }, pairings);
}

for (const theme of ['light', 'dark']) {
  test(`text token pairings meet 4.5:1 in the ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    await page.getByLabel('Theme').selectOption(theme);
    for (const result of await contrastRatios(page, TEXT_PAIRINGS)) {
      expect
        .soft(result.ratio, `${result.foreground} on ${result.background} (${theme})`)
        .toBeGreaterThanOrEqual(result.minimum);
    }
  });

  test(`non-text token pairings meet 3:1 in the ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    await page.getByLabel('Theme').selectOption(theme);
    for (const result of await contrastRatios(page, NON_TEXT_PAIRINGS)) {
      expect
        .soft(result.ratio, `${result.foreground} on ${result.background} (${theme})`)
        .toBeGreaterThanOrEqual(result.minimum);
    }
  });
}
