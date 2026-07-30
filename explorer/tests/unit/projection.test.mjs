// Projection tests: reference-side values and finding locators agree with
// the shared Python-generated golden fixture (explorer §6, §17.1).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildReviewRows,
  confidenceText,
  locatorKey,
  occurrenceSpanText,
  projectLocators,
  referenceOccurrence,
  rowSpanText,
} from '../../src/lib/projection.js';
import { fixtureReport, loadLocatorFixture, locatorsEqual } from './helpers.mjs';

test('locators agree with the Python-generated golden fixture', () => {
  const fixture = loadLocatorFixture();
  const rows = buildReviewRows(fixture.report);
  assert.ok(locatorsEqual(rows.map((row) => row.locator), fixture.locators));
});

test('locator occurrence counts subsequences sharing identity and line', () => {
  const fixture = loadLocatorFixture();
  const alpha = fixture.report.projects[0];
  const locators = projectLocators(alpha.project, alpha.diffs);
  const counts = new Map();
  for (const locator of locators) {
    const key = JSON.stringify([locator.identity, locator.line]);
    assert.equal(locator.occurrence, counts.get(key) ?? 0);
    counts.set(key, locator.occurrence + 1);
  }
  assert.ok(Math.max(...counts.values()) >= 2);
});

test('reference side is head for new and base otherwise', () => {
  const fixture = fixtureReport();
  for (const project of fixture.projects) {
    for (const diff of project.diffs) {
      const reference = referenceOccurrence(diff);
      if (diff.diff_class === 'new') {
        assert.equal(reference, diff.head_occurrence);
      } else {
        assert.equal(reference, diff.base_occurrence);
      }
    }
  }
  assert.throws(
    () =>
      referenceOccurrence({
        diff_class: 'new',
        head_occurrence: null,
        base_occurrence: null,
        identity: '',
        tool: '',
        project: '',
        path: '',
        symbol: null,
        kind: '',
        changed_fields: [],
        schema_version: '1.1.0',
      }),
    /reference side is absent/,
  );
});

test('rows join repository and corpus SHA from the unique pin', () => {
  const rows = buildReviewRows(fixtureReport());
  const alpha = rows.find((row) => row.project === 'alpha');
  assert.equal(alpha.repository, 'https://github.com/example/alpha');
  assert.equal(alpha.corpusSha, '3'.repeat(40));
  const beta = rows.find((row) => row.project === 'beta');
  assert.equal(beta.repository, 'ssh://git@internal.invalid/beta.git');
  assert.equal(beta.baseSourcePermalink, null);
  assert.equal(beta.headSourcePermalink, null);
});

test('a missing pin join is an invalid report', () => {
  const report = fixtureReport();
  report.manifest.corpus_pins = [report.manifest.corpus_pins[0]];
  assert.throws(() => buildReviewRows(report), /has no corpus pin/);
});

test('span and confidence text follow the reporting contract forms', () => {
  const rows = buildReviewRows(fixtureReport());
  const mover = rows.find((row) => row.locator.line === 10 && row.diffClass === 'changed');
  assert.equal(rowSpanText(mover), 'L10->L20');
  assert.equal(occurrenceSpanText(mover.baseOccurrence), 'L10-11');
  const zero = rows.find((row) => row.changedFields.includes('confidence'));
  assert.equal(confidenceText(zero), '0%->NA');
  const solo = rows.find((row) => row.project === 'beta');
  assert.equal(confidenceText(solo), 'NA');
  assert.equal(rowSpanText(solo), 'L5');
  const plain = rows.find((row) => row.diffClass === 'dropped' && row.locator.line === 5);
  assert.equal(confidenceText(plain), '60%');
});

test('search text covers path, symbol, message, rule, and kind, lowercased', () => {
  const rows = buildReviewRows(fixtureReport());
  const ruled = rows.find((row) => row.ruleId === 'SKY-U001');
  assert.ok(ruled.searchText.includes('sky-u001'));
  assert.ok(ruled.searchText.includes('pkg/a.py'));
  assert.ok(ruled.searchText.includes('function'));
});

test('locator keys are stable and unique', () => {
  const rows = buildReviewRows(fixtureReport());
  const keys = new Set(rows.map((row) => row.locatorKey));
  assert.equal(keys.size, rows.length);
  assert.equal(locatorKey(rows[0].locator), rows[0].locatorKey);
});

test('canonical and global indices restore report order', () => {
  const rows = buildReviewRows(fixtureReport());
  assert.deepEqual(
    rows.map((row) => row.globalIndex),
    rows.map((_row, index) => index),
  );
  let expected = 0;
  for (const row of rows) {
    if (row.canonicalIndex === 0) expected = 0;
    assert.equal(row.canonicalIndex, expected);
    expected += 1;
  }
});
