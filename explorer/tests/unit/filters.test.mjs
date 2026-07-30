// Filter tests: every dimension, OR-within/AND-across composition, and
// confidence-side semantics (explorer contract §8.1-§8.3).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  NO_RULE_ID,
  confidenceMatches,
  confidenceSideMatches,
  dimensionMatches,
  emptyFilters,
  filterRows,
  optionCounts,
  rowMatches,
  ruleFilterValue,
} from '../../src/lib/filters.js';
import { buildReviewRows } from '../../src/lib/projection.js';
import { fixtureReport } from './helpers.mjs';

const rows = buildReviewRows(fixtureReport());
const unreviewed = () => 'unreviewed';

test('empty filters display every row', () => {
  assert.equal(filterRows(rows, emptyFilters(), unreviewed).length, rows.length);
});

test('selections within one dimension are ORed', () => {
  const filters = emptyFilters();
  filters.classes.add('new');
  filters.classes.add('dropped');
  const displayed = filterRows(rows, filters, unreviewed);
  assert.ok(displayed.length > 0);
  assert.ok(displayed.every((row) => row.diffClass === 'new' || row.diffClass === 'dropped'));
});

test('active dimensions are ANDed', () => {
  const filters = emptyFilters();
  filters.projects.add('alpha');
  filters.classes.add('new');
  const displayed = filterRows(rows, filters, unreviewed);
  assert.ok(displayed.every((row) => row.project === 'alpha' && row.diffClass === 'new'));
  filters.search = 'no-such-text-anywhere';
  assert.equal(filterRows(rows, filters, unreviewed).length, 0);
});

test('the rule dimension offers an explicit no-rule-id option', () => {
  const filters = emptyFilters();
  filters.rules.add(NO_RULE_ID);
  const displayed = filterRows(rows, filters, unreviewed);
  assert.ok(displayed.length > 0);
  assert.ok(displayed.every((row) => row.ruleId === null));
  const ruled = emptyFilters();
  ruled.rules.add('SKY-U001');
  assert.ok(filterRows(rows, ruled, unreviewed).every((row) => row.ruleId === 'SKY-U001'));
  assert.equal(ruleFilterValue(displayed[0]), NO_RULE_ID);
});

test('kind and changed-field dimensions filter on their values', () => {
  const kinds = emptyFilters();
  kinds.kinds.add('function');
  assert.ok(filterRows(rows, kinds, unreviewed).length > 0);
  const fields = emptyFilters();
  fields.changedFields.add('rule');
  const displayed = filterRows(rows, fields, unreviewed);
  assert.ok(displayed.length > 0);
  assert.ok(displayed.every((row) => row.changedFields.includes('rule')));
});

test('disposition filtering uses the supplied lookup', () => {
  const filters = emptyFilters();
  filters.dispositions.add('expected');
  const marked = rows[0].locatorKey;
  const lookup = (row) => (row.locatorKey === marked ? 'expected' : 'unreviewed');
  const displayed = filterRows(rows, filters, lookup);
  assert.equal(displayed.length, 1);
  assert.equal(displayed[0].locatorKey, marked);
});

test('text search is case-insensitive over the indexed fields', () => {
  const filters = emptyFilters();
  filters.search = 'SKY-u001';
  const displayed = filterRows(rows, filters, unreviewed);
  assert.ok(displayed.length > 0);
  filters.search = 'lib/b.py';
  assert.equal(filterRows(rows, filters, unreviewed).length, 1);
});

test('confidence sides distinguish NA, zero, range, and absent occurrences', () => {
  const naOnly = { active: true, side: 'reference', min: 0, max: 100, includeNa: true, includeRange: false };
  const zeroOnly = { active: true, side: 'reference', min: 0, max: 0, includeNa: false, includeRange: true };
  const zeroRow = rows.find((row) => row.reference.confidence === 0);
  const naRow = rows.find((row) => row.reference.confidence === null);
  assert.equal(confidenceMatches(zeroRow, zeroOnly), true);
  assert.equal(confidenceMatches(zeroRow, naOnly), false);
  assert.equal(confidenceMatches(naRow, naOnly), true);
  assert.equal(confidenceMatches(naRow, zeroOnly), false);
  // An absent occurrence never matches its side, even for NA.
  assert.equal(confidenceSideMatches(null, naOnly), false);
  const dropped = rows.find((row) => row.diffClass === 'dropped');
  assert.equal(confidenceMatches(dropped, { ...naOnly, side: 'head' }), false);
  assert.equal(confidenceMatches(dropped, { ...naOnly, side: 'head', active: false }), true);
  const sixty = { active: true, side: 'either', min: 50, max: 70, includeNa: false, includeRange: true };
  assert.equal(confidenceMatches(dropped, sixty), true);
  assert.equal(confidenceMatches(dropped, { ...sixty, side: 'base' }), true);
  assert.equal(confidenceMatches(dropped, { ...sixty, min: 90, max: 100 }), false);
});

test('option counts are relative to the other active dimensions', () => {
  const filters = emptyFilters();
  filters.projects.add('beta');
  const classCounts = optionCounts(rows, filters, 'classes', (row) => [row.diffClass], unreviewed);
  assert.equal(classCounts.get('new'), 1);
  assert.equal(classCounts.get('dropped') ?? 0, 0);
  // The dimension being counted ignores its own selection.
  filters.classes.add('dropped');
  const again = optionCounts(rows, filters, 'classes', (row) => [row.diffClass], unreviewed);
  assert.equal(again.get('new'), 1);
});

test('dimensionMatches treats empty dimensions as unrestricted', () => {
  const filters = emptyFilters();
  for (const dimension of ['projects', 'classes', 'rules', 'kinds', 'changedFields', 'dispositions', 'confidence', 'search']) {
    assert.equal(dimensionMatches(rows[0], filters, dimension, unreviewed), true);
  }
  assert.equal(rowMatches(rows[0], filters, unreviewed), true);
});
