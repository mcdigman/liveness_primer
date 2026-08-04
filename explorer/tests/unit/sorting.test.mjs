import assert from 'node:assert/strict';
import { test } from 'node:test';

import { projectReport } from '../../src/lib/projection.js';
import { SORT_OPTIONS, sortOption, sortRows } from '../../src/lib/sorting.js';
import { goldenReport } from './helpers.mjs';

const projection = projectReport(goldenReport());
const rows = projection.rows;

test('report order restores the exact serialized order after any sort', () => {
  for (const option of SORT_OPTIONS) {
    const reordered = sortRows(rows, option.value);
    assert.equal(reordered.length, rows.length);
    const restored = sortRows(reordered, 'report');
    assert.deepEqual(
      restored.map((row) => row.key),
      rows.map((row) => row.key),
    );
  }
});

test('sorting never mutates the input row array', () => {
  const before = rows.map((row) => row.key);
  sortRows(rows, 'location');
  assert.deepEqual(
    rows.map((row) => row.key),
    before,
  );
});

test('location sorts by path then reference line', () => {
  const sorted = sortRows(rows, 'location');
  const keys = sorted.map((row) => `${row.path}:${String(row.line).padStart(8, '0')}`);
  assert.deepEqual(
    keys,
    [...keys].sort((a, b) => a.localeCompare(b)),
  );
});

test('confidence sorts high first with NA last', () => {
  const sorted = sortRows(rows, 'confidence');
  const values = sorted.map((row) => row.confidenceValue ?? -1);
  assert.deepEqual(
    values,
    [...values].sort((a, b) => b - a),
  );
  assert.equal(sorted.at(-1).confidenceValue, null);
});

test('rule sorts findings without a rule last; class ranks new, dropped, changed', () => {
  const byRule = sortRows(rows, 'rule');
  const lastRule = byRule.at(-1);
  assert.equal(lastRule.ruleValue, null);
  const byClass = sortRows(rows, 'class');
  const ranks = byClass.map((row) => ({ new: 0, dropped: 1, changed: 2 })[row.diffClass]);
  assert.deepEqual(
    ranks,
    [...ranks].sort((a, b) => a - b),
  );
  const byKind = sortRows(rows, 'kind');
  assert.equal(byKind.length, rows.length);
});

test('unknown sort values fall back to report order', () => {
  assert.equal(sortOption('nonsense').value, 'report');
  assert.deepEqual(
    sortRows(rows, 'nonsense').map((row) => row.index),
    rows.map((row) => row.index),
  );
});
