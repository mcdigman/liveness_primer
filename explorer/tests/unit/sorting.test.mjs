// Sorting tests: stability, determinism, missing-value placement, and
// canonical-order restoration (explorer contract §8.4).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildReviewRows } from '../../src/lib/projection.js';
import { SORT_KEYS, sortRows } from '../../src/lib/sorting.js';
import { fixtureReport } from './helpers.mjs';

const rows = buildReviewRows(fixtureReport());
const unreviewed = () => 'unreviewed';

test('report order restores the canonical sequence exactly', () => {
  const shuffled = [...rows].reverse();
  const restored = sortRows(shuffled, 'report', false, unreviewed);
  assert.deepEqual(
    restored.map((row) => row.locatorKey),
    rows.map((row) => row.locatorKey),
  );
});

test('every sort key is stable and deterministic', () => {
  for (const key of SORT_KEYS) {
    const first = sortRows(rows, key, false, unreviewed).map((row) => row.locatorKey);
    const second = sortRows([...rows].reverse(), key, false, unreviewed).map((row) => row.locatorKey);
    assert.deepEqual(first, second, `sort key ${key} is not deterministic`);
  }
});

test('missing confidence sorts after present values in ascending order', () => {
  const sorted = sortRows(rows, 'confidence', false, unreviewed);
  const values = sorted.map((row) => row.reference.confidence);
  const firstNull = values.indexOf(null);
  assert.notEqual(firstNull, -1);
  assert.ok(values.slice(firstNull).every((value) => value === null));
  const present = values.slice(0, firstNull);
  assert.deepEqual(present, [...present].sort((a, b) => a - b));
});

test('descending reverses the primary order but keeps ties canonical', () => {
  const ascending = sortRows(rows, 'class', false, unreviewed);
  const descending = sortRows(rows, 'class', true, unreviewed);
  assert.equal(ascending[0].diffClass, 'new');
  assert.equal(descending[0].diffClass, 'changed');
  const changedTies = descending.filter((row) => row.diffClass === 'changed').map((row) => row.globalIndex);
  assert.deepEqual(changedTies, [...changedTies].sort((a, b) => a - b));
});

test('rule sorting falls back to the kind label and disposition sorting ranks unexpected first', () => {
  const byRule = sortRows(rows, 'rule', false, unreviewed);
  assert.notEqual(byRule[0].ruleId, null);
  const marked = rows[rows.length - 1].locatorKey;
  const lookup = (row) => (row.locatorKey === marked ? 'unexpected' : 'unreviewed');
  const byDisposition = sortRows(rows, 'disposition', false, lookup);
  assert.equal(byDisposition[0].locatorKey, marked);
  const byProject = sortRows(rows, 'project', false, unreviewed);
  assert.equal(byProject[0].project, 'alpha');
  const byPath = sortRows(rows, 'path', false, unreviewed);
  assert.equal(byPath[byPath.length - 1].path, 'pkg/a.py');
  const byLine = sortRows(rows, 'line', false, unreviewed);
  const lines = byLine.map((row) => row.locator.line);
  assert.deepEqual(lines, [...lines].sort((a, b) => a - b));
});
