import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  anySelection,
  emptySelections,
  facetCounts,
  matchesFacets,
  matchesSearch,
  rowPredicate,
  searchTerms,
} from '../../src/lib/facets.js';
import { NO_RULE, projectReport } from '../../src/lib/projection.js';
import { goldenReport } from './helpers.mjs';

const projection = projectReport(goldenReport());
const rows = projection.rows;

test('facet counts are full-report counts with a clear no-rule value', () => {
  const counts = facetCounts(rows);
  const total = rows.length;
  assert.equal(
    [...counts.diffClass.values()].reduce((a, b) => a + b, 0),
    total,
  );
  assert.equal(counts.project.get('alpha') + counts.project.get('beta'), total);
  assert.ok(counts.rule.get(NO_RULE) > 0);
  assert.ok(counts.kind.get('function') > 0);
  assert.equal(
    [...counts.confidence.values()].reduce((a, b) => a + b, 0),
    total,
  );
  // Open-ended categories order by descending count, then label.
  const ruleCounts = [...counts.rule.values()];
  assert.deepEqual(
    ruleCounts,
    [...ruleCounts].sort((a, b) => b - a),
  );
});

test('selections OR within a category and AND across categories', () => {
  const selections = emptySelections();
  assert.equal(anySelection(selections), false);
  selections.diffClass.add('new');
  selections.diffClass.add('changed');
  assert.equal(anySelection(selections), true);
  const newOrChanged = rows.filter((row) => matchesFacets(row, selections));
  assert.ok(newOrChanged.every((row) => row.diffClass === 'new' || row.diffClass === 'changed'));
  selections.project.add('beta');
  const also = rows.filter((row) => matchesFacets(row, selections));
  assert.ok(also.every((row) => row.project === 'beta'));
  selections.rule.add(NO_RULE);
  const noRule = rows.filter((row) => matchesFacets(row, selections));
  assert.ok(noRule.every((row) => row.ruleValue === null));
  selections.kind.add('function');
  selections.confidence.add('na');
  const full = rows.filter((row) => matchesFacets(row, selections));
  assert.ok(full.every((row) => row.kind === 'function' && row.confidenceValue === null));
  const kindMiss = { ...emptySelections(), kind: new Set(['import']) };
  assert.ok(rows.every((row) => !matchesFacets(row, kindMiss)));
  const ruleMiss = { ...emptySelections(), rule: new Set(['NOT-A-RULE']) };
  assert.ok(rows.every((row) => !matchesFacets(row, ruleMiss)));
  const projectMiss = { ...emptySelections(), project: new Set(['no-such-project']) };
  assert.ok(rows.every((row) => !matchesFacets(row, projectMiss)));
});

test('search terms are case-insensitive and ANDed', () => {
  assert.deepEqual(searchTerms('  '), []);
  assert.deepEqual(searchTerms(' SKY  pkg/A.py '), ['sky', 'pkg/a.py']);
  const ruled = rows.find((row) => row.symbol === 'ruled');
  assert.ok(matchesSearch(ruled, searchTerms('SKY-U001 ruled')));
  assert.ok(!matchesSearch(ruled, searchTerms('SKY-U001 missing-term')));
  assert.ok(rows.every((row) => matchesSearch(row, [])));
});

test('the combined predicate honors hidden state and show-hidden', () => {
  const hiddenRow = rows[0];
  const hidden = new Set([hiddenRow.key]);
  const defaultView = rowPredicate(emptySelections(), '', hidden, false);
  assert.equal(defaultView(hiddenRow), false);
  assert.equal(defaultView(rows[1]), true);
  const revealed = rowPredicate(emptySelections(), '', hidden, true);
  assert.equal(revealed(hiddenRow), true);
  const searched = rowPredicate(emptySelections(), 'no-such-token-anywhere', hidden, true);
  assert.ok(rows.every((row) => !searched(row)));
});
