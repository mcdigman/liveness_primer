import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  CONFIDENCE_BUCKETS,
  confidenceBucket,
  projectHeaderModel,
  projectReport,
  rollupLines,
  rowSourceUrl,
} from '../../src/lib/projection.js';
import { locatorKey } from '../../src/lib/workspace.js';
import { goldenReport, loadGoldenFixture } from './helpers.mjs';

test('every serialized diff projects one row in report order with its locator key', () => {
  const fixture = loadGoldenFixture();
  const projection = projectReport(fixture.report);
  const diffCount = fixture.report.projects.reduce((sum, project) => sum + project.diffs.length, 0);
  assert.equal(projection.rows.length, diffCount);
  assert.deepEqual(
    projection.rows.map((row) => row.locator),
    fixture.locators,
  );
  assert.deepEqual(
    projection.rows.map((row) => row.index),
    projection.rows.map((_row, index) => index),
  );
  for (const row of projection.rows) {
    assert.equal(projection.rowsByKey.get(row.key), row);
    assert.equal(row.key, locatorKey(row.locator));
  }
});

test('projection refuses a diff without a serialized locator', () => {
  const report = goldenReport();
  report.projects[0].diffs[0].locator = null;
  assert.throws(() => projectReport(report), /serialized locators/u);
});

test('paired changed values show base and head', () => {
  const projection = projectReport(goldenReport());
  const bySymbol = new Map(projection.rows.map((row) => [`${row.symbol}:${row.diffClass}`, row]));
  // The identity pins the line span and rule ID: a moved span or renamed
  // rule code is a dropped row plus a new row, each at its own location.
  assert.equal(bySymbol.get('mover:dropped').location, 'pkg/a.py:10');
  assert.equal(bySymbol.get('mover:new').location, 'pkg/a.py:20');
  assert.equal(bySymbol.get('ruled:dropped').rule, 'SKY-U001');
  assert.equal(bySymbol.get('ruled:new').rule, 'SKY-U003');
  assert.equal(bySymbol.get('gain:dropped').rule, '-');
  assert.equal(bySymbol.get('gain:new').rule, 'SKY-U002');
  const zero = bySymbol.get('zero:changed');
  assert.equal(zero.confidence, '0% → NA');
  // A severity change pairs as one changed row with a paired display.
  const sev = bySymbol.get('sev:changed');
  assert.equal(sev.severity, 'MEDIUM → HIGH');
  assert.equal(sev.severityValue, 'MEDIUM');
  assert.equal(projection.hasSeverity, true);
  const solo = projection.rows.find((row) => row.project === 'beta');
  assert.equal(solo.diffClass, 'new');
  assert.equal(solo.confidence, 'NA');
  assert.equal(solo.confidenceBucket, 'na');
  assert.equal(solo.severity, '-');
  assert.equal(solo.severityValue, null);
});

test('a report without severities projects hasSeverity false', () => {
  const report = goldenReport();
  for (const project of report.projects) {
    for (const diff of project.diffs) {
      for (const occurrence of [diff.base_occurrence, diff.head_occurrence]) {
        if (occurrence !== null) {
          occurrence.severity = null;
        }
      }
    }
  }
  assert.equal(projectReport(report).hasSeverity, false);
});

test('search haystack covers path, symbol, messages, rules, and kind', () => {
  const projection = projectReport(goldenReport());
  const ruled = projection.rows.find((row) => row.symbol === 'ruled' && row.diffClass === 'dropped');
  for (const needle of ['pkg/a.py', 'ruled', 'sky-u001', 'function']) {
    assert.ok(ruled.haystack.includes(needle), needle);
  }
  const renamed = projection.rows.find((row) => row.symbol === 'ruled' && row.diffClass === 'new');
  assert.ok(renamed.haystack.includes('sky-u003'));
});

test('status reflects manifest safety and per-project health', () => {
  const projection = projectReport(goldenReport());
  // The golden fixture is an escape-hatch run: not comparable, isolation on.
  assert.equal(projection.status.comparable, false);
  assert.equal(projection.status.isolationEnforced, true);
  assert.equal(projection.status.clean, false);
  assert.equal(projection.status.errorCount, 0);
  assert.equal(projection.status.truncated, false);
  assert.deepEqual(projection.status.truncatedProjects, []);
  assert.equal(projection.revisions.base, 'base command: old-faketool');
  assert.equal(projection.revisions.head, 'head command: new-faketool');
});

test('a clean managed report reports clean status and environment refs', () => {
  const report = goldenReport();
  report.manifest.comparable = true;
  report.manifest.base = {
    ref: 'v4.31.0',
    sha: 'a'.repeat(40),
    fingerprint: 'f',
    freeze: [],
    from_cache: true,
    rebuilt: false,
  };
  report.manifest.head = { ...report.manifest.base, ref: 'v4.31.1' };
  report.manifest.base_cmd = null;
  report.manifest.head_cmd = null;
  const projection = projectReport(report);
  assert.deepEqual(projection.revisions, { base: 'v4.31.0', head: 'v4.31.1' });
  assert.equal(projection.status.clean, true);
  const truncated = goldenReport();
  truncated.truncated = true;
  truncated.projects[1].truncated = true;
  assert.deepEqual(projectReport(truncated).status.truncatedProjects, ['beta']);
  const bare = goldenReport();
  bare.manifest.base_cmd = null;
  assert.equal(projectReport(bare).revisions.base, 'unknown base');
});

test('project headers show pinned tree, counts, and rollups', () => {
  const projection = projectReport(goldenReport());
  const alpha = projection.projectsByName.get('alpha');
  const header = projectHeaderModel(alpha);
  assert.equal(header.repoLine, 'example/alpha @ 33333333');
  assert.match(header.countsLine, /^base 14 findings → head 14 · \+\d+ new · -\d+ dropped · ~\d+ changed$/u);
  assert.ok(header.rollupLines.length > 0);
  const beta = projection.projectsByName.get('beta');
  assert.equal(projectHeaderModel(beta).repoLine, 'ssh://git@internal.invalid/beta.git @ 44444444');
  assert.match(projectHeaderModel(beta).countsLine, /base 0 findings/u);
  const unpinned = goldenReport();
  unpinned.manifest.corpus_pins = [];
  const headerless = projectReport(unpinned);
  assert.equal(projectHeaderModel(headerless.projectsByName.get('alpha')).repoLine, 'no corpus pin recorded');
  const single = goldenReport();
  single.projects[0].base_findings = 1;
  const singleHeader = projectHeaderModel(projectReport(single).projectsByName.get('alpha'));
  assert.match(singleHeader.countsLine, /^base 1 finding →/u);
});

test('rollup lines follow the reporting-contract display shape', () => {
  const rollup = (diffClass, ruleId, kind, count) => ({
    diff_class: diffClass,
    rule_id: ruleId,
    kind,
    count,
  });
  assert.deepEqual(rollupLines([]), []);
  assert.deepEqual(rollupLines([rollup('new', 'SKY-U001', null, 80), rollup('new', null, 'function', 3)]), [
    'new 83: SKY-U001 80, kind:function 3',
  ]);
  const many = [
    rollup('changed', 'R1', null, 9),
    rollup('changed', 'R2', null, 8),
    rollup('changed', 'R3', null, 7),
    rollup('changed', 'R4', null, 6),
    rollup('changed', 'R5', null, 5),
    rollup('changed', 'R6', null, 2),
    rollup('changed', 'R7', null, 1),
  ];
  assert.deepEqual(rollupLines(many), [
    'changed 38: R1 9, R2 8, R3 7, R4 6, R5 5, 3 findings across 2 other groups',
  ]);
});

test('confidence buckets cover the declared facet options', () => {
  assert.deepEqual(
    CONFIDENCE_BUCKETS.map((bucket) => bucket.value),
    ['high', 'medium', 'low', 'na'],
  );
  assert.equal(confidenceBucket(95), 'high');
  assert.equal(confidenceBucket(90), 'high');
  assert.equal(confidenceBucket(75), 'medium');
  assert.equal(confidenceBucket(0), 'low');
  assert.equal(confidenceBucket(null), 'na');
});

test('row source URLs exist only for GitHub-pinned projects', () => {
  const projection = projectReport(goldenReport());
  const alphaRow = projection.rows.find((row) => row.project === 'alpha');
  assert.match(
    rowSourceUrl(alphaRow),
    /^https:\/\/github\.com\/example\/alpha\/blob\/3{40}\/pkg\/a\.py#L\d/u,
  );
  const betaRow = projection.rows.find((row) => row.project === 'beta');
  assert.equal(rowSourceUrl(betaRow), null);
  const unpinned = goldenReport();
  unpinned.manifest.corpus_pins = [];
  const pinless = projectReport(unpinned);
  assert.equal(rowSourceUrl(pinless.rows[0]), null);
});
