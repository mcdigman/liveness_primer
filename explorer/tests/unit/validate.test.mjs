import assert from 'node:assert/strict';
import { test } from 'node:test';

import { supportedSchemaVersion } from '../../src/generated/validators.js';
import { MAX_REPORT_BYTES, checkReport } from '../../src/lib/validate.js';
import { goldenReport } from './helpers.mjs';

/** @param {object} report */
function textOf(report) {
  return JSON.stringify(report);
}

test('a real Python-generated report validates and activates', () => {
  const result = checkReport(textOf(goldenReport()));
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.report.schema_version, supportedSchemaVersion);
});

test('malformed JSON and non-object documents are rejected with bounded errors', () => {
  const malformed = checkReport('{"schema_version": ');
  assert.equal(malformed.ok, false);
  assert.match(malformed.errors[0], /^Malformed JSON:/u);
  assert.ok(malformed.errors[0].length <= 260);
  for (const text of ['[]', '"report"', '3', 'null', 'true']) {
    const rejected = checkReport(text);
    assert.equal(rejected.ok, false);
    assert.ok(rejected.errors.length >= 1);
  }
});

test('unsupported and missing schema versions are named explicitly', () => {
  const outdated = goldenReport();
  outdated.schema_version = '0.9.0';
  const rejectedOld = checkReport(textOf(outdated));
  assert.equal(rejectedOld.ok, false);
  assert.match(rejectedOld.errors[0], /Unsupported schema version 0\.9\.0/u);
  assert.match(rejectedOld.errors[0], new RegExp(supportedSchemaVersion.replaceAll('.', '\\.')));
  const missing = goldenReport();
  delete missing.schema_version;
  const rejectedMissing = checkReport(textOf(missing));
  assert.equal(rejectedMissing.ok, false);
  assert.match(rejectedMissing.errors[0], /Unsupported schema version missing/u);
});

test('structural schema violations produce path-based errors', () => {
  const truncatedManifest = goldenReport();
  delete truncatedManifest.manifest;
  const missingManifest = checkReport(textOf(truncatedManifest));
  assert.equal(missingManifest.ok, false);
  assert.ok(missingManifest.errors.length >= 1);
  const badTotals = goldenReport();
  badTotals.totals.new = 'many';
  const rejected = checkReport(textOf(badTotals));
  assert.equal(rejected.ok, false);
  assert.match(rejected.errors[0], /\/totals\/new/u);
  const extra = goldenReport();
  extra.unexpected_field = 1;
  assert.equal(checkReport(textOf(extra)).ok, false);
});

test('adversarial string content is data, not a bypass', () => {
  const hostile = goldenReport();
  const diff = hostile.projects[0].diffs[0];
  const side = diff.diff_class === 'new' ? 'head_occurrence' : 'base_occurrence';
  diff[side].message = '<img src=x onerror=alert(1)>__proto__[x]';
  diff.path = 'pkg/&lt;script&gt;.py';
  const result = checkReport(textOf(hostile));
  assert.equal(result.ok, true);
});

test('locator UI preconditions reject missing and duplicate locators', () => {
  const missing = goldenReport();
  missing.projects[0].diffs[1].locator = null;
  const rejectedMissing = checkReport(textOf(missing));
  assert.equal(rejectedMissing.ok, false);
  assert.match(
    rejectedMissing.errors[0],
    /^\/projects\/0\/diffs\/1\/locator: every serialized finding diff/u,
  );
  const duplicated = goldenReport();
  duplicated.projects[0].diffs[1].locator = structuredClone(duplicated.projects[0].diffs[0].locator);
  const rejectedDuplicate = checkReport(textOf(duplicated));
  assert.equal(rejectedDuplicate.ok, false);
  assert.match(rejectedDuplicate.errors[0], /duplicate locator/u);
});

test('many precondition failures stay bounded', () => {
  const broken = goldenReport();
  // Double the diff list so the failure count exceeds the error bound.
  broken.projects[0].diffs = [...broken.projects[0].diffs, ...structuredClone(broken.projects[0].diffs)];
  for (const project of broken.projects) {
    for (const diff of project.diffs) {
      diff.locator = null;
    }
  }
  const rejected = checkReport(textOf(broken));
  assert.equal(rejected.ok, false);
  assert.equal(rejected.errors.length, 20);
});

test('the size bound is 50 MiB', () => {
  assert.equal(MAX_REPORT_BYTES, 50 * 1024 * 1024);
});
