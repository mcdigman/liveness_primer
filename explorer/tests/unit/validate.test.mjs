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
  // A first-generation report is its own origin (§6).
  assert.equal(result.sourceSha256, null);
});

test('the two document kinds are disjoint and each is held to its own schema', () => {
  const asExport = goldenReport();
  asExport.document_kind = 'explorer-export';
  asExport.source_report_sha256 = 'ab'.repeat(32);
  const accepted = checkReport(textOf(asExport));
  assert.equal(accepted.ok, true, JSON.stringify(accepted));
  assert.equal(accepted.sourceSha256, 'ab'.repeat(32));
  // An export without provenance, and a report wearing export fields, both
  // fail: neither schema admits the other's document.
  const noOrigin = goldenReport();
  noOrigin.document_kind = 'explorer-export';
  assert.equal(checkReport(textOf(noOrigin)).ok, false);
  const undeclared = goldenReport();
  undeclared.source_report_sha256 = 'ab'.repeat(32);
  assert.equal(checkReport(textOf(undeclared)).ok, false);
  // An unknown discriminator is validated as a report, and rejected as one.
  const unknownKind = goldenReport();
  unknownKind.document_kind = 'something-else';
  const rejected = checkReport(textOf(unknownKind));
  assert.equal(rejected.ok, false);
  assert.match(rejected.errors[1], /document_kind|additional properties/u);
});

test('an unexpected property is named, not just counted', () => {
  // "must NOT have additional properties" alone cannot be acted on: the
  // reader has to diff the file against the schema to find the key. This
  // is the shape a report generated before a field rename presents.
  const stale = goldenReport();
  stale.projects[0].totals.changed_confidence = 1;
  const result = checkReport(textOf(stale));
  assert.equal(result.ok, false);
  assert.ok(
    result.errors.some((line) => line.includes('changed_confidence')),
    JSON.stringify(result.errors),
  );
});

test('export comments are validated by locator shape, not accepted blindly', () => {
  const withComments = goldenReport();
  withComments.document_kind = 'explorer-export';
  withComments.source_report_sha256 = 'ab'.repeat(32);
  withComments.comments = [{ locator: withComments.projects[0].diffs[0].locator, comment: 'look again' }];
  assert.equal(checkReport(textOf(withComments)).ok, true);
  withComments.comments = [{ locator: { project: 'alpha' }, comment: 'incomplete' }];
  const rejected = checkReport(textOf(withComments));
  assert.equal(rejected.ok, false);
  assert.match(rejected.errors[1], /\/comments\/0\/locator/u);
});

test('a comment is bounded to a margin note at the import boundary', () => {
  const withComments = goldenReport();
  withComments.document_kind = 'explorer-export';
  withComments.source_report_sha256 = 'ab'.repeat(32);
  const locator = withComments.projects[0].diffs[0].locator;
  withComments.comments = [{ locator, comment: 'x'.repeat(200) }];
  assert.equal(checkReport(textOf(withComments)).ok, true);
  withComments.comments = [{ locator, comment: 'x'.repeat(201) }];
  const rejected = checkReport(textOf(withComments));
  assert.equal(rejected.ok, false);
  assert.match(rejected.errors[1], /\/comments\/0\/comment/u);
  assert.match(rejected.errors[1], /200/u);
  // The bound counts code points, as Python's `len` does, so an astral
  // character costs one here and one there rather than one and two.
  withComments.comments = [{ locator, comment: '😀'.repeat(200) }];
  assert.equal(checkReport(textOf(withComments)).ok, true);
  withComments.comments = [{ locator, comment: '😀'.repeat(201) }];
  assert.equal(checkReport(textOf(withComments)).ok, false);
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
  assert.match(rejected.errors[0], /not structured like a liveness-primer report/u);
  assert.match(rejected.errors[1], /\/totals\/new/u);
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
  assert.match(rejectedMissing.errors[0], /^\/projects\/0\/diffs\/1\/locator: this finding has no locator/u);
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
