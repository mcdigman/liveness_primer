import assert from 'node:assert/strict';
import { test } from 'node:test';

import { supportedSchemaVersion, validateExplorerExport } from '../../src/generated/validators.js';
import { projectReport } from '../../src/lib/projection.js';
import {
  buildReportExport,
  reportExportFilename,
  serializeReportExport,
} from '../../src/lib/reportexport.js';
import { checkReport } from '../../src/lib/validate.js';
import { goldenReport } from './helpers.mjs';

const ORIGIN = 'ab'.repeat(32);

/** @param {object[]} rows */
function keysOf(rows) {
  return rows.map((row) => row.key);
}

test('an export is the report over the chosen rows plus its origin digest', () => {
  const report = goldenReport();
  const rows = projectReport(report).rows;
  const chosen = [rows[0], rows[3], rows[17]];
  const payload = buildReportExport(report, ORIGIN, chosen);
  assert.equal(payload.schema_version, supportedSchemaVersion);
  assert.equal(payload.document_kind, 'explorer-export');
  assert.equal(payload.source_report_sha256, ORIGIN);
  assert.deepEqual(payload.comments, []);
  assert.deepEqual(payload.manifest, report.manifest);
  const exportedRows = projectReport(payload).rows;
  assert.deepEqual(keysOf(exportedRows), keysOf(chosen));
  assert.ok(validateExplorerExport(payload), JSON.stringify(validateExplorerExport.errors));
});

test('aggregates describe the run, not the subset, and truncation says so', () => {
  const report = goldenReport();
  const rows = projectReport(report).rows;
  const payload = buildReportExport(report, ORIGIN, [rows[0]]);
  // Reporting §3.2: totals and rollups are the complete pre-truncation
  // counts, so a filtered export carries them through untouched.
  assert.deepEqual(payload.totals, report.totals);
  assert.deepEqual(payload.rollups, report.rollups);
  assert.equal(report.truncated, false);
  assert.equal(payload.truncated, true);
  assert.deepEqual(
    payload.projects.map((project) => project.truncated),
    [true, true],
  );
});

test('an untouched project keeps its own truncation flag', () => {
  const report = goldenReport();
  const rows = projectReport(report).rows;
  const beta = rows.filter((row) => row.project === 'beta');
  const alpha = rows.filter((row) => row.project === 'alpha');
  const whole = buildReportExport(report, ORIGIN, [...alpha, ...beta]);
  assert.equal(whole.truncated, false);
  assert.deepEqual(
    whole.projects.map((project) => project.truncated),
    [false, false],
  );
  const preTruncated = goldenReport();
  preTruncated.projects[1].truncated = true;
  preTruncated.truncated = true;
  const carried = buildReportExport(preTruncated, ORIGIN, [...alpha, ...beta]);
  assert.equal(carried.projects[1].truncated, true);
});

test('exporting nothing keeps a valid, empty-diff document', () => {
  const report = goldenReport();
  const payload = buildReportExport(report, ORIGIN, []);
  assert.deepEqual(
    payload.projects.map((project) => project.diffs.length),
    [0, 0],
  );
  assert.equal(checkReport(serializeReportExport(payload)).ok, true);
});

test('the explorer accepts its own export as an import', () => {
  const report = goldenReport();
  const rows = projectReport(report).rows;
  const chosen = [rows[1], rows[2], rows[17]];
  const text = serializeReportExport(buildReportExport(report, ORIGIN, chosen));
  const result = checkReport(text);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.sourceSha256, ORIGIN);
  assert.deepEqual(keysOf(projectReport(result.report).rows), keysOf(chosen));
});

test('re-exporting an export narrows further and still names the origin', () => {
  const report = goldenReport();
  const rows = projectReport(report).rows;
  const once = buildReportExport(report, ORIGIN, [rows[0], rows[1], rows[17]]);
  const imported = checkReport(serializeReportExport(once));
  assert.equal(imported.ok, true);
  // The chain is irrelevant: the second generation names the same origin,
  // which is the digest the importer reports rather than the file's own.
  const twice = buildReportExport(imported.report, imported.sourceSha256, [
    projectReport(imported.report).rows[0],
  ]);
  assert.equal(twice.source_report_sha256, ORIGIN);
  assert.deepEqual(twice.totals, report.totals);
  const reimported = checkReport(serializeReportExport(twice));
  assert.equal(reimported.ok, true, JSON.stringify(reimported));
  assert.equal(projectReport(reimported.report).rows.length, 1);
});

test('comments an import carried survive only for exported findings', () => {
  const report = goldenReport();
  const rows = projectReport(report).rows;
  const carrier = buildReportExport(report, ORIGIN, rows);
  carrier.comments = [
    { locator: rows[0].locator, comment: 'kept' },
    { locator: rows[5].locator, comment: 'dropped with its finding' },
  ];
  assert.equal(checkReport(serializeReportExport(carrier)).ok, true);
  const narrowed = buildReportExport(carrier, ORIGIN, [rows[0]]);
  assert.deepEqual(narrowed.comments, [{ locator: rows[0].locator, comment: 'kept' }]);
});

test('the filename names the run the export came from', () => {
  assert.equal(reportExportFilename(ORIGIN), `liveness-primer-export-${ORIGIN.slice(0, 12)}.json`);
  assert.equal(serializeReportExport({ a: 1 }), '{\n  "a": 1\n}\n');
});
