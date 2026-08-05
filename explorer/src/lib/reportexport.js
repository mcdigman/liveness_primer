// Report export over the selected findings (explorer contract §6).
//
// The export is the input format: the same document with `diffs` narrowed
// to the chosen rows. Aggregates are not recomputed, because `totals` and
// `rollups` are defined as the complete pre-truncation counts of the run —
// carrying them through unchanged, with `truncated` raised, is exactly the
// truncation the format already models, and keeps the export honest about
// how large the run it came from was. Diffs stay in serialized report
// order because the rows are.
//
// `source_report_sha256` always names the original run's report bytes, so
// re-exporting an export chains no history: locators identify findings
// across every generation, which makes the intermediate documents
// irrelevant.

import { EXPORT_DOCUMENT_KIND } from './validate.js';
import { locatorKey } from './workspace.js';

/** @typedef {import('./types.js').Report} Report */
/** @typedef {import('./types.js').ExplorerExport} ExplorerExport */
/** @typedef {import('./types.js').FindingComment} FindingComment */
/** @typedef {import('./projection.js').FindingRow} FindingRow */

/**
 * Build the export document for the chosen rows.
 *
 * @param {Report} report the imported document, itself possibly an export
 * @param {string} sourceSha256 origin digest of the original report bytes
 * @param {FindingRow[]} rows rows to export, in serialized report order
 * @returns {ExplorerExport}
 */
export function buildReportExport(report, sourceSha256, rows) {
  const keys = new Set(rows.map((row) => row.key));
  const projects = report.projects.map((project) => {
    const diffs = project.diffs.filter((diff) => diff.locator !== null && keys.has(locatorKey(diff.locator)));
    return { ...project, diffs, truncated: project.truncated || diffs.length < project.diffs.length };
  });
  // Comments an imported export carried survive for the findings that do.
  const carried = /** @type {{comments?: FindingComment[]}} */ (report).comments ?? [];
  return {
    ...report,
    document_kind: EXPORT_DOCUMENT_KIND,
    source_report_sha256: sourceSha256,
    comments: carried.filter((comment) => keys.has(locatorKey(comment.locator))),
    projects,
    truncated: projects.some((project) => project.truncated),
  };
}

/**
 * Serialize the export document for download.
 *
 * @param {ExplorerExport} payload
 * @returns {string}
 */
export function serializeReportExport(payload) {
  return `${JSON.stringify(payload, null, 2)}\n`;
}

/**
 * Suggested download filename, named for the run the export came from.
 *
 * @param {string} sourceSha256
 * @returns {string}
 */
export function reportExportFilename(sourceSha256) {
  return `liveness-primer-export-${sourceSha256.slice(0, 12)}.json`;
}
