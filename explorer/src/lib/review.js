// The portable review record (explorer contract §6).
//
// The payload shape is the generated `explorer-review` schema exported
// from the Pydantic ExplorerReview model; the browser builds instances of
// that schema rather than defining its own record. Locator tuples are
// emitted in serialized report order — a producer obligation the schema
// cannot express.

import { supportedSchemaVersion } from '../generated/validators.js';

/** @typedef {import('./types.js').ExplorerReview} ExplorerReview */
/** @typedef {import('./projection.js').FindingRow} FindingRow */
/** @typedef {import('./workspace.js').Workspace} Workspace */

/**
 * Build the review payload for the current workspace.
 *
 * @param {string} digest report SHA-256
 * @param {Workspace} workspace
 * @param {FindingRow[]} rows in serialized report order
 * @returns {ExplorerReview}
 */
export function buildReviewPayload(digest, workspace, rows) {
  return {
    schema_version: supportedSchemaVersion,
    report_sha256: digest,
    selected: rows.filter((row) => workspace.selected.has(row.key)).map((row) => row.locator),
    hidden: rows.filter((row) => workspace.hidden.has(row.key)).map((row) => row.locator),
  };
}

/**
 * Serialize the review payload for download.
 *
 * @param {ExplorerReview} payload
 * @returns {string}
 */
export function serializeReview(payload) {
  return `${JSON.stringify(payload, null, 2)}\n`;
}

/**
 * Suggested download filename beside the imported report name.
 *
 * @param {string} digest
 * @returns {string}
 */
export function reviewFilename(digest) {
  return `liveness-primer-review-${digest.slice(0, 12)}.json`;
}
