// Review-session schema, import, and export (explorer contract §10, §11).
//
// Review dispositions concern the expected blast radius of a detector
// change; they are never translated into internal-corpus annotations.
// Import applies JSON Schema validation followed by report-digest
// matching, known and unique locator checks, canonical entry ordering,
// and note limits, and fails atomically.

import { REVIEW_SESSION_SCHEMA } from '../generated/schemas.js';
import { validateAgainstSchema } from './jsonschema.js';
import { locatorKey } from './projection.js';

export const DISPOSITIONS = /** @type {const} */ (['expected', 'unexpected']);

/**
 * @typedef {import('./jsonschema.js').SchemaError} SchemaError
 * @typedef {import('./projection.js').Locator} Locator
 * @typedef {{ locator: Locator, disposition: 'expected' | 'unexpected', note: string | null }} ReviewEntry
 * @typedef {{ schema_version: string, report_sha256: string, report_schema_version: string,
 *   created_at: string, updated_at: string, entries: ReviewEntry[] }} ReviewSession
 */

/**
 * @typedef {{ dispositions: Map<string, 'expected' | 'unexpected'>, notes: Map<string, string> }} ReviewState
 */

/**
 * Build an empty in-memory review state.
 *
 * @returns {ReviewState} Fresh review state.
 */
export function emptyReviewState() {
  return { dispositions: new Map(), notes: new Map() };
}

/**
 * The UI disposition of one row: `unreviewed` when nothing is recorded.
 *
 * @param {ReviewState} state Review state.
 * @param {string} key Locator key.
 * @returns {'expected' | 'unexpected' | 'unreviewed'} Disposition.
 */
export function dispositionOf(state, key) {
  return state.dispositions.get(key) ?? 'unreviewed';
}

/**
 * Assemble the portable review session from in-memory state (explorer §11.1).
 *
 * Entries carry unique locators in canonical report order; unreviewed
 * findings are omitted. A note without a disposition is not portable.
 *
 * @param {ReviewState} state Review state.
 * @param {import('./projection.js').ReviewRow[]} rows All rows in canonical order.
 * @param {{ schemaVersion: string, reportSha256: string, reportSchemaVersion: string,
 *   createdAt: string, updatedAt: string }} meta Session metadata.
 * @returns {ReviewSession} The portable session.
 */
export function buildReviewSession(state, rows, meta) {
  /** @type {ReviewEntry[]} */
  const entries = [];
  for (const row of rows) {
    const disposition = state.dispositions.get(row.locatorKey);
    if (disposition === undefined) continue;
    const note = state.notes.get(row.locatorKey);
    entries.push({
      locator: row.locator,
      disposition,
      note: note === undefined || note === '' ? null : note,
    });
  }
  return {
    schema_version: meta.schemaVersion,
    report_sha256: meta.reportSha256,
    report_schema_version: meta.reportSchemaVersion,
    created_at: meta.createdAt,
    updated_at: meta.updatedAt,
    entries,
  };
}

/**
 * Serialize a review session as canonical UTF-8 JSON (explorer §11.2).
 *
 * @param {ReviewSession} session The session.
 * @returns {string} Two-space indented JSON, newline-terminated.
 */
export function serializeReviewSession(session) {
  return `${JSON.stringify(session, null, 2)}\n`;
}

/**
 * Validate an imported review session against the active report (explorer §11.2).
 *
 * The import fails atomically: any duplicate locator, unknown locator,
 * mismatched digest, unsupported schema version, overlong note, or
 * non-canonical entry order rejects the whole document.
 *
 * @param {unknown} document Parsed JSON document.
 * @param {{ reportSha256: string, rowOrder: Map<string, number> }} context Active-report context:
 *   digest and locator-key to canonical position.
 * @returns {{ ok: boolean, errors: SchemaError[], session: ReviewSession | null }} Outcome.
 */
export function validateReviewSession(document, context) {
  const structural = validateAgainstSchema(REVIEW_SESSION_SCHEMA, document);
  if (structural.length > 0) {
    return { ok: false, errors: structural, session: null };
  }
  const session = /** @type {ReviewSession} */ (document);
  /** @type {SchemaError[]} */
  const errors = [];
  if (session.report_sha256 !== context.reportSha256) {
    errors.push({ path: '$.report_sha256', message: 'review session was recorded for a different report digest' });
  }
  /** @type {Set<string>} */
  const seen = new Set();
  let previousPosition = -1;
  for (let index = 0; index < session.entries.length; index += 1) {
    const entry = session.entries[index];
    const key = locatorKey(entry.locator);
    const path = `$.entries[${index}]`;
    if (seen.has(key)) {
      errors.push({ path, message: 'duplicate review-entry locator' });
    }
    seen.add(key);
    const position = context.rowOrder.get(key);
    if (position === undefined) {
      errors.push({ path, message: 'locator does not resolve to a displayed finding' });
    } else {
      if (position <= previousPosition) {
        errors.push({ path, message: 'entries are not in canonical report order' });
      }
      previousPosition = position;
    }
    // Note length is enforced by the schema layer's maxLength, which
    // counts Unicode code points exactly like the Python model.
  }
  if (errors.length > 0) {
    return { ok: false, errors, session: null };
  }
  return { ok: true, errors: [], session };
}

/**
 * Apply a validated imported session, replacing local review state.
 *
 * @param {ReviewSession} session Validated session.
 * @returns {ReviewState} The replacement state.
 */
export function stateFromSession(session) {
  const state = emptyReviewState();
  for (const entry of session.entries) {
    const key = locatorKey(entry.locator);
    state.dispositions.set(key, entry.disposition);
    if (entry.note !== null) {
      state.notes.set(key, entry.note);
    }
  }
  return state;
}
