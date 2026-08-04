// Structural validation of untrusted imported reports (explorer contract
// §4.3).
//
// The bundled Ajv standalone validator, compiled at build time from the
// exported Pydantic schema for the dialect it declares, decides whether
// the browser can safely consume the document. Malformed JSON, unsupported
// schema versions, and schema failures prevent activation with bounded
// path-based errors. The two direct checks below are documented UI
// preconditions, not a parallel report verifier: the workbench keys every
// row by its serialized locator, so a diff without one, or two diffs
// sharing one, cannot be rendered meaningfully.

import { supportedSchemaVersion, validateReport } from '../generated/validators.js';
import { locatorKey } from './workspace.js';

/** @typedef {import('./types.js').Report} Report */

/** Reports above this byte size are rejected before reading (§8). */
export const MAX_REPORT_BYTES = 50 * 1024 * 1024;

const MAX_ERRORS = 20;
const MAX_ERROR_LENGTH = 240;

/**
 * @param {string} text
 * @returns {string}
 */
function bounded(text) {
  return text.length > MAX_ERROR_LENGTH ? `${text.slice(0, MAX_ERROR_LENGTH)}…` : text;
}

/**
 * @typedef {{ok: true, report: Report} | {ok: false, errors: string[]}} ReportCheck
 */

/**
 * Validate one parsed-from-text report document.
 *
 * @param {string} text UTF-8 decoded report bytes
 * @returns {ReportCheck}
 */
export function checkReport(text) {
  /** @type {unknown} */
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { ok: false, errors: [bounded(`Malformed JSON: ${detail}`)] };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, errors: ['The document is not a JSON object.'] };
  }
  const declared = /** @type {Record<string, unknown>} */ (parsed)['schema_version'];
  if (declared !== supportedSchemaVersion) {
    const shown = typeof declared === 'string' ? declared : 'missing';
    return {
      ok: false,
      errors: [
        bounded(`Unsupported schema version ${shown}; this explorer supports ${supportedSchemaVersion}.`),
      ],
    };
  }
  if (!validateReport(parsed)) {
    const failures = (validateReport.errors ?? []).slice(0, MAX_ERRORS).map((failure) => {
      const where = failure.instancePath === '' ? '/' : failure.instancePath;
      return bounded(`${where}: ${failure.message ?? 'schema violation'}`);
    });
    return {
      ok: false,
      errors: failures.length > 0 ? failures : ['The document does not match the report schema.'],
    };
  }
  const report = /** @type {Report} */ (parsed);
  const preconditionErrors = locatorPreconditions(report);
  if (preconditionErrors.length > 0) {
    return { ok: false, errors: preconditionErrors };
  }
  return { ok: true, report };
}

/**
 * UI preconditions over serialized locators (explorer contract §4.3):
 * every diff carries one and they are unique within the report.
 *
 * @param {Report} report
 * @returns {string[]}
 */
function locatorPreconditions(report) {
  const seen = new Set();
  const errors = [];
  for (const [projectIndex, project] of report.projects.entries()) {
    for (const [diffIndex, diff] of project.diffs.entries()) {
      const where = `/projects/${projectIndex}/diffs/${diffIndex}/locator`;
      if (diff.locator === null) {
        errors.push(`${where}: every serialized finding diff must carry a locator`);
      } else {
        const key = locatorKey(diff.locator);
        if (seen.has(key)) {
          errors.push(`${where}: duplicate locator within the report`);
        }
        seen.add(key);
      }
      if (errors.length >= MAX_ERRORS) {
        return errors;
      }
    }
  }
  return errors;
}
