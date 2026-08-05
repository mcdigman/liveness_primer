// Structural validation of untrusted imported reports (explorer contract
// §4.3).
//
// The bundled Ajv standalone validators, compiled at build time from the
// exported Pydantic schemas for the dialect they declare, decide whether
// the browser can safely consume the document. Malformed JSON, unsupported
// schema versions, and schema failures prevent activation with bounded
// path-based errors. The two direct checks below are documented UI
// preconditions, not a parallel report verifier: the workbench keys every
// row by its serialized locator, so a diff without one, or two diffs
// sharing one, cannot be rendered meaningfully.
//
// Two document kinds activate the workbench: a first-generation report and
// an explorer export, which is that report over a chosen subset plus the
// origin digest. Both schemas forbid unknown properties, so the kinds are
// disjoint and the discriminator selects the validator rather than
// widening either one. An export is structurally a report, so everything
// downstream consumes it unchanged.

import { supportedSchemaVersion, validateExplorerExport, validateReport } from '../generated/validators.js';
import { locatorKey } from './workspace.js';

/** @typedef {import('./types.js').Report} Report */

/** Discriminator an explorer export carries and a report never does (§6). */
export const EXPORT_DOCUMENT_KIND = 'explorer-export';

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
 * `sourceSha256` is the origin digest an export carries, and null for a
 * first-generation report, whose own digest is its origin.
 *
 * @typedef {{ok: true, report: Report, sourceSha256: string | null} |
 *   {ok: false, errors: string[]}} ReportCheck
 */

/**
 * Validate one parsed-from-text report or explorer export document.
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
  const record = /** @type {Record<string, unknown>} */ (parsed);
  const declared = record['schema_version'];
  if (declared !== supportedSchemaVersion) {
    const shown = typeof declared === 'string' ? declared : 'missing';
    return {
      ok: false,
      errors: [
        bounded(`Unsupported schema version ${shown}; this explorer supports ${supportedSchemaVersion}.`),
      ],
    };
  }
  const isExport = record['document_kind'] === EXPORT_DOCUMENT_KIND;
  const validate = isExport ? validateExplorerExport : validateReport;
  if (!validate(parsed)) {
    const failures = (validate.errors ?? []).slice(0, MAX_ERRORS).map((failure) => {
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
  const source = isExport ? /** @type {string} */ (record['source_report_sha256']) : null;
  return { ok: true, report, sourceSha256: source };
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
