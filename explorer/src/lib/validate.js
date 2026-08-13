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
        bounded(
          `Unsupported schema version ${shown}; this explorer reads version ${supportedSchemaVersion}. ` +
            'Regenerate the report with the liveness-primer release this explorer ships with, or open it ' +
            'in the explorer build matching the report.',
        ),
      ],
    };
  }
  const isExport = record['document_kind'] === EXPORT_DOCUMENT_KIND;
  const validate = isExport ? validateExplorerExport : validateReport;
  if (!validate(parsed)) {
    const failures = (validate.errors ?? []).slice(0, MAX_ERRORS).map((failure) => {
      const where = failure.instancePath === '' ? '/' : failure.instancePath;
      // Ajv names the offending key in params but not in the message, so
      // "must NOT have additional properties" alone cannot be acted on.
      const offending = /** @type {{additionalProperty?: string}} */ (failure.params ?? {})
        .additionalProperty;
      const named = offending === undefined ? '' : `: ${offending}`;
      return bounded(`${where}: ${failure.message ?? 'schema violation'}${named}`);
    });
    const lead =
      'This file is not structured like a liveness-primer report or export, so it cannot be opened.';
    return {
      ok: false,
      errors:
        failures.length > 0 ? [`${lead} The first problems, located by JSON path:`, ...failures] : [lead],
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
        errors.push(
          `${where}: this finding has no locator, the stable ID the explorer tracks findings by. ` +
            'Regenerate the report with a liveness-primer release that writes locators.',
        );
      } else {
        const key = locatorKey(diff.locator);
        if (seen.has(key)) {
          errors.push(
            `${where}: duplicate locator — two findings carry the same stable ID, so the explorer ` +
              'cannot tell them apart. This report was not produced by a standard liveness-primer run.',
          );
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
