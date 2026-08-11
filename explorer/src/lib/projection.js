// Report-to-view projection (explorer contract §4.1).
//
// This is direct presentation over serialized values: indexing projects
// and pins by their declared name, choosing already-defined
// reference-side values, normalizing text for search, and shaping row and
// group view models. It never recomputes identities, diff classes,
// pairings, ordering, totals, rollups, truncation, or locators.

import { abbreviatedSha } from './digest.js';
import {
  confidenceDisplay,
  locationDisplay,
  messageDisplay,
  referenceOccurrence,
  ruleDisplay,
  severityDisplay,
} from './format.js';
import { sourceUrl, treeReference } from './permalink.js';
import { locatorKey } from './workspace.js';

/** @typedef {import('./types.js').Report} Report */
/** @typedef {import('./types.js').ProjectReport} ProjectReport */
/** @typedef {import('./types.js').FindingDiff} FindingDiff */
/** @typedef {import('./types.js').DiffRollup} DiffRollup */
/** @typedef {import('./types.js').CorpusPinRecord} CorpusPinRecord */

/** Sentinel facet value for findings without a rule ID (§2.3). */
export const NO_RULE = '(no rule)';

/** Sentinel facet value for findings without a severity (§2.3). */
export const NO_SEVERITY = '(no severity)';

/** Confidence facet buckets, including unavailable confidence (§2.3). */
export const CONFIDENCE_BUCKETS = /** @type {const} */ ([
  { value: 'high', label: '90–100%' },
  { value: 'medium', label: '70–89%' },
  { value: 'low', label: 'Below 70%' },
  { value: 'na', label: 'Unavailable' },
]);

/**
 * @param {number | null} confidence
 * @returns {'high' | 'medium' | 'low' | 'na'}
 */
export function confidenceBucket(confidence) {
  if (confidence === null) {
    return 'na';
  }
  if (confidence >= 90) {
    return 'high';
  }
  return confidence >= 70 ? 'medium' : 'low';
}

/**
 * @typedef {object} FindingRow
 * @property {string} key locator key; the stable row index
 * @property {import('./types.js').FindingLocator} locator
 * @property {number} index zero-based serialized report order
 * @property {string} project
 * @property {import('./types.js').DiffClass} diffClass
 * @property {string} rule display form, possibly paired
 * @property {string | null} ruleValue reference-side rule ID
 * @property {string} confidence display form, possibly paired
 * @property {number | null} confidenceValue reference-side confidence
 * @property {'high' | 'medium' | 'low' | 'na'} confidenceBucket
 * @property {string} severity display form, possibly paired
 * @property {string | null} severityValue reference-side severity
 * @property {string} kind
 * @property {string | null} symbol
 * @property {string} path
 * @property {number} line reference-side start line
 * @property {string} location display form, possibly paired
 * @property {string} message display form, possibly paired
 * @property {string} haystack lower-cased searchable text
 * @property {FindingDiff} diff the serialized diff itself
 * @property {CorpusPinRecord | null} pin resolved corpus pin, when declared
 */

/**
 * @typedef {object} ProjectView
 * @property {string} name
 * @property {CorpusPinRecord | null} pin
 * @property {{label: string, url: string} | null} tree pinned-tree reference
 * @property {ProjectReport} report
 * @property {string[]} rollupLines display rollup lines (reporting §3.2)
 */

/**
 * @typedef {object} StatusModel
 * @property {boolean} comparable
 * @property {boolean} isolationEnforced
 * @property {boolean} truncated
 * @property {string[]} truncatedProjects
 * @property {number} errorCount
 * @property {number} integrityWarningCount
 * @property {number} sourceWarningCount
 * @property {import('./types.js').DependencyDelta[]} environmentDelta
 * @property {boolean} isExport the document is an explorer export of a chosen subset
 * @property {boolean} clean no condition present
 */

/**
 * @typedef {object} Projection
 * @property {{base: string, head: string}} revisions
 * @property {ProjectView[]} projects
 * @property {FindingRow[]} rows serialized report order
 * @property {Map<string, FindingRow>} rowsByKey
 * @property {Map<string, ProjectView>} projectsByName
 * @property {boolean} hasSeverity any occurrence carries a severity label
 * @property {StatusModel} status
 * @property {Report} report
 */

/**
 * @param {import('./types.js').EnvironmentRecord | null} environment
 * @param {string[] | null} command
 * @param {string} side
 * @returns {string}
 */
function revisionLabel(environment, command, side) {
  if (environment !== null) {
    return environment.ref;
  }
  if (command !== null && command.length > 0) {
    // Escape-hatch argv is trusted manifest configuration (reporting §3.5).
    return `${side} command: ${command.join(' ')}`;
  }
  return `unknown ${side}`;
}

/**
 * Rollup display lines per diff class: the five largest groups plus an
 * explicit omitted tail, mirroring the reporting contract §3.2 layout.
 *
 * @param {DiffRollup[]} rollups
 * @returns {string[]} one line per nonzero diff class
 */
export function rollupLines(rollups) {
  /** @type {string[]} */
  const lines = [];
  for (const diffClass of /** @type {const} */ (['new', 'dropped', 'changed'])) {
    const groups = rollups.filter((rollup) => rollup.diff_class === diffClass);
    if (groups.length === 0) {
      continue;
    }
    const total = groups.reduce((sum, group) => sum + group.count, 0);
    const shown = groups.slice(0, 5);
    const parts = shown.map((group) => `${group.rule_id ?? `kind:${group.kind}`} ${group.count}`);
    const omitted = groups.slice(5);
    if (omitted.length > 0) {
      const findings = omitted.reduce((sum, group) => sum + group.count, 0);
      parts.push(`${findings} findings across ${omitted.length} other groups`);
    }
    lines.push(`${diffClass} ${total}: ${parts.join(', ')}`);
  }
  return lines;
}

/**
 * @param {FindingDiff} diff
 * @returns {string}
 */
function searchHaystack(diff) {
  const parts = [diff.path, diff.symbol ?? '', diff.kind];
  for (const occurrence of [diff.base_occurrence, diff.head_occurrence]) {
    if (occurrence !== null) {
      parts.push(occurrence.message, occurrence.rule_id ?? '');
    }
  }
  return parts.join('\n').toLowerCase();
}

/**
 * Build the immutable view model the workbench renders.
 *
 * @param {Report} report
 * @returns {Projection}
 */
export function projectReport(report) {
  const manifest = report.manifest;
  const pins = new Map(manifest.corpus_pins.map((pin) => [pin.name, pin]));
  /** @type {FindingRow[]} */
  const rows = [];
  /** @type {ProjectView[]} */
  const projects = [];
  let errorCount = 0;
  let integrityWarningCount = 0;
  let sourceWarningCount = 0;
  /** @type {string[]} */
  const truncatedProjects = [];
  let hasSeverity = false;
  let index = 0;
  for (const project of report.projects) {
    const pin = pins.get(project.project) ?? null;
    projects.push({
      name: project.project,
      pin,
      tree: pin === null ? null : treeReference(pin),
      report: project,
      rollupLines: rollupLines(project.rollups),
    });
    errorCount += project.errors.length;
    integrityWarningCount += project.integrity_warnings.length;
    sourceWarningCount += project.source_warnings.length;
    if (project.truncated) {
      truncatedProjects.push(project.project);
    }
    for (const diff of project.diffs) {
      const locator = diff.locator;
      if (locator === null) {
        // Unreachable after validate.js preconditions; kept as a guard.
        throw new Error('projection requires serialized locators');
      }
      const reference = referenceOccurrence(diff);
      if (
        (diff.base_occurrence?.severity ?? null) !== null ||
        (diff.head_occurrence?.severity ?? null) !== null
      ) {
        hasSeverity = true;
      }
      rows.push({
        key: locatorKey(locator),
        locator,
        index,
        project: project.project,
        diffClass: diff.diff_class,
        rule: ruleDisplay(diff),
        ruleValue: reference.rule_id,
        confidence: confidenceDisplay(diff),
        confidenceValue: reference.confidence,
        confidenceBucket: confidenceBucket(reference.confidence),
        severity: severityDisplay(diff),
        severityValue: reference.severity,
        kind: diff.kind,
        symbol: diff.symbol,
        path: diff.path,
        line: reference.start_line,
        location: locationDisplay(diff),
        message: messageDisplay(diff),
        haystack: searchHaystack(diff),
        diff,
        pin,
      });
      index += 1;
    }
  }
  const status = {
    comparable: manifest.comparable,
    isolationEnforced: manifest.isolation_enforced,
    truncated: report.truncated,
    truncatedProjects,
    errorCount,
    integrityWarningCount,
    sourceWarningCount,
    environmentDelta: manifest.environment_delta,
    isExport: /** @type {{document_kind?: unknown}} */ (report).document_kind !== undefined,
    clean:
      manifest.comparable &&
      manifest.isolation_enforced &&
      !report.truncated &&
      errorCount === 0 &&
      integrityWarningCount === 0 &&
      sourceWarningCount === 0 &&
      manifest.environment_delta.length === 0,
  };
  return {
    revisions: {
      base: revisionLabel(manifest.base, manifest.base_cmd, 'base'),
      head: revisionLabel(manifest.head, manifest.head_cmd, 'head'),
    },
    projects,
    rows,
    rowsByKey: new Map(rows.map((row) => [row.key, row])),
    projectsByName: new Map(projects.map((project) => [project.name, project])),
    hasSeverity,
    status,
    report,
  };
}

/**
 * The pinned source permalink of a row's reference side, when one exists.
 *
 * @param {FindingRow} row
 * @returns {string | null}
 */
export function rowSourceUrl(row) {
  if (row.pin === null) {
    return null;
  }
  const reference = referenceOccurrence(row.diff);
  return sourceUrl(row.pin, row.diff.path, reference.start_line, reference.end_line);
}

/**
 * Group-header display data for one project (§2.4).
 *
 * @param {ProjectView} project
 * @returns {{repoLine: string, countsLine: string, rollupLines: string[]}}
 */
export function projectHeaderModel(project) {
  const report = project.report;
  const repoLine =
    project.tree !== null
      ? `${project.tree.label} @ ${abbreviatedSha(project.pin?.resolved_sha ?? '')}`
      : project.pin !== null
        ? `${project.pin.repo} @ ${abbreviatedSha(project.pin.resolved_sha)}`
        : 'no corpus pin recorded';
  const totals = report.totals;
  const findings = report.base_findings === 1 ? 'finding' : 'findings';
  const countsLine =
    `base ${report.base_findings} ${findings} → head ${report.head_findings} · ` +
    `+${totals.new} new · -${totals.dropped} dropped · ~${totals.changed} changed`;
  return { repoLine, countsLine, rollupLines: project.rollupLines };
}
