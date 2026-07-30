// Two-layer report validation (explorer contract §5).
//
// Layer 1 applies the packaged exported JSON Schema (jsonschema.js); layer
// 2 enforces the cross-field, cross-item, and ordering invariants that
// exported JSON Schema does not express. Passing the schema check alone is
// never sufficient. All failures are bounded structural paths and
// messages; the offending value is never echoed.

import { REPORT_SCHEMA } from '../generated/schemas.js';
import { validateAgainstSchema } from './jsonschema.js';
import { projectLocators, referenceOccurrence, locatorKey } from './projection.js';

/** Input limits applied before a report becomes active (explorer §5.2). */
export const REPORT_BYTE_LIMIT = 50 * 1024 * 1024;
export const DIFF_LIMIT = 100000;
export const NOTE_LIMIT = 4096;
export const SOURCE_BYTE_LIMIT = 2 * 1024 * 1024;

/** Reports at or above this size parse off the main thread (explorer §5.2). */
export const WORKER_BYTE_THRESHOLD = 5 * 1024 * 1024;

const MAX_ERRORS = 50;

/**
 * @typedef {import('./jsonschema.js').SchemaError} SchemaError
 * @typedef {import('./projection.js').Diff} Diff
 * @typedef {import('./projection.js').Occurrence} Occurrence
 */

/**
 * @typedef {{ manifest: { tool: string, comparable: boolean, isolation_enforced: boolean,
 *   detector_repo: string | null, created_at: string, schema_version: string,
 *   platform: string, python_version: string, installer: string | null,
 *   base: { ref: string, sha: string } | null, head: { ref: string, sha: string } | null,
 *   base_cmd: string[] | null, head_cmd: string[] | null,
 *   environment_delta: Array<Record<string, unknown>>,
 *   fetches: Array<Record<string, unknown>>,
 *   corpus_pins: Array<{ name: string, repo: string, requested: string, resolved_sha: string }>,
 *   settings: { jobs: number, timeout: number, max_results: number, excerpt_lines: number,
 *     fail_on: string[], selection: string[] } },
 *   projects: Array<{ project: string, diffs: Diff[],
 *     totals: { new: number, dropped: number, changed: number,
 *       changed_confidence: number, changed_message_only: number },
 *     rollups: Array<{ diff_class: string, rule_id: string | null, kind: string | null, count: number }>,
 *     truncated: boolean, base_findings: number, head_findings: number,
 *     measured_cost_seconds: number | null,
 *     errors: Array<{ side: string, exit_code: number | null, detail: string }>,
 *     integrity_warnings: Array<{ project: string, tool: string, detail: string }>,
 *     source_warnings: string[] }>,
 *   totals: { new: number, dropped: number, changed: number,
 *     changed_confidence: number, changed_message_only: number },
 *   rollups: Array<{ diff_class: string, rule_id: string | null, kind: string | null, count: number }>,
 *   truncated: boolean, schema_version: string }} Report
 */

/**
 * Validate the structural layer: the packaged report schema.
 *
 * @param {unknown} document Parsed JSON document.
 * @returns {SchemaError[]} Bounded structural errors.
 */
export function validateReportStructure(document) {
  return validateAgainstSchema(REPORT_SCHEMA, document);
}

/**
 * @param {Occurrence} base
 * @param {Occurrence} head
 * @returns {string[]}
 */
export function computedChangedFields(base, head) {
  /** @type {string[]} */
  const fields = [];
  if (base.start_line !== head.start_line || base.end_line !== head.end_line) fields.push('line-span');
  if (base.message !== head.message) fields.push('message');
  if (base.confidence !== head.confidence) fields.push('confidence');
  if (base.rule_id !== head.rule_id) fields.push('rule');
  return fields;
}

/**
 * Compute the finding identity digest exactly as the Python core does:
 * SHA-256 over the compact JSON array of (tool, project, path, symbol,
 * kind) (contract §7).
 *
 * @param {Diff} diff Serialized diff.
 * @param {SubtleCrypto} subtle Web Crypto implementation.
 * @returns {Promise<string>} Lowercase hex digest.
 */
export async function computeIdentity(diff, subtle) {
  const material = JSON.stringify([diff.tool, diff.project, diff.path, diff.symbol, diff.kind]);
  const digest = await subtle.digest('SHA-256', new TextEncoder().encode(material));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * @param {SchemaError[]} errors
 * @param {string} path
 * @param {string} message
 */
function push(errors, path, message) {
  if (errors.length < MAX_ERRORS) errors.push({ path, message });
}

const CLASS_RANK = { new: 0, dropped: 1, changed: 2 };

/**
 * @param {Array<{ diff_class: string, rule_id: string | null, kind: string | null, count: number }>} rollups
 * @returns {Array<{ diff_class: string, rule_id: string | null, kind: string | null, count: number }>}
 */
function orderedRollups(rollups) {
  return [...rollups].sort((left, right) => {
    const classOrder =
      CLASS_RANK[/** @type {'new' | 'dropped' | 'changed'} */ (left.diff_class)] -
      CLASS_RANK[/** @type {'new' | 'dropped' | 'changed'} */ (right.diff_class)];
    if (classOrder !== 0) return classOrder;
    if (left.count !== right.count) return right.count - left.count;
    const leftLabel = left.rule_id ?? left.kind ?? '';
    const rightLabel = right.rule_id ?? right.kind ?? '';
    if (leftLabel < rightLabel) return -1;
    if (leftLabel > rightLabel) return 1;
    return 0;
  });
}

/**
 * @param {Diff[]} diffs
 * @returns {Array<{ diff_class: string, rule_id: string | null, kind: string | null, count: number }>}
 */
export function computeRollups(diffs) {
  /** @type {Map<string, { diff_class: string, rule_id: string | null, kind: string | null, count: number }>} */
  const groups = new Map();
  for (const diff of diffs) {
    const ruleId = referenceOccurrence(diff).rule_id;
    const kind = ruleId === null ? diff.kind : null;
    const key = JSON.stringify([diff.diff_class, ruleId, kind]);
    const group = groups.get(key);
    if (group === undefined) {
      groups.set(key, { diff_class: diff.diff_class, rule_id: ruleId, kind, count: 1 });
    } else {
      group.count += 1;
    }
  }
  return orderedRollups([...groups.values()]);
}

/**
 * @param {Array<{ diff_class: string, rule_id: string | null, kind: string | null, count: number }>} left
 * @param {Array<{ diff_class: string, rule_id: string | null, kind: string | null, count: number }>} right
 * @returns {boolean}
 */
function rollupsEqual(left, right) {
  if (left.length !== right.length) return false;
  return left.every(
    (rollup, index) =>
      rollup.diff_class === right[index].diff_class &&
      rollup.rule_id === right[index].rule_id &&
      rollup.kind === right[index].kind &&
      rollup.count === right[index].count,
  );
}

/**
 * @param {SchemaError[]} errors
 * @param {string} path
 * @param {Diff} diff
 */
function checkDiffShape(errors, path, diff) {
  const base = diff.base_occurrence;
  const head = diff.head_occurrence;
  for (const [name, occurrence] of /** @type {Array<[string, Occurrence | null]>} */ ([
    ['base_occurrence', base],
    ['head_occurrence', head],
  ])) {
    if (occurrence !== null && occurrence.end_line < occurrence.start_line) {
      push(errors, `${path}.${name}`, 'end_line precedes start_line');
    }
  }
  const shape = { new: base === null && head !== null, dropped: base !== null && head === null, changed: base !== null && head !== null };
  if (!shape[/** @type {'new' | 'dropped' | 'changed'} */ (diff.diff_class)]) {
    push(errors, path, `populated sides contradict diff class ${JSON.stringify(diff.diff_class)}`);
    return;
  }
  if (diff.diff_class === 'changed') {
    if (base !== null && head !== null) {
      const expected = computedChangedFields(base, head);
      if (JSON.stringify(expected) !== JSON.stringify(diff.changed_fields)) {
        push(errors, `${path}.changed_fields`, 'changed_fields do not equal the changed observable fields');
      }
    }
  } else if (diff.changed_fields.length !== 0) {
    push(errors, `${path}.changed_fields`, 'changed_fields must be empty for new and dropped diffs');
  }
}

/**
 * @param {SchemaError[]} errors
 * @param {string} path
 * @param {Occurrence} occurrence
 * @param {number} excerptLines
 */
function checkSourceExcerpt(errors, path, occurrence, excerptLines) {
  const excerpt = occurrence.source_excerpt;
  if (excerpt === null) return;
  if (excerptLines === 0) {
    push(errors, path, 'source excerpt present although the evidence budget is zero');
    return;
  }
  if (excerpt.start_line !== occurrence.start_line) {
    push(errors, path, 'source excerpt does not begin at the reported start line');
  }
  if (excerpt.lines.length > excerptLines) {
    push(errors, path, 'source excerpt exceeds the evidence budget');
  }
  const span = occurrence.end_line - occurrence.start_line + 1;
  const retainedInSpan = Math.min(excerpt.lines.length, span);
  if (excerpt.omitted_lines > Math.max(0, span - retainedInSpan)) {
    push(errors, path, 'omitted-span count contradicts the occurrence span');
  }
  if (excerpt.lines.length < excerptLines && excerpt.omitted_lines !== 0) {
    push(errors, path, 'omitted-span count is positive although the budget was not exhausted');
  }
}

/**
 * Validate the semantic layer over a structurally valid report (explorer §5.3).
 *
 * @param {Report} report Structurally valid report document.
 * @param {SubtleCrypto} subtle Web Crypto implementation for identity checks.
 * @returns {Promise<SchemaError[]>} Bounded semantic errors.
 */
export async function validateReportSemantics(report, subtle) {
  /** @type {SchemaError[]} */
  const errors = [];
  const pins = report.manifest.corpus_pins;
  const pinNames = pins.map((pin) => pin.name);
  if (new Set(pinNames).size !== pinNames.length) {
    push(errors, '$.manifest.corpus_pins', 'duplicate corpus-pin names');
  }
  const projectNames = report.projects.map((project) => project.project);
  if (new Set(projectNames).size !== projectNames.length) {
    push(errors, '$.projects', 'duplicate project-report names');
  }
  const selection = report.manifest.settings.selection;
  if (JSON.stringify(selection) !== JSON.stringify(pinNames) || JSON.stringify(selection) !== JSON.stringify(projectNames)) {
    push(errors, '$.manifest.settings.selection', 'selection, pins, and projects do not describe the same run');
  }
  const totalDiffs = report.projects.reduce((count, project) => count + project.diffs.length, 0);
  if (totalDiffs > DIFF_LIMIT) {
    // The input limit is decisive on its own; per-diff work is skipped so
    // an oversized report fails promptly (explorer §5.2).
    push(errors, '$.projects', `report carries more than ${DIFF_LIMIT} finding diffs`);
    return errors;
  }
  /** @type {Set<string>} */
  const seenLocators = new Set();
  /** @type {Array<Array<{ diff_class: string, rule_id: string | null, kind: string | null, count: number }>>} */
  const projectRollups = [];
  const overallTotals = { new: 0, dropped: 0, changed: 0, changed_confidence: 0, changed_message_only: 0 };
  for (let projectIndex = 0; projectIndex < report.projects.length; projectIndex += 1) {
    const project = report.projects[projectIndex];
    const path = `$.projects[${projectIndex}]`;
    if (pinNames.filter((name) => name === project.project).length !== 1) {
      push(errors, path, 'project does not join exactly one corpus pin');
    }
    const displayed = { new: 0, dropped: 0, changed: 0, changed_confidence: 0, changed_message_only: 0 };
    for (let diffIndex = 0; diffIndex < project.diffs.length; diffIndex += 1) {
      const diff = project.diffs[diffIndex];
      const diffPath = `${path}.diffs[${diffIndex}]`;
      if (diff.project !== project.project) {
        push(errors, diffPath, 'diff project contradicts its containing project report');
      }
      if (diff.tool !== report.manifest.tool) {
        push(errors, diffPath, 'diff tool contradicts the report manifest');
      }
      checkDiffShape(errors, diffPath, diff);
      const settings = report.manifest.settings;
      for (const [name, occurrence] of /** @type {Array<[string, Occurrence | null]>} */ ([
        ['base_occurrence', diff.base_occurrence],
        ['head_occurrence', diff.head_occurrence],
      ])) {
        if (occurrence !== null) {
          checkSourceExcerpt(errors, `${diffPath}.${name}.source_excerpt`, occurrence, settings.excerpt_lines);
        }
      }
      const identity = await computeIdentity(diff, subtle);
      if (identity !== diff.identity) {
        push(errors, `${diffPath}.identity`, 'identity is not the digest of its tool, project, path, symbol, and kind');
      }
      const bucket = /** @type {'new' | 'dropped' | 'changed'} */ (diff.diff_class);
      displayed[bucket] += 1;
      if (bucket === 'changed') {
        if (diff.changed_fields.includes('confidence')) displayed.changed_confidence += 1;
        if (diff.changed_fields.length === 1 && diff.changed_fields[0] === 'message') {
          displayed.changed_message_only += 1;
        }
      }
    }
    // Locators and rollups are derivable only when every diff carries its
    // reference side; shape violations were already recorded above.
    const shapeSound = project.diffs.every((diff) =>
      diff.diff_class === 'new' ? diff.head_occurrence !== null : diff.base_occurrence !== null,
    );
    if (shapeSound) {
      for (const locator of projectLocators(project.project, project.diffs)) {
        const key = locatorKey(locator);
        if (seenLocators.has(key)) {
          push(errors, path, 'duplicate finding locator');
        }
        seenLocators.add(key);
      }
    }
    const totals = project.totals;
    if (project.truncated) {
      for (const name of /** @type {Array<'new' | 'dropped' | 'changed'>} */ (['new', 'dropped', 'changed'])) {
        if (displayed[name] > totals[name]) {
          push(errors, `${path}.totals`, `displayed ${name} count exceeds the pre-truncation total`);
        }
      }
      if (project.diffs.length >= totals.new + totals.dropped + totals.changed) {
        push(errors, `${path}.truncated`, 'truncation is claimed but every diff is present');
      }
    } else if (
      displayed.new !== totals.new ||
      displayed.dropped !== totals.dropped ||
      displayed.changed !== totals.changed ||
      displayed.changed_confidence !== totals.changed_confidence ||
      displayed.changed_message_only !== totals.changed_message_only
    ) {
      push(errors, `${path}.totals`, 'totals contradict the serialized findings');
    }
    if (!rollupsEqual(orderedRollups(project.rollups), project.rollups)) {
      push(errors, `${path}.rollups`, 'rollups are not deterministically ordered');
    }
    if (shapeSound && !project.truncated && !rollupsEqual(computeRollups(project.diffs), project.rollups)) {
      push(errors, `${path}.rollups`, 'rollups contradict the serialized findings');
    }
    projectRollups.push(project.rollups);
    for (const name of /** @type {Array<keyof typeof overallTotals>} */ (Object.keys(overallTotals))) {
      overallTotals[name] += totals[name];
    }
  }
  for (const name of /** @type {Array<keyof typeof overallTotals>} */ (Object.keys(overallTotals))) {
    if (overallTotals[name] !== report.totals[name]) {
      push(errors, '$.totals', 'overall totals contradict the project totals');
      break;
    }
  }
  /** @type {Map<string, { diff_class: string, rule_id: string | null, kind: string | null, count: number }>} */
  const merged = new Map();
  for (const rollups of projectRollups) {
    for (const rollup of rollups) {
      const key = JSON.stringify([rollup.diff_class, rollup.rule_id, rollup.kind]);
      const existing = merged.get(key);
      if (existing === undefined) {
        merged.set(key, { ...rollup });
      } else {
        existing.count += rollup.count;
      }
    }
  }
  if (!rollupsEqual(orderedRollups([...merged.values()]), report.rollups)) {
    push(errors, '$.rollups', 'overall rollups are not the ordered sum of the project rollups');
  }
  if (report.truncated !== report.projects.some((project) => project.truncated)) {
    push(errors, '$.truncated', 'overall truncation state contradicts the projects');
  }
  return errors;
}

/**
 * Run both validation layers over a parsed report document (explorer §5.3).
 *
 * @param {unknown} document Parsed JSON document.
 * @param {SubtleCrypto} subtle Web Crypto implementation.
 * @returns {Promise<{ ok: boolean, errors: SchemaError[], report: Report | null }>}
 *   Validation outcome; `report` is set only when both layers pass.
 */
export async function validateReport(document, subtle) {
  const structural = validateReportStructure(document);
  if (structural.length > 0) {
    return { ok: false, errors: structural, report: null };
  }
  const report = /** @type {Report} */ (document);
  const semantic = await validateReportSemantics(report, subtle);
  if (semantic.length > 0) {
    return { ok: false, errors: semantic, report: null };
  }
  return { ok: true, errors: [], report };
}
