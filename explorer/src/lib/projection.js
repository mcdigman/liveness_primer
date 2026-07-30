// Pure review projection over one validated report (explorer contract §6).
//
// Each serialized FindingDiff becomes one ReviewRow; filtering, sorting,
// pagination, and review state never change locators or canonical order.

import { sourceUrl } from './permalink.js';

/**
 * @typedef {{ start_line: number, end_line: number, message: string,
 *   confidence: number | null, rule_id: string | null,
 *   raw_excerpt: string | null,
 *   source_excerpt: { start_line: number, lines: string[], omitted_lines: number } | null,
 *   schema_version: string }} Occurrence
 */

/**
 * @typedef {{ diff_class: 'new' | 'dropped' | 'changed', identity: string,
 *   tool: string, project: string, path: string, symbol: string | null,
 *   kind: string, base_occurrence: Occurrence | null,
 *   head_occurrence: Occurrence | null, changed_fields: string[],
 *   schema_version: string }} Diff
 */

/**
 * @typedef {{ project: string, identity: string, line: number, occurrence: number }} Locator
 */

/**
 * @typedef {{ locator: Locator, locatorKey: string, canonicalIndex: number,
 *   globalIndex: number, tool: string, project: string, repository: string,
 *   corpusSha: string, diffClass: 'new' | 'dropped' | 'changed',
 *   ruleId: string | null, kind: string, path: string, symbol: string | null,
 *   baseOccurrence: Occurrence | null, headOccurrence: Occurrence | null,
 *   changedFields: string[], reference: Occurrence,
 *   baseSourcePermalink: string | null, headSourcePermalink: string | null,
 *   searchText: string }} ReviewRow
 */

/**
 * Reference-side occurrence of one diff: head for `new`, base otherwise.
 *
 * @param {Diff} diff Serialized diff.
 * @returns {Occurrence} The reference occurrence.
 */
export function referenceOccurrence(diff) {
  const occurrence = diff.diff_class === 'new' ? diff.head_occurrence : diff.base_occurrence;
  if (occurrence === null) {
    throw new Error('reference side is absent');
  }
  return occurrence;
}

/**
 * Serialize a locator into a stable string key for maps and storage.
 *
 * @param {Locator} locator Finding locator.
 * @returns {string} Stable key.
 */
export function locatorKey(locator) {
  return JSON.stringify([locator.project, locator.identity, locator.line, locator.occurrence]);
}

/**
 * Compute the ordered locators of one project's serialized diff sequence.
 *
 * The serialized per-project diff sequence is the indexing set; the
 * occurrence index counts diffs sharing (identity, reference-side start
 * line) in serialized order (explorer contract §6.2).
 *
 * @param {string} project Project name.
 * @param {Diff[]} diffs Serialized diffs in canonical order.
 * @returns {Locator[]} One locator per diff, in serialized order.
 */
export function projectLocators(project, diffs) {
  /** @type {Map<string, number>} */
  const counters = new Map();
  return diffs.map((diff) => {
    const line = referenceOccurrence(diff).start_line;
    const key = JSON.stringify([diff.identity, line]);
    const occurrence = counters.get(key) ?? 0;
    counters.set(key, occurrence + 1);
    return { project, identity: diff.identity, line, occurrence };
  });
}

/**
 * Build the searchable text of one row: path, symbol, reference message,
 * rule ID, and kind, lowercased once per row (explorer §8.1, §15).
 *
 * @param {Diff} diff Serialized diff.
 * @param {Occurrence} reference Reference occurrence.
 * @returns {string} Lowercased searchable text.
 */
function searchText(diff, reference) {
  return [diff.path, diff.symbol ?? '', reference.message, reference.rule_id ?? '', diff.kind]
    .join('\n')
    .toLowerCase();
}

/**
 * Project one validated report onto its review rows (explorer §6.1).
 *
 * @param {{ manifest: { tool: string, corpus_pins: Array<{ name: string, repo: string,
 *   requested: string, resolved_sha: string }> },
 *   projects: Array<{ project: string, diffs: Diff[] }> }} report Validated report.
 * @returns {ReviewRow[]} Rows in canonical report order.
 */
export function buildReviewRows(report) {
  /** @type {ReviewRow[]} */
  const rows = [];
  const pins = new Map(report.manifest.corpus_pins.map((pin) => [pin.name, pin]));
  let globalIndex = 0;
  for (const project of report.projects) {
    const pin = pins.get(project.project);
    if (pin === undefined) {
      throw new Error(`project ${JSON.stringify(project.project)} has no corpus pin`);
    }
    const locators = projectLocators(project.project, project.diffs);
    for (let index = 0; index < project.diffs.length; index += 1) {
      const diff = project.diffs[index];
      const reference = referenceOccurrence(diff);
      const base = diff.base_occurrence;
      const head = diff.head_occurrence;
      rows.push({
        locator: locators[index],
        locatorKey: locatorKey(locators[index]),
        canonicalIndex: index,
        globalIndex,
        tool: diff.tool,
        project: project.project,
        repository: pin.repo,
        corpusSha: pin.resolved_sha,
        diffClass: diff.diff_class,
        ruleId: reference.rule_id,
        kind: diff.kind,
        path: diff.path,
        symbol: diff.symbol,
        baseOccurrence: base,
        headOccurrence: head,
        changedFields: diff.changed_fields,
        reference,
        baseSourcePermalink:
          base === null ? null : sourceUrl(pin, diff.path, base.start_line, base.end_line),
        headSourcePermalink:
          head === null ? null : sourceUrl(pin, diff.path, head.start_line, head.end_line),
        searchText: searchText(diff, reference),
      });
      globalIndex += 1;
    }
  }
  return rows;
}

/**
 * Compact span text of one occurrence: `L5` or `L5-8`.
 *
 * @param {Occurrence} occurrence Occurrence to describe.
 * @returns {string} Span text.
 */
export function occurrenceSpanText(occurrence) {
  if (occurrence.end_line !== occurrence.start_line) {
    return `L${occurrence.start_line}-${occurrence.end_line}`;
  }
  return `L${occurrence.start_line}`;
}

/**
 * Compact location span of one row: `L5`, `L5-8`, or `L5->L9` for moved
 * changed pairs (reporting contract §4).
 *
 * @param {ReviewRow} row Review row.
 * @returns {string} Span text.
 */
export function rowSpanText(row) {
  if (
    row.diffClass === 'changed' &&
    row.baseOccurrence !== null &&
    row.headOccurrence !== null &&
    row.baseOccurrence.start_line !== row.headOccurrence.start_line
  ) {
    return `L${row.baseOccurrence.start_line}->L${row.headOccurrence.start_line}`;
  }
  return occurrenceSpanText(row.reference);
}

/**
 * Exact confidence text in the reporting contract §4.3 forms.
 *
 * @param {ReviewRow} row Review row.
 * @returns {string} `NA`, `XX%`, `NA->XX%`, `XX%->NA`, or `XX%->YY%`.
 */
export function confidenceText(row) {
  /** @param {number | null} value */
  const text = (value) => (value === null ? 'NA' : `${value}%`);
  if (
    row.changedFields.includes('confidence') &&
    row.baseOccurrence !== null &&
    row.headOccurrence !== null
  ) {
    return `${text(row.baseOccurrence.confidence)}->${text(row.headOccurrence.confidence)}`;
  }
  return text(row.reference.confidence);
}
