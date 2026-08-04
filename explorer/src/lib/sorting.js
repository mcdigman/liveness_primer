// Row ordering (explorer contract §2.4, §6).
//
// Sorting is presentation over the projected rows; it never changes
// finding identity or the serialized locator, and returning to report
// order restores the exact serialized project and finding order via the
// stored report-order index.

/** @typedef {import('./projection.js').FindingRow} FindingRow */

const CLASS_RANK = { new: 0, dropped: 1, changed: 2 };

/**
 * @typedef {{value: string, label: string, compare: (a: FindingRow, b: FindingRow) => number}} SortOption
 */

/**
 * @param {FindingRow} a
 * @param {FindingRow} b
 * @returns {number}
 */
function byReportOrder(a, b) {
  return a.index - b.index;
}

/**
 * @param {FindingRow} a
 * @param {FindingRow} b
 * @returns {number}
 */
function byLocation(a, b) {
  return a.path.localeCompare(b.path) || a.line - b.line || byReportOrder(a, b);
}

/**
 * @param {FindingRow} a
 * @param {FindingRow} b
 * @returns {number}
 */
function byRule(a, b) {
  const left = a.ruleValue ?? '\u{10FFFF}';
  const right = b.ruleValue ?? '\u{10FFFF}';
  return left.localeCompare(right) || byReportOrder(a, b);
}

/**
 * @param {FindingRow} a
 * @param {FindingRow} b
 * @returns {number}
 */
function byConfidenceDescending(a, b) {
  const left = a.confidenceValue ?? -1;
  const right = b.confidenceValue ?? -1;
  return right - left || byReportOrder(a, b);
}

/**
 * @param {FindingRow} a
 * @param {FindingRow} b
 * @returns {number}
 */
function byDiffClass(a, b) {
  return CLASS_RANK[a.diffClass] - CLASS_RANK[b.diffClass] || byReportOrder(a, b);
}

/**
 * @param {FindingRow} a
 * @param {FindingRow} b
 * @returns {number}
 */
function byKind(a, b) {
  return a.kind.localeCompare(b.kind) || byReportOrder(a, b);
}

/** @type {SortOption[]} */
export const SORT_OPTIONS = [
  { value: 'report', label: 'Report order', compare: byReportOrder },
  { value: 'location', label: 'Location', compare: byLocation },
  { value: 'rule', label: 'Rule', compare: byRule },
  { value: 'confidence', label: 'Confidence (high first)', compare: byConfidenceDescending },
  { value: 'class', label: 'Diff class', compare: byDiffClass },
  { value: 'kind', label: 'Kind', compare: byKind },
];

/**
 * @param {string} value
 * @returns {SortOption} the matching option, or report order
 */
export function sortOption(value) {
  return SORT_OPTIONS.find((option) => option.value === value) ?? SORT_OPTIONS[0];
}

/**
 * @param {FindingRow[]} rows
 * @param {string} value sort option value
 * @returns {FindingRow[]} a newly ordered copy
 */
export function sortRows(rows, value) {
  return [...rows].sort(sortOption(value).compare);
}
