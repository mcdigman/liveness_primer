// Stable, deterministic sorting of review rows (explorer contract §8.4).
//
// Default sorting is project run order followed by each project's
// serialized canonical diff order; every sort is stable, missing values
// sort after present values in ascending order, and returning to report
// order restores the canonical sequence exactly.

/**
 * @typedef {'report' | 'project' | 'class' | 'rule' | 'confidence' | 'path' |
 *   'line' | 'disposition'} SortKey
 */

const CLASS_RANK = { new: 0, dropped: 1, changed: 2 };
const DISPOSITION_RANK = { unexpected: 0, expected: 1, unreviewed: 2 };

export const SORT_KEYS = /** @type {SortKey[]} */ ([
  'report',
  'project',
  'class',
  'rule',
  'confidence',
  'path',
  'line',
  'disposition',
]);

/**
 * Compare two nullable values with nulls after values in ascending order.
 *
 * @param {string | number | null} left Left value.
 * @param {string | number | null} right Right value.
 * @returns {number} Comparison result.
 */
function compareNullable(left, right) {
  if (left === null && right === null) return 0;
  if (left === null) return 1;
  if (right === null) return -1;
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

/**
 * Primary comparison value(s) of one row for one sort key.
 *
 * @param {import('./projection.js').ReviewRow} row Review row.
 * @param {SortKey} key Sort key.
 * @param {(row: import('./projection.js').ReviewRow) => string} disposition Disposition lookup.
 * @returns {Array<string | number | null>} Comparison values.
 */
function sortValues(row, key, disposition) {
  switch (key) {
    case 'report':
      return [row.globalIndex];
    case 'project':
      return [row.project];
    case 'class':
      return [CLASS_RANK[row.diffClass]];
    case 'rule':
      return [row.ruleId ?? `kind:${row.kind}`];
    case 'confidence':
      return [row.reference.confidence];
    case 'path':
      return [row.path];
    case 'line':
      return [row.locator.line];
    default:
      return [DISPOSITION_RANK[/** @type {'unexpected' | 'expected' | 'unreviewed'} */ (disposition(row))]];
  }
}

/**
 * Sort displayed rows deterministically; ties keep canonical order.
 *
 * @param {import('./projection.js').ReviewRow[]} rows Displayed rows.
 * @param {SortKey} key Sort key.
 * @param {boolean} descending Whether the primary order is descending.
 * @param {(row: import('./projection.js').ReviewRow) => string} disposition Disposition lookup.
 * @returns {import('./projection.js').ReviewRow[]} A newly sorted array.
 */
export function sortRows(rows, key, descending, disposition) {
  const decorated = rows.map((row, index) => ({ row, index, values: sortValues(row, key, disposition) }));
  decorated.sort((left, right) => {
    for (let position = 0; position < left.values.length; position += 1) {
      const outcome = compareNullable(left.values[position], right.values[position]);
      if (outcome !== 0) return descending ? -outcome : outcome;
    }
    // Stable, deterministic tiebreak: the canonical global order.
    return left.row.globalIndex - right.row.globalIndex;
  });
  return decorated.map((entry) => entry.row);
}
