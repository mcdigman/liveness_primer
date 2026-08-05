// Display formatting for report values (explorer contract §2.4).
//
// Diff classes always pair a stable glyph with text, changed values show
// base and head rather than collapsing them, and none of these helpers
// ever emit markup: every result is plain text for text-safe insertion.

/** @typedef {import('./types.js').DiffClass} DiffClass */
/** @typedef {import('./types.js').FindingDiff} FindingDiff */
/** @typedef {import('./types.js').FindingOccurrence} FindingOccurrence */

/** @type {Record<DiffClass, {glyph: string, label: string}>} */
export const DIFF_CLASS_PRESENTATION = {
  new: { glyph: '+', label: 'New' },
  dropped: { glyph: '-', label: 'Dropped' },
  changed: { glyph: '~', label: 'Changed' },
};

/**
 * @param {number | null} confidence
 * @returns {string}
 */
export function confidenceText(confidence) {
  return confidence === null ? 'NA' : `${confidence}%`;
}

/**
 * The confidence cell: one value, or `base → head` when a changed pair
 * differs (explorer contract §2.4).
 *
 * @param {FindingDiff} diff
 * @returns {string}
 */
export function confidenceDisplay(diff) {
  const base = diff.base_occurrence;
  const head = diff.head_occurrence;
  if (base !== null && head !== null && base.confidence !== head.confidence) {
    return `${confidenceText(base.confidence)} → ${confidenceText(head.confidence)}`;
  }
  return confidenceText(referenceOccurrence(diff).confidence);
}

/**
 * The rule cell: `-` without a rule, or `base → head` when a changed pair
 * moved rules.
 *
 * @param {FindingDiff} diff
 * @returns {string}
 */
export function ruleDisplay(diff) {
  const base = diff.base_occurrence;
  const head = diff.head_occurrence;
  if (base !== null && head !== null && base.rule_id !== head.rule_id) {
    return `${base.rule_id ?? '-'} → ${head.rule_id ?? '-'}`;
  }
  const rule = referenceOccurrence(diff).rule_id;
  return rule === null ? '-' : rule;
}

/**
 * The location cell: `path:line`, with `base → head` line spans when a
 * changed pair moved.
 *
 * @param {FindingDiff} diff
 * @returns {string}
 */
export function locationDisplay(diff) {
  const base = diff.base_occurrence;
  const head = diff.head_occurrence;
  if (base !== null && head !== null && base.start_line !== head.start_line) {
    return `${diff.path}:${base.start_line} → ${head.start_line}`;
  }
  return `${diff.path}:${referenceOccurrence(diff).start_line}`;
}

/**
 * The message cell: the reference message, or `base → head` when a changed
 * pair reworded it.
 *
 * @param {FindingDiff} diff
 * @returns {string}
 */
export function messageDisplay(diff) {
  const base = diff.base_occurrence;
  const head = diff.head_occurrence;
  if (base !== null && head !== null && base.message !== head.message) {
    return `${base.message} → ${head.message}`;
  }
  return referenceOccurrence(diff).message;
}

/**
 * The diff class's reference-side occurrence: head for `new`, base for
 * `dropped` and `changed` (initial contract §12).
 *
 * @param {FindingDiff} diff
 * @returns {FindingOccurrence}
 */
export function referenceOccurrence(diff) {
  const occurrence = diff.diff_class === 'new' ? diff.head_occurrence : diff.base_occurrence;
  if (occurrence === null) {
    throw new Error(`diff for ${diff.identity} is missing its reference side`);
  }
  return occurrence;
}

/**
 * Reported span text such as `L119–123`.
 *
 * @param {FindingOccurrence} occurrence
 * @returns {string}
 */
export function spanDisplay(occurrence) {
  return occurrence.start_line === occurrence.end_line
    ? `L${occurrence.start_line}`
    : `L${occurrence.start_line}–${occurrence.end_line}`;
}

/**
 * `+N` / `-N` / `~N` totals line fragments for toolbars and group headers.
 *
 * @param {import('./types.js').DiffTotals} totals
 * @returns {{new: string, dropped: string, changed: string}}
 */
export function totalsDisplay(totals) {
  return { new: `+${totals.new}`, dropped: `-${totals.dropped}`, changed: `~${totals.changed}` };
}
