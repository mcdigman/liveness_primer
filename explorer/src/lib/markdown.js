// Markdown review-summary export (explorer contract §11.3).
//
// All untrusted text is escaped for Markdown structure, control
// characters are removed or visibly replaced, and generated links use
// only validated pinned permalinks. A note cannot create a heading, list
// item, link destination, HTML block, or fenced block outside its
// assigned quoted text.

import { confidenceText, rowSpanText } from './projection.js';
import { dispositionOf } from './review.js';

const FIELD_CAP = 300;

/**
 * Replace non-printable characters with spaces and cap the length.
 *
 * @param {string} text Untrusted text.
 * @param {number} cap Maximum retained characters.
 * @returns {string} Control-free bounded text.
 */
function cleaned(text, cap) {
  /** @type {string[]} */
  const kept = [];
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    const isControl =
      code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029 || /\p{Cf}/u.test(ch);
    kept.push(isControl ? ' ' : ch);
  }
  const joined = kept.join('');
  if (joined.length <= cap) return joined;
  return `${joined.slice(0, cap)}...(+${joined.length - cap})`;
}

/**
 * Escape untrusted text for inline Markdown use.
 *
 * @param {string} text Untrusted text.
 * @returns {string} Escaped text.
 */
export function escapeMarkdown(text) {
  let escaped = cleaned(text, FIELD_CAP).replaceAll('\\', '\\\\');
  for (const meta of ['|', '`', '<', '>', '[', ']', '*', '_', '#', '~']) {
    escaped = escaped.replaceAll(meta, `\\${meta}`);
  }
  return escaped;
}

/**
 * @param {import('./projection.js').ReviewRow} row
 * @returns {string}
 */
function locationText(row) {
  const label = `${row.path}:${rowSpanText(row)}`;
  const url = row.diffClass === 'new' ? row.headSourcePermalink : row.baseSourcePermalink;
  if (url === null) {
    return escapeMarkdown(label);
  }
  return `[${escapeMarkdown(label)}](${url})`;
}

const CLASS_GLYPHS = { new: '+', dropped: '-', changed: '~' };

/**
 * @param {import('./projection.js').ReviewRow} row
 * @param {import('./review.js').ReviewState} state
 * @returns {string[]}
 */
function findingLines(row, state) {
  const glyph = CLASS_GLYPHS[row.diffClass];
  const ruleOrKind = row.ruleId === null ? `kind:${escapeMarkdown(row.kind)}` : escapeMarkdown(row.ruleId);
  const parts = [
    `- \\${glyph} ${row.diffClass}`,
    `\`${escapeMarkdown(row.project)}\``,
    ruleOrKind,
    locationText(row),
    escapeMarkdown(row.reference.message),
  ];
  if (row.symbol !== null) {
    parts.push(escapeMarkdown(row.symbol));
  }
  parts.push(`(${confidenceText(row)})`);
  const lines = [parts.join(' — ')];
  const note = state.notes.get(row.locatorKey);
  if (note !== undefined && note !== '') {
    lines.push(`  > ${escapeMarkdown(note)}`);
  }
  return lines;
}

/**
 * @typedef {{ generatedAt: string, reportSha256: string, reportSchemaVersion: string,
 *   detectorRepo: string | null, baseSha: string | null, headSha: string | null,
 *   comparable: boolean, isolationEnforced: boolean, errorCount: number,
 *   warningCount: number, truncated: boolean, selectionCount: number | null }} SummaryMeta
 */

/**
 * Build the Markdown review summary (explorer contract §11.3).
 *
 * The default summary covers all reviewed findings independent of active
 * filters; unexpected findings appear before expected findings, each in
 * canonical report order.
 *
 * @param {import('./projection.js').ReviewRow[]} rows Rows in canonical order
 *   (all displayed rows, or an explicit selection).
 * @param {import('./review.js').ReviewState} state Review state.
 * @param {SummaryMeta} meta Report metadata.
 * @returns {string} The Markdown summary, newline-terminated.
 */
export function buildMarkdownSummary(rows, state, meta) {
  const unexpected = rows.filter((row) => dispositionOf(state, row.locatorKey) === 'unexpected');
  const expected = rows.filter((row) => dispositionOf(state, row.locatorKey) === 'expected');
  const unreviewed = rows.length - unexpected.length - expected.length;
  const lines = [
    '# liveness primer review summary',
    '',
    `- **generated**: ${meta.generatedAt}`,
    `- **report digest**: \`${meta.reportSha256}\` (schema ${escapeMarkdown(meta.reportSchemaVersion)})`,
  ];
  if (meta.detectorRepo !== null) {
    lines.push(`- **detector**: ${escapeMarkdown(meta.detectorRepo)}`);
  }
  if (meta.baseSha !== null && meta.headSha !== null) {
    lines.push(`- **base**: \`${escapeMarkdown(meta.baseSha)}\`; **head**: \`${escapeMarkdown(meta.headSha)}\``);
  }
  lines.push(
    `- **comparable**: ${meta.comparable ? 'yes' : 'no'}; **isolation**: ${meta.isolationEnforced ? 'enforced' : 'NOT ENFORCED'}`,
    `- **errors**: ${meta.errorCount}; **warnings**: ${meta.warningCount}; **truncated**: ${meta.truncated ? 'yes' : 'no'}`,
    `- **reviewed**: ${unexpected.length} unexpected, ${expected.length} expected, ${unreviewed} unreviewed displayed finding(s)`,
  );
  if (meta.truncated) {
    lines.push(
      '',
      '> **Incomplete finding detail**: this report was truncated; the review covers displayed findings only, not the complete blast radius.',
    );
  }
  if (meta.selectionCount !== null) {
    lines.push('', `> **Partial summary**: covers ${meta.selectionCount} explicitly selected finding(s).`);
  }
  lines.push('', '## Unexpected', '');
  if (unexpected.length === 0) {
    lines.push('(none)');
  }
  for (const row of unexpected) {
    lines.push(...findingLines(row, state));
  }
  lines.push('', '## Expected', '');
  if (expected.length === 0) {
    lines.push('(none)');
  }
  for (const row of expected) {
    lines.push(...findingLines(row, state));
  }
  lines.push('', `${unreviewed} displayed finding(s) remain unreviewed.`);
  return `${lines.join('\n')}\n`;
}
