// Markdown export of the selected findings (explorer contract §6).
//
// Untrusted report values are escaped as text at the Markdown structural
// boundary: they cannot create Markdown structure or link targets. The
// only link targets are permalinks constructed from schema-validated pin
// fields, never from report-supplied URLs.

import { abbreviatedSha } from './digest.js';
import { DIFF_CLASS_PRESENTATION } from './format.js';
import { rowSourceUrl } from './projection.js';

/** @typedef {import('./projection.js').Projection} Projection */
/** @typedef {import('./projection.js').FindingRow} FindingRow */

// Backslash-escape every ASCII punctuation character CommonMark honors,
// so untrusted text stays inline text wherever it lands.
const MARKDOWN_PUNCTUATION = /[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/gu;
const CONTROL = /[\u0000-\u0008\u000A-\u001F\u007F-\u009F]/gu;

/**
 * @param {string} text untrusted report-derived text
 * @returns {string} inline-safe Markdown text
 */
export function escapeMarkdown(text) {
  return text
    .replace(CONTROL, '�')
    .replace(/\t/gu, ' ')
    .replace(MARKDOWN_PUNCTUATION, (character) => `\\${character}`);
}

/**
 * @param {Projection} projection
 * @returns {string[]} comparison safety and completeness lines (§3)
 */
function statusLines(projection) {
  const status = projection.status;
  const comparison = status.comparable
    ? 'base and head ran in matching managed environments'
    : '**environments may differ** (a side ran with a custom command), so differences may not come from the detector alone';
  const sandbox = status.isolationEnforced
    ? 'sandboxing was enforced'
    : '**sandboxing was not enforced**, so analyzed projects could have influenced the run';
  const projectList = status.truncatedProjects.map(escapeMarkdown).join(', ');
  const completeness = !status.truncated
    ? 'findings complete'
    : status.isExport
      ? `findings are **a chosen subset**: this export omits unselected findings of ${projectList}; totals still describe the complete run`
      : `findings **incomplete**: the results cap left findings out of ${projectList}; totals still count the complete run`;
  const counts = [
    `detector errors ${status.errorCount}`,
    `unexpected baseline findings ${status.integrityWarningCount}`,
    `source excerpt warnings ${status.sourceWarningCount}`,
    `dependency differences ${status.environmentDelta.length}`,
  ];
  return [`- comparison: ${comparison}; ${sandbox}; ${completeness}`, `- run health: ${counts.join(', ')}`];
}

/**
 * Render the selected findings as a portable Markdown review document.
 *
 * @param {object} input
 * @param {string} input.filename imported report filename
 * @param {string} input.digest report SHA-256
 * @param {Projection} input.projection
 * @param {FindingRow[]} input.selectedRows in serialized report order
 * @returns {string}
 */
export function renderMarkdown({ filename, digest, projection, selectedRows }) {
  /** @type {Map<string, FindingRow[]>} */
  const byProject = new Map();
  for (const row of selectedRows) {
    const rows = byProject.get(row.project);
    if (rows === undefined) {
      byProject.set(row.project, [row]);
    } else {
      rows.push(row);
    }
  }
  const lines = [
    '# liveness primer review export',
    '',
    `- report: ${escapeMarkdown(filename)}`,
    `- report sha256: \`${digest}\``,
    `- detector: ${escapeMarkdown(projection.report.manifest.tool)}, ${escapeMarkdown(
      projection.revisions.base,
    )} → ${escapeMarkdown(projection.revisions.head)}`,
    ...statusLines(projection),
    `- selected findings: ${selectedRows.length} across ${byProject.size} project${byProject.size === 1 ? '' : 's'}`,
    '',
  ];
  for (const [project, rows] of byProject.entries()) {
    const view = projection.projectsByName.get(project);
    const pinSuffix =
      view !== undefined && view.pin !== null ? ` @ ${abbreviatedSha(view.pin.resolved_sha)}` : '';
    lines.push(`## ${escapeMarkdown(project)}${pinSuffix} — ${rows.length} selected`, '');
    for (const row of rows) {
      const presentation = DIFF_CLASS_PRESENTATION[row.diffClass];
      const parts = [
        `\`${presentation.glyph}\` ${presentation.label}`,
        escapeMarkdown(row.rule),
        escapeMarkdown(row.confidence),
        escapeMarkdown(row.kind),
        escapeMarkdown(row.location),
      ];
      const url = rowSourceUrl(row);
      if (url !== null) {
        parts.push(`[pinned source](${url})`);
      }
      lines.push(`- ${parts.join(' · ')}`);
      lines.push(`  - message: ${escapeMarkdown(row.message)}`);
      if (row.symbol !== null) {
        lines.push(`  - symbol: ${escapeMarkdown(row.symbol)}`);
      }
    }
    lines.push('');
  }
  return `${lines.join('\n')}`;
}

/**
 * Suggested download filename for the Markdown export.
 *
 * @param {string} digest
 * @returns {string}
 */
export function markdownFilename(digest) {
  return `liveness-primer-review-${digest.slice(0, 12)}.md`;
}
