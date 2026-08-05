import assert from 'node:assert/strict';
import { test } from 'node:test';

import { escapeMarkdown, markdownFilename, renderMarkdown } from '../../src/lib/markdown.js';
import { projectReport } from '../../src/lib/projection.js';
import { goldenReport } from './helpers.mjs';

const DIGEST = 'ab'.repeat(32);

/** @param {object} report */
function selectedExport(report, count = 4) {
  const projection = projectReport(report);
  const selectedRows = projection.rows.slice(0, count);
  const text = renderMarkdown({
    filename: 'skylos-4.31.0-vs-4.31.1.json',
    digest: DIGEST,
    projection,
    selectedRows,
  });
  return { projection, selectedRows, text };
}

test('escapeMarkdown neutralizes structure, links, HTML, and control characters', () => {
  assert.equal(escapeMarkdown('plain words'), 'plain words');
  assert.equal(
    escapeMarkdown('[label](https://evil.example)'),
    '\\[label\\]\\(https\\:\\/\\/evil\\.example\\)',
  );
  assert.equal(escapeMarkdown('`code` *em* _u_ # h | cell'), '\\`code\\` \\*em\\* \\_u\\_ \\# h \\| cell');
  assert.equal(escapeMarkdown('<script>alert(1)</script>'), '\\<script\\>alert\\(1\\)\\<\\/script\\>');
  assert.equal(escapeMarkdown('line\nbreak\u0007bell'), 'line�break�bell');
  assert.equal(escapeMarkdown('tab\there'), 'tab here');
});

test('the export states count, digest, revisions, safety state, and project counts', () => {
  const { text, selectedRows } = selectedExport(goldenReport());
  assert.match(text, /^# liveness primer review export$/mu);
  assert.match(text, new RegExp(`report sha256: \`${DIGEST}\``, 'u'));
  assert.match(text, /detector: faketool, base command\\: old\\-faketool → head command\\: new\\-faketool/u);
  assert.match(text, /comparison: \*\*environments may differ\*\*/u);
  assert.match(text, /sandboxing was enforced; findings complete/u);
  assert.match(
    text,
    /run health: detector errors 0, unexpected baseline findings 0, source excerpt warnings 0, dependency differences 0/u,
  );
  assert.match(text, new RegExp(`selected findings: ${selectedRows.length} across 1 project\\b`, 'u'));
  assert.match(text, /## alpha @ 33333333 — \d+ selected/u);
});

test('a clean comparable run states so plainly', () => {
  const report = goldenReport();
  report.manifest.comparable = true;
  const { text } = selectedExport(report, 1);
  assert.match(
    text,
    /comparison: base and head ran in matching managed environments; sandboxing was enforced; findings complete/u,
  );
  assert.match(text, /selected findings: 1 across 1 project\b/u);
});

test('safety flags surface truncation and isolation failures', () => {
  const report = goldenReport();
  report.truncated = true;
  report.projects[0].truncated = true;
  report.manifest.isolation_enforced = false;
  const { text } = selectedExport(report);
  assert.match(text, /\*\*sandboxing was not enforced\*\*/u);
  assert.match(text, /findings \*\*incomplete\*\*: the results cap left findings out of alpha/u);
});

test('an export document states its subset nature instead of claiming a results cap', () => {
  const report = goldenReport();
  report.document_kind = 'explorer-export';
  report.truncated = true;
  report.projects[0].truncated = true;
  const { text } = selectedExport(report);
  assert.match(
    text,
    /findings are \*\*an export subset\*\*: findings are missing from alpha \(unselected at export, cut by the original run's results cap, or both\)/u,
  );
});

test('pinned source links appear only for GitHub-pinned projects and only as built URLs', () => {
  const projection = projectReport(goldenReport());
  const alphaRow = projection.rows.find((row) => row.project === 'alpha');
  const betaRow = projection.rows.find((row) => row.project === 'beta');
  const text = renderMarkdown({
    filename: 'r.json',
    digest: DIGEST,
    projection,
    selectedRows: [alphaRow, betaRow],
  });
  assert.match(
    text,
    /\[pinned source\]\(https:\/\/github\.com\/example\/alpha\/blob\/3{40}\/pkg\/a\.py#L\d+\)/u,
  );
  const betaSection = text.slice(text.indexOf('## beta'));
  assert.ok(!betaSection.includes('pinned source'), betaSection);
  assert.match(text, /selected findings: 2 across 2 projects/u);
});

test('hostile report strings cannot create Markdown structure or link targets', () => {
  const report = goldenReport();
  const diff = report.projects[0].diffs[0];
  const side = diff.diff_class === 'new' ? 'head_occurrence' : 'base_occurrence';
  diff[side].message = '[click me](javascript:alert(1)) <b>bold</b>\n# fake heading';
  diff.symbol = '`](javascript:x)`';
  const projection = projectReport(report);
  const row = projection.rows[0];
  const text = renderMarkdown({ filename: 'r.json', digest: DIGEST, projection, selectedRows: [row] });
  assert.ok(!text.includes('](javascript:'), text);
  assert.ok(!text.includes('\n# fake heading'), text);
  assert.ok(!text.includes('<b>'), text);
});

test('the markdown filename derives from the digest', () => {
  assert.equal(markdownFilename(DIGEST), `liveness-primer-review-${DIGEST.slice(0, 12)}.md`);
});
