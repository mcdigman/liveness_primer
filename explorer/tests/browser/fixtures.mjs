// Browser-test fixtures derived from the shared Python-generated locator
// golden fixture (explorer contract §17.1, §17.4).
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

export function goldenReport() {
  const fixture = JSON.parse(
    readFileSync(join(here, '..', '..', '..', 'tests', 'fixtures', 'locator_golden.json'), 'utf8'),
  );
  return fixture.report;
}

export function reportFile(report, name = 'report.json') {
  return { name, mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(report, null, 2)) };
}

/** Recompute one diff identity after mutating identity components. */
export function identityOf(diff) {
  const material = JSON.stringify([diff.tool, diff.project, diff.path, diff.symbol, diff.kind]);
  return createHash('sha256').update(material, 'utf8').digest('hex');
}

/**
 * A report carrying hostile values in fields that do not participate in
 * identity or diff classification, so it stays semantically valid while
 * exercising every injection sink (explorer contract §17.4).
 */
export function hostileReport() {
  const report = goldenReport();
  const fresh = report.projects[1].diffs[0];
  fresh.head_occurrence.message =
    '<img src=x onerror=alert(1)> <script>alert(2)</script> [x](javascript:alert(3)) ' +
    ']8;;https://evil.invalid\\osc8]8;;\\ [31mansi ' +
    '‮BIDI `fence` </textarea></pre>"};';
  fresh.head_occurrence.source_excerpt = {
    start_line: fresh.head_occurrence.start_line,
    lines: ['<style>*{display:none}</style> | pipe bell', '"></div><div id=escaped>'],
    omitted_lines: 0,
  };
  report.projects[1].source_warnings = ['<iframe src=https://evil.invalid></iframe> warning'];
  report.projects[1].errors = [
    { side: 'head', exit_code: 2, detail: '<svg onload=alert(4)> stderr {{template}} ${interpolation}' },
  ];
  return report;
}

export function truncatedReport() {
  const report = goldenReport();
  const alpha = report.projects[0];
  alpha.diffs = alpha.diffs.slice(0, 4);
  alpha.truncated = true;
  report.truncated = true;
  return report;
}
