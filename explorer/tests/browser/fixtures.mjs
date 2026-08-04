// Browser-suite fixtures (explorer contract §10). The primary report is
// the Python-generated locator golden fixture; the large and adversarial
// variants derive from producer-shaped data so structural validation
// accepts them.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/** @returns {{locators: object[], report: any}} */
export function loadGoldenFixture() {
  const path = join(here, '..', '..', '..', 'tests', 'fixtures', 'locator_golden.json');
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** @returns {any} */
export function goldenReport() {
  return structuredClone(loadGoldenFixture().report);
}

/** Total serialized diffs in the golden report. */
export function goldenRowCount() {
  const report = loadGoldenFixture().report;
  return report.projects.reduce((sum, project) => sum + project.diffs.length, 0);
}

const SCHEMA_VERSION = '1.2.0';

/**
 * @param {number} index
 * @returns {string} deterministic fake 64-hex identity
 */
function identityOf(index) {
  return index.toString(16).padStart(64, '0');
}

/**
 * A large managed-run report for responsiveness and layout tests.
 *
 * @param {number} perProject findings per project
 * @param {number} projectCount
 * @returns {any}
 */
export function largeReport(perProject = 1500, projectCount = 3) {
  const projects = [];
  const pins = [];
  for (let projectIndex = 0; projectIndex < projectCount; projectIndex += 1) {
    const name = `project-${projectIndex}`;
    pins.push({
      name,
      repo: `https://github.com/example/${name}`,
      requested: 'branch:main',
      resolved_sha: 'a'.repeat(40),
    });
    const diffs = [];
    for (let index = 0; index < perProject; index += 1) {
      const line = index + 1;
      const identity = identityOf(projectIndex * perProject + index);
      diffs.push({
        schema_version: SCHEMA_VERSION,
        diff_class: 'new',
        identity,
        tool: 'skylos',
        project: name,
        path: `pkg/module_${index % 40}.py`,
        symbol: `unused_symbol_${index}`,
        kind: 'function',
        base_occurrence: null,
        head_occurrence: {
          schema_version: SCHEMA_VERSION,
          start_line: line,
          end_line: line,
          message: `Unused function 'unused_symbol_${index}'`,
          confidence: 60 + (index % 41),
          rule_id: `SKY-U00${(index % 4) + 1}`,
          raw_excerpt: null,
          source_excerpt:
            index % 7 === 0
              ? {
                  start_line: line,
                  lines: [`def unused_symbol_${index}():`, '    return None'],
                  omitted_lines: 0,
                }
              : null,
        },
        changed_fields: [],
        locator: { project: name, identity, line, occurrence: 0 },
      });
    }
    const rollups = [1, 2, 3, 4].map((rule) => ({
      diff_class: 'new',
      rule_id: `SKY-U00${rule}`,
      kind: null,
      count: diffs.filter((diff) => diff.head_occurrence.rule_id === `SKY-U00${rule}`).length,
    }));
    projects.push({
      project: name,
      diffs,
      totals: { new: perProject, dropped: 0, changed: 0, changed_confidence: 0, changed_message_only: 0 },
      rollups,
      truncated: false,
      base_findings: 0,
      head_findings: perProject,
      measured_cost_seconds: 12.5,
      errors: [],
      integrity_warnings: [],
      source_warnings: [],
    });
  }
  const environment = {
    ref: 'v4.31.0',
    sha: 'b'.repeat(40),
    fingerprint: 'fingerprint',
    freeze: ['skylos==4.31.0'],
    from_cache: true,
    rebuilt: false,
  };
  return {
    schema_version: SCHEMA_VERSION,
    manifest: {
      schema_version: SCHEMA_VERSION,
      created_at: '2026-08-01T12:00:00Z',
      tool: 'skylos',
      detector_repo: 'https://github.com/codex-skylos/skylos',
      base: environment,
      head: { ...environment, ref: 'v4.31.1', sha: 'c'.repeat(40) },
      base_cmd: null,
      head_cmd: null,
      comparable: true,
      environment_delta: [],
      isolation_enforced: true,
      platform: 'linux-x86_64',
      python_version: '3.14.0',
      installer: 'uv 0.6.0',
      fetches: [],
      corpus_pins: pins,
      settings: {
        jobs: 4,
        timeout: 120,
        max_results: 100000,
        excerpt_lines: 2,
        fail_on: [],
        selection: pins.map((pin) => pin.name),
      },
    },
    projects,
    totals: {
      new: perProject * projectCount,
      dropped: 0,
      changed: 0,
      changed_confidence: 0,
      changed_message_only: 0,
    },
    rollups: [1, 2, 3, 4].map((rule) => ({
      diff_class: 'new',
      rule_id: `SKY-U00${rule}`,
      kind: null,
      count: projects.reduce(
        (sum, project) =>
          sum + project.rollups.find((rollup) => rollup.rule_id === `SKY-U00${rule}`).count,
        0,
      ),
    })),
    truncated: false,
  };
}

export const HOSTILE_MESSAGE = '<img src=x onerror="alert(1)"><script>alert(2)</script>[x](javascript:alert(3))';
export const HOSTILE_SYMBOL = '</td><style>*{display:none}</style>';

/**
 * The golden report with hostile detector-derived strings injected.
 *
 * @returns {any}
 */
export function adversarialReport() {
  const report = goldenReport();
  const diff = report.projects[0].diffs[0];
  const side = diff.diff_class === 'new' ? 'head_occurrence' : 'base_occurrence';
  diff[side].message = HOSTILE_MESSAGE;
  diff.symbol = HOSTILE_SYMBOL;
  // A hostile repository string must not fabricate a source URL.
  report.manifest.corpus_pins[0].repo = 'javascript:alert(4)';
  return report;
}

/**
 * Open a report payload through the file input.
 *
 * @param {import('@playwright/test').Page} page
 * @param {string} text report bytes
 * @param {string} [name]
 */
export async function openReport(page, text, name = 'report.json') {
  await page
    .locator('input[type="file"]')
    .first()
    .setInputFiles({ name, mimeType: 'application/json', buffer: Buffer.from(text, 'utf8') });
}

/**
 * Open a report and wait for the findings grid to render rows.
 *
 * @param {import('@playwright/test').Page} page
 * @param {any} report
 * @param {string} [name]
 */
export async function openReportAndWait(page, report, name = 'report.json') {
  await openReport(page, JSON.stringify(report), name);
  await page.locator('.tabulator-row').first().waitFor({ state: 'visible', timeout: 30_000 });
}
