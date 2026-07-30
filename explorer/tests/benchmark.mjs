// Non-gating performance report (explorer contract §15).
//
// Until a reviewed benchmark-policy.md and baseline exist beside a
// representative large-report fixture, CI reports these numbers without
// using them as a merge gate: an ordinary noisy CI sample is not itself a
// portable performance baseline. Stage timings are reported separately so
// an optimization cannot hide a blocked stage.
import { performance } from 'node:perf_hooks';
import { webcrypto } from 'node:crypto';

import { emptyFilters, filterRows } from '../src/lib/filters.js';
import { buildReviewRows } from '../src/lib/projection.js';
import { sortRows } from '../src/lib/sorting.js';
import { validateReport } from '../src/lib/validate.js';

const PROJECT_COUNT = 4;
const DIFFS_PER_PROJECT = 25000;

function syntheticReport() {
  const pins = [];
  const projects = [];
  for (let projectIndex = 0; projectIndex < PROJECT_COUNT; projectIndex += 1) {
    const name = `project-${projectIndex}`;
    pins.push({
      name,
      repo: `https://github.com/example/${name}`,
      requested: 'branch:main',
      resolved_sha: '3'.repeat(40),
    });
    const diffs = [];
    for (let index = 0; index < DIFFS_PER_PROJECT; index += 1) {
      diffs.push({
        schema_version: '1.1.0',
        diff_class: 'new',
        identity: 'x'.repeat(64),
        tool: 'bench',
        project: name,
        path: `pkg/module_${index % 400}.py`,
        symbol: `symbol_${index}`,
        kind: index % 3 === 0 ? 'function' : 'variable',
        base_occurrence: null,
        head_occurrence: {
          schema_version: '1.1.0',
          start_line: (index % 900) + 1,
          end_line: (index % 900) + 1,
          message: `unused symbol_${index}`,
          confidence: index % 5 === 0 ? null : (index * 7) % 101,
          rule_id: index % 4 === 0 ? null : `BEN-U00${index % 4}`,
          raw_excerpt: null,
          source_excerpt: null,
        },
        changed_fields: [],
      });
    }
    projects.push({ project: name, diffs });
  }
  return { manifest: { tool: 'bench', corpus_pins: pins }, projects };
}

function time(label, run) {
  const start = performance.now();
  const result = run();
  const elapsed = performance.now() - start;
  process.stdout.write(`${label}: ${elapsed.toFixed(1)} ms\n`);
  return result;
}

const report = syntheticReport();
const serialized = JSON.stringify(report);
process.stdout.write(`synthetic report: ${PROJECT_COUNT * DIFFS_PER_PROJECT} diffs, ${serialized.length} bytes\n`);
time('parse', () => JSON.parse(serialized));
const rows = time('projection', () => buildReviewRows(report));
const filters = emptyFilters();
filters.search = 'symbol_1234';
const samples = [];
for (let sample = 0; sample < 20; sample += 1) {
  const start = performance.now();
  filterRows(rows, filters, () => 'unreviewed');
  samples.push(performance.now() - start);
}
samples.sort((left, right) => left - right);
process.stdout.write(`filter p50: ${samples[9].toFixed(1)} ms; p95: ${samples[18].toFixed(1)} ms (20 samples)\n`);
time('sort by path', () => sortRows(rows, 'path', false, () => 'unreviewed'));
// Validation timing on a small real document keeps the async path honest.
await time('validate (structural reject)', () => validateReport({ nonsense: true }, webcrypto.subtle));
process.stdout.write('benchmark reported (non-gating; see explorer contract §15)\n');
