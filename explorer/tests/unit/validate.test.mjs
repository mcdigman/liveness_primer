// Report validation tests: schema acceptance/rejection plus every
// supplemental semantic invariant of explorer contract §5.3.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DIFF_LIMIT,
  computeIdentity,
  computeRollups,
  computedChangedFields,
  validateReport,
  validateReportSemantics,
  validateReportStructure,
} from '../../src/lib/validate.js';
import { validateAgainstSchema } from '../../src/lib/jsonschema.js';
import { fixtureReport, subtle } from './helpers.mjs';

async function expectSemanticError(mutate, fragment) {
  const report = fixtureReport();
  mutate(report);
  const structural = validateReportStructure(report);
  assert.equal(structural.length, 0, JSON.stringify(structural.slice(0, 3)));
  const errors = await validateReportSemantics(report, subtle);
  assert.ok(
    errors.some((error) => error.message.includes(fragment)),
    `expected ${JSON.stringify(fragment)} in ${JSON.stringify(errors.slice(0, 5))}`,
  );
}

test('the checked-in fixture report passes both layers', async () => {
  const outcome = await validateReport(fixtureReport(), subtle);
  assert.equal(outcome.ok, true);
  assert.deepEqual(outcome.errors, []);
  assert.notEqual(outcome.report, null);
});

test('malformed and structurally invalid documents are rejected', () => {
  assert.ok(validateReportStructure(null).length > 0);
  assert.ok(validateReportStructure([]).length > 0);
  assert.ok(validateReportStructure({}).length > 0);
  const report = fixtureReport();
  delete report.manifest;
  assert.ok(validateReportStructure(report).some((error) => error.message.includes('manifest')));
});

test('unknown fields are rejected by the structural layer', () => {
  const report = fixtureReport();
  report.surprise = 1;
  assert.ok(validateReportStructure(report).some((error) => error.message.includes('unknown field')));
});

test('an unsupported schema version is rejected', () => {
  const report = fixtureReport();
  report.schema_version = '9.0.0';
  assert.ok(validateReportStructure(report).length > 0);
});

test('scalar bounds are enforced structurally', () => {
  // Occurrences are nullable (anyOf), so a bound violation inside one
  // surfaces as the alternative mismatch at the occurrence path.
  const negativeConfidence = fixtureReport();
  negativeConfidence.projects[1].diffs[0].head_occurrence.confidence = -1;
  assert.ok(
    validateReportStructure(negativeConfidence).some((error) =>
      error.path.includes('head_occurrence'),
    ),
  );
  const zeroLine = fixtureReport();
  zeroLine.projects[1].diffs[0].head_occurrence.start_line = 0;
  assert.ok(validateReportStructure(zeroLine).length > 0);
  const badCount = fixtureReport();
  badCount.projects[1].rollups[0].count = 0;
  assert.ok(validateReportStructure(badCount).some((error) => error.message.includes('minimum')));
});

test('semantic: inverted spans are rejected', async () => {
  await expectSemanticError((report) => {
    const occurrence = report.projects[1].diffs[0].head_occurrence;
    occurrence.start_line = 9;
    occurrence.end_line = 3;
  }, 'end_line precedes start_line');
});

test('semantic: sides must match the diff class', async () => {
  await expectSemanticError((report) => {
    report.projects[1].diffs[0].base_occurrence = report.projects[1].diffs[0].head_occurrence;
  }, 'populated sides contradict diff class');
  await expectSemanticError((report) => {
    const diff = report.projects[1].diffs[0];
    diff.diff_class = 'dropped';
    report.projects[1].totals = { ...report.projects[1].totals, new: 0, dropped: 1 };
    report.totals = { ...report.totals, new: report.totals.new - 1, dropped: report.totals.dropped + 1 };
  }, 'populated sides contradict diff class');
});

test('semantic: changed_fields must equal the changed observable fields', async () => {
  await expectSemanticError((report) => {
    const changed = report.projects[0].diffs.find((diff) => diff.diff_class === 'changed');
    changed.changed_fields = ['message'];
  }, 'changed_fields do not equal');
  await expectSemanticError((report) => {
    const fresh = report.projects[1].diffs[0];
    fresh.changed_fields = ['message'];
  }, 'changed_fields must be empty');
});

test('semantic: identity must be the digest of its components', async () => {
  await expectSemanticError((report) => {
    report.projects[1].diffs[0].identity = 'f'.repeat(64);
  }, 'identity is not the digest');
});

test('semantic: source evidence must agree with its occurrence', async () => {
  const budgeted = (mutate) => (report) => {
    const occurrence = report.projects[1].diffs[0].head_occurrence;
    occurrence.source_excerpt = { start_line: occurrence.start_line, lines: ['x'], omitted_lines: 0 };
    mutate(occurrence);
  };
  await expectSemanticError(
    budgeted((occurrence) => {
      occurrence.source_excerpt.start_line += 1;
    }),
    'does not begin at the reported start line',
  );
  await expectSemanticError(
    budgeted((occurrence) => {
      occurrence.source_excerpt.lines = ['a', 'b', 'c'];
    }),
    'exceeds the evidence budget',
  );
  await expectSemanticError(
    budgeted((occurrence) => {
      occurrence.source_excerpt.omitted_lines = 3;
    }),
    'omitted-span count contradicts',
  );
  await expectSemanticError(
    budgeted((occurrence) => {
      occurrence.end_line = occurrence.start_line + 5;
      occurrence.source_excerpt.omitted_lines = 4;
    }),
    'budget was not exhausted',
  );
  await expectSemanticError((report) => {
    report.manifest.settings = { ...report.manifest.settings, excerpt_lines: 0 };
    const occurrence = report.projects[1].diffs[0].head_occurrence;
    occurrence.source_excerpt = { start_line: occurrence.start_line, lines: ['x'], omitted_lines: 0 };
  }, 'evidence budget is zero');
});

test('semantic: duplicate pins, projects, and broken joins are rejected', async () => {
  await expectSemanticError((report) => {
    report.manifest.corpus_pins = [...report.manifest.corpus_pins, report.manifest.corpus_pins[0]];
  }, 'duplicate corpus-pin names');
  await expectSemanticError((report) => {
    report.projects = [report.projects[0], report.projects[0]];
  }, 'duplicate project-report names');
  await expectSemanticError((report) => {
    report.manifest.corpus_pins = [report.manifest.corpus_pins[0]];
  }, 'does not join exactly one corpus pin');
  await expectSemanticError((report) => {
    report.projects[1].diffs[0].project = 'alpha';
  }, 'diff project contradicts');
  await expectSemanticError((report) => {
    report.projects[1].diffs[0].tool = 'othertool';
  }, 'diff tool contradicts');
  await expectSemanticError((report) => {
    report.manifest.settings = { ...report.manifest.settings, selection: ['beta', 'alpha'] };
  }, 'do not describe the same run');
});

test('semantic: totals, rollups, and truncation must agree', async () => {
  await expectSemanticError((report) => {
    report.projects[1].totals = { ...report.projects[1].totals, new: 5 };
    report.totals = { ...report.totals, new: report.totals.new + 4 };
  }, 'totals contradict the serialized findings');
  await expectSemanticError((report) => {
    report.totals = { ...report.totals, dropped: report.totals.dropped + 1 };
  }, 'overall totals contradict');
  await expectSemanticError((report) => {
    report.projects[0].rollups = [...report.projects[0].rollups].reverse();
  }, 'not deterministically ordered');
  await expectSemanticError((report) => {
    const rollups = report.projects[1].rollups;
    rollups[0] = { ...rollups[0], count: 1, kind: 'mystery' , rule_id: null};
  }, 'rollups contradict the serialized findings');
  await expectSemanticError((report) => {
    report.rollups = [];
  }, 'ordered sum of the project rollups');
  await expectSemanticError((report) => {
    report.truncated = true;
  }, 'overall truncation state contradicts');
  await expectSemanticError((report) => {
    report.projects[1].truncated = true;
    report.truncated = true;
  }, 'truncation is claimed but every diff is present');
});

test('semantic: a truncated project may not display more than its totals', async () => {
  await expectSemanticError((report) => {
    report.projects[1].truncated = true;
    report.truncated = true;
    report.projects[1].totals = { ...report.projects[1].totals, new: 0 };
    report.totals = { ...report.totals, new: report.totals.new - 1 };
  }, 'displayed new count exceeds');
});

test('semantic: the finding-diff cap is enforced', async () => {
  const report = fixtureReport();
  const template = report.projects[1].diffs[0];
  const many = [];
  for (let index = 0; index < 8; index += 1) {
    many.push(structuredClone(template));
  }
  report.projects[1].diffs = many;
  const errors = await validateReportSemantics(report, subtle);
  assert.ok(errors.length > 0);
  const limited = await validateReportSemantics(report, subtle);
  assert.ok(limited.every((error) => typeof error.path === 'string'));
  assert.ok(DIFF_LIMIT >= 100000);
});

test('computedChangedFields reports each observable field', () => {
  const base = {
    start_line: 1,
    end_line: 1,
    message: 'm',
    confidence: 10,
    rule_id: 'A',
    raw_excerpt: null,
    source_excerpt: null,
    schema_version: '1.1.0',
  };
  const head = { ...base, end_line: 2, message: 'n', confidence: null, rule_id: null };
  assert.deepEqual(computedChangedFields(base, head), ['line-span', 'message', 'confidence', 'rule']);
  assert.deepEqual(computedChangedFields(base, { ...base }), []);
});

test('computeRollups groups by rule with kind fallback and orders deterministically', () => {
  const occurrence = (ruleId) => ({
    start_line: 1,
    end_line: 1,
    message: 'm',
    confidence: null,
    rule_id: ruleId,
    raw_excerpt: null,
    source_excerpt: null,
    schema_version: '1.1.0',
  });
  const diff = (klass, ruleId, kind) => ({
    diff_class: klass,
    identity: 'x'.repeat(64),
    tool: 't',
    project: 'p',
    path: 'a.py',
    symbol: null,
    kind,
    base_occurrence: klass === 'new' ? null : occurrence(ruleId),
    head_occurrence: klass === 'dropped' ? null : occurrence(ruleId),
    changed_fields: [],
    schema_version: '1.1.0',
  });
  const rollups = computeRollups([
    diff('new', 'R2', 'function'),
    diff('new', 'R1', 'function'),
    diff('new', 'R1', 'function'),
    diff('new', null, 'variable'),
    diff('dropped', null, 'variable'),
  ]);
  assert.deepEqual(rollups, [
    { diff_class: 'new', rule_id: 'R1', kind: null, count: 2 },
    { diff_class: 'new', rule_id: 'R2', kind: null, count: 1 },
    { diff_class: 'new', rule_id: null, kind: 'variable', count: 1 },
    { diff_class: 'dropped', rule_id: null, kind: 'variable', count: 1 },
  ]);
});

test('computeIdentity matches the Python identity for known values', async () => {
  const report = fixtureReport();
  const diff = report.projects[1].diffs[0];
  assert.equal(await computeIdentity(diff, subtle), diff.identity);
});

test('validateReport rejects with bounded errors and no report on failure', async () => {
  const outcome = await validateReport({ nonsense: true }, subtle);
  assert.equal(outcome.ok, false);
  assert.equal(outcome.report, null);
  assert.ok(outcome.errors.length > 0);
  const semanticFailure = fixtureReport();
  semanticFailure.projects[1].diffs[0].identity = 'f'.repeat(64);
  const semanticOutcome = await validateReport(semanticFailure, subtle);
  assert.equal(semanticOutcome.ok, false);
  assert.equal(semanticOutcome.report, null);
});

test('semantic errors are capped at the reporting bound', async () => {
  const report = fixtureReport();
  const template = structuredClone(report.projects[1].diffs[0]);
  const many = [];
  for (let index = 0; index < 60; index += 1) {
    const clone = structuredClone(template);
    clone.symbol = `bogus_${index}`;
    // Identity no longer matches the mutated symbol: one error per diff.
    many.push(clone);
  }
  report.projects[1].diffs = many;
  report.projects[1].totals = { ...report.projects[1].totals, new: 60 };
  report.totals = { ...report.totals, new: report.totals.new + 59 };
  const errors = await validateReportSemantics(report, subtle);
  assert.equal(errors.length, 50);
});

test('unknown schema types are reported, not silently accepted', () => {
  const errors = validateAgainstSchema({ type: 'unicorn' }, 'anything');
  assert.ok(errors.some((error) => error.message.includes('unicorn')));
});

test('a report beyond the finding-diff limit fails promptly', async () => {
  const report = fixtureReport();
  const template = report.projects[1].diffs[0];
  report.projects[1].diffs = Array.from({ length: 100001 }, () => template);
  const errors = await validateReportSemantics(report, subtle);
  assert.equal(errors.length, 1);
  assert.ok(errors[0].message.includes('more than 100000'));
});

test('duplicated rollup groups are contradictions, not reorderings', async () => {
  const report = fixtureReport();
  report.projects[1].rollups = [...report.projects[1].rollups, ...report.projects[1].rollups];
  const errors = await validateReportSemantics(report, subtle);
  assert.ok(errors.some((error) => error.message.includes('rollups contradict')));
});
