import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  DIFF_CLASS_PRESENTATION,
  confidenceDisplay,
  confidenceText,
  locationDisplay,
  messageDisplay,
  referenceOccurrence,
  ruleDisplay,
  spanDisplay,
  totalsDisplay,
} from '../../src/lib/format.js';

function occurrence(overrides = {}) {
  return {
    schema_version: '1.2.0',
    start_line: 10,
    end_line: 10,
    message: 'unused',
    confidence: 60,
    rule_id: 'SKY-U001',
    raw_excerpt: null,
    source_excerpt: null,
    ...overrides,
  };
}

function diff(overrides = {}) {
  return {
    schema_version: '1.2.0',
    diff_class: 'changed',
    identity: 'i',
    tool: 't',
    project: 'p',
    path: 'pkg/a.py',
    symbol: 's',
    kind: 'function',
    base_occurrence: occurrence(),
    head_occurrence: occurrence(),
    changed_fields: ['message'],
    locator: null,
    ...overrides,
  };
}

test('diff classes pair a stable glyph with text', () => {
  assert.deepEqual(DIFF_CLASS_PRESENTATION.new, { glyph: '+', label: 'New' });
  assert.deepEqual(DIFF_CLASS_PRESENTATION.dropped, { glyph: '-', label: 'Dropped' });
  assert.deepEqual(DIFF_CLASS_PRESENTATION.changed, { glyph: '~', label: 'Changed' });
});

test('confidence pairs show base and head instead of collapsing', () => {
  assert.equal(confidenceText(null), 'NA');
  assert.equal(confidenceText(0), '0%');
  assert.equal(confidenceDisplay(diff()), '60%');
  assert.equal(
    confidenceDisplay(diff({ head_occurrence: occurrence({ confidence: 90 }) })),
    '60% → 90%',
  );
  assert.equal(
    confidenceDisplay(diff({ base_occurrence: occurrence({ confidence: null }) })),
    'NA → 60%',
  );
  assert.equal(
    confidenceDisplay(diff({ head_occurrence: occurrence({ confidence: null }) })),
    '60% → NA',
  );
  assert.equal(
    confidenceDisplay(diff({ diff_class: 'new', base_occurrence: null, changed_fields: [] })),
    '60%',
  );
});

test('rule pairs and absent rules render without invention', () => {
  assert.equal(ruleDisplay(diff()), 'SKY-U001');
  assert.equal(ruleDisplay(diff({ head_occurrence: occurrence({ rule_id: 'SKY-U003' }) })), 'SKY-U001 → SKY-U003');
  assert.equal(ruleDisplay(diff({ base_occurrence: occurrence({ rule_id: null }) })), '- → SKY-U001');
  assert.equal(
    ruleDisplay(
      diff({
        diff_class: 'dropped',
        head_occurrence: null,
        base_occurrence: occurrence({ rule_id: null }),
        changed_fields: [],
      }),
    ),
    '-',
  );
});

test('location and message pair changed values', () => {
  assert.equal(locationDisplay(diff()), 'pkg/a.py:10');
  assert.equal(
    locationDisplay(diff({ head_occurrence: occurrence({ start_line: 20, end_line: 20 }) })),
    'pkg/a.py:10 → 20',
  );
  assert.equal(messageDisplay(diff()), 'unused');
  assert.equal(
    messageDisplay(diff({ head_occurrence: occurrence({ message: 'renamed' }) })),
    'unused → renamed',
  );
});

test('reference side follows the diff class', () => {
  const dropped = diff({
    diff_class: 'dropped',
    head_occurrence: null,
    base_occurrence: occurrence({ message: 'base side' }),
    changed_fields: [],
  });
  assert.equal(referenceOccurrence(dropped).message, 'base side');
  const fresh = diff({
    diff_class: 'new',
    base_occurrence: null,
    head_occurrence: occurrence({ message: 'head side' }),
    changed_fields: [],
  });
  assert.equal(referenceOccurrence(fresh).message, 'head side');
  assert.throws(
    () => referenceOccurrence(diff({ diff_class: 'new', base_occurrence: null, head_occurrence: null })),
    /reference side/u,
  );
});

test('span and totals fragments', () => {
  assert.equal(spanDisplay(occurrence()), 'L10');
  assert.equal(spanDisplay(occurrence({ end_line: 14 })), 'L10–14');
  assert.deepEqual(totalsDisplay({ new: 168, dropped: 0, changed: 3, changed_confidence: 1, changed_message_only: 1 }), {
    new: '+168',
    dropped: '-0',
    changed: '~3',
  });
});
