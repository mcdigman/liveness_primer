// Structural validator tests: the keyword subset the exported schemas use
// (explorer contract §5.3, layer 1).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MAX_SCHEMA_ERRORS, validateAgainstSchema } from '../../src/lib/jsonschema.js';
import { sha256Hex, abbreviateDigest } from '../../src/lib/digest.js';
import { subtle } from './helpers.mjs';

test('types, bounds, and lengths are enforced', () => {
  const schema = {
    type: 'object',
    additionalProperties: false,
    required: ['count', 'name'],
    properties: {
      count: { type: 'integer', minimum: 1, maximum: 10 },
      ratio: { type: 'number' },
      name: { type: 'string', minLength: 1, maxLength: 4 },
      flag: { type: 'boolean' },
      nothing: { type: 'null' },
    },
  };
  assert.deepEqual(validateAgainstSchema(schema, { count: 3, name: 'ok' }), []);
  assert.ok(validateAgainstSchema(schema, { count: 0, name: 'ok' }).some((e) => e.message.includes('minimum')));
  assert.ok(validateAgainstSchema(schema, { count: 11, name: 'ok' }).some((e) => e.message.includes('maximum')));
  assert.ok(validateAgainstSchema(schema, { count: 1.5, name: 'ok' }).some((e) => e.message.includes('integer')));
  assert.ok(validateAgainstSchema(schema, { count: 3, name: '' }).some((e) => e.message.includes('shorter')));
  assert.ok(validateAgainstSchema(schema, { count: 3, name: 'toolong' }).some((e) => e.message.includes('longer')));
  assert.ok(validateAgainstSchema(schema, { name: 'ok' }).some((e) => e.message.includes('required')));
  assert.ok(validateAgainstSchema(schema, { count: 3, name: 'ok', extra: 1 }).some((e) => e.message.includes('unknown field')));
  assert.ok(validateAgainstSchema(schema, { count: 3, name: 'ok', flag: 'yes' }).some((e) => e.message.includes('boolean')));
  assert.ok(validateAgainstSchema(schema, { count: 3, name: 'ok', nothing: 0 }).some((e) => e.message.includes('null')));
  assert.ok(validateAgainstSchema(schema, { count: 3, name: 'ok', ratio: Number.NaN }).length > 0);
  assert.ok(validateAgainstSchema(schema, 'not an object').some((e) => e.message.includes('object')));
});

test('arrays, enums, consts, patterns, and formats are enforced', () => {
  const schema = {
    type: 'object',
    properties: {
      items: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 2 },
      klass: { enum: ['new', 'dropped'] },
      version: { const: '1.1.0' },
      sha: { type: 'string', pattern: '^[0-9a-f]{4}$' },
      when: { type: 'string', format: 'date-time' },
    },
  };
  assert.deepEqual(
    validateAgainstSchema(schema, {
      items: ['a'],
      klass: 'new',
      version: '1.1.0',
      sha: '0a1b',
      when: '2026-07-29T12:00:00+00:00',
    }),
    [],
  );
  assert.ok(validateAgainstSchema(schema, { items: [] }).some((e) => e.message.includes('fewer')));
  assert.ok(validateAgainstSchema(schema, { items: ['a', 'b', 'c'] }).some((e) => e.message.includes('more')));
  assert.ok(validateAgainstSchema(schema, { items: ['a', 1] }).some((e) => e.path.includes('[1]')));
  assert.ok(validateAgainstSchema(schema, { klass: 'changed?' }).some((e) => e.message.includes('enumeration')));
  assert.ok(validateAgainstSchema(schema, { version: '2.0.0' }).some((e) => e.message.includes('constant')));
  assert.ok(validateAgainstSchema(schema, { sha: 'ZZZZ' }).some((e) => e.message.includes('pattern')));
  assert.ok(validateAgainstSchema(schema, { when: 'yesterday' }).some((e) => e.message.includes('date-time')));
  assert.deepEqual(validateAgainstSchema(schema, { when: '2026-07-29T12:00:00Z' }), []);
});

test('refs and anyOf resolve locally; broken refs are errors', () => {
  const schema = {
    $defs: { Leaf: { type: 'string' } },
    type: 'object',
    properties: {
      leaf: { $ref: '#/$defs/Leaf' },
      maybe: { anyOf: [{ type: 'string' }, { type: 'null' }] },
      broken: { $ref: '#/$defs/Missing' },
      external: { $ref: 'https://evil.invalid/schema.json' },
    },
  };
  assert.deepEqual(validateAgainstSchema(schema, { leaf: 'x', maybe: null }), []);
  assert.deepEqual(validateAgainstSchema(schema, { maybe: 'x' }), []);
  assert.ok(validateAgainstSchema(schema, { leaf: 1 }).some((e) => e.message.includes('string')));
  assert.ok(validateAgainstSchema(schema, { maybe: 1 }).some((e) => e.message.includes('alternative')));
  assert.ok(validateAgainstSchema(schema, { broken: 'x' }).some((e) => e.message.includes('unresolvable')));
  assert.ok(validateAgainstSchema(schema, { external: 'x' }).some((e) => e.message.includes('unresolvable')));
});

test('error counts and paths are bounded; deep nesting is cut off', () => {
  const schema = { type: 'array', items: { type: 'string' } };
  const errors = validateAgainstSchema(schema, Array.from({ length: 500 }, () => 1));
  assert.equal(errors.length, MAX_SCHEMA_ERRORS);
  const deepSchema = { $defs: {}, type: 'object', properties: {} };
  let node = deepSchema;
  const value = {};
  let cursor = value;
  for (let index = 0; index < 100; index += 1) {
    node.type = 'object';
    node.properties = { child: {} };
    node = node.properties.child;
    cursor.child = {};
    cursor = cursor.child;
  }
  const deepErrors = validateAgainstSchema(deepSchema, value);
  assert.ok(deepErrors.some((e) => e.message.includes('too deeply')));
  assert.ok(deepErrors.every((e) => e.path.length <= 203));
});

test('sha256 digests match a known vector and abbreviate for display', async () => {
  const digest = await sha256Hex(new TextEncoder().encode('abc'), subtle);
  assert.equal(digest, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(abbreviateDigest(digest), 'ba7816bf8f01');
});
