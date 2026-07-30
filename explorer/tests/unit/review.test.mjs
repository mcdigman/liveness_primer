// Review-session tests: validation, uniqueness, ordering, digest
// matching, and byte-exact JSON export (explorer contract §10, §11).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildReviewRows } from '../../src/lib/projection.js';
import {
  buildReviewSession,
  dispositionOf,
  emptyReviewState,
  serializeReviewSession,
  stateFromSession,
  validateReviewSession,
} from '../../src/lib/review.js';
import { fixtureReport } from './helpers.mjs';

const rows = buildReviewRows(fixtureReport());
const DIGEST = 'a'.repeat(64);
const META = {
  schemaVersion: '1.1.0',
  reportSha256: DIGEST,
  reportSchemaVersion: '1.1.0',
  createdAt: '2026-07-29T12:00:00+00:00',
  updatedAt: '2026-07-29T12:30:00+00:00',
};

function context() {
  return { reportSha256: DIGEST, rowOrder: new Map(rows.map((row, index) => [row.locatorKey, index])) };
}

function reviewedState() {
  const state = emptyReviewState();
  state.dispositions.set(rows[2].locatorKey, 'unexpected');
  state.dispositions.set(rows[0].locatorKey, 'expected');
  state.notes.set(rows[2].locatorKey, 'needs a look');
  state.notes.set(rows[5].locatorKey, 'orphan note without disposition');
  return state;
}

test('sessions serialize entries in canonical order and omit unreviewed findings', () => {
  const session = buildReviewSession(reviewedState(), rows, META);
  assert.equal(session.entries.length, 2);
  assert.deepEqual(session.entries[0].locator, rows[0].locator);
  assert.deepEqual(session.entries[1].locator, rows[2].locator);
  assert.equal(session.entries[0].note, null);
  assert.equal(session.entries[1].note, 'needs a look');
  assert.equal(session.report_sha256, DIGEST);
});

test('sessions round-trip through the canonical JSON serialization', () => {
  const session = buildReviewSession(reviewedState(), rows, META);
  const text = serializeReviewSession(session);
  assert.ok(text.endsWith('\n'));
  const outcome = validateReviewSession(JSON.parse(text), context());
  assert.equal(outcome.ok, true, JSON.stringify(outcome.errors));
  const restored = stateFromSession(outcome.session);
  assert.equal(dispositionOf(restored, rows[0].locatorKey), 'expected');
  assert.equal(dispositionOf(restored, rows[2].locatorKey), 'unexpected');
  assert.equal(dispositionOf(restored, rows[1].locatorKey), 'unreviewed');
  assert.equal(restored.notes.get(rows[2].locatorKey), 'needs a look');
  // Byte-exact export: serializing the restored state reproduces the text.
  const again = serializeReviewSession(buildReviewSession(restored, rows, META));
  assert.equal(again, text);
});

test('structural violations are rejected', () => {
  assert.equal(validateReviewSession(null, context()).ok, false);
  assert.equal(validateReviewSession({}, context()).ok, false);
  const session = buildReviewSession(reviewedState(), rows, META);
  const extra = { ...session, surprise: 1 };
  assert.equal(validateReviewSession(extra, context()).ok, false);
  const badDigest = { ...session, report_sha256: 'Z'.repeat(64) };
  assert.equal(validateReviewSession(badDigest, context()).ok, false);
  const badDisposition = structuredClone(session);
  badDisposition.entries[0].disposition = 'maybe';
  assert.equal(validateReviewSession(badDisposition, context()).ok, false);
});

test('a mismatched report digest fails atomically', () => {
  const session = buildReviewSession(reviewedState(), rows, META);
  const outcome = validateReviewSession(structuredClone(session), {
    ...context(),
    reportSha256: 'b'.repeat(64),
  });
  assert.equal(outcome.ok, false);
  assert.ok(outcome.errors.some((error) => error.message.includes('different report digest')));
  assert.equal(outcome.session, null);
});

test('duplicate and unknown locators fail atomically', () => {
  const session = buildReviewSession(reviewedState(), rows, META);
  const duplicated = structuredClone(session);
  duplicated.entries = [duplicated.entries[0], duplicated.entries[0]];
  const duplicateOutcome = validateReviewSession(duplicated, context());
  assert.equal(duplicateOutcome.ok, false);
  assert.ok(duplicateOutcome.errors.some((error) => error.message.includes('duplicate review-entry locator')));
  const unknown = structuredClone(session);
  unknown.entries[0].locator.line = 9999;
  const unknownOutcome = validateReviewSession(unknown, context());
  assert.equal(unknownOutcome.ok, false);
  assert.ok(unknownOutcome.errors.some((error) => error.message.includes('does not resolve')));
});

test('entries must appear in canonical report order', () => {
  const session = buildReviewSession(reviewedState(), rows, META);
  const reversed = structuredClone(session);
  reversed.entries = [...reversed.entries].reverse();
  const outcome = validateReviewSession(reversed, context());
  assert.equal(outcome.ok, false);
  assert.ok(outcome.errors.some((error) => error.message.includes('canonical report order')));
});

test('overlong notes are rejected', () => {
  const session = buildReviewSession(reviewedState(), rows, META);
  const overlong = structuredClone(session);
  overlong.entries[0].note = 'x'.repeat(4097);
  const outcome = validateReviewSession(overlong, context());
  assert.equal(outcome.ok, false);
  const exact = structuredClone(session);
  exact.entries[0].note = '\u{1f40d}'.repeat(4096);
  assert.equal(validateReviewSession(exact, context()).ok, true);
});

test('an empty note exports as null and clearing returns to unreviewed', () => {
  const state = emptyReviewState();
  state.dispositions.set(rows[0].locatorKey, 'expected');
  state.notes.set(rows[0].locatorKey, '');
  const session = buildReviewSession(state, rows, META);
  assert.equal(session.entries[0].note, null);
  state.dispositions.delete(rows[0].locatorKey);
  assert.equal(dispositionOf(state, rows[0].locatorKey), 'unreviewed');
  assert.equal(buildReviewSession(state, rows, META).entries.length, 0);
});
