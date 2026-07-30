// Local persistence tests: digest-scoped keys, failure behavior, and
// theme separation (explorer contract §10.3, §14.4).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { buildReviewRows } from '../../src/lib/projection.js';
import { emptyReviewState } from '../../src/lib/review.js';
import {
  THEME_KEY,
  clearReview,
  loadReview,
  loadTheme,
  reviewStorageKey,
  saveReview,
  saveTheme,
} from '../../src/lib/storage.js';
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

function memoryStorage() {
  const map = new Map();
  return {
    map,
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => {
      map.set(key, value);
    },
    removeItem: (key) => {
      map.delete(key);
    },
  };
}

function context(digest = DIGEST) {
  return { reportSha256: digest, rowOrder: new Map(rows.map((row, index) => [row.locatorKey, index])) };
}

function reviewedState() {
  const state = emptyReviewState();
  state.dispositions.set(rows[0].locatorKey, 'expected');
  state.notes.set(rows[0].locatorKey, 'ok');
  return state;
}

test('review state survives a save and load under the exact digest', () => {
  const storage = memoryStorage();
  const saved = saveReview(storage, reviewedState(), rows, META);
  assert.deepEqual(saved, { ok: true, reason: null });
  assert.ok(storage.map.has(reviewStorageKey(DIGEST)));
  const { state, createdAt } = loadReview(storage, context());
  assert.notEqual(state, null);
  assert.equal(state.dispositions.get(rows[0].locatorKey), 'expected');
  assert.equal(state.notes.get(rows[0].locatorKey), 'ok');
  assert.equal(createdAt, META.createdAt);
});

test('state recorded for one digest never leaks to a byte-different report', () => {
  const storage = memoryStorage();
  saveReview(storage, reviewedState(), rows, META);
  const other = loadReview(storage, context('b'.repeat(64)));
  assert.equal(other.state, null);
});

test('storage failures report without claiming success', () => {
  const failing = {
    getItem: () => {
      throw new Error('QuotaExceededError');
    },
    setItem: () => {
      const error = new Error('quota');
      error.name = 'QuotaExceededError';
      throw error;
    },
    removeItem: () => {
      throw new Error('nope');
    },
  };
  const saved = saveReview(failing, reviewedState(), rows, META);
  assert.equal(saved.ok, false);
  assert.equal(saved.reason, 'QuotaExceededError');
  assert.deepEqual(loadReview(failing, context()), { state: null, createdAt: null });
  assert.equal(clearReview(failing, DIGEST), false);
});

test('corrupt or invalid stored sessions are ignored', () => {
  const storage = memoryStorage();
  storage.setItem(reviewStorageKey(DIGEST), 'not json');
  assert.equal(loadReview(storage, context()).state, null);
  storage.setItem(reviewStorageKey(DIGEST), JSON.stringify({ nonsense: true }));
  assert.equal(loadReview(storage, context()).state, null);
  assert.equal(loadReview(memoryStorage(), context()).state, null);
});

test('clearReview deletes only the active report state', () => {
  const storage = memoryStorage();
  saveReview(storage, reviewedState(), rows, META);
  storage.setItem(reviewStorageKey('b'.repeat(64)), '{}');
  assert.equal(clearReview(storage, DIGEST), true);
  assert.equal(storage.map.has(reviewStorageKey(DIGEST)), false);
  assert.equal(storage.map.has(reviewStorageKey('b'.repeat(64))), true);
});

test('theme preference is stored separately and defaults to system', () => {
  const storage = memoryStorage();
  assert.equal(loadTheme(storage), 'system');
  saveTheme(storage, 'dark');
  assert.equal(loadTheme(storage), 'dark');
  saveTheme(storage, 'light');
  assert.equal(loadTheme(storage), 'light');
  assert.ok(storage.map.has(THEME_KEY));
  assert.ok(!storage.map.has(reviewStorageKey(DIGEST)));
  storage.setItem(THEME_KEY, 'sparkle');
  assert.equal(loadTheme(storage), 'system');
  const failing = {
    getItem: () => {
      throw new Error('nope');
    },
    setItem: () => {
      throw new Error('nope');
    },
    removeItem: () => {},
  };
  assert.equal(loadTheme(failing), 'system');
  saveTheme(failing, 'dark');
});
