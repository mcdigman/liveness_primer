import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  clearSelection,
  emptyWorkspace,
  loadWorkspace,
  locatorKey,
  saveWorkspace,
  setFlagForAll,
  storageKey,
  toggleFlag,
} from '../../src/lib/workspace.js';
import { FakeStorage } from './helpers.mjs';

const DIGEST = 'ab'.repeat(32);

function locator(overrides = {}) {
  return { project: 'alpha', identity: 'i'.repeat(64), line: 5, occurrence: 0, ...overrides };
}

test('locatorKey separates components unambiguously', () => {
  const a = locatorKey({ project: 'ab', identity: '1x', line: 2, occurrence: 3 });
  const b = locatorKey({ project: 'a', identity: 'b1x', line: 2, occurrence: 3 });
  assert.notEqual(a, b);
  assert.notEqual(
    locatorKey(locator({ line: 12, occurrence: 3 })),
    locatorKey(locator({ line: 1, occurrence: 23 })),
  );
  assert.equal(locatorKey(locator()), locatorKey(locator()));
});

test('toggle and bulk updates never mutate the input workspace', () => {
  const before = emptyWorkspace();
  const key = locatorKey(locator());
  const selectedOn = toggleFlag(before, 'selected', key);
  assert.equal(before.selected.size, 0);
  assert.ok(selectedOn.selected.has(key));
  const selectedOff = toggleFlag(selectedOn, 'selected', key);
  assert.ok(!selectedOff.selected.has(key));
  const forcedOn = toggleFlag(selectedOff, 'hidden', key, true);
  assert.ok(forcedOn.hidden.has(key));
  const stillOn = toggleFlag(forcedOn, 'hidden', key, true);
  assert.ok(stillOn.hidden.has(key));
  const bulk = setFlagForAll(stillOn, 'selected', [key, 'other'], true);
  assert.equal(bulk.selected.size, 2);
  const bulkOff = setFlagForAll(bulk, 'selected', ['other'], false);
  assert.deepEqual([...bulkOff.selected], [key]);
});

test('a hidden finding may remain selected, and clearing selection keeps hidden state', () => {
  const key = locatorKey(locator());
  let workspace = emptyWorkspace();
  workspace = toggleFlag(workspace, 'selected', key);
  workspace = toggleFlag(workspace, 'hidden', key);
  assert.ok(workspace.selected.has(key) && workspace.hidden.has(key));
  const cleared = clearSelection(workspace);
  assert.equal(cleared.selected.size, 0);
  assert.ok(cleared.hidden.has(key));
});

test('save and load roundtrip through the review payload under the digest key', () => {
  const storage = new FakeStorage();
  const selected = locator();
  const hidden = locator({ occurrence: 1 });
  const payload = {
    schema_version: '1.2.0',
    report_sha256: DIGEST,
    selected: [selected],
    hidden: [hidden],
  };
  assert.deepEqual(saveWorkspace(storage, DIGEST, payload), { ok: true });
  assert.ok(storage.items.has(storageKey(DIGEST)));
  const known = new Set([locatorKey(selected), locatorKey(hidden)]);
  const { workspace, failed } = loadWorkspace(storage, DIGEST, known);
  assert.equal(failed, false);
  assert.deepEqual([...workspace.selected], [locatorKey(selected)]);
  assert.deepEqual([...workspace.hidden], [locatorKey(hidden)]);
});

test('loading ignores absent, digest-mismatched, malformed, and unknown entries', () => {
  const storage = new FakeStorage();
  const known = new Set([locatorKey(locator())]);
  assert.equal(loadWorkspace(storage, DIGEST, known).workspace.selected.size, 0);
  storage.items.set(
    storageKey(DIGEST),
    JSON.stringify({ report_sha256: 'cd'.repeat(32), selected: [locator()], hidden: [] }),
  );
  assert.equal(loadWorkspace(storage, DIGEST, known).workspace.selected.size, 0);
  storage.items.set(storageKey(DIGEST), JSON.stringify({ report_sha256: DIGEST, selected: 7, hidden: null }));
  assert.equal(loadWorkspace(storage, DIGEST, known).workspace.selected.size, 0);
  storage.items.set(storageKey(DIGEST), JSON.stringify(null));
  assert.equal(loadWorkspace(storage, DIGEST, known).failed, false);
  storage.items.set(
    storageKey(DIGEST),
    JSON.stringify({
      report_sha256: DIGEST,
      selected: [locator(), locator({ project: 'not-in-report' })],
      hidden: [],
    }),
  );
  const { workspace } = loadWorkspace(storage, DIGEST, known);
  assert.deepEqual([...workspace.selected], [locatorKey(locator())]);
});

test('storage failure leaves the in-memory workspace usable and is reported', () => {
  const storage = new FakeStorage();
  storage.items.set(storageKey(DIGEST), 'not json');
  const broken = loadWorkspace(storage, DIGEST, new Set());
  assert.equal(broken.failed, true);
  assert.equal(broken.workspace.selected.size, 0);
  storage.failNext = true;
  assert.equal(loadWorkspace(storage, DIGEST, new Set()).failed, true);
  assert.deepEqual(
    saveWorkspace(storage, DIGEST, {
      schema_version: '1.2.0',
      report_sha256: DIGEST,
      selected: [],
      hidden: [],
    }),
    { ok: false },
  );
});
