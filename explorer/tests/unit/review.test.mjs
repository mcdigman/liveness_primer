import assert from 'node:assert/strict';
import { test } from 'node:test';

import { supportedSchemaVersion, validateExplorerReview } from '../../src/generated/validators.js';
import { projectReport } from '../../src/lib/projection.js';
import { buildReviewPayload, reviewFilename, serializeReview } from '../../src/lib/review.js';
import { emptyWorkspace, toggleFlag } from '../../src/lib/workspace.js';
import { goldenReport } from './helpers.mjs';

const DIGEST = 'ab'.repeat(32);
const projection = projectReport(goldenReport());

test('the payload lists locators in serialized report order regardless of click order', () => {
  let workspace = emptyWorkspace();
  const last = projection.rows.at(-1);
  const first = projection.rows[0];
  workspace = toggleFlag(workspace, 'selected', last.key);
  workspace = toggleFlag(workspace, 'selected', first.key);
  workspace = toggleFlag(workspace, 'hidden', last.key);
  const payload = buildReviewPayload(DIGEST, workspace, projection.rows);
  assert.equal(payload.schema_version, supportedSchemaVersion);
  assert.equal(payload.report_sha256, DIGEST);
  assert.deepEqual(payload.selected, [first.locator, last.locator]);
  assert.deepEqual(payload.hidden, [last.locator]);
});

test('the payload validates against the generated explorer-review schema', () => {
  let workspace = emptyWorkspace();
  for (const row of projection.rows.slice(0, 3)) {
    workspace = toggleFlag(workspace, 'selected', row.key);
  }
  workspace = toggleFlag(workspace, 'hidden', projection.rows[4].key);
  const payload = buildReviewPayload(DIGEST, workspace, projection.rows);
  assert.equal(validateExplorerReview(payload), true, JSON.stringify(validateExplorerReview.errors));
  const empty = buildReviewPayload(DIGEST, emptyWorkspace(), projection.rows);
  assert.equal(validateExplorerReview(empty), true);
  assert.equal(validateExplorerReview({ ...payload, report_sha256: 'ZZ'.repeat(32) }), false);
  assert.equal(validateExplorerReview({ ...payload, extra: true }), false);
});

test('serialization is stable pretty JSON with a trailing newline', () => {
  const payload = buildReviewPayload(DIGEST, emptyWorkspace(), projection.rows);
  const text = serializeReview(payload);
  assert.ok(text.endsWith('\n'));
  assert.deepEqual(JSON.parse(text), payload);
  assert.equal(reviewFilename(DIGEST), `liveness-primer-review-${DIGEST.slice(0, 12)}.json`);
});
