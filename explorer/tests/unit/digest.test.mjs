import assert from 'node:assert/strict';
import { test } from 'node:test';

import { abbreviatedDigest, abbreviatedSha, sha256Hex } from '../../src/lib/digest.js';

test('sha256Hex matches the known empty-input vector', async () => {
  const digest = await sha256Hex(new Uint8Array(0));
  assert.equal(digest, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('sha256Hex digests exact bytes', async () => {
  const bytes = new TextEncoder().encode('{"a":1}');
  const digest = await sha256Hex(bytes);
  assert.match(digest, /^[0-9a-f]{64}$/);
  assert.notEqual(digest, await sha256Hex(new TextEncoder().encode('{"a":2}')));
});

test('display abbreviations keep leading characters', () => {
  const digest = 'ab'.repeat(32);
  assert.equal(abbreviatedDigest(digest), 'abababababab');
  assert.equal(abbreviatedSha('9b42e4c2'.repeat(5)), '9b42e4c2');
});
