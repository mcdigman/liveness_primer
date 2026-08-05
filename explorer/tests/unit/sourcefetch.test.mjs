import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MAX_SOURCE_BYTES, RAW_SOURCE_ORIGIN, fetchCompleteFile } from '../../src/lib/sourcefetch.js';

const URL_OK = `${RAW_SOURCE_ORIGIN}/example/alpha/${'3'.repeat(40)}/pkg/a.py`;

/**
 * @param {Uint8Array[]} chunks
 * @param {object} [overrides]
 */
function fakeResponse(chunks, overrides = {}) {
  return {
    ok: true,
    status: 200,
    headers: new Headers(overrides.headers ?? {}),
    body:
      'body' in overrides
        ? overrides.body
        : new ReadableStream({
            start(controller) {
              for (const chunk of chunks) {
                controller.enqueue(chunk);
              }
              controller.close();
            },
          }),
    ...('ok' in overrides || 'status' in overrides ? { ok: overrides.ok, status: overrides.status } : {}),
  };
}

test('loads bounded text from the raw GitHub origin without credentials', async () => {
  /** @type {RequestInit | undefined} */
  let seenInit;
  const fetchImpl = async (_url, init) => {
    seenInit = init;
    return fakeResponse([new TextEncoder().encode('def f():\n    return 1\n')]);
  };
  const result = await fetchCompleteFile(URL_OK, { fetchImpl });
  assert.deepEqual(result, { ok: true, text: 'def f():\n    return 1\n' });
  assert.equal(seenInit.credentials, 'omit');
  assert.equal(seenInit.referrerPolicy, 'no-referrer');
});

test('refuses other origins and invalid URLs without fetching', async () => {
  const fetchImpl = async () => {
    throw new Error('must not be called');
  };
  const foreign = await fetchCompleteFile('https://evil.example/x.py', { fetchImpl });
  assert.deepEqual(foreign, { ok: false, reason: 'refused: not the pinned raw GitHub origin' });
  const invalid = await fetchCompleteFile('not a url', { fetchImpl });
  assert.deepEqual(invalid, { ok: false, reason: 'invalid source URL' });
});

test('HTTP failures and network failures fall back with a reason', async () => {
  const httpError = await fetchCompleteFile(URL_OK, {
    fetchImpl: async () => fakeResponse([], { ok: false, status: 404 }),
  });
  assert.deepEqual(httpError, { ok: false, reason: 'HTTP 404' });
  const networkError = await fetchCompleteFile(URL_OK, {
    fetchImpl: async () => {
      throw new TypeError('offline');
    },
  });
  assert.deepEqual(networkError, { ok: false, reason: 'network request failed' });
  const emptyBody = await fetchCompleteFile(URL_OK, {
    fetchImpl: async () => fakeResponse([], { body: null }),
  });
  assert.deepEqual(emptyBody, { ok: false, reason: 'empty response body' });
});

test('the 2 MiB bound applies to both declared and streamed sizes', async () => {
  assert.equal(MAX_SOURCE_BYTES, 2 * 1024 * 1024);
  const declared = await fetchCompleteFile(URL_OK, {
    fetchImpl: async () => fakeResponse([], { headers: { 'content-length': String(MAX_SOURCE_BYTES + 1) } }),
  });
  assert.deepEqual(declared, { ok: false, reason: 'file is larger than the 2 MiB bound' });
  const streamed = await fetchCompleteFile(URL_OK, {
    fetchImpl: async () => fakeResponse([new Uint8Array(600), new Uint8Array(600)]),
    maxBytes: 1000,
  });
  assert.deepEqual(streamed, { ok: false, reason: 'file is larger than the 2 MiB bound' });
});

test('a stream that errors mid-read reports a network failure', async () => {
  const result = await fetchCompleteFile(URL_OK, {
    fetchImpl: async () =>
      fakeResponse([], {
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('partial'));
            controller.error(new Error('reset'));
          },
        }),
      }),
  });
  assert.deepEqual(result, { ok: false, reason: 'network request failed' });
});
