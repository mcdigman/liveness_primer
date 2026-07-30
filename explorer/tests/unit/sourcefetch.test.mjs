// Optional complete-file loading tests: allowed origin, byte limits,
// strict decoding, and safe fallbacks (explorer contract §9.3).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { RAW_ORIGIN } from '../../src/lib/permalink.js';
import { SourceFileCache, fetchPinnedFile } from '../../src/lib/sourcefetch.js';

const PIN = {
  name: 'alpha',
  repo: 'https://github.com/example/alpha',
  requested: 'branch:main',
  resolved_sha: '3'.repeat(40),
};

function streamOf(chunks) {
  let index = 0;
  return {
    getReader: () => ({
      read: async () =>
        index < chunks.length ? { done: false, value: chunks[index++] } : { done: true },
      cancel: async () => {
        index = chunks.length;
      },
    }),
  };
}

function response({ url, ok = true, status = 200, chunks = [new TextEncoder().encode('hello')], body = true }) {
  return {
    url,
    ok,
    status,
    body: body ? streamOf(chunks) : null,
  };
}

test('a successful fetch decodes UTF-8 strictly from the allowed origin', async () => {
  let requested = null;
  let init = null;
  const fetchImpl = async (url, options) => {
    requested = url;
    init = options;
    return response({ url });
  };
  const outcome = await fetchPinnedFile(PIN, 'pkg/a.py', fetchImpl);
  assert.deepEqual(outcome, { ok: true, text: 'hello' });
  assert.equal(requested, `${RAW_ORIGIN}/example/alpha/${'3'.repeat(40)}/pkg/a.py`);
  assert.equal(init.credentials, 'omit');
  assert.equal(init.referrerPolicy, 'no-referrer');
});

test('non-GitHub pins produce no request at all', async () => {
  let called = false;
  const outcome = await fetchPinnedFile(
    { ...PIN, repo: 'ssh://git@internal.invalid/beta.git' },
    'pkg/a.py',
    async () => {
      called = true;
      return response({ url: RAW_ORIGIN });
    },
  );
  assert.equal(outcome.ok, false);
  assert.ok(outcome.reason.includes('no validated pinned GitHub source target'));
  assert.equal(called, false);
});

test('a redirect off the allowed origin is rejected without reading the body', async () => {
  const outcome = await fetchPinnedFile(PIN, 'pkg/a.py', async (_url) =>
    response({ url: 'https://evil.invalid/capture' }),
  );
  assert.equal(outcome.ok, false);
  assert.ok(outcome.reason.includes('left the allowed source origin'));
});

test('failure statuses, missing bodies, and network errors are bounded reasons', async () => {
  const notFound = await fetchPinnedFile(PIN, 'pkg/a.py', async (url) =>
    response({ url, ok: false, status: 404 }),
  );
  assert.equal(notFound.ok, false);
  assert.ok(notFound.reason.includes('404'));
  const noBody = await fetchPinnedFile(PIN, 'pkg/a.py', async (url) => response({ url, body: false }));
  assert.equal(noBody.ok, false);
  const network = await fetchPinnedFile(PIN, 'pkg/a.py', async () => {
    throw new TypeError('offline');
  });
  assert.equal(network.ok, false);
  assert.equal(network.reason, 'network request failed');
  const streamError = await fetchPinnedFile(PIN, 'pkg/a.py', async (url) => ({
    url,
    ok: true,
    status: 200,
    body: {
      getReader: () => ({
        read: async () => {
          throw new Error('reset');
        },
        cancel: async () => {},
      }),
    },
  }));
  assert.equal(streamError.ok, false);
  assert.ok(streamError.reason.includes('streaming'));
});

test('delivered bytes crossing the limit cancel the stream promptly', async () => {
  let cancelled = false;
  const big = new Uint8Array(1024).fill(65);
  const fetchImpl = async (url) => ({
    url,
    ok: true,
    status: 200,
    body: {
      getReader: () => {
        let count = 0;
        return {
          read: async () => (count < 10 ? (count += 1, { done: false, value: big }) : { done: true }),
          cancel: async () => {
            cancelled = true;
          },
        };
      },
    },
  });
  const outcome = await fetchPinnedFile(PIN, 'pkg/a.py', fetchImpl, 2048);
  assert.equal(outcome.ok, false);
  assert.ok(outcome.reason.includes('2048-byte limit'));
  assert.equal(cancelled, true);
});

test('invalid UTF-8 is rejected rather than replaced', async () => {
  const outcome = await fetchPinnedFile(PIN, 'pkg/a.py', async (url) =>
    response({ url, chunks: [new Uint8Array([0xff, 0xfe, 0x00])] }),
  );
  assert.equal(outcome.ok, false);
  assert.ok(outcome.reason.includes('not valid UTF-8'));
});

test('the tab-local cache serves repeats without refetching', async () => {
  const cache = new SourceFileCache();
  let calls = 0;
  const fetchImpl = async (url) => {
    calls += 1;
    return response({ url });
  };
  const first = await cache.fetch(PIN, 'pkg/a.py', fetchImpl);
  const second = await cache.fetch(PIN, 'pkg/a.py', fetchImpl);
  assert.deepEqual(first, second);
  assert.equal(calls, 1);
  let failCalls = 0;
  const failingImpl = async (url) => {
    failCalls += 1;
    return response({ url, ok: false, status: 404 });
  };
  const failing = await cache.fetch(PIN, 'pkg/missing.py', failingImpl);
  assert.equal(failing.ok, false);
  // Failures are never cached: a retry issues a fresh request.
  await cache.fetch(PIN, 'pkg/missing.py', failingImpl);
  assert.equal(failCalls, 2);
  assert.equal(calls, 1);
});
