// Permalink and raw-URL validation tests (explorer §9.3, reporting §5).
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  RAW_ORIGIN,
  encodedPath,
  githubOwnerRepo,
  rawFileUrl,
  sourceUrl,
  treeUrl,
} from '../../src/lib/permalink.js';

const PIN = {
  name: 'alpha',
  repo: 'https://github.com/example/alpha',
  requested: 'branch:main',
  resolved_sha: '3'.repeat(40),
};

test('github URLs parse into owner and repository', () => {
  assert.deepEqual(githubOwnerRepo('https://github.com/example/alpha'), { owner: 'example', repo: 'alpha' });
  assert.deepEqual(githubOwnerRepo('https://github.com/example/alpha.git/'), {
    owner: 'example',
    repo: 'alpha',
  });
  assert.equal(githubOwnerRepo('http://github.com/example/alpha'), null);
  assert.equal(githubOwnerRepo('https://github.evil.invalid/example/alpha'), null);
  assert.equal(githubOwnerRepo('ssh://git@internal.invalid/beta.git'), null);
  assert.equal(githubOwnerRepo('https://github.com/-bad/alpha'), null);
  assert.equal(githubOwnerRepo('https://github.com/example/..'), null);
});

test('tree, blob, and raw URLs derive only from validated components', () => {
  assert.equal(treeUrl(PIN), `https://github.com/example/alpha/tree/${'3'.repeat(40)}`);
  assert.equal(
    sourceUrl(PIN, 'pkg/a.py', 4, 4),
    `https://github.com/example/alpha/blob/${'3'.repeat(40)}/pkg/a.py#L4`,
  );
  assert.equal(
    sourceUrl(PIN, 'pkg/a.py', 4, 9),
    `https://github.com/example/alpha/blob/${'3'.repeat(40)}/pkg/a.py#L4-L9`,
  );
  assert.equal(rawFileUrl(PIN, 'pkg/a.py'), `${RAW_ORIGIN}/example/alpha/${'3'.repeat(40)}/pkg/a.py`);
});

test('non-GitHub pins and unresolved SHAs produce no URL', () => {
  const adHoc = { ...PIN, repo: 'ssh://git@internal.invalid/beta.git' };
  assert.equal(treeUrl(adHoc), null);
  assert.equal(sourceUrl(adHoc, 'pkg/a.py', 1, 1), null);
  assert.equal(rawFileUrl(adHoc, 'pkg/a.py'), null);
  const branchPin = { ...PIN, resolved_sha: 'main' };
  assert.equal(treeUrl(branchPin), null);
  assert.equal(rawFileUrl(branchPin, 'pkg/a.py'), null);
  const upperSha = { ...PIN, resolved_sha: '3'.repeat(39) + 'F' };
  assert.equal(rawFileUrl(upperSha, 'pkg/a.py'), null);
});

test('path segments are individually percent-encoded', () => {
  assert.equal(encodedPath('pkg/has space+q.py'), 'pkg/has%20space%2Bq.py');
  assert.equal(
    rawFileUrl(PIN, 'pkg/has space.py'),
    `${RAW_ORIGIN}/example/alpha/${'3'.repeat(40)}/pkg/has%20space.py`,
  );
});

test('empty, dot, absolute, backslash, and control paths are rejected', () => {
  for (const hostile of [
    '',
    '.',
    '..',
    'pkg//a.py',
    'pkg/./a.py',
    'pkg/../a.py',
    '/etc/passwd',
    'pkg\\a.py',
    'pkg/a\u0007.py',
    'pkg/a\u007f.py',
  ]) {
    assert.equal(encodedPath(hostile), null, JSON.stringify(hostile));
    assert.equal(sourceUrl(PIN, hostile, 1, 1), null, JSON.stringify(hostile));
    assert.equal(rawFileUrl(PIN, hostile), null, JSON.stringify(hostile));
  }
});
