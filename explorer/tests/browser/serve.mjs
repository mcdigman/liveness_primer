// Static test server mounting explorer/dist beneath a repository-style
// subpath (explorer contract §8, §10): the browser suites and the smoke
// test exercise the same relative-URL behavior GitHub Pages requires.
// This server exists for tests and local preview only; production hosting
// is any static file host.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', '..', 'dist');

export const SUBPATH = '/liveness-primer/explorer/';

// The endpoint comes from the environment rather than the source so a run
// can move off an occupied port (4173 is also Vite's default preview port)
// or bind somewhere reachable from another container. This module is the
// single source of truth: playwright.config.js imports it, so the address
// the suites drive and the address this server binds cannot drift. The
// defaults keep the historical loopback-only endpoint; overriding the host
// exposes dist/ beyond this machine.
export const HOST = process.env.EXPLORER_TEST_HOST ?? '127.0.0.1';
export const PORT = Number(process.env.EXPLORER_TEST_PORT ?? 4173);

/**
 * @param {string} [host]
 * @param {number} [port]
 * @returns {string}
 */
export function baseUrl(host = HOST, port = PORT) {
  return `http://${host}:${port}${SUBPATH}`;
}

const TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.txt', 'text/plain; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
]);

/**
 * @param {number} [port]
 * @param {string} [host]
 * @returns {Promise<import('node:http').Server>}
 */
export function serve(port = PORT, host = HOST) {
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://localhost');
    let path = url.pathname;
    if (!path.startsWith(SUBPATH)) {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('outside the mounted subpath');
      return;
    }
    path = path.slice(SUBPATH.length);
    if (path === '' || path.endsWith('/')) {
      path += 'index.html';
    }
    const file = normalize(join(dist, path));
    if (!file.startsWith(dist)) {
      response.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('forbidden');
      return;
    }
    try {
      const body = await readFile(file);
      response.writeHead(200, {
        'content-type': TYPES.get(extname(file)) ?? 'application/octet-stream',
        'cache-control': 'no-store',
      });
      response.end(body);
    } catch {
      response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      response.end('not found');
    }
  });
  return new Promise((resolve) => {
    server.listen(port, host, () => resolve(server));
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const portFlag = process.argv.indexOf('--port');
  const port = portFlag === -1 ? PORT : Number(process.argv[portFlag + 1]);
  await serve(port);
  console.log(`serving dist at ${baseUrl(HOST, port)}`);
}
