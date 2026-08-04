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
 * @param {number} port
 * @returns {Promise<import('node:http').Server>}
 */
export function serve(port) {
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
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const portFlag = process.argv.indexOf('--port');
  const port = portFlag === -1 ? 4173 : Number(process.argv[portFlag + 1]);
  await serve(port);
  console.log(`serving dist at http://127.0.0.1:${port}${SUBPATH}`);
}
