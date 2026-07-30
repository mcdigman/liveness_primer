// Static test server mounting the production build beneath a GitHub
// Pages-style repository subpath (explorer contract §17.2). Dependency-free.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', '..', 'dist');
const PREFIX = '/liveness_primer/explorer/';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
};

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? '/', 'http://127.0.0.1');
  let path = url.pathname;
  if (!path.startsWith(PREFIX)) {
    response.writeHead(404).end('outside the mounted subpath');
    return;
  }
  path = path.slice(PREFIX.length);
  if (path === '' || path.endsWith('/')) path += 'index.html';
  const resolved = normalize(join(dist, path));
  if (!resolved.startsWith(dist)) {
    response.writeHead(403).end();
    return;
  }
  try {
    const body = await readFile(resolved);
    response.writeHead(200, { 'content-type': TYPES[extname(resolved)] ?? 'application/octet-stream' });
    response.end(body);
  } catch {
    response.writeHead(404).end('not found');
  }
});

server.listen(8930, '127.0.0.1', () => {
  process.stdout.write('serving dist at http://127.0.0.1:8930/liveness_primer/explorer/\n');
});
