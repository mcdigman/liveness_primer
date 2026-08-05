// Bundled-dependency license check (explorer contract §5, §10): every
// dependency compiled into the production bundle must carry a permissive
// license and ship its license text in the distribution notice.
//
// Run after `node build.mjs`: node explorer/check-licenses.mjs
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/** Packages whose code is compiled into the production assets. */
export const BUNDLED = ['react', 'react-dom', 'scheduler', 'tabulator-tables', 'ajv'];

const PERMISSIVE = new Set(['MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD']);

let failures = 0;
const notice = readFileSync(join(here, 'dist', 'NOTICE.txt'), 'utf8');
for (const name of BUNDLED) {
  const meta = JSON.parse(readFileSync(join(here, 'node_modules', name, 'package.json'), 'utf8'));
  if (!PERMISSIVE.has(meta.license)) {
    console.error(`${name}@${meta.version}: license ${meta.license} is not on the permissive allowlist`);
    failures += 1;
    continue;
  }
  if (!notice.includes(`${meta.name} ${meta.version} (${meta.license})`)) {
    console.error(`${name}@${meta.version}: missing from dist/NOTICE.txt`);
    failures += 1;
    continue;
  }
  console.log(`${name}@${meta.version}: ${meta.license} ok, notice present`);
}
if (failures > 0) {
  process.exit(1);
}
