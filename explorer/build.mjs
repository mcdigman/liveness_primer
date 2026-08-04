// Deterministic production build (explorer contract §5, §8).
//
// esbuild bundles the React application, the import worker, and the
// stylesheet into content-hashed assets under explorer/dist/, with the
// pinned local dependencies compiled in; production loads nothing from a
// CDN. Every emitted reference is relative, so the bundle works beneath a
// GitHub Pages repository subpath. The supported schema documents and the
// bundled-dependency license notices ship with the application.
//
// Run: node explorer/build.mjs
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');
const dist = join(here, 'dist');
const version = process.env.EXPLORER_VERSION ?? 'development';

rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, 'assets'), { recursive: true });
mkdirSync(join(dist, 'schemas'), { recursive: true });

/** Shared esbuild options for both entry points. */
const shared = {
  bundle: true,
  minify: true,
  sourcemap: false,
  format: /** @type {const} */ ('esm'),
  target: 'es2022',
  outdir: join(dist, 'assets'),
  entryNames: '[name]-[hash]',
  assetNames: '[name]-[hash]',
  metafile: true,
  legalComments: /** @type {const} */ ('none'),
  define: { 'process.env.NODE_ENV': '"production"' },
  logLevel: /** @type {const} */ ('warning'),
};

/**
 * @param {Record<string, {entryPoint?: string}>} outputs
 * @param {string} suffix
 * @returns {string} the emitted file, relative to dist/
 */
function emittedAsset(outputs, suffix) {
  const paths = Object.keys(outputs).filter((path) => path.endsWith(suffix));
  if (paths.length !== 1) {
    throw new Error(`expected exactly one emitted ${suffix} asset, saw: ${paths.join(', ') || 'none'}`);
  }
  const relative = paths[0].split('dist/')[1];
  if (!relative) {
    throw new Error(`emitted asset ${paths[0]} is outside dist/`);
  }
  return relative;
}

// 1. The import worker bundles first so the application bundle can address
//    its content-hashed name relative to the document base URL.
const workerResult = await build({
  ...shared,
  entryPoints: [join(here, 'src', 'app', 'worker.js')],
});
const workerAsset = emittedAsset(workerResult.metafile.outputs, '.js');

// 2. The application bundle. CSS imported from the modules (the explorer
//    stylesheet and the Tabulator base stylesheet) is emitted as one
//    content-hashed stylesheet.
const mainResult = await build({
  ...shared,
  entryPoints: [join(here, 'src', 'app', 'main.jsx')],
  jsx: 'automatic',
  define: { ...shared.define, __WORKER_ASSET__: JSON.stringify(workerAsset) },
});
const mainJs = emittedAsset(mainResult.metafile.outputs, '.js');
const mainCss = emittedAsset(mainResult.metafile.outputs, '.css');

// 3. The static entry page references the hashed assets relatively.
const page = readFileSync(join(here, 'index.html'), 'utf8')
  .replace('./assets/main.js', `./${mainJs}`)
  .replace('./assets/main.css', `./${mainCss}`)
  .replace('%EXPLORER_VERSION%', version);
if (page.includes('%EXPLORER_VERSION%') || !page.includes(mainJs) || !page.includes(mainCss)) {
  throw new Error('index.html placeholders were not fully substituted');
}
writeFileSync(join(dist, 'index.html'), page);

// 4. The supported schema documents ship with the application (§8).
for (const name of ['report.schema.json', 'explorer-review.schema.json']) {
  copyFileSync(join(repoRoot, 'liveness_primer', 'schemas', name), join(dist, 'schemas', name));
}

// 5. License notices for the application and every bundled dependency.
copyFileSync(join(repoRoot, 'LICENSE'), join(dist, 'LICENSE'));
const bundled = ['react', 'react-dom', 'scheduler', 'tabulator-tables', 'ajv'];
const notices = ['Third-party licenses for dependencies bundled into this application.', ''];
for (const name of bundled) {
  const packageDir = join(here, 'node_modules', name);
  const meta = JSON.parse(readFileSync(join(packageDir, 'package.json'), 'utf8'));
  const licenseText = readFileSync(join(packageDir, 'LICENSE'), 'utf8');
  notices.push('='.repeat(72), `${meta.name} ${meta.version} (${meta.license})`, '='.repeat(72), licenseText.trimEnd(), '');
}
writeFileSync(join(dist, 'NOTICE.txt'), notices.join('\n'));

console.log('built %s (worker %s, css %s) version %s', mainJs, workerAsset, mainCss, version);
