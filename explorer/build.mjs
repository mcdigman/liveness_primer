// Deterministic, dependency-free production build (explorer contract §16).
//
// Emits content-hashed module assets, a static entry page, the supported
// schemas, and the license notice into explorer/dist/. The build works
// beneath a repository subpath because every emitted reference is
// relative; no development server, fixture report, credential, or
// absolute developer path is included. Run: node explorer/build.mjs
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, posix, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');
const dist = join(here, 'dist');

/** @param {Uint8Array | string} content */
function hashOf(content) {
  return createHash('sha256').update(content).digest('hex').slice(0, 12);
}

/** @param {string} directory */
function walk(directory) {
  /** @type {string[]} */
  const files = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      files.push(...walk(path));
    } else {
      files.push(path);
    }
  }
  return files;
}

rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, 'assets'), { recursive: true });

const version = process.env.EXPLORER_VERSION ?? 'development';

// 1. Collect the module graph in dependency order and rewrite the import
//    specifiers to their content-hashed names. Hashing proceeds leaf-first
//    so a changed dependency changes its importers' hashes too.
const sources = walk(join(here, 'src')).filter((path) => path.endsWith('.js'));
/** @type {Map<string, string>} module path -> hashed emitted name */
const emitted = new Map();

/** @param {string} path */
function emitModule(path) {
  const existing = emitted.get(path);
  if (existing !== undefined) return existing;
  let text = readFileSync(path, 'utf8');
  const importPattern = /from '(\.[^']+)'/gu;
  const urlPattern = /new URL\('(\.[^']+)', import\.meta\.url\)/gu;
  /** @param {string} specifier */
  const rewrite = (specifier) => {
    const target = join(dirname(path), specifier);
    const name = emitModule(target);
    return `./${name}`;
  };
  text = text.replace(importPattern, (_match, specifier) => `from '${rewrite(specifier)}'`);
  text = text.replace(urlPattern, (_match, specifier) => `new URL('${rewrite(specifier)}', import.meta.url)`);
  const stem = posix.basename(path, '.js');
  const name = `${stem}-${hashOf(text)}.js`;
  writeFileSync(join(dist, 'assets', name), text);
  emitted.set(path, name);
  return name;
}

for (const source of sources) {
  emitModule(source);
}
const mainName = emitted.get(join(here, 'src', 'app', 'main.js'));

// 2. Stylesheet.
const css = readFileSync(join(here, 'styles.css'), 'utf8');
const cssName = `styles-${hashOf(css)}.css`;
writeFileSync(join(dist, 'assets', cssName), css);

// 3. Entry page with rewritten asset references and build metadata.
let html = readFileSync(join(here, 'index.html'), 'utf8');
html = html.replace('./styles.css', `./assets/${cssName}`);
html = html.replace('./src/app/main.js', `./assets/${mainName}`);
html = html.replace('<html lang="en">', `<html lang="en" data-explorer-version="${version}">`);
writeFileSync(join(dist, 'index.html'), html);

// 4. Supported schemas ship with the distribution (explorer §16).
mkdirSync(join(dist, 'schemas'), { recursive: true });
for (const name of ['report.schema.json', 'review-session.schema.json']) {
  cpSync(join(repoRoot, 'liveness_primer', 'schemas', name), join(dist, 'schemas', name));
}

// 5. License notice: the explorer is project-authored Apache-2.0 code with
//    no third-party runtime code, fonts, or assets.
cpSync(join(repoRoot, 'LICENSE'), join(dist, 'LICENSE'));
writeFileSync(
  join(dist, 'NOTICE.txt'),
  [
    'liveness primer report explorer',
    '',
    'All application code, styles, and assets in this distribution are',
    'project-authored and distributed under the Apache-2.0 license (see',
    'LICENSE). This distribution contains no third-party runtime code,',
    'fonts, icons, or other third-party assets.',
    '',
  ].join('\n'),
);

const manifest = [...emitted.values()].sort();
process.stdout.write(`built ${relative(repoRoot, dist)} (${manifest.length + 2} assets, version ${version})\n`);
