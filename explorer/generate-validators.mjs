// Compiles the exported JSON Schemas into a bundled standalone validator
// module (explorer contract §4.3).
//
// The Pydantic models are the source of truth; `schema export` writes the
// schema documents, and this script compiles them with Ajv into
// `src/generated/validators.js`. The generated module contains no runtime
// schema compilation, so it works under a Content Security Policy without
// `unsafe-eval`. CI regenerates the module and fails when the checked-in
// copy is stale. Each schema document declares its JSON Schema dialect;
// compilation selects the Ajv class for that declared dialect rather than
// a build-time guess. Format assertions such as `date-time` remain Python
// semantics: the browser boundary is structural, so format validation is
// disabled rather than half-reimplemented.
//
// Ajv emits CommonJS `require` calls for the runtime helpers a few keywords
// need, even under ESM standalone output, which no browser and no ESM
// loader can evaluate. The one helper the schemas reach — the string length
// `maxLength` measures — is substituted below, and any other one fails the
// build rather than shipping a module that throws on import.
//
// Run: node explorer/generate-validators.mjs
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import standaloneCode from 'ajv/dist/standalone/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const schemasDir = join(here, '..', 'liveness_primer', 'schemas');

/** Ajv classes by the dialect URI a schema document declares. */
const DIALECTS = new Map([['https://json-schema.org/draft/2020-12/schema', Ajv2020]]);

/**
 * @param {string} name
 * @returns {{schema: Record<string, unknown>, dialect: string}}
 */
function loadSchema(name) {
  const raw = readFileSync(join(schemasDir, name), 'utf8');
  const schema = JSON.parse(raw);
  const dialect = schema['$schema'];
  if (typeof dialect !== 'string' || !DIALECTS.has(dialect)) {
    throw new Error(`${name} declares unsupported JSON Schema dialect: ${String(dialect)}`);
  }
  return { schema, dialect };
}

const report = loadSchema('report.schema.json');
const review = loadSchema('explorer-review.schema.json');
const exported = loadSchema('explorer-export.schema.json');
for (const { name, loaded } of [
  { name: 'explorer-review', loaded: review },
  { name: 'explorer-export', loaded: exported },
]) {
  if (report.dialect !== loaded.dialect) {
    throw new Error(`report and ${name} schemas declare different dialects`);
  }
}

const AjvClass = DIALECTS.get(report.dialect);
const ajv = new AjvClass({
  allErrors: false,
  code: { source: true, esm: true, optimize: true },
  strict: true,
  validateFormats: false,
});
ajv.addSchema(report.schema, 'report');
ajv.addSchema(review.schema, 'explorer-review');
ajv.addSchema(exported.schema, 'explorer-export');
const generated = standaloneCode(ajv, {
  validateReport: 'report',
  validateExplorerReview: 'explorer-review',
  validateExplorerExport: 'explorer-export',
});

// Ajv's ucs2length counts a surrogate pair as one character, which is what
// Python's `len` counts, so the bound means the same on both sides.
const UCS2LENGTH_HELPER = 'ajvUcs2Length';
const moduleCode = generated.replaceAll('require("ajv/dist/runtime/ucs2length").default', UCS2LENGTH_HELPER);
const stray = moduleCode.match(/require\([^)]*\)/u);
if (stray !== null) {
  throw new Error(`generated validators keep an unsubstituted CommonJS import: ${stray[0]}`);
}

const properties = /** @type {Record<string, {const?: unknown}>} */ (report.schema['properties']);
const supportedVersion = properties?.schema_version?.const;
if (typeof supportedVersion !== 'string') {
  throw new Error('report.schema.json does not pin a schema_version const');
}

const banner = [
  '// GENERATED FILE - do not edit.',
  '// Compiled by generate-validators.mjs from the exported Pydantic JSON',
  '// Schemas with Ajv standalone code generation (explorer contract §4.3).',
  '/* eslint-disable */',
  '// @ts-nocheck',
  '',
  `const ${UCS2LENGTH_HELPER} = (text) => [...text].length;`,
  '',
].join('\n');
const footer = [
  '',
  `export const supportedSchemaVersion = ${JSON.stringify(supportedVersion)};`,
  `export const schemaDialect = ${JSON.stringify(report.dialect)};`,
  '',
].join('\n');

mkdirSync(join(here, 'src', 'generated'), { recursive: true });
writeFileSync(join(here, 'src', 'generated', 'validators.js'), banner + moduleCode + footer);
console.log('wrote src/generated/validators.js for schema version %s', supportedVersion);
