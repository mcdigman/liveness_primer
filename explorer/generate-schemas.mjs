// Regenerate explorer/src/generated/schemas.js from the exported package
// schemas. The pydantic models remain the source of truth (contract §7);
// this embeds the report and review-session schemas into the application
// bundle so loading a report performs no network request (explorer §3.2).
//
// Run:  node explorer/generate-schemas.mjs
// CI verifies the generated module matches the checked-in schemas.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const schemasDir = join(here, '..', 'liveness_primer', 'schemas');

/** @param {string} name */
function load(name) {
  return JSON.parse(readFileSync(join(schemasDir, name), 'utf8'));
}

const report = load('report.schema.json');
const reviewSession = load('review-session.schema.json');

const banner = [
  '// GENERATED FILE - do not edit by hand.',
  '// Regenerate with: node explorer/generate-schemas.mjs',
  '// Source of truth: liveness_primer/schemas/*.schema.json (contract §7).',
].join('\n');

const body = [
  banner,
  '',
  `export const REPORT_SCHEMA = ${JSON.stringify(report, null, 2)};`,
  '',
  `export const REVIEW_SESSION_SCHEMA = ${JSON.stringify(reviewSession, null, 2)};`,
  '',
  `export const SUPPORTED_REPORT_SCHEMA_VERSIONS = ${JSON.stringify([
    report.properties.schema_version.const,
  ])};`,
  '',
].join('\n');

const target = join(here, 'src', 'generated', 'schemas.js');
writeFileSync(target, body);
process.stdout.write(`wrote ${target}\n`);
