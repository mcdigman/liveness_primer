// Shared unit-test helpers: the Python-generated locator golden fixture is
// the single source of truth for report shape (explorer contract §17.1).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';

const here = dirname(fileURLToPath(import.meta.url));

export const FIXTURES = join(here, '..', '..', '..', 'tests', 'fixtures');

export const subtle = webcrypto.subtle;

export function loadLocatorFixture() {
  return JSON.parse(readFileSync(join(FIXTURES, 'locator_golden.json'), 'utf8'));
}

export function fixtureReport() {
  return structuredClone(loadLocatorFixture().report);
}

/** Structural locator equality, independent of JSON key order. */
export function locatorsEqual(left, right) {
  if (left.length !== right.length) return false;
  return left.every(
    (locator, index) =>
      locator.project === right[index].project &&
      locator.identity === right[index].identity &&
      locator.line === right[index].line &&
      locator.occurrence === right[index].occurrence,
  );
}
