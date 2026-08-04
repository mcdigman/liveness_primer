// Shared unit-test helpers: the Python-generated locator golden fixture is
// the canonical cross-implementation input (explorer contract §10).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/** @returns {{locators: object[], report: object}} */
export function loadGoldenFixture() {
  const path = join(here, '..', '..', '..', 'tests', 'fixtures', 'locator_golden.json');
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** @returns {object} a deep copy of the golden report */
export function goldenReport() {
  return structuredClone(loadGoldenFixture().report);
}

/** Minimal GitHub-hosted corpus pin. */
export function githubPin(overrides = {}) {
  return {
    name: 'alpha',
    repo: 'https://github.com/example/alpha',
    requested: 'branch:main',
    resolved_sha: '3'.repeat(40),
    ...overrides,
  };
}

/** In-memory Storage stand-in for workspace persistence tests. */
export class FakeStorage {
  constructor() {
    /** @type {Map<string, string>} */
    this.items = new Map();
    this.failNext = false;
  }

  /** @param {string} key */
  getItem(key) {
    if (this.failNext) {
      throw new Error('storage unavailable');
    }
    return this.items.get(key) ?? null;
  }

  /**
   * @param {string} key
   * @param {string} value
   */
  setItem(key, value) {
    if (this.failNext) {
      throw new Error('storage unavailable');
    }
    this.items.set(key, value);
  }
}
