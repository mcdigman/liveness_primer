// Local review persistence (explorer contract §10.3).
//
// Review entries are saved under a key containing the report SHA-256
// digest; the imported report itself is never persisted. Storage failure
// leaves in-memory review functional and is reported to the caller, which
// must warn and offer immediate downloads; a save is never claimed before
// the storage operation completes.

import { buildReviewSession, stateFromSession, validateReviewSession } from './review.js';

const REVIEW_PREFIX = 'liveness-primer-review:';
export const THEME_KEY = 'liveness-primer-theme';

/**
 * @typedef {{ getItem(key: string): string | null,
 *   setItem(key: string, value: string): void,
 *   removeItem(key: string): void }} StorageLike
 */

/**
 * Storage key of one report digest's review state.
 *
 * @param {string} reportSha256 Report digest.
 * @returns {string} Storage key.
 */
export function reviewStorageKey(reportSha256) {
  return `${REVIEW_PREFIX}${reportSha256}`;
}

/**
 * Persist the portable review session for one report digest.
 *
 * @param {StorageLike} storage Backing storage.
 * @param {import('./review.js').ReviewState} state In-memory review state.
 * @param {import('./projection.js').ReviewRow[]} rows Rows in canonical order.
 * @param {{ schemaVersion: string, reportSha256: string, reportSchemaVersion: string,
 *   createdAt: string, updatedAt: string }} meta Session metadata.
 * @returns {{ ok: boolean, reason: string | null }} Save outcome.
 */
export function saveReview(storage, state, rows, meta) {
  const session = buildReviewSession(state, rows, meta);
  try {
    storage.setItem(reviewStorageKey(meta.reportSha256), JSON.stringify(session));
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.name : 'storage failure' };
  }
  return { ok: true, reason: null };
}

/**
 * Load persisted review state for one report digest.
 *
 * The stored session is untrusted data and passes the same validation as
 * an imported session; state recorded for a byte-different report never
 * leaks in because the digest is part of the key and re-checked.
 *
 * @param {StorageLike} storage Backing storage.
 * @param {{ reportSha256: string, rowOrder: Map<string, number> }} context Active-report context.
 * @returns {{ state: import('./review.js').ReviewState | null, createdAt: string | null }}
 *   The restored state, or nulls when absent or invalid.
 */
export function loadReview(storage, context) {
  /** @type {string | null} */
  let raw = null;
  try {
    raw = storage.getItem(reviewStorageKey(context.reportSha256));
  } catch {
    return { state: null, createdAt: null };
  }
  if (raw === null) return { state: null, createdAt: null };
  /** @type {unknown} */
  let document = null;
  try {
    document = JSON.parse(raw);
  } catch {
    return { state: null, createdAt: null };
  }
  const outcome = validateReviewSession(document, context);
  if (!outcome.ok || outcome.session === null) {
    return { state: null, createdAt: null };
  }
  return { state: stateFromSession(outcome.session), createdAt: outcome.session.created_at };
}

/**
 * Delete persisted review state for the active report (explorer §14.4).
 *
 * @param {StorageLike} storage Backing storage.
 * @param {string} reportSha256 Report digest.
 * @returns {boolean} Whether the delete succeeded.
 */
export function clearReview(storage, reportSha256) {
  try {
    storage.removeItem(reviewStorageKey(reportSha256));
  } catch {
    return false;
  }
  return true;
}

/**
 * Load the persisted theme preference; stored separately from review state.
 *
 * @param {StorageLike} storage Backing storage.
 * @returns {'system' | 'light' | 'dark'} The stored preference.
 */
export function loadTheme(storage) {
  /** @type {string | null} */
  let value = null;
  try {
    value = storage.getItem(THEME_KEY);
  } catch {
    return 'system';
  }
  return value === 'light' || value === 'dark' ? value : 'system';
}

/**
 * Persist the theme preference.
 *
 * @param {StorageLike} storage Backing storage.
 * @param {'system' | 'light' | 'dark'} theme Preference to store.
 * @returns {void}
 */
export function saveTheme(storage, theme) {
  try {
    storage.setItem(THEME_KEY, theme);
  } catch {
    // Theme persistence is a nonessential enhancement: a storage failure
    // must not disturb the review surface (explorer §15).
  }
}
