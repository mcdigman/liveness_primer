// Optional complete pinned-file loading (explorer contract §9.3).
//
// The request target is derived exclusively from the validated corpus
// repository, full resolved commit SHA, and normalized POSIX path; the
// fetch sends no credentials, uses a no-referrer policy, decodes UTF-8
// strictly, verifies the final response URL stays on the allowed origin,
// and cancels promptly once delivered decoded bytes cross the §5.2 limit.

import { RAW_ORIGIN, rawFileUrl } from './permalink.js';
import { SOURCE_BYTE_LIMIT } from './validate.js';

/**
 * @typedef {{ ok: true, text: string } | { ok: false, reason: string }} FetchOutcome
 */

/**
 * Fetch one complete pinned source file from the allowed raw origin.
 *
 * @param {import('./permalink.js').CorpusPin} pin Resolved corpus pin.
 * @param {string} path Normalized repository-relative POSIX path.
 * @param {typeof fetch} fetchImpl Fetch implementation (injectable).
 * @param {number} [byteLimit] Decoded response-body byte limit.
 * @returns {Promise<FetchOutcome>} The decoded text or a bounded reason.
 */
export async function fetchPinnedFile(pin, path, fetchImpl, byteLimit = SOURCE_BYTE_LIMIT) {
  const url = rawFileUrl(pin, path);
  if (url === null) {
    return { ok: false, reason: 'no validated pinned GitHub source target exists' };
  }
  /** @type {Response} */
  let response;
  try {
    response = await fetchImpl(url, {
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      redirect: 'follow',
      mode: 'cors',
    });
  } catch {
    return { ok: false, reason: 'network request failed' };
  }
  if (!response.url.startsWith(`${RAW_ORIGIN}/`)) {
    // A redirect landed off the allowed origin; the body is not read.
    return { ok: false, reason: 'response left the allowed source origin' };
  }
  if (!response.ok) {
    return { ok: false, reason: `source request failed with status ${response.status}` };
  }
  if (response.body === null) {
    return { ok: false, reason: 'source response had no body' };
  }
  const reader = response.body.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  let received = 0;
  for (;;) {
    /** @type {{ done: boolean, value?: Uint8Array }} */
    let step;
    try {
      step = await reader.read();
    } catch {
      return { ok: false, reason: 'network request failed while streaming' };
    }
    if (step.done) break;
    const chunk = step.value ?? new Uint8Array(0);
    received += chunk.byteLength;
    if (received > byteLimit) {
      // Application-retained buffering never exceeds the limit plus this
      // one delivered chunk; excess bytes are discarded immediately.
      await reader.cancel();
      return { ok: false, reason: `source file exceeds the ${byteLimit}-byte limit` };
    }
    chunks.push(chunk);
  }
  const merged = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return { ok: true, text: new TextDecoder('utf-8', { fatal: true }).decode(merged) };
  } catch {
    return { ok: false, reason: 'source file is not valid UTF-8' };
  }
}

/**
 * In-memory, tab-local cache of fetched complete files (explorer §9.3).
 */
export class SourceFileCache {
  constructor() {
    /** @type {Map<string, string>} */
    this.files = new Map();
  }

  /**
   * Fetch one pinned file through the cache.
   *
   * @param {import('./permalink.js').CorpusPin} pin Resolved corpus pin.
   * @param {string} path Normalized repository-relative POSIX path.
   * @param {typeof fetch} fetchImpl Fetch implementation.
   * @returns {Promise<FetchOutcome>} The decoded text or a bounded reason.
   */
  async fetch(pin, path, fetchImpl) {
    const key = JSON.stringify([pin.repo, pin.resolved_sha, path]);
    const cached = this.files.get(key);
    if (cached !== undefined) {
      return { ok: true, text: cached };
    }
    const outcome = await fetchPinnedFile(pin, path, fetchImpl);
    if (outcome.ok) {
      this.files.set(key, outcome.text);
    }
    return outcome;
  }
}
