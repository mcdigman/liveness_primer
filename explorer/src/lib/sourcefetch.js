// Optional complete-file loading (explorer contract §7).
//
// Fetching happens only after an explicit user action, only from the raw
// GitHub origin URL constructed from schema-validated pin fields, sends no
// credentials, renders the response as text, and is bounded to 2 MiB.
// Failure falls back to the embedded excerpt; the caller surfaces the
// reason.

/** Loaded complete files are bounded to this many bytes. */
export const MAX_SOURCE_BYTES = 2 * 1024 * 1024;

/** The only origin the optional source load may contact. */
export const RAW_SOURCE_ORIGIN = 'https://raw.githubusercontent.com';

/**
 * @typedef {{ok: true, text: string} | {ok: false, reason: string}} SourceFetchResult
 */

/**
 * Fetch one pinned source file as bounded text.
 *
 * @param {string} url from {@link import('./permalink.js').rawSourceUrl}
 * @param {object} [options]
 * @param {typeof fetch} [options.fetchImpl]
 * @param {number} [options.maxBytes]
 * @param {AbortSignal} [options.signal]
 * @returns {Promise<SourceFetchResult>}
 */
export async function fetchCompleteFile(url, { fetchImpl = fetch, maxBytes = MAX_SOURCE_BYTES, signal } = {}) {
  /** @type {URL} */
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: 'invalid source URL' };
  }
  if (parsed.origin !== RAW_SOURCE_ORIGIN) {
    return { ok: false, reason: 'refused: not the pinned raw GitHub origin' };
  }
  /** @type {Response} */
  let response;
  try {
    response = await fetchImpl(parsed.href, {
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal,
    });
  } catch {
    return { ok: false, reason: 'network request failed' };
  }
  if (!response.ok) {
    return { ok: false, reason: `HTTP ${response.status}` };
  }
  const declared = Number(response.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > maxBytes) {
    return { ok: false, reason: 'file is larger than the 2 MiB bound' };
  }
  const body = response.body;
  if (body === null) {
    return { ok: false, reason: 'empty response body' };
  }
  const reader = body.getReader();
  /** @type {Uint8Array[]} */
  const chunks = [];
  let received = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel();
        return { ok: false, reason: 'file is larger than the 2 MiB bound' };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, reason: 'network request failed' };
  }
  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { ok: true, text: new TextDecoder('utf-8', { fatal: false }).decode(bytes) };
}
