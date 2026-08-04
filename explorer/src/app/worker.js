// Import worker (explorer contract §8): digesting, parsing, and
// structural validation of an untrusted report run off the main thread so
// the shell stays responsive and cancelable. The main thread terminates
// this worker to cancel an import.

import { sha256Hex } from '../lib/digest.js';
import { checkReport } from '../lib/validate.js';

/** @type {(message: unknown) => void} */
const post = self.postMessage.bind(self);

self.addEventListener('message', (event) => {
  const data = /** @type {{kind?: string, buffer?: ArrayBuffer}} */ (
    /** @type {MessageEvent} */ (event).data
  );
  if (
    data === null ||
    typeof data !== 'object' ||
    data.kind !== 'import' ||
    !(data.buffer instanceof ArrayBuffer)
  ) {
    return;
  }
  void importReport(data.buffer);
});

/**
 * @param {ArrayBuffer} buffer
 * @returns {Promise<void>}
 */
async function importReport(buffer) {
  try {
    const bytes = new Uint8Array(buffer);
    const digest = await sha256Hex(bytes);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const result = checkReport(text);
    if (result.ok) {
      post({ kind: 'result', ok: true, digest, report: result.report });
    } else {
      post({ kind: 'result', ok: false, errors: result.errors });
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'unknown error';
    post({ kind: 'result', ok: false, errors: [`Import failed: ${detail}`] });
  }
}
