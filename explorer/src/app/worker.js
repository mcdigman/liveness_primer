// Off-main-thread report parsing and validation (explorer contract §5.2).
//
// Reports at or above the worker threshold are parsed and validated here
// so UI controls never appear operable while the main thread is blocked.
// The worker receives the decoded report text and posts back the bounded
// validation outcome; terminating the worker cancels the import.

import { validateReport } from '../lib/validate.js';

globalThis.addEventListener('message', (event) => {
  const text = /** @type {string} */ (event.data);
  /** @type {unknown} */
  let document = null;
  try {
    document = JSON.parse(text);
  } catch {
    globalThis.postMessage({
      ok: false,
      errors: [{ path: '$', message: 'the file is not valid JSON' }],
      report: null,
    });
    return;
  }
  validateReport(document, globalThis.crypto.subtle).then((outcome) => {
    globalThis.postMessage(outcome);
  });
});
