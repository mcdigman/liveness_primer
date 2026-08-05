// Browser export side effects: downloads and clipboard (explorer §6).
//
// Exports are generated in memory and delivered through object URLs; the
// same bytes can be downloaded or copied. Clipboard failure is reported to
// the caller so the interface can offer the download instead.

/**
 * Offer text as a file download.
 *
 * @param {string} filename
 * @param {string} text
 * @param {string} type MIME type
 * @returns {void}
 */
export function downloadText(filename, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  // Give the click a tick before releasing the object URL.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Copy text to the clipboard.
 *
 * @param {string} text
 * @returns {Promise<boolean>} false when the clipboard is unavailable
 */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
