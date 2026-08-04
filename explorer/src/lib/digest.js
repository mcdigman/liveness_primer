// Report-byte digesting (explorer contract §6): workspace state is keyed
// by the SHA-256 of the exact imported bytes, so a byte-different report
// never inherits selection or hidden state.

/**
 * Hex SHA-256 digest of the exact report bytes.
 *
 * @param {ArrayBuffer | Uint8Array} bytes
 * @param {SubtleCrypto} [subtle]
 * @returns {Promise<string>} 64 lowercase hex characters
 */
export async function sha256Hex(bytes, subtle = crypto.subtle) {
  const digest = await subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Abbreviate a digest for display; the full digest stays in the title.
 *
 * @param {string} digest
 * @returns {string}
 */
export function abbreviatedDigest(digest) {
  return digest.slice(0, 12);
}

/**
 * Abbreviate a commit SHA for display beside a repository name.
 *
 * @param {string} sha
 * @returns {string}
 */
export function abbreviatedSha(sha) {
  return sha.slice(0, 8);
}
