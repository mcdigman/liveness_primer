// Report digests over exact imported bytes (explorer contract §5.4).

/**
 * Compute the lowercase hex SHA-256 digest of exact bytes.
 *
 * The CI artifact is the canonical byte representation: semantically
 * equivalent but byte-different JSON documents intentionally have
 * different digests, and the explorer never rewrites or canonicalizes the
 * imported bytes.
 *
 * @param {Uint8Array} bytes Exact imported bytes.
 * @param {SubtleCrypto} subtle Web Crypto implementation.
 * @returns {Promise<string>} 64 lowercase hex characters.
 */
export async function sha256Hex(bytes, subtle) {
  const buffer = new Uint8Array(bytes).buffer;
  const digest = await subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Abbreviate a report digest for display.
 *
 * @param {string} digest Lowercase hex digest.
 * @returns {string} The first twelve characters.
 */
export function abbreviateDigest(digest) {
  return digest.slice(0, 12);
}
