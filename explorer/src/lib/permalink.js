// Deterministic GitHub permalinks from schema-validated pin fields
// (explorer contract §7; reporting contract §5).
//
// This mirrors the Python renderer's rules exactly: repository and path
// components are parsed and encoded, never interpolated from an
// unvalidated raw string. When the pin is not a GitHub repository or
// carries no resolved full commit SHA, no URL is fabricated and the
// escaped location text remains the evidence.

/** @typedef {import('./types.js').CorpusPinRecord} CorpusPinRecord */

// GitHub owners are alphanumerics and inner hyphens; repository names also
// allow dots and underscores but never consist of dots alone. Identical to
// the Python `_GITHUB_PATTERN`.
const GITHUB_PATTERN =
  /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\/((?!\.\.?(?:\.git)?\/?$)[A-Za-z0-9._-]+?)(?:\.git)?\/?$/;

const FULL_SHA = /^[0-9a-f]{40}$/;

// Python `str.isprintable()` is false for the Other and Separator
// categories except the plain space; a path segment carrying any such
// character never becomes a URL.
const UNPRINTABLE = /[\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}]|(?![ ])\p{Zs}/u;

// Under the `u` flag a surrogate range matches only lone surrogates;
// `encodeURIComponent` would throw on them.
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;

/**
 * @param {string} url
 * @returns {[string, string] | null} `[owner, repo]` for a GitHub HTTPS URL
 */
export function githubOwnerRepo(url) {
  const match = GITHUB_PATTERN.exec(url);
  return match === null ? null : [match[1], match[2]];
}

/**
 * @param {string} path repository-relative POSIX path
 * @returns {string | null} segment-wise encoded path, or null when unsafe
 */
export function encodedPath(path) {
  const segments = path.split('/');
  for (const segment of segments) {
    if (segment === '' || segment === '.' || segment === '..') {
      return null;
    }
    if (segment.includes('\\') || UNPRINTABLE.test(segment) || LONE_SURROGATE.test(segment)) {
      return null;
    }
  }
  return segments.map((segment) => encodeURIComponent(segment)).join('/');
}

/**
 * @param {CorpusPinRecord} pin
 * @returns {[string, string] | null}
 */
function validatedRepo(pin) {
  const ownerRepo = githubOwnerRepo(pin.repo);
  if (ownerRepo === null || !FULL_SHA.test(pin.resolved_sha)) {
    return null;
  }
  return ownerRepo;
}

/**
 * Pinned corpus tree label and URL for a project header.
 *
 * @param {CorpusPinRecord} pin
 * @returns {{label: string, url: string} | null}
 */
export function treeReference(pin) {
  const ownerRepo = validatedRepo(pin);
  if (ownerRepo === null) {
    return null;
  }
  const [owner, repository] = ownerRepo;
  return {
    label: `${owner}/${repository}`,
    url: `https://github.com/${owner}/${repository}/tree/${pin.resolved_sha}`,
  };
}

/**
 * Pinned source permalink for one occurrence span.
 *
 * @param {CorpusPinRecord} pin
 * @param {string} path
 * @param {number} startLine
 * @param {number} endLine
 * @returns {string | null}
 */
export function sourceUrl(pin, path, startLine, endLine) {
  const ownerRepo = validatedRepo(pin);
  const encoded = encodedPath(path);
  if (ownerRepo === null || encoded === null) {
    return null;
  }
  const [owner, repository] = ownerRepo;
  const fragment = endLine === startLine ? `#L${startLine}` : `#L${startLine}-L${endLine}`;
  return `https://github.com/${owner}/${repository}/blob/${pin.resolved_sha}/${encoded}${fragment}`;
}

/**
 * Raw-content URL for the optional complete-file load (explorer §7). Built
 * only from the same validated fields; never from report-supplied URLs.
 *
 * @param {CorpusPinRecord} pin
 * @param {string} path
 * @returns {string | null}
 */
export function rawSourceUrl(pin, path) {
  const ownerRepo = validatedRepo(pin);
  const encoded = encodedPath(path);
  if (ownerRepo === null || encoded === null) {
    return null;
  }
  const [owner, repository] = ownerRepo;
  return `https://raw.githubusercontent.com/${owner}/${repository}/${pin.resolved_sha}/${encoded}`;
}
