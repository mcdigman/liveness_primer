// Pinned GitHub source links and raw-file targets (explorer §9.3, reporting §5).
//
// Every generated URL is derived exclusively from the validated corpus
// repository, the full resolved commit SHA, and the normalized POSIX path.
// Report-supplied strings never become arbitrary request targets; for a
// non-GitHub ad-hoc project no URL is fabricated.

const GITHUB_PATTERN =
  /^https:\/\/github\.com\/(?<owner>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)\/(?<repo>(?!\.\.?(?:\.git)?\/?$)[A-Za-z0-9._-]+?)(?:\.git)?\/?$/u;

const FULL_SHA = /^[0-9a-f]{40}$/u;

/** Origin allowed for optional complete-file loading (explorer §9.3). */
export const RAW_ORIGIN = 'https://raw.githubusercontent.com';

/**
 * @typedef {{ name: string, repo: string, requested: string, resolved_sha: string }} CorpusPin
 */

/**
 * Parse a GitHub repository URL into its owner and repository name.
 *
 * @param {string} url Repository URL as recorded in the corpus pin.
 * @returns {{ owner: string, repo: string } | null} Parsed names, or null.
 */
export function githubOwnerRepo(url) {
  const match = GITHUB_PATTERN.exec(url);
  if (match === null || match.groups === undefined) return null;
  return { owner: match.groups.owner, repo: match.groups.repo };
}

/**
 * @param {CorpusPin} pin
 * @returns {{ owner: string, repo: string } | null}
 */
function validatedRepo(pin) {
  const parsed = githubOwnerRepo(pin.repo);
  if (parsed === null || !FULL_SHA.test(pin.resolved_sha)) return null;
  return parsed;
}

/**
 * Report whether one normalized path segment is safe to encode.
 *
 * @param {string} segment Path segment.
 * @returns {boolean} False for empty, dot, backslash, or control segments.
 */
function safeSegment(segment) {
  if (segment === '' || segment === '.' || segment === '..') return false;
  if (segment.includes('\\')) return false;
  return ![...segment].some((ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f;
  });
}

/**
 * Percent-encode an already-normalized repository-relative POSIX path.
 *
 * @param {string} path Normalized POSIX path.
 * @returns {string | null} Segment-wise encoded path, or null when unsafe.
 */
export function encodedPath(path) {
  const segments = path.split('/');
  if (!segments.every(safeSegment)) return null;
  return segments.map((segment) => encodeURIComponent(segment)).join('/');
}

/**
 * Build the pinned corpus tree URL (reporting contract §4.1).
 *
 * @param {CorpusPin} pin Resolved corpus pin.
 * @returns {string | null} URL, or null for a non-GitHub ad-hoc project.
 */
export function treeUrl(pin) {
  const parsed = validatedRepo(pin);
  if (parsed === null) return null;
  return `https://github.com/${parsed.owner}/${parsed.repo}/tree/${pin.resolved_sha}`;
}

/**
 * Build the pinned source permalink for one occurrence span (reporting §5).
 *
 * @param {CorpusPin} pin Resolved corpus pin.
 * @param {string} path Normalized repository-relative POSIX path.
 * @param {number} startLine Reported span start (1-based).
 * @param {number} endLine Reported span end (1-based, inclusive).
 * @returns {string | null} Permalink, or null for non-GitHub or unsafe input.
 */
export function sourceUrl(pin, path, startLine, endLine) {
  const parsed = validatedRepo(pin);
  const encoded = encodedPath(path);
  if (parsed === null || encoded === null) return null;
  const fragment = endLine === startLine ? `#L${startLine}` : `#L${startLine}-L${endLine}`;
  return `https://github.com/${parsed.owner}/${parsed.repo}/blob/${pin.resolved_sha}/${encoded}${fragment}`;
}

/**
 * Build the raw-file target for optional complete-file loading (explorer §9.3).
 *
 * @param {CorpusPin} pin Resolved corpus pin.
 * @param {string} path Normalized repository-relative POSIX path.
 * @returns {string | null} HTTPS raw URL on the allowed origin, or null.
 */
export function rawFileUrl(pin, path) {
  const parsed = validatedRepo(pin);
  const encoded = encodedPath(path);
  if (parsed === null || encoded === null) return null;
  return `${RAW_ORIGIN}/${parsed.owner}/${parsed.repo}/${pin.resolved_sha}/${encoded}`;
}
