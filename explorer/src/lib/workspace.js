// Local workspace state: the `selected` and `hidden` flags every finding
// carries (explorer contract §6).
//
// State lives in memory as sets of locator keys and persists locally under
// the SHA-256 digest of the exact report bytes, stored as the same
// portable ExplorerReview payload the export produces. A byte-different
// report never inherits state. Storage failure leaves the in-memory
// workspace usable; callers surface the returned failure.

/** @typedef {import('./types.js').FindingLocator} FindingLocator */
/** @typedef {import('./types.js').ExplorerReview} ExplorerReview */

/**
 * @typedef {object} Workspace
 * @property {Set<string>} selected locator keys selected for export
 * @property {Set<string>} hidden locator keys hidden from the default view
 */

const STORAGE_PREFIX = 'liveness-primer-explorer:v1:';

/**
 * Stable string key of one serialized locator. The unit separator cannot
 * appear in a corpus project name or identity hash meaningfully; the line
 * and occurrence components are numbers, so distinct locators map to
 * distinct keys.
 *
 * @param {FindingLocator} locator
 * @returns {string}
 */
export function locatorKey(locator) {
  return [locator.project, locator.identity, String(locator.line), String(locator.occurrence)].join('\u001f');
}

/**
 * @returns {Workspace}
 */
export function emptyWorkspace() {
  return { selected: new Set(), hidden: new Set() };
}

/**
 * @param {string} digest
 * @returns {string}
 */
export function storageKey(digest) {
  return `${STORAGE_PREFIX}${digest}`;
}

/**
 * Restore the workspace persisted for this exact report digest. Entries
 * that do not name a locator serialized in the loaded report are dropped.
 *
 * @param {Pick<Storage, 'getItem'>} storage
 * @param {string} digest
 * @param {ReadonlySet<string>} knownKeys locator keys serialized in the report
 * @returns {{workspace: Workspace, failed: boolean}}
 */
export function loadWorkspace(storage, digest, knownKeys) {
  const workspace = emptyWorkspace();
  try {
    const raw = storage.getItem(storageKey(digest));
    if (raw === null) {
      return { workspace, failed: false };
    }
    const parsed = /** @type {Partial<ExplorerReview>} */ (JSON.parse(raw));
    if (parsed === null || typeof parsed !== 'object' || parsed.report_sha256 !== digest) {
      return { workspace, failed: false };
    }
    for (const [flag, entries] of /** @type {const} */ ([
      ['selected', parsed.selected],
      ['hidden', parsed.hidden],
    ])) {
      for (const locator of Array.isArray(entries) ? entries : []) {
        const key = locatorKey(locator);
        if (knownKeys.has(key)) {
          workspace[flag].add(key);
        }
      }
    }
    return { workspace, failed: false };
  } catch {
    return { workspace: emptyWorkspace(), failed: true };
  }
}

/**
 * Persist the workspace as its portable review payload.
 *
 * @param {Pick<Storage, 'setItem'>} storage
 * @param {string} digest
 * @param {ExplorerReview} payload
 * @returns {{ok: boolean}}
 */
export function saveWorkspace(storage, digest, payload) {
  try {
    storage.setItem(storageKey(digest), JSON.stringify(payload));
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

/**
 * Toggle one flag on one row key, returning a new workspace.
 *
 * @param {Workspace} workspace
 * @param {'selected' | 'hidden'} flag
 * @param {string} key
 * @param {boolean} [force]
 * @returns {Workspace}
 */
export function toggleFlag(workspace, flag, key, force) {
  const next = { selected: new Set(workspace.selected), hidden: new Set(workspace.hidden) };
  const target = next[flag];
  const enable = force ?? !target.has(key);
  if (enable) {
    target.add(key);
  } else {
    target.delete(key);
  }
  return next;
}

/**
 * Set one flag across many row keys at once (bulk selection).
 *
 * @param {Workspace} workspace
 * @param {'selected' | 'hidden'} flag
 * @param {Iterable<string>} keys
 * @param {boolean} enable
 * @returns {Workspace}
 */
export function setFlagForAll(workspace, flag, keys, enable) {
  const next = { selected: new Set(workspace.selected), hidden: new Set(workspace.hidden) };
  const target = next[flag];
  for (const key of keys) {
    if (enable) {
      target.add(key);
    } else {
      target.delete(key);
    }
  }
  return next;
}

/**
 * Clear the export selection without touching hidden state.
 *
 * @param {Workspace} workspace
 * @returns {Workspace}
 */
export function clearSelection(workspace) {
  return { selected: new Set(), hidden: new Set(workspace.hidden) };
}
