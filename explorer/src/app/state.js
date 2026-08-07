// Application state (explorer contract §2, §6): one reducer owns the
// import lifecycle, workspace flags, filters, and view controls so a
// replacement import is atomic — an invalid report leaves the current
// report and workspace untouched.

import { emptySelections } from '../lib/facets.js';
import { projectReport } from '../lib/projection.js';
import { clearSelection, emptyWorkspace, setFlagForAll, toggleFlag } from '../lib/workspace.js';

/** @typedef {import('../lib/projection.js').Projection} Projection */
/** @typedef {import('../lib/facets.js').FacetSelections} FacetSelections */
/** @typedef {import('../lib/workspace.js').Workspace} Workspace */

/**
 * @typedef {object} AppState
 * @property {'empty' | 'importing' | 'ready'} phase
 * @property {string[] | null} importErrors
 * @property {string | null} filename
 * @property {string | null} digest
 * @property {string | null} sourceSha256 origin digest of the imported document
 * @property {Projection | null} projection
 * @property {Workspace} workspace
 * @property {boolean} storageFailed
 * @property {FacetSelections} selections
 * @property {string} query
 * @property {'project' | 'rule' | 'none'} grouping
 * @property {string} sort
 * @property {boolean} showHidden
 * @property {string | null} openKey locator key of the open finding context
 * @property {{id: number, text: string} | null} announcement
 */

/** @returns {AppState} */
export function initialState() {
  return {
    phase: 'empty',
    importErrors: null,
    filename: null,
    digest: null,
    sourceSha256: null,
    projection: null,
    workspace: emptyWorkspace(),
    storageFailed: false,
    selections: emptySelections(),
    query: '',
    grouping: 'project',
    sort: 'report',
    showHidden: false,
    openKey: null,
    announcement: null,
  };
}

let announcementId = 0;

/**
 * @param {AppState} state
 * @param {string} text
 * @returns {AppState}
 */
function withAnnouncement(state, text) {
  announcementId += 1;
  return { ...state, announcement: { id: announcementId, text } };
}

/**
 * @typedef {(
 *   {type: 'import-started'} |
 *   {type: 'import-failed', errors: string[]} |
 *   {type: 'import-succeeded', filename: string, digest: string, sourceSha256: string,
 *     report: import('../lib/types.js').Report, workspace: Workspace, storageFailed: boolean} |
 *   {type: 'import-cancelled'} |
 *   {type: 'workspace-replaced', workspace: Workspace, storageFailed: boolean} |
 *   {type: 'toggle-flag', flag: 'selected' | 'hidden', key: string, force?: boolean} |
 *   {type: 'set-flag-all', flag: 'selected' | 'hidden', keys: string[], enable: boolean} |
 *   {type: 'clear-selection'} |
 *   {type: 'facet-toggled', category: keyof FacetSelections, value: string} |
 *   {type: 'filters-reset'} |
 *   {type: 'query-changed', query: string} |
 *   {type: 'grouping-changed', grouping: 'project' | 'rule' | 'none'} |
 *   {type: 'sort-changed', sort: string} |
 *   {type: 'show-hidden-changed', showHidden: boolean} |
 *   {type: 'context-opened', key: string} |
 *   {type: 'context-closed'} |
 *   {type: 'storage-failed'} |
 *   {type: 'announced', text: string}
 * )} AppAction
 */

/**
 * @param {AppState} state
 * @param {AppAction} action
 * @returns {AppState}
 */
export function reduce(state, action) {
  switch (action.type) {
    case 'import-started':
      return { ...state, phase: 'importing', importErrors: null };
    case 'import-failed':
      // Atomic replacement: the previous report and workspace stay intact.
      return withAnnouncement(
        {
          ...state,
          phase: state.projection === null ? 'empty' : 'ready',
          importErrors: action.errors,
        },
        'Report rejected.',
      );
    case 'import-cancelled':
      return withAnnouncement(
        { ...state, phase: state.projection === null ? 'empty' : 'ready' },
        'Import cancelled.',
      );
    case 'import-succeeded': {
      const projection = projectReport(action.report);
      return withAnnouncement(
        {
          ...state,
          phase: 'ready',
          importErrors: null,
          filename: action.filename,
          digest: action.digest,
          sourceSha256: action.sourceSha256,
          projection,
          workspace: action.workspace,
          storageFailed: action.storageFailed,
          selections: emptySelections(),
          query: '',
          openKey: null,
        },
        `Report loaded: ${projection.rows.length} findings.`,
      );
    }
    case 'workspace-replaced':
      return { ...state, workspace: action.workspace, storageFailed: action.storageFailed };
    case 'toggle-flag':
      return { ...state, workspace: toggleFlag(state.workspace, action.flag, action.key, action.force) };
    case 'set-flag-all':
      return {
        ...state,
        workspace: setFlagForAll(state.workspace, action.flag, action.keys, action.enable),
      };
    case 'clear-selection':
      return withAnnouncement(
        { ...state, workspace: clearSelection(state.workspace) },
        `Cleared ${state.workspace.selected.size} selected findings.`,
      );
    case 'facet-toggled': {
      const selections = {
        diffClass: new Set(state.selections.diffClass),
        project: new Set(state.selections.project),
        rule: new Set(state.selections.rule),
        kind: new Set(state.selections.kind),
        confidence: new Set(state.selections.confidence),
        severity: new Set(state.selections.severity),
      };
      const chosen = selections[action.category];
      if (chosen.has(action.value)) {
        chosen.delete(action.value);
      } else {
        chosen.add(action.value);
      }
      return { ...state, selections };
    }
    case 'filters-reset':
      // Filters only: selected and hidden state stay untouched (§2.3).
      return { ...state, selections: emptySelections(), query: '' };
    case 'query-changed':
      return { ...state, query: action.query };
    case 'grouping-changed':
      return { ...state, grouping: action.grouping };
    case 'sort-changed':
      return { ...state, sort: action.sort };
    case 'show-hidden-changed':
      return { ...state, showHidden: action.showHidden };
    case 'context-opened':
      return { ...state, openKey: action.key };
    case 'context-closed':
      return { ...state, openKey: null };
    case 'storage-failed':
      return state.storageFailed
        ? state
        : withAnnouncement(
            { ...state, storageFailed: true },
            'Saving workspace state failed; selections remain in memory only.',
          );
    case 'announced':
      return withAnnouncement(state, action.text);
    default:
      return state;
  }
}
