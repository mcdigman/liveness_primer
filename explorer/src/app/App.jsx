// The desktop workbench shell (explorer contract §2): header, filter rail,
// scrolling findings region, and the export/context right region.

import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';

import { facetCounts, rowPredicate } from '../lib/facets.js';
import { renderMarkdown, markdownFilename } from '../lib/markdown.js';
import { buildReviewPayload, reviewFilename, serializeReview } from '../lib/review.js';
import { sortRows } from '../lib/sorting.js';
import { MAX_REPORT_BYTES } from '../lib/validate.js';
import { loadWorkspace, locatorKey, saveWorkspace } from '../lib/workspace.js';
import { copyText, downloadText } from './exporting.js';
import { initialState, reduce } from './state.js';
import { applyTheme, persistTheme, storedTheme, watchSystemTheme } from './theme.js';
import { ContextPanel } from './components/ContextPanel.jsx';
import { ExportPanel } from './components/ExportPanel.jsx';
import { FilterRail } from './components/FilterRail.jsx';
import { FindingsTable } from './components/FindingsTable.jsx';
import { Header } from './components/Header.jsx';
import { StatusStrip } from './components/StatusStrip.jsx';
import { Toolbar } from './components/Toolbar.jsx';

/** @typedef {import('../lib/types.js').Report} Report */

/**
 * @param {Report} report
 * @returns {Set<string>}
 */
function knownLocatorKeys(report) {
  const keys = new Set();
  for (const project of report.projects) {
    for (const diff of project.diffs) {
      if (diff.locator !== null) {
        keys.add(locatorKey(diff.locator));
      }
    }
  }
  return keys;
}

export function App() {
  const [state, dispatch] = useReducer(reduce, undefined, initialState);
  const [theme, setTheme] = useState(storedTheme);
  const [narrowPanel, setNarrowPanel] = useState(/** @type {'none' | 'filters' | 'export'} */ ('none'));
  const workerRef = useRef(/** @type {Worker | null} */ (null));
  const themeRef = useRef(theme);
  themeRef.current = theme;

  useEffect(() => {
    applyTheme(themeRef.current);
    return watchSystemTheme(() => themeRef.current);
  }, []);

  const selectTheme = useCallback((/** @type {import('./theme.js').ThemeMode} */ mode) => {
    setTheme(mode);
    persistTheme(mode);
    applyTheme(mode);
  }, []);

  const cancelImport = useCallback(() => {
    if (workerRef.current !== null) {
      workerRef.current.terminate();
      workerRef.current = null;
      dispatch({ type: 'import-cancelled' });
    }
  }, []);

  const openFile = useCallback(async (/** @type {File} */ file) => {
    if (file.size > MAX_REPORT_BYTES) {
      dispatch({
        type: 'import-failed',
        errors: [`${file.name} is larger than the 50 MiB report bound and was not read.`],
      });
      return;
    }
    workerRef.current?.terminate();
    dispatch({ type: 'import-started' });
    const buffer = await file.arrayBuffer();
    const worker = new Worker(new URL(__WORKER_ASSET__, document.baseURI), { type: 'module' });
    workerRef.current = worker;
    worker.addEventListener('message', (event) => {
      if (workerRef.current !== worker) {
        return;
      }
      workerRef.current = null;
      worker.terminate();
      const result = /** @type {{ok: boolean, digest?: string, report?: Report, errors?: string[]}} */ (
        event.data
      );
      if (!result.ok) {
        dispatch({ type: 'import-failed', errors: result.errors ?? ['Import failed.'] });
        return;
      }
      const report = /** @type {Report} */ (result.report);
      const digest = /** @type {string} */ (result.digest);
      const { workspace, failed } = loadWorkspace(localStorage, digest, knownLocatorKeys(report));
      dispatch({
        type: 'import-succeeded',
        filename: file.name,
        digest,
        report,
        workspace,
        storageFailed: failed,
      });
    });
    worker.addEventListener('error', () => {
      if (workerRef.current === worker) {
        workerRef.current = null;
        worker.terminate();
        dispatch({ type: 'import-failed', errors: ['The import worker failed to run.'] });
      }
    });
    worker.postMessage({ kind: 'import', buffer }, [buffer]);
  }, []);

  const { projection, workspace, digest } = state;

  // Persist workspace state under the exact report digest (§6).
  useEffect(() => {
    if (projection === null || digest === null) {
      return;
    }
    const payload = buildReviewPayload(digest, workspace, projection.rows);
    if (!saveWorkspace(localStorage, digest, payload).ok) {
      dispatch({ type: 'storage-failed' });
    }
  }, [projection, workspace, digest]);

  const counts = useMemo(() => (projection === null ? null : facetCounts(projection.rows)), [projection]);

  const visibleRows = useMemo(() => {
    if (projection === null) {
      return [];
    }
    const predicate = rowPredicate(state.selections, state.query, workspace.hidden, state.showHidden);
    return sortRows(projection.rows.filter(predicate), state.sort);
  }, [projection, state.selections, state.query, state.showHidden, state.sort, workspace.hidden]);

  const selectedRows = useMemo(
    () => (projection === null ? [] : projection.rows.filter((row) => workspace.selected.has(row.key))),
    [projection, workspace.selected],
  );

  const openRow = state.openKey === null ? null : (projection?.rowsByKey.get(state.openKey) ?? null);

  const closeContext = useCallback(() => {
    const key = state.openKey;
    dispatch({ type: 'context-closed' });
    if (key !== null) {
      requestAnimationFrame(() => {
        const control = document.querySelector(`[data-context-button="${CSS.escape(key)}"]`);
        if (control instanceof HTMLElement) {
          control.focus();
        }
      });
    }
  }, [state.openKey]);

  const exportMarkdown = useCallback(() => {
    if (projection === null || digest === null || state.filename === null) {
      return '';
    }
    return renderMarkdown({ filename: state.filename, digest, projection, selectedRows });
  }, [projection, digest, state.filename, selectedRows]);

  const handleDownloadMarkdown = useCallback(() => {
    if (digest === null) {
      return;
    }
    downloadText(markdownFilename(digest), exportMarkdown(), 'text/markdown');
    dispatch({ type: 'announced', text: `Downloaded Markdown for ${selectedRows.length} findings.` });
  }, [digest, exportMarkdown, selectedRows.length]);

  const handleCopyMarkdown = useCallback(async () => {
    const copied = await copyText(exportMarkdown());
    dispatch({
      type: 'announced',
      text: copied
        ? `Copied Markdown for ${selectedRows.length} findings.`
        : 'Clipboard is unavailable; use the download instead.',
    });
  }, [exportMarkdown, selectedRows.length]);

  const handleDownloadReview = useCallback(() => {
    if (projection === null || digest === null) {
      return;
    }
    const payload = buildReviewPayload(digest, workspace, projection.rows);
    downloadText(reviewFilename(digest), serializeReview(payload), 'application/json');
    dispatch({ type: 'announced', text: 'Downloaded the review JSON record.' });
  }, [projection, digest, workspace]);

  return (
    <div className="app" data-phase={state.phase}>
      <a className="skip-link" href="#findings-region">
        Skip to findings
      </a>
      <Header
        filename={state.filename}
        digest={digest}
        query={state.query}
        searchEnabled={projection !== null}
        importing={state.phase === 'importing'}
        theme={theme}
        onQueryChange={(query) => dispatch({ type: 'query-changed', query })}
        onOpenFile={openFile}
        onCancelImport={cancelImport}
        onThemeChange={selectTheme}
      />
      {state.importErrors !== null && (
        <div className="import-errors" role="alert">
          <strong>Report rejected.</strong>
          <ul>
            {state.importErrors.map((error) => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        </div>
      )}
      {state.storageFailed && projection !== null && (
        <div className="storage-warning" role="alert">
          <span>
            Local storage is unavailable: selection and hidden state live in memory only. Export now to keep
            them.
          </span>
          <button type="button" onClick={handleDownloadReview}>
            Review export JSON
          </button>
          <button type="button" onClick={handleDownloadMarkdown}>
            Export Markdown
          </button>
        </div>
      )}
      {projection === null ? (
        <main className="empty-state">
          <section aria-labelledby="empty-heading">
            <h1 id="empty-heading">Open a liveness primer report</h1>
            <p>
              Select the JSON report produced by a <code>liveness-primer</code> run. The report is read
              entirely in this browser: nothing is uploaded, and no network request is made.
            </p>
            {state.phase === 'importing' ? (
              <p role="status">
                Validating report…{' '}
                <button type="button" onClick={cancelImport}>
                  Cancel
                </button>
              </p>
            ) : (
              <FilePicker onOpenFile={openFile} />
            )}
          </section>
        </main>
      ) : (
        <div className="workbench" data-narrow-panel={narrowPanel}>
          <FilterRail
            counts={/** @type {NonNullable<typeof counts>} */ (counts)}
            selections={state.selections}
            visibleCount={visibleRows.length}
            onToggle={(category, value) => dispatch({ type: 'facet-toggled', category, value })}
            onReset={() => dispatch({ type: 'filters-reset' })}
            onClose={() => setNarrowPanel('none')}
          />
          <section id="findings-region" className="findings-region" aria-label="Findings" tabIndex={-1}>
            <StatusStrip status={projection.status} projects={projection.projects} />
            <Toolbar
              projection={projection}
              visibleCount={visibleRows.length}
              grouping={state.grouping}
              sort={state.sort}
              showHidden={state.showHidden}
              onGroupingChange={(grouping) => dispatch({ type: 'grouping-changed', grouping })}
              onSortChange={(sort) => dispatch({ type: 'sort-changed', sort })}
              onShowHiddenChange={(showHidden) => dispatch({ type: 'show-hidden-changed', showHidden })}
              onToggleFilters={() => setNarrowPanel(narrowPanel === 'filters' ? 'none' : 'filters')}
              onToggleExport={() => setNarrowPanel(narrowPanel === 'export' ? 'none' : 'export')}
              selectedCount={selectedRows.length}
            />
            <FindingsTable
              rows={visibleRows}
              projection={projection}
              workspace={workspace}
              openKey={state.openKey}
              grouping={state.grouping}
              onToggleFlag={(flag, key, enable) =>
                dispatch({ type: 'toggle-flag', flag, key, force: enable })
              }
              onToggleAllVisible={(enable) =>
                dispatch({
                  type: 'set-flag-all',
                  flag: 'selected',
                  keys: visibleRows.map((row) => row.key),
                  enable,
                })
              }
              onOpenContext={(key) => dispatch({ type: 'context-opened', key })}
            />
          </section>
          <aside
            className={`side-region${openRow !== null || narrowPanel === 'export' ? ' side-region-open' : ''}`}
            aria-label={openRow === null ? 'Export summary' : 'Finding context'}
          >
            {openRow === null ? (
              <ExportPanel
                selectedRows={selectedRows}
                storageFailed={state.storageFailed}
                onDownloadMarkdown={handleDownloadMarkdown}
                onCopyMarkdown={handleCopyMarkdown}
                onDownloadReview={handleDownloadReview}
                onClearSelection={() => dispatch({ type: 'clear-selection' })}
              />
            ) : (
              <ContextPanel
                row={openRow}
                projection={projection}
                workspace={workspace}
                onClose={closeContext}
                onAnnounce={(text) => dispatch({ type: 'announced', text })}
              />
            )}
          </aside>
        </div>
      )}
      <div className="visually-hidden" role="status" aria-live="polite">
        {state.announcement?.text}
      </div>
    </div>
  );
}

/**
 * @param {{onOpenFile: (file: File) => void}} props
 */
function FilePicker({ onOpenFile }) {
  const inputRef = useRef(/** @type {HTMLInputElement | null} */ (null));
  return (
    <p>
      <button type="button" className="primary" onClick={() => inputRef.current?.click()}>
        Open report
      </button>
      <input
        ref={inputRef}
        className="visually-hidden"
        type="file"
        accept=".json,application/json"
        aria-label="Report JSON file"
        onChange={(event) => {
          const file = event.currentTarget.files?.[0];
          event.currentTarget.value = '';
          if (file !== undefined) {
            onOpenFile(file);
          }
        }}
      />
    </p>
  );
}
