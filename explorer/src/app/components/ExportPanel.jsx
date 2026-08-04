// Export summary (explorer contract §2.5): selected counts, per-project
// breakdown, export actions, and the local-storage statement.

/** @typedef {import('../../lib/projection.js').FindingRow} FindingRow */

/**
 * @param {object} props
 * @param {FindingRow[]} props.selectedRows
 * @param {boolean} props.storageFailed
 * @param {() => void} props.onDownloadMarkdown
 * @param {() => void} props.onCopyMarkdown
 * @param {() => void} props.onDownloadReview
 * @param {() => void} props.onClearSelection
 */
export function ExportPanel({
  selectedRows,
  storageFailed,
  onDownloadMarkdown,
  onCopyMarkdown,
  onDownloadReview,
  onClearSelection,
}) {
  /** @type {Map<string, number>} */
  const perProject = new Map();
  for (const row of selectedRows) {
    perProject.set(row.project, (perProject.get(row.project) ?? 0) + 1);
  }
  const none = selectedRows.length === 0;
  return (
    <div className="export-panel">
      <h2 className="side-heading">Export</h2>
      <p className="export-count">
        <strong>{selectedRows.length}</strong> selected finding{selectedRows.length === 1 ? '' : 's'}
      </p>
      <p className="export-projects-note">
        {none
          ? 'Select findings in the table to export them.'
          : `Across ${perProject.size} project${perProject.size === 1 ? '' : 's'}`}
      </p>
      {perProject.size > 0 && (
        <ul className="export-projects">
          {[...perProject.entries()].map(([project, count]) => (
            <li key={project}>
              <span className="export-project-name">{project}</span>
              <span className="export-project-count">{count}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="export-actions">
        <button type="button" className="primary" disabled={none} onClick={onDownloadMarkdown}>
          Export selected findings
        </button>
        <button type="button" disabled={none} onClick={onCopyMarkdown}>
          Copy export Markdown
        </button>
        <button type="button" onClick={onDownloadReview}>
          Review export JSON
        </button>
        <button type="button" className="link-button" disabled={none} onClick={onClearSelection}>
          Clear selection ({selectedRows.length})
        </button>
      </div>
      <div className={`storage-note${storageFailed ? ' storage-note-failed' : ''}`}>
        <h3>Local workspace state</h3>
        <p>
          {storageFailed
            ? 'Saving failed: selection and hidden findings are held in memory only for this tab.'
            : 'Selection and hidden findings are saved in this browser, keyed by the report digest. Nothing is uploaded.'}
        </p>
      </div>
    </div>
  );
}
