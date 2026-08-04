// Persistent report status (explorer contract §3): non-comparability,
// unenforced isolation, truncation, detector errors, corpus/source
// warnings, and environment deltas are visible without opening details.

/**
 * @param {object} props
 * @param {import('../../lib/projection.js').StatusModel} props.status
 * @param {import('../../lib/projection.js').ProjectView[]} props.projects
 */
export function StatusStrip({ status, projects }) {
  if (status.clean) {
    return null;
  }
  /** @type {{key: string, severity: 'error' | 'warning', text: string}[]} */
  const conditions = [];
  if (!status.comparable) {
    conditions.push({ key: 'comparable', severity: 'error', text: 'Not comparable' });
  }
  if (!status.isolationEnforced) {
    conditions.push({ key: 'isolation', severity: 'error', text: 'Isolation not enforced' });
  }
  if (status.truncated) {
    conditions.push({
      key: 'truncated',
      severity: 'warning',
      text: `Truncated: ${status.truncatedProjects.length} project${
        status.truncatedProjects.length === 1 ? '' : 's'
      }`,
    });
  }
  if (status.errorCount > 0) {
    conditions.push({ key: 'errors', severity: 'error', text: `Detector errors: ${status.errorCount}` });
  }
  if (status.integrityWarningCount > 0) {
    conditions.push({
      key: 'integrity',
      severity: 'warning',
      text: `Corpus warnings: ${status.integrityWarningCount}`,
    });
  }
  if (status.sourceWarningCount > 0) {
    conditions.push({
      key: 'source',
      severity: 'warning',
      text: `Source warnings: ${status.sourceWarningCount}`,
    });
  }
  if (status.environmentDelta.length > 0) {
    conditions.push({
      key: 'delta',
      severity: 'warning',
      text: `Environment deltas: ${status.environmentDelta.length}`,
    });
  }
  return (
    <details className="status-strip">
      <summary>
        <span className="status-title">Report status</span>
        <span className="status-badges">
          {conditions.map((condition) => (
            <span key={condition.key} className={`status-badge status-${condition.severity}`}>
              <span aria-hidden="true">{condition.severity === 'error' ? '✕' : '!'}</span> {condition.text}
            </span>
          ))}
        </span>
        <span className="status-more">Details</span>
      </summary>
      <div className="status-details">
        {!status.comparable && (
          <p>
            This run is not comparable: at least one side ran through the unmanaged escape hatch, so the two
            revisions are not guaranteed to differ only in the detector.
          </p>
        )}
        {!status.isolationEnforced && <p>Build and analysis sandboxing was not enforced for this run.</p>}
        {status.truncated && (
          <p>
            Displayed findings were truncated by the results cap in: {status.truncatedProjects.join(', ')}.
            Totals and rollups remain complete-run values.
          </p>
        )}
        {status.environmentDelta.length > 0 && (
          <ul>
            {status.environmentDelta.map((delta) => (
              <li key={delta.package}>
                <code>{delta.package}</code>: {delta.base_version ?? 'absent'} →{' '}
                {delta.head_version ?? 'absent'}
              </li>
            ))}
          </ul>
        )}
        {projects
          .filter(
            (project) =>
              project.report.errors.length > 0 ||
              project.report.integrity_warnings.length > 0 ||
              project.report.source_warnings.length > 0,
          )
          .map((project) => (
            <div key={project.name} className="status-project">
              <h3>{project.name}</h3>
              <ul>
                {project.report.errors.map((error, index) => (
                  <li key={`error-${index}`}>
                    detector error ({error.side}
                    {error.exit_code === null ? ', timeout' : `, exit ${error.exit_code}`}): {error.detail}
                  </li>
                ))}
                {project.report.integrity_warnings.map((warning, index) => (
                  <li key={`integrity-${index}`}>corpus integrity: {warning.detail}</li>
                ))}
                {project.report.source_warnings.map((warning, index) => (
                  <li key={`source-${index}`}>source: {warning}</li>
                ))}
              </ul>
            </div>
          ))}
      </div>
    </details>
  );
}
