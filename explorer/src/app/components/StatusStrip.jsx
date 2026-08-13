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
    conditions.push({ key: 'comparable', severity: 'error', text: 'Comparison unreliable' });
  }
  if (!status.isolationEnforced) {
    conditions.push({ key: 'isolation', severity: 'error', text: 'Sandboxing disabled' });
  }
  if (status.truncated) {
    conditions.push({
      key: 'truncated',
      severity: 'warning',
      text: `Findings incomplete: ${status.truncatedProjects.length} project${
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
      text: `Unexpected baseline findings: ${status.integrityWarningCount}`,
    });
  }
  if (status.sourceWarningCount > 0) {
    conditions.push({
      key: 'source',
      severity: 'warning',
      text: `Source excerpt warnings: ${status.sourceWarningCount}`,
    });
  }
  if (status.environmentDelta.length > 0) {
    conditions.push({
      key: 'delta',
      severity: 'warning',
      text: `Dependency differences: ${status.environmentDelta.length}`,
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
            The base and head detectors did not run in matching managed environments: at least one side was
            launched with a custom command. Differences shown here may come from the environments rather than
            the detector change, so treat this comparison with caution; re-run without the custom command for
            a reliable one.
          </p>
        )}
        {!status.isolationEnforced && (
          <p>
            This run did not sandbox the build and analysis steps, so the analyzed projects&apos; own code
            could have influenced the results. Re-run with isolation enforced to rule that out.
          </p>
        )}
        {status.truncated &&
          (status.isExport ? (
            <p>
              This file is an explorer export, so findings are missing from:{' '}
              {status.truncatedProjects.join(', ')}. They were left unselected when the export was made, cut
              by the original run&apos;s results cap, or both. Totals and rollups still describe the complete
              original run.
            </p>
          ) : (
            <p>
              Some findings did not fit in this report: the results cap cut the finding list short in:{' '}
              {status.truncatedProjects.join(', ')}. Totals and rollups still count every finding from the
              run; only the detailed list is incomplete. Raise the cap and re-run to see the missing findings.
            </p>
          ))}
        {status.environmentDelta.length > 0 && (
          <>
            <p>
              These dependencies differ between the base and head environments, which can change results
              independently of the detector:
            </p>
            <ul>
              {status.environmentDelta.map((delta) => (
                <li key={delta.package}>
                  <code>{delta.package}</code>: {delta.base_version ?? 'absent'} →{' '}
                  {delta.head_version ?? 'absent'}
                </li>
              ))}
            </ul>
          </>
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
                    The detector failed on the {error.side} side (
                    {error.exit_code === null ? 'timed out' : `exit code ${error.exit_code}`}), so its
                    findings are missing from this comparison: {error.detail}
                  </li>
                ))}
                {project.report.integrity_warnings.map((warning, index) => (
                  <li key={`integrity-${index}`}>
                    The base revision unexpectedly reported findings on this project, which was expected to be
                    clean, so results here may be untrustworthy: {warning.detail}
                  </li>
                ))}
                {project.report.source_warnings.map((warning, index) => (
                  <li key={`source-${index}`}>
                    A problem reading pinned source files left some excerpts incomplete: {warning}
                  </li>
                ))}
              </ul>
            </div>
          ))}
      </div>
    </details>
  );
}
