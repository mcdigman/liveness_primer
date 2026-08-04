// Finding context (explorer contract §2.5): identity, labelled base and
// head analyzer values, the embedded pinned-source excerpt with real line
// numbers and highlighted span, pinned-source actions, and workspace
// status for the open finding.

import { useEffect, useRef, useState } from 'react';

import {
  DIFF_CLASS_PRESENTATION,
  confidenceText,
  referenceOccurrence,
  spanDisplay,
} from '../../lib/format.js';
import { rawSourceUrl } from '../../lib/permalink.js';
import { rowSourceUrl } from '../../lib/projection.js';
import { fetchCompleteFile } from '../../lib/sourcefetch.js';

/** @typedef {import('../../lib/projection.js').FindingRow} FindingRow */
/** @typedef {import('../../lib/types.js').FindingOccurrence} FindingOccurrence */

// Source-location newline semantics: only \n, \r\n, and \r are line
// boundaries (reporting contract §3.3).
const LINE_BREAK = /\r\n|\r|\n/u;

/** Complete-file rendering stays bounded around the reported span (§8). */
const COMPLETE_FILE_CONTEXT_LINES = 1000;

/**
 * @param {object} props
 * @param {string[]} props.lines
 * @param {number} props.startLine line number of lines[0]
 * @param {number} props.highlightStart
 * @param {number} props.highlightEnd
 */
function SourceLines({ lines, startLine, highlightStart, highlightEnd }) {
  return (
    <div className="source-lines" translate="no">
      {lines.map((line, offset) => {
        const number = startLine + offset;
        const highlighted = number >= highlightStart && number <= highlightEnd;
        return (
          <div key={number} className={`source-line${highlighted ? ' source-line-highlight' : ''}`}>
            <span className="source-number" aria-hidden="true">
              {number}
            </span>
            <span className="source-text">{line === '' ? ' ' : line}</span>
          </div>
        );
      })}
    </div>
  );
}

/**
 * @param {object} props
 * @param {string} props.side
 * @param {string} props.revision
 * @param {FindingOccurrence | null} props.occurrence
 * @param {boolean} props.isReference
 */
function AnalyzerCard({ side, revision, occurrence, isReference }) {
  return (
    <div className={`analyzer-card${occurrence === null ? ' analyzer-card-empty' : ''}`}>
      <p className="analyzer-title">
        <span className="analyzer-side">{side}</span>
        <span className="analyzer-revision">{revision}</span>
        {occurrence !== null && isReference && <span className="analyzer-tag">Finding reported</span>}
      </p>
      {occurrence === null ? (
        <>
          <p className="analyzer-none">No finding</p>
          <p className="analyzer-none-detail">No finding reported for this identity.</p>
        </>
      ) : (
        <dl className="analyzer-facts">
          <dt>Message</dt>
          <dd>{occurrence.message}</dd>
          <dt>Rule</dt>
          <dd>{occurrence.rule_id ?? '-'}</dd>
          <dt>Confidence</dt>
          <dd>{confidenceText(occurrence.confidence)}</dd>
          <dt>Reported span</dt>
          <dd>{spanDisplay(occurrence)}</dd>
        </dl>
      )}
    </div>
  );
}

/**
 * @param {object} props
 * @param {FindingRow} props.row
 * @param {import('../../lib/projection.js').Projection} props.projection
 * @param {import('../../lib/workspace.js').Workspace} props.workspace
 * @param {() => void} props.onClose
 * @param {(text: string) => void} props.onAnnounce
 */
export function ContextPanel({ row, projection, workspace, onClose, onAnnounce }) {
  const headingRef = useRef(/** @type {HTMLHeadingElement | null} */ (null));
  const [completeFile, setCompleteFile] = useState(
    /** @type {{status: 'idle' | 'loading' | 'loaded' | 'failed', text?: string, reason?: string}} */ ({
      status: 'idle',
    }),
  );
  const abortRef = useRef(/** @type {AbortController | null} */ (null));

  useEffect(() => {
    headingRef.current?.focus();
    setCompleteFile({ status: 'idle' });
    abortRef.current?.abort();
    return () => abortRef.current?.abort();
  }, [row.key]);

  const diff = row.diff;
  const reference = referenceOccurrence(diff);
  const excerpt = reference.source_excerpt;
  const presentation = DIFF_CLASS_PRESENTATION[row.diffClass];
  const pinnedUrl = rowSourceUrl(row);
  const rawUrl = row.pin === null ? null : rawSourceUrl(row.pin, diff.path);
  const selected = workspace.selected.has(row.key);
  const hidden = workspace.hidden.has(row.key);
  const project = projection.projectsByName.get(row.project);

  const loadCompleteFile = async () => {
    if (rawUrl === null) {
      return;
    }
    const controller = new AbortController();
    abortRef.current = controller;
    setCompleteFile({ status: 'loading' });
    onAnnounce('Loading the complete pinned file…');
    const result = await fetchCompleteFile(rawUrl, { signal: controller.signal });
    if (controller.signal.aborted) {
      return;
    }
    if (result.ok) {
      setCompleteFile({ status: 'loaded', text: result.text });
      onAnnounce('Complete file loaded.');
    } else {
      setCompleteFile({ status: 'failed', reason: result.reason });
      onAnnounce(`Complete file failed to load: ${result.reason}. Showing the embedded excerpt.`);
    }
  };

  /** @returns {{lines: string[], startLine: number, note: string | null}} */
  const completeFileView = () => {
    const text = completeFile.text ?? '';
    const lines = text.split(LINE_BREAK);
    const first = Math.max(1, reference.start_line - COMPLETE_FILE_CONTEXT_LINES);
    const last = Math.min(lines.length, reference.end_line + COMPLETE_FILE_CONTEXT_LINES);
    const note =
      first > 1 || last < lines.length
        ? `Showing lines ${first}–${last} of ${lines.length} around the reported span.`
        : null;
    return { lines: lines.slice(first - 1, last), startLine: first, note };
  };

  return (
    <div className="context-panel">
      <div className="context-header">
        <h2 className="side-heading">Finding context</h2>
        <button type="button" className="context-close" onClick={onClose} aria-label="Close finding context">
          ✕
        </button>
      </div>
      <h3 ref={headingRef} tabIndex={-1} className="context-location" translate="no">
        {row.location}
      </h3>
      <p className="context-badges">
        <span className={`diff-badge diff-${row.diffClass}`}>
          <span className="diff-glyph">{presentation.glyph}</span>
          <span className="diff-label">{presentation.label}</span>
        </span>
        <span className="context-badge cell-mono">{row.rule}</span>
        <span className="context-badge cell-mono">{row.confidence}</span>
      </p>
      <p className="context-message">{row.message}</p>
      <dl className="context-facts">
        <dt>Project</dt>
        <dd>{row.project}</dd>
        <dt>Kind</dt>
        <dd>{row.kind}</dd>
        <dt>Symbol</dt>
        <dd translate="no">{row.symbol ?? '-'}</dd>
        <dt>Locator</dt>
        <dd translate="no">
          line {row.locator.line}, occurrence {row.locator.occurrence}, identity{' '}
          <code>{row.locator.identity.slice(0, 12)}</code>
        </dd>
        {diff.changed_fields.length > 0 && (
          <>
            <dt>Changed fields</dt>
            <dd>{diff.changed_fields.join(', ')}</dd>
          </>
        )}
      </dl>
      <h3 className="context-section">Analyzer output</h3>
      <div className="analyzer-cards">
        <AnalyzerCard
          side="Base"
          revision={projection.revisions.base}
          occurrence={diff.base_occurrence}
          isReference={row.diffClass !== 'new'}
        />
        <AnalyzerCard
          side="Head"
          revision={projection.revisions.head}
          occurrence={diff.head_occurrence}
          isReference={row.diffClass === 'new'}
        />
      </div>
      <h3 className="context-section">Source context</h3>
      <p className="context-source-provenance">
        Shared pinned corpus source · unchanged between analyzer revisions
        {project?.tree !== null && project !== undefined && (
          <>
            <br />
            <span translate="no">
              {project.tree.label} @ {project.pin === null ? '' : project.pin.resolved_sha.slice(0, 8)}
            </span>
          </>
        )}
        <br />
        <span translate="no">{row.path}</span>
      </p>
      {completeFile.status === 'loaded' ? (
        (() => {
          const view = completeFileView();
          return (
            <>
              {view.note !== null && <p className="source-note">{view.note}</p>}
              <SourceLines
                lines={view.lines}
                startLine={view.startLine}
                highlightStart={reference.start_line}
                highlightEnd={reference.end_line}
              />
            </>
          );
        })()
      ) : excerpt !== null ? (
        <>
          <SourceLines
            lines={excerpt.lines}
            startLine={excerpt.start_line}
            highlightStart={reference.start_line}
            highlightEnd={reference.end_line}
          />
          {excerpt.omitted_lines > 0 && (
            <p className="source-note">
              {excerpt.omitted_lines} reported-span line{excerpt.omitted_lines === 1 ? '' : 's'} beyond the
              evidence budget.
            </p>
          )}
        </>
      ) : (
        <p className="source-note">No source excerpt is embedded in the report for this finding.</p>
      )}
      {completeFile.status === 'failed' && (
        <p className="source-note source-error" role="alert">
          Complete file failed to load ({completeFile.reason}); the embedded excerpt remains the evidence.
        </p>
      )}
      <div className="context-actions">
        {pinnedUrl !== null && (
          <a className="button-like" href={pinnedUrl} target="_blank" rel="noreferrer noopener">
            Open pinned source
          </a>
        )}
        {rawUrl !== null && completeFile.status !== 'loaded' && (
          <button type="button" onClick={loadCompleteFile} disabled={completeFile.status === 'loading'}>
            {completeFile.status === 'loading' ? 'Loading complete file…' : 'Load complete file'}
          </button>
        )}
      </div>
      <p className="context-workspace">
        <span className={`workspace-flag${selected ? ' on' : ''}`}>
          {selected ? '✓ Selected for export' : 'Not selected for export'}
        </span>
        <span className={`workspace-flag${hidden ? '' : ' on'}`}>{hidden ? 'Hidden' : 'Visible'}</span>
      </p>
      <p className="context-workspace-hint">Change Export or Hide from the finding row.</p>
    </div>
  );
}
