// Findings toolbar (explorer contract §2.4): displayed and report counts,
// detector revisions, complete diff totals, grouping, hidden reveal, and
// sorting including exact report order.

import { useId } from 'react';

import { totalsDisplay } from '../../lib/format.js';
import { SORT_OPTIONS } from '../../lib/sorting.js';

/**
 * @param {object} props
 * @param {import('../../lib/projection.js').Projection} props.projection
 * @param {number} props.visibleCount
 * @param {'project' | 'rule' | 'none'} props.grouping
 * @param {string} props.sort
 * @param {boolean} props.showHidden
 * @param {(grouping: 'project' | 'rule' | 'none') => void} props.onGroupingChange
 * @param {(sort: string) => void} props.onSortChange
 * @param {(showHidden: boolean) => void} props.onShowHiddenChange
 * @param {() => void} props.onToggleFilters
 * @param {() => void} props.onToggleExport
 * @param {number} props.selectedCount
 */
export function Toolbar({
  projection,
  visibleCount,
  grouping,
  sort,
  showHidden,
  onGroupingChange,
  onSortChange,
  onShowHiddenChange,
  onToggleFilters,
  onToggleExport,
  selectedCount,
}) {
  const groupId = useId();
  const sortId = useId();
  const total = projection.rows.length;
  const totals = totalsDisplay(projection.report.totals);
  return (
    <div className="findings-toolbar">
      <button type="button" className="filters-toggle" onClick={onToggleFilters}>
        Filters
      </button>
      <h1 className="findings-title">Findings</h1>
      <p className="findings-counts">
        <span className="count-shown">
          {visibleCount === total ? `${total} total` : `${visibleCount} of ${total}`}
        </span>
      </p>
      <p className="findings-revisions" title="detector revisions">
        <span className="revision">{projection.revisions.base}</span>
        <span aria-hidden="true"> → </span>
        <span className="visually-hidden">to</span>
        <span className="revision">{projection.revisions.head}</span>
      </p>
      <p className="findings-totals" title="complete new, dropped, and changed totals">
        <span className="total-new">{totals.new}</span>{' '}
        <span className="total-dropped">{totals.dropped}</span>{' '}
        <span className="total-changed">{totals.changed}</span>
      </p>
      <span className="toolbar-spacer" />
      <label htmlFor={groupId}>Group by</label>
      <select
        id={groupId}
        value={grouping}
        onChange={(event) =>
          onGroupingChange(/** @type {'project' | 'rule' | 'none'} */ (event.currentTarget.value))
        }
      >
        <option value="project">Project</option>
        <option value="rule">Rule</option>
        <option value="none">None</option>
      </select>
      <label className="show-hidden">
        <input
          type="checkbox"
          checked={showHidden}
          onChange={(event) => onShowHiddenChange(event.currentTarget.checked)}
        />
        Show hidden findings
      </label>
      <label htmlFor={sortId}>Sort</label>
      <select id={sortId} value={sort} onChange={(event) => onSortChange(event.currentTarget.value)}>
        {SORT_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      <button type="button" className="export-toggle" onClick={onToggleExport}>
        Export ({selectedCount})
      </button>
    </div>
  );
}
