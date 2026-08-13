// Collapsible facet rail (explorer contract §2.3). Counts are full-report
// counts; the toolbar separately reports the visible count. Reset clears
// filters without touching selected or hidden state.

import { CONFIDENCE_BUCKETS } from '../../lib/projection.js';
import { DIFF_CLASS_PRESENTATION } from '../../lib/format.js';

/** @typedef {import('../../lib/facets.js').FacetSelections} FacetSelections */

/**
 * @param {object} props
 * @param {string} props.title
 * @param {[string, number][]} props.options value and full-report count
 * @param {(value: string) => string} [props.labelFor]
 * @param {Set<string>} props.chosen
 * @param {(value: string) => void} props.onToggle
 */
function Facet({ title, options, labelFor, chosen, onToggle }) {
  return (
    <details className="facet" open>
      <summary>{title}</summary>
      <ul>
        {options.map(([value, count]) => (
          <li key={value}>
            <label>
              <input type="checkbox" checked={chosen.has(value)} onChange={() => onToggle(value)} />
              <span className="facet-label">{labelFor === undefined ? value : labelFor(value)}</span>
              <span className="facet-count">{count}</span>
            </label>
          </li>
        ))}
      </ul>
    </details>
  );
}

/**
 * @param {object} props
 * @param {ReturnType<typeof import('../../lib/facets.js').facetCounts>} props.counts
 * @param {FacetSelections} props.selections
 * @param {number} props.visibleCount
 * @param {boolean} props.hasSeverity the report carries severity labels (§2.3)
 * @param {(category: keyof FacetSelections, value: string) => void} props.onToggle
 * @param {() => void} props.onReset
 * @param {() => void} props.onClose closes the drawer at narrow widths
 */
export function FilterRail({ counts, selections, visibleCount, hasSeverity, onToggle, onReset, onClose }) {
  return (
    <nav className="filter-rail" aria-label="Filters">
      <div className="rail-header">
        <h2 className="rail-heading">Filters</h2>
        <button type="button" className="rail-close" onClick={onClose} aria-label="Close filters">
          ✕
        </button>
      </div>
      <p className="visually-hidden" aria-live="polite">
        {visibleCount} findings match the current filters.
      </p>
      <Facet
        title="Diff class"
        options={[...counts.diffClass.entries()]}
        labelFor={(value) => {
          const presentation =
            DIFF_CLASS_PRESENTATION[/** @type {import('../../lib/types.js').DiffClass} */ (value)];
          return `${presentation.glyph} ${presentation.label}`;
        }}
        chosen={selections.diffClass}
        onToggle={(value) => onToggle('diffClass', value)}
      />
      <Facet
        title="Project"
        options={[...counts.project.entries()]}
        chosen={selections.project}
        onToggle={(value) => onToggle('project', value)}
      />
      <Facet
        title="Rule"
        options={[...counts.rule.entries()]}
        chosen={selections.rule}
        onToggle={(value) => onToggle('rule', value)}
      />
      <Facet
        title="Kind"
        options={[...counts.kind.entries()]}
        chosen={selections.kind}
        onToggle={(value) => onToggle('kind', value)}
      />
      <Facet
        title="Confidence"
        options={CONFIDENCE_BUCKETS.map((bucket) => [bucket.value, counts.confidence.get(bucket.value) ?? 0])}
        labelFor={(value) => CONFIDENCE_BUCKETS.find((bucket) => bucket.value === value)?.label ?? value}
        chosen={selections.confidence}
        onToggle={(value) => onToggle('confidence', value)}
      />
      {hasSeverity && (
        <Facet
          title="Severity"
          options={[...counts.severity.entries()]}
          chosen={selections.severity}
          onToggle={(value) => onToggle('severity', value)}
        />
      )}
      <p className="rail-actions">
        <button type="button" onClick={onReset}>
          Reset all
        </button>
      </p>
    </nav>
  );
}
