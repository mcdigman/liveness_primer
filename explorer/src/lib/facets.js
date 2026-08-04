// Facet filtering and text search over projected finding rows (explorer
// contract §2.3, §6).
//
// Selections within one category are ORed; categories and the search query
// combine with AND. Facet counts are full-report counts; the toolbar
// separately reports the visible count.

import { NO_RULE } from './projection.js';

/** @typedef {import('./projection.js').FindingRow} FindingRow */

/**
 * @typedef {object} FacetSelections
 * @property {Set<string>} diffClass
 * @property {Set<string>} project
 * @property {Set<string>} rule NO_RULE stands for findings without a rule
 * @property {Set<string>} kind
 * @property {Set<string>} confidence bucket values
 */

/**
 * @returns {FacetSelections}
 */
export function emptySelections() {
  return {
    diffClass: new Set(),
    project: new Set(),
    rule: new Set(),
    kind: new Set(),
    confidence: new Set(),
  };
}

/**
 * @param {FacetSelections} selections
 * @returns {boolean}
 */
export function anySelection(selections) {
  return Object.values(selections).some((chosen) => chosen.size > 0);
}

/**
 * @param {FindingRow} row
 * @returns {string}
 */
function ruleFacetValue(row) {
  return row.ruleValue ?? NO_RULE;
}

/**
 * Full-report option counts per facet category, in first-seen order for
 * projects and descending count for the open-ended categories.
 *
 * @param {FindingRow[]} rows
 * @returns {{diffClass: Map<string, number>, project: Map<string, number>, rule: Map<string, number>,
 *   kind: Map<string, number>, confidence: Map<string, number>}}
 */
export function facetCounts(rows) {
  /** @type {Record<'diffClass' | 'project' | 'rule' | 'kind' | 'confidence', Map<string, number>>} */
  const counts = {
    diffClass: new Map([
      ['new', 0],
      ['dropped', 0],
      ['changed', 0],
    ]),
    project: new Map(),
    rule: new Map(),
    kind: new Map(),
    confidence: new Map(),
  };
  /**
   * @param {Map<string, number>} map
   * @param {string} key
   */
  const bump = (map, key) => map.set(key, (map.get(key) ?? 0) + 1);
  for (const row of rows) {
    bump(counts.diffClass, row.diffClass);
    bump(counts.project, row.project);
    bump(counts.rule, ruleFacetValue(row));
    bump(counts.kind, row.kind);
    bump(counts.confidence, row.confidenceBucket);
  }
  for (const category of /** @type {const} */ (['rule', 'kind'])) {
    counts[category] = new Map(
      [...counts[category].entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])),
    );
  }
  return counts;
}

/**
 * @param {string} query
 * @returns {string[]} lower-cased whitespace-separated terms
 */
export function searchTerms(query) {
  return query.toLowerCase().split(/\s+/u).filter((term) => term.length > 0);
}

/**
 * @param {FindingRow} row
 * @param {FacetSelections} selections
 * @returns {boolean}
 */
export function matchesFacets(row, selections) {
  if (selections.diffClass.size > 0 && !selections.diffClass.has(row.diffClass)) {
    return false;
  }
  if (selections.project.size > 0 && !selections.project.has(row.project)) {
    return false;
  }
  if (selections.rule.size > 0 && !selections.rule.has(ruleFacetValue(row))) {
    return false;
  }
  if (selections.kind.size > 0 && !selections.kind.has(row.kind)) {
    return false;
  }
  return selections.confidence.size === 0 || selections.confidence.has(row.confidenceBucket);
}

/**
 * @param {FindingRow} row
 * @param {string[]} terms from {@link searchTerms}
 * @returns {boolean} every term appears in the row's searchable text
 */
export function matchesSearch(row, terms) {
  return terms.every((term) => row.haystack.includes(term));
}

/**
 * Combined visibility predicate for the findings surface.
 *
 * @param {FacetSelections} selections
 * @param {string} query
 * @param {ReadonlySet<string>} hidden hidden locator keys
 * @param {boolean} showHidden
 * @returns {(row: FindingRow) => boolean}
 */
export function rowPredicate(selections, query, hidden, showHidden) {
  const terms = searchTerms(query);
  return (row) => {
    if (!showHidden && hidden.has(row.key)) {
      return false;
    }
    return matchesFacets(row, selections) && matchesSearch(row, terms);
  };
}
