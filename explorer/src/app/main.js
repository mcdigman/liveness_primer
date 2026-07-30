// Application controller: wiring between the framework-neutral modules and
// the semantic HTML shell (explorer contract §7-§11).
//
// Every report-derived string is inserted with text-safe DOM APIs; nothing
// untrusted ever reaches innerHTML, URLs, styles, or handlers (§14.1).
// Generated links come only from the validated permalink module.

import { abbreviateDigest, sha256Hex } from '../lib/digest.js';
import {
  NO_RULE_ID,
  emptyFilters,
  filterRows,
  optionCounts,
} from '../lib/filters.js';
import { buildMarkdownSummary } from '../lib/markdown.js';
import {
  buildReviewRows,
  confidenceText,
  occurrenceSpanText,
  rowSpanText,
} from '../lib/projection.js';
import {
  buildReviewSession,
  dispositionOf,
  emptyReviewState,
  serializeReviewSession,
  stateFromSession,
  validateReviewSession,
} from '../lib/review.js';
import { rawFileUrl } from '../lib/permalink.js';
import { SourceFileCache } from '../lib/sourcefetch.js';
import { sortRows, SORT_KEYS } from '../lib/sorting.js';
import {
  clearReview,
  loadReview,
  loadTheme,
  saveReview,
  saveTheme,
} from '../lib/storage.js';
import {
  NOTE_LIMIT,
  REPORT_BYTE_LIMIT,
  WORKER_BYTE_THRESHOLD,
  validateReport,
} from '../lib/validate.js';

const PAGE_SIZE = 200;

/** @type {ReturnType<typeof initialState>} */
let app = initialState();

function initialState() {
  return {
    report: /** @type {import('../lib/validate.js').Report | null} */ (null),
    reportSha256: '',
    fileName: '',
    rows: /** @type {import('../lib/projection.js').ReviewRow[]} */ ([]),
    rowByKey: new Map(),
    rowOrder: new Map(),
    filters: emptyFilters(),
    sortKey: /** @type {import('../lib/sorting.js').SortKey} */ ('report'),
    sortDescending: false,
    page: 0,
    selectedKey: /** @type {string | null} */ (null),
    review: emptyReviewState(),
    reviewCreatedAt: /** @type {string | null} */ (null),
    storageHealthy: true,
    sourceCache: new SourceFileCache(),
    worker: /** @type {Worker | null} */ (null),
  };
}

/** @param {string} id */
function byId(id) {
  const element = document.getElementById(id);
  if (element === null) throw new Error(`missing element #${id}`);
  return element;
}

/**
 * @param {string} tag
 * @param {{ className?: string, text?: string, id?: string }} [options]
 */
function el(tag, options = {}) {
  const element = document.createElement(tag);
  if (options.className !== undefined) element.className = options.className;
  if (options.text !== undefined) element.textContent = options.text;
  if (options.id !== undefined) element.id = options.id;
  return element;
}

/** @param {string} message */
function announce(message) {
  byId('status').textContent = message;
}

/** @param {string} message */
function announceAlert(message) {
  byId('alert').textContent = message;
}

function nowIso() {
  return new Date().toISOString();
}

// ---------------------------------------------------------------- theme

function applyTheme(theme) {
  if (theme === 'system') {
    delete document.documentElement.dataset.theme;
  } else {
    document.documentElement.dataset.theme = theme;
  }
}

function initTheme() {
  const select = /** @type {HTMLSelectElement} */ (byId('theme-select'));
  const stored = loadTheme(localStorage);
  select.value = stored;
  applyTheme(stored);
  select.addEventListener('change', () => {
    const theme = /** @type {'system' | 'light' | 'dark'} */ (select.value);
    applyTheme(theme);
    saveTheme(localStorage, theme);
  });
}

// ---------------------------------------------------------------- import

function resetImportFeedback() {
  byId('import-errors').hidden = true;
  byId('import-errors-list').replaceChildren();
  byId('import-progress').hidden = true;
}

/** @param {import('../lib/jsonschema.js').SchemaError[]} errors */
function showImportErrors(errors) {
  resetImportFeedback();
  const box = byId('import-errors');
  box.hidden = false;
  byId('import-errors-summary').textContent =
    `The selected file is not a valid report; the previously loaded report, if any, is unchanged. ${errors.length} problem(s):`;
  const list = byId('import-errors-list');
  for (const error of errors.slice(0, 20)) {
    list.append(el('li', { text: `${error.path}: ${error.message}` }));
  }
  announceAlert('Report rejected; see the error list.');
}

/**
 * @param {string} text
 * @returns {Promise<{ ok: boolean, errors: import('../lib/jsonschema.js').SchemaError[],
 *   report: import('../lib/validate.js').Report | null }>}
 */
function validateInWorker(text) {
  return new Promise((resolve) => {
    const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
    app.worker = worker;
    worker.addEventListener('message', (event) => {
      worker.terminate();
      app.worker = null;
      resolve(event.data);
    });
    worker.addEventListener('error', () => {
      worker.terminate();
      app.worker = null;
      resolve({ ok: false, errors: [{ path: '$', message: 'validation failed in the worker' }], report: null });
    });
    worker.postMessage(text);
  });
}

/** @param {File} file */
async function importReport(file) {
  resetImportFeedback();
  // The byte limit is enforced from File.size before any content is read.
  if (file.size > REPORT_BYTE_LIMIT) {
    showImportErrors([
      { path: '$', message: `the file is ${file.size} bytes; the limit is ${REPORT_BYTE_LIMIT} bytes` },
    ]);
    return;
  }
  const progress = byId('import-progress');
  progress.hidden = false;
  byId('import-progress-text').textContent = `Validating ${file.name}…`;
  let cancelled = false;
  const cancel = byId('import-cancel');
  const onCancel = () => {
    cancelled = true;
    if (app.worker !== null) {
      app.worker.terminate();
      app.worker = null;
    }
    progress.hidden = true;
    announce('Report import cancelled.');
  };
  cancel.addEventListener('click', onCancel, { once: true });
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (cancelled) return;
    const digest = await sha256Hex(bytes, crypto.subtle);
    /** @type {string} */
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      showImportErrors([{ path: '$', message: 'the file is not valid UTF-8' }]);
      return;
    }
    let outcome;
    if (bytes.byteLength >= WORKER_BYTE_THRESHOLD && typeof Worker !== 'undefined') {
      outcome = await validateInWorker(text);
    } else {
      /** @type {unknown} */
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        showImportErrors([{ path: '$', message: 'the file is not valid JSON' }]);
        return;
      }
      outcome = await validateReport(parsed, crypto.subtle);
    }
    if (cancelled) return;
    if (!outcome.ok || outcome.report === null) {
      showImportErrors(outcome.errors);
      return;
    }
    activateReport(outcome.report, digest, file.name);
  } finally {
    cancel.removeEventListener('click', onCancel);
    progress.hidden = true;
  }
}

/**
 * @param {import('../lib/validate.js').Report} report
 * @param {string} digest
 * @param {string} fileName
 */
function activateReport(report, digest, fileName) {
  const rows = buildReviewRows(report);
  app = { ...initialState(), report, reportSha256: digest, fileName, rows };
  app.rowByKey = new Map(rows.map((row) => [row.locatorKey, row]));
  app.rowOrder = new Map(rows.map((row, index) => [row.locatorKey, index]));
  const restored = loadReview(localStorage, { reportSha256: digest, rowOrder: app.rowOrder });
  if (restored.state !== null) {
    app.review = restored.state;
    app.reviewCreatedAt = restored.createdAt;
  }
  document.querySelector('main')?.classList.add('loaded');
  byId('report-identity').hidden = false;
  byId('report-filename').textContent = fileName;
  byId('report-digest-abbrev').textContent = abbreviateDigest(digest);
  byId('open-another').hidden = false;
  byId('export-jump').hidden = false;
  for (const id of ['summary-region', 'filters-region', 'findings-region', 'export-region']) {
    byId(id).hidden = false;
  }
  byId('details-region').hidden = true;
  renderSummary();
  renderFilters();
  renderFindings();
  renderReviewProgress();
  announce(`Report ${fileName} loaded: ${rows.length} displayed finding diff(s).`);
}

// ---------------------------------------------------------------- summary

/**
 * @param {HTMLElement} list
 * @param {string} term
 * @param {string} value
 */
function fact(list, term, value) {
  list.append(el('dt', { text: term }), el('dd', { text: value }));
}

function totalsText(totals) {
  return (
    `${totals.new} new, ${totals.dropped} dropped, ${totals.changed} changed ` +
    `(${totals.changed_confidence} confidence, ${totals.changed_message_only} message-only)`
  );
}

function rollupLabel(rollup) {
  return rollup.rule_id === null ? `kind:${rollup.kind ?? ''}` : rollup.rule_id;
}

function renderSummary() {
  const report = app.report;
  if (report === null) return;
  const manifest = report.manifest;
  const banners = byId('banners');
  banners.replaceChildren();
  if (report.truncated) {
    const banner = el('p', { className: 'banner error' });
    const total = report.totals.new + report.totals.dropped + report.totals.changed;
    banner.textContent =
      `Incomplete finding detail: this report is truncated. ${app.rows.length} diff(s) are displayed ` +
      `of ${total} in the complete comparison. Counts and dispositions apply to displayed findings only.`;
    banners.append(banner);
  }
  if (!manifest.comparable) {
    banners.append(
      el('p', {
        className: 'banner',
        text: 'This run is not comparable (escape-hatch detector commands); gating semantics do not apply.',
      }),
    );
  }
  if (!manifest.isolation_enforced) {
    banners.append(
      el('p', {
        className: 'banner',
        text: 'Isolation was NOT ENFORCED for this run: build/analysis ran without a network sandbox.',
      }),
    );
  }
  const errorCount = report.projects.reduce((count, project) => count + project.errors.length, 0);
  const warningCount = report.projects.reduce(
    (count, project) => count + project.integrity_warnings.length + project.source_warnings.length,
    0,
  );
  if (errorCount > 0) {
    banners.append(el('p', { className: 'banner error', text: `${errorCount} detector invocation error(s); see run details.` }));
  }
  if (warningCount > 0) {
    banners.append(el('p', { className: 'banner', text: `${warningCount} corpus-integrity or source warning(s); see run details.` }));
  }
  const facts = byId('summary-facts');
  facts.replaceChildren();
  fact(facts, 'detector', manifest.tool);
  if (manifest.detector_repo !== null) fact(facts, 'repository', manifest.detector_repo);
  if (manifest.base !== null) fact(facts, 'base', `${manifest.base.ref} @ ${manifest.base.sha.slice(0, 12)}`);
  if (manifest.head !== null) fact(facts, 'head', `${manifest.head.ref} @ ${manifest.head.sha.slice(0, 12)}`);
  fact(facts, 'created', manifest.created_at);
  fact(facts, 'report schema', report.schema_version);
  fact(facts, 'explorer version', document.documentElement.dataset.explorerVersion ?? 'development');
  fact(facts, 'comparable', manifest.comparable ? 'yes' : 'no');
  fact(facts, 'isolation', manifest.isolation_enforced ? 'enforced' : 'NOT ENFORCED');
  fact(facts, 'complete totals', totalsText(report.totals));
  fact(facts, 'displayed findings', String(app.rows.length));
  const rollups = byId('summary-rollups');
  rollups.replaceChildren(el('h2', { text: 'Complete run rollups' }));
  const list = el('ul');
  for (const rollup of report.rollups) {
    list.append(el('li', { text: `${rollup.diff_class} ${rollupLabel(rollup)}: ${rollup.count}` }));
  }
  if (report.rollups.length === 0) list.append(el('li', { text: '(none)' }));
  rollups.append(list);
  const details = byId('run-details-facts');
  details.replaceChildren();
  fact(details, 'platform', String(manifest.platform));
  fact(details, 'python', String(manifest.python_version));
  if (manifest.base_cmd !== null) fact(details, 'base command', manifest.base_cmd.join(' '));
  if (manifest.head_cmd !== null) fact(details, 'head command', manifest.head_cmd.join(' '));
  for (const pin of manifest.corpus_pins) {
    fact(details, `pin ${pin.name}`, `${pin.repo} @ ${pin.resolved_sha}`);
  }
  for (const project of report.projects) {
    fact(details, `project ${project.project}`, `${totalsText(project.totals)}${project.truncated ? ' (truncated)' : ''}`);
    for (const error of project.errors) {
      fact(details, `error [${project.project}/${error.side}]`, error.detail);
    }
    for (const warning of project.integrity_warnings) {
      fact(details, `corpus-integrity [${project.project}]`, warning.detail);
    }
    for (const warning of project.source_warnings) {
      fact(details, `source warning [${project.project}]`, warning);
    }
  }
}

// ---------------------------------------------------------------- filters

const disposition = (row) => dispositionOf(app.review, row.locatorKey);

/**
 * @param {string} title
 * @param {'projects' | 'classes' | 'rules' | 'kinds' | 'changedFields' | 'dispositions'} dimension
 * @param {Array<{ value: string, label: string }>} options
 * @param {Map<string, number>} counts
 */
function filterGroup(title, dimension, options, counts) {
  const fieldset = el('fieldset');
  fieldset.append(el('legend', { text: title }));
  for (const option of options) {
    const wrapper = el('div', { className: 'filter-option' });
    const input = /** @type {HTMLInputElement} */ (el('input'));
    input.type = 'checkbox';
    input.id = `filter-${dimension}-${options.indexOf(option)}`;
    input.checked = app.filters[dimension].has(option.value);
    input.addEventListener('change', () => {
      if (input.checked) {
        app.filters[dimension].add(option.value);
      } else {
        app.filters[dimension].delete(option.value);
      }
      app.page = 0;
      renderFilters();
      renderFindings();
    });
    const label = el('label', { text: option.label });
    label.htmlFor = input.id;
    const count = el('span', { className: 'count', text: ` (${counts.get(option.value) ?? 0})` });
    wrapper.append(input, label, count);
    fieldset.append(wrapper);
  }
  return fieldset;
}

function renderFilters() {
  const groups = byId('filter-groups');
  groups.replaceChildren();
  const rows = app.rows;
  const unique = (values) => [...new Set(values)].sort();
  const projectOptions = unique(rows.map((row) => row.project)).map((value) => ({ value, label: value }));
  const classOptions = ['new', 'dropped', 'changed'].map((value) => ({ value, label: value }));
  const ruleOptions = unique(rows.map((row) => row.ruleId ?? NO_RULE_ID)).map((value) => ({
    value,
    label: value === NO_RULE_ID ? 'No rule ID' : value,
  }));
  const kindOptions = unique(rows.map((row) => row.kind)).map((value) => ({ value, label: value }));
  const fieldOptions = ['line-span', 'message', 'confidence', 'rule'].map((value) => ({ value, label: value }));
  const dispositionOptions = ['expected', 'unexpected', 'unreviewed'].map((value) => ({ value, label: value }));
  const count = (dimension, values) => optionCounts(rows, app.filters, dimension, values, disposition);
  groups.append(
    filterGroup('Project', 'projects', projectOptions, count('projects', (row) => [row.project])),
    filterGroup('Diff class', 'classes', classOptions, count('classes', (row) => [row.diffClass])),
    filterGroup('Rule', 'rules', ruleOptions, count('rules', (row) => [row.ruleId ?? NO_RULE_ID])),
    filterGroup('Kind', 'kinds', kindOptions, count('kinds', (row) => [row.kind])),
    filterGroup('Changed field', 'changedFields', fieldOptions, count('changedFields', (row) => row.changedFields)),
    filterGroup('Review disposition', 'dispositions', dispositionOptions, count('dispositions', (row) => [disposition(row)])),
  );
}

function readConfidenceFilter() {
  app.filters.confidence = {
    active: /** @type {HTMLInputElement} */ (byId('confidence-active')).checked,
    side: /** @type {import('../lib/filters.js').ConfidenceSide} */ (
      /** @type {HTMLSelectElement} */ (byId('confidence-side')).value
    ),
    min: Number(/** @type {HTMLInputElement} */ (byId('confidence-min')).value) || 0,
    max: Number(/** @type {HTMLInputElement} */ (byId('confidence-max')).value) || 100,
    includeNa: /** @type {HTMLInputElement} */ (byId('confidence-na')).checked,
    includeRange: /** @type {HTMLInputElement} */ (byId('confidence-range')).checked,
  };
}

// ---------------------------------------------------------------- findings

function displayedRows() {
  const filtered = filterRows(app.rows, app.filters, disposition);
  return sortRows(filtered, app.sortKey, app.sortDescending, disposition);
}

/** @param {import('../lib/projection.js').ReviewRow} row */
function locationCell(row) {
  const cell = el('td');
  const label = `${row.path}:${rowSpanText(row)}`;
  const url = row.diffClass === 'new' ? row.headSourcePermalink : row.baseSourcePermalink;
  if (url === null) {
    cell.textContent = label;
  } else {
    const link = /** @type {HTMLAnchorElement} */ (el('a', { text: label }));
    link.href = url;
    link.rel = 'noopener noreferrer';
    link.target = '_blank';
    cell.append(link);
  }
  return cell;
}

/** @param {'expected' | 'unexpected' | 'unreviewed'} value */
function reviewBadge(value) {
  const symbol = value === 'expected' ? '✓' : value === 'unexpected' ? '⚑' : '·';
  return el('span', { className: `review-badge ${value}`, text: `${symbol} ${value}` });
}

/** @param {import('../lib/projection.js').ReviewRow} row */
function classBadge(row) {
  return el('span', { className: `class-badge ${row.diffClass}`, text: `${{ new: '+', dropped: '-', changed: '~' }[row.diffClass]} ${row.diffClass}` });
}

function renderFindings() {
  const report = app.report;
  if (report === null) return;
  const sorted = displayedRows();
  const pages = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  if (app.page >= pages) app.page = pages - 1;
  const pageRows = sorted.slice(app.page * PAGE_SIZE, (app.page + 1) * PAGE_SIZE);
  byId('findings-count').textContent =
    `${sorted.length} of ${app.rows.length} displayed findings match the active filters.`;
  const body = byId('findings-body');
  body.replaceChildren();
  for (const row of pageRows) {
    const tr = el('tr');
    if (row.locatorKey === app.selectedKey) tr.className = 'selected';
    const classCell = el('td');
    classCell.append(classBadge(row));
    tr.append(classCell);
    tr.append(el('td', { text: row.ruleId ?? '-' }));
    tr.append(el('td', { text: confidenceText(row) }));
    tr.append(el('td', { text: row.kind }));
    tr.append(el('td', { text: row.project }));
    tr.append(locationCell(row));
    tr.append(el('td', { text: row.reference.message }));
    const reviewCell = el('td');
    reviewCell.append(reviewBadge(disposition(row)));
    tr.append(reviewCell);
    const detailsCell = el('td');
    const button = el('button', { text: 'Details' });
    button.setAttribute('aria-label', `Details for ${row.path} line ${row.locator.line}`);
    button.addEventListener('click', () => {
      app.selectedKey = row.locatorKey;
      renderFindings();
      renderDetails(true);
    });
    detailsCell.append(button);
    tr.append(detailsCell);
    body.append(tr);
  }
  byId('page-status').textContent = `Page ${app.page + 1} of ${pages}`;
  /** @type {HTMLButtonElement} */ (byId('page-previous')).disabled = app.page === 0;
  /** @type {HTMLButtonElement} */ (byId('page-next')).disabled = app.page >= pages - 1;
  announce(`${sorted.length} of ${app.rows.length} displayed findings match.`);
  if (app.selectedKey !== null && !sorted.some((row) => row.locatorKey === app.selectedKey)) {
    // Filtering removed the selected row: close its detail view without
    // moving focus to the top of the page (explorer §8.6).
    app.selectedKey = null;
    byId('details-region').hidden = true;
  }
}

// ---------------------------------------------------------------- details

/**
 * @param {HTMLElement} container
 * @param {string} label
 * @param {import('../lib/projection.js').Occurrence} occurrence
 * @param {string | null} permalink
 * @param {import('../lib/projection.js').ReviewRow} row
 */
function sourceBlock(container, label, occurrence, permalink, row) {
  container.append(el('p', { className: 'source-label', text: label }));
  if (permalink !== null) {
    const link = /** @type {HTMLAnchorElement} */ (el('a', { text: 'Open pinned source on GitHub' }));
    link.href = permalink;
    link.rel = 'noopener noreferrer';
    link.target = '_blank';
    const paragraph = el('p');
    paragraph.append(link);
    container.append(paragraph);
  }
  const excerpt = occurrence.source_excerpt;
  if (excerpt === null) {
    container.append(el('p', { className: 'hint', text: 'No embedded source excerpt was collected for this side.' }));
  } else {
    const view = el('div', { className: 'source-view' });
    const pre = el('pre');
    for (let index = 0; index < excerpt.lines.length; index += 1) {
      const lineNumber = excerpt.start_line + index;
      const inSpan = lineNumber >= occurrence.start_line && lineNumber <= occurrence.end_line;
      const line = el('div', { className: inSpan ? 'source-line highlight' : 'source-line' });
      const marker = inSpan ? '▶' : ' ';
      line.append(el('span', { className: 'lineno', text: `${marker}${lineNumber}` }));
      line.append(document.createTextNode(excerpt.lines[index]));
      pre.append(line);
    }
    view.append(pre);
    container.append(view);
    if (excerpt.omitted_lines > 0) {
      container.append(
        el('p', {
          className: 'hint',
          text: `${excerpt.omitted_lines} reported-span line(s) omitted by the evidence budget.`,
        }),
      );
    }
  }
  const pin = app.report?.manifest.corpus_pins.find((candidate) => candidate.name === row.project);
  if (pin !== undefined && rawFileUrl(pin, row.path) !== null) {
    const load = el('button', { text: `Load complete pinned file (${label})` });
    const output = el('div');
    load.addEventListener('click', async () => {
      load.disabled = true;
      announce('Loading complete pinned file…');
      const outcome = await app.sourceCache.fetch(pin, row.path, fetch.bind(globalThis));
      load.disabled = false;
      output.replaceChildren();
      if (!outcome.ok) {
        output.append(el('p', { className: 'hint', text: `Complete file unavailable (${outcome.reason}); the embedded excerpt above remains the evidence.` }));
        announce('Complete pinned file failed to load.');
        return;
      }
      const fileView = el('div', { className: 'source-view' });
      const filePre = el('pre');
      const lines = outcome.text.split('\n');
      /** @type {HTMLElement | null} */
      let target = null;
      for (let index = 0; index < lines.length; index += 1) {
        const lineNumber = index + 1;
        const inSpan = lineNumber >= occurrence.start_line && lineNumber <= occurrence.end_line;
        const line = el('div', { className: inSpan ? 'source-line highlight' : 'source-line' });
        line.append(el('span', { className: 'lineno', text: `${inSpan ? '▶' : ' '}${lineNumber}` }));
        line.append(document.createTextNode(lines[index]));
        filePre.append(line);
        if (inSpan && target === null) target = line;
      }
      fileView.append(filePre);
      output.append(fileView);
      announce('Complete pinned file loaded.');
      target?.scrollIntoView({ block: 'center' });
    });
    container.append(load, output);
  }
}

/** @param {boolean} moveFocus */
function renderDetails(moveFocus) {
  const region = byId('details-region');
  const key = app.selectedKey;
  if (key === null) {
    region.hidden = true;
    return;
  }
  const row = app.rowByKey.get(key);
  if (row === undefined) {
    region.hidden = true;
    return;
  }
  region.hidden = false;
  const content = byId('details-content');
  content.replaceChildren();
  const heading = el('div');
  heading.append(classBadge(row));
  heading.append(el('span', { text: ` ${row.path}:${rowSpanText(row)}` }));
  content.append(heading);
  const facts = el('dl', { className: 'facts' });
  fact(facts, 'project', `${row.project} (${row.repository})`);
  fact(facts, 'tool', row.tool);
  fact(facts, 'rule ID', row.ruleId ?? '-');
  fact(facts, 'kind', row.kind);
  fact(facts, 'symbol', row.symbol ?? '-');
  fact(facts, 'identity', `${row.locator.identity.slice(0, 12)}…`);
  fact(facts, 'locator', `${row.project} · L${row.locator.line} · occurrence ${row.locator.occurrence}`);
  fact(facts, 'confidence', confidenceText(row));
  fact(
    facts,
    'changed fields',
    row.changedFields.length === 0 ? '- (unchanged)' : row.changedFields.join(', '),
  );
  const base = row.baseOccurrence;
  const head = row.headOccurrence;
  if (base !== null && head !== null) {
    fact(facts, 'base span / message', `${occurrenceSpanText(base)} — ${base.message}`);
    fact(facts, 'head span / message', `${occurrenceSpanText(head)} — ${head.message}`);
    fact(facts, 'base confidence', base.confidence === null ? 'NA' : `${base.confidence}%`);
    fact(facts, 'head confidence', head.confidence === null ? 'NA' : `${head.confidence}%`);
    fact(facts, 'base rule', base.rule_id ?? '-');
    fact(facts, 'head rule', head.rule_id ?? '-');
  } else {
    fact(facts, 'message', row.reference.message);
  }
  content.append(facts);
  const moved =
    base !== null && head !== null && (base.start_line !== head.start_line || base.end_line !== head.end_line);
  if (row.diffClass === 'new' && head !== null) {
    sourceBlock(content, 'head source', head, row.headSourcePermalink, row);
  } else if (moved && base !== null && head !== null) {
    sourceBlock(content, 'base source', base, row.baseSourcePermalink, row);
    sourceBlock(content, 'head source', head, row.headSourcePermalink, row);
  } else if (base !== null) {
    sourceBlock(content, 'source', base, row.baseSourcePermalink, row);
  }
  const reviewSet = el('fieldset');
  reviewSet.append(el('legend', { text: 'Review disposition' }));
  const current = disposition(row);
  for (const option of ['expected', 'unexpected']) {
    const wrapper = el('div', { className: 'filter-option' });
    const input = /** @type {HTMLInputElement} */ (el('input'));
    input.type = 'radio';
    input.name = 'disposition';
    input.id = `disposition-${option}`;
    input.checked = current === option;
    input.addEventListener('change', () => {
      setDisposition(row, /** @type {'expected' | 'unexpected'} */ (option));
    });
    const label = el('label', { text: option });
    label.htmlFor = input.id;
    wrapper.append(input, label);
    reviewSet.append(wrapper);
  }
  const clear = el('button', { text: 'Clear disposition (mark unreviewed)' });
  clear.addEventListener('click', () => {
    app.review.dispositions.delete(row.locatorKey);
    persistReview();
    renderFindings();
    renderDetails(false);
    renderReviewProgress();
    announce('Disposition cleared; the finding is unreviewed.');
  });
  reviewSet.append(clear);
  content.append(reviewSet);
  const noteLabel = el('label', { text: `Review note (up to ${NOTE_LIMIT} characters, optional)` });
  noteLabel.htmlFor = 'note-input';
  const note = /** @type {HTMLTextAreaElement} */ (el('textarea'));
  note.id = 'note-input';
  note.rows = 3;
  note.maxLength = NOTE_LIMIT;
  note.value = app.review.notes.get(row.locatorKey) ?? '';
  note.addEventListener('change', () => {
    if (note.value === '') {
      app.review.notes.delete(row.locatorKey);
    } else {
      app.review.notes.set(row.locatorKey, note.value.slice(0, NOTE_LIMIT));
    }
    persistReview();
    renderReviewProgress();
  });
  content.append(noteLabel, note);
  if (moveFocus) {
    region.focus();
  }
}

/**
 * @param {import('../lib/projection.js').ReviewRow} row
 * @param {'expected' | 'unexpected'} value
 */
function setDisposition(row, value) {
  app.review.dispositions.set(row.locatorKey, value);
  persistReview();
  renderFindings();
  renderDetails(false);
  renderReviewProgress();
  announce(`Marked ${value}.`);
}

// ---------------------------------------------------------------- review

function sessionMeta() {
  const report = app.report;
  return {
    schemaVersion: report === null ? '1.1.0' : report.schema_version,
    reportSha256: app.reportSha256,
    reportSchemaVersion: report === null ? '' : report.schema_version,
    createdAt: app.reviewCreatedAt ?? nowIso(),
    updatedAt: nowIso(),
  };
}

function persistReview() {
  const meta = sessionMeta();
  if (app.reviewCreatedAt === null) app.reviewCreatedAt = meta.createdAt;
  const saved = saveReview(localStorage, app.review, app.rows, meta);
  if (!saved.ok && app.storageHealthy) {
    app.storageHealthy = false;
    announceAlert(
      'Review state could not be saved to browser storage; it remains in memory only. Download the review JSON to keep it.',
    );
  }
  if (saved.ok && !app.storageHealthy) {
    app.storageHealthy = true;
  }
  renderStorageBanner();
}

function renderStorageBanner() {
  const existing = document.getElementById('storage-banner');
  if (app.storageHealthy) {
    existing?.remove();
    return;
  }
  if (existing !== null) return;
  const banner = el('p', { className: 'banner error', id: 'storage-banner' });
  banner.textContent =
    'Browser storage is unavailable: review state lives in memory only and is lost on reload. Use the JSON and Markdown downloads.';
  byId('export-region').prepend(banner);
}

function renderReviewProgress() {
  const total = app.rows.length;
  let expected = 0;
  let unexpected = 0;
  for (const row of app.rows) {
    const value = disposition(row);
    if (value === 'expected') expected += 1;
    if (value === 'unexpected') unexpected += 1;
  }
  byId('review-progress').textContent =
    `${unexpected} unexpected, ${expected} expected, ${total - expected - unexpected} unreviewed ` +
    `of ${total} displayed finding(s).`;
}

/**
 * @param {string} name
 * @param {string} text
 * @param {string} type
 */
function download(name, text, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = /** @type {HTMLAnchorElement} */ (el('a'));
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function markdownSummary() {
  const report = app.report;
  if (report === null) return '';
  const manifest = report.manifest;
  const errorCount = report.projects.reduce((count, project) => count + project.errors.length, 0);
  const warningCount = report.projects.reduce(
    (count, project) => count + project.integrity_warnings.length + project.source_warnings.length,
    0,
  );
  return buildMarkdownSummary(app.rows, app.review, {
    generatedAt: nowIso(),
    reportSha256: app.reportSha256,
    reportSchemaVersion: report.schema_version,
    detectorRepo: manifest.detector_repo,
    baseSha: manifest.base?.sha ?? null,
    headSha: manifest.head?.sha ?? null,
    comparable: manifest.comparable,
    isolationEnforced: manifest.isolation_enforced,
    errorCount,
    warningCount,
    truncated: report.truncated,
    selectionCount: null,
  });
}

function initExport() {
  byId('export-json').addEventListener('click', () => {
    const session = buildReviewSession(app.review, app.rows, sessionMeta());
    download(`review-${abbreviateDigest(app.reportSha256)}.json`, serializeReviewSession(session), 'application/json');
    announce('Review JSON downloaded.');
  });
  byId('download-markdown').addEventListener('click', () => {
    const markdown = markdownSummary();
    /** @type {HTMLTextAreaElement} */ (byId('markdown-fallback')).value = markdown;
    download(`review-${abbreviateDigest(app.reportSha256)}.md`, markdown, 'text/markdown');
    announce('Markdown summary downloaded.');
  });
  byId('copy-markdown').addEventListener('click', async () => {
    const markdown = markdownSummary();
    /** @type {HTMLTextAreaElement} */ (byId('markdown-fallback')).value = markdown;
    try {
      await navigator.clipboard.writeText(markdown);
      announce('Markdown summary copied to the clipboard.');
    } catch {
      announce('Clipboard unavailable; the summary is shown below for manual copying.');
      /** @type {HTMLTextAreaElement} */ (byId('markdown-fallback')).focus();
    }
  });
  byId('session-import').addEventListener('change', async (event) => {
    const input = /** @type {HTMLInputElement} */ (event.target);
    const file = input.files?.item(0);
    input.value = '';
    if (file === null || file === undefined || app.report === null) return;
    /** @type {unknown} */
    let parsed = null;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      announceAlert('The review file is not valid JSON; local review is unchanged.');
      return;
    }
    const outcome = validateReviewSession(parsed, {
      reportSha256: app.reportSha256,
      rowOrder: app.rowOrder,
    });
    if (!outcome.ok || outcome.session === null) {
      announceAlert(
        `Review import failed (${outcome.errors[0]?.message ?? 'invalid session'}); local review is unchanged.`,
      );
      return;
    }
    const hasLocal = app.review.dispositions.size > 0;
    if (hasLocal) {
      const replace = window.confirm(
        `Replace the local review (${app.review.dispositions.size} entr(ies)) with the imported review ` +
          `(${outcome.session.entries.length} entr(ies))? Choosing Cancel keeps the local review.`,
      );
      if (!replace) {
        announce('Kept the local review.');
        return;
      }
    }
    app.review = stateFromSession(outcome.session);
    app.reviewCreatedAt = outcome.session.created_at;
    persistReview();
    renderFindings();
    renderDetails(false);
    renderReviewProgress();
    announce(`Imported ${outcome.session.entries.length} review entr(ies).`);
  });
  byId('clear-review').addEventListener('click', () => {
    if (!window.confirm('Delete the locally stored review for this report? Downloaded files are not affected.')) {
      return;
    }
    clearReview(localStorage, app.reportSha256);
    app.review = emptyReviewState();
    app.reviewCreatedAt = null;
    renderFindings();
    renderDetails(false);
    renderReviewProgress();
    announce('Local review cleared.');
  });
}

// ---------------------------------------------------------------- wiring

function init() {
  initTheme();
  byId('report-input').addEventListener('change', (event) => {
    const input = /** @type {HTMLInputElement} */ (event.target);
    const file = input.files?.item(0);
    input.value = '';
    if (file !== null && file !== undefined) {
      void importReport(file);
    }
  });
  byId('open-another').addEventListener('click', () => {
    byId('import-region').scrollIntoView();
    byId('report-input').focus();
  });
  const sortSelect = /** @type {HTMLSelectElement} */ (byId('sort-select'));
  for (const key of SORT_KEYS) {
    const option = /** @type {HTMLOptionElement} */ (el('option', { text: key === 'report' ? 'Report order' : key }));
    option.value = key;
    sortSelect.append(option);
  }
  sortSelect.addEventListener('change', () => {
    app.sortKey = /** @type {import('../lib/sorting.js').SortKey} */ (sortSelect.value);
    app.page = 0;
    renderFindings();
  });
  byId('sort-descending').addEventListener('change', (event) => {
    app.sortDescending = /** @type {HTMLInputElement} */ (event.target).checked;
    renderFindings();
  });
  byId('search-input').addEventListener('input', (event) => {
    app.filters.search = /** @type {HTMLInputElement} */ (event.target).value;
    app.page = 0;
    renderFindings();
  });
  for (const id of ['confidence-active', 'confidence-side', 'confidence-min', 'confidence-max', 'confidence-na', 'confidence-range']) {
    byId(id).addEventListener('change', () => {
      readConfidenceFilter();
      app.page = 0;
      renderFilters();
      renderFindings();
    });
  }
  byId('filters-reset').addEventListener('click', () => {
    app.filters = emptyFilters();
    /** @type {HTMLInputElement} */ (byId('search-input')).value = '';
    /** @type {HTMLInputElement} */ (byId('confidence-active')).checked = false;
    /** @type {HTMLInputElement} */ (byId('confidence-na')).checked = true;
    /** @type {HTMLInputElement} */ (byId('confidence-range')).checked = true;
    /** @type {HTMLInputElement} */ (byId('confidence-min')).value = '0';
    /** @type {HTMLInputElement} */ (byId('confidence-max')).value = '100';
    app.page = 0;
    renderFilters();
    renderFindings();
    announce('Filters reset; canonical report order restored. Review state is unchanged.');
  });
  byId('page-previous').addEventListener('click', () => {
    app.page = Math.max(0, app.page - 1);
    renderFindings();
  });
  byId('page-next').addEventListener('click', () => {
    app.page += 1;
    renderFindings();
  });
  byId('details-close').addEventListener('click', () => {
    app.selectedKey = null;
    byId('details-region').hidden = true;
    byId('findings-region').focus();
  });
  initExport();
}

init();
