// The grouped findings grid (explorer contract §2.4, §5), built on
// Tabulator: row grouping, bounded virtual rendering, and compact rows.
//
// All report-derived cell content is inserted through DOM nodes built with
// textContent — never markup. React owns the data flow: filtering,
// sorting, and workspace flags are computed outside and pushed in through
// replaceData, which preserves the central scroll position.

import { useEffect, useMemo, useRef } from 'react';
import { TabulatorFull as Tabulator } from 'tabulator-tables';

import { DIFF_CLASS_PRESENTATION } from '../../lib/format.js';
import { NO_RULE, projectHeaderModel } from '../../lib/projection.js';

/** @typedef {import('../../lib/projection.js').FindingRow} FindingRow */
/** @typedef {import('../../lib/projection.js').Projection} Projection */
/** @typedef {import('../../lib/workspace.js').Workspace} Workspace */

/**
 * @typedef {object} TableHandlers
 * @property {Projection} projection
 * @property {(flag: 'selected' | 'hidden', key: string, enable: boolean) => void} onToggleFlag
 * @property {(enable: boolean) => void} onToggleAllVisible
 * @property {(key: string) => void} onOpenContext
 */

/**
 * @param {string} text
 * @param {string} className
 * @returns {HTMLSpanElement}
 */
function span(text, className) {
  const element = document.createElement('span');
  element.className = className;
  element.textContent = text;
  return element;
}

/**
 * @param {object} props
 * @param {FindingRow[]} props.rows visible rows in display order
 * @param {Projection} props.projection
 * @param {Workspace} props.workspace
 * @param {string | null} props.openKey
 * @param {'project' | 'rule' | 'none'} props.grouping
 * @param {(flag: 'selected' | 'hidden', key: string, enable: boolean) => void} props.onToggleFlag
 * @param {(enable: boolean) => void} props.onToggleAllVisible
 * @param {(key: string) => void} props.onOpenContext
 */
export function FindingsTable({
  rows,
  projection,
  workspace,
  openKey,
  grouping,
  onToggleFlag,
  onToggleAllVisible,
  onOpenContext,
}) {
  const containerRef = useRef(/** @type {HTMLDivElement | null} */ (null));
  const tableRef = useRef(/** @type {Tabulator | null} */ (null));
  const builtRef = useRef(false);
  const headerCheckboxRef = useRef(/** @type {HTMLInputElement | null} */ (null));
  const handlersRef = useRef(
    /** @type {TableHandlers} */ ({ projection, onToggleFlag, onToggleAllVisible, onOpenContext }),
  );
  handlersRef.current = { projection, onToggleFlag, onToggleAllVisible, onOpenContext };

  const data = useMemo(
    () =>
      rows.map((row) => ({
        ...row,
        ruleFacet: row.ruleValue ?? NO_RULE,
        selected: workspace.selected.has(row.key),
        hiddenFlag: workspace.hidden.has(row.key),
        open: row.key === openKey,
      })),
    [rows, workspace, openKey],
  );
  const dataRef = useRef(data);
  dataRef.current = data;

  useEffect(() => {
    const container = containerRef.current;
    if (container === null) {
      return undefined;
    }
    /** @param {'selected' | 'hidden'} flag */
    const checkboxColumn = (flag) => ({
      title: flag === 'selected' ? 'Export' : 'Hide',
      field: flag === 'selected' ? 'selected' : 'hiddenFlag',
      width: flag === 'selected' ? 88 : 64,
      hozAlign: /** @type {const} */ ('center'),
      responsive: flag === 'selected' ? 0 : 4,
      /** @param {import('tabulator-tables').CellComponent} cell */
      formatter: (cell) => {
        const rowData = /** @type {{key: string, location: string}} */ (cell.getRow().getData());
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.className = 'row-flag';
        input.checked = Boolean(cell.getValue());
        const verb = flag === 'selected' ? 'Select for export' : 'Hide';
        input.setAttribute('aria-label', `${verb}: ${rowData.location}`);
        input.addEventListener('click', (event) => event.stopPropagation());
        input.addEventListener('change', () => {
          handlersRef.current.onToggleFlag(flag, rowData.key, input.checked);
        });
        return input;
      },
    });
    const table = new Tabulator(container, {
      index: 'key',
      data: dataRef.current,
      layout: 'fitColumns',
      height: '100%',
      renderVertical: 'virtual',
      responsiveLayout: 'hide',
      placeholder: 'No findings match the current filters.',
      groupBy: 'project',
      groupToggleElement: 'header',
      /**
       * @param {unknown} value
       * @param {number} count
       */
      groupHeader: (value, count) => {
        const handlers = handlersRef.current;
        const wrapper = document.createElement('div');
        wrapper.className = 'group-header';
        const name = String(value);
        const view = handlers.projection.projectsByName.get(name);
        if (view === undefined) {
          wrapper.append(span(name, 'group-name'), span(`${count} findings`, 'group-counts'));
          return wrapper;
        }
        const model = projectHeaderModel(view);
        wrapper.append(span(name, 'group-name'), span(model.repoLine, 'group-repo'), span(model.countsLine, 'group-counts'));
        for (const line of model.rollupLines) {
          wrapper.append(span(line, 'group-rollup'));
        }
        if (count !== view.report.diffs.length) {
          wrapper.append(span(`${count} of ${view.report.diffs.length} findings shown`, 'group-filtered'));
        }
        return wrapper;
      },
      columnDefaults: { headerSort: false, vertAlign: 'middle' },
      columns: [
        {
          title: 'Diff',
          field: 'diffClass',
          width: 118,
          responsive: 0,
          /** @param {import('tabulator-tables').CellComponent} cell */
          formatter: (cell) => {
            const value = /** @type {import('../../lib/types.js').DiffClass} */ (cell.getValue());
            const presentation = DIFF_CLASS_PRESENTATION[value];
            const badge = document.createElement('span');
            badge.className = `diff-badge diff-${value}`;
            badge.append(span(presentation.glyph, 'diff-glyph'), span(presentation.label, 'diff-label'));
            return badge;
          },
        },
        { title: 'Rule', field: 'rule', width: 150, responsive: 2, cssClass: 'cell-mono' },
        { title: '%', field: 'confidence', width: 96, responsive: 3, cssClass: 'cell-mono' },
        { title: 'Kind', field: 'kind', width: 104, responsive: 5 },
        {
          title: 'Location',
          field: 'location',
          minWidth: 180,
          widthGrow: 2,
          responsive: 0,
          cssClass: 'cell-mono',
          /** @param {import('tabulator-tables').CellComponent} cell */
          formatter: (cell) => {
            const element = span(String(cell.getValue()), 'cell-location');
            element.title = String(cell.getValue());
            return element;
          },
        },
        {
          title: 'Message',
          field: 'message',
          minWidth: 200,
          widthGrow: 3,
          responsive: 0,
          /** @param {import('tabulator-tables').CellComponent} cell */
          formatter: (cell) => {
            const element = span(String(cell.getValue()), 'cell-message');
            element.title = String(cell.getValue());
            return element;
          },
        },
        {
          ...checkboxColumn('selected'),
          /** @param {import('tabulator-tables').ColumnComponent} _column */
          titleFormatter: (_column) => {
            const wrapper = document.createElement('span');
            wrapper.className = 'header-export';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.setAttribute('aria-label', 'Select all visible findings for export');
            input.addEventListener('click', (event) => event.stopPropagation());
            input.addEventListener('change', () => handlersRef.current.onToggleAllVisible(input.checked));
            headerCheckboxRef.current = input;
            wrapper.append(input, span('Export', 'header-export-label'));
            return wrapper;
          },
        },
        checkboxColumn('hidden'),
        {
          title: 'Open',
          field: 'open',
          width: 56,
          responsive: 0,
          /** @param {import('tabulator-tables').CellComponent} cell */
          formatter: (cell) => {
            const rowData = /** @type {{key: string, location: string}} */ (cell.getRow().getData());
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'context-open';
            button.textContent = '›';
            button.setAttribute('aria-label', `Open finding context: ${rowData.location}`);
            button.setAttribute('data-context-button', rowData.key);
            button.addEventListener('click', (event) => {
              event.stopPropagation();
              handlersRef.current.onOpenContext(rowData.key);
            });
            return button;
          },
        },
      ],
      /** @param {import('tabulator-tables').RowComponent} row */
      rowFormatter: (row) => {
        const rowData = /** @type {{hiddenFlag: boolean, open: boolean}} */ (row.getData());
        const element = row.getElement();
        element.classList.toggle('row-hidden', Boolean(rowData.hiddenFlag));
        element.classList.toggle('row-open', Boolean(rowData.open));
      },
    });
    table.on('tableBuilt', () => {
      builtRef.current = true;
    });
    table.on('rowClick', (event, row) => {
      const target = /** @type {HTMLElement} */ (event.target);
      if (target.closest('input, button, a') !== null) {
        return;
      }
      const rowData = /** @type {{key: string}} */ (row.getData());
      handlersRef.current.onOpenContext(rowData.key);
    });
    tableRef.current = table;
    return () => {
      builtRef.current = false;
      tableRef.current = null;
      table.destroy();
    };
  }, []);

  // Push data changes into the grid; replaceData preserves scroll (§2.4).
  useEffect(() => {
    const table = tableRef.current;
    if (table === null) {
      return;
    }
    /** @type {() => void} */
    const push = () => {
      void table.replaceData(data);
      const header = headerCheckboxRef.current;
      if (header !== null) {
        const selectedVisible = data.filter((row) => row.selected).length;
        header.checked = data.length > 0 && selectedVisible === data.length;
        header.indeterminate = selectedVisible > 0 && selectedVisible < data.length;
      }
    };
    if (builtRef.current) {
      push();
    } else {
      table.on('tableBuilt', push);
    }
  }, [data]);

  useEffect(() => {
    const table = tableRef.current;
    if (table === null) {
      return;
    }
    /** @type {() => void} */
    const apply = () => {
      if (grouping === 'none') {
        table.setGroupBy(/** @type {never} */ (false));
      } else {
        table.setGroupBy(grouping === 'project' ? 'project' : 'ruleFacet');
      }
    };
    if (builtRef.current) {
      apply();
    } else {
      table.on('tableBuilt', apply);
    }
  }, [grouping]);

  return <div className="findings-table" ref={containerRef} data-testid="findings-table" />;
}
