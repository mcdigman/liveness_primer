// The grouped findings grid (explorer contract §2.4, §5), built on
// Tabulator: row grouping, bounded virtual rendering, and compact rows.
//
// All report-derived cell content is inserted through DOM nodes built with
// textContent — never markup. React owns the data flow: filtering,
// sorting, and workspace flags are computed outside. The visible row set
// is pushed with replaceData; workspace flag changes patch rows in place
// with updateData and the open-row highlight is a class toggle, so
// selection and context opening never move the central scroll position.

import { useCallback, useEffect, useRef } from 'react';
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
 * @property {(enable: boolean, keys: string[]) => void} onToggleAllVisible
 * @property {(key: string) => void} onOpenContext
 */

/**
 * @param {FindingRow[]} rows
 * @param {Workspace} workspace
 * @returns {object[]} Tabulator row data with current workspace flags
 */
function buildData(rows, workspace) {
  return rows.map((row) => ({
    ...row,
    ruleFacet: row.ruleValue ?? NO_RULE,
    selected: workspace.selected.has(row.key),
    hiddenFlag: workspace.hidden.has(row.key),
  }));
}

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
 * Tabulator's flat markup is not a conformant ARIA grid on its own: the
 * scrollable holder is a focusable generic and group headers are
 * row-less rowgroups. This presentation-only surgery re-roles those
 * elements so the exposed tree is grid > rowgroup > row > gridcell.
 *
 * @param {HTMLElement} container
 */
function applyAriaRepairs(container) {
  const holder = container.querySelector('.tabulator-tableholder');
  if (holder !== null) {
    holder.setAttribute('role', 'rowgroup');
  }
  for (const table of container.querySelectorAll('.tabulator-table')) {
    table.removeAttribute('role');
  }
  for (const group of container.querySelectorAll('.tabulator-group')) {
    group.setAttribute('role', 'row');
  }
  for (const arrow of container.querySelectorAll('.tabulator-arrow')) {
    arrow.setAttribute('aria-hidden', 'true');
  }
}

/**
 * @param {object} props
 * @param {FindingRow[]} props.rows visible rows in display order
 * @param {Projection} props.projection
 * @param {Workspace} props.workspace
 * @param {string | null} props.openKey
 * @param {'project' | 'rule' | 'none'} props.grouping
 * @param {(flag: 'selected' | 'hidden', key: string, enable: boolean) => void} props.onToggleFlag
 * @param {(enable: boolean, keys: string[]) => void} props.onToggleAllVisible select-all over the given row keys
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
  const openKeyRef = useRef(openKey);
  openKeyRef.current = openKey;
  const workspaceRef = useRef(workspace);
  const rowsRef = useRef(rows);
  rowsRef.current = rows;
  const groupingRef = useRef(grouping);
  groupingRef.current = grouping;
  // Collapsed group headers, keyed by group field and value so the state
  // survives sort, filter, and data replacement (which rebuild the groups).
  const collapsedGroupsRef = useRef(/** @type {Set<string>} */ (new Set()));
  const handlersRef = useRef(
    /** @type {TableHandlers} */ ({ projection, onToggleFlag, onToggleAllVisible, onOpenContext }),
  );
  handlersRef.current = { projection, onToggleFlag, onToggleAllVisible, onOpenContext };

  /** Keys of visible rows that are not under a collapsed group header. */
  const expandedRowKeys = useCallback(() => {
    const activeGrouping = groupingRef.current;
    if (activeGrouping === 'none') {
      return rowsRef.current.map((row) => row.key);
    }
    const field = activeGrouping === 'project' ? 'project' : 'ruleFacet';
    const collapsed = collapsedGroupsRef.current;
    return rowsRef.current
      .filter((row) => {
        const value = activeGrouping === 'project' ? row.project : (row.ruleValue ?? NO_RULE);
        return !collapsed.has(`${field}:${value}`);
      })
      .map((row) => row.key);
  }, []);

  /** Header select-all reflects the rows it would act on: expanded ones. */
  const syncHeaderCheckbox = useCallback(() => {
    const header = headerCheckboxRef.current;
    if (header === null) {
      return;
    }
    const keys = expandedRowKeys();
    const selectedCount = keys.filter((key) => workspaceRef.current.selected.has(key)).length;
    header.checked = keys.length > 0 && selectedCount === keys.length;
    header.indeterminate = selectedCount > 0 && selectedCount < keys.length;
  }, [expandedRowKeys]);

  // Reapply the recorded collapse state after Tabulator rebuilds its
  // groups, which recreates them expanded. Imperative show/hide is the
  // channel: a groupStartOpen callback is stored as the group's visibility
  // and only resolved lazily during element generation, leaving a function
  // where boolean checks read it as open in the meantime.
  const restoreCollapsedGroups = useCallback(() => {
    const table = tableRef.current;
    if (table === null || groupingRef.current === 'none') {
      return;
    }
    for (const group of table.getGroups()) {
      const shouldBeOpen = !collapsedGroupsRef.current.has(`${group.getField()}:${String(group.getKey())}`);
      if (group.isVisible() !== shouldBeOpen) {
        if (shouldBeOpen) {
          group.show();
        } else {
          group.hide();
        }
      }
    }
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (container === null) {
      return undefined;
    }
    /** @param {'selected' | 'hidden'} flag */
    const checkboxColumn = (flag) => ({
      title: flag === 'selected' ? 'Export' : 'Hide',
      field: flag === 'selected' ? 'selected' : 'hiddenFlag',
      // 84 fits the checkbox plus an unclipped "Export" title while the
      // default desktop widths still keep the Hide column visible.
      width: flag === 'selected' ? 84 : 52,
      hozAlign: /** @type {const} */ ('center'),
      responsive: flag === 'selected' ? 0 : 3,
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
      data: buildData(rowsRef.current, workspaceRef.current),
      layout: 'fitColumns',
      height: '100%',
      renderVertical: 'virtual',
      responsiveLayout: 'hide',
      placeholder: 'No findings match the current filters.',
      groupBy: 'project',
      groupToggleElement: 'header',
      // Tabulator accepts a DOM node from groupHeader at runtime; the
      // published typings only admit strings, hence the cast.
      groupHeader: /** @type {never} */ (
        /**
         * @param {unknown} value
         * @param {number} count
         */
        (value, count) => {
          const handlers = handlersRef.current;
          const wrapper = document.createElement('div');
          wrapper.className = 'group-header';
          wrapper.setAttribute('role', 'gridcell');
          const name = String(value);
          const view = handlers.projection.projectsByName.get(name);
          if (view === undefined) {
            wrapper.append(span(name, 'group-name'), span(`${count} findings`, 'group-counts'));
            return wrapper;
          }
          const model = projectHeaderModel(view);
          wrapper.append(
            span(name, 'group-name'),
            span(model.repoLine, 'group-repo'),
            span(model.countsLine, 'group-counts'),
          );
          for (const line of model.rollupLines) {
            wrapper.append(span(line, 'group-rollup'));
          }
          if (count !== view.report.diffs.length) {
            wrapper.append(span(`${count} of ${view.report.diffs.length} findings shown`, 'group-filtered'));
          }
          return wrapper;
        }
      ),
      columnDefaults: { headerSort: false, vertAlign: 'middle' },
      columns: [
        {
          title: 'Diff',
          field: 'diffClass',
          width: 86,
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
        { title: 'Rule', field: 'rule', width: 100, responsive: 2, cssClass: 'cell-mono' },
        { title: '%', field: 'confidence', width: 72, responsive: 2, cssClass: 'cell-mono' },
        { title: 'Kind', field: 'kind', width: 84, responsive: 4 },
        {
          title: 'Location',
          field: 'location',
          minWidth: 130,
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
          minWidth: 150,
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
          /** @param {import('tabulator-tables').CellComponent} _cell */
          titleFormatter: (_cell) => {
            const wrapper = document.createElement('span');
            wrapper.className = 'header-export';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.setAttribute('aria-label', 'Select all visible findings for export');
            input.addEventListener('click', (event) => event.stopPropagation());
            // Collapsed groups are excluded: the checkbox only flags rows
            // the user can currently see.
            input.addEventListener('change', () =>
              handlersRef.current.onToggleAllVisible(input.checked, expandedRowKeys()),
            );
            headerCheckboxRef.current = input;
            wrapper.append(input, span('Export', 'header-export-label'));
            return wrapper;
          },
        },
        checkboxColumn('hidden'),
        {
          title: 'Open',
          field: 'open',
          width: 42,
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
        const rowData = /** @type {{key: string, hiddenFlag: boolean}} */ (row.getData());
        const element = row.getElement();
        element.classList.toggle('row-hidden', Boolean(rowData.hiddenFlag));
        element.classList.toggle('row-open', rowData.key === openKeyRef.current);
      },
    });
    table.on('tableBuilt', () => {
      builtRef.current = true;
      applyAriaRepairs(container);
    });
    table.on('renderComplete', () => {
      if (builtRef.current) {
        applyAriaRepairs(container);
      }
    });
    table.on('groupVisibilityChanged', (group, visible) => {
      const key = `${group.getField()}:${String(group.getKey())}`;
      if (visible) {
        collapsedGroupsRef.current.delete(key);
      } else {
        collapsedGroupsRef.current.add(key);
      }
      syncHeaderCheckbox();
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
  }, [expandedRowKeys, syncHeaderCheckbox]);

  /** Run now when the table is built, otherwise once it is. */
  const whenBuilt = (/** @type {() => void} */ action) => {
    const table = tableRef.current;
    if (table === null) {
      return;
    }
    if (builtRef.current) {
      action();
    } else {
      table.on('tableBuilt', action);
    }
  };

  // Push the visible row set; replaceData preserves scroll (§2.4).
  const previousRowsRef = useRef(/** @type {FindingRow[] | null} */ (null));
  useEffect(() => {
    whenBuilt(() => {
      const table = tableRef.current;
      if (table === null) {
        return;
      }
      if (previousRowsRef.current !== rows) {
        previousRowsRef.current = rows;
        void table.replaceData(buildData(rows, workspace)).then(restoreCollapsedGroups);
      } else {
        // Same rows, changed workspace flags: patch rows in place so the
        // central scroll position never moves.
        const previous = workspaceRef.current;
        /** @type {{key: string, selected: boolean, hiddenFlag: boolean}[]} */
        const updates = [];
        for (const row of rows) {
          const selected = workspace.selected.has(row.key);
          const hiddenFlag = workspace.hidden.has(row.key);
          if (previous.selected.has(row.key) !== selected || previous.hidden.has(row.key) !== hiddenFlag) {
            updates.push({ key: row.key, selected, hiddenFlag });
          }
        }
        if (updates.length > 0) {
          void table.updateData(updates);
        }
      }
      workspaceRef.current = workspace;
      syncHeaderCheckbox();
    });
  }, [rows, workspace, syncHeaderCheckbox, restoreCollapsedGroups]);

  // The open-row highlight is a class toggle, not a data change.
  useEffect(() => {
    const container = containerRef.current;
    if (container === null || !builtRef.current) {
      return;
    }
    for (const element of container.querySelectorAll('.row-open')) {
      element.classList.remove('row-open');
    }
    if (openKey !== null) {
      const button = container.querySelector(`[data-context-button="${CSS.escape(openKey)}"]`);
      button?.closest('.tabulator-row')?.classList.add('row-open');
    }
  }, [openKey]);

  useEffect(() => {
    whenBuilt(() => {
      const table = tableRef.current;
      if (table === null) {
        return;
      }
      if (grouping === 'none') {
        table.setGroupBy(/** @type {never} */ (false));
      } else {
        table.setGroupBy(grouping === 'project' ? 'project' : 'ruleFacet');
        restoreCollapsedGroups();
      }
      syncHeaderCheckbox();
    });
  }, [grouping, restoreCollapsedGroups, syncHeaderCheckbox]);

  return <div className="findings-table" ref={containerRef} data-testid="findings-table" />;
}
