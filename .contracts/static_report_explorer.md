# Static report explorer contract for `liveness_primer`

Status: proposed replacement.

This contract defines the browser interface for reviewing a completed
`liveness_primer` JSON report. [`initial_contract.md`](initial_contract.md) remains
authoritative for the runner, diff engine, provenance, identities, and locator semantics.
[`human_readable_reporting.md`](human_readable_reporting.md) remains authoritative for rule
IDs, rollups, source evidence, links, sanitization, and reference-side presentation.

The visual references are:

- [dashboard and export view](../design/mockups/static-report-explorer-dashboard-v2-final.png);
- [finding context view](../design/mockups/static-report-explorer-finding-context-v2-final.png).

They are authoritative for information hierarchy, density, region placement, and interaction
model. Exact fonts, pixels, and colors may vary when required for accessibility or browser
compatibility.

## 1. Product goal

The explorer turns an already-computed report into a desktop engineering workbench. It does
not run a detector, recompute a diff, or decide whether a finding is correct.

A reviewer must be able to:

- open a local report without uploading it;
- see what changed across the detector revisions and which projects are affected;
- search, filter, group, sort, select, and hide findings;
- inspect base/head analyzer output and pinned source evidence for one finding;
- preserve local selection and hidden state for the same report; and
- export the selected findings as Markdown or a versioned JSON review record.

The findings are the primary content. Provenance and operational warnings remain prominent,
but they must not displace the findings into a narrow mobile-style column on a laptop.

## 2. Application shape

### 2.1 Desktop workbench

The loaded-report view fills the browser viewport and has four persistent regions:

```text
+--------------------------------------------------------------------------+
| report header, search, open-report action, and theme                     |
+--------------+--------------------------------------+--------------------+
| filters      | findings toolbar and grouped table  | export summary or  |
|              |                                      | finding context    |
|              | only this primary region scrolls     |                    |
+--------------+--------------------------------------+--------------------+
```

At ordinary laptop widths, the application header and side regions remain in place while the
central findings region scrolls. The document body must not scroll during normal review.
Side regions may acquire their own contained scroll only when their content exceeds the
viewport.

The central region receives the available width and height. It must not be constrained by a
page-style maximum width or surrounded by large decorative margins.

### 2.2 Header

The compact header contains:

- `liveness primer` and `Report explorer`;
- imported filename and abbreviated SHA-256 digest;
- search over path, symbol, message, rule, and kind;
- `Open report`; and
- light, dark, or system theme selection.

Importing a replacement report is atomic: an invalid replacement leaves the current report
and workspace intact.

### 2.3 Filter rail

The left rail provides collapsible facets for:

- diff class;
- project;
- rule ID, with a clear no-rule value;
- kind; and
- confidence, including unavailable confidence.

Every option has a visible count. `Reset all` clears filters without clearing selected or
hidden state. Facet counts are full-report counts unless explicitly labelled as filtered; the
toolbar separately reports the current visible count.

### 2.4 Findings region

The findings toolbar shows:

- displayed and report finding counts;
- base and head detector revisions;
- complete new, dropped, and changed totals;
- grouping control;
- `Show hidden findings`; and
- sorting control, including exact report order.

Project is the default grouping. The grouped view shows the project repository and pin,
base/head finding totals, diff totals, and the most important report-provided rollups. Groups
can be collapsed. Grouping by rule and an ungrouped view may also be offered.

Each finding row presents, in this order:

```text
diff class | rule | confidence | kind | location | message | export | hide
```

Diff class uses both glyph and text: `+ New`, `- Dropped`, and `~ Changed`. Changed confidence
or other paired values show base and head values rather than collapsing them into one value.
The row remains compact enough to compare findings across projects.

Selecting a row opens finding context in the right region without resetting filters,
group expansion, selection, or central scroll position.

### 2.5 Right region

With no finding open, the right region is the export summary. It shows the selected count,
selected counts per project, export actions, and a short statement that workspace state is
stored locally.

With a finding open, it shows:

- location, class, rule, confidence, message, project, kind, symbol, and serialized locator;
- labelled base and head analyzer values;
- the report's source excerpt with real line numbers and a highlighted reported span;
- pinned-source and optional complete-file actions; and
- whether the finding is selected for export and visible or hidden.

The context view closes back to the export summary. Source text is always selectable and
copyable.

### 2.6 Responsive behavior

The three-region workbench is the default at a content width of 1,200 CSS pixels or greater.
At intermediate widths, the finding context may overlay the right side while filters and the
findings table remain visible. At smaller widths the filters may become a drawer.

The interface must not switch to a stacked card application at an ordinary laptop width.
Only genuinely narrow viewports may replace the table with a compact list. At 200% zoom,
controls remain operable and the central findings surface remains the primary content.

Dark presentation follows the visual references. A complete light theme is also required.
Color is never the only representation of class, selection, hidden state, warning, or error.

## 3. Report status

The explorer must not make an unsafe or incomplete comparison look routine. Before or beside
the findings toolbar, it displays persistent, concise status for:

- non-comparability or unenforced isolation;
- report or project truncation;
- detector errors and corpus/source warnings; and
- non-detector environment deltas.

Details may open in a secondary panel, but the existence and severity of these conditions
must be visible without opening it. Complete report totals and rollups are labelled as such;
counts derived from displayed, filtered, selected, or hidden rows are not presented as
complete-run values.

## 4. Thin-client boundary

### 4.1 Python owns report semantics

The Python models and generated JSON Schema are the source of truth. The browser presents
their serialized result; it is not a second implementation of the report model.

The browser must not independently reconstruct or certify:

- finding identities or diff classification;
- base/head occurrence pairing;
- canonical occurrence ordering;
- finding locators;
- complete totals, rollups, or truncation semantics;
- source-excerpt correctness; or
- Pydantic cross-field model validators.

If the UI needs a semantic value that is absent from the report, the Python model and exported
schema must be extended to carry it. Reimplementing the Python algorithm in JavaScript is not
an acceptable shortcut.

Direct presentation operations are permitted: indexing projects and pins by their declared
name, choosing already-defined reference-side values, normalizing text for search, deriving
visible facet counts, and ordering rows through the selected grid control.

### 4.2 Serialized locators

`FindingDiff` gains an additive `locator: FindingLocator` field. Python computes it while
assembling the canonical report, using the existing locator and reference-side semantics.
The browser treats it as opaque structured data.

```text
FindingLocator:
    project: str
    identity: str
    line: int
    occurrence: int
```

The locator is unique within a report. Python tests cover duplicate occurrences and all diff
classes. Browser selection, hiding, inspection, persistence, and export reference this
serialized locator; browser code must not calculate the occurrence ordinal.

### 4.3 Structural validation

Every imported report is untrusted input. Before rendering report-derived text, the browser
must validate the complete parsed value against the bundled `report.schema.json` matching the
supported schema version.

Validation is provided by Ajv, a maintained, standards-conforming JSON Schema library.
The schema is compiled during the build into a bundled validator compatible with the
production Content Security Policy. A custom JSON Schema interpreter is prohibited.

Malformed JSON, unsupported schema versions, and schema failures prevent activation and
produce bounded path-based errors. Structural validation establishes that the browser can
safely consume the document; it does not claim to reproduce every Python semantic validator
or certify that a hand-authored document could have been emitted by `liveness_primer`.

Small, direct defensive checks may prevent a misleading or broken view, but they must be
documented as UI preconditions rather than grow into a parallel report verifier. A semantic
invariant needed by both producers and consumers belongs in the Python model or exported
schema wherever expressible.

## 5. Grid and component dependencies

The implementation uses maintained libraries for general frontend infrastructure rather than
rebuilding it in project code. React and Tabulator have been identified as suitable libraries.

In particular:

- JSON Schema validation uses the library boundary in §4.3;
- the findings surface uses a maintained data-grid or grouped-table library providing row
  grouping, sorting, keyboard behavior, and bounded rendering or virtualization; and
- a component library or framework may own component rendering and shared application state.

A custom schema engine, custom virtualization engine, or hand-built general-purpose data grid
is out of scope. The project implementation should consist primarily of report-to-view
mapping, `liveness_primer`-specific presentation, workspace state, and export behavior.

Dependencies are bundled locally, pinned by a lock file, actively maintained, and
permissively licensed. Production loads no code, CSS, fonts, icons, or telemetry from a CDN.
The distribution includes required license notices.


## 6. Filtering, selection, and workspace state

Facet selections within one category are ORed; categories and text search are combined with
AND. Sorting and grouping never change finding identity or the serialized locator. Returning
to report order restores the serialized project and finding order.

Every finding has two independent workspace flags:

- `selected` means include it in review export;
- `hidden` removes it from the default findings view.

`Show hidden findings` reveals hidden rows without clearing their state. A hidden finding may
remain selected. Bulk actions operate only on explicitly selected rows and show the affected
count.

Workspace state is stored locally under the SHA-256 digest of the exact report bytes. A
byte-different report never inherits it. Storage failure leaves the in-memory workspace usable
and displays a persistent warning with immediate export actions.

The versioned JSON review record contains only:

```text
ExplorerReview:
    schema_version: str
    report_sha256: str
    selected: tuple[FindingLocator, ...]
    hidden: tuple[FindingLocator, ...]
```

Entries are unique and follow report order. The implementation supplies a Python model and
generated schema for this portable record rather than maintaining independent Python and
browser definitions. Importing review JSON is optional for v1; exporting it is required.

The Markdown export covers selected findings only and clearly states the selected count,
report digest, detector revisions, comparison safety/completeness state, and affected project
counts. Each finding includes class, project, rule or kind, confidence, message, symbol,
location, and pinned source link when available. The same bytes can be downloaded or copied.
Untrusted values are escaped as text and cannot create Markdown structure or link targets.

## 7. Source inspection

The baseline context view uses the `SourceExcerpt` already embedded in the report. It does not
parse `raw_excerpt` as source and does not require the network.

`Open pinned source` constructs the same deterministic HTTPS permalink defined by the
human-readable reporting contract from schema-validated repository, commit, path, and span
fields. An optional `Load complete file` action may fetch a raw GitHub file only after an
explicit user action and only from those values. It sends no credentials and renders the
response as text. Failure falls back to the embedded excerpt.

The browser does not host or cache complete source trees. Loaded complete files are bounded to
2 MiB and remain in memory for the active tab.

## 8. Static hosting, security, and privacy

The production application consists only of static HTML, CSS, JavaScript, images, schemas,
and license files. It works below a GitHub Pages repository subpath and needs no Python or Node
server at runtime.

Opening a local report makes no network request and never uploads report or review data. The
application has no analytics, advertising, remote logging, cookies, or telemetry. Optional
source loading is the only report-triggered network capability and requires the explicit
action in §7.

Report, source, filename, and review values are inserted only through text-safe APIs or
library renderers with equivalent guarantees. They never become raw HTML, CSS, script,
arbitrary URLs, dynamic imports, templates, or executable callbacks.

The production Content Security Policy disallows inline/evaluated scripts, framing, plugins,
form submission, and undeclared connection origins. All runtime assets come from the
application origin; the optional raw GitHub source origin is the only additional connection
origin.

Reports larger than 50 MiB are rejected before reading. Parsing and validation of realistic
large reports occur off the main thread so the shell remains responsive and cancelable. The
findings library must avoid rendering all rows of a large report simultaneously.

The Pages deployment builds only trusted default-branch code. Actions used by the deployment
workflow are pinned to immutable commit SHAs, and write permissions exist only in the deploy
job.

## 9. Accessibility and interaction quality

The explorer targets WCAG 2.2 AA. All workflows are keyboard operable, focus remains visible,
and selecting or filtering a row does not unexpectedly move focus. Native controls are used
where practical; the chosen grid must expose meaningful headers, rows, selection state, and
keyboard navigation to assistive technology.

Visible text accompanies semantic color and icons. Both themes meet text and non-text
contrast requirements. Reduced motion, forced colors, browser zoom, and increased text
spacing do not remove information or operation.

Loading, validation, result-count, persistence, clipboard, and source-fetch status is
announced without flooding assistive technology. Dialogs and overlay panels restore focus to
their invoking control.

## 10. Verification

CI runs formatting, linting, strict type checking, unit tests, browser tests, accessibility
scans, a production build, and static-subpath smoke tests. Project-authored production logic
follows the repository's line and branch coverage policy; library internals and generated
validators are not reimplemented merely to make them coverable.

Python tests establish:

- generated report and review schemas match their Pydantic models;
- every serialized finding has the correct unique locator; and
- locator behavior covers duplicate occurrences and new, dropped, and changed findings.

Frontend tests establish:

- library schema validation accepts a real generated report and rejects malformed,
  unsupported, and structurally invalid input;
- searching, facets, grouping, sorting, hiding, selection, persistence, and both exports use
  serialized report values and locators correctly;
- unsafe strings remain inert in the DOM and Markdown;
- storage, clipboard, and optional source failures preserve the active report; and
- no report load or row selection causes an unexpected network request.

Browser tests cover the two visual-reference states at 1,440 by 900 and 1,280 by 800 CSS
pixels, plus an intermediate and a narrow layout. They verify that only the findings region
scrolls in the desktop state, that opening context preserves its scroll position, and that
the workflow is usable by keyboard in both themes and at 200% zoom.

A representative large generated report verifies responsive filtering and bounded rendering.
Performance evidence distinguishes import/validation time from grid rendering time; no
portable millisecond threshold is asserted without a documented reference runner.

## 11. Acceptance criteria

Implementation is complete when:

1. The production app reproduces the visual references' desktop hierarchy and density at the
   two required laptop viewports.
2. The header and side regions remain stationary while the central findings surface scrolls.
3. A valid local report loads without upload or network access and exposes provenance,
   safety, completeness, errors, warnings, totals, and environment deltas.
4. Structural validation uses the bundled generated schema and a maintained JSON Schema
   validator; the project contains no custom schema interpreter.
5. Python serializes each unique `FindingLocator`; browser code does not recreate locator,
   identity, diff, rollup, truncation, or Pydantic validation algorithms.
6. Findings can be searched, filtered, grouped by project, sorted, selected, hidden, and
   restored to exact report order.
7. The project groups and finding rows expose the information shown in the visual references,
   including paired changed values.
8. Selecting a row opens base/head analyzer context and embedded pinned source evidence
   without changing central scroll or workspace state.
9. Selection and hidden state persist only for the exact report digest, survive storage
   failure in memory, and export through the generated review schema.
10. Selected findings download and copy as safe, useful Markdown, while review state downloads
    as versioned JSON.
11. The static bundle works from a GitHub Pages subpath, includes no remote runtime dependency
    or telemetry, and enforces its CSP without `unsafe-inline` or `unsafe-eval`.
12. Large reports remain bounded and responsive through off-main-thread import and a maintained
    virtualized or bounded-rendering findings library.
13. Keyboard, screen-reader, contrast, zoom, reduced-motion, forced-colors, and responsive
    browser checks pass in light and dark themes.
14. Required CI and deployment checks pass using pinned tooling and immutable deployment
    actions.
