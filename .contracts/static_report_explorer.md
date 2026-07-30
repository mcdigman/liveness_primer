# Static report explorer contract for `liveness_primer`

Status: draft.

This document specifies the browser-based review surface for completed `liveness_primer`
reports. It depends on the approved, not-yet-implemented
[`human_readable_reporting.md`](human_readable_reporting.md) contract for report semantics,
rule IDs, aggregate rollups, source evidence, source permalinks, and sanitization. The
[`initial_contract.md`](initial_contract.md) remains authoritative for the runner, diff
engine, report provenance, trust model, and finding-locator semantics.

This contract is authoritative for static hosting, report import, interactive filtering,
finding inspection, expected/unexpected review state, review export, browser security,
accessibility, responsive layout, and light/dark presentation.

## 1. Purpose

The explorer turns an already-computed JSON report into an interactive review surface. It
does not run a detector, recompute a diff, or adjudicate whether a finding is correct.

A reviewer must be able to:

- load a report without sending it to an application server;
- understand the report's provenance, completeness, errors, and warnings;
- filter and sort findings by their structured fields;
- inspect the source evidence and exact pinned source location for a finding;
- mark findings as expected or unexpected, with optional notes;
- resume that review on the same browser;
- export the review as versioned JSON; and
- copy or download a concise Markdown summary suitable for a pull-request review.

The explorer must remain useful when JavaScript can access no network after the application
shell has loaded. Embedded report data and source excerpts are therefore the baseline review
experience; fetching a complete source file is an optional enhancement.

## 2. Scope and non-goals

### 2.1 Required scope

The v1 explorer is a client-side HTML5 application whose production output consists only of
static HTML, CSS, JavaScript, images, and license files. GitHub Pages is the reference host.
The same build output may be served from Read the Docs or any ordinary static web server.

The application supports one `Report` at a time. It consumes the versioned report JSON and
must not depend on a detector-specific raw-output format.

### 2.2 Non-goals

The v1 explorer does not:

- make Dash, Flask, Django, or any other application server a runtime dependency;
- require a Python process after the static assets have been built;
- run or import detector code, corpus code, hooks, or code found in an artifact;
- download GitHub Actions artifacts directly from the browser;
- publish, update, or comment on a pull request;
- provide shared or simultaneous multi-reviewer state;
- decide whether a finding is live, dead, a false positive, or a false negative;
- replace the text or GitHub report as the durable CI summary;
- replace the JSON report as the authoritative machine-readable result;
- host copies of complete corpus source trees;
- require a per-PR Pages deployment; or
- promise functional or visual parity with a future Dash wrapper.

The report projection, filtering, locator, permalink, and export logic must nevertheless be
implemented as framework-neutral, strictly typed modules rather than embedded in view event
handlers. A later host may reuse those modules without becoming a v1 compatibility target.

## 3. Architecture and trust boundary

### 3.1 Static application boundary

The deployed application shell is trusted project code. Every imported report, review
sidecar, detector-derived string, corpus-derived string, and remotely fetched source byte is
untrusted data.

The application has three layers:

```text
validated Report + ReviewSession
             |
             v
pure review projection, filtering, sorting, locators, and export
             |
             v
semantic HTML components and theme tokens
```

Report content must never select a module, component, template, callback, URL scheme,
stylesheet, script, or executable behavior. Tool, project, rule, kind, path, message,
symbol, note, and source values are data only.

### 3.2 Browser-only processing

Loading, validation, projection, filtering, review persistence, and export occur locally in
the reviewer's browser. The explorer must not upload a report, review state, or note to the
host or to a third party.

The application must make no network request merely because a report was loaded or a row was
selected. A network request is permitted only when the reviewer explicitly asks to load a
complete pinned source file as described in §9.3.

### 3.3 Framework and dependency policy

The implementation may use TypeScript and a browser UI library, but the delivered
application must not load code, fonts, styles, telemetry, or other assets from a public CDN.
All runtime assets are built and served from the explorer's own origin.

Frontend production dependencies must be few, actively maintained, pinned by a lock file,
and permissively licensed. Their required licenses and notices must ship with the static
distribution. Copyleft or source-available dependencies require explicit project approval.

TypeScript, when used, runs in strict mode. Production application code must not introduce
unbounded `any` or unchecked type assertions as substitutes for input validation.

## 4. Hosting and launch model

### 4.1 Reference deployment

GitHub Pages hosts one stable explorer application for the project, for example:

```text
https://OWNER.github.io/liveness_primer/explorer/
```

The build must work beneath a repository subpath and must use relative or build-time base
URLs for its own assets. It must not assume deployment at `/`.

The workflow that publishes the application uses trusted default-branch code. It does not
check out, build, import, or execute code from an untrusted pull request with a Pages write
token. Reports remain downloadable workflow artifacts and are opened locally by the stable
explorer.

### 4.2 Reviewer entry points

A detector PR's check summary may provide:

- the stable explorer URL;
- a link to the workflow run containing the JSON artifact; and
- optional instructions for downloading the artifact with the GitHub CLI.

The explorer itself accepts a local JSON file. Artifact authentication and download remain
GitHub's responsibility rather than being reimplemented in browser JavaScript.

### 4.3 Other static hosts

The identical static build may be included in Read the Docs output or served locally over an
ordinary loopback HTTP server. Host-specific code must not be required for core behavior.

The baseline application must not depend on service workers, installability, push
notifications, background synchronization, server rewrites, or history-API routing. These
features may be considered later without changing report or review-session semantics.

## 5. Report import and validation

### 5.1 Import surface

The empty state contains a native, keyboard-operable file input accepting `.json`. A
drag-and-drop target may enhance it but must not be the only import mechanism.

The application must state next to the input that the report is processed in the browser
and is not uploaded. It must not request a directory or broader filesystem access.

GitHub Actions ZIP archives are not a required v1 input. An unsupported ZIP produces an
instruction to extract and select the JSON report rather than an attempt to inspect arbitrary
archive entries.

### 5.2 Input limits

The following limits apply before a report becomes active:

| Resource | Limit |
| --- | ---: |
| report JSON bytes | 50 MiB |
| finding diffs | 100,000 |
| review-note length | 4,096 Unicode code points |
| remotely fetched source bytes | 2 MiB |

The local report-byte limit is enforced from `File.size` before any report content is read.
The remote source limit applies to decoded response-body bytes delivered to the application.
A source request may use an HTTP Range request when the server supports it; otherwise the
application reads the response as a stream and cancels it as soon as a delivered chunk
crosses the limit. Application-retained source buffering never exceeds the limit plus that
one delivered chunk, and excess bytes are discarded immediately. This contract does not
claim control over buffering internal to the browser or network stack.

A limit failure is explicit and does not leave a partially loaded report active.

Large JSON parsing and schema validation must not make controls appear operable while the UI
thread is blocked. Files of 5 MiB or larger are parsed and projected in a Web Worker or an
equivalent off-main-thread mechanism. A labelled progress state remains visible and
cancelable.

### 5.3 Structural and semantic validation

The explorer packages every `Report` JSON Schema version it claims to support. It validates
the complete input before rendering any report-derived field through two mandatory layers:

1. **Structural validation** applies the matching exported JSON Schema to types, required
   fields, enumerations, scalar bounds such as confidence and positive line numbers, unknown
   fields, and other constraints the schema actually expresses.
2. **Semantic validation** enforces cross-field, cross-item, and ordering invariants that
   exported JSON Schema does not express. Passing an AJV or equivalent schema check alone is
   not sufficient.

The structural layer:

- rejects malformed JSON;
- rejects a schema major version it does not support;
- rejects a schema minor version whose required semantics it does not implement; and
- accepts additive fields only when the applicable schema version permits them.

The semantic layer rejects at least:

- a finding or occurrence whose `end_line` precedes its `start_line`;
- a `FindingDiff` whose populated sides or `changed_fields` contradict its diff class, or
  whose `changed_fields` do not equal its changed observable occurrence fields;
- a finding identity that is not the specified digest of its tool, project, path, symbol,
  and kind;
- source evidence whose start, retained lines, or omitted-span count contradicts its
  occurrence or the human-readable reporting contract;
- duplicate corpus-pin names, duplicate project-report names, a project without exactly one
  matching pin, a diff whose project or tool contradicts its containing report, or a
  manifest selection/pin/project sequence that does not describe the same run;
- overall totals, project totals, rollups, or truncation state that contradict one another or
  the serialized findings to the extent that a truncated report permits verification; and
- duplicate finding locators or other violations of the §6 projection rules.

`ReviewSession` import applies the analogous two layers from §11: JSON Schema validation is
followed by report-digest matching, known and unique locator checks, canonical entry ordering,
and note limits. The checked-in semantic-validation fixtures are shared with Python so a
constraint enforced only by a Pydantic model validator cannot silently disappear in the
browser implementation.

All validation failures are reported as bounded structural paths and messages, never by
dumping the complete offending value into the DOM.

The application displays both its own version and the report schema version in the report
information surface.

### 5.4 Report digest

After the byte limit check and before parsing, the explorer computes the lowercase hex
SHA-256 digest of the exact imported report bytes using the Web Crypto API. The digest is the
report reference for local review state and exported review sessions.

Semantically equivalent but byte-different JSON documents intentionally have different
digests. The CI artifact is the canonical byte representation; the explorer does not rewrite
or silently canonicalize it.

### 5.5 Replacement and failure

Loading a second valid report replaces the active report only after the second report passes
validation. Failure leaves the current report and its review state intact.

A visible `Open another report` action returns to the importer. If review state could not be
persisted, the application warns before discarding the active report and offers JSON and
Markdown downloads.

## 6. Review projection and locators

### 6.1 Review rows

Each serialized `FindingDiff` becomes one `ReviewRow` carrying only these derived fields:

```text
locator
canonical_index
tool
project
repository
corpus_sha
diff_class
rule_id
kind
path
symbol
base_occurrence
head_occurrence
changed_fields
base_source_permalink: str | None
head_source_permalink: str | None
review_disposition
review_note
```

`canonical_index` is the finding's position in the serialized per-project diff sequence and
is used only to restore the report's canonical display order. It is not a persistent finding
identifier.

Repository and corpus SHA are joined from the unique `CorpusPinRecord` whose `name` equals
the project. A missing or ambiguous join is an invalid report.

### 6.2 Finding locators

Review state uses the initial contract's finding-locator semantics. A serialized locator has
this shape:

```text
project: str
identity: str
line: int
occurrence: int
```

`line` addresses the diff class's reference-side start line: head for `new`, base for
`dropped` and `changed`. To assign `occurrence`, take the subsequence of that same
`ProjectReport.diffs` tuple whose identity and reference-side start line equal
`(identity, line)`, without changing its serialized order. `occurrence` is the zero-based
position of the diff in that subsequence. Explorer filtering, sorting, pagination, and review
state never affect this value.

The serialized per-project diff sequence is the indexing set. Occurrences removed by the
diff engine's equal-occurrence intersection are not indexed because they are not finding
diffs and are absent from the report. Result truncation retains a canonical prefix, so the
indices of retained findings are unchanged from the complete canonical diff sequence.
That sequence uses the human-readable reporting contract's expanded canonical occurrence key,
including `rule_id` in its specified position.

This rule fixes the indexing set and zero-based convention left implicit by initial contract
§12. The `bisect --occurrence` implementation must consume the same report subsequence and
apply this identical rule. It must not index the detector side's complete pre-diff occurrence
multiset.

Locators are unique within one validated report. Duplicate computed locators are a validation
failure, because silently sharing one disposition between two displayed rows would corrupt
review state.

### 6.3 Reference and comparison values

The table's primary message, rule ID, confidence, line span, and source excerpt follow the
human-readable reporting contract's reference-side rules. A changed value additionally
exposes labelled base and head values in the details pane.

Filters operate on explicit base and head values rather than an undocumented combined value.
The projection must not collapse `None`, zero confidence, an empty string, and an absent side.

### 6.4 Incomplete reports

If `Report.truncated` or any `ProjectReport.truncated` is true, the explorer remains usable
but displays a persistent high-priority `Incomplete finding detail` banner. The banner gives
the displayed diff count and complete pre-truncation totals.

The explorer must not claim that all findings were reviewed when a report is truncated.
Every JSON or Markdown review export carries an explicit incompleteness warning. Filtering,
reviewed percentages, and disposition counts are labelled as applying to displayed findings.

Tool errors, corpus-integrity warnings, environment deltas, non-comparability, and unenforced
isolation likewise remain prominent and cannot be dismissed permanently.

## 7. Information architecture

### 7.1 Page regions

The loaded-report page uses these semantic landmarks in DOM order:

1. skip link;
2. application header;
3. report status and provenance summary;
4. filter controls;
5. findings results;
6. finding details and source evidence; and
7. review export controls.

The visual layout may place filters, findings, and details side by side on wide screens, but
CSS placement must not change the meaningful DOM or focus order.

### 7.2 Application header

The compact header contains:

- product and `Report explorer` names;
- `Open another report`;
- report filename and abbreviated digest;
- theme selector (`System`, `Light`, `Dark`); and
- a clearly labelled review-export action.

The header may be sticky. Sticky content must not obscure focused controls or anchored source
lines.

### 7.3 Report summary

The summary exposes, without opening another panel:

- detector name and repository;
- resolved base and head refs and SHAs;
- report creation time and schema version;
- comparable and isolation status;
- complete overall diff totals;
- complete overall rollups from the human-readable reporting contract;
- displayed and filtered finding counts;
- expected, unexpected, and unreviewed displayed counts; and
- report-level error, warning, and truncation states.

Detailed environment freezes, fetch records, settings, corpus pins, environment deltas, and
per-project totals remain available in an accessible disclosure labelled `Run details`.

### 7.4 Wide layout

At widths that comfortably support three regions, the preferred layout is:

```text
+----------------+------------------------------+-----------------------+
| filters        | findings                     | finding details       |
| and counts     | table                        | source and review      |
+----------------+------------------------------+-----------------------+
```

The findings region is the primary flexible column. Filter and detail panes have bounded
minimum and maximum widths and may be resized with buttons or an accessible separator whose
keyboard behavior follows the applicable WAI-ARIA pattern.

### 7.5 Narrow layout

At narrow widths, filters and details become ordinary in-flow sections or modal dialogs with
correct focus management. The findings table becomes a labelled card list when its minimum
columns cannot fit. It must not force the entire page to scroll horizontally.

Only source code, which intrinsically depends on preserved whitespace, may use a contained
horizontal scroll region. The surrounding interface reflows at 320 CSS pixels without loss
of information or operation.

## 8. Filtering, search, sorting, and navigation

### 8.1 Filter dimensions

The explorer supports these independent filters:

- project/repository;
- diff class (`new`, `dropped`, `changed`);
- detector rule ID, with an explicit `No rule ID` option;
- finding kind;
- confidence;
- changed field (`line-span`, `message`, `confidence`, `rule`);
- review disposition (`expected`, `unexpected`, `unreviewed`); and
- case-insensitive text search over path, symbol, normalized message, rule ID, and kind.

Selections within one dimension are ORed; active dimensions are ANDed. Empty selection in a
dimension means no restriction. Resetting filters restores the canonical report order and
does not clear review state.

### 8.2 Confidence filtering

Confidence filtering has an explicit side selector:

- `reference` applies the human-report reference-side value;
- `base` applies only the base occurrence;
- `head` applies only the head occurrence; and
- `either` matches when either occurrence satisfies the predicate.

The predicate supports an inclusive `0` through `100` range and a separate `NA` choice.
Absent occurrences do not count as `NA`; they do not match that side. A confidence change may
also be selected through the changed-field filter.

### 8.3 Counts and rollups

Every filter control shows its option counts relative to the other active filter dimensions.
The results heading announces `N of M displayed findings`, where `M` is the number serialized
in the report, not the complete pre-truncation total.

Approved report rollups remain labelled `Complete run rollups`. Any rollup recomputed from
the current filtered rows is labelled `Filtered displayed findings`. The two must never be
presented as interchangeable.

### 8.4 Sorting

Default sorting is project run order followed by each project's serialized canonical diff
order. The reviewer may sort by project, diff class, rule/kind, confidence, path, line, or
review disposition.

Every sort is stable, deterministic, and has an explicit ascending/descending label. Missing
values sort consistently after present values in ascending order. Returning to `Report order`
restores the canonical sequence exactly.

### 8.5 Result presentation

The default findings presentation uses a native HTML table with real column headers. The
minimum visible columns are:

```text
class | rule | % | kind | project | location | message | review
```

Symbol and changed fields may be columns at wide widths and labelled continuations at smaller
widths. Selecting a row opens the details pane; the location itself remains a conventional
link to pinned source.

Pagination is preferred to an ARIA data grid or inaccessible DOM virtualization. If an
interactive grid is used, it must fully implement the WAI-ARIA grid keyboard model, row and
column positions, selection state, focus restoration, and assistive-technology announcements.
Merely adding `role="grid"` to a table is forbidden.

### 8.6 Keyboard navigation and focus

All functions are available with a keyboard. Native tab order reaches filters, sorting,
finding links, review controls, source actions, and export controls.

After a row is activated, focus moves only when the reviewer explicitly opened the detail
view. Closing a modal detail view restores focus to the invoking row. Filtering that removes
the selected row closes its detail view and announces the updated result count without
moving focus to the top of the page.

No unmodified character key is captured globally. Optional shortcuts must be discoverable,
remappable or disableable, and inactive while a text field has focus.

## 9. Finding details and source inspection

### 9.1 Finding details

The details pane provides:

- visible diff-class glyph and name;
- project, repository, tool, rule ID, and kind;
- path, symbol, identity abbreviation, and locator;
- base and head line spans, messages, confidence, and rule IDs;
- explicit changed fields;
- source excerpts under the human-readable reporting contract's side rules;
- base and head pinned permalinks where applicable;
- expected/unexpected controls; and
- an optional review note.

Unchanged base/head fields may be shown once with an `unchanged` label. Changed values must
remain visually paired and screen-reader understandable; color alone must not identify which
side changed.

### 9.2 Embedded source evidence

The source pane always works from the report's retained `SourceExcerpt`. It displays real line
numbers, preserves source whitespace, highlights the reported span, and states the exact
number of omitted reported-span lines when positive.

For a moved `changed` finding, labelled base and head excerpts are both available and the
reviewer can switch or compare them. For unchanged line spans, the reference-side excerpt is
shown once.

Source text is inserted as text, never HTML. Syntax highlighting is optional; if provided,
it must operate on escaped text, preserve selection/copying, and meet the same contrast and
non-color requirements as the rest of the application.

### 9.3 Optional complete-file loading

A visible `Load complete pinned file` action may fetch the complete file only after an
explicit reviewer action. It is an enhancement, not a prerequisite for reviewing the
finding.

The action is present only when the joined corpus repository is a validated GitHub HTTPS
repository and the pin supplies a full commit SHA. For a non-GitHub ad-hoc project,
`base_source_permalink` and `head_source_permalink` are `None`, the action is absent, and the
embedded excerpt retains an escaped plain `path:Lx` or `path:Lx-Ly` location.

For a GitHub corpus repository, the request target is derived exclusively from the validated
corpus repository, full resolved commit SHA, and normalized POSIX path:

```text
https://raw.githubusercontent.com/OWNER/REPOSITORY/SHA/PATH
```

The implementation must:

- require HTTPS and the exact `raw.githubusercontent.com` origin;
- validate owner and repository names rather than copying an arbitrary report URL;
- require a full hexadecimal commit SHA;
- percent-encode each already-normalized path segment independently;
- reject empty, `.`, `..`, absolute, backslash-containing, or control-containing paths;
- send no credentials and use a no-referrer request policy;
- cancel promptly when delivered decoded bytes exceed the §5.2 source-byte limit and retain
  no more than that section permits;
- decode UTF-8 strictly;
- verify that the final response URL remains on the allowed origin;
- render the response only as text; and
- cache it in memory for the active browser tab only.

On success, the viewer scrolls the real file to the applicable span, gives the target lines a
non-color-only highlight, and retains the exact pinned GitHub permalink. On network, CORS,
size, decoding, or validation failure, it shows a bounded error and falls back to the embedded
excerpt and, when available, permalink. A non-GitHub project falls back to its plain relative
location rather than inventing a URL.

The application must not use an iframe for GitHub pages or raw source.

## 10. Review state

### 10.1 Meaning of dispositions

Every displayed finding has exactly one UI state:

- `unreviewed` — no review disposition has been recorded;
- `expected` — the reviewer believes this diff belongs in the intended blast radius; or
- `unexpected` — the reviewer believes this diff warrants attention in the detector PR.

These dispositions concern the expected blast radius of a detector change. They are not the
internal-corpus annotation verdicts `live`, `dead`, `no-coverage`, or `unknown`, and they must
not be stored in or translated into `Annotation`.

Clearing a disposition returns the finding to `unreviewed`. A note does not itself change the
disposition.

### 10.2 Interaction

Expected and unexpected controls are a labelled radio group or equivalent native control.
Their state is visible in both the result row and detail pane. Review controls remain usable
without opening the optional complete source file.

Bulk assignment may be offered for explicitly selected rows. It must show the exact selected
count, require confirmation when affecting more than one row, and never operate implicitly on
all filtered rows merely because a filter is active.

### 10.3 Local persistence

Review entries are saved automatically in browser storage under a key containing the report
SHA-256 digest. The imported report itself, its source excerpts, and fetched complete files
are not persisted by default.

Storage failure or quota exhaustion leaves in-memory review functional, displays a persistent
warning, and offers immediate JSON and Markdown downloads. The application must not claim a
save succeeded before the storage operation completes.

Theme preference is stored separately from review state. Filter, sort, selected-row, and pane
layout state may be session-local but are not part of the portable review record.

## 11. Review-session schema and export

### 11.1 Models

This contract adds `ReviewSession`, `ReviewEntry`, `ReviewDisposition`, and
`FindingLocator` to the versioned schema surface in initial contract §7. Pydantic models are
the source of truth and `review-session.schema.json` is exported with the other schemas.

The narrow serialized shapes are:

```text
ReviewDisposition = "expected" | "unexpected"

FindingLocator:
    project: str
    identity: str
    line: int
    occurrence: int

ReviewEntry:
    locator: FindingLocator
    disposition: ReviewDisposition
    note: str | None

ReviewSession:
    schema_version: SchemaVersion
    report_sha256: str
    report_schema_version: str
    created_at: datetime
    updated_at: datetime
    entries: tuple[ReviewEntry, ...]
```

`report_sha256` is exactly 64 lowercase hexadecimal characters. `line` is positive;
`occurrence` is non-negative. Notes contain at most 4,096 Unicode code points. Review entries
have unique locators and appear in canonical report order. Unreviewed findings are omitted.

The explorer sets `created_at` once for a report digest and updates `updated_at` whenever a
portable entry changes. Times are UTC RFC 3339 values. It does not add a reviewer identity
unless a future contract defines its privacy and provenance semantics.

### 11.2 JSON import and export

The reviewer can download the current `ReviewSession` as UTF-8 JSON and later import it beside
the matching report. Import requires schema validation and an exact report digest match.

An import with duplicate locators, unknown locators, a mismatched digest, an unsupported
schema version, or an overlong note fails atomically. It does not partially overwrite current
review state.

When valid imported state conflicts with local state, the explorer previews counts and asks
the reviewer to choose `Replace local review` or `Keep local review`. Silent merging is not
permitted in v1.

### 11.3 Markdown summary

The explorer can copy or download a Markdown summary. The default summary covers all reviewed
findings, independent of active filters. A separate `Export selected findings` action may be
provided but must label the resulting summary as partial and state the selection count.

The default summary contains, in order:

1. title and generation time;
2. report digest and schema version;
3. detector repository and resolved base/head SHAs;
4. comparable, isolation, error, warning, and truncation status;
5. expected, unexpected, and unreviewed displayed counts;
6. an `Unexpected` section;
7. an `Expected` section; and
8. a statement of any remaining unreviewed displayed findings.

Each reviewed finding line includes diff class, project, rule ID or kind fallback, normalized
message, symbol when present, and note when present. It uses a pinned source link when one is
available; otherwise it includes an escaped plain `path:Lx` or `path:Lx-Ly` location.
Unexpected findings appear before expected findings; each group retains canonical report
order.

The summary does not include raw detector records or complete source files. All untrusted
text is escaped for Markdown structure, control characters are removed or visibly replaced,
and generated links use only validated pinned permalinks. The plain-location fallback is text,
not a report-supplied link target. A note cannot create a heading, list item, link destination,
HTML block, or fenced block outside its assigned quoted text.

Clipboard success and failure are announced through a polite status region. If the Clipboard
API is unavailable or denied, the same bytes remain downloadable as `.md` and selectable in
a labelled plain-text control.

## 12. Visual design and theming

### 12.1 Design principles

The explorer is a dense engineering review tool, not a marketing dashboard. Its visual design
must be modern, calm, and legible:

- clear hierarchy rather than decorative chrome;
- restrained borders, radii, shadows, and elevation;
- compact but comfortable controls;
- consistent spacing based on a small token scale;
- system UI fonts for interface text and a readable monospace stack for source;
- sticky controls only where they improve orientation;
- no gradients, animated backgrounds, glass effects, or low-contrast placeholder text needed
  to understand state; and
- no animation that delays access to report content.

Cards may group report status and details, but finding rows remain visually comparable and do
not become a wall of unrelated cards on wide screens.

### 12.2 Theme model

The application supports `System`, `Light`, and `Dark` modes. `System` is the default and
follows `prefers-color-scheme`; it updates if the operating-system preference changes while
the application is open. An explicit light or dark choice overrides the system preference
and persists for the explorer origin.

The root declares support for both browser color schemes so native controls, scrollbars, and
form widgets match the active theme. Every component uses semantic CSS custom properties;
components must not hard-code theme-specific foreground or background values.

Required token roles include:

```text
canvas, surface, elevated-surface, border
text, muted-text, link, focus
new-foreground, new-background, new-border
dropped-foreground, dropped-background, dropped-border
changed-foreground, changed-background, changed-border
expected-foreground, expected-background, expected-border
unexpected-foreground, unexpected-background, unexpected-border
unreviewed-foreground, unreviewed-background, unreviewed-border
warning-foreground, warning-background, warning-border
error-foreground, error-background, error-border
selection-background, code-background, code-highlight
```

Both themes define and test every role. Dark mode is designed independently rather than
computed by mechanically inverting the light palette.

### 12.3 Finding highlighting

Diff classes use the human-report glyphs and visible labels:

- `+ New`, with a green semantic accent;
- `- Dropped`, with a red semantic accent; and
- `~ Changed`, with an amber or yellow semantic accent.

A class may tint its badge, leading row accent, and selected-source marker. The entire row
must not be saturated with class color. Glyph and visible label remain present in every theme,
in forced-colors mode, and when custom colors are unavailable.

Review disposition uses a separate visual vocabulary so it cannot be confused with diff
class:

- `Expected`, with a check symbol and blue or teal accent;
- `Unexpected`, with a flag or exclamation symbol and purple accent; and
- `Unreviewed`, with a neutral symbol and neutral accent.

Error and warning colors remain reserved for operational state. An unexpected review
disposition is not rendered as an application error.

### 12.4 Motion and state changes

Transitions are limited to short opacity, color, and size changes that aid continuity. They
must not exceed 200 ms for ordinary controls. Loading indicators do not flash faster than
accessibility guidance permits.

Under `prefers-reduced-motion: reduce`, nonessential animation and smooth scrolling are
disabled. Selecting a finding may scroll the contained source pane directly to a line but
must not animate the page unexpectedly.

## 13. Accessibility

### 13.1 Conformance target

The explorer targets WCAG 2.2 Level AA. Accessibility is a release requirement, not a theme
or optional mode.

In particular:

- color is never the only means of identifying a diff class, review disposition, selection,
  error, warning, changed value, or source span;
- ordinary text has a contrast ratio of at least 4.5:1 against its background;
- large text, where the WCAG definition applies, has a ratio of at least 3:1;
- focus indicators, stateful borders, icons, and graphical controls that convey information
  have at least 3:1 non-text contrast against adjacent colors;
- decorative row tints never reduce text or control contrast below those thresholds;
- every function is keyboard operable without timing requirements;
- focus remains visible and is not obscured by sticky regions or dialogs;
- content reflows at 320 CSS pixels except for the contained source-code scroll region;
- controls meet a 40 by 40 CSS pixel design target and never fall below the WCAG 2.2 AA
  minimum target size unless an explicit exception applies;
- browser zoom to 200 percent and text-spacing overrides do not clip content or controls;
- status changes are announced without moving focus; and
- labels, names, roles, values, descriptions, errors, and required state are programmatically
  determinable.

### 13.2 Semantic structure

The implementation prefers native HTML elements. It uses headings in order, real landmarks,
`button` for actions, `a` for navigation, `input`/`select`/`fieldset`/`legend` for filters and
dispositions, and `table`/`th`/`td` for ordinary tabular results.

ARIA supplements native semantics only when needed. Custom composite widgets must implement
the complete applicable WAI-ARIA Authoring Practices interaction model. A clickable `div`,
positive `tabindex`, or ARIA role used only to imitate appearance is forbidden.

Each details pane has a heading derived from safe structured fields, and each source region
has a visible side label and accessible name. Repeated controls include the applicable
finding location in their accessible description without producing an excessively verbose
visible label.

### 13.3 Focus and announcements

The page begins with a visible-on-focus skip link to findings. Dialogs trap focus only while
open, close with `Escape` unless a destructive confirmation is pending, and restore focus to
their invoker.

Import failures and security/validation failures use an assertive alert. Filter counts,
successful saves, copied summaries, and source-load results use a polite status region.
Repeated keystrokes must not flood the accessibility tree with one announcement per row.

### 13.4 Forced colors and user preferences

The explorer honors `forced-colors`, `prefers-contrast`, `prefers-reduced-motion`, and
`prefers-color-scheme` when supported. In forced-colors mode it uses system colors and
preserves borders, glyphs, labels, selection, and focus. `forced-color-adjust: none` is not
applied broadly to preserve brand or semantic colors.

Hover-only content is forbidden. Tooltips, when present, are also reachable on focus,
dismissible, hoverable, and nonessential to completing a review.

## 14. Browser security and privacy

### 14.1 DOM and injection safety

Report, source, and note strings are inserted with text-safe DOM APIs. Production code must
not pass them to `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, dynamic
script creation, inline event handlers, CSS text, URL-bearing style properties, `eval`, or
the `Function` constructor.

If a UI library exposes an HTML-escape bypass, unsafe renderer, raw-template directive, or
Markdown-to-HTML path, that feature is prohibited for all untrusted values.

Bidi controls, terminal controls, zero-width characters, overlong fields, Markdown
metacharacters, and strings resembling HTML or JSON closing tags must not change UI structure
or exported Markdown structure. The explorer preserves useful Unicode while making dangerous
control behavior inert and reviewable.

### 14.2 Links and URLs

Generated source links use only HTTPS GitHub repository information validated under the
report contract. They open with `noopener` and `noreferrer` behavior when a new browsing
context is used.

Report-supplied strings must not become arbitrary `href`, `src`, `style`, `download`, form
action, worker, import, or fetch targets. The filename of a downloaded export is generated
from trusted fixed text plus a digest abbreviation, not from an untrusted project or detector
name.

### 14.3 Content Security Policy

The production page supplies the strictest enforceable Content Security Policy compatible
with static hosting. At minimum it allows scripts, styles, fonts, images, and workers only
from the application origin, allows connections only to the application origin and the
optional raw GitHub source origin, and forbids plugins, child frames, base-URL changes, and
form submissions.

The implementation uses external bundled scripts and styles rather than `unsafe-inline` or
`unsafe-eval`. If a host can set response headers, it additionally prevents framing with the
applicable CSP directive. A meta-delivered policy does not claim to enforce directives that
the CSP standard requires in an HTTP response header.

### 14.4 Privacy

The explorer has no analytics, advertising SDK, error-reporting beacon, tracking pixel,
cookie, fingerprinting, or telemetry by default. It must not log report content, notes, or
source to a remote console.

Local review storage is explained in a short privacy disclosure and can be deleted through a
`Clear local review` action scoped to the active report. Clearing requires confirmation and
does not delete the user's downloaded files.

## 15. Performance and resilience

Filtering and sorting operate over the validated in-memory projection; they do not reparse
JSON or refetch source. Text-search normalization is computed once per row.

The interface remains responsive for the maximum accepted finding count through pagination,
incremental rendering, indexed filter values, workers, or other bounded techniques. It must
not create one persistent event listener per cell or render all 100,000 rows into the DOM at
once.

Changing a common filter on the representative large-report fixture must update visible
results within 200 ms at the 95th percentile after initial projection on a documented,
pinned reference browser and runner. A checked-in `benchmark-policy.md` beside that fixture
defines the runner, browser version, warmups, sample count, percentile calculation, tolerance,
rerun rule, and baseline-update procedure. CI reads that policy as its single source of truth.
Until the file exists and its baseline has been reviewed, CI reports the benchmark without
using it as a merge gate; an ordinary noisy CI sample is not itself a portable performance
baseline. Initial load performance is reported separately for parsing, validation,
projection, and first render so optimizations cannot hide a blocked stage.

A runtime error in optional complete-source loading, clipboard access, local storage, or a
nonessential enhancement must not discard the report or review entries. The UI offers a
bounded recovery action and preserves the baseline review surface.

## 16. Build and distribution

The production build is deterministic from the tracked source and lock file except for
declared build metadata. It emits content-hashed assets, a static entry page, the supported
schemas, and dependency license notices.

The build contains no development server, source-map URL pointing to a private host, test
fixture report, API credential, absolute developer path, or dependency fetched at page load.
Production source maps are either omitted or deliberately published after confirming they
contain no secrets or local paths.

Project-authored explorer source and assets are distributed under the repository's
Apache-2.0 license. Third-party code, fonts, icons, or other assets retain their own required
licenses and notices in the distribution; an asset without compatible, documented terms is
not included.

The static bundle is built and tested in CI before deployment. Deployment permissions exist
only in the deployment job and are not granted to ordinary PR test jobs.

## 17. Testing strategy

The frontend toolchain is pinned by its lock file and checked-in configuration. CI runs its
formatter check, linter with zero warnings, strict type checker, unit tests with coverage,
and browser tests. Hand-written production TypeScript and JavaScript in the framework-neutral
validation, projection, filtering, locator, persistence, and export modules must achieve full
line and branch coverage with non-vacuous tests. Generated files may be excluded by explicit
configuration; blanket directory, file, or branch exclusions for hand-written production
logic are forbidden. UI behavior that depends on browser APIs remains subject to the browser
and accessibility gates below rather than being treated as covered by a DOM mock alone.

### 17.1 Pure logic tests

Unit tests cover:

- report-schema acceptance and rejection;
- every supplemental semantic-validation invariant from §5.3;
- digest calculation over exact bytes;
- project-to-corpus-pin joins;
- reference-side values and finding locators;
- every filter dimension and their OR-within/AND-across composition;
- confidence-side and `NA` semantics;
- stable sorting and canonical-order restoration;
- complete versus filtered rollup labels;
- review-session validation, uniqueness, ordering, and digest matching;
- local-state failure behavior; and
- byte-exact JSON and Markdown exports.

Python generates a checked-in locator golden fixture containing report JSON and the exact
ordered `FindingLocator` sequence expected from it. Python tests, frontend tests, and the
future `bisect` tests consume the same fixture and assert the same ordered locator values.
Byte equality is required only for a serialization whose canonical UTF-8 JSON form is
specified; otherwise the assertion is exact structural sequence equality.

The fixture covers at least duplicate occurrences, `new`/`dropped`/`changed` candidates that
share an identity and line, identical reference occurrence keys that lead to different diff
classes, moved spans, missing and zero confidence, absent and present rule IDs, and a rule-ID
change. It is generated only by an explicit maintenance command; ordinary tests compare the
checked-in expected values rather than silently regenerating them.

### 17.2 Browser tests

Browser automation runs against current Chromium, Firefox, and WebKit engines and covers:

- keyboard-only import, filtering, row inspection, disposition, note, and export;
- focus order, restoration, visible focus, skip link, dialogs, and announcements;
- light, dark, system, reduced-motion, high-contrast, and forced-colors behavior;
- 320, 768, and 1440 CSS-pixel layouts at normal and 200-percent zoom;
- native-table and narrow card presentations;
- source excerpt display, moved-span comparison, complete-file success, and every fallback;
- clipboard denial and storage quota failure;
- truncated, non-comparable, error-bearing, and warning-bearing reports; and
- navigation and asset loading from a GitHub Pages-style repository subpath.

### 17.3 Accessibility verification

Automated accessibility scanning runs on the empty state, loaded summary, filtered findings,
open details, source comparison, review export dialog, and both themes. Automated results are
necessary but not sufficient.

Before the first release and after material interaction changes, a documented manual pass
covers at least one desktop screen reader/browser combination, VoiceOver with Safari,
keyboard-only use, 200-percent zoom, and a forced-colors or operating-system high-contrast
configuration.

Computed-style tests verify every semantic token pairing used in both themes against the
required text and non-text contrast ratios. Visual snapshots alone are not accepted as
contrast evidence.

### 17.4 Adversarial fixtures

Fixtures include malicious or pathological values containing:

- HTML, SVG, script, style, Markdown, and template syntax;
- `</script>` and event-handler strings;
- URL schemes other than HTTPS;
- absolute, traversal, backslash, percent-encoded, and control-containing paths;
- ANSI, OSC-8, bidi, combining, wide, zero-width, and invalid Unicode-related cases;
- duplicate identities and locators;
- missing and duplicate corpus-pin joins;
- large reports and oversized source responses; and
- notes attempting to escape their Markdown context.

Tests assert inert DOM structure, no unexpected network requests, no CSP violations, bounded
errors, and structurally valid exports.

## 18. Acceptance criteria

Implementation is complete only when all of the following are established.

1. The production build is static and works from a GitHub Pages repository subpath without a
   Python or Node server at runtime.
2. Loading a valid report performs no network request and displays its digest, schema,
   detector refs, totals, rollups, warnings, and completeness state.
3. Malformed, oversized, unsupported, structurally invalid, or semantically invalid reports
   fail before any report-derived HTML is rendered.
4. Project, repository, diff-class, rule, kind, confidence, changed-field, disposition, and
   text filters have non-vacuous tests and correct combined semantics.
5. Report-order restoration produces the exact serialized project/diff sequence.
6. `0` confidence, `NA` confidence, and an absent occurrence remain distinguishable in every
   applicable filter and details view.
7. Every review row resolves to one unique finding locator using the contract's reference-side
   and occurrence-index rules, and Python, frontend, and future bisect tests agree on the
   shared locator golden fixtures.
8. A truncated report cannot produce a UI or exported summary claiming the complete blast
   radius was reviewed.
9. New, dropped, and changed findings use green, red, and amber/yellow highlights respectively,
   while retaining visible glyphs and text labels without color.
10. Expected, unexpected, and unreviewed use a distinct labelled visual vocabulary and cannot
    be mistaken for diff class or operational error state.
11. All semantic text, control, focus, border, icon, and source-highlight combinations meet
    the specified WCAG contrast thresholds in light and dark themes.
12. System, light, and dark modes work, persist as specified, and remain operable with forced
    colors and reduced motion.
13. The complete workflow from file import through review and export is possible by keyboard
    at 320 CSS pixels and 200-percent zoom.
14. Selecting a finding displays its structured base/head evidence and embedded pinned source
    excerpt without requiring a network request.
15. Optional complete-file loading is absent for non-GitHub projects; when available it fetches
    only the validated pinned GitHub raw URL, observes the decoded-byte and buffering limits,
    and safely falls back on every failure.
16. No source is embedded through an iframe, and no untrusted value reaches an HTML, script,
    style, template, or arbitrary-URL execution sink.
17. Review state survives a same-browser reload under the exact report digest and never leaks
    to a byte-different report.
18. JSON review export validates against the checked-in generated schema, uses unique canonical
    locators, and round-trips without loss.
19. Markdown export places unexpected findings before expected findings, preserves canonical
    order, uses pinned links when available and plain escaped locations otherwise, reports
    incomplete/unreviewed state, and resists structural injection from every untrusted field.
20. Clipboard, storage, source-network, and optional-enhancement failures preserve the loaded
    report and offer an accessible recovery path.
21. Pinned frontend formatting, linting, strict typing, full line/branch coverage, browser,
    accessibility, contrast, adversarial, and strict CSP gates pass in CI, and the required
    manual accessibility pass is recorded for release.
22. The deployed bundle contains no remote runtime dependency, analytics, credential,
    developer path, bundled report fixture, or unaccounted third-party license.

## 19. Standards references

- [Web Content Accessibility Guidelines (WCAG) 2.2](https://www.w3.org/TR/WCAG22/)
- [WAI-ARIA Authoring Practices: table pattern](https://www.w3.org/WAI/ARIA/apg/patterns/table/)
- [WAI-ARIA Authoring Practices: grid pattern](https://www.w3.org/WAI/ARIA/apg/patterns/grid/)
- [Media Queries Level 5](https://www.w3.org/TR/mediaqueries-5/)
- [CSS Color Adjustment Level 1](https://www.w3.org/TR/css-color-adjust-1/)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP/)
