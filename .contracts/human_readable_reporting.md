# Human-readable reporting contract for `liveness_primer`

Status: approved; implementation pending.

This document refines §§7–9, §12, §15, and §17 of
[`initial_contract.md`](initial_contract.md). It is authoritative for human-readable report
data, layout, source evidence, links, terminal styling, and the dependency amendment required
by them. The initial contract remains authoritative elsewhere.

## 1. Purpose

The human report is the primary review surface for deciding whether the blast radius of a
detector change is expected. A reviewer must be able to inspect each displayed finding and
make a preliminary judgment without opening the JSON report or finding a temporary checkout.
A source permalink is supporting evidence, not a substitute for evidence in the report.

The human report therefore must provide, for every displayed finding:

- its diff class;
- its detector rule ID, when the detector or its documented output category supplies one;
- confidence;
- kind;
- repository-relative location;
- normalized diagnostic message;
- symbol;
- changed fields; and
- a bounded excerpt of the pinned source at the reported location.

GitHub output narrows the column set that carries these: §7 drops the `kind`, `symbol`, and
changed-field columns because a GitHub table cannot scroll horizontally on its own. Kind and
symbol remain in text output and in JSON, the symbol is named by the normalized diagnostic
message and located by the pinned link beside it, and every changed field still appears in
the row as an explicit base→head value. This is a layout narrowing rather than a loss of
observables.

The report must remain compact enough to scan across a corpus. It must not reproduce raw
structured detector records or expose temporary local paths through detector-derived finding
content. Trusted manifest commands remain reproducibility data (§3.5).

## 2. Scope and non-goals

This contract covers `--output text` and `--output github`. JSON remains the complete,
unstyled machine-readable `Report` serialization.

Initial contract §9 makes the JSON artifact the CI-consumable product, but `--output` selects
exactly one mode, so a CI job that publishes the human report cannot also archive the JSON
without paying for a second complete corpus run. That is not an acceptable price for the
product the contract calls canonical. `liveness-primer run` therefore additionally accepts
`--json-out PATH`, which writes the complete JSON `Report` to `PATH` for any `--output` mode.
The written payload is byte-identical to `--output json` on the same report; the selected
`--output` mode still goes to standard output unchanged.

A CI job that renders `--output github` is expected to append that rendering to
`$GITHUB_STEP_SUMMARY` — writing it only to a file leaves the job log showing raw Markdown
and the run summary empty — and to archive the `--json-out` payload as the machine-readable
artifact.

This contract does not:

- adjudicate whether a detector finding is correct;
- add an interactive TUI;
- host source files;
- treat color as the only representation of meaning;
- add presentation escape sequences to JSON; or
- make raw detector output part of the default human report.

## 3. Report data

### 3.1 Rule IDs

`Finding` and `FindingOccurrence` must carry a nullable `rule_id` field. A rule ID is an
observable detector result, not a renderer decoration.

An adapter must populate `rule_id` using the following precedence:

1. a rule ID explicitly present on the detector finding;
2. a documented, versioned mapping from a structured output bucket to its canonical rule ID;
3. `None` when neither source exists.

An adapter must not infer a rule ID from free-form message text. The human renderer displays
an absent rule ID as `-`; it must not invent a tool-specific code.

The Skylos JSON buckets currently ingested by `liveness_primer` map as follows:

| Skylos bucket | Rule ID | Meaning |
| --- | --- | --- |
| `unused_functions` | `SKY-U001` | unused function or method |
| `unused_imports` | `SKY-U002` | unused import |
| `unused_variables` | `SKY-U003` | unused variable or constant |
| `unused_classes` | `SKY-U004` | unused class or type |
| `unused_parameters` | `SKY-U006` | unused parameter |

The mapping is adapter normalization and must be covered by recorded-output tests. If a
supported Skylos revision changes the documented mapping, the adapter must be updated rather
than silently retaining a stale code.

`rule_id` remains outside finding identity so that a rule-code change on the same target can
pair as one `changed` diff. It participates in the canonical occurrence key and in
`changed_fields`; the latter gains the value `rule`. A rule-code change must never disappear
from the blast radius.

To refine initial contract §8 without reordering occurrences distinguished by existing
fields, `rule_id` is appended after confidence in the canonical occurrence key. The complete
key under this contract is:

```text
(start_line, end_line, message,
 confidence_presence, confidence_value,
 rule_id_presence, rule_id_value)
```

Each presence component is `0` when its field is absent and `1` when present, so absent sorts
before present. The paired value component is `0` for absent confidence and the empty string
for an absent rule ID; it otherwise carries the normalized value. `raw_excerpt` and
`SourceExcerpt` do not participate. Python diffing, serialized report ordering, browser
locators, and `bisect --occurrence` must use this exact key wherever the canonical occurrence
key is required.

### 3.2 Aggregate rollups

The report must answer whether a large blast radius consists primarily of one rule or kind
without requiring a reviewer to read every finding row. `ProjectReport` and `Report` therefore
carry complete pre-truncation rollups by diff class and rule ID. Findings without rule IDs
fall back to kind so a detector such as Vulture does not collapse into an uninformative `-`
group.

Both models expose `rollups: tuple[DiffRollup, ...]`. Each `DiffRollup` has this narrow shape:

```text
diff_class: DiffClass
rule_id: str | None
kind: str | None
count: int
```

Exactly one of `rule_id` and `kind` is non-null. A finding with a rule ID groups by rule ID
regardless of kind; otherwise it groups by kind. A `changed` pair groups by its
reference-side occurrence. `count` is positive.

Rollups are computed from the complete diff sequence before `--max-results` truncation, in
the same assembly step as `DiffTotals`. The serialized tuple is deterministically ordered by
diff class in `new`, `dropped`, `changed` order, then descending count, then lexicographically
by rule ID or kind — the display ordering below without the top-five cap. Overall rollups are
the sum of the complete project rollups. A hook that filters or replaces diffs must recompute totals and rollups before the
final report is truncated or serialized; stale aggregate data is an invalid report.

`rollups` is a required field of both models rather than a defaulted one, so the generated
schemas demand it. Because "stale aggregate data is an invalid report" must be enforced and
not merely asserted, both models reject, at validation time, a value whose per-diff-class
rollup counts disagree with the corresponding `DiffTotals` counts, and `Report` additionally
rejects overall totals or rollups that are not the sum of its projects'. Validation is the
transformation boundary: a hook that rewrites diffs without recomputing aggregates fails
there instead of producing a silently stale report.

Human renderers show nonzero diff classes as one line each. They display at most the five
largest groups, ordered by descending count and then lexicographically by rule ID or kind. An
omitted tail is explicit and gives both its finding count and group count:

```text
new 168: SKY-U006 155, SKY-U002 13
changed 24: SKY-U001 18, SKY-U003 4, 2 findings across 2 other rules
```

Kind fallbacks render as `kind:<kind>` rather than being presented as rule IDs.

### 3.3 Source evidence

The actual source text is not the detector's `raw_excerpt`. Source evidence must be derived
from the byte-identical pinned corpus checkout after the adapter has normalized and validated
the reported path.

Each occurrence may carry a nullable, frozen `SourceExcerpt` with the narrow shape:

```text
start_line: int
lines: tuple[str, ...]
omitted_lines: int
```

The line numbers represented by `lines` are consecutive and begin at `start_line`. The first
line must be the reported `start_line`.

Decoded source is divided into lines using source-location newline semantics: `\n`, `\r\n`,
and `\r` are the only line boundaries. Form feed, vertical tab, the C1 `NEL` character, and
the Unicode line and paragraph separators are ordinary characters inside a line, because
Python and the detectors do not count them when numbering source lines. Splitting on them
would silently shift every subsequent excerpt and present source the detector never reported.

`--excerpt-lines N` controls the maximum number of source lines stored and rendered per
occurrence:

- `N = 0` disables source excerpts;
- a point finding begins at the reported line and may use following existing lines to fill the
  `N`-line evidence budget;
- a multi-line span begins at its first line, prioritizes lines in the reported span, and may
  use following existing lines to fill any remaining evidence budget;
- `omitted_lines` counts existing lines in the reported span that were not retained because
  the span exceeded `N`;
- context beyond the `N`-line evidence budget was never requested and is not counted as
  omitted;
- a point finding near end-of-file has `omitted_lines = 0` when fewer than `N` source lines
  exist; and
- missing, unreadable, non-regular, or out-of-range source produces no excerpt and a bounded
  report warning rather than fabricated text.

Source evidence is derived review context. It must not participate in finding identity, the
canonical occurrence key, or changed-field classification. The corpus is identical across
the two detector revisions; detector-reported line changes remain observable through the
existing line-span field.

Source extraction must use the repository's bounded, containment-enforcing filesystem
helpers. Corpus-controlled symlinks, special files, oversized files, undecodable bytes, and
control characters must not bypass the report trust boundary.

Those helpers must normalize *every* expected filesystem failure into their own bounded
policy error. Path resolution and file reads raise operating-system errors that a narrow
`except` on the policy error would miss — an unreadable regular file raises `PermissionError`,
and on the supported Python floor a self-referential symlink raises `RuntimeError` out of
`Path.resolve()`. A corpus-controlled file must never terminate report assembly: each such
failure becomes one bounded per-project warning, whose text carries the repository-relative
path only and never the disposable local checkout prefix.

### 3.4 Raw detector records

`raw_excerpt` remains optional provenance in JSON. Human renderers must not display a raw
JSON object, raw serialized record, or other structured detector payload by default.

In particular, a structured record must not be rendered as one long line and then truncated
as an undifferentiated string. Any future diagnostic mode that exposes raw records must be an
explicit opt-in distinct from `--excerpt-lines`.

### 3.5 Trusted manifest commands

User-supplied escape-hatch `base_cmd` and `head_cmd` argv are trusted configuration and
reproducibility evidence under the initial contract's trust model. Human manifest headers
render every argv value faithfully, including absolute or temporary paths. Values are
shell-quoted and structurally escaped for the output format, but are not path-shortened or
rewritten. This exception does not apply to detector-derived locations, excerpts, messages,
or source links.

### 3.6 Schema version

Adding nullable `rule_id`, nullable `SourceExcerpt`, complete rollups, and the additive `rule`
changed-field value requires an additive schema-version update and regenerated checked-in
schemas. The source excerpt must be present in JSON when collected so an archived report
remains self-contained after disposable workspaces are gone.

## 4. Common finding presentation

### 4.1 Project header

Each project section begins with its name, repository, abbreviated corpus SHA,
base/head finding counts, complete pre-truncation diff totals, measured cost, errors, and
integrity warnings. If findings are capped, the section states both the number displayed and
the complete total.

For a GitHub-hosted project, the project link must name the pinned corpus tree, not the
detector repository, the corpus default branch, a cache directory, or a disposable checkout.
For a non-GitHub ad-hoc project, the renderer shows the escaped repository string and corpus
SHA separately without fabricating a pinned-tree URL.

Corpus provenance occupies exactly one `corpus:` line per project. The repository must not be
printed once as a bare string and then again inside a separate pinned-tree URL line: when a
pinned-tree URL exists and can be attached as a terminal hyperlink, the line shows
`owner/repository @ <abbreviated SHA>` carrying the link; when it exists but cannot be
attached, the line is the pinned-tree URL itself, which already names both. A non-GitHub
ad-hoc project shows the escaped repository string and the abbreviated SHA with no URL.

The overall header and each project header include the aggregate rollup lines from §3.2. The
overall header uses overall rollups; each project header uses only that project's rollups.

The overall header carries the same facts in every human output mode. Text and GitHub output
must both state overall base/head finding counts, complete totals, overall rollups, measured
execution cost, and the counts of errors, corpus-integrity warnings, and source warnings. A
mode that omits cost or the warning summaries is incomplete, not merely styled differently.

### 4.2 Borderless table

Findings render in a compact, aligned table with this exact semantic column order:

```text
  rule       %          kind       location                    symbol               message                        fields
+ SKY-U001   90%        function   httpx/_auth.py:L225         httpx._auth.example  unused function 'example'      -
- SKY-U002   NA         import     httpx/_client.py:L14        typing               unused import 'typing'         -
~ SKY-U003   60%->90%   variable   httpx/_config.py:L81        DEFAULT              unused variable 'DEFAULT'      %
```

The first column has a blank header. There is no left border and no vertical border in text
mode. Columns are separated by padding, not literal `|` characters.

Class glyphs are stable and output-independent:

- `+` means `new`;
- `-` means `dropped`; and
- `~` means `changed`.

A compact `+ new; - dropped; ~ changed` legend appears once before the first finding table.
The glyphs and legend preserve meaning without color.

### 4.3 Confidence column

The `%` column uses the following exact forms:

- `NA` when the applicable occurrence has no confidence;
- `XX%` for a single applicable confidence or unchanged paired confidence;
- `NA->XX%` when confidence appears;
- `XX%->NA` when confidence disappears; and
- `XX%->YY%` when confidence changes.

The column is measured like any other: it sizes to the widest value actually present in the
section and expands naturally when a paired form such as `100%->100%` occurs. It must never
be padded to a fixed reservation for forms that no displayed finding uses — a section whose
every value is `90%` gets a three-cell column, and the reclaimed cells go to the flexible
columns. Its minimum is two cells, sufficient for `NA`. It must not emit ambiguous forms such
as `-->90%`.

### 4.4 Fields column

The `fields` column is `-` for `new` and `dropped`. A `changed` row contains a comma-separated
combination of these compact tokens in canonical field order:

- `line` for a changed line span;
- `message` for a changed message;
- `%` for changed confidence; and
- `rule` for a changed rule ID.

The renderer must additionally show both base and head values for each changed field. It may
use indented continuation lines beneath the summary row. Listing only the field names is not
sufficient evidence.

### 4.5 Source continuation

For `new`, the head excerpt follows the summary row. For `dropped`, the base excerpt follows
it. For `changed` with an unchanged line span, the reference-side base excerpt appears once.
For `changed` with `line` in `changed_fields`, both excerpts appear, labelled `base` and
`head`, because the two reported locations are the evidence needed to review the move. Each
side uses its own reported span and pinned permalink when one is available. If one side
cannot be collected, the available side remains visible with the bounded warning for the
missing side.

A finding and its evidence must read as one visually coherent block. The continuation region
is indented two cells from the left margin — not aligned under the location column, which
pushes evidence far to the right and wastes the width the excerpt needs. Each source line
carries its real line number followed by a `|` gutter, and one blank line separates a
complete finding block from the next one, so it is unambiguous where a diagnostic ends and
its evidence begins:

```text
+ SKY-U001  90%  function  httpx/_auth.py:L225   httpx._auth.example  unused function 'example'  -
  225 | def example(request):
  226 |     return request

- SKY-U002  NA   import    httpx/_client.py:L14  typing               unused import 'typing'     -
   14 | import typing
```

The line number is normal-contrast semantic data; only the `|` gutter itself may be styled as
decoration. A finding with no continuation region is not followed by a blank line, so a
report rendered with `--excerpt-lines 0` stays a dense table.

The source is evidence, not another table record. Long excerpts end with an explicit omitted
line count derived from `SourceExcerpt.omitted_lines` rather than an unexplained ellipsis. No
omission marker appears when `omitted_lines` is zero.

### 4.6 Column measurement and narrow outputs

Every row in one project section uses the same measured column widths. The renderer must
sanitize cells before measuring them and must use terminal display width, not Python string
length, so combining and wide Unicode characters do not make the table ragged. Styling and
hyperlink escape sequences have zero display width.

The class, rule, confidence, kind, and fields columns do not wrap. Location, message, and
symbol are the flexible columns: they receive declared minimum and maximum widths and shrink
toward the minimum only when the available width demands it.

Flexible columns must not be chopped at arbitrary character boundaries. Each declares how it
degrades:

- `message` wraps onto indented continuation lines at word boundaries, falling back to cell
  chopping only for a single word wider than the column;
- `location` truncates in the middle, preserving its leading directories and its trailing
  file name and line span; and
- `symbol` truncates at the end.

Truncation is deliberate and counted: a truncated cell states how many characters it omitted
(§8). Only `message` produces continuation lines, and they preserve the original column
boundaries.

If the available width cannot satisfy the table's minimum widths, the renderer uses a
labelled stacked finding layout. It must not fall back to concatenating cells with single
spaces or allow the host terminal's uncontrolled wrapping to create ragged columns.

Redirected text uses a deterministic fallback width when no terminal width is available.
Tests may supply an explicit width; output must not depend on ambient developer terminal
size.

### 4.7 End-of-report summary

A corpus report is long. After scrolling through every project section, the terminal sits at
the bottom of the report with no decision surface, and the overall totals and rollups near
the top are far out of view. Text output therefore repeats the overall summary at the end
rather than moving it: the leading copy remains useful in a pager and in archived text, and
the trailing copy is where the reviewer actually decides.

The footer repeats the overall totals, rollups, measured cost, and error and warning counts,
and adds an aligned per-project impact table with this exact column order:

```text
project | base -> head | delta | ratio | new | dropped | changed | cost | warnings
```

- `delta` is `head - base` with an explicit sign, so a shrinking corpus is legible.
- `ratio` is `head / base` rendered as `N.NNx`. A zero baseline has no ratio: it renders
  `new` when the head side found anything and `-` when both sides are empty. Absolute and
  relative change always appear together, because a percentage alone misleads at small
  baselines and an absolute count alone hides a blast radius.
- `cost` is the project's measured wall-clock cost, or `n/a`.
- `warnings` counts that project's errors, corpus-integrity warnings, and source warnings.

Rows are ordered by descending absolute `delta`, then by project name, so the largest blast
radius is surfaced first. This ordering is local to the footer: it must not reorder the
detailed project sections, which stay in run order.

A nonzero `delta` carries emphasis; the emphasis is a styling accent only, and the signed
number and ratio remain fully legible without color.

The footer is text-output structure. GitHub output already opens with the overall header on a
page the reader can scroll back to, and repeats nothing.

## 5. Source permalinks

The report already has all components needed for stable GitHub permalinks:

- `CorpusPinRecord.repo`;
- `CorpusPinRecord.resolved_sha`;
- the normalized repository-relative finding path; and
- the occurrence line span.

For a GitHub-hosted corpus project, the renderer constructs:

```text
https://github.com/OWNER/REPOSITORY/blob/SHA/PATH#LSTART
https://github.com/OWNER/REPOSITORY/blob/SHA/PATH#LSTART-LEND
```

Repository and path components must be parsed and encoded, not interpolated from an
unvalidated raw detector path. A source link must never contain a local checkout, cache,
home, or temporary-directory prefix.

The permalink targets the pinned corpus SHA. It must not target the detector base/head SHA
or a moving corpus branch.

For a non-GitHub ad-hoc project, no GitHub permalink exists. Human renderers retain the
escaped, copyable relative `path:Lx` or `path:Lx-Ly` location as plain text and must not invent
a source URL from an unvalidated repository string.

In GitHub output, the visible `path:Lx` or `path:Lx-Ly` is the Markdown link label. A
`changed` location with a moved span (`path:Lx->Ly`) links its base-side span; the head-side
permalink accompanies the labelled head excerpt (§4.5). In text output with supported
terminal hyperlinks, the same visible location is an OSC-8 link. A hidden terminal hyperlink
must never be the only representation of the target.

When terminal hyperlinks are disabled or unsupported, the copyable relative location and the
project's `corpus:` pinned-tree line remain, and together they reconstruct the permalink. A
full per-finding URL continuation line is therefore **not** printed by default: across a
corpus-sized report those lines outnumber and visually dominate the findings themselves. They
are available on request through `--source-urls` (§6.3), which prints the pinned URL as a
labelled continuation for every finding side that has one.

## 6. Terminal rendering and color

### 6.1 Rendering library

The terminal renderer must use Rich as a runtime dependency rather than implementing
Unicode width, ANSI styling, wrapping, and OSC-8 links independently. The table is borderless
and header-bearing, with no padded outer edge.

This explicitly amends initial contract §17: runtime dependencies additionally include
`rich>=13`. The supported floor is installed and tested by the repository's
lowest-direct-resolution CI jobs.

All detector-derived and corpus-derived strings must be sanitized first and passed to Rich
as literal `Text`. They must never be parsed as Rich markup. Generated styles and links are
applied only after sanitization and width calculation.

### 6.2 Style map

Semantic data must stay at normal contrast. `dim` is a legibility failure on real terminal
themes: it renders semantic columns and project boundaries barely readable against common
light and dark backgrounds, and it is reserved here for pure decoration that carries no
information. Likewise, the `bright_*` variants are not a reliable contrast improvement — they
wash out on light themes — so the class accent uses the standard palette entries, which every
theme maps to a foreground legible against its own background.

The class glyph is a high-contrast, bold treatment; its color is a secondary cue, and the
same class accent is carried through the rule column so the eye can group findings by class
without color being load-bearing. The default terminal style map is:

| Element | Style |
| --- | --- |
| `+` | bold green |
| `-` | bold red |
| `~` | bold yellow |
| rule ID | the row's class accent: green, red, or yellow |
| confidence | magenta |
| kind | cyan |
| linked location | blue and underlined |
| message | default foreground |
| symbol | default foreground |
| changed fields | yellow |
| headers and project headers | bold |
| source line numbers | default foreground |
| source gutter (`|`) | dim |
| footer impact emphasis | bold yellow |
| errors | bold red |
| warnings | bold yellow |

The renderer colors the class glyph strongly rather than coloring the complete row. Large
reports must remain readable, and copied source must retain normal contrast.

### 6.3 Capability controls

The CLI provides:

```text
--color auto|always|never
--hyperlinks auto|always|never
--source-urls
```

`--color` and `--hyperlinks` default to `auto`. `--source-urls` is an off-by-default switch
that opts into the per-finding pinned URL continuation lines described in §5; it affects text
output only.

For color, `auto` enables ANSI styling only when standard output is an interactive terminal,
`TERM` is not `dumb`, and `NO_COLOR` is absent. `--color always` explicitly enables generated
styling in redirected output; `--color never` forbids it. JSON and GitHub output never
contain ANSI styling regardless of this setting.

For hyperlinks, `never` forbids OSC-8 links and `always` explicitly enables them. `auto`
enables them only when all of these conditions hold:

- standard output is an interactive terminal;
- `TERM` is not `dumb`;
- neither `TMUX` nor `STY` is set, because multiplexer passthrough cannot be inferred; and
- at least one conservative capability signal is present: `TERM_PROGRAM` is exactly one of
  `ghostty`, `iTerm.app`, `WezTerm`, or `vscode`; `KITTY_WINDOW_ID` is nonempty (kitty does
  not set `TERM_PROGRAM`); `VTE_VERSION` is a decimal integer greater than or equal to
  `5000`; or `WT_SESSION` is nonempty.

An absent, malformed, or unrecognized capability signal disables hyperlinks in `auto` mode.
The implementation must not claim that terminfo or Rich detects OSC-8 support. Redirected
text contains no OSC-8 escapes unless `always` was requested.

Plain and colored terminal reports must have identical visible text, column widths, wrapping,
and semantics after ANSI and OSC-8 sequences are stripped.

## 7. GitHub rendering

GitHub does not interpret ANSI styling, and Markdown links do not work inside fenced `diff`
blocks. Exact source links and readable evidence take precedence over whole-line diff color.

A GitHub-rendered table has no horizontal scroll affordance of its own: an over-wide row
forces the whole table sideways and destroys the scannability §1 requires. At corpus scale a
report carries well over a hundred findings, so the per-row budget is the binding constraint,
not the per-finding one.

GitHub rows therefore carry the **first retained source line only**, rendered as a Markdown
code span so it reads as code, followed by a bare `[...]` when the excerpt continues. That
satisfies this section's requirement that a reviewer see the first retained line without
expanding anything, while spending the fewest cells on the fact that more exists; the exact
retained and omitted line counts stay in the JSON report, which is the CI-consumable product.
A code span also renders its content literally, so Markdown structure, raw HTML, and link
syntax inside pinned source are inert there; only the table's own `|` separator still needs
escaping, which GitHub honors inside code spans. In-row caps for the message, changed values,
and source text are tighter than the terminal renderer's for the same reason: those caps, not
the link targets, set the rendered column width, because a Markdown link renders as its short
label. A row that serializes a whole excerpt into one cell violates this section.

The width budget also decides the column set. GitHub output narrows the terminal renderer's
columns to the blank class column, `rule`, `%`, `location`, and `message`, in that order.
`kind`, `symbol`, and the changed-field summary column are dropped. `kind` remains in the
JSON report and in text output; the symbol is already named inside the normalized diagnostic
message and pinpointed by the pinned link in the location cell, so a dedicated column spends
width on text the row states twice; and every changed field still appears beneath the
diagnostic as an explicit base→head value. Nothing observable is lost — only the columns
whose content is most repetitive or most redundant across a corpus.

GitHub output keeps the class glyphs. It may add a colored status marker
in the blank class header column because GitHub-rendered tables do not have terminal color:

- `🟢 +` for `new`;
- `🔴 -` for `dropped`; and
- `🟡 ~` for `changed`.

The `+`, `-`, and `~` remain mandatory so color is not the only carrier of meaning. For a
GitHub-hosted corpus project, the location is a Markdown link to the pinned source line. For
a non-GitHub ad-hoc project, it is escaped plain text. Source evidence appears in the same row
beneath the diagnostic using escaped inline or preformatted text; a reviewer must not have
to expand a collapsed section to see the first retained source line, and continuation is
marked rather than silent.

GitHub table source may omit a leading and trailing `|`. GitHub's required separator row is
not a user-facing semantic header. The first header cell is blank; the remaining headers are
`rule`, `%`, `location`, and `message`.

## 8. Sanitization and truncation

Paths, messages, symbols, kinds, source text, detector rule IDs, errors, and warnings are
untrusted. Human renderers must:

- replace or escape terminal control characters;
- prevent Rich-markup interpretation;
- escape Markdown and HTML metacharacters at the GitHub structural boundary;
- apply independent per-cell length caps;
- show how many characters or lines were omitted, the one exception being §7's in-row source
  elision marker, which is deliberately bare because the exact counts remain in JSON;
- preserve the beginning and identifying portion of locations and rule IDs;
- prevent any one field from consuming another field's display budget; and
- apply generated ANSI or hyperlink control sequences only outside untrusted text.

A row must never be truncated as one serialized aggregate. In particular, a long source path
must not hide rule, confidence, message, symbol, or changed fields.

Trusted manifest argv remain shell-quoted and structurally escaped as described in §3.5, but
are not normalized or suppressed as detector-derived data.

## 9. Output-mode guarantees

| Property | `text`, interactive | `text`, redirected | `github` | `json` |
| --- | --- | --- | --- | --- |
| aligned human table | yes | yes | yes | no |
| class glyphs | yes | yes | yes | structured value |
| ANSI color | capability-dependent | explicit only | never | never |
| colored fallback marker | not required | no | yes | no |
| source location/link | pinned OSC-8 when available, plus visible fallback | plain location; pinned URL only under `--source-urls` | pinned Markdown link when available, otherwise plain location | structured/derivable |
| bounded source excerpt | yes | yes | first retained line as a code span plus `[...]` | complete retained excerpt |
| end-of-report summary | yes | yes | no (header only) | no |
| raw detector record | no | no | no | when retained |
| temporary paths in detector-derived finding content | never | never | never | never in normalized locations |
| trusted escape-hatch argv | faithfully rendered | faithfully rendered | faithfully rendered | complete manifest argv |

## 10. Acceptance criteria

Implementation is complete only when tests establish all of the following.

1. A recorded Skylos finding renders its canonical `SKY-Uxxx` code in text, GitHub, and JSON.
2. A detector-provided rule ID takes precedence over the bucket mapping.
3. A fake-detector finding with otherwise identical identity fields and different explicit
   rule IDs becomes one `changed` finding with `rule` in `changed_fields`. A Skylos bucket
   move that also changes kind remains a `new` plus a `dropped` finding.
4. Vulture findings without a native rule ID render `-`, not an invented code.
5. Project and overall rollups use the complete pre-truncation diffs, group by rule with kind
   fallback, apply the deterministic top-five ordering, and report the omitted finding and
   group counts.
6. `NA`, `XX%`, `NA->XX%`, `XX%->NA`, and `XX%->YY%` have focused regression coverage.
7. Rows align at their visible column boundaries with ASCII, combining Unicode, wide Unicode,
   long paths, long messages, and long symbols.
8. Narrow output uses the defined stacked layout rather than uncontrolled wrapping.
9. The source excerpt contains the actual pinned source line at the detector-reported location.
10. A changed finding with a changed line span shows labelled base and head excerpts using
    their respective locations; an unchanged span shows the reference-side excerpt once.
11. For a GitHub-hosted project, the source permalink contains the corpus SHA and normalized
    path and opens the exact line or span. A non-GitHub ad-hoc project renders the same
    relative location as escaped plain text without an invented URL.
12. No detector-derived finding row, source excerpt, or source link contains a disposable
    checkout prefix such as `/private/var/folders/`, a cache path, or a serialized `"file"`
    field from a detector record. Trusted manifest argv may contain such paths.
13. Source content and detector strings cannot inject ANSI, OSC-8, Rich markup, Markdown
    structure, HTML, or terminal control behavior.
14. `--color never` and redirected `auto` output contain no ANSI escapes.
15. `--color always` styles only trusted renderer elements, and stripping its escapes produces
    the byte-equivalent visible plain report.
16. Hyperlink tests cover `always`, `never`, redirected output, `TERM=dumb`, multiplexer
    suppression, every `auto` allowlist signal, malformed `VTE_VERSION`, and the unknown-terminal
    default-off case.
17. GitHub locations are clickable, GitHub output contains no ANSI/OSC-8 escapes, and its
    status remains understandable without emoji color.
18. `--excerpt-lines 0` suppresses source evidence without suppressing the diagnostic row.
19. `SourceExcerpt.omitted_lines` counts only real reported-span lines omitted by the evidence
    budget; a point finding at end-of-file has zero omissions, and omission text appears only
    for a positive count.
20. Result truncation continues to report complete pre-truncation totals, rollups, and displayed
    counts.
21. The overall and project headers contain the applicable pinned-tree link, or the plain
    repository fallback for a non-GitHub project, plus the abbreviated SHA, base/head finding
    counts, complete totals, aggregate rollups, execution cost, and bounded errors or warnings.
    This is asserted for `text` and `github` alike: the GitHub overall header carries measured
    cost and the error, corpus-integrity, and source-warning summaries, not only totals.
22. Existing message-only suppression remains explicit and the JSON report retains complete
    structured detail.
23. Decoded source is split only on `\n`, `\r\n`, and `\r`. A file whose line embeds a form
    feed, vertical tab, `NEL`, or a Unicode separator still reports the excerpt Python and the
    detector number at the reported line.
24. An unreadable regular file and a self-referential symlink each yield no excerpt, one
    bounded warning free of the local checkout prefix, and a completed report — never an
    uncaught `PermissionError` or `RuntimeError`.
25. `rollups` is required by the generated schemas, and a `ProjectReport` or `Report` whose
    rollups or overall totals disagree with their diff totals fails validation.
26. The confidence column measures to its widest present value; a section whose values are
    all `XX%` renders a three-cell column, and a `100%->100%` value expands it.
27. `location` truncates in the middle, `symbol` truncates at the end, `message` wraps at word
    boundaries, and each truncation states its omitted character count.
28. Per-finding pinned URL lines are absent by default and present under `--source-urls`;
    every project prints exactly one `corpus:` provenance line.
29. The text report ends with the repeated overall summary and the per-project impact table,
    ordered by descending absolute delta, showing signed delta and ratio together and
    rendering a zero baseline as `new` or `-`.
30. No GitHub table row serializes more than the first retained source line of a side; the
    line renders as a code span, a continuing excerpt is marked `[...]`, and the header row
    is exactly the blank class column, `rule`, `%`, `location`, and `message`.
31. `--json-out PATH` writes the byte-identical `--output json` payload for any `--output`
    mode without changing what reaches standard output.

Plain-text and GitHub golden fixtures must cover a representative `new`, `dropped`, and
multi-field `changed` finding. Color and hyperlink tests must assert capabilities and visible
width separately from those unstyled golden files.
