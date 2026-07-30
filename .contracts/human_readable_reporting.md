# Human-readable reporting contract for `liveness_primer`

Status: draft.

This document refines §§7–9, §12, and §15 of
[`initial_contract.md`](initial_contract.md). It is authoritative for human-readable report
data, layout, source evidence, links, and terminal styling. The initial contract remains
authoritative elsewhere.

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

The report must remain compact enough to scan across a corpus. It must not reproduce raw
structured detector records or temporary local paths.

## 2. Scope and non-goals

This contract covers `--output text` and `--output github`. JSON remains the complete,
unstyled machine-readable `Report` serialization.

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

### 3.2 Source evidence

The actual source text is not the detector's `raw_excerpt`. Source evidence must be derived
from the byte-identical pinned corpus checkout after the adapter has normalized and validated
the reported path.

Each occurrence may carry a nullable, frozen `SourceExcerpt` with the narrow shape:

```text
start_line: int
lines: tuple[str, ...]
truncated: bool
```

The line numbers represented by `lines` are consecutive and begin at `start_line`. The first
line must be the reported `start_line`. `--excerpt-lines N` controls the maximum number of
source lines stored and rendered per occurrence:

- `N = 0` disables source excerpts;
- a point finding begins at the reported line and includes at most `N` consecutive lines;
- a multi-line span begins at its first line and includes at most `N` lines;
- `truncated` is true when the reported span or requested context contains more source lines
  than were retained; and
- missing, unreadable, non-regular, or out-of-range source produces no excerpt and a bounded
  report warning rather than fabricated text.

Source evidence is derived review context. It must not participate in finding identity, the
canonical occurrence key, or changed-field classification. The corpus is identical across
the two detector revisions; detector-reported line changes remain observable through the
existing line-span field.

Source extraction must use the repository's bounded, containment-enforcing filesystem
helpers. Corpus-controlled symlinks, special files, oversized files, undecodable bytes, and
control characters must not bypass the report trust boundary.

### 3.3 Raw detector records

`raw_excerpt` remains optional provenance in JSON. Human renderers must not display a raw
JSON object, raw serialized record, or other structured detector payload by default.

In particular, a structured record must not be rendered as one long line and then truncated
as an undifferentiated string. Any future diagnostic mode that exposes raw records must be an
explicit opt-in distinct from `--excerpt-lines`.

### 3.4 Schema version

Adding nullable `rule_id`, nullable `SourceExcerpt`, and the additive `rule` changed-field
value requires an additive schema-version update and regenerated checked-in schemas. The
source excerpt must be present in JSON when collected so an archived report remains
self-contained after disposable workspaces are gone.

## 4. Common finding presentation

### 4.1 Project header

Each project section begins with its name, pinned repository URL, abbreviated corpus SHA,
base/head finding counts, complete pre-truncation diff totals, measured cost, errors, and
integrity warnings. If findings are capped, the section states both the number displayed and
the complete total.

The project link must name the pinned corpus tree, not the detector repository, the corpus
default branch, a cache directory, or a disposable checkout.

### 4.2 Borderless table

Findings render in a compact, aligned table with this exact semantic column order:

```text
  rule       %          kind       location                    message                        symbol               fields
+ SKY-U001   90%        function   httpx/_auth.py:L225         unused function 'example'      httpx._auth.example  -
- SKY-U002   NA         import     httpx/_client.py:L14        unused import 'typing'         typing               -
~ SKY-U003   60%->90%   variable   httpx/_config.py:L81        unused variable 'DEFAULT'      DEFAULT              %
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

The column has a minimum display width of 10, sufficient for `100%->100%`. It must not emit
ambiguous forms such as `-->90%`.

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

When a source excerpt is present, it follows the summary row as a continuation of that row.
Each source line includes its real line number:

```text
+ SKY-U001   90%        function   httpx/_auth.py:L225         unused function 'example'      httpx._auth.example  -
                                                                  225 | def example(request):
                                                                  226 |     return request
```

The source is evidence, not another table record. Long excerpts end with an explicit omitted
line count rather than an unexplained ellipsis.

### 4.6 Column measurement and narrow outputs

Every row in one project section uses the same measured column widths. The renderer must
sanitize cells before measuring them and must use terminal display width, not Python string
length, so combining and wide Unicode characters do not make the table ragged. Styling and
hyperlink escape sequences have zero display width.

The class, rule, confidence, kind, and fields columns do not wrap. Location, message, and
symbol are the flexible columns. They receive declared minimum and maximum widths and may
wrap onto indented continuation lines. All continuation lines preserve the original column
boundaries.

If the available width cannot satisfy the table's minimum widths, the renderer uses a
labelled stacked finding layout. It must not fall back to concatenating cells with single
spaces or allow the host terminal's uncontrolled wrapping to create ragged columns.

Redirected text uses a deterministic fallback width when no terminal width is available.
Tests may supply an explicit width; output must not depend on ambient developer terminal
size.

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

In GitHub output, the visible `path:Lx` or `path:Lx-Ly` is the Markdown link label. In text
output with supported terminal hyperlinks, the same visible location is an OSC-8 link. When
terminal hyperlinks are disabled or unsupported, the copyable relative location remains and
the stable URL may be printed as a labelled continuation. A hidden terminal hyperlink must
never be the only representation of the target.

## 6. Terminal rendering and color

### 6.1 Rendering library

The terminal renderer should use Rich as a runtime dependency rather than implementing
Unicode width, ANSI styling, wrapping, and OSC-8 links independently. The table is borderless
and header-bearing, with no padded outer edge.

All detector-derived and corpus-derived strings must be sanitized first and passed to Rich
as literal `Text`. They must never be parsed as Rich markup. Generated styles and links are
applied only after sanitization and width calculation.

### 6.2 Style map

The default terminal style map is:

| Element | Style |
| --- | --- |
| `+` | bold bright green |
| `-` | bold bright red |
| `~` | bold yellow |
| rule ID | cyan |
| confidence | magenta or bold default |
| kind | dim cyan |
| linked location | blue and underlined |
| message | default foreground |
| symbol | dim |
| changed fields | yellow |
| headers and source line numbers | bold dim |
| errors | bold bright red |
| warnings | bold yellow |

The renderer colors the class glyph strongly rather than coloring the complete row. Large
reports must remain readable, and copied source must retain normal contrast.

### 6.3 Capability controls

The CLI provides:

```text
--color auto|always|never
--hyperlinks auto|always|never
```

Both default to `auto`.

For color, `auto` enables ANSI styling only when standard output is an interactive terminal,
`TERM` is not `dumb`, and `NO_COLOR` is absent. `--color always` explicitly enables generated
styling in redirected output; `--color never` forbids it. JSON and GitHub output never
contain ANSI styling regardless of this setting.

For hyperlinks, `auto` enables OSC-8 links only on an interactive terminal whose declared
capabilities support them. `always` is an explicit request; `never` forbids them. Redirected
text must contain no OSC-8 escapes unless `always` was requested.

Plain and colored terminal reports must have identical visible text, column widths, wrapping,
and semantics after ANSI and OSC-8 sequences are stripped.

## 7. GitHub rendering

GitHub does not interpret ANSI styling, and Markdown links do not work inside fenced `diff`
blocks. Exact source links and readable evidence take precedence over whole-line diff color.

GitHub output uses the same column order and class glyphs. It may add a colored status marker
in the blank class header column because GitHub-rendered tables do not have terminal color:

- `🟢 +` for `new`;
- `🔴 -` for `dropped`; and
- `🟡 ~` for `changed`.

The `+`, `-`, and `~` remain mandatory so color is not the only carrier of meaning. The
location is a Markdown link to the pinned source line. Source evidence appears in the same
row beneath the diagnostic using escaped inline or preformatted text; a reviewer must not
have to expand a collapsed section to see the first retained source line.

GitHub table source may omit a leading and trailing `|`. GitHub's required separator row is
not a user-facing semantic header. The first header cell is blank; the remaining headers are
`rule`, `%`, `kind`, `location`, `message`, `symbol`, and `fields`.

## 8. Sanitization and truncation

Paths, messages, symbols, kinds, source text, detector rule IDs, errors, and warnings are
untrusted. Human renderers must:

- replace or escape terminal control characters;
- prevent Rich-markup interpretation;
- escape Markdown and HTML metacharacters at the GitHub structural boundary;
- apply independent per-cell length caps;
- show how many characters or lines were omitted;
- preserve the beginning and identifying portion of locations and rule IDs;
- prevent any one field from consuming another field's display budget; and
- apply generated ANSI or hyperlink control sequences only outside untrusted text.

A row must never be truncated as one serialized aggregate. In particular, a long source path
must not hide rule, confidence, message, symbol, or changed fields.

## 9. Output-mode guarantees

| Property | `text`, interactive | `text`, redirected | `github` | `json` |
| --- | --- | --- | --- | --- |
| aligned human table | yes | yes | yes | no |
| class glyphs | yes | yes | yes | structured value |
| ANSI color | capability-dependent | explicit only | never | never |
| colored fallback marker | not required | no | yes | no |
| exact pinned source link | OSC-8 plus visible fallback | visible URL | Markdown link | structured/derivable |
| bounded source excerpt | yes | yes | yes | complete retained excerpt |
| raw detector record | no | no | no | when retained |
| temporary local paths | never | never | never | never in normalized locations |

## 10. Acceptance criteria

Implementation is complete only when tests establish all of the following.

1. A recorded Skylos finding renders its canonical `SKY-Uxxx` code in text, GitHub, and JSON.
2. A detector-provided rule ID takes precedence over the bucket mapping.
3. A rule-ID change becomes one `changed` finding with `rule` in `changed_fields`.
4. Vulture findings without a native rule ID render `-`, not an invented code.
5. `NA`, `XX%`, `NA->XX%`, `XX%->NA`, and `XX%->YY%` have focused regression coverage.
6. Rows align at their visible column boundaries with ASCII, combining Unicode, wide Unicode,
   long paths, long messages, and long symbols.
7. Narrow output uses the defined stacked layout rather than uncontrolled wrapping.
8. The source excerpt contains the actual pinned source line at the detector-reported location.
9. The source permalink contains the corpus SHA and normalized path and opens the exact line
   or span.
10. No human report contains a disposable checkout prefix such as `/private/var/folders/`, a
    cache path, or a serialized `"file"` field from a detector record.
11. Source content and detector strings cannot inject ANSI, OSC-8, Rich markup, Markdown
    structure, HTML, or terminal control behavior.
12. `--color never` and redirected `auto` output contain no ANSI escapes.
13. `--color always` styles only trusted renderer elements, and stripping its escapes produces
    the byte-equivalent visible plain report.
14. Hyperlink capability modes follow their explicit and automatic contracts.
15. GitHub locations are clickable, GitHub output contains no ANSI/OSC-8 escapes, and its
    status remains understandable without emoji color.
16. `--excerpt-lines 0` suppresses source evidence without suppressing the diagnostic row.
17. Result truncation continues to report complete pre-truncation totals and displayed counts.
18. Existing message-only suppression remains explicit and the JSON report retains complete
    structured detail.

Plain-text and GitHub golden fixtures must cover a representative `new`, `dropped`, and
multi-field `changed` finding. Color and hyperlink tests must assert capabilities and visible
width separately from those unstyled golden files.
