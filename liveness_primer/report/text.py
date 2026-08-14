# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""The Rich-based terminal report renderer (contract §9, reporting contract §4-§6).

Findings render in a compact, borderless, aligned table whose class glyphs
(``+``/``-``/``~``) and legend preserve meaning without color. All
detector-derived and corpus-derived strings are sanitized first and passed
to Rich as literal text — never parsed as markup; generated styles and
OSC-8 links are applied only after sanitization and width calculation.
Plain and colored reports have identical visible text once escape
sequences are stripped.
"""

import shlex
from io import StringIO

from rich.console import Console
from rich.style import Style
from rich.text import Text

from liveness_primer.findings import (
    CorpusPinRecord,
    FindingDiff,
    FindingOccurrence,
    ProjectReport,
    Report,
    RunManifest,
)
from liveness_primer.report.common import (
    CLASS_GLYPHS,
    CLASS_LEGEND,
    abbreviated_sha,
    cap_message_only,
    changed_fields_text,
    changed_value_details,
    confidence_text,
    displayed_text,
    excerpt_sides,
    overall_summary,
    pin_for_project,
    report_has_severity,
    rollup_lines,
    rule_text,
    severity_text,
    span_text,
    totals_text,
)
from liveness_primer.report.permalink import source_url, tree_reference
from liveness_primer.report.sanitize import escape_argv_text, sanitize_inline, sanitize_location
from liveness_primer.report.table import (
    Cell,
    Line,
    Segment,
    aligned_table,
    continuation_lines,
    finding_lines,
    header_line,
    layout_columns,
    measure_widths,
)
from liveness_primer.report.terminal import TextRenderOptions

# Default terminal style map (reporting contract §6.2). Roles without an
# entry render in the default foreground; the class glyph is colored
# strongly rather than the complete row. `dim` is reserved for pure
# decoration and the `bright_*` variants are avoided: both lose contrast
# against common light and dark terminal themes, and semantic data — kind,
# symbol, project headers, source line numbers — must stay readable.
STYLES: dict[str, str] = {
    'class-new': 'bold green',
    'class-dropped': 'bold red',
    'class-changed': 'bold yellow',
    'rule-new': 'green',
    'rule-dropped': 'red',
    'rule-changed': 'yellow',
    'confidence': 'magenta',
    'severity': 'magenta',
    'kind': 'cyan',
    'location-link': 'blue underline',
    'fields': 'yellow',
    'header': 'bold',
    'gutter': 'dim',
    'label': 'bold',
    'impact': 'bold yellow',
    'error': 'bold red',
    'warning': 'bold yellow',
}

# Independent per-cell length caps (reporting contract §8): no field may
# consume another field's display budget.
_RULE_CAP = 32
_SEVERITY_CAP = 32
_KIND_CAP = 32
_LOCATION_CAP = 96
_MESSAGE_CAP = 200
_SYMBOL_CAP = 96
_VALUE_CAP = 120
_SOURCE_CAP = 200
_REPO_CAP = 120
_PROJECT_CAP = 48

# The continuation region sits two cells in, not under the location column:
# evidence belongs with its finding and needs the width (reporting §4.5).
_DETAIL_INDENT = 2
_STACKED_INDENT = 4
_SAFE_CONSOLE_WIDTH = 4000

# End-of-report per-project impact table (reporting contract §4.7).
_IMPACT_HEADERS = ('project', 'base -> head', 'delta', 'ratio', 'new', 'dropped', 'changed', 'cost', 'warnings')
_IMPACT_RIGHT_ALIGNED = frozenset({2, 3, 4, 5, 6, 7, 8})


def _plain_line(text: str, role: str = 'plain', link: str | None = None) -> Line:
    """Build one physical line from a single segment.

    Parameters
    ----------
    text : str
        Sanitized line text.
    role : str
        Style role of the line.
    link : str | None
        Generated link for the text, when any.

    Returns
    -------
    Line
        The single-segment line.
    """
    return (Segment(text=text, role=role, link=link),)


def _manifest_lines(manifest: RunManifest) -> list[Line]:
    """Render the manifest header.

    Parameters
    ----------
    manifest : RunManifest
        The run manifest.

    Returns
    -------
    list[Line]
        Header lines, with unenforced isolation and any environment delta
        rendered prominently (contract §3, §11). Trusted escape-hatch argv
        render shell-quoted and structurally escaped, never path-shortened
        (reporting contract §3.5).
    """
    lines = [
        _plain_line(f'liveness primer report - tool: {manifest.tool}', 'header'),
        _plain_line(f'schema: {manifest.schema_version}; created: {manifest.created_at.isoformat()}'),
    ]
    if manifest.detector_repo is not None:
        lines.append(_plain_line(f'detector: {manifest.detector_repo}'))
    for side_name, record in (('base', manifest.base), ('head', manifest.head)):
        if record is not None:
            provenance = 'cached' if record.from_cache else 'rebuilt'
            lines.append(_plain_line(f'  {side_name}: {record.ref} @ {record.sha[:12]} ({provenance})'))
    for side_name, command in (('base', manifest.base_cmd), ('head', manifest.head_cmd)):
        if command is not None:
            lines.append(_plain_line(f'  {side_name} command: {escape_argv_text(shlex.join(command))}'))
    lines.append(
        _plain_line(f'comparable: {"yes" if manifest.comparable else "no (escape-hatch run; gating refused)"}')
    )
    if manifest.isolation_enforced:
        lines.append(_plain_line('isolation: enforced'))
    else:
        lines.append(_plain_line('isolation: NOT ENFORCED - build/analysis ran without a network sandbox', 'warning'))
    if manifest.installer is not None:
        lines.append(_plain_line(f'installer: {manifest.installer}'))
    if manifest.environment_delta:
        lines.append(_plain_line('environment delta - non-detector dependencies differ between the sides:'))
        for delta in manifest.environment_delta:
            base = delta.base_version if delta.base_version is not None else 'absent'
            head = delta.head_version if delta.head_version is not None else 'absent'
            # Freeze-derived text originates in the untrusted environments.
            lines.append(_plain_line('  ' + sanitize_inline(f'{delta.package}: {base} -> {head}')))
    return lines


def _summary_lines(report: Report) -> list[Line]:
    """Render the overall facts shared by the header and footer (§4.1, §4.7).

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    list[Line]
        Counts, totals, rollups, cost, and bounded error/warning summaries.
    """
    summary = overall_summary(report)
    lines = [
        _plain_line(f'base findings {summary.base_findings}, head findings {summary.head_findings}'),
        _plain_line(f'totals: {totals_text(report.totals)}'),
    ]
    lines.extend(_plain_line(rollup) for rollup in rollup_lines(report.rollups))
    lines.append(_plain_line(f'cost: {summary.cost}'))
    if summary.errors:
        lines.append(_plain_line(f'errors: {summary.errors}', 'error'))
    if summary.integrity_warnings:
        lines.append(_plain_line(f'corpus-integrity warnings: {summary.integrity_warnings}', 'warning'))
    if summary.source_warnings:
        lines.append(_plain_line(f'source warnings: {summary.source_warnings}', 'warning'))
    return lines


def _overview_lines(report: Report) -> list[Line]:
    """Render the overall header: counts, totals, rollups, cost, and legend.

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    list[Line]
        The overall header lines (reporting contract §4.1).
    """
    lines = _summary_lines(report)
    if report.truncated:
        lines.append(
            _plain_line('note: some project diffs were truncated by --max-results; totals reflect the full comparison')
        )
    lines.append(_plain_line(f'legend: {CLASS_LEGEND}'))
    return lines


def _impact_ratio(base_findings: int, head_findings: int) -> str:
    """Render a project's head/base finding ratio (reporting contract §4.7).

    Parameters
    ----------
    base_findings : int
        Base-side finding count.
    head_findings : int
        Head-side finding count.

    Returns
    -------
    str
        ``N.NNx``, or the explicit zero-baseline forms ``new`` and ``-``.
    """
    if base_findings:
        return f'{head_findings / base_findings:.2f}x'
    return 'new' if head_findings else '-'


def _impact_rows(report: Report) -> list[tuple[Segment, ...]]:
    """Build the per-project impact rows (reporting contract §4.7).

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    list[tuple[Segment, ...]]
        Rows ordered by descending absolute delta, then project name.
    """
    ordered = sorted(
        report.projects,
        key=lambda project: (-abs(project.head_findings - project.base_findings), project.project),
    )
    rows: list[tuple[Segment, ...]] = []
    for project in ordered:
        delta = project.head_findings - project.base_findings
        # A changed blast radius is the reason to read the footer at all.
        emphasis = 'impact' if delta else 'plain'
        warnings = len(project.errors) + len(project.integrity_warnings) + len(project.source_warnings)
        cost = f'{project.measured_cost_seconds:.2f}s' if project.measured_cost_seconds is not None else 'n/a'
        rows.append(
            (
                Segment(text=sanitize_inline(project.project, max_length=_PROJECT_CAP)),
                Segment(text=f'{project.base_findings} -> {project.head_findings}'),
                Segment(text=f'{delta:+d}', role=emphasis),
                Segment(text=_impact_ratio(project.base_findings, project.head_findings), role=emphasis),
                Segment(text=str(project.totals.new)),
                Segment(text=str(project.totals.dropped)),
                Segment(text=str(project.totals.changed)),
                Segment(text=cost),
                Segment(text=str(warnings), role='warning' if warnings else 'plain'),
            )
        )
    return rows


def _footer_lines(report: Report) -> list[Line]:
    """Repeat the overall summary at the end of the report (reporting §4.7).

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    list[Line]
        The footer lines, ending with the per-project impact table.
    """
    lines: list[Line] = [(), _plain_line('summary', 'header'), *_summary_lines(report)]
    if report.projects:
        lines.append(())
        lines.extend(
            aligned_table(
                _IMPACT_HEADERS,
                _impact_rows(report),
                indent=2,
                right_aligned=_IMPACT_RIGHT_ALIGNED,
            )
        )
    return lines


def _reference_url(diff: FindingDiff, pin: CorpusPinRecord | None) -> str | None:
    """Build the pinned permalink of a diff's reference-side span.

    Parameters
    ----------
    diff : FindingDiff
        The diff to link.
    pin : CorpusPinRecord | None
        Resolved corpus pin of the project, when any.

    Returns
    -------
    str | None
        The permalink, or ``None`` for a non-GitHub ad-hoc project.
    """
    if pin is None:
        return None
    reference = diff.reference_occurrence
    return source_url(pin, diff.path, reference.start_line, reference.end_line)


def _row_cells(
    diff: FindingDiff,
    *,
    url: str | None,
    options: TextRenderOptions,
    has_severity: bool,
) -> tuple[Cell, ...]:
    """Build the sanitized cells of one finding row (reporting §4.2).

    Parameters
    ----------
    diff : FindingDiff
        The diff to render.
    url : str | None
        Pinned permalink of the reference-side span, when any.
    options : TextRenderOptions
        Resolved presentation options.
    has_severity : bool
        Whether the severity column is part of the layout.

    Returns
    -------
    tuple[Cell, ...]
        Cells in semantic column order.
    """
    symbol = sanitize_inline(diff.symbol, max_length=_SYMBOL_CAP) if diff.symbol is not None else '-'
    location = sanitize_location(f'{diff.path}:{span_text(diff)}', max_length=_LOCATION_CAP)
    linked = url is not None and options.hyperlinks
    severity_cells = (
        (Cell(text=sanitize_inline(severity_text(diff), max_length=_SEVERITY_CAP), role='severity'),)
        if has_severity
        else ()
    )
    return (
        Cell(text=CLASS_GLYPHS[diff.diff_class], role=f'class-{diff.diff_class.value}'),
        # The class accent continues through the rule column so findings
        # group by class without color carrying the meaning (§6.2).
        Cell(text=sanitize_inline(rule_text(diff), max_length=_RULE_CAP), role=f'rule-{diff.diff_class.value}'),
        Cell(text=confidence_text(diff), role='confidence'),
        *severity_cells,
        Cell(text=sanitize_inline(diff.kind, max_length=_KIND_CAP), role='kind'),
        Cell(text=location, role='location-link' if linked else 'location', link=url if linked else None),
        Cell(text=symbol, role='symbol'),
        Cell(text=sanitize_inline(diff.reference_occurrence.message, max_length=_MESSAGE_CAP), role='message'),
        Cell(text=changed_fields_text(diff), role='fields'),
    )


def _excerpt_block(
    occurrence: FindingOccurrence,
    *,
    indent: int,
    options: TextRenderOptions,
) -> list[Line]:
    """Render one source-evidence block (reporting contract §4.5).

    Parameters
    ----------
    occurrence : FindingOccurrence
        The occurrence whose evidence renders.
    indent : int
        Indentation of the continuation region.
    options : TextRenderOptions
        Resolved presentation options.

    Returns
    -------
    list[Line]
        The block's physical lines.
    """
    lines: list[Line] = []
    excerpt = occurrence.source_excerpt
    if excerpt is None:
        return lines
    number_width = len(str(excerpt.start_line + len(excerpt.lines) - 1))
    for offset, raw_line in enumerate(excerpt.lines):
        # The line number is semantic data and stays at normal contrast;
        # only the gutter itself is decoration (reporting contract §4.5).
        prefix = (
            Segment(text=f'{excerpt.start_line + offset:>{number_width}}'),
            Segment(text=' | ', role='gutter'),
        )
        lines.extend(
            continuation_lines(
                indent=indent,
                prefix=prefix,
                body=Segment(text=sanitize_inline(raw_line, max_length=_SOURCE_CAP), role='source'),
                total_width=options.width,
            )
        )
    if excerpt.omitted_lines:
        lines.extend(
            continuation_lines(
                indent=indent,
                body=Segment(text=f'({excerpt.omitted_lines} reported-span line(s) omitted)', role='label'),
                total_width=options.width,
            )
        )
    return lines


def _detail_lines(
    diff: FindingDiff,
    *,
    url: str | None,
    indent: int,
    excerpt_lines: int,
    options: TextRenderOptions,
) -> list[Line]:
    """Render a finding's continuation region: values, links, and evidence.

    Parameters
    ----------
    diff : FindingDiff
        The diff to render.
    url : str | None
        Pinned permalink of the reference-side span, when any.
    indent : int
        Indentation of the continuation region.
    excerpt_lines : int
        Source-evidence budget from the run settings; ``0`` disables.
    options : TextRenderOptions
        Resolved presentation options.

    Returns
    -------
    list[Line]
        The continuation lines beneath the summary row.
    """
    lines: list[Line] = []
    for token, base_value, head_value in changed_value_details(diff):
        base_text = sanitize_inline(base_value, max_length=_VALUE_CAP)
        head_text = sanitize_inline(head_value, max_length=_VALUE_CAP)
        lines.extend(
            continuation_lines(
                indent=indent,
                body=Segment(text=f'{token}: {base_text} -> {head_text}', role='fields'),
                total_width=options.width,
            )
        )
    if url is not None and options.source_urls:
        lines.extend(
            continuation_lines(
                indent=indent,
                body=Segment(text=f'url: {url}'),
                total_width=options.width,
            )
        )
    if excerpt_lines == 0:
        return lines
    for occurrence in excerpt_sides(diff):
        lines.extend(_excerpt_block(occurrence, indent=indent, options=options))
    return lines


def _stacked_finding_lines(
    diff: FindingDiff,
    *,
    url: str | None,
    excerpt_lines: int,
    options: TextRenderOptions,
    has_severity: bool,
) -> list[Line]:
    """Render one finding in the labelled stacked layout (reporting §4.6).

    Parameters
    ----------
    diff : FindingDiff
        The diff to render.
    url : str | None
        Pinned permalink of the reference-side span, when any.
    excerpt_lines : int
        Source-evidence budget from the run settings.
    options : TextRenderOptions
        Resolved presentation options.
    has_severity : bool
        Whether the severity field is part of the layout.

    Returns
    -------
    list[Line]
        The stacked lines for the finding.
    """
    cells = _row_cells(diff, url=url, options=options, has_severity=has_severity)
    lines: list[Line] = [
        (
            Segment(text=CLASS_GLYPHS[diff.diff_class], role=f'class-{diff.diff_class.value}'),
            Segment(text=f' {diff.diff_class.value}'),
        )
    ]
    labels = tuple(column.header for column in layout_columns(has_severity=has_severity)[1:])
    for label, cell in zip(labels, cells[1:], strict=True):
        lines.extend(
            continuation_lines(
                indent=2,
                prefix=(Segment(text=f'{label}: ', role='header'),),
                body=Segment(text=cell.text, role=cell.role, link=cell.link),
                total_width=options.width,
            )
        )
    lines.extend(
        _detail_lines(
            diff,
            url=url,
            indent=_STACKED_INDENT,
            excerpt_lines=excerpt_lines,
            options=options,
        )
    )
    return lines


def _finding_table(
    shown: list[FindingDiff],
    *,
    pin: CorpusPinRecord | None,
    manifest: RunManifest,
    options: TextRenderOptions,
    has_severity: bool,
) -> list[Line]:
    """Render the aligned finding table or its stacked fallback.

    Parameters
    ----------
    shown : list[FindingDiff]
        Diffs to render, in report order.
    pin : CorpusPinRecord | None
        Resolved corpus pin of the project, when any.
    manifest : RunManifest
        The run manifest supplying the evidence budget.
    options : TextRenderOptions
        Resolved presentation options.
    has_severity : bool
        Whether the severity column is part of the layout.

    Returns
    -------
    list[Line]
        The table lines.
    """
    excerpt_lines = manifest.settings.excerpt_lines
    urls = [_reference_url(diff, pin) for diff in shown]
    rows = [
        _row_cells(diff, url=url, options=options, has_severity=has_severity)
        for diff, url in zip(shown, urls, strict=True)
    ]
    columns = layout_columns(has_severity=has_severity)
    widths = measure_widths(rows, total_width=options.width, columns=columns)
    lines: list[Line] = []
    if widths is None:
        # The available width cannot satisfy the minimum column widths:
        # use the labelled stacked layout rather than ragged wrapping.
        for index, (diff, url) in enumerate(zip(shown, urls, strict=True)):
            if index:
                lines.append(())
            lines.extend(
                _stacked_finding_lines(
                    diff,
                    url=url,
                    excerpt_lines=excerpt_lines,
                    options=options,
                    has_severity=has_severity,
                )
            )
        return lines
    lines.append(header_line(widths, columns=columns))
    separate = False
    for diff, url, row in zip(shown, urls, rows, strict=True):
        # One blank line separates a complete finding block from the next;
        # a report with no continuation regions stays a dense table (§4.5).
        if separate:
            lines.append(())
        lines.extend(finding_lines(row, widths, columns=columns))
        details = _detail_lines(
            diff,
            url=url,
            indent=_DETAIL_INDENT,
            excerpt_lines=excerpt_lines,
            options=options,
        )
        lines.extend(details)
        separate = bool(details)
    return lines


def _corpus_line(pin: CorpusPinRecord, *, options: TextRenderOptions) -> Line:
    """Render one project's single corpus provenance line (reporting §4.1).

    Parameters
    ----------
    pin : CorpusPinRecord
        Resolved corpus pin of the project.
    options : TextRenderOptions
        Resolved presentation options.

    Returns
    -------
    Line
        The `corpus:` line; the repository never appears twice.
    """
    sha = sanitize_inline(abbreviated_sha(pin.resolved_sha))
    reference = tree_reference(pin)
    if reference is None:
        return _plain_line(f'  corpus: {sanitize_inline(pin.repo, max_length=_REPO_CAP)} @ {sha}')
    label, pinned_tree = reference
    if options.hyperlinks:
        return (
            Segment(text='  corpus: '),
            Segment(text=f'{label} @ {sha}', role='location-link', link=pinned_tree),
        )
    # The pinned-tree URL already names the repository and the SHA; a
    # separate repository line would print both a second time.
    return _plain_line(f'  corpus: {pinned_tree}')


def _project_lines(
    project: ProjectReport,
    *,
    manifest: RunManifest,
    options: TextRenderOptions,
    has_severity: bool,
) -> list[Line]:
    """Render one project section (reporting contract §4).

    Parameters
    ----------
    project : ProjectReport
        The per-project report.
    manifest : RunManifest
        The run manifest supplying the corpus pin.
    options : TextRenderOptions
        Resolved presentation options.
    has_severity : bool
        Whether the severity column is part of the layout.

    Returns
    -------
    list[Line]
        Section lines with all untrusted text sanitized.
    """
    pin = pin_for_project(manifest, project.project)
    cost = f'{project.measured_cost_seconds:.2f}s' if project.measured_cost_seconds is not None else 'n/a'
    name = sanitize_inline(project.project)
    header = (
        f'project {name} - base {project.base_findings} findings, '
        f'head {project.head_findings}; {totals_text(project.totals)}; cost {cost}'
    )
    lines = [_plain_line(header, 'header')]
    if pin is not None:
        lines.append(_corpus_line(pin, options=options))
    lines.extend(_plain_line('  ' + rollup) for rollup in rollup_lines(project.rollups))
    lines.extend(
        _plain_line(f'  error[{error.side}]: {sanitize_inline(error.detail)}', 'error') for error in project.errors
    )
    lines.extend(
        _plain_line(f'  warning[corpus-integrity]: {sanitize_inline(warning.detail)}', 'warning')
        for warning in project.integrity_warnings
    )
    lines.extend(
        _plain_line(f'  warning[source]: {sanitize_inline(warning)}', 'warning') for warning in project.source_warnings
    )
    capped = displayed_text(len(project.diffs), project.totals)
    if capped is not None:
        lines.append(_plain_line(f'  {capped}'))
    shown, suppressed = cap_message_only(project.diffs)
    if shown:
        lines.extend(_finding_table(shown, pin=pin, manifest=manifest, options=options, has_severity=has_severity))
    if suppressed:
        lines.extend(
            (
                (),
                _plain_line(
                    f'  ({suppressed} more message-only change(s) not shown; the JSON report retains full detail)'
                ),
            )
        )
    return lines


def _segment_style(segment: Segment, options: TextRenderOptions) -> Style | None:
    """Map one segment to its generated Rich style.

    Parameters
    ----------
    segment : Segment
        The segment to style.
    options : TextRenderOptions
        Resolved presentation options.

    Returns
    -------
    Style | None
        The combined color and link style, or ``None`` for plain text.
    """
    style: Style | None = None
    if options.color and segment.role in STYLES:
        style = Style.parse(STYLES[segment.role])
    if segment.link is not None and options.hyperlinks:
        link_style = Style(link=segment.link)
        style = link_style if style is None else style + link_style
    return style


def _emit(lines: list[Line], options: TextRenderOptions) -> str:
    """Emit physical lines as terminal text through Rich.

    Parameters
    ----------
    lines : list[Line]
        The physical lines in display order.
    options : TextRenderOptions
        Resolved presentation options.

    Returns
    -------
    str
        The rendered report, newline-terminated.
    """
    if not options.color and not options.hyperlinks:
        return '\n'.join(''.join(segment.text for segment in line) for line in lines) + '\n'
    buffer = StringIO()
    console = Console(
        file=buffer,
        force_terminal=True,
        color_system='standard',
        width=_SAFE_CONSOLE_WIDTH,
        markup=False,
        emoji=False,
        highlight=False,
        soft_wrap=True,
        legacy_windows=False,
    )
    for line in lines:
        text = Text()
        for segment in line:
            style = _segment_style(segment, options)
            if style is None:
                text.append(segment.text)
            else:
                text.append(segment.text, style=style)
        console.print(text)
    return buffer.getvalue()


def render_text(report: Report, options: TextRenderOptions | None = None) -> str:
    """Render the report for terminal consumption.

    Parameters
    ----------
    report : Report
        The assembled report.
    options : TextRenderOptions | None
        Resolved presentation options; plain, link-free output at the
        deterministic fallback width by default.

    Returns
    -------
    str
        The full text report, newline-terminated.
    """
    resolved = options if options is not None else TextRenderOptions()
    has_severity = report_has_severity(report)
    lines = _manifest_lines(report.manifest)
    lines.extend(_overview_lines(report))
    for project in report.projects:
        lines.append(())
        lines.extend(_project_lines(project, manifest=report.manifest, options=resolved, has_severity=has_severity))
    lines.extend(_footer_lines(report))
    return _emit(lines, resolved)
