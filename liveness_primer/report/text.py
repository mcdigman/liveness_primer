"""The Rich-based terminal report renderer (contract §9, reporting contract §4-§6).

Copyright (C) 2026 Matthew C. Digman

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
    pin_for_project,
    rollup_lines,
    rule_text,
    span_text,
    totals_text,
)
from liveness_primer.report.permalink import source_url, tree_url
from liveness_primer.report.sanitize import escape_argv_text, sanitize_inline, sanitize_location
from liveness_primer.report.table import (
    Cell,
    Line,
    Segment,
    column_offset,
    continuation_lines,
    finding_lines,
    header_line,
    measure_widths,
)
from liveness_primer.report.terminal import TextRenderOptions

# Default terminal style map (reporting contract §6.2). Roles without an
# entry render in the default foreground; the class glyph is colored
# strongly rather than the complete row.
STYLES: dict[str, str] = {
    'class-new': 'bold bright_green',
    'class-dropped': 'bold bright_red',
    'class-changed': 'bold yellow',
    'rule': 'cyan',
    'confidence': 'magenta',
    'kind': 'dim cyan',
    'location-link': 'blue underline',
    'symbol': 'dim',
    'fields': 'yellow',
    'header': 'bold dim',
    'source-number': 'bold dim',
    'label': 'bold dim',
    'error': 'bold bright_red',
    'warning': 'bold yellow',
}

# Independent per-cell length caps (reporting contract §8): no field may
# consume another field's display budget.
_RULE_CAP = 32
_KIND_CAP = 32
_LOCATION_CAP = 96
_MESSAGE_CAP = 200
_SYMBOL_CAP = 96
_VALUE_CAP = 120
_SOURCE_CAP = 200
_REPO_CAP = 120

_DETAIL_INDENT = 4
_SAFE_CONSOLE_WIDTH = 4000

_LOCATION_COLUMN = 4


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
        lines.append(
            _plain_line(
                'isolation: NOT ENFORCED - build/analysis ran without a network sandbox (contract §11)', 'warning'
            )
        )
    if manifest.installer is not None:
        lines.append(_plain_line(f'installer: {manifest.installer}'))
    if manifest.environment_delta:
        lines.append(
            _plain_line('environment delta - non-detector dependencies differ between the sides (contract §3):')
        )
        for delta in manifest.environment_delta:
            base = delta.base_version if delta.base_version is not None else 'absent'
            head = delta.head_version if delta.head_version is not None else 'absent'
            # Freeze-derived text originates in the untrusted environments.
            lines.append(_plain_line('  ' + sanitize_inline(f'{delta.package}: {base} -> {head}')))
    return lines


def _cost_text(report: Report) -> str:
    """Summarize the measured execution cost across projects.

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    str
        Total measured seconds, or ``n/a`` when nothing was measured.
    """
    measured = [
        project.measured_cost_seconds for project in report.projects if project.measured_cost_seconds is not None
    ]
    if not measured:
        return 'n/a'
    return f'{sum(measured):.2f}s'


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
    base_findings = sum(project.base_findings for project in report.projects)
    head_findings = sum(project.head_findings for project in report.projects)
    lines = [
        _plain_line(f'base findings {base_findings}, head findings {head_findings}'),
        _plain_line(f'totals: {totals_text(report.totals)}'),
    ]
    lines.extend(_plain_line(rollup) for rollup in rollup_lines(report.rollups))
    lines.append(_plain_line(f'cost: {_cost_text(report)}'))
    error_count = sum(len(project.errors) for project in report.projects)
    integrity_count = sum(len(project.integrity_warnings) for project in report.projects)
    source_count = sum(len(project.source_warnings) for project in report.projects)
    if error_count:
        lines.append(_plain_line(f'errors: {error_count}', 'error'))
    if integrity_count:
        lines.append(_plain_line(f'corpus-integrity warnings: {integrity_count}', 'warning'))
    if source_count:
        lines.append(_plain_line(f'source warnings: {source_count}', 'warning'))
    if report.truncated:
        lines.append(
            _plain_line('note: some project diffs were truncated by --max-results; totals reflect the full comparison')
        )
    lines.append(_plain_line(f'legend: {CLASS_LEGEND}'))
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


def _row_cells(diff: FindingDiff, *, url: str | None, options: TextRenderOptions) -> tuple[Cell, ...]:
    """Build the eight sanitized cells of one finding row (reporting §4.2).

    Parameters
    ----------
    diff : FindingDiff
        The diff to render.
    url : str | None
        Pinned permalink of the reference-side span, when any.
    options : TextRenderOptions
        Resolved presentation options.

    Returns
    -------
    tuple[Cell, ...]
        Cells in semantic column order.
    """
    symbol = sanitize_inline(diff.symbol, max_length=_SYMBOL_CAP) if diff.symbol is not None else '-'
    location = sanitize_location(f'{diff.path}:{span_text(diff)}', max_length=_LOCATION_CAP)
    linked = url is not None and options.hyperlinks
    return (
        Cell(text=CLASS_GLYPHS[diff.diff_class], role=f'class-{diff.diff_class.value}'),
        Cell(text=sanitize_inline(rule_text(diff), max_length=_RULE_CAP), role='rule'),
        Cell(text=confidence_text(diff), role='confidence'),
        Cell(text=sanitize_inline(diff.kind, max_length=_KIND_CAP), role='kind'),
        Cell(text=location, role='location-link' if linked else 'location', link=url if linked else None),
        Cell(text=sanitize_inline(diff.reference_occurrence.message, max_length=_MESSAGE_CAP), role='message'),
        Cell(text=symbol, role='symbol'),
        Cell(text=changed_fields_text(diff), role='fields'),
    )


def _excerpt_block(
    occurrence: FindingOccurrence,
    *,
    label: str | None,
    side_url: str | None,
    indent: int,
    options: TextRenderOptions,
) -> list[Line]:
    """Render one source-evidence block (reporting contract §4.5).

    Parameters
    ----------
    occurrence : FindingOccurrence
        The occurrence whose evidence renders.
    label : str | None
        ``base``/``head`` label for moved spans.
    side_url : str | None
        Pinned permalink of this side's span, when any.
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
    if label is not None:
        link = side_url if options.hyperlinks else None
        lines.extend(
            continuation_lines(
                indent=indent,
                prefix=None,
                body=Segment(text=f'{label}:', role='label', link=link),
                total_width=options.width,
            )
        )
        # The base-side span is already linked from the location cell (or
        # its url fallback); only the head side needs its own url line.
        if side_url is not None and not options.hyperlinks and label == 'head':
            lines.extend(
                continuation_lines(
                    indent=indent,
                    prefix=None,
                    body=Segment(text=f'url: {side_url}'),
                    total_width=options.width,
                )
            )
    excerpt = occurrence.source_excerpt
    if excerpt is None:
        if label is not None:
            lines.extend(
                continuation_lines(
                    indent=indent,
                    prefix=None,
                    body=Segment(text='(no source excerpt collected; see source warnings)', role='warning'),
                    total_width=options.width,
                )
            )
        return lines
    number_width = len(str(excerpt.start_line + len(excerpt.lines) - 1))
    for offset, raw_line in enumerate(excerpt.lines):
        prefix = Segment(text=f'{excerpt.start_line + offset:>{number_width}} | ', role='source-number')
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
                prefix=None,
                body=Segment(text=f'({excerpt.omitted_lines} reported-span line(s) omitted)', role='label'),
                total_width=options.width,
            )
        )
    return lines


def _detail_lines(
    diff: FindingDiff,
    *,
    pin: CorpusPinRecord | None,
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
    pin : CorpusPinRecord | None
        Resolved corpus pin of the project, when any.
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
                prefix=None,
                body=Segment(text=f'{token}: {base_text} -> {head_text}', role='fields'),
                total_width=options.width,
            )
        )
    if url is not None and not options.hyperlinks:
        lines.extend(
            continuation_lines(
                indent=indent,
                prefix=None,
                body=Segment(text=f'url: {url}'),
                total_width=options.width,
            )
        )
    if excerpt_lines == 0:
        return lines
    sides = excerpt_sides(diff)
    for label, occurrence in sides:
        side_url = None
        if label is not None and pin is not None:
            side_url = source_url(pin, diff.path, occurrence.start_line, occurrence.end_line)
        lines.extend(_excerpt_block(occurrence, label=label, side_url=side_url, indent=indent, options=options))
    return lines


def _stacked_finding_lines(
    diff: FindingDiff,
    *,
    pin: CorpusPinRecord | None,
    url: str | None,
    excerpt_lines: int,
    options: TextRenderOptions,
) -> list[Line]:
    """Render one finding in the labelled stacked layout (reporting §4.6).

    Parameters
    ----------
    diff : FindingDiff
        The diff to render.
    pin : CorpusPinRecord | None
        Resolved corpus pin of the project, when any.
    url : str | None
        Pinned permalink of the reference-side span, when any.
    excerpt_lines : int
        Source-evidence budget from the run settings.
    options : TextRenderOptions
        Resolved presentation options.

    Returns
    -------
    list[Line]
        The stacked lines for the finding.
    """
    cells = _row_cells(diff, url=url, options=options)
    lines: list[Line] = [
        (
            Segment(text=CLASS_GLYPHS[diff.diff_class], role=f'class-{diff.diff_class.value}'),
            Segment(text=f' {diff.diff_class.value}'),
        )
    ]
    labels = ('rule', '%', 'kind', 'location', 'message', 'symbol', 'fields')
    for label, cell in zip(labels, cells[1:], strict=True):
        lines.extend(
            continuation_lines(
                indent=2,
                prefix=Segment(text=f'{label}: ', role='header'),
                body=Segment(text=cell.text, role=cell.role, link=cell.link),
                total_width=options.width,
            )
        )
    lines.extend(
        _detail_lines(
            diff,
            pin=pin,
            url=url,
            indent=_DETAIL_INDENT,
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

    Returns
    -------
    list[Line]
        The table lines.
    """
    excerpt_lines = manifest.settings.excerpt_lines
    urls = [_reference_url(diff, pin) for diff in shown]
    rows = [_row_cells(diff, url=url, options=options) for diff, url in zip(shown, urls, strict=True)]
    widths = measure_widths(rows, total_width=options.width)
    lines: list[Line] = []
    if widths is None:
        # The available width cannot satisfy the minimum column widths:
        # use the labelled stacked layout rather than ragged wrapping.
        for diff, url in zip(shown, urls, strict=True):
            lines.extend(_stacked_finding_lines(diff, pin=pin, url=url, excerpt_lines=excerpt_lines, options=options))
        return lines
    lines.append(header_line(widths))
    indent = column_offset(widths, _LOCATION_COLUMN)
    for diff, url, row in zip(shown, urls, rows, strict=True):
        lines.extend(finding_lines(row, widths))
        lines.extend(
            _detail_lines(
                diff,
                pin=pin,
                url=url,
                indent=indent,
                excerpt_lines=excerpt_lines,
                options=options,
            )
        )
    return lines


def _project_lines(project: ProjectReport, *, manifest: RunManifest, options: TextRenderOptions) -> list[Line]:
    """Render one project section (reporting contract §4).

    Parameters
    ----------
    project : ProjectReport
        The per-project report.
    manifest : RunManifest
        The run manifest supplying the corpus pin.
    options : TextRenderOptions
        Resolved presentation options.

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
        pinned_tree = tree_url(pin)
        repo_text = f'  repo {sanitize_inline(pin.repo, max_length=_REPO_CAP)} @ '
        sha_text = sanitize_inline(abbreviated_sha(pin.resolved_sha))
        if pinned_tree is not None and options.hyperlinks:
            lines.append(
                (
                    Segment(text=repo_text),
                    Segment(text=sha_text, role='location-link', link=pinned_tree),
                )
            )
        else:
            lines.append(_plain_line(repo_text + sha_text))
            if pinned_tree is not None:
                lines.append(_plain_line(f'  tree: {pinned_tree}'))
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
        lines.extend(_finding_table(shown, pin=pin, manifest=manifest, options=options))
    if suppressed:
        lines.append(
            _plain_line(f'  ({suppressed} more message-only change(s) not shown; the JSON report retains full detail)')
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
    """Render the report for terminal consumption (contract §9, reporting §4-§6).

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
    lines = _manifest_lines(report.manifest)
    lines.extend(_overview_lines(report))
    for project in report.projects:
        lines.append(())
        lines.extend(_project_lines(project, manifest=report.manifest, options=resolved))
    return _emit(lines, resolved)
