"""The GitHub step-summary (markdown) report renderer (contract §9, reporting §7).

Copyright (C) 2026 Matthew C. Digman

GitHub does not interpret ANSI styling, and markdown links do not work
inside fenced ``diff`` blocks: exact pinned source links and readable
evidence take precedence over whole-line diff color. The table keeps the
semantic column order and class glyphs of the terminal report, adds a
colored status marker beside the mandatory glyph, and shows source
evidence in the same row beneath the diagnostic — never behind a
collapsed section.
"""

import shlex

from liveness_primer.findings import (
    CorpusPinRecord,
    FindingDiff,
    ProjectReport,
    Report,
    RunManifest,
    SourceExcerpt,
)
from liveness_primer.report.common import (
    CLASS_GLYPHS,
    CLASS_LEGEND,
    abbreviated_sha,
    cap_message_only,
    changed_multiple,
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
from liveness_primer.report.permalink import source_url, tree_url
from liveness_primer.report.sanitize import (
    code_cell,
    code_span,
    escape_argv_text,
    sanitize_cell,
    sanitize_inline,
)

# Colored status markers beside the mandatory class glyphs (reporting §7):
# GitHub-rendered tables have no terminal color, and the glyph keeps the
# meaning without emoji color.
_CLASS_MARKERS = {'new': '\U0001f7e2', 'dropped': '\U0001f534', 'changed': '\U0001f7e1'}

# In-row caps are tighter than the terminal renderer's: a GitHub table has
# no horizontal scroll of its own, so the physical row width is the binding
# constraint at corpus scale (reporting contract §7).
_MESSAGE_CAP = 120
_VALUE_CAP = 80
_SOURCE_CAP = 120
_NAME_CAP = 120


def _manifest_lines(manifest: RunManifest) -> list[str]:
    """Render the manifest header as markdown.

    Parameters
    ----------
    manifest : RunManifest
        The run manifest.

    Returns
    -------
    list[str]
        Markdown lines, with unenforced isolation and any environment
        delta rendered prominently (contract §3, §11). Trusted
        escape-hatch argv render shell-quoted and structurally escaped,
        never path-shortened (reporting contract §3.5).
    """
    lines = [
        f'# liveness primer report - `{sanitize_inline(manifest.tool, max_length=_NAME_CAP)}`',
        '',
        f'- **schema**: {manifest.schema_version}; **created**: {manifest.created_at.isoformat()}',
    ]
    if manifest.detector_repo is not None:
        lines.append(f'- **detector**: {manifest.detector_repo}')
    for side_name, record in (('base', manifest.base), ('head', manifest.head)):
        if record is not None:
            provenance = 'cached' if record.from_cache else 'rebuilt'
            lines.append(f'- **{side_name}**: `{record.ref}` @ `{record.sha[:12]}` ({provenance})')
    for side_name, command in (('base', manifest.base_cmd), ('head', manifest.head_cmd)):
        if command is not None:
            lines.append(f'- **{side_name} command**: {code_span(escape_argv_text(shlex.join(command)))}')
    comparable = 'yes' if manifest.comparable else 'no (escape-hatch run; gating refused)'
    lines.append(f'- **comparable**: {comparable}')
    if manifest.isolation_enforced:
        lines.append('- **isolation**: enforced')
    else:
        lines.append('- **isolation**: :warning: **NOT ENFORCED** - no network sandbox')
    if manifest.installer is not None:
        lines.append(f'- **installer**: {manifest.installer}')
    if manifest.environment_delta:
        lines.extend(
            [
                '',
                '## :warning: Environment delta',
                '',
                'Non-detector dependencies differ between the sides:',
                '',
                '| package | base | head |',
                '| --- | --- | --- |',
            ]
        )
        for delta in manifest.environment_delta:
            base = delta.base_version if delta.base_version is not None else 'absent'
            head = delta.head_version if delta.head_version is not None else 'absent'
            # Freeze-derived text originates in the untrusted environments.
            lines.append(f'| {sanitize_cell(delta.package)} | {sanitize_cell(base)} | {sanitize_cell(head)} |')
    return lines


def _location_cell(diff: FindingDiff, pin: CorpusPinRecord | None) -> str:
    """Render the location cell: pinned markdown link or escaped plain text.

    Parameters
    ----------
    diff : FindingDiff
        The diff to locate.
    pin : CorpusPinRecord | None
        Resolved corpus pin of the project, when any.

    Returns
    -------
    str
        The cell text, linked to the reference-side span when a pinned
        permalink exists (reporting contract §5).
    """
    label = sanitize_cell(f'{diff.path}:{span_text(diff)}')
    if pin is None:
        return label
    reference = diff.reference_occurrence
    url = source_url(pin, diff.path, reference.start_line, reference.end_line)
    if url is None:
        return label
    return f'[{label}]({url})'


def _excerpt_parts(excerpt: SourceExcerpt) -> list[str]:
    """Render one excerpt's in-row fragments (reporting contract §7).

    Only the first retained line goes in the row: a GitHub table has no
    horizontal scroll of its own, and serializing a whole excerpt into one
    cell forces the table sideways. The source itself renders as a code
    span so it reads as code, and a compact ``[...]`` marks that the
    excerpt continues. The complete retained excerpt, with its exact
    retained and omitted line counts, stays in the JSON report.

    Parameters
    ----------
    excerpt : SourceExcerpt
        Collected pinned-source evidence.

    Returns
    -------
    list[str]
        The fenced first source line and any elision marker.
    """
    parts = [f'{excerpt.start_line} \\| {code_cell(excerpt.lines[0], max_length=_SOURCE_CAP)}']
    if len(excerpt.lines) > 1 or excerpt.omitted_lines:
        parts.append(sanitize_cell('[...]'))
    return parts


def _source_parts(diff: FindingDiff, *, excerpt_lines: int) -> list[str]:
    """Render the in-row source evidence of one finding (reporting §7).

    Parameters
    ----------
    diff : FindingDiff
        The diff to render.
    excerpt_lines : int
        Source-evidence budget from the run settings; ``0`` disables.

    Returns
    -------
    list[str]
        Escaped evidence fragments joined beneath the diagnostic.
    """
    if excerpt_lines == 0:
        return []
    parts: list[str] = []
    for occurrence in excerpt_sides(diff):
        excerpt = occurrence.source_excerpt
        if excerpt is None:
            continue
        parts.extend(_excerpt_parts(excerpt))
    return parts


def _message_cell(diff: FindingDiff, *, excerpt_lines: int) -> str:
    """Render the message cell: diagnostic, changed values, then evidence.

    Parameters
    ----------
    diff : FindingDiff
        The diff to render.
    excerpt_lines : int
        Source-evidence budget from the run settings.

    Returns
    -------
    str
        The composite cell text.
    """
    parts = [sanitize_cell(diff.reference_occurrence.message, max_length=_MESSAGE_CAP)]
    parts.extend(
        f'{token}: {sanitize_cell(base_value, max_length=_VALUE_CAP)} '
        f'-> {sanitize_cell(head_value, max_length=_VALUE_CAP)}'
        for token, base_value, head_value in changed_value_details(diff)
    )
    parts.extend(_source_parts(diff, excerpt_lines=excerpt_lines))
    return '<br>'.join(parts)


def _project_lines(project: ProjectReport, *, manifest: RunManifest, has_severity: bool) -> list[str]:
    """Render one project section as markdown (reporting contract §4, §7).

    Parameters
    ----------
    project : ProjectReport
        The per-project report.
    manifest : RunManifest
        The run manifest supplying the corpus pin and evidence budget.
    has_severity : bool
        Whether the severity column is part of the table.

    Returns
    -------
    list[str]
        Markdown lines with all untrusted text sanitized.
    """
    pin = pin_for_project(manifest, project.project)
    cost = f'{project.measured_cost_seconds:.2f}s' if project.measured_cost_seconds is not None else 'n/a'
    lines = [
        '',
        f'## `{sanitize_inline(project.project, max_length=_NAME_CAP)}`',
        '',
        (
            f'base {project.base_findings} findings, head {project.head_findings}; '
            f'{totals_text(project.totals)}; cost {cost}'
        ),
    ]
    if pin is not None:
        pinned_tree = tree_url(pin)
        repo_label = sanitize_cell(pin.repo, max_length=_NAME_CAP)
        sha_label = sanitize_cell(abbreviated_sha(pin.resolved_sha))
        if pinned_tree is not None:
            lines.append(f'- **corpus**: [{repo_label} @ {sha_label}]({pinned_tree})')
        else:
            lines.append(f'- **corpus**: {repo_label} @ {sha_label}')
    lines.extend(f'- **rollup**: {sanitize_cell(rollup)}' for rollup in rollup_lines(project.rollups))
    # Error details quote detector stderr — attacker-influenced text that
    # must not reach markdown unescaped (contract §9).
    lines.extend(f'- **error[{error.side}]**: {sanitize_cell(error.detail)}' for error in project.errors)
    lines.extend(
        f'- **warning[corpus-integrity]**: {sanitize_cell(warning.detail)}' for warning in project.integrity_warnings
    )
    lines.extend(f'- **warning[source]**: {sanitize_cell(warning)}' for warning in project.source_warnings)
    capped = displayed_text(len(project.diffs), project.totals)
    if capped is not None:
        lines.append(f'- note: {capped.replace("--max-results", "`--max-results`")}')
    shown, suppressed = cap_message_only(project.diffs)
    if shown:
        severity_header = ' severity |' if has_severity else ''
        column_count = 6 if has_severity else 5
        lines.extend(['', f'|  | rule | % |{severity_header} location | message |', '|' + ' --- |' * column_count])
        excerpt_lines = manifest.settings.excerpt_lines
        for diff in shown:
            marker = _CLASS_MARKERS[diff.diff_class.value]
            severity_cell = f'| {sanitize_cell(severity_text(diff))} ' if has_severity else ''
            lines.append(
                f'| {marker} {CLASS_GLYPHS[diff.diff_class]} '
                f'| {sanitize_cell(rule_text(diff))} '
                f'| {confidence_text(diff)} '
                f'{severity_cell}'
                f'| {_location_cell(diff, pin)} '
                f'| {_message_cell(diff, excerpt_lines=excerpt_lines)} |'
            )
    if suppressed:
        lines.extend(('', f'({suppressed} more message-only change(s) not shown; the JSON report retains full detail)'))
    return lines


def render_github(report: Report) -> str:
    """Render the report as a GitHub step summary.

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    str
        Markdown, newline-terminated; never ANSI styling or OSC-8 links.
    """
    lines = _manifest_lines(report.manifest)
    summary = overall_summary(report)
    has_severity = report_has_severity(report)
    lines.extend(
        [
            '',
            '## Totals',
            '',
            f'base findings {summary.base_findings}, head findings {summary.head_findings}',
            '',
            '| new | dropped | changed | confidence-only | message-only | severity-only | multiple |',
            '| --- | --- | --- | --- | --- | --- | --- |',
            (
                f'| {report.totals.new} | {report.totals.dropped} | {report.totals.changed} '
                f'| {report.totals.changed_confidence_only} | {report.totals.changed_message_only} '
                f'| {report.totals.changed_severity_only} | {changed_multiple(report.totals)} |'
            ),
            '',
        ]
    )
    lines.extend(f'- **rollup**: {sanitize_cell(rollup)}' for rollup in rollup_lines(report.rollups))
    # The overall header states the same facts in every human output mode
    # (reporting contract §4.1, acceptance 21).
    lines.append(f'- **cost**: {summary.cost}')
    if summary.errors:
        lines.append(f'- **errors**: {summary.errors}')
    if summary.integrity_warnings:
        lines.append(f'- **corpus-integrity warnings**: {summary.integrity_warnings}')
    if summary.source_warnings:
        lines.append(f'- **source warnings**: {summary.source_warnings}')
    if report.truncated:
        lines.extend(('', 'Some project diffs were truncated by `--max-results`; totals reflect the full comparison.'))
    lines.extend(('', f'legend: {CLASS_LEGEND}'))
    for project in report.projects:
        lines.extend(_project_lines(project, manifest=report.manifest, has_severity=has_severity))
    return '\n'.join(line.rstrip() for line in lines) + '\n'
