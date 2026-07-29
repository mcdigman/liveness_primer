"""The GitHub step-summary (markdown) report renderer (contract §9).

Copyright (C) 2026 Matthew C. Digman

PR-comment posting is out of core; this markdown targets
``GITHUB_STEP_SUMMARY`` and the JSON artifact remains the CI-consumable
product.
"""

from liveness_primer.findings import ProjectReport, Report, RunManifest
from liveness_primer.report.common import (
    cap_message_only,
    changed_fields_text,
    confidence_text,
    span_text,
    totals_text,
)
from liveness_primer.report.sanitize import fenced_block, sanitize_cell, sanitize_excerpt, sanitize_inline


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
        delta rendered prominently (contract §3, §11).
    """
    lines = [
        f'# liveness primer report - `{manifest.tool}`',
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
            lines.append(f'- **{side_name} command**: `{" ".join(command)}`')
    comparable = 'yes' if manifest.comparable else 'no (escape-hatch run; gating refused)'
    lines.append(f'- **comparable**: {comparable}')
    if manifest.isolation_enforced:
        lines.append('- **isolation**: enforced')
    else:
        lines.append('- **isolation**: :warning: **NOT ENFORCED** - no network sandbox (contract §11)')
    if manifest.installer is not None:
        lines.append(f'- **installer**: {manifest.installer}')
    if manifest.environment_delta:
        lines.extend(
            [
                '',
                '## :warning: Environment delta',
                '',
                'Non-detector dependencies differ between the sides (contract §3):',
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


def _project_lines(project: ProjectReport, *, excerpt_lines: int) -> list[str]:
    """Render one project section as markdown.

    Parameters
    ----------
    project : ProjectReport
        The per-project report.
    excerpt_lines : int
        Excerpt line cap from the run settings.

    Returns
    -------
    list[str]
        Markdown lines with all untrusted text sanitized and excerpts
        fenced as data (contract §9).
    """
    cost = f'{project.measured_cost_seconds:.2f}s' if project.measured_cost_seconds is not None else 'n/a'
    lines = [
        '',
        f'## `{project.project}`',
        '',
        (
            f'base {project.base_findings} findings, head {project.head_findings}; '
            f'{totals_text(project.totals)}; cost {cost}'
        ),
    ]
    # Error details quote detector stderr — attacker-influenced text that
    # must not reach markdown unescaped (contract §9).
    lines.extend(f'- **error[{error.side}]**: {sanitize_cell(error.detail)}' for error in project.errors)
    lines.extend(
        f'- **warning[corpus-integrity]**: {sanitize_cell(warning.detail)}' for warning in project.integrity_warnings
    )
    if project.truncated:
        lines.append('- note: diffs below are truncated by `--max-results`; totals reflect the full comparison')
    shown, suppressed = cap_message_only(project.diffs)
    if shown:
        lines.extend(['', '| class | location | kind | symbol | fields | confidence | message |', '|' + ' --- |' * 7])
        for diff in shown:
            symbol = sanitize_cell(diff.symbol) if diff.symbol is not None else '-'
            lines.append(
                f'| {diff.diff_class.value} '
                f'| {sanitize_cell(diff.path)}:{span_text(diff)} '
                f'| {sanitize_cell(diff.kind)} '
                f'| {symbol} '
                f'| {changed_fields_text(diff)} '
                f'| {confidence_text(diff)} '
                f'| {sanitize_cell(diff.reference_occurrence.message)} |'
            )
    if suppressed:
        lines.extend(('', f'({suppressed} more message-only change(s) not shown; the JSON report retains full detail)'))
    excerpts: list[str] = []
    for diff in shown:
        raw = diff.reference_occurrence.raw_excerpt
        if raw is not None:
            location = sanitize_inline(diff.path) + ':' + span_text(diff)
            excerpts.append(f'[{diff.diff_class.value}] {location}')
            excerpts.extend(sanitize_excerpt(raw, max_lines=excerpt_lines))
    if excerpts:
        lines.extend(
            ['', '<details><summary>excerpts (untrusted data)</summary>', '', fenced_block(excerpts), '', '</details>']
        )
    return lines


def render_github(report: Report) -> str:
    """Render the report as a GitHub step summary (contract §9).

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    str
        Markdown, newline-terminated.
    """
    lines = _manifest_lines(report.manifest)
    lines.extend(
        [
            '',
            '## Totals',
            '',
            '| new | dropped | changed | confidence changes | message-only |',
            '| --- | --- | --- | --- | --- |',
            (
                f'| {report.totals.new} | {report.totals.dropped} | {report.totals.changed} '
                f'| {report.totals.changed_confidence} | {report.totals.changed_message_only} |'
            ),
        ]
    )
    if report.truncated:
        lines.extend(('', 'Some project diffs were truncated by `--max-results`; totals reflect the full comparison.'))
    for project in report.projects:
        lines.extend(_project_lines(project, excerpt_lines=report.manifest.settings.excerpt_lines))
    return '\n'.join(line.rstrip() for line in lines) + '\n'
