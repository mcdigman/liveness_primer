"""The CLI text report renderer (contract §9).

Copyright (C) 2026 Matthew C. Digman
"""

from liveness_primer.findings import ProjectReport, Report, RunManifest
from liveness_primer.report.common import (
    cap_message_only,
    changed_fields_text,
    confidence_text,
    span_text,
    totals_text,
)
from liveness_primer.report.sanitize import sanitize_excerpt, sanitize_inline


def _manifest_lines(manifest: RunManifest) -> list[str]:
    """Render the manifest header.

    Parameters
    ----------
    manifest : RunManifest
        The run manifest.

    Returns
    -------
    list[str]
        Header lines, with unenforced isolation and any environment delta
        rendered prominently (contract §3, §11).
    """
    lines = [
        f'liveness primer report - tool: {manifest.tool}',
        f'schema: {manifest.schema_version}; created: {manifest.created_at.isoformat()}',
    ]
    if manifest.detector_repo is not None:
        lines.append(f'detector: {manifest.detector_repo}')
    for side_name, record in (('base', manifest.base), ('head', manifest.head)):
        if record is not None:
            provenance = 'cached' if record.from_cache else 'rebuilt'
            lines.append(f'  {side_name}: {record.ref} @ {record.sha[:12]} ({provenance})')
    for side_name, command in (('base', manifest.base_cmd), ('head', manifest.head_cmd)):
        if command is not None:
            lines.append(f'  {side_name} command: {" ".join(command)}')
    lines.append(f'comparable: {"yes" if manifest.comparable else "no (escape-hatch run; gating refused)"}')
    if manifest.isolation_enforced:
        lines.append('isolation: enforced')
    else:
        lines.append('isolation: NOT ENFORCED - build/analysis ran without a network sandbox (contract §11)')
    if manifest.installer is not None:
        lines.append(f'installer: {manifest.installer}')
    if manifest.environment_delta:
        lines.append('environment delta - non-detector dependencies differ between the sides (contract §3):')
        for delta in manifest.environment_delta:
            base = delta.base_version if delta.base_version is not None else 'absent'
            head = delta.head_version if delta.head_version is not None else 'absent'
            lines.append(f'  {delta.package}: {base} -> {head}')
    return lines


def _project_lines(project: ProjectReport, *, excerpt_lines: int) -> list[str]:
    """Render one project section.

    Parameters
    ----------
    project : ProjectReport
        The per-project report.
    excerpt_lines : int
        Excerpt line cap from the run settings.

    Returns
    -------
    list[str]
        Section lines with all untrusted text sanitized (contract §9).
    """
    cost = f'{project.measured_cost_seconds:.2f}s' if project.measured_cost_seconds is not None else 'n/a'
    header = (
        f'project {project.project} - base {project.base_findings} findings, '
        f'head {project.head_findings}; {totals_text(project.totals)}; cost {cost}'
    )
    lines = [header]
    lines.extend(f'  error[{error.side}]: {sanitize_inline(error.detail)}' for error in project.errors)
    lines.extend(
        f'  warning[corpus-integrity]: {sanitize_inline(warning.detail)}' for warning in project.integrity_warnings
    )
    if project.truncated:
        lines.append('  note: diffs below are truncated by --max-results; totals above reflect the full comparison')
    shown, suppressed = cap_message_only(project.diffs)
    for diff in shown:
        symbol = sanitize_inline(diff.symbol) if diff.symbol is not None else '-'
        heading = (
            f'  {diff.diff_class.value:<7} {sanitize_inline(diff.path)}:{span_text(diff)} '
            f'{sanitize_inline(diff.kind)} {symbol} [{changed_fields_text(diff)}] ({confidence_text(diff)})'
        )
        lines.extend((heading, f'          {sanitize_inline(diff.reference_occurrence.message)}'))
        excerpt = diff.reference_occurrence.raw_excerpt
        if excerpt is not None:
            lines.extend(f'          | {line}' for line in sanitize_excerpt(excerpt, max_lines=excerpt_lines))
    if suppressed:
        lines.append(f'  ({suppressed} more message-only change(s) not shown; the JSON report retains full detail)')
    return lines


def render_text(report: Report) -> str:
    """Render the report for terminal consumption (contract §9).

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    str
        The full text report, newline-terminated.
    """
    lines = _manifest_lines(report.manifest)
    lines.append(f'totals: {totals_text(report.totals)}')
    if report.truncated:
        lines.append('note: some project diffs were truncated by --max-results; totals reflect the full comparison')
    for project in report.projects:
        lines.append('')
        lines.extend(_project_lines(project, excerpt_lines=report.manifest.settings.excerpt_lines))
    return '\n'.join(line.rstrip() for line in lines) + '\n'
