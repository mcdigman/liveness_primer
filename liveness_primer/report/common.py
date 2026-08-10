"""Formatting helpers shared by the report renderers (contract §8, §9).

Copyright (C) 2026 Matthew C. Digman

The helpers here fix the semantic text of both human renderers — class
glyphs, confidence forms, changed-field tokens, and aggregate rollup lines
(reporting contract §3.2, §4) — so the text and GitHub reports differ only
in structure and styling.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import NamedTuple

from liveness_primer.findings import (
    ChangedField,
    CorpusPinRecord,
    DiffClass,
    DiffRollup,
    DiffTotals,
    FindingDiff,
    FindingOccurrence,
    Report,
    RunManifest,
)
from liveness_primer.report.sanitize import sanitize_inline
from liveness_primer.tools.base import UnknownToolError
from liveness_primer.tools.registry import get_adapter

# Rendered reports cap message-only changes to a count plus bounded
# examples; the JSON report retains full detail (contract §8).
MESSAGE_ONLY_EXAMPLES = 3

# Stable, output-independent class glyphs (reporting contract §4.2).
CLASS_GLYPHS = {DiffClass.NEW: '+', DiffClass.DROPPED: '-', DiffClass.CHANGED: '~'}

# Compact legend shown once before the first finding table.
CLASS_LEGEND = '+ new; - dropped; ~ changed'

# Human renderers show at most the five largest rollup groups per class.
ROLLUP_DISPLAY_GROUPS = 5

# Compact changed-field tokens in canonical field order (reporting §4.4).
_FIELD_TOKENS = {
    ChangedField.MESSAGE: 'message',
    ChangedField.CONFIDENCE: '%',
    ChangedField.SEVERITY: 'severity',
}

_ROLLUP_LABEL_CAP = 40
_ABBREVIATED_SHA = 12


def abbreviated_sha(sha: str) -> str:
    """Abbreviate a resolved commit SHA for headers.

    Parameters
    ----------
    sha : str
        Full resolved SHA.

    Returns
    -------
    str
        The first twelve characters.
    """
    return sha[:_ABBREVIATED_SHA]


def pin_for_project(manifest: RunManifest, project: str) -> CorpusPinRecord | None:
    """Look up the resolved corpus pin of one project.

    Parameters
    ----------
    manifest : RunManifest
        The run manifest.
    project : str
        Corpus project name.

    Returns
    -------
    CorpusPinRecord | None
        The first pin whose name matches, or ``None``.
    """
    for pin in manifest.corpus_pins:
        if pin.name == project:
            return pin
    return None


def tool_has_severity(tool: str) -> bool:
    """Report whether a tool's adapter declares the has-severity capability.

    Renderers omit the severity column for tools without the capability
    (reporting contract §4.3); an unregistered tool name is assumed capable
    and left to :func:`report_has_severity`, which suppresses the column
    when no finding carries a severity anyway.

    Parameters
    ----------
    tool : str
        Adapter name from the run manifest.

    Returns
    -------
    bool
        True when a registered adapter declares has-severity, or the tool
        is unregistered.
    """
    try:
        adapter = get_adapter(tool)
    except UnknownToolError:
        return True
    return adapter.capabilities.has_severity


def report_has_severity(report: Report) -> bool:
    """Report whether a rendered severity column would carry any value.

    A severity-capable tool can still produce a report in which no finding
    has a severity; the column is suppressed rather than rendered wholly
    absent (reporting contract §4.3).

    Parameters
    ----------
    report : Report
        The report to render.

    Returns
    -------
    bool
        True when the tool is severity-capable and at least one occurrence
        carries a severity label.
    """
    if not tool_has_severity(report.manifest.tool):
        return False
    return any(
        occurrence is not None and occurrence.severity is not None
        for project in report.projects
        for diff in project.diffs
        for occurrence in (diff.base_occurrence, diff.head_occurrence)
    )


def occurrence_span_text(occurrence: FindingOccurrence) -> str:
    """Describe one occurrence's line span compactly.

    Parameters
    ----------
    occurrence : FindingOccurrence
        The occurrence to describe.

    Returns
    -------
    str
        ``L5`` for a point span, else ``L5-8``.
    """
    if occurrence.end_line != occurrence.start_line:
        return f'L{occurrence.start_line}-{occurrence.end_line}'
    return f'L{occurrence.start_line}'


def span_text(diff: FindingDiff) -> str:
    """Describe the line position of a diff compactly.

    The identity hash pins the line span, so both sides of a ``changed``
    pair always share it.

    Parameters
    ----------
    diff : FindingDiff
        The diff to describe.

    Returns
    -------
    str
        ``L5`` for a point span, else ``L5-8``.
    """
    return occurrence_span_text(diff.reference_occurrence)


def confidence_value_text(confidence: int | None) -> str:
    """Render one confidence value (reporting contract §4.3).

    Parameters
    ----------
    confidence : int | None
        Confidence percentage, when present.

    Returns
    -------
    str
        ``NA`` when absent, else ``XX%``.
    """
    return 'NA' if confidence is None else f'{confidence}%'


def confidence_text(diff: FindingDiff) -> str:
    """Describe a diff's confidence in the exact §4.3 forms.

    Parameters
    ----------
    diff : FindingDiff
        The diff to describe.

    Returns
    -------
    str
        ``NA``, ``XX%``, ``NA->XX%``, ``XX%->NA``, or ``XX%->YY%``.
    """
    if (
        ChangedField.CONFIDENCE in diff.changed_fields
        and diff.base_occurrence is not None
        and diff.head_occurrence is not None
    ):
        base = confidence_value_text(diff.base_occurrence.confidence)
        head = confidence_value_text(diff.head_occurrence.confidence)
        return f'{base}->{head}'
    return confidence_value_text(diff.reference_occurrence.confidence)


def severity_value_text(severity: str | None) -> str:
    """Render one severity value (reporting contract §4.3).

    Parameters
    ----------
    severity : str | None
        Canonical severity label, when present.

    Returns
    -------
    str
        ``NA`` when absent, else the label; sanitize before display.
    """
    return 'NA' if severity is None else severity


def severity_text(diff: FindingDiff) -> str:
    """Describe a diff's severity in analogy to :func:`confidence_text`.

    Parameters
    ----------
    diff : FindingDiff
        The diff to describe.

    Returns
    -------
    str
        ``NA``, ``HIGH``, ``NA->HIGH``, ``HIGH->NA``, or ``HIGH->LOW``;
        raw text to sanitize before display.
    """
    if (
        ChangedField.SEVERITY in diff.changed_fields
        and diff.base_occurrence is not None
        and diff.head_occurrence is not None
    ):
        base = severity_value_text(diff.base_occurrence.severity)
        head = severity_value_text(diff.head_occurrence.severity)
        return f'{base}->{head}'
    return severity_value_text(diff.reference_occurrence.severity)


def rule_text(diff: FindingDiff) -> str:
    """Render the reference-side rule ID of a diff (reporting contract §3.1).

    An absent rule ID displays as ``-``; a tool-specific code is never
    invented.

    Parameters
    ----------
    diff : FindingDiff
        The diff to describe.

    Returns
    -------
    str
        The raw reference-side rule ID, or ``-``; sanitize before display.
    """
    rule_id = diff.reference_occurrence.rule_id
    return '-' if rule_id is None else rule_id


def changed_fields_text(diff: FindingDiff) -> str:
    """Describe the changed-field set with the compact §4.4 tokens.

    Parameters
    ----------
    diff : FindingDiff
        The diff to describe.

    Returns
    -------
    str
        Comma-joined tokens in canonical field order, or ``-``.
    """
    if not diff.changed_fields:
        return '-'
    return ','.join(_FIELD_TOKENS[field] for field in diff.changed_fields)


class ChangedValue(NamedTuple):
    """One changed field's compact token and its base and head values.

    Attributes
    ----------
    token : str
        Compact changed-field token, in canonical field order.
    base : str
        Raw base-side value; sanitize before display.
    head : str
        Raw head-side value; sanitize before display.
    """

    token: str
    base: str
    head: str


def changed_value_details(diff: FindingDiff) -> tuple[ChangedValue, ...]:
    """List base and head values for each changed field.

    Listing only the field names is not sufficient evidence; renderers show
    these pairs as continuation lines beneath the summary row.

    Parameters
    ----------
    diff : FindingDiff
        The ``changed`` diff to describe.

    Returns
    -------
    tuple[ChangedValue, ...]
        One entry per changed field.
    """
    base = diff.base_occurrence
    head = diff.head_occurrence
    if base is None or head is None:
        return ()
    values: dict[ChangedField, tuple[str, str]] = {
        ChangedField.MESSAGE: (base.message, head.message),
        ChangedField.CONFIDENCE: (confidence_value_text(base.confidence), confidence_value_text(head.confidence)),
        ChangedField.SEVERITY: (severity_value_text(base.severity), severity_value_text(head.severity)),
    }
    return tuple(ChangedValue(_FIELD_TOKENS[field], *values[field]) for field in diff.changed_fields)


def rollup_label(rollup: DiffRollup) -> str:
    """Render one rollup group's label (reporting contract §3.2).

    Kind fallbacks render as ``kind:<kind>`` rather than being presented as
    rule IDs.

    Parameters
    ----------
    rollup : DiffRollup
        The rollup group.

    Returns
    -------
    str
        The sanitized group label.
    """
    if rollup.rule_id is not None:
        return sanitize_inline(rollup.rule_id, max_length=_ROLLUP_LABEL_CAP)
    return 'kind:' + sanitize_inline(rollup.kind if rollup.kind is not None else '', max_length=_ROLLUP_LABEL_CAP)


def rollup_lines(rollups: Sequence[DiffRollup]) -> tuple[str, ...]:
    """Render aggregate rollups, one line per nonzero diff class (reporting §3.2).

    Each line shows at most the five largest groups; an omitted tail states
    both its finding count and group count.

    Parameters
    ----------
    rollups : Sequence[DiffRollup]
        Deterministically ordered rollup groups.

    Returns
    -------
    tuple[str, ...]
        The rollup display lines.
    """
    lines: list[str] = []
    for diff_class in (DiffClass.NEW, DiffClass.DROPPED, DiffClass.CHANGED):
        groups = [rollup for rollup in rollups if rollup.diff_class is diff_class]
        if not groups:
            continue
        class_total = sum(group.count for group in groups)
        parts = [f'{rollup_label(group)} {group.count}' for group in groups[:ROLLUP_DISPLAY_GROUPS]]
        tail = groups[ROLLUP_DISPLAY_GROUPS:]
        if tail:
            tail_findings = sum(group.count for group in tail)
            parts.append(f'{tail_findings} finding(s) across {len(tail)} other group(s)')
        lines.append(f'{diff_class.value} {class_total}: {", ".join(parts)}')
    return tuple(lines)


def excerpt_sides(diff: FindingDiff) -> tuple[FindingOccurrence, ...]:
    """Choose the source-evidence occurrences a diff renders (reporting §4.5).

    Parameters
    ----------
    diff : FindingDiff
        The diff to render.

    Returns
    -------
    tuple[FindingOccurrence, ...]
        The head side for ``new``, else the base side. Both sides of a
        ``changed`` pair share their identity-pinned span, so one block
        always suffices.
    """
    if diff.diff_class is DiffClass.NEW and diff.head_occurrence is not None:
        return (diff.head_occurrence,)
    if diff.base_occurrence is None:
        return ()
    return (diff.base_occurrence,)


def is_message_only(diff: FindingDiff) -> bool:
    """Report whether a diff is a message-only change.

    Parameters
    ----------
    diff : FindingDiff
        The diff to test.

    Returns
    -------
    bool
        True when only the message changed.
    """
    return diff.changed_fields == (ChangedField.MESSAGE,)


def cap_message_only(diffs: Sequence[FindingDiff]) -> tuple[list[FindingDiff], int]:
    """Cap message-only changes to bounded examples (contract §8).

    Parameters
    ----------
    diffs : Sequence[FindingDiff]
        Diffs in report order.

    Returns
    -------
    tuple[list[FindingDiff], int]
        The diffs to render (order preserved) and the number of suppressed
        message-only changes.
    """
    shown: list[FindingDiff] = []
    message_only_seen = 0
    for diff in diffs:
        if is_message_only(diff):
            message_only_seen += 1
            if message_only_seen > MESSAGE_ONLY_EXAMPLES:
                continue
        shown.append(diff)
    suppressed = max(0, message_only_seen - MESSAGE_ONLY_EXAMPLES)
    return shown, suppressed


def totals_text(totals: DiffTotals) -> str:
    """Summarize diff totals on one line (contract §8).

    Parameters
    ----------
    totals : DiffTotals
        The totals to summarize.

    Returns
    -------
    str
        Counts per class with confidence, message-only, and severity-only
        breakouts.
    """
    return (
        f'{totals.new} new, {totals.dropped} dropped, {totals.changed} changed '
        f'({totals.changed_confidence} confidence, {totals.changed_message_only} message-only, '
        f'{totals.changed_severity_only} severity-only)'
    )


@dataclass(frozen=True, slots=True)
class OverallSummary:
    """Overall header facts shared by both human renderers (reporting §4.1).

    Attributes
    ----------
    base_findings : int
        Base-side findings parsed across all projects.
    head_findings : int
        Head-side findings parsed across all projects.
    cost : str
        Measured execution cost, or ``n/a`` when nothing was measured.
    errors : int
        Detector invocation failures across all projects.
    integrity_warnings : int
        Corpus-integrity warnings across all projects.
    source_warnings : int
        Pinned-source evidence warnings across all projects.
    """

    base_findings: int
    head_findings: int
    cost: str
    errors: int
    integrity_warnings: int
    source_warnings: int


def overall_summary(report: Report) -> OverallSummary:
    """Summarize the overall header facts (reporting contract §4.1).

    Every human output mode states the same facts; a mode that omits cost
    or the warning summaries is incomplete, not merely styled differently.

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    OverallSummary
        The shared overall header facts.
    """
    measured = [
        project.measured_cost_seconds for project in report.projects if project.measured_cost_seconds is not None
    ]
    return OverallSummary(
        base_findings=sum(project.base_findings for project in report.projects),
        head_findings=sum(project.head_findings for project in report.projects),
        cost=f'{sum(measured):.2f}s' if measured else 'n/a',
        errors=sum(len(project.errors) for project in report.projects),
        integrity_warnings=sum(len(project.integrity_warnings) for project in report.projects),
        source_warnings=sum(len(project.source_warnings) for project in report.projects),
    )


def displayed_text(displayed: int, totals: DiffTotals) -> str | None:
    """State displayed versus complete finding counts when capped (reporting §4.1).

    Parameters
    ----------
    displayed : int
        Retained finding diffs after the results cap.
    totals : DiffTotals
        Complete pre-truncation totals.

    Returns
    -------
    str | None
        The capped-count statement, or ``None`` when nothing was capped.
    """
    complete = totals.new + totals.dropped + totals.changed
    if displayed >= complete:
        return None
    return f'showing {displayed} of {complete} finding diffs (truncated by --max-results)'
