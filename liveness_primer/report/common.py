"""Formatting helpers shared by the report renderers (contract §8, §9).

Copyright (C) 2026 Matthew C. Digman
"""

from collections.abc import Sequence

from liveness_primer.findings import ChangedField, DiffClass, DiffTotals, FindingDiff

# Rendered reports cap message-only changes to a count plus bounded
# examples; the JSON report retains full detail (contract §8).
MESSAGE_ONLY_EXAMPLES = 3


def span_text(diff: FindingDiff) -> str:
    """Describe the line position of a diff compactly.

    Parameters
    ----------
    diff : FindingDiff
        The diff to describe.

    Returns
    -------
    str
        ``L5``, ``L5-8``, or ``L5->L9`` for cross-line ``changed`` pairs.
    """
    if diff.diff_class is DiffClass.CHANGED:
        base = diff.base_occurrence
        head = diff.head_occurrence
        if base is not None and head is not None and base.start_line != head.start_line:
            return f'L{base.start_line}->L{head.start_line}'
    occurrence = diff.reference_occurrence
    if occurrence.end_line != occurrence.start_line:
        return f'L{occurrence.start_line}-{occurrence.end_line}'
    return f'L{occurrence.start_line}'


def confidence_text(diff: FindingDiff) -> str:
    """Describe the reference-side confidence of a diff.

    Parameters
    ----------
    diff : FindingDiff
        The diff to describe.

    Returns
    -------
    str
        ``NN%``, ``NN%->MM%`` for confidence changes, or ``-``.
    """
    reference = diff.reference_occurrence
    if ChangedField.CONFIDENCE in diff.changed_fields and diff.head_occurrence is not None:
        head_confidence = diff.head_occurrence.confidence
        head_text = '-' if head_confidence is None else f'{head_confidence}%'
        base_text = '-' if reference.confidence is None else f'{reference.confidence}%'
        return f'{base_text}->{head_text}'
    if reference.confidence is None:
        return '-'
    return f'{reference.confidence}%'


def changed_fields_text(diff: FindingDiff) -> str:
    """Describe the changed-field set of a diff.

    Parameters
    ----------
    diff : FindingDiff
        The diff to describe.

    Returns
    -------
    str
        Comma-joined field names, or ``-`` for ``new``/``dropped``.
    """
    if not diff.changed_fields:
        return '-'
    return ','.join(field.value for field in diff.changed_fields)


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
        Counts per class with confidence and message-only breakouts.
    """
    return (
        f'{totals.new} new, {totals.dropped} dropped, {totals.changed} changed '
        f'({totals.changed_confidence} confidence, {totals.changed_message_only} message-only)'
    )
