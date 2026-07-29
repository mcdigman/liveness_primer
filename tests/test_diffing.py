"""Tests for the four-stage deterministic diff engine (contract §8).

Copyright (C) 2026 Matthew C. Digman
"""

import pytest

from liveness_primer.diffing import DiffEngineError, diff_findings
from liveness_primer.findings import ChangedField, DiffClass, DiffTotals, Finding


def mk(
    start_line: int,
    *,
    end_line: int | None = None,
    message: str = 'm',
    confidence: int | None = None,
    symbol: str | None = 'sym',
    path: str = 'f.py',
    kind: str = 'function',
    tool: str = 'vulture',
    project: str = 'demo',
) -> Finding:
    return Finding(
        tool=tool,
        project=project,
        path=path,
        symbol=symbol,
        kind=kind,
        message=message,
        start_line=start_line,
        end_line=end_line if end_line is not None else start_line,
        confidence=confidence,
        raw_excerpt=f'{path}:{start_line}: {message}',
    )


def test_identical_sides_yield_no_diffs() -> None:
    findings = [mk(3), mk(7, message='other')]
    result = diff_findings(findings, findings, confidence_capable=False)
    assert result.diffs == ()
    assert result.totals == DiffTotals()


def test_multiset_semantics_keep_surplus_duplicates() -> None:
    result = diff_findings([mk(3), mk(3)], [mk(3)], confidence_capable=False)
    assert len(result.diffs) == 1
    diff = result.diffs[0]
    assert diff.diff_class is DiffClass.DROPPED
    assert diff.base_occurrence is not None
    assert diff.base_occurrence.start_line == 3
    assert result.totals == DiffTotals(dropped=1)


def test_disjoint_identities_classify_new_and_dropped() -> None:
    result = diff_findings([mk(3, symbol='gone')], [mk(9, symbol='fresh')], confidence_capable=False)
    by_class = {diff.diff_class: diff for diff in result.diffs}
    assert by_class[DiffClass.DROPPED].symbol == 'gone'
    assert by_class[DiffClass.NEW].symbol == 'fresh'
    assert result.totals == DiffTotals(new=1, dropped=1)


def test_same_line_message_change_pairs_in_stage_two() -> None:
    result = diff_findings([mk(5, message='before')], [mk(5, message='after')], confidence_capable=False)
    (diff,) = result.diffs
    assert diff.diff_class is DiffClass.CHANGED
    assert diff.changed_fields == (ChangedField.MESSAGE,)
    assert result.totals == DiffTotals(changed=1, changed_message_only=1)


def test_same_line_confidence_change_when_capable() -> None:
    result = diff_findings([mk(5, confidence=60)], [mk(5, confidence=90)], confidence_capable=True)
    (diff,) = result.diffs
    assert diff.changed_fields == (ChangedField.CONFIDENCE,)
    assert result.totals == DiffTotals(changed=1, changed_confidence=1)


def test_end_line_growth_is_a_line_span_change() -> None:
    result = diff_findings([mk(5, end_line=6)], [mk(5, end_line=9)], confidence_capable=False)
    (diff,) = result.diffs
    assert diff.changed_fields == (ChangedField.LINE_SPAN,)


def test_confidence_change_without_capability_is_an_engine_error() -> None:
    with pytest.raises(DiffEngineError, match='has-confidence'):
        diff_findings([mk(5, confidence=60)], [mk(5, confidence=90)], confidence_capable=False)


def test_cross_line_movement_pairs_in_stage_three() -> None:
    result = diff_findings([mk(10)], [mk(12)], confidence_capable=False)
    (diff,) = result.diffs
    assert diff.diff_class is DiffClass.CHANGED
    assert diff.changed_fields == (ChangedField.LINE_SPAN,)
    assert diff.base_occurrence is not None
    assert diff.head_occurrence is not None
    assert (diff.base_occurrence.start_line, diff.head_occurrence.start_line) == (10, 12)


def test_alignment_minimizes_total_start_line_distance() -> None:
    base = [mk(10), mk(50)]
    head = [mk(11), mk(30), mk(51)]
    result = diff_findings(base, head, confidence_capable=False)
    changed = [diff for diff in result.diffs if diff.diff_class is DiffClass.CHANGED]
    new = [diff for diff in result.diffs if diff.diff_class is DiffClass.NEW]
    pairs = {
        (diff.base_occurrence.start_line, diff.head_occurrence.start_line)
        for diff in changed
        if diff.base_occurrence is not None and diff.head_occurrence is not None
    }
    assert pairs == {(10, 11), (50, 51)}
    assert len(new) == 1
    assert new[0].head_occurrence is not None
    assert new[0].head_occurrence.start_line == 30
    assert result.totals == DiffTotals(new=1, changed=2)


def test_alignment_ties_break_toward_earlier_lines() -> None:
    result = diff_findings([mk(10)], [mk(8), mk(12)], confidence_capable=False)
    changed = [diff for diff in result.diffs if diff.diff_class is DiffClass.CHANGED]
    new = [diff for diff in result.diffs if diff.diff_class is DiffClass.NEW]
    assert len(changed) == 1
    assert changed[0].head_occurrence is not None
    assert changed[0].head_occurrence.start_line == 8
    assert len(new) == 1
    assert new[0].head_occurrence is not None
    assert new[0].head_occurrence.start_line == 12


def test_alignment_skips_surplus_base_occurrences() -> None:
    result = diff_findings([mk(10), mk(30), mk(52)], [mk(11), mk(51)], confidence_capable=False)
    dropped = [diff for diff in result.diffs if diff.diff_class is DiffClass.DROPPED]
    assert len(dropped) == 1
    assert dropped[0].base_occurrence is not None
    assert dropped[0].base_occurrence.start_line == 30


def test_stage_two_and_three_compose() -> None:
    base = [mk(5, message='a'), mk(5, message='b')]
    head = [mk(5, message='c'), mk(9, message='a')]
    result = diff_findings(base, head, confidence_capable=False)
    assert result.totals == DiffTotals(changed=2, changed_message_only=1)
    stage_two = [diff for diff in result.diffs if ChangedField.LINE_SPAN not in diff.changed_fields]
    stage_three = [diff for diff in result.diffs if ChangedField.LINE_SPAN in diff.changed_fields]
    (two,) = stage_two
    assert two.base_occurrence is not None
    assert two.head_occurrence is not None
    assert (two.base_occurrence.message, two.head_occurrence.message) == ('a', 'c')
    (three,) = stage_three
    assert three.base_occurrence is not None
    assert three.head_occurrence is not None
    assert (three.base_occurrence.message, three.head_occurrence.message) == ('b', 'a')
    assert three.changed_fields == (ChangedField.LINE_SPAN, ChangedField.MESSAGE)


def test_matching_is_order_independent() -> None:
    base = [mk(10), mk(50, message='x'), mk(5, symbol='other'), mk(50)]
    head = [mk(12), mk(51), mk(5, symbol='other', message='y'), mk(50, message='z')]
    forward = diff_findings(base, head, confidence_capable=False)
    backward = diff_findings(list(reversed(base)), list(reversed(head)), confidence_capable=False)
    assert forward == backward


def test_report_order_is_deterministic_across_identities() -> None:
    base = [
        mk(9, path='b.py', symbol='zeta'),
        mk(2, path='a.py', symbol='alpha'),
        mk(4, path='a.py', symbol='alpha', kind='method'),
    ]
    result = diff_findings(base, [], confidence_capable=False)
    ordering = [(diff.path, diff.symbol, diff.kind) for diff in result.diffs]
    assert ordering == [('a.py', 'alpha', 'function'), ('a.py', 'alpha', 'method'), ('b.py', 'zeta', 'function')]
    assert result.totals == DiffTotals(dropped=3)


def test_new_and_dropped_within_one_identity_order_canonically() -> None:
    base = [mk(30), mk(10)]
    head: list[Finding] = []
    result = diff_findings(base, head, confidence_capable=False)
    lines = [diff.base_occurrence.start_line for diff in result.diffs if diff.base_occurrence is not None]
    assert lines == [10, 30]


def test_excerpt_differences_alone_do_not_survive_stage_one() -> None:
    base = [mk(5)]
    head_finding = mk(5).model_copy(update={'raw_excerpt': 'different raw text'})
    result = diff_findings(base, [head_finding], confidence_capable=False)
    assert result.diffs == ()
