"""Tests for the four-stage deterministic diff engine (contract §8).

Copyright (C) 2026 Matthew C. Digman
"""

from collections.abc import Iterable, Sequence

import pytest

from liveness_primer.diffing import DiffEngineError, compute_rollups, diff_findings, merge_rollups
from liveness_primer.findings import ChangedField, DiffClass, DiffRollup, DiffTotals, Finding, FindingOccurrence


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
    rule_id: str | None = None,
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
        rule_id=rule_id,
        raw_excerpt=f'{path}:{start_line}: {message}',
    )


def test_identical_sides_yield_no_diffs() -> None:
    findings = [mk(3), mk(7, message='other')]
    result = diff_findings(findings, findings, confidence_capable=False)
    assert result.diffs == ()
    assert result.totals == DiffTotals()


def test_equal_pair_surviving_stage_one_raises_informative_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def retain_equal_pairs(
        base: Sequence[FindingOccurrence],
        head: Sequence[FindingOccurrence],
    ) -> tuple[list[FindingOccurrence], list[FindingOccurrence]]:
        return list(base), list(head)

    monkeypatch.setattr('liveness_primer.diffing._remove_equal', retain_equal_pairs)
    finding = mk(3)
    with pytest.raises(DiffEngineError, match='no changed observable field survived stage 1'):
        diff_findings([finding], [finding], confidence_capable=False)


def test_identity_missing_from_both_indexes_raises_informative_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_identity(
        _findings: Iterable[Finding],
    ) -> dict[str, tuple[None, list[FindingOccurrence]]]:
        return {'missing': (None, [])}

    monkeypatch.setattr('liveness_primer.diffing._index_findings', missing_identity)
    with pytest.raises(DiffEngineError, match="identity 'missing' is absent from both base and head indexes"):
        diff_findings([], [], confidence_capable=False)


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


def test_rule_id_change_pairs_as_one_changed_diff() -> None:
    # Reporting contract §3.1 and acceptance 3: identical identity fields
    # with different explicit rule IDs become one `changed` finding with
    # `rule` in changed_fields — the change never leaves the blast radius.
    result = diff_findings([mk(5, rule_id='SKY-U001')], [mk(5, rule_id='SKY-U003')], confidence_capable=False)
    (diff,) = result.diffs
    assert diff.diff_class is DiffClass.CHANGED
    assert diff.changed_fields == (ChangedField.RULE,)
    assert result.totals == DiffTotals(changed=1)


def test_rule_id_appearing_or_disappearing_is_a_rule_change() -> None:
    result = diff_findings([mk(5, rule_id=None)], [mk(5, rule_id='SKY-U001')], confidence_capable=False)
    (diff,) = result.diffs
    assert diff.changed_fields == (ChangedField.RULE,)


def test_kind_change_stays_new_plus_dropped() -> None:
    # A bucket move that also changes kind changes identity: it remains a
    # `new` plus a `dropped` finding (reporting acceptance 3).
    result = diff_findings(
        [mk(5, kind='variable', rule_id='SKY-U003')],
        [mk(5, kind='parameter', rule_id='SKY-U006')],
        confidence_capable=False,
    )
    assert {diff.diff_class for diff in result.diffs} == {DiffClass.NEW, DiffClass.DROPPED}
    assert result.totals == DiffTotals(new=1, dropped=1)


def test_canonical_key_orders_rule_ids_after_confidence() -> None:
    # Same line and message; the rule ID is the deciding key component, and
    # absent sorts before present (reporting contract §3.1).
    base = [mk(5, rule_id='SKY-U001'), mk(5, rule_id=None)]
    head = [mk(5, rule_id='SKY-U002'), mk(5, rule_id='SKY-U009')]
    result = diff_findings(base, head, confidence_capable=False)
    pairs = [
        (diff.base_occurrence.rule_id, diff.head_occurrence.rule_id)
        for diff in result.diffs
        if diff.base_occurrence is not None and diff.head_occurrence is not None
    ]
    assert pairs == [(None, 'SKY-U002'), ('SKY-U001', 'SKY-U009')]


def test_rollups_group_by_rule_with_kind_fallback() -> None:
    base = [mk(1, symbol='a', rule_id='SKY-U001'), mk(2, symbol='b', kind='variable')]
    head = [
        mk(3, symbol='c', rule_id='SKY-U001'),
        mk(4, symbol='d', rule_id='SKY-U001'),
        mk(5, symbol='e', rule_id='SKY-U002'),
        mk(6, symbol='f', message='x'),
    ]
    result = diff_findings(base, head, confidence_capable=False)
    assert result.rollups == (
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=2),
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U002', kind=None, count=1),
        DiffRollup(diff_class=DiffClass.NEW, rule_id=None, kind='function', count=1),
        DiffRollup(diff_class=DiffClass.DROPPED, rule_id='SKY-U001', kind=None, count=1),
        DiffRollup(diff_class=DiffClass.DROPPED, rule_id=None, kind='variable', count=1),
    )


def test_rollups_changed_pairs_group_by_reference_side() -> None:
    # A `changed` pair groups by its reference-side (base) occurrence.
    result = diff_findings([mk(5, rule_id='SKY-U001')], [mk(5, rule_id='SKY-U003')], confidence_capable=False)
    assert result.rollups == (DiffRollup(diff_class=DiffClass.CHANGED, rule_id='SKY-U001', kind=None, count=1),)


def test_rollup_ordering_is_class_then_count_then_label() -> None:
    rollups = compute_rollups(
        diff_findings(
            [],
            [
                mk(1, symbol='a', rule_id='SKY-U009'),
                mk(2, symbol='b', rule_id='SKY-U001'),
                mk(3, symbol='c', rule_id='SKY-U001'),
                mk(4, symbol='d', rule_id='SKY-U005'),
            ],
            confidence_capable=False,
        ).diffs
    )
    assert [(rollup.rule_id, rollup.count) for rollup in rollups] == [
        ('SKY-U001', 2),
        ('SKY-U005', 1),
        ('SKY-U009', 1),
    ]


def test_merge_rollups_sums_and_reorders() -> None:
    alpha = (
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=1),
        DiffRollup(diff_class=DiffClass.CHANGED, rule_id=None, kind='function', count=2),
    )
    beta = (
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U002', kind=None, count=4),
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=2),
    )
    assert merge_rollups([alpha, beta]) == (
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U002', kind=None, count=4),
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=3),
        DiffRollup(diff_class=DiffClass.CHANGED, rule_id=None, kind='function', count=2),
    )
