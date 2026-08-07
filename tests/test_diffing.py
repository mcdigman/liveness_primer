"""Tests for the three-stage deterministic diff engine (contract §8).

Copyright (C) 2026 Matthew C. Digman
"""

from collections.abc import Iterable, Sequence

import pytest

from liveness_primer.diffing import DiffEngineError, ProjectDiff, compute_rollups, diff_findings, merge_rollups
from liveness_primer.findings import ChangedField, DiffClass, DiffRollup, DiffTotals, Finding, FindingOccurrence


def mk(
    start_line: int,
    *,
    end_line: int | None = None,
    message: str = 'm',
    confidence: int | None = None,
    severity: str | None = None,
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
        severity=severity,
        rule_id=rule_id,
        raw_excerpt=f'{path}:{start_line}: {message}',
    )


def run_diff(
    base: Iterable[Finding],
    head: Iterable[Finding],
    *,
    confidence_capable: bool = False,
    severity_capable: bool = False,
) -> ProjectDiff:
    return diff_findings(base, head, confidence_capable=confidence_capable, severity_capable=severity_capable)


def test_identical_sides_yield_no_diffs() -> None:
    findings = [mk(3), mk(7, message='other')]
    result = run_diff(findings, findings)
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
        run_diff([finding], [finding])


def test_identity_missing_from_both_indexes_raises_informative_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_identity(
        _findings: Iterable[Finding],
    ) -> dict[str, tuple[None, list[FindingOccurrence]]]:
        return {'missing': (None, [])}

    monkeypatch.setattr('liveness_primer.diffing._index_findings', missing_identity)
    with pytest.raises(DiffEngineError, match="identity 'missing' is absent from both base and head indexes"):
        run_diff([], [])


def test_multiset_semantics_keep_surplus_duplicates() -> None:
    result = run_diff([mk(3), mk(3)], [mk(3)])
    assert len(result.diffs) == 1
    diff = result.diffs[0]
    assert diff.diff_class is DiffClass.DROPPED
    assert diff.base_occurrence is not None
    assert diff.base_occurrence.start_line == 3
    assert result.totals == DiffTotals(dropped=1)


def test_disjoint_identities_classify_new_and_dropped() -> None:
    result = run_diff([mk(3, symbol='gone')], [mk(9, symbol='fresh')])
    by_class = {diff.diff_class: diff for diff in result.diffs}
    assert by_class[DiffClass.DROPPED].symbol == 'gone'
    assert by_class[DiffClass.NEW].symbol == 'fresh'
    assert result.totals == DiffTotals(new=1, dropped=1)


def test_same_identity_message_change_pairs_in_stage_two() -> None:
    result = run_diff([mk(5, message='before')], [mk(5, message='after')])
    (diff,) = result.diffs
    assert diff.diff_class is DiffClass.CHANGED
    assert diff.changed_fields == (ChangedField.MESSAGE,)
    assert result.totals == DiffTotals(changed=1, changed_message_only=1)


def test_same_identity_confidence_change_when_capable() -> None:
    result = run_diff([mk(5, confidence=60)], [mk(5, confidence=90)], confidence_capable=True)
    (diff,) = result.diffs
    assert diff.changed_fields == (ChangedField.CONFIDENCE,)
    assert result.totals == DiffTotals(changed=1, changed_confidence=1)


def test_same_identity_severity_change_when_capable() -> None:
    result = run_diff([mk(5, severity='MEDIUM')], [mk(5, severity='HIGH')], severity_capable=True)
    (diff,) = result.diffs
    assert diff.diff_class is DiffClass.CHANGED
    assert diff.changed_fields == (ChangedField.SEVERITY,)
    assert result.totals == DiffTotals(changed=1, changed_severity_only=1)


def test_severity_appearing_or_disappearing_is_a_severity_change() -> None:
    result = run_diff([mk(5, severity=None)], [mk(5, severity='LOW')], severity_capable=True)
    (diff,) = result.diffs
    assert diff.changed_fields == (ChangedField.SEVERITY,)


def test_confidence_change_without_capability_is_an_engine_error() -> None:
    with pytest.raises(DiffEngineError, match='has-confidence'):
        run_diff([mk(5, confidence=60)], [mk(5, confidence=90)])


def test_severity_change_without_capability_is_an_engine_error() -> None:
    with pytest.raises(DiffEngineError, match='has-severity'):
        run_diff([mk(5, severity='MEDIUM')], [mk(5, severity='HIGH')])


def test_end_line_growth_changes_identity() -> None:
    # The line span is part of the finding identity: a grown span is a
    # dropped finding plus a new one, never a `changed` pair.
    result = run_diff([mk(5, end_line=6)], [mk(5, end_line=9)])
    assert {diff.diff_class for diff in result.diffs} == {DiffClass.NEW, DiffClass.DROPPED}
    assert result.totals == DiffTotals(new=1, dropped=1)


def test_cross_line_movement_changes_identity() -> None:
    result = run_diff([mk(10)], [mk(12)])
    by_class = {diff.diff_class: diff for diff in result.diffs}
    dropped = by_class[DiffClass.DROPPED].base_occurrence
    new = by_class[DiffClass.NEW].head_occurrence
    assert dropped is not None
    assert new is not None
    assert (dropped.start_line, new.start_line) == (10, 12)
    assert result.totals == DiffTotals(new=1, dropped=1)


def test_stage_two_pairs_canonically_and_leaves_the_surplus() -> None:
    # Three base and two head occurrences of one identity, none equal:
    # both sides pair positionally in canonical (message) order and the
    # surplus base occurrence drops.
    base = [mk(5, message='a'), mk(5, message='c'), mk(5, message='e')]
    head = [mk(5, message='b'), mk(5, message='d')]
    result = run_diff(base, head)
    changed = [diff for diff in result.diffs if diff.diff_class is DiffClass.CHANGED]
    dropped = [diff for diff in result.diffs if diff.diff_class is DiffClass.DROPPED]
    pairs = [
        (diff.base_occurrence.message, diff.head_occurrence.message)
        for diff in changed
        if diff.base_occurrence is not None and diff.head_occurrence is not None
    ]
    assert pairs == [('a', 'b'), ('c', 'd')]
    assert len(dropped) == 1
    assert dropped[0].base_occurrence is not None
    assert dropped[0].base_occurrence.message == 'e'
    assert result.totals == DiffTotals(dropped=1, changed=2, changed_message_only=2)


def test_stage_one_removes_equal_occurrences_before_pairing() -> None:
    base = [mk(5, message='same'), mk(5, message='b')]
    head = [mk(5, message='same'), mk(5, message='z')]
    result = run_diff(base, head)
    (diff,) = result.diffs
    assert diff.diff_class is DiffClass.CHANGED
    assert diff.base_occurrence is not None
    assert diff.head_occurrence is not None
    assert (diff.base_occurrence.message, diff.head_occurrence.message) == ('b', 'z')


def test_matching_is_order_independent() -> None:
    base = [mk(10), mk(50, message='x'), mk(5, symbol='other'), mk(50)]
    head = [mk(12), mk(51), mk(5, symbol='other', message='y'), mk(50, message='z')]
    forward = run_diff(base, head)
    backward = run_diff(list(reversed(base)), list(reversed(head)))
    assert forward == backward


def test_report_order_is_path_then_line_then_rule() -> None:
    # Contract §8, §12: diffs read in file order — path, then start line,
    # rule ID (absent first), end line, identity — not symbol order.
    base = [
        mk(9, path='b.py', symbol='zeta'),
        mk(4, path='a.py', symbol='alpha'),
        mk(2, path='a.py', symbol='zeta'),
        mk(4, path='a.py', symbol='alpha', kind='method', rule_id='SKY-U001'),
    ]
    result = run_diff(base, [])
    ordering = [
        (diff.path, diff.reference_occurrence.start_line, diff.reference_occurrence.rule_id) for diff in result.diffs
    ]
    assert ordering == [('a.py', 2, None), ('a.py', 4, None), ('a.py', 4, 'SKY-U001'), ('b.py', 9, None)]
    assert result.totals == DiffTotals(dropped=4)


def test_new_and_dropped_within_one_identity_order_canonically() -> None:
    base = [mk(10, message='b'), mk(10, message='a')]
    head: list[Finding] = []
    result = run_diff(base, head)
    messages = [diff.base_occurrence.message for diff in result.diffs if diff.base_occurrence is not None]
    assert messages == ['a', 'b']


def test_excerpt_differences_alone_do_not_survive_stage_one() -> None:
    base = [mk(5)]
    head_finding = mk(5).model_copy(update={'raw_excerpt': 'different raw text'})
    result = run_diff(base, [head_finding])
    assert result.diffs == ()


def test_rule_id_change_is_new_plus_dropped() -> None:
    # Reporting contract §3.1 and acceptance 3: the rule ID is part of the
    # finding identity, so a changed rule code is a dropped finding of the
    # first code plus a new finding of the second — never one `changed`
    # pair. The change never leaves the blast radius.
    result = run_diff([mk(5, rule_id='SKY-U001')], [mk(5, rule_id='SKY-U003')])
    assert {diff.diff_class for diff in result.diffs} == {DiffClass.NEW, DiffClass.DROPPED}
    assert result.totals == DiffTotals(new=1, dropped=1)


def test_rule_id_appearing_or_disappearing_changes_identity() -> None:
    result = run_diff([mk(5, rule_id=None)], [mk(5, rule_id='SKY-U001')])
    assert {diff.diff_class for diff in result.diffs} == {DiffClass.NEW, DiffClass.DROPPED}


def test_kind_change_stays_new_plus_dropped() -> None:
    # A bucket move that also changes kind changes identity: it remains a
    # `new` plus a `dropped` finding (reporting acceptance 3).
    result = run_diff(
        [mk(5, kind='variable', rule_id='SKY-U003')],
        [mk(5, kind='parameter', rule_id='SKY-U006')],
    )
    assert {diff.diff_class for diff in result.diffs} == {DiffClass.NEW, DiffClass.DROPPED}
    assert result.totals == DiffTotals(new=1, dropped=1)


def test_same_line_findings_with_distinct_rules_keep_distinct_identities() -> None:
    # Two security diagnostics on one line (e.g. skylos SKY-D203 and
    # SKY-D212) never cross-pair; each matches only its own rule.
    base = [mk(9, kind='danger', symbol=None, rule_id='SKY-D203', severity='HIGH', message='os.system')]
    head = [
        mk(9, kind='danger', symbol=None, rule_id='SKY-D203', severity='CRITICAL', message='os.system'),
        mk(9, kind='danger', symbol=None, rule_id='SKY-D212', severity='CRITICAL', message='injection'),
    ]
    result = run_diff(base, head, severity_capable=True)
    by_class = {diff.diff_class: diff for diff in result.diffs}
    assert by_class[DiffClass.CHANGED].reference_occurrence.rule_id == 'SKY-D203'
    assert by_class[DiffClass.CHANGED].changed_fields == (ChangedField.SEVERITY,)
    assert by_class[DiffClass.NEW].reference_occurrence.rule_id == 'SKY-D212'
    assert result.totals == DiffTotals(new=1, changed=1, changed_severity_only=1)


def test_severity_and_unused_findings_coexist_on_one_symbol() -> None:
    # A security diagnostic and a dead-code finding on the same symbol have
    # different kinds and rules, hence distinct identities.
    unused = mk(5, kind='function', rule_id='SKY-U001', confidence=100)
    danger = mk(5, kind='danger', rule_id='SKY-D205', severity='CRITICAL', message='pickle.loads')
    result = run_diff([unused, danger], [unused], severity_capable=True, confidence_capable=True)
    (diff,) = result.diffs
    assert diff.diff_class is DiffClass.DROPPED
    assert diff.kind == 'danger'


def test_rollups_group_by_rule_with_kind_fallback() -> None:
    base = [mk(1, symbol='a', rule_id='SKY-U001'), mk(2, symbol='b', kind='variable')]
    head = [
        mk(3, symbol='c', rule_id='SKY-U001'),
        mk(4, symbol='d', rule_id='SKY-U001'),
        mk(5, symbol='e', rule_id='SKY-U002'),
        mk(6, symbol='f', message='x'),
    ]
    result = run_diff(base, head)
    assert result.rollups == (
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=2),
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U002', kind=None, count=1),
        DiffRollup(diff_class=DiffClass.NEW, rule_id=None, kind='function', count=1),
        DiffRollup(diff_class=DiffClass.DROPPED, rule_id='SKY-U001', kind=None, count=1),
        DiffRollup(diff_class=DiffClass.DROPPED, rule_id=None, kind='variable', count=1),
    )


def test_rollups_changed_pairs_group_by_reference_side() -> None:
    # A `changed` pair groups by its reference-side (base) occurrence.
    result = run_diff([mk(5, rule_id='SKY-U001', message='a')], [mk(5, rule_id='SKY-U001', message='b')])
    assert result.rollups == (DiffRollup(diff_class=DiffClass.CHANGED, rule_id='SKY-U001', kind=None, count=1),)


def test_rollup_ordering_is_class_then_count_then_label() -> None:
    rollups = compute_rollups(
        run_diff(
            [],
            [
                mk(1, symbol='a', rule_id='SKY-U009'),
                mk(2, symbol='b', rule_id='SKY-U001'),
                mk(3, symbol='c', rule_id='SKY-U001'),
                mk(4, symbol='d', rule_id='SKY-U005'),
            ],
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
