"""The deterministic, order-independent diff engine (contract §8).

Copyright (C) 2026 Matthew C. Digman

Both revisions see identical files; matching proceeds in four stages per
finding identity: (1) full-field-equal occurrences are removed by multiset
intersection; (2) occurrences sharing (identity, start line) are paired in
canonical-key order as ``changed``; (3) occurrences sharing identity are
paired across lines by a deterministic order-preserving alignment minimizing
total start-line distance, ties broken toward earlier lines, as ``changed``;
(4) leftovers classify as ``new`` or ``dropped``.
"""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from liveness_primer.errors import LivenessPrimerError
from liveness_primer.findings import (
    ChangedField,
    DiffClass,
    DiffRollup,
    DiffTotals,
    Finding,
    FindingDiff,
    FindingOccurrence,
    canonical_occurrence_key,
)


class DiffEngineError(LivenessPrimerError):
    """Raised when findings violate a diff-engine invariant."""


@dataclass(frozen=True, slots=True)
class _IdentityInfo:
    """Denormalized identity fields shared by all occurrences of one identity.

    Attributes
    ----------
    tool : str
        Adapter name of the reporting detector.
    project : str
        Corpus project name.
    path : str
        Repo-relative POSIX path.
    symbol : str | None
        Reported symbol, when present.
    kind : str
        Normalized finding kind.
    """

    tool: str
    project: str
    path: str
    symbol: str | None
    kind: str


@dataclass(frozen=True, slots=True)
class ProjectDiff:
    """Classified diffs and pre-truncation aggregates for one (project, tool) pair.

    Attributes
    ----------
    diffs : tuple[FindingDiff, ...]
        All classified diffs in deterministic report order, untruncated.
    totals : DiffTotals
        Totals over ``diffs``.
    rollups : tuple[DiffRollup, ...]
        Complete rollups over ``diffs`` (reporting contract §3.2).
    """

    diffs: tuple[FindingDiff, ...]
    totals: DiffTotals
    rollups: tuple[DiffRollup, ...]


_CLASS_RANK = {DiffClass.NEW: 0, DiffClass.DROPPED: 1, DiffClass.CHANGED: 2}


def _index_findings(findings: Iterable[Finding]) -> dict[str, tuple[_IdentityInfo, list[FindingOccurrence]]]:
    """Group findings into per-identity occurrence multisets.

    Parameters
    ----------
    findings : Iterable[Finding]
        Findings from one report side.

    Returns
    -------
    dict[str, tuple[_IdentityInfo, list[FindingOccurrence]]]
        Identity hash mapped to its shared fields and occurrence list, each
        occurrence list sorted by canonical key.
    """
    grouped: dict[str, tuple[_IdentityInfo, list[FindingOccurrence]]] = {}
    for finding in findings:
        identity = finding.identity
        if identity not in grouped:
            info = _IdentityInfo(
                tool=finding.tool,
                project=finding.project,
                path=finding.path,
                symbol=finding.symbol,
                kind=finding.kind,
            )
            grouped[identity] = (info, [])
        grouped[identity][1].append(finding.occurrence())
    for _info, occurrences in grouped.values():
        occurrences.sort(key=canonical_occurrence_key)
    return grouped


def _remove_equal(
    base: Sequence[FindingOccurrence],
    head: Sequence[FindingOccurrence],
) -> tuple[list[FindingOccurrence], list[FindingOccurrence]]:
    """Remove full-field-equal occurrences by multiset intersection (stage 1).

    Equality is on the canonical occurrence tuple; the untrusted raw excerpt
    is provenance, not an observable field.

    Parameters
    ----------
    base : Sequence[FindingOccurrence]
        Base-side occurrences in canonical-key order.
    head : Sequence[FindingOccurrence]
        Head-side occurrences in canonical-key order.

    Returns
    -------
    tuple[list[FindingOccurrence], list[FindingOccurrence]]
        The surviving base and head occurrences, still in canonical order.
    """
    base_left: list[FindingOccurrence] = []
    head_left: list[FindingOccurrence] = []
    i = j = 0
    while i < len(base) and j < len(head):
        base_key = canonical_occurrence_key(base[i])
        head_key = canonical_occurrence_key(head[j])
        if base_key == head_key:
            i += 1
            j += 1
        elif base_key < head_key:
            base_left.append(base[i])
            i += 1
        else:
            head_left.append(head[j])
            j += 1
    base_left.extend(base[i:])
    head_left.extend(head[j:])
    return base_left, head_left


def _pair_same_line(
    base: Sequence[FindingOccurrence],
    head: Sequence[FindingOccurrence],
) -> tuple[
    list[tuple[FindingOccurrence, FindingOccurrence]],
    list[FindingOccurrence],
    list[FindingOccurrence],
]:
    """Pair occurrences sharing a start line in canonical-key order (stage 2).

    Parameters
    ----------
    base : Sequence[FindingOccurrence]
        Surviving base occurrences in canonical order.
    head : Sequence[FindingOccurrence]
        Surviving head occurrences in canonical order.

    Returns
    -------
    tuple[list[tuple[FindingOccurrence, FindingOccurrence]], list[FindingOccurrence], list[FindingOccurrence]]
        The ``changed`` pairs plus the base and head leftovers in canonical
        order.
    """
    base_by_line: dict[int, list[FindingOccurrence]] = defaultdict(list)
    head_by_line: dict[int, list[FindingOccurrence]] = defaultdict(list)
    for occurrence in base:
        base_by_line[occurrence.start_line].append(occurrence)
    for occurrence in head:
        head_by_line[occurrence.start_line].append(occurrence)
    pairs: list[tuple[FindingOccurrence, FindingOccurrence]] = []
    base_left: list[FindingOccurrence] = []
    head_left: list[FindingOccurrence] = []
    for line in sorted(base_by_line.keys() | head_by_line.keys()):
        base_group = base_by_line.get(line, [])
        head_group = head_by_line.get(line, [])
        paired = min(len(base_group), len(head_group))
        pairs.extend(zip(base_group[:paired], head_group[:paired], strict=True))
        base_left.extend(base_group[paired:])
        head_left.extend(head_group[paired:])
    base_left.sort(key=canonical_occurrence_key)
    head_left.sort(key=canonical_occurrence_key)
    return pairs, base_left, head_left


def _align_across_lines(
    base: Sequence[FindingOccurrence],
    head: Sequence[FindingOccurrence],
) -> tuple[
    list[tuple[FindingOccurrence, FindingOccurrence]],
    list[FindingOccurrence],
    list[FindingOccurrence],
]:
    """Align remaining occurrences across lines (stage 3).

    Both sides are in canonical-key order; the alignment is order-preserving
    with gaps, pairs exactly ``min(len(base), len(head))`` occurrences, and
    minimizes total start-line distance. Ties are broken toward pairing at the
    earliest positions, i.e. toward earlier lines.

    Parameters
    ----------
    base : Sequence[FindingOccurrence]
        Base leftovers in canonical order.
    head : Sequence[FindingOccurrence]
        Head leftovers in canonical order.

    Returns
    -------
    tuple[list[tuple[FindingOccurrence, FindingOccurrence]], list[FindingOccurrence], list[FindingOccurrence]]
        The ``changed`` pairs plus unpaired base and head occurrences.
    """
    m, n = len(base), len(head)
    if m == 0 or n == 0:
        return [], list(base), list(head)
    # cost[i][j]: minimal total start-line distance aligning base[i:] with
    # head[j:] while pairing exactly min(m - i, n - j) occurrences.
    cost = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m - 1, -1, -1):
        for j in range(n - 1, -1, -1):
            match = abs(base[i].start_line - head[j].start_line) + cost[i + 1][j + 1]
            remaining_base = m - i
            remaining_head = n - j
            if remaining_base == remaining_head:
                cost[i][j] = match
            elif remaining_base < remaining_head:
                cost[i][j] = min(match, cost[i][j + 1])
            else:
                cost[i][j] = min(match, cost[i + 1][j])
    pairs: list[tuple[FindingOccurrence, FindingOccurrence]] = []
    base_left: list[FindingOccurrence] = []
    head_left: list[FindingOccurrence] = []
    i = j = 0
    while i < m and j < n:
        match = abs(base[i].start_line - head[j].start_line) + cost[i + 1][j + 1]
        if cost[i][j] == match:
            pairs.append((base[i], head[j]))
            i += 1
            j += 1
        elif m - i < n - j:
            head_left.append(head[j])
            j += 1
        else:
            base_left.append(base[i])
            i += 1
    base_left.extend(base[i:])
    head_left.extend(head[j:])
    return pairs, base_left, head_left


def _changed_fields(
    base: FindingOccurrence,
    head: FindingOccurrence,
    *,
    confidence_capable: bool,
) -> tuple[ChangedField, ...]:
    """Compute the changed-field set of a paired occurrence (contract §8).

    Parameters
    ----------
    base : FindingOccurrence
        Base-side occurrence.
    head : FindingOccurrence
        Head-side occurrence.
    confidence_capable : bool
        Whether the tool declares the has-confidence capability.

    Returns
    -------
    tuple[ChangedField, ...]
        The non-empty subset of fields that differ, in enum order.

    Raises
    ------
    DiffEngineError
        If confidence differs for a tool without the has-confidence
        capability, or no observable field differs at all.
    """
    changed: list[ChangedField] = []
    if (base.start_line, base.end_line) != (head.start_line, head.end_line):
        changed.append(ChangedField.LINE_SPAN)
    if base.message != head.message:
        changed.append(ChangedField.MESSAGE)
    if base.confidence != head.confidence:
        if not confidence_capable:
            msg = 'confidence differs for a tool without the has-confidence capability'
            raise DiffEngineError(msg)
        changed.append(ChangedField.CONFIDENCE)
    if base.rule_id != head.rule_id:
        # A rule-code change on the same target pairs as one `changed` diff
        # and must never disappear from the blast radius (reporting §3.1).
        changed.append(ChangedField.RULE)
    if not changed:
        msg = 'paired occurrences with no changed observable field survived stage 1'
        raise DiffEngineError(msg)
    return tuple(changed)


class _DiffSortKey(NamedTuple):
    path: str
    symbol: str
    kind: str
    identity: str
    class_rank: int
    reference_occurrence: tuple[int, int, str, int, int, int, str]


def _diff_sort_key(diff: FindingDiff) -> _DiffSortKey:
    """Compute the deterministic report-order key of a diff (contract §8, §12).

    Parameters
    ----------
    diff : FindingDiff
        The diff to key.

    Returns
    -------
    _DiffSortKey
        Sort key: path, symbol, kind, identity, class rank, then the
        reference-side canonical occurrence key that ``--occurrence`` indexes.
    """
    return _DiffSortKey(
        path=diff.path,
        symbol='' if diff.symbol is None else diff.symbol,
        kind=diff.kind,
        identity=diff.identity,
        class_rank=_CLASS_RANK[diff.diff_class],
        reference_occurrence=canonical_occurrence_key(diff.reference_occurrence),
    )


def _rollup_sort_key(rollup: DiffRollup) -> tuple[int, int, str]:
    """Compute the deterministic rollup ordering key (reporting contract §3.2).

    Parameters
    ----------
    rollup : DiffRollup
        The rollup group to key.

    Returns
    -------
    tuple[int, int, str]
        Sort key: diff class in ``new``/``dropped``/``changed`` order, then
        descending count, then the rule ID or kind lexicographically.
    """
    label = rollup.rule_id if rollup.rule_id is not None else rollup.kind
    return (_CLASS_RANK[rollup.diff_class], -rollup.count, label if label is not None else '')


def compute_rollups(diffs: Iterable[FindingDiff]) -> tuple[DiffRollup, ...]:
    """Roll the complete diff sequence up by diff class and rule ID (reporting §3.2).

    A finding with a rule ID groups by rule ID regardless of kind; otherwise
    it groups by kind. A ``changed`` pair groups by its reference-side
    occurrence. Rollups must be computed before ``--max-results`` truncation.

    Parameters
    ----------
    diffs : Iterable[FindingDiff]
        The complete classified diff sequence.

    Returns
    -------
    tuple[DiffRollup, ...]
        Deterministically ordered rollup groups.
    """
    counts: dict[tuple[DiffClass, str | None, str | None], int] = {}
    for diff in diffs:
        rule_id = diff.reference_occurrence.rule_id
        key = (diff.diff_class, rule_id, diff.kind if rule_id is None else None)
        counts[key] = counts.get(key, 0) + 1
    rollups = [
        DiffRollup(diff_class=diff_class, rule_id=rule_id, kind=kind, count=count)
        for (diff_class, rule_id, kind), count in counts.items()
    ]
    rollups.sort(key=_rollup_sort_key)
    return tuple(rollups)


def merge_rollups(rollup_groups: Iterable[tuple[DiffRollup, ...]]) -> tuple[DiffRollup, ...]:
    """Sum per-project rollups into overall rollups (reporting contract §3.2).

    Parameters
    ----------
    rollup_groups : Iterable[tuple[DiffRollup, ...]]
        Complete rollups of each project.

    Returns
    -------
    tuple[DiffRollup, ...]
        Deterministically ordered overall rollup groups.
    """
    counts: dict[tuple[DiffClass, str | None, str | None], int] = {}
    for group in rollup_groups:
        for rollup in group:
            key = (rollup.diff_class, rollup.rule_id, rollup.kind)
            counts[key] = counts.get(key, 0) + rollup.count
    merged = [
        DiffRollup(diff_class=diff_class, rule_id=rule_id, kind=kind, count=count)
        for (diff_class, rule_id, kind), count in counts.items()
    ]
    merged.sort(key=_rollup_sort_key)
    return tuple(merged)


def _totals(diffs: Sequence[FindingDiff]) -> DiffTotals:
    """Tally diff totals before truncation (contract §8).

    Parameters
    ----------
    diffs : Sequence[FindingDiff]
        All classified diffs.

    Returns
    -------
    DiffTotals
        Counts per class, with confidence and message-only changes broken out.
    """
    new = sum(1 for diff in diffs if diff.diff_class is DiffClass.NEW)
    dropped = sum(1 for diff in diffs if diff.diff_class is DiffClass.DROPPED)
    changed = [diff for diff in diffs if diff.diff_class is DiffClass.CHANGED]
    return DiffTotals(
        new=new,
        dropped=dropped,
        changed=len(changed),
        changed_confidence=sum(1 for diff in changed if ChangedField.CONFIDENCE in diff.changed_fields),
        changed_message_only=sum(1 for diff in changed if diff.changed_fields == (ChangedField.MESSAGE,)),
    )


def diff_findings(
    base: Iterable[Finding],
    head: Iterable[Finding],
    *,
    confidence_capable: bool,
) -> ProjectDiff:
    """Diff the base and head findings of one (project, tool) pair (contract §8).

    Matching is deterministic and order-independent; every normalized
    observable field participates in the comparison.

    Parameters
    ----------
    base : Iterable[Finding]
        Base-side findings.
    head : Iterable[Finding]
        Head-side findings.
    confidence_capable : bool
        Whether the tool declares the has-confidence capability.

    Returns
    -------
    ProjectDiff
        All classified diffs in deterministic order plus totals.

    Raises
    ------
    DiffEngineError
        If confidence changes without declared support, a paired occurrence
        has no changed field, or an indexed identity has no metadata on either
        side.
    """
    base_index = _index_findings(base)
    head_index = _index_findings(head)
    absent: tuple[_IdentityInfo | None, list[FindingOccurrence]] = (None, [])
    diffs: list[FindingDiff] = []
    for identity in base_index.keys() | head_index.keys():
        base_info, base_occurrences = base_index.get(identity, absent)
        head_info, head_occurrences = head_index.get(identity, absent)
        info = base_info if base_info is not None else head_info
        if info is None:
            msg = f'identity {identity!r} is absent from both base and head indexes'
            raise DiffEngineError(msg)
        base_rest, head_rest = _remove_equal(base_occurrences, head_occurrences)
        line_pairs, base_rest, head_rest = _pair_same_line(base_rest, head_rest)
        cross_pairs, base_rest, head_rest = _align_across_lines(base_rest, head_rest)
        for base_occurrence, head_occurrence in (*line_pairs, *cross_pairs):
            diffs.append(
                FindingDiff(
                    diff_class=DiffClass.CHANGED,
                    identity=identity,
                    tool=info.tool,
                    project=info.project,
                    path=info.path,
                    symbol=info.symbol,
                    kind=info.kind,
                    base_occurrence=base_occurrence,
                    head_occurrence=head_occurrence,
                    changed_fields=_changed_fields(
                        base_occurrence,
                        head_occurrence,
                        confidence_capable=confidence_capable,
                    ),
                )
            )
        diffs.extend(
            FindingDiff(
                diff_class=DiffClass.DROPPED,
                identity=identity,
                tool=info.tool,
                project=info.project,
                path=info.path,
                symbol=info.symbol,
                kind=info.kind,
                base_occurrence=occurrence,
            )
            for occurrence in base_rest
        )
        diffs.extend(
            FindingDiff(
                diff_class=DiffClass.NEW,
                identity=identity,
                tool=info.tool,
                project=info.project,
                path=info.path,
                symbol=info.symbol,
                kind=info.kind,
                head_occurrence=occurrence,
            )
            for occurrence in head_rest
        )
    diffs.sort(key=_diff_sort_key)
    return ProjectDiff(diffs=tuple(diffs), totals=_totals(diffs), rollups=compute_rollups(diffs))
