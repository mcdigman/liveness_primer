# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for pinned-source evidence collection (reporting contract §3.3)."""

import os
from pathlib import Path

import pytest

from liveness_primer.filesystem import atomic_write_text
from liveness_primer.findings import ChangedField, DiffClass, SourceExcerpt
from liveness_primer.report.source import (
    MAX_SOURCE_WARNINGS,
    collect_source_evidence,
    extract_excerpt,
    split_source_lines,
)
from tests.test_report import diff, occurrence

FILE_LINES = [f'line {number}' for number in range(1, 21)]


def write_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / 'checkout'
    (checkout / 'pkg').mkdir(parents=True)
    atomic_write_text(checkout / 'pkg' / 'mod.py', '\n'.join(FILE_LINES) + '\n')
    return checkout


def test_extract_excerpt_point_finding_fills_budget_with_following_lines() -> None:
    excerpt, warning = extract_excerpt(FILE_LINES, start_line=4, end_line=4, budget=3)
    assert warning is None
    assert excerpt == SourceExcerpt(start_line=4, lines=('line 4', 'line 5', 'line 6'), omitted_lines=0)


def test_extract_excerpt_span_prioritizes_span_and_counts_omissions() -> None:
    excerpt, warning = extract_excerpt(FILE_LINES, start_line=2, end_line=9, budget=3)
    assert warning is None
    # The span exceeds the budget: its first lines are retained and the
    # remaining existing span lines are counted, never the context beyond.
    assert excerpt == SourceExcerpt(start_line=2, lines=('line 2', 'line 3', 'line 4'), omitted_lines=5)


def test_extract_excerpt_short_span_fills_remaining_budget() -> None:
    excerpt, warning = extract_excerpt(FILE_LINES, start_line=2, end_line=3, budget=4)
    assert warning is None
    assert excerpt == SourceExcerpt(start_line=2, lines=('line 2', 'line 3', 'line 4', 'line 5'), omitted_lines=0)


def test_extract_excerpt_point_near_end_of_file_has_zero_omissions() -> None:
    # Reporting acceptance 19.
    excerpt, warning = extract_excerpt(FILE_LINES, start_line=20, end_line=20, budget=5)
    assert warning is None
    assert excerpt == SourceExcerpt(start_line=20, lines=('line 20',), omitted_lines=0)


def test_extract_excerpt_span_truncated_by_end_of_file_counts_only_existing_lines() -> None:
    excerpt, warning = extract_excerpt(FILE_LINES, start_line=19, end_line=25, budget=1)
    assert warning is None
    # Existing span lines are 19 and 20; the budget keeps line 19 only.
    assert excerpt == SourceExcerpt(start_line=19, lines=('line 19',), omitted_lines=1)


def test_extract_excerpt_beyond_end_of_file_warns_instead_of_fabricating() -> None:
    excerpt, warning = extract_excerpt(FILE_LINES, start_line=99, end_line=99, budget=3)
    assert excerpt is None
    assert warning == 'reported line 99 is beyond the end of the file (20 line(s))'


def test_collect_attaches_reference_side_evidence(tmp_path: Path) -> None:
    checkout = write_checkout(tmp_path)
    new = diff(DiffClass.NEW, 'a', head=occurrence(4, 'm'))
    dropped = diff(DiffClass.DROPPED, 'b', base=occurrence(6, 'm'))
    (enriched_new, enriched_dropped), warnings = collect_source_evidence(
        (new, dropped), checkout=checkout, excerpt_lines=2
    )
    assert warnings == ()
    assert enriched_new.head_occurrence is not None
    assert enriched_new.head_occurrence.source_excerpt == SourceExcerpt(
        start_line=4, lines=('line 4', 'line 5'), omitted_lines=0
    )
    assert enriched_dropped.base_occurrence is not None
    assert enriched_dropped.base_occurrence.source_excerpt is not None
    assert enriched_dropped.base_occurrence.source_excerpt.lines[0] == 'line 6'


def test_collect_changed_pair_gets_the_reference_side_only(tmp_path: Path) -> None:
    # Both sides of a `changed` pair share their identity-pinned span, so
    # collection touches the reference-side base occurrence only.
    checkout = write_checkout(tmp_path)
    changed = diff(
        DiffClass.CHANGED,
        'u',
        base=occurrence(3, 'old'),
        head=occurrence(3, 'new'),
        fields=(ChangedField.MESSAGE,),
    )
    (enriched,), warnings = collect_source_evidence((changed,), checkout=checkout, excerpt_lines=1)
    assert warnings == ()
    assert enriched.base_occurrence is not None
    assert enriched.base_occurrence.source_excerpt is not None
    assert enriched.base_occurrence.source_excerpt.lines == ('line 3',)
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt is None


def test_collect_zero_budget_disables_collection(tmp_path: Path) -> None:
    checkout = write_checkout(tmp_path)
    entry = diff(DiffClass.NEW, 'a', head=occurrence(4, 'm'))
    (enriched,), warnings = collect_source_evidence((entry,), checkout=checkout, excerpt_lines=0)
    assert warnings == ()
    assert enriched == entry


def test_collect_missing_file_warns_once_per_file(tmp_path: Path) -> None:
    checkout = write_checkout(tmp_path)
    first = diff(DiffClass.NEW, 'a', path='pkg/gone.py', head=occurrence(1, 'm'))
    second = diff(DiffClass.NEW, 'b', path='pkg/gone.py', head=occurrence(2, 'm'))
    (enriched_first, enriched_second), warnings = collect_source_evidence(
        (first, second), checkout=checkout, excerpt_lines=2
    )
    assert enriched_first.head_occurrence is not None
    assert enriched_first.head_occurrence.source_excerpt is None
    assert enriched_second.head_occurrence is not None
    assert enriched_second.head_occurrence.source_excerpt is None
    (warning,) = warnings
    assert warning.startswith('pkg/gone.py: not a regular non-symlink file')


def test_collect_skips_repository_level_findings_without_warning(tmp_path: Path) -> None:
    # Repository-level diagnostics (e.g. skylos SKY-R104) carry the '.'
    # path: they name no file, so no evidence is collected and no warning
    # is emitted.
    checkout = write_checkout(tmp_path)
    repo_level = diff(DiffClass.NEW, 'pre-commit-policy', path='.', kind='quality', head=occurrence(1, 'm'))
    (enriched,), warnings = collect_source_evidence((repo_level,), checkout=checkout, excerpt_lines=2)
    assert warnings == ()
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt is None


def test_collect_out_of_range_line_warns_per_location(tmp_path: Path) -> None:
    checkout = write_checkout(tmp_path)
    entry = diff(DiffClass.NEW, 'a', head=occurrence(99, 'm'))
    (enriched,), warnings = collect_source_evidence((entry,), checkout=checkout, excerpt_lines=2)
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt is None
    (warning,) = warnings
    assert warning == 'pkg/mod.py:L99: reported line 99 is beyond the end of the file (20 line(s))'


def test_collect_file_level_finding_on_zero_line_file_is_source_less(tmp_path: Path) -> None:
    # Reporting §3.3: a file-level finding on a file with zero source lines
    # (e.g. skylos SKY-E002) reports the emptiness itself. It is
    # intentionally source-less, so it neither fabricates an excerpt nor
    # spends the warning budget that exists for genuine source anomalies.
    checkout = write_checkout(tmp_path)
    atomic_write_text(checkout / 'pkg' / 'blank.py', '')
    empty = diff(
        DiffClass.NEW,
        None,
        path='pkg/blank.py',
        kind='file',
        head=occurrence(1, 'Empty Python file (no code, or docstring-only)', rule_id='SKY-E002'),
    )
    missing = diff(DiffClass.NEW, 'a', path='pkg/gone.py', head=occurrence(1, 'm'))
    (enriched_empty, enriched_missing), warnings = collect_source_evidence(
        (empty, missing), checkout=checkout, excerpt_lines=2
    )
    assert enriched_empty.head_occurrence is not None
    assert enriched_empty.head_occurrence.source_excerpt is None
    # The budget still surfaces the unrelated anomaly.
    (warning,) = warnings
    assert warning.startswith('pkg/gone.py: ')
    assert enriched_missing.head_occurrence is not None
    assert enriched_missing.head_occurrence.source_excerpt is None


def test_collect_file_level_finding_on_nonempty_file_gets_evidence(tmp_path: Path) -> None:
    # A docstring-only file also triggers SKY-E002 but has source lines:
    # ordinary excerpt extraction applies.
    checkout = write_checkout(tmp_path)
    atomic_write_text(checkout / 'pkg' / 'doc.py', '"""Docstring only."""\n')
    entry = diff(
        DiffClass.NEW,
        None,
        path='pkg/doc.py',
        kind='file',
        head=occurrence(1, 'Empty Python file (no code, or docstring-only)', rule_id='SKY-E002'),
    )
    (enriched,), warnings = collect_source_evidence((entry,), checkout=checkout, excerpt_lines=2)
    assert warnings == ()
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt == SourceExcerpt(
        start_line=1, lines=('"""Docstring only."""',), omitted_lines=0
    )


def test_collect_symbol_finding_on_zero_line_file_still_warns(tmp_path: Path) -> None:
    # The empty-file exemption is for file-level findings only: a symbol
    # finding pointing into a zero-line file remains a source anomaly.
    checkout = write_checkout(tmp_path)
    atomic_write_text(checkout / 'pkg' / 'blank.py', '')
    entry = diff(DiffClass.NEW, 'a', path='pkg/blank.py', head=occurrence(1, 'm'))
    (enriched,), warnings = collect_source_evidence((entry,), checkout=checkout, excerpt_lines=2)
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt is None
    (warning,) = warnings
    assert warning == 'pkg/blank.py:L1: reported line 1 is beyond the end of the file (0 line(s))'


def test_collect_rejects_symlinks_special_and_undecodable_files(tmp_path: Path) -> None:
    checkout = write_checkout(tmp_path)
    (checkout / 'pkg' / 'link.py').symlink_to(checkout / 'pkg' / 'mod.py')
    (checkout / 'pkg' / 'binary.py').write_bytes(b'\xff\xfe\x00broken')
    os.mkfifo(checkout / 'pkg' / 'fifo.py')
    entries = tuple(
        diff(DiffClass.NEW, symbol, path=path, head=occurrence(1, 'm'))
        for symbol, path in (('a', 'pkg/link.py'), ('b', 'pkg/binary.py'), ('c', 'pkg/fifo.py'))
    )
    enriched, warnings = collect_source_evidence(entries, checkout=checkout, excerpt_lines=2)
    for entry in enriched:
        assert entry.head_occurrence is not None
        assert entry.head_occurrence.source_excerpt is None
    assert len(warnings) == 3
    assert any('link.py' in warning for warning in warnings)
    assert any('not valid UTF-8' in warning for warning in warnings)
    assert any('fifo.py' in warning for warning in warnings)


def test_collect_rejects_oversized_files(tmp_path: Path) -> None:
    checkout = write_checkout(tmp_path)
    (checkout / 'pkg' / 'huge.py').write_text('x' * 1_048_577, encoding='utf-8')
    entry = diff(DiffClass.NEW, 'a', path='pkg/huge.py', head=occurrence(1, 'm'))
    (enriched,), warnings = collect_source_evidence((entry,), checkout=checkout, excerpt_lines=2)
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt is None
    (warning,) = warnings
    assert 'exceeds' in warning


def test_collect_bounds_warning_count(tmp_path: Path) -> None:
    checkout = write_checkout(tmp_path)
    entries = tuple(
        diff(DiffClass.NEW, f's{index}', path=f'pkg/missing{index}.py', head=occurrence(1, 'm'))
        for index in range(MAX_SOURCE_WARNINGS + 5)
    )
    _, warnings = collect_source_evidence(entries, checkout=checkout, excerpt_lines=1)
    assert len(warnings) == MAX_SOURCE_WARNINGS + 1
    assert warnings[-1] == '(5 more source warning(s) omitted)'


@pytest.mark.parametrize(
    ('text', 'expected'),
    [
        ('a\nb\n', ('a', 'b')),
        ('a\r\nb\r\n', ('a', 'b')),
        ('a\rb\r', ('a', 'b')),
        ('a\nb', ('a', 'b')),
        ('a\n\nb\n', ('a', '', 'b')),
        ('', ()),
        # Form feed, vertical tab, NEL, and the Unicode separators are
        # ordinary in-line characters for source numbering (§3.3).
        ('a\fb\nc\n', ('a\fb', 'c')),
        ('a\vb\nc\n', ('a\vb', 'c')),
        ('a\x1cb\x1db\x1eb\nc\n', ('a\x1cb\x1db\x1eb', 'c')),
        ('a\x85b\nc\n', ('a\x85b', 'c')),
        ('a\u2028b\u2029c\nd\n', ('a\u2028b\u2029c', 'd')),
    ],
)
def test_split_source_lines_uses_source_location_newline_semantics(text: str, expected: tuple[str, ...]) -> None:
    assert split_source_lines(text) == expected


def test_collect_does_not_shift_lines_on_hostile_control_characters(tmp_path: Path) -> None:
    # Reporting §3.3 / acceptance 9: a corpus file may embed a form feed on
    # a line that Python counts as one line. Splitting on it would present
    # `FAKE_EVIDENCE` as the source at the reported line 2.
    checkout = tmp_path / 'checkout'
    (checkout / 'pkg').mkdir(parents=True)
    (checkout / 'pkg' / 'mod.py').write_text('# harmless\fFAKE_EVIDENCE = 1\nactual = 2\n', encoding='utf-8')
    entry = diff(DiffClass.NEW, 'actual', head=occurrence(2, 'm'))
    (enriched,), warnings = collect_source_evidence((entry,), checkout=checkout, excerpt_lines=1)
    assert warnings == ()
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt == SourceExcerpt(
        start_line=2, lines=('actual = 2',), omitted_lines=0
    )


def test_collect_unreadable_file_warns_without_leaking_the_checkout(tmp_path: Path) -> None:
    # Reporting §3.3: a PermissionError must not terminate collection.
    checkout = write_checkout(tmp_path)
    unreadable = checkout / 'pkg' / 'locked.py'
    unreadable.write_text('x = 1\n', encoding='utf-8')
    unreadable.chmod(0o000)
    entries = (
        diff(DiffClass.NEW, 'a', path='pkg/locked.py', head=occurrence(1, 'm')),
        diff(DiffClass.NEW, 'b', head=occurrence(4, 'm')),
    )
    try:
        (locked, readable), warnings = collect_source_evidence(entries, checkout=checkout, excerpt_lines=1)
    finally:
        unreadable.chmod(0o600)
    assert locked.head_occurrence is not None
    assert readable.head_occurrence is not None
    if locked.head_occurrence.source_excerpt is not None:  # only reachable when running as root
        pytest.skip('the process can read mode 000 files')
    (warning,) = warnings
    assert warning == 'pkg/locked.py: file could not be read'
    assert str(tmp_path) not in warning
    # Collection continued: the following finding still has its evidence.
    assert readable.head_occurrence.source_excerpt is not None


def test_collect_symlink_loop_warns_instead_of_aborting(tmp_path: Path) -> None:
    # Reporting §3.3: a self-referential symlink is bounded on every
    # supported interpreter, however Path.resolve() reports it.
    checkout = write_checkout(tmp_path)
    (checkout / 'pkg' / 'loop.py').symlink_to(checkout / 'pkg' / 'loop.py')
    entry = diff(DiffClass.NEW, 'a', path='pkg/loop.py', head=occurrence(1, 'm'))
    (enriched,), warnings = collect_source_evidence((entry,), checkout=checkout, excerpt_lines=1)
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt is None
    (warning,) = warnings
    assert warning.startswith('pkg/loop.py: ')
    assert str(tmp_path) not in warning


def test_collect_rejects_traversal_paths(tmp_path: Path) -> None:
    checkout = write_checkout(tmp_path)
    entry = diff(DiffClass.NEW, 'a', path='pkg/../../outside.py', head=occurrence(1, 'm'))
    (enriched,), warnings = collect_source_evidence((entry,), checkout=checkout, excerpt_lines=2)
    assert enriched.head_occurrence is not None
    assert enriched.head_occurrence.source_excerpt is None
    (warning,) = warnings
    assert 'without traversal' in warning
