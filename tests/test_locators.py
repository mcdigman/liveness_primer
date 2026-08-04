"""Tests for serialized finding locators and the shared golden fixture (explorer contract §4.2).

Copyright (C) 2026 Matthew C. Digman

Python generates the checked-in locator golden fixture; the explorer's
frontend tests and the future ``bisect --occurrence`` tests consume the
same fixture and must agree on the identical serialized locator values.
Regenerate it only with the explicit maintenance command
``LP_UPDATE_GOLDENS=1 python -m pytest tests/test_locators.py``; ordinary
runs compare the checked-in values.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from liveness_primer.config import CorpusProject
from liveness_primer.corpus import CheckoutStore
from liveness_primer.diffing import diff_findings, merge_rollups
from liveness_primer.filesystem import atomic_write_text, contained_path, read_small_text
from liveness_primer.findings import (
    CorpusPinRecord,
    DiffClass,
    DiffTotals,
    Finding,
    FindingDiff,
    ProjectReport,
    Report,
    RunManifest,
    RunSettings,
)
from liveness_primer.isolation import UNENFORCED
from liveness_primer.locators import attach_locators
from liveness_primer.runner import PrimerRunner, RunOptions
from liveness_primer.testing import FakeFinding, create_fake_project, write_fake_detector_script
from liveness_primer.tools.registry import get_adapter

GOLDEN_DIR = Path(__file__).parent / 'fixtures'
GOLDEN_NAME = 'locator_golden.json'

TOOL = 'faketool'


def mk(
    project: str,
    symbol: str,
    line: int,
    *,
    path: str = 'pkg/a.py',
    message: str = 'm',
    confidence: int | None = 60,
    rule_id: str | None = None,
    end_line: int | None = None,
) -> Finding:
    return Finding(
        tool=TOOL,
        project=project,
        path=path,
        symbol=symbol,
        kind='function',
        message=message,
        start_line=line,
        end_line=end_line if end_line is not None else line,
        confidence=confidence,
        rule_id=rule_id,
    )


def alpha_sides() -> tuple[list[Finding], list[Finding]]:
    base = [
        # Duplicate occurrences: two identical diffs share (identity, line).
        mk('alpha', 'dup', 5),
        mk('alpha', 'dup', 5),
        # New and changed candidates sharing one (identity, line).
        mk('alpha', 'triple', 7, message='aa'),
        mk('alpha', 'triple', 7, message='bb'),
        # Dropped and changed candidates sharing one (identity, line).
        mk('alpha', 'mixed', 8, message='aa'),
        mk('alpha', 'mixed', 8, message='bb'),
        mk('alpha', 'mixed', 8, message='yy'),
        mk('alpha', 'mixed', 8, message='zz'),
        # Identical reference occurrence keys, different diff classes.
        mk('alpha', 'ghost-a', 9, message='same', confidence=None),
        # A moved span: the locator addresses the base side.
        mk('alpha', 'mover', 10, end_line=11),
        # Zero confidence versus missing confidence stays observable.
        mk('alpha', 'zero', 12, message='z', confidence=0),
        # An explicit rule-ID change on one target.
        mk('alpha', 'ruled', 15, message='r', rule_id='SKY-U001'),
        # A rule ID appearing where none existed.
        mk('alpha', 'gain', 17, message='g'),
    ]
    head = [
        mk('alpha', 'triple', 7, message='cc'),
        mk('alpha', 'triple', 7, message='dd'),
        mk('alpha', 'triple', 7, message='ee'),
        mk('alpha', 'mixed', 8, message='aa2'),
        mk('alpha', 'mixed', 8, message='bb2'),
        mk('alpha', 'mixed', 8, message='yy2'),
        mk('alpha', 'ghost-b', 9, message='same', confidence=None),
        mk('alpha', 'mover', 20, end_line=21),
        mk('alpha', 'zero', 12, message='z', confidence=None),
        mk('alpha', 'zeronew', 13, message='zn', confidence=0),
        mk('alpha', 'ruled', 15, message='r', rule_id='SKY-U003'),
        mk('alpha', 'gain', 17, message='g', rule_id='SKY-U002'),
        mk('alpha', 'ruleless', 16, message='q'),
    ]
    return base, head


def build_locator_report() -> Report:
    manifest = RunManifest(
        created_at=datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC),
        tool=TOOL,
        detector_repo=None,
        base=None,
        head=None,
        base_cmd=('old-faketool',),
        head_cmd=('new-faketool',),
        comparable=False,
        environment_delta=(),
        isolation_enforced=True,
        platform='linux-x86_64',
        python_version='3.14.0',
        installer=None,
        fetches=(),
        corpus_pins=(
            CorpusPinRecord(
                name='alpha',
                repo='https://github.com/example/alpha',
                requested='branch:main',
                resolved_sha='3' * 40,
            ),
            CorpusPinRecord(
                name='beta',
                repo='ssh://git@internal.invalid/beta.git',
                requested='4' * 40,
                resolved_sha='4' * 40,
            ),
        ),
        settings=RunSettings(
            jobs=1,
            timeout=60.0,
            max_results=200,
            excerpt_lines=2,
            fail_on=(),
            selection=('alpha', 'beta'),
        ),
    )
    base, head = alpha_sides()
    alpha_diff = diff_findings(base, head, confidence_capable=True)
    beta_diff = diff_findings(
        [],
        [mk('beta', 'solo', 5, path='lib/b.py', message='s', confidence=None)],
        confidence_capable=True,
    )
    projects = [
        ProjectReport(
            project=name,
            diffs=attach_locators(name, outcome.diffs),
            totals=outcome.totals,
            rollups=outcome.rollups,
            truncated=False,
            base_findings=base_count,
            head_findings=head_count,
            measured_cost_seconds=cost,
        )
        for name, outcome, base_count, head_count, cost in (
            ('alpha', alpha_diff, len(base), len(head), 1.5),
            ('beta', beta_diff, 0, 1, 0.5),
        )
    ]
    totals = DiffTotals(
        new=sum(entry.totals.new for entry in projects),
        dropped=sum(entry.totals.dropped for entry in projects),
        changed=sum(entry.totals.changed for entry in projects),
        changed_confidence=sum(entry.totals.changed_confidence for entry in projects),
        changed_message_only=sum(entry.totals.changed_message_only for entry in projects),
    )
    return Report(
        manifest=manifest,
        projects=tuple(projects),
        totals=totals,
        rollups=merge_rollups(entry.rollups for entry in projects),
        truncated=False,
    )


def serialized_diffs(report: Report) -> list[FindingDiff]:
    return [diff for project in report.projects for diff in project.diffs]


def render_fixture(report: Report) -> str:
    document = {
        'locators': [diff.locator.model_dump(mode='json') for diff in serialized_diffs(report) if diff.locator],
        'report': report.model_dump(mode='json'),
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + '\n'


def test_locator_fixture_matches_checked_in_bytes() -> None:
    rendered = render_fixture(build_locator_report())
    golden_path = contained_path(GOLDEN_DIR, GOLDEN_NAME)
    if os.environ.get('LP_UPDATE_GOLDENS'):
        atomic_write_text(golden_path, rendered)
    assert rendered == read_small_text(golden_path)


def test_every_serialized_diff_carries_a_unique_locator() -> None:
    report = build_locator_report()
    diffs = serialized_diffs(report)
    locators = [diff.locator for diff in diffs]
    assert all(locator is not None for locator in locators)
    # Locators are unique within one report (explorer contract §4.2).
    assert len(set(locators)) == len(locators)
    by_identity_line: dict[tuple[str, str, int], list[int]] = {}
    for diff in diffs:
        assert diff.locator is not None
        assert diff.locator.identity == diff.identity
        key = (diff.locator.project, diff.locator.identity, diff.locator.line)
        by_identity_line.setdefault(key, []).append(diff.locator.occurrence)
    # Occurrence indices count up from zero in serialized order.
    for occurrences in by_identity_line.values():
        assert occurrences == list(range(len(occurrences)))
    # The duplicate-occurrence pair produced two diffs at one line.
    assert max(len(occurrences) for occurrences in by_identity_line.values()) >= 2


def test_locator_line_is_the_reference_side() -> None:
    report = build_locator_report()
    (alpha, _beta) = report.projects
    by_symbol = {diff.symbol: diff for diff in alpha.diffs}
    mover = by_symbol['mover']
    assert mover.diff_class is DiffClass.CHANGED
    assert mover.base_occurrence is not None
    assert mover.head_occurrence is not None
    assert (mover.base_occurrence.start_line, mover.head_occurrence.start_line) == (10, 20)
    assert mover.locator is not None
    # Base side for `changed` and `dropped`; head only for `new`.
    assert mover.locator.line == 10
    fresh = by_symbol['ruleless']
    assert fresh.diff_class is DiffClass.NEW
    assert fresh.head_occurrence is not None
    assert fresh.locator is not None
    assert fresh.locator.line == fresh.head_occurrence.start_line


def test_truncation_retains_complete_sequence_ordinals() -> None:
    base, head = alpha_sides()
    complete = attach_locators('alpha', diff_findings(base, head, confidence_capable=True).diffs)
    # An ordinal depends only on earlier diffs in the sequence, so
    # re-indexing any canonical prefix reproduces the complete-sequence
    # locators for the retained diffs (explorer contract §4.2).
    for cap in (1, 3, len(complete)):
        stripped = [diff.model_copy(update={'locator': None}) for diff in complete[:cap]]
        assert attach_locators('alpha', stripped) == complete[:cap]


def test_fixture_covers_required_shapes() -> None:
    # Explorer contract §10: locator behavior covers duplicate occurrences
    # and new, dropped, and changed findings.
    report = build_locator_report()
    (alpha, beta) = report.projects
    by_symbol: dict[str | None, list[str]] = {}
    for diff in alpha.diffs:
        by_symbol.setdefault(diff.symbol, []).append(diff.diff_class.value)
    assert by_symbol['dup'] == ['dropped', 'dropped']
    assert sorted(by_symbol['triple']) == ['changed', 'changed', 'new']
    assert sorted(by_symbol['mixed']) == ['changed', 'changed', 'changed', 'dropped']
    assert by_symbol['ghost-a'] == ['dropped']
    assert by_symbol['ghost-b'] == ['new']
    assert by_symbol['mover'] == ['changed']
    assert by_symbol['zero'] == ['changed']
    assert by_symbol['ruled'] == ['changed']
    assert by_symbol['gain'] == ['changed']
    assert by_symbol['ruleless'] == ['new']
    assert [diff.symbol for diff in beta.diffs] == ['solo']
    ruled = next(diff for diff in alpha.diffs if diff.symbol == 'ruled')
    assert [field.value for field in ruled.changed_fields] == ['rule']


def test_checked_in_fixture_report_validates_and_agrees() -> None:
    document = json.loads(read_small_text(contained_path(GOLDEN_DIR, GOLDEN_NAME)))
    assert isinstance(document, dict)
    report = Report.model_validate(document['report'])
    assert [diff.locator.model_dump(mode='json') for diff in serialized_diffs(report) if diff.locator] == (
        document['locators']
    )
    assert render_fixture(report) == read_small_text(contained_path(GOLDEN_DIR, GOLDEN_NAME))


def runner_for(tmp_path: Path, options: RunOptions) -> PrimerRunner:
    return PrimerRunner(
        adapter=get_adapter('vulture'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=UNENFORCED,
        options=options,
    )


def test_runner_serializes_locators_end_to_end(tmp_path: Path) -> None:
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    project = CorpusProject(name='fakeproj', repo=origin.url, pin=origin.head_sha)
    head = [FakeFinding(path='pkg/mod.py', line=5, symbol=f'sym{index}', kind='function') for index in range(3)]
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [])
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', head)
    report = runner_for(tmp_path, RunOptions(jobs=2, timeout=30.0)).run_escape_hatch(
        [project],
        base_cmd=base_cmd,
        head_cmd=head_cmd,
    )
    (project_report,) = report.projects
    locators = [diff.locator for diff in project_report.diffs]
    assert all(locator is not None for locator in locators)
    assert len(set(locators)) == len(locators)
    # A truncated run keeps the complete-sequence ordinals for the prefix.
    truncated = runner_for(tmp_path, RunOptions(jobs=2, timeout=30.0, max_results=2)).run_escape_hatch(
        [project],
        base_cmd=base_cmd,
        head_cmd=head_cmd,
    )
    (truncated_report,) = truncated.projects
    assert truncated_report.truncated
    assert [diff.locator for diff in truncated_report.diffs] == locators[:2]
