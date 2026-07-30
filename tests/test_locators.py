"""Tests for finding locators and the shared locator golden fixture (explorer §6.2, §17.1).

Copyright (C) 2026 Matthew C. Digman

Python generates the checked-in locator golden fixture; frontend tests and
the future ``bisect`` tests consume the same fixture and must agree on the
identical ordered locator values. Regenerate it only with the explicit
maintenance command ``LP_UPDATE_GOLDENS=1 python -m pytest
tests/test_locators.py``; ordinary runs compare the checked-in values.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from liveness_primer.diffing import diff_findings, merge_rollups
from liveness_primer.filesystem import atomic_write_text, contained_path, read_small_text
from liveness_primer.findings import (
    CorpusPinRecord,
    DiffTotals,
    Finding,
    FindingLocator,
    ProjectReport,
    Report,
    RunManifest,
    RunSettings,
)
from liveness_primer.locators import finding_locators, project_locators

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
            diffs=outcome.diffs,
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


def render_fixture(report: Report) -> str:
    document = {
        'locators': [locator.model_dump(mode='json') for locator in finding_locators(report)],
        'report': report.model_dump(mode='json'),
    }
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + '\n'


def load_fixture() -> dict[str, object]:
    text = read_small_text(contained_path(GOLDEN_DIR, GOLDEN_NAME))
    document = json.loads(text)
    assert isinstance(document, dict)
    return document


def test_locator_fixture_matches_checked_in_bytes() -> None:
    rendered = render_fixture(build_locator_report())
    golden_path = contained_path(GOLDEN_DIR, GOLDEN_NAME)
    if os.environ.get('LP_UPDATE_GOLDENS'):
        atomic_write_text(golden_path, rendered)
    assert rendered == read_small_text(golden_path)


def test_locators_follow_reference_side_and_occurrence_rule() -> None:
    report = build_locator_report()
    locators = finding_locators(report)
    assert len(locators) == sum(len(project.diffs) for project in report.projects)
    # Locators are unique within one validated report (explorer §6.2).
    assert len(set(locators)) == len(locators)
    by_identity_line: dict[tuple[str, str, int], list[int]] = {}
    for locator in locators:
        by_identity_line.setdefault((locator.project, locator.identity, locator.line), []).append(locator.occurrence)
    # Occurrence indices count up from zero in serialized order.
    for occurrences in by_identity_line.values():
        assert occurrences == list(range(len(occurrences)))
    # The duplicate-occurrence pair produced two diffs at one line.
    assert max(len(occurrences) for occurrences in by_identity_line.values()) >= 2


def test_locator_line_is_reference_side() -> None:
    report = build_locator_report()
    (alpha, _beta) = report.projects
    locators = project_locators(alpha)
    moved = [(diff, locator) for diff, locator in zip(alpha.diffs, locators, strict=True) if diff.symbol == 'mover']
    ((diff, locator),) = moved
    assert diff.base_occurrence is not None
    assert diff.head_occurrence is not None
    assert diff.base_occurrence.start_line == 10
    assert diff.head_occurrence.start_line == 20
    # Base side for `changed`; head is only the reference for `new`.
    assert locator.line == 10


def test_fixture_covers_required_shapes() -> None:
    # Explorer contract §17.1: the fixture must cover duplicate
    # occurrences, class mixtures on one (identity, line), identical
    # reference keys with different classes, moved spans, missing and zero
    # confidence, absent and present rule IDs, and a rule-ID change.
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
    document = load_fixture()
    report = Report.model_validate(document['report'])
    raw_locators = document['locators']
    assert isinstance(raw_locators, list)
    expected = [FindingLocator.model_validate(raw) for raw in raw_locators]
    assert list(finding_locators(report)) == expected
