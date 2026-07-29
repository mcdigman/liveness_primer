"""Tests for the report renderers and mandatory sanitization (contract §9, §15).

Copyright (C) 2026 Matthew C. Digman

The text and GitHub renderers are locked by golden files; regenerate them
with ``LP_UPDATE_GOLDENS=1 python -m pytest tests/test_report.py``.
"""

import os
from datetime import UTC, datetime
from pathlib import Path

from liveness_primer.findings import (
    ChangedField,
    CorpusIntegrityWarning,
    CorpusPinRecord,
    DependencyDelta,
    DiffClass,
    DiffTotals,
    EnvironmentRecord,
    FetchRecord,
    FindingDiff,
    FindingOccurrence,
    ProjectReport,
    Report,
    RunManifest,
    RunSettings,
    ToolError,
    finding_identity,
)
from liveness_primer.report import render_github, render_json, render_text
from liveness_primer.report.sanitize import fenced_block, sanitize_cell, sanitize_excerpt, sanitize_inline

GOLDEN_DIR = Path(__file__).parent / 'fixtures'


def occurrence(
    line: int, message: str, *, confidence: int | None = 60, excerpt: str | None = None
) -> FindingOccurrence:
    return FindingOccurrence(
        start_line=line,
        end_line=line,
        message=message,
        confidence=confidence,
        raw_excerpt=excerpt,
    )


def diff(
    diff_class: DiffClass,
    symbol: str,
    *,
    base: FindingOccurrence | None = None,
    head: FindingOccurrence | None = None,
    fields: tuple[ChangedField, ...] = (),
    kind: str = 'function',
    path: str = 'pkg/mod.py',
) -> FindingDiff:
    return FindingDiff(
        diff_class=diff_class,
        identity=finding_identity('vulture', 'alpha', path, symbol, kind),
        tool='vulture',
        project='alpha',
        path=path,
        symbol=symbol,
        kind=kind,
        base_occurrence=base,
        head_occurrence=head,
        changed_fields=fields,
    )


def message_only(symbol: str) -> FindingDiff:
    return diff(
        DiffClass.CHANGED,
        symbol,
        base=occurrence(30, f'old wording for {symbol}'),
        head=occurrence(30, f'new wording for {symbol}'),
        fields=(ChangedField.MESSAGE,),
    )


def build_report() -> Report:
    manifest = RunManifest(
        created_at=datetime(2026, 7, 28, 12, 0, 0, tzinfo=UTC),
        tool='vulture',
        detector_repo='https://github.com/jendrikseipp/vulture',
        base=EnvironmentRecord(
            ref='main',
            sha='1' * 40,
            fingerprint='fp-base',
            freeze=('vulture @ file:///base', 'tomli==2.4.0'),
            from_cache=True,
            rebuilt=False,
        ),
        head=EnvironmentRecord(
            ref='pr-branch',
            sha='2' * 40,
            fingerprint='fp-head',
            freeze=('vulture @ file:///head', 'tomli==2.5.0'),
            from_cache=False,
            rebuilt=True,
        ),
        base_cmd=None,
        head_cmd=None,
        comparable=True,
        environment_delta=(DependencyDelta(package='tomli', base_version='2.4.0', head_version='2.5.0'),),
        isolation_enforced=False,
        platform='linux-x86_64',
        python_version='3.14.0',
        installer='pip 26.0',
        fetches=(FetchRecord(kind='git', name='https://github.com/jendrikseipp/vulture', resolved='2' * 40),),
        corpus_pins=(
            CorpusPinRecord(
                name='alpha',
                repo='https://github.com/example/alpha',
                requested='branch:main',
                resolved_sha='3' * 40,
            ),
            CorpusPinRecord(
                name='beta',
                repo='https://github.com/example/beta',
                requested='4' * 40,
                resolved_sha='4' * 40,
            ),
        ),
        settings=RunSettings(
            jobs=2,
            timeout=300.0,
            max_results=200,
            excerpt_lines=2,
            fail_on=('new',),
            selection=('alpha', 'beta'),
        ),
    )
    hostile_excerpt = 'evil.py:9: unused function `x` \x1b[31mANSI\x07 (60% confidence)\nline two\nline three'
    alpha_diffs = (
        diff(
            DiffClass.NEW,
            'fresh | pipe`tick`',
            head=occurrence(9, 'unused function with a very hostile excerpt', confidence=100, excerpt=hostile_excerpt),
        ),
        diff(
            DiffClass.DROPPED,
            'goner',
            base=occurrence(5, "unused function 'goner'", excerpt="pkg/mod.py:5: unused function 'goner'"),
        ),
        diff(
            DiffClass.CHANGED,
            'mover',
            base=occurrence(10, "unused function 'mover'"),
            head=occurrence(14, "unused function 'mover'"),
            fields=(ChangedField.LINE_SPAN,),
        ),
        diff(
            DiffClass.CHANGED,
            'flaky',
            base=occurrence(21, "unused function 'flaky'", confidence=60),
            head=occurrence(21, "unused function 'flaky'", confidence=90),
            fields=(ChangedField.CONFIDENCE,),
        ),
        message_only('reworded-1'),
        message_only('reworded-2'),
        message_only('reworded-3'),
        message_only('reworded-4'),
        message_only('reworded-5'),
    )
    alpha = ProjectReport(
        project='alpha',
        diffs=alpha_diffs,
        totals=DiffTotals(new=2, dropped=1, changed=7, changed_confidence=1, changed_message_only=5),
        truncated=True,
        base_findings=12,
        head_findings=13,
        measured_cost_seconds=1.25,
        errors=(ToolError(side='head', exit_code=1, detail='stderr said \x00something\x1b odd'),),
        integrity_warnings=(
            CorpusIntegrityWarning(
                project='alpha',
                tool='vulture',
                detail='expected-clean base side reported 12 finding(s) and exit code 3',
            ),
        ),
    )
    beta = ProjectReport(
        project='beta',
        diffs=(),
        totals=DiffTotals(),
        truncated=False,
        base_findings=0,
        head_findings=0,
        measured_cost_seconds=0.42,
    )
    return Report(
        manifest=manifest,
        projects=(alpha, beta),
        totals=DiffTotals(new=2, dropped=1, changed=7, changed_confidence=1, changed_message_only=5),
        truncated=True,
    )


def check_golden(rendered: str, golden_name: str) -> None:
    golden_path = GOLDEN_DIR / golden_name
    if os.environ.get('LP_UPDATE_GOLDENS'):
        golden_path.write_text(rendered, encoding='utf-8')
    assert rendered == golden_path.read_text(encoding='utf-8')


def test_text_report_matches_golden() -> None:
    check_golden(render_text(build_report()), 'report_golden.txt')


def test_github_report_matches_golden() -> None:
    check_golden(render_github(build_report()), 'report_golden.md')


def test_json_report_round_trips_with_full_detail() -> None:
    report = build_report()
    payload = render_json(report)
    assert payload.endswith('\n')
    restored = Report.model_validate_json(payload)
    assert restored == report
    assert restored.schema_version == report.schema_version


def test_escape_hatch_manifest_renders_commands() -> None:
    report = build_report()
    manifest = report.manifest.model_copy(
        update={
            'detector_repo': None,
            'base': None,
            'head': None,
            'base_cmd': ('old-vulture', '--flag'),
            'head_cmd': ('new-vulture',),
            'comparable': False,
            'installer': None,
            'environment_delta': (),
            'isolation_enforced': True,
        }
    )
    text = render_text(report.model_copy(update={'manifest': manifest}))
    assert 'base command: old-vulture --flag' in text
    assert 'comparable: no (escape-hatch run; gating refused)' in text
    assert 'isolation: enforced' in text
    assert 'installer:' not in text
    markdown = render_github(report.model_copy(update={'manifest': manifest}))
    assert '**base command**: `old-vulture --flag`' in markdown
    assert '**isolation**: enforced' in markdown


def test_span_and_confidence_edge_renderings() -> None:
    multi_line = FindingOccurrence(start_line=4, end_line=9, message='m', confidence=None)
    report = build_report()
    dropped_span = diff(DiffClass.DROPPED, 'span', base=multi_line)
    gained_confidence = diff(
        DiffClass.CHANGED,
        'gained',
        base=occurrence(7, 'm', confidence=None),
        head=occurrence(7, 'm', confidence=90),
        fields=(ChangedField.CONFIDENCE,),
    )
    project = ProjectReport(
        project='edges',
        diffs=(dropped_span, gained_confidence),
        totals=DiffTotals(dropped=1, changed=1, changed_confidence=1),
        truncated=False,
        base_findings=2,
        head_findings=1,
        measured_cost_seconds=None,
    )
    plain = report.model_copy(update={'projects': (project,), 'truncated': False, 'totals': project.totals})
    text = render_text(plain)
    assert 'pkg/mod.py:L4-9 function span [-] (-)' in text
    assert '(-->90%)' in text
    assert 'cost n/a' in text
    assert 'note: some project diffs were truncated' not in text
    markdown = render_github(plain)
    assert 'Some project diffs were truncated' not in markdown
    assert '| -->90% |' in markdown


def test_sanitize_inline_strips_and_caps() -> None:
    assert sanitize_inline('a\x00b\x1bc\nd') == 'a b c d'
    long = 'x' * 400
    capped = sanitize_inline(long)
    assert len(capped) == 300
    assert capped.endswith('...')
    assert sanitize_inline('short') == 'short'


def test_sanitize_excerpt_caps_lines_and_notes_omissions() -> None:
    lines = sanitize_excerpt('one\ntwo\nthree\nfour', max_lines=2)
    assert lines[:2] == ('one', 'two')
    assert '2 more excerpt line(s) omitted' in lines[2]
    assert sanitize_excerpt('single', max_lines=5) == ('single',)


def test_sanitize_cell_escapes_table_metacharacters() -> None:
    assert sanitize_cell('a|b`c\\d') == 'a\\|b\\`c\\\\d'


def test_fenced_block_outruns_content_backticks() -> None:
    block = fenced_block(('normal', '```` four ticks'))
    fence = block.split('\n')[0]
    assert fence.startswith('`````')
    assert fence.endswith('text')
    assert block.endswith('`' * 5)
    simple = fenced_block(('plain',))
    assert simple.startswith('```text\n')
