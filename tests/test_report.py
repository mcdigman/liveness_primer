"""Tests for the report renderers and mandatory sanitization (contract §9, §15).

Copyright (C) 2026 Matthew C. Digman

The text and GitHub renderers are locked by golden files; regenerate them
with ``LP_UPDATE_GOLDENS=1 python -m pytest tests/test_report.py``. Color
and hyperlink behavior is asserted separately from the unstyled goldens in
``test_report_terminal.py`` (reporting contract §10).
"""

import os
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from liveness_primer.diffing import compute_rollups
from liveness_primer.filesystem import (
    FilesystemPolicyError,
    atomic_write_text,
    contained_path,
    read_small_text,
)
from liveness_primer.findings import (
    ChangedField,
    CorpusIntegrityWarning,
    CorpusPinRecord,
    DependencyDelta,
    DiffClass,
    DiffRollup,
    DiffTotals,
    EnvironmentRecord,
    FetchRecord,
    FindingDiff,
    FindingOccurrence,
    ProjectReport,
    Report,
    RunManifest,
    RunSettings,
    SourceExcerpt,
    ToolError,
    finding_identity,
)
from liveness_primer.report import render_github, render_json, render_text
from liveness_primer.report.common import (
    confidence_text,
    excerpt_sides,
    pin_for_project,
    report_has_severity,
    rollup_lines,
    tool_has_severity,
)
from liveness_primer.report.permalink import source_url, tree_url
from liveness_primer.report.sanitize import (
    code_span,
    escape_argv_text,
    sanitize_cell,
    sanitize_inline,
    sanitize_location,
)
from liveness_primer.report.terminal import TextRenderOptions

GOLDEN_DIR = Path(__file__).parent / 'fixtures'

WIDE = TextRenderOptions(width=160)


def occurrence(
    line: int,
    message: str,
    *,
    end_line: int | None = None,
    confidence: int | None = 60,
    severity: str | None = None,
    rule_id: str | None = None,
    excerpt: str | None = None,
    source: SourceExcerpt | None = None,
) -> FindingOccurrence:
    return FindingOccurrence(
        start_line=line,
        end_line=end_line if end_line is not None else line,
        message=message,
        confidence=confidence,
        severity=severity,
        rule_id=rule_id,
        raw_excerpt=excerpt,
        source_excerpt=source,
    )


def diff(
    diff_class: DiffClass,
    symbol: str | None,
    *,
    base: FindingOccurrence | None = None,
    head: FindingOccurrence | None = None,
    fields: tuple[ChangedField, ...] = (),
    kind: str = 'function',
    path: str = 'pkg/mod.py',
    project: str = 'alpha',
    tool: str = 'vulture',
) -> FindingDiff:
    reference = base if base is not None else head
    assert reference is not None
    return FindingDiff(
        diff_class=diff_class,
        identity=finding_identity(
            tool,
            project,
            path,
            symbol,
            kind,
            reference.rule_id,
            reference.start_line,
            reference.end_line,
        ),
        tool=tool,
        project=project,
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


def source_lines(start: int, *lines: str, omitted: int = 0) -> SourceExcerpt:
    return SourceExcerpt(start_line=start, lines=lines, omitted_lines=omitted)


ALPHA_PIN = CorpusPinRecord(
    name='alpha',
    repo='https://github.com/example/alpha',
    requested='branch:main',
    resolved_sha='3' * 40,
)
# beta is a non-GitHub ad-hoc project: no permalink may be fabricated.
BETA_PIN = CorpusPinRecord(
    name='beta',
    repo='ssh://git@internal.invalid/beta.git',
    requested='4' * 40,
    resolved_sha='4' * 40,
)


def build_manifest() -> RunManifest:
    return RunManifest(
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
        corpus_pins=(ALPHA_PIN, BETA_PIN),
        settings=RunSettings(
            jobs=2,
            timeout=300.0,
            max_results=200,
            excerpt_lines=2,
            fail_on=('new',),
            selection=('alpha', 'beta'),
        ),
    )


def build_report() -> Report:
    hostile_excerpt = 'evil.py:9: unused function `x` \x1b[31mANSI\x07 (60% confidence)\nline two\nline three'
    alpha_diffs = (
        diff(
            DiffClass.DROPPED,
            'goner',
            base=occurrence(
                5,
                "unused function 'goner'",
                excerpt="pkg/mod.py:5: unused function 'goner'",
                source=source_lines(5, 'def goner():'),
            ),
        ),
        diff(
            DiffClass.NEW,
            'fresh | pipe`tick`',
            head=occurrence(
                9,
                'unused function with a very hostile excerpt',
                confidence=100,
                rule_id='SKY-U001',
                excerpt=hostile_excerpt,
                source=source_lines(9, 'def fresh(request):', '    return request'),
            ),
        ),
        # A moved span is a dropped finding plus a new one: the line span
        # is part of the finding identity.
        diff(
            DiffClass.DROPPED,
            'mover',
            base=occurrence(10, "unused function 'mover'", source=source_lines(10, 'def mover():')),
        ),
        diff(
            DiffClass.NEW,
            'mover',
            head=occurrence(14, "unused function 'mover'", source=source_lines(14, 'def mover():  # moved')),
        ),
        diff(
            DiffClass.CHANGED,
            'flaky',
            base=occurrence(21, "unused function 'flaky'", confidence=60, source=source_lines(21, 'def flaky():')),
            head=occurrence(21, "unused function 'flaky'", confidence=90),
            fields=(ChangedField.CONFIDENCE,),
        ),
        message_only('reworded-1'),
        message_only('reworded-2'),
        message_only('reworded-3'),
        message_only('reworded-4'),
        message_only('reworded-5'),
        # A renumbered rule code is likewise a dropped finding of the first
        # code plus a new finding of the second.
        diff(
            DiffClass.DROPPED,
            'renumbered',
            base=occurrence(40, 'renumbered rule', rule_id='SKY-U001', source=source_lines(40, 'def renumbered():')),
        ),
        diff(
            DiffClass.NEW,
            'renumbered',
            head=occurrence(40, 'renumbered rule', rule_id='SKY-U003'),
        ),
        diff(
            DiffClass.DROPPED,
            'span',
            base=occurrence(
                50,
                'multi-line span with an omitted tail',
                end_line=57,
                confidence=None,
                source=source_lines(50, 'class Span:', '    a = 1', omitted=6),
            ),
        ),
    )
    alpha = ProjectReport(
        project='alpha',
        diffs=alpha_diffs,
        totals=DiffTotals(new=3, dropped=4, changed=7, changed_confidence_only=1, changed_message_only=5),
        rollups=(
            DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U003', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.NEW, rule_id=None, kind='function', count=1),
            DiffRollup(diff_class=DiffClass.DROPPED, rule_id=None, kind='function', count=3),
            DiffRollup(diff_class=DiffClass.DROPPED, rule_id='SKY-U001', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.CHANGED, rule_id=None, kind='function', count=7),
        ),
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
        source_warnings=('pkg/gone.py: not a regular non-symlink file',),
    )
    beta_diffs = (
        diff(
            DiffClass.NEW,
            'unlinked',
            project='beta',
            path='lib/util.py',
            head=occurrence(3, 'no permalink for ad-hoc hosts', confidence=None, source=source_lines(3, 'x = 1')),
        ),
        diff(
            DiffClass.CHANGED,
            'wanderer',
            project='beta',
            path='lib/move.py',
            base=occurrence(7, 'old wording without a permalink', confidence=None, source=source_lines(7, 'old = 7')),
            head=occurrence(7, 'new wording without a permalink', confidence=None),
            fields=(ChangedField.MESSAGE,),
        ),
    )
    beta = ProjectReport(
        project='beta',
        diffs=beta_diffs,
        totals=DiffTotals(new=1, changed=1, changed_message_only=1),
        rollups=(
            DiffRollup(diff_class=DiffClass.NEW, rule_id=None, kind='function', count=1),
            DiffRollup(diff_class=DiffClass.CHANGED, rule_id=None, kind='function', count=1),
        ),
        truncated=False,
        base_findings=1,
        head_findings=2,
        measured_cost_seconds=0.42,
    )
    # gamma has no corpus pin and no diffs: headers must stay well-formed.
    gamma = ProjectReport(
        project='gamma',
        diffs=(),
        totals=DiffTotals(),
        rollups=(),
        truncated=False,
        base_findings=0,
        head_findings=0,
        measured_cost_seconds=None,
    )
    overall = DiffTotals(new=4, dropped=4, changed=8, changed_confidence_only=1, changed_message_only=6)
    return Report(
        manifest=build_manifest(),
        projects=(alpha, beta, gamma),
        totals=overall,
        rollups=(
            DiffRollup(diff_class=DiffClass.NEW, rule_id=None, kind='function', count=2),
            DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U003', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.DROPPED, rule_id=None, kind='function', count=3),
            DiffRollup(diff_class=DiffClass.DROPPED, rule_id='SKY-U001', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.CHANGED, rule_id=None, kind='function', count=8),
        ),
        truncated=True,
    )


SEC_PIN = CorpusPinRecord(
    name='sec',
    repo='https://github.com/example/sec',
    requested='branch:main',
    resolved_sha='5' * 40,
)


def build_severity_report() -> Report:
    """Build a severity-capable (skylos) report exercising the severity column.

    Returns
    -------
    Report
        One-project report with danger diagnostics carrying ``CRITICAL``,
        ``HIGH``, and ``MEDIUM`` labels beside a severity-less dead-code
        finding.
    """
    manifest = build_manifest().model_copy(
        update={
            'tool': 'skylos',
            'detector_repo': 'https://github.com/duriantaco/skylos',
            'corpus_pins': (SEC_PIN,),
            'environment_delta': (),
        }
    )
    sec_diffs = (
        diff(
            DiffClass.NEW,
            'app.load',
            tool='skylos',
            project='sec',
            path='app/load.py',
            kind='danger',
            head=occurrence(
                6,
                'Untrusted deserialization via pickle.loads',
                confidence=None,
                severity='CRITICAL',
                rule_id='SKY-D205',
                source=source_lines(6, '    return pickle.loads(data)'),
            ),
        ),
        diff(
            DiffClass.CHANGED,
            None,
            tool='skylos',
            project='sec',
            path='app/exec.py',
            kind='danger',
            base=occurrence(
                9,
                'Use of os.system()',
                confidence=None,
                severity='MEDIUM',
                rule_id='SKY-D203',
                source=source_lines(9, '    os.system(cmd)'),
            ),
            head=occurrence(9, 'Use of os.system()', confidence=None, severity='HIGH', rule_id='SKY-D203'),
            fields=(ChangedField.SEVERITY,),
        ),
        diff(
            DiffClass.DROPPED,
            None,
            tool='skylos',
            project='sec',
            path='app/hash.py',
            kind='danger',
            base=occurrence(
                12,
                'Weak hash algorithm md5',
                confidence=None,
                severity='MEDIUM',
                rule_id='SKY-D401',
                source=source_lines(12, 'digest = hashlib.md5(blob)'),
            ),
        ),
        diff(
            DiffClass.NEW,
            'app.unused',
            tool='skylos',
            project='sec',
            path='app/load.py',
            head=occurrence(
                20,
                "unused function 'unused'",
                confidence=80,
                rule_id='SKY-U001',
                source=source_lines(20, 'def unused():'),
            ),
        ),
    )
    sec = ProjectReport(
        project='sec',
        diffs=sec_diffs,
        totals=DiffTotals(new=2, dropped=1, changed=1, changed_severity_only=1),
        rollups=(
            DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-D205', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.DROPPED, rule_id='SKY-D401', kind=None, count=1),
            DiffRollup(diff_class=DiffClass.CHANGED, rule_id='SKY-D203', kind=None, count=1),
        ),
        truncated=False,
        base_findings=2,
        head_findings=3,
        measured_cost_seconds=0.9,
    )
    return Report(
        manifest=manifest,
        projects=(sec,),
        totals=sec.totals,
        rollups=sec.rollups,
        truncated=False,
    )


def check_golden(rendered: str, golden_name: str) -> None:
    golden_path = contained_path(GOLDEN_DIR, golden_name)
    if os.environ.get('LP_UPDATE_GOLDENS'):
        atomic_write_text(golden_path, rendered)
    assert rendered == read_small_text(golden_path)


def test_text_report_matches_golden() -> None:
    check_golden(render_text(build_report(), WIDE), 'report_golden.txt')


def test_github_report_matches_golden() -> None:
    check_golden(render_github(build_report()), 'report_golden.md')


def test_severity_text_report_matches_golden() -> None:
    check_golden(render_text(build_severity_report(), WIDE), 'report_severity_golden.txt')


def test_severity_github_report_matches_golden() -> None:
    check_golden(render_github(build_severity_report()), 'report_severity_golden.md')


def test_severity_column_appears_for_capable_tools_carrying_a_severity() -> None:
    # Reporting acceptance 32: the severity column exists exactly for
    # severity-capable tools whose report carries at least one severity.
    vulture_text = render_text(build_report(), WIDE)
    vulture_header = next(line for line in vulture_text.splitlines() if 'rule' in line and 'fields' in line)
    assert 'severity' not in vulture_header
    skylos_text = render_text(build_severity_report(), WIDE)
    header_row = next(line for line in skylos_text.splitlines() if 'severity' in line and 'fields' in line)
    assert header_row.index('%') < header_row.index('severity') < header_row.index('kind')
    assert 'CRITICAL' in skylos_text
    assert 'MEDIUM->HIGH' in skylos_text
    markdown = render_github(build_severity_report())
    header = next(line for line in markdown.splitlines() if line.startswith('|  | rule'))
    assert header == '|  | rule | % | severity | location | message |'
    assert 'totals: 2 new, 1 dropped, 1 changed (0 confidence-only, 0 message-only, 1 severity-only)' in skylos_text


def test_severity_column_is_suppressed_when_no_finding_carries_one() -> None:
    # A severity-capable tool can still produce a report in which nothing
    # has a severity: text and GitHub drop the column rather than render a
    # wholly absent one.
    report = build_severity_report()
    stripped = report.model_copy(
        update={
            'projects': tuple(
                project.model_copy(
                    update={
                        'diffs': tuple(
                            diff.model_copy(
                                update={
                                    'changed_fields': (),
                                    'diff_class': DiffClass.NEW,
                                    'base_occurrence': None,
                                    'head_occurrence': diff.reference_occurrence.model_copy(update={'severity': None}),
                                }
                            )
                            for diff in project.diffs
                        )
                    }
                )
                for project in report.projects
            )
        }
    )
    assert report_has_severity(report) is True
    assert report_has_severity(stripped) is False
    text = render_text(stripped, WIDE)
    header_row = next(line for line in text.splitlines() if 'rule' in line and 'fields' in line)
    assert 'severity' not in header_row
    markdown = render_github(stripped)
    header = next(line for line in markdown.splitlines() if line.startswith('|  | rule'))
    assert header == '|  | rule | % | location | message |'


def test_absent_severity_renders_na_for_capable_tools() -> None:
    # The dead-code finding in a severity-capable report has no severity:
    # its cell is `NA`, and no label is invented. Reporting contract §4.3
    # forbids ambiguous forms, so absence must not render as a bare arrow
    # side such as `->HIGH`.
    text = render_text(build_severity_report(), WIDE)
    row = next(line for line in text.splitlines() if line.startswith('+') and 'SKY-U001' in line)
    assert row.split()[3] == 'NA'
    # No cell may open with a bare arrow: an absent side renders as `NA`,
    # so `NA->HIGH` appears where `->HIGH` would have been.
    assert re.search(r'\s->\S', text) is None


def test_golden_check_rejects_traversal() -> None:
    with pytest.raises(FilesystemPolicyError, match='without traversal'):
        check_golden('', '../outside.txt')


def test_json_report_round_trips_with_full_detail() -> None:
    report = build_report()
    payload = render_json(report)
    assert payload.endswith('\n')
    restored = Report.model_validate_json(payload)
    assert restored == report
    assert restored.schema_version == report.schema_version


def test_json_report_serializes_rule_ids_and_source_excerpts() -> None:
    # Reporting acceptance 1 and §3.6: rule IDs and collected source
    # evidence are part of the archived JSON report.
    payload = render_json(build_report())
    assert '"rule_id": "SKY-U001"' in payload
    assert '"source_excerpt"' in payload
    assert '"def fresh(request):"' in payload
    assert '"omitted_lines": 6' in payload
    assert '"rollups"' in payload


def test_escape_hatch_manifest_renders_commands() -> None:
    report = build_report()
    manifest = report.manifest.model_copy(
        update={
            'detector_repo': None,
            'base': None,
            'head': None,
            'base_cmd': ('/private/var/folders/zz/old-vulture', '--flag', 'a b'),
            'head_cmd': ('new-vulture',),
            'comparable': False,
            'installer': None,
            'environment_delta': (),
            'isolation_enforced': True,
        }
    )
    text = render_text(report.model_copy(update={'manifest': manifest}), WIDE)
    # Trusted manifest argv render faithfully: shell-quoted, never
    # path-shortened, even when they carry temporary paths (reporting §3.5).
    assert "base command: /private/var/folders/zz/old-vulture --flag 'a b'" in text
    assert 'comparable: no (escape-hatch run; gating refused)' in text
    assert 'isolation: enforced' in text
    assert 'installer:' not in text
    markdown = render_github(report.model_copy(update={'manifest': manifest}))
    assert "**base command**: `/private/var/folders/zz/old-vulture --flag 'a b'`" in markdown
    assert '**isolation**: enforced' in markdown


def test_text_report_shows_required_finding_columns() -> None:
    # Reporting §1: diff class, rule ID, confidence, kind, location,
    # message, symbol, and changed fields for every displayed finding.
    text = render_text(build_report(), WIDE)
    assert 'legend: + new; - dropped; ~ changed' in text
    header_row = next(line for line in text.splitlines() if 'rule' in line and 'fields' in line)
    assert header_row.index('rule') < header_row.index('%') < header_row.index('kind')
    assert header_row.index('kind') < header_row.index('location') < header_row.index('symbol')
    assert header_row.index('symbol') < header_row.index('message') < header_row.index('fields')
    assert 'SKY-U001' in text
    assert 'pkg/mod.py:L9' in text
    assert 'NA' in text


def test_confidence_column_exact_forms() -> None:
    # Reporting §4.3 and acceptance 6: NA, XX%, NA->XX%, XX%->NA, and
    # XX%->YY% are the only forms; `-->90%` style output is forbidden.
    changed_cases = [
        (None, 90, 'NA->90%'),
        (90, None, '90%->NA'),
        (60, 90, '60%->90%'),
    ]
    for base_confidence, head_confidence, expected in changed_cases:
        entry = diff(
            DiffClass.CHANGED,
            's',
            base=occurrence(1, 'm', confidence=base_confidence),
            head=occurrence(1, 'm', confidence=head_confidence),
            fields=(ChangedField.CONFIDENCE,),
        )
        assert confidence_text(entry) == expected
    assert confidence_text(diff(DiffClass.NEW, 's', head=occurrence(1, 'm', confidence=None))) == 'NA'
    assert confidence_text(diff(DiffClass.DROPPED, 's', base=occurrence(1, 'm', confidence=90))) == '90%'
    unchanged = diff(
        DiffClass.CHANGED,
        's',
        base=occurrence(1, 'old', confidence=75),
        head=occurrence(1, 'new', confidence=75),
        fields=(ChangedField.MESSAGE,),
    )
    assert confidence_text(unchanged) == '75%'
    assert '-->' not in render_text(build_report(), WIDE)


def test_changed_rows_show_base_and_head_values() -> None:
    # Reporting §4.4: listing only field names is not sufficient evidence.
    text = render_text(build_report(), WIDE)
    assert '%: 60% -> 90%' in text
    assert 'message: old wording for reworded-1 -> new wording for reworded-1' in text
    severity_text_report = render_text(build_severity_report(), WIDE)
    assert 'severity: MEDIUM -> HIGH' in severity_text_report


def test_changed_fields_tokens() -> None:
    entry = diff(
        DiffClass.CHANGED,
        's',
        base=occurrence(1, 'old', confidence=10, rule_id='A'),
        head=occurrence(1, 'new', confidence=20, rule_id='A'),
        fields=(ChangedField.MESSAGE, ChangedField.CONFIDENCE),
    )
    # The project name has no corpus pin: locations render as escaped
    # plain text in both outputs without a fabricated URL.
    project = ProjectReport(
        project='orphan',
        diffs=(entry,),
        totals=DiffTotals(changed=1),
        rollups=compute_rollups((entry,)),
        truncated=False,
        base_findings=1,
        head_findings=1,
        measured_cost_seconds=None,
    )
    report = build_report().model_copy(update={'projects': (project,), 'truncated': False})
    text = render_text(report, WIDE)
    assert 'message,%' in text
    markdown = render_github(report)
    assert '| pkg/mod.py:L1 |' in markdown
    assert 'message: old -> new' in markdown
    assert '](http' not in markdown.split('## `orphan`')[1]


def test_absent_rule_id_renders_dash_not_invented_code() -> None:
    # Reporting acceptance 4.
    text = render_text(build_report(), WIDE)
    beta_section = text[text.index('project beta') :]
    row = next(line for line in beta_section.splitlines() if 'lib/util.py' in line)
    assert row.split()[1] == '-'


def test_rollup_lines_top_five_and_tail() -> None:
    rollups = tuple(
        DiffRollup(diff_class=DiffClass.NEW, rule_id=f'SKY-U{index:03d}', kind=None, count=100 - index)
        for index in range(1, 8)
    )
    (line,) = rollup_lines(rollups)
    assert line.startswith('new 672: SKY-U001 99, SKY-U002 98, SKY-U003 97, SKY-U004 96, SKY-U005 95')
    assert line.endswith('187 finding(s) across 2 other group(s)')


def test_rollup_lines_kind_fallback_and_class_split() -> None:
    rollups = (
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U006', kind=None, count=155),
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U002', kind=None, count=13),
        DiffRollup(diff_class=DiffClass.CHANGED, rule_id=None, kind='variable', count=4),
    )
    assert rollup_lines(rollups) == (
        'new 168: SKY-U006 155, SKY-U002 13',
        'changed 4: kind:variable 4',
    )


def test_headers_carry_rollups_and_counts() -> None:
    # Reporting acceptance 21: overall and project headers carry counts,
    # totals, rollups, cost, and bounded errors and warnings.
    text = render_text(build_report(), WIDE)
    overall = text[: text.index('project alpha')]
    assert 'base findings 13, head findings 15' in overall
    assert (
        'totals: 4 new, 4 dropped, 8 changed (1 confidence-only, 6 message-only, 0 severity-only, 1 multiple)'
        in overall
    )
    assert 'new 4: kind:function 2, SKY-U001 1, SKY-U003 1' in overall
    assert 'cost: 1.67s' in overall
    assert 'errors: 1' in overall
    assert 'corpus-integrity warnings: 1' in overall
    assert 'source warnings: 1' in overall
    alpha_section = text[text.index('project alpha') : text.index('project beta')]
    assert 'base 12 findings, head 13' in alpha_section
    assert 'new 3: SKY-U001 1, SKY-U003 1, kind:function 1' in alpha_section
    assert 'error[head]: stderr said  something  odd' in alpha_section
    assert 'warning[corpus-integrity]:' in alpha_section
    assert 'warning[source]: pkg/gone.py: not a regular non-symlink file' in alpha_section
    assert 'showing 13 of 14 finding diffs (truncated by --max-results)' in alpha_section


def test_project_header_links_pinned_tree_not_detector_repo() -> None:
    # Reporting §4.1: exactly one corpus line per project, naming the
    # pinned corpus tree without printing the repository twice.
    text = render_text(build_report(), WIDE)
    alpha_section = text[text.index('project alpha') : text.index('project beta')]
    assert f'  corpus: https://github.com/example/alpha/tree/{"3" * 40}' in alpha_section
    assert alpha_section.count('corpus:') == 1
    assert 'tree:' not in alpha_section
    assert 'jendrikseipp' not in alpha_section
    beta_section = text[text.index('project beta') : text.index('project gamma')]
    # Non-GitHub ad-hoc project: escaped repository string and SHA on the
    # same one line; no pinned-tree URL is fabricated (reporting §4.1, §5).
    assert '  corpus: ssh://git@internal.invalid/beta.git @ 444444444444' in beta_section
    assert beta_section.count('corpus:') == 1
    assert 'https://github.com' not in beta_section


def test_source_permalink_targets_corpus_sha_and_normalized_path() -> None:
    # Reporting acceptance 11 and 28: per-finding URL lines are opt-in.
    plain = render_text(build_report(), WIDE)
    assert 'url: https://github.com/' not in plain
    text = render_text(build_report(), TextRenderOptions(width=160, source_urls=True))
    assert f'url: https://github.com/example/alpha/blob/{"3" * 40}/pkg/mod.py#L9' in text
    assert f'url: https://github.com/example/alpha/blob/{"3" * 40}/pkg/mod.py#L14' in text
    # The detector base/head SHAs never form source links (reporting §5).
    assert f'blob/{"1" * 40}' not in text
    assert f'blob/{"2" * 40}' not in text


def test_moved_span_renders_as_dropped_plus_new_with_own_excerpts() -> None:
    # Reporting acceptance 10: a detector-reported line change surfaces as
    # a dropped plus a new finding, each with its own single excerpt; the
    # labelled base/head excerpt pair no longer exists.
    text = render_text(build_report(), WIDE)
    assert '10 | def mover():' in text
    assert '14 | def mover():  # moved' in text
    labels = {line.strip() for line in text.splitlines()}
    assert 'base:' not in labels
    assert 'head:' not in labels


def test_unchanged_span_shows_reference_excerpt_once() -> None:
    text = render_text(build_report(), WIDE)
    assert text.count('def flaky():') == 1
    section = text[text.index("unused function 'flaky'") : text.index('def flaky():')]
    assert 'base:' not in section
    assert 'head:' not in section


def test_source_lines_carry_real_line_numbers_and_omission_counts() -> None:
    # Reporting §4.5 and acceptance 19: omission text appears only for a
    # positive count and never as an unexplained ellipsis.
    text = render_text(build_report(), WIDE)
    assert '9 | def fresh(request):' in text
    assert '10 |     return request' in text
    assert '(6 reported-span line(s) omitted)' in text
    assert text.count('reported-span line(s) omitted') == 1


def test_excerpt_lines_zero_suppresses_source_but_not_rows() -> None:
    # Reporting acceptance 18.
    report = build_report()
    manifest = report.manifest.model_copy(
        update={'settings': report.manifest.settings.model_copy(update={'excerpt_lines': 0})}
    )
    text = render_text(report.model_copy(update={'manifest': manifest}), WIDE)
    assert 'def fresh(request):' not in text
    assert 'pkg/mod.py:L9' in text
    markdown = render_github(report.model_copy(update={'manifest': manifest}))
    assert 'def fresh(request):' not in markdown
    assert 'pkg/mod.py:L9' in markdown


def test_raw_detector_records_never_render() -> None:
    # Reporting §3.4: raw excerpts stay JSON provenance; human renderers
    # never display serialized detector records.
    report = build_report()
    text = render_text(report, WIDE)
    markdown = render_github(report)
    for rendered in (text, markdown):
        assert 'evil.py:9' not in rendered
        assert 'line two' not in rendered
    assert 'evil.py' in render_json(report)


def test_message_only_suppression_remains_explicit() -> None:
    report = build_report()
    text = render_text(report, WIDE)
    assert 'old wording for reworded-3' in text
    assert 'old wording for reworded-4' not in text
    assert '(2 more message-only change(s) not shown; the JSON report retains full detail)' in text
    markdown = render_github(report)
    assert '(2 more message-only change(s) not shown; the JSON report retains full detail)' in markdown
    assert 'reworded-4' in render_json(report)


def test_github_locations_are_pinned_markdown_links() -> None:
    # Reporting acceptance 17: locations are clickable; ad-hoc projects
    # render escaped plain text without an invented URL.
    markdown = render_github(build_report())
    assert f'[pkg/mod.py:L9](https://github.com/example/alpha/blob/{"3" * 40}/pkg/mod.py#L9)' in markdown
    assert f'[pkg/mod.py:L14](https://github.com/example/alpha/blob/{"3" * 40}/pkg/mod.py#L14)' in markdown
    beta_section = markdown[markdown.index('## `beta`') :]
    assert 'lib/util.py:L3' in beta_section
    assert '](https://' not in beta_section


def test_github_output_contains_no_ansi_and_keeps_glyphs() -> None:
    markdown = render_github(build_report())
    assert '\x1b' not in markdown
    assert '\U0001f7e2 +' in markdown
    assert '\U0001f534 -' in markdown
    assert '\U0001f7e1 ~' in markdown
    header = next(line for line in markdown.splitlines() if line.startswith('|  | rule'))
    assert header == '|  | rule | % | location | message |'


def test_github_source_evidence_is_in_row_not_collapsed() -> None:
    markdown = render_github(build_report())
    assert '<details>' not in markdown
    row = next(line for line in markdown.splitlines() if 'fresh' in line and line.startswith('|'))
    assert '9 \\| `def fresh(request):`' in row


def test_github_escapes_untrusted_error_details() -> None:
    report = build_report()
    hostile_error = ToolError(side='base', exit_code=2, detail='<script>alert(1)</script> [link](https://evil.invalid)')
    project = report.projects[0].model_copy(update={'errors': (hostile_error,)})
    hostile = report.model_copy(update={'projects': (project, *report.projects[1:])})
    markdown = render_github(hostile)
    assert markdown.count('<script>') == markdown.count('\\<script>') > 0
    assert markdown.count('</script>') == markdown.count('\\</script>') > 0
    assert markdown.count('[link\\]') == markdown.count('\\[link\\]') > 0


def test_hostile_source_and_fields_cannot_break_structure() -> None:
    hostile = diff(
        DiffClass.NEW,
        'evil | [x](y) `tick` <b>',
        path='pkg\\evil|path.py',
        head=occurrence(
            2,
            'msg with [rich markup] and | pipe and \x1b[31mansi',
            confidence=None,
            rule_id='RULE`|<[*_',
            source=source_lines(2, 'code | with pipe \x1b]8;;http://evil\x1b\\ and <img src=x>'),
        ),
    )
    project = ProjectReport(
        project='alpha',
        diffs=(hostile,),
        totals=DiffTotals(new=1),
        rollups=compute_rollups((hostile,)),
        truncated=False,
        base_findings=0,
        head_findings=1,
        measured_cost_seconds=None,
    )
    report = build_report().model_copy(update={'projects': (project,), 'truncated': False})
    text = render_text(report, WIDE)
    assert '\x1b' not in text
    markdown = render_github(report)
    assert '\x1b' not in markdown
    finding_row = next(row for row in markdown.splitlines() if row.startswith('| ') and 'evil' in row)
    # Escaped pipes only: the row still has exactly its 5 columns.
    assert finding_row.count('|') - finding_row.count('\\|') == 6
    # Source text renders as a code span, where markdown structure and raw
    # HTML are inert, so the hostile tag stays literal text (reporting §7).
    source_span = finding_row.rsplit('<br>', maxsplit=1)[-1]
    assert source_span.startswith('2 \\| `')
    assert '<img src=x>' in source_span
    assert markdown.count('<img') == 1


def test_sanitize_inline_strips_and_caps_with_counts() -> None:
    assert sanitize_inline('a\x00b\x1bc\nd') == 'a b c d'
    capped = sanitize_inline('x' * 400)
    assert len(capped) == 300
    assert capped == 'x' * 291 + '...(+109)'
    assert sanitize_inline('short') == 'short'


@pytest.mark.parametrize(
    ('cap', 'expected'),
    [(0, ''), (2, 'xx'), (6, 'xxxxxx'), (8, 'xxxxxxxx'), (9, 'x...(+49)')],
)
def test_sanitize_inline_never_exceeds_tiny_caps(cap: int, expected: str) -> None:
    # Regression: caps below the marker length must fall back to a hard cut
    # rather than exceeding the cap.
    assert sanitize_inline('x' * 50, max_length=cap) == expected


def test_sanitize_location_preserves_beginning_and_ending() -> None:
    path = 'src/deeply/' + 'nested/' * 30 + 'module.py:L4'
    capped = sanitize_location(path, max_length=40)
    assert len(capped) <= 40
    assert capped.startswith('src/deep')
    assert capped.endswith('module.py:L4')
    assert '...(+' in capped
    assert sanitize_location('short.py:L1', max_length=40) == 'short.py:L1'


def test_sanitize_location_tiny_caps_fall_back_to_end_truncation() -> None:
    assert sanitize_location('x' * 50, max_length=8) == 'xxxxxxxx'
    assert sanitize_location('y' * 50, max_length=12) == 'yyyy...(+46)'


def test_sanitize_cell_escapes_metacharacters() -> None:
    assert sanitize_cell('a|b`c\\d') == 'a\\|b\\`c\\\\d'
    assert sanitize_cell('<img src=x>') == '\\<img src=x>'
    assert sanitize_cell('[x](javascript:1)') == '\\[x\\](javascript:1)'
    assert sanitize_cell('*bold* _em_') == '\\*bold\\* \\_em\\_'


def test_escape_argv_text_escapes_controls_without_shortening() -> None:
    assert escape_argv_text('/very/long/path/that/stays') == '/very/long/path/that/stays'
    assert escape_argv_text('a\x1bb\u2028c') == 'a\\x1bb\\u2028c'


def test_code_span_outruns_content_backticks() -> None:
    assert code_span('plain') == '`plain`'
    assert code_span('has `tick` inside') == '``has `tick` inside``'
    assert code_span('run ```` of four').startswith('`````run')
    assert code_span('`edge') == '`` `edge ``'
    assert code_span('') == '`  `'


def test_tree_and_source_url_validation() -> None:
    assert tree_url(ALPHA_PIN) == f'https://github.com/example/alpha/tree/{"3" * 40}'
    assert tree_url(BETA_PIN) is None
    assert (
        source_url(ALPHA_PIN, 'pkg/mod.py', 4, 4) == f'https://github.com/example/alpha/blob/{"3" * 40}/pkg/mod.py#L4'
    )
    assert source_url(ALPHA_PIN, 'pkg/mod.py', 4, 9) == (
        f'https://github.com/example/alpha/blob/{"3" * 40}/pkg/mod.py#L4-L9'
    )
    assert source_url(ALPHA_PIN, 'pkg/has space+q.py', 1, 1) == (
        f'https://github.com/example/alpha/blob/{"3" * 40}/pkg/has%20space%2Bq.py#L1'
    )
    assert source_url(BETA_PIN, 'pkg/mod.py', 1, 1) is None
    unresolved = ALPHA_PIN.model_copy(update={'resolved_sha': 'branch-name'})
    assert source_url(unresolved, 'pkg/mod.py', 1, 1) is None
    for hostile in ('pkg//mod.py', 'pkg/./mod.py', 'pkg/../mod.py', 'pkg\\mod.py', 'pkg/mo\x07d.py'):
        assert source_url(ALPHA_PIN, hostile, 1, 1) is None


def construct_diff(
    diff_class: DiffClass, base: FindingOccurrence | None, head: FindingOccurrence | None
) -> FindingDiff:
    # model_construct skips validation: these diffs are deliberately
    # inconsistent so the renderers' defensive branches are exercised.
    return FindingDiff.model_construct(
        diff_class=diff_class,
        identity='x' * 64,
        tool='vulture',
        project='alpha',
        path='pkg/mod.py',
        symbol='s',
        kind='function',
        base_occurrence=base,
        head_occurrence=head,
        changed_fields=(),
    )


def test_excerpt_sides_tolerate_invalidly_constructed_diffs() -> None:
    assert excerpt_sides(construct_diff(DiffClass.NEW, None, None)) == ()
    headless_changed = construct_diff(DiffClass.CHANGED, occurrence(1, 'm'), None)
    assert excerpt_sides(headless_changed) == (occurrence(1, 'm'),)
    assert pin_for_project(build_manifest(), 'unknown-project') is None


def test_tool_has_severity_defaults_to_true_for_unknown_tools() -> None:
    # A transformed report may carry an unregistered tool name: it is
    # assumed capable, and report_has_severity suppresses the column when
    # no finding actually carries a severity.
    assert tool_has_severity('vulture') is False
    assert tool_has_severity('skylos') is True
    assert tool_has_severity('no-such-tool') is True


def test_text_report_ends_with_the_repeated_summary_and_impact_table() -> None:
    # Reporting acceptance 29.
    text = render_text(build_report(), WIDE)
    footer = text[text.rindex('\nsummary\n') :]
    assert (
        'totals: 4 new, 4 dropped, 8 changed (1 confidence-only, 6 message-only, 0 severity-only, 1 multiple)' in footer
    )
    assert 'new 4: kind:function 2, SKY-U001 1, SKY-U003 1' in footer
    assert 'cost: 1.67s' in footer
    assert 'errors: 1' in footer
    header = next(line for line in footer.splitlines() if line.strip().startswith('project '))
    assert header.split() == [
        'project',
        'base',
        '->',
        'head',
        'delta',
        'ratio',
        'new',
        'dropped',
        'changed',
        'cost',
        'warnings',
    ]
    rows = [line for line in footer.splitlines() if line.startswith('  ') and not line.strip().startswith('project')]
    # Ordered by descending absolute delta, then project name: alpha and
    # beta both moved by one, gamma did not move at all.
    assert [row.split()[0] for row in rows] == ['alpha', 'beta', 'gamma']
    assert '12 -> 13' in rows[0]
    assert '+1' in rows[0]
    assert '1.08x' in rows[0]
    assert '1.25s' in rows[0]
    # alpha carries one error, one integrity warning, and one source warning.
    assert rows[0].split()[-1] == '3'
    # A zero baseline renders explicitly rather than as a misleading ratio.
    assert rows[2].split()[4:6] == ['+0', '-']


def test_impact_ratio_marks_a_zero_baseline_as_new() -> None:
    # Reporting acceptance 29: absolute and relative change appear together
    # and a zero baseline is explicit.
    report = build_report()
    grown = report.projects[2].model_copy(update={'base_findings': 0, 'head_findings': 7})
    text = render_text(report.model_copy(update={'projects': (grown,)}), WIDE)
    footer = text[text.rindex('\nsummary\n') :]
    row = next(line for line in footer.splitlines() if line.strip().startswith('gamma'))
    assert row.split()[1:5] == ['0', '->', '7', '+7']
    assert row.split()[5] == 'new'


def test_github_overall_header_carries_cost_and_warning_summaries() -> None:
    # Reporting acceptance 21: the GitHub overall header is not a reduced
    # version of the text one.
    markdown = render_github(build_report())
    overall = markdown[markdown.index('## Totals') : markdown.index('## `alpha`')]
    assert '- **cost**: 1.67s' in overall
    assert '- **errors**: 1' in overall
    assert '- **corpus-integrity warnings**: 1' in overall
    assert '- **source warnings**: 1' in overall
    assert '- **rollup**: new 4: kind:function 2, SKY-U001 1, SKY-U003 1' in overall
    assert '| new | dropped | changed | confidence-only | message-only | severity-only | multiple |' in overall
    # Anchored on the newline: the row without its multiple cell is a
    # prefix of the row with one, so an unanchored match asserts nothing
    # about the last column.
    assert '\n| 4 | 4 | 8 | 1 | 6 | 0 | 1 |\n' in overall


def test_github_rows_carry_only_the_first_retained_source_line() -> None:
    # Reporting acceptance 30.
    markdown = render_github(build_report())
    rows = [line for line in markdown.splitlines() if line.startswith(('| \U0001f7e2', '| \U0001f534'))]
    fresh = next(row for row in rows if 'hostile excerpt' in row)
    assert '9 \\| `def fresh(request):`' in fresh
    assert 'return request' not in fresh
    assert fresh.endswith('<br>\\[...\\] |')
    span = next(row for row in rows if 'omitted tail' in row)
    assert '50 \\| `class Span:`' in span
    assert 'a = 1' not in span
    assert span.endswith('<br>\\[...\\] |')
    # The complete retained excerpt is still in JSON (§7).
    assert '    a = 1' in render_json(build_report())
    # No row serializes a whole excerpt into one cell.
    assert max(len(row) for row in rows) < 400


def test_footer_omits_the_impact_table_when_no_project_ran() -> None:
    empty = Report(manifest=build_manifest(), projects=(), totals=DiffTotals(), rollups=(), truncated=False)
    text = render_text(empty, WIDE)
    footer = text[text.rindex('\nsummary\n') :]
    assert 'totals: 0 new, 0 dropped, 0 changed' in footer
    assert 'cost: n/a' in footer
    assert 'base -> head' not in footer
