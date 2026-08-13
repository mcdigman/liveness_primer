# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the schema models and finding identity (contract §7)."""

from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from liveness_primer.findings import (
    SCHEMA_VERSION,
    Annotation,
    AnnotationProvenance,
    AnnotationTarget,
    ChangedField,
    CorpusPinRecord,
    DiffClass,
    DiffRollup,
    DiffTotals,
    EvidenceKind,
    ExplorerExport,
    ExplorerReview,
    FetchRecord,
    Finding,
    FindingComment,
    FindingDiff,
    FindingLocator,
    FindingOccurrence,
    ProjectReport,
    Report,
    RunManifest,
    RunSettings,
    SourceExcerpt,
    Verdict,
    canonical_occurrence_key,
    finding_identity,
)


def make_finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        'tool': 'vulture',
        'project': 'demo',
        'path': 'pkg/mod.py',
        'symbol': 'unused_fn',
        'kind': 'function',
        'message': "unused function 'unused_fn'",
        'start_line': 10,
        'end_line': 10,
        'confidence': 60,
        'raw_excerpt': "pkg/mod.py:10: unused function 'unused_fn' (60% confidence)",
    }
    fields.update(overrides)
    return Finding.model_validate(fields)


def make_manifest() -> RunManifest:
    return RunManifest(
        created_at=datetime(2026, 7, 28, tzinfo=UTC),
        tool='vulture',
        detector_repo='https://example.invalid/detector.git',
        base=None,
        head=None,
        base_cmd=('old-vulture',),
        head_cmd=('new-vulture',),
        comparable=False,
        environment_delta=(),
        isolation_enforced=False,
        platform='macosx_14_0_arm64',
        python_version='3.14.6',
        installer=None,
        fetches=(FetchRecord(kind='git', name='https://example.invalid/detector.git', resolved='a' * 40),),
        corpus_pins=(
            CorpusPinRecord(
                name='demo',
                repo='https://example.invalid/demo.git',
                requested='branch:main',
                resolved_sha='b' * 40,
            ),
        ),
        settings=RunSettings(
            jobs=2,
            timeout=60.0,
            max_results=100,
            excerpt_lines=5,
            fail_on=(),
            selection=('demo',),
        ),
    )


def test_identity_is_stable_across_observable_fields() -> None:
    base = make_finding()
    observed = make_finding(confidence=10, message='different message', severity='HIGH')
    assert base.identity == observed.identity
    assert base.identity == finding_identity('vulture', 'demo', 'pkg/mod.py', 'unused_fn', 'function', None, 10, 10)


def test_identity_distinguishes_each_component() -> None:
    base = make_finding()
    assert base.identity != make_finding(tool='skylos').identity
    assert base.identity != make_finding(project='other').identity
    assert base.identity != make_finding(path='pkg/other.py').identity
    assert base.identity != make_finding(symbol='other_fn').identity
    assert base.identity != make_finding(kind='method').identity
    assert base.identity != make_finding(rule_id='SKY-U001').identity
    assert base.identity != make_finding(start_line=9).identity
    assert base.identity != make_finding(end_line=11).identity


def test_identity_distinguishes_no_symbol_from_empty_like_symbol() -> None:
    assert finding_identity('t', 'p', 'f.py', None, 'k', None, 1, 1) != finding_identity(
        't', 'p', 'f.py', '', 'k', None, 1, 1
    )


def test_identity_serialization_is_unambiguous_across_field_boundaries() -> None:
    # Regression: delimiter characters inside attacker-controlled fields
    # must never make distinct (path, symbol) pairs collide.
    assert finding_identity('t', 'p', 'a\x1fsb', 'c', 'k', None, 1, 1) != finding_identity(
        't', 'p', 'a', 'b\x1fsc', 'k', None, 1, 1
    )
    assert finding_identity('t', 'p', 'a"b', 'c', 'k', None, 1, 1) != finding_identity(
        't', 'p', 'a', 'b"c', 'k', None, 1, 1
    )
    assert finding_identity('t', 'p\x1f', 'a', None, 'k', None, 1, 1) != finding_identity(
        't', 'p', '\x1fa', None, 'k', None, 1, 1
    )


def test_finding_rejects_inverted_span() -> None:
    with pytest.raises(ValidationError, match='precedes'):
        make_finding(start_line=5, end_line=4)


def test_occurrence_rejects_inverted_span() -> None:
    with pytest.raises(ValidationError, match='precedes'):
        FindingOccurrence(start_line=5, end_line=4, message='m')


def test_occurrence_projection_carries_all_fields() -> None:
    occurrence = make_finding(rule_id='SKY-U001', severity='HIGH').occurrence()
    assert occurrence == FindingOccurrence(
        start_line=10,
        end_line=10,
        message="unused function 'unused_fn'",
        confidence=60,
        severity='HIGH',
        rule_id='SKY-U001',
        raw_excerpt="pkg/mod.py:10: unused function 'unused_fn' (60% confidence)",
    )


def test_canonical_key_orders_missing_confidence_first() -> None:
    with_confidence = FindingOccurrence(start_line=1, end_line=1, message='m', confidence=0)
    without_confidence = FindingOccurrence(start_line=1, end_line=1, message='m', confidence=None)
    assert canonical_occurrence_key(without_confidence) < canonical_occurrence_key(with_confidence)


def test_canonical_key_field_order() -> None:
    occurrence = FindingOccurrence(
        start_line=3,
        end_line=4,
        message='m',
        confidence=80,
        severity='HIGH',
        rule_id='SKY-U001',
    )
    assert canonical_occurrence_key(occurrence) == (3, 4, 'm', 1, 80, 1, 'SKY-U001', 1, 'HIGH')


def test_canonical_key_orders_missing_rule_id_and_severity_first() -> None:
    # Reporting contract §3.1: rule_id and severity carry presence
    # components, so absent sorts before present.
    with_rule = FindingOccurrence(start_line=1, end_line=1, message='m', rule_id='A')
    without_rule = FindingOccurrence(start_line=1, end_line=1, message='m', rule_id=None)
    assert canonical_occurrence_key(without_rule) < canonical_occurrence_key(with_rule)
    assert canonical_occurrence_key(without_rule) == (1, 1, 'm', 0, 0, 0, '', 0, '')
    with_severity = FindingOccurrence(start_line=1, end_line=1, message='m', severity='LOW')
    assert canonical_occurrence_key(without_rule) < canonical_occurrence_key(with_severity)


def test_rule_id_and_span_are_part_of_finding_identity() -> None:
    # A rule-code change on the same target is a dropped finding plus a new
    # one, never a `changed` pair; the line span pins identity the same way.
    assert make_finding(rule_id='SKY-U001').identity != make_finding(rule_id='SKY-U999').identity


def test_severity_normalizes_on_validation() -> None:
    # Casing and punctuation variants of one label must never read as a
    # changed field, and a label with nothing left normalizes to absent.
    assert make_finding(severity='High').severity == 'HIGH'
    assert make_finding(severity=' very-high! ').severity == 'VERYHIGH'
    assert make_finding(severity='!!').severity is None
    assert make_finding(severity=None).severity is None
    occurrence = FindingOccurrence(start_line=1, end_line=1, message='m', severity='Medium ')
    assert occurrence.severity == 'MEDIUM'


def test_source_excerpt_shape_is_validated() -> None:
    excerpt = SourceExcerpt(start_line=4, lines=('def f():', '    pass'), omitted_lines=1)
    assert excerpt.start_line == 4
    with pytest.raises(ValidationError, match='at least 1'):
        SourceExcerpt(start_line=4, lines=(), omitted_lines=0)
    with pytest.raises(ValidationError, match='greater than or equal'):
        SourceExcerpt.model_validate({'start_line': 0, 'lines': ('x',), 'omitted_lines': 0})
    with pytest.raises(ValidationError, match='greater than or equal'):
        SourceExcerpt.model_validate({'start_line': 1, 'lines': ('x',), 'omitted_lines': -1})


def test_diff_rollup_requires_exactly_one_group_key() -> None:
    rollup = DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=2)
    assert rollup.count == 2
    fallback = DiffRollup(diff_class=DiffClass.NEW, rule_id=None, kind='function', count=1)
    assert fallback.kind == 'function'
    with pytest.raises(ValidationError, match='exactly one of rule_id and kind'):
        DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind='function', count=1)
    with pytest.raises(ValidationError, match='exactly one of rule_id and kind'):
        DiffRollup(diff_class=DiffClass.NEW, rule_id=None, kind=None, count=1)
    with pytest.raises(ValidationError, match='greater than or equal'):
        DiffRollup.model_validate({'diff_class': DiffClass.NEW, 'rule_id': 'SKY-U001', 'kind': None, 'count': 0})


def project_report(totals: DiffTotals, rollups: tuple[DiffRollup, ...]) -> ProjectReport:
    return ProjectReport(
        project='alpha',
        diffs=(),
        totals=totals,
        rollups=rollups,
        truncated=False,
        base_findings=0,
        head_findings=0,
        measured_cost_seconds=None,
    )


def test_diff_totals_counts_are_non_negative_and_partition_the_changed_count() -> None:
    # Renderers derive the multi-field breakout by subtracting the three
    # exclusive ones from `changed`, so an untrusted payload that breaks the
    # partition must not deserialize: it would render a negative count.
    for field in ('new', 'dropped', 'changed', 'changed_confidence_only'):
        with pytest.raises(ValidationError, match='greater than or equal to 0'):
            DiffTotals(**{field: -1})
    with pytest.raises(ValidationError, match='breakouts sum to 8, above the changed count 2'):
        DiffTotals(changed=2, changed_confidence_only=3, changed_message_only=5)
    # An exact partition and a partition with a remainder both stand.
    exact = DiffTotals(changed=3, changed_confidence_only=1, changed_message_only=1, changed_severity_only=1)
    assert exact.changed == 3
    assert DiffTotals(changed=8, changed_confidence_only=1, changed_message_only=6).changed == 8


def test_project_rollups_are_required_and_must_match_the_totals() -> None:
    # Reporting acceptance 25: stale aggregate data is an invalid report,
    # and validation is where a rewriting hook fails.
    group = DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=1)
    assert project_report(DiffTotals(new=1), (group,)).rollups == (group,)
    with pytest.raises(ValidationError, match='Field required'):
        ProjectReport.model_validate(
            {
                'project': 'alpha',
                'diffs': (),
                'totals': DiffTotals(new=1),
                'truncated': False,
                'base_findings': 0,
                'head_findings': 0,
                'measured_cost_seconds': None,
            }
        )
    with pytest.raises(ValidationError, match='rollups are stale: new counts disagree'):
        project_report(DiffTotals(new=1), ())
    with pytest.raises(ValidationError, match='rollups are stale: dropped, changed counts disagree'):
        project_report(
            DiffTotals(new=1),
            (
                group,
                DiffRollup(diff_class=DiffClass.DROPPED, rule_id=None, kind='function', count=2),
                DiffRollup(diff_class=DiffClass.CHANGED, rule_id=None, kind='function', count=3),
            ),
        )


def test_overall_aggregates_must_be_the_sum_of_the_projects() -> None:
    # Reporting acceptance 25.
    group = DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=1)
    project = project_report(DiffTotals(new=1), (group,))
    manifest = make_manifest()
    report = Report(manifest=manifest, projects=(project,), totals=DiffTotals(new=1), rollups=(group,), truncated=False)
    assert report.rollups == (group,)
    with pytest.raises(ValidationError, match='overall totals are stale'):
        Report(manifest=manifest, projects=(project,), totals=DiffTotals(new=2), rollups=(group,), truncated=False)
    with pytest.raises(ValidationError, match='overall rollups are stale'):
        Report(manifest=manifest, projects=(project,), totals=DiffTotals(new=1), rollups=(), truncated=False)


def occurrence_at(line: int, *, message: str = 'm') -> FindingOccurrence:
    return FindingOccurrence(start_line=line, end_line=line, message=message, confidence=None)


def diff_identity(line: int) -> str:
    return finding_identity('vulture', 'demo', 'pkg/mod.py', 'unused_fn', 'function', None, line, line)


def diff_common(line: int) -> dict[str, object]:
    return {
        'identity': diff_identity(line),
        'tool': 'vulture',
        'project': 'demo',
        'path': 'pkg/mod.py',
        'symbol': 'unused_fn',
        'kind': 'function',
    }


def test_diff_requires_consistent_sides() -> None:
    with pytest.raises(ValidationError, match='inconsistent'):
        FindingDiff.model_validate({**diff_common(1), 'diff_class': DiffClass.NEW, 'base_occurrence': occurrence_at(1)})
    with pytest.raises(ValidationError, match='inconsistent'):
        FindingDiff.model_validate(
            {**diff_common(1), 'diff_class': DiffClass.DROPPED, 'head_occurrence': occurrence_at(1)}
        )
    with pytest.raises(ValidationError, match='inconsistent'):
        FindingDiff.model_validate(
            {
                **diff_common(1),
                'diff_class': DiffClass.CHANGED,
                'base_occurrence': occurrence_at(1),
                'head_occurrence': occurrence_at(1, message='m2'),
            }
        )


def test_diff_rejects_occurrences_contradicting_the_identity_hash() -> None:
    # The identity hash covers the rule ID and line span; a side whose
    # recomputed hash disagrees is an invalid diff, which also forbids a
    # `changed` pair whose sides differ in rule or span.
    with pytest.raises(ValidationError, match='contradicts the declared identity'):
        FindingDiff.model_validate({**diff_common(1), 'diff_class': DiffClass.NEW, 'head_occurrence': occurrence_at(2)})
    with pytest.raises(ValidationError, match='contradicts the declared identity'):
        FindingDiff.model_validate(
            {
                **diff_common(1),
                'diff_class': DiffClass.CHANGED,
                'base_occurrence': occurrence_at(1),
                'head_occurrence': occurrence_at(2, message='m2'),
                'changed_fields': (ChangedField.MESSAGE,),
            }
        )


def test_diff_reference_side_follows_class() -> None:
    new = FindingDiff.model_validate(
        {**diff_common(2), 'diff_class': DiffClass.NEW, 'head_occurrence': occurrence_at(2)}
    )
    dropped = FindingDiff.model_validate(
        {**diff_common(1), 'diff_class': DiffClass.DROPPED, 'base_occurrence': occurrence_at(1)}
    )
    changed = FindingDiff.model_validate(
        {
            **diff_common(1),
            'diff_class': DiffClass.CHANGED,
            'base_occurrence': occurrence_at(1),
            'head_occurrence': occurrence_at(1, message='m2'),
            'changed_fields': (ChangedField.MESSAGE,),
        }
    )
    assert new.reference_occurrence == occurrence_at(2)
    assert dropped.reference_occurrence == occurrence_at(1)
    assert changed.reference_occurrence == occurrence_at(1)


def test_diff_reference_side_rejects_invalidly_constructed_diff() -> None:
    invalid = FindingDiff.model_construct(
        diff_class=DiffClass.NEW,
        identity=make_finding().identity,
        tool='vulture',
        project='demo',
        path='pkg/mod.py',
        symbol='unused_fn',
        kind='function',
        base_occurrence=None,
        head_occurrence=None,
        changed_fields=(),
    )
    with pytest.raises(ValueError, match='reference side is absent'):
        _ = invalid.reference_occurrence


def test_report_embeds_schema_version() -> None:
    report = Report(manifest=make_manifest(), projects=(), totals=DiffTotals(), rollups=(), truncated=False)
    assert report.schema_version == SCHEMA_VERSION
    assert report.manifest.schema_version == SCHEMA_VERSION
    payload = report.model_dump_json()
    assert SCHEMA_VERSION in payload


def test_every_standalone_payload_embeds_schema_version() -> None:
    # Contract §7: the package-wide version appears in every independently
    # exported payload, including findings, occurrences, and diffs.
    finding = make_finding()
    occurrence = finding.occurrence()
    diff = FindingDiff(
        diff_class=DiffClass.NEW,
        identity=finding.identity,
        tool=finding.tool,
        project=finding.project,
        path=finding.path,
        symbol=finding.symbol,
        kind=finding.kind,
        head_occurrence=occurrence,
    )
    for payload in (finding, occurrence, diff):
        assert payload.schema_version == SCHEMA_VERSION
        assert f'"schema_version":"{SCHEMA_VERSION}"' in payload.model_dump_json()


def locator_at(occurrence: int, *, line: int = 10, project: str = 'demo') -> FindingLocator:
    return FindingLocator(project=project, identity='a' * 64, line=line, occurrence=occurrence)


def test_diff_locator_is_absent_until_canonical_assembly() -> None:
    finding = make_finding()
    diff = FindingDiff(
        diff_class=DiffClass.NEW,
        identity=finding.identity,
        tool=finding.tool,
        project=finding.project,
        path=finding.path,
        symbol=finding.symbol,
        kind=finding.kind,
        head_occurrence=finding.occurrence(),
    )
    assert diff.locator is None
    located = diff.model_copy(update={'locator': locator_at(0)})
    assert '"locator":{"project":"demo"' in located.model_dump_json()


def test_explorer_review_roundtrips_and_embeds_schema_version() -> None:
    review = ExplorerReview(
        report_sha256='ab' * 32,
        selected=(locator_at(0), locator_at(1)),
        hidden=(locator_at(0),),
    )
    assert review.schema_version == SCHEMA_VERSION
    # A hidden finding may remain selected (explorer contract §6).
    assert ExplorerReview.model_validate_json(review.model_dump_json()) == review


def test_explorer_review_requires_a_lowercase_full_digest() -> None:
    for digest in ('AB' * 32, 'ab' * 31, 'ab' * 33, 'zz' * 32, ''):
        with pytest.raises(ValidationError, match='report_sha256'):
            ExplorerReview.model_validate({'report_sha256': digest, 'selected': (), 'hidden': ()})


def make_export(**overrides: object) -> ExplorerExport:
    group = DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U001', kind=None, count=1)
    fields: dict[str, object] = {
        'source_report_sha256': 'ab' * 32,
        'manifest': make_manifest(),
        'projects': (project_report(DiffTotals(new=1), (group,)),),
        'totals': DiffTotals(new=1),
        'rollups': (group,),
        'truncated': True,
    }
    fields.update(overrides)
    return ExplorerExport.model_validate(fields)


def test_explorer_export_is_a_report_carrying_provenance() -> None:
    # Explorer contract §6: the export is the report format plus the origin
    # digest, so the subset it carries is the truncation the format models.
    export = make_export()
    assert isinstance(export, Report)
    assert export.schema_version == SCHEMA_VERSION
    assert export.document_kind == 'explorer-export'
    assert export.comments == ()
    assert ExplorerExport.model_validate_json(export.model_dump_json()) == export
    # The two documents stay distinct under strict validation both ways.
    with pytest.raises(ValidationError, match='document_kind'):
        Report.model_validate(export.model_dump())
    with pytest.raises(ValidationError, match='source_report_sha256'):
        ExplorerExport.model_validate(
            Report(manifest=make_manifest(), projects=(), totals=DiffTotals(), rollups=(), truncated=False).model_dump()
        )


def test_explorer_export_rejects_a_foreign_document_kind() -> None:
    assert make_export(document_kind='explorer-export').document_kind == 'explorer-export'
    with pytest.raises(ValidationError, match="document_kind 'something-else' is not the supported"):
        make_export(document_kind='something-else')


def test_explorer_export_inherits_the_aggregate_checks() -> None:
    with pytest.raises(ValidationError, match='overall totals are stale'):
        make_export(totals=DiffTotals(new=2))


def test_explorer_export_requires_a_lowercase_full_origin_digest() -> None:
    for digest in ('AB' * 32, 'ab' * 31, 'ab' * 33, 'zz' * 32, ''):
        with pytest.raises(ValidationError, match='source_report_sha256'):
            make_export(source_report_sha256=digest)


def test_explorer_export_comments_are_additive_and_keyed_by_unique_locators() -> None:
    # The sidecar ships with its final shape so populating it later is not a
    # schema change: a comment names the finding it annotates by locator.
    comment = FindingComment(locator=locator_at(0), comment='needs a second look')
    export = make_export(comments=(comment,))
    assert export.comments == (comment,)
    assert ExplorerExport.model_validate_json(export.model_dump_json()) == export
    with pytest.raises(ValidationError, match='comments contains duplicate locators'):
        make_export(comments=(comment, FindingComment(locator=locator_at(0), comment='again')))


def test_finding_comment_is_bounded_to_a_margin_note() -> None:
    # A comment is a margin note, not a thread: 200 characters is the bound
    # both implementations enforce, and raising it later would strand new
    # exports in explorers pinned to this schema version.
    assert FindingComment(locator=locator_at(0), comment='x' * 200).comment == 'x' * 200
    with pytest.raises(ValidationError, match='at most 200 characters'):
        FindingComment(locator=locator_at(0), comment='x' * 201)


def test_explorer_review_rejects_duplicate_locators_within_a_tuple() -> None:
    for name in ('selected', 'hidden'):
        with pytest.raises(ValidationError, match=f'{name} contains duplicate locators'):
            ExplorerReview.model_validate(
                {
                    'report_sha256': 'ab' * 32,
                    'selected': (),
                    'hidden': (),
                    name: (locator_at(0), locator_at(0)),
                }
            )


def test_finding_locator_bounds() -> None:
    with pytest.raises(ValidationError, match='line'):
        FindingLocator.model_validate({'project': 'demo', 'identity': 'a' * 64, 'line': 0, 'occurrence': 0})
    with pytest.raises(ValidationError, match='occurrence'):
        FindingLocator.model_validate({'project': 'demo', 'identity': 'a' * 64, 'line': 1, 'occurrence': -1})


def test_schema_version_is_constrained_to_the_supported_version() -> None:
    with pytest.raises(ValidationError, match='is not the supported'):
        make_finding(schema_version='0.9.0')
    with pytest.raises(ValidationError, match='is not the supported'):
        FindingOccurrence(schema_version='1.2.0', start_line=1, end_line=1, message='m')
    manifest = make_manifest()
    with pytest.raises(ValidationError, match='is not the supported'):
        Report(schema_version='1.0.1', manifest=manifest, projects=(), totals=DiffTotals(), rollups=(), truncated=False)


def test_annotation_coverage_rule() -> None:
    provenance = AnnotationProvenance(
        source_project='demo',
        commit='c' * 40,
        extraction_date=date(2026, 7, 28),
    )
    target = AnnotationTarget(path='pkg/mod.py', symbol='unused_fn', line=10)
    live = Annotation(target=target, verdict=Verdict.LIVE, evidence=EvidenceKind.COVERAGE, provenance=provenance)
    no_coverage = Annotation(
        target=target,
        verdict=Verdict.NO_COVERAGE,
        evidence=EvidenceKind.COVERAGE,
        provenance=provenance,
    )
    assert live.schema_version == SCHEMA_VERSION
    assert no_coverage.verdict is Verdict.NO_COVERAGE
    with pytest.raises(ValidationError, match='coverage evidence cannot support'):
        Annotation(target=target, verdict=Verdict.DEAD, evidence=EvidenceKind.COVERAGE, provenance=provenance)
    manual_dead = Annotation(
        target=target,
        verdict=Verdict.DEAD,
        evidence=EvidenceKind.MANUAL,
        provenance=provenance,
        runner='corpus_runners/demo.py',
    )
    assert manual_dead.runner == 'corpus_runners/demo.py'
