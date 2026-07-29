"""Tests for the schema models and finding identity (contract §7).

Copyright (C) 2026 Matthew C. Digman
"""

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
    DiffTotals,
    EvidenceKind,
    FetchRecord,
    Finding,
    FindingDiff,
    FindingOccurrence,
    Report,
    RunManifest,
    RunSettings,
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


def test_identity_is_stable_and_excludes_position() -> None:
    base = make_finding()
    moved = make_finding(start_line=99, end_line=99, confidence=10, message='different message')
    assert base.identity == moved.identity
    assert base.identity == finding_identity('vulture', 'demo', 'pkg/mod.py', 'unused_fn', 'function')


def test_identity_distinguishes_each_component() -> None:
    base = make_finding()
    assert base.identity != make_finding(tool='skylos').identity
    assert base.identity != make_finding(project='other').identity
    assert base.identity != make_finding(path='pkg/other.py').identity
    assert base.identity != make_finding(symbol='other_fn').identity
    assert base.identity != make_finding(kind='method').identity


def test_identity_distinguishes_no_symbol_from_empty_like_symbol() -> None:
    assert finding_identity('t', 'p', 'f.py', None, 'k') != finding_identity('t', 'p', 'f.py', '', 'k')


def test_finding_rejects_inverted_span() -> None:
    with pytest.raises(ValidationError, match='precedes'):
        make_finding(start_line=5, end_line=4)


def test_occurrence_rejects_inverted_span() -> None:
    with pytest.raises(ValidationError, match='precedes'):
        FindingOccurrence(start_line=5, end_line=4, message='m')


def test_occurrence_projection_carries_all_fields() -> None:
    occurrence = make_finding().occurrence()
    assert occurrence == FindingOccurrence(
        start_line=10,
        end_line=10,
        message="unused function 'unused_fn'",
        confidence=60,
        raw_excerpt="pkg/mod.py:10: unused function 'unused_fn' (60% confidence)",
    )


def test_canonical_key_orders_missing_confidence_first() -> None:
    with_confidence = FindingOccurrence(start_line=1, end_line=1, message='m', confidence=0)
    without_confidence = FindingOccurrence(start_line=1, end_line=1, message='m', confidence=None)
    assert canonical_occurrence_key(without_confidence) < canonical_occurrence_key(with_confidence)


def test_canonical_key_field_order() -> None:
    occurrence = FindingOccurrence(start_line=3, end_line=4, message='m', confidence=80)
    assert canonical_occurrence_key(occurrence) == (3, 4, 'm', 1, 80)


def occurrence_at(line: int) -> FindingOccurrence:
    return FindingOccurrence(start_line=line, end_line=line, message='m', confidence=None)


def test_diff_requires_consistent_sides() -> None:
    identity = make_finding().identity
    common: dict[str, object] = {
        'identity': identity,
        'tool': 'vulture',
        'project': 'demo',
        'path': 'pkg/mod.py',
        'symbol': 'unused_fn',
        'kind': 'function',
    }
    with pytest.raises(ValidationError, match='inconsistent'):
        FindingDiff.model_validate({**common, 'diff_class': DiffClass.NEW, 'base_occurrence': occurrence_at(1)})
    with pytest.raises(ValidationError, match='inconsistent'):
        FindingDiff.model_validate({**common, 'diff_class': DiffClass.DROPPED, 'head_occurrence': occurrence_at(1)})
    with pytest.raises(ValidationError, match='inconsistent'):
        FindingDiff.model_validate(
            {
                **common,
                'diff_class': DiffClass.CHANGED,
                'base_occurrence': occurrence_at(1),
                'head_occurrence': occurrence_at(2),
            }
        )


def test_diff_reference_side_follows_class() -> None:
    identity = make_finding().identity
    common: dict[str, object] = {
        'identity': identity,
        'tool': 'vulture',
        'project': 'demo',
        'path': 'pkg/mod.py',
        'symbol': 'unused_fn',
        'kind': 'function',
    }
    new = FindingDiff.model_validate({**common, 'diff_class': DiffClass.NEW, 'head_occurrence': occurrence_at(2)})
    dropped = FindingDiff.model_validate(
        {**common, 'diff_class': DiffClass.DROPPED, 'base_occurrence': occurrence_at(1)}
    )
    changed = FindingDiff.model_validate(
        {
            **common,
            'diff_class': DiffClass.CHANGED,
            'base_occurrence': occurrence_at(1),
            'head_occurrence': occurrence_at(2),
            'changed_fields': (ChangedField.LINE_SPAN,),
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
    report = Report(manifest=make_manifest(), projects=(), totals=DiffTotals(), truncated=False)
    assert report.schema_version == SCHEMA_VERSION
    assert report.manifest.schema_version == SCHEMA_VERSION
    payload = report.model_dump_json()
    assert SCHEMA_VERSION in payload


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
