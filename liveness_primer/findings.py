"""Versioned schema models for findings, diffs, manifests, reports, and annotations.

Copyright (C) 2026 Matthew C. Digman

Pydantic models are the source of truth (contract §7); JSON Schema files under
``liveness_primer/schemas/`` are exported from them by ``schema export``.
"""

import hashlib
import json
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

# Package-wide semver embedded in every serialized payload (contract §7).
# Minor versions are additive-only; breaking changes require a major bump.
SCHEMA_VERSION = '1.0.0'


def _validated_schema_version(value: str) -> str:
    """Constrain a payload's schema version to the supported one (contract §7).

    Parameters
    ----------
    value : str
        Declared schema version of the payload.

    Returns
    -------
    str
        The validated version.

    Raises
    ------
    ValueError
        If the version is not the package-wide :data:`SCHEMA_VERSION`.
    """
    if value != SCHEMA_VERSION:
        msg = f'schema_version {value!r} is not the supported {SCHEMA_VERSION!r}'
        raise ValueError(msg)
    return value


# Every independently exported payload carries this constrained field.
SchemaVersion = Annotated[
    str,
    AfterValidator(_validated_schema_version),
    Field(json_schema_extra={'const': SCHEMA_VERSION}),
]


class DiffClass(StrEnum):
    """Classification of one finding diff (contract §8).

    Attributes
    ----------
    NEW
        Present on the head side only.
    DROPPED
        Present on the base side only.
    CHANGED
        Present on both sides with at least one observable field changed.
    """

    NEW = 'new'
    DROPPED = 'dropped'
    CHANGED = 'changed'


class ChangedField(StrEnum):
    """Observable occurrence field that may differ within a ``changed`` diff (contract §8).

    Attributes
    ----------
    LINE_SPAN
        The start/end line span moved.
    MESSAGE
        The message text changed.
    CONFIDENCE
        The confidence value changed (only for tools declaring the capability).
    """

    LINE_SPAN = 'line-span'
    MESSAGE = 'message'
    CONFIDENCE = 'confidence'


class BindingPoint(StrEnum):
    """Hook binding point (contract §10).

    Attributes
    ----------
    PRE_TRIAGE
        Normalization and security veto; fails closed.
    TRIAGE
        Ranking; fails open unless a triage safety error forces fail-closed.
    POST_TRIAGE
        Filtering and final normalization; fails open by default.
    """

    PRE_TRIAGE = 'pre-triage'
    TRIAGE = 'triage'
    POST_TRIAGE = 'post-triage'


class Verdict(StrEnum):
    """Annotation verdict for internal-corpus entries (contract §13).

    Attributes
    ----------
    LIVE
        The target is demonstrably reachable.
    DEAD
        The target is demonstrably unreachable.
    NO_COVERAGE
        An expected-meaningful coverage run reported no coverage of the target.
    UNKNOWN
        Coverage has not been run, is not runnable, or cannot be meaningful.
    """

    LIVE = 'live'
    DEAD = 'dead'
    NO_COVERAGE = 'no-coverage'
    UNKNOWN = 'unknown'


class EvidenceKind(StrEnum):
    """Kind of evidence backing an annotation (contract §13).

    Attributes
    ----------
    COVERAGE
        Produced by a coverage run; can only support ``live`` or ``no-coverage``.
    MANUAL
        Human judgment.
    LLM_ASSISTED
        LLM-assisted judgment.
    RUNNER
        Demonstrated by an executable runner file.
    """

    COVERAGE = 'coverage'
    MANUAL = 'manual'
    LLM_ASSISTED = 'llm-assisted'
    RUNNER = 'runner'


class _FrozenModel(BaseModel):
    """Base for all schema models: frozen, extra-forbidding, hence hashable."""

    model_config = ConfigDict(frozen=True, extra='forbid')


def finding_identity(tool: str, project: str, path: str, symbol: str | None, kind: str) -> str:
    """Compute the stable identity hash naming a finding across runs (contract §7).

    The hash covers (tool, project, path, symbol, kind) and excludes line and
    confidence; it carries no positional ordinal.

    Parameters
    ----------
    tool : str
        Adapter name of the reporting detector.
    project : str
        Corpus project name.
    path : str
        Repo-relative POSIX path.
    symbol : str | None
        Symbol name, when the detector reports one.
    kind : str
        Normalized finding kind.

    Returns
    -------
    str
        Hex SHA-256 digest of the canonical identity tuple.
    """
    # Canonical JSON keeps distinct tuples distinct: delimiters occurring
    # inside attacker-controlled fields are escaped, and a null symbol is
    # structurally different from any string.
    material = json.dumps([tool, project, path, symbol, kind], ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


class FindingOccurrence(_FrozenModel):
    """One occurrence of a finding identity in a report (contract §7).

    A report holds a multiset of occurrences per identity; the canonical
    occurrence key (contract §8) orders them deterministically.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver (contract §7).
    start_line : int
        First line of the reported span (1-based).
    end_line : int
        Last line of the reported span (1-based, inclusive).
    message : str
        Normalized message text.
    confidence : int | None
        Confidence percentage, for tools declaring the capability.
    raw_excerpt : str | None
        Untrusted raw detector output for this occurrence; sanitized on render.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    message: str
    confidence: int | None = Field(default=None, ge=0, le=100)
    raw_excerpt: str | None = None

    @model_validator(mode='after')
    def _check_span(self) -> Self:
        """Reject spans whose end precedes their start.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If ``end_line`` is smaller than ``start_line``.
        """
        if self.end_line < self.start_line:
            msg = f'end_line {self.end_line} precedes start_line {self.start_line}'
            raise ValueError(msg)
        return self


def canonical_occurrence_key(occurrence: FindingOccurrence) -> tuple[int, int, str, int, int]:
    """Compute the canonical occurrence key governing all diff-engine ordering (contract §8).

    The key is the complete normalized occurrence tuple in fixed field order:
    start line, end line, message, confidence (absent sorts first).

    Parameters
    ----------
    occurrence : FindingOccurrence
        The occurrence to key.

    Returns
    -------
    tuple[int, int, str, int, int]
        Sort key: (start, end, message, confidence-presence, confidence).
    """
    return (
        occurrence.start_line,
        occurrence.end_line,
        occurrence.message,
        0 if occurrence.confidence is None else 1,
        0 if occurrence.confidence is None else occurrence.confidence,
    )


class Finding(_FrozenModel):
    """One normalized detector report item (contract §7).

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver (contract §7).
    tool : str
        Adapter name of the reporting detector.
    project : str
        Corpus project name.
    path : str
        Repo-relative POSIX path of the reported file.
    symbol : str | None
        Reported symbol, when the detector names one.
    kind : str
        Normalized finding kind (e.g. ``function``, ``import``).
    message : str
        Normalized message text.
    start_line : int
        First line of the reported span (1-based).
    end_line : int
        Last line of the reported span (1-based, inclusive).
    confidence : int | None
        Confidence percentage, for tools declaring the capability.
    raw_excerpt : str | None
        Untrusted raw detector output for this finding; sanitized on render.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    tool: str
    project: str
    path: str
    symbol: str | None
    kind: str
    message: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    confidence: int | None = Field(default=None, ge=0, le=100)
    raw_excerpt: str | None = None

    @model_validator(mode='after')
    def _check_span(self) -> Self:
        """Reject spans whose end precedes their start.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If ``end_line`` is smaller than ``start_line``.
        """
        if self.end_line < self.start_line:
            msg = f'end_line {self.end_line} precedes start_line {self.start_line}'
            raise ValueError(msg)
        return self

    @property
    def identity(self) -> str:
        """Stable identity hash of this finding (contract §7).

        Returns
        -------
        str
            Hex SHA-256 digest over (tool, project, path, symbol, kind).
        """
        return finding_identity(self.tool, self.project, self.path, self.symbol, self.kind)

    def occurrence(self) -> FindingOccurrence:
        """Project this finding onto its occurrence fields.

        Returns
        -------
        FindingOccurrence
            The occurrence (line span, message, confidence, raw excerpt).
        """
        return FindingOccurrence(
            start_line=self.start_line,
            end_line=self.end_line,
            message=self.message,
            confidence=self.confidence,
            raw_excerpt=self.raw_excerpt,
        )


class FindingDiff(_FrozenModel):
    """One classified difference between the base and head reports (contract §8).

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver (contract §7).
    diff_class : DiffClass
        ``new``, ``dropped``, or ``changed``.
    identity : str
        Stable identity hash shared by the paired occurrences.
    tool : str
        Adapter name of the reporting detector.
    project : str
        Corpus project name.
    path : str
        Repo-relative POSIX path of the reported file.
    symbol : str | None
        Reported symbol, when the detector names one.
    kind : str
        Normalized finding kind.
    base_occurrence : FindingOccurrence | None
        Base-side occurrence; absent for ``new``.
    head_occurrence : FindingOccurrence | None
        Head-side occurrence; absent for ``dropped``.
    changed_fields : tuple[ChangedField, ...]
        Fields differing within a ``changed`` pair; empty otherwise.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    diff_class: DiffClass
    identity: str
    tool: str
    project: str
    path: str
    symbol: str | None
    kind: str
    base_occurrence: FindingOccurrence | None = None
    head_occurrence: FindingOccurrence | None = None
    changed_fields: tuple[ChangedField, ...] = ()

    @model_validator(mode='after')
    def _check_sides(self) -> Self:
        """Enforce side presence and ``changed_fields`` consistency per diff class.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If the populated sides or ``changed_fields`` contradict the class.
        """
        by_class = {
            DiffClass.NEW: (self.base_occurrence is None, self.head_occurrence is not None, not self.changed_fields),
            DiffClass.DROPPED: (
                self.base_occurrence is not None,
                self.head_occurrence is None,
                not self.changed_fields,
            ),
            DiffClass.CHANGED: (
                self.base_occurrence is not None,
                self.head_occurrence is not None,
                bool(self.changed_fields),
            ),
        }
        if not all(by_class[self.diff_class]):
            msg = f'inconsistent sides or changed_fields for diff class {self.diff_class.value!r}'
            raise ValueError(msg)
        return self

    @property
    def reference_occurrence(self) -> FindingOccurrence:
        """Occurrence on the diff class's reference side (contract §12).

        The reference side is head for ``new``, base for ``dropped`` and
        ``changed``.

        Returns
        -------
        FindingOccurrence
            The reference-side occurrence.

        Raises
        ------
        ValueError
            If the reference side is absent (impossible after validation).
        """
        occurrence = self.head_occurrence if self.diff_class is DiffClass.NEW else self.base_occurrence
        if occurrence is None:
            msg = 'reference side is absent'
            raise ValueError(msg)
        return occurrence


class FetchRecord(_FrozenModel):
    """Record of one network fetch performed during the fetch step (contract §3).

    Attributes
    ----------
    kind : str
        Fetch kind: ``git`` or ``wheel``.
    name : str
        Repository URL for ``git`` fetches; distribution filename for ``wheel``.
    resolved : str
        Resolved commit SHA (``git``) or version (``wheel``).
    digest : str | None
        Hex SHA-256 of the fetched artifact, when applicable.
    """

    kind: str
    name: str
    resolved: str
    digest: str | None = None


class EnvironmentRecord(_FrozenModel):
    """Record of one resolved detector environment (contract §3).

    Attributes
    ----------
    ref : str
        Detector ref as requested on the CLI.
    sha : str
        Resolved commit SHA.
    fingerprint : str
        Full cache fingerprint key of the environment.
    freeze : tuple[str, ...]
        Resolved dependency freeze (``name==version`` lines).
    from_cache : bool
        Whether the environment was reused directly from cache.
    rebuilt : bool
        Whether the environment was rebuilt in this run.
    """

    ref: str
    sha: str
    fingerprint: str
    freeze: tuple[str, ...]
    from_cache: bool
    rebuilt: bool


class DependencyDelta(_FrozenModel):
    """One surviving non-detector dependency difference between environments (contract §3).

    Attributes
    ----------
    package : str
        Canonical distribution name.
    base_version : str | None
        Version in the base environment; absent if not installed there.
    head_version : str | None
        Version in the head environment; absent if not installed there.
    """

    package: str
    base_version: str | None
    head_version: str | None


class CorpusPinRecord(_FrozenModel):
    """Resolved pin for one corpus project in one run (contract §3).

    Attributes
    ----------
    name : str
        Corpus project name.
    repo : str
        Repository URL.
    requested : str
        The pin SHA or ``branch:<name>`` selector from the corpus file.
    resolved_sha : str
        Commit SHA both revisions analyzed.
    """

    name: str
    repo: str
    requested: str
    resolved_sha: str


class RunSettings(_FrozenModel):
    """Effective settings of one run, recorded for reproducibility (contract §3).

    Attributes
    ----------
    jobs : int
        Maximum concurrent per-project subprocesses.
    timeout : float
        Default per-(project, tool) timeout in seconds.
    max_results : int
        Cap on rendered finding diffs.
    excerpt_lines : int
        Cap on rendered excerpt lines.
    fail_on : tuple[str, ...]
        Enabled ``--fail-on`` gates.
    selection : tuple[str, ...]
        Selected corpus project names, in run order.
    """

    jobs: int
    timeout: float
    max_results: int
    excerpt_lines: int
    fail_on: tuple[str, ...]
    selection: tuple[str, ...]


class RunManifest(_FrozenModel):
    """Record of resolved refs, versions, environments, and settings for one run (contract §2).

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver (contract §7).
    created_at : datetime
        UTC timestamp of manifest assembly.
    tool : str
        Adapter name of the detector under test.
    detector_repo : str | None
        Detector repository URL; absent for escape-hatch runs.
    base : EnvironmentRecord | None
        Base-side environment; absent for escape-hatch runs.
    head : EnvironmentRecord | None
        Head-side environment; absent for escape-hatch runs.
    base_cmd : tuple[str, ...] | None
        Escape-hatch base command (``--old-cmd``), if used.
    head_cmd : tuple[str, ...] | None
        Escape-hatch head command (``--new-cmd``), if used.
    comparable : bool
        False only for unmanaged escape-hatch runs (contract §3).
    environment_delta : tuple[DependencyDelta, ...]
        Non-detector dependency differences surviving paired resolution.
    isolation_enforced : bool
        Whether build/analysis sandboxing was enforced (contract §11).
    platform : str
        Platform tag of the run host.
    python_version : str
        Python version running the detectors.
    installer : str | None
        Installer name and version used to build environments.
    fetches : tuple[FetchRecord, ...]
        Every fetch performed during the fetch step.
    corpus_pins : tuple[CorpusPinRecord, ...]
        Resolved corpus pins for the run.
    settings : RunSettings
        Effective run settings.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    created_at: datetime
    tool: str
    detector_repo: str | None
    base: EnvironmentRecord | None
    head: EnvironmentRecord | None
    base_cmd: tuple[str, ...] | None
    head_cmd: tuple[str, ...] | None
    comparable: bool
    environment_delta: tuple[DependencyDelta, ...]
    isolation_enforced: bool
    platform: str
    python_version: str
    installer: str | None
    fetches: tuple[FetchRecord, ...]
    corpus_pins: tuple[CorpusPinRecord, ...]
    settings: RunSettings


class ToolError(_FrozenModel):
    """Failure of one detector invocation on one project side (contract §9).

    Attributes
    ----------
    side : str
        ``base`` or ``head``.
    exit_code : int | None
        Subprocess exit code; absent when the invocation timed out.
    detail : str
        Sanitized description of the failure.
    """

    side: str
    exit_code: int | None
    detail: str


class CorpusIntegrityWarning(_FrozenModel):
    """Corpus-integrity warning for an expected-clean pair (contract §5).

    Attributes
    ----------
    project : str
        Corpus project name.
    tool : str
        Adapter name.
    detail : str
        What the base side reported (findings or nonzero exit).
    """

    project: str
    tool: str
    detail: str


class DiffTotals(_FrozenModel):
    """Diff totals before truncation (contract §8).

    Attributes
    ----------
    new : int
        Count of ``new`` diffs.
    dropped : int
        Count of ``dropped`` diffs.
    changed : int
        Count of ``changed`` diffs.
    changed_confidence : int
        ``changed`` diffs whose ``changed_fields`` include confidence.
    changed_message_only : int
        ``changed`` diffs whose only changed field is the message.
    """

    new: int = 0
    dropped: int = 0
    changed: int = 0
    changed_confidence: int = 0
    changed_message_only: int = 0


class ProjectReport(_FrozenModel):
    """Per-project slice of the blast radius (contract §8, §9).

    Attributes
    ----------
    project : str
        Corpus project name.
    diffs : tuple[FindingDiff, ...]
        Classified diffs, canonically ordered, possibly truncated.
    totals : DiffTotals
        Totals before truncation.
    truncated : bool
        Whether ``diffs`` was truncated by the results cap.
    base_findings : int
        Total base-side findings parsed.
    head_findings : int
        Total head-side findings parsed.
    measured_cost_seconds : float | None
        Measured wall-clock analysis cost, when both sides completed.
    errors : tuple[ToolError, ...]
        Detector invocation failures for this project.
    integrity_warnings : tuple[CorpusIntegrityWarning, ...]
        Expected-clean violations observed on the base side.
    """

    project: str
    diffs: tuple[FindingDiff, ...]
    totals: DiffTotals
    truncated: bool
    base_findings: int
    head_findings: int
    measured_cost_seconds: float | None
    errors: tuple[ToolError, ...] = ()
    integrity_warnings: tuple[CorpusIntegrityWarning, ...] = ()


class Report(_FrozenModel):
    """The blast radius: all finding diffs plus summary totals (contract §2, §9).

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver (contract §7).
    manifest : RunManifest
        Run manifest for reproducibility.
    projects : tuple[ProjectReport, ...]
        Per-project reports, in run order.
    totals : DiffTotals
        Overall totals before truncation.
    truncated : bool
        Whether any project's diffs were truncated.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    manifest: RunManifest
    projects: tuple[ProjectReport, ...]
    totals: DiffTotals
    truncated: bool


class HookEnvelope(_FrozenModel):
    """Versioned JSON envelope spoken by the subprocess hook bridge (contract §10).

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver (contract §7).
    binding_point : BindingPoint
        Hook binding point the payload targets.
    report : Report
        The report payload under transformation.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    binding_point: BindingPoint
    report: Report


class AnnotationTarget(_FrozenModel):
    """Target of an internal-corpus annotation (contract §13).

    Attributes
    ----------
    path : str
        Repo-relative POSIX path.
    symbol : str | None
        Symbol name, when the annotation names one.
    line : int | None
        Line number, when the annotation is line-scoped.
    """

    path: str
    symbol: str | None = None
    line: int | None = Field(default=None, ge=1)


class AnnotationProvenance(_FrozenModel):
    """Provenance of an internal-corpus annotation (contract §13).

    Attributes
    ----------
    source_project : str
        Approved corpus project the entry was extracted from.
    commit : str
        Commit SHA of the source at extraction.
    extraction_date : date
        Date the entry was extracted.
    """

    source_project: str
    commit: str
    extraction_date: date


class Annotation(_FrozenModel):
    """One internal-corpus annotation with sidecar evidence (contract §13).

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver (contract §7).
    target : AnnotationTarget
        Annotated path/symbol/line.
    verdict : Verdict
        ``live``, ``dead``, ``no-coverage``, or ``unknown``.
    evidence : EvidenceKind
        Kind of evidence backing the verdict.
    provenance : AnnotationProvenance
        Source project, commit, and extraction date.
    runner : str | None
        Repo-relative path of a runner file demonstrating the evidence.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    target: AnnotationTarget
    verdict: Verdict
    evidence: EvidenceKind
    provenance: AnnotationProvenance
    runner: str | None = None

    @model_validator(mode='after')
    def _check_coverage_rule(self) -> Self:
        """Enforce that coverage evidence never supports a ``dead`` verdict (contract §13).

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If coverage evidence is paired with a verdict other than
            ``live`` or ``no-coverage``.
        """
        if self.evidence is EvidenceKind.COVERAGE and self.verdict not in {Verdict.LIVE, Verdict.NO_COVERAGE}:
            msg = f'coverage evidence cannot support verdict {self.verdict.value!r}'
            raise ValueError(msg)
        return self
