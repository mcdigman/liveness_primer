"""Versioned schema models for findings, diffs, manifests, reports, and annotations.

Copyright (C) 2026 Matthew C. Digman

Pydantic models are the source of truth (contract §7); JSON Schema files under
``liveness_primer/schemas/`` are exported from them by ``schema export``.
"""

import hashlib
import json
from collections.abc import Sequence
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

# Package-wide semver embedded in every serialized payload (contract §7).
# Minor versions are additive-only; breaking changes require a major bump.
# 1.1.0 adds nullable rule IDs, nullable source excerpts, aggregate rollups,
# and the additive `rule` changed-field value (reporting contract §3.6).
SCHEMA_VERSION = '1.1.0'


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
    RULE
        The detector rule ID changed (reporting contract §3.1).
    """

    LINE_SPAN = 'line-span'
    MESSAGE = 'message'
    CONFIDENCE = 'confidence'
    RULE = 'rule'


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


class SourceExcerpt(_FrozenModel):
    """Bounded pinned-source evidence for one occurrence (reporting contract §3.3).

    The excerpt is derived review context read from the byte-identical
    pinned corpus checkout; it never participates in finding identity, the
    canonical occurrence key, or changed-field classification.

    Attributes
    ----------
    start_line : int
        Line number of the first retained line (1-based); always the
        occurrence's reported ``start_line``.
    lines : tuple[str, ...]
        Retained consecutive source lines, starting at ``start_line``.
    omitted_lines : int
        Existing reported-span lines dropped by the evidence budget.
    """

    start_line: int = Field(ge=1)
    lines: tuple[str, ...] = Field(min_length=1)
    omitted_lines: int = Field(default=0, ge=0)


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
    rule_id : str | None
        Detector rule ID, when the detector or its documented output
        category supplies one (reporting contract §3.1).
    raw_excerpt : str | None
        Untrusted raw detector output for this occurrence; sanitized on render.
    source_excerpt : SourceExcerpt | None
        Bounded pinned-source evidence (reporting contract §3.3).
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    message: str
    confidence: int | None = Field(default=None, ge=0, le=100)
    rule_id: str | None = None
    raw_excerpt: str | None = None
    source_excerpt: SourceExcerpt | None = None

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


def canonical_occurrence_key(occurrence: FindingOccurrence) -> tuple[int, int, str, int, int, int, str]:
    """Compute the canonical occurrence key governing all diff-engine ordering (contract §8).

    The key is the complete normalized occurrence tuple in fixed field order:
    start line, end line, message, confidence, rule ID (reporting contract
    §3.1). Each presence component is 0 when its field is absent and 1 when
    present, so absent sorts before present. Derived source evidence and the
    raw excerpt never participate.

    Parameters
    ----------
    occurrence : FindingOccurrence
        The occurrence to key.

    Returns
    -------
    tuple[int, int, str, int, int, int, str]
        Sort key: (start, end, message, confidence-presence, confidence,
        rule-presence, rule ID).
    """
    return (
        occurrence.start_line,
        occurrence.end_line,
        occurrence.message,
        0 if occurrence.confidence is None else 1,
        0 if occurrence.confidence is None else occurrence.confidence,
        0 if occurrence.rule_id is None else 1,
        '' if occurrence.rule_id is None else occurrence.rule_id,
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
    rule_id : str | None
        Detector rule ID, when the detector or its documented output
        category supplies one (reporting contract §3.1).
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
    rule_id: str | None = None
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
            The occurrence (line span, message, confidence, rule ID, raw
            excerpt).
        """
        return FindingOccurrence(
            start_line=self.start_line,
            end_line=self.end_line,
            message=self.message,
            confidence=self.confidence,
            rule_id=self.rule_id,
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
        Pinned-source evidence lines stored and rendered per occurrence;
        ``0`` disables source excerpts (reporting contract §3.3).
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


class DiffRollup(_FrozenModel):
    """One complete pre-truncation rollup group (reporting contract §3.2).

    Exactly one of ``rule_id`` and ``kind`` is non-null: a finding with a
    rule ID groups by rule ID regardless of kind; otherwise it groups by
    kind. A ``changed`` pair groups by its reference-side occurrence.

    Attributes
    ----------
    diff_class : DiffClass
        ``new``, ``dropped``, or ``changed``.
    rule_id : str | None
        Rule ID of the group, when its findings carry one.
    kind : str | None
        Kind fallback of the group, when its findings carry no rule ID.
    count : int
        Number of findings in the group; positive.
    """

    diff_class: DiffClass
    rule_id: str | None
    kind: str | None
    count: int = Field(ge=1)

    @model_validator(mode='after')
    def _check_group_key(self) -> Self:
        """Require exactly one of ``rule_id`` and ``kind``.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If neither or both of ``rule_id`` and ``kind`` are set.
        """
        if (self.rule_id is None) == (self.kind is None):
            msg = 'exactly one of rule_id and kind must be non-null'
            raise ValueError(msg)
        return self


def _check_aggregates(totals: DiffTotals, rollups: Sequence[DiffRollup]) -> None:
    """Reject rollups that disagree with their totals (reporting §3.2).

    Stale aggregate data is an invalid report, so validation — not a
    convention — is the transformation boundary a rewriting hook must pass.

    Parameters
    ----------
    totals : DiffTotals
        Complete pre-truncation totals.
    rollups : Sequence[DiffRollup]
        Complete pre-truncation rollups.

    Raises
    ------
    ValueError
        If any diff class's rollup counts do not sum to its total.
    """
    counts = dict.fromkeys(DiffClass, 0)
    for rollup in rollups:
        counts[rollup.diff_class] += rollup.count
    expected = {
        DiffClass.NEW: totals.new,
        DiffClass.DROPPED: totals.dropped,
        DiffClass.CHANGED: totals.changed,
    }
    stale = [diff_class.value for diff_class, total in expected.items() if counts[diff_class] != total]
    if stale:
        msg = f'rollups are stale: {", ".join(stale)} counts disagree with totals'
        raise ValueError(msg)


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
    rollups : tuple[DiffRollup, ...]
        Complete pre-truncation rollups by diff class and rule ID with kind
        fallback, deterministically ordered (reporting contract §3.2).
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
    source_warnings : tuple[str, ...]
        Bounded warnings from pinned-source evidence collection (reporting
        contract §3.3).
    """

    project: str
    diffs: tuple[FindingDiff, ...]
    totals: DiffTotals
    rollups: tuple[DiffRollup, ...]
    truncated: bool
    base_findings: int
    head_findings: int
    measured_cost_seconds: float | None
    errors: tuple[ToolError, ...] = ()
    integrity_warnings: tuple[CorpusIntegrityWarning, ...] = ()
    source_warnings: tuple[str, ...] = ()

    @model_validator(mode='after')
    def _check_rollups(self) -> Self:
        """Reject rollups that disagree with the project totals (§3.2).

        Returns
        -------
        Self
            The validated model.
        """
        _check_aggregates(self.totals, self.rollups)
        return self


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
    rollups : tuple[DiffRollup, ...]
        Overall rollups: the sum of the complete project rollups,
        deterministically ordered (reporting contract §3.2).
    truncated : bool
        Whether any project's diffs were truncated.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    manifest: RunManifest
    projects: tuple[ProjectReport, ...]
    totals: DiffTotals
    rollups: tuple[DiffRollup, ...]
    truncated: bool

    @model_validator(mode='after')
    def _check_overall_aggregates(self) -> Self:
        """Reject overall aggregates that are not the projects' sum (§3.2).

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If the overall totals or rollups are stale.
        """
        summed = DiffTotals(
            new=sum(project.totals.new for project in self.projects),
            dropped=sum(project.totals.dropped for project in self.projects),
            changed=sum(project.totals.changed for project in self.projects),
            changed_confidence=sum(project.totals.changed_confidence for project in self.projects),
            changed_message_only=sum(project.totals.changed_message_only for project in self.projects),
        )
        if self.totals != summed:
            msg = 'overall totals are stale: they are not the sum of the project totals'
            raise ValueError(msg)
        merged: dict[tuple[DiffClass, str | None, str | None], int] = {}
        for project in self.projects:
            for rollup in project.rollups:
                key = (rollup.diff_class, rollup.rule_id, rollup.kind)
                merged[key] = merged.get(key, 0) + rollup.count
        overall = {(rollup.diff_class, rollup.rule_id, rollup.kind): rollup.count for rollup in self.rollups}
        if overall != merged:
            msg = 'overall rollups are stale: they are not the sum of the project rollups'
            raise ValueError(msg)
        return self


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
