# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Versioned schema models for findings, diffs, manifests, reports, and annotations.

Pydantic models are the source of truth; JSON Schema files under
``liveness_primer/schemas/`` are exported from them by ``schema export``.
"""

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

# Package-wide semver embedded in every serialized payload (contract §7).
# Minor versions are additive-only; breaking changes require a major bump.
# 1.1.0 adds nullable rule IDs, nullable source excerpts, aggregate rollups,
# and the additive `rule` changed-field value (reporting contract §3.6).
# 1.2.0 adds the additive serialized finding locator and the portable
# explorer review record (explorer contract §4.2, §6).
# 2.0.0 folds the rule ID and line span into the finding identity, drops the
# `line-span` and `rule` changed-field values, and adds the normalized
# severity occurrence field with its changed-field value and severity-only
# total (reporting contract §3.1, §3.6).
# 2.1.0 adds the additive per-project record of the corpus-selected opt-in
# analyses (contract §5).
SCHEMA_VERSION = '2.1.0'


def _validated_schema_version(value: str) -> str:
    """Constrain a payload's schema version to the supported one.

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
    """Classification of one finding diff.

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
    """Observable occurrence field that may differ within a ``changed`` diff.

    The line span and rule ID are part of the finding identity and can
    never differ within one ``changed`` pair: a moved span or a renamed
    rule code is a dropped finding plus a new one.

    Attributes
    ----------
    MESSAGE
        The message text changed.
    CONFIDENCE
        The confidence value changed (only for tools declaring the capability).
    SEVERITY
        The severity label changed (only for tools declaring the capability).
    """

    MESSAGE = 'message'
    CONFIDENCE = 'confidence'
    SEVERITY = 'severity'


class BindingPoint(StrEnum):
    """Hook binding point.

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
    """Annotation verdict for internal-corpus entries.

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
    """Kind of evidence backing an annotation.

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


def finding_identity(
    tool: str,
    project: str,
    path: str,
    symbol: str | None,
    kind: str,
    rule_id: str | None,
    start_line: int,
    end_line: int,
) -> str:
    """Compute the stable identity hash naming a finding across runs.

    The hash covers (tool, project, path, symbol, kind, rule ID, line span)
    and excludes message, confidence, and severity; it carries no positional
    ordinal. The rule ID and line span are identity rather than observable
    change: a renamed rule code is not semantically one finding, and for
    detectors reporting truncated symbol names the line number is the only
    thing separating two findings on one symbol.

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
    rule_id : str | None
        Detector rule ID, when one is supplied.
    start_line : int
        First line of the reported span (1-based).
    end_line : int
        Last line of the reported span (1-based, inclusive).

    Returns
    -------
    str
        Hex SHA-256 digest of the canonical identity tuple.
    """
    # Canonical JSON keeps distinct tuples distinct: delimiters occurring
    # inside attacker-controlled fields are escaped, and a null symbol or
    # rule ID is structurally different from any string.
    material = json.dumps(
        [tool, project, path, symbol, kind, rule_id, start_line, end_line],
        ensure_ascii=False,
        separators=(',', ':'),
    )
    return hashlib.sha256(material.encode('utf-8')).hexdigest()


# Severity labels compare in canonical form only: uppercased and stripped to
# ASCII letters and digits, so 'High' and 'HIGH ' never read as a change.
_SEVERITY_DISALLOWED = re.compile(r'[^A-Z0-9]')


def normalized_severity(value: str | None) -> str | None:
    """Normalize a detector severity label to its canonical form.

    Parameters
    ----------
    value : str | None
        Severity label as reported, when any.

    Returns
    -------
    str | None
        The uppercased label with every character other than ASCII letters
        and digits removed, or ``None`` when nothing remains.
    """
    if value is None:
        return None
    canonical = _SEVERITY_DISALLOWED.sub('', value.upper())
    return canonical or None


# Every severity field normalizes on validation, wherever the payload
# entered (adapter parse, JSON load, or the hook bridge).
SeverityLabel = Annotated[str | None, AfterValidator(normalized_severity)]


class SourceExcerpt(_FrozenModel):
    """Bounded pinned-source evidence for one occurrence.

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
    """One occurrence of a finding identity in a report.

    A report holds a multiset of occurrences per identity; the canonical
    occurrence key orders them deterministically.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver.
    start_line : int
        First line of the reported span (1-based).
    end_line : int
        Last line of the reported span (1-based, inclusive).
    message : str
        Normalized message text.
    confidence : int | None
        Confidence percentage, for tools declaring the capability.
    severity : SeverityLabel
        Canonical severity label (e.g. ``HIGH``), for tools declaring the
        capability; normalized on validation.
    rule_id : str | None
        Detector rule ID, when the detector or its documented output
        category supplies one.
    raw_excerpt : str | None
        Untrusted raw detector output for this occurrence; sanitized on render.
    source_excerpt : SourceExcerpt | None
        Bounded pinned-source evidence.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    message: str
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: SeverityLabel = None
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


def canonical_occurrence_key(occurrence: FindingOccurrence) -> tuple[int, int, str, int, int, int, str, int, str]:
    """Compute the canonical occurrence key governing all diff-engine ordering.

    The key is the complete normalized occurrence tuple in fixed field order:
    start line, end line, message, confidence, rule ID, severity. Each
    presence component is 0 when its field is absent and 1 when present, so
    absent sorts before present. Derived source evidence and the raw excerpt
    never participate.

    Parameters
    ----------
    occurrence : FindingOccurrence
        The occurrence to key.

    Returns
    -------
    tuple[int, int, str, int, int, int, str, int, str]
        Sort key: (start, end, message, confidence-presence, confidence,
        rule-presence, rule ID, severity-presence, severity).
    """
    return (
        occurrence.start_line,
        occurrence.end_line,
        occurrence.message,
        0 if occurrence.confidence is None else 1,
        0 if occurrence.confidence is None else occurrence.confidence,
        0 if occurrence.rule_id is None else 1,
        '' if occurrence.rule_id is None else occurrence.rule_id,
        0 if occurrence.severity is None else 1,
        '' if occurrence.severity is None else occurrence.severity,
    )


class Finding(_FrozenModel):
    """One normalized detector report item.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver.
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
    severity : SeverityLabel
        Canonical severity label (e.g. ``HIGH``), for tools declaring the
        capability; normalized on validation.
    rule_id : str | None
        Detector rule ID, when the detector or its documented output
        category supplies one.
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
    severity: SeverityLabel = None
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
        """Stable identity hash of this finding.

        Returns
        -------
        str
            Hex SHA-256 digest over (tool, project, path, symbol, kind,
            rule ID, line span).
        """
        return finding_identity(
            self.tool,
            self.project,
            self.path,
            self.symbol,
            self.kind,
            self.rule_id,
            self.start_line,
            self.end_line,
        )

    def occurrence(self) -> FindingOccurrence:
        """Project this finding onto its occurrence fields.

        Returns
        -------
        FindingOccurrence
            The occurrence (line span, message, confidence, severity, rule
            ID, raw excerpt).
        """
        return FindingOccurrence(
            start_line=self.start_line,
            end_line=self.end_line,
            message=self.message,
            confidence=self.confidence,
            severity=self.severity,
            rule_id=self.rule_id,
            raw_excerpt=self.raw_excerpt,
        )


class FindingLocator(_FrozenModel):
    """Persistent reference to one serialized finding diff (explorer contract §4.2).

    ``line`` is the diff class's reference-side start line — head for
    ``new``, base for ``dropped`` and ``changed``. The identity hash covers
    the start line, so every diff sharing ``identity`` shares ``line``; the
    field stays serialized as denormalized display data. ``occurrence`` is
    the diff's zero-based position within the subsequence of the same
    serialized ``ProjectReport.diffs`` tuple whose identity and
    reference-side start line equal ``(identity, line)``, in serialized
    order.

    Attributes
    ----------
    project : str
        Corpus project name.
    identity : str
        Stable finding identity hash.
    line : int
        Reference-side start line (1-based).
    occurrence : int
        Zero-based index among diffs sharing ``(identity, line)``.
    """

    project: str
    identity: str
    line: int = Field(ge=1)
    occurrence: int = Field(ge=0)


class FindingDiff(_FrozenModel):
    """One classified difference between the base and head reports.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver.
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
    locator : FindingLocator | None
        Unique serialized locator, assigned during canonical report
        assembly — after the canonical sort and any diff-transforming
        hook, before truncation and serialization (explorer contract §4.2).
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
    locator: FindingLocator | None = None

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

    @model_validator(mode='after')
    def _check_identity(self) -> Self:
        """Reject occurrences whose recomputed hash contradicts ``identity``.

        The identity hash covers the rule ID and line span, so this also
        enforces that both sides of a ``changed`` pair agree on them.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If either populated side hashes to a different identity.
        """
        for occurrence in (self.base_occurrence, self.head_occurrence):
            if occurrence is None:
                continue
            recomputed = finding_identity(
                self.tool,
                self.project,
                self.path,
                self.symbol,
                self.kind,
                occurrence.rule_id,
                occurrence.start_line,
                occurrence.end_line,
            )
            if recomputed != self.identity:
                msg = f'occurrence contradicts the declared identity {self.identity!r}'
                raise ValueError(msg)
        return self

    @property
    def reference_occurrence(self) -> FindingOccurrence:
        """Occurrence on the diff class's reference side.

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
    """Record of one network fetch performed during the fetch step.

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
    """Record of one resolved detector environment.

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
    """One surviving non-detector dependency difference between environments.

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
    """Resolved pin for one corpus project in one run.

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
    """Effective settings of one run, recorded for reproducibility.

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
        ``0`` disables source excerpts.
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
    """Record of resolved refs, versions, environments, and settings for one run.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver.
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
        False only for unmanaged escape-hatch runs.
    environment_delta : tuple[DependencyDelta, ...]
        Non-detector dependency differences surviving paired resolution.
    isolation_enforced : bool
        Whether build/analysis sandboxing was enforced.
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
    """Failure of one detector invocation on one project side.

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
    """Corpus-integrity warning for an expected-clean pair.

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
    """Diff totals before truncation.

    Attributes
    ----------
    new : int
        Count of ``new`` diffs.
    dropped : int
        Count of ``dropped`` diffs.
    changed : int
        Count of ``changed`` diffs.
    changed_confidence_only : int
        ``changed`` diffs whose only changed field is the confidence.
    changed_message_only : int
        ``changed`` diffs whose only changed field is the message.
    changed_severity_only : int
        ``changed`` diffs whose only changed field is the severity.
    """

    new: int = Field(default=0, ge=0)
    dropped: int = Field(default=0, ge=0)
    changed: int = Field(default=0, ge=0)
    changed_confidence_only: int = Field(default=0, ge=0)
    changed_message_only: int = Field(default=0, ge=0)
    changed_severity_only: int = Field(default=0, ge=0)

    @model_validator(mode='after')
    def _check_exclusive_breakouts(self) -> Self:
        """Reject breakouts that cannot be a partition of ``changed``.

        The three breakouts are mutually exclusive subsets of the
        ``changed`` diffs, so the multi-field remainder renderers derive
        from them is non-negative exactly when this holds (contract §8).

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If the exclusive breakouts exceed the ``changed`` count.
        """
        exclusive = self.changed_confidence_only + self.changed_message_only + self.changed_severity_only
        if exclusive > self.changed:
            msg = f'exclusive changed breakouts sum to {exclusive}, above the changed count {self.changed}'
            raise ValueError(msg)
        return self


class DiffRollup(_FrozenModel):
    """One complete pre-truncation rollup group.

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
    """Reject rollups that disagree with their totals.

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
    """Per-project slice of the blast radius.

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
        fallback, deterministically ordered.
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
        Bounded warnings from pinned-source evidence collection.
    analyses : tuple[str, ...]
        Corpus-selected opt-in analyses for this (project, tool) pair.
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
    analyses: tuple[str, ...] = ()

    @model_validator(mode='after')
    def _check_rollups(self) -> Self:
        """Reject rollups that disagree with the project totals.

        Returns
        -------
        Self
            The validated model.
        """
        _check_aggregates(self.totals, self.rollups)
        return self


class Report(_FrozenModel):
    """The blast radius: all finding diffs plus summary totals.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver.
    manifest : RunManifest
        Run manifest for reproducibility.
    projects : tuple[ProjectReport, ...]
        Per-project reports, in run order.
    totals : DiffTotals
        Overall totals before truncation.
    rollups : tuple[DiffRollup, ...]
        Overall rollups: the sum of the complete project rollups,
        deterministically ordered.
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
        """Reject overall aggregates that are not the projects' sum.

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
            changed_confidence_only=sum(project.totals.changed_confidence_only for project in self.projects),
            changed_message_only=sum(project.totals.changed_message_only for project in self.projects),
            changed_severity_only=sum(project.totals.changed_severity_only for project in self.projects),
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


class ExplorerReview(_FrozenModel):
    """Portable review record exported by the report explorer (explorer contract §6).

    ``report_sha256`` is the SHA-256 digest of the exact report bytes; a
    byte-different report never inherits workspace state. Report order of
    the tuples is a producer obligation the model cannot check without the
    report.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver.
    report_sha256 : str
        Lowercase hex SHA-256 digest of the exact report bytes.
    selected : tuple[FindingLocator, ...]
        Locators selected for export; unique.
    hidden : tuple[FindingLocator, ...]
        Locators hidden from the default findings view; unique.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    report_sha256: str = Field(pattern='^[0-9a-f]{64}$')
    selected: tuple[FindingLocator, ...]
    hidden: tuple[FindingLocator, ...]

    @model_validator(mode='after')
    def _check_unique_locators(self) -> Self:
        """Reject duplicate locators within either tuple.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If ``selected`` or ``hidden`` repeats a locator.
        """
        for name, entries in (('selected', self.selected), ('hidden', self.hidden)):
            if len(set(entries)) != len(entries):
                msg = f'{name} contains duplicate locators'
                raise ValueError(msg)
        return self


class FindingComment(_FrozenModel):
    """One reviewer comment attached to a serialized finding (explorer contract §6).

    Attributes
    ----------
    locator : FindingLocator
        Locator of the commented finding.
    comment : str
        Reviewer text, at most 200 characters; opaque to this package. The
        bound keeps a comment a margin note rather than a thread, and
        raising it later would make new exports unreadable to explorers
        pinned to this schema version.
    """

    locator: FindingLocator
    comment: str = Field(max_length=200)


EXPLORER_EXPORT_KIND = 'explorer-export'


def _validated_document_kind(value: str) -> str:
    """Constrain an export's discriminator to the one kind it may declare.

    Parameters
    ----------
    value : str
        Declared document kind of the payload.

    Returns
    -------
    str
        The validated kind.

    Raises
    ------
    ValueError
        If the kind is not :data:`EXPLORER_EXPORT_KIND`.
    """
    if value != EXPLORER_EXPORT_KIND:
        msg = f'document_kind {value!r} is not the supported {EXPLORER_EXPORT_KIND!r}'
        raise ValueError(msg)
    return value


# Pinned the same way as SchemaVersion rather than through Literal: the
# annotation fixes how the constant renders as JSON Schema (`type` from
# `str`, `const` from the extra), so the exported document does not shift
# under the range of pydantic versions the package supports.
DocumentKind = Annotated[
    str,
    AfterValidator(_validated_document_kind),
    Field(json_schema_extra={'const': EXPLORER_EXPORT_KIND}),
]


class ExplorerExport(Report):
    """Report re-emitted by the explorer over a chosen subset (explorer contract §6).

    Every field of :class:`Report` keeps its meaning: ``totals`` and
    ``rollups`` stay the complete pre-truncation aggregates of the original
    run while ``diffs`` carries only the exported subset, which is exactly
    the truncation the format already models. ``source_report_sha256``
    names the original run's report bytes and is carried through unchanged
    by a re-export, so an export chain of any length points at one origin;
    locators identify findings across every generation, which makes the
    intermediate history irrelevant.

    Attributes
    ----------
    document_kind : DocumentKind
        Discriminator separating an export from a first-generation report.
    source_report_sha256 : str
        Lowercase hex SHA-256 digest of the original report's exact bytes.
    comments : tuple[FindingComment, ...]
        Reviewer comments by locator; unique, and empty until the explorer
        learns to write them.
    """

    document_kind: DocumentKind = EXPLORER_EXPORT_KIND
    source_report_sha256: str = Field(pattern='^[0-9a-f]{64}$')
    comments: tuple[FindingComment, ...] = ()

    @model_validator(mode='after')
    def _check_unique_comment_locators(self) -> Self:
        """Reject repeated comment locators.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If two comments name the same locator.
        """
        locators = [comment.locator for comment in self.comments]
        if len(set(locators)) != len(locators):
            msg = 'comments contains duplicate locators'
            raise ValueError(msg)
        return self


class HookEnvelope(_FrozenModel):
    """Versioned JSON envelope spoken by the subprocess hook bridge.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver.
    binding_point : BindingPoint
        Hook binding point the payload targets.
    report : Report
        The report payload under transformation.
    """

    schema_version: SchemaVersion = SCHEMA_VERSION
    binding_point: BindingPoint
    report: Report


class AnnotationTarget(_FrozenModel):
    """Target of an internal-corpus annotation.

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
    """Provenance of an internal-corpus annotation.

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
    """One internal-corpus annotation with sidecar evidence.

    Attributes
    ----------
    schema_version : SchemaVersion
        Package-wide schema semver.
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
        """Enforce that coverage evidence never supports a ``dead`` verdict.

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
