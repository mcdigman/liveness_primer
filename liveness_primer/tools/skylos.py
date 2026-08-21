# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Adapter for the ``skylos`` dead-code detector (contract §4).

Skylos emits a JSON document on stdout under ``--json``. The dead-code
arrays are always ingested; the diagnostic arrays (``danger``, ``secrets``,
``quality``, ``ai_defects``) are ingested when present — each appears only
when a corpus config opts into the matching analysis (contract §4, §5).
"""

import json
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from liveness_primer.findings import Finding
from liveness_primer.tools.base import (
    AdapterCapabilities,
    AdapterError,
    BuildRecipe,
    RawToolOutput,
    normalize_finding_path,
)

# Dead-code finding arrays in the skylos JSON document; the complete
# always-ingested bucket list, public so the fake detector emits the same
# document shape as a real skylos run.
DEAD_CODE_KEYS = (
    'unused_functions',
    'unused_imports',
    'unused_classes',
    'unused_variables',
    'unused_parameters',
    'unused_files',
)

# Diagnostic arrays, each emitted only under its opt-in analysis flag,
# mapped to the normalized kind stamped onto its findings. Entries carry a
# severity label and rule ID instead of a confidence value.
DIAGNOSTIC_KINDS = MappingProxyType(
    {'danger': 'danger', 'secrets': 'secret', 'quality': 'quality', 'ai_defects': 'ai_defect'}
)

# Analysis name (as selected in a corpus file) to the diagnostic array it
# opts into; parse ingests only selected arrays, so a target repository's
# own skylos configuration cannot widen the run beyond its provenance.
_ANALYSIS_BUCKETS = {'danger': 'danger', 'secrets': 'secrets', 'quality': 'quality', 'ai-defects': 'ai_defects'}

# Buckets whose entries name their subject in ``name``; elsewhere ``name``
# is a rule marker (e.g. danger's SKY-D260 carries name=prompt_injection),
# never a source symbol.
_NAME_SUBJECT_BUCKETS = frozenset({'quality'})

# Neutral config shipped with the package. Skylos revisions honoring
# SKYLOS_CONFIG_FILE read it instead of discovering the analyzed
# repository's own pyproject.toml, so a target's [tool.skylos] policy
# cannot enable (and spend runtime on) analyses the run never selected;
# explicitly selected analyses still win as CLI flags. Older revisions
# ignore the variable, where the parse-side gate still protects the report.
_NEUTRAL_CONFIG = Path(__file__).with_name('skylos_neutral_config.toml')

# Wall-clock budget, in seconds, for skylos's grep-verify post-pass. The
# pass truncates when the budget runs out, so pinning one value keeps both
# sides working from the same allowance rather than the ambient default;
# it does not make a loaded machine's truncation point identical across
# sides. Chosen well under the 300s default per-(project, tool) timeout so
# the pass cannot on its own starve the rest of the run.
_GREP_BUDGET_SECONDS = '150'

# Documented, versioned mapping from each ingested single-rule skylos
# symbol bucket to its canonical rule ID (reporting contract §3.1). A rule
# ID explicitly present on the detector finding takes precedence; a rule ID
# is never inferred from free-form message text. The multi-rule
# ``unused_files`` bucket is deliberately absent: it has no canonical
# bucket-level code, so its entries must carry their explicit rule IDs
# (see ``_SkylosUnusedFileEntry``). If a supported skylos revision changes
# the documented mapping, this table must be updated rather than silently
# retaining a stale code.
BUCKET_RULE_IDS = {
    'unused_functions': 'SKY-U001',
    'unused_imports': 'SKY-U002',
    'unused_variables': 'SKY-U003',
    'unused_classes': 'SKY-U004',
    'unused_parameters': 'SKY-U006',
}


class _SkylosEntry(BaseModel):
    """One dead-code entry from a skylos JSON array (untrusted input)."""

    model_config = ConfigDict(frozen=True, extra='ignore')

    name: str
    full_name: str | None = None
    type: str
    file: str
    line: int
    confidence: int | None = Field(default=None, ge=0, le=100)
    rule_id: str | None = None


class _SkylosDiagnosticEntry(BaseModel):
    """One diagnostic from a skylos opt-in analysis array (untrusted input).

    Undeclared entry fields (e.g. the secret ``preview``) stay out of the
    model and therefore out of the report's raw excerpt.
    """

    model_config = ConfigDict(frozen=True, extra='ignore')

    rule_id: str | None = None
    severity: str | None = None
    message: str
    file: str
    line: int
    symbol: str | None = None
    name: str | None = None


class _SkylosUnusedFileEntry(BaseModel):
    """One unused-file entry from a skylos JSON array (untrusted input).

    ``unused_files`` is a multi-rule bucket (``SKY-E002`` empty file,
    ``SKY-E003`` unused TypeScript/JavaScript file) and every supported
    skylos revision stamps the rule ID explicitly on each entry, so
    ``rule_id`` is a guaranteed field: no bucket fallback exists, and
    defaulting one rule's code onto the other's entries would corrupt the
    finding identity (reporting contract §3.1).
    """

    model_config = ConfigDict(frozen=True, extra='ignore')

    rule_id: str
    severity: str | None = None
    message: str
    file: str
    line: int


class SkylosAdapter:
    """Adapter for skylos's JSON report (contract §4).

    Attributes
    ----------
    name : str
        Tool name: ``skylos``.
    distribution : str
        Distribution name: ``skylos``.
    executable : str
        Console script: ``skylos``.
    default_args : tuple[str, ...]
        ``--json`` for machine-readable output.
    analyses : Mapping[str, tuple[str, ...]]
        Opt-in analyses selectable in a corpus file, mapped to their flags.
    invocation_env : Mapping[str, str]
        ``SKYLOS_CONFIG_FILE`` pinned to the packaged neutral config, so
        the analyzed repository's own skylos policy never alters the run,
        and ``SKYLOS_GREP_BUDGET`` pinned so both sides run the
        grep-verify post-pass under the same wall-clock allowance.
    passthrough_env : tuple[str, ...]
        ``SKYLOS_GO_BIN``, naming the prebuilt native Go engine. A project
        containing Go sources — skylos itself, notably — is analyzed
        incompletely without it, and on revisions that surface that as an
        analysis error the invocation fails outright. Both sides receive
        the same operator-supplied binary, so the engine is a constant of
        the comparison rather than part of the diff.
    success_exit_codes : frozenset[int]
        0 only; skylos exits 2 when analysis errors occurred.
    capabilities : AdapterCapabilities
        Confidence- and severity-capable JSON output.
    build_recipe : BuildRecipe
        Generic Python source install; compiled dependencies arrive as
        prefetched wheels (contract §4).
    """

    name: str = 'skylos'
    distribution: str = 'skylos'
    executable: str = 'skylos'
    default_args: tuple[str, ...] = ('--json',)
    analyses: Mapping[str, tuple[str, ...]] = MappingProxyType(
        {
            'danger': ('--danger',),
            'secrets': ('--secrets',),
            'quality': ('--quality',),
            'ai-defects': ('--ai-defects',),
        }
    )
    invocation_env: Mapping[str, str] = MappingProxyType(
        {'SKYLOS_CONFIG_FILE': str(_NEUTRAL_CONFIG), 'SKYLOS_GREP_BUDGET': _GREP_BUDGET_SECONDS}
    )
    passthrough_env: tuple[str, ...] = ('SKYLOS_GO_BIN',)
    success_exit_codes: frozenset[int] = frozenset({0})
    capabilities: AdapterCapabilities = AdapterCapabilities(
        has_confidence=True,
        has_severity=True,
        output_format='json',
    )
    build_recipe: BuildRecipe = BuildRecipe(backend='python-source')

    @staticmethod
    def parse(output: RawToolOutput, *, project: str, root: Path, analyses: tuple[str, ...] = ()) -> list[Finding]:
        """Parse the skylos JSON document into findings.

        Parameters
        ----------
        output : RawToolOutput
            Captured skylos output, possibly from a failed invocation.
        project : str
            Corpus project name to stamp onto findings.
        root : Path
            Checkout directory skylos analyzed.
        analyses : tuple[str, ...]
            Selected opt-in analyses; only their diagnostic arrays are
            ingested, keeping the report on the categories the run's
            provenance claims even when a target repository's own skylos
            configuration enables more.

        Returns
        -------
        list[Finding]
            One finding per dead-code entry and per diagnostic in a
            selected analysis array.

        Raises
        ------
        AdapterError
            If stdout is not a JSON object, an entry is malformed, or an
            analysis is not declared. Failed output must also produce at
            least one finding from a recognized result bucket.
        """
        selected: set[str] = set()
        for name in analyses:
            if name not in _ANALYSIS_BUCKETS:
                msg = f'skylos does not provide analysis {name!r}'
                raise AdapterError(msg)
            selected.add(_ANALYSIS_BUCKETS[name])
        try:
            document = json.loads(output.stdout)
        except json.JSONDecodeError as exc:
            msg = f'skylos output is not valid JSON: {exc}'
            raise AdapterError(msg) from exc
        if not isinstance(document, dict):
            msg = 'skylos output is not a JSON object'
            raise AdapterError(msg)
        result_keys = (*DEAD_CODE_KEYS, *(bucket for bucket in DIAGNOSTIC_KINDS if bucket in selected))
        findings: list[Finding] = []
        for key in result_keys:
            bucket = document.get(key, [])
            if not isinstance(bucket, list):
                msg = f'skylos key {key!r} is not an array'
                raise AdapterError(msg)
            if key == 'unused_files':
                parse_entry = _parse_unused_file_entry
            elif key in DIAGNOSTIC_KINDS:
                parse_entry = _parse_diagnostic_entry
            else:
                parse_entry = _parse_entry
            findings.extend(parse_entry(raw, key=key, project=project, root=root) for raw in bucket)
        if output.returncode not in SkylosAdapter.success_exit_codes and not findings:
            msg = 'failed skylos output has no findings in recognized result buckets'
            raise AdapterError(msg)
        return findings


def _parse_entry(raw: object, *, key: str, project: str, root: Path) -> Finding:
    """Convert one skylos array entry into a finding.

    Parameters
    ----------
    raw : object
        Untrusted JSON entry.
    key : str
        Array name the entry came from, for error context.
    project : str
        Corpus project name to stamp onto the finding.
    root : Path
        Checkout directory skylos analyzed.

    Returns
    -------
    Finding
        The normalized finding.

    Raises
    ------
    AdapterError
        If the entry does not carry the guaranteed skylos fields.
    """
    try:
        entry = _SkylosEntry.model_validate(raw)
    except ValidationError as exc:
        msg = f'malformed skylos entry in {key!r}: {exc}'
        raise AdapterError(msg) from exc
    line = max(entry.line, 1)
    return Finding(
        tool=SkylosAdapter.name,
        project=project,
        path=normalize_finding_path(entry.file, root),
        symbol=entry.full_name if entry.full_name is not None else entry.name,
        kind=entry.type,
        message=f"unused {entry.type} '{entry.name}'",
        start_line=line,
        end_line=line,
        confidence=entry.confidence,
        # An explicit detector rule ID wins; the documented bucket mapping
        # is the fallback (reporting contract §3.1).
        rule_id=entry.rule_id if entry.rule_id is not None else BUCKET_RULE_IDS.get(key),
        raw_excerpt=json.dumps(entry.model_dump(), sort_keys=True),
    )


def _parse_unused_file_entry(raw: object, *, key: str, project: str, root: Path) -> Finding:
    """Convert one unused-file entry into a finding.

    Parameters
    ----------
    raw : object
        Untrusted JSON entry.
    key : str
        Array name the entry came from, for error context.
    project : str
        Corpus project name to stamp onto the finding.
    root : Path
        Checkout directory skylos analyzed.

    Returns
    -------
    Finding
        The normalized file-level finding.

    Raises
    ------
    AdapterError
        If the entry does not carry the guaranteed skylos fields.
    """
    try:
        entry = _SkylosUnusedFileEntry.model_validate(raw)
    except ValidationError as exc:
        msg = f'malformed skylos entry in {key!r}: {exc}'
        raise AdapterError(msg) from exc
    line = max(entry.line, 1)
    return Finding(
        tool=SkylosAdapter.name,
        project=project,
        path=normalize_finding_path(entry.file, root),
        symbol=None,
        kind='file',
        message=entry.message,
        start_line=line,
        end_line=line,
        severity=entry.severity,
        rule_id=entry.rule_id,
        raw_excerpt=json.dumps(entry.model_dump(), sort_keys=True),
    )


def _parse_diagnostic_entry(raw: object, *, key: str, project: str, root: Path) -> Finding:
    """Convert one skylos opt-in analysis diagnostic into a finding.

    Diagnostics carry a severity label and rule ID instead of a confidence
    value, and may omit the symbol; the line number is therefore an
    inseparable part of the finding identity. Quality diagnostics name
    their subject in ``name`` rather than ``symbol``, and repository-level
    policy diagnostics (e.g. ``SKY-R104``) report the checkout root itself,
    normalized to the ``.`` path.

    Parameters
    ----------
    raw : object
        Untrusted JSON entry.
    key : str
        Array name the entry came from, for error context.
    project : str
        Corpus project name to stamp onto the finding.
    root : Path
        Checkout directory skylos analyzed.

    Returns
    -------
    Finding
        The normalized finding.

    Raises
    ------
    AdapterError
        If the entry does not carry the guaranteed skylos fields.
    """
    try:
        entry = _SkylosDiagnosticEntry.model_validate(raw)
    except ValidationError as exc:
        msg = f'malformed skylos entry in {key!r}: {exc}'
        raise AdapterError(msg) from exc
    line = max(entry.line, 1)
    subject_name = entry.name if key in _NAME_SUBJECT_BUCKETS else None
    return Finding(
        tool=SkylosAdapter.name,
        project=project,
        path=normalize_finding_path(entry.file, root, allow_root=True),
        symbol=entry.symbol if entry.symbol is not None else subject_name,
        kind=DIAGNOSTIC_KINDS[key],
        message=entry.message,
        start_line=line,
        end_line=line,
        severity=entry.severity,
        rule_id=entry.rule_id,
        raw_excerpt=json.dumps(entry.model_dump(), sort_keys=True),
    )
