"""Adapter for the ``skylos`` dead-code detector (contract §4).

Copyright (C) 2026 Matthew C. Digman

Skylos emits a JSON document on stdout under ``--json``. Only the dead-code
arrays are ingested; its security, secrets, and quality categories live in
separate top-level keys and are filtered at the adapter (contract §4).
"""

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from liveness_primer.findings import Finding
from liveness_primer.tools.base import (
    AdapterCapabilities,
    AdapterError,
    BuildRecipe,
    RawToolOutput,
    normalize_finding_path,
)

# Dead-code finding arrays in the skylos JSON document; other report
# categories (danger, secrets, quality, ...) are deliberately not ingested.
_DEAD_CODE_KEYS = ('unused_functions', 'unused_imports', 'unused_classes', 'unused_variables', 'unused_parameters')


class _SkylosEntry(BaseModel):
    """One dead-code entry from a skylos JSON array (untrusted input)."""

    model_config = ConfigDict(frozen=True, extra='ignore')

    name: str
    full_name: str | None = None
    type: str
    file: str
    line: int
    confidence: int | None = Field(default=None, ge=0, le=100)


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
    success_exit_codes : frozenset[int]
        0 only; skylos exits 2 when analysis errors occurred.
    capabilities : AdapterCapabilities
        Confidence-capable JSON output.
    build_recipe : BuildRecipe
        Generic Python source install; compiled dependencies arrive as
        prefetched wheels (contract §4).
    """

    name: str = 'skylos'
    distribution: str = 'skylos'
    executable: str = 'skylos'
    default_args: tuple[str, ...] = ('--json',)
    success_exit_codes: frozenset[int] = frozenset({0})
    capabilities: AdapterCapabilities = AdapterCapabilities(has_confidence=True, output_format='json')
    build_recipe: BuildRecipe = BuildRecipe(backend='python-source')

    @staticmethod
    def parse(output: RawToolOutput, *, project: str, root: Path) -> list[Finding]:
        """Parse the skylos JSON document into findings.

        Parameters
        ----------
        output : RawToolOutput
            Captured skylos output with a success exit code.
        project : str
            Corpus project name to stamp onto findings.
        root : Path
            Checkout directory skylos analyzed.

        Returns
        -------
        list[Finding]
            One finding per dead-code entry.

        Raises
        ------
        AdapterError
            If stdout is not a JSON object or an entry is malformed.
        """
        try:
            document = json.loads(output.stdout)
        except json.JSONDecodeError as exc:
            msg = f'skylos output is not valid JSON: {exc}'
            raise AdapterError(msg) from exc
        if not isinstance(document, dict):
            msg = 'skylos output is not a JSON object'
            raise AdapterError(msg)
        findings: list[Finding] = []
        for key in _DEAD_CODE_KEYS:
            bucket = document.get(key, [])
            if not isinstance(bucket, list):
                msg = f'skylos key {key!r} is not an array'
                raise AdapterError(msg)
            findings.extend(_parse_entry(raw, key=key, project=project, root=root) for raw in bucket)
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
        raw_excerpt=json.dumps(entry.model_dump(), sort_keys=True),
    )
