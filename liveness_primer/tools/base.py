"""The typed detector-adapter protocol and shared adapter plumbing (contract §4).

Copyright (C) 2026 Matthew C. Digman

Adapters turn raw invocation output into ``list[Finding]``, declare
capabilities and a build recipe, and never interpolate corpus content into
commands: invocations are argv lists composed from typed, validated models.
"""

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from liveness_primer.config import ToolSettings
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.findings import Finding


class AdapterError(LivenessPrimerError):
    """Raised when detector output cannot be parsed into findings."""


class UnknownToolError(LivenessPrimerError):
    """Raised when no adapter provides a requested tool name."""


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Capabilities an adapter declares (contract §4).

    Attributes
    ----------
    has_confidence : bool
        Whether findings carry a confidence value.
    output_format : str
        Raw output format the detector emits (``text`` or ``json``).
    """

    has_confidence: bool
    output_format: str


@dataclass(frozen=True, slots=True)
class ToolchainRequirement:
    """One toolchain prerequisite of a build recipe (contract §4).

    Attributes
    ----------
    name : str
        Prerequisite name (e.g. ``rust``, ``maturin``).
    minimum_version : str
        Minimum acceptable version.
    """

    name: str
    minimum_version: str


@dataclass(frozen=True, slots=True)
class BuildRecipe:
    """Build recipe an adapter declares (contract §4).

    Attributes
    ----------
    backend : str
        Build path; ``python-source`` is the generic source-install path.
    toolchain : tuple[ToolchainRequirement, ...]
        Toolchain prerequisites the runner verifies before building.
    """

    backend: str
    toolchain: tuple[ToolchainRequirement, ...] = ()

    def digest(self) -> str:
        """Hash the recipe for the environment-cache fingerprint (contract §3).

        Returns
        -------
        str
            Stable hex digest of the canonical recipe encoding.
        """
        material = json.dumps(
            {
                'backend': self.backend,
                'toolchain': [[entry.name, entry.minimum_version] for entry in self.toolchain],
            },
            sort_keys=True,
        )
        return hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class RawToolOutput:
    """Captured output of one detector invocation.

    Attributes
    ----------
    returncode : int
        Detector exit code.
    stdout : str
        Captured standard output (untrusted).
    stderr : str
        Captured standard error (untrusted).
    """

    returncode: int
    stdout: str
    stderr: str


@runtime_checkable
class DetectorAdapter(Protocol):
    """Typed protocol every detector adapter satisfies (contract §4).

    Attributes
    ----------
    name : str
        Tool name used on the CLI and in corpus files.
    distribution : str
        Distribution name of the detector package, excluded from the
        non-detector dependency delta (contract §3).
    executable : str
        Console-script name inside the managed environment.
    default_args : tuple[str, ...]
        Arguments the adapter always passes before targets.
    success_exit_codes : frozenset[int]
        Exit codes that mean the run completed (findings or clean).
    capabilities : AdapterCapabilities
        Declared capabilities.
    build_recipe : BuildRecipe
        Declared build recipe.
    """

    name: str
    distribution: str
    executable: str
    default_args: tuple[str, ...]
    success_exit_codes: frozenset[int]
    capabilities: AdapterCapabilities
    build_recipe: BuildRecipe

    def parse(self, output: RawToolOutput, *, project: str, root: Path) -> list[Finding]:
        """Parse raw invocation output into normalized findings.

        Parameters
        ----------
        output : RawToolOutput
            Captured detector output with a success exit code.
        project : str
            Corpus project name to stamp onto findings.
        root : Path
            Checkout directory the detector analyzed, for path normalization.

        Returns
        -------
        list[Finding]
            Normalized dead-code findings only (contract §4).
        """
        ...


def build_invocation(adapter: DetectorAdapter, executable: Sequence[str], settings: ToolSettings) -> list[str]:
    """Compose the analysis argv for one (project, tool) pair (contract §11).

    The per-tool corpus ``command`` override replaces the default program and
    arguments, with the literal element ``{exe}`` spliced with the detector
    command; ``args`` appends; targets default to the checkout root. Corpus
    *content* is never interpolated — every element originates from typed,
    validated models.

    Parameters
    ----------
    adapter : DetectorAdapter
        The adapter providing defaults.
    executable : Sequence[str]
        Detector command prefix: the managed console script, or an
        escape-hatch command (contract §3).
    settings : ToolSettings
        Per-(project, tool) corpus table.

    Returns
    -------
    list[str]
        The composed argv.
    """
    base: list[str] = []
    if settings.command is not None:
        for element in settings.command:
            if element == '{exe}':
                base.extend(executable)
            else:
                base.append(element)
    else:
        base.extend([*executable, *adapter.default_args])
    targets = list(settings.targets) if settings.targets else ['.']
    return [*base, *settings.args, *targets]


def normalize_finding_path(raw: str, root: Path) -> str:
    """Normalize a detector-reported path to repo-relative POSIX form (contract §7).

    Parameters
    ----------
    raw : str
        Path exactly as the detector printed it (untrusted).
    root : Path
        Checkout directory the detector analyzed.

    Returns
    -------
    str
        The path relative to ``root`` when possible, without a leading
        ``./``, in POSIX notation.
    """
    path = Path(raw)
    if path.is_absolute():
        try:
            path = path.relative_to(root)
        except ValueError:
            return path.as_posix()
    posix = path.as_posix()
    return posix.removeprefix('./')
