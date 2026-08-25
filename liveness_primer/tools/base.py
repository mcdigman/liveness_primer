# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""The typed detector-adapter protocol and shared adapter plumbing (contract §4).

Adapters turn raw invocation output into ``list[Finding]``, declare
capabilities and a build recipe, and never interpolate corpus content into
commands: invocations are argv lists composed from typed, validated models.
"""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath
from typing import Literal, Protocol, runtime_checkable

from liveness_primer.config import CorpusConfigError, ToolSettings
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.findings import Finding


class AdapterError(LivenessPrimerError):
    """Raised when detector output cannot be parsed into findings."""


class UnknownToolError(LivenessPrimerError):
    """Raised when no adapter provides a requested tool name."""


# Static executable a detector requires in a minimal container runtime.
RuntimeBinary = Literal['rg']


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Capabilities an adapter declares (contract §4).

    Attributes
    ----------
    has_confidence : bool
        Whether findings carry a confidence value.
    has_severity : bool
        Whether findings carry a severity label.
    output_format : str
        Raw output format the detector emits (``text`` or ``json``).
    """

    has_confidence: bool
    has_severity: bool
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
    analyses : Mapping[str, tuple[str, ...]]
        Opt-in analyses the adapter supports, mapped to the arguments each
        one adds; corpus ``analyses`` selections validate against the keys.
    invocation_env : Mapping[str, str]
        Static, side-identical environment variables layered over the
        scrubbed environment of every detector invocation (e.g. pinning a
        detector's config discovery, contract §3, §11).
    invocation_env_files : Mapping[str, Path]
        Side-identical environment variables whose value is a packaged
        host file the detector must be able to read. The execution backend
        supplies the path in the detector's own filesystem view: the host
        path directly, or a copy staged into the container mounts
        (contract §3, §11).
    passthrough_env : tuple[str, ...]
        Environment variables naming an operator-supplied native helper
        executable the detector needs. The §3 scrub drops everything
        unlisted, so a declared variable is the only way an operator sets
        one for the analysis invocation (the build step does not receive
        them); the runner validates and hashes each value and records it in
        the manifest. A detector may still locate a helper by its own
        means — bundled in its install, or on the surviving ``PATH``.
    runtime_binaries : tuple[RuntimeBinary, ...]
        Static executables staged into a minimal container runtime. Empty for
        a pure-Python detector.
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
    analyses: Mapping[str, tuple[str, ...]]
    invocation_env: Mapping[str, str]
    invocation_env_files: Mapping[str, Path]
    passthrough_env: tuple[str, ...]
    runtime_binaries: tuple[RuntimeBinary, ...]
    success_exit_codes: frozenset[int]
    capabilities: AdapterCapabilities
    build_recipe: BuildRecipe

    def parse(
        self, output: RawToolOutput, *, project: str, root: PurePath, analyses: tuple[str, ...] = ()
    ) -> list[Finding]:
        """Parse raw invocation output into normalized findings.

        Parameters
        ----------
        output : RawToolOutput
            Captured detector output, possibly from a failed invocation.
        project : str
            Corpus project name to stamp onto findings.
        root : PurePath
            Checkout root as the detector saw it (a container-side pure
            POSIX path in container mode), for path normalization.
        analyses : tuple[str, ...]
            Selected opt-in analyses; only their categories are ingested,
            so the report never carries categories the run's provenance
            does not claim (contract §4, §5).

        Returns
        -------
        list[Finding]
            Normalized dead-code findings plus selected-analysis findings.
        """
        ...


def build_invocation(adapter: DetectorAdapter, executable: Sequence[str], settings: ToolSettings) -> list[str]:
    """Compose the analysis argv for one (project, tool) pair (contract §11).

    The per-tool corpus ``command`` override replaces the default program and
    arguments, with its mandatory ``{exe}`` element spliced with the detector
    command; selected ``analyses`` resolve through the adapter's declared
    flags; ``args`` appends; targets default to the checkout root. Corpus
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

    Raises
    ------
    CorpusConfigError
        If ``settings`` selects an analysis the adapter does not declare.
    """
    base: list[str] = []
    if settings.command is not None:
        # ToolSettings guarantees the placeholder is present, so both sides
        # always run their own executables.
        for element in settings.command:
            if element == '{exe}':
                base.extend(executable)
            else:
                base.append(element)
    else:
        base.extend([*executable, *adapter.default_args])
    for analysis in settings.analyses:
        flags = adapter.analyses.get(analysis)
        if flags is None:
            msg = f'tool {adapter.name!r} does not provide analysis {analysis!r}'
            raise CorpusConfigError(msg)
        base.extend(flags)
    targets = list(settings.targets) if settings.targets else ['.']
    return [*base, *settings.args, *targets]


def _relative_to_root(path: PurePath, root: PurePath) -> PurePath | None:
    """Express an absolute reported path relative to the checkout root.

    Parameters
    ----------
    path : PurePath
        Absolute path as reported.
    root : PurePath
        Checkout root as the detector saw it; only a concrete host ``Path``
        can also be resolved.

    Returns
    -------
    PurePath | None
        The relative path, or ``None`` when outside the root.
    """
    candidates = (root, root.resolve()) if isinstance(root, Path) else (root,)
    for candidate_root in candidates:
        try:
            return path.relative_to(candidate_root)
        except ValueError:
            continue
    return None


def normalize_finding_path(raw: str, root: PurePath, *, allow_root: bool = False) -> str:
    """Normalize a detector-reported path to repo-relative POSIX form (contract §7).

    Detector output is untrusted: paths resolving outside the analyzed
    checkout are rejected as malformed adapter output rather than
    preserved (contract §11).

    Parameters
    ----------
    raw : str
        Path exactly as the detector printed it (untrusted).
    root : PurePath
        Checkout root as the detector saw it: a host ``Path``, or a pure
        POSIX path for container-side roots.
    allow_root : bool
        Whether a path naming the checkout root itself normalizes to
        ``.`` (repository-level findings) instead of failing.

    Returns
    -------
    str
        The path relative to ``root``, without a leading ``./``, in POSIX
        notation.

    Raises
    ------
    AdapterError
        If the path escapes the checkout root, or names no file while
        ``allow_root`` is unset.
    """
    # A pure root is container-side: parse the reported path in the same
    # POSIX flavor so absolute-path detection is host-independent.
    path: PurePath = Path(raw) if isinstance(root, Path) else PurePosixPath(raw)
    if path.is_absolute():
        relative = _relative_to_root(path, root)
        if relative is None:
            msg = f'detector reported a path outside the checkout: {raw!r}'
            raise AdapterError(msg)
        path = relative
    # Lexically normalize the untrusted relative path (pathlib already
    # collapses `.` segments); `..` escaping the checkout root is malformed
    # adapter output (contract §7, §11).
    parts: list[str] = []
    for part in path.parts:
        if part == '..':
            if not parts:
                msg = f'detector reported a path outside the checkout: {raw!r}'
                raise AdapterError(msg)
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        if allow_root:
            return '.'
        msg = f'detector reported a path naming no file: {raw!r}'
        raise AdapterError(msg)
    return PurePosixPath(*parts).as_posix()
