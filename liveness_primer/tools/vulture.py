# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Adapter for the ``vulture`` dead-code detector (contract §4).

Vulture prints one finding per stdout line as
``path:line: message (NN% confidence)`` and exits 0 when clean, 3 when
findings exist, 1 on invalid input, and 2 on invalid arguments.
"""

import re
from collections.abc import Mapping
from pathlib import Path, PurePath
from types import MappingProxyType

from liveness_primer.findings import Finding
from liveness_primer.tools.base import (
    AdapterCapabilities,
    AdapterError,
    BuildRecipe,
    RawToolOutput,
    RuntimeBinary,
    normalize_finding_path,
)

_LINE_RE = re.compile(
    r'^(?P<path>.+):(?P<line>\d+): (?P<message>.+) \((?P<confidence>\d{1,3})% confidence(?:, \d+ lines?)?\)$'
)
_UNUSED_RE = re.compile(r"^unused (?P<kind>attribute|class|function|import|method|property|variable) '(?P<symbol>.+)'$")


class VultureAdapter:
    """Adapter for vulture's text report (contract §4).

    Attributes
    ----------
    name : str
        Tool name: ``vulture``.
    distribution : str
        Distribution name: ``vulture``.
    executable : str
        Console script: ``vulture``.
    default_args : tuple[str, ...]
        No extra arguments; targets are positional.
    analyses : Mapping[str, tuple[str, ...]]
        Empty: vulture offers no opt-in analyses.
    invocation_env : Mapping[str, str]
        Empty: vulture needs no invocation environment.
    invocation_env_files : Mapping[str, Path]
        Empty: vulture reads no packaged files.
    passthrough_env : tuple[str, ...]
        Empty: vulture is pure Python and needs no native helper.
    runtime_binaries : tuple[RuntimeBinary, ...]
        Empty: vulture needs no runtime utility.
    success_exit_codes : frozenset[int]
        0 (clean) and 3 (findings).
    capabilities : AdapterCapabilities
        Confidence-capable text output.
    build_recipe : BuildRecipe
        Generic Python source install; no toolchain prerequisites.
    """

    name: str = 'vulture'
    distribution: str = 'vulture'
    executable: str = 'vulture'
    default_args: tuple[str, ...] = ()
    analyses: Mapping[str, tuple[str, ...]] = MappingProxyType({})
    invocation_env: Mapping[str, str] = MappingProxyType({})
    invocation_env_files: Mapping[str, Path] = MappingProxyType({})
    passthrough_env: tuple[str, ...] = ()
    runtime_binaries: tuple[RuntimeBinary, ...] = ()
    success_exit_codes: frozenset[int] = frozenset({0, 3})
    capabilities: AdapterCapabilities = AdapterCapabilities(
        has_confidence=True,
        has_severity=False,
        output_format='text',
    )
    build_recipe: BuildRecipe = BuildRecipe(backend='python-source')

    @staticmethod
    def failure_detail(output: RawToolOutput) -> str | None:
        """Return no structured failure detail for vulture output.

        Parameters
        ----------
        output : RawToolOutput
            Captured vulture output.

        Returns
        -------
        str | None
            Vulture reports operational errors on standard error.
        """
        del output
        return None

    @staticmethod
    def parse(output: RawToolOutput, *, project: str, root: PurePath, analyses: tuple[str, ...] = ()) -> list[Finding]:
        """Parse vulture stdout lines into findings.

        Reachability messages (``unreachable code after 'return'``,
        ``unsatisfiable 'if' condition``, ...) normalize to the
        ``unreachable_code`` kind with no symbol.

        Parameters
        ----------
        output : RawToolOutput
            Captured vulture output, possibly from a failed invocation.
        project : str
            Corpus project name to stamp onto findings.
        root : PurePath
            Checkout directory vulture analyzed.
        analyses : tuple[str, ...]
            Must be empty: vulture declares no opt-in analyses.

        Returns
        -------
        list[Finding]
            One finding per report line.

        Raises
        ------
        AdapterError
            If an analysis is selected, or a non-empty stdout line does
            not match the report format.
        """
        if analyses:
            msg = f'vulture does not provide analysis {analyses[0]!r}'
            raise AdapterError(msg)
        findings: list[Finding] = []
        unparsed: list[str] = []
        for line in output.stdout.splitlines():
            if not line.strip():
                continue
            match = _LINE_RE.match(line)
            if match is None:
                unparsed.append(line)
                continue
            message = match.group('message')
            unused = _UNUSED_RE.match(message)
            if unused is not None:
                kind, symbol = unused.group('kind'), unused.group('symbol')
            else:
                kind, symbol = 'unreachable_code', None
            start_line = int(match.group('line'))
            findings.append(
                Finding(
                    tool=VultureAdapter.name,
                    project=project,
                    path=normalize_finding_path(match.group('path'), root),
                    symbol=symbol,
                    kind=kind,
                    message=message,
                    start_line=max(start_line, 1),
                    end_line=max(start_line, 1),
                    confidence=min(int(match.group('confidence')), 100),
                    raw_excerpt=line,
                )
            )
        if unparsed:
            preview = ' | '.join(unparsed[:3])
            msg = f'{len(unparsed)} unparseable vulture output line(s), e.g.: {preview}'
            raise AdapterError(msg)
        return findings
