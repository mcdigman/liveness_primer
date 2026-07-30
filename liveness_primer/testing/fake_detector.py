"""A fake detector producing any required output or diff characteristic (contract §15).

Copyright (C) 2026 Matthew C. Digman

The fake detector reads a JSON script and emits vulture-format report lines,
so runs parse through the real ``vulture`` adapter. Pointing the escape
hatch (``--old-cmd``/``--new-cmd``) at two different scripts simulates two
fake pinned detector commits.
"""

import json
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from liveness_primer.testing.filesystem import atomic_write_text


@dataclass(frozen=True, slots=True)
class FakeFinding:
    """One scripted finding the fake detector will report.

    Attributes
    ----------
    path : str
        Repo-relative path to report.
    line : int
        Line number to report.
    symbol : str
        Symbol name to report.
    kind : str
        Vulture kind (``function``, ``import``, ...).
    confidence : int
        Confidence percentage.
    """

    path: str
    line: int
    symbol: str
    kind: str = 'function'
    confidence: int = 60

    def report_line(self) -> str:
        """Format the finding as a vulture report line.

        Returns
        -------
        str
            ``path:line: unused kind 'symbol' (NN% confidence)``.
        """
        return f"{self.path}:{self.line}: unused {self.kind} '{self.symbol}' ({self.confidence}% confidence)"


def fake_detector_command(script_path: Path) -> list[str]:
    """Build the command that runs the fake detector on a script.

    The command bootstraps ``sys.path`` so the fake detector imports this
    package regardless of the child's working directory (detectors run with
    the checkout as their cwd).

    Parameters
    ----------
    script_path : Path
        The JSON script location.

    Returns
    -------
    list[str]
        Argv prefix invoking this module with the current interpreter.
    """
    package_root = str(Path(__file__).resolve().parent.parent.parent)
    bootstrap = (
        'import sys; '
        f'sys.path.insert(0, {package_root!r}); '
        'from liveness_primer.testing.fake_detector import main; '
        'sys.exit(main(sys.argv[1:]))'
    )
    return [sys.executable, '-c', bootstrap, str(script_path)]


def write_fake_detector_script(
    script_path: Path,
    findings: Sequence[FakeFinding],
    *,
    exit_code: int | None = None,
    stderr: str = '',
    raw_lines: Sequence[str] = (),
    sleep_seconds: float = 0.0,
) -> list[str]:
    """Write a fake-detector script and return the command to run it.

    Parameters
    ----------
    script_path : Path
        Where to write the JSON script.
    findings : Sequence[FakeFinding]
        Findings to report.
    exit_code : int | None
        Exit code override; defaults to vulture semantics (3 with findings,
        0 when clean).
    stderr : str
        Text to emit on standard error.
    raw_lines : Sequence[str]
        Extra raw stdout lines (e.g. garbage to trip the parser).
    sleep_seconds : float
        Delay before emitting, for timeout scenarios.

    Returns
    -------
    list[str]
        Argv prefix suitable for ``--old-cmd``/``--new-cmd``.
    """
    script = {
        'findings': [
            {
                'path': finding.path,
                'line': finding.line,
                'symbol': finding.symbol,
                'kind': finding.kind,
                'confidence': finding.confidence,
            }
            for finding in findings
        ],
        'exit_code': exit_code,
        'stderr': stderr,
        'raw_lines': list(raw_lines),
        'sleep_seconds': sleep_seconds,
    }
    atomic_write_text(script_path, json.dumps(script, indent=2))
    return fake_detector_command(script_path)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fake detector: emit the scripted report.

    Extra arguments after the script path (adapter default arguments and
    targets) are accepted and ignored, mirroring a real detector invocation.

    Parameters
    ----------
    argv : Sequence[str] | None
        Arguments; the first must be the script path. Defaults to
        ``sys.argv[1:]``.

    Returns
    -------
    int
        The scripted exit code; vulture semantics by default.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        sys.stderr.write('usage: fake_detector SCRIPT.json [target ...]\n')
        return 2
    script = json.loads(Path(arguments[0]).read_text(encoding='utf-8'))
    sleep_seconds = float(script.get('sleep_seconds', 0.0))
    if sleep_seconds > 0:
        time.sleep(sleep_seconds)
    lines = [
        FakeFinding(
            path=str(entry['path']),
            line=int(entry['line']),
            symbol=str(entry['symbol']),
            kind=str(entry['kind']),
            confidence=int(entry['confidence']),
        ).report_line()
        for entry in script.get('findings', [])
    ]
    lines.extend(str(raw) for raw in script.get('raw_lines', []))
    for line in lines:
        sys.stdout.write(line + '\n')
    stderr_text = str(script.get('stderr', ''))
    if stderr_text:
        sys.stderr.write(stderr_text)
    exit_code = script.get('exit_code')
    if exit_code is None:
        return 3 if lines else 0
    return int(exit_code)
