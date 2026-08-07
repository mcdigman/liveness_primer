"""A fake detector producing any required output or diff characteristic (contract §15).

Copyright (C) 2026 Matthew C. Digman

The fake detector reads a JSON script and emits vulture-format report lines
or a skylos-format JSON document, so runs parse through the real adapters.
Pointing the escape hatch (``--old-cmd``/``--new-cmd``) at two different
scripts simulates two fake pinned detector commits; the skylos format can
carry explicit rule IDs (reporting contract §3.1), and its ``danger``
bucket emits security diagnostics with severity labels.
"""

import json
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from liveness_primer.filesystem import atomic_write_text

FakeFormat = Literal['vulture', 'skylos']


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
        Finding kind (``function``, ``import``, ...).
    confidence : int
        Confidence percentage.
    bucket : str
        Skylos array the finding lands in (skylos format only); the
        ``danger`` bucket emits the security-diagnostic entry shape.
    rule_id : str | None
        Explicit detector rule ID (skylos format only).
    severity : str | None
        Severity label (skylos ``danger`` bucket only).
    message : str | None
        Message override (skylos ``danger`` bucket only).
    """

    path: str
    line: int
    symbol: str
    kind: str = 'function'
    confidence: int = 60
    bucket: str = 'unused_functions'
    rule_id: str | None = None
    severity: str | None = None
    message: str | None = None

    def report_line(self) -> str:
        """Format the finding as a vulture report line.

        Returns
        -------
        str
            ``path:line: unused kind 'symbol' (NN% confidence)``.
        """
        return f"{self.path}:{self.line}: unused {self.kind} '{self.symbol}' ({self.confidence}% confidence)"

    def skylos_entry(self) -> dict[str, object]:
        """Format the finding as a skylos JSON array entry.

        Returns
        -------
        dict[str, object]
            The dead-code entry shape, or the security-diagnostic shape for
            the ``danger`` bucket; optional fields are present only when
            scripted.
        """
        if self.bucket == 'danger':
            diagnostic: dict[str, object] = {
                'message': self.message if self.message is not None else f"dangerous use of '{self.symbol}'",
                'file': self.path,
                'line': self.line,
                'symbol': self.symbol,
            }
            if self.rule_id is not None:
                diagnostic['rule_id'] = self.rule_id
            if self.severity is not None:
                diagnostic['severity'] = self.severity
            return diagnostic
        entry: dict[str, object] = {
            'name': self.symbol,
            'full_name': self.symbol,
            'type': self.kind,
            'file': self.path,
            'line': self.line,
            'confidence': self.confidence,
        }
        if self.rule_id is not None:
            entry['rule_id'] = self.rule_id
        return entry


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
    output_format: FakeFormat = 'vulture',
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
    output_format : FakeFormat
        Report format: vulture text lines or a skylos JSON document.
    exit_code : int | None
        Exit code override; defaults to the format's own semantics
        (vulture: 3 with findings, 0 when clean; skylos: 0).
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
        'format': output_format,
        'findings': [
            {
                'path': finding.path,
                'line': finding.line,
                'symbol': finding.symbol,
                'kind': finding.kind,
                'confidence': finding.confidence,
                'bucket': finding.bucket,
                'rule_id': finding.rule_id,
                'severity': finding.severity,
                'message': finding.message,
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


def _scripted_findings(script: dict[str, object]) -> list[FakeFinding]:
    """Rebuild the scripted findings from the parsed JSON script.

    Parameters
    ----------
    script : dict[str, object]
        The parsed script document.

    Returns
    -------
    list[FakeFinding]
        The scripted findings.
    """
    entries = script.get('findings', [])
    findings: list[FakeFinding] = []
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                rule_id = entry.get('rule_id')
                severity = entry.get('severity')
                message = entry.get('message')
                findings.append(
                    FakeFinding(
                        path=str(entry['path']),
                        line=int(str(entry['line'])),
                        symbol=str(entry['symbol']),
                        kind=str(entry['kind']),
                        confidence=int(str(entry['confidence'])),
                        bucket=str(entry.get('bucket', 'unused_functions')),
                        rule_id=str(rule_id) if rule_id is not None else None,
                        severity=str(severity) if severity is not None else None,
                        message=str(message) if message is not None else None,
                    )
                )
    return findings


def _emit_vulture(findings: Sequence[FakeFinding], raw_lines: Sequence[str]) -> int:
    """Emit the vulture-format report.

    Parameters
    ----------
    findings : Sequence[FakeFinding]
        Findings to report.
    raw_lines : Sequence[str]
        Extra raw stdout lines.

    Returns
    -------
    int
        The default vulture exit code: 3 with output, 0 when clean.
    """
    lines = [finding.report_line() for finding in findings]
    lines.extend(str(raw) for raw in raw_lines)
    for line in lines:
        sys.stdout.write(line + '\n')
    return 3 if lines else 0


def _emit_skylos(findings: Sequence[FakeFinding]) -> int:
    """Emit the skylos-format JSON document.

    Parameters
    ----------
    findings : Sequence[FakeFinding]
        Findings to report.

    Returns
    -------
    int
        The default skylos exit code: 0.
    """
    document: dict[str, list[dict[str, object]]] = {}
    for finding in findings:
        document.setdefault(finding.bucket, []).append(finding.skylos_entry())
    sys.stdout.write(json.dumps(document, indent=2) + '\n')
    return 0


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
        The scripted exit code; format-default semantics otherwise.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        sys.stderr.write('usage: fake_detector SCRIPT.json [target ...]\n')
        return 2
    script = json.loads(Path(arguments[0]).read_text(encoding='utf-8'))
    sleep_seconds = float(script.get('sleep_seconds', 0.0))
    if sleep_seconds > 0:
        time.sleep(sleep_seconds)
    findings = _scripted_findings(script)
    if script.get('format', 'vulture') == 'skylos':
        default_exit = _emit_skylos(findings)
    else:
        default_exit = _emit_vulture(findings, [str(raw) for raw in script.get('raw_lines', [])])
    stderr_text = str(script.get('stderr', ''))
    if stderr_text:
        sys.stderr.write(stderr_text)
    exit_code = script.get('exit_code')
    if exit_code is None:
        return default_exit
    return int(exit_code)
