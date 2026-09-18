# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Validate a container smoke report and probe its Skylos runtime binaries."""

import hashlib
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from liveness_primer.container import (
    DEFAULT_CONTAINER_BUILDER_IMAGE,
    DEFAULT_CONTAINER_IMAGE,
    ContainerError,
    image_tag,
    ripgrep_artifact_for,
)
from liveness_primer.filesystem import (
    MAX_NATIVE_TOOL_BYTES,
    FilesystemPolicyError,
    open_bounded_regular,
    read_bounded_chunks,
    read_small_text,
)
from liveness_primer.findings import NativeToolRecord, Report, RunManifest
from liveness_primer.launcher import SyncLauncher, run_sync

# The detector images do not contain liveness_primer or a sha256sum command.
# This stdlib-only command is exercised as a real subprocess in the unit tests.
HASH_FILE_SCRIPT = (
    'import hashlib, sys\n'
    'with open(sys.argv[1], "rb") as stream:\n'
    '    print(hashlib.file_digest(stream, "sha256").hexdigest())\n'
)
_DOCKER_PROBE = (
    'docker',
    'run',
    '--rm',
    '--network',
    'none',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '64',
    '--user',
    '65532:65532',
    '--entrypoint',
    '',
)


class SmokeCheckError(ValueError):
    """Raised when a smoke report or runtime binary fails verification."""


@dataclass(frozen=True)
class BinaryCheck:
    """One expected runtime executable.

    Attributes
    ----------
    path : str
        Absolute path inside the image.
    digest : str
        Expected SHA-256 of the executable.
    version_prefix : str
        Required prefix of its version output.
    """

    path: str
    digest: str
    version_prefix: str


def _manifest_failures(manifest: RunManifest, environ: Mapping[str, str]) -> list[str]:
    """Check detector and image provenance.

    Parameters
    ----------
    manifest : RunManifest
        Report provenance.
    environ : Mapping[str, str]
        Expected smoke case settings.

    Returns
    -------
    list[str]
        Failed checks.
    """
    failures: list[str] = []
    installer = manifest.installer or ''
    if not manifest.isolation_enforced or not manifest.comparable:
        failures.append('expected an isolated, comparable container run')
    if manifest.tool != environ['SMOKE_TOOL'] or manifest.detector_repo != environ['SMOKE_REPO']:
        failures.append('unexpected detector identity')
    if not installer.startswith('docker '):
        failures.append(f'installer is not docker: {installer!r}')
    failures.extend(
        f'image {image} absent from installer'
        for image in (DEFAULT_CONTAINER_BUILDER_IMAGE, DEFAULT_CONTAINER_IMAGE)
        if image not in installer
    )
    for side, expected in ((manifest.base, environ['SMOKE_OLD']), (manifest.head, environ['SMOKE_NEW'])):
        if side is None or side.sha != expected or not side.rebuilt or side.from_cache:
            failures.append(f'expected a fresh environment for {expected}')
    return failures


def _project_failures(report: Report, project_name: str) -> list[str]:
    """Check completed analyses and immutable corpus provenance.

    Parameters
    ----------
    report : Report
        Parsed comparison.
    project_name : str
        Expected corpus project.

    Returns
    -------
    list[str]
        Failed checks.
    """
    failures: list[str] = []
    if tuple(project.project for project in report.projects) != (project_name,):
        failures.append(f'expected exactly one project: {project_name}')
    for project in report.projects:
        if project.errors or project.measured_cost_seconds is None:
            failures.append(f'{project.project}: analyses did not both complete successfully')
        if project.base_findings <= 0 or project.head_findings <= 0:
            failures.append(f'{project.project}: expected findings on both sides of this fixture')
    if tuple(pin.name for pin in report.manifest.corpus_pins) != (project_name,):
        failures.append('missing or unexpected corpus provenance')
    failures.extend(
        f'{pin.name}: expected an immutable corpus pin'
        for pin in report.manifest.corpus_pins
        if pin.requested != pin.resolved_sha
    )
    return failures


def _skylos_checks(manifest: RunManifest, helper_path: Path) -> tuple[tuple[BinaryCheck, BinaryCheck], list[str]]:
    """Resolve runtime binaries once and check their recorded provenance.

    Parameters
    ----------
    manifest : RunManifest
        Report provenance, including the runtime's sysconfig platform tag.
    helper_path : Path
        Operator-supplied Go executable.

    Returns
    -------
    tuple[tuple[BinaryCheck, BinaryCheck], list[str]]
        Expected binaries and failed provenance checks.
    """
    artifact = ripgrep_artifact_for(manifest.platform.removeprefix('linux-'))
    digest = hashlib.sha256()
    with open_bounded_regular(helper_path, description='smoke helper', max_bytes=MAX_NATIVE_TOOL_BYTES) as stream:
        for chunk in read_bounded_chunks(stream, description='smoke helper', max_bytes=MAX_NATIVE_TOOL_BYTES):
            digest.update(chunk)
    helper_digest = digest.hexdigest()
    helper = NativeToolRecord(variable='SKYLOS_GO_BIN', sha256=helper_digest)
    installer = manifest.installer or ''
    failures: list[str] = []
    if manifest.native_tools != (helper,):
        failures.append('the supplied Go helper was not admitted with its expected digest')
    if f'SKYLOS_GO_BIN sha256:{helper_digest}' not in installer:
        failures.append('Go helper digest absent from installer')
    if not any(
        fetch.kind == 'binary'
        and fetch.name == artifact.filename
        and fetch.resolved == artifact.version
        and fetch.digest == artifact.archive_digest
        for fetch in manifest.fetches
    ):
        failures.append('expected verified ripgrep download provenance')
    if f'sha256:{artifact.binary_digest}' not in installer:
        failures.append('ripgrep binary digest absent from installer')
    checks = (
        BinaryCheck('/usr/bin/rg', artifact.binary_digest, 'ripgrep '),
        BinaryCheck('/liveness/native-tools/SKYLOS_GO_BIN', helper_digest, 'skylos-go '),
    )
    return checks, failures


def validate_report(report: Report, environ: Mapping[str, str]) -> tuple[BinaryCheck, ...]:
    """Validate a smoke report and return its runtime binary expectations.

    Parameters
    ----------
    report : Report
        Parsed comparison.
    environ : Mapping[str, str]
        Expected case and supplied helper path.

    Returns
    -------
    tuple[BinaryCheck, ...]
        Skylos binaries to probe; empty for Vulture.

    Raises
    ------
    SmokeCheckError
        If the report fails a smoke assertion.
    """
    failures = _manifest_failures(report.manifest, environ)
    failures.extend(_project_failures(report, environ['SMOKE_PROJECT']))
    binaries: tuple[BinaryCheck, ...] = ()
    if report.manifest.tool == 'skylos':
        binaries, binary_failures = _skylos_checks(report.manifest, Path(environ['SKYLOS_GO_BIN']))
        failures.extend(binary_failures)
    elif report.manifest.native_tools or any(fetch.kind == 'binary' for fetch in report.manifest.fetches):
        failures.append('Vulture should exercise the path without auxiliary binaries')
    if failures:
        msg = 'container smoke assertions failed:\n' + '\n'.join(f'  - {failure}' for failure in failures)
        raise SmokeCheckError(msg)
    return binaries


def _probe_output(argv: Sequence[str], launcher: SyncLauncher) -> str:
    """Run a bounded Docker probe.

    Parameters
    ----------
    argv : Sequence[str]
        Docker command arguments.
    launcher : SyncLauncher
        Audited command launcher.

    Returns
    -------
    str
        Captured output.

    Raises
    ------
    SmokeCheckError
        If the probe fails or times out.
    """
    result = launcher(argv, timeout=60)
    if not result.ok:
        msg = f'container binary probe failed: {result.stderr}; exit={result.returncode}; timeout={result.timed_out}'
        raise SmokeCheckError(msg)
    return result.stdout


def verify_images(report: Report, binaries: Sequence[BinaryCheck], *, launcher: SyncLauncher = run_sync) -> None:
    """Verify binary bytes and execution inside both detector images.

    Parameters
    ----------
    report : Report
        Validated comparison with both environment fingerprints.
    binaries : Sequence[BinaryCheck]
        Expectations prepared while validating the report.
    launcher : SyncLauncher
        Audited Docker launcher.

    Raises
    ------
    SmokeCheckError
        If an environment is absent or a binary check fails.
    """
    for side in (report.manifest.base, report.manifest.head):
        if side is None:
            msg = 'missing detector environment'
            raise SmokeCheckError(msg)
        prefix = (*_DOCKER_PROBE, image_tag(side.fingerprint))
        for binary in binaries:
            digest = _probe_output(
                (*prefix, '/liveness/venv/bin/python', '-c', HASH_FILE_SCRIPT, binary.path), launcher
            ).strip()
            if digest != binary.digest:
                msg = f'{binary.path}: staged binary digest mismatch'
                raise SmokeCheckError(msg)
            version = _probe_output((*prefix, binary.path, '--version'), launcher)
            if not version.startswith(binary.version_prefix):
                msg = f'{binary.path}: unexpected version output: {version!r}'
                raise SmokeCheckError(msg)
            sys.stdout.write(version)


def main(argv: Sequence[str]) -> int:
    """Check a report using the workflow's expected-case environment.

    Parameters
    ----------
    argv : Sequence[str]
        One report path.

    Returns
    -------
    int
        Zero on success, one on failure, or two for invalid usage.
    """
    if len(argv) != 1:
        sys.stderr.write('usage: container_smoke_check.py REPORT_JSON\n')
        return 2
    try:
        report = Report.model_validate_json(read_small_text(Path(argv[0])))
        binaries = validate_report(report, os.environ)
        if binaries:
            verify_images(report, binaries)
    except (OSError, KeyError, ValidationError, ContainerError, FilesystemPolicyError, SmokeCheckError) as error:
        sys.stderr.write(f'{error}\n')
        return 1
    sys.stdout.write(f'container smoke OK: {report.manifest.installer}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
