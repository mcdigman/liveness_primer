# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Regression controls for the real-container CI check."""

import hashlib
import platform
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import pytest

from liveness_primer.container import (
    DEFAULT_CONTAINER_BUILDER_IMAGE,
    DEFAULT_CONTAINER_IMAGE,
    ContainerError,
    image_tag,
    ripgrep_artifact_for,
)
from liveness_primer.filesystem import atomic_write_bytes
from liveness_primer.findings import (
    CorpusPinRecord,
    DiffTotals,
    EnvironmentRecord,
    FetchRecord,
    NativeToolRecord,
    ProjectReport,
    Report,
    ToolError,
)
from liveness_primer.launcher import LaunchResult, run_sync
from scripts import container_smoke_check as smoke
from tests.test_findings import make_manifest

Tool = Literal['vulture', 'skylos']
HELPER_BYTES = b'controlled Go helper fixture'
HELPER_DIGEST = hashlib.sha256(HELPER_BYTES).hexdigest()


def smoke_environment(tmp_path: Path, tool: Tool = 'vulture') -> dict[str, str]:
    helper = tmp_path / 'skylos-go'
    atomic_write_bytes(helper, HELPER_BYTES)
    return {
        'SMOKE_TOOL': tool,
        'SMOKE_PROJECT': 'pluggy' if tool == 'vulture' else 'bubbletea',
        'SMOKE_REPO': f'https://example.invalid/{tool}',
        'SMOKE_OLD': 'a' * 40,
        'SMOKE_NEW': 'b' * 40,
        'SKYLOS_GO_BIN': str(helper),
    }


def valid_report(environ: Mapping[str, str], machine: str = 'x86_64') -> Report:
    base = EnvironmentRecord(
        ref=environ['SMOKE_OLD'],
        sha=environ['SMOKE_OLD'],
        fingerprint='a' * 64,
        freeze=(),
        from_cache=False,
        rebuilt=True,
    )
    head = base.model_copy(update={'ref': environ['SMOKE_NEW'], 'sha': environ['SMOKE_NEW'], 'fingerprint': 'b' * 64})
    installer = f'docker 28; builder {DEFAULT_CONTAINER_BUILDER_IMAGE}; runtime {DEFAULT_CONTAINER_IMAGE}'
    native_tools: tuple[NativeToolRecord, ...] = ()
    fetches: tuple[FetchRecord, ...] = ()
    if environ['SMOKE_TOOL'] == 'skylos':
        artifact = ripgrep_artifact_for(machine)
        installer += f'; ripgrep sha256:{artifact.binary_digest}; SKYLOS_GO_BIN sha256:{HELPER_DIGEST}'
        native_tools = (NativeToolRecord(variable='SKYLOS_GO_BIN', sha256=HELPER_DIGEST),)
        fetches = (
            FetchRecord(
                kind='binary',
                name=artifact.filename,
                resolved=artifact.version,
                digest=artifact.archive_digest,
            ),
        )
    manifest = make_manifest().model_copy(
        update={
            'tool': environ['SMOKE_TOOL'],
            'detector_repo': environ['SMOKE_REPO'],
            'base': base,
            'head': head,
            'base_cmd': None,
            'head_cmd': None,
            'isolation_enforced': True,
            'comparable': True,
            'installer': installer,
            'platform': f'linux-{machine}',
            'native_tools': native_tools,
            'fetches': fetches,
            'corpus_pins': (
                CorpusPinRecord(
                    name=environ['SMOKE_PROJECT'],
                    repo='https://example.invalid/project',
                    requested='c' * 40,
                    resolved_sha='c' * 40,
                ),
            ),
        }
    )
    project = ProjectReport(
        project=environ['SMOKE_PROJECT'],
        diffs=(),
        totals=DiffTotals(),
        rollups=(),
        truncated=False,
        base_findings=2,
        head_findings=2,
        measured_cost_seconds=1,
    )
    return Report(manifest=manifest, projects=(project,), totals=DiffTotals(), rollups=(), truncated=False)


@pytest.mark.parametrize('tool', ['vulture', 'skylos'])
def test_valid_report(tool: Tool, tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path, tool)
    checks = smoke.validate_report(valid_report(environ), environ)
    if tool == 'vulture':
        assert checks == ()
    else:
        assert checks == (
            smoke.BinaryCheck('/usr/bin/rg', ripgrep_artifact_for('x86_64').binary_digest, 'ripgrep '),
            smoke.BinaryCheck('/liveness/native-tools/SKYLOS_GO_BIN', HELPER_DIGEST, 'skylos-go '),
        )


@pytest.mark.parametrize('tool', ['vulture', 'skylos'])
@pytest.mark.parametrize(
    ('updates', 'message'),
    [
        ({'isolation_enforced': False}, 'isolated, comparable'),
        ({'comparable': False}, 'isolated, comparable'),
        ({'tool': 'wrong'}, 'detector identity'),
        ({'detector_repo': 'https://wrong.invalid'}, 'detector identity'),
        ({'installer': None}, 'installer is not docker'),
        ({'installer': 'podman 5'}, 'installer is not docker'),
        ({'installer': f'docker 28; {DEFAULT_CONTAINER_BUILDER_IMAGE}'}, 'absent from installer'),
        ({'installer': f'docker 28; {DEFAULT_CONTAINER_IMAGE}'}, 'absent from installer'),
    ],
)
def test_invalid_manifest(
    tool: Tool,
    updates: dict[str, str | bool | None],
    message: str,
    tmp_path: Path,
) -> None:
    environ = smoke_environment(tmp_path, tool)
    report = valid_report(environ)
    report = report.model_copy(update={'manifest': report.manifest.model_copy(update=updates)})
    with pytest.raises(smoke.SmokeCheckError, match=message):
        smoke.validate_report(report, environ)


@pytest.mark.parametrize('side', ['base', 'head'])
@pytest.mark.parametrize('updates', [None, {'sha': 'wrong'}, {'rebuilt': False}, {'from_cache': True}])
def test_invalid_environment(side: str, updates: dict[str, str | bool] | None, tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path)
    report = valid_report(environ)
    original = report.manifest.base if side == 'base' else report.manifest.head
    assert original is not None
    replacement = None if updates is None else original.model_copy(update=updates)
    report = report.model_copy(update={'manifest': report.manifest.model_copy(update={side: replacement})})
    with pytest.raises(smoke.SmokeCheckError, match='fresh environment'):
        smoke.validate_report(report, environ)


@pytest.mark.parametrize(
    ('updates', 'message'),
    [
        ({'project': 'wrong'}, 'exactly one project'),
        ({'errors': (ToolError(side='head', exit_code=2, detail='helper unavailable'),)}, 'complete successfully'),
        ({'measured_cost_seconds': None}, 'complete successfully'),
        ({'base_findings': 0}, 'expected findings'),
        ({'head_findings': 0}, 'expected findings'),
    ],
)
def test_invalid_project(
    updates: dict[str, str | int | tuple[ToolError, ...] | None],
    message: str,
    tmp_path: Path,
) -> None:
    environ = smoke_environment(tmp_path)
    report = valid_report(environ)
    project = report.projects[0].model_copy(update=updates)
    with pytest.raises(smoke.SmokeCheckError, match=message):
        smoke.validate_report(report.model_copy(update={'projects': (project,)}), environ)


@pytest.mark.parametrize('count', [0, 2])
def test_project_selection_is_exact(count: int, tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path)
    report = valid_report(environ)
    with pytest.raises(smoke.SmokeCheckError, match='exactly one project'):
        smoke.validate_report(report.model_copy(update={'projects': report.projects * count}), environ)


@pytest.mark.parametrize('updates', [None, {'name': 'wrong'}, {'requested': 'branch:main'}])
def test_invalid_corpus_provenance(updates: dict[str, str] | None, tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path)
    report = valid_report(environ)
    pins = () if updates is None else (report.manifest.corpus_pins[0].model_copy(update=updates),)
    report = report.model_copy(update={'manifest': report.manifest.model_copy(update={'corpus_pins': pins})})
    with pytest.raises(smoke.SmokeCheckError, match=r'corpus provenance|immutable corpus pin'):
        smoke.validate_report(report, environ)


@pytest.mark.parametrize(
    'tools',
    [
        (),
        (NativeToolRecord(variable='SKYLOS_GO_BIN', sha256='0' * 64),),
        (NativeToolRecord(variable='WRONG', sha256=HELPER_DIGEST),),
    ],
)
def test_helper_admission(tools: tuple[NativeToolRecord, ...], tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path, 'skylos')
    report = valid_report(environ)
    report = report.model_copy(update={'manifest': report.manifest.model_copy(update={'native_tools': tools})})
    with pytest.raises(smoke.SmokeCheckError, match='not admitted'):
        smoke.validate_report(report, environ)


@pytest.mark.parametrize(
    'updates',
    [
        None,
        {'kind': 'wheel'},
        {'name': 'wrong'},
        {'resolved': 'wrong'},
        {'digest': '0' * 64},
    ],
)
def test_ripgrep_fetch_provenance(updates: dict[str, str] | None, tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path, 'skylos')
    report = valid_report(environ)
    fetches = () if updates is None else (report.manifest.fetches[0].model_copy(update=updates),)
    report = report.model_copy(update={'manifest': report.manifest.model_copy(update={'fetches': fetches})})
    with pytest.raises(smoke.SmokeCheckError, match='ripgrep download provenance'):
        smoke.validate_report(report, environ)


@pytest.mark.parametrize('binary', ['ripgrep', 'helper'])
def test_binary_installer_identity(binary: str, tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path, 'skylos')
    report = valid_report(environ)
    digest = HELPER_DIGEST if binary == 'helper' else ripgrep_artifact_for('x86_64').binary_digest
    assert report.manifest.installer is not None
    installer = report.manifest.installer.replace(digest, 'wrong')
    report = report.model_copy(update={'manifest': report.manifest.model_copy(update={'installer': installer})})
    with pytest.raises(smoke.SmokeCheckError, match='digest absent from installer'):
        smoke.validate_report(report, environ)


@pytest.mark.parametrize('binary', ['ripgrep', 'helper'])
def test_vulture_rejects_auxiliary_binaries(binary: str, tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path)
    report = valid_report(environ)
    skylos = valid_report(smoke_environment(tmp_path, 'skylos'))
    manifest = report.manifest.model_copy(
        update={
            'native_tools': skylos.manifest.native_tools if binary == 'helper' else (),
            'fetches': skylos.manifest.fetches if binary == 'ripgrep' else (),
        }
    )
    with pytest.raises(smoke.SmokeCheckError, match='without auxiliary binaries'):
        smoke.validate_report(report.model_copy(update={'manifest': manifest}), environ)


@pytest.mark.parametrize(('host', 'runtime'), [('x86_64', 'aarch64'), ('aarch64', 'x86_64')])
def test_ripgrep_follows_runtime_not_host(
    host: str,
    runtime: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, 'machine', lambda: host)
    environ = smoke_environment(tmp_path, 'skylos')
    checks = smoke.validate_report(valid_report(environ, runtime), environ)
    assert checks[0].digest == ripgrep_artifact_for(runtime).binary_digest
    assert checks[0].digest != ripgrep_artifact_for(host).binary_digest


def test_unsupported_runtime_fails_closed(tmp_path: Path) -> None:
    environ = smoke_environment(tmp_path, 'skylos')
    report = valid_report(environ)
    manifest = report.manifest.model_copy(update={'platform': 'linux-unknown'})
    with pytest.raises(ContainerError, match='no pinned ripgrep artifact'):
        smoke.validate_report(report.model_copy(update={'manifest': manifest}), environ)


@dataclass
class ProbeLauncher:
    """Record Docker commands and return controlled digest/version output."""

    outputs: list[str]
    returncode: int | None = 0
    timed_out: bool = False
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        """Return the next scripted result.

        Returns
        -------
        LaunchResult
            Controlled probe output and status.
        """
        assert cwd is None
        assert env is None
        assert timeout == 60
        self.calls.append(tuple(argv))
        return LaunchResult(
            argv=tuple(argv),
            returncode=self.returncode,
            stdout=self.outputs.pop(0),
            stderr='probe stderr',
            duration_seconds=0,
            timed_out=self.timed_out,
        )


def test_image_probes_check_both_binaries_on_both_sides(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    environ = smoke_environment(tmp_path, 'skylos')
    report = valid_report(environ)
    checks = smoke.validate_report(report, environ)
    outputs = [value for check in checks for value in (check.digest + '\n', check.version_prefix + '1\n')] * 2
    launcher = ProbeLauncher(outputs)
    smoke.verify_images(report, checks, launcher=launcher)
    assert len(launcher.calls) == 8
    assert launcher.outputs == []
    for side, calls in zip(
        (report.manifest.base, report.manifest.head), (launcher.calls[:4], launcher.calls[4:]), strict=True
    ):
        assert side is not None
        for call in calls:
            assert image_tag(side.fingerprint) in call
            assert call[:4] == ('docker', 'run', '--rm', '--network')
            assert call[call.index('--network') + 1] == 'none'
            assert '--read-only' in call
            assert call[call.index('--cap-drop') + 1] == 'ALL'
            assert call[call.index('--user') + 1] == '65532:65532'
            assert call[call.index('--security-opt') + 1] == 'no-new-privileges'
        for check, digest_call, version_call in zip(checks, calls[::2], calls[1::2], strict=True):
            assert digest_call[-4:] == ('/liveness/venv/bin/python', '-c', smoke.HASH_FILE_SCRIPT, check.path)
            assert version_call[-2:] == (check.path, '--version')
    assert capsys.readouterr().out == 'ripgrep 1\nskylos-go 1\n' * 2


@pytest.mark.parametrize(
    ('outputs', 'message'),
    [
        (['wrong'], 'digest mismatch'),
        (['correct', 'wrong version'], 'unexpected version output'),
    ],
)
def test_bad_image_binary(outputs: list[str], message: str, tmp_path: Path) -> None:
    report = valid_report(smoke_environment(tmp_path))
    launcher = ProbeLauncher(outputs.copy())
    with pytest.raises(smoke.SmokeCheckError, match=message):
        smoke.verify_images(report, (smoke.BinaryCheck('/bin/tool', 'correct', 'expected '),), launcher=launcher)


@pytest.mark.parametrize(('returncode', 'timed_out'), [(1, False), (None, True)])
def test_failed_image_probe(returncode: int | None, *, timed_out: bool, tmp_path: Path) -> None:
    report = valid_report(smoke_environment(tmp_path))
    launcher = ProbeLauncher([''], returncode=returncode, timed_out=timed_out)
    with pytest.raises(smoke.SmokeCheckError, match='probe failed: probe stderr'):
        smoke.verify_images(report, (smoke.BinaryCheck('/bin/tool', 'digest', 'version'),), launcher=launcher)
    assert len(launcher.calls) == 1


def test_absent_image_environment(tmp_path: Path) -> None:
    report = valid_report(smoke_environment(tmp_path))
    report = report.model_copy(update={'manifest': report.manifest.model_copy(update={'base': None})})
    with pytest.raises(smoke.SmokeCheckError, match='missing detector environment'):
        smoke.verify_images(report, ())


def test_no_binary_probes_for_empty_expectations(tmp_path: Path) -> None:
    launcher = ProbeLauncher([])
    smoke.verify_images(valid_report(smoke_environment(tmp_path)), (), launcher=launcher)
    assert launcher.calls == []


def test_hash_script_reads_real_binary_bytes(tmp_path: Path) -> None:
    binary = tmp_path / 'binary'
    binary.write_bytes(b'\x00\xff\x80fixture\n')
    result = run_sync([sys.executable, '-c', smoke.HASH_FILE_SCRIPT, str(binary)])
    assert result.ok
    assert result.stdout.strip() == hashlib.sha256(binary.read_bytes()).hexdigest()
    missing = run_sync([sys.executable, '-c', smoke.HASH_FILE_SCRIPT, str(tmp_path / 'missing')])
    assert not missing.ok
    assert 'FileNotFoundError' in missing.stderr


@pytest.mark.parametrize('tool', ['vulture', 'skylos'])
def test_main_success(
    tool: Tool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environ = smoke_environment(tmp_path, tool)
    report = valid_report(environ)
    report_path = tmp_path / 'report.json'
    report_path.write_text(report.model_dump_json(), encoding='utf-8')
    for key, value in environ.items():
        monkeypatch.setenv(key, value)
    calls: list[tuple[smoke.BinaryCheck, ...]] = []

    def verify(parsed: Report, binaries: Sequence[smoke.BinaryCheck]) -> None:
        assert parsed == report
        calls.append(tuple(binaries))

    monkeypatch.setattr(smoke, 'verify_images', verify)
    assert smoke.main([str(report_path)]) == 0
    assert len(calls) == (1 if tool == 'skylos' else 0)
    assert 'container smoke OK: docker' in capsys.readouterr().out


@pytest.mark.parametrize('argv', [[], ['one', 'two']])
def test_main_usage(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert smoke.main(argv) == 2
    assert 'usage:' in capsys.readouterr().err


@pytest.mark.parametrize(
    'failure', ['missing file', 'malformed json', 'invalid report', 'missing env', 'missing helper', 'architecture']
)
def test_main_failures(
    failure: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    environ = smoke_environment(tmp_path, 'skylos')
    report = valid_report(environ)
    for key, value in environ.items():
        monkeypatch.setenv(key, value)
    path = tmp_path / 'report.json'
    if failure == 'missing env':
        monkeypatch.delenv('SMOKE_TOOL')
    if failure == 'missing helper':
        Path(environ['SKYLOS_GO_BIN']).unlink()
    if failure == 'invalid report':
        report = report.model_copy(update={'projects': ()})
    if failure == 'architecture':
        report = report.model_copy(
            update={'manifest': report.manifest.model_copy(update={'platform': 'linux-unknown'})}
        )
    if failure != 'missing file':
        path.write_text('{' if failure == 'malformed json' else report.model_dump_json(), encoding='utf-8')
    assert smoke.main([str(path)]) == 1
    captured = capsys.readouterr()
    assert captured.err
    assert not captured.out
