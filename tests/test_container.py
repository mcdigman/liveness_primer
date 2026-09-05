# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the container-backed detector environments (contract §3, §11, §15)."""

import hashlib
import os
import shutil
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Literal, cast

import pytest
from filelock import FileLock

import liveness_primer.container as container_module
from liveness_primer.container import (
    CONTAINER_ISOLATION,
    CONTAINER_TMP_ROOT,
    CONTAINER_WORK_ROOT,
    DEFAULT_CONTAINER_BUILDER_IMAGE,
    DEFAULT_CONTAINER_IMAGE,
    ContainerEnvironments,
    ContainerError,
    ContainerExecution,
    ContainerNativeTool,
    DockerCli,
    DockerRuntime,
    StaticBinaryArtifact,
    container_fingerprint,
    container_user,
    image_tag,
    promote_prefetched,
    ripgrep_artifact_for,
    stage_container_native_tool,
    stage_invocation_env_files,
    stage_static_binary,
    stage_wheelhouses,
    validate_container_native_tool_platform,
)
from liveness_primer.corpus import CheckoutStore
from liveness_primer.execution import SideWorkspace
from liveness_primer.filesystem import atomic_write_bytes, atomic_write_text, read_small_text
from liveness_primer.findings import DependencyDelta
from liveness_primer.launcher import LauncherError, SyncLauncher, run_async
from liveness_primer.tools.skylos import SkylosAdapter
from liveness_primer.tools.vulture import VultureAdapter
from tests.test_envcache import (
    FREEZE_A,
    FREEZE_B,
    FREEZE_BUMPED,
    DetectorRepo,
    RecordingLauncher,
    detector_repo,
    git,
)

__all__ = ['detector_repo']

if TYPE_CHECKING:
    from liveness_primer.tools.base import RuntimeBinary


def test_default_container_images_are_digest_pinned_chainguard_pair() -> None:
    assert DEFAULT_CONTAINER_BUILDER_IMAGE.startswith('cgr.dev/chainguard/python:latest-dev@sha256:')
    assert DEFAULT_CONTAINER_IMAGE.startswith('cgr.dev/chainguard/python:latest@sha256:')


def test_docker_cli_rejects_async_launcher() -> None:
    with pytest.raises(LauncherError, match='launcher must be synchronous'):
        DockerCli(launcher=cast('SyncLauncher', run_async))


def test_identity_parses_server_version() -> None:
    launcher = RecordingLauncher(stdout='27.5.1\n')
    assert DockerCli(launcher=launcher).identity() == 'docker 27.5.1'
    (argv,) = launcher.calls
    assert argv == ('docker', 'version', '--format', '{{.Server.Version}}')


@pytest.mark.parametrize(
    ('launcher', 'detail'),
    [
        (RecordingLauncher(returncode=1), 'boom'),
        (RecordingLauncher(stdout='   '), 'no version reported'),
        (RecordingLauncher(timed_out=True), 'timed out'),
    ],
)
def test_identity_requires_a_daemon(launcher: RecordingLauncher, detail: str) -> None:
    with pytest.raises(ContainerError, match=f'requires a running Docker daemon.*{detail}'):
        DockerCli(launcher=launcher).identity()


def test_image_exists_reflects_inspect() -> None:
    assert DockerCli(launcher=RecordingLauncher(stdout='sha256:abc')).image_exists('t:1') is True
    launcher = RecordingLauncher(returncode=1)
    assert DockerCli(launcher=launcher).image_exists('t:1') is False
    (argv,) = launcher.calls
    assert argv == ('docker', 'image', 'inspect', '--format', '{{.Id}}', 't:1')


def test_build_image_argv_is_offline(tmp_path: Path) -> None:
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).build_image('t:1', tmp_path, fresh=False)
    (argv,) = launcher.calls
    assert argv == ('docker', 'build', '--network', 'none', '--quiet', '--tag', 't:1', str(tmp_path))


def test_build_image_fresh_bypasses_the_layer_cache(tmp_path: Path) -> None:
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).build_image('t:1', tmp_path, fresh=True)
    (argv,) = launcher.calls
    assert '--no-cache' in argv
    with pytest.raises(ContainerError, match='docker build failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).build_image('t:1', tmp_path, fresh=True)


def test_architecture_queries_the_builder_image_offline() -> None:
    launcher = RecordingLauncher(stdout='aarch64\n')
    assert DockerCli(launcher=launcher).architecture('builder:1') == 'aarch64'
    run_argv, rm_argv = launcher.calls
    assert run_argv[run_argv.index('--network') + 1] == 'none'
    assert not run_argv[run_argv.index('--entrypoint') + 1]
    assert 'builder:1' in run_argv
    name = run_argv[run_argv.index('--name') + 1]
    assert name.startswith('liveness-primer-arch-')
    assert rm_argv == ('docker', 'rm', '--force', name)
    with pytest.raises(ContainerError, match='container architecture probe failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).architecture('builder:1')


def test_platform_queries_the_runtime_image_offline() -> None:
    launcher = RecordingLauncher(stdout='linux-aarch64\n')
    assert DockerCli(launcher=launcher).platform('runtime:1') == 'linux-aarch64'
    run_argv, rm_argv = launcher.calls
    assert run_argv[run_argv.index('--network') + 1] == 'none'
    assert 'runtime:1' in run_argv
    assert 'sysconfig.get_platform()' in run_argv[-1]
    name = run_argv[run_argv.index('--name') + 1]
    assert name.startswith('liveness-primer-platform-')
    assert rm_argv == ('docker', 'rm', '--force', name)
    with pytest.raises(ContainerError, match='container platform probe failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).platform('runtime:1')


def assert_hardened(argv: tuple[str, ...]) -> None:
    assert argv[argv.index('--cap-drop') + 1] == 'ALL'
    assert argv[argv.index('--security-opt') + 1] == 'no-new-privileges'
    assert argv[argv.index('--pids-limit') + 1] == '4096'
    assert '--read-only' in argv
    assert argv[argv.index('--tmpfs') + 1] == str(CONTAINER_TMP_ROOT)


def test_prefetch_runs_pip_download_in_the_base_image(tmp_path: Path) -> None:
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).prefetch('python:3.12-slim', ('tomli>=2',), tmp_path)
    run_argv, rm_argv = launcher.calls
    assert run_argv[:3] == ('docker', 'run', '--rm')
    name = run_argv[run_argv.index('--name') + 1]
    assert name.startswith('liveness-primer-fetch-')
    # The fetch container is tracked: a client-side timeout cannot leave an
    # anonymous container running.
    assert rm_argv == ('docker', 'rm', '--force', name)
    assert_hardened(run_argv)
    assert not run_argv[run_argv.index('--entrypoint') + 1]
    assert run_argv[run_argv.index('--user') + 1] == container_user()
    assert f'{tmp_path}:/liveness/wheelhouse' in run_argv
    assert run_argv[run_argv.index('--env') + 1] == f'HOME={CONTAINER_TMP_ROOT}'
    assert run_argv[-1] == 'tomli>=2'
    assert 'python:3.12-slim' in run_argv
    failing = RecordingLauncher(returncode=1)
    with pytest.raises(ContainerError, match='dependency prefetch'):
        DockerCli(launcher=failing).prefetch('python:3.12-slim', ('tomli>=2',), tmp_path)
    # The tracked cleanup still runs on the failure path.
    assert failing.calls[-1][:3] == ('docker', 'rm', '--force')


def test_prefetch_without_posix_ids_omits_the_user_mapping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, 'getuid')
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).prefetch('python:3.12-slim', ('tomli>=2',), tmp_path)
    run_argv = launcher.calls[0]
    assert '--user' not in run_argv


def test_prefetch_mounts_find_links_read_only(tmp_path: Path) -> None:
    base_links = tmp_path / 'base-wheels'
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).prefetch('python:3.12-slim', ('tomli>=2.1',), tmp_path, find_links=base_links)
    run_argv = launcher.calls[0]
    # The base wheelhouse is offered read-only for reuse, never writable.
    assert f'{base_links}:/liveness/base-links:ro' in run_argv
    assert run_argv[run_argv.index('--find-links') + 1] == '/liveness/base-links'


def test_prefetch_static_binary_uses_artifact_executable_name(tmp_path: Path) -> None:
    payload = b'static-helper'
    executable = cast('RuntimeBinary', 'helper')
    artifact = StaticBinaryArtifact(
        name='helper-tool',
        executable=executable,
        version='1.2.3',
        architecture='aarch64',
        filename='helper.tar.gz',
        url='https://example.invalid/helper.tar.gz',
        archive_digest='a' * 64,
        member='helper/bin/helper',
        binary_digest=hashlib.sha256(payload).hexdigest(),
    )
    target = tmp_path / executable
    atomic_write_bytes(target, payload)
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).prefetch_static_binary('builder:1', artifact, tmp_path)
    run_argv, rm_argv = launcher.calls
    assert f'{tmp_path}:/liveness/tool' in run_argv
    assert '--network' not in run_argv
    assert artifact.url in run_argv
    assert artifact.archive_digest in run_argv
    assert artifact.binary_digest in run_argv
    assert executable in run_argv
    name = run_argv[run_argv.index('--name') + 1]
    assert name.startswith('liveness-primer-static-binary-fetch-')
    assert rm_argv == ('docker', 'rm', '--force', name)
    assert target.stat().st_mode & 0o777 == 0o555


def test_prefetch_static_binary_rejects_failed_or_invalid_output(tmp_path: Path) -> None:
    payload = b'static-ripgrep'
    artifact = StaticBinaryArtifact(
        name='ripgrep',
        executable='rg',
        version='1.2.3',
        architecture='aarch64',
        filename='ripgrep.tar.gz',
        url='https://example.invalid/ripgrep.tar.gz',
        archive_digest='a' * 64,
        member='ripgrep/rg',
        binary_digest=hashlib.sha256(payload).hexdigest(),
    )
    with pytest.raises(ContainerError, match='ripgrep prefetch failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).prefetch_static_binary('builder:1', artifact, tmp_path)
    with pytest.raises(ContainerError, match='did not produce rg'):
        DockerCli(launcher=RecordingLauncher()).prefetch_static_binary('builder:1', artifact, tmp_path)
    target = tmp_path / 'rg'
    atomic_write_bytes(target, b'tampered')
    with pytest.raises(ContainerError, match='static binary rg digest mismatch'):
        DockerCli(launcher=RecordingLauncher()).prefetch_static_binary('builder:1', artifact, tmp_path)
    target.unlink()
    target.mkdir()
    with pytest.raises(ContainerError, match='non-regular rg'):
        DockerCli(launcher=RecordingLauncher()).prefetch_static_binary('builder:1', artifact, tmp_path)
    target.rmdir()
    payload_path = tmp_path / 'payload'
    atomic_write_bytes(payload_path, payload)
    target.symlink_to(payload_path)
    with pytest.raises(ContainerError, match='non-regular rg'):
        DockerCli(launcher=RecordingLauncher()).prefetch_static_binary('builder:1', artifact, tmp_path)


def test_freeze_parses_lines() -> None:
    launcher = RecordingLauncher(stdout='tomli==2.4.0\n\nvulture @ file:///x\n')
    assert DockerCli(launcher=launcher).freeze('t:1') == ('tomli==2.4.0', 'vulture @ file:///x')
    run_argv, rm_argv = launcher.calls
    assert run_argv[:3] == ('docker', 'run', '--rm')
    name = run_argv[run_argv.index('--name') + 1]
    assert name.startswith('liveness-primer-freeze-')
    assert rm_argv == ('docker', 'rm', '--force', name)
    assert run_argv[run_argv.index('--network') + 1] == 'none'
    assert_hardened(run_argv)
    assert run_argv[-3:-1] == ('python', '-c')
    assert '/liveness/freeze.txt' in run_argv[-1]
    assert 't:1' in run_argv
    with pytest.raises(ContainerError, match='environment freeze failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).freeze('t:1')


def test_python_version_queries_the_image_offline() -> None:
    launcher = RecordingLauncher(stdout='3.12.5\n')
    assert DockerCli(launcher=launcher).python_version('t:1') == '3.12.5'
    run_argv, rm_argv = launcher.calls
    assert run_argv[:3] == ('docker', 'run', '--rm')
    assert run_argv[run_argv.index('--network') + 1] == 'none'
    name = run_argv[run_argv.index('--name') + 1]
    assert name.startswith('liveness-primer-pyver-')
    assert rm_argv == ('docker', 'rm', '--force', name)
    assert_hardened(run_argv)
    assert 't:1' in run_argv
    with pytest.raises(ContainerError, match='container python version failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).python_version('t:1')


def test_environment_python_version_uses_the_exact_venv_interpreter() -> None:
    launcher = RecordingLauncher(stdout='3.14.7\n')
    assert DockerCli(launcher=launcher).environment_python_version('t:1') == '3.14.7'
    run_argv, rm_argv = launcher.calls
    assert run_argv[run_argv.index('--network') + 1] == 'none'
    assert run_argv[-3] == '/liveness/venv/bin/python'
    name = run_argv[run_argv.index('--name') + 1]
    assert name.startswith('liveness-primer-env-pyver-')
    assert rm_argv == ('docker', 'rm', '--force', name)
    with pytest.raises(ContainerError, match='environment interpreter probe failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).environment_python_version('t:1')


def test_remove_container_reports_the_outcome() -> None:
    launcher = RecordingLauncher()
    assert DockerCli(launcher=launcher).remove_container('primer-base') is True
    (argv,) = launcher.calls
    assert argv == ('docker', 'rm', '--force', 'primer-base')
    assert DockerCli(launcher=RecordingLauncher(returncode=1)).remove_container('primer-base') is False
    # An already-absent container counts as confirmed removal.
    gone = RecordingLauncher(returncode=1, stderr_text='Error response from daemon: No such container: primer-base')
    assert DockerCli(launcher=gone).remove_container('primer-base') is True


def test_container_user_maps_posix_ids() -> None:
    assert container_user() == f'{os.getuid()}:{os.getgid()}'


def test_container_user_without_posix_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, 'getuid')
    assert container_user() is None


def test_container_fingerprint_varies_by_inputs() -> None:
    adapter = VultureAdapter()
    base = container_fingerprint('https://r', 'a' * 40, adapter, 'docker 27', 'builder:1', 'runtime:1', ('ripgrep:1',))
    assert base == container_fingerprint(
        'https://r', 'a' * 40, adapter, 'docker 27', 'builder:1', 'runtime:1', ('ripgrep:1',)
    )
    assert base != container_fingerprint(
        'https://other', 'a' * 40, adapter, 'docker 27', 'builder:1', 'runtime:1', ('ripgrep:1',)
    )
    assert base != container_fingerprint(
        'https://r', 'b' * 40, adapter, 'docker 27', 'builder:1', 'runtime:1', ('ripgrep:1',)
    )
    assert base != container_fingerprint(
        'https://r', 'a' * 40, adapter, 'docker 28', 'builder:1', 'runtime:1', ('ripgrep:1',)
    )
    assert base != container_fingerprint(
        'https://r', 'a' * 40, adapter, 'docker 27', 'builder:2', 'runtime:1', ('ripgrep:1',)
    )
    assert base != container_fingerprint(
        'https://r', 'a' * 40, adapter, 'docker 27', 'builder:1', 'runtime:2', ('ripgrep:1',)
    )
    assert base != container_fingerprint(
        'https://r', 'a' * 40, adapter, 'docker 27', 'builder:1', 'runtime:1', ('ripgrep:2',)
    )
    assert base != container_fingerprint(
        'https://r',
        'a' * 40,
        adapter,
        'docker 27',
        'builder:1',
        'runtime:1',
        ('ripgrep:1',),
        ('SKYLOS_GO_BIN sha256:1234',),
    )


def test_container_fingerprint_tracks_the_cache_format(monkeypatch: pytest.MonkeyPatch) -> None:
    # A cache-format / security revision must make every prior image miss the
    # cache and rebuild, so it participates in the fingerprint material.
    adapter = VultureAdapter()
    before = container_fingerprint(
        'https://r', 'a' * 40, adapter, 'docker 27', 'builder:1', 'runtime:1', ('ripgrep:1',)
    )
    monkeypatch.setattr(container_module, '_CONTAINER_CACHE_FORMAT', 999)
    assert before != container_fingerprint(
        'https://r', 'a' * 40, adapter, 'docker 27', 'builder:1', 'runtime:1', ('ripgrep:1',)
    )


def test_image_tag_embeds_the_fingerprint() -> None:
    assert image_tag('abc123') == 'liveness-primer/env:abc123'


@pytest.mark.parametrize(
    ('machine', 'architecture'),
    [('x86_64', 'x86_64'), ('amd64', 'x86_64'), ('aarch64', 'aarch64'), ('arm64', 'aarch64')],
)
def test_ripgrep_artifact_for_supported_architectures(machine: str, architecture: str) -> None:
    artifact = ripgrep_artifact_for(machine)
    assert artifact.architecture == architecture
    assert artifact.url.startswith('https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/')
    assert len(artifact.archive_digest) == 64
    assert len(artifact.binary_digest) == 64


def test_ripgrep_artifact_for_rejects_unsupported_architecture() -> None:
    with pytest.raises(ContainerError, match="architecture 's390x' has no pinned ripgrep artifact"):
        ripgrep_artifact_for('s390x')


def write_linux_elf(
    path: Path,
    architecture: Literal['aarch64', 'x86_64'],
    *,
    elf_type: int = 2,
    os_abi: int = 0,
) -> Path:
    """Write the ELF header prefix used by native-helper admission tests.

    Returns
    -------
    Path
        Executable test-file path.
    """
    machine = {'x86_64': 62, 'aarch64': 183}[architecture]
    header = bytearray(20)
    header[:7] = b'\x7fELF\x02\x01\x01'
    header[7] = os_abi
    header[16:18] = elf_type.to_bytes(2, byteorder='little')
    header[18:20] = machine.to_bytes(2, byteorder='little')
    atomic_write_bytes(path, bytes(header))
    path.chmod(0o755)
    return path


def test_stage_static_binary_copies_only_a_regular_file(tmp_path: Path) -> None:
    source = tmp_path / 'source' / 'rg'
    source.parent.mkdir()
    atomic_write_bytes(source, b'ripgrep')
    destination = tmp_path / 'context' / 'rg'
    stage_static_binary(source, destination)
    assert destination.read_bytes() == b'ripgrep'
    assert destination.stat().st_mode & 0o777 == 0o555
    with pytest.raises(ContainerError, match='static binary is missing'):
        stage_static_binary(tmp_path / 'missing', tmp_path / 'unused' / 'rg')
    symlink = tmp_path / 'linked-rg'
    symlink.symlink_to(source)
    with pytest.raises(ContainerError, match='static binary is not a regular file'):
        stage_static_binary(symlink, tmp_path / 'unused' / 'rg')
    directory = tmp_path / 'directory-rg'
    directory.mkdir()
    with pytest.raises(ContainerError, match='static binary is not a regular file'):
        stage_static_binary(directory, tmp_path / 'unused' / 'rg')


def test_stage_static_binaries_share_one_tools_directory(tmp_path: Path) -> None:
    first = tmp_path / 'source' / 'first'
    second = tmp_path / 'source' / 'second'
    first.parent.mkdir()
    atomic_write_bytes(first, b'first')
    atomic_write_bytes(second, b'second')
    tools = tmp_path / 'context' / 'tools'
    tools.parent.mkdir()
    stage_static_binary(first, tools / 'first')
    stage_static_binary(second, tools / 'second')
    assert (tools / 'first').read_bytes() == b'first'
    assert (tools / 'second').read_bytes() == b'second'


def test_stage_container_native_tool_revalidates_the_admitted_digest(tmp_path: Path) -> None:
    source = tmp_path / 'skylos-go'
    atomic_write_bytes(source, b'go-engine')
    source.chmod(0o755)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    tool = ContainerNativeTool(variable='SKYLOS_GO_BIN', source=source, sha256=digest)

    destination = tmp_path / 'context' / 'native-tools' / tool.variable
    stage_container_native_tool(tool, destination)
    assert destination.read_bytes() == b'go-engine'
    assert destination.stat().st_mode & 0o777 == 0o555
    assert tool.container_path == PurePosixPath('/liveness/native-tools/SKYLOS_GO_BIN')
    assert tool.identity == f'SKYLOS_GO_BIN sha256:{digest}'

    atomic_write_bytes(source, b'changed-engine')
    with pytest.raises(ContainerError, match='SKYLOS_GO_BIN changed after admission'):
        stage_container_native_tool(tool, tmp_path / 'second-context' / tool.variable)


def test_stage_container_native_tool_names_an_invalid_operator_source(tmp_path: Path) -> None:
    missing = tmp_path / 'skylos-go'
    tool = ContainerNativeTool(variable='SKYLOS_GO_BIN', source=missing, sha256='a' * 64)
    with pytest.raises(ContainerError, match='native helper SKYLOS_GO_BIN is missing: skylos-go'):
        stage_container_native_tool(tool, tmp_path / 'context' / tool.variable)

    target = tmp_path / 'engine'
    atomic_write_bytes(target, b'engine')
    missing.symlink_to(target)
    with pytest.raises(ContainerError, match='native helper SKYLOS_GO_BIN is not a regular file: skylos-go'):
        stage_container_native_tool(tool, tmp_path / 'context' / tool.variable)


@pytest.mark.parametrize('machine', ['aarch64', 'arm64'])
def test_validate_container_native_tool_accepts_matching_linux_elf(tmp_path: Path, machine: str) -> None:
    source = write_linux_elf(tmp_path / 'skylos-go', 'aarch64')
    tool = ContainerNativeTool(
        variable='SKYLOS_GO_BIN', source=source, sha256=hashlib.sha256(source.read_bytes()).hexdigest()
    )
    validate_container_native_tool_platform(tool, machine)


@pytest.mark.parametrize(
    ('payload', 'detail'),
    [
        (b'', 'not a supported 64-bit Linux ELF executable'),
        (b'x' * 20, 'not a supported 64-bit Linux ELF executable'),
    ],
)
def test_validate_container_native_tool_rejects_invalid_elf(tmp_path: Path, payload: bytes, detail: str) -> None:
    source = tmp_path / 'skylos-go'
    atomic_write_bytes(source, payload)
    tool = ContainerNativeTool(variable='SKYLOS_GO_BIN', source=source, sha256=hashlib.sha256(payload).hexdigest())
    with pytest.raises(ContainerError, match=detail):
        validate_container_native_tool_platform(tool, 'aarch64')


@pytest.mark.parametrize(('elf_type', 'os_abi'), [(2, 9), (1, 0)])
def test_validate_container_native_tool_rejects_non_executable_or_non_linux_elf(
    tmp_path: Path, elf_type: int, os_abi: int
) -> None:
    source = write_linux_elf(tmp_path / 'skylos-go', 'aarch64', elf_type=elf_type, os_abi=os_abi)
    tool = ContainerNativeTool(
        variable='SKYLOS_GO_BIN', source=source, sha256=hashlib.sha256(source.read_bytes()).hexdigest()
    )
    with pytest.raises(ContainerError, match='not a supported 64-bit Linux ELF executable'):
        validate_container_native_tool_platform(tool, 'aarch64')


def test_validate_container_native_tool_rejects_wrong_or_unsupported_architecture(tmp_path: Path) -> None:
    source = write_linux_elf(tmp_path / 'skylos-go', 'x86_64')
    tool = ContainerNativeTool(
        variable='SKYLOS_GO_BIN', source=source, sha256=hashlib.sha256(source.read_bytes()).hexdigest()
    )
    with pytest.raises(ContainerError, match='targets x86_64, not container architecture aarch64'):
        validate_container_native_tool_platform(tool, 'aarch64')
    with pytest.raises(ContainerError, match="container architecture 's390x' cannot admit native helpers"):
        validate_container_native_tool_platform(tool, 's390x')


def test_validate_container_native_tool_wraps_read_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = write_linux_elf(tmp_path / 'skylos-go', 'aarch64')
    tool = ContainerNativeTool(
        variable='SKYLOS_GO_BIN', source=source, sha256=hashlib.sha256(source.read_bytes()).hexdigest()
    )

    def deny_open(_path: Path, _mode: str) -> None:
        message = 'denied'
        raise PermissionError(message)

    monkeypatch.setattr(Path, 'open', deny_open)
    with pytest.raises(ContainerError, match='cannot read native helper SKYLOS_GO_BIN: denied'):
        validate_container_native_tool_platform(tool, 'aarch64')


def requirement_wheel(requirement: str) -> str:
    """Map a requirement string to the wheel filename the fake resolves it to.

    Every version of a package resolves to one fixed wheel name, so the base
    and head fetches of the same package produce the same filename — which is
    what lets the head fetch reuse (and the promotion exclude) it.

    Parameters
    ----------
    requirement : str
        A PEP 508 requirement string.

    Returns
    -------
    str
        The scripted wheel filename.
    """
    package = requirement
    for separator in ('>=', '<=', '==', '!=', '~=', '<', '>', ' '):
        package = package.split(separator)[0]
    return f'{package}-1.0-py3-none-any.whl'


@dataclass
class FakeDocker:
    """Scripted Docker runtime recording every operation (contract §15)."""

    binary: str = 'docker'
    freezes: deque[tuple[str, ...]] = field(default_factory=deque)
    always_cached: bool = False
    remove_ok: bool = True
    wheel_symlink_target: Path | None = None
    ripgrep_symlink_target: Path | None = None
    architectures: dict[str, str] = field(default_factory=dict)
    python_versions: dict[str, str] = field(default_factory=dict)
    environment_python_version_value: str = '3.14.99'
    platform_value: str = 'linux-aarch64'
    # Files a head-side build hook fabricates during the head fetch (the
    # fetch with a find_links source); each maps a filename to its bytes.
    fabricate: dict[str, bytes] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)
    existing_images: set[str] = field(default_factory=set)
    prefetches: list[tuple[str, tuple[str, ...], Path | None]] = field(default_factory=list)
    ripgrep_prefetches: list[tuple[str, StaticBinaryArtifact]] = field(default_factory=list)
    ripgrep_destinations: list[Path] = field(default_factory=list)
    staging_paths: list[Path] = field(default_factory=list)
    built: list[tuple[str, bool]] = field(default_factory=list)
    built_contexts: list[tuple[tuple[str, ...], str]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    def identity(self) -> str:
        """Report a fixed identity.

        Returns
        -------
        str
            ``docker 99.9``.
        """
        self.events.append('identity')
        return 'docker 99.9'

    def image_exists(self, tag: str) -> bool:
        """Report the scripted cache state.

        Returns
        -------
        bool
            True when caching is forced or the tag was built.
        """
        self.events.append('inspect')
        return self.always_cached or tag in self.existing_images

    def architecture(self, image: str) -> str:
        """Report a fixed builder architecture.

        Returns
        -------
        str
            ``aarch64``.
        """
        self.events.append('arch')
        return self.architectures.get(image, 'aarch64')

    def platform(self, image: str) -> str:
        """Report a fixed container platform tag.

        Returns
        -------
        str
            ``linux-aarch64`` unless scripted otherwise.
        """
        del image
        self.events.append('platform')
        return self.platform_value

    def build_image(self, tag: str, context: Path, *, fresh: bool) -> None:
        """Record the build and remember the context contents."""
        self.events.append('build')
        self.built.append((tag, fresh))
        names = tuple(sorted(str(entry.relative_to(context)) for entry in context.rglob('*')))
        self.built_contexts.append((names, read_small_text(context / 'Dockerfile')))
        self.existing_images.add(tag)

    def prefetch(
        self, image: str, requirements: Sequence[str], destination: Path, *, find_links: Path | None = None
    ) -> None:
        """Record the request and materialize scripted wheel files.

        Every resolved requirement's wheel is written into the staging
        destination — including ones a real ``pip download`` would copy back
        from the read-only ``find_links`` source — so the promotion's
        exclusion of base-owned names is exercised. A head fetch (the one
        with a ``find_links`` source) additionally writes any fabricated
        files, modelling an untrusted build hook.
        """
        self.events.append('prefetch')
        self.prefetches.append((image, tuple(requirements), find_links))
        self.staging_paths.append(destination)
        for requirement in requirements:
            wheel = requirement_wheel(requirement)
            if self.wheel_symlink_target is None:
                atomic_write_bytes(destination / wheel, b'payload-' + wheel.encode('utf-8'))
            else:
                (destination / wheel).symlink_to(self.wheel_symlink_target)
        if find_links is not None:
            for name, payload in self.fabricate.items():
                atomic_write_bytes(destination / name, payload)

    def prefetch_static_binary(self, image: str, artifact: StaticBinaryArtifact, destination: Path) -> None:
        """Record the request and materialize a scripted static binary."""
        self.events.append('ripgrep-prefetch')
        self.ripgrep_prefetches.append((image, artifact))
        self.ripgrep_destinations.append(destination)
        target = destination / artifact.executable
        if self.ripgrep_symlink_target is None:
            atomic_write_bytes(target, b'fake-ripgrep')
            target.chmod(0o555)
        else:
            target.symlink_to(self.ripgrep_symlink_target)

    def freeze(self, tag: str) -> tuple[str, ...]:
        """Pop the next scripted freeze.

        Returns
        -------
        tuple[str, ...]
            The scripted freeze lines, or a fixed default when exhausted.
        """
        del tag
        self.events.append('freeze')
        if not self.freezes:
            return ('vulture @ file:///fake',)
        return self.freezes.popleft()

    def python_version(self, tag: str) -> str:
        """Report a fixed interpreter version.

        Returns
        -------
        str
            ``3.14.99``.
        """
        self.events.append('pyver')
        return self.python_versions.get(tag, '3.14.99')

    def environment_python_version(self, tag: str) -> str:
        """Report the scripted managed-environment interpreter version.

        Returns
        -------
        str
            Scripted environment version.
        """
        del tag
        self.events.append('env-pyver')
        return self.environment_python_version_value

    def remove_container(self, name: str) -> bool:
        """Record the removal.

        Returns
        -------
        bool
            The scripted removal outcome.
        """
        self.events.append(f'rm:{name}')
        self.removed.append(name)
        return self.remove_ok


def environments(
    tmp_path: Path,
    docker: FakeDocker,
    *,
    builder_image: str = DEFAULT_CONTAINER_BUILDER_IMAGE,
    runtime_image: str = DEFAULT_CONTAINER_IMAGE,
    fresh: bool = False,
) -> ContainerEnvironments:
    return ContainerEnvironments(
        CheckoutStore(tmp_path / 'cache'),
        tmp_path / 'cache',
        docker=docker,
        builder_image=builder_image,
        runtime_image=runtime_image,
        fresh=fresh,
    )


def test_fake_docker_satisfies_the_runtime_protocol() -> None:
    assert isinstance(FakeDocker(), DockerRuntime)


def test_malformed_image_reference_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ContainerError, match='malformed container builder image reference'):
        environments(tmp_path, FakeDocker(), builder_image='python:3.12 --privileged')
    with pytest.raises(ContainerError, match='malformed container runtime image reference'):
        environments(tmp_path, FakeDocker(), runtime_image='python:3.12 --privileged')


def test_container_mode_refuses_hosts_without_posix_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The §11 run-as-host-user hardening cannot be enforced without POSIX
    # ids; the mode refuses instead of silently running as the untrusted
    # image's default user while recording enforced isolation.
    monkeypatch.delattr(os, 'getuid')
    with pytest.raises(ContainerError, match='requires POSIX user ids'):
        environments(tmp_path, FakeDocker())


def test_image_pair_python_mismatch_fails_before_cache_or_build(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(
        python_versions={
            DEFAULT_CONTAINER_BUILDER_IMAGE: '3.14.7',
            DEFAULT_CONTAINER_IMAGE: '3.12.14',
        }
    )
    with (
        pytest.raises(
            ContainerError,
            match=r'builder/runtime Python version mismatch: builder 3\.14\.7; runtime 3\.12\.14',
        ),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()),
    ):
        pass
    assert 'inspect' not in docker.events
    assert 'build' not in docker.events
    assert 'freeze' not in docker.events
    assert docker.prefetches == []


def test_image_pair_architecture_mismatch_fails_before_cache_or_build(
    tmp_path: Path, detector_repo: DetectorRepo
) -> None:
    docker = FakeDocker(
        architectures={
            DEFAULT_CONTAINER_BUILDER_IMAGE: 'aarch64',
            DEFAULT_CONTAINER_IMAGE: 'x86_64',
        }
    )
    with (
        pytest.raises(
            ContainerError,
            match='builder/runtime architecture mismatch: builder aarch64; runtime x86_64',
        ),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()),
    ):
        pass
    assert 'inspect' not in docker.events
    assert 'build' not in docker.events


def test_cached_environment_requires_the_exact_managed_interpreter(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(always_cached=True, environment_python_version_value='3.12.14')
    with (
        pytest.raises(ContainerError, match=r'environment interpreter mismatch: expected Python 3\.14\.99'),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()),
    ):
        pass
    assert docker.built == []
    assert 'freeze' not in docker.events


def test_build_refuses_checkout_outside_the_cache(
    tmp_path: Path,
    detector_repo: DetectorRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = CheckoutStore(tmp_path / 'cache')

    def misdirected_materialize(_repo: str, _sha: str) -> Path:
        return detector_repo.path

    monkeypatch.setattr(store, 'materialize', misdirected_materialize)
    docker = FakeDocker()
    unsafe = ContainerEnvironments(store, tmp_path / 'cache', docker=docker)
    with (
        pytest.raises(ContainerError, match='not a checkout cache entry'),
        unsafe.prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()),
    ):
        pass
    assert docker.built == []
    assert docker.removed == []


def test_cold_pair_builds_images_and_prepares_side_workspaces(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, docker).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        assert pair.installer_identity == (
            f'docker 99.9; builder {DEFAULT_CONTAINER_BUILDER_IMAGE}; runtime {DEFAULT_CONTAINER_IMAGE}'
        )
        assert pair.python_version == '3.14.99'
        assert pair.platform == 'linux-aarch64'
        assert pair.base.record.rebuilt
        assert not pair.base.record.from_cache
        assert pair.head.record.rebuilt
        assert not pair.head.record.from_cache
        assert pair.base.record.fingerprint != pair.head.record.fingerprint
        assert pair.base.image == image_tag(pair.base.record.fingerprint)
        assert pair.environment_delta == ()
        assert pair.work_root.is_dir()
        assert pair.active_containers == set()
        # Each invocation mounts only its own side's workspace root, so
        # neither side's untrusted code can reach the other's checkout copy.
        assert pair.base_work_root != pair.head_work_root
        assert pair.base_work_root.parent == pair.work_root
        assert pair.head_work_root.parent == pair.work_root
        assert docker.removed == []
    assert docker.removed == []
    assert not pair.work_root.exists()
    # Two fetches: base first (no find-links), then head reusing the base
    # wheelhouse read-only — the shared closure is downloaded only once.
    (base_fetch, head_fetch) = docker.prefetches
    assert base_fetch == (DEFAULT_CONTAINER_BUILDER_IMAGE, ('tomli>=2', 'setuptools>=61'), None)
    head_image, head_reqs, head_links = head_fetch
    assert head_image == DEFAULT_CONTAINER_BUILDER_IMAGE
    assert head_reqs == ('tomli>=2.1', 'setuptools>=61')
    assert head_links is not None
    prefetch_indexes = [index for index, event in enumerate(docker.events) if event == 'prefetch']
    assert prefetch_indexes[0] < docker.events.index('build')
    git_fetches = [record for record in pair.fetches if record.kind == 'git']
    assert len(git_fetches) == 2
    # The head fetch reuses the base wheels (same names) and adds nothing, so
    # each shared wheel is recorded once.
    wheel_fetches = [record for record in pair.fetches if record.kind == 'wheel']
    assert sorted(record.name for record in wheel_fetches) == [
        'setuptools-1.0-py3-none-any.whl',
        'tomli-1.0-py3-none-any.whl',
    ]
    assert all(not path.exists() for path in docker.staging_paths)
    assert docker.ripgrep_prefetches == []
    tool_fetches = [record for record in pair.fetches if record.kind == 'binary']
    assert tool_fetches == []
    # Build contexts are offline and self-contained: Dockerfile, the
    # .git-less checkout, and the shared wheelhouse (contract §3, §11).
    for names, dockerfile in docker.built_contexts:
        assert dockerfile.startswith(f'FROM {DEFAULT_CONTAINER_BUILDER_IMAGE} AS builder\n')
        runtime_stage = dockerfile.split(f'FROM {DEFAULT_CONTAINER_IMAGE}\n', maxsplit=1)[1]
        assert 'ENTRYPOINT []' in runtime_stage
        assert '/liveness/venv/bin:$PATH' in runtime_stage
        assert 'pip' not in runtime_stage
        assert '/liveness/detector' not in runtime_stage
        assert 'COPY tools/rg /usr/bin/rg' not in runtime_stage
        assert '"pip", "uninstall"' in dockerfile
        assert dockerfile.index('USER 0') < dockerfile.index('RUN mkdir -p /liveness/home')
        assert dockerfile.index('USER 65532:65532') < dockerfile.index('/liveness/venv/bin/python -m pip install')
        assert dockerfile.count('USER 0') == 1
        assert 'COPY --chown=65532:65532 wheelhouse /liveness/wheelhouse' in dockerfile
        assert 'COPY --chown=65532:65532 detector /liveness/detector' in dockerfile
        assert 'detector/pyproject.toml' in names
        assert 'wheelhouse/tomli-1.0-py3-none-any.whl' in names
        assert 'wheelhouse/setuptools-1.0-py3-none-any.whl' in names
        assert 'tools/rg' not in names
        assert not any(name.startswith('detector/.git') for name in names)


def test_cached_pair_skips_builds(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]), always_cached=True)
    with environments(tmp_path, docker).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert pair.base.record.from_cache
    assert not pair.base.record.rebuilt
    assert pair.head.record.from_cache
    assert not pair.head.record.rebuilt
    assert docker.built == []
    assert docker.prefetches == []
    assert docker.ripgrep_prefetches == []
    assert pair.environment_delta == ()


def test_native_tool_platform_is_validated_before_cached_pair_reuse(
    tmp_path: Path, detector_repo: DetectorRepo
) -> None:
    source = write_linux_elf(tmp_path / 'skylos-go', 'x86_64')
    tool = ContainerNativeTool(
        variable='SKYLOS_GO_BIN', source=source, sha256=hashlib.sha256(source.read_bytes()).hexdigest()
    )
    docker = FakeDocker(always_cached=True)
    with (
        pytest.raises(ContainerError, match='targets x86_64, not container architecture aarch64'),
        environments(tmp_path, docker).prepare_pair(
            detector_repo.url,
            'base-branch',
            'head-branch',
            VultureAdapter(),
            native_tools=(tool,),
        ),
    ):
        pass
    assert 'inspect' not in docker.events
    assert docker.prefetches == []
    assert docker.built == []


def test_cached_delta_triggers_paired_same_run_rebuild(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # Attribution is temporal, never textual (contract §3): a cached pair
    # showing a non-detector delta is rebuilt in this run, and the delta
    # here does not survive.
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_BUMPED, FREEZE_A, FREEZE_A]), always_cached=True)
    with environments(tmp_path, docker).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert len(docker.built) == 2
    assert pair.base.record.rebuilt
    assert pair.head.record.rebuilt
    assert pair.environment_delta == ()


def test_delta_surviving_paired_rebuild_is_recorded(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_BUMPED, FREEZE_A, FREEZE_BUMPED]), always_cached=True)
    with environments(tmp_path, docker).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert pair.environment_delta == (DependencyDelta(package='tomli', base_version='2.4.0', head_version='2.5.0'),)


def test_fresh_forces_image_rebuilds(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]), always_cached=True)
    with environments(tmp_path, docker, fresh=True).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert [fresh for _tag, fresh in docker.built] == [True, True]
    assert pair.base.record.rebuilt
    assert not pair.base.record.from_cache


def prepare_with_leftover(pair_environments: ContainerEnvironments, repo: str, work_roots: list[Path]) -> None:
    """Leave one registered container for context-exit cleanup."""
    with pair_environments.prepare_pair(repo, 'base-branch', 'head-branch', VultureAdapter()) as pair:
        work_roots.append(pair.work_root)
        pair.active_containers.add('primer-orphan')


def explode_with_leftover(pair_environments: ContainerEnvironments, repo: str, work_roots: list[Path]) -> None:
    """Raise while one registered container still needs cleanup.

    Raises
    ------
    RuntimeError
        Always, while the analysis context is active.
    """
    with pair_environments.prepare_pair(repo, 'base-branch', 'head-branch', VultureAdapter()) as pair:
        work_roots.append(pair.work_root)
        pair.active_containers.add('primer-orphan')
        msg = 'analysis exploded'
        raise RuntimeError(msg)


def test_leftover_containers_are_removed_when_the_analysis_raises(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]))
    work_roots: list[Path] = []
    with pytest.raises(RuntimeError, match='analysis exploded'):
        explode_with_leftover(environments(tmp_path, docker), detector_repo.url, work_roots)
    assert docker.removed == ['primer-orphan']
    assert len(work_roots) == 1
    assert not work_roots[0].exists()


def test_same_sha_on_both_sides_shares_the_image(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_A]))
    with environments(tmp_path, docker).prepare_pair(
        detector_repo.url, 'base-branch', 'base-branch', VultureAdapter()
    ) as pair:
        pass
    git_fetches = [record for record in pair.fetches if record.kind == 'git']
    assert len(git_fetches) == 1
    assert pair.base.record.fingerprint == pair.head.record.fingerprint
    # The head side reuses the image the base side just built.
    assert len(docker.built) == 1
    assert pair.head.record.from_cache


def test_dependency_free_detector_skips_the_prefetch(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    minimal = '[build-system]\nrequires = []\n\n[project]\nname = "fakedet"\nversion = "1"\n'
    atomic_write_text(detector_repo.path / 'pyproject.toml', minimal)
    git('add', 'pyproject.toml', cwd=detector_repo.path)
    git('commit', '--quiet', '-m', 'no deps', cwd=detector_repo.path)
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_A]))
    with environments(tmp_path, docker).prepare_pair(detector_repo.url, 'head-branch', 'head-branch', VultureAdapter()):
        pass
    assert docker.prefetches == []
    assert docker.ripgrep_prefetches == []


def test_skylos_declared_runtime_binary_is_fetched_and_staged(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, docker).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', SkylosAdapter()
    ) as pair:
        pass
    assert len(docker.ripgrep_prefetches) == 1
    binary_fetches = [record for record in pair.fetches if record.kind == 'binary']
    assert [(record.name, record.resolved, record.digest) for record in binary_fetches] == [
        (
            'ripgrep-15.2.0-aarch64-unknown-linux-musl.tar.gz',
            '15.2.0',
            '800b1e7206afe799dfb5a6901f23147cfaabe0e52210538100f61e86e1740915',
        )
    ]
    for names, dockerfile in docker.built_contexts:
        assert 'tools/rg' in names
        assert 'COPY tools/rg /usr/bin/rg' in dockerfile
    assert pair.installer_identity.endswith(
        'ripgrep 15.2.0 (aarch64; executable rg) '
        'sha256:c14cdb389f34e504d69e386cfc67d5c5d9a730a990de03ca6910b2a15e30386a'
    )


def test_adapter_can_stage_two_distinct_runtime_binaries(
    tmp_path: Path,
    detector_repo: DetectorRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = cast('RuntimeBinary', 'helper')
    adapter = VultureAdapter()
    adapter.runtime_binaries = cast('tuple[RuntimeBinary, ...]', ('rg', helper))

    def artifact_for(binary: 'RuntimeBinary', machine: str) -> StaticBinaryArtifact:
        """Return the real rg artifact or a second scripted utility.

        Returns
        -------
        StaticBinaryArtifact
            Architecture-specific test artifact.
        """
        if binary == 'rg':
            return ripgrep_artifact_for(machine)
        return StaticBinaryArtifact(
            name='helper-tool',
            executable=binary,
            version='1.0',
            architecture='aarch64',
            filename='helper-tool.tar.gz',
            url='https://example.invalid/helper-tool.tar.gz',
            archive_digest='b' * 64,
            member='helper-tool/helper',
            binary_digest='c' * 64,
        )

    monkeypatch.setattr(container_module, '_runtime_binary_artifact', artifact_for)
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_A]))
    with environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'base-branch', adapter) as pair:
        pass
    assert [artifact.executable for _image, artifact in docker.ripgrep_prefetches] == ['rg', helper]
    ((names, dockerfile),) = docker.built_contexts
    assert 'tools/rg' in names
    assert 'tools/helper' in names
    assert 'COPY tools/rg /usr/bin/rg' in dockerfile
    assert 'COPY tools/helper /usr/bin/helper' in dockerfile
    assert 'helper-tool 1.0 (aarch64; executable helper)' in pair.installer_identity


def test_runtime_binary_registry_rejects_an_unsupported_executable(
    tmp_path: Path,
    detector_repo: DetectorRepo,
) -> None:
    helper = cast('RuntimeBinary', 'helper')
    adapter = VultureAdapter()
    adapter.runtime_binaries = cast('tuple[RuntimeBinary, ...]', (helper,))
    docker = FakeDocker()

    with (
        pytest.raises(ContainerError, match="container runtime binary 'helper' has no pinned artifact"),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', adapter),
    ):
        pass
    assert docker.ripgrep_prefetches == []
    assert docker.built == []


def test_runtime_binary_registry_rejects_a_mismatched_executable(
    tmp_path: Path,
    detector_repo: DetectorRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = cast('RuntimeBinary', 'helper')
    mismatched = StaticBinaryArtifact(
        name='helper-tool',
        executable=helper,
        version='1.0',
        architecture='aarch64',
        filename='helper-tool.tar.gz',
        url='https://example.invalid/helper-tool.tar.gz',
        archive_digest='b' * 64,
        member='helper-tool/helper',
        binary_digest='c' * 64,
    )
    monkeypatch.setattr(container_module, '_runtime_binary_artifact', lambda _binary, _machine: mismatched)
    docker = FakeDocker()
    with (
        pytest.raises(ContainerError, match="registry mismatch: requested 'rg', artifact provides 'helper'"),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', SkylosAdapter()),
    ):
        pass
    assert docker.ripgrep_prefetches == []
    assert docker.built == []


def test_prefetched_symlink_never_reaches_the_wheelhouse(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # A build hook running inside the fetch container can plant a symlink
    # whose target only resolves on the host; the staged download must be
    # rejected before anything host-side dereferences it (contract §11).
    secret = tmp_path / 'host-secret'
    secret.write_text('credentials', encoding='utf-8')
    docker = FakeDocker(wheel_symlink_target=secret)
    with (
        pytest.raises(ContainerError, match='prefetched distribution is not a regular file'),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', SkylosAdapter()),
    ):
        pass
    assert docker.built == []
    assert docker.removed == []
    assert all(not path.exists() for path in docker.staging_paths)


def test_prefetched_ripgrep_symlink_never_reaches_the_build(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    secret = tmp_path / 'host-binary'
    atomic_write_bytes(secret, b'host tool')
    docker = FakeDocker(ripgrep_symlink_target=secret)
    with (
        pytest.raises(ContainerError, match='prefetched static binary is not a regular file'),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', SkylosAdapter()),
    ):
        pass
    assert docker.built == []
    assert len(docker.ripgrep_destinations) == 1
    assert (docker.ripgrep_destinations[0] / 'rg').is_symlink()


def test_promote_prefetched_reports_only_new_files(tmp_path: Path) -> None:
    staging = tmp_path / 'staging'
    wheelhouse = tmp_path / 'wheelhouse'
    staging.mkdir()
    wheelhouse.mkdir()
    atomic_write_bytes(wheelhouse / 'cached.whl', b'old')
    atomic_write_bytes(staging / 'cached.whl', b'replaced')
    atomic_write_bytes(staging / 'fresh.whl', b'fresh')
    assert promote_prefetched(staging, wheelhouse) == {'fresh.whl'}
    assert (wheelhouse / 'cached.whl').read_bytes() == b'replaced'
    assert (wheelhouse / 'fresh.whl').read_bytes() == b'fresh'


def test_promote_prefetched_drops_excluded_names(tmp_path: Path) -> None:
    # A head fetch's staging holds base wheels the resolver copied back plus
    # its own extras; base-owned names are dropped, never promoted, so the
    # head side cannot introduce an artifact under a base dependency's name.
    staging = tmp_path / 'staging'
    wheelhouse = tmp_path / 'wheelhouse'
    staging.mkdir()
    wheelhouse.mkdir()
    atomic_write_bytes(staging / 'base-dep.whl', b'forged')
    atomic_write_bytes(staging / 'head-extra.whl', b'real')
    assert promote_prefetched(staging, wheelhouse, exclude=frozenset({'base-dep.whl'})) == {'head-extra.whl'}
    assert not (wheelhouse / 'base-dep.whl').exists()
    assert (wheelhouse / 'head-extra.whl').read_bytes() == b'real'


def test_promote_prefetched_validates_before_any_promotion(tmp_path: Path) -> None:
    # A symlink sorting after a good wheel must not leave already-promoted
    # files behind: a rejected fetch would otherwise plant unrecorded
    # artifacts that later builds silently stage into images.
    staging = tmp_path / 'staging'
    wheelhouse = tmp_path / 'wheelhouse'
    staging.mkdir()
    wheelhouse.mkdir()
    atomic_write_bytes(staging / 'aaa-good.whl', b'payload')
    (staging / 'zzz-evil.whl').symlink_to(tmp_path / 'host-secret')
    with pytest.raises(ContainerError, match='prefetched distribution is not a regular file'):
        promote_prefetched(staging, wheelhouse)
    assert list(wheelhouse.iterdir()) == []


def test_stage_wheelhouses_refuses_symlinked_cache_entries(tmp_path: Path) -> None:
    # The persistent wheelhouse outlives runs: a symlink that slipped in
    # must never be dereferenced while assembling a build context.
    wheelhouse = tmp_path / 'wheelhouse'
    wheelhouse.mkdir()
    atomic_write_bytes(wheelhouse / 'good.whl', b'payload')
    (wheelhouse / 'evil.whl').symlink_to(tmp_path / 'host-secret')
    with pytest.raises(ContainerError, match='cached distribution is not a regular file'):
        stage_wheelhouses([wheelhouse], tmp_path / 'context')
    (wheelhouse / 'evil.whl').unlink()
    stage_wheelhouses([wheelhouse], tmp_path / 'clean-context')
    assert (tmp_path / 'clean-context' / 'good.whl').read_bytes() == b'payload'


def test_stage_wheelhouses_rejects_cross_source_name_collision(tmp_path: Path) -> None:
    base = tmp_path / 'base'
    head = tmp_path / 'head'
    base.mkdir()
    head.mkdir()
    atomic_write_bytes(base / 'shared.whl', b'base')
    atomic_write_bytes(head / 'shared.whl', b'head')
    with pytest.raises(ContainerError, match='appears in more than one source'):
        stage_wheelhouses([base, head], tmp_path / 'context')


def test_head_fetch_cannot_poison_the_base_image(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # A head-side build hook fabricates a wheel named for a base dependency
    # during the head fetch. Because the base image builds only from the
    # base wheelhouse — which the head fetch mounts read-only and whose names
    # the promotion excludes — the forgery never reaches the base build, and
    # the comparison's independence is preserved (contract §3, §11).
    docker = FakeDocker(
        freezes=deque([FREEZE_A, FREEZE_B]),
        fabricate={'tomli-1.0-py3-none-any.whl': b'forged', 'sneaky-9.9-py3-none-any.whl': b'forged'},
    )
    with environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()):
        pass
    base_context, head_context = docker.built_contexts
    base_names, _ = base_context
    head_names, _ = head_context
    # The base build never sees the forged base wheel or the sneaky extra:
    # its own tomli wheel is the one the base fetch produced.
    assert 'wheelhouse/sneaky-9.9-py3-none-any.whl' not in base_names
    # The head fetch mounts the base wheelhouse read-only for reuse.
    (_base_fetch, head_fetch) = docker.prefetches
    _image, _reqs, head_links = head_fetch
    assert head_links is not None
    # The sneaky extra is confined to the head image, never the base one.
    assert 'wheelhouse/sneaky-9.9-py3-none-any.whl' in head_names


def pair_dir_and_base_tag(tmp_path: Path, repo_url: str) -> tuple[Path, str]:
    """Compute the pair wheelhouse directory and base image tag of the fixture refs.

    Parameters
    ----------
    tmp_path : Path
        Test directory holding the cache.
    repo_url : str
        Fixture detector repository URL.

    Returns
    -------
    tuple[Path, str]
        The persistent pair wheelhouse directory and the base image tag.
    """
    store = CheckoutStore(tmp_path / 'cache')
    adapter = VultureAdapter()
    fingerprints = [
        container_fingerprint(
            repo_url,
            store.resolve_ref(repo_url, ref),
            adapter,
            'docker 99.9',
            DEFAULT_CONTAINER_BUILDER_IMAGE,
            DEFAULT_CONTAINER_IMAGE,
            (),
        )
        for ref in ('base-branch', 'head-branch')
    ]
    pair_key = hashlib.sha256(f'{fingerprints[0]}:{fingerprints[1]}'.encode()).hexdigest()[:24]
    return tmp_path / 'cache' / 'wheelhouse-container' / pair_key, image_tag(fingerprints[0])


def test_stale_wheelhouses_from_a_cached_base_run_are_reset(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # Run 1: only the base image is cached, so the head fetch owns the full
    # shared closure and persists it in the head wheelhouse.
    pair_dir, base_tag = pair_dir_and_base_tag(tmp_path, detector_repo.url)
    docker = FakeDocker(existing_images={base_tag})
    with environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()):
        pass
    assert sorted(entry.name for entry in (pair_dir / 'head').iterdir()) == [
        'setuptools-1.0-py3-none-any.whl',
        'tomli-1.0-py3-none-any.whl',
    ]
    # Run 2 after image eviction (or --fresh): both sides rebuild and the
    # base fetch now owns the closure; the persisted head wheelhouse must be
    # reset, not collide with the base one as a duplicate name.
    evicted = FakeDocker()
    with environments(tmp_path, evicted).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ):
        pass
    assert len(evicted.built) == 2
    assert sorted(entry.name for entry in (pair_dir / 'base').iterdir()) == [
        'setuptools-1.0-py3-none-any.whl',
        'tomli-1.0-py3-none-any.whl',
    ]
    assert list((pair_dir / 'head').iterdir()) == []


@pytest.mark.parametrize('level', ['root', 'pair', 'base', 'tools'])
@pytest.mark.parametrize('kind', ['symlink', 'file'])
def test_unsafe_container_cache_directories_are_rejected(
    tmp_path: Path,
    detector_repo: DetectorRepo,
    level: Literal['root', 'pair', 'base', 'tools'],
    kind: Literal['symlink', 'file'],
) -> None:
    pair_dir, _base_tag = pair_dir_and_base_tag(tmp_path, detector_repo.url)
    locations = {
        'root': pair_dir.parent,
        'pair': pair_dir,
        'base': pair_dir / 'base',
        'tools': pair_dir / 'tools',
    }
    unsafe = locations[level]
    unsafe.parent.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / 'cache-victim'
    victim.mkdir()
    atomic_write_text(victim / 'sentinel.txt', 'untouched')
    if kind == 'symlink':
        unsafe.symlink_to(victim, target_is_directory=True)
    else:
        atomic_write_text(unsafe, 'not a directory')

    docker = FakeDocker()
    with (
        pytest.raises(ContainerError, match='container cache path is not a regular directory'),
        environments(tmp_path, docker).prepare_pair(
            detector_repo.url,
            'base-branch',
            'head-branch',
            VultureAdapter(),
        ),
    ):
        pass
    assert read_small_text(victim / 'sentinel.txt') == 'untouched'
    assert docker.built == []
    assert docker.removed == []


def test_container_wheelhouse_reset_failure_is_a_domain_error(
    tmp_path: Path,
    detector_repo: DetectorRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse_removal(_path: Path) -> None:
        msg = 'permission denied'
        raise OSError(msg)

    monkeypatch.setattr(shutil, 'rmtree', refuse_removal)
    docker = FakeDocker()
    with (
        pytest.raises(ContainerError, match='cannot reset the base container wheelhouse'),
        environments(tmp_path, docker).prepare_pair(
            detector_repo.url,
            'base-branch',
            'head-branch',
            VultureAdapter(),
        ),
    ):
        pass
    assert docker.built == []
    assert docker.removed == []


def test_container_tool_cache_reset_failure_is_a_domain_error(
    tmp_path: Path,
    detector_repo: DetectorRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    minimal = '[build-system]\nrequires = []\n\n[project]\nname = "fakedet"\nversion = "1"\n'
    atomic_write_text(detector_repo.path / 'pyproject.toml', minimal)
    git('add', 'pyproject.toml', cwd=detector_repo.path)
    git('commit', '--quiet', '-m', 'no deps', cwd=detector_repo.path)
    real_rmtree = shutil.rmtree

    def refuse_tool_removal(path: Path) -> None:
        if Path(path).name == 'tools':
            monkeypatch.setattr(shutil, 'rmtree', real_rmtree)
            msg = 'permission denied'
            raise OSError(msg)
        real_rmtree(path)

    monkeypatch.setattr(shutil, 'rmtree', refuse_tool_removal)
    docker = FakeDocker()
    with (
        pytest.raises(ContainerError, match='cannot reset the container tool cache'),
        environments(tmp_path, docker).prepare_pair(
            detector_repo.url,
            'head-branch',
            'head-branch',
            SkylosAdapter(),
        ),
    ):
        pass
    assert docker.built == []


def test_pair_wheelhouse_lock_timeout_fails_the_run(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # The persistent pair wheelhouses are mutated, snapshotted, and reset
    # during preparation; a concurrent run of the same pair must wait on the
    # cross-process lock rather than corrupt them (contract §3, §11).
    pair_dir, _base_tag = pair_dir_and_base_tag(tmp_path, detector_repo.url)
    pair_dir.parent.mkdir(parents=True, exist_ok=True)
    impatient = ContainerEnvironments(
        CheckoutStore(tmp_path / 'cache'),
        tmp_path / 'cache',
        docker=FakeDocker(),
        lock_timeout=0.05,
    )
    with (
        FileLock(str(pair_dir) + '.lock'),
        pytest.raises(ContainerError, match='timed out waiting for the container wheelhouse lock'),
        impatient.prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()),
    ):
        pass


def test_stage_invocation_env_files_copies_into_every_side(tmp_path: Path) -> None:
    config = tmp_path / 'neutral.toml'
    config.write_text('[tool]\n', encoding='utf-8')
    base_root = tmp_path / 'base'
    head_root = tmp_path / 'head'
    base_root.mkdir()
    head_root.mkdir()
    staged = stage_invocation_env_files({'TOOL_CONFIG': config}, (base_root, head_root))
    # Both sides hold an identical copy at one container-side path.
    assert staged == {'TOOL_CONFIG': '/liveness/work/invocation-env/TOOL_CONFIG/neutral.toml'}
    for root in (base_root, head_root):
        assert (root / 'invocation-env' / 'TOOL_CONFIG' / 'neutral.toml').read_text(encoding='utf-8') == '[tool]\n'


def test_unconfirmed_removal_fails_the_run(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # Contract §3, §11: report output must never be written while an
    # analysis container may still exist, so the success path fails closed.
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]), remove_ok=False)
    with pytest.raises(ContainerError, match='could not confirm removal of analysis container'):
        prepare_with_leftover(environments(tmp_path, docker), detector_repo.url, [])
    assert docker.removed == ['primer-orphan']


def test_analysis_failure_is_not_masked_by_removal_failure(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # On the failure path teardown stays best-effort: the in-flight error
    # already prevents report output and must reach the caller unmasked.
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]), remove_ok=False)
    with pytest.raises(RuntimeError, match='analysis exploded'):
        explode_with_leftover(environments(tmp_path, docker), detector_repo.url, [])
    assert docker.removed == ['primer-orphan']


def workspace_under(work_root: Path, side: Literal['base', 'head']) -> SideWorkspace:
    root = work_root / 'liveness-primer-side-x1'
    return SideWorkspace(root=root, checkout=root / 'checkout', home=root / 'liveness-primer-home-y2', side=side)


def side_execution(tmp_path: Path) -> ContainerExecution:
    return ContainerExecution(
        work_roots={'base': tmp_path / 'base', 'head': tmp_path / 'head'},
        images={'base': 'base-image', 'head': 'head-image'},
        invocation_env={},
        docker=FakeDocker(),
        active_containers=set(),
    )


def test_execution_workspaces_live_under_the_side_mounted_root(tmp_path: Path) -> None:
    execution = side_execution(tmp_path)
    assert execution.workspace_parents == {'base': tmp_path / 'base', 'head': tmp_path / 'head'}


def test_launch_plan_builds_a_named_hardened_container(tmp_path: Path) -> None:
    docker = FakeDocker()
    active: set[str] = set()
    execution = ContainerExecution(
        work_roots={'base': tmp_path / 'base', 'head': tmp_path / 'head'},
        images={'base': 'base-image', 'head': 'head-image'},
        invocation_env={'SKYLOS_GREP_BUDGET': '5'},
        docker=docker,
        active_containers=active,
        user='501:20',
    )
    workspace = workspace_under(tmp_path / 'head', 'head')
    plan = execution.launch_plan(argv=('vulture', '.'), workspace=workspace)
    assert plan.cwd is None
    assert plan.env is None
    assert plan.argv == (
        'docker',
        'run',
        '--rm',
        '--init',
        '--network',
        'none',
        '--name',
        'liveness-primer-side-x1-head',
        '--entrypoint',
        '',
        '--cap-drop',
        'ALL',
        '--security-opt',
        'no-new-privileges',
        '--pids-limit',
        '4096',
        '--read-only',
        '--tmpfs',
        str(CONTAINER_TMP_ROOT),
        '--volume',
        f'{tmp_path / "head"}:{CONTAINER_WORK_ROOT}',
        '--workdir',
        '/liveness/work/liveness-primer-side-x1/checkout',
        '--env',
        'HOME=/liveness/work/liveness-primer-side-x1/liveness-primer-home-y2',
        '--env',
        'SKYLOS_GREP_BUDGET=5',
        '--user',
        '501:20',
        'head-image',
        'vulture',
        '.',
    )
    container_name = 'liveness-primer-side-x1-head'
    assert plan.cleanup is not None
    assert active == {container_name}
    with pytest.raises(ContainerError, match='already active'):
        execution.launch_plan(argv=('vulture', '.'), workspace=workspace)
    plan.cleanup()
    assert docker.removed == [container_name]
    assert active == set()


def test_container_cleanup_confirms_removal(tmp_path: Path) -> None:
    execution = side_execution(tmp_path)
    failing = ContainerExecution(
        work_roots=execution.work_roots,
        images=execution.images,
        invocation_env={},
        docker=FakeDocker(remove_ok=False),
        active_containers=set(),
    )
    workspace = workspace_under(tmp_path / 'base', 'base')
    plan = failing.launch_plan(argv=('vulture', '.'), workspace=workspace)
    assert plan.cleanup is not None
    with pytest.raises(ContainerError, match='could not confirm removal'):
        plan.cleanup()
    assert failing.active_containers == {'liveness-primer-side-x1-base'}


def test_launch_plan_without_a_user_mapping(tmp_path: Path) -> None:
    execution = side_execution(tmp_path)
    plan = execution.launch_plan(argv=('vulture', '.'), workspace=workspace_under(tmp_path / 'base', 'base'))
    assert '--user' not in plan.argv
    assert 'base-image' in plan.argv


def test_analysis_root_is_the_container_side_checkout(tmp_path: Path) -> None:
    execution = side_execution(tmp_path)
    root = execution.analysis_root(workspace_under(tmp_path / 'base', 'base'))
    assert root == PurePosixPath('/liveness/work/liveness-primer-side-x1/checkout')
    # A pure POSIX path, never a native host path: it must stay absolute on
    # every host platform so path normalization strips the prefix (§7).
    assert not isinstance(root, Path)
    assert root.is_absolute()


def test_execution_records_the_container_isolation(tmp_path: Path) -> None:
    assert side_execution(tmp_path).isolation is CONTAINER_ISOLATION
