# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the container-backed detector environments (contract §3, §11, §15)."""

import os
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

from liveness_primer.container import (
    CONTAINER_WORK_ROOT,
    DEFAULT_CONTAINER_IMAGE,
    ContainerEnvironments,
    ContainerError,
    ContainerExecution,
    DockerCli,
    DockerRuntime,
    container_fingerprint,
    container_user,
    image_tag,
)
from liveness_primer.corpus import CheckoutStore
from liveness_primer.execution import SideWorkspace
from liveness_primer.filesystem import atomic_write_bytes, read_small_text
from liveness_primer.findings import DependencyDelta
from liveness_primer.launcher import LauncherError, SyncLauncher, run_async
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


def test_prefetch_runs_pip_download_in_the_base_image(tmp_path: Path) -> None:
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).prefetch('python:3.12-slim', ('tomli>=2',), tmp_path)
    (argv,) = launcher.calls
    assert argv[:3] == ('docker', 'run', '--rm')
    assert (argv[3], argv[4]) == ('--user', container_user())
    assert f'{tmp_path}:/liveness/wheelhouse' in argv
    assert (argv[7], argv[8]) == ('--env', 'HOME=/tmp')
    assert argv[-1] == 'tomli>=2'
    assert 'python:3.12-slim' in argv
    with pytest.raises(ContainerError, match='dependency prefetch'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).prefetch('python:3.12-slim', ('tomli>=2',), tmp_path)


def test_prefetch_without_posix_ids_omits_the_user_mapping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, 'getuid')
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).prefetch('python:3.12-slim', ('tomli>=2',), tmp_path)
    (argv,) = launcher.calls
    assert '--user' not in argv


def test_freeze_parses_lines() -> None:
    launcher = RecordingLauncher(stdout='tomli==2.4.0\n\nvulture @ file:///x\n')
    assert DockerCli(launcher=launcher).freeze('t:1') == ('tomli==2.4.0', 'vulture @ file:///x')
    (argv,) = launcher.calls
    assert argv == ('docker', 'run', '--rm', '--network', 'none', 't:1', 'python', '-m', 'pip', 'freeze')
    with pytest.raises(ContainerError, match='pip freeze failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).freeze('t:1')


def test_start_container_argv_is_network_less(tmp_path: Path) -> None:
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).start_container('t:1', 'primer-base', work_root=tmp_path)
    (argv,) = launcher.calls
    assert (argv[5], argv[6]) == ('--network', 'none')
    assert (argv[7], argv[8]) == ('--name', 'primer-base')
    assert f'{tmp_path}:{CONTAINER_WORK_ROOT}' in argv
    assert argv[-2:] == ('sleep', 'infinity')
    assert {'--detach', '--rm', '--init'} <= set(argv)
    with pytest.raises(ContainerError, match='container start failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).start_container('t:1', 'primer-base', work_root=tmp_path)


def test_remove_container_reports_the_outcome() -> None:
    launcher = RecordingLauncher()
    assert DockerCli(launcher=launcher).remove_container('primer-base') is True
    (argv,) = launcher.calls
    assert argv == ('docker', 'rm', '--force', 'primer-base')
    assert DockerCli(launcher=RecordingLauncher(returncode=1)).remove_container('primer-base') is False


def test_container_user_maps_posix_ids() -> None:
    assert container_user() == f'{os.getuid()}:{os.getgid()}'


def test_container_user_without_posix_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(os, 'getuid')
    assert container_user() is None


def test_container_fingerprint_varies_by_inputs() -> None:
    adapter = VultureAdapter()
    base = container_fingerprint('https://r', 'a' * 40, adapter, 'docker 27', 'python:3.12-slim')
    assert base == container_fingerprint('https://r', 'a' * 40, adapter, 'docker 27', 'python:3.12-slim')
    assert base != container_fingerprint('https://other', 'a' * 40, adapter, 'docker 27', 'python:3.12-slim')
    assert base != container_fingerprint('https://r', 'b' * 40, adapter, 'docker 27', 'python:3.12-slim')
    assert base != container_fingerprint('https://r', 'a' * 40, adapter, 'docker 28', 'python:3.12-slim')
    assert base != container_fingerprint('https://r', 'a' * 40, adapter, 'docker 27', 'python:3.13-slim')


def test_image_tag_embeds_the_fingerprint() -> None:
    assert image_tag('abc123') == 'liveness-primer/env:abc123'


@dataclass
class FakeDocker:
    """Scripted Docker runtime recording every operation (contract §15)."""

    freezes: deque[tuple[str, ...]] = field(default_factory=deque)
    always_cached: bool = False
    events: list[str] = field(default_factory=list)
    existing_images: set[str] = field(default_factory=set)
    prefetches: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    built: list[tuple[str, bool]] = field(default_factory=list)
    built_contexts: list[tuple[tuple[str, ...], str]] = field(default_factory=list)
    started: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    work_roots: list[Path] = field(default_factory=list)
    wheel_names: tuple[str, ...] = ('tomli-2.4.0-py3-none-any.whl',)

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

    def build_image(self, tag: str, context: Path, *, fresh: bool) -> None:
        """Record the build and remember the context contents."""
        self.events.append('build')
        self.built.append((tag, fresh))
        names = tuple(sorted(str(entry.relative_to(context)) for entry in context.rglob('*')))
        self.built_contexts.append((names, read_small_text(context / 'Dockerfile')))
        self.existing_images.add(tag)

    def prefetch(self, image: str, requirements: Sequence[str], wheelhouse: Path) -> None:
        """Record the request and materialize scripted wheel files."""
        self.events.append('prefetch')
        self.prefetches.append((image, tuple(requirements)))
        for wheel in self.wheel_names:
            atomic_write_bytes(wheelhouse / wheel, b'payload-' + wheel.encode('utf-8'))

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

    def start_container(self, tag: str, name: str, *, work_root: Path) -> None:
        """Record the started container and its mounted root."""
        del tag
        self.events.append(f'start:{name}')
        self.started.append(name)
        self.work_roots.append(work_root)

    def remove_container(self, name: str) -> bool:
        """Record the removal.

        Returns
        -------
        bool
            Always True.
        """
        self.events.append(f'rm:{name}')
        self.removed.append(name)
        return True


def environments(
    tmp_path: Path,
    docker: FakeDocker,
    *,
    image: str = DEFAULT_CONTAINER_IMAGE,
    fresh: bool = False,
) -> ContainerEnvironments:
    return ContainerEnvironments(
        CheckoutStore(tmp_path / 'cache'),
        tmp_path / 'cache',
        docker=docker,
        image=image,
        fresh=fresh,
    )


def test_fake_docker_satisfies_the_runtime_protocol() -> None:
    assert isinstance(FakeDocker(), DockerRuntime)


def test_malformed_image_reference_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ContainerError, match='malformed container image reference'):
        environments(tmp_path, FakeDocker(), image='python:3.12 --privileged')


def test_cold_pair_builds_images_and_runs_ephemeral_containers(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, docker).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        assert pair.installer_identity == f'docker 99.9; image {DEFAULT_CONTAINER_IMAGE}'
        assert pair.base.record.rebuilt
        assert not pair.base.record.from_cache
        assert pair.head.record.rebuilt
        assert not pair.head.record.from_cache
        assert pair.base.record.fingerprint != pair.head.record.fingerprint
        assert pair.base.image == image_tag(pair.base.record.fingerprint)
        assert pair.environment_delta == ()
        assert pair.work_root.is_dir()
        assert pair.base_container == f'{pair.work_root.name}-base'
        assert pair.head_container == f'{pair.work_root.name}-head'
        assert docker.started == [pair.base_container, pair.head_container]
        assert docker.work_roots == [pair.work_root, pair.work_root]
        assert docker.removed == []
    assert docker.removed == [pair.base_container, pair.head_container]
    assert not pair.work_root.exists()
    # The union prefetch ran once, in the base image, before either build.
    ((image, requirements),) = docker.prefetches
    assert image == DEFAULT_CONTAINER_IMAGE
    assert requirements == ('tomli>=2', 'setuptools>=61', 'tomli>=2.1')
    assert docker.events.index('prefetch') < docker.events.index('build')
    git_fetches = [record for record in pair.fetches if record.kind == 'git']
    assert len(git_fetches) == 2
    wheel_fetches = [record for record in pair.fetches if record.kind == 'wheel']
    assert [record.name for record in wheel_fetches] == ['tomli-2.4.0-py3-none-any.whl']
    # Build contexts are offline and self-contained: Dockerfile, the
    # .git-less checkout, and the wheelhouse (contract §3, §11).
    for names, dockerfile in docker.built_contexts:
        assert dockerfile.startswith(f'FROM {DEFAULT_CONTAINER_IMAGE}\n')
        assert 'detector/pyproject.toml' in names
        assert 'wheelhouse/tomli-2.4.0-py3-none-any.whl' in names
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
    assert pair.environment_delta == ()


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


def explode_during_analysis(pair_environments: ContainerEnvironments, repo: str) -> None:
    with pair_environments.prepare_pair(repo, 'base-branch', 'head-branch', VultureAdapter()):
        msg = 'analysis exploded'
        raise RuntimeError(msg)


def test_containers_are_removed_when_the_analysis_raises(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]))
    with pytest.raises(RuntimeError, match='analysis exploded'):
        explode_during_analysis(environments(tmp_path, docker), detector_repo.url)
    assert len(docker.started) == 2
    assert docker.removed == docker.started
    assert not docker.work_roots[0].exists()


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
    (detector_repo.path / 'pyproject.toml').write_text(minimal, encoding='utf-8')
    git('add', 'pyproject.toml', cwd=detector_repo.path)
    git('commit', '--quiet', '-m', 'no deps', cwd=detector_repo.path)
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_A]))
    with environments(tmp_path, docker).prepare_pair(detector_repo.url, 'head-branch', 'head-branch', VultureAdapter()):
        pass
    assert docker.prefetches == []


def workspace_under(work_root: Path) -> SideWorkspace:
    root = work_root / 'liveness-primer-side-x1'
    return SideWorkspace(root=root, checkout=root / 'checkout', home=root / 'home')


def test_execution_workspaces_live_under_the_mounted_root(tmp_path: Path) -> None:
    execution = ContainerExecution(
        work_root=tmp_path,
        containers={'base': 'primer-base', 'head': 'primer-head'},
        invocation_env={},
    )
    assert execution.workspace_parent == tmp_path


def test_launch_plan_builds_a_docker_exec(tmp_path: Path) -> None:
    execution = ContainerExecution(
        work_root=tmp_path,
        containers={'base': 'primer-base', 'head': 'primer-head'},
        invocation_env={'SKYLOS_GREP_BUDGET': '5'},
        user='501:20',
    )
    workspace = workspace_under(tmp_path)
    plan = execution.launch_plan(side='head', argv=('vulture', '.'), workspace=workspace)
    assert plan.cwd is None
    assert plan.env is None
    assert plan.argv == (
        'docker',
        'exec',
        '--workdir',
        '/liveness/work/liveness-primer-side-x1/checkout',
        '--env',
        'HOME=/liveness/work/liveness-primer-side-x1/home',
        '--env',
        'SKYLOS_GREP_BUDGET=5',
        '--user',
        '501:20',
        'primer-head',
        'vulture',
        '.',
    )


def test_launch_plan_without_a_user_mapping(tmp_path: Path) -> None:
    execution = ContainerExecution(
        work_root=tmp_path,
        containers={'base': 'primer-base', 'head': 'primer-head'},
        invocation_env={},
    )
    plan = execution.launch_plan(side='base', argv=('vulture', '.'), workspace=workspace_under(tmp_path))
    assert '--user' not in plan.argv
    assert 'primer-base' in plan.argv


def test_analysis_root_is_the_container_side_checkout(tmp_path: Path) -> None:
    execution = ContainerExecution(
        work_root=tmp_path,
        containers={'base': 'primer-base', 'head': 'primer-head'},
        invocation_env={},
    )
    root = execution.analysis_root(workspace_under(tmp_path))
    assert root == Path('/liveness/work/liveness-primer-side-x1/checkout')
