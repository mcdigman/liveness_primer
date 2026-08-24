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
    promote_prefetched,
    stage_wheelhouse,
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


def assert_hardened(argv: tuple[str, ...]) -> None:
    assert argv[argv.index('--cap-drop') + 1] == 'ALL'
    assert argv[argv.index('--security-opt') + 1] == 'no-new-privileges'
    assert argv[argv.index('--pids-limit') + 1] == '4096'
    assert '--read-only' in argv
    assert argv[argv.index('--tmpfs') + 1] == '/tmp'


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
    assert run_argv[run_argv.index('--user') + 1] == container_user()
    assert f'{tmp_path}:/liveness/wheelhouse' in run_argv
    assert run_argv[run_argv.index('--env') + 1] == 'HOME=/tmp'
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
    assert run_argv[-4:] == ('python', '-m', 'pip', 'freeze')
    assert 't:1' in run_argv
    with pytest.raises(ContainerError, match='pip freeze failed'):
        DockerCli(launcher=RecordingLauncher(returncode=1)).freeze('t:1')


def test_start_container_argv_is_network_less_and_hardened(tmp_path: Path) -> None:
    launcher = RecordingLauncher()
    DockerCli(launcher=launcher).start_container('t:1', 'primer-base', work_root=tmp_path)
    (argv,) = launcher.calls
    assert argv[argv.index('--network') + 1] == 'none'
    assert argv[argv.index('--name') + 1] == 'primer-base'
    assert_hardened(argv)
    # PID 1 (the untrusted image's own `sleep`) runs as the mapped host
    # user, never as the image default.
    assert argv[argv.index('--user') + 1] == container_user()
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
    remove_ok: bool = True
    wheel_symlink_target: Path | None = None
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

    def prefetch(self, image: str, requirements: Sequence[str], destination: Path) -> None:
        """Record the request and materialize scripted wheel files."""
        self.events.append('prefetch')
        self.prefetches.append((image, tuple(requirements)))
        for wheel in self.wheel_names:
            if self.wheel_symlink_target is None:
                atomic_write_bytes(destination / wheel, b'payload-' + wheel.encode('utf-8'))
            else:
                (destination / wheel).symlink_to(self.wheel_symlink_target)

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
            The scripted removal outcome.
        """
        self.events.append(f'rm:{name}')
        self.removed.append(name)
        return self.remove_ok


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
        # Each container mounts only its own side's workspace root, so
        # neither side's untrusted code can reach the other's checkout copy.
        assert docker.work_roots == [pair.base_work_root, pair.head_work_root]
        assert pair.base_work_root != pair.head_work_root
        assert pair.base_work_root.parent == pair.work_root
        assert pair.head_work_root.parent == pair.work_root
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


def test_prefetched_symlink_never_reaches_the_wheelhouse(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # A build hook running inside the fetch container can plant a symlink
    # whose target only resolves on the host; the staged download must be
    # rejected before anything host-side dereferences it (contract §11).
    secret = tmp_path / 'host-secret'
    secret.write_text('credentials', encoding='utf-8')
    docker = FakeDocker(wheel_symlink_target=secret)
    with (
        pytest.raises(ContainerError, match='prefetched distribution is not a regular file'),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()),
    ):
        pass
    assert docker.built == []
    assert docker.started == []


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


def test_stage_wheelhouse_refuses_symlinked_cache_entries(tmp_path: Path) -> None:
    # The persistent wheelhouse outlives runs: a symlink that slipped in
    # must never be dereferenced while assembling a build context.
    wheelhouse = tmp_path / 'wheelhouse'
    wheelhouse.mkdir()
    atomic_write_bytes(wheelhouse / 'good.whl', b'payload')
    (wheelhouse / 'evil.whl').symlink_to(tmp_path / 'host-secret')
    with pytest.raises(ContainerError, match='cached distribution is not a regular file'):
        stage_wheelhouse(wheelhouse, tmp_path / 'context')
    (wheelhouse / 'evil.whl').unlink()
    stage_wheelhouse(wheelhouse, tmp_path / 'clean-context')
    assert (tmp_path / 'clean-context' / 'good.whl').read_bytes() == b'payload'


def test_unconfirmed_removal_fails_the_run(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # Contract §3, §11: report output must never be written while an
    # analysis container may still exist, so the success path fails closed.
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]), remove_ok=False)
    with (
        pytest.raises(ContainerError, match='could not confirm removal of analysis container'),
        environments(tmp_path, docker).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()),
    ):
        pass
    assert docker.removed == docker.started


def test_analysis_failure_is_not_masked_by_removal_failure(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # On the failure path teardown stays best-effort: the in-flight error
    # already prevents report output and must reach the caller unmasked.
    docker = FakeDocker(freezes=deque([FREEZE_A, FREEZE_B]), remove_ok=False)
    with pytest.raises(RuntimeError, match='analysis exploded'):
        explode_during_analysis(environments(tmp_path, docker), detector_repo.url)
    assert docker.removed == docker.started


def workspace_under(work_root: Path) -> SideWorkspace:
    root = work_root / 'liveness-primer-side-x1'
    return SideWorkspace(root=root, checkout=root / 'checkout', home=root / 'home')


def side_execution(tmp_path: Path) -> ContainerExecution:
    return ContainerExecution(
        work_roots={'base': tmp_path / 'base', 'head': tmp_path / 'head'},
        containers={'base': 'primer-base', 'head': 'primer-head'},
        invocation_env={},
    )


def test_execution_workspaces_live_under_the_side_mounted_root(tmp_path: Path) -> None:
    execution = side_execution(tmp_path)
    assert execution.workspace_parent('base') == tmp_path / 'base'
    assert execution.workspace_parent('head') == tmp_path / 'head'


def test_launch_plan_builds_a_docker_exec(tmp_path: Path) -> None:
    execution = ContainerExecution(
        work_roots={'base': tmp_path / 'base', 'head': tmp_path / 'head'},
        containers={'base': 'primer-base', 'head': 'primer-head'},
        invocation_env={'SKYLOS_GREP_BUDGET': '5'},
        user='501:20',
    )
    workspace = workspace_under(tmp_path / 'head')
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
    execution = side_execution(tmp_path)
    plan = execution.launch_plan(side='base', argv=('vulture', '.'), workspace=workspace_under(tmp_path / 'base'))
    assert '--user' not in plan.argv
    assert 'primer-base' in plan.argv


def test_analysis_root_is_the_container_side_checkout(tmp_path: Path) -> None:
    execution = side_execution(tmp_path)
    root = execution.analysis_root(workspace_under(tmp_path / 'base'))
    assert root == Path('/liveness/work/liveness-primer-side-x1/checkout')
