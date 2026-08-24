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
from typing import Literal, cast

import pytest
from filelock import FileLock

import liveness_primer.container as container_module
from liveness_primer.container import (
    CONTAINER_ISOLATION,
    CONTAINER_TMP_ROOT,
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
    stage_invocation_env_files,
    stage_wheelhouses,
)
from liveness_primer.corpus import CheckoutStore
from liveness_primer.execution import SideWorkspace
from liveness_primer.filesystem import atomic_write_bytes, atomic_write_text, read_small_text
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


def test_default_container_image_uses_current_python() -> None:
    assert DEFAULT_CONTAINER_IMAGE == 'python:3.14-slim'


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


def test_container_fingerprint_tracks_the_cache_format(monkeypatch: pytest.MonkeyPatch) -> None:
    # A cache-format / security revision must make every prior image miss the
    # cache and rebuild, so it participates in the fingerprint material.
    adapter = VultureAdapter()
    before = container_fingerprint('https://r', 'a' * 40, adapter, 'docker 27', 'python:3.12-slim')
    monkeypatch.setattr(container_module, '_CONTAINER_CACHE_FORMAT', 999)
    assert before != container_fingerprint('https://r', 'a' * 40, adapter, 'docker 27', 'python:3.12-slim')


def test_image_tag_embeds_the_fingerprint() -> None:
    assert image_tag('abc123') == 'liveness-primer/env:abc123'


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
    # Files a head-side build hook fabricates during the head fetch (the
    # fetch with a find_links source); each maps a filename to its bytes.
    fabricate: dict[str, bytes] = field(default_factory=dict)
    events: list[str] = field(default_factory=list)
    existing_images: set[str] = field(default_factory=set)
    prefetches: list[tuple[str, tuple[str, ...], Path | None]] = field(default_factory=list)
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
        del tag
        self.events.append('pyver')
        return '3.14.99'

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


def test_container_mode_refuses_hosts_without_posix_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The §11 run-as-host-user hardening cannot be enforced without POSIX
    # ids; the mode refuses instead of silently running as the untrusted
    # image's default user while recording enforced isolation.
    monkeypatch.delattr(os, 'getuid')
    with pytest.raises(ContainerError, match='requires POSIX user ids'):
        environments(tmp_path, FakeDocker())


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
        assert pair.installer_identity == f'docker 99.9; image {DEFAULT_CONTAINER_IMAGE}'
        assert pair.python_version == '3.14.99'
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
    assert base_fetch == (DEFAULT_CONTAINER_IMAGE, ('tomli>=2', 'setuptools>=61'), None)
    head_image, head_reqs, head_links = head_fetch
    assert head_image == DEFAULT_CONTAINER_IMAGE
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
    # Build contexts are offline and self-contained: Dockerfile, the
    # .git-less checkout, and the shared wheelhouse (contract §3, §11).
    for names, dockerfile in docker.built_contexts:
        assert dockerfile.startswith(f'FROM {DEFAULT_CONTAINER_IMAGE}\n')
        assert 'detector/pyproject.toml' in names
        assert 'wheelhouse/tomli-1.0-py3-none-any.whl' in names
        assert 'wheelhouse/setuptools-1.0-py3-none-any.whl' in names
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
    assert docker.removed == []
    assert all(not path.exists() for path in docker.staging_paths)


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
            repo_url, store.resolve_ref(repo_url, ref), adapter, 'docker 99.9', DEFAULT_CONTAINER_IMAGE
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


@pytest.mark.parametrize('level', ['root', 'pair', 'base'])
@pytest.mark.parametrize('kind', ['symlink', 'file'])
def test_unsafe_container_cache_directories_are_rejected(
    tmp_path: Path,
    detector_repo: DetectorRepo,
    level: Literal['root', 'pair', 'base'],
    kind: Literal['symlink', 'file'],
) -> None:
    pair_dir, _base_tag = pair_dir_and_base_tag(tmp_path, detector_repo.url)
    locations = {'root': pair_dir.parent, 'pair': pair_dir, 'base': pair_dir / 'base'}
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
