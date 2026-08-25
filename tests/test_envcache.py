# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the environment cache and detector install machinery (contract §3, §15)."""

import json
import shutil
import sys
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest
from filelock import FileLock, Timeout

from liveness_primer.corpus import CheckoutStore
from liveness_primer.envcache import (
    DetectorEnvironments,
    EnvCacheError,
    Installer,
    PipInstaller,
    UnsupportedDetectorError,
    UvInstaller,
    choose_installer,
    dependency_delta,
    env_executable,
    environment_fingerprint,
    parse_freeze,
    parse_static_metadata,
)
from liveness_primer.filesystem import atomic_write_bytes, atomic_write_text
from liveness_primer.findings import DependencyDelta
from liveness_primer.isolation import UNENFORCED, Isolation
from liveness_primer.launcher import LauncherError, LaunchResult, SyncLauncher, run_async, run_sync
from liveness_primer.tools.vulture import VultureAdapter

PYPROJECT = """
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "fakedet"
version = "0.1"
dependencies = ["tomli>=2"]

[project.optional-dependencies]
extra = ["rich>=13"]
"""


def write_pyproject(directory: Path, content: str = PYPROJECT) -> None:
    atomic_write_text(directory / 'pyproject.toml', content)


def test_metadata_full_document(tmp_path: Path) -> None:
    write_pyproject(tmp_path)
    metadata = parse_static_metadata(tmp_path)
    assert metadata.dependencies == ('tomli>=2',)
    assert metadata.optional_dependencies == ('rich>=13',)
    assert metadata.build_requires == ('setuptools>=61',)


def test_missing_pyproject_is_unsupported(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedDetectorError, match='v1 requires statically declared metadata'):
        parse_static_metadata(tmp_path)


def test_symlinked_pyproject_is_rejected(tmp_path: Path) -> None:
    # git clones materialize committed symlinks as symlinks; following one
    # would read outside the untrusted checkout (contract §11).
    outside = tmp_path / 'outside.toml'
    outside.write_text('[project]\nname = "d"\nversion = "1"\n', encoding='utf-8')
    checkout = tmp_path / 'checkout'
    checkout.mkdir()
    (checkout / 'pyproject.toml').symlink_to(outside)
    with pytest.raises(EnvCacheError, match='symlink'):
        parse_static_metadata(checkout)


def test_oversized_pyproject_is_rejected(tmp_path: Path) -> None:
    write_pyproject(tmp_path, '#' * 1_048_577)
    with pytest.raises(EnvCacheError, match='exceeds'):
        parse_static_metadata(tmp_path)


def test_unreadable_pyproject(tmp_path: Path) -> None:
    (tmp_path / 'pyproject.toml').mkdir()
    with pytest.raises(EnvCacheError, match='cannot read'):
        parse_static_metadata(tmp_path)


def test_invalid_toml(tmp_path: Path) -> None:
    write_pyproject(tmp_path, '[project')
    with pytest.raises(EnvCacheError, match='TOML'):
        parse_static_metadata(tmp_path)


def test_missing_project_table_is_unsupported(tmp_path: Path) -> None:
    write_pyproject(tmp_path, '[build-system]\nrequires = []\n')
    with pytest.raises(UnsupportedDetectorError, match=r'no \[project\] table'):
        parse_static_metadata(tmp_path)


@pytest.mark.parametrize('dynamic', ['dependencies', 'optional-dependencies'])
def test_dynamic_dependencies_are_unsupported(tmp_path: Path, dynamic: str) -> None:
    write_pyproject(tmp_path, f'[project]\nname = "d"\nversion = "1"\ndynamic = ["{dynamic}"]\n')
    with pytest.raises(UnsupportedDetectorError, match='dynamic dependency metadata'):
        parse_static_metadata(tmp_path)


def test_dynamic_version_is_fine(tmp_path: Path) -> None:
    write_pyproject(tmp_path, '[project]\nname = "d"\ndynamic = ["version"]\n')
    metadata = parse_static_metadata(tmp_path)
    assert metadata.dependencies == ()
    assert metadata.build_requires == ('setuptools>=40.8.0', 'wheel')


def test_non_list_dependencies_rejected(tmp_path: Path) -> None:
    write_pyproject(tmp_path, '[project]\nname = "d"\nversion = "1"\ndependencies = "tomli"\n')
    with pytest.raises(EnvCacheError, match='array of strings'):
        parse_static_metadata(tmp_path)


def test_non_table_optional_dependencies_rejected(tmp_path: Path) -> None:
    write_pyproject(tmp_path, '[project]\nname = "d"\nversion = "1"\noptional-dependencies = ["x"]\n')
    with pytest.raises(EnvCacheError, match='must be a table'):
        parse_static_metadata(tmp_path)


def test_invalid_requirement_rejected(tmp_path: Path) -> None:
    write_pyproject(tmp_path, '[project]\nname = "d"\nversion = "1"\ndependencies = ["===broken==="]\n')
    with pytest.raises(EnvCacheError, match='invalid requirement'):
        parse_static_metadata(tmp_path)


def test_parse_freeze_formats() -> None:
    freeze = [
        'Package-One==1.2.3',
        'fakedet @ file:///checkouts/fakedet',
        '# comment',
        '',
        'bare-name',
    ]
    assert parse_freeze(freeze) == {
        'package-one': '1.2.3',
        'fakedet': 'file:///checkouts/fakedet',
        'bare-name': '',
    }


def test_dependency_delta_excludes_detector_and_sorts() -> None:
    base = ['vulture==2.15', 'shared==1.0', 'gone==1.0', 'bumped==1.0']
    head = ['vulture==2.16', 'shared==1.0', 'added==2.0', 'bumped==1.1']
    delta = dependency_delta(base, head, detector_distribution='Vulture')
    assert delta == (
        DependencyDelta(package='added', base_version=None, head_version='2.0'),
        DependencyDelta(package='bumped', base_version='1.0', head_version='1.1'),
        DependencyDelta(package='gone', base_version='1.0', head_version=None),
    )


def test_environment_fingerprint_varies_by_inputs() -> None:
    adapter = VultureAdapter()
    base = environment_fingerprint('https://r', 'a' * 40, adapter, 'pip 25.0')
    assert base == environment_fingerprint('https://r', 'a' * 40, adapter, 'pip 25.0')
    assert base != environment_fingerprint('https://other', 'a' * 40, adapter, 'pip 25.0')
    assert base != environment_fingerprint('https://r', 'b' * 40, adapter, 'pip 25.0')
    assert base != environment_fingerprint('https://r', 'a' * 40, adapter, 'uv 0.9')


@dataclass
class RecordingLauncher:
    """Launcher stub returning scripted stdout and exit code."""

    stdout: str = ''
    returncode: int = 0
    timed_out: bool = False
    stderr_text: str | None = None
    calls: list[tuple[str, ...]] = field(default_factory=list)
    envs: list[Mapping[str, str] | None] = field(default_factory=list)

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        """Record the argv and environment, returning the scripted outcome.

        Returns
        -------
        LaunchResult
            The scripted outcome.
        """
        del cwd, timeout
        self.calls.append(tuple(argv))
        self.envs.append(env)
        stderr = self.stderr_text if self.stderr_text is not None else ('boom' if self.returncode else '')
        return LaunchResult(
            argv=tuple(argv),
            returncode=None if self.timed_out else self.returncode,
            stdout=self.stdout,
            stderr=stderr,
            duration_seconds=0.0,
            timed_out=self.timed_out,
        )


SANDBOX = Isolation(enforced=True, description='netns:test', prefix=('sandbox-wrap',))

SCRUBBED = {'PATH': '/usr/bin', 'HOME': '/scratch-home'}


def test_pip_installer_rejects_async_launcher() -> None:
    with pytest.raises(LauncherError, match='launcher must be synchronous'):
        PipInstaller(launcher=cast('SyncLauncher', run_async))


def test_uv_installer_rejects_async_launcher() -> None:
    with pytest.raises(LauncherError, match='launcher must be synchronous'):
        UvInstaller(launcher=cast('SyncLauncher', run_async))


def test_pip_installer_argv_and_parsing(tmp_path: Path) -> None:
    launcher = RecordingLauncher(stdout='pip 26.1.2 from /site-packages/pip (python 3.14)')
    installer = PipInstaller(launcher=launcher)
    assert installer.name == 'pip'
    assert installer.identity() == 'pip 26.1.2'
    env_dir = tmp_path / 'env'
    installer.create_venv(env_dir, isolation=SANDBOX, env=SCRUBBED)
    assert launcher.calls[-1] == ('sandbox-wrap', sys.executable, '-m', 'venv', str(env_dir))
    assert launcher.envs[-1] == SCRUBBED
    installer.install_offline(env_dir, tmp_path / 'wheels', tmp_path / 'src', isolation=SANDBOX, env=SCRUBBED)
    install_argv = launcher.calls[-1]
    assert install_argv[0] == 'sandbox-wrap'
    assert install_argv[1] == str(env_dir / 'bin' / 'python')
    assert '--no-index' in install_argv
    assert install_argv[-1] == str(tmp_path / 'src')
    assert install_argv[install_argv.index('--find-links') + 1] == str(tmp_path / 'wheels')
    assert launcher.envs[-1] == SCRUBBED
    freeze_launcher = RecordingLauncher(stdout='alpha==1.0\n\nbeta==2.0\n')
    assert PipInstaller(launcher=freeze_launcher).freeze(env_dir) == ('alpha==1.0', 'beta==2.0')
    assert freeze_launcher.calls[-1] == (str(env_dir / 'bin' / 'python'), '-m', 'pip', 'freeze')


def test_pip_installer_prefetch_uses_the_host_pip(tmp_path: Path) -> None:
    launcher = RecordingLauncher()
    PipInstaller(launcher=launcher).prefetch(('tomli>=2', 'rich>=13'), tmp_path / 'wheels')
    (argv,) = launcher.calls
    assert argv == (
        sys.executable,
        '-m',
        'pip',
        'download',
        '--quiet',
        '--dest',
        str(tmp_path / 'wheels'),
        '--prefer-binary',
        'tomli>=2',
        'rich>=13',
    )


def test_uv_installer_argv_and_parsing(tmp_path: Path) -> None:
    launcher = RecordingLauncher(stdout='uv 0.9.2 (linux)')
    installer = UvInstaller(launcher=launcher)
    assert installer.name == 'uv'
    assert installer.identity() == 'uv 0.9.2'
    env_dir = tmp_path / 'env'
    installer.create_venv(env_dir, isolation=SANDBOX, env=SCRUBBED)
    assert launcher.calls[-1] == ('sandbox-wrap', 'uv', 'venv', '--python', sys.executable, str(env_dir))
    assert launcher.envs[-1] == SCRUBBED
    installer.install_offline(env_dir, tmp_path / 'wheels', tmp_path / 'src', isolation=UNENFORCED)
    install_argv = launcher.calls[-1]
    assert install_argv[:3] == ('uv', 'pip', 'install')
    assert '--no-index' in install_argv
    installer.freeze(env_dir)
    freeze_argv: tuple[str, ...] = launcher.calls[-1]
    assert freeze_argv == ('uv', 'pip', 'freeze', '--python', str(env_dir / 'bin' / 'python'))


def test_uv_installer_prefetch_seeds_a_scratch_pip(tmp_path: Path) -> None:
    # uv has no `pip download`; the prefetch bootstraps a throwaway seeded
    # venv and downloads with its pip.
    launcher = RecordingLauncher()
    UvInstaller(launcher=launcher).prefetch(('tomli>=2',), tmp_path / 'wheels')
    seed_argv, download_argv = launcher.calls
    assert seed_argv[:4] == ('uv', 'venv', '--seed', '--python')
    helper = Path(seed_argv[-1])
    assert helper.name == 'seed-venv'
    assert download_argv[0] == str(helper / 'bin' / 'python')
    assert download_argv[1:5] == ('-m', 'pip', 'download', '--quiet')
    assert download_argv[-1] == 'tomli>=2'


def test_installer_failure_raises_env_cache_error(tmp_path: Path) -> None:
    failing = PipInstaller(launcher=RecordingLauncher(returncode=1))
    with pytest.raises(EnvCacheError, match='venv creation failed: boom'):
        failing.create_venv(tmp_path / 'env', isolation=UNENFORCED)
    timing_out = PipInstaller(launcher=RecordingLauncher(timed_out=True))
    with pytest.raises(EnvCacheError, match='pip freeze failed: timed out'):
        timing_out.freeze(tmp_path / 'env')


def test_choose_installer_returns_installer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, 'which', lambda name: '/opt/uv' if name == 'uv' else None)
    assert isinstance(choose_installer(), Installer)
    monkeypatch.setattr(shutil, 'which', lambda _name: None)
    assert isinstance(choose_installer(), Installer)


def test_choose_installer_rejects_async_launcher() -> None:
    with pytest.raises(LauncherError, match='launcher must be synchronous'):
        choose_installer(launcher=cast('SyncLauncher', run_async))


def test_choose_installer_prefers_uv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, 'which', lambda name: '/opt/uv' if name == 'uv' else None)
    assert isinstance(choose_installer(), UvInstaller)
    monkeypatch.setattr(shutil, 'which', lambda _name: None)
    assert isinstance(choose_installer(), PipInstaller)


def test_env_executable_path(tmp_path: Path) -> None:
    assert env_executable(tmp_path, 'vulture') == str(tmp_path / 'bin' / 'vulture')


def git(*args: str, cwd: Path | None = None) -> str:
    result = run_sync(['git', *args], cwd=cwd)
    assert result.ok, result.stderr
    return result.stdout.strip()


@dataclass
class DetectorRepo:
    """A throwaway detector repository with base and head branches."""

    url: str
    path: Path


@pytest.fixture
def detector_repo(tmp_path: Path) -> DetectorRepo:
    repo_dir = tmp_path / 'detector-origin'
    repo_dir.mkdir()
    git('init', '--quiet', str(repo_dir))
    git('symbolic-ref', 'HEAD', 'refs/heads/base-branch', cwd=repo_dir)
    git('config', 'user.email', 'test@example.invalid', cwd=repo_dir)
    git('config', 'user.name', 'Test', cwd=repo_dir)
    write_pyproject(repo_dir)
    git('add', 'pyproject.toml', cwd=repo_dir)
    git('commit', '--quiet', '-m', 'base', cwd=repo_dir)
    git('checkout', '--quiet', '-b', 'head-branch', cwd=repo_dir)
    write_pyproject(repo_dir, PYPROJECT.replace('tomli>=2', 'tomli>=2.1'))
    git('add', 'pyproject.toml', cwd=repo_dir)
    git('commit', '--quiet', '-m', 'head', cwd=repo_dir)
    return DetectorRepo(url=repo_dir.as_uri(), path=repo_dir)


@dataclass
class FakeInstaller:
    """Scripted installer that fabricates environments without pip."""

    freezes: deque[tuple[str, ...]]
    wheel_names: tuple[str, ...] = ('tomli-2.4.0-py3-none-any.whl', 'legacy-1.0.tar.gz', 'not-a-wheel.whl')
    wheel_symlink_target: Path | None = None
    manifest_symlink_target: Path | None = None
    name: str = 'fake'
    events: list[str] = field(default_factory=list)
    prefetches: list[tuple[str, ...]] = field(default_factory=list)
    created: list[Path] = field(default_factory=list)
    installs: list[tuple[Path, Path, Path, str]] = field(default_factory=list)
    build_envs: list[Mapping[str, str] | None] = field(default_factory=list)

    @staticmethod
    def identity() -> str:
        """Report a fixed identity.

        Returns
        -------
        str
            ``fake 1.0``.
        """
        return 'fake 1.0'

    def prefetch(self, requirements: Sequence[str], wheelhouse: Path) -> None:
        """Record the request and materialize scripted wheel files."""
        self.events.append('prefetch')
        self.prefetches.append(tuple(requirements))
        for wheel in self.wheel_names:
            destination = wheelhouse / wheel
            if self.wheel_symlink_target is None:
                atomic_write_bytes(destination, b'payload-' + wheel.encode('utf-8'))
            else:
                destination.symlink_to(self.wheel_symlink_target)

    def create_venv(self, env_dir: Path, *, isolation: Isolation, env: Mapping[str, str] | None = None) -> None:
        """Create the environment directory like a real venv would."""
        del isolation
        self.events.append('create')
        env_dir.mkdir(parents=True)
        self.created.append(env_dir)
        self.build_envs.append(env)

    def install_offline(
        self,
        env_dir: Path,
        wheelhouse: Path,
        target: Path,
        *,
        isolation: Isolation,
        env: Mapping[str, str] | None = None,
    ) -> None:
        """Record the install request."""
        del env
        self.installs.append((env_dir, wheelhouse, target, isolation.description))
        if self.manifest_symlink_target is not None:
            (env_dir / 'liveness-primer-env.json').symlink_to(self.manifest_symlink_target)

    def freeze(self, env_dir: Path) -> tuple[str, ...]:
        """Pop the next scripted freeze.

        Returns
        -------
        tuple[str, ...]
            The scripted freeze lines.
        """
        del env_dir
        return self.freezes.popleft()


def environments(
    tmp_path: Path,
    installer: FakeInstaller,
    *,
    fresh: bool = False,
    lock_timeout: float | None = None,
) -> DetectorEnvironments:
    store = CheckoutStore(tmp_path / 'cache')
    extra: dict[str, float] = {} if lock_timeout is None else {'lock_timeout': lock_timeout}
    return DetectorEnvironments(
        store,
        tmp_path / 'cache',
        installer=installer,
        isolation=SANDBOX,
        fresh=fresh,
        **extra,
    )


FREEZE_A = ('vulture @ file:///x', 'tomli==2.4.0')
FREEZE_B = ('vulture @ file:///y', 'tomli==2.4.0')
FREEZE_BUMPED = ('vulture @ file:///y', 'tomli==2.5.0')


def test_cold_cache_builds_both_and_records_fetches(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    installer = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, installer).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert pair.installer_identity == 'fake 1.0'
    assert pair.base.record.rebuilt
    assert not pair.base.record.from_cache
    assert pair.head.record.rebuilt
    assert not pair.head.record.from_cache
    assert pair.base.record.fingerprint != pair.head.record.fingerprint
    assert pair.environment_delta == ()
    assert pair.base.executable.endswith('bin/vulture')
    git_fetches = [record for record in pair.fetches if record.kind == 'git']
    assert len(git_fetches) == 2
    wheel_fetches = {record.name: record for record in pair.fetches if record.kind == 'wheel'}
    assert wheel_fetches['tomli-2.4.0-py3-none-any.whl'].resolved == '2.4.0'
    assert wheel_fetches['legacy-1.0.tar.gz'].resolved == '1.0'
    assert wheel_fetches['not-a-wheel.whl'].resolved == 'unknown'
    assert all(record.digest for record in wheel_fetches.values())
    assert len(installer.installs) == 2
    assert installer.installs[0][3] == 'netns:test'


def test_pair_prefetch_is_a_single_union_before_any_build(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # Both refs' dependencies and build requirements are prefetched together
    # before either side builds, so paired resolution sees identical inputs
    # (contract §3). The fixture's ``extra`` requirement stays out of the
    # union: the build installs no extras, so their wheels are never needed.
    installer = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, installer).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ):
        pass
    assert installer.prefetches == [('tomli>=2', 'setuptools>=61', 'tomli>=2.1')]
    assert installer.events[0] == 'prefetch'
    assert installer.events.count('prefetch') == 1
    assert installer.events.count('create') == 2


def test_prefetch_refuses_symlinked_distribution(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    outside = tmp_path / 'outside.whl'
    outside.write_bytes(b'outside payload')
    installer = FakeInstaller(
        freezes=deque(),
        wheel_names=('tomli-2.4.0-py3-none-any.whl',),
        wheel_symlink_target=outside,
    )
    with (
        pytest.raises(EnvCacheError, match='not a regular file'),
        environments(tmp_path, installer).prepare_pair(
            detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
        ),
    ):
        pass


def test_builds_use_a_scrubbed_credential_free_environment(
    tmp_path: Path,
    detector_repo: DetectorRepo,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('LP_PLANTED_SECRET', 'boom')
    installer = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, installer).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ):
        pass
    assert len(installer.build_envs) == 2
    for env in installer.build_envs:
        assert env is not None
        assert 'LP_PLANTED_SECRET' not in env
        assert 'liveness-primer-build-home-' in env['HOME']


def test_environment_locks_are_held_while_the_pair_is_in_use(
    tmp_path: Path,
    detector_repo: DetectorRepo,
) -> None:
    # Contract §3: a concurrent run (e.g. with --fresh) must not be able to
    # delete an environment while this run still executes from it.
    installer = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, installer).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        contender = FileLock(str(pair.base.env_dir) + '.lock')
        with pytest.raises(Timeout):
            contender.acquire(timeout=0.1)
    released = FileLock(str(pair.base.env_dir) + '.lock')
    released.acquire(timeout=0.1)
    released.release()


def test_warm_cache_reuses_pair_without_building(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, first).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()):
        pass
    second = FakeInstaller(freezes=deque())
    with environments(tmp_path, second).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert pair.base.record.from_cache
    assert not pair.base.record.rebuilt
    assert pair.head.record.from_cache
    assert not pair.head.record.rebuilt
    assert pair.base.record.freeze == FREEZE_A
    assert second.created == []
    assert second.prefetches == []
    assert pair.environment_delta == ()


def test_cached_delta_triggers_paired_rebuild_and_can_dissolve(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # Prime the cache with a pair whose freezes differ (a temporal artifact).
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_BUMPED]))
    with environments(tmp_path, first).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as primed:
        pass
    # Both sides were built in the same run, so the delta is ref-attributable.
    assert primed.environment_delta == (DependencyDelta(package='tomli', base_version='2.4.0', head_version='2.5.0'),)
    # A warm run sees the cached delta, rebuilds the pair, and the delta dissolves.
    second = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, second).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert pair.base.record.rebuilt
    assert pair.head.record.rebuilt
    assert pair.environment_delta == ()
    assert len(second.created) == 2


def test_surviving_delta_is_recorded_after_paired_rebuild(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_BUMPED]))
    with environments(tmp_path, first).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()):
        pass
    second = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_BUMPED]))
    with environments(tmp_path, second).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert pair.environment_delta == (DependencyDelta(package='tomli', base_version='2.4.0', head_version='2.5.0'),)


def test_fresh_forces_rebuild_of_cached_pair(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, first).prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()):
        pass
    second = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, second, fresh=True).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert pair.base.record.rebuilt
    assert pair.head.record.rebuilt
    assert len(second.created) == 2


def test_corrupt_env_manifest_triggers_rebuild(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, first).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as primed:
        pass
    manifest = primed.base.env_dir / 'liveness-primer-env.json'
    for corrupt in ('not json', '[1]', '{"other": 1}', '{"freeze": "nope"}', '{"freeze": [1]}'):
        manifest.write_text(corrupt, encoding='utf-8')
        again = FakeInstaller(freezes=deque([FREEZE_A]))
        with environments(tmp_path, again).prepare_pair(
            detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
        ) as pair:
            pass
        assert pair.base.record.rebuilt
        assert pair.head.record.from_cache


def test_symlinked_env_manifest_triggers_rebuild(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, first).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as primed:
        pass
    outside = tmp_path / 'outside-manifest.json'
    outside.write_text(json.dumps({'freeze': ['poison==1']}), encoding='utf-8')
    manifest = primed.base.env_dir / 'liveness-primer-env.json'
    manifest.unlink()
    manifest.symlink_to(outside)

    again = FakeInstaller(freezes=deque([FREEZE_A]))
    with environments(tmp_path, again).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as pair:
        pass
    assert pair.base.record.rebuilt
    assert pair.base.record.freeze == FREEZE_A
    assert pair.head.record.from_cache
    assert json.loads(outside.read_text(encoding='utf-8')) == {'freeze': ['poison==1']}


def test_build_replaces_planted_manifest_symlink(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    victim = tmp_path / 'victim.json'
    victim.write_text('do not overwrite', encoding='utf-8')
    installer = FakeInstaller(
        freezes=deque([FREEZE_A]),
        manifest_symlink_target=victim,
    )
    with environments(tmp_path, installer).prepare_pair(
        detector_repo.url, 'base-branch', 'base-branch', VultureAdapter()
    ) as pair:
        pass

    manifest = pair.base.env_dir / 'liveness-primer-env.json'
    assert victim.read_text(encoding='utf-8') == 'do not overwrite'
    assert not manifest.is_symlink()
    assert json.loads(manifest.read_text(encoding='utf-8'))['freeze'] == list(FREEZE_A)


def test_same_ref_on_both_sides_records_one_git_fetch(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    installer = FakeInstaller(freezes=deque([FREEZE_A]))
    with environments(tmp_path, installer).prepare_pair(
        detector_repo.url, 'base-branch', 'base-branch', VultureAdapter()
    ) as pair:
        pass
    git_fetches = [record for record in pair.fetches if record.kind == 'git']
    assert len(git_fetches) == 1
    assert pair.base.record.fingerprint == pair.head.record.fingerprint
    # The same fingerprint is built once and then served from cache.
    assert pair.base.record.rebuilt
    assert pair.head.record.from_cache


def test_empty_requirements_skip_the_prefetch(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    git('checkout', '--quiet', '-b', 'minimal', cwd=detector_repo.path)
    write_pyproject(detector_repo.path, '[build-system]\nrequires = []\n\n[project]\nname = "d"\nversion = "1"\n')
    git('add', 'pyproject.toml', cwd=detector_repo.path)
    git('commit', '--quiet', '-m', 'minimal', cwd=detector_repo.path)
    installer = FakeInstaller(freezes=deque([FREEZE_A]))
    with environments(tmp_path, installer).prepare_pair(
        detector_repo.url, 'minimal', 'minimal', VultureAdapter()
    ) as pair:
        pass
    assert installer.prefetches == []
    assert [record.kind for record in pair.fetches] == ['git']


def test_env_lock_timeout_raises(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    installer = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    with environments(tmp_path, installer).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    ) as primed:
        pass
    held = FileLock(str(primed.base.env_dir) + '.lock')
    held.acquire()
    try:
        impatient = environments(tmp_path, FakeInstaller(freezes=deque()), lock_timeout=0.2)
        with (
            pytest.raises(EnvCacheError, match='timed out waiting for the environment lock'),
            impatient.prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()),
        ):
            pass
    finally:
        held.release()
