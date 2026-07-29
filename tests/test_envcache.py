"""Tests for the environment cache and detector install machinery (contract §3, §15).

Copyright (C) 2026 Matthew C. Digman
"""

import shutil
import sys
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from filelock import FileLock

from liveness_primer.corpus import CheckoutStore
from liveness_primer.envcache import (
    DetectorEnvironments,
    EnvCacheError,
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
from liveness_primer.findings import DependencyDelta
from liveness_primer.isolation import UNENFORCED, Isolation
from liveness_primer.launcher import LaunchResult, run_sync
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
    (directory / 'pyproject.toml').write_text(content, encoding='utf-8')


def test_metadata_full_document(tmp_path: Path) -> None:
    write_pyproject(tmp_path)
    metadata = parse_static_metadata(tmp_path)
    assert metadata.dependencies == ('tomli>=2',)
    assert metadata.optional_dependencies == ('rich>=13',)
    assert metadata.build_requires == ('setuptools>=61',)


def test_missing_pyproject_is_unsupported(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedDetectorError, match='v1 requires statically declared metadata'):
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
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        """Record the argv and return the scripted outcome.

        Returns
        -------
        LaunchResult
            The scripted outcome.
        """
        del cwd, env, timeout
        self.calls.append(tuple(argv))
        return LaunchResult(
            argv=tuple(argv),
            returncode=None if self.timed_out else self.returncode,
            stdout=self.stdout,
            stderr='boom' if self.returncode else '',
            duration_seconds=0.0,
            timed_out=self.timed_out,
        )


SANDBOX = Isolation(enforced=True, description='netns:test', prefix=('sandbox-wrap',))


def test_pip_installer_argv_and_parsing(tmp_path: Path) -> None:
    launcher = RecordingLauncher(stdout='pip 26.1.2 from /site-packages/pip (python 3.14)')
    installer = PipInstaller(launcher=launcher)
    assert installer.name == 'pip'
    assert installer.identity() == 'pip 26.1.2'
    env_dir = tmp_path / 'env'
    installer.create_venv(env_dir)
    assert launcher.calls[-1] == (sys.executable, '-m', 'venv', str(env_dir))
    installer.install_offline(env_dir, tmp_path / 'wheels', tmp_path / 'src', SANDBOX)
    install_argv = launcher.calls[-1]
    assert install_argv[0] == 'sandbox-wrap'
    assert install_argv[1] == str(env_dir / 'bin' / 'python')
    assert '--no-index' in install_argv
    assert install_argv[-1] == str(tmp_path / 'src')
    assert install_argv[install_argv.index('--find-links') + 1] == str(tmp_path / 'wheels')
    freeze_launcher = RecordingLauncher(stdout='alpha==1.0\n\nbeta==2.0\n')
    assert PipInstaller(launcher=freeze_launcher).freeze(env_dir) == ('alpha==1.0', 'beta==2.0')
    assert freeze_launcher.calls[-1] == (str(env_dir / 'bin' / 'python'), '-m', 'pip', 'freeze')


def test_uv_installer_argv_and_parsing(tmp_path: Path) -> None:
    launcher = RecordingLauncher(stdout='uv 0.9.2 (linux)')
    installer = UvInstaller(launcher=launcher)
    assert installer.name == 'uv'
    assert installer.identity() == 'uv 0.9.2'
    env_dir = tmp_path / 'env'
    installer.create_venv(env_dir)
    assert launcher.calls[-1] == ('uv', 'venv', '--python', sys.executable, str(env_dir))
    installer.install_offline(env_dir, tmp_path / 'wheels', tmp_path / 'src', UNENFORCED)
    install_argv = launcher.calls[-1]
    assert install_argv[:3] == ('uv', 'pip', 'install')
    assert '--no-index' in install_argv
    installer.freeze(env_dir)
    assert launcher.calls[-1] == ('uv', 'pip', 'freeze', '--python', str(env_dir / 'bin' / 'python'))


def test_installer_failure_raises_env_cache_error(tmp_path: Path) -> None:
    failing = PipInstaller(launcher=RecordingLauncher(returncode=1))
    with pytest.raises(EnvCacheError, match='venv creation failed: boom'):
        failing.create_venv(tmp_path / 'env')
    timing_out = PipInstaller(launcher=RecordingLauncher(timed_out=True))
    with pytest.raises(EnvCacheError, match='pip freeze failed: timed out'):
        timing_out.freeze(tmp_path / 'env')


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
    name: str = 'fake'
    created: list[Path] = field(default_factory=list)
    installs: list[tuple[Path, Path, Path, str]] = field(default_factory=list)

    @staticmethod
    def identity() -> str:
        """Report a fixed identity.

        Returns
        -------
        str
            ``fake 1.0``.
        """
        return 'fake 1.0'

    def create_venv(self, env_dir: Path) -> None:
        """Create the environment directory like a real venv would."""
        env_dir.mkdir(parents=True)
        self.created.append(env_dir)

    def install_offline(self, env_dir: Path, wheelhouse: Path, target: Path, isolation: Isolation) -> None:
        """Record the install request."""
        self.installs.append((env_dir, wheelhouse, target, isolation.description))

    def freeze(self, env_dir: Path) -> tuple[str, ...]:
        """Pop the next scripted freeze.

        Returns
        -------
        tuple[str, ...]
            The scripted freeze lines.
        """
        del env_dir
        return self.freezes.popleft()


@dataclass
class PrefetchLauncher:
    """Launcher stub that materializes wheel files for pip download calls."""

    wheel_names: tuple[str, ...] = ('tomli-2.4.0-py3-none-any.whl', 'legacy-1.0.tar.gz', 'not-a-wheel.whl')
    downloads: list[tuple[str, ...]] = field(default_factory=list)

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        """Simulate pip download by writing scripted files into --dest.

        Returns
        -------
        LaunchResult
            A success result.
        """
        del cwd, env, timeout
        assert list(argv[:4]) == [sys.executable, '-m', 'pip', 'download'], argv
        self.downloads.append(tuple(argv))
        dest = Path(argv[argv.index('--dest') + 1])
        for name in self.wheel_names:
            (dest / name).write_bytes(b'payload-' + name.encode('utf-8'))
        return LaunchResult(argv=tuple(argv), returncode=0, stdout='', stderr='', duration_seconds=0.0, timed_out=False)


def environments(
    tmp_path: Path,
    installer: FakeInstaller,
    launcher: PrefetchLauncher,
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
        launcher=launcher,
        isolation=SANDBOX,
        fresh=fresh,
        **extra,
    )


FREEZE_A = ('vulture @ file:///x', 'tomli==2.4.0')
FREEZE_B = ('vulture @ file:///y', 'tomli==2.4.0')
FREEZE_BUMPED = ('vulture @ file:///y', 'tomli==2.5.0')


def test_cold_cache_builds_both_and_records_fetches(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    installer = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    launcher = PrefetchLauncher()
    pair = environments(tmp_path, installer, launcher).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
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
    assert len(launcher.downloads) == 2


def test_warm_cache_reuses_pair_without_building(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    environments(tmp_path, first, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    second = FakeInstaller(freezes=deque())
    pair = environments(tmp_path, second, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    assert pair.base.record.from_cache
    assert not pair.base.record.rebuilt
    assert pair.head.record.from_cache
    assert not pair.head.record.rebuilt
    assert pair.base.record.freeze == FREEZE_A
    assert second.created == []
    assert pair.environment_delta == ()


def test_cached_delta_triggers_paired_rebuild_and_can_dissolve(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    # Prime the cache with a pair whose freezes differ (a temporal artifact).
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_BUMPED]))
    primed = environments(tmp_path, first, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    # Both sides were built in the same run, so the delta is ref-attributable.
    assert primed.environment_delta == (DependencyDelta(package='tomli', base_version='2.4.0', head_version='2.5.0'),)
    # A warm run sees the cached delta, rebuilds the pair, and the delta dissolves.
    second = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    pair = environments(tmp_path, second, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    assert pair.base.record.rebuilt
    assert pair.head.record.rebuilt
    assert pair.environment_delta == ()
    assert len(second.created) == 2


def test_surviving_delta_is_recorded_after_paired_rebuild(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_BUMPED]))
    environments(tmp_path, first, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    second = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_BUMPED]))
    pair = environments(tmp_path, second, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    assert pair.environment_delta == (DependencyDelta(package='tomli', base_version='2.4.0', head_version='2.5.0'),)


def test_fresh_forces_rebuild_of_cached_pair(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    environments(tmp_path, first, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    second = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    pair = environments(tmp_path, second, PrefetchLauncher(), fresh=True).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    assert pair.base.record.rebuilt
    assert pair.head.record.rebuilt
    assert len(second.created) == 2


def test_corrupt_env_manifest_triggers_rebuild(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    first = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    primed = environments(tmp_path, first, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    manifest = primed.base.env_dir / 'liveness-primer-env.json'
    for corrupt in ('not json', '[1]', '{"other": 1}', '{"freeze": "nope"}', '{"freeze": [1]}'):
        manifest.write_text(corrupt, encoding='utf-8')
        again = FakeInstaller(freezes=deque([FREEZE_A]))
        pair = environments(tmp_path, again, PrefetchLauncher()).prepare_pair(
            detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
        )
        assert pair.base.record.rebuilt
        assert pair.head.record.from_cache


def test_same_ref_on_both_sides_records_one_git_fetch(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    installer = FakeInstaller(freezes=deque([FREEZE_A]))
    launcher = PrefetchLauncher()
    pair = environments(tmp_path, installer, launcher).prepare_pair(
        detector_repo.url, 'base-branch', 'base-branch', VultureAdapter()
    )
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
    launcher = PrefetchLauncher()
    pair = environments(tmp_path, installer, launcher).prepare_pair(
        detector_repo.url, 'minimal', 'minimal', VultureAdapter()
    )
    assert launcher.downloads == []
    assert [record.kind for record in pair.fetches] == ['git']


def test_env_lock_timeout_raises(tmp_path: Path, detector_repo: DetectorRepo) -> None:
    installer = FakeInstaller(freezes=deque([FREEZE_A, FREEZE_B]))
    primed = environments(tmp_path, installer, PrefetchLauncher()).prepare_pair(
        detector_repo.url, 'base-branch', 'head-branch', VultureAdapter()
    )
    held = FileLock(str(primed.base.env_dir) + '.lock')
    held.acquire()
    try:
        impatient = environments(tmp_path, FakeInstaller(freezes=deque()), PrefetchLauncher(), lock_timeout=0.2)
        with pytest.raises(EnvCacheError, match='timed out waiting for the environment lock'):
            impatient.prepare_pair(detector_repo.url, 'base-branch', 'head-branch', VultureAdapter())
    finally:
        held.release()
