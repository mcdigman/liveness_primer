# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Fingerprint-keyed detector environment cache and install machinery (contract §3).

Detector refs are installed into isolated cached virtualenvs. Dependencies
are resolved by statically parsing ``[project.dependencies]`` and
``[build-system].requires`` — no build backend is invoked during the fetch
step — then prefetched into a local wheel cache. Builds install offline
(``--no-index --find-links``) under the §11 sandbox. Cache entries are keyed
by the full fingerprint and guarded by ``filelock``; attribution of
dependency deltas is temporal, never textual.
"""

import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import sysconfig
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeGuard, runtime_checkable

from filelock import BaseFileLock, FileLock, Timeout
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from liveness_primer.corpus import CheckoutStore
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.findings import DependencyDelta, EnvironmentRecord, FetchRecord
from liveness_primer.isolation import UNENFORCED, Isolation, scrubbed_environment
from liveness_primer.launcher import LaunchResult, SyncLauncher, run_sync, validate_sync_launcher
from liveness_primer.tools.base import DetectorAdapter, GoExecutableBuild

_DEFAULT_BUILD_REQUIRES: tuple[str, ...] = ('setuptools>=40.8.0', 'wheel')

_INSTALL_TIMEOUT = 1800.0
_GO_VERSION_PATTERN = re.compile(r'\bgo(?P<version>[0-9]+(?:\.[0-9]+){1,2})\b')

# Upper bound for the statically parsed pyproject.toml: real files are a few
# KiB; anything larger is hostile or broken (contract §11 untrusted content).
_MAX_PYPROJECT_BYTES = 1_048_576


class EnvCacheError(LivenessPrimerError):
    """Raised when a detector environment cannot be prepared."""


class UnsupportedDetectorError(EnvCacheError):
    """Raised for detectors violating the §4 static-metadata rule."""


@dataclass(frozen=True, slots=True)
class _GoToolchain:
    """Resolved Go compiler used by one managed environment build."""

    executable: str
    identity: str


@dataclass(frozen=True, slots=True)
class _GoBuildPlan:
    """Resolved revision-scoped Go build inputs."""

    source: Path
    recipe: GoExecutableBuild
    toolchain: _GoToolchain


@dataclass(frozen=True, slots=True)
class _CachedEnvironment:
    """Validated private cache metadata for one managed environment."""

    freeze: tuple[str, ...]
    artifacts: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class DetectorMetadata:
    """Statically parsed dependency metadata of one detector ref (contract §3).

    Attributes
    ----------
    dependencies : tuple[str, ...]
        ``[project.dependencies]`` requirement strings.
    optional_dependencies : tuple[str, ...]
        Flattened ``[project.optional-dependencies]`` requirement strings.
    build_requires : tuple[str, ...]
        ``[build-system].requires``, defaulted per PEP 518 when absent.
    """

    dependencies: tuple[str, ...]
    optional_dependencies: tuple[str, ...]
    build_requires: tuple[str, ...]


def _require_str_list(value: object, *, where: str) -> tuple[str, ...]:
    """Validate an untrusted TOML value as a list of strings.

    Parameters
    ----------
    value : object
        Parsed TOML value.
    where : str
        Location description for error messages.

    Returns
    -------
    tuple[str, ...]
        The validated strings.

    Raises
    ------
    EnvCacheError
        If the value is not a list of strings.
    """
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        msg = f'{where} must be an array of strings'
        raise EnvCacheError(msg)
    return tuple(value)


def _check_requirements(requirements: Iterable[str], *, where: str) -> None:
    """Validate that requirement strings parse as PEP 508 requirements.

    Parameters
    ----------
    requirements : Iterable[str]
        Requirement strings from detector metadata.
    where : str
        Location description for error messages.

    Raises
    ------
    EnvCacheError
        If a requirement string is invalid.
    """
    for requirement in requirements:
        try:
            Requirement(requirement)
        except InvalidRequirement as exc:
            msg = f'invalid requirement {requirement!r} in {where}: {exc}'
            raise EnvCacheError(msg) from exc


def _read_pyproject_text(pyproject: Path) -> str:
    """Read an untrusted ``pyproject.toml`` defensively (contract §11).

    The checkout is untrusted and this read happens during the fetch step,
    before any sandbox exists: symlinks are refused (git happily
    materializes one pointing anywhere) and the read size is capped.

    Parameters
    ----------
    pyproject : Path
        The ``pyproject.toml`` location inside the checkout.

    Returns
    -------
    str
        The file contents.

    Raises
    ------
    UnsupportedDetectorError
        If the file is missing.
    EnvCacheError
        If the file is a symlink, oversized, or unreadable.
    """
    if pyproject.is_symlink():
        msg = 'detector pyproject.toml is a symlink; refusing to follow it out of the checkout (§11)'
        raise EnvCacheError(msg)
    if pyproject.exists() and pyproject.stat().st_size > _MAX_PYPROJECT_BYTES:
        msg = f'detector pyproject.toml exceeds {_MAX_PYPROJECT_BYTES} bytes'
        raise EnvCacheError(msg)
    try:
        return pyproject.read_text(encoding='utf-8')
    except FileNotFoundError as exc:
        msg = 'detector has no pyproject.toml; v1 requires statically declared metadata (§4)'
        raise UnsupportedDetectorError(msg) from exc
    except OSError as exc:
        msg = f'cannot read {pyproject}: {exc}'
        raise EnvCacheError(msg) from exc


def parse_static_metadata(checkout: Path) -> DetectorMetadata:
    """Parse detector dependencies statically — no build backend runs (contract §3).

    Enforces the §4 static-metadata rule: ``dependencies`` and
    ``optional-dependencies`` must not be listed in ``[project].dynamic``;
    other dynamic fields (e.g. ``version``) are fine and resolve during the
    sandboxed build.

    Parameters
    ----------
    checkout : Path
        Detector checkout directory.

    Returns
    -------
    DetectorMetadata
        The statically declared dependency sets.

    Raises
    ------
    UnsupportedDetectorError
        If ``pyproject.toml`` or ``[project]`` is missing, or dependency
        metadata is dynamic.
    EnvCacheError
        If the file is a symlink, oversized, unreadable, not valid TOML,
        or malformed.
    """
    text = _read_pyproject_text(checkout / 'pyproject.toml')
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        msg = f'detector pyproject.toml is not valid TOML: {exc}'
        raise EnvCacheError(msg) from exc
    project = data.get('project')
    if not isinstance(project, dict):
        msg = 'detector pyproject.toml has no [project] table; v1 requires statically declared metadata (§4)'
        raise UnsupportedDetectorError(msg)
    dynamic = _require_str_list(project.get('dynamic', []), where='[project].dynamic')
    if 'dependencies' in dynamic or 'optional-dependencies' in dynamic:
        msg = 'detector declares dynamic dependency metadata and is unsupported (§4)'
        raise UnsupportedDetectorError(msg)
    dependencies = _require_str_list(project.get('dependencies', []), where='[project.dependencies]')
    optional_raw = project.get('optional-dependencies', {})
    if not isinstance(optional_raw, dict):
        msg = '[project.optional-dependencies] must be a table'
        raise EnvCacheError(msg)
    optional: list[str] = []
    for extra, entries in optional_raw.items():
        optional.extend(_require_str_list(entries, where=f'[project.optional-dependencies].{extra}'))
    build_system = data.get('build-system', {})
    build_requires = _DEFAULT_BUILD_REQUIRES
    if isinstance(build_system, dict) and 'requires' in build_system:
        build_requires = _require_str_list(build_system['requires'], where='[build-system].requires')
    _check_requirements(dependencies, where='[project.dependencies]')
    _check_requirements(optional, where='[project.optional-dependencies]')
    _check_requirements(build_requires, where='[build-system].requires')
    return DetectorMetadata(
        dependencies=dependencies,
        optional_dependencies=tuple(optional),
        build_requires=build_requires,
    )


@runtime_checkable
class Installer(Protocol):
    """Injectable environment installer (contract §3, §15)."""

    @property
    def name(self) -> str:
        """Installer family name (``uv`` or ``pip``).

        Returns
        -------
        str
            The family name.
        """
        ...

    def identity(self) -> str:
        """Report the installer name and version for the fingerprint.

        Returns
        -------
        str
            E.g. ``pip 25.0`` or ``uv 0.9.2``.
        """
        ...

    def prefetch(self, requirements: Sequence[str], wheelhouse: Path) -> None:
        """Download distributions into the local wheel cache (fetch step, §3).

        Parameters
        ----------
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        wheelhouse : Path
            Destination wheel cache directory.
        """
        ...

    def create_venv(self, env_dir: Path, *, isolation: Isolation, env: Mapping[str, str] | None = None) -> None:
        """Create a fresh virtualenv (build step, sandboxed, §3).

        Parameters
        ----------
        env_dir : Path
            Directory the virtualenv is created in.
        isolation : Isolation
            Network isolation wrapped around the creation (contract §11).
        env : Mapping[str, str] | None
            Scrubbed environment for the subprocess (contract §3).
        """
        ...

    def install_offline(
        self,
        env_dir: Path,
        wheelhouse: Path,
        target: Path,
        *,
        isolation: Isolation,
        env: Mapping[str, str] | None = None,
    ) -> None:
        """Install a project into the virtualenv from the local wheel cache only.

        Parameters
        ----------
        env_dir : Path
            The virtualenv to install into.
        wheelhouse : Path
            Local wheel cache used via ``--no-index --find-links``.
        target : Path
            Project directory to build and install (sandboxed).
        isolation : Isolation
            Network isolation wrapped around the build (contract §11).
        env : Mapping[str, str] | None
            Scrubbed environment for the subprocess (contract §3).
        """
        ...

    def freeze(self, env_dir: Path) -> tuple[str, ...]:
        """Capture the resolved dependency freeze of the virtualenv.

        Parameters
        ----------
        env_dir : Path
            The virtualenv to freeze.

        Returns
        -------
        tuple[str, ...]
            Freeze lines.
        """
        ...


def _env_python(env_dir: Path) -> str:
    """Locate the interpreter inside a virtualenv.

    Parameters
    ----------
    env_dir : Path
        The virtualenv directory.

    Returns
    -------
    str
        Path to the interpreter.
    """
    scripts = 'Scripts' if os.name == 'nt' else 'bin'
    exe = 'python.exe' if os.name == 'nt' else 'python'
    return str(env_dir / scripts / exe)


def env_executable(env_dir: Path, executable: str) -> str:
    """Locate a console script inside a virtualenv.

    Parameters
    ----------
    env_dir : Path
        The virtualenv directory.
    executable : str
        Console-script name declared by the adapter.

    Returns
    -------
    str
        Path to the console script.
    """
    scripts = 'Scripts' if os.name == 'nt' else 'bin'
    suffix = '.exe' if os.name == 'nt' else ''
    return str(env_dir / scripts / (executable + suffix))


def _checked(result: LaunchResult, *, action: str) -> LaunchResult:
    """Raise a domain error when an installer command failed.

    Parameters
    ----------
    result : LaunchResult
        The launch outcome.
    action : str
        Description for the error message.

    Returns
    -------
    LaunchResult
        The successful result.

    Raises
    ------
    EnvCacheError
        If the command failed or timed out.
    """
    if not result.ok:
        detail = 'timed out' if result.timed_out else result.stderr.strip()[-1000:]
        msg = f'{action} failed: {detail}'
        raise EnvCacheError(msg)
    return result


def _artifact_digest(path: Path) -> str:
    """Hash one regular, non-symlink build artifact.

    Parameters
    ----------
    path : Path
        Artifact path.

    Returns
    -------
    str
        SHA-256 hex digest.

    Raises
    ------
    EnvCacheError
        If the path is not a regular file.
    """
    if path.is_symlink() or not path.is_file():
        msg = f'build artifact is not a regular file: {path.name}'
        raise EnvCacheError(msg)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1_048_576), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _go_source_directory(checkout: Path, build: GoExecutableBuild) -> Path | None:
    """Resolve an optional Go module without following checkout symlinks.

    Parameters
    ----------
    checkout : Path
        Detector checkout.
    build : GoExecutableBuild
        Adapter-declared build specification.

    Returns
    -------
    Path | None
        Go module path, or ``None`` when the revision has no module.

    Raises
    ------
    EnvCacheError
        If the declared source is unsafe or malformed.
    """
    relative = build.source_dir
    if not relative.parts or relative.is_absolute() or '..' in relative.parts:
        msg = f'invalid Go build source directory: {relative.as_posix()!r}'
        raise EnvCacheError(msg)
    candidate = checkout
    for part in relative.parts:
        candidate /= part
        if candidate.is_symlink():
            msg = f'Go build source traverses a symlink: {relative.as_posix()}'
            raise EnvCacheError(msg)
    if not candidate.exists():
        return None
    if not candidate.is_dir():
        msg = f'Go build source is not a directory: {relative.as_posix()}'
        raise EnvCacheError(msg)
    go_mod = candidate / 'go.mod'
    if go_mod.is_symlink() or not go_mod.is_file():
        msg = f'Go build source has no regular go.mod: {relative.as_posix()}'
        raise EnvCacheError(msg)
    return candidate


def _resolve_go_toolchain(
    build: GoExecutableBuild,
    *,
    launcher: SyncLauncher,
    isolation: Isolation,
) -> _GoToolchain:
    """Resolve, validate, and identify the host Go compiler.

    Parameters
    ----------
    build : GoExecutableBuild
        Adapter-declared build specification.
    launcher : SyncLauncher
        Audited launcher for the version probe.
    isolation : Isolation
        Network isolation wrapper.

    Returns
    -------
    _GoToolchain
        Validated compiler path and cache identity.

    Raises
    ------
    EnvCacheError
        If Go is missing, invalid, or too old.
    """
    executable = shutil.which('go')
    if executable is None:
        msg = f'{build.executable} requires Go >= {build.minimum_version} on PATH'
        raise EnvCacheError(msg)
    resolved = Path(executable).resolve()
    if not resolved.is_file():
        msg = f'Go toolchain is not a regular file: {executable}'
        raise EnvCacheError(msg)
    with tempfile.TemporaryDirectory(prefix='liveness-primer-go-version-home-') as scratch_home:
        env = scrubbed_environment(home=Path(scratch_home))
        env['GOTOOLCHAIN'] = 'local'
        result = _checked(
            launcher(isolation.wrap([str(resolved), 'version']), env=env, timeout=60.0),
            action='go version',
        )
    match = _GO_VERSION_PATTERN.search(result.stdout)
    if match is None:
        msg = f'could not parse Go version from {result.stdout.strip()!r}'
        raise EnvCacheError(msg)
    try:
        version = Version(match.group('version'))
        minimum = Version(build.minimum_version)
    except InvalidVersion as exc:
        msg = f'invalid Go toolchain version: {exc}'
        raise EnvCacheError(msg) from exc
    if version < minimum:
        msg = f'{build.executable} requires Go >= {minimum}; found {version}'
        raise EnvCacheError(msg)
    identity = f'{result.stdout.strip()} sha256:{_artifact_digest(resolved)}'
    return _GoToolchain(executable=str(resolved), identity=identity)


@dataclass(frozen=True, slots=True)
class PipInstaller:
    """Stdlib ``venv`` + ``pip`` installer (the fallback path, contract §3).

    Attributes
    ----------
    name : str
        ``pip``.
    python : str
        Host interpreter used to create virtualenvs.
    launcher : SyncLauncher
        Audited launcher for every invocation.
    """

    name: str = 'pip'
    python: str = sys.executable
    launcher: SyncLauncher = run_sync

    def __post_init__(self) -> None:
        """Validate the injected launcher."""
        validate_sync_launcher(self.launcher)

    def identity(self) -> str:
        """Report the host pip name and version.

        Returns
        -------
        str
            E.g. ``pip 25.0``.
        """
        result = _checked(
            self.launcher([self.python, '-m', 'pip', '--version'], timeout=_INSTALL_TIMEOUT),
            action='pip --version',
        )
        return ' '.join(result.stdout.split()[:2])

    def prefetch(self, requirements: Sequence[str], wheelhouse: Path) -> None:
        """Download distributions with the host pip (fetch step, §3).

        Parameters
        ----------
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        wheelhouse : Path
            Destination wheel cache directory.
        """
        argv = [
            self.python,
            '-m',
            'pip',
            'download',
            '--quiet',
            '--dest',
            str(wheelhouse),
            '--prefer-binary',
            *requirements,
        ]
        _checked(self.launcher(argv, timeout=_INSTALL_TIMEOUT), action='dependency prefetch (pip download)')

    def create_venv(self, env_dir: Path, *, isolation: Isolation, env: Mapping[str, str] | None = None) -> None:
        """Create a virtualenv with bundled pip (sandboxed, §3).

        Parameters
        ----------
        env_dir : Path
            Directory the virtualenv is created in.
        isolation : Isolation
            Network isolation wrapped around the creation (contract §11).
        env : Mapping[str, str] | None
            Scrubbed environment for the subprocess (contract §3).
        """
        argv = [self.python, '-m', 'venv', str(env_dir)]
        _checked(
            self.launcher(isolation.wrap(argv), env=env, timeout=_INSTALL_TIMEOUT),
            action='venv creation',
        )

    def install_offline(
        self,
        env_dir: Path,
        wheelhouse: Path,
        target: Path,
        *,
        isolation: Isolation,
        env: Mapping[str, str] | None = None,
    ) -> None:
        """Install the detector offline with the virtualenv's own pip.

        Parameters
        ----------
        env_dir : Path
            The virtualenv to install into.
        wheelhouse : Path
            Local wheel cache used via ``--no-index --find-links``.
        target : Path
            Project directory to build and install (sandboxed).
        isolation : Isolation
            Network isolation wrapped around the build (contract §11).
        env : Mapping[str, str] | None
            Scrubbed environment for the subprocess (contract §3).
        """
        argv = [
            _env_python(env_dir),
            '-m',
            'pip',
            'install',
            '--quiet',
            '--no-index',
            '--find-links',
            str(wheelhouse),
            str(target),
        ]
        _checked(self.launcher(isolation.wrap(argv), env=env, timeout=_INSTALL_TIMEOUT), action='pip install')

    def freeze(self, env_dir: Path) -> tuple[str, ...]:
        """Capture the freeze with the virtualenv's own pip.

        Parameters
        ----------
        env_dir : Path
            The virtualenv to freeze.

        Returns
        -------
        tuple[str, ...]
            Freeze lines.
        """
        result = _checked(
            self.launcher([_env_python(env_dir), '-m', 'pip', 'freeze'], timeout=_INSTALL_TIMEOUT),
            action='pip freeze',
        )
        return tuple(line for line in result.stdout.splitlines() if line.strip())


@dataclass(frozen=True, slots=True)
class UvInstaller:
    """``uv``-based installer, used opportunistically when on ``PATH`` (contract §3).

    Attributes
    ----------
    name : str
        ``uv``.
    python : str
        Host interpreter the virtualenvs are created for.
    launcher : SyncLauncher
        Audited launcher for every invocation.
    """

    name: str = 'uv'
    python: str = sys.executable
    launcher: SyncLauncher = run_sync

    def __post_init__(self) -> None:
        """Validate the injected launcher."""
        validate_sync_launcher(self.launcher)

    def identity(self) -> str:
        """Report the uv name and version.

        Returns
        -------
        str
            E.g. ``uv 0.9.2``.
        """
        result = _checked(self.launcher(['uv', '--version'], timeout=_INSTALL_TIMEOUT), action='uv --version')
        return ' '.join(result.stdout.split()[:2])

    def prefetch(self, requirements: Sequence[str], wheelhouse: Path) -> None:
        """Download distributions via a seeded scratch venv (fetch step, §3).

        ``uv`` has no ``pip download`` equivalent, so a throwaway
        ``uv venv --seed`` environment supplies the pip that fills the
        wheelhouse.

        Parameters
        ----------
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        wheelhouse : Path
            Destination wheel cache directory.
        """
        with tempfile.TemporaryDirectory(prefix='liveness-primer-uv-seed-') as scratch:
            helper = Path(scratch) / 'seed-venv'
            _checked(
                self.launcher(['uv', 'venv', '--seed', '--python', self.python, str(helper)], timeout=_INSTALL_TIMEOUT),
                action='uv venv --seed',
            )
            argv = [
                _env_python(helper),
                '-m',
                'pip',
                'download',
                '--quiet',
                '--dest',
                str(wheelhouse),
                '--prefer-binary',
                *requirements,
            ]
            _checked(self.launcher(argv, timeout=_INSTALL_TIMEOUT), action='dependency prefetch (pip download)')

    def create_venv(self, env_dir: Path, *, isolation: Isolation, env: Mapping[str, str] | None = None) -> None:
        """Create a virtualenv with uv (sandboxed, §3).

        Parameters
        ----------
        env_dir : Path
            Directory the virtualenv is created in.
        isolation : Isolation
            Network isolation wrapped around the creation (contract §11).
        env : Mapping[str, str] | None
            Scrubbed environment for the subprocess (contract §3).
        """
        argv = ['uv', 'venv', '--python', self.python, str(env_dir)]
        _checked(
            self.launcher(isolation.wrap(argv), env=env, timeout=_INSTALL_TIMEOUT),
            action='uv venv',
        )

    def install_offline(
        self,
        env_dir: Path,
        wheelhouse: Path,
        target: Path,
        *,
        isolation: Isolation,
        env: Mapping[str, str] | None = None,
    ) -> None:
        """Install the detector offline with ``uv pip``.

        Parameters
        ----------
        env_dir : Path
            The virtualenv to install into.
        wheelhouse : Path
            Local wheel cache used via ``--no-index --find-links``.
        target : Path
            Project directory to build and install (sandboxed).
        isolation : Isolation
            Network isolation wrapped around the build (contract §11).
        env : Mapping[str, str] | None
            Scrubbed environment for the subprocess (contract §3).
        """
        argv = [
            'uv',
            'pip',
            'install',
            '--quiet',
            '--python',
            _env_python(env_dir),
            '--no-index',
            '--find-links',
            str(wheelhouse),
            str(target),
        ]
        _checked(self.launcher(isolation.wrap(argv), env=env, timeout=_INSTALL_TIMEOUT), action='uv pip install')

    def freeze(self, env_dir: Path) -> tuple[str, ...]:
        """Capture the freeze with ``uv pip``.

        Parameters
        ----------
        env_dir : Path
            The virtualenv to freeze.

        Returns
        -------
        tuple[str, ...]
            Freeze lines.
        """
        result = _checked(
            self.launcher(['uv', 'pip', 'freeze', '--python', _env_python(env_dir)], timeout=_INSTALL_TIMEOUT),
            action='uv pip freeze',
        )
        return tuple(line for line in result.stdout.splitlines() if line.strip())


def choose_installer(*, launcher: SyncLauncher = run_sync) -> Installer:
    """Pick ``uv pip`` when on ``PATH``, else stdlib ``venv`` + ``pip`` (contract §3).

    Parameters
    ----------
    launcher : SyncLauncher
        Audited launcher handed to the chosen installer.

    Returns
    -------
    Installer
        The chosen installer.
    """
    validate_sync_launcher(launcher)
    if shutil.which('uv') is not None:
        return UvInstaller(launcher=launcher)
    return PipInstaller(launcher=launcher)


def parse_freeze(freeze: Iterable[str]) -> dict[str, str]:
    """Parse freeze lines into canonical name to version/source mapping.

    Parameters
    ----------
    freeze : Iterable[str]
        ``pip freeze``-style lines.

    Returns
    -------
    dict[str, str]
        Canonicalized distribution name mapped to its version (or direct
        reference for ``name @ url`` lines).
    """
    parsed: dict[str, str] = {}
    for line in freeze:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if ' @ ' in stripped:
            name, _, source = stripped.partition(' @ ')
            parsed[canonicalize_name(name.strip())] = source.strip()
        elif '==' in stripped:
            name, _, version = stripped.partition('==')
            parsed[canonicalize_name(name.strip())] = version.strip()
        else:
            parsed[canonicalize_name(stripped)] = ''
    return parsed


def dependency_delta(
    base_freeze: Iterable[str],
    head_freeze: Iterable[str],
    *,
    detector_distribution: str,
) -> tuple[DependencyDelta, ...]:
    """Compute the non-detector dependency delta of an environment pair (contract §3).

    Parameters
    ----------
    base_freeze : Iterable[str]
        Base-side freeze lines.
    head_freeze : Iterable[str]
        Head-side freeze lines.
    detector_distribution : str
        Detector distribution name, excluded from the delta.

    Returns
    -------
    tuple[DependencyDelta, ...]
        Differing packages, sorted by name.
    """
    detector = canonicalize_name(detector_distribution)
    base = parse_freeze(base_freeze)
    head = parse_freeze(head_freeze)
    delta: list[DependencyDelta] = []
    for name in sorted(base.keys() | head.keys()):
        if name == detector:
            continue
        base_version = base.get(name)
        head_version = head.get(name)
        if base_version != head_version:
            delta.append(DependencyDelta(package=name, base_version=base_version, head_version=head_version))
    return tuple(delta)


def _fetch_records_for(wheelhouse: Path, added: Iterable[str]) -> tuple[FetchRecord, ...]:
    """Build manifest fetch records for newly downloaded distribution files.

    Parameters
    ----------
    wheelhouse : Path
        The local wheel cache.
    added : Iterable[str]
        Filenames added by the current download.

    Returns
    -------
    tuple[FetchRecord, ...]
        One record per file: name, resolved version, SHA-256 digest.

    Raises
    ------
    EnvCacheError
        If a downloaded distribution is a symlink or not a regular file.
    """
    records: list[FetchRecord] = []
    for filename in sorted(added):
        path = wheelhouse / filename
        if path.is_symlink() or not path.is_file():
            msg = f'downloaded distribution is not a regular file: {filename}'
            raise EnvCacheError(msg)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        try:
            if filename.endswith('.whl'):
                _, parsed_version, _, _ = parse_wheel_filename(filename)
            else:
                _, parsed_version = parse_sdist_filename(filename)
            version = str(parsed_version)
        except (InvalidWheelFilename, InvalidSdistFilename):
            version = 'unknown'
        records.append(FetchRecord(kind='wheel', name=filename, resolved=version, digest=digest))
    return tuple(records)


def environment_fingerprint(
    repo: str,
    sha: str,
    adapter: DetectorAdapter,
    installer_identity: str,
    *,
    toolchain_identity: str | None = None,
) -> str:
    """Compute the full environment fingerprint (contract §3).

    Parameters
    ----------
    repo : str
        Detector repository URL.
    sha : str
        Resolved detector commit.
    adapter : DetectorAdapter
        Adapter supplying the build-recipe hash.
    installer_identity : str
        Installer name and version.
    toolchain_identity : str | None
        Native toolchain identity when the revision builds an artifact.

    Returns
    -------
    str
        Stable hex fingerprint over repository, SHA, recipe, Python version
        and ABI, platform tag, and installer.
    """
    material = json.dumps(
        {
            'repo': repo,
            'sha': sha,
            'recipe': adapter.build_recipe.digest(),
            'python': platform.python_version(),
            'abi': sysconfig.get_config_var('SOABI') or '',
            'platform': sysconfig.get_platform(),
            'installer': installer_identity,
            'toolchain': toolchain_identity,
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]


def _is_str_list(value: object) -> TypeGuard[list[str]]:
    """Check for a list containing only strings.

    Parameters
    ----------
    value : object
        Untrusted manifest value.

    Returns
    -------
    TypeGuard[list[str]]
        Whether the value is a string list.
    """
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _is_str_dict(value: object) -> TypeGuard[dict[str, str]]:
    """Check for a string-to-string dictionary.

    Parameters
    ----------
    value : object
        Untrusted manifest value.

    Returns
    -------
    TypeGuard[dict[str, str]]
        Whether the value is a string dictionary.
    """
    return isinstance(value, dict) and all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    )


def _validate_cached_artifacts(
    env_dir: Path,
    artifacts: Mapping[str, str],
    expected_artifacts: tuple[str, ...],
) -> tuple[tuple[str, str], ...] | None:
    """Validate every cached artifact against its recorded digest.

    Parameters
    ----------
    env_dir : Path
        Managed environment directory.
    artifacts : Mapping[str, str]
        Manifest artifact paths and digests.
    expected_artifacts : tuple[str, ...]
        Artifact paths required by the build recipe.

    Returns
    -------
    tuple[tuple[str, str], ...] | None
        Validated artifact entries, or ``None`` on mismatch.
    """
    if set(artifacts) != set(expected_artifacts):
        return None
    validated: list[tuple[str, str]] = []
    for relative, digest in sorted(artifacts.items()):
        artifact = env_dir / relative
        try:
            actual_digest = _artifact_digest(artifact)
        except (EnvCacheError, OSError):
            return None
        if not os.access(artifact, os.X_OK) or actual_digest != digest:
            return None
        validated.append((relative, digest))
    return tuple(validated)


def _read_env_manifest(
    env_manifest: Path,
    *,
    fingerprint: str,
    env_dir: Path,
    expected_artifacts: tuple[str, ...],
) -> _CachedEnvironment | None:
    """Read a cached environment manifest, tolerating corruption.

    Parameters
    ----------
    env_manifest : Path
        The per-environment manifest file.
    fingerprint : str
        Expected environment fingerprint.
    env_dir : Path
        Managed environment containing recorded artifacts.
    expected_artifacts : tuple[str, ...]
        Relative artifact paths required by this revision's recipe.

    Returns
    -------
    _CachedEnvironment | None
        Validated metadata, or ``None`` when a rebuild is required.
    """
    if env_manifest.is_symlink() or not env_manifest.is_file():
        return None
    try:
        stored = json.loads(env_manifest.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    if not isinstance(stored, dict) or stored.get('fingerprint') != fingerprint:
        return None
    freeze = stored.get('freeze')
    artifacts = stored.get('artifacts')
    if not _is_str_list(freeze) or not _is_str_dict(artifacts):
        return None
    validated = _validate_cached_artifacts(env_dir, artifacts, expected_artifacts)
    return None if validated is None else _CachedEnvironment(freeze=tuple(freeze), artifacts=validated)


def _write_env_manifest(env_manifest: Path, fingerprint: str, cached: _CachedEnvironment) -> None:
    """Atomically replace one environment manifest.

    Parameters
    ----------
    env_manifest : Path
        Destination manifest path.
    fingerprint : str
        Full environment fingerprint.
    cached : _CachedEnvironment
        Installed distribution freeze and native-artifact digests.
    """
    payload = json.dumps(
        {
            'fingerprint': fingerprint,
            'freeze': list(cached.freeze),
            'artifacts': dict(cached.artifacts),
        }
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix='.liveness-primer-env-', dir=env_manifest.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as manifest:
            manifest.write(payload)
        temporary.replace(env_manifest)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class EnvHandle:
    """A ready detector environment plus its manifest record.

    Attributes
    ----------
    record : EnvironmentRecord
        Manifest record (ref, sha, fingerprint, freeze, cache provenance).
    env_dir : Path
        The virtualenv directory.
    executable : str
        Path to the detector console script.
    runtime_env : tuple[tuple[str, str], ...]
        Side-specific managed environment variables for analysis.
    """

    record: EnvironmentRecord
    env_dir: Path
    executable: str
    runtime_env: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class PreparedPair:
    """The prepared base/head environment pair (contract §3).

    Attributes
    ----------
    base : EnvHandle
        Base-side environment.
    head : EnvHandle
        Head-side environment.
    environment_delta : tuple[DependencyDelta, ...]
        Non-detector delta surviving paired same-run resolution.
    fetches : tuple[FetchRecord, ...]
        Every fetch performed while preparing the pair.
    installer_identity : str
        Installer name and version used for builds.
    """

    base: EnvHandle
    head: EnvHandle
    environment_delta: tuple[DependencyDelta, ...]
    fetches: tuple[FetchRecord, ...]
    installer_identity: str


class DetectorEnvironments:
    """Builds and caches the two detector environments of a run (contract §3).

    Parameters
    ----------
    store : CheckoutStore
        Checkout store for detector clones.
    cache_dir : Path
        Cache directory holding environments and the wheelhouse.
    installer : Installer
        Environment installer (uv or pip); also performs the dependency
        prefetch.
    isolation : Isolation
        Network isolation for build-step subprocesses (contract §11).
    launcher : SyncLauncher
        Audited launcher for native toolchain probes and builds.
    fresh : bool
        Force same-run rebuilds of both environments (``--fresh``).
    lock_timeout : float
        Seconds to wait for another run holding an environment lock.
    """

    def __init__(
        self,
        store: CheckoutStore,
        cache_dir: Path,
        *,
        installer: Installer,
        isolation: Isolation = UNENFORCED,
        launcher: SyncLauncher = run_sync,
        fresh: bool = False,
        lock_timeout: float = _INSTALL_TIMEOUT,
    ) -> None:
        self._store = store
        self._cache_dir = cache_dir
        self._installer = installer
        self._isolation = isolation
        validate_sync_launcher(launcher)
        self._launcher = launcher
        self._fresh = fresh
        self._lock_timeout = lock_timeout
        self._fetches: list[FetchRecord] = []

    def _prefetch(self, requirements: Sequence[str]) -> Path:
        """Prefetch wheels into the local wheel cache via the installer (fetch step, §3).

        Parameters
        ----------
        requirements : Sequence[str]
            Requirement strings, duplicates allowed.

        Returns
        -------
        Path
            The wheelhouse directory.
        """
        wheelhouse = self._cache_dir / 'wheelhouse'
        wheelhouse.mkdir(parents=True, exist_ok=True)
        deduped = tuple(dict.fromkeys(requirements))
        if not deduped:
            return wheelhouse
        before = {entry.name for entry in wheelhouse.iterdir()}
        self._installer.prefetch(deduped, wheelhouse)
        added = {entry.name for entry in wheelhouse.iterdir()} - before
        self._fetches.extend(_fetch_records_for(wheelhouse, added))
        return wheelhouse

    def _pair_wheelhouse(self, repo: str, shas: Sequence[str]) -> Path:
        """Prefetch the union of every ref's requirements before any build (§3).

        Both sides build against identical resolution inputs, keeping delta
        attribution temporal, never textual. The union covers declared
        dependencies and build requirements; extras are excluded because
        the build installs no extras.

        Parameters
        ----------
        repo : str
            Detector repository URL.
        shas : Sequence[str]
            Resolved commit SHAs of the refs being prepared.

        Returns
        -------
        Path
            The wheelhouse directory.
        """
        requirements: list[str] = []
        for sha in dict.fromkeys(shas):
            checkout = self._store.materialize(repo, sha)
            metadata = parse_static_metadata(checkout)
            requirements.extend(metadata.dependencies)
            # Extras are deliberately left out: the offline install targets
            # the checkout without any extras selected, so an extra's wheels
            # are never installed, and prefetching them only spends fetch
            # time and fails the run when an extra is unresolvable. Their
            # requirement strings are still parsed and validated.
            requirements.extend(metadata.build_requires)
        return self._prefetch(requirements)

    def _build_go_executable(
        self,
        env_dir: Path,
        source: Path,
        build: GoExecutableBuild,
        toolchain: _GoToolchain,
        *,
        env: Mapping[str, str],
    ) -> tuple[str, str]:
        """Build one revision-scoped Go executable into its environment.

        Parameters
        ----------
        env_dir : Path
            Managed environment receiving the executable.
        source : Path
            Validated detector-revision Go module.
        build : GoExecutableBuild
            Adapter-declared build specification.
        toolchain : _GoToolchain
            Validated Go compiler and its cache identity.
        env : Mapping[str, str]
            Scrubbed, credential-free base environment.

        Returns
        -------
        tuple[str, str]
            Environment-relative executable path and SHA-256 digest.
        """
        destination = Path(env_executable(env_dir, build.executable))
        descriptor, temporary_name = tempfile.mkstemp(prefix=f'.{build.executable}-', dir=destination.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        scratch = Path(env['HOME'])
        build_env = dict(env)
        build_env.update(
            {
                'CGO_ENABLED': '0',
                'GOCACHE': str(scratch / 'go-build-cache'),
                'GOMODCACHE': str(scratch / 'go-module-cache'),
                'GOPATH': str(scratch / 'go-path'),
                'GOPROXY': 'off',
                'GOSUMDB': 'off',
                'GOTOOLCHAIN': 'local',
                'GOWORK': 'off',
                'TMPDIR': str(scratch / 'tmp'),
            }
        )
        Path(build_env['TMPDIR']).mkdir()
        argv = [
            toolchain.executable,
            'build',
            '-trimpath',
            '-buildvcs=false',
            '-mod=readonly',
            '-o',
            str(temporary),
            build.package,
        ]
        try:
            _checked(
                self._launcher(
                    self._isolation.wrap(argv),
                    cwd=source,
                    env=build_env,
                    timeout=_INSTALL_TIMEOUT,
                ),
                action=f'build {build.executable}',
            )
            digest = _artifact_digest(temporary)
            temporary.chmod(0o755)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        relative = destination.relative_to(env_dir).as_posix()
        return relative, digest

    def _build(
        self,
        fingerprint: str,
        checkout: Path,
        wheelhouse: Path,
        *,
        go_plan: _GoBuildPlan | None,
    ) -> _CachedEnvironment:
        """Build one environment: venv, offline sandboxed install, freeze.

        Every build-step subprocess runs under the §11 sandbox with a
        scrubbed, credential-free environment (contract §3).

        Parameters
        ----------
        fingerprint : str
            Full environment fingerprint from ``environment_fingerprint``.
        checkout : Path
            Detector checkout to install.
        wheelhouse : Path
            Prefetched wheel cache both sides install from.
        go_plan : _GoBuildPlan | None
            Resolved native build inputs, when this revision has them.

        Returns
        -------
        _CachedEnvironment
            The freeze and native-artifact digests of the built environment.
        """
        env_dir = self._cache_dir / 'envs' / Path(fingerprint).name
        if env_dir.exists():
            shutil.rmtree(env_dir)
        with tempfile.TemporaryDirectory(prefix='liveness-primer-build-home-') as scratch_home:
            env = scrubbed_environment(home=Path(scratch_home))
            self._installer.create_venv(env_dir, isolation=self._isolation, env=env)
            self._installer.install_offline(env_dir, wheelhouse, checkout, isolation=self._isolation, env=env)
            artifacts: tuple[tuple[str, str], ...] = ()
            if go_plan is not None:
                artifacts = (
                    self._build_go_executable(
                        env_dir,
                        go_plan.source,
                        go_plan.recipe,
                        go_plan.toolchain,
                        env=env,
                    ),
                )
        return _CachedEnvironment(freeze=self._installer.freeze(env_dir), artifacts=artifacts)

    def _ensure(
        self,
        *,
        ref: str,
        sha: str,
        checkout: Path,
        adapter: DetectorAdapter,
        fingerprint: str,
        wheelhouse: Callable[[], Path],
        go_plan: _GoBuildPlan | None,
        force_rebuild: bool,
    ) -> EnvHandle:
        """Return a cached environment or build it; the caller holds its lock.

        Parameters
        ----------
        ref : str
            Ref as requested on the CLI.
        sha : str
            Resolved commit SHA.
        checkout : Path
            Materialized detector revision.
        adapter : DetectorAdapter
            Adapter for recipe, distribution, and executable names.
        fingerprint : str
            Full environment fingerprint of this ref.
        wheelhouse : Callable[[], Path]
            Lazy provider of the pair's prefetched wheelhouse.
        go_plan : _GoBuildPlan | None
            Resolved native build inputs, when this revision has them.
        force_rebuild : bool
            Skip cache reuse and rebuild.

        Returns
        -------
        EnvHandle
            The ready environment.
        """
        env_dir = self._cache_dir / 'envs' / Path(fingerprint).name
        env_manifest = env_dir / 'liveness-primer-env.json'
        go_build = adapter.build_recipe.go_executable
        expected_artifacts: tuple[str, ...] = ()
        if go_plan is not None:
            expected_artifacts = (
                Path(env_executable(env_dir, go_plan.recipe.executable)).relative_to(env_dir).as_posix(),
            )
        cached = (
            None
            if force_rebuild
            else _read_env_manifest(
                env_manifest,
                fingerprint=fingerprint,
                env_dir=env_dir,
                expected_artifacts=expected_artifacts,
            )
        )
        if cached is not None:
            record = EnvironmentRecord(
                ref=ref,
                sha=sha,
                fingerprint=fingerprint,
                freeze=cached.freeze,
                from_cache=True,
                rebuilt=False,
            )
        else:
            house = wheelhouse()
            cached = self._build(
                fingerprint,
                checkout,
                house,
                go_plan=go_plan,
            )
            _write_env_manifest(env_manifest, fingerprint, cached)
            record = EnvironmentRecord(
                ref=ref,
                sha=sha,
                fingerprint=fingerprint,
                freeze=cached.freeze,
                from_cache=False,
                rebuilt=True,
            )
        runtime_env = (
            () if go_build is None else ((go_build.runtime_env, env_executable(env_dir, go_build.executable)),)
        )
        return EnvHandle(
            record=record,
            env_dir=env_dir,
            executable=env_executable(env_dir, adapter.executable),
            runtime_env=runtime_env,
        )

    def _acquire_locks(self, stack: contextlib.ExitStack, fingerprints: Iterable[str]) -> None:
        """Acquire the per-fingerprint cache locks in deterministic order.

        Parameters
        ----------
        stack : contextlib.ExitStack
            Stack that releases every acquired lock on exit.
        fingerprints : Iterable[str]
            Fingerprints to lock; duplicates collapse to one lock.

        Raises
        ------
        EnvCacheError
            If a lock cannot be acquired in time.
        """
        envs = self._cache_dir / 'envs'
        for fingerprint in sorted(set(fingerprints)):
            lock: BaseFileLock = FileLock(str(envs / Path(fingerprint).name) + '.lock')
            try:
                lock.acquire(timeout=self._lock_timeout)
            except Timeout as exc:
                msg = f'timed out waiting for the environment lock of {fingerprint}'
                raise EnvCacheError(msg) from exc
            stack.callback(lock.release)

    @contextlib.contextmanager
    def prepare_pair(self, repo: str, base_ref: str, head_ref: str, adapter: DetectorAdapter) -> Iterator[PreparedPair]:
        """Prepare the base/head environment pair with paired delta resolution (contract §3).

        Cached pairs with an empty non-detector dependency delta are used
        directly; any non-empty delta triggers an automatic paired same-run
        rebuild. Only a delta that survives that rebuild is ref-attributable
        and recorded. ``fresh`` forces the rebuild unconditionally. The
        pair's cache locks are held until the context exits, so a concurrent
        ``--fresh`` rebuild cannot delete an environment out from under an
        in-flight analysis.

        Parameters
        ----------
        repo : str
            Detector repository URL.
        base_ref : str
            Base ref as requested on the CLI.
        head_ref : str
            Head ref as requested on the CLI.
        adapter : DetectorAdapter
            Adapter of the tool under test.

        Yields
        ------
        PreparedPair
            The two environments, surviving delta, and fetch records.
        """
        base_sha = self._store.resolve_ref(repo, base_ref)
        head_sha = self._store.resolve_ref(repo, head_ref)
        self._fetches.append(FetchRecord(kind='git', name=repo, resolved=base_sha))
        if head_sha != base_sha:
            self._fetches.append(FetchRecord(kind='git', name=repo, resolved=head_sha))
        installer_identity = self._installer.identity()
        base_checkout = self._store.materialize(repo, base_sha)
        head_checkout = base_checkout if head_sha == base_sha else self._store.materialize(repo, head_sha)
        go_build = adapter.build_recipe.go_executable
        base_go_plan: _GoBuildPlan | None = None
        head_go_plan: _GoBuildPlan | None = None
        if go_build is not None:
            base_go_source = _go_source_directory(base_checkout, go_build)
            head_go_source = _go_source_directory(head_checkout, go_build)
            if base_go_source is not None or head_go_source is not None:
                go_toolchain = _resolve_go_toolchain(go_build, launcher=self._launcher, isolation=self._isolation)
                if base_go_source is not None:
                    base_go_plan = _GoBuildPlan(base_go_source, go_build, go_toolchain)
                if head_go_source is not None:
                    head_go_plan = _GoBuildPlan(head_go_source, go_build, go_toolchain)
        base_toolchain_identity = None if base_go_plan is None else base_go_plan.toolchain.identity
        head_toolchain_identity = None if head_go_plan is None else head_go_plan.toolchain.identity
        base_fingerprint = environment_fingerprint(
            repo,
            base_sha,
            adapter,
            installer_identity,
            toolchain_identity=base_toolchain_identity,
        )
        head_fingerprint = environment_fingerprint(
            repo,
            head_sha,
            adapter,
            installer_identity,
            toolchain_identity=head_toolchain_identity,
        )
        (self._cache_dir / 'envs').mkdir(parents=True, exist_ok=True)
        wheelhouse: Path | None = None

        def pair_wheelhouse() -> Path:
            """Prefetch the pair's union wheelhouse once, on first build.

            Returns
            -------
            Path
                The wheelhouse directory.
            """
            nonlocal wheelhouse
            if wheelhouse is None:
                wheelhouse = self._pair_wheelhouse(repo, (base_sha, head_sha))
            return wheelhouse

        with contextlib.ExitStack() as stack:
            self._acquire_locks(stack, (base_fingerprint, head_fingerprint))
            base = self._ensure(
                ref=base_ref,
                sha=base_sha,
                checkout=base_checkout,
                adapter=adapter,
                fingerprint=base_fingerprint,
                wheelhouse=pair_wheelhouse,
                go_plan=base_go_plan,
                force_rebuild=self._fresh,
            )
            head = self._ensure(
                ref=head_ref,
                sha=head_sha,
                checkout=head_checkout,
                adapter=adapter,
                fingerprint=head_fingerprint,
                wheelhouse=pair_wheelhouse,
                go_plan=head_go_plan,
                force_rebuild=self._fresh,
            )
            delta = dependency_delta(
                base.record.freeze,
                head.record.freeze,
                detector_distribution=adapter.distribution,
            )
            if delta and not (base.record.rebuilt and head.record.rebuilt):
                # Attribution is temporal, never textual: rebuild both sides
                # in this run before attributing the delta to the refs (§3).
                base = self._ensure(
                    ref=base_ref,
                    sha=base_sha,
                    checkout=base_checkout,
                    adapter=adapter,
                    fingerprint=base_fingerprint,
                    wheelhouse=pair_wheelhouse,
                    go_plan=base_go_plan,
                    force_rebuild=True,
                )
                head = self._ensure(
                    ref=head_ref,
                    sha=head_sha,
                    checkout=head_checkout,
                    adapter=adapter,
                    fingerprint=head_fingerprint,
                    wheelhouse=pair_wheelhouse,
                    go_plan=head_go_plan,
                    force_rebuild=True,
                )
                delta = dependency_delta(
                    base.record.freeze,
                    head.record.freeze,
                    detector_distribution=adapter.distribution,
                )
            yield PreparedPair(
                base=base,
                head=head,
                environment_delta=delta,
                fetches=tuple(self._fetches),
                installer_identity=installer_identity,
            )
