# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Container-backed detector environments: ephemeral per-side Docker containers (contract §3, §11).

``--container`` moves the build and execution of both detector refs into
Docker. Each ref is installed into a fingerprint-keyed image by an offline
``docker build --network none`` fed from a wheelhouse prefetched during the
fetch step; each side of the run then executes inside its own ephemeral,
hardened container (non-root, all capabilities dropped, no new privileges,
PID-limited, read-only root filesystem) started from that image with
networking disabled and with only its own side's workspace mounted. Both
containers are force-removed when the analysis context exits, and a removal
the daemon cannot confirm fails the run — so no report output is ever
rendered or written while a container may still exist. Docker is driven
exclusively through the audited launcher via the ``docker`` CLI, and the
runtime is injectable so the logic is testable without a daemon (contract
§15).
"""

import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable

from liveness_primer.corpus import CheckoutStore
from liveness_primer.envcache import dependency_delta, fetch_records_for, parse_static_metadata
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.execution import LaunchPlan, SideWorkspace
from liveness_primer.findings import DependencyDelta, EnvironmentRecord, FetchRecord
from liveness_primer.isolation import Isolation
from liveness_primer.launcher import LaunchResult, SyncLauncher, run_sync, validate_sync_launcher
from liveness_primer.tools.base import DetectorAdapter

DEFAULT_CONTAINER_IMAGE = 'python:3.12-slim'

# Both sides' containers run with networking disabled; unlike the host netns
# probe this is enforced by the container runtime on every platform (§11).
CONTAINER_ISOLATION = Isolation(enforced=True, description='container:docker-network-none', prefix=())

# Container-side mount point of the run's workspace root; side workspaces are
# created under it on the host and addressed through it inside the containers.
CONTAINER_WORK_ROOT = PurePosixPath('/liveness/work')

_DOCKER_TIMEOUT = 1800.0

# Cache-format / security revision of the environment image. Bump whenever the
# Dockerfile, the build inputs (e.g. per-side isolated wheelhouses), or the
# container hardening change in a way that must not silently reuse an image an
# earlier revision cached under an otherwise-identical fingerprint.
#   1: initial ephemeral-container build.
#   2: container hardening + per-side isolated fetch/build wheelhouses.
_CONTAINER_CACHE_FORMAT = 2

# Fork-bomb backstop for every container this module starts; generous enough
# for any real detector or pip invocation.
_PIDS_LIMIT = 4096

# Privilege and resource hardening applied to every container: untrusted
# detector code participates in the image build, so even the container's own
# entrypoint binaries are untrusted (contract §11). Deliberately absent are
# hard memory/CPU caps: the §3 per-(project, tool) timeout is the resource
# bound, and a fixed cap would misfail legitimately large analyses.
_HARDENING_FLAGS: tuple[str, ...] = (
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    str(_PIDS_LIMIT),
    '--read-only',
    '--tmpfs',
    '/tmp',
)

_IMAGE_REFERENCE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/@-]*$')

_DOCKERFILE = """\
FROM {image}
COPY wheelhouse /liveness/wheelhouse
COPY detector /liveness/detector
RUN python -m pip install --quiet --no-index --find-links /liveness/wheelhouse /liveness/detector
"""


class ContainerError(LivenessPrimerError):
    """Raised when the Docker runtime cannot prepare or run an environment."""


def _checked(result: LaunchResult, *, action: str) -> LaunchResult:
    """Raise a domain error when a docker command failed.

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
    ContainerError
        If the command failed or timed out.
    """
    if not result.ok:
        detail = 'timed out' if result.timed_out else result.stderr.strip()[-1000:]
        msg = f'{action} failed: {detail}'
        raise ContainerError(msg)
    return result


def container_user() -> str | None:
    """Report the host user mapping for container-side file writes.

    Detector processes and the prefetch run as the invoking host user, so
    files they create in bind mounts stay removable by the run.

    Returns
    -------
    str | None
        ``uid:gid``, or ``None`` on platforms without POSIX ids.
    """
    if hasattr(os, 'getuid') and hasattr(os, 'getgid'):
        return f'{os.getuid()}:{os.getgid()}'
    return None


def _user_flags() -> tuple[str, ...]:
    """Build the ``--user`` argv flags for every container this module runs.

    Returns
    -------
    tuple[str, ...]
        ``('--user', 'uid:gid')``, or empty on platforms without POSIX ids.
    """
    user = container_user()
    if user is None:
        return ()
    return ('--user', user)


def promote_prefetched(staging: Path, wheelhouse: Path, *, exclude: frozenset[str] = frozenset()) -> set[str]:
    """Validate staged downloads and move them into a side's wheelhouse (contract §3, §11).

    The download runs third-party build hooks inside a container that can
    write anything into the staged directory — including a symlink whose
    target only resolves on the host, or a wheel fabricated under the name
    of the *other* side's dependency. Every promoted entry must therefore be
    a regular, non-symlink file, and any name already owned by the base side
    (``exclude``) is dropped rather than promoted, so the head fetch can
    never introduce an artifact the base image would build from.

    Parameters
    ----------
    staging : Path
        Fresh staging directory the fetch container wrote into.
    wheelhouse : Path
        The side's own wheelhouse the validated files move to (same
        filesystem); never the other side's.
    exclude : frozenset[str]
        Filenames the base side already owns; a staged entry with one of
        these names is a base wheel the resolver copied back (or a head
        fabrication of a base name) and is discarded, not promoted.

    Returns
    -------
    set[str]
        Filenames that were not previously present in the wheelhouse.

    Raises
    ------
    ContainerError
        If a promoted staged entry is a symlink or not a regular file.
    """
    before = {entry.name for entry in wheelhouse.iterdir()}
    added: set[str] = set()
    for entry in sorted(staging.iterdir()):
        if entry.name in exclude:
            continue
        if entry.is_symlink() or not entry.is_file():
            msg = f'prefetched distribution is not a regular file: {entry.name}'
            raise ContainerError(msg)
        entry.replace(wheelhouse / entry.name)
        if entry.name not in before:
            added.add(entry.name)
    return added


def stage_wheelhouses(sources: Sequence[Path], destination: Path) -> None:
    """Copy one or more wheelhouses into a build context, never following symlinks (contract §11).

    A cached wheelhouse persists across runs; a symlink that slipped into
    one must never be dereferenced on the host while assembling an image
    build context. Sources are staged in order; because the head-side
    wheelhouse excludes every name the base side owns, no name collides
    across sources, and a collision is treated as a defect rather than
    silently resolved.

    Parameters
    ----------
    sources : Sequence[Path]
        Cached wheelhouse directories, in precedence order.
    destination : Path
        Build-context wheelhouse directory to create and fill.

    Raises
    ------
    ContainerError
        If a cached entry is a symlink, is not a regular file, or a name
        appears in more than one source.
    """
    destination.mkdir()
    for source in sources:
        for entry in sorted(source.iterdir()):
            if entry.is_symlink() or not entry.is_file():
                msg = f'cached distribution is not a regular file: {entry.name}'
                raise ContainerError(msg)
            target = destination / entry.name
            if target.exists():
                msg = f'wheelhouse name appears in more than one source: {entry.name}'
                raise ContainerError(msg)
            shutil.copyfile(entry, target)


def container_fingerprint(repo: str, sha: str, adapter: DetectorAdapter, docker_identity: str, image: str) -> str:
    """Compute the environment fingerprint of one containerized ref (contract §3).

    Parameters
    ----------
    repo : str
        Detector repository URL.
    sha : str
        Resolved detector commit.
    adapter : DetectorAdapter
        Adapter supplying the build-recipe hash.
    docker_identity : str
        Docker runtime name and version.
    image : str
        Base image reference the environment builds from.

    Returns
    -------
    str
        Stable hex fingerprint over the cache-format revision, repository,
        SHA, recipe, base image, and Docker runtime. A cache-format bump
        makes every prior image miss the cache and rebuild.
    """
    material = json.dumps(
        {
            'cache_format': _CONTAINER_CACHE_FORMAT,
            'repo': repo,
            'sha': sha,
            'recipe': adapter.build_recipe.digest(),
            'image': image,
            'runtime': docker_identity,
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]


def image_tag(fingerprint: str) -> str:
    """Name the cached environment image of one fingerprint.

    Parameters
    ----------
    fingerprint : str
        Full container environment fingerprint.

    Returns
    -------
    str
        The image tag.
    """
    return f'liveness-primer/env:{fingerprint}'


@runtime_checkable
class DockerRuntime(Protocol):
    """Injectable Docker runtime operations (contract §15)."""

    def identity(self) -> str:
        """Report the runtime name and version for the fingerprint.

        Returns
        -------
        str
            E.g. ``docker 27.5.1``.
        """
        ...

    def image_exists(self, tag: str) -> bool:
        """Report whether an image tag resolves locally.

        Parameters
        ----------
        tag : str
            Image tag to look up.

        Returns
        -------
        bool
            True when the image exists.
        """
        ...

    def build_image(self, tag: str, context: Path, *, fresh: bool) -> None:
        """Build an environment image offline (build step, §3, §11).

        Parameters
        ----------
        tag : str
            Tag for the built image.
        context : Path
            Build context holding the Dockerfile, checkout, and wheelhouse.
        fresh : bool
            Bypass the layer cache (``--no-cache``).
        """
        ...

    def prefetch(
        self, image: str, requirements: Sequence[str], destination: Path, *, find_links: Path | None = None
    ) -> None:
        """Download distributions into a staging directory (fetch step, §3).

        Runs pip inside the base image so the fetched wheels match the
        container platform, not the host. The destination is a fresh
        staging directory, never the persistent cache: the caller validates
        and promotes the results (contract §11). ``find_links``, when given,
        is mounted **read-only** and offered to the resolver, so the head
        fetch reuses the base side's already-downloaded wheels without being
        able to alter them.

        Parameters
        ----------
        image : str
            Base image whose pip performs the download.
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        destination : Path
            Fresh host staging directory mounted into the fetch container.
        find_links : Path | None
            Base-side wheelhouse mounted read-only as an extra resolver
            source, or ``None`` for the base fetch itself.
        """
        ...

    def freeze(self, tag: str) -> tuple[str, ...]:
        """Capture the resolved dependency freeze of an environment image.

        Parameters
        ----------
        tag : str
            Environment image to freeze.

        Returns
        -------
        tuple[str, ...]
            Freeze lines.
        """
        ...

    def start_container(self, tag: str, name: str, *, work_root: Path) -> None:
        """Start one ephemeral, network-less, hardened analysis container.

        Parameters
        ----------
        tag : str
            Environment image to run.
        name : str
            Container name used for ``docker exec`` and removal.
        work_root : Path
            This side's host workspace root, mounted at the container work
            root.
        """
        ...

    def remove_container(self, name: str) -> bool:
        """Force-remove one analysis container and confirm the outcome.

        Parameters
        ----------
        name : str
            Container name to remove.

        Returns
        -------
        bool
            True when the daemon confirmed the container no longer exists.
        """
        ...


@dataclass(frozen=True, slots=True)
class DockerCli:
    """Docker runtime driven through the audited launcher (contract §11).

    Attributes
    ----------
    binary : str
        Docker client binary name.
    launcher : SyncLauncher
        Audited launcher for every invocation.
    """

    binary: str = 'docker'
    launcher: SyncLauncher = run_sync

    def __post_init__(self) -> None:
        """Validate the injected launcher."""
        validate_sync_launcher(self.launcher)

    def identity(self) -> str:
        """Report the Docker server name and version.

        Returns
        -------
        str
            E.g. ``docker 27.5.1``.

        Raises
        ------
        ContainerError
            If no usable Docker daemon answers.
        """
        result = self.launcher(
            [self.binary, 'version', '--format', '{{.Server.Version}}'],
            timeout=_DOCKER_TIMEOUT,
        )
        if not result.ok or not result.stdout.strip():
            detail = 'timed out' if result.timed_out else result.stderr.strip()[-500:] or 'no version reported'
            msg = f'--container requires a running Docker daemon; probing it failed: {detail}'
            raise ContainerError(msg)
        return f'docker {result.stdout.strip()}'

    def image_exists(self, tag: str) -> bool:
        """Report whether an image tag resolves locally.

        Parameters
        ----------
        tag : str
            Image tag to look up.

        Returns
        -------
        bool
            True when the image exists.
        """
        return self.launcher(
            [self.binary, 'image', 'inspect', '--format', '{{.Id}}', tag],
            timeout=_DOCKER_TIMEOUT,
        ).ok

    def build_image(self, tag: str, context: Path, *, fresh: bool) -> None:
        """Build an environment image with networking disabled (contract §11).

        Parameters
        ----------
        tag : str
            Tag for the built image.
        context : Path
            Build context holding the Dockerfile, checkout, and wheelhouse.
        fresh : bool
            Bypass the layer cache (``--no-cache``).
        """
        argv = [self.binary, 'build', '--network', 'none', '--quiet', '--tag', tag]
        if fresh:
            argv.append('--no-cache')
        argv.append(str(context))
        _checked(self.launcher(argv, timeout=_DOCKER_TIMEOUT), action='docker build')

    def _remove_auxiliary(self, name: str) -> None:
        """Force-remove one named helper container, tolerating absence.

        A client-side launcher timeout kills the docker CLI but not the
        container it started; the tracked name lets the cleanup reach it.

        Parameters
        ----------
        name : str
            Helper container name to remove.
        """
        self.launcher([self.binary, 'rm', '--force', name], timeout=_DOCKER_TIMEOUT)

    def prefetch(
        self, image: str, requirements: Sequence[str], destination: Path, *, find_links: Path | None = None
    ) -> None:
        """Download distributions with the base image's pip (fetch step, §3).

        The fetch container is named and force-removed afterwards, so a
        client-side timeout cannot leak an untracked running container. A
        ``find_links`` wheelhouse is mounted read-only, so the head fetch
        reuses base-side wheels it cannot modify (contract §3, §11).

        Parameters
        ----------
        image : str
            Base image whose pip performs the download.
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        destination : Path
            Fresh host staging directory mounted into the fetch container.
        find_links : Path | None
            Base-side wheelhouse mounted read-only as an extra resolver
            source, or ``None`` for the base fetch itself.
        """
        name = f'liveness-primer-fetch-{secrets.token_hex(6)}'
        argv = [
            self.binary,
            'run',
            '--rm',
            '--name',
            name,
            *_HARDENING_FLAGS,
            *_user_flags(),
            '--volume',
            f'{destination}:/liveness/wheelhouse',
            '--env',
            'HOME=/tmp',
        ]
        download_flags = ['--prefer-binary']
        if find_links is not None:
            argv.extend(['--volume', f'{find_links}:/liveness/base-links:ro'])
            download_flags.extend(['--find-links', '/liveness/base-links'])
        argv.extend(
            [
                image,
                'python',
                '-m',
                'pip',
                'download',
                '--quiet',
                '--dest',
                '/liveness/wheelhouse',
                *download_flags,
                *requirements,
            ]
        )
        try:
            _checked(self.launcher(argv, timeout=_DOCKER_TIMEOUT), action='dependency prefetch (pip download)')
        finally:
            self._remove_auxiliary(name)

    def freeze(self, tag: str) -> tuple[str, ...]:
        """Capture the freeze of an environment image, offline.

        Parameters
        ----------
        tag : str
            Environment image to freeze.

        Returns
        -------
        tuple[str, ...]
            Freeze lines.
        """
        name = f'liveness-primer-freeze-{secrets.token_hex(6)}'
        argv = [
            self.binary,
            'run',
            '--rm',
            '--name',
            name,
            '--network',
            'none',
            *_HARDENING_FLAGS,
            *_user_flags(),
            '--env',
            'HOME=/tmp',
            tag,
            'python',
            '-m',
            'pip',
            'freeze',
        ]
        try:
            result = _checked(self.launcher(argv, timeout=_DOCKER_TIMEOUT), action='pip freeze')
        finally:
            self._remove_auxiliary(name)
        return tuple(line for line in result.stdout.splitlines() if line.strip())

    def start_container(self, tag: str, name: str, *, work_root: Path) -> None:
        """Start one ephemeral, network-less, hardened analysis container (contract §11).

        ``--rm`` backstops removal on daemon-side stops; ``--init`` reaps
        detector children of the idle keep-alive process. The untrusted
        detector build shaped the image — including its ``sleep`` binary —
        so PID 1 already runs as the mapped host user with all capabilities
        dropped, no new privileges, a PID limit, and a read-only root
        filesystem; only this side's workspace root is mounted writable.

        Parameters
        ----------
        tag : str
            Environment image to run.
        name : str
            Container name used for ``docker exec`` and removal.
        work_root : Path
            This side's host workspace root, mounted at the container work
            root.
        """
        argv = [
            self.binary,
            'run',
            '--detach',
            '--rm',
            '--init',
            '--network',
            'none',
            '--name',
            name,
            *_HARDENING_FLAGS,
            *_user_flags(),
            '--volume',
            f'{work_root}:{CONTAINER_WORK_ROOT}',
            tag,
            'sleep',
            'infinity',
        ]
        _checked(self.launcher(argv, timeout=_DOCKER_TIMEOUT), action='container start')

    def remove_container(self, name: str) -> bool:
        """Force-remove one analysis container and confirm the outcome.

        Parameters
        ----------
        name : str
            Container name to remove.

        Returns
        -------
        bool
            True when the daemon confirmed removal — the command succeeded,
            or the container already no longer exists.
        """
        result = self.launcher([self.binary, 'rm', '--force', name], timeout=_DOCKER_TIMEOUT)
        return result.ok or 'No such container' in result.stderr


@dataclass(frozen=True, slots=True)
class ContainerEnvHandle:
    """A ready containerized detector environment plus its manifest record.

    Attributes
    ----------
    record : EnvironmentRecord
        Manifest record (ref, sha, fingerprint, freeze, cache provenance).
    image : str
        The environment image tag.
    """

    record: EnvironmentRecord
    image: str


@dataclass(frozen=True, slots=True)
class PreparedContainerPair:
    """The prepared base/head container pair of one run (contract §3).

    Attributes
    ----------
    base : ContainerEnvHandle
        Base-side environment.
    head : ContainerEnvHandle
        Head-side environment.
    environment_delta : tuple[DependencyDelta, ...]
        Non-detector delta surviving paired same-run resolution.
    fetches : tuple[FetchRecord, ...]
        Every fetch performed while preparing the pair.
    installer_identity : str
        Docker runtime and base image used for builds.
    work_root : Path
        Host directory holding both per-side workspace roots.
    base_work_root : Path
        Base-side workspace root; the only mount the base container sees.
    head_work_root : Path
        Head-side workspace root; the only mount the head container sees.
    base_container : str
        Name of the running base-side container.
    head_container : str
        Name of the running head-side container.
    """

    base: ContainerEnvHandle
    head: ContainerEnvHandle
    environment_delta: tuple[DependencyDelta, ...]
    fetches: tuple[FetchRecord, ...]
    installer_identity: str
    work_root: Path
    base_work_root: Path
    head_work_root: Path
    base_container: str
    head_container: str


class ContainerEnvironments:
    """Builds the two detector environment images and runs their containers (contract §3).

    Environment images are keyed by the container fingerprint and cached by
    the Docker image store, which also serializes concurrent builds of the
    same tag; no host filelock is needed. The analysis containers themselves
    are ephemeral: started when the pair context is entered and force-removed
    when it exits, before any report output is rendered or written.

    Parameters
    ----------
    store : CheckoutStore
        Checkout store for detector clones.
    cache_dir : Path
        Cache directory holding the per-pair container wheelhouses.
    docker : DockerRuntime
        Docker runtime operations; injectable for tests (contract §15).
    image : str
        Base image both environments build from.
    fresh : bool
        Force same-run image rebuilds (``--fresh``).

    Raises
    ------
    ContainerError
        If the base image reference is malformed.
    """

    def __init__(
        self,
        store: CheckoutStore,
        cache_dir: Path,
        *,
        docker: DockerRuntime,
        image: str = DEFAULT_CONTAINER_IMAGE,
        fresh: bool = False,
    ) -> None:
        if not _IMAGE_REFERENCE.match(image):
            msg = f'malformed container image reference: {image!r}'
            raise ContainerError(msg)
        self._store = store
        self._cache_dir = cache_dir
        self._docker = docker
        self._image = image
        self._fresh = fresh
        self._fetches: list[FetchRecord] = []

    def _side_requirements(self, repo: str, sha: str) -> tuple[str, ...]:
        """Statically resolve one ref's fetch requirements (fetch step, §3).

        Parameters
        ----------
        repo : str
            Detector repository URL.
        sha : str
            Resolved commit SHA of the ref.

        Returns
        -------
        tuple[str, ...]
            Deduplicated declared dependencies and build requirements.
            Extras are deliberately left out, exactly as in the host-venv
            path: the offline install selects no extras (contract §3).
        """
        checkout = self._store.materialize(repo, sha)
        metadata = parse_static_metadata(checkout)
        return tuple(dict.fromkeys((*metadata.dependencies, *metadata.build_requires)))

    def _fetch_into(
        self, repo: str, sha: str, wheelhouse: Path, *, find_links: Path | None, exclude: frozenset[str]
    ) -> None:
        """Fetch one ref's requirements into its own wheelhouse (fetch step, §3, §11).

        The download runs inside the base image so wheels match the
        container platform, not the host. The fetch container only ever
        writes into a fresh staging directory; every entry it produces is
        validated as a regular, non-symlink file, and any name the base side
        already owns (``exclude``) is dropped, before promotion — so an
        untrusted build hook cannot slip an artifact into a wheelhouse the
        *other* side builds from. When ``find_links`` is set, the base-side
        wheelhouse is offered read-only as a resolver source, so the head
        fetch reuses base's already-downloaded wheels instead of fetching
        the shared closure again.

        Parameters
        ----------
        repo : str
            Detector repository URL.
        sha : str
            Resolved commit SHA of the ref to fetch.
        wheelhouse : Path
            This side's own wheelhouse; promotion never touches the other
            side's.
        find_links : Path | None
            Base-side wheelhouse mounted read-only for reuse, or ``None``
            for the base fetch itself.
        exclude : frozenset[str]
            Filenames the base side already owns, dropped from promotion.
        """
        requirements = self._side_requirements(repo, sha)
        if not requirements:
            return
        # Same filesystem as the wheelhouse, so promotion is an atomic rename.
        staging = Path(tempfile.mkdtemp(prefix='liveness-primer-fetch-', dir=wheelhouse.parent))
        try:
            self._docker.prefetch(self._image, requirements, staging, find_links=find_links)
            added = promote_prefetched(staging, wheelhouse, exclude=exclude)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        self._fetches.extend(fetch_records_for(wheelhouse, added))

    def _build(self, tag: str, checkout: Path, wheelhouses: Sequence[Path]) -> None:
        """Build one environment image from an offline context (build step, §3, §11).

        Parameters
        ----------
        tag : str
            Tag for the built image.
        checkout : Path
            Detector checkout to install.
        wheelhouses : Sequence[Path]
            This side's wheelhouse directories, staged into one offline
            context (base side: its own; head side: base's plus its own
            extras).
        """
        with tempfile.TemporaryDirectory(prefix='liveness-primer-context-') as scratch:
            context = Path(scratch)
            # Symlinks are copied as symlinks: following them could pull
            # content from outside the untrusted checkout into the image.
            shutil.copytree(checkout, context / 'detector', symlinks=True, ignore=shutil.ignore_patterns('.git'))
            stage_wheelhouses(wheelhouses, context / 'wheelhouse')
            (context / 'Dockerfile').write_text(_DOCKERFILE.format(image=self._image), encoding='utf-8')
            self._docker.build_image(tag, context, fresh=self._fresh)

    def _ensure(
        self,
        *,
        repo: str,
        ref: str,
        sha: str,
        fingerprint: str,
        wheelhouses: Callable[[], Sequence[Path]],
        force_rebuild: bool,
    ) -> ContainerEnvHandle:
        """Return a cached environment image or build it.

        Parameters
        ----------
        repo : str
            Detector repository URL.
        ref : str
            Ref as requested on the CLI.
        sha : str
            Resolved commit SHA.
        fingerprint : str
            Full container fingerprint of this ref.
        wheelhouses : Callable[[], Sequence[Path]]
            Lazy provider of this side's wheelhouse directories, triggering
            its fetch on first build.
        force_rebuild : bool
            Skip cache reuse and rebuild.

        Returns
        -------
        ContainerEnvHandle
            The ready environment image.
        """
        tag = image_tag(fingerprint)
        cached = not force_rebuild and self._docker.image_exists(tag)
        if not cached:
            houses = wheelhouses()
            checkout = self._store.materialize(repo, sha)
            self._build(tag, checkout, houses)
        record = EnvironmentRecord(
            ref=ref,
            sha=sha,
            fingerprint=fingerprint,
            freeze=self._docker.freeze(tag),
            from_cache=cached,
            rebuilt=not cached,
        )
        return ContainerEnvHandle(record=record, image=tag)

    @contextlib.contextmanager
    def prepare_pair(
        self, repo: str, base_ref: str, head_ref: str, adapter: DetectorAdapter
    ) -> Iterator[PreparedContainerPair]:
        """Prepare both environment images and run their ephemeral containers (contract §3, §11).

        The two refs are fetched in sequence into separate wheelhouses: the
        base side first, into a wheelhouse the head fetch then reads
        **read-only** for reuse (so the shared dependency closure is
        downloaded only once), and the head side into its own wheelhouse
        holding only the names base does not already own. The base image is
        built from the base wheelhouse alone, so an untrusted head build
        hook cannot introduce an artifact the base side would install and so
        cannot forge the independent-reference comparison (contract §3,
        §11).

        Cached image pairs with an empty non-detector dependency delta are
        used directly; any non-empty delta triggers an automatic paired
        same-run rebuild, so only a delta that survives it is
        ref-attributable. Both analysis containers start network-less before
        the context yields, each seeing only its own side's workspace root,
        and are force-removed when the context exits — regardless of
        analysis outcome, and before the caller can assemble or write any
        report output. When the analysis itself succeeded, a removal the
        daemon cannot confirm fails the run rather than letting output be
        written while a container may still exist.

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
        PreparedContainerPair
            The two running containers, surviving delta, and fetch records.

        Raises
        ------
        ContainerError
            If an environment cannot be prepared, or teardown of a
            container cannot be confirmed after a successful analysis.
        """
        base_sha = self._store.resolve_ref(repo, base_ref)
        head_sha = self._store.resolve_ref(repo, head_ref)
        self._fetches.append(FetchRecord(kind='git', name=repo, resolved=base_sha))
        if head_sha != base_sha:
            self._fetches.append(FetchRecord(kind='git', name=repo, resolved=head_sha))
        docker_identity = self._docker.identity()
        base_fingerprint = container_fingerprint(repo, base_sha, adapter, docker_identity, self._image)
        head_fingerprint = container_fingerprint(repo, head_sha, adapter, docker_identity, self._image)
        pair_key = hashlib.sha256(f'{base_fingerprint}:{head_fingerprint}'.encode()).hexdigest()[:24]
        pair_dir = self._cache_dir / 'wheelhouse-container' / Path(pair_key).name
        base_house = pair_dir / 'base'
        head_house = pair_dir / 'head'
        base_house.mkdir(parents=True, exist_ok=True)
        head_house.mkdir(parents=True, exist_ok=True)

        def base_wheelhouses() -> Sequence[Path]:
            """Fetch the base closure, then serve the base wheelhouse.

            Called once per build of the base side (``_ensure`` fetches only
            when it actually builds, and a paired rebuild resets first).

            Returns
            -------
            Sequence[Path]
                The base side's single wheelhouse.
            """
            self._fetch_into(repo, base_sha, base_house, find_links=None, exclude=frozenset())
            return (base_house,)

        def head_wheelhouses() -> Sequence[Path]:
            """Fetch the head extras, reusing base wheels read-only.

            The base fetch, when it runs at all, always precedes the head
            fetch (base ``_ensure`` runs first), so ``base_house`` already
            holds the shared closure the head fetch reuses and excludes; when
            the base side is cached, ``base_house`` is empty and the head
            fetch downloads its own full closure.

            Returns
            -------
            Sequence[Path]
                The base wheelhouse followed by the head-extras wheelhouse.
            """
            owned = frozenset(entry.name for entry in base_house.iterdir())
            self._fetch_into(repo, head_sha, head_house, find_links=base_house, exclude=owned)
            return (base_house, head_house)

        base = self._ensure(
            repo=repo,
            ref=base_ref,
            sha=base_sha,
            fingerprint=base_fingerprint,
            wheelhouses=base_wheelhouses,
            force_rebuild=self._fresh,
        )
        head = self._ensure(
            repo=repo,
            ref=head_ref,
            sha=head_sha,
            fingerprint=head_fingerprint,
            wheelhouses=head_wheelhouses,
            force_rebuild=self._fresh,
        )

        def reset_fetches() -> None:
            """Discard partial fetch state before a forced two-phase re-fetch.

            A cached side leaves its wheelhouse empty while the other side
            fetched a full closure; forcing both to build must re-fetch
            cleanly base-first, or the head wheelhouse would overlap the
            now-populated base one.
            """
            for house in (base_house, head_house):
                shutil.rmtree(house, ignore_errors=True)
                house.mkdir(parents=True, exist_ok=True)

        delta = dependency_delta(base.record.freeze, head.record.freeze, detector_distribution=adapter.distribution)
        if delta and not (base.record.rebuilt and head.record.rebuilt):
            # Attribution is temporal, never textual: rebuild both sides in
            # this run before attributing the delta to the refs (§3).
            reset_fetches()
            base = self._ensure(
                repo=repo,
                ref=base_ref,
                sha=base_sha,
                fingerprint=base_fingerprint,
                wheelhouses=base_wheelhouses,
                force_rebuild=True,
            )
            head = self._ensure(
                repo=repo,
                ref=head_ref,
                sha=head_sha,
                fingerprint=head_fingerprint,
                wheelhouses=head_wheelhouses,
                force_rebuild=True,
            )
            delta = dependency_delta(base.record.freeze, head.record.freeze, detector_distribution=adapter.distribution)
        work_root = Path(tempfile.mkdtemp(prefix='liveness-primer-run-'))
        base_work_root = work_root / 'base'
        head_work_root = work_root / 'head'
        base_work_root.mkdir()
        head_work_root.mkdir()
        base_container = f'{work_root.name}-base'
        head_container = f'{work_root.name}-head'
        started: list[str] = []
        completed = False
        try:
            # Each container mounts only its own side's root: the sides run
            # concurrently, and a shared writable mount would let one side's
            # untrusted code rewrite the other's checkout copy (contract §3).
            for name, handle, side_root in (
                (base_container, base, base_work_root),
                (head_container, head, head_work_root),
            ):
                self._docker.start_container(handle.image, name, work_root=side_root)
                started.append(name)
            yield PreparedContainerPair(
                base=base,
                head=head,
                environment_delta=delta,
                fetches=tuple(self._fetches),
                installer_identity=f'{docker_identity}; image {self._image}',
                work_root=work_root,
                base_work_root=base_work_root,
                head_work_root=head_work_root,
                base_container=base_container,
                head_container=head_container,
            )
            completed = True
        finally:
            leftovers = [name for name in started if not self._docker.remove_container(name)]
            shutil.rmtree(work_root, ignore_errors=True)
            # The success path fails closed: report output must never be
            # written while a container may still exist, so an unconfirmed
            # removal fails the run (contract §3, §11). With an analysis
            # error already in flight, teardown stays best-effort — raising
            # here would mask that error, and the error itself already
            # prevents any report output.
            if completed and leftovers:
                names = ', '.join(leftovers)
                msg = f'could not confirm removal of analysis container(s) {names}; refusing to produce report output'
                raise ContainerError(msg)


@dataclass(frozen=True, slots=True)
class ContainerExecution:
    """Run detector invocations inside the per-side containers (contract §3, §11).

    Attributes
    ----------
    work_roots : dict[str, Path]
        Host workspace root per side (``base``/``head``); each container
        mounts only its own side's root, so one side's untrusted code can
        never reach the other's workspaces.
    containers : dict[str, str]
        Container name per side (``base``/``head``).
    invocation_env : dict[str, str]
        Adapter-declared side-identical variables set on every exec.
    binary : str
        Docker client binary name.
    user : str | None
        ``uid:gid`` the detector runs as, or ``None`` for the image default.
    """

    work_roots: dict[str, Path]
    containers: dict[str, str]
    invocation_env: dict[str, str]
    binary: str = 'docker'
    user: str | None = None

    def workspace_parent(self, side: str) -> Path | None:
        """Report where one side's workspaces must be created.

        Parameters
        ----------
        side : str
            ``base`` or ``head``.

        Returns
        -------
        Path | None
            That side's mounted workspace root — only paths under it exist
            inside that side's container.
        """
        return self.work_roots[side]

    @staticmethod
    def _container_side_root(workspace: SideWorkspace) -> PurePosixPath:
        """Map one side workspace to its container-side checkout path.

        Parameters
        ----------
        workspace : SideWorkspace
            Workspace created under the mounted root.

        Returns
        -------
        PurePosixPath
            The checkout path as the container sees it.
        """
        return CONTAINER_WORK_ROOT / workspace.root.name / 'checkout'

    def launch_plan(self, *, side: str, argv: Sequence[str], workspace: SideWorkspace) -> LaunchPlan:
        """Rewrite the detector argv into a ``docker exec`` (contract §3, §11).

        The container only receives explicitly passed variables, so the
        exec is inherently credential-free; the docker client itself is
        trusted host code and keeps its own environment.

        Parameters
        ----------
        side : str
            ``base`` or ``head``, selecting the container.
        argv : Sequence[str]
            Composed detector argv.
        workspace : SideWorkspace
            The invocation's disposable workspace under the mounted root.

        Returns
        -------
        LaunchPlan
            The prepared ``docker exec`` launch.
        """
        home = CONTAINER_WORK_ROOT / workspace.root.name / 'home'
        plan = [self.binary, 'exec', '--workdir', str(self._container_side_root(workspace))]
        plan.extend(['--env', f'HOME={home}'])
        for name, value in self.invocation_env.items():
            plan.extend(['--env', f'{name}={value}'])
        if self.user is not None:
            plan.extend(['--user', self.user])
        plan.append(self.containers[side])
        plan.extend(argv)
        return LaunchPlan(argv=tuple(plan), cwd=None, env=None)

    def analysis_root(self, workspace: SideWorkspace) -> Path:
        """Report the checkout root as the detector sees it.

        Parameters
        ----------
        workspace : SideWorkspace
            The invocation's disposable workspace.

        Returns
        -------
        Path
            The container-side checkout path, used to normalize
            detector-reported absolute paths (contract §7).
        """
        return Path(str(self._container_side_root(workspace)))
