# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Container-backed detector environments: ephemeral per-side Docker containers (contract §3, §11).

``--container`` moves the build and execution of both detector refs into
Docker. Each ref is installed into a fingerprint-keyed image by an offline
``docker build --network none`` fed from a wheelhouse prefetched during the
fetch step; each side of the run then executes inside its own ephemeral
container started from that image with networking disabled. Both containers
are force-removed when the analysis context exits — before any report output
is rendered or written. Docker is driven exclusively through the audited
launcher via the ``docker`` CLI, and the runtime is injectable so the logic
is testable without a daemon (contract §15).
"""

import contextlib
import hashlib
import json
import os
import re
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
        Stable hex fingerprint over repository, SHA, recipe, base image,
        and Docker runtime.
    """
    material = json.dumps(
        {
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

    def prefetch(self, image: str, requirements: Sequence[str], wheelhouse: Path) -> None:
        """Download distributions into the wheelhouse (fetch step, §3).

        Runs pip inside the base image so the fetched wheels match the
        container platform, not the host.

        Parameters
        ----------
        image : str
            Base image whose pip performs the download.
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        wheelhouse : Path
            Host wheelhouse directory mounted into the fetch container.
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
        """Start one ephemeral, network-less analysis container.

        Parameters
        ----------
        tag : str
            Environment image to run.
        name : str
            Container name used for ``docker exec`` and removal.
        work_root : Path
            Host workspace root mounted at the container work root.
        """
        ...

    def remove_container(self, name: str) -> bool:
        """Force-remove one analysis container, best effort.

        Parameters
        ----------
        name : str
            Container name to remove.

        Returns
        -------
        bool
            True when the removal command succeeded.
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

    def prefetch(self, image: str, requirements: Sequence[str], wheelhouse: Path) -> None:
        """Download distributions with the base image's pip (fetch step, §3).

        Parameters
        ----------
        image : str
            Base image whose pip performs the download.
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        wheelhouse : Path
            Host wheelhouse directory mounted into the fetch container.
        """
        argv = [self.binary, 'run', '--rm']
        user = container_user()
        if user is not None:
            argv.extend(['--user', user])
        argv.extend(
            [
                '--volume',
                f'{wheelhouse}:/liveness/wheelhouse',
                '--env',
                'HOME=/tmp',
                image,
                'python',
                '-m',
                'pip',
                'download',
                '--quiet',
                '--dest',
                '/liveness/wheelhouse',
                '--prefer-binary',
                *requirements,
            ]
        )
        _checked(self.launcher(argv, timeout=_DOCKER_TIMEOUT), action='dependency prefetch (pip download)')

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
        result = _checked(
            self.launcher(
                [self.binary, 'run', '--rm', '--network', 'none', tag, 'python', '-m', 'pip', 'freeze'],
                timeout=_DOCKER_TIMEOUT,
            ),
            action='pip freeze',
        )
        return tuple(line for line in result.stdout.splitlines() if line.strip())

    def start_container(self, tag: str, name: str, *, work_root: Path) -> None:
        """Start one ephemeral, network-less analysis container (contract §11).

        ``--rm`` backstops removal on daemon-side stops; ``--init`` reaps
        detector children of the idle keep-alive process.

        Parameters
        ----------
        tag : str
            Environment image to run.
        name : str
            Container name used for ``docker exec`` and removal.
        work_root : Path
            Host workspace root mounted at the container work root.
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
            '--volume',
            f'{work_root}:{CONTAINER_WORK_ROOT}',
            tag,
            'sleep',
            'infinity',
        ]
        _checked(self.launcher(argv, timeout=_DOCKER_TIMEOUT), action='container start')

    def remove_container(self, name: str) -> bool:
        """Force-remove one analysis container, best effort.

        Parameters
        ----------
        name : str
            Container name to remove.

        Returns
        -------
        bool
            True when the removal command succeeded.
        """
        return self.launcher([self.binary, 'rm', '--force', name], timeout=_DOCKER_TIMEOUT).ok


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
        Host workspace root mounted into both containers.
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

    def _prefetch(self, repo: str, shas: Sequence[str], pair_key: str) -> Path:
        """Prefetch the union of every ref's requirements before any build (§3).

        Both sides build against identical resolution inputs, keeping delta
        attribution temporal, never textual. The download runs inside the
        base image so the wheels match the container platform, not the host;
        the wheelhouse is keyed per pair so each build context stays bounded.

        Parameters
        ----------
        repo : str
            Detector repository URL.
        shas : Sequence[str]
            Resolved commit SHAs of the refs being prepared.
        pair_key : str
            Stable key of the (base, head) fingerprint pair.

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
            # Extras are deliberately left out, exactly as in the host-venv
            # path: the offline install selects no extras (contract §3).
            requirements.extend(metadata.build_requires)
        wheelhouse = self._cache_dir / 'wheelhouse-container' / Path(pair_key).name
        wheelhouse.mkdir(parents=True, exist_ok=True)
        deduped = tuple(dict.fromkeys(requirements))
        if not deduped:
            return wheelhouse
        before = {entry.name for entry in wheelhouse.iterdir()}
        self._docker.prefetch(self._image, deduped, wheelhouse)
        added = {entry.name for entry in wheelhouse.iterdir()} - before
        self._fetches.extend(fetch_records_for(wheelhouse, added))
        return wheelhouse

    def _build(self, tag: str, checkout: Path, wheelhouse: Path) -> None:
        """Build one environment image from an offline context (build step, §3, §11).

        Parameters
        ----------
        tag : str
            Tag for the built image.
        checkout : Path
            Detector checkout to install.
        wheelhouse : Path
            Prefetched wheelhouse both sides install from.
        """
        with tempfile.TemporaryDirectory(prefix='liveness-primer-context-') as scratch:
            context = Path(scratch)
            # Symlinks are copied as symlinks: following them could pull
            # content from outside the untrusted checkout into the image.
            shutil.copytree(checkout, context / 'detector', symlinks=True, ignore=shutil.ignore_patterns('.git'))
            shutil.copytree(wheelhouse, context / 'wheelhouse')
            (context / 'Dockerfile').write_text(_DOCKERFILE.format(image=self._image), encoding='utf-8')
            self._docker.build_image(tag, context, fresh=self._fresh)

    def _ensure(
        self,
        *,
        repo: str,
        ref: str,
        sha: str,
        fingerprint: str,
        wheelhouse: Callable[[], Path],
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
        wheelhouse : Callable[[], Path]
            Lazy provider of the pair's prefetched wheelhouse.
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
            house = wheelhouse()
            checkout = self._store.materialize(repo, sha)
            self._build(tag, checkout, house)
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

        Cached image pairs with an empty non-detector dependency delta are
        used directly; any non-empty delta triggers an automatic paired
        same-run rebuild, so only a delta that survives it is
        ref-attributable. Both analysis containers start network-less before
        the context yields and are force-removed when it exits — regardless
        of analysis outcome, and before the caller can assemble or write any
        report output.

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
                wheelhouse = self._prefetch(repo, (base_sha, head_sha), pair_key)
            return wheelhouse

        base = self._ensure(
            repo=repo,
            ref=base_ref,
            sha=base_sha,
            fingerprint=base_fingerprint,
            wheelhouse=pair_wheelhouse,
            force_rebuild=self._fresh,
        )
        head = self._ensure(
            repo=repo,
            ref=head_ref,
            sha=head_sha,
            fingerprint=head_fingerprint,
            wheelhouse=pair_wheelhouse,
            force_rebuild=self._fresh,
        )
        delta = dependency_delta(base.record.freeze, head.record.freeze, detector_distribution=adapter.distribution)
        if delta and not (base.record.rebuilt and head.record.rebuilt):
            # Attribution is temporal, never textual: rebuild both sides in
            # this run before attributing the delta to the refs (§3).
            base = self._ensure(
                repo=repo,
                ref=base_ref,
                sha=base_sha,
                fingerprint=base_fingerprint,
                wheelhouse=pair_wheelhouse,
                force_rebuild=True,
            )
            head = self._ensure(
                repo=repo,
                ref=head_ref,
                sha=head_sha,
                fingerprint=head_fingerprint,
                wheelhouse=pair_wheelhouse,
                force_rebuild=True,
            )
            delta = dependency_delta(base.record.freeze, head.record.freeze, detector_distribution=adapter.distribution)
        work_root = Path(tempfile.mkdtemp(prefix='liveness-primer-run-'))
        base_container = f'{work_root.name}-base'
        head_container = f'{work_root.name}-head'
        started: list[str] = []
        try:
            for name, handle in ((base_container, base), (head_container, head)):
                self._docker.start_container(handle.image, name, work_root=work_root)
                started.append(name)
            yield PreparedContainerPair(
                base=base,
                head=head,
                environment_delta=delta,
                fetches=tuple(self._fetches),
                installer_identity=f'{docker_identity}; image {self._image}',
                work_root=work_root,
                base_container=base_container,
                head_container=head_container,
            )
        finally:
            # The removal is unconditional and happens before the caller can
            # continue past the analysis context — no report output exists
            # while a container is still running. Removal is best-effort:
            # `--rm` on the containers backstops a failed force-remove.
            for name in started:
                self._docker.remove_container(name)
            shutil.rmtree(work_root, ignore_errors=True)


@dataclass(frozen=True, slots=True)
class ContainerExecution:
    """Run detector invocations inside the per-side containers (contract §3, §11).

    Attributes
    ----------
    work_root : Path
        Host workspace root mounted at the container work root; every side
        workspace is created under it.
    containers : dict[str, str]
        Container name per side (``base``/``head``).
    invocation_env : dict[str, str]
        Adapter-declared side-identical variables set on every exec.
    binary : str
        Docker client binary name.
    user : str | None
        ``uid:gid`` the detector runs as, or ``None`` for the image default.
    """

    work_root: Path
    containers: dict[str, str]
    invocation_env: dict[str, str]
    binary: str = 'docker'
    user: str | None = None

    @property
    def workspace_parent(self) -> Path | None:
        """Report where side workspaces must be created.

        Returns
        -------
        Path | None
            The mounted workspace root — only paths under it exist inside
            the containers.
        """
        return self.work_root

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
