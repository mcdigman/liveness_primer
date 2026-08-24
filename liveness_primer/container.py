# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Container-backed detector environments: ephemeral invocation containers (contract §3, §11).

``--container`` moves the build and execution of both detector refs into
Docker. Each ref is installed into a fingerprint-keyed, distroless runtime
image by an offline multi-stage ``docker build --network none`` fed from a
wheelhouse prefetched with the matching builder image. Every detector
invocation then runs in its own named, hardened container (non-root, all
capabilities dropped, no new privileges, PID-limited, read-only root
filesystem) with networking disabled and only its side's workspace root
mounted. Each container is force-removed before its workspace; the pair
context reaps any leftover before output, and an unconfirmed removal fails the
run. Docker is driven exclusively through the audited launcher via the
``docker`` CLI, and the runtime is injectable so the logic is testable without
a daemon (contract §15).
"""

import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol, runtime_checkable

from filelock import BaseFileLock, FileLock, Timeout

from liveness_primer.corpus import CheckoutStore
from liveness_primer.envcache import (
    fetch_records_for,
    parse_static_metadata,
    resolve_pair_refs,
    resolve_paired_delta,
)
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.execution import LaunchPlan, SideWorkspace
from liveness_primer.findings import DependencyDelta, EnvironmentRecord, FetchRecord
from liveness_primer.isolation import Isolation
from liveness_primer.launcher import LaunchResult, SyncLauncher, run_sync, validate_sync_launcher
from liveness_primer.tools.base import DetectorAdapter

# The public Chainguard tags are mutable daily-build pointers. Pin the
# multi-platform OCI indexes so a cache fingerprint names exact builder and
# runtime bytes on both supported architectures.
DEFAULT_CONTAINER_BUILDER_IMAGE = (
    'cgr.dev/chainguard/python:latest-dev@sha256:14acabef9a759e7d07bf647afec92bc28cbe0f89c978fe426411c85035121c14'
)
DEFAULT_CONTAINER_IMAGE = (
    'cgr.dev/chainguard/python:latest@sha256:d812438658b47b73cb4c089f4cca09bca1ba50f6cd1843133864ee074d9ec49b'
)


@dataclass(frozen=True, slots=True)
class StaticBinaryArtifact:
    """One digest-pinned static runtime utility release artifact.

    Attributes
    ----------
    version : str
        Upstream release version.
    architecture : Literal['x86_64', 'aarch64']
        Linux machine architecture.
    filename : str
        Release archive filename.
    url : str
        Immutable release download URL.
    archive_digest : str
        Expected archive SHA-256.
    member : str
        Exact archive member holding the executable.
    binary_digest : str
        Expected extracted executable SHA-256.
    """

    version: str
    architecture: Literal['x86_64', 'aarch64']
    filename: str
    url: str
    archive_digest: str
    member: str
    binary_digest: str


_RIPGREP_VERSION = '15.2.0'
_RIPGREP_ARTIFACTS: Mapping[str, StaticBinaryArtifact] = {
    'x86_64': StaticBinaryArtifact(
        version=_RIPGREP_VERSION,
        architecture='x86_64',
        filename=f'ripgrep-{_RIPGREP_VERSION}-x86_64-unknown-linux-musl.tar.gz',
        url=(
            'https://github.com/BurntSushi/ripgrep/releases/download/'
            f'{_RIPGREP_VERSION}/ripgrep-{_RIPGREP_VERSION}-x86_64-unknown-linux-musl.tar.gz'
        ),
        archive_digest='33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c',
        member=f'ripgrep-{_RIPGREP_VERSION}-x86_64-unknown-linux-musl/rg',
        binary_digest='e62198eb19b136b88c330af83647b5a962cb99b6b1f066758568f12de1974849',
    ),
    'aarch64': StaticBinaryArtifact(
        version=_RIPGREP_VERSION,
        architecture='aarch64',
        filename=f'ripgrep-{_RIPGREP_VERSION}-aarch64-unknown-linux-musl.tar.gz',
        url=(
            'https://github.com/BurntSushi/ripgrep/releases/download/'
            f'{_RIPGREP_VERSION}/ripgrep-{_RIPGREP_VERSION}-aarch64-unknown-linux-musl.tar.gz'
        ),
        archive_digest='800b1e7206afe799dfb5a6901f23147cfaabe0e52210538100f61e86e1740915',
        member=f'ripgrep-{_RIPGREP_VERSION}-aarch64-unknown-linux-musl/rg',
        binary_digest='c14cdb389f34e504d69e386cfc67d5c5d9a730a990de03ca6910b2a15e30386a',
    ),
}

# Download and extract the one expected release member inside the hardened,
# network-enabled fetch container. Both the archive and extracted binary are
# bounded and digest-checked before the host-visible output is created.
_RIPGREP_FETCH_SCRIPT = """\
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import urllib.request

url, archive_digest, member_name, binary_digest = sys.argv[1:]
with urllib.request.urlopen(url, timeout=300) as response:
    payload = response.read(8_388_609)
if len(payload) > 8_388_608:
    raise RuntimeError("ripgrep archive exceeds 8 MiB")
if hashlib.sha256(payload).hexdigest() != archive_digest:
    raise RuntimeError("ripgrep archive digest mismatch")
with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
    member = archive.getmember(member_name)
    if not member.isfile():
        raise RuntimeError("ripgrep archive member is not a regular file")
    source = archive.extractfile(member)
    if source is None:
        raise RuntimeError("ripgrep archive member cannot be read")
    binary = source.read(16_777_217)
if len(binary) > 16_777_216:
    raise RuntimeError("ripgrep binary exceeds 16 MiB")
if hashlib.sha256(binary).hexdigest() != binary_digest:
    raise RuntimeError("ripgrep binary digest mismatch")
target = Path("/liveness/tool/rg")
target.write_bytes(binary)
target.chmod(0o555)
"""

# Both sides' containers run with networking disabled; unlike the host netns
# probe this is enforced by the container runtime on every platform (§11).
CONTAINER_ISOLATION = Isolation(enforced=True, description='container:docker-network-none', prefix=())

# Container-side mount point of the run's workspace root; side workspaces are
# created under it on the host and addressed through it inside the containers.
CONTAINER_WORK_ROOT = PurePosixPath('/liveness/work')

# Container-side tmpfs mount point. Constructing it as a POSIX container path
# keeps it distinct from host filesystem paths governed by tempfile.
CONTAINER_TMP_ROOT = PurePosixPath('/') / 'tmp'

_DOCKER_TIMEOUT = 1800.0

# Cache-format / security revision of the environment image. Bump whenever the
# Dockerfile, the build inputs (e.g. per-side isolated wheelhouses), or the
# container hardening change in a way that must not silently reuse an image an
# earlier revision cached under an otherwise-identical fingerprint.
#   1: initial ephemeral-container build.
#   2: container hardening + per-side isolated fetch/build wheelhouses.
#   3: separate builder/runtime images + pip-free distroless runtime with a
#      pinned static ripgrep utility for Skylos verification.
_CONTAINER_CACHE_FORMAT = 3

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
    str(CONTAINER_TMP_ROOT),
)

_IMAGE_REFERENCE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/@-]*$')

_DOCKERFILE = """\
FROM {builder_image} AS builder
USER 0
RUN ["/usr/bin/python", "-m", "venv", "/liveness/venv"]
COPY wheelhouse /liveness/wheelhouse
COPY detector /liveness/detector
RUN /liveness/venv/bin/python -m pip install --quiet --no-index \
    --find-links /liveness/wheelhouse /liveness/detector
RUN /liveness/venv/bin/python -m pip freeze > /liveness/freeze.txt
RUN ["/liveness/venv/bin/python", "-m", "pip", "uninstall", "--yes", "pip"]

FROM {runtime_image}
COPY --from=builder /liveness/venv /liveness/venv
COPY --from=builder /liveness/freeze.txt /liveness/freeze.txt
COPY tools/rg /usr/bin/rg
ENV PATH="/liveness/venv/bin:$PATH"
ENTRYPOINT []
"""


class ContainerError(LivenessPrimerError):
    """Raised when the Docker runtime cannot prepare or run an environment."""


def _validate_cache_directory(path: Path) -> None:
    """Reject a persistent cache path that redirects or is not a directory.

    Parameters
    ----------
    path : Path
        Cache directory to validate before use.

    Raises
    ------
    ContainerError
        If the path is a symlink or exists as anything but a directory.
    """
    try:
        status = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        msg = f'container cache path is not a regular directory: {path}'
        raise ContainerError(msg)


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
        If any non-excluded staged entry is a symlink or not a regular
        file; nothing is promoted in that case.
    """
    staged = [entry for entry in sorted(staging.iterdir()) if entry.name not in exclude]
    # Validate every entry before promoting any: a rejected fetch must
    # leave the persistent wheelhouse without unrecorded artifacts.
    for entry in staged:
        if entry.is_symlink() or not entry.is_file():
            msg = f'prefetched distribution is not a regular file: {entry.name}'
            raise ContainerError(msg)
    before = {entry.name for entry in wheelhouse.iterdir()}
    added: set[str] = set()
    for entry in staged:
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


def stage_invocation_env_files(files: Mapping[str, Path], work_roots: Iterable[Path]) -> dict[str, str]:
    """Stage adapter-declared environment files into each side's mount (contract §3).

    A declared file lives on the host, which the containers cannot see; a
    copy under every side's mounted work root gives both sides the identical
    file at the identical container path.

    Parameters
    ----------
    files : Mapping[str, Path]
        Adapter-declared variables mapped to packaged host files.
    work_roots : Iterable[Path]
        Host work roots mounted at the container work root, one per side.

    Returns
    -------
    dict[str, str]
        Each variable mapped to the staged file's container-side path.
    """
    work_roots = tuple(work_roots)
    staged: dict[str, str] = {}
    for name, source in files.items():
        for root in work_roots:
            target_dir = root / 'invocation-env' / name
            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target_dir / source.name)
        staged[name] = str(CONTAINER_WORK_ROOT / 'invocation-env' / name / source.name)
    return staged


def container_fingerprint(
    repo: str,
    sha: str,
    adapter: DetectorAdapter,
    docker_identity: str,
    builder_image: str,
    runtime_image: str,
    ripgrep_identity: str,
) -> str:
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
    builder_image : str
        Development image that fetches and installs distributions.
    runtime_image : str
        Minimal image that runs the installed detector.
    ripgrep_identity : str
        Version, architecture, and exact binary digest of the runtime search
        utility.

    Returns
    -------
    str
        Stable hex fingerprint over the cache-format revision, repository,
        SHA, recipe, both exact image references, runtime search utility, and
        Docker runtime. A cache-format bump makes every prior image miss the
        cache and rebuild.
    """
    material = json.dumps(
        {
            'cache_format': _CONTAINER_CACHE_FORMAT,
            'repo': repo,
            'sha': sha,
            'recipe': adapter.build_recipe.digest(),
            'builder_image': builder_image,
            'runtime': docker_identity,
            'runtime_image': runtime_image,
            'ripgrep': ripgrep_identity,
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


def ripgrep_artifact_for(machine: str) -> StaticBinaryArtifact:
    """Select the pinned ripgrep artifact for one container architecture.

    Parameters
    ----------
    machine : str
        Architecture reported by Python inside the builder image.

    Returns
    -------
    StaticBinaryArtifact
        Matching static Linux release artifact.

    Raises
    ------
    ContainerError
        If the architecture has no pinned artifact.
    """
    normalized = {'amd64': 'x86_64', 'arm64': 'aarch64'}.get(machine, machine)
    try:
        return _RIPGREP_ARTIFACTS[normalized]
    except KeyError as error:
        msg = f'container architecture {machine!r} has no pinned ripgrep artifact'
        raise ContainerError(msg) from error


def _ripgrep_identity(artifact: StaticBinaryArtifact) -> str:
    """Describe exact ripgrep runtime bytes for fingerprints and manifests.

    Parameters
    ----------
    artifact : StaticBinaryArtifact
        Architecture-specific pinned release metadata.

    Returns
    -------
    str
        Stable version, architecture, and binary-digest identity.
    """
    return f'ripgrep {artifact.version} ({artifact.architecture}) sha256:{artifact.binary_digest}'


def stage_static_binary(source: Path, destination: Path) -> None:
    """Copy one verified static binary into an offline build context.

    Parameters
    ----------
    source : Path
        Fresh output of the runtime's digest-verifying fetch operation.
    destination : Path
        Build-context path to create.

    Raises
    ------
    ContainerError
        If the fetch output is missing, a symlink, or not a regular file.
    """
    try:
        status = source.lstat()
    except FileNotFoundError as error:
        msg = f'prefetched static binary is missing: {source.name}'
        raise ContainerError(msg) from error
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        msg = f'prefetched static binary is not a regular file: {source.name}'
        raise ContainerError(msg)
    destination.parent.mkdir()
    shutil.copyfile(source, destination)
    destination.chmod(0o555)


def _validate_prefetched_binary(path: Path, expected_digest: str) -> None:
    """Validate the runtime's host-visible static-binary fetch output.

    Parameters
    ----------
    path : Path
        Host-visible executable written by the fetch container.
    expected_digest : str
        Required executable SHA-256.

    Raises
    ------
    ContainerError
        If the output is missing, non-regular, or has the wrong digest.
    """
    try:
        status = path.lstat()
    except FileNotFoundError as error:
        msg = 'ripgrep fetch did not produce rg'
        raise ContainerError(msg) from error
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        msg = 'ripgrep fetch produced a non-regular rg'
        raise ContainerError(msg)
    actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_digest != expected_digest:
        msg = f'ripgrep binary digest mismatch: expected {expected_digest}, got {actual_digest}'
        raise ContainerError(msg)
    path.chmod(0o555)


@runtime_checkable
class DockerRuntime(Protocol):
    """Injectable Docker runtime operations (contract §15)."""

    @property
    def binary(self) -> str:
        """Client binary spawning every container-mode argv.

        Per-invocation container launches are composed outside this protocol
        and must spawn the same client, so the runtime names it.

        Returns
        -------
        str
            E.g. ``docker`` or ``podman``.
        """
        ...

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

    def architecture(self, image: str) -> str:
        """Report the machine architecture inside an image.

        Parameters
        ----------
        image : str
            Builder image to inspect.

        Returns
        -------
        str
            Python's normalized machine name inside the image.
        """
        ...

    def prefetch(
        self, image: str, requirements: Sequence[str], destination: Path, *, find_links: Path | None = None
    ) -> None:
        """Download distributions into a staging directory (fetch step, §3).

        Runs pip inside the builder image so the fetched wheels match the
        runtime platform, not the host. The destination is a fresh
        staging directory, never the persistent cache: the caller validates
        and promotes the results (contract §11). ``find_links``, when given,
        is mounted **read-only** and offered to the resolver, so the head
        fetch reuses the base side's already-downloaded wheels without being
        able to alter them.

        Parameters
        ----------
        image : str
            Builder image whose pip performs the download.
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        destination : Path
            Fresh host staging directory mounted into the fetch container.
        find_links : Path | None
            Base-side wheelhouse mounted read-only as an extra resolver
            source, or ``None`` for the base fetch itself.
        """
        ...

    def prefetch_ripgrep(self, image: str, artifact: StaticBinaryArtifact, destination: Path) -> None:
        """Fetch and verify a pinned static ripgrep binary.

        Parameters
        ----------
        image : str
            Builder image whose Python performs the fetch.
        artifact : StaticBinaryArtifact
            Architecture-specific release metadata and digests.
        destination : Path
            Fresh directory that receives an executable named ``rg``.
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

    def python_version(self, tag: str) -> str:
        """Report the interpreter version inside an environment image.

        Parameters
        ----------
        tag : str
            Environment image to inspect.

        Returns
        -------
        str
            The container-side ``platform.python_version()``.
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

    def _run_auxiliary(
        self,
        kind: str,
        image: str,
        command: Sequence[str],
        *,
        action: str,
        offline: bool,
        volumes: Sequence[str] = (),
    ) -> LaunchResult:
        """Run one named, hardened helper container and force-remove it (contract §11).

        Every helper shares the hardening, user mapping, tmpfs ``HOME``, and
        tracked-name cleanup; only the fetch step may reach the network.

        Parameters
        ----------
        kind : str
            Helper kind embedded in the tracked container name.
        image : str
            Image to run.
        command : Sequence[str]
            Command executed inside the container.
        action : str
            Description for error messages.
        offline : bool
            Disable networking (every helper except the fetch step).
        volumes : Sequence[str]
            ``--volume`` specifications to mount.

        Returns
        -------
        LaunchResult
            The successful result.
        """
        name = f'liveness-primer-{kind}-{secrets.token_hex(6)}'
        argv = [self.binary, 'run', '--rm', '--name', name, '--entrypoint', '']
        if offline:
            argv.extend(('--network', 'none'))
        argv.extend((*_HARDENING_FLAGS, *_user_flags()))
        for volume in volumes:
            argv.extend(('--volume', volume))
        argv.extend(('--env', f'HOME={CONTAINER_TMP_ROOT}', image, *command))
        try:
            return _checked(self.launcher(argv, timeout=_DOCKER_TIMEOUT), action=action)
        finally:
            self._remove_auxiliary(name)

    def architecture(self, image: str) -> str:
        """Report the machine architecture inside an image, offline.

        Parameters
        ----------
        image : str
            Builder image to inspect.

        Returns
        -------
        str
            Python's machine name inside the image.
        """
        command = ('python', '-c', 'import platform; print(platform.machine())')
        result = self._run_auxiliary('arch', image, command, action='container architecture probe', offline=True)
        return result.stdout.strip()

    def prefetch(
        self, image: str, requirements: Sequence[str], destination: Path, *, find_links: Path | None = None
    ) -> None:
        """Download distributions with the builder image's pip (fetch step, §3).

        The fetch container is named and force-removed afterwards, so a
        client-side timeout cannot leak an untracked running container. A
        ``find_links`` wheelhouse is mounted read-only, so the head fetch
        reuses base-side wheels it cannot modify (contract §3, §11).

        Parameters
        ----------
        image : str
            Builder image whose pip performs the download.
        requirements : Sequence[str]
            Requirement strings to download, wheels preferred.
        destination : Path
            Fresh host staging directory mounted into the fetch container.
        find_links : Path | None
            Base-side wheelhouse mounted read-only as an extra resolver
            source, or ``None`` for the base fetch itself.
        """
        volumes = [f'{destination}:/liveness/wheelhouse']
        download_flags = ['--prefer-binary']
        if find_links is not None:
            volumes.append(f'{find_links}:/liveness/base-links:ro')
            download_flags.extend(['--find-links', '/liveness/base-links'])
        command = ['python', '-m', 'pip', 'download', '--quiet', '--dest', '/liveness/wheelhouse', *download_flags]
        command.extend(requirements)
        self._run_auxiliary(
            'fetch',
            image,
            command,
            action='dependency prefetch (pip download)',
            offline=False,
            volumes=volumes,
        )

    def prefetch_ripgrep(self, image: str, artifact: StaticBinaryArtifact, destination: Path) -> None:
        """Fetch and digest-verify one static ripgrep release binary.

        Parameters
        ----------
        image : str
            Builder image whose Python performs the fetch and extraction.
        artifact : StaticBinaryArtifact
            Architecture-specific release metadata and digests.
        destination : Path
            Fresh directory that receives an executable named ``rg``.
        """
        command = (
            'python',
            '-c',
            _RIPGREP_FETCH_SCRIPT,
            artifact.url,
            artifact.archive_digest,
            artifact.member,
            artifact.binary_digest,
        )
        self._run_auxiliary(
            'ripgrep-fetch',
            image,
            command,
            action='ripgrep prefetch',
            offline=False,
            volumes=(f'{destination}:/liveness/tool',),
        )
        _validate_prefetched_binary(destination / 'rg', artifact.binary_digest)

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
        command = (
            'python',
            '-c',
            "from pathlib import Path; print(Path('/liveness/freeze.txt').read_text(), end='')",
        )
        result = self._run_auxiliary('freeze', tag, command, action='environment freeze', offline=True)
        return tuple(line for line in result.stdout.splitlines() if line.strip())

    def python_version(self, tag: str) -> str:
        """Report the interpreter version inside an environment image, offline.

        Parameters
        ----------
        tag : str
            Environment image to inspect.

        Returns
        -------
        str
            The container-side ``platform.python_version()``.
        """
        command = ('python', '-c', 'import platform; print(platform.python_version())')
        result = self._run_auxiliary('pyver', tag, command, action='container python version', offline=True)
        return result.stdout.strip()

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
        Docker runtime, exact builder/runtime images, and exact ripgrep bytes.
    python_version : str
        Interpreter version inside the environment images.
    work_root : Path
        Host directory holding both per-side workspace roots.
    base_work_root : Path
        Base-side workspace root; the only mount the base container sees.
    head_work_root : Path
        Head-side workspace root; the only mount the head container sees.
    active_containers : set[str]
        Invocation container names still requiring confirmed removal.
    """

    base: ContainerEnvHandle
    head: ContainerEnvHandle
    environment_delta: tuple[DependencyDelta, ...]
    fetches: tuple[FetchRecord, ...]
    installer_identity: str
    python_version: str
    work_root: Path
    base_work_root: Path
    head_work_root: Path
    active_containers: set[str]


class ContainerEnvironments:
    """Build two detector images and own their invocation lifecycle (contract §3).

    Environment images are keyed by the container fingerprint and cached by
    the Docker image store, which also serializes concurrent builds of the
    same tag; the persistent per-pair wheelhouses are guarded by a
    cross-process ``filelock`` instead. Analysis containers are created per
    invocation and force-removed before their workspaces; the pair context
    tracks and reaps any leftover before report output.

    Parameters
    ----------
    store : CheckoutStore
        Checkout store for detector clones.
    cache_dir : Path
        Cache directory holding the per-pair container wheelhouses.
    docker : DockerRuntime
        Docker runtime operations; injectable for tests (contract §15).
    builder_image : str
        Development image used for dependency fetching and installation.
    runtime_image : str
        Minimal image used for detector execution.
    fresh : bool
        Force same-run image rebuilds (``--fresh``).
    lock_timeout : float
        Seconds to wait for the pair wheelhouse lock.

    Raises
    ------
    ContainerError
        If either image reference is malformed, or the host has no POSIX user
        ids — the §11 run-as-host-user hardening cannot be enforced, and the
        mode refuses rather than silently degrading.
    """

    def __init__(
        self,
        store: CheckoutStore,
        cache_dir: Path,
        *,
        docker: DockerRuntime,
        builder_image: str = DEFAULT_CONTAINER_BUILDER_IMAGE,
        runtime_image: str = DEFAULT_CONTAINER_IMAGE,
        fresh: bool = False,
        lock_timeout: float = _DOCKER_TIMEOUT,
    ) -> None:
        for role, image in (('builder', builder_image), ('runtime', runtime_image)):
            if not _IMAGE_REFERENCE.match(image):
                msg = f'malformed container {role} image reference: {image!r}'
                raise ContainerError(msg)
        if container_user() is None:
            msg = '--container requires POSIX user ids to enforce the run-as-host-user hardening (§11)'
            raise ContainerError(msg)
        self._store = store
        self._cache_dir = cache_dir
        self._docker = docker
        self._builder_image = builder_image
        self._runtime_image = runtime_image
        self._fresh = fresh
        self._lock_timeout = lock_timeout
        self._fetches: list[FetchRecord] = []

    @property
    def runtime(self) -> DockerRuntime:
        """Runtime that owns invocation containers.

        Returns
        -------
        DockerRuntime
            Runtime used for both environment preparation and analysis.
        """
        return self._docker

    @contextlib.contextmanager
    def _pair_lock(self, pair_dir: Path) -> Iterator[None]:
        """Hold the cross-process lock of one pair's wheelhouses (contract §3).

        The Docker image store serializes builds of a tag, but the
        persistent wheelhouses are fetched into, snapshotted, and reset by
        this process; without the lock a concurrent run of the same pair
        could corrupt or delete them mid-use.

        Parameters
        ----------
        pair_dir : Path
            The pair's wheelhouse directory.

        Yields
        ------
        None
            While the lock is held.

        Raises
        ------
        ContainerError
            If the lock cannot be acquired in time.
        """
        lock: BaseFileLock = FileLock(str(pair_dir) + '.lock')
        try:
            lock.acquire(timeout=self._lock_timeout)
        except Timeout as exc:
            msg = f'timed out waiting for the container wheelhouse lock at {pair_dir}'
            raise ContainerError(msg) from exc
        try:
            yield
        finally:
            lock.release()

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

        The download runs inside the builder image so wheels match the
        runtime platform, not the host. The fetch container only ever
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
        with tempfile.TemporaryDirectory(prefix='liveness-primer-fetch-', dir=wheelhouse.parent) as scratch:
            staging = Path(scratch)
            self._docker.prefetch(self._builder_image, requirements, staging, find_links=find_links)
            added = promote_prefetched(staging, wheelhouse, exclude=exclude)
        self._fetches.extend(fetch_records_for(wheelhouse, added))

    def _build(
        self,
        tag: str,
        checkout: Path,
        wheelhouses: Sequence[Path],
        ripgrep: Callable[[], Path],
    ) -> None:
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
        ripgrep : Callable[[], Path]
            Lazy provider of the verified static search binary shared by both
            side builds.

        Raises
        ------
        ContainerError
            If ``checkout`` is not a direct entry of the checkout cache.
        """
        source = self._store.checkout_root / Path(checkout).name
        if source != checkout:
            msg = f'refusing to build from {checkout}: not a checkout cache entry'
            raise ContainerError(msg)
        with tempfile.TemporaryDirectory(prefix='liveness-primer-context-') as scratch:
            context = Path(scratch)
            # Symlinks are copied as symlinks: following them could pull
            # content from outside the untrusted checkout into the image.
            shutil.copytree(source, context / 'detector', symlinks=True, ignore=shutil.ignore_patterns('.git'))
            stage_wheelhouses(wheelhouses, context / 'wheelhouse')
            stage_static_binary(ripgrep(), context / 'tools' / 'rg')
            dockerfile = _DOCKERFILE.format(
                builder_image=self._builder_image,
                runtime_image=self._runtime_image,
            )
            (context / 'Dockerfile').write_text(dockerfile, encoding='utf-8')
            self._docker.build_image(tag, context, fresh=self._fresh)

    def _ensure(
        self,
        *,
        repo: str,
        ref: str,
        sha: str,
        fingerprint: str,
        wheelhouses: Callable[[], Sequence[Path]],
        ripgrep: Callable[[], Path],
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
        ripgrep : Callable[[], Path]
            Lazy provider of the verified static search binary.
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
            self._build(tag, checkout, houses, ripgrep)
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
        ref-attributable. The yielded pair owns a registry of per-invocation
        containers. Each is force-removed before its writable workspace; the
        context exit reaps any leftover before the caller can assemble or
        write report output. When analysis succeeded, a removal the daemon
        cannot confirm fails the run instead of allowing output while a
        container may still exist.

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
            The two environment images, lifecycle registry, surviving delta,
            and fetch records.

        Raises
        ------
        ContainerError
            If an environment cannot be prepared, or teardown of a
            container cannot be confirmed after a successful analysis.
        """
        base_sha, head_sha, ref_fetches = resolve_pair_refs(self._store, repo, base_ref, head_ref)
        self._fetches.extend(ref_fetches)
        docker_identity = self._docker.identity()
        ripgrep_artifact = ripgrep_artifact_for(self._docker.architecture(self._builder_image))
        ripgrep_id = _ripgrep_identity(ripgrep_artifact)
        base_fingerprint = container_fingerprint(
            repo,
            base_sha,
            adapter,
            docker_identity,
            self._builder_image,
            self._runtime_image,
            ripgrep_id,
        )
        head_fingerprint = container_fingerprint(
            repo,
            head_sha,
            adapter,
            docker_identity,
            self._builder_image,
            self._runtime_image,
            ripgrep_id,
        )
        pair_key = hashlib.sha256(f'{base_fingerprint}:{head_fingerprint}'.encode()).hexdigest()[:24]
        wheelhouse_root = self._cache_dir / 'wheelhouse-container'
        pair_dir = wheelhouse_root / Path(pair_key).name
        base_house = pair_dir / 'base'
        head_house = pair_dir / 'head'
        tool_dir = pair_dir / 'tools'
        houses: dict[Literal['base', 'head'], Path] = {'base': base_house, 'head': head_house}

        def reset_house(side: Literal['base', 'head']) -> None:
            """Restore one persistent wheelhouse to an empty state.

            Parameters
            ----------
            side : Literal['base', 'head']
                Wheelhouse side to empty.

            Raises
            ------
            ContainerError
                If the cache path is unsafe or cannot be reset.
            """
            house = houses[side]
            _validate_cache_directory(house)
            try:
                shutil.rmtree(house)
                house.mkdir()
            except OSError as error:
                msg = f'cannot reset the {side} container wheelhouse: {error}'
                raise ContainerError(msg) from error

        def base_wheelhouses() -> Sequence[Path]:
            """Fetch the base closure, then serve the base wheelhouse.

            Called only when the base side builds. Both houses are emptied
            first: which names each side owns depends on which sides were
            cached when they were last filled, so state persisted by an
            earlier run would otherwise collide with this fetch.

            Returns
            -------
            Sequence[Path]
                The base side's single wheelhouse.
            """
            reset_house('base')
            reset_house('head')
            self._fetch_into(repo, base_sha, base_house, find_links=None, exclude=frozenset())
            return (base_house,)

        def head_wheelhouses() -> Sequence[Path]:
            """Fetch the head extras, reusing base wheels read-only.

            The base fetch, when it runs at all, always precedes the head
            fetch (base ``_ensure`` runs first), so ``base_house`` already
            holds the shared closure the head fetch reuses and excludes; when
            the base side is cached, ``base_house`` is empty and the head
            fetch downloads its own full closure. The head house is emptied
            first so names a previous run promoted under a different base
            state cannot collide with ``base_house``.

            Returns
            -------
            Sequence[Path]
                The base wheelhouse followed by the head-extras wheelhouse.
            """
            reset_house('head')
            owned = frozenset(entry.name for entry in base_house.iterdir())
            self._fetch_into(repo, head_sha, head_house, find_links=base_house, exclude=owned)
            return (base_house, head_house)

        _validate_cache_directory(wheelhouse_root)
        wheelhouse_root.mkdir(parents=True, exist_ok=True)
        _validate_cache_directory(wheelhouse_root)
        with self._pair_lock(pair_dir):
            ripgrep_path: Path | None = None

            def fetch_ripgrep() -> Path:
                """Fetch the shared pinned runtime search binary once.

                Returns
                -------
                Path
                    Verified executable shared by both side builds.

                Raises
                ------
                ContainerError
                    If the tool cache cannot be reset or the fetch fails.
                """
                nonlocal ripgrep_path
                if ripgrep_path is None:
                    _validate_cache_directory(tool_dir)
                    try:
                        shutil.rmtree(tool_dir)
                        tool_dir.mkdir()
                    except OSError as error:
                        msg = f'cannot reset the container tool cache: {error}'
                        raise ContainerError(msg) from error
                    self._docker.prefetch_ripgrep(self._builder_image, ripgrep_artifact, tool_dir)
                    ripgrep_path = tool_dir / 'rg'
                    self._fetches.append(
                        FetchRecord(
                            kind='binary',
                            name=ripgrep_artifact.filename,
                            resolved=ripgrep_artifact.version,
                            digest=ripgrep_artifact.archive_digest,
                        )
                    )
                return ripgrep_path

            _validate_cache_directory(pair_dir)
            pair_dir.mkdir(exist_ok=True)
            _validate_cache_directory(pair_dir)
            for house in houses.values():
                _validate_cache_directory(house)
                house.mkdir(exist_ok=True)
                _validate_cache_directory(house)
            _validate_cache_directory(tool_dir)
            tool_dir.mkdir(exist_ok=True)
            _validate_cache_directory(tool_dir)
            base, head, delta = resolve_paired_delta(
                lambda force: self._ensure(
                    repo=repo,
                    ref=base_ref,
                    sha=base_sha,
                    fingerprint=base_fingerprint,
                    wheelhouses=base_wheelhouses,
                    ripgrep=fetch_ripgrep,
                    force_rebuild=force,
                ),
                lambda force: self._ensure(
                    repo=repo,
                    ref=head_ref,
                    sha=head_sha,
                    fingerprint=head_fingerprint,
                    wheelhouses=head_wheelhouses,
                    ripgrep=fetch_ripgrep,
                    force_rebuild=force,
                ),
                fresh=self._fresh,
                detector_distribution=adapter.distribution,
            )
            python_version = self._docker.python_version(base.image)
        work_root = Path(tempfile.mkdtemp(prefix='liveness-primer-run-'))
        base_work_root = work_root / 'base'
        head_work_root = work_root / 'head'
        base_work_root.mkdir()
        head_work_root.mkdir()
        active_containers: set[str] = set()
        completed = False
        try:
            yield PreparedContainerPair(
                base=base,
                head=head,
                environment_delta=delta,
                fetches=tuple(self._fetches),
                installer_identity=(
                    f'{docker_identity}; builder {self._builder_image}; runtime {self._runtime_image}; {ripgrep_id}'
                ),
                python_version=python_version,
                work_root=work_root,
                base_work_root=base_work_root,
                head_work_root=head_work_root,
                active_containers=active_containers,
            )
            completed = True
        finally:
            leftovers = [name for name in tuple(active_containers) if not self._docker.remove_container(name)]
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
    """Run each detector invocation in its own container (contract §3, §11).

    Attributes
    ----------
    work_roots : dict[str, Path]
        Host workspace root per side (``base``/``head``); each invocation
        mounts only its own side's root, so one side's untrusted code can
        never reach the other's workspaces.
    images : dict[str, str]
        Environment image tag per side.
    invocation_env : dict[str, str]
        Adapter-declared side-identical variables set on every invocation.
    docker : DockerRuntime
        Runtime used to confirm force-removal after every invocation.
    active_containers : set[str]
        Names registered before launch and discarded only after confirmed
        removal.
    isolation : Isolation
        The isolation this backend enforces, recorded in the manifest; the
        container runtime disables networking on every invocation.
    user : str | None
        ``uid:gid`` the detector runs as, or ``None`` for the image default.
    """

    work_roots: dict[str, Path]
    images: dict[str, str]
    invocation_env: dict[str, str]
    docker: DockerRuntime
    active_containers: set[str]
    isolation: Isolation = CONTAINER_ISOLATION
    user: str | None = None

    @property
    def workspace_parents(self) -> Mapping[str, Path]:
        """Report where side workspaces must be created.

        Returns
        -------
        Mapping[str, Path]
            Mounted workspace roots keyed by side.
        """
        return self.work_roots

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

    def _cleanup_container(self, container_name: str) -> None:
        """Force-remove one invocation container and confirm it is gone.

        Parameters
        ----------
        container_name : str
            Name registered for the invocation container.

        Raises
        ------
        ContainerError
            If the daemon cannot confirm removal.
        """
        if not self.docker.remove_container(container_name):
            msg = f'could not confirm removal of analysis container {container_name}'
            raise ContainerError(msg)
        self.active_containers.discard(container_name)

    def launch_plan(self, *, argv: Sequence[str], workspace: SideWorkspace) -> LaunchPlan:
        """Rewrite the detector argv into a named ``docker run`` (contract §3, §11).

        One container per invocation gives the host daemon an authoritative
        kill handle. If the outer timeout cancels the attached Docker client,
        ``cleanup`` force-removes this exact container before its writable
        workspace is deleted. The container receives only explicitly passed
        variables; the trusted Docker client keeps its host environment.

        Parameters
        ----------
        argv : Sequence[str]
            Composed detector argv.
        workspace : SideWorkspace
            The invocation's disposable workspace under the mounted root.

        Returns
        -------
        LaunchPlan
            The prepared attached container launch.

        Raises
        ------
        ContainerError
            If the invocation's unique container name is already active.
        """
        side = workspace.side
        container_name = f'{workspace.root.name}-{side}'
        if container_name in self.active_containers:
            msg = f'analysis container name is already active: {container_name}'
            raise ContainerError(msg)
        home = CONTAINER_WORK_ROOT / workspace.root.name / workspace.home.name
        plan = [
            self.docker.binary,
            'run',
            '--rm',
            '--init',
            '--network',
            'none',
            '--name',
            container_name,
            '--entrypoint',
            '',
            *_HARDENING_FLAGS,
            '--volume',
            f'{self.work_roots[side]}:{CONTAINER_WORK_ROOT}',
            '--workdir',
            str(self._container_side_root(workspace)),
        ]
        plan.extend(['--env', f'HOME={home}'])
        for name, value in self.invocation_env.items():
            plan.extend(['--env', f'{name}={value}'])
        if self.user is not None:
            plan.extend(['--user', self.user])
        plan.append(self.images[side])
        plan.extend(argv)
        self.active_containers.add(container_name)
        return LaunchPlan(
            argv=tuple(plan),
            cwd=None,
            env=None,
            cleanup=partial(self._cleanup_container, container_name),
        )

    def analysis_root(self, workspace: SideWorkspace) -> PurePosixPath:
        """Report the checkout root as the detector sees it.

        A pure POSIX path, never a native host path: coercing it into a
        host ``Path`` would lose absoluteness on Windows and break the
        normalization of detector-reported paths (contract §7).

        Parameters
        ----------
        workspace : SideWorkspace
            The invocation's disposable workspace.

        Returns
        -------
        PurePosixPath
            The container-side checkout path, used to normalize
            detector-reported absolute paths (contract §7).
        """
        return self._container_side_root(workspace)
