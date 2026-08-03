"""Network isolation for build- and analysis-step subprocesses (contract §11).

Copyright (C) 2026 Matthew C. Digman

Networking is disabled via Linux network namespaces, enforced on the Linux
reference platform and best-effort elsewhere. ``--no-index`` alone is not
isolation; the namespace is the guarantee. The manifest records whether
isolation was enforced, and reports flag unenforced runs. Sandboxed
subprocesses additionally run with a minimal allowlisted environment so no
credentials reach untrusted code (contract §3).
"""

import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from liveness_primer.errors import LivenessPrimerError
from liveness_primer.launcher import SyncLauncher, run_sync, validate_sync_launcher

_PROBE_TIMEOUT = 30.0

# Candidate unshare invocations, most faithful first: mapping the current
# user keeps uid-dependent build steps working; the unmapped variant still
# cuts networking on older util-linux.
_CANDIDATES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ('netns:unshare-map-current-user', ('unshare', '--user', '--net', '--map-current-user')),
    ('netns:unshare', ('unshare', '--user', '--net')),
)

# Runs inside the candidate namespace and confirms networking is actually
# severed: a fresh network namespace exposes at most a loopback interface.
_VERIFY_SNIPPET = (
    'import socket, sys; names = {name for _, name in socket.if_nameindex()}; sys.exit(0 if names <= {"lo"} else 1)'
)

# Environment variables allowed through to sandboxed subprocesses. The §3
# trust model requires untrusted detector code to run with no credentials:
# everything not allowlisted (tokens, cloud credentials, CI secrets) is
# dropped, and HOME is redirected to a scratch directory.
_ENV_ALLOWLIST = (
    'COLUMNS',
    'COMSPEC',
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
    'PATH',
    'PATHEXT',
    'SYSTEMROOT',
    'TERM',
    'TMP',
    'TMPDIR',
    'TZ',
)


class IsolationError(LivenessPrimerError):
    """Raised when required network isolation cannot be established."""


@dataclass(frozen=True, slots=True)
class Isolation:
    """A network-isolation strategy wrapping sandboxed subprocess launches.

    Attributes
    ----------
    enforced : bool
        Whether networking is actually disabled; recorded in the manifest.
    description : str
        Human-readable strategy name (e.g. ``netns:unshare``, ``none``).
    prefix : tuple[str, ...]
        Argv prefix prepended to every sandboxed command.
    """

    enforced: bool
    description: str
    prefix: tuple[str, ...]

    def wrap(self, argv: Sequence[str]) -> list[str]:
        """Wrap a sandboxed command in the isolation prefix.

        Parameters
        ----------
        argv : Sequence[str]
            The command to sandbox.

        Returns
        -------
        list[str]
            The prefixed argv.
        """
        return [*self.prefix, *argv]


UNENFORCED = Isolation(enforced=False, description='none', prefix=())


def scrubbed_environment(*, home: Path, source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the minimal allowlisted environment for sandboxed subprocesses (contract §3).

    Untrusted detector code must see no credentials: only the allowlisted
    variables survive, and ``HOME`` points at the given scratch directory.

    Parameters
    ----------
    home : Path
        Scratch directory to expose as ``HOME``.
    source : Mapping[str, str] | None
        Environment to filter; ``os.environ`` when ``None``.

    Returns
    -------
    dict[str, str]
        The scrubbed environment.
    """
    base = os.environ if source is None else source
    scrubbed = {name: base[name] for name in _ENV_ALLOWLIST if name in base}
    scrubbed['HOME'] = str(home)
    return scrubbed


def detect_isolation(
    *,
    platform_name: str = sys.platform,
    launcher: SyncLauncher = run_sync,
    python_executable: str = sys.executable,
) -> Isolation:
    """Probe for an enforceable network-isolation strategy (contract §11).

    On Linux, rootless ``unshare`` variants are probed in order; a candidate
    counts as working only when a probe process inside the namespace confirms
    that no non-loopback interface is visible. Elsewhere isolation is
    best-effort and unenforced.

    Parameters
    ----------
    platform_name : str
        Platform to decide for; injectable for tests (contract §15).
    launcher : SyncLauncher
        Audited launcher used for the probes; injectable for tests.
    python_executable : str
        Interpreter used for the in-namespace verification probe.

    Returns
    -------
    Isolation
        The first verified strategy, or :data:`UNENFORCED`.
    """
    validate_sync_launcher(launcher)
    if platform_name != 'linux':
        return UNENFORCED
    for description, prefix in _CANDIDATES:
        probe = launcher([*prefix, 'true'], timeout=_PROBE_TIMEOUT)
        if not probe.ok:
            continue
        verified = launcher([*prefix, python_executable, '-c', _VERIFY_SNIPPET], timeout=_PROBE_TIMEOUT)
        if verified.ok:
            return Isolation(enforced=True, description=description, prefix=prefix)
    return UNENFORCED


def require_isolation(
    *,
    platform_name: str = sys.platform,
    launcher: SyncLauncher = run_sync,
    python_executable: str = sys.executable,
) -> Isolation:
    """Detect isolation, failing closed on the Linux reference platform (contract §11, §19.1).

    Managed runs execute untrusted detector refs; on Linux (and therefore in
    CI) they must not proceed without an enforced network sandbox. Other
    platforms remain best-effort, recorded and flagged by the report.

    Parameters
    ----------
    platform_name : str
        Platform to decide for; injectable for tests (contract §15).
    launcher : SyncLauncher
        Audited launcher used for the probes; injectable for tests.
    python_executable : str
        Interpreter used for the in-namespace verification probe.

    Returns
    -------
    Isolation
        The verified strategy, or :data:`UNENFORCED` off Linux.

    Raises
    ------
    IsolationError
        If the platform is Linux and no strategy probes clean.
    """
    isolation = detect_isolation(
        platform_name=platform_name,
        launcher=launcher,
        python_executable=python_executable,
    )
    if platform_name == 'linux' and not isolation.enforced:
        msg = (
            'network isolation is required on Linux but no rootless unshare '
            'strategy works here; refusing to execute untrusted detector code. '
            'Pre-built trusted commands via --old-cmd/--new-cmd '
            'remain available.'
        )
        raise IsolationError(msg)
    return isolation
