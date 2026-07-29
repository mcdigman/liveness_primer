"""Network isolation for build- and analysis-step subprocesses (contract §11).

Copyright (C) 2026 Matthew C. Digman

Networking is disabled via Linux network namespaces, enforced on the Linux
reference platform and best-effort elsewhere. ``--no-index`` alone is not
isolation; the namespace is the guarantee. The manifest records whether
isolation was enforced, and reports flag unenforced runs.
"""

import sys
from collections.abc import Sequence
from dataclasses import dataclass

from liveness_primer.launcher import SyncLauncher, run_sync, validate_sync_launcher

_PROBE_TIMEOUT = 30.0

# Candidate unshare invocations, most faithful first: mapping the current
# user keeps uid-dependent build steps working; the unmapped variant still
# cuts networking on older util-linux.
_CANDIDATES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ('netns:unshare-map-current-user', ('unshare', '--user', '--net', '--map-current-user')),
    ('netns:unshare', ('unshare', '--user', '--net')),
)


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


def detect_isolation(*, platform_name: str = sys.platform, launcher: SyncLauncher = run_sync) -> Isolation:
    """Probe for an enforceable network-isolation strategy (contract §11).

    On Linux, rootless ``unshare`` variants are probed in order; elsewhere
    isolation is best-effort and unenforced.

    Parameters
    ----------
    platform_name : str
        Platform to decide for; injectable for tests (contract §15).
    launcher : SyncLauncher
        Audited launcher used for the probes; injectable for tests.

    Returns
    -------
    Isolation
        The first working strategy, or :data:`UNENFORCED`.
    """
    validate_sync_launcher(launcher)
    if platform_name != 'linux':
        return UNENFORCED
    for description, prefix in _CANDIDATES:
        probe = launcher([*prefix, 'true'], timeout=_PROBE_TIMEOUT)
        if probe.ok:
            return Isolation(enforced=True, description=description, prefix=prefix)
    return UNENFORCED
