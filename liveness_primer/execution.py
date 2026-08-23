# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Execution backends: where and how one detector invocation runs (contract §3, §11).

The runner materializes a disposable per-invocation workspace and asks a
backend to turn the composed detector argv into a concrete launch: the host
backend wraps it in the §11 network sandbox with a scrubbed environment,
while the container backend rewrites it into a ``docker exec`` against a
side's ephemeral container. Backends are injectable, so isolation logic is
testable without real sandboxes or containers (contract §15).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from liveness_primer.isolation import Isolation, scrubbed_environment


@dataclass(frozen=True, slots=True)
class SideWorkspace:
    """Disposable per-invocation workspace (contract §3, §11).

    Attributes
    ----------
    root : Path
        Workspace directory removed after the invocation.
    checkout : Path
        This side's own copy of the pinned checkout.
    home : Path
        Scratch ``HOME`` exposed to the detector.
    """

    root: Path
    checkout: Path
    home: Path


@dataclass(frozen=True, slots=True)
class LaunchPlan:
    """One concrete detector launch a backend prepared.

    Attributes
    ----------
    argv : tuple[str, ...]
        Full argv handed to the audited launcher.
    cwd : Path | None
        Working directory of the launched process.
    env : Mapping[str, str] | None
        Environment of the launched process; inherited when ``None``.
    """

    argv: tuple[str, ...]
    cwd: Path | None
    env: Mapping[str, str] | None


@runtime_checkable
class ExecutionBackend(Protocol):
    """Injectable strategy deciding where detector invocations run (contract §15).

    ``workspace_parent`` names the directory side workspaces must be
    created under, when the backend can only reach a specific host location
    (e.g. a container mount); ``None`` lets the runner use the default
    temporary directory.
    """

    @property
    def workspace_parent(self) -> Path | None:
        """Report where side workspaces must be created.

        Returns
        -------
        Path | None
            The required parent directory, or ``None`` for the default.
        """
        ...

    def launch_plan(self, *, side: str, argv: Sequence[str], workspace: SideWorkspace) -> LaunchPlan:
        """Turn a composed detector argv into a concrete launch.

        Parameters
        ----------
        side : str
            ``base`` or ``head``.
        argv : Sequence[str]
            Composed detector argv (contract §4).
        workspace : SideWorkspace
            The invocation's disposable workspace.

        Returns
        -------
        LaunchPlan
            The prepared launch.
        """
        ...

    def analysis_root(self, workspace: SideWorkspace) -> Path:
        """Report the checkout root as the detector sees it.

        Parameters
        ----------
        workspace : SideWorkspace
            The invocation's disposable workspace.

        Returns
        -------
        Path
            Root used to normalize detector-reported paths (contract §7).
        """
        ...


@dataclass(frozen=True, slots=True)
class HostExecution:
    """Run detector invocations on the host under the §11 sandbox.

    Attributes
    ----------
    isolation : Isolation
        Network isolation wrapped around every invocation (contract §11).
    invocation_env : Mapping[str, str]
        Adapter-declared side-identical variables layered over the scrub.
    passthrough_env : Mapping[str, str]
        Admitted native helper variables layered last (contract §3).
    """

    isolation: Isolation
    invocation_env: Mapping[str, str]
    passthrough_env: Mapping[str, str]

    @property
    def workspace_parent(self) -> Path | None:
        """Report where side workspaces must be created.

        Returns
        -------
        Path | None
            Always ``None``: the default temporary directory works.
        """
        return None

    def launch_plan(self, *, side: str, argv: Sequence[str], workspace: SideWorkspace) -> LaunchPlan:
        """Wrap the argv in the sandbox with a scrubbed environment (contract §3, §11).

        Parameters
        ----------
        side : str
            ``base`` or ``head``; both sides launch identically.
        argv : Sequence[str]
            Composed detector argv.
        workspace : SideWorkspace
            The invocation's disposable workspace.

        Returns
        -------
        LaunchPlan
            The sandboxed launch.
        """
        del side
        environment = scrubbed_environment(home=workspace.home)
        environment.update(self.invocation_env)
        environment.update(self.passthrough_env)
        return LaunchPlan(argv=tuple(self.isolation.wrap(list(argv))), cwd=workspace.checkout, env=environment)

    @staticmethod
    def analysis_root(workspace: SideWorkspace) -> Path:
        """Report the checkout root as the detector sees it.

        Parameters
        ----------
        workspace : SideWorkspace
            The invocation's disposable workspace.

        Returns
        -------
        Path
            The host-side workspace checkout.
        """
        return workspace.checkout
