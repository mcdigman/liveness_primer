"""The audited subprocess launcher: the only module allowed to launch subprocesses.

Copyright (C) 2026 Matthew C. Digman

Contract §11: every subprocess launch goes through this module, which accepts
only typed argv lists and exposes no shell parameter. Raw subprocess APIs are
banned everywhere else via ``TID251`` in ``ruff.toml``, backstopped by the
AST-walking test required by contract §15.
"""

import asyncio
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from liveness_primer.errors import LivenessPrimerError


class LauncherError(LivenessPrimerError):
    """Raised when an argv list is structurally invalid."""


def _validated_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Validate an argv list, rejecting shell strings and non-string elements.

    Parameters
    ----------
    argv : Sequence[str]
        Command and arguments as a typed list.

    Returns
    -------
    tuple[str, ...]
        The validated argv tuple.

    Raises
    ------
    LauncherError
        If ``argv`` is a bare string, empty, contains a non-string element,
        or its first element is empty.
    """
    if isinstance(argv, str):
        msg = 'argv must be a sequence of arguments, not a shell string'
        raise LauncherError(msg)
    checked = tuple(argv)
    if not checked:
        msg = 'argv must not be empty'
        raise LauncherError(msg)
    for element in checked:
        if not isinstance(element, str):  # pyright: ignore[reportUnnecessaryIsInstance]
            msg = f'argv elements must be str, got {type(element).__name__}'
            raise LauncherError(msg)
    if not checked[0]:
        msg = 'argv[0] must not be empty'
        raise LauncherError(msg)
    return checked


@dataclass(frozen=True, slots=True)
class LaunchResult:
    """Outcome of one subprocess launch.

    Attributes
    ----------
    argv : tuple[str, ...]
        The validated argv that was launched.
    returncode : int | None
        Process exit code; ``None`` when the launch timed out.
    stdout : str
        Captured standard output, decoded UTF-8 with replacement.
    stderr : str
        Captured standard error, decoded UTF-8 with replacement.
    duration_seconds : float
        Wall-clock duration of the launch.
    timed_out : bool
        Whether the process was killed on timeout.
    """

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool

    @property
    def ok(self) -> bool:
        """Whether the process exited zero without timing out.

        Returns
        -------
        bool
            True when ``returncode`` is 0 and the launch did not time out.
        """
        return not self.timed_out and self.returncode == 0


class SyncLauncher(Protocol):
    """Injectable synchronous launcher signature (contract §15)."""

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        """Launch ``argv`` and capture its output.

        Parameters
        ----------
        argv : Sequence[str]
            Command and arguments as a typed list.
        cwd : Path | None
            Working directory for the child process.
        env : Mapping[str, str] | None
            Environment for the child; inherited when ``None``.
        timeout : float | None
            Seconds before the child is killed.

        Returns
        -------
        LaunchResult
            The captured outcome.
        """
        ...


class AsyncLauncher(Protocol):
    """Injectable asynchronous launcher signature (contract §15).

    Timeouts are the caller's concern: wrap calls in :func:`asyncio.timeout`;
    implementations kill the child process on cancellation.
    """

    async def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        """Launch ``argv`` and capture its output without blocking the loop.

        Parameters
        ----------
        argv : Sequence[str]
            Command and arguments as a typed list.
        cwd : Path | None
            Working directory for the child process.
        env : Mapping[str, str] | None
            Environment for the child; inherited when ``None``.

        Returns
        -------
        LaunchResult
            The captured outcome.
        """
        ...


def _spawn_failure(argv: tuple[str, ...], exc: OSError, start: float) -> LaunchResult:
    """Build the result for a launch that failed to spawn at all.

    Parameters
    ----------
    argv : tuple[str, ...]
        The validated argv that failed to spawn.
    exc : OSError
        The spawn error (missing binary, permissions, ...).
    start : float
        Monotonic start time of the attempt.

    Returns
    -------
    LaunchResult
        A conventional command-not-found result (exit code 127).
    """
    return LaunchResult(
        argv=argv,
        returncode=127,
        stdout='',
        stderr=str(exc),
        duration_seconds=time.monotonic() - start,
        timed_out=False,
    )


def _decode(data: bytes) -> str:
    """Decode captured process output, tolerating untrusted bytes.

    Parameters
    ----------
    data : bytes
        Raw captured bytes.

    Returns
    -------
    str
        UTF-8 text with undecodable bytes replaced.
    """
    return data.decode('utf-8', errors='replace')


def run_sync(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
) -> LaunchResult:
    """Launch a subprocess synchronously and capture its output.

    Parameters
    ----------
    argv : Sequence[str]
        Command and arguments as a typed list; never a shell string.
    cwd : Path | None
        Working directory for the child process.
    env : Mapping[str, str] | None
        Environment for the child; inherited when ``None``.
    timeout : float | None
        Seconds before the child is killed and the result marked timed out.

    Returns
    -------
    LaunchResult
        The captured outcome.
    """
    checked = _validated_argv(argv)
    start = time.monotonic()
    try:
        completed = subprocess.run(
            checked,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except OSError as exc:
        return _spawn_failure(checked, exc, start)
    except subprocess.TimeoutExpired as exc:
        return LaunchResult(
            argv=checked,
            returncode=None,
            stdout=_decode(exc.stdout or b''),
            stderr=_decode(exc.stderr or b''),
            duration_seconds=time.monotonic() - start,
            timed_out=True,
        )
    return LaunchResult(
        argv=checked,
        returncode=completed.returncode,
        stdout=_decode(completed.stdout),
        stderr=_decode(completed.stderr),
        duration_seconds=time.monotonic() - start,
        timed_out=False,
    )


async def run_async(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> LaunchResult:
    """Launch a subprocess from the event loop and capture its output.

    Cancellation-safe: if the surrounding task is cancelled (e.g. by an
    :func:`asyncio.timeout` scope), the child process is killed and reaped
    before the cancellation propagates.

    Parameters
    ----------
    argv : Sequence[str]
        Command and arguments as a typed list; never a shell string.
    cwd : Path | None
        Working directory for the child process.
    env : Mapping[str, str] | None
        Environment for the child; inherited when ``None``.

    Returns
    -------
    LaunchResult
        The captured outcome.

    Raises
    ------
    asyncio.CancelledError
        Re-raised after killing the child when the surrounding task is
        cancelled.
    """
    checked = _validated_argv(argv)
    start = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *checked,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return _spawn_failure(checked, exc, start)
    try:
        stdout_bytes, stderr_bytes = await process.communicate()
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise
    return LaunchResult(
        argv=checked,
        returncode=process.returncode,
        stdout=_decode(stdout_bytes),
        stderr=_decode(stderr_bytes),
        duration_seconds=time.monotonic() - start,
        timed_out=False,
    )
