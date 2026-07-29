"""Tests for network-isolation detection and wrapping (contract §11, §15).

Copyright (C) 2026 Matthew C. Digman
"""

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from liveness_primer.isolation import UNENFORCED, Isolation, detect_isolation
from liveness_primer.launcher import LaunchResult, run_sync


@dataclass
class ScriptedLauncher:
    """Launcher stub approving exactly the argvs listed in ``succeeding``."""

    succeeding: tuple[tuple[str, ...], ...]
    seen: list[tuple[str, ...]] | None = None

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        """Return success only for scripted argvs.

        Returns
        -------
        LaunchResult
            A zero-exit result when scripted, 127 otherwise.
        """
        del cwd, env, timeout
        if self.seen is not None:
            self.seen.append(tuple(argv))
        code = 0 if tuple(argv) in self.succeeding else 127
        return LaunchResult(
            argv=tuple(argv),
            returncode=code,
            stdout='',
            stderr='' if code == 0 else 'probe refused',
            duration_seconds=0.0,
            timed_out=False,
        )


def test_non_linux_platforms_are_unenforced() -> None:
    isolation = detect_isolation(platform_name='darwin')
    assert isolation is UNENFORCED
    assert not isolation.enforced
    assert isolation.wrap(['detector', '.']) == ['detector', '.']


def test_linux_prefers_the_mapped_unshare_variant() -> None:
    launcher = ScriptedLauncher(succeeding=(('unshare', '--user', '--net', '--map-current-user', 'true'),))
    isolation = detect_isolation(platform_name='linux', launcher=launcher)
    assert isolation.enforced
    assert isolation.description == 'netns:unshare-map-current-user'
    assert isolation.wrap(['detector', '.'])[:4] == ['unshare', '--user', '--net', '--map-current-user']


def test_linux_falls_back_to_unmapped_unshare() -> None:
    seen: list[tuple[str, ...]] = []
    launcher = ScriptedLauncher(succeeding=(('unshare', '--user', '--net', 'true'),), seen=seen)
    isolation = detect_isolation(platform_name='linux', launcher=launcher)
    assert isolation.enforced
    assert isolation.description == 'netns:unshare'
    assert isolation.prefix == ('unshare', '--user', '--net')
    assert len(seen) == 2


def test_linux_without_working_unshare_is_unenforced() -> None:
    launcher = ScriptedLauncher(succeeding=())
    isolation = detect_isolation(platform_name='linux', launcher=launcher)
    assert isolation == UNENFORCED


def test_default_platform_probe_is_safe_to_run() -> None:
    isolation = detect_isolation()
    if sys.platform != 'linux':
        assert isolation is UNENFORCED
    assert isinstance(isolation, Isolation)


def test_missing_probe_binary_yields_command_not_found() -> None:
    result = run_sync(['/definitely/not/a/real/binary'])
    assert result.returncode == 127
    assert not result.ok
    assert result.stderr
