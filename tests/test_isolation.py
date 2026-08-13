# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for network-isolation detection, enforcement, and env scrubbing (contract §3, §11, §15)."""

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from liveness_primer.isolation import (
    UNENFORCED,
    Isolation,
    IsolationError,
    detect_isolation,
    require_isolation,
    scrubbed_environment,
)
from liveness_primer.launcher import LauncherError, LaunchResult, SyncLauncher, run_async, run_sync

MAPPED = ('unshare', '--user', '--net', '--map-current-user')
UNMAPPED = ('unshare', '--user', '--net')


@dataclass
class ScriptedLauncher:
    """Launcher stub approving exactly the argvs listed in ``succeeding``.

    An entry ending in ``...`` approves any argv extending its prefix, which
    matches the interpreter-based verification probe without duplicating its
    snippet here.
    """

    succeeding: tuple[tuple[str, ...], ...]
    refusing_flags: tuple[str, ...] = ()
    seen: list[tuple[str, ...]] | None = None

    def _approves(self, argv: tuple[str, ...]) -> bool:
        """Check the scripted approvals against one argv.

        Returns
        -------
        bool
            Whether the argv is approved.
        """
        if any(flag in argv for flag in self.refusing_flags):
            return False
        for entry in self.succeeding:
            if entry and entry[-1] == '...':
                if argv[: len(entry) - 1] == entry[:-1]:
                    return True
            elif argv == entry:
                return True
        return False

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
        checked = tuple(argv)
        if self.seen is not None:
            self.seen.append(checked)
        code = 0 if self._approves(checked) else 127
        return LaunchResult(
            argv=checked,
            returncode=code,
            stdout='',
            stderr='' if code == 0 else 'probe refused',
            duration_seconds=0.0,
            timed_out=False,
        )


def approving(*prefixes: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    return tuple((*prefix, '...') for prefix in prefixes)


def test_non_linux_platforms_are_unenforced() -> None:
    isolation = detect_isolation(platform_name='darwin')
    assert isolation is UNENFORCED
    assert not isolation.enforced
    assert isolation.wrap(['detector', '.']) == ['detector', '.']


def test_detect_isolation_rejects_async_launcher() -> None:
    with pytest.raises(LauncherError, match='launcher must be synchronous'):
        detect_isolation(platform_name='darwin', launcher=cast('SyncLauncher', run_async))


def test_linux_prefers_the_mapped_unshare_variant() -> None:
    launcher = ScriptedLauncher(succeeding=approving(MAPPED))
    isolation = detect_isolation(platform_name='linux', launcher=launcher)
    assert isolation.enforced
    assert isolation.description == 'netns:unshare-map-current-user'
    assert isolation.wrap(['detector', '.'])[:4] == list(MAPPED)


def test_linux_falls_back_to_unmapped_unshare() -> None:
    seen: list[tuple[str, ...]] = []
    launcher = ScriptedLauncher(succeeding=approving(UNMAPPED), refusing_flags=('--map-current-user',), seen=seen)
    isolation = detect_isolation(platform_name='linux', launcher=launcher)
    assert isolation.enforced
    assert isolation.description == 'netns:unshare'
    assert isolation.prefix == UNMAPPED
    # The mapped candidate probes once and fails; the unmapped candidate
    # probes and then verifies inside the namespace.
    assert len(seen) == 3


def test_verification_probes_run_the_interpreter_inside_the_namespace() -> None:
    seen: list[tuple[str, ...]] = []
    launcher = ScriptedLauncher(succeeding=approving(MAPPED), seen=seen)
    detect_isolation(platform_name='linux', launcher=launcher, python_executable='/opt/py')
    binary_probe, verification = seen
    assert binary_probe == (*MAPPED, 'true')
    assert verification[: len(MAPPED) + 1] == (*MAPPED, '/opt/py')
    assert verification[len(MAPPED) + 1] == '-c'
    assert 'if_nameindex' in verification[-1]


def test_unverified_namespace_is_not_trusted() -> None:
    # `unshare ... true` succeeds but the in-namespace verification still
    # sees non-loopback interfaces: the candidate must be rejected.
    launcher = ScriptedLauncher(succeeding=((*MAPPED, 'true'), (*UNMAPPED, 'true')))
    isolation = detect_isolation(platform_name='linux', launcher=launcher)
    assert isolation == UNENFORCED


def test_linux_without_working_unshare_detects_unenforced() -> None:
    launcher = ScriptedLauncher(succeeding=())
    isolation = detect_isolation(platform_name='linux', launcher=launcher)
    assert isolation == UNENFORCED


def test_require_isolation_fails_closed_on_linux() -> None:
    launcher = ScriptedLauncher(succeeding=())
    with pytest.raises(IsolationError, match='refusing to execute untrusted detector code'):
        require_isolation(platform_name='linux', launcher=launcher)


def test_require_isolation_returns_verified_linux_strategy() -> None:
    launcher = ScriptedLauncher(succeeding=approving(MAPPED))
    isolation = require_isolation(platform_name='linux', launcher=launcher)
    assert isolation.enforced


def test_require_isolation_is_best_effort_off_linux() -> None:
    isolation = require_isolation(platform_name='darwin', launcher=ScriptedLauncher(succeeding=()))
    assert isolation is UNENFORCED


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


def test_scrubbed_environment_drops_credentials(tmp_path: Path) -> None:
    source = {
        'PATH': '/usr/bin',
        'LANG': 'C.UTF-8',
        'HOME': '/real/home',
        'GITHUB_TOKEN': 'secret',
        'AWS_SECRET_ACCESS_KEY': 'secret',
        'CI': 'true',
    }
    scrubbed = scrubbed_environment(home=tmp_path, source=source)
    assert scrubbed == {'PATH': '/usr/bin', 'LANG': 'C.UTF-8', 'HOME': str(tmp_path)}


def test_scrubbed_environment_defaults_to_the_process_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv('LP_PLANTED_SECRET', 'boom')
    monkeypatch.setenv('TERM', 'xterm')
    scrubbed = scrubbed_environment(home=tmp_path / 'home')
    assert 'LP_PLANTED_SECRET' not in scrubbed
    assert scrubbed['TERM'] == 'xterm'
    assert scrubbed['HOME'] == str(tmp_path / 'home')
