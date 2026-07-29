"""Tests for the audited subprocess launcher (contract §11).

Copyright (C) 2026 Matthew C. Digman
"""

import asyncio
import sys
import time
from pathlib import Path
from typing import cast

import pytest

from liveness_primer.launcher import LauncherError, LaunchResult, run_async, run_sync


def test_rejects_shell_string() -> None:
    with pytest.raises(LauncherError, match='shell string'):
        run_sync('echo hi')


def test_rejects_empty_argv() -> None:
    with pytest.raises(LauncherError, match='must not be empty'):
        run_sync([])


def test_rejects_non_string_element() -> None:
    with pytest.raises(LauncherError, match='elements must be str'):
        run_sync(cast('list[str]', [sys.executable, 7]))


def test_rejects_empty_program_name() -> None:
    with pytest.raises(LauncherError, match=r'argv\[0\]'):
        run_sync(['', 'x'])


def test_sync_captures_output_and_exit_code(tmp_path: Path) -> None:
    result = run_sync(
        [sys.executable, '-c', 'import sys, os; print(os.getcwd()); print("boo", file=sys.stderr); sys.exit(4)'],
        cwd=tmp_path,
    )
    assert result.returncode == 4
    assert not result.ok
    assert not result.timed_out
    assert Path(result.stdout.strip()).resolve() == tmp_path.resolve()
    assert result.stderr.strip() == 'boo'
    assert result.duration_seconds >= 0.0


def test_sync_success_is_ok() -> None:
    result = run_sync([sys.executable, '-c', 'print("hi")'])
    assert result.ok
    assert result.stdout.strip() == 'hi'
    assert result.argv[0] == sys.executable


def test_sync_passes_environment() -> None:
    result = run_sync(
        [sys.executable, '-c', 'import os; print(os.environ["LP_PROBE"]); print(len(os.environ))'],
        env={'LP_PROBE': 'value'},
    )
    assert result.stdout.splitlines()[0] == 'value'


def test_sync_tolerates_undecodable_output() -> None:
    result = run_sync([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"\\xff\\xfeok")'])
    assert result.ok
    assert 'ok' in result.stdout


def test_sync_timeout_kills_and_reports() -> None:
    start = time.monotonic()
    result = run_sync([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=0.5)
    assert result.timed_out
    assert result.returncode is None
    assert not result.ok
    assert time.monotonic() - start < 25.0


def test_async_captures_output() -> None:
    async def scenario() -> LaunchResult:
        return await run_async([sys.executable, '-c', 'import sys; print("out"); print("err", file=sys.stderr)'])

    result = asyncio.run(scenario())
    assert result.ok
    assert result.stdout.strip() == 'out'
    assert result.stderr.strip() == 'err'


def test_async_reports_exit_code_cwd_and_env(tmp_path: Path) -> None:
    async def scenario() -> LaunchResult:
        return await run_async(
            [sys.executable, '-c', 'import os, sys; print(os.getcwd()); print(os.environ["LP_A"]); sys.exit(3)'],
            cwd=tmp_path,
            env={'LP_A': 'async-env'},
        )

    result = asyncio.run(scenario())
    assert result.returncode == 3
    lines = result.stdout.splitlines()
    assert Path(lines[0]).resolve() == tmp_path.resolve()
    assert lines[1] == 'async-env'


def test_async_rejects_shell_string() -> None:
    async def scenario() -> LaunchResult:
        return await run_async('echo hi')

    with pytest.raises(LauncherError, match='shell string'):
        asyncio.run(scenario())


def test_async_missing_binary_yields_command_not_found() -> None:
    async def scenario() -> LaunchResult:
        return await run_async(['/definitely/not/a/real/binary'])

    result = asyncio.run(scenario())
    assert result.returncode == 127
    assert not result.ok
    assert result.stderr


def test_async_cancellation_kills_child() -> None:
    async def scenario() -> None:
        async with asyncio.timeout(0.5):
            await run_async([sys.executable, '-c', 'import time; time.sleep(30)'])

    start = time.monotonic()
    with pytest.raises(TimeoutError):
        asyncio.run(scenario())
    assert time.monotonic() - start < 25.0
