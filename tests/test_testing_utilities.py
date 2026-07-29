"""Tests for the shipped fake detector and fake project factory (contract §15).

Copyright (C) 2026 Matthew C. Digman
"""

import json
import time
from pathlib import Path
from typing import cast

import pytest

from liveness_primer.launcher import LauncherError, SyncLauncher, run_async, run_sync
from liveness_primer.testing import FakeFinding, create_fake_project, write_fake_detector_script
from liveness_primer.testing.fake_detector import main
from liveness_primer.testing.fake_project import DEFAULT_FILES, FakeProjectError


def test_fake_finding_report_line_matches_vulture_format() -> None:
    finding = FakeFinding(path='pkg/mod.py', line=5, symbol='helper', kind='function', confidence=72)
    assert finding.report_line() == "pkg/mod.py:5: unused function 'helper' (72% confidence)"


def test_main_emits_scripted_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    command = write_fake_detector_script(
        tmp_path / 'script.json',
        [FakeFinding(path='a.py', line=1, symbol='x')],
        stderr='warning: something',
        raw_lines=['extra raw line'],
    )
    exit_code = main([*command[3:], '.'])
    captured = capsys.readouterr()
    assert exit_code == 3
    assert "a.py:1: unused function 'x' (60% confidence)" in captured.out
    assert 'extra raw line' in captured.out
    assert captured.err == 'warning: something'


def test_main_clean_script_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    command = write_fake_detector_script(tmp_path / 'script.json', [])
    assert main(command[3:]) == 0
    assert not capsys.readouterr().out


def test_main_exit_code_override(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    command = write_fake_detector_script(tmp_path / 'script.json', [], exit_code=7)
    assert main(command[3:]) == 7
    del capsys


def test_main_sleeps_when_scripted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    command = write_fake_detector_script(tmp_path / 'script.json', [], sleep_seconds=0.05)
    start = time.monotonic()
    assert main(command[3:]) == 0
    assert time.monotonic() - start >= 0.05
    del capsys


def test_main_without_arguments_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert 'usage' in capsys.readouterr().err


def test_command_runs_as_a_real_subprocess_from_any_cwd(tmp_path: Path) -> None:
    command = write_fake_detector_script(tmp_path / 'script.json', [FakeFinding(path='a.py', line=1, symbol='x')])
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()
    result = run_sync([*command, '.'], cwd=elsewhere)
    assert result.returncode == 3
    assert "unused function 'x'" in result.stdout


def test_script_file_is_valid_json(tmp_path: Path) -> None:
    write_fake_detector_script(tmp_path / 'script.json', [FakeFinding(path='a.py', line=1, symbol='x')])
    document = json.loads((tmp_path / 'script.json').read_text(encoding='utf-8'))
    assert document['findings'][0]['symbol'] == 'x'


def test_create_fake_project_without_git(tmp_path: Path) -> None:
    project = create_fake_project(tmp_path / 'proj')
    assert project.head_sha is None
    assert project.url.startswith('file://')
    for relative in DEFAULT_FILES:
        assert (project.path / relative).exists()


def test_create_fake_project_rejects_async_launcher(tmp_path: Path) -> None:
    with pytest.raises(LauncherError, match='launcher must be synchronous'):
        create_fake_project(tmp_path / 'proj', launcher=cast('SyncLauncher', run_async))


def test_create_fake_project_with_custom_files(tmp_path: Path) -> None:
    project = create_fake_project(tmp_path / 'proj', files={'only.py': 'X = 1\n'})
    assert (project.path / 'only.py').read_text(encoding='utf-8') == 'X = 1\n'
    assert not (project.path / 'pkg').exists()


def test_create_fake_project_with_git(tmp_path: Path) -> None:
    project = create_fake_project(tmp_path / 'proj', init_git=True)
    assert project.head_sha is not None
    assert len(project.head_sha) == 40


def test_create_fake_project_git_failure(tmp_path: Path) -> None:
    blocker = tmp_path / 'proj' / '.git'
    blocker.parent.mkdir(parents=True)
    blocker.write_text('not a directory', encoding='utf-8')
    with pytest.raises(FakeProjectError, match='failed while building a fake project'):
        create_fake_project(tmp_path / 'proj', init_git=True)
