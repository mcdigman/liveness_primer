"""Tests for the shipped fake detector and fake project factory (contract §15).

Copyright (C) 2026 Matthew C. Digman
"""

import json
import stat
import time
from pathlib import Path
from typing import cast

import pytest

from liveness_primer.filesystem import (
    FilesystemPolicyError,
    atomic_write_bytes,
    atomic_write_text,
    contained_path,
    read_small_text,
)
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


def test_create_fake_project_rejects_traversal(tmp_path: Path) -> None:
    outside = tmp_path / 'escape.py'
    with pytest.raises(FakeProjectError, match='without traversal'):
        create_fake_project(tmp_path / 'proj', files={'../escape.py': 'escaped\n'})
    assert not outside.exists()


def test_create_fake_project_rejects_symlink_parent_escape(tmp_path: Path) -> None:
    project = tmp_path / 'proj'
    project.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (project / 'linked').symlink_to(outside, target_is_directory=True)
    with pytest.raises(FakeProjectError, match='escapes its root'):
        create_fake_project(project, files={'linked/escape.py': 'escaped\n'})
    assert not (outside / 'escape.py').exists()


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


def test_contained_path_accepts_nested_relative_path(tmp_path: Path) -> None:
    root = tmp_path / 'root'
    root.mkdir()
    assert contained_path(root, 'nested/artifact.txt') == root / 'nested' / 'artifact.txt'


@pytest.mark.parametrize('relative', ['', '../artifact.txt'])
def test_contained_path_rejects_invalid_relative_path(tmp_path: Path, relative: str) -> None:
    with pytest.raises(FilesystemPolicyError, match='non-empty relative path without traversal'):
        contained_path(tmp_path, relative)


def test_contained_path_rejects_absolute_path(tmp_path: Path) -> None:
    with pytest.raises(FilesystemPolicyError, match='non-empty relative path without traversal'):
        contained_path(tmp_path, str(tmp_path / 'artifact.txt'))


def test_read_small_text_reads_utf8_within_limit(tmp_path: Path) -> None:
    artifact = tmp_path / 'artifact.txt'
    artifact.write_text('naïve', encoding='utf-8')
    assert read_small_text(artifact, max_bytes=6) == 'naïve'


def test_read_small_text_rejects_negative_limit(tmp_path: Path) -> None:
    with pytest.raises(FilesystemPolicyError, match='non-negative'):
        read_small_text(tmp_path / 'artifact.txt', max_bytes=-1)


@pytest.mark.parametrize('kind', ['directory', 'symlink'])
def test_read_small_text_rejects_non_regular_path(tmp_path: Path, kind: str) -> None:
    artifact = tmp_path / 'artifact.txt'
    if kind == 'directory':
        artifact.mkdir()
    else:
        target = tmp_path / 'target.txt'
        target.write_text('outside', encoding='utf-8')
        artifact.symlink_to(target)
    with pytest.raises(FilesystemPolicyError, match='not a regular non-symlink file'):
        read_small_text(artifact)


def test_read_small_text_rejects_oversized_file(tmp_path: Path) -> None:
    artifact = tmp_path / 'artifact.txt'
    artifact.write_bytes(b'1234')
    with pytest.raises(FilesystemPolicyError, match='exceeds 3 bytes'):
        read_small_text(artifact, max_bytes=3)


def test_atomic_writes_create_text_and_bytes(tmp_path: Path) -> None:
    text_path = tmp_path / 'text.txt'
    bytes_path = tmp_path / 'bytes.txt'
    atomic_write_text(text_path, 'naïve')
    atomic_write_bytes(bytes_path, b'payload')
    assert read_small_text(text_path) == 'naïve'
    assert read_small_text(bytes_path) == 'payload'


def test_atomic_write_preserves_regular_destination_mode(tmp_path: Path) -> None:
    artifact = tmp_path / 'artifact.txt'
    artifact.write_text('old', encoding='utf-8')
    artifact.chmod(0o640)
    atomic_write_text(artifact, 'new')
    assert read_small_text(artifact) == 'new'
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o640


def test_atomic_write_replaces_symlink_without_touching_target(tmp_path: Path) -> None:
    outside = tmp_path / 'outside.txt'
    outside.write_text('outside', encoding='utf-8')
    artifact = tmp_path / 'artifact.txt'
    artifact.symlink_to(outside)
    atomic_write_text(artifact, 'inside')
    assert not artifact.is_symlink()
    assert read_small_text(artifact) == 'inside'
    assert read_small_text(outside) == 'outside'


def test_main_emits_skylos_format_with_explicit_rule_ids(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    command = write_fake_detector_script(
        tmp_path / 'script.json',
        [
            FakeFinding(path='a.py', line=1, symbol='x', kind='function', rule_id='SKY-U777'),
            FakeFinding(path='a.py', line=2, symbol='y', kind='variable', bucket='unused_variables'),
        ],
        output_format='skylos',
    )
    exit_code = main([*command[3:], '.'])
    captured = capsys.readouterr()
    assert exit_code == 0
    document = json.loads(captured.out)
    (function_entry,) = document['unused_functions']
    assert function_entry['rule_id'] == 'SKY-U777'
    assert function_entry['line'] == 1
    (variable_entry,) = document['unused_variables']
    assert 'rule_id' not in variable_entry
    assert variable_entry['name'] == 'y'


def test_main_skylos_format_clean_document(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    command = write_fake_detector_script(tmp_path / 'script.json', [], output_format='skylos')
    assert main(command[3:]) == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_main_tolerates_malformed_script_documents(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Hand-written scripts may be sloppy: non-list findings and non-dict
    # entries are skipped rather than crashing the fake detector.
    script = tmp_path / 'weird.json'
    script.write_text('{"findings": "nope"}', encoding='utf-8')
    assert main([str(script)]) == 0
    script.write_text('{"findings": [42]}', encoding='utf-8')
    assert main([str(script)]) == 0
    assert 'nope' not in capsys.readouterr().out
