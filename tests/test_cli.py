"""Tests for the command-line interface (contract §12).

Copyright (C) 2026 Matthew C. Digman
"""

import shlex
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import pytest

import liveness_primer.cli
from liveness_primer.cli import EXIT_FAILURE, EXIT_GATE, EXIT_OK, main
from liveness_primer.findings import Report
from liveness_primer.isolation import UNENFORCED, Isolation, IsolationError
from liveness_primer.license_check import LicenseCheckResult
from liveness_primer.testing import FakeFinding, create_fake_project, write_fake_detector_script
from liveness_primer.testing.filesystem import atomic_write_text
from tests.test_runner import ScriptedEnvInstaller, fake_detector_repo

__all__ = ['fake_detector_repo']

BASE = FakeFinding(path='pkg/mod.py', line=5, symbol='unused_helper')
MOVED = FakeFinding(path='pkg/mod.py', line=9, symbol='unused_helper')
NEW = FakeFinding(path='pkg/extra.py', line=2, symbol='fresh', kind='variable', confidence=100)


@pytest.fixture
def project_url(tmp_path: Path) -> str:
    return create_fake_project(tmp_path / 'origin', init_git=True).url


@pytest.fixture
def _isolated_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(liveness_primer.cli, 'cache_root', lambda: tmp_path / 'cli-cache')


def escape_argv(
    tmp_path: Path,
    project_url: str,
    base_findings: list[FakeFinding],
    head_findings: list[FakeFinding],
    *extra: str,
) -> list[str]:
    base_cmd = write_fake_detector_script(tmp_path / 'cli-base.json', base_findings)
    head_cmd = write_fake_detector_script(tmp_path / 'cli-head.json', head_findings)
    return [
        'run',
        '--tool',
        'vulture',
        '--project',
        project_url,
        '--old-cmd',
        shlex.join(base_cmd),
        '--new-cmd',
        shlex.join(head_cmd),
        *extra,
    ]


@pytest.mark.usefixtures('_isolated_cache')
def test_run_escape_hatch_text_output(
    tmp_path: Path,
    project_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    limits = ('--jobs', '2', '--timeout', '30', '--max-results', '50', '--excerpt-lines', '3')
    code = main(escape_argv(tmp_path, project_url, [BASE], [MOVED, NEW], *limits))
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert 'liveness primer report - tool: vulture' in captured.out
    assert '1 new, 0 dropped, 1 changed' in captured.out
    assert 'comparable: no' in captured.out


@pytest.mark.usefixtures('_isolated_cache')
def test_run_json_output_parses_into_the_report_model(
    tmp_path: Path,
    project_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(escape_argv(tmp_path, project_url, [BASE], [BASE], '--output', 'json'))
    captured = capsys.readouterr()
    assert code == EXIT_OK
    report = Report.model_validate_json(captured.out)
    assert report.totals.new == 0
    assert report.manifest.comparable is False


@pytest.mark.usefixtures('_isolated_cache')
def test_run_github_output(tmp_path: Path, project_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(escape_argv(tmp_path, project_url, [], [NEW], '--output', 'github'))
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert captured.out.startswith('# liveness primer report')


@pytest.mark.usefixtures('_isolated_cache')
def test_run_failure_exit_code(tmp_path: Path, project_url: str, capsys: pytest.CaptureFixture[str]) -> None:
    base_cmd = write_fake_detector_script(tmp_path / 'cli-base.json', [], exit_code=2, stderr='blew up')
    head_cmd = write_fake_detector_script(tmp_path / 'cli-head.json', [])
    code = main(
        [
            'run',
            '--tool',
            'vulture',
            '--project',
            project_url,
            '--old-cmd',
            shlex.join(base_cmd),
            '--new-cmd',
            shlex.join(head_cmd),
        ]
    )
    captured = capsys.readouterr()
    assert code == EXIT_FAILURE
    assert 'run failure' in captured.err


@pytest.mark.usefixtures('_isolated_cache')
def test_fail_on_refuses_escape_hatch_runs(
    tmp_path: Path,
    project_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(escape_argv(tmp_path, project_url, [], [NEW], '--fail-on', 'new'))
    captured = capsys.readouterr()
    assert code == EXIT_FAILURE
    assert 'non-comparable' in captured.err


def test_run_mode_flag_matrix_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    incomplete = ['run', '--tool', 'vulture', '--project', 'https://example.invalid/x', '--old-cmd', 'x']
    assert main(incomplete) == EXIT_FAILURE
    assert 'must be given together' in capsys.readouterr().err
    mixed = [
        'run',
        '--tool',
        'vulture',
        '--project',
        'https://example.invalid/x',
        '--old-cmd',
        'x',
        '--new-cmd',
        'y',
        '--repo',
        'https://example.invalid/r',
    ]
    assert main(mixed) == EXIT_FAILURE
    assert 'escape hatch' in capsys.readouterr().err
    managed_incomplete = ['run', '--tool', 'vulture', '--project', 'https://example.invalid/x', '--old', 'a']
    assert main(managed_incomplete) == EXIT_FAILURE
    assert 'managed run requires' in capsys.readouterr().err
    del tmp_path


def test_run_rejects_ad_hoc_with_selectors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    argv = escape_argv(tmp_path, 'https://example.invalid/x', [], [], '--all')
    assert main(argv) == EXIT_FAILURE
    assert 'ad-hoc mode' in capsys.readouterr().err


def test_run_unknown_tool_fails_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(['run', '--tool', 'pylint', '--repo', 'r', '--old', 'a', '--new', 'b'])
    assert code == EXIT_FAILURE
    assert 'unknown tool' in capsys.readouterr().err


def test_usage_errors_exit_two() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(['run'])
    assert excinfo.value.code == 2
    with pytest.raises(SystemExit) as excinfo:
        main(['no-such-command'])
    assert excinfo.value.code == 2


@pytest.mark.parametrize(
    ('flag', 'value'),
    [
        ('--jobs', '0'),
        ('--jobs', '-1'),
        ('--jobs', 'many'),
        ('--timeout', '0'),
        ('--timeout', '-5'),
        ('--timeout', 'nan'),
        ('--timeout', 'inf'),
        ('--timeout', 'soon'),
        ('--max-results', '0'),
        ('--max-results', '-3'),
        ('--excerpt-lines', '-1'),
        ('--excerpt-lines', 'x'),
        ('--max-cost', '0'),
    ],
)
def test_unusable_resource_limits_are_usage_errors(flag: str, value: str) -> None:
    # Contract §12: `--jobs 0` must not hang and `--jobs -1` must not
    # escape as a raw traceback; both are rejected at the parser.
    with pytest.raises(SystemExit) as excinfo:
        main(['run', '--tool', 'vulture', '--repo', 'r', '--old', 'a', '--new', 'b', flag, value])
    assert excinfo.value.code == 2


def test_managed_run_refuses_to_start_without_required_isolation(
    project_url: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Contract §11/§19.1: managed runs execute untrusted detector refs and
    # fail closed when enforced isolation is unavailable.
    def refuse() -> Isolation:
        msg = 'network isolation is required on Linux'
        raise IsolationError(msg)

    monkeypatch.setattr(liveness_primer.cli, 'require_isolation', refuse)
    code = main(
        [
            'run',
            '--tool',
            'vulture',
            '--project',
            project_url,
            '--repo',
            'https://example.invalid/detector',
            '--old',
            'a',
            '--new',
            'b',
        ]
    )
    assert code == EXIT_FAILURE
    assert 'network isolation is required' in capsys.readouterr().err


def test_version_prints_package_and_schema_versions(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(liveness_primer.cli, 'metadata_version', lambda _name: '9.9.9')
    with pytest.raises(SystemExit) as excinfo:
        main(['--version'])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert '9.9.9' in out
    assert 'schema 1.0.0' in out


def test_version_tolerates_uninstalled_package(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_name: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr(liveness_primer.cli, 'metadata_version', missing)
    with pytest.raises(SystemExit):
        main(['--version'])
    assert 'unknown' in capsys.readouterr().out


CORPUS_TOML = """
[[projects]]
name = "alpha"
repo = "https://github.com/example/alpha"
license = "MIT"
pin = "{pin}"

[[projects]]
name = "beta"
repo = "https://github.com/example/beta"
license = "Apache-2.0"
branch = "main"
""".format(pin='a' * 40)


def write_corpus(tmp_path: Path, content: str = CORPUS_TOML) -> Path:
    corpus_file = tmp_path / 'corpus.toml'
    atomic_write_text(corpus_file, content)
    return corpus_file


def test_corpus_validate_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    corpus_file = write_corpus(tmp_path)
    assert main(['corpus', 'validate', '--corpus', str(corpus_file)]) == EXIT_OK
    out = capsys.readouterr().out
    assert 'corpus OK: 2 project(s)' in out
    assert 'alpha' in out


def test_corpus_validate_rejects_bad_corpus(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    corpus_file = write_corpus(tmp_path, CORPUS_TOML.replace('MIT', 'GPL-3.0-only'))
    assert main(['corpus', 'validate', '--corpus', str(corpus_file)]) == EXIT_FAILURE
    assert 'copyleft' in capsys.readouterr().err


def license_result(name: str, *, ok: bool) -> LicenseCheckResult:
    return LicenseCheckResult(
        project=name,
        repo=f'https://github.com/example/{name}',
        declared='MIT',
        detected='MIT' if ok else 'Apache-2.0',
        ok=ok,
        detail='confirmed MIT' if ok else 'declared MIT but GitHub detects Apache-2.0',
    )


def test_corpus_license_check_ok(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus_file = write_corpus(tmp_path)
    seen_tokens: list[str | None] = []

    def fake_check(projects: object, *, token: str | None = None) -> tuple[LicenseCheckResult, ...]:
        del projects
        seen_tokens.append(token)
        return (license_result('alpha', ok=True), license_result('beta', ok=True))

    monkeypatch.setattr(liveness_primer.cli, 'check_licenses', fake_check)
    monkeypatch.setenv('GITHUB_TOKEN', 'from-env')
    assert main(['corpus', 'license-check', '--corpus', str(corpus_file)]) == EXIT_OK
    assert seen_tokens == ['from-env']
    assert 'ok   alpha: confirmed MIT' in capsys.readouterr().out


def test_corpus_license_check_failure(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corpus_file = write_corpus(tmp_path)

    def fake_check(projects: object, *, token: str | None = None) -> tuple[LicenseCheckResult, ...]:
        del projects, token
        return (license_result('alpha', ok=True), license_result('beta', ok=False))

    monkeypatch.setattr(liveness_primer.cli, 'check_licenses', fake_check)
    assert main(['corpus', 'license-check', '--corpus', str(corpus_file)]) == EXIT_FAILURE
    assert 'FAIL beta' in capsys.readouterr().out


def test_schema_export_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / 'schemas'

    def fake_export() -> tuple[Path, ...]:
        return (target / 'report.schema.json',)

    monkeypatch.setattr(liveness_primer.cli, 'export_schemas', fake_export)
    assert main(['schema', 'export']) == EXIT_OK
    assert 'report.schema.json' in capsys.readouterr().out


@pytest.mark.usefixtures('_isolated_cache')
def test_run_with_corpus_file_selection(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Corpus files require GitHub-hosted repos, so exercise the corpus path
    # up to pin resolution, which fails on the unreachable host.
    corpus_file = write_corpus(tmp_path)
    base_cmd = write_fake_detector_script(tmp_path / 'b.json', [])
    head_cmd = write_fake_detector_script(tmp_path / 'h.json', [])
    code = main(
        [
            'run',
            '--tool',
            'vulture',
            '--corpus',
            str(corpus_file),
            '-k',
            'nomatch',
            '--old-cmd',
            shlex.join(base_cmd),
            '--new-cmd',
            shlex.join(head_cmd),
        ]
    )
    assert code == EXIT_FAILURE
    assert 'no corpus project matches' in capsys.readouterr().err


@pytest.mark.usefixtures('_isolated_cache')
def test_managed_run_fires_gates_with_exit_three(
    project_url: str,
    fake_detector_repo: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(liveness_primer.cli, 'choose_installer', ScriptedEnvInstaller)
    monkeypatch.setattr(liveness_primer.cli, 'require_isolation', lambda: UNENFORCED)
    code = main(
        [
            'run',
            '--tool',
            'vulture',
            '--project',
            project_url,
            '--repo',
            fake_detector_repo,
            '--old',
            'base-branch',
            '--new',
            'head-branch',
            '--fail-on',
            'new',
            '--fail-on',
            'dropped',
        ]
    )
    captured = capsys.readouterr()
    assert code == EXIT_GATE
    assert 'comparable: yes' in captured.out
    assert 'gate failure: new: 1' in captured.err


@pytest.mark.usefixtures('_isolated_cache')
def test_managed_run_without_firing_gates_exits_zero(
    project_url: str,
    fake_detector_repo: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(liveness_primer.cli, 'choose_installer', ScriptedEnvInstaller)
    monkeypatch.setattr(liveness_primer.cli, 'require_isolation', lambda: UNENFORCED)
    code = main(
        [
            'run',
            '--tool',
            'vulture',
            '--project',
            project_url,
            '--repo',
            fake_detector_repo,
            '--old',
            'base-branch',
            '--new',
            'head-branch',
            '--fail-on',
            'dropped',
        ]
    )
    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert 'installer: fake 1.0' in captured.out
