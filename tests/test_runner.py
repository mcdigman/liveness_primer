"""Tests for the two-revision runner over the fake detector (contract §3, §15).

Copyright (C) 2026 Matthew C. Digman
"""

import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest

from liveness_primer.config import CorpusProject
from liveness_primer.corpus import CheckoutStore
from liveness_primer.envcache import DetectorEnvironments
from liveness_primer.findings import DiffClass, DiffTotals, Report
from liveness_primer.isolation import UNENFORCED, Isolation
from liveness_primer.launcher import AsyncLauncher, LaunchResult, run_async, run_sync
from liveness_primer.runner import PrimerRunner, RunnerError, RunOptions, evaluate_gates, report_has_failures
from liveness_primer.testing import FakeFinding, create_fake_project, write_fake_detector_script
from liveness_primer.tools.registry import get_adapter

BASE_FINDING = FakeFinding(path='pkg/mod.py', line=5, symbol='unused_helper', kind='function', confidence=60)
MOVED_FINDING = FakeFinding(path='pkg/mod.py', line=9, symbol='unused_helper', kind='function', confidence=60)
NEW_FINDING = FakeFinding(path='pkg/extra.py', line=2, symbol='fresh', kind='variable', confidence=100)

DEFAULT_OPTIONS = RunOptions(jobs=2, timeout=30.0)


@pytest.fixture
def corpus_project(tmp_path: Path) -> CorpusProject:
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    return CorpusProject(name='fakeproj', repo=origin.url, pin=origin.head_sha)


def runner_for(tmp_path: Path, options: RunOptions = DEFAULT_OPTIONS) -> PrimerRunner:
    return PrimerRunner(
        adapter=get_adapter('vulture'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=UNENFORCED,
        options=options,
    )


def test_runner_rejects_synchronous_async_launcher(tmp_path: Path) -> None:
    with pytest.raises(RunnerError, match='async_launcher must be an asynchronous callable'):
        PrimerRunner(
            adapter=get_adapter('vulture'),
            store=CheckoutStore(tmp_path / 'cache'),
            isolation=UNENFORCED,
            options=DEFAULT_OPTIONS,
            async_launcher=cast('AsyncLauncher', run_sync),
        )


def escape_run(
    tmp_path: Path,
    project: CorpusProject,
    base_findings: list[FakeFinding],
    head_findings: list[FakeFinding],
    options: RunOptions = DEFAULT_OPTIONS,
) -> Report:
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', base_findings)
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', head_findings)
    return runner_for(tmp_path, options).run_escape_hatch([project], base_cmd=base_cmd, head_cmd=head_cmd)


def test_escape_hatch_reports_blast_radius(tmp_path: Path, corpus_project: CorpusProject) -> None:
    report = escape_run(tmp_path, corpus_project, [BASE_FINDING], [MOVED_FINDING, NEW_FINDING])
    assert report.totals == DiffTotals(new=1, changed=1)
    (project_report,) = report.projects
    assert project_report.project == 'fakeproj'
    assert project_report.base_findings == 1
    assert project_report.head_findings == 2
    assert not project_report.truncated
    assert project_report.errors == ()
    assert project_report.measured_cost_seconds is not None
    by_class = {diff.diff_class: diff for diff in project_report.diffs}
    changed = by_class[DiffClass.CHANGED]
    assert changed.base_occurrence is not None
    assert changed.head_occurrence is not None
    assert (changed.base_occurrence.start_line, changed.head_occurrence.start_line) == (5, 9)
    assert by_class[DiffClass.NEW].symbol == 'fresh'
    assert not report_has_failures(report)


def test_escape_hatch_manifest_is_not_comparable(tmp_path: Path, corpus_project: CorpusProject) -> None:
    report = escape_run(tmp_path, corpus_project, [BASE_FINDING], [BASE_FINDING])
    manifest = report.manifest
    assert manifest.comparable is False
    assert manifest.tool == 'vulture'
    assert manifest.detector_repo is None
    assert manifest.base is None
    assert manifest.base_cmd is not None
    assert manifest.base_cmd[-1].endswith('base.json')
    assert manifest.installer is None
    assert manifest.isolation_enforced is False
    (pin,) = manifest.corpus_pins
    assert pin.name == 'fakeproj'
    assert pin.resolved_sha == corpus_project.pin
    git_fetches = [record for record in manifest.fetches if record.kind == 'git']
    assert [record.name for record in git_fetches] == [corpus_project.repo]
    assert manifest.settings.selection == ('fakeproj',)
    assert report.totals == DiffTotals()


def test_identical_sides_produce_empty_blast_radius(tmp_path: Path, corpus_project: CorpusProject) -> None:
    report = escape_run(tmp_path, corpus_project, [BASE_FINDING], [BASE_FINDING])
    (project_report,) = report.projects
    assert project_report.diffs == ()
    assert project_report.totals == DiffTotals()


def test_truncation_caps_diffs_but_not_totals(tmp_path: Path, corpus_project: CorpusProject) -> None:
    head = [FakeFinding(path='pkg/mod.py', line=line, symbol=f'sym{line}') for line in range(1, 6)]
    report = escape_run(tmp_path, corpus_project, [], head, RunOptions(jobs=2, timeout=30.0, max_results=2))
    (project_report,) = report.projects
    assert project_report.truncated
    assert report.truncated
    assert len(project_report.diffs) == 2
    assert project_report.totals.new == 5


def test_tool_failure_is_recorded_not_raised(tmp_path: Path, corpus_project: CorpusProject) -> None:
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [], exit_code=2, stderr='config exploded')
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [BASE_FINDING])
    report = runner_for(tmp_path).run_escape_hatch([corpus_project], base_cmd=base_cmd, head_cmd=head_cmd)
    (project_report,) = report.projects
    (error,) = project_report.errors
    assert error.side == 'base'
    assert error.exit_code == 2
    assert 'config exploded' in error.detail
    assert project_report.diffs == ()
    assert project_report.measured_cost_seconds is None
    assert report_has_failures(report)


def test_unparseable_output_is_recorded_as_error(tmp_path: Path, corpus_project: CorpusProject) -> None:
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [], raw_lines=['?? not a report line'])
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [])
    report = runner_for(tmp_path).run_escape_hatch([corpus_project], base_cmd=base_cmd, head_cmd=head_cmd)
    (project_report,) = report.projects
    (error,) = project_report.errors
    assert error.side == 'base'
    assert 'unparseable vulture output' in error.detail


def test_timeout_is_recorded_with_settings_override(tmp_path: Path) -> None:
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    project = CorpusProject.model_validate(
        {
            'name': 'slowproj',
            'repo': origin.url,
            'pin': origin.head_sha,
            'tools': {'vulture': {'timeout': 0.5}},
        }
    )
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [BASE_FINDING], sleep_seconds=30.0)
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [BASE_FINDING])
    report = runner_for(tmp_path).run_escape_hatch([project], base_cmd=base_cmd, head_cmd=head_cmd)
    (project_report,) = report.projects
    (error,) = project_report.errors
    assert error.side == 'base'
    assert error.exit_code is None
    assert 'timed out after 0.5s' in error.detail


def test_expected_clean_violation_warns_but_comparison_runs(tmp_path: Path) -> None:
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    project = CorpusProject.model_validate(
        {
            'name': 'cleanproj',
            'repo': origin.url,
            'pin': origin.head_sha,
            'tools': {'vulture': {'expected_clean': True}},
        }
    )
    report = escape_run(tmp_path, project, [BASE_FINDING], [MOVED_FINDING])
    (project_report,) = report.projects
    (warning,) = project_report.integrity_warnings
    assert warning.project == 'cleanproj'
    assert warning.tool == 'vulture'
    assert '1 finding(s)' in warning.detail
    assert 'exit code 3' in warning.detail
    assert project_report.totals.changed == 1


def test_expected_clean_pass_produces_no_warning(tmp_path: Path) -> None:
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    project = CorpusProject.model_validate(
        {
            'name': 'cleanproj',
            'repo': origin.url,
            'pin': origin.head_sha,
            'tools': {'vulture': {'expected_clean': True}},
        }
    )
    report = escape_run(tmp_path, project, [], [NEW_FINDING])
    (project_report,) = report.projects
    assert project_report.integrity_warnings == ()
    assert project_report.totals.new == 1


def test_analysis_commands_are_isolation_wrapped(tmp_path: Path, corpus_project: CorpusProject) -> None:
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [BASE_FINDING])
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [BASE_FINDING])
    seen: list[tuple[str, ...]] = []

    async def spying_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        seen.append(tuple(argv))
        return await run_async(list(argv)[1:], cwd=cwd, env=env)

    runner = PrimerRunner(
        adapter=get_adapter('vulture'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=Isolation(enforced=True, description='netns:test', prefix=('fake-sandbox-prefix',)),
        options=DEFAULT_OPTIONS,
        async_launcher=spying_launcher,
    )
    report = runner.run_escape_hatch([corpus_project], base_cmd=base_cmd, head_cmd=head_cmd)
    assert report.manifest.isolation_enforced is True
    assert len(seen) == 2
    assert all(argv[0] == 'fake-sandbox-prefix' for argv in seen)
    assert not report_has_failures(report)


def test_multiple_projects_run_in_order(tmp_path: Path) -> None:
    projects = []
    for index in range(3):
        origin = create_fake_project(tmp_path / f'origin{index}', init_git=True)
        assert origin.head_sha is not None
        projects.append(CorpusProject(name=f'proj{index}', repo=origin.url, pin=origin.head_sha))
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [])
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [BASE_FINDING])
    report = runner_for(tmp_path).run_escape_hatch(projects, base_cmd=base_cmd, head_cmd=head_cmd)
    assert [entry.project for entry in report.projects] == ['proj0', 'proj1', 'proj2']
    assert report.totals.new == 3
    assert report.manifest.settings.selection == ('proj0', 'proj1', 'proj2')


def make_gate_report(tmp_path: Path, corpus_project: CorpusProject) -> Report:
    return escape_run(tmp_path, corpus_project, [BASE_FINDING], [MOVED_FINDING, NEW_FINDING])


def test_evaluate_gates_refuses_non_comparable_runs(tmp_path: Path, corpus_project: CorpusProject) -> None:
    report = make_gate_report(tmp_path, corpus_project)
    with pytest.raises(RunnerError, match='non-comparable'):
        evaluate_gates(report, ('new',))


def test_evaluate_gates_matrix(tmp_path: Path, corpus_project: CorpusProject) -> None:
    report = make_gate_report(tmp_path, corpus_project)
    comparable = report.model_copy(update={'manifest': report.manifest.model_copy(update={'comparable': True})})
    assert evaluate_gates(comparable, ()) == ()
    assert evaluate_gates(comparable, ('dropped',)) == ()
    assert evaluate_gates(comparable, ('new',)) == ('new: 1',)
    assert evaluate_gates(comparable, ('any',)) == ('new: 1', 'changed: 1')
    assert evaluate_gates(comparable, ('corpus-integrity',)) == ()


def test_evaluate_gates_corpus_integrity(tmp_path: Path) -> None:
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    project = CorpusProject.model_validate(
        {
            'name': 'cleanproj',
            'repo': origin.url,
            'pin': origin.head_sha,
            'tools': {'vulture': {'expected_clean': True}},
        }
    )
    report = escape_run(tmp_path, project, [BASE_FINDING], [BASE_FINDING])
    comparable = report.model_copy(update={'manifest': report.manifest.model_copy(update={'comparable': True})})
    assert evaluate_gates(comparable, ('corpus-integrity',)) == ('corpus-integrity: 1',)
    assert evaluate_gates(comparable, ('any',)) == ()


def test_fetch_records_dedupe_shared_pins(tmp_path: Path) -> None:
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    first = CorpusProject(name='alias-one', repo=origin.url, pin=origin.head_sha)
    second = CorpusProject(name='alias-two', repo=origin.url, pin=origin.head_sha)
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [])
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [])
    report = runner_for(tmp_path).run_escape_hatch([first, second], base_cmd=base_cmd, head_cmd=head_cmd)
    git_fetches = [record for record in report.manifest.fetches if record.kind == 'git']
    assert len(git_fetches) == 1
    assert len(report.manifest.corpus_pins) == 2


@dataclass
class ScriptedEnvInstaller:
    """Installer that fabricates a runnable fake-detector 'venv' per ref."""

    name: str = 'fake'
    created: list[Path] = field(default_factory=list)

    @staticmethod
    def identity() -> str:
        """Report a fixed identity.

        Returns
        -------
        str
            ``fake 1.0``.
        """
        return 'fake 1.0'

    def create_venv(self, env_dir: Path) -> None:
        """Create the environment directory."""
        env_dir.mkdir(parents=True)
        self.created.append(env_dir)

    @staticmethod
    def install_offline(env_dir: Path, wheelhouse: Path, target: Path, isolation: Isolation) -> None:
        """Install the detector by wiring its per-ref script to a wrapper."""
        del wheelhouse, isolation
        script = env_dir / 'script.json'
        script.write_text((target / 'script.json').read_text(encoding='utf-8'), encoding='utf-8')
        bin_dir = env_dir / 'bin'
        bin_dir.mkdir()
        wrapper = bin_dir / 'vulture'
        package_root = Path(__file__).resolve().parent.parent
        wrapper.write_text(
            f'#!{sys.executable}\n'
            'import sys\n'
            f'sys.path.insert(0, {str(package_root)!r})\n'
            'from liveness_primer.testing.fake_detector import main\n'
            f'sys.exit(main([{str(script)!r}, *sys.argv[1:]]))\n',
            encoding='utf-8',
        )
        wrapper.chmod(0o755)

    @staticmethod
    def freeze(env_dir: Path) -> tuple[str, ...]:
        """Report a fixed freeze.

        Returns
        -------
        tuple[str, ...]
            One line naming the detector.
        """
        del env_dir
        return ('vulture @ file:///fake',)


MINIMAL_DETECTOR_PYPROJECT = '[build-system]\nrequires = []\n\n[project]\nname = "vulture"\nversion = "9.9"\n'


def detector_git(repo_dir: Path, *args: str) -> str:
    result = run_sync(['git', *args], cwd=repo_dir)
    assert result.ok, result.stderr
    return result.stdout.strip()


@pytest.fixture
def fake_detector_repo(tmp_path: Path) -> str:
    repo_dir = tmp_path / 'detector-origin'
    repo_dir.mkdir()
    detector_git(repo_dir, 'init', '--quiet')
    detector_git(repo_dir, 'symbolic-ref', 'HEAD', 'refs/heads/base-branch')
    detector_git(repo_dir, 'config', 'user.email', 'test@example.invalid')
    detector_git(repo_dir, 'config', 'user.name', 'Test')
    (repo_dir / 'pyproject.toml').write_text(MINIMAL_DETECTOR_PYPROJECT, encoding='utf-8')
    write_fake_detector_script(repo_dir / 'script.json', [BASE_FINDING])
    detector_git(repo_dir, 'add', '--all')
    detector_git(repo_dir, 'commit', '--quiet', '-m', 'base detector')
    detector_git(repo_dir, 'checkout', '--quiet', '-b', 'head-branch')
    write_fake_detector_script(repo_dir / 'script.json', [MOVED_FINDING, NEW_FINDING])
    detector_git(repo_dir, 'add', '--all')
    detector_git(repo_dir, 'commit', '--quiet', '-m', 'head detector')
    return repo_dir.as_uri()


def test_managed_run_end_to_end(tmp_path: Path, corpus_project: CorpusProject, fake_detector_repo: str) -> None:
    installer = ScriptedEnvInstaller()
    environments = DetectorEnvironments(
        CheckoutStore(tmp_path / 'cache'),
        tmp_path / 'cache',
        installer=installer,
    )
    report = runner_for(tmp_path).run_managed(
        [corpus_project],
        detector_repo=fake_detector_repo,
        base_ref='base-branch',
        head_ref='head-branch',
        environments=environments,
    )
    manifest = report.manifest
    assert manifest.comparable is True
    assert manifest.detector_repo == fake_detector_repo
    assert manifest.base is not None
    assert manifest.head is not None
    assert manifest.base.sha != manifest.head.sha
    assert manifest.base.ref == 'base-branch'
    assert manifest.installer == 'fake 1.0'
    assert manifest.environment_delta == ()
    assert manifest.base_cmd is None
    assert report.totals == DiffTotals(new=1, changed=1)
    assert not report_has_failures(report)
    git_fetches = [record for record in manifest.fetches if record.kind == 'git']
    assert fake_detector_repo in {record.name for record in git_fetches}
    assert corpus_project.repo in {record.name for record in git_fetches}
