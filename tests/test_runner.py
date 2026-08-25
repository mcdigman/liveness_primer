# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the two-revision runner over the fake detector (contract §3, §15)."""

import asyncio
import hashlib
import os
import re
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import cast, override

import pytest

import liveness_primer.runner as runner_module
from liveness_primer.config import CorpusProject, ToolSettings
from liveness_primer.container import (
    CONTAINER_ISOLATION,
    CONTAINER_WORK_ROOT,
    DEFAULT_CONTAINER_BUILDER_IMAGE,
    DEFAULT_CONTAINER_IMAGE,
    ContainerEnvironments,
)
from liveness_primer.corpus import CheckoutStore
from liveness_primer.envcache import DetectorEnvironments
from liveness_primer.filesystem import atomic_write_text, contained_path, read_small_text
from liveness_primer.findings import ChangedField, DiffClass, DiffRollup, DiffTotals, Report
from liveness_primer.isolation import UNENFORCED, Isolation
from liveness_primer.launcher import AsyncLauncher, LaunchResult, run_async, run_sync
from liveness_primer.report import render_github, render_text
from liveness_primer.report.terminal import TextRenderOptions
from liveness_primer.runner import (
    PrimerRunner,
    RunnerError,
    RunOptions,
    evaluate_gates,
    report_has_failures,
    resolve_native_tools,
)
from liveness_primer.testing import FakeFinding, create_fake_project, write_fake_detector_script
from liveness_primer.tools.registry import get_adapter
from tests.test_container import FakeDocker

BASE_FINDING = FakeFinding(path='pkg/mod.py', line=5, symbol='unused_helper', kind='function', confidence=60)
MOVED_FINDING = FakeFinding(path='pkg/mod.py', line=9, symbol='unused_helper', kind='function', confidence=60)
NEW_FINDING = FakeFinding(path='pkg/extra.py', line=2, symbol='fresh', kind='variable', confidence=100)

DEFAULT_OPTIONS = RunOptions(jobs=2, timeout=30.0)


@dataclass
class WorkspaceCheckingDocker(FakeDocker):
    """Fake runtime checking cleanup precedes workspace deletion."""

    invocation_workspaces: dict[str, Path] = field(default_factory=dict)
    workspace_existed_at_removal: list[bool] = field(default_factory=list)

    @override
    def remove_container(self, name: str) -> bool:
        """Record whether the named invocation workspace still exists.

        Returns
        -------
        bool
            The scripted removal outcome.
        """
        self.workspace_existed_at_removal.append(self.invocation_workspaces[name].is_dir())
        return super().remove_container(name)


@pytest.fixture
def corpus_project(tmp_path: Path) -> CorpusProject:
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    return CorpusProject(name='fakeproj', repo=origin.url, pin=origin.head_sha)


def runner_for(tmp_path: Path, options: RunOptions = DEFAULT_OPTIONS, *, tool: str = 'vulture') -> PrimerRunner:
    return PrimerRunner(
        adapter=get_adapter(tool),
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
    # The moved helper is a dropped finding at its old line plus a new one
    # at its new line: the line is part of the finding identity.
    assert report.totals == DiffTotals(new=2, dropped=1)
    (project_report,) = report.projects
    assert project_report.project == 'fakeproj'
    assert project_report.base_findings == 1
    assert project_report.head_findings == 2
    assert not project_report.truncated
    assert project_report.errors == ()
    assert project_report.measured_cost_seconds is not None
    by_class: dict[tuple[DiffClass, str | None], int] = {}
    for entry in project_report.diffs:
        by_class[entry.diff_class, entry.symbol] = entry.reference_occurrence.start_line
    assert by_class[DiffClass.DROPPED, 'unused_helper'] == 5
    assert by_class[DiffClass.NEW, 'unused_helper'] == 9
    assert (DiffClass.NEW, 'fresh') in by_class
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


def test_failed_skylos_with_empty_result_buckets_does_not_diff(
    tmp_path: Path,
    corpus_project: CorpusProject,
) -> None:
    base_cmd = write_fake_detector_script(
        tmp_path / 'base.json',
        [BASE_FINDING],
        output_format='skylos',
    )
    head_cmd = write_fake_detector_script(
        tmp_path / 'head.json',
        [],
        output_format='skylos',
        exit_code=2,
        stderr='analysis aborted',
    )
    report = runner_for(tmp_path, tool='skylos').run_escape_hatch(
        [corpus_project],
        base_cmd=base_cmd,
        head_cmd=head_cmd,
    )
    (project_report,) = report.projects
    (error,) = project_report.errors
    assert 'no findings in recognized result buckets' in error.detail
    assert project_report.base_findings == 1
    assert project_report.head_findings == 0
    assert project_report.diffs == ()
    assert project_report.totals == DiffTotals()
    assert project_report.measured_cost_seconds is None


def test_unparseable_output_is_recorded_as_error(tmp_path: Path, corpus_project: CorpusProject) -> None:
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [], raw_lines=['?? not a report line'])
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [])
    report = runner_for(tmp_path).run_escape_hatch([corpus_project], base_cmd=base_cmd, head_cmd=head_cmd)
    (project_report,) = report.projects
    (error,) = project_report.errors
    assert error.side == 'base'
    assert 'unparseable vulture output' in error.detail


def test_unparseable_failure_output_preserves_exit_error(tmp_path: Path, corpus_project: CorpusProject) -> None:
    base_cmd = write_fake_detector_script(
        tmp_path / 'base.json',
        [],
        exit_code=2,
        stderr='config exploded',
        raw_lines=['?? not a report line'],
    )
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [])
    report = runner_for(tmp_path).run_escape_hatch([corpus_project], base_cmd=base_cmd, head_cmd=head_cmd)
    (error,) = report.projects[0].errors
    assert error.exit_code == 2
    assert 'config exploded' in error.detail
    assert 'output parse failed' in error.detail


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
    assert project_report.totals == DiffTotals(new=1, dropped=1)


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
    assert evaluate_gates(comparable, ('changed',)) == ()
    assert evaluate_gates(comparable, ('new',)) == ('new: 2',)
    assert evaluate_gates(comparable, ('any',)) == ('new: 2', 'dropped: 1')
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

    @staticmethod
    def prefetch(requirements: Sequence[str], wheelhouse: Path) -> None:
        """Accept the prefetch request without downloading anything."""
        del requirements, wheelhouse

    def create_venv(self, env_dir: Path, *, isolation: Isolation, env: Mapping[str, str] | None = None) -> None:
        """Create the environment directory."""
        del isolation, env
        env_dir.mkdir(parents=True)
        self.created.append(env_dir)

    @staticmethod
    def install_offline(
        env_dir: Path,
        wheelhouse: Path,
        target: Path,
        *,
        isolation: Isolation,
        env: Mapping[str, str] | None = None,
    ) -> None:
        """Install the detector by wiring its per-ref script to a wrapper."""
        del wheelhouse, isolation, env
        script = env_dir / 'script.json'
        atomic_write_text(script, read_small_text(target / 'script.json'))
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


def test_run_options_reject_unusable_limits() -> None:
    with pytest.raises(RunnerError, match='jobs must be at least 1'):
        RunOptions(jobs=0)
    with pytest.raises(RunnerError, match='timeout must be positive'):
        RunOptions(timeout=0.0)
    with pytest.raises(RunnerError, match='timeout must be positive'):
        RunOptions(timeout=float('nan'))
    with pytest.raises(RunnerError, match='max_results must be at least 1'):
        RunOptions(max_results=0)
    with pytest.raises(RunnerError, match='excerpt_lines must not be negative'):
        RunOptions(excerpt_lines=-1)
    both = re.escape('jobs must be at least 1, got -1; timeout must be positive, got -2.0')
    with pytest.raises(RunnerError, match=both):
        RunOptions(jobs=-1, timeout=-2.0)


def spying_runner(tmp_path: Path, launcher: AsyncLauncher) -> PrimerRunner:
    return PrimerRunner(
        adapter=get_adapter('vulture'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=UNENFORCED,
        options=DEFAULT_OPTIONS,
        async_launcher=launcher,
    )


def test_each_side_analyzes_its_own_disposable_copy(tmp_path: Path, corpus_project: CorpusProject) -> None:
    # Contract §3: both revisions see byte-identical trees, but neither may
    # share a writable working tree with the other or with the cache.
    seen_cwds: list[Path | None] = []

    async def spying_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        seen_cwds.append(cwd)
        return await run_async(list(argv), cwd=cwd, env=env)

    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [BASE_FINDING])
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [BASE_FINDING])
    report = spying_runner(tmp_path, spying_launcher).run_escape_hatch(
        [corpus_project], base_cmd=base_cmd, head_cmd=head_cmd
    )
    assert not report_has_failures(report)
    first, second = seen_cwds
    assert first is not None
    assert second is not None
    assert first != second
    for side_cwd in (first, second):
        assert side_cwd.name == 'checkout'
        assert 'liveness-primer-side-' in side_cwd.parent.name
        assert not str(side_cwd).startswith(str(tmp_path / 'cache'))
        assert not side_cwd.exists()  # workspaces are disposed after use
    # The cached checkout keeps its .git and is untouched by the run.
    cached = [path for path in (tmp_path / 'cache' / 'checkouts').iterdir() if path.is_dir()]
    (checkout,) = cached
    assert (checkout / 'pkg' / 'mod.py').exists()
    assert (checkout / '.git').exists()


def test_side_copy_refuses_a_checkout_outside_the_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = CheckoutStore(tmp_path / 'cache')
    trusted = store.checkout_root / 'checkout-key'
    trusted.mkdir(parents=True)
    (trusted / 'marker.txt').write_text('trusted', encoding='utf-8')
    outside = tmp_path / 'checkout-key'
    outside.mkdir()
    (outside / 'marker.txt').write_text('outside', encoding='utf-8')

    def misdirect_materialize(repo: str, sha: str) -> Path:
        """Return an identically named path outside the cache.

        Parameters
        ----------
        repo : str
            Ignored repository URL.
        sha : str
            Ignored commit SHA.

        Returns
        -------
        Path
            The outside path.
        """
        del repo, sha
        return outside

    monkeypatch.setattr(store, 'materialize', misdirect_materialize)
    launched: list[tuple[str, ...]] = []

    async def recording_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        del cwd, env
        await asyncio.sleep(0)
        launched.append(tuple(argv))
        return LaunchResult(
            argv=tuple(argv),
            returncode=0,
            stdout='',
            stderr='',
            duration_seconds=0.0,
            timed_out=False,
        )

    project = CorpusProject(
        name='fakeproj',
        repo='https://example.invalid/repo',
        pin='a' * 40,
    )
    runner = PrimerRunner(
        adapter=get_adapter('vulture'),
        store=store,
        isolation=UNENFORCED,
        options=DEFAULT_OPTIONS,
        async_launcher=recording_launcher,
    )
    with pytest.raises(ExceptionGroup) as excinfo:
        runner.run_escape_hatch([project], base_cmd=('detector',), head_cmd=('detector',))
    assert excinfo.group_contains(RunnerError, match='not a checkout cache entry')
    assert launched == []
    assert (outside / 'marker.txt').read_text(encoding='utf-8') == 'outside'


def test_analysis_runs_with_a_scrubbed_environment(
    tmp_path: Path,
    corpus_project: CorpusProject,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Contract §3 trust model: untrusted analysis subprocesses get no
    # credentials — allowlisted variables only, HOME in the workspace.
    monkeypatch.setenv('LP_PLANTED_SECRET', 'boom')
    captured: list[Mapping[str, str] | None] = []

    async def spying_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        captured.append(env)
        return await run_async(list(argv), cwd=cwd, env=env)

    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [])
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [])
    report = spying_runner(tmp_path, spying_launcher).run_escape_hatch(
        [corpus_project], base_cmd=base_cmd, head_cmd=head_cmd
    )
    assert not report_has_failures(report)
    assert len(captured) == 2
    for env in captured:
        assert env is not None
        assert 'LP_PLANTED_SECRET' not in env
        assert 'liveness-primer-side-' in env['HOME']
        assert 'liveness-primer-home-' in env['HOME']


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
    assert report.totals == DiffTotals(new=2, dropped=1)
    assert not report_has_failures(report)
    git_fetches = [record for record in manifest.fetches if record.kind == 'git']
    assert fake_detector_repo in {record.name for record in git_fetches}
    assert corpus_project.repo in {record.name for record in git_fetches}


def test_run_collects_source_evidence_from_pinned_checkout(tmp_path: Path, corpus_project: CorpusProject) -> None:
    # Reporting §3.3 and acceptance 9: the excerpt is the actual pinned
    # source line at the detector-reported location, and unreadable or
    # out-of-range locations produce bounded warnings, not fabricated text.
    report = escape_run(tmp_path, corpus_project, [BASE_FINDING], [MOVED_FINDING, NEW_FINDING])
    (project_report,) = report.projects
    dropped = next(diff for diff in project_report.diffs if diff.diff_class is DiffClass.DROPPED)
    assert dropped.base_occurrence is not None
    excerpt = dropped.base_occurrence.source_excerpt
    assert excerpt is not None
    assert excerpt.start_line == 5
    assert excerpt.lines[0] == 'def unused_helper() -> int:'
    assert excerpt.omitted_lines == 0
    # The moved helper's new side (line 9) is beyond the 6-line file: no
    # excerpt, one bounded warning.
    moved = next(
        diff for diff in project_report.diffs if diff.diff_class is DiffClass.NEW and diff.symbol == 'unused_helper'
    )
    assert moved.head_occurrence is not None
    assert moved.head_occurrence.source_excerpt is None
    assert 'pkg/mod.py:L9: reported line 9 is beyond the end of the file (6 line(s))' in project_report.source_warnings
    assert 'pkg/extra.py: not a regular non-symlink file' in project_report.source_warnings


def test_zero_excerpt_lines_disables_source_collection(tmp_path: Path, corpus_project: CorpusProject) -> None:
    options = RunOptions(jobs=2, timeout=30.0, excerpt_lines=0)
    report = escape_run(tmp_path, corpus_project, [], [BASE_FINDING], options)
    (project_report,) = report.projects
    (new,) = project_report.diffs
    assert new.head_occurrence is not None
    assert new.head_occurrence.source_excerpt is None
    assert project_report.source_warnings == ()


def test_rendered_finding_content_never_leaks_disposable_paths(tmp_path: Path, corpus_project: CorpusProject) -> None:
    # Reporting acceptance 12: no finding row, source excerpt, or source
    # link contains a checkout, cache, or temporary-directory prefix, and no
    # serialized detector record reaches the human output. Trusted manifest
    # argv (the fake detector command) and the local repo URL may.
    report = escape_run(tmp_path, corpus_project, [BASE_FINDING], [MOVED_FINDING, NEW_FINDING])
    text = render_text(report, TextRenderOptions(width=160))
    markdown = render_github(report)
    for rendered, trusted_marker in ((text, 'command:'), (markdown, '**base command**')):
        for line in rendered.splitlines():
            if 'command' in line or line.strip().startswith(('corpus:', '- **corpus**')):
                continue
            assert str(tmp_path) not in line
            assert '/private/var/folders' not in line
            assert '"file"' not in line
        assert trusted_marker in rendered


def skylos_runner(tmp_path: Path) -> PrimerRunner:
    return PrimerRunner(
        adapter=get_adapter('skylos'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=UNENFORCED,
        options=DEFAULT_OPTIONS,
    )


def test_fake_skylos_rule_change_splits_into_dropped_plus_new(tmp_path: Path, corpus_project: CorpusProject) -> None:
    # Reporting acceptance 3, end to end through the skylos adapter: the
    # rule ID is part of the finding identity, so the same target with
    # different explicit rule IDs is a `dropped` plus a `new` finding, as
    # is a bucket move that also changes kind.
    base_cmd = write_fake_detector_script(
        tmp_path / 'sky-base.json',
        [
            FakeFinding(path='pkg/mod.py', line=5, symbol='unused_helper', kind='function', rule_id='SKY-U001'),
            FakeFinding(
                path='pkg/mod.py', line=2, symbol='shifty', kind='variable', bucket='unused_variables', rule_id=None
            ),
        ],
        output_format='skylos',
    )
    head_cmd = write_fake_detector_script(
        tmp_path / 'sky-head.json',
        [
            FakeFinding(path='pkg/mod.py', line=5, symbol='unused_helper', kind='function', rule_id='SKY-U009'),
            FakeFinding(
                path='pkg/mod.py', line=2, symbol='shifty', kind='parameter', bucket='unused_parameters', rule_id=None
            ),
        ],
        output_format='skylos',
    )
    report = skylos_runner(tmp_path).run_escape_hatch([corpus_project], base_cmd=base_cmd, head_cmd=head_cmd)
    (project_report,) = report.projects
    assert project_report.errors == ()
    assert project_report.totals == DiffTotals(new=2, dropped=2)
    renamed = {
        diff.diff_class: diff.reference_occurrence.rule_id
        for diff in project_report.diffs
        if diff.symbol == 'unused_helper'
    }
    assert renamed == {DiffClass.DROPPED: 'SKY-U001', DiffClass.NEW: 'SKY-U009'}
    moved_kinds = {diff.diff_class: diff.kind for diff in project_report.diffs if diff.symbol == 'shifty'}
    assert moved_kinds == {DiffClass.DROPPED: 'variable', DiffClass.NEW: 'parameter'}
    # The bucket mapping stamps the fallback rule IDs on the moved pair.
    assert DiffRollup(diff_class=DiffClass.NEW, rule_id='SKY-U006', kind=None, count=1) in project_report.rollups
    assert DiffRollup(diff_class=DiffClass.DROPPED, rule_id='SKY-U003', kind=None, count=1) in project_report.rollups
    assert report.rollups == project_report.rollups


def test_fake_skylos_unused_file_end_to_end(tmp_path: Path) -> None:
    # A realistic SKY-E002 target: the pinned corpus checkout contains an
    # actually zero-byte file. The file-level finding flows through as one
    # `new` diff that is intentionally source-less — no excerpt, and no
    # source warning spent on the expected emptiness (reporting §3.3).
    origin = create_fake_project(
        tmp_path / 'origin',
        files={'pkg/mod.py': 'used = 1\n', 'pkg/empty.py': ''},
        init_git=True,
    )
    assert origin.head_sha is not None
    project = CorpusProject(name='fakeproj', repo=origin.url, pin=origin.head_sha)
    head_cmd = write_fake_detector_script(
        tmp_path / 'sky-head.json',
        [
            FakeFinding(
                path='pkg/empty.py',
                line=1,
                symbol='pkg/empty.py',
                bucket='unused_files',
                rule_id='SKY-E002',
                severity='LOW',
                message='Empty Python file (no code, or docstring-only)',
            )
        ],
        output_format='skylos',
    )
    base_cmd = write_fake_detector_script(tmp_path / 'sky-base.json', [], output_format='skylos')

    report = skylos_runner(tmp_path).run_escape_hatch(
        [project],
        base_cmd=base_cmd,
        head_cmd=head_cmd,
    )

    (project_report,) = report.projects
    assert project_report.errors == ()
    assert project_report.source_warnings == ()
    assert project_report.totals == DiffTotals(new=1)
    (diff,) = project_report.diffs
    assert diff.path == 'pkg/empty.py'
    assert diff.symbol is None
    assert diff.kind == 'file'
    assert diff.head_occurrence is not None
    assert diff.head_occurrence.message == 'Empty Python file (no code, or docstring-only)'
    assert diff.head_occurrence.rule_id == 'SKY-E002'
    assert diff.head_occurrence.severity == 'LOW'
    assert diff.head_occurrence.source_excerpt is None


def test_fake_skylos_danger_severity_change_end_to_end(tmp_path: Path, corpus_project: CorpusProject) -> None:
    # Reporting acceptance 32, end to end through the skylos adapter's
    # danger ingestion: a severity change pairs as one `changed` diff, and
    # a second security diagnostic on the same line keeps its own identity.
    corpus_project = CorpusProject(
        name=corpus_project.name,
        repo=corpus_project.repo,
        pin=corpus_project.pin,
        tools={'skylos': ToolSettings(analyses=('danger',))},
    )
    base_cmd = write_fake_detector_script(
        tmp_path / 'sky-base.json',
        [
            FakeFinding(
                path='pkg/mod.py',
                line=3,
                symbol='runner',
                bucket='danger',
                rule_id='SKY-D203',
                severity='Medium',
                message='Use of os.system()',
            ),
        ],
        output_format='skylos',
    )
    head_cmd = write_fake_detector_script(
        tmp_path / 'sky-head.json',
        [
            FakeFinding(
                path='pkg/mod.py',
                line=3,
                symbol='runner',
                bucket='danger',
                rule_id='SKY-D203',
                severity='HIGH',
                message='Use of os.system()',
            ),
            FakeFinding(
                path='pkg/mod.py',
                line=3,
                symbol='runner',
                bucket='danger',
                rule_id='SKY-D212',
                severity='CRITICAL',
                message='Possible command injection',
            ),
        ],
        output_format='skylos',
    )
    report = skylos_runner(tmp_path).run_escape_hatch([corpus_project], base_cmd=base_cmd, head_cmd=head_cmd)
    (project_report,) = report.projects
    assert project_report.errors == ()
    assert project_report.totals == DiffTotals(new=1, changed=1, changed_severity_only=1)
    changed = next(diff for diff in project_report.diffs if diff.diff_class is DiffClass.CHANGED)
    assert changed.kind == 'danger'
    assert changed.changed_fields == (ChangedField.SEVERITY,)
    assert changed.base_occurrence is not None
    # The scripted 'Medium' label normalized at the adapter boundary.
    assert changed.base_occurrence.severity == 'MEDIUM'
    assert changed.head_occurrence is not None
    assert changed.head_occurrence.severity == 'HIGH'
    fresh = next(diff for diff in project_report.diffs if diff.diff_class is DiffClass.NEW)
    assert fresh.reference_occurrence.rule_id == 'SKY-D212'
    assert fresh.reference_occurrence.severity == 'CRITICAL'


def test_fake_skylos_analyses_selection_reaches_argv_and_report(tmp_path: Path) -> None:
    # Corpus-selected analyses resolve to the adapter's declared flags in
    # the invocation and are recorded per project in the report (§5).
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    project = CorpusProject(
        name='fakeproj',
        repo=origin.url,
        pin=origin.head_sha,
        tools={'skylos': ToolSettings(analyses=('danger', 'secrets'))},
    )
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [], output_format='skylos')
    head_cmd = write_fake_detector_script(
        tmp_path / 'head.json',
        [FakeFinding(path='pkg/mod.py', line=4, symbol='API_KEY', bucket='secrets', rule_id='SKY-S101')],
        output_format='skylos',
    )
    seen: list[tuple[str, ...]] = []
    environs: list[dict[str, str]] = []

    async def spying_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        seen.append(tuple(argv))
        environs.append(dict(env) if env is not None else {})
        return await run_async(list(argv), cwd=cwd, env=env)

    runner = PrimerRunner(
        adapter=get_adapter('skylos'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=UNENFORCED,
        options=DEFAULT_OPTIONS,
        async_launcher=spying_launcher,
    )
    report = runner.run_escape_hatch([project], base_cmd=base_cmd, head_cmd=head_cmd)
    (project_report,) = report.projects
    assert project_report.errors == ()
    assert project_report.analyses == ('danger', 'secrets')
    assert all(argv[-3:] == ('--danger', '--secrets', '.') for argv in seen)
    # The adapter's invocation environment pins skylos config discovery to
    # the packaged neutral file on both sides (contract §3, §11).
    assert all(environment['SKYLOS_CONFIG_FILE'].endswith('skylos_neutral_config.toml') for environment in environs)
    fresh = next(diff for diff in project_report.diffs if diff.diff_class is DiffClass.NEW)
    assert fresh.kind == 'secret'
    assert fresh.symbol == 'API_KEY'


def write_fake_native_engine(path: Path) -> Path:
    atomic_write_text(path, '#!/bin/sh\nexit 0\n')
    path.chmod(0o755)
    return path


def test_resolve_native_tools_ignores_unset_and_undeclared_variables(tmp_path: Path) -> None:
    # An unset or blank variable leaves the detector's own discovery alone;
    # an adapter that declares no native helper never admits one at all.
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    skylos = get_adapter('skylos')
    assert resolve_native_tools(skylos, {}) == ()
    assert resolve_native_tools(skylos, {'SKYLOS_GO_BIN': '   '}) == ()
    assert resolve_native_tools(get_adapter('vulture'), {'SKYLOS_GO_BIN': str(engine)}) == ()


def test_resolve_native_tools_resolves_path_and_digest(tmp_path: Path) -> None:
    # The detector is handed the symlink-resolved path, and the digest is
    # taken from the file that path names.
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    link = tmp_path / 'link-to-engine'
    link.symlink_to(engine)
    (admitted,) = resolve_native_tools(get_adapter('skylos'), {'SKYLOS_GO_BIN': str(link)})
    assert admitted.variable == 'SKYLOS_GO_BIN'
    assert admitted.path == str(engine.resolve())
    assert admitted.sha256 == hashlib.sha256(engine.read_bytes()).hexdigest()


def test_native_tool_record_withholds_the_host_path(tmp_path: Path) -> None:
    # A report is publishable, so the serialized record carries the digest
    # that identifies the binary but never where it sits on the run host.
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    (admitted,) = resolve_native_tools(get_adapter('skylos'), {'SKYLOS_GO_BIN': str(engine)})
    payload = admitted.record().model_dump(mode='json')
    assert payload == {
        'variable': 'SKYLOS_GO_BIN',
        'sha256': hashlib.sha256(engine.read_bytes()).hexdigest(),
    }
    assert admitted.path not in str(payload)


def test_resolve_native_tools_rejects_a_symlink_swap_after_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    saved_engine = tmp_path / 'original-skylos-go'
    replacement = write_fake_native_engine(tmp_path / 'replacement-skylos-go')
    real_is_file = Path.is_file

    def swap_after_check(self: Path) -> bool:
        is_file = real_is_file(self)
        if self == engine:
            self.replace(saved_engine)
            self.symlink_to(replacement)
        return is_file

    # The hook deterministically schedules a real symlink replacement in the
    # otherwise nondeterministic resolve-to-admission race window.
    monkeypatch.setattr(Path, 'is_file', swap_after_check)
    with pytest.raises(RunnerError, match='native tool is not a regular non-symlink file'):
        resolve_native_tools(get_adapter('skylos'), {'SKYLOS_GO_BIN': str(engine)})


def test_resolve_native_tools_rejects_an_oversized_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    limit = engine.stat().st_size - 1
    # Lowering the production cap avoids constructing a 256 MiB test artifact;
    # the same size comparison and operator-facing error path are exercised.
    monkeypatch.setattr(runner_module, '_MAX_NATIVE_TOOL_BYTES', limit)
    with pytest.raises(RunnerError, match=rf'native tool exceeds {limit} bytes'):
        resolve_native_tools(get_adapter('skylos'), {'SKYLOS_GO_BIN': str(engine)})


def test_executable_digest_rejects_a_changed_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    real_fstat = os.fstat

    def changed_fstat(descriptor: int) -> os.stat_result:
        values = list(real_fstat(descriptor))
        values[stat.ST_INO] += 1
        return os.stat_result(values)

    # A real lstat-to-open replacement race is nondeterministic. Altering only
    # the opened inode pins the identity-mismatch branch; it is not end-to-end
    # evidence that the later subprocess executes the recorded digest.
    monkeypatch.setattr(os, 'fstat', changed_fstat)
    with pytest.raises(RunnerError, match='native tool changed while it was being admitted'):
        resolve_native_tools(get_adapter('skylos'), {'SKYLOS_GO_BIN': str(engine)})


def test_executable_digest_stops_if_the_file_grows_while_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    actual_stat = engine.stat()
    bounded_values = list(actual_stat)
    bounded_values[stat.ST_SIZE] = actual_stat.st_size - 1
    bounded_stat = os.stat_result(bounded_values)
    # A concurrent grow during this short read would be flaky to schedule.
    # Fixed stat results keep the admission checks below the lowered cap while
    # the real stream crosses it, pinning only the post-open growth guard.
    monkeypatch.setattr(Path, 'lstat', lambda _path: bounded_stat)
    monkeypatch.setattr(os, 'fstat', lambda _descriptor: bounded_stat)
    monkeypatch.setattr(runner_module, '_MAX_NATIVE_TOOL_BYTES', actual_stat.st_size - 1)
    with pytest.raises(RunnerError, match='native tool exceeds'):
        resolve_native_tools(get_adapter('skylos'), {'SKYLOS_GO_BIN': str(engine)})


@pytest.mark.parametrize('kind', ['absent', 'plain-file', 'directory'])
def test_resolve_native_tools_rejects_unusable_paths(tmp_path: Path, kind: str) -> None:
    # A wrong path must stop the run here: silently falling through would
    # leave both sides analyzing Go sources incompletely.
    target = tmp_path / 'unusable-native-tool'
    if kind == 'plain-file':
        atomic_write_text(target, 'not executable\n')
    elif kind == 'directory':
        target.mkdir()
    with pytest.raises(RunnerError, match='SKYLOS_GO_BIN does not name'):
        resolve_native_tools(get_adapter('skylos'), {'SKYLOS_GO_BIN': str(target)})


def test_declared_native_tool_reaches_both_sides_and_the_manifest(tmp_path: Path) -> None:
    # The operator-supplied engine is layered over the scrubbed environment
    # of both invocations — the scrub drops it otherwise — and the manifest
    # records exactly which binary the sides shared (contract §3, §11).
    origin = create_fake_project(tmp_path / 'origin', init_git=True)
    assert origin.head_sha is not None
    project = CorpusProject(name='fakeproj', repo=origin.url, pin=origin.head_sha)
    base_cmd = write_fake_detector_script(tmp_path / 'base.json', [], output_format='skylos')
    head_cmd = write_fake_detector_script(tmp_path / 'head.json', [], output_format='skylos')
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    environs: list[dict[str, str]] = []

    async def spying_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        environs.append(dict(env) if env is not None else {})
        return await run_async(list(argv), cwd=cwd, env=env)

    runner = PrimerRunner(
        adapter=get_adapter('skylos'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=UNENFORCED,
        options=DEFAULT_OPTIONS,
        async_launcher=spying_launcher,
        environ={'SKYLOS_GO_BIN': str(engine)},
    )
    report = runner.run_escape_hatch([project], base_cmd=base_cmd, head_cmd=head_cmd)
    assert len(environs) == 2
    assert all(environment['SKYLOS_GO_BIN'] == str(engine.resolve()) for environment in environs)
    (record,) = report.manifest.native_tools
    assert record.variable == 'SKYLOS_GO_BIN'
    assert record.sha256 == hashlib.sha256(engine.read_bytes()).hexdigest()


def test_runner_reads_the_process_environment_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The CLI passes no explicit environment, so an operator exporting the
    # variable before the run is what the default path must pick up.
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    monkeypatch.setenv('SKYLOS_GO_BIN', str(engine))
    runner = PrimerRunner(
        adapter=get_adapter('skylos'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=UNENFORCED,
        options=DEFAULT_OPTIONS,
    )
    manifest = runner.run_escape_hatch([], base_cmd=('true',), head_cmd=('true',)).manifest
    (record,) = manifest.native_tools
    assert record.sha256 == hashlib.sha256(engine.read_bytes()).hexdigest()


def test_container_run_end_to_end(tmp_path: Path, corpus_project: CorpusProject, fake_detector_repo: str) -> None:
    # A non-default client binary must reach every per-invocation exec, not
    # only the image builds (contract §15).
    docker = FakeDocker(binary='podman')
    environments = ContainerEnvironments(CheckoutStore(tmp_path / 'cache'), tmp_path / 'cache', docker=docker)
    events = docker.events
    exec_argvs: list[tuple[str, ...]] = []

    async def docker_exec_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        # The docker client is trusted host code: no scrub, no cwd — the
        # workdir and environment live inside the exec argv (contract §3).
        assert cwd is None
        assert env is None
        await asyncio.sleep(0)
        container_name = argv[argv.index('--name') + 1]
        events.append(f'exec:{container_name}')
        exec_argvs.append(tuple(argv))
        volume = argv[argv.index('--volume') + 1]
        host_root = Path(volume.split(':', maxsplit=1)[0])
        home_entry = next(entry for entry in argv if entry.startswith('HOME='))
        container_home = PurePosixPath(home_entry.removeprefix('HOME='))
        relative_home = container_home.relative_to(CONTAINER_WORK_ROOT)
        assert host_root.joinpath(*relative_home.parts).is_dir()
        if any(element.endswith('-base') for element in argv):
            stdout = "pkg/mod.py:5: unused function 'unused_helper' (60% confidence)\n"
        else:
            stdout = (
                "pkg/mod.py:9: unused function 'unused_helper' (60% confidence)\n"
                "pkg/extra.py:2: unused variable 'fresh' (100% confidence)\n"
            )
        return LaunchResult(
            argv=tuple(argv),
            returncode=3,
            stdout=stdout,
            stderr='',
            duration_seconds=0.0,
            timed_out=False,
        )

    runner = PrimerRunner(
        adapter=get_adapter('vulture'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=CONTAINER_ISOLATION,
        options=DEFAULT_OPTIONS,
        async_launcher=docker_exec_launcher,
    )
    report = runner.run_container(
        [corpus_project],
        detector_repo=fake_detector_repo,
        base_ref='base-branch',
        head_ref='head-branch',
        environments=environments,
    )
    assert report.totals == DiffTotals(new=2, dropped=1)
    assert not report_has_failures(report)
    manifest = report.manifest
    assert manifest.comparable is True
    assert manifest.isolation_enforced is True
    assert manifest.installer == (
        f'docker 99.9; builder {DEFAULT_CONTAINER_BUILDER_IMAGE}; runtime {DEFAULT_CONTAINER_IMAGE}'
    )
    # The manifest records the container interpreter, not the host's.
    assert manifest.python_version == '3.14.99'
    assert manifest.platform == 'linux-aarch64'
    assert manifest.base is not None
    assert manifest.head is not None
    assert manifest.base.sha != manifest.head.sha
    assert manifest.base.ref == 'base-branch'
    # Both invocations were named containers with per-side workspace mounts,
    # running the console script from the environment image's PATH.
    assert len(exec_argvs) == 2
    for argv in exec_argvs:
        assert argv[:2] == ('podman', 'run')
        assert argv[argv.index('--network') + 1] == 'none'
        workdir = argv[argv.index('--workdir') + 1]
        assert workdir.startswith('/liveness/work/liveness-primer-side-')
        assert workdir.endswith('/checkout')
        home = argv[argv.index('--env') + 1]
        assert home.startswith('HOME=/liveness/work/liveness-primer-side-')
        assert '/liveness-primer-home-' in home
        assert argv[-2:] == ('vulture', '.')
    # Both invocation containers were removed after their detector launch
    # and before the report could be assembled (contract §3, §11).
    container_names = {argv[argv.index('--name') + 1] for argv in exec_argvs}
    assert {event.removeprefix('rm:') for event in events if event.startswith('rm:')} == container_names
    for name in container_names:
        assert events.index(f'exec:{name}') < events.index(f'rm:{name}')


def test_container_timeout_force_removes_each_invocation(
    tmp_path: Path, corpus_project: CorpusProject, fake_detector_repo: str
) -> None:
    project = corpus_project.model_copy(update={'tools': {'vulture': ToolSettings(timeout=0.05)}})
    docker = WorkspaceCheckingDocker()
    environments = ContainerEnvironments(CheckoutStore(tmp_path / 'cache'), tmp_path / 'cache', docker=docker)
    launches: list[tuple[str, ...]] = []
    cancelled: list[str] = []

    async def hanging_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        del cwd, env
        launched = tuple(argv)
        launches.append(launched)
        name = launched[launched.index('--name') + 1]
        volume = launched[launched.index('--volume') + 1]
        side_root = Path(volume.split(':', maxsplit=1)[0])
        workdir = PurePosixPath(launched[launched.index('--workdir') + 1])
        docker.invocation_workspaces[name] = side_root / workdir.relative_to(CONTAINER_WORK_ROOT).parts[0]
        try:
            await asyncio.sleep(30.0)
        except asyncio.CancelledError:
            cancelled.append(name)
            raise
        msg = 'timeout did not cancel the attached container client'
        raise AssertionError(msg)

    runner = PrimerRunner(
        adapter=get_adapter('vulture'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=CONTAINER_ISOLATION,
        options=DEFAULT_OPTIONS,
        async_launcher=hanging_launcher,
    )
    report = runner.run_container(
        [project],
        detector_repo=fake_detector_repo,
        base_ref='base-branch',
        head_ref='head-branch',
        environments=environments,
    )
    (project_report,) = report.projects
    assert len(project_report.errors) == 2
    assert all(error.exit_code is None for error in project_report.errors)
    assert all('timed out after 0.05s' in error.detail for error in project_report.errors)
    names = {argv[argv.index('--name') + 1] for argv in launches}
    assert set(cancelled) == names
    assert set(docker.removed) == names
    assert len(docker.removed) == 2
    assert docker.workspace_existed_at_removal == [True, True]


def test_container_run_stages_the_skylos_neutral_config(
    tmp_path: Path, corpus_project: CorpusProject, fake_detector_repo: str
) -> None:
    # The packaged neutral config is a host file the containers cannot see:
    # each side gets an identical staged copy under its own mount, and every
    # exec points SKYLOS_CONFIG_FILE at the container-side path (§3, §11).
    docker = FakeDocker()
    environments = ContainerEnvironments(CheckoutStore(tmp_path / 'cache'), tmp_path / 'cache', docker=docker)
    exec_argvs: list[tuple[str, ...]] = []

    async def docker_exec_launcher(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> LaunchResult:
        del cwd, env
        await asyncio.sleep(0)
        exec_argvs.append(tuple(argv))
        # The staged copy exists under the invocation's side mount.
        volume = argv[argv.index('--volume') + 1]
        work_root, temporary_root = await asyncio.gather(
            asyncio.to_thread(Path(volume.split(':', maxsplit=1)[0]).resolve),
            asyncio.to_thread(Path(tempfile.gettempdir()).resolve),
        )
        relative_root = work_root.relative_to(temporary_root)
        assert len(relative_root.parts) == 2
        run_name, side = relative_root.parts
        assert run_name.startswith('liveness-primer-run-')
        assert side in {'base', 'head'}
        trusted_work_root = await asyncio.to_thread(contained_path, temporary_root, str(relative_root))
        staged = await asyncio.to_thread(
            contained_path,
            trusted_work_root,
            'invocation-env/SKYLOS_CONFIG_FILE/skylos_neutral_config.toml',
        )
        assert '[skylos]' in await asyncio.to_thread(read_small_text, staged, max_bytes=4096)
        return LaunchResult(
            argv=tuple(argv), returncode=0, stdout='{}', stderr='', duration_seconds=0.0, timed_out=False
        )

    runner = PrimerRunner(
        adapter=get_adapter('skylos'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=CONTAINER_ISOLATION,
        options=DEFAULT_OPTIONS,
        async_launcher=docker_exec_launcher,
    )
    report = runner.run_container(
        [corpus_project],
        detector_repo=fake_detector_repo,
        base_ref='base-branch',
        head_ref='head-branch',
        environments=environments,
    )
    assert not report_has_failures(report)
    assert len(docker.ripgrep_prefetches) == 1
    container_path = '/liveness/work/invocation-env/SKYLOS_CONFIG_FILE/skylos_neutral_config.toml'
    assert len(exec_argvs) == 2
    for argv in exec_argvs:
        assert f'SKYLOS_CONFIG_FILE={container_path}' in argv
        assert 'SKYLOS_GREP_BUDGET=150' in argv


def test_container_run_refuses_native_helper_passthrough(tmp_path: Path) -> None:
    # A host executable cannot run inside the Linux container, so admitting
    # one would silently degrade both sides' analysis (contract §3).
    engine = write_fake_native_engine(tmp_path / 'skylos-go')
    docker = FakeDocker()
    environments = ContainerEnvironments(CheckoutStore(tmp_path / 'cache'), tmp_path / 'cache', docker=docker)
    runner = PrimerRunner(
        adapter=get_adapter('skylos'),
        store=CheckoutStore(tmp_path / 'cache'),
        isolation=CONTAINER_ISOLATION,
        options=DEFAULT_OPTIONS,
        environ={'SKYLOS_GO_BIN': str(engine)},
    )
    with pytest.raises(RunnerError, match=r'SKYLOS_GO_BIN.*not supported in --container mode'):
        runner.run_container(
            [],
            detector_repo='https://example.invalid/repo',
            base_ref='a',
            head_ref='b',
            environments=environments,
        )
    assert docker.events == []
