"""The two-revision runner: fetch, build, and analysis steps (contract §3).

Copyright (C) 2026 Matthew C. Digman

Corpus refs are resolved once per run and then pinned; both detector
revisions analyze byte-identical checkouts. ``asyncio`` orchestrates
per-project subprocesses under the ``--jobs`` limit with per-(project, tool)
timeouts; analysis-step subprocesses run under the §11 network isolation.
"""

import asyncio
import inspect
import platform
import shutil
import sysconfig
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from liveness_primer.config import CorpusProject, ToolSettings
from liveness_primer.corpus import CheckoutStore
from liveness_primer.diffing import diff_findings, merge_rollups
from liveness_primer.envcache import DetectorEnvironments, PreparedPair
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.findings import (
    CorpusIntegrityWarning,
    CorpusPinRecord,
    DiffClass,
    DiffTotals,
    FetchRecord,
    Finding,
    ProjectReport,
    Report,
    RunManifest,
    RunSettings,
    ToolError,
)
from liveness_primer.isolation import Isolation, scrubbed_environment
from liveness_primer.launcher import AsyncLauncher, LaunchResult, run_async
from liveness_primer.locators import attach_locators
from liveness_primer.report.source import collect_source_evidence
from liveness_primer.tools.base import AdapterError, DetectorAdapter, RawToolOutput, build_invocation

GATE_CHOICES = ('new', 'dropped', 'changed', 'any', 'corpus-integrity')

_STDERR_SNIPPET = 500


class RunnerError(LivenessPrimerError):
    """Raised when a run is misconfigured."""


@dataclass(frozen=True, slots=True)
class RunOptions:
    """Effective run options (contract §12).

    Attributes
    ----------
    jobs : int
        Maximum concurrent detector subprocesses.
    timeout : float
        Default per-(project, tool) timeout in seconds (contract §3).
    max_results : int
        Per-project cap on rendered finding diffs (contract §8).
    excerpt_lines : int
        Pinned-source evidence lines stored and rendered per occurrence;
        ``0`` disables source excerpts (reporting contract §3.3).
    fail_on : tuple[str, ...]
        Enabled ``--fail-on`` gates.
    fresh : bool
        Whether environment rebuilds were forced.
    """

    jobs: int = 2
    timeout: float = 300.0
    max_results: int = 200
    excerpt_lines: int = 5
    fail_on: tuple[str, ...] = ()
    fresh: bool = False

    def __post_init__(self) -> None:
        """Reject unusable resource limits at the typed boundary (contract §12).

        Raises
        ------
        RunnerError
            If a limit is zero, negative, or otherwise unusable.
        """
        problems: list[str] = []
        if self.jobs < 1:
            problems.append(f'jobs must be at least 1, got {self.jobs}')
        if not self.timeout > 0:
            problems.append(f'timeout must be positive, got {self.timeout}')
        if self.max_results < 1:
            problems.append(f'max_results must be at least 1, got {self.max_results}')
        if self.excerpt_lines < 0:
            problems.append(f'excerpt_lines must not be negative, got {self.excerpt_lines}')
        if problems:
            raise RunnerError('; '.join(problems))


@dataclass(frozen=True, slots=True)
class _ProjectWork:
    """One project's analysis inputs.

    Attributes
    ----------
    project : CorpusProject
        The corpus entry.
    settings : ToolSettings
        Per-(project, tool) table.
    pin : CorpusPinRecord
        Resolved pin.
    checkout : Path
        Materialized checkout both sides analyze.
    """

    project: CorpusProject
    settings: ToolSettings
    pin: CorpusPinRecord
    checkout: Path


@dataclass(frozen=True, slots=True)
class _SideOutcome:
    """Outcome of one detector invocation on one side.

    Attributes
    ----------
    side : str
        ``base`` or ``head``.
    findings : tuple[Finding, ...] | None
        Parsed findings; ``None`` when the invocation failed.
    error : ToolError | None
        The failure, when the invocation failed.
    duration_seconds : float
        Wall-clock duration of the invocation.
    returncode : int | None
        Detector exit code; ``None`` on timeout.
    """

    side: str
    findings: tuple[Finding, ...] | None
    error: ToolError | None
    duration_seconds: float
    returncode: int | None


def _integrity_warnings(
    item: _ProjectWork,
    base: _SideOutcome,
    *,
    tool: str,
) -> tuple[CorpusIntegrityWarning, ...]:
    """Check the expected-clean rule on the base side (contract §5).

    Findings or a nonzero tool exit on the base side of an expected-clean
    (project, tool) pair are corpus-integrity warnings; the comparison still
    runs.

    Parameters
    ----------
    item : _ProjectWork
        The project inputs.
    base : _SideOutcome
        Base-side outcome.
    tool : str
        Adapter name.

    Returns
    -------
    tuple[CorpusIntegrityWarning, ...]
        At most one warning describing the violation.
    """
    if not item.settings.expected_clean:
        return ()
    observations: list[str] = []
    if base.findings:
        observations.append(f'{len(base.findings)} finding(s)')
    if base.returncode != 0:
        code = 'timeout' if base.returncode is None else str(base.returncode)
        observations.append(f'exit code {code}')
    if not observations:
        return ()
    detail = f'expected-clean base side reported {" and ".join(observations)}'
    return (CorpusIntegrityWarning(project=item.project.name, tool=tool, detail=detail),)


def _assemble_report(manifest: RunManifest, project_reports: Sequence[ProjectReport]) -> Report:
    """Assemble the full report with overall totals (contract §8, §9).

    Parameters
    ----------
    manifest : RunManifest
        The run manifest.
    project_reports : Sequence[ProjectReport]
        Per-project reports in run order.

    Returns
    -------
    Report
        The blast radius.
    """
    totals = DiffTotals(
        new=sum(entry.totals.new for entry in project_reports),
        dropped=sum(entry.totals.dropped for entry in project_reports),
        changed=sum(entry.totals.changed for entry in project_reports),
        changed_confidence_only=sum(entry.totals.changed_confidence_only for entry in project_reports),
        changed_message_only=sum(entry.totals.changed_message_only for entry in project_reports),
        changed_severity_only=sum(entry.totals.changed_severity_only for entry in project_reports),
    )
    return Report(
        manifest=manifest,
        projects=tuple(project_reports),
        totals=totals,
        rollups=merge_rollups(entry.rollups for entry in project_reports),
        truncated=any(entry.truncated for entry in project_reports),
    )


@dataclass(frozen=True, slots=True)
class _SideWorkspace:
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


class PrimerRunner:
    """Runs one two-revision comparison over selected corpus projects.

    Parameters
    ----------
    adapter : DetectorAdapter
        Adapter of the tool under test.
    store : CheckoutStore
        Checkout store for corpus repositories.
    isolation : Isolation
        Network isolation for analysis subprocesses (contract §11).
    options : RunOptions
        Effective run options.
    async_launcher : AsyncLauncher
        Audited launcher for detector invocations (contract §11).

    Raises
    ------
    RunnerError
        If ``async_launcher`` is not an asynchronous callable.
    """

    def __init__(
        self,
        *,
        adapter: DetectorAdapter,
        store: CheckoutStore,
        isolation: Isolation,
        options: RunOptions,
        async_launcher: AsyncLauncher = run_async,
    ) -> None:
        if not inspect.iscoroutinefunction(async_launcher) and not inspect.iscoroutinefunction(
            type(async_launcher).__call__
        ):
            msg = 'async_launcher must be an asynchronous callable'
            raise RunnerError(msg)
        self._adapter = adapter
        self._store = store
        self._checkout_root = store.checkout_root
        self._isolation = isolation
        self._options = options
        self._async_launcher = async_launcher

    def _materialize_side(self, checkout: Path) -> _SideWorkspace:
        """Give one detector invocation its own disposable checkout copy.

        Both sides derive from the same pinned cache entry, so the copies are
        byte-identical (contract §3) — but neither side can influence the other
        (or a later run) through writes to a shared working tree, and the
        detector's scratch ``HOME`` lives and dies with the workspace.

        Parameters
        ----------
        checkout : Path
            Pinned cached checkout to copy.

        Returns
        -------
        _SideWorkspace
            The materialized workspace.

        Raises
        ------
        RunnerError
            If the checkout is not a direct child of the checkout cache.
        """
        # Only the pinned cache is ever copied: re-anchoring the name under the
        # cache root keeps a misdirected checkout from reaching the detector.
        source = self._checkout_root / Path(checkout).name
        if source != checkout:
            msg = f'refusing to copy {checkout}: not a checkout cache entry'
            raise RunnerError(msg)
        root = Path(tempfile.mkdtemp(prefix='liveness-primer-side-'))
        side_checkout = root / 'checkout'
        # Symlinks are copied as symlinks: following them could pull content
        # from outside the pinned tree into the analyzed copy.
        shutil.copytree(source, side_checkout, symlinks=True, ignore=shutil.ignore_patterns('.git'))
        home = root / 'home'
        home.mkdir()
        return _SideWorkspace(root=root, checkout=side_checkout, home=home)

    def _fetch_corpus(self, projects: Sequence[CorpusProject]) -> tuple[list[_ProjectWork], tuple[FetchRecord, ...]]:
        """Resolve and materialize every selected project (fetch step, §3).

        Parameters
        ----------
        projects : Sequence[CorpusProject]
            Selected corpus projects.

        Returns
        -------
        tuple[list[_ProjectWork], tuple[FetchRecord, ...]]
            Per-project work items plus corpus fetch records.
        """
        work: list[_ProjectWork] = []
        fetches: dict[tuple[str, str], FetchRecord] = {}
        for project in projects:
            pin = self._store.resolve_project(project)
            checkout = self._store.materialize(project.repo, pin.resolved_sha)
            key = (project.repo, pin.resolved_sha)
            if key not in fetches:
                fetches[key] = FetchRecord(kind='git', name=project.repo, resolved=pin.resolved_sha)
            work.append(
                _ProjectWork(
                    project=project,
                    settings=project.tool_settings(self._adapter.name),
                    pin=pin,
                    checkout=checkout,
                )
            )
        return work, tuple(fetches.values())

    def _parse_outcome(self, item: _ProjectWork, *, side: str, result: LaunchResult, root: Path) -> _SideOutcome:
        """Turn one captured detector invocation into a side outcome.

        Parameters
        ----------
        item : _ProjectWork
            The project inputs.
        side : str
            ``base`` or ``head``.
        result : LaunchResult
            The captured launch.
        root : Path
            Checkout copy the detector analyzed, for path normalization.

        Returns
        -------
        _SideOutcome
            The parsed outcome.
        """
        if result.returncode not in self._adapter.success_exit_codes:
            detail = f'exit code {result.returncode}: {result.stderr.strip()[-_STDERR_SNIPPET:]}'
            error = ToolError(side=side, exit_code=result.returncode, detail=detail)
            return _SideOutcome(
                side=side,
                findings=None,
                error=error,
                duration_seconds=result.duration_seconds,
                returncode=result.returncode,
            )
        raw = RawToolOutput(
            returncode=result.returncode if result.returncode is not None else 0,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        try:
            findings = self._adapter.parse(raw, project=item.project.name, root=root, analyses=item.settings.analyses)
        except AdapterError as exc:
            error = ToolError(side=side, exit_code=result.returncode, detail=str(exc))
            return _SideOutcome(
                side=side,
                findings=None,
                error=error,
                duration_seconds=result.duration_seconds,
                returncode=result.returncode,
            )
        return _SideOutcome(
            side=side,
            findings=tuple(findings),
            error=None,
            duration_seconds=result.duration_seconds,
            returncode=result.returncode,
        )

    async def _invoke(
        self,
        item: _ProjectWork,
        *,
        side: str,
        command: tuple[str, ...],
        semaphore: asyncio.Semaphore,
    ) -> _SideOutcome:
        """Run the detector once on one side of one project (analysis step, §3).

        Parameters
        ----------
        item : _ProjectWork
            The project inputs.
        side : str
            ``base`` or ``head``.
        command : tuple[str, ...]
            Detector command prefix for this side.
        semaphore : asyncio.Semaphore
            The ``--jobs`` limiter.

        Returns
        -------
        _SideOutcome
            The captured, parsed outcome.
        """
        argv = build_invocation(self._adapter, command, item.settings)
        timeout = item.settings.timeout if item.settings.timeout is not None else self._options.timeout
        async with semaphore:
            # Each side analyzes its own disposable copy of the pinned
            # checkout under a scrubbed, credential-free environment
            # (contract §3, §11).
            workspace = await asyncio.to_thread(self._materialize_side, item.checkout)
            try:
                environment = scrubbed_environment(home=workspace.home)
                try:
                    async with asyncio.timeout(timeout):
                        result = await self._async_launcher(
                            self._isolation.wrap(argv),
                            cwd=workspace.checkout,
                            env=environment,
                        )
                except TimeoutError:
                    error = ToolError(side=side, exit_code=None, detail=f'timed out after {timeout:g}s')
                    return _SideOutcome(
                        side=side,
                        findings=None,
                        error=error,
                        duration_seconds=timeout,
                        returncode=None,
                    )
                return self._parse_outcome(item, side=side, result=result, root=workspace.checkout)
            finally:
                await asyncio.to_thread(shutil.rmtree, workspace.root, ignore_errors=True)

    def _project_report(self, item: _ProjectWork, base: _SideOutcome, head: _SideOutcome) -> ProjectReport:
        """Assemble one project report from both side outcomes.

        Parameters
        ----------
        item : _ProjectWork
            The project inputs.
        base : _SideOutcome
            Base-side outcome.
        head : _SideOutcome
            Head-side outcome.

        Returns
        -------
        ProjectReport
            Diffs (when both sides completed), totals, errors, and
            corpus-integrity warnings (contract §5, §8).
        """
        errors = tuple(outcome.error for outcome in (base, head) if outcome.error is not None)
        integrity = _integrity_warnings(item, base, tool=self._adapter.name)
        source_warnings: tuple[str, ...] = ()
        if base.findings is not None and head.findings is not None:
            outcome = diff_findings(
                base.findings,
                head.findings,
                confidence_capable=self._adapter.capabilities.has_confidence,
                severity_capable=self._adapter.capabilities.has_severity,
            )
            # Locators index the complete canonical sequence before
            # truncation, so retained indices match it (explorer §4.2).
            located = attach_locators(item.project.name, outcome.diffs)
            truncated = len(located) > self._options.max_results
            # Source evidence is read from the pinned corpus checkout for
            # the retained diffs only, after truncation (reporting §3.3).
            diffs, source_warnings = collect_source_evidence(
                located[: self._options.max_results],
                checkout=item.checkout,
                excerpt_lines=self._options.excerpt_lines,
            )
            totals = outcome.totals
            rollups = outcome.rollups
            measured: float | None = base.duration_seconds + head.duration_seconds
        else:
            truncated = False
            diffs = ()
            totals = DiffTotals()
            rollups = ()
            measured = None
        return ProjectReport(
            project=item.project.name,
            diffs=diffs,
            totals=totals,
            rollups=rollups,
            truncated=truncated,
            base_findings=len(base.findings) if base.findings is not None else 0,
            head_findings=len(head.findings) if head.findings is not None else 0,
            measured_cost_seconds=measured,
            errors=errors,
            integrity_warnings=integrity,
            source_warnings=source_warnings,
            analyses=item.settings.analyses,
        )

    async def _analyze_project(
        self,
        item: _ProjectWork,
        *,
        semaphore: asyncio.Semaphore,
        base_command: tuple[str, ...],
        head_command: tuple[str, ...],
    ) -> ProjectReport:
        """Analyze one project on both sides and diff the outcomes.

        Parameters
        ----------
        item : _ProjectWork
            The project inputs.
        semaphore : asyncio.Semaphore
            The ``--jobs`` limiter.
        base_command : tuple[str, ...]
            Base detector command prefix.
        head_command : tuple[str, ...]
            Head detector command prefix.

        Returns
        -------
        ProjectReport
            The per-project slice of the blast radius.
        """
        async with asyncio.TaskGroup() as group:
            base_task = group.create_task(self._invoke(item, side='base', command=base_command, semaphore=semaphore))
            head_task = group.create_task(self._invoke(item, side='head', command=head_command, semaphore=semaphore))
        return self._project_report(item, base_task.result(), head_task.result())

    async def _analyze_all(
        self,
        work: Sequence[_ProjectWork],
        *,
        base_command: tuple[str, ...],
        head_command: tuple[str, ...],
    ) -> tuple[ProjectReport, ...]:
        """Fan analysis out over projects under the jobs limit (contract §3).

        Parameters
        ----------
        work : Sequence[_ProjectWork]
            Per-project inputs.
        base_command : tuple[str, ...]
            Base detector command prefix.
        head_command : tuple[str, ...]
            Head detector command prefix.

        Returns
        -------
        tuple[ProjectReport, ...]
            Reports in run order.
        """
        semaphore = asyncio.Semaphore(self._options.jobs)
        async with asyncio.TaskGroup() as group:
            tasks = [
                group.create_task(
                    self._analyze_project(
                        item,
                        semaphore=semaphore,
                        base_command=base_command,
                        head_command=head_command,
                    )
                )
                for item in work
            ]
        return tuple(task.result() for task in tasks)

    def _manifest(
        self,
        *,
        detector_repo: str | None,
        pair: PreparedPair | None,
        base_cmd: tuple[str, ...] | None,
        head_cmd: tuple[str, ...] | None,
        fetches: tuple[FetchRecord, ...],
        pins: tuple[CorpusPinRecord, ...],
    ) -> RunManifest:
        """Assemble the run manifest (contract §2, §3).

        Parameters
        ----------
        detector_repo : str | None
            Detector repository URL; absent for escape-hatch runs.
        pair : PreparedPair | None
            Prepared environments; absent for escape-hatch runs.
        base_cmd : tuple[str, ...] | None
            Escape-hatch base command.
        head_cmd : tuple[str, ...] | None
            Escape-hatch head command.
        fetches : tuple[FetchRecord, ...]
            Every fetch performed during the run.
        pins : tuple[CorpusPinRecord, ...]
            Resolved corpus pins.

        Returns
        -------
        RunManifest
            The manifest; ``comparable`` is false only for unmanaged
            escape-hatch runs (contract §3).
        """
        options = self._options
        return RunManifest(
            created_at=datetime.now(tz=UTC),
            tool=self._adapter.name,
            detector_repo=detector_repo,
            base=pair.base.record if pair is not None else None,
            head=pair.head.record if pair is not None else None,
            base_cmd=base_cmd,
            head_cmd=head_cmd,
            comparable=pair is not None,
            environment_delta=pair.environment_delta if pair is not None else (),
            isolation_enforced=self._isolation.enforced,
            platform=sysconfig.get_platform(),
            python_version=platform.python_version(),
            installer=pair.installer_identity if pair is not None else None,
            fetches=fetches,
            corpus_pins=pins,
            settings=RunSettings(
                jobs=options.jobs,
                timeout=options.timeout,
                max_results=options.max_results,
                excerpt_lines=options.excerpt_lines,
                fail_on=options.fail_on,
                selection=tuple(pin.name for pin in pins),
            ),
        )

    def run_managed(
        self,
        projects: Sequence[CorpusProject],
        *,
        detector_repo: str,
        base_ref: str,
        head_ref: str,
        environments: DetectorEnvironments,
    ) -> Report:
        """Run the primer with managed detector environments (contract §3).

        Parameters
        ----------
        projects : Sequence[CorpusProject]
            Selected corpus projects, in run order.
        detector_repo : str
            Detector repository URL.
        base_ref : str
            Base detector ref.
        head_ref : str
            Head detector ref.
        environments : DetectorEnvironments
            Environment cache building both refs.

        Returns
        -------
        Report
            The blast radius.
        """
        # The pair's environment locks stay held until analysis completes,
        # so a concurrent --fresh rebuild cannot delete an environment in
        # use (contract §3).
        with environments.prepare_pair(detector_repo, base_ref, head_ref, self._adapter) as pair:
            work, corpus_fetches = self._fetch_corpus(projects)
            project_reports = asyncio.run(
                self._analyze_all(work, base_command=(pair.base.executable,), head_command=(pair.head.executable,))
            )
        manifest = self._manifest(
            detector_repo=detector_repo,
            pair=pair,
            base_cmd=None,
            head_cmd=None,
            fetches=(*pair.fetches, *corpus_fetches),
            pins=tuple(item.pin for item in work),
        )
        return _assemble_report(manifest, project_reports)

    def run_escape_hatch(
        self,
        projects: Sequence[CorpusProject],
        *,
        base_cmd: Sequence[str],
        head_cmd: Sequence[str],
    ) -> Report:
        """Run the primer against pre-built detector commands (contract §3).

        Escape-hatch runs are unmanaged and therefore not comparable;
        ``--fail-on`` gating refuses to act on them (contract §3).

        Parameters
        ----------
        projects : Sequence[CorpusProject]
            Selected corpus projects, in run order.
        base_cmd : Sequence[str]
            Base detector command (``--old-cmd``), a typed argv list.
        head_cmd : Sequence[str]
            Head detector command (``--new-cmd``), a typed argv list.

        Returns
        -------
        Report
            The blast radius.
        """
        work, corpus_fetches = self._fetch_corpus(projects)
        project_reports = asyncio.run(
            self._analyze_all(work, base_command=tuple(base_cmd), head_command=tuple(head_cmd))
        )
        manifest = self._manifest(
            detector_repo=None,
            pair=None,
            base_cmd=tuple(base_cmd),
            head_cmd=tuple(head_cmd),
            fetches=corpus_fetches,
            pins=tuple(item.pin for item in work),
        )
        return _assemble_report(manifest, project_reports)


def report_has_failures(report: Report) -> bool:
    """Report whether any detector invocation failed (run failure, §9).

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    bool
        True when any project recorded a tool error.
    """
    return any(project.errors for project in report.projects)


def evaluate_gates(report: Report, fail_on: Sequence[str]) -> tuple[str, ...]:
    """Evaluate the opt-in ``--fail-on`` gates (contract §9).

    ``any`` covers the three diff classes, not ``corpus-integrity``. Gating
    refuses to act on non-comparable runs (contract §3).

    Parameters
    ----------
    report : Report
        The assembled report.
    fail_on : Sequence[str]
        Enabled gates.

    Returns
    -------
    tuple[str, ...]
        Human-readable descriptions of the gates that fired.

    Raises
    ------
    RunnerError
        If gating is requested for a non-comparable run.
    """
    if not fail_on:
        return ()
    if not report.manifest.comparable:
        msg = '--fail-on refuses to act on a non-comparable (escape-hatch) run (§3)'
        raise RunnerError(msg)
    enabled = set(fail_on)
    fired: list[str] = []
    totals = report.totals
    by_class = {
        DiffClass.NEW.value: totals.new,
        DiffClass.DROPPED.value: totals.dropped,
        DiffClass.CHANGED.value: totals.changed,
    }
    for name, count in by_class.items():
        if count and (name in enabled or 'any' in enabled):
            fired.append(f'{name}: {count}')
    integrity = sum(len(project.integrity_warnings) for project in report.projects)
    if integrity and 'corpus-integrity' in enabled:
        fired.append(f'corpus-integrity: {integrity}')
    return tuple(fired)
