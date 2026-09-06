# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""The two-revision runner: fetch, build, and analysis steps (contract §3).

Corpus refs are resolved once per run and then pinned; both detector
revisions analyze byte-identical checkouts. ``asyncio`` orchestrates
per-project subprocesses under the ``--jobs`` limit with per-(project, tool)
timeouts; analysis-step subprocesses run under the §11 network isolation.
"""

import asyncio
import hashlib
import inspect
import os
import platform
import shutil
import stat
import sysconfig
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePath

from liveness_primer.config import CorpusProject, ToolSettings
from liveness_primer.container import (
    ContainerEnvironments,
    ContainerExecution,
    ContainerNativeTool,
    PreparedContainerPair,
    container_user,
    stage_invocation_env_files,
)
from liveness_primer.corpus import CheckoutStore
from liveness_primer.diffing import diff_findings, merge_rollups
from liveness_primer.envcache import DetectorEnvironments, PreparedPair
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.execution import ExecutionBackend, HostExecution, SideName, SideWorkspace
from liveness_primer.findings import (
    CorpusIntegrityWarning,
    CorpusPinRecord,
    DiffClass,
    DiffTotals,
    FetchRecord,
    Finding,
    NativeToolRecord,
    ProjectReport,
    Report,
    RunManifest,
    RunSettings,
    ToolError,
)
from liveness_primer.isolation import Isolation
from liveness_primer.launcher import AsyncLauncher, LaunchResult, run_async
from liveness_primer.locators import attach_locators
from liveness_primer.report.sanitize import FAILURE_DETAIL_PART_CAP, truncate_end, truncate_start
from liveness_primer.report.source import collect_source_evidence
from liveness_primer.tools.base import AdapterError, DetectorAdapter, RawToolOutput, build_invocation

GATE_CHOICES = ('new', 'dropped', 'changed', 'any', 'corpus-integrity')

_DIGEST_CHUNK = 1_048_576

# Hashing is already chunked, so this cap bounds admission I/O and time rather
# than peak memory. 256 MiB leaves room for ordinary native analyzer engines.
_MAX_NATIVE_TOOL_BYTES = 268_435_456


class RunnerError(LivenessPrimerError):
    """Raised when a run is misconfigured."""


def _executable_digest(path: Path) -> str:
    """Hash one bounded executable after verifying its opened-file identity.

    Parameters
    ----------
    path : Path
        Resolved executable path.

    Returns
    -------
    str
        SHA-256 hex digest.

    Raises
    ------
    OSError
        If the resolved path is not a regular file, the opened file differs
        from the one inspected, or the read exceeds the native-tool size
        limit.
    """
    path_stat = path.lstat()
    if not stat.S_ISREG(path_stat.st_mode):
        msg = 'native tool is not a regular non-symlink file'
        raise OSError(msg)
    if path_stat.st_size > _MAX_NATIVE_TOOL_BYTES:
        msg = f'native tool exceeds {_MAX_NATIVE_TOOL_BYTES} bytes'
        raise OSError(msg)

    with path.open('rb') as stream:
        opened_stat = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened_stat.st_mode) or (
            opened_stat.st_dev,
            opened_stat.st_ino,
        ) != (path_stat.st_dev, path_stat.st_ino):
            msg = 'native tool changed while it was being admitted'
            raise OSError(msg)

        digest = hashlib.sha256()
        bytes_read = 0
        for chunk in iter(lambda: stream.read(_DIGEST_CHUNK), b''):
            bytes_read += len(chunk)
            if bytes_read > _MAX_NATIVE_TOOL_BYTES:
                msg = f'native tool exceeds {_MAX_NATIVE_TOOL_BYTES} bytes'
                raise OSError(msg)
            digest.update(chunk)
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class AdmittedNativeTool:
    """One validated operator-supplied executable admitted into a run.

    The resolved host path lives here and nowhere else: it is needed to
    build the invocation environment, and stays out of the serialized
    record so a publishable report never carries the operator's filesystem
    layout (contract §3).

    Attributes
    ----------
    variable : str
        Adapter-declared environment variable carrying the executable.
    path : str
        Resolved host path, passed to the detector at invocation time.
    sha256 : str
        Digest of the executable's bytes.
    """

    variable: str
    path: str
    sha256: str

    def record(self) -> NativeToolRecord:
        """Reduce this tool to its publishable manifest record.

        Returns
        -------
        NativeToolRecord
            The variable and digest, without the host path.
        """
        return NativeToolRecord(variable=self.variable, sha256=self.sha256)


def resolve_native_tools(adapter: DetectorAdapter, environ: Mapping[str, str]) -> tuple[AdmittedNativeTool, ...]:
    """Admit the adapter's declared native helper executables (contract §3).

    The scrubbed analysis environment drops every unlisted variable, so an
    adapter declaration is the only channel by which an operator hands the
    detector a native helper (e.g. skylos's Go engine). Each supplied path
    is resolved, required to be an executable regular file, and hashed, so
    a missing or wrong binary fails the run here rather than silently
    degrading both sides' analysis.

    Parameters
    ----------
    adapter : DetectorAdapter
        Adapter of the tool under test.
    environ : Mapping[str, str]
        Operator environment supplying the declared variables.

    Returns
    -------
    tuple[AdmittedNativeTool, ...]
        One entry per declared variable the operator set, in declaration
        order; empty when none were set.

    Raises
    ------
    RunnerError
        If a declared variable names anything but a readable, executable
        regular file.
    """
    admitted: list[AdmittedNativeTool] = []
    for variable in adapter.passthrough_env:
        value = environ.get(variable, '').strip()
        if not value:
            continue
        try:
            resolved = Path(value).expanduser().resolve(strict=True)
            if not resolved.is_file() or not os.access(resolved, os.X_OK):
                msg = f'{variable} does not name an executable file: {value}'
                raise RunnerError(msg)
            digest = _executable_digest(resolved)
        except (OSError, RuntimeError) as error:
            msg = f'{variable} does not name a usable executable: {value} ({error})'
            raise RunnerError(msg) from error
        admitted.append(AdmittedNativeTool(variable=variable, path=str(resolved), sha256=digest))
    return tuple(admitted)


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
        Parsed findings, including usable partial failure output; ``None``
        when no usable output was available.
    error : ToolError | None
        The invocation or output-parsing failure, when present.
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
    environ : Mapping[str, str] | None
        Operator environment supplying the adapter's declared native
        helper executables; ``os.environ`` when ``None``.

    Raises
    ------
    RunnerError
        If ``async_launcher`` is not an asynchronous callable, or a
        declared native helper variable names no usable executable.
    """

    def __init__(
        self,
        *,
        adapter: DetectorAdapter,
        store: CheckoutStore,
        isolation: Isolation,
        options: RunOptions,
        async_launcher: AsyncLauncher = run_async,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        if not inspect.iscoroutinefunction(async_launcher) and not inspect.iscoroutinefunction(
            type(async_launcher).__call__
        ):
            msg = 'async_launcher must be an asynchronous callable'
            raise RunnerError(msg)
        # Resolved once, before any fetching or building, so an unusable
        # helper path fails the run immediately; both sides then receive
        # the identical binary.
        admitted = resolve_native_tools(adapter, os.environ if environ is None else environ)
        self._passthrough_env = {tool.variable: tool.path for tool in admitted}
        self._container_native_tools = tuple(
            ContainerNativeTool(variable=tool.variable, source=Path(tool.path), sha256=tool.sha256) for tool in admitted
        )
        self._native_tools = tuple(tool.record() for tool in admitted)
        self._adapter = adapter
        self._store = store
        self._checkout_root = store.checkout_root
        self._isolation = isolation
        self._options = options
        self._async_launcher = async_launcher

    def _materialize_side(self, checkout: Path, parent: Path | None, side: SideName) -> SideWorkspace:
        """Give one detector invocation its own disposable checkout copy.

        Both sides derive from the same pinned cache entry, so the copies are
        byte-identical (contract §3) — but neither side can influence the other
        (or a later run) through writes to a shared working tree, and the
        detector's scratch ``HOME`` lives and dies with the workspace.

        Parameters
        ----------
        checkout : Path
            Pinned cached checkout to copy.
        parent : Path | None
            Directory the workspace must be created under (an execution
            backend's reachable root), or ``None`` for the default
            temporary directory.
        side : SideName
            Detector revision that will use the workspace.

        Returns
        -------
        SideWorkspace
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
        root = Path(tempfile.mkdtemp(prefix='liveness-primer-side-', dir=parent))
        side_checkout = root / 'checkout'
        # Symlinks are copied as symlinks: following them could pull content
        # from outside the pinned tree into the analyzed copy.
        shutil.copytree(source, side_checkout, symlinks=True, ignore=shutil.ignore_patterns('.git'))
        home = Path(tempfile.mkdtemp(prefix='liveness-primer-home-', dir=root))
        return SideWorkspace(root=root, checkout=side_checkout, home=home, side=side)

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

    def _parse_outcome(self, item: _ProjectWork, *, side: str, result: LaunchResult, root: PurePath) -> _SideOutcome:
        """Turn one captured detector invocation into a side outcome.

        Parameters
        ----------
        item : _ProjectWork
            The project inputs.
        side : str
            ``base`` or ``head``.
        result : LaunchResult
            The captured launch.
        root : PurePath
            Checkout copy as the detector saw it, for path normalization.

        Returns
        -------
        _SideOutcome
            The parsed outcome.
        """
        raw = RawToolOutput(
            returncode=result.returncode if result.returncode is not None else 0,
            stdout=result.stdout,
            stderr=result.stderr,
        )
        error: ToolError | None = None
        if result.returncode not in self._adapter.success_exit_codes:
            # Record both accounts of the failure: stderr keeps its tail (a
            # traceback ends with the exception) and the detector's own
            # structured detail keeps its head (the first reported errors).
            # Incidental stderr noise must not hide the structured detail.
            stderr_detail = truncate_start(result.stderr.strip(), FAILURE_DETAIL_PART_CAP)
            adapter_detail = truncate_end(self._adapter.failure_detail(raw, root=root) or '', FAILURE_DETAIL_PART_CAP)
            parts = [part for part in (stderr_detail, adapter_detail) if part]
            detail = f'exit code {result.returncode}'
            if parts:
                detail += f': {"; ".join(parts)}'
            error = ToolError(side=side, exit_code=result.returncode, detail=detail)
            if not result.stdout.strip():
                return _SideOutcome(
                    side=side,
                    findings=None,
                    error=error,
                    duration_seconds=result.duration_seconds,
                    returncode=result.returncode,
                )
        try:
            findings = self._adapter.parse(raw, project=item.project.name, root=root, analyses=item.settings.analyses)
        except AdapterError as exc:
            detail = str(exc) if error is None else f'{error.detail}; output parse failed: {exc}'
            error = ToolError(side=side, exit_code=result.returncode, detail=detail)
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
            error=error,
            duration_seconds=result.duration_seconds,
            returncode=result.returncode,
        )

    async def _invoke(
        self,
        item: _ProjectWork,
        *,
        side: SideName,
        command: tuple[str, ...],
        semaphore: asyncio.Semaphore,
        execution: ExecutionBackend,
    ) -> _SideOutcome:
        """Run the detector once on one side of one project (analysis step, §3).

        Parameters
        ----------
        item : _ProjectWork
            The project inputs.
        side : SideName
            ``base`` or ``head``.
        command : tuple[str, ...]
            Detector command prefix for this side.
        semaphore : asyncio.Semaphore
            The ``--jobs`` limiter.
        execution : ExecutionBackend
            Backend deciding where and how the invocation runs.

        Returns
        -------
        _SideOutcome
            The captured, parsed outcome.
        """
        argv = build_invocation(self._adapter, command, item.settings)
        timeout = item.settings.timeout if item.settings.timeout is not None else self._options.timeout
        async with semaphore:
            # Each side analyzes its own disposable copy of the pinned
            # checkout in a sandboxed, credential-free environment prepared
            # by the execution backend (contract §3, §11).
            workspace = await asyncio.to_thread(
                self._materialize_side,
                item.checkout,
                execution.workspace_parents.get(side),
                side,
            )
            try:
                plan = execution.launch_plan(argv=argv, workspace=workspace)
                try:
                    try:
                        async with asyncio.timeout(timeout):
                            result = await self._async_launcher(list(plan.argv), cwd=plan.cwd, env=plan.env)
                    except TimeoutError:
                        error = ToolError(side=side, exit_code=None, detail=f'timed out after {timeout:g}s')
                        return _SideOutcome(
                            side=side,
                            findings=None,
                            error=error,
                            duration_seconds=timeout,
                            returncode=None,
                        )
                    return self._parse_outcome(
                        item,
                        side=side,
                        result=result,
                        root=execution.analysis_root(workspace),
                    )
                finally:
                    # Container plans force-remove the named invocation here.
                    # This runs after cancellation has killed only the host
                    # Docker client, but before the writable workspace is
                    # deleted; host plans own no cleanup action.
                    if plan.cleanup is not None:
                        await asyncio.to_thread(plan.cleanup)
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
        execution: ExecutionBackend,
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
        execution : ExecutionBackend
            Backend deciding where and how invocations run.

        Returns
        -------
        ProjectReport
            The per-project slice of the blast radius.
        """
        async with asyncio.TaskGroup() as group:
            base_task = group.create_task(
                self._invoke(item, side='base', command=base_command, semaphore=semaphore, execution=execution)
            )
            head_task = group.create_task(
                self._invoke(item, side='head', command=head_command, semaphore=semaphore, execution=execution)
            )
        return self._project_report(item, base_task.result(), head_task.result())

    async def _analyze_all(
        self,
        work: Sequence[_ProjectWork],
        *,
        base_command: tuple[str, ...],
        head_command: tuple[str, ...],
        execution: ExecutionBackend,
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
        execution : ExecutionBackend
            Backend deciding where and how invocations run.

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
                        execution=execution,
                    )
                )
                for item in work
            ]
        return tuple(task.result() for task in tasks)

    def _host_execution(self) -> HostExecution:
        """Build the host execution backend of this runner's configuration.

        Returns
        -------
        HostExecution
            Sandboxed host execution (contract §3, §11).
        """
        env_files = {name: str(path) for name, path in self._adapter.invocation_env_files.items()}
        return HostExecution(
            isolation=self._isolation,
            invocation_env={**self._adapter.invocation_env, **env_files},
            passthrough_env=self._passthrough_env,
        )

    def _manifest(
        self,
        *,
        detector_repo: str | None,
        pair: PreparedPair | PreparedContainerPair | None,
        base_cmd: tuple[str, ...] | None,
        head_cmd: tuple[str, ...] | None,
        fetches: tuple[FetchRecord, ...],
        pins: tuple[CorpusPinRecord, ...],
        isolation: Isolation,
        python_version: str | None = None,
        platform_tag: str | None = None,
    ) -> RunManifest:
        """Assemble the run manifest (contract §2, §3).

        Parameters
        ----------
        detector_repo : str | None
            Detector repository URL; absent for escape-hatch runs.
        pair : PreparedPair | PreparedContainerPair | None
            Prepared environments; absent for escape-hatch runs.
        base_cmd : tuple[str, ...] | None
            Escape-hatch base command.
        head_cmd : tuple[str, ...] | None
            Escape-hatch head command.
        fetches : tuple[FetchRecord, ...]
            Every fetch performed during the run.
        pins : tuple[CorpusPinRecord, ...]
            Resolved corpus pins.
        isolation : Isolation
            The isolation of the execution backend that ran the detectors,
            so record and enforcement can never diverge.
        python_version : str | None
            Interpreter version that ran the detectors, when it is not the
            host interpreter (container mode); host version when ``None``.
        platform_tag : str | None
            Platform where detectors ran, when it is not the host platform
            (container mode); host platform when ``None``.

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
            isolation_enforced=isolation.enforced,
            platform=platform_tag if platform_tag is not None else sysconfig.get_platform(),
            python_version=python_version if python_version is not None else platform.python_version(),
            installer=pair.installer_identity if pair is not None else None,
            native_tools=self._native_tools,
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
        execution = self._host_execution()
        with environments.prepare_pair(detector_repo, base_ref, head_ref, self._adapter) as pair:
            work, corpus_fetches = self._fetch_corpus(projects)
            project_reports = asyncio.run(
                self._analyze_all(
                    work,
                    base_command=(pair.base.executable,),
                    head_command=(pair.head.executable,),
                    execution=execution,
                )
            )
        manifest = self._manifest(
            detector_repo=detector_repo,
            pair=pair,
            base_cmd=None,
            head_cmd=None,
            fetches=(*pair.fetches, *corpus_fetches),
            pins=tuple(item.pin for item in work),
            isolation=execution.isolation,
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
        execution = self._host_execution()
        work, corpus_fetches = self._fetch_corpus(projects)
        project_reports = asyncio.run(
            self._analyze_all(
                work,
                base_command=tuple(base_cmd),
                head_command=tuple(head_cmd),
                execution=execution,
            )
        )
        manifest = self._manifest(
            detector_repo=None,
            pair=None,
            base_cmd=tuple(base_cmd),
            head_cmd=tuple(head_cmd),
            fetches=corpus_fetches,
            pins=tuple(item.pin for item in work),
            isolation=execution.isolation,
        )
        return _assemble_report(manifest, project_reports)

    def run_container(
        self,
        projects: Sequence[CorpusProject],
        *,
        detector_repo: str,
        base_ref: str,
        head_ref: str,
        environments: ContainerEnvironments,
    ) -> Report:
        """Run the primer with ephemeral per-invocation containers (contract §3, §11).

        Both detector refs build into fingerprint-keyed images. Every
        invocation runs in its own named, network-less container, which is
        force-removed before its workspace; the context reaps any leftover
        before the manifest or report output is assembled.

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
        environments : ContainerEnvironments
            Container environment builder running both refs.

        Returns
        -------
        Report
            The blast radius.

        """
        with environments.prepare_pair(
            detector_repo,
            base_ref,
            head_ref,
            self._adapter,
            native_tools=self._container_native_tools,
        ) as pair:
            # Declared env files exist only on the host; each side gets an
            # identical copy under its mount, at one container-side path.
            env_files = stage_invocation_env_files(
                self._adapter.invocation_env_files, (pair.base_work_root, pair.head_work_root)
            )
            execution = ContainerExecution(
                work_roots={'base': pair.base_work_root, 'head': pair.head_work_root},
                images={'base': pair.base.image, 'head': pair.head.image},
                invocation_env={
                    **self._adapter.invocation_env,
                    **env_files,
                    **{tool.variable: str(tool.container_path) for tool in self._container_native_tools},
                },
                docker=environments.runtime,
                active_containers=pair.active_containers,
                user=container_user(),
            )
            work, corpus_fetches = self._fetch_corpus(projects)
            project_reports = asyncio.run(
                self._analyze_all(
                    work,
                    base_command=(self._adapter.executable,),
                    head_command=(self._adapter.executable,),
                    execution=execution,
                )
            )
        # Every invocation container is force-removed before its workspace;
        # the context exit above reaps any leftover before report assembly.
        manifest = self._manifest(
            detector_repo=detector_repo,
            pair=pair,
            base_cmd=None,
            head_cmd=None,
            fetches=(*pair.fetches, *corpus_fetches),
            pins=tuple(item.pin for item in work),
            isolation=execution.isolation,
            python_version=pair.python_version,
            platform_tag=pair.platform,
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
