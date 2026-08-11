"""The command-line interface (contract §12).

Copyright (C) 2026 Matthew C. Digman

Commands: ``run``, ``corpus validate``, ``corpus license-check``, and
``schema export``. Exit codes (contract §9): 0 for any successful run
regardless of diff size, 1 for run or configuration failures, 2 for usage
errors (argparse), and 3 for opt-in ``--fail-on`` gate failures.
"""

import argparse
import math
import os
import shlex
import shutil
import sys
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as metadata_version
from pathlib import Path
from typing import cast

from liveness_primer.config import CorpusProject, ad_hoc_project, load_corpus, select_projects
from liveness_primer.corpus import CheckoutStore, cache_root
from liveness_primer.envcache import DetectorEnvironments, choose_installer
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.filesystem import atomic_write_text
from liveness_primer.findings import SCHEMA_VERSION, Report
from liveness_primer.isolation import detect_isolation, require_isolation
from liveness_primer.license_check import check_licenses
from liveness_primer.report import render_github, render_json, render_text
from liveness_primer.report.terminal import (
    CAPABILITY_CHOICES,
    DEFAULT_REDIRECTED_WIDTH,
    CapabilityMode,
    resolve_text_options,
)
from liveness_primer.runner import (
    GATE_CHOICES,
    PrimerRunner,
    RunnerError,
    RunOptions,
    evaluate_gates,
    report_has_failures,
)
from liveness_primer.schema_export import export_schemas
from liveness_primer.tools.registry import adapter_analyses, adapter_names, get_adapter

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_GATE = 3

_OUTPUT_MODES = ('github', 'json', 'text')


def _positive_int(text: str) -> int:
    """Parse a strictly positive integer CLI value (contract §12).

    Parameters
    ----------
    text : str
        Raw argument text.

    Returns
    -------
    int
        The parsed value.

    Raises
    ------
    argparse.ArgumentTypeError
        If the value is not an integer of at least 1.
    """
    try:
        value = int(text)
    except ValueError as exc:
        msg = f'{text!r} is not an integer'
        raise argparse.ArgumentTypeError(msg) from exc
    if value < 1:
        msg = f'must be at least 1, got {value}'
        raise argparse.ArgumentTypeError(msg)
    return value


def _nonnegative_int(text: str) -> int:
    """Parse a non-negative integer CLI value (contract §12).

    Parameters
    ----------
    text : str
        Raw argument text.

    Returns
    -------
    int
        The parsed value.

    Raises
    ------
    argparse.ArgumentTypeError
        If the value is not an integer of at least 0.
    """
    try:
        value = int(text)
    except ValueError as exc:
        msg = f'{text!r} is not an integer'
        raise argparse.ArgumentTypeError(msg) from exc
    if value < 0:
        msg = f'must not be negative, got {value}'
        raise argparse.ArgumentTypeError(msg)
    return value


def _positive_float(text: str) -> float:
    """Parse a strictly positive, finite float CLI value (contract §12).

    Parameters
    ----------
    text : str
        Raw argument text.

    Returns
    -------
    float
        The parsed value.

    Raises
    ------
    argparse.ArgumentTypeError
        If the value is not a finite number greater than zero.
    """
    try:
        value = float(text)
    except ValueError as exc:
        msg = f'{text!r} is not a number'
        raise argparse.ArgumentTypeError(msg) from exc
    if not math.isfinite(value) or value <= 0:
        msg = f'must be a positive finite number, got {text}'
        raise argparse.ArgumentTypeError(msg)
    return value


def _package_version() -> str:
    """Report the installed package version.

    Returns
    -------
    str
        The distribution version, or ``unknown`` outside an install.
    """
    try:
        return metadata_version('liveness_primer')
    except PackageNotFoundError:
        return 'unknown'


def _add_run_parser(subcommands: 'argparse._SubParsersAction[argparse.ArgumentParser]') -> None:
    """Add the ``run`` command (contract §12).

    Parameters
    ----------
    subcommands : argparse._SubParsersAction[argparse.ArgumentParser]
        The root subcommand registry.
    """
    run_parser = subcommands.add_parser('run', help='run a two-revision comparison')
    run_parser.add_argument('--tool', required=True, help='detector adapter name')
    run_parser.add_argument('--repo', help='detector repository URL')
    run_parser.add_argument('--old', help='base detector ref')
    run_parser.add_argument('--new', help='head detector ref')
    run_parser.add_argument('--old-cmd', help='escape hatch: pre-built base detector command')
    run_parser.add_argument('--new-cmd', help='escape hatch: pre-built head detector command')
    run_parser.add_argument('-k', dest='keywords', action='append', default=[], help='select projects by substring')
    run_parser.add_argument('--all', dest='select_all', action='store_true', help='select every applicable project')
    run_parser.add_argument('--max-cost', type=_positive_float, help='greedy selection budget in CPU-seconds')
    run_parser.add_argument('--corpus', type=Path, default=Path('corpus.yaml'), help='corpus YAML file')
    run_parser.add_argument('--project', dest='project_url', help='ad-hoc mode: single target repository URL')
    run_parser.add_argument(
        '--analyses',
        action='append',
        default=[],
        metavar='NAME',
        help='ad-hoc mode: enable an adapter-declared opt-in analysis; repeatable',
    )
    run_parser.add_argument('--max-results', type=_positive_int, default=200, help='per-project cap on rendered diffs')
    run_parser.add_argument(
        '--excerpt-lines',
        type=_nonnegative_int,
        default=5,
        help='pinned-source evidence lines stored and rendered per occurrence (0 disables)',
    )
    run_parser.add_argument('--output', choices=_OUTPUT_MODES, default='text', help='report mode')
    run_parser.add_argument(
        '--color',
        choices=CAPABILITY_CHOICES,
        default='auto',
        help='ANSI styling in text output',
    )
    run_parser.add_argument(
        '--hyperlinks',
        choices=CAPABILITY_CHOICES,
        default='auto',
        help='OSC-8 terminal hyperlinks in text output',
    )
    run_parser.add_argument(
        '--source-urls',
        action='store_true',
        help='print per-finding pinned URL lines in text output',
    )
    run_parser.add_argument(
        '--json-out',
        type=Path,
        help='also write the complete JSON report to this path',
    )
    run_parser.add_argument(
        '--fail-on',
        action='append',
        default=[],
        choices=GATE_CHOICES,
        help='opt-in gate; repeatable',
    )
    run_parser.add_argument('--jobs', type=_positive_int, default=2, help='concurrent detector subprocesses')
    run_parser.add_argument(
        '--timeout', type=_positive_float, default=300.0, help='default per-(project, tool) timeout'
    )
    run_parser.add_argument('--fresh', action='store_true', help='force same-run environment rebuilds')


def _add_corpus_parser(subcommands: 'argparse._SubParsersAction[argparse.ArgumentParser]') -> None:
    """Add the ``corpus`` command group (contract §12).

    Parameters
    ----------
    subcommands : argparse._SubParsersAction[argparse.ArgumentParser]
        The root subcommand registry.
    """
    corpus_parser = subcommands.add_parser('corpus', help='corpus maintenance commands')
    corpus_commands = corpus_parser.add_subparsers(dest='corpus_command', required=True)
    validate_parser = corpus_commands.add_parser('validate', help='parse and validate the corpus YAML')
    validate_parser.add_argument('--corpus', type=Path, default=Path('corpus.yaml'), help='corpus YAML file')
    license_parser = corpus_commands.add_parser('license-check', help='verify licenses via the GitHub API (§6)')
    license_parser.add_argument('--corpus', type=Path, default=Path('corpus.yaml'), help='corpus YAML file')


def _add_schema_parser(subcommands: 'argparse._SubParsersAction[argparse.ArgumentParser]') -> None:
    """Add the ``schema`` command group (contract §12).

    Parameters
    ----------
    subcommands : argparse._SubParsersAction[argparse.ArgumentParser]
        The root subcommand registry.
    """
    schema_parser = subcommands.add_parser('schema', help='schema maintenance commands')
    schema_commands = schema_parser.add_subparsers(dest='schema_command', required=True)
    export_parser = schema_commands.add_parser('export', help='regenerate liveness_primer/schemas/ (§7)')
    # The default target is resolved from the imported package, so a
    # non-editable install exports into site-packages and leaves the
    # checkout untouched. CI passes the repository directory explicitly
    # so the sync check compares the files it is meant to guard.
    export_parser.add_argument(
        '--output-dir',
        type=Path,
        help='directory to write the schema files to (default: the in-package schemas/)',
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse command tree (contract §12).

    Returns
    -------
    argparse.ArgumentParser
        The root parser; every command accepts ``-h``/``--help``.
    """
    parser = argparse.ArgumentParser(
        prog='liveness-primer',
        description='Run a Python dead-code detector at two revisions and report the blast radius.',
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {_package_version()} (schema {SCHEMA_VERSION})',
    )
    subcommands = parser.add_subparsers(dest='command', required=True)
    _add_run_parser(subcommands)
    _add_corpus_parser(subcommands)
    _add_schema_parser(subcommands)
    return parser


def _check_run_mode(args: argparse.Namespace) -> bool:
    """Validate the managed-vs-escape-hatch flag matrix (contract §3, §12).

    Parameters
    ----------
    args : argparse.Namespace
        Parsed ``run`` arguments.

    Returns
    -------
    bool
        True for an escape-hatch run.

    Raises
    ------
    RunnerError
        If the flags mix modes, are incomplete, or request gating for a
        non-comparable run.
    """
    escape = args.old_cmd is not None or args.new_cmd is not None
    if escape:
        if args.old_cmd is None or args.new_cmd is None:
            msg = '--old-cmd and --new-cmd must be given together'
            raise RunnerError(msg)
        if args.repo is not None or args.old is not None or args.new is not None:
            msg = 'the escape hatch (--old-cmd/--new-cmd) replaces --repo/--old/--new'
            raise RunnerError(msg)
        if args.fail_on:
            msg = '--fail-on refuses to act on a non-comparable (escape-hatch) run (§3)'
            raise RunnerError(msg)
    elif args.repo is None or args.old is None or args.new is None:
        msg = 'a managed run requires --repo, --old, and --new (or use --old-cmd/--new-cmd)'
        raise RunnerError(msg)
    return escape


def _select_run_projects(args: argparse.Namespace) -> tuple[CorpusProject, ...]:
    """Resolve the projects a ``run`` targets (contract §5).

    Parameters
    ----------
    args : argparse.Namespace
        Parsed ``run`` arguments.

    Returns
    -------
    tuple[CorpusProject, ...]
        Selected corpus projects, or the single ad-hoc project.

    Raises
    ------
    RunnerError
        If ad-hoc mode is mixed with corpus selectors, ``--analyses`` is
        used outside ad-hoc mode, or an analysis is not declared.
    """
    if args.project_url is not None:
        if args.keywords or args.select_all or args.max_cost is not None:
            msg = '--project (ad-hoc mode) does not take -k/--all/--max-cost'
            raise RunnerError(msg)
        declared = get_adapter(args.tool).analyses
        unknown = [name for name in args.analyses if name not in declared]
        if unknown:
            msg = f'tool {args.tool!r} does not provide analysis {unknown[0]!r}'
            raise RunnerError(msg)
        return (ad_hoc_project(args.project_url, tool=args.tool, analyses=tuple(args.analyses)),)
    if args.analyses:
        msg = '--analyses applies to ad-hoc --project runs; corpus runs select analyses in the corpus file'
        raise RunnerError(msg)
    corpus = load_corpus(args.corpus, known_tools=adapter_names(), known_analyses=adapter_analyses())
    return select_projects(
        corpus,
        tool=args.tool,
        keywords=tuple(args.keywords),
        select_all=args.select_all,
        max_cost=args.max_cost,
    )


def _terminal_width() -> int | None:
    """Measure the interactive terminal width.

    Returns
    -------
    int | None
        The measured width, or ``None`` when unavailable.
    """
    width = shutil.get_terminal_size(fallback=(0, 0)).columns
    return width if width > 0 else None


def _render_report(report: Report, args: argparse.Namespace) -> str:
    """Render the report in the selected output mode (contract §9, reporting §6).

    JSON and GitHub output never contain ANSI styling or OSC-8 links; the
    text renderer resolves its capabilities from ``--color``,
    ``--hyperlinks``, the environment, and the output stream.

    Parameters
    ----------
    report : Report
        The assembled report.
    args : argparse.Namespace
        Parsed ``run`` arguments.

    Returns
    -------
    str
        The rendered report.
    """
    if args.output == 'json':
        return render_json(report)
    if args.output == 'github':
        return render_github(report)
    interactive = sys.stdout.isatty()
    options = resolve_text_options(
        color_mode=cast('CapabilityMode', args.color),
        hyperlink_mode=cast('CapabilityMode', args.hyperlinks),
        interactive=interactive,
        env=os.environ,
        terminal_width=_terminal_width() if interactive else DEFAULT_REDIRECTED_WIDTH,
        source_urls=args.source_urls,
    )
    return render_text(report, options)


def _write_json_report(report: Report, path: Path) -> None:
    """Archive the complete JSON report alongside any output mode (§2).

    Initial contract §9 makes the JSON artifact the CI-consumable product,
    but ``--output`` selects one mode; a CI job must not have to pay for a
    second complete corpus run to keep it.

    Parameters
    ----------
    report : Report
        The assembled report.
    path : Path
        Destination file.

    Raises
    ------
    RunnerError
        If the destination cannot be written.
    """
    try:
        atomic_write_text(path, render_json(report))
    except OSError as error:
        msg = f'could not write the JSON report to {path}: {error.strerror}'
        raise RunnerError(msg) from error


def _exit_code_for(report: Report, fail_on: tuple[str, ...]) -> int:
    """Derive the process exit code from a finished run (contract §9).

    Parameters
    ----------
    report : Report
        The assembled report.
    fail_on : tuple[str, ...]
        Enabled gates.

    Returns
    -------
    int
        Distinct codes for run failure (1) and gate failure (3), else 0.
    """
    fired = evaluate_gates(report, fail_on)
    if report_has_failures(report):
        sys.stderr.write('run failure: one or more detector invocations failed; see the report\n')
        return EXIT_FAILURE
    if fired:
        sys.stderr.write('gate failure: ' + '; '.join(fired) + '\n')
        return EXIT_GATE
    return EXIT_OK


def _command_run(args: argparse.Namespace) -> int:
    """Execute the ``run`` command (contract §12).

    Parameters
    ----------
    args : argparse.Namespace
        Parsed ``run`` arguments.

    Returns
    -------
    int
        0 on success, 1 on run failure, 3 on gate failure.
    """
    adapter = get_adapter(args.tool)
    escape = _check_run_mode(args)
    projects = _select_run_projects(args)
    options = RunOptions(
        jobs=args.jobs,
        timeout=args.timeout,
        max_results=args.max_results,
        excerpt_lines=args.excerpt_lines,
        fail_on=tuple(args.fail_on),
        fresh=args.fresh,
    )
    store = CheckoutStore(cache_root())
    # Managed runs execute untrusted detector refs and fail closed on Linux
    # without an enforced sandbox; escape-hatch commands are trusted user
    # code, so unenforced isolation is recorded and flagged instead (§11).
    isolation = detect_isolation() if escape else require_isolation()
    runner = PrimerRunner(adapter=adapter, store=store, isolation=isolation, options=options)
    if escape:
        report = runner.run_escape_hatch(
            projects,
            base_cmd=shlex.split(args.old_cmd),
            head_cmd=shlex.split(args.new_cmd),
        )
    else:
        environments = DetectorEnvironments(
            store,
            cache_root(),
            installer=choose_installer(),
            isolation=isolation,
            fresh=args.fresh,
        )
        report = runner.run_managed(
            projects,
            detector_repo=args.repo,
            base_ref=args.old,
            head_ref=args.new,
            environments=environments,
        )
    if args.json_out is not None:
        _write_json_report(report, args.json_out)
    sys.stdout.write(_render_report(report, args))
    return _exit_code_for(report, options.fail_on)


def _command_validate(args: argparse.Namespace) -> int:
    """Execute ``corpus validate`` (contract §12).

    Parameters
    ----------
    args : argparse.Namespace
        Parsed arguments.

    Returns
    -------
    int
        0 when the corpus file is valid.
    """
    corpus = load_corpus(args.corpus, known_tools=adapter_names(), known_analyses=adapter_analyses())
    names = ', '.join(project.name for project in corpus.projects)
    sys.stdout.write(f'corpus OK: {len(corpus.projects)} project(s): {names}\n')
    return EXIT_OK


def _command_license_check(args: argparse.Namespace) -> int:
    """Execute ``corpus license-check`` (contract §6, §12).

    Parameters
    ----------
    args : argparse.Namespace
        Parsed arguments.

    Returns
    -------
    int
        0 when every declared license is confirmed.
    """
    corpus = load_corpus(args.corpus, known_tools=adapter_names(), known_analyses=adapter_analyses())
    results = check_licenses(corpus.projects, token=os.environ.get('GITHUB_TOKEN'))
    for result in results:
        marker = 'ok  ' if result.ok else 'FAIL'
        sys.stdout.write(f'{marker} {result.project}: {result.detail}\n')
    if all(result.ok for result in results):
        return EXIT_OK
    return EXIT_FAILURE


def _command_schema_export(args: argparse.Namespace) -> int:
    """Execute ``schema export`` (contract §7, §12).

    Parameters
    ----------
    args : argparse.Namespace
        Parsed arguments carrying the optional output directory.

    Returns
    -------
    int
        0 after regenerating the schema files.
    """
    for path in export_schemas(args.output_dir):
        sys.stdout.write(f'wrote {path}\n')
    return EXIT_OK


def _dispatch(args: argparse.Namespace) -> int:
    """Route parsed arguments to their command.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed arguments.

    Returns
    -------
    int
        The command's exit code.
    """
    if args.command == 'run':
        return _command_run(args)
    if args.command == 'corpus':
        if args.corpus_command == 'validate':
            return _command_validate(args)
        return _command_license_check(args)
    return _command_schema_export(args)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI (contract §12).

    Parameters
    ----------
    argv : Sequence[str] | None
        Arguments without the program name; ``sys.argv[1:]`` by default.

    Returns
    -------
    int
        Process exit code (see the module docstring).
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(args)
    except LivenessPrimerError as exc:
        sys.stderr.write(f'error: {exc}\n')
        return EXIT_FAILURE
