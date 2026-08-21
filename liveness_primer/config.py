# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Corpus specification models, license rules, and project selection (contract §5, §6).

The corpus is a human-authored YAML file parsed with ``PyYAML`` and validated
into the pydantic models here, which are the source of truth.
"""

import re
from collections.abc import Collection, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from liveness_primer.errors import LivenessPrimerError

# SPDX identifiers admissible for corpus projects (contract §6).
LICENSE_ALLOWLIST = frozenset({'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'PSF-2.0'})

_COPYLEFT_PREFIXES = ('GPL-', 'AGPL-', 'LGPL-', 'MPL-')

# Bare `.`/`..` segments are excluded everywhere: HTTP clients normalize
# dot segments away, silently retargeting the request path.
_NAME_PATTERN = re.compile(r'^(?!\.\.?$)[A-Za-z0-9._-]+$')
# GitHub owners are alphanumerics and inner hyphens; repository names also
# allow dots and underscores but never consist of dots alone.
_GITHUB_PATTERN = re.compile(
    r'^https://github\.com/'
    r'(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/'
    r'(?P<repo>(?!\.\.?(?:\.git)?/?$)[A-Za-z0-9._-]+?)'
    r'(\.git)?/?$'
)

_MAX_CORPUS_BYTES = 1_048_576


class CorpusConfigError(LivenessPrimerError):
    """Raised when the corpus specification is invalid or selection fails."""


class LicenseStatus(StrEnum):
    """Outcome of checking one SPDX identifier against the §6 rules.

    Attributes
    ----------
    ALLOWED
        On the corpus allowlist.
    FORBIDDEN
        Copyleft or missing: hard fail.
    UNRECOGNIZED
        Not on the allowlist and not recognizably copyleft: human review.
    """

    ALLOWED = 'allowed'
    FORBIDDEN = 'forbidden'
    UNRECOGNIZED = 'unrecognized'


def classify_license(spdx: str | None) -> LicenseStatus:
    """Classify an SPDX identifier per the §6 corpus allowlist rules.

    Parameters
    ----------
    spdx : str | None
        Declared SPDX identifier, or ``None``/empty when missing.

    Returns
    -------
    LicenseStatus
        ``ALLOWED``, ``FORBIDDEN`` (copyleft or missing), or
        ``UNRECOGNIZED`` (requires human review).
    """
    if spdx is None or not spdx.strip():
        return LicenseStatus.FORBIDDEN
    if spdx in LICENSE_ALLOWLIST:
        return LicenseStatus.ALLOWED
    if spdx.upper().startswith(_COPYLEFT_PREFIXES):
        return LicenseStatus.FORBIDDEN
    return LicenseStatus.UNRECOGNIZED


def github_owner_repo(url: str) -> tuple[str, str] | None:
    """Parse a GitHub repository URL into its owner and repository name.

    Parameters
    ----------
    url : str
        Repository URL as written in the corpus file.

    Returns
    -------
    tuple[str, str] | None
        ``(owner, repo)`` for a GitHub HTTPS URL, else ``None``.
    """
    match = _GITHUB_PATTERN.match(url)
    if match is None:
        return None
    return match.group('owner'), match.group('repo')


class _ConfigModel(BaseModel):
    """Base for corpus models: immutable and typo-rejecting."""

    model_config = ConfigDict(frozen=True, extra='forbid')


class ToolSettings(_ConfigModel):
    """Per-(project, tool) table from the corpus file (contract §5).

    Attributes
    ----------
    command : tuple[str, ...] | None
        Full argv override; the element ``{exe}`` is replaced by the managed
        detector executable. Always an argv list, never a shell string.
    analyses : tuple[str, ...]
        Opt-in analyses to enable, drawn from the adapter's declared set.
    args : tuple[str, ...]
        Extra arguments appended to the invocation.
    targets : tuple[str, ...]
        Checkout-relative paths to analyze; adapter default when empty.
    expected_clean : bool
        Whether base-side findings are corpus-integrity warnings (§5).
    timeout : float | None
        Per-(project, tool) override of the run timeout in seconds (§3).
    cost : float | None
        Declared approximate cost in CPU-seconds on the reference runner.
    """

    command: tuple[str, ...] | None = None
    analyses: tuple[str, ...] = ()
    args: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    expected_clean: bool = False
    timeout: float | None = Field(default=None, gt=0)
    cost: float | None = Field(default=None, ge=0)

    @model_validator(mode='after')
    def _check_unique_analyses(self) -> Self:
        """Reject duplicate analysis selections.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If ``analyses`` selects the same analysis more than once.
        """
        duplicates = {name for name in self.analyses if self.analyses.count(name) > 1}
        if duplicates:
            msg = f'analyses selects {min(duplicates)!r} more than once'
            raise ValueError(msg)
        return self

    @model_validator(mode='after')
    def _check_command_placeholder(self) -> Self:
        """Require the ``{exe}`` placeholder in command overrides.

        Without it, both revisions would silently run the identical
        override and compare a detector against itself.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If ``command`` is set but contains no ``{exe}`` element.
        """
        if self.command is not None and '{exe}' not in self.command:
            msg = "a command override must contain the '{exe}' placeholder; without it both sides run the same binary"
            raise ValueError(msg)
        return self


class CorpusProject(_ConfigModel):
    """One corpus project entry (contract §5).

    The same repository may appear under distinct names to allow multiple
    pins. License and host rules are enforced at the corpus-file level so
    ad-hoc CLI projects stay usable (§5 ad-hoc mode).

    Attributes
    ----------
    name : str
        Unique key of the entry.
    repo : str
        Repository URL.
    license : str | None
        Declared SPDX identifier; required in corpus files.
    pin : str | None
        Full commit SHA to analyze; exclusive with ``branch``.
    branch : str | None
        Branch for latest-on-branch pinning; exclusive with ``pin``.
    tools : dict[str, ToolSettings]
        Per-tool tables keyed by adapter name.
    include_tools : tuple[str, ...] | None
        When set, only these tools run against the project.
    exclude_tools : tuple[str, ...]
        Tools that never run against the project.
    """

    name: str = Field(pattern=r'^[A-Za-z0-9._-]+$')
    repo: str
    license: str | None = None
    pin: str | None = Field(default=None, pattern=r'^[0-9a-f]{40}$')
    branch: str | None = None
    tools: dict[str, ToolSettings] = Field(default_factory=dict)
    include_tools: tuple[str, ...] | None = None
    exclude_tools: tuple[str, ...] = ()

    @model_validator(mode='after')
    def _check_pin_branch(self) -> Self:
        """Reject entries pinning both a commit and a branch.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If both ``pin`` and ``branch`` are set.
        """
        if self.pin is not None and self.branch is not None:
            msg = f'project {self.name!r} sets both pin and branch'
            raise ValueError(msg)
        return self

    def supports_tool(self, tool: str) -> bool:
        """Report whether a tool participates for this project (contract §5).

        Parameters
        ----------
        tool : str
            Adapter name.

        Returns
        -------
        bool
            False when excluded or absent from a non-empty include list.
        """
        if tool in self.exclude_tools:
            return False
        return self.include_tools is None or tool in self.include_tools

    def tool_settings(self, tool: str) -> ToolSettings:
        """Fetch the per-tool table, defaulting to empty settings.

        Parameters
        ----------
        tool : str
            Adapter name.

        Returns
        -------
        ToolSettings
            The declared table or defaults.
        """
        return self.tools.get(tool, ToolSettings())


class Corpus(_ConfigModel):
    """The corpus file: the validated set of project entries (contract §5).

    Attributes
    ----------
    projects : tuple[CorpusProject, ...]
        Project entries in file order.
    """

    projects: tuple[CorpusProject, ...]

    @model_validator(mode='after')
    def _check_corpus_rules(self) -> Self:
        """Enforce corpus-file rules: unique names, pins, licenses, GitHub hosting.

        Returns
        -------
        Self
            The validated model.

        Raises
        ------
        ValueError
            If names collide, an entry lacks exactly one of pin/branch, a
            license violates §6, or a repository is not GitHub-hosted.
        """
        problems: list[str] = []
        seen: set[str] = set()
        for project in self.projects:
            if project.name in seen:
                problems.append(f'duplicate project name {project.name!r}')
            seen.add(project.name)
            if (project.pin is None) == (project.branch is None):
                problems.append(f'project {project.name!r} must set exactly one of pin or branch')
            status = classify_license(project.license)
            if status is LicenseStatus.FORBIDDEN:
                problems.append(f'project {project.name!r} license {project.license!r} is copyleft or missing (§6)')
            elif status is LicenseStatus.UNRECOGNIZED:
                problems.append(
                    f'project {project.name!r} license {project.license!r} is not on the allowlist; '
                    'human review required (§6)'
                )
            if github_owner_repo(project.repo) is None:
                problems.append(f'project {project.name!r} repo {project.repo!r} is not GitHub-hosted (§6)')
        if problems:
            raise ValueError('; '.join(problems))
        return self


def _check_tool_names(
    corpus: Corpus,
    known_tools: Collection[str],
    known_analyses: Mapping[str, Collection[str]] | None,
) -> None:
    """Reject tool names no adapter provides and undeclared analyses.

    Parameters
    ----------
    corpus : Corpus
        The validated corpus.
    known_tools : Collection[str]
        Adapter names available in this build.
    known_analyses : Mapping[str, Collection[str]] | None
        When given, per-tool ``analyses`` selections must be drawn from the
        named adapter's declared set.

    Raises
    ------
    CorpusConfigError
        If a per-tool table or include/exclude list names an unknown tool,
        or a per-tool table selects an undeclared analysis.
    """
    problems: list[str] = []
    for project in corpus.projects:
        include = project.include_tools if project.include_tools is not None else ()
        referenced = (*project.tools.keys(), *include, *project.exclude_tools)
        problems.extend(
            f'project {project.name!r} references unknown tool {tool!r}'
            for tool in dict.fromkeys(referenced)
            if tool not in known_tools
        )
        if known_analyses is not None:
            problems.extend(
                f'project {project.name!r} tool {tool!r} selects undeclared analysis {analysis!r}'
                for tool, settings in project.tools.items()
                for analysis in settings.analyses
                if analysis not in known_analyses.get(tool, ())
            )
    if problems:
        raise CorpusConfigError('; '.join(problems))


def default_corpus_path() -> Path:
    """Locate the corpus file shipped inside the installed package.

    The corpus travels with the distribution rather than sitting at the
    repository root, so ``liveness-primer run`` and ``corpus validate`` work
    from any working directory once the package is installed. Operators
    override it with ``--corpus``.

    Returns
    -------
    Path
        ``liveness_primer/data/corpus.yaml``.
    """
    return Path(__file__).parent / 'data' / 'corpus.yaml'


def _read_corpus_text(path: Path) -> str:
    """Read a bounded UTF-8 corpus file from a regular resolved path.

    Parameters
    ----------
    path : Path
        Operator-selected corpus file path.

    Returns
    -------
    str
        Decoded corpus contents.

    Raises
    ------
    CorpusConfigError
        If the path is missing, not a regular file, oversized, unreadable,
        or not valid UTF-8.
    """
    not_regular = f'corpus file {path} is not a regular file'
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise CorpusConfigError(not_regular)
        with resolved.open('rb') as corpus_file:
            encoded = corpus_file.read(_MAX_CORPUS_BYTES + 1)
    except (OSError, RuntimeError) as exc:
        msg = f'cannot read corpus file {path}: {exc}'
        raise CorpusConfigError(msg) from exc
    if len(encoded) > _MAX_CORPUS_BYTES:
        msg = f'corpus file {path} exceeds {_MAX_CORPUS_BYTES} bytes'
        raise CorpusConfigError(msg)
    try:
        return encoded.decode('utf-8')
    except UnicodeDecodeError as exc:
        msg = f'corpus file {path} is not valid UTF-8: {exc}'
        raise CorpusConfigError(msg) from exc


def load_corpus(
    path: Path,
    *,
    known_tools: Collection[str] | None = None,
    known_analyses: Mapping[str, Collection[str]] | None = None,
) -> Corpus:
    """Load and validate a corpus YAML file (contract §5).

    Parameters
    ----------
    path : Path
        Corpus file location.
    known_tools : Collection[str] | None
        When given, per-tool table keys and include/exclude entries must be
        drawn from it.
    known_analyses : Mapping[str, Collection[str]] | None
        When given, per-tool ``analyses`` selections must be drawn from the
        named adapter's declared set.

    Returns
    -------
    Corpus
        The validated corpus.

    Raises
    ------
    CorpusConfigError
        If the file is missing, not regular, oversized, unreadable, not valid
        UTF-8 or YAML, or violates the schema.
    """
    text = _read_corpus_text(path)
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f'corpus file {path} is not valid YAML: {exc}'
        raise CorpusConfigError(msg) from exc
    try:
        corpus = Corpus.model_validate(raw)
    except ValidationError as exc:
        msg = f'corpus file {path} is invalid: {exc}'
        raise CorpusConfigError(msg) from exc
    if known_tools is not None:
        _check_tool_names(corpus, known_tools, known_analyses)
    return corpus


def ad_hoc_project(repo: str, *, tool: str | None = None, analyses: Sequence[str] = ()) -> CorpusProject:
    """Build the single-project corpus entry for ad-hoc mode (contract §5).

    The project uses default settings and latest-on-default-branch pinning,
    represented as neither ``pin`` nor ``branch``; ``--analyses`` selections
    become the tool's per-project table.

    Parameters
    ----------
    repo : str
        Target repository URL from the CLI.
    tool : str | None
        Adapter name the run targets; required when ``analyses`` is given.
    analyses : Sequence[str]
        Opt-in analyses selected on the CLI.

    Returns
    -------
    CorpusProject
        The synthesized entry.

    Raises
    ------
    CorpusConfigError
        If a project name cannot be derived from the URL, analyses are
        given without a tool, or the selection is invalid.
    """
    tail = repo.rstrip('/').rsplit('/', maxsplit=1)[-1].removesuffix('.git')
    if not _NAME_PATTERN.match(tail):
        msg = f'cannot derive a project name from repository URL {repo!r}'
        raise CorpusConfigError(msg)
    tools: dict[str, ToolSettings] = {}
    if analyses:
        if tool is None:
            msg = 'ad-hoc analyses require a tool name'
            raise CorpusConfigError(msg)
        try:
            tools[tool] = ToolSettings(analyses=tuple(analyses))
        except ValidationError as exc:
            msg = f'invalid ad-hoc analyses: {exc}'
            raise CorpusConfigError(msg) from exc
    return CorpusProject(name=tail, repo=repo, tools=tools)


def _select_by_cost(
    applicable: Sequence[CorpusProject],
    *,
    tool: str,
    max_cost: float,
) -> list[CorpusProject]:
    """Select greedily under a declared-cost budget (contract §5).

    Parameters
    ----------
    applicable : Sequence[CorpusProject]
        Projects supporting the tool, in corpus-file order.
    tool : str
        Adapter name whose declared costs apply.
    max_cost : float
        Budget in CPU-seconds.

    Returns
    -------
    list[CorpusProject]
        Chosen projects restored to corpus-file order.
    """
    budgeted: list[tuple[float, CorpusProject]] = []
    for project in applicable:
        cost = project.tool_settings(tool).cost
        if cost is not None:
            budgeted.append((cost, project))
    chosen: list[CorpusProject] = []
    remaining = max_cost
    for cost, project in sorted(budgeted, key=lambda pair: (pair[0], pair[1].name)):
        if cost <= remaining:
            chosen.append(project)
            remaining -= cost
    order = {project.name: index for index, project in enumerate(applicable)}
    chosen.sort(key=lambda project: order[project.name])
    return chosen


def select_projects(
    corpus: Corpus,
    *,
    tool: str,
    keywords: Sequence[str] = (),
    select_all: bool = False,
    max_cost: float | None = None,
    ignore_include_tools: bool = False,
) -> tuple[CorpusProject, ...]:
    """Select corpus projects for a run (contract §5).

    Exactly one selector must be active: ``keywords`` (name substrings),
    ``select_all``, or ``max_cost`` (greedy under declared per-tool cost,
    ascending by cost then name; projects without a declared cost for the
    tool cannot be budgeted and are skipped).

    Parameters
    ----------
    corpus : Corpus
        The validated corpus.
    tool : str
        Adapter name the run targets; ``-k`` may select a project omitted by
        ``include_tools``, but never one that excludes the tool.
    keywords : Sequence[str]
        Substring selectors (``-k``), unioned.
    select_all : bool
        Select every applicable project (``--all``).
    max_cost : float | None
        Cost budget in CPU-seconds (``--max-cost``).
    ignore_include_tools : bool
        Include projects omitted by ``include_tools`` with ``--all`` or
        ``--max-cost``; ``exclude_tools`` remains effective.

    Returns
    -------
    tuple[CorpusProject, ...]
        Selected projects in corpus-file order.

    Raises
    ------
    CorpusConfigError
        If no or several selectors are active, or nothing matches.
    """
    active = sum((bool(keywords), select_all, max_cost is not None))
    if active != 1:
        msg = 'exactly one of -k, --all, or --max-cost must be given'
        raise CorpusConfigError(msg)
    if ignore_include_tools and keywords:
        msg = '--ignore-include-tools does not apply to -k, which already ignores include_tools'
        raise CorpusConfigError(msg)
    eligible = [project for project in corpus.projects if tool not in project.exclude_tools]
    applicable = eligible if ignore_include_tools else [project for project in eligible if project.supports_tool(tool)]
    if select_all:
        selected = applicable
    elif keywords:
        selected = [project for project in eligible if any(keyword in project.name for keyword in keywords)]
    else:
        selected = _select_by_cost(applicable, tool=tool, max_cost=max_cost if max_cost is not None else 0.0)
    if not selected:
        msg = f'no corpus project matches the selection for tool {tool!r}'
        raise CorpusConfigError(msg)
    return tuple(selected)
