# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for corpus models, license rules, and selection (contract §5, §6)."""

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from liveness_primer.config import (
    Corpus,
    CorpusConfigError,
    CorpusProject,
    LicenseStatus,
    ToolSettings,
    ad_hoc_project,
    classify_license,
    default_corpus_path,
    github_owner_repo,
    load_corpus,
    select_projects,
)
from liveness_primer.tools.registry import adapter_analyses, adapter_names

PIN_A = 'a' * 40
PIN_B = 'b' * 40


def project(name: str = 'demo', **overrides: object) -> CorpusProject:
    fields: dict[str, object] = {
        'name': name,
        'repo': f'https://github.com/example/{name}',
        'license': 'MIT',
        'pin': PIN_A,
    }
    fields.update(overrides)
    return CorpusProject.model_validate(fields)


@pytest.mark.parametrize('spdx', ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'PSF-2.0'])
def test_allowlisted_licenses(spdx: str) -> None:
    assert classify_license(spdx) is LicenseStatus.ALLOWED


@pytest.mark.parametrize(
    'spdx',
    [None, '', '  ', 'GPL-2.0-only', 'GPL-3.0-or-later', 'AGPL-3.0', 'LGPL-2.1', 'MPL-2.0', 'gpl-2.0'],
)
def test_copyleft_or_missing_licenses_are_forbidden(spdx: str | None) -> None:
    assert classify_license(spdx) is LicenseStatus.FORBIDDEN


@pytest.mark.parametrize('spdx', ['Unlicense', 'WTFPL', 'EPL-2.0'])
def test_unknown_licenses_require_human_review(spdx: str) -> None:
    assert classify_license(spdx) is LicenseStatus.UNRECOGNIZED


@pytest.mark.parametrize(
    ('url', 'expected'),
    [
        ('https://github.com/python-attrs/attrs', ('python-attrs', 'attrs')),
        ('https://github.com/pallets/click.git', ('pallets', 'click')),
        ('https://github.com/pallets/jinja/', ('pallets', 'jinja')),
    ],
)
def test_github_owner_repo_parses_hosted_urls(url: str, expected: tuple[str, str]) -> None:
    assert github_owner_repo(url) == expected


@pytest.mark.parametrize(
    'url',
    [
        'https://gitlab.com/owner/repo',
        'git@github.com:owner/repo.git',
        'http://github.com/owner/repo',
        'https://github.com/owner',
        'https://github.com/owner/repo/tree/main',
    ],
)
def test_github_owner_repo_rejects_other_hosts(url: str) -> None:
    assert github_owner_repo(url) is None


@pytest.mark.parametrize(
    'url',
    [
        # HTTP clients normalize dot segments, silently retargeting the
        # request path, so bare `.`/`..` never count as owner or repo.
        'https://github.com/../..',
        'https://github.com/owner/..',
        'https://github.com/owner/.',
        'https://github.com/owner/../',
        'https://github.com/owner/..git',
        'https://github.com/./repo',
        # GitHub owners are alphanumerics and inner hyphens only.
        'https://github.com/own.er/repo',
        'https://github.com/own_er/repo',
        'https://github.com/-owner/repo',
    ],
)
def test_github_owner_repo_rejects_dot_segments_and_bad_owners(url: str) -> None:
    assert github_owner_repo(url) is None


def test_github_owner_repo_accepts_dotted_repository_names() -> None:
    assert github_owner_repo('https://github.com/owner/.github') == ('owner', '.github')
    assert github_owner_repo('https://github.com/owner/repo.js.git') == ('owner', 'repo.js')


def test_tool_settings_bounds() -> None:
    with pytest.raises(ValidationError):
        ToolSettings.model_validate({'timeout': 0})
    with pytest.raises(ValidationError):
        ToolSettings.model_validate({'cost': -1})
    settings = ToolSettings(command=('{exe}', '--flag'), args=('-v',), targets=('src',), timeout=5.0, cost=2.0)
    assert settings.expected_clean is False


def test_tool_settings_command_requires_the_exe_placeholder() -> None:
    # Without {exe} both revisions would run the identical override and
    # silently compare a detector against itself.
    with pytest.raises(ValidationError, match=r'\{exe\}'):
        ToolSettings(command=('/opt/wrapper', '--mode', 'scan'))


def test_project_rejects_bad_name_and_short_pin() -> None:
    with pytest.raises(ValidationError):
        project(name='bad name')
    with pytest.raises(ValidationError):
        project(pin='abc123')
    with pytest.raises(ValidationError):
        project(pin=PIN_A.upper())


def test_project_rejects_pin_and_branch_together() -> None:
    with pytest.raises(ValidationError, match='both pin and branch'):
        project(branch='main')


def test_project_tool_participation() -> None:
    entry = project(exclude_tools=('skylos',))
    assert entry.supports_tool('vulture')
    assert not entry.supports_tool('skylos')
    included = project(include_tools=('vulture',))
    assert included.supports_tool('vulture')
    assert not included.supports_tool('skylos')
    both = project(include_tools=('vulture',), exclude_tools=('vulture',))
    assert not both.supports_tool('vulture')


def test_project_tool_settings_default() -> None:
    entry = project(tools={'vulture': {'cost': 3.5}})
    assert entry.tool_settings('vulture').cost == 3.5
    assert entry.tool_settings('skylos') == ToolSettings()


def test_corpus_rejects_duplicate_names() -> None:
    with pytest.raises(ValidationError, match='duplicate project name'):
        Corpus(projects=(project(), project()))


def test_corpus_requires_exactly_one_pinning_mode() -> None:
    with pytest.raises(ValidationError, match='exactly one of pin or branch'):
        Corpus(projects=(project(pin=None),))


def test_corpus_rejects_forbidden_and_unrecognized_licenses() -> None:
    with pytest.raises(ValidationError, match='copyleft or missing'):
        Corpus(projects=(project(license='GPL-3.0-only'),))
    with pytest.raises(ValidationError, match='human review'):
        Corpus(projects=(project(license='WTFPL'),))
    with pytest.raises(ValidationError, match='copyleft or missing'):
        Corpus(projects=(project(license=None),))


def test_corpus_rejects_non_github_hosts() -> None:
    with pytest.raises(ValidationError, match='not GitHub-hosted'):
        Corpus(projects=(project(repo='https://gitlab.com/example/demo'),))


def test_corpus_accepts_valid_entries() -> None:
    corpus = Corpus(projects=(project('one'), project('two', pin=None, branch='main')))
    assert [entry.name for entry in corpus.projects] == ['one', 'two']


VALID_YAML = f"""
projects:
  - name: one
    repo: https://github.com/example/one
    license: MIT
    pin: {PIN_A}
    tools:
      vulture:
        targets:
          - src
        cost: 3.0
        expected_clean: true
  - name: two
    repo: https://github.com/example/two
    license: Apache-2.0
    branch: main
    exclude_tools:
      - skylos
"""


def test_load_corpus_round_trip(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text(VALID_YAML, encoding='utf-8')
    corpus = load_corpus(corpus_file, known_tools=('vulture', 'skylos'))
    assert corpus.projects[0].tool_settings('vulture').expected_clean is True
    assert corpus.projects[1].branch == 'main'


def test_load_corpus_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CorpusConfigError, match='cannot read corpus file'):
        load_corpus(tmp_path / 'absent.yaml')


def test_load_corpus_accepts_symlink_to_regular_file(tmp_path: Path) -> None:
    target = tmp_path / 'target.yaml'
    target.write_text(VALID_YAML, encoding='utf-8')
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.symlink_to(target)
    corpus = load_corpus(corpus_file)
    assert len(corpus.projects) == 2


def test_load_corpus_rejects_broken_symlink(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.symlink_to(tmp_path / 'absent.yaml')
    with pytest.raises(CorpusConfigError, match='cannot read corpus file'):
        load_corpus(corpus_file)


def test_load_corpus_rejects_symlink_to_directory(tmp_path: Path) -> None:
    target = tmp_path / 'target'
    target.mkdir()
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.symlink_to(target)
    with pytest.raises(CorpusConfigError, match='not a regular file'):
        load_corpus(corpus_file)


def test_load_corpus_rejects_symlink_loop(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.symlink_to(corpus_file)
    with pytest.raises(CorpusConfigError, match='cannot read corpus file'):
        load_corpus(corpus_file)


def test_load_corpus_rejects_non_file(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.mkdir()
    with pytest.raises(CorpusConfigError, match='not a regular file'):
        load_corpus(corpus_file)


def test_load_corpus_rejects_character_device() -> None:
    # A character device would stream without end, so the size cap alone
    # cannot bound the read: only the regular-file check stops it.
    with pytest.raises(CorpusConfigError, match='not a regular file'):
        load_corpus(Path(os.devnull))


def test_load_corpus_rejects_oversized_file(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text(VALID_YAML + '\n#' + 'x' * 1_048_576, encoding='utf-8')
    with pytest.raises(CorpusConfigError, match='exceeds 1048576 bytes'):
        load_corpus(corpus_file)


def test_load_corpus_rejects_invalid_utf8(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_bytes(b'\xff')
    with pytest.raises(CorpusConfigError, match='not valid UTF-8'):
        load_corpus(corpus_file)


def test_load_corpus_rejects_bad_yaml(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text('projects: [', encoding='utf-8')
    with pytest.raises(CorpusConfigError, match='not valid YAML'):
        load_corpus(corpus_file)


def test_load_corpus_rejects_schema_violations(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text(VALID_YAML.replace('  - name: two', '  - name: two\n    surprise: 1'), encoding='utf-8')
    with pytest.raises(CorpusConfigError, match='invalid'):
        load_corpus(corpus_file)


def test_load_corpus_rejects_unknown_tool_references(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text(VALID_YAML, encoding='utf-8')
    with pytest.raises(CorpusConfigError, match="unknown tool 'skylos'"):
        load_corpus(corpus_file, known_tools=('vulture',))


def test_load_corpus_without_known_tools_skips_reference_check(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text(VALID_YAML, encoding='utf-8')
    corpus = load_corpus(corpus_file)
    assert len(corpus.projects) == 2


ANALYSES_YAML = VALID_YAML.replace('        cost: 3.0', '        cost: 3.0\n        analyses:\n          - danger')


def test_load_corpus_accepts_declared_analyses(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text(ANALYSES_YAML, encoding='utf-8')
    corpus = load_corpus(
        corpus_file,
        known_tools=('vulture', 'skylos'),
        known_analyses={'vulture': ('danger',), 'skylos': ()},
    )
    assert corpus.projects[0].tool_settings('vulture').analyses == ('danger',)


def test_load_corpus_rejects_undeclared_analyses(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text(ANALYSES_YAML, encoding='utf-8')
    with pytest.raises(CorpusConfigError, match="tool 'vulture' selects undeclared analysis 'danger'"):
        load_corpus(corpus_file, known_tools=('vulture', 'skylos'), known_analyses={'skylos': ('danger',)})


def test_load_corpus_without_known_analyses_skips_analysis_check(tmp_path: Path) -> None:
    corpus_file = tmp_path / 'corpus.yaml'
    corpus_file.write_text(ANALYSES_YAML, encoding='utf-8')
    corpus = load_corpus(corpus_file, known_tools=('vulture', 'skylos'))
    assert corpus.projects[0].tool_settings('vulture').analyses == ('danger',)


def test_tool_settings_reject_duplicate_analyses() -> None:
    with pytest.raises(ValidationError, match="analyses selects 'danger' more than once"):
        ToolSettings(analyses=('danger', 'secrets', 'danger'))


def test_ad_hoc_project_carries_cli_analyses() -> None:
    project = ad_hoc_project('https://github.com/example/thing', tool='skylos', analyses=('quality',))
    assert project.tool_settings('skylos').analyses == ('quality',)
    assert ad_hoc_project('https://github.com/example/thing', tool='skylos').tools == {}


def test_ad_hoc_project_analyses_require_a_tool() -> None:
    with pytest.raises(CorpusConfigError, match='require a tool name'):
        ad_hoc_project('https://github.com/example/thing', analyses=('quality',))


def test_ad_hoc_project_rejects_invalid_analyses() -> None:
    with pytest.raises(CorpusConfigError, match='invalid ad-hoc analyses'):
        ad_hoc_project('https://github.com/example/thing', tool='skylos', analyses=('quality', 'quality'))


def test_ad_hoc_project_derives_name() -> None:
    entry = ad_hoc_project('https://example.com/group/target.git')
    assert entry.name == 'target'
    assert entry.pin is None
    assert entry.branch is None
    assert entry.license is None


def test_ad_hoc_project_rejects_underivable_names() -> None:
    with pytest.raises(CorpusConfigError, match='cannot derive'):
        ad_hoc_project('https://example.com/group/%20bad')


def corpus_for_selection() -> Corpus:
    return Corpus(
        projects=(
            project('cheap', tools={'vulture': {'cost': 1.0}}),
            project('mid', tools={'vulture': {'cost': 5.0}}),
            project('pricey', tools={'vulture': {'cost': 30.0}}),
            project('uncosted'),
            project('excluded', exclude_tools=('vulture',), tools={'vulture': {'cost': 1.0}}),
        )
    )


def test_select_requires_exactly_one_selector() -> None:
    corpus = corpus_for_selection()
    with pytest.raises(CorpusConfigError, match='exactly one'):
        select_projects(corpus, tool='vulture')
    with pytest.raises(CorpusConfigError, match='exactly one'):
        select_projects(corpus, tool='vulture', select_all=True, max_cost=10.0)


def test_select_all_filters_tool_support() -> None:
    names = [entry.name for entry in select_projects(corpus_for_selection(), tool='vulture', select_all=True)]
    assert names == ['cheap', 'mid', 'pricey', 'uncosted']


def test_select_by_keyword_substring_union() -> None:
    names = [entry.name for entry in select_projects(corpus_for_selection(), tool='vulture', keywords=('chea', 'cost'))]
    assert names == ['cheap', 'uncosted']


def test_select_by_keyword_no_match_raises() -> None:
    with pytest.raises(CorpusConfigError, match='no corpus project matches'):
        select_projects(corpus_for_selection(), tool='vulture', keywords=('nomatch',))


def test_select_by_cost_greedy_under_budget() -> None:
    names = [entry.name for entry in select_projects(corpus_for_selection(), tool='vulture', max_cost=7.0)]
    assert names == ['cheap', 'mid']


def test_select_by_cost_skips_undeclared_and_keeps_file_order() -> None:
    corpus = Corpus(
        projects=(
            project('later', tools={'vulture': {'cost': 5.0}}),
            project('earlier', tools={'vulture': {'cost': 1.0}}),
        )
    )
    names = [entry.name for entry in select_projects(corpus, tool='vulture', max_cost=6.0)]
    assert names == ['later', 'earlier']


def test_select_by_cost_ties_break_by_name() -> None:
    corpus = Corpus(
        projects=(
            project('zeta', tools={'vulture': {'cost': 4.0}}),
            project('alpha', tools={'vulture': {'cost': 4.0}}),
        )
    )
    names = [entry.name for entry in select_projects(corpus, tool='vulture', max_cost=4.0)]
    assert names == ['alpha']


def test_packaged_corpus_loads_against_the_real_registry() -> None:
    """The shipped corpus resolves inside the package and validates (contract §5).

    The CLI's ``--corpus`` default points here, so this guards both the
    packaging (the file must travel with the distribution) and the corpus
    content against the adapters actually registered.
    """
    path = default_corpus_path()
    assert path.is_file()
    assert path.parent.parent.name == 'liveness_primer'
    corpus = load_corpus(path, known_tools=adapter_names(), known_analyses=adapter_analyses())
    assert corpus.projects
