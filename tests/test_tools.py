# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the adapter protocol and the vulture/skylos adapters (contract §4, §15).

Adapters are tested against recorded raw-output fixtures.
"""

import json
from pathlib import Path, PurePosixPath

import pytest

from liveness_primer.config import CorpusConfigError, ToolSettings
from liveness_primer.tools import adapter_names, get_adapter
from liveness_primer.tools.base import (
    AdapterError,
    BuildRecipe,
    DetectorAdapter,
    RawToolOutput,
    ToolchainRequirement,
    UnknownToolError,
    build_invocation,
    normalize_finding_path,
)
from liveness_primer.tools.skylos import DEAD_CODE_KEYS, SkylosAdapter
from liveness_primer.tools.vulture import VultureAdapter

FIXTURES = Path(__file__).parent / 'fixtures'
ROOT = Path('/checkout')


def raw(stdout: str, returncode: int = 0) -> RawToolOutput:
    return RawToolOutput(returncode=returncode, stdout=stdout, stderr='')


def test_registry_lists_phase_one_adapters() -> None:
    assert adapter_names() == ('vulture', 'skylos')


def test_registry_returns_protocol_satisfying_adapters() -> None:
    for name in adapter_names():
        assert isinstance(get_adapter(name), DetectorAdapter)


def test_registry_rejects_unknown_tools() -> None:
    with pytest.raises(UnknownToolError, match="unknown tool 'pylint'"):
        get_adapter('pylint')


def test_build_recipe_digest_is_stable_and_content_sensitive() -> None:
    plain = BuildRecipe(backend='python-source')
    rust = BuildRecipe(backend='maturin', toolchain=(ToolchainRequirement(name='rust', minimum_version='1.74'),))
    assert plain.digest() == BuildRecipe(backend='python-source').digest()
    assert plain.digest() != rust.digest()


def test_build_invocation_defaults() -> None:
    argv = build_invocation(VultureAdapter(), ['/envs/base/bin/vulture'], ToolSettings())
    assert argv == ['/envs/base/bin/vulture', '.']


def test_build_invocation_with_targets_and_args() -> None:
    settings = ToolSettings(args=('--min-confidence', '80'), targets=('src', 'tests'))
    argv = build_invocation(VultureAdapter(), ['/envs/base/bin/vulture'], settings)
    assert argv == ['/envs/base/bin/vulture', '--min-confidence', '80', 'src', 'tests']


def test_build_invocation_command_override_substitutes_exe() -> None:
    settings = ToolSettings(command=('{exe}', '--json'), targets=('pkg',))
    argv = build_invocation(SkylosAdapter(), ['python', '-m', 'skylos'], settings)
    assert argv == ['python', '-m', 'skylos', '--json', 'pkg']


def test_build_invocation_appends_declared_analysis_flags() -> None:
    settings = ToolSettings(analyses=('danger', 'secrets'), args=('--confidence', '80'), targets=('src',))
    argv = build_invocation(SkylosAdapter(), ['/envs/base/bin/skylos'], settings)
    assert argv == ['/envs/base/bin/skylos', '--json', '--danger', '--secrets', '--confidence', '80', 'src']


def test_build_invocation_rejects_undeclared_analyses() -> None:
    with pytest.raises(CorpusConfigError, match="tool 'vulture' does not provide analysis 'danger'"):
        build_invocation(VultureAdapter(), ['/envs/base/bin/vulture'], ToolSettings(analyses=('danger',)))


def test_skylos_declares_the_documented_analyses() -> None:
    assert dict(SkylosAdapter.analyses) == {
        'danger': ('--danger',),
        'secrets': ('--secrets',),
        'quality': ('--quality',),
        'ai-defects': ('--ai-defects',),
    }
    assert dict(VultureAdapter.analyses) == {}


def test_normalize_finding_path_relative_and_absolute() -> None:
    assert normalize_finding_path('pkg/mod.py', ROOT) == 'pkg/mod.py'
    assert normalize_finding_path('./pkg/mod.py', ROOT) == 'pkg/mod.py'
    assert normalize_finding_path('/checkout/pkg/mod.py', ROOT) == 'pkg/mod.py'
    assert normalize_finding_path('pkg/../mod.py', ROOT) == 'mod.py'


def test_normalize_finding_path_with_a_container_side_root() -> None:
    # A container-side root is a pure POSIX path; reported paths parse in
    # the same flavor, so prefix stripping works on every host platform —
    # including Windows, where PurePosixPath is not a native Path (§7).
    root = PurePosixPath('/liveness/work/side-x1/checkout')
    assert normalize_finding_path('/liveness/work/side-x1/checkout/pkg/mod.py', root) == 'pkg/mod.py'
    assert normalize_finding_path('pkg/mod.py', root) == 'pkg/mod.py'
    with pytest.raises(AdapterError, match='outside the checkout'):
        normalize_finding_path('/somewhere/else.py', root)


def test_normalize_finding_path_resolves_symlinked_roots(tmp_path: Path) -> None:
    # e.g. macOS /tmp -> /private/tmp: detectors may print the resolved
    # absolute prefix while the runner holds the unresolved one.
    real_root = tmp_path / 'real'
    real_root.mkdir()
    link_root = tmp_path / 'link'
    link_root.symlink_to(real_root)
    assert normalize_finding_path(str(real_root / 'pkg' / 'mod.py'), link_root) == 'pkg/mod.py'


@pytest.mark.parametrize(
    'hostile',
    [
        '/etc/passwd',
        '/elsewhere/mod.py',
        '../secret.py',
        'pkg/../../secret.py',
        '..',
    ],
)
def test_normalize_finding_path_rejects_escapes(hostile: str) -> None:
    # Contract §7: Finding.path is repo-relative; out-of-root detector
    # output is malformed, never preserved (contract §11).
    with pytest.raises(AdapterError, match='outside the checkout'):
        normalize_finding_path(hostile, ROOT)


@pytest.mark.parametrize('empty', ['', '.', 'pkg/..'])
def test_normalize_finding_path_rejects_non_files(empty: str) -> None:
    with pytest.raises(AdapterError, match='naming no file'):
        normalize_finding_path(empty, ROOT)


def test_vulture_parses_recorded_fixture() -> None:
    output = raw((FIXTURES / 'vulture_output.txt').read_text(encoding='utf-8'), returncode=3)
    findings = VultureAdapter.parse(output, project='demo', root=ROOT)
    assert len(findings) == 11
    by_symbol = {finding.symbol: finding for finding in findings if finding.symbol is not None}
    assert by_symbol['os'].kind == 'import'
    assert by_symbol['os'].confidence == 90
    assert by_symbol['greet'].kind == 'function'
    assert by_symbol['message'].kind == 'variable'
    assert by_symbol['attr'].kind == 'attribute'
    assert by_symbol['Widget'].kind == 'class'
    assert by_symbol['render'].kind == 'method'
    assert by_symbol['total'].kind == 'property'
    assert by_symbol['arg'].path == 'relative.py'
    unreachable = [finding for finding in findings if finding.symbol is None]
    assert {finding.kind for finding in unreachable} == {'unreachable_code'}
    assert {finding.message for finding in unreachable} == {
        "unreachable code after 'return'",
        "unsatisfiable 'if' condition",
        "unreachable 'else' block",
    }
    assert all(finding.confidence == 100 for finding in unreachable)
    assert all(finding.start_line == finding.end_line for finding in findings)
    assert all(finding.raw_excerpt is not None for finding in findings)


def test_vulture_parses_sort_by_size_suffix() -> None:
    output = raw("big.py:10: unused function 'huge' (60% confidence, 121 lines)\n", returncode=3)
    (finding,) = VultureAdapter.parse(output, project='demo', root=ROOT)
    assert (finding.symbol, finding.start_line, finding.confidence) == ('huge', 10, 60)


def test_vulture_tolerates_blank_lines_and_empty_output() -> None:
    assert VultureAdapter.parse(raw('\n\n'), project='demo', root=ROOT) == []
    assert VultureAdapter.parse(raw(''), project='demo', root=ROOT) == []


def test_vulture_rejects_unparseable_lines() -> None:
    output = raw('completely unexpected chatter\n', returncode=3)
    with pytest.raises(AdapterError, match='unparseable vulture output'):
        VultureAdapter.parse(output, project='demo', root=ROOT)


def test_vulture_symbols_may_contain_quotes() -> None:
    output = raw("odd.py:2: unused variable 'it''s' (60% confidence)\n", returncode=3)
    (finding,) = VultureAdapter.parse(output, project='demo', root=ROOT)
    assert finding.symbol == "it''s"


def test_skylos_parses_recorded_fixture() -> None:
    document = (FIXTURES / 'skylos_output.json').read_text(encoding='utf-8')
    recorded = json.loads(document)
    # Recorded Skylos 4.33.2 result buckets use absolute paths, while its
    # nested evidence retains relative paths. Preserve that mixed raw shape.
    assert all(Path(entry['file']).is_absolute() for key in DEAD_CODE_KEYS for entry in recorded[key])
    evidence = recorded['dead_code_evidence']['symbols']
    assert evidence
    assert all(not Path(entry['file']).is_absolute() for entry in evidence)
    scope = recorded['analysis_summary']['comparison_scope']
    assert scope['repository_root'] == ROOT.as_posix()
    assert scope['scan_path'] == ROOT.as_posix()
    output = raw(document)
    findings = SkylosAdapter.parse(output, project='demo', root=ROOT)
    assert len(findings) == 8
    assert all(not finding.path.startswith('/') for finding in findings)
    by_symbol = {finding.symbol: finding for finding in findings if finding.symbol is not None}
    assert by_symbol['pkg.mod.orphan'].kind == 'function'
    assert by_symbol['pkg.mod.orphan'].confidence == 100
    assert by_symbol['pkg.mod.orphan'].message == "unused function 'orphan'"
    assert by_symbol['pkg.mod.Greeter.farewell'].kind == 'method'
    assert by_symbol['os'].kind == 'import'
    assert by_symbol['pkg.shapes.Hexagon'].kind == 'class'
    assert by_symbol['pkg.consts.LEGACY_LIMIT'].kind == 'variable'
    assert by_symbol['pkg.mod.orphan.flag'].kind == 'parameter'
    assert by_symbol['pkg.mod.orphan.flag'].start_line == 7
    excerpt = by_symbol['pkg.mod.orphan'].raw_excerpt
    assert excerpt is not None
    assert json.loads(excerpt)['name'] == 'orphan'
    # Reporting contract §3.1: the documented bucket mapping supplies the
    # canonical rule ID for every ingested symbol category.
    assert by_symbol['pkg.mod.orphan'].rule_id == 'SKY-U001'
    assert by_symbol['pkg.mod.Greeter.farewell'].rule_id == 'SKY-U001'
    assert by_symbol['os'].rule_id == 'SKY-U002'
    assert by_symbol['pkg.consts.LEGACY_LIMIT'].rule_id == 'SKY-U003'
    assert by_symbol['pkg.shapes.Hexagon'].rule_id == 'SKY-U004'
    assert by_symbol['pkg.mod.orphan.flag'].rule_id == 'SKY-U006'
    # Reporting contract §3.1: `unused_files` is a multi-rule bucket whose
    # entries carry their explicit rule IDs; there is no bucket fallback.
    by_path = {finding.path: finding for finding in findings if finding.kind == 'file'}
    assert by_path['pkg/blank.py'].rule_id == 'SKY-E002'
    assert by_path['pkg/blank.py'].symbol is None
    assert by_path['pkg/blank.py'].severity == 'LOW'
    assert by_path['pkg/blank.py'].start_line == 1
    assert by_path['pkg/orphan.ts'].rule_id == 'SKY-E003'
    assert by_path['pkg/orphan.ts'].message == 'Unused TypeScript/JavaScript file (not imported by any other file)'


def test_skylos_explicit_rule_id_takes_precedence_over_bucket_mapping() -> None:
    # Reporting contract §3.1 precedence: a rule ID explicitly present on
    # the detector finding wins over the documented bucket mapping.
    document = {
        'unused_functions': [
            {'name': 'a', 'type': 'function', 'file': 'a.py', 'line': 1, 'rule_id': 'SKY-U777'},
            {'name': 'b', 'type': 'function', 'file': 'a.py', 'line': 2},
        ]
    }
    explicit, mapped = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT)
    assert explicit.rule_id == 'SKY-U777'
    assert mapped.rule_id == 'SKY-U001'


def test_skylos_ingests_unused_files() -> None:
    document = {
        'unused_files': [
            {
                'rule_id': 'SKY-E003',
                'message': 'Unused TypeScript/JavaScript file (not imported by any other file)',
                'file': '/checkout/pkg/orphan.ts',
                'line': 1,
                'severity': 'low',
                'category': 'DEAD_CODE',
            },
            {
                'rule_id': 'SKY-E002',
                'message': 'Empty Python file (no code, or docstring-only)',
                'file': 'pkg/zero.py',
                'line': 0,
            },
        ]
    }

    findings = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT)

    assert len(findings) == 2
    typescript, python = findings
    assert typescript.path == 'pkg/orphan.ts'
    assert typescript.symbol is None
    assert typescript.kind == 'file'
    assert typescript.message == 'Unused TypeScript/JavaScript file (not imported by any other file)'
    assert typescript.start_line == typescript.end_line == 1
    assert typescript.confidence is None
    assert typescript.severity == 'LOW'
    assert typescript.rule_id == 'SKY-E003'
    assert typescript.raw_excerpt is not None
    assert 'category' not in json.loads(typescript.raw_excerpt)
    assert python.path == 'pkg/zero.py'
    assert python.start_line == python.end_line == 1
    assert python.severity is None
    assert python.rule_id == 'SKY-E002'


@pytest.mark.parametrize(
    'entry',
    [
        # Guaranteed fields missing outright.
        {'file': 'empty.py', 'line': 1},
        # An entry without its explicit rule ID is malformed: `unused_files`
        # is a multi-rule bucket with no fallback (reporting contract §3.1),
        # so a defaulted code would corrupt the finding identity.
        {'message': 'Empty Python file (no code, or docstring-only)', 'file': 'empty.py', 'line': 1},
    ],
)
def test_skylos_rejects_malformed_unused_file_entries(entry: dict[str, object]) -> None:
    document = {'unused_files': [entry]}
    with pytest.raises(AdapterError, match="malformed skylos entry in 'unused_files'"):
        SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT)


@pytest.mark.parametrize(
    'document',
    [
        {},
        {'error': 'analysis aborted before producing a report'},
        {
            'unused_functions': [],
            'unused_imports': [],
            'unused_classes': [],
            'unused_variables': [],
            'unused_parameters': [],
            'analysis_errors': [{'rule_id': 'SKY-ANALYSIS-INCOMPLETE'}],
        },
    ],
)
def test_skylos_rejects_failed_output_without_findings(document: dict[str, object]) -> None:
    with pytest.raises(AdapterError, match='no findings in recognized result buckets'):
        SkylosAdapter.parse(raw(json.dumps(document), returncode=2), project='demo', root=ROOT)


def test_skylos_accepts_failed_output_with_a_result_bucket() -> None:
    document = {'unused_functions': [{'name': 'a', 'type': 'function', 'file': 'a.py', 'line': 1}]}
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document), returncode=2), project='demo', root=ROOT)
    assert finding.symbol == 'a'


def test_vulture_findings_carry_no_invented_rule_id() -> None:
    # Reporting contract §3.1 and acceptance 4: a detector without a native
    # rule ID yields None, never an invented tool-specific code.
    output = raw("clean.py:3: unused function 'f' (60% confidence)\n", returncode=3)
    (finding,) = VultureAdapter.parse(output, project='demo', root=ROOT)
    assert finding.rule_id is None


def test_skylos_ingests_diagnostic_buckets_with_per_bucket_kinds() -> None:
    # Every opt-in analysis array is ingested when present; arrays outside
    # the documented set stay filtered at the adapter (contract §4).
    document: dict[str, list[dict[str, object]]] = {
        'danger': [{'rule_id': 'SKY-D001', 'message': 'eval', 'file': 'a.py', 'line': 1}],
        'secrets': [{'rule_id': 'SKY-S101', 'severity': 'CRITICAL', 'message': 'AWS key', 'file': 'a.py', 'line': 2}],
        'quality': [{'rule_id': 'SKY-L014', 'severity': 'HIGH', 'message': 'bare except', 'file': 'a.py', 'line': 3}],
        'ai_defects': [{'rule_id': 'SKY-AI001', 'message': 'hallucinated API', 'file': 'a.py', 'line': 4}],
        'circular_dependencies': [{'rule_id': 'SKY-CIRC'}],
    }
    findings = SkylosAdapter.parse(
        raw(json.dumps(document)),
        project='demo',
        root=ROOT,
        analyses=('danger', 'secrets', 'quality', 'ai-defects'),
    )
    by_rule = {finding.rule_id: finding for finding in findings}
    assert set(by_rule) == {'SKY-D001', 'SKY-S101', 'SKY-L014', 'SKY-AI001'}
    assert by_rule['SKY-D001'].kind == 'danger'
    assert by_rule['SKY-S101'].kind == 'secret'
    assert by_rule['SKY-L014'].kind == 'quality'
    assert by_rule['SKY-AI001'].kind == 'ai_defect'
    assert by_rule['SKY-D001'].symbol is None
    assert by_rule['SKY-D001'].severity is None
    assert by_rule['SKY-S101'].severity == 'CRITICAL'
    assert all(finding.confidence is None for finding in findings)


def test_skylos_secret_entries_keep_undeclared_fields_out_of_the_excerpt() -> None:
    document = {
        'secrets': [
            {
                'rule_id': 'SKY-S101',
                'severity': 'CRITICAL',
                'message': 'Potential AWS secret access key detected',
                'file': 'a.py',
                'line': 4,
                'preview': 'wJal****EKEY',
                'entropy': 4.66,
                'provider': 'aws_secret_access_key',
            }
        ]
    }
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT, analyses=('secrets',))
    assert finding.raw_excerpt is not None
    excerpt = json.loads(finding.raw_excerpt)
    assert 'preview' not in excerpt
    assert 'entropy' not in excerpt
    assert 'provider' not in excerpt


def test_skylos_unselected_diagnostic_buckets_are_filtered() -> None:
    # Provenance guard: a target repository's own skylos configuration may
    # emit diagnostic arrays the run never selected; parse ingests only
    # the selected analyses (contract §4, §5).
    document = {
        'unused_functions': [{'name': 'a', 'type': 'function', 'file': 'a.py', 'line': 1}],
        'danger': [{'rule_id': 'SKY-D001', 'message': 'eval', 'file': 'a.py', 'line': 1}],
        'secrets': [{'rule_id': 'SKY-S101', 'message': 'key', 'file': 'a.py', 'line': 2}],
    }
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT)
    assert finding.kind == 'function'
    partial = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT, analyses=('danger',))
    assert [entry.kind for entry in partial] == ['function', 'danger']


def test_skylos_danger_name_is_a_rule_marker_not_a_symbol() -> None:
    # Real SKY-D260 output carries name=prompt_injection as a rule marker;
    # promoting it to the symbol would change the finding identity. Only
    # quality diagnostics name their subject in `name`.
    document = {
        'danger': [
            {
                'rule_id': 'SKY-D260',
                'severity': 'HIGH',
                'message': 'Potential prompt injection sink',
                'file': 'a.py',
                'line': 3,
                'name': 'prompt_injection',
            }
        ]
    }
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT, analyses=('danger',))
    assert finding.symbol is None


def test_adapters_declare_invocation_environments() -> None:
    env = dict(SkylosAdapter.invocation_env)
    assert set(env) == {'SKYLOS_GREP_BUDGET'}
    # The neutral config is declared as a file, so container mode can stage
    # it where the detector reads it instead of forwarding a host-only path.
    neutral_config = SkylosAdapter.invocation_env_files['SKYLOS_CONFIG_FILE']
    assert neutral_config.is_absolute()
    assert neutral_config.is_file()
    assert '[skylos]' in neutral_config.read_text(encoding='utf-8')
    # Skylos parses the budget as a float of seconds; it has to stay under
    # the default per-(project, tool) timeout to leave room for the run.
    assert 0 < float(env['SKYLOS_GREP_BUDGET']) < 300
    assert dict(VultureAdapter.invocation_env) == {}
    assert dict(VultureAdapter.invocation_env_files) == {}


def test_adapters_declare_native_helper_variables() -> None:
    # Skylos needs its prebuilt Go engine to analyze Go sources — including
    # its own — and the scrubbed environment admits it only by declaration.
    assert SkylosAdapter.passthrough_env == ('SKYLOS_GO_BIN',)
    # A declared variable must not collide with the pinned static ones.
    pinned = set(SkylosAdapter.invocation_env) | set(SkylosAdapter.invocation_env_files)
    assert not set(SkylosAdapter.passthrough_env) & pinned
    assert VultureAdapter.passthrough_env == ()


def test_skylos_parse_rejects_undeclared_analyses() -> None:
    with pytest.raises(AdapterError, match="skylos does not provide analysis 'sca'"):
        SkylosAdapter.parse(raw('{}'), project='demo', root=ROOT, analyses=('sca',))


def test_vulture_parse_rejects_any_analyses() -> None:
    with pytest.raises(AdapterError, match="vulture does not provide analysis 'danger'"):
        VultureAdapter.parse(raw(''), project='demo', root=ROOT, analyses=('danger',))


def test_skylos_parses_recorded_analyses_fixture() -> None:
    # Recorded skylos 4.33 output: quality carries source-anchored and
    # repository-level policy diagnostics; the latter report the checkout
    # root itself and normalize to the '.' path instead of aborting the
    # project analysis.
    output = raw((FIXTURES / 'skylos_analyses_output.json').read_text(encoding='utf-8'))
    findings = SkylosAdapter.parse(output, project='demo', root=ROOT, analyses=('danger', 'secrets', 'quality'))
    by_rule = {finding.rule_id: finding for finding in findings}
    assert set(by_rule) == {'SKY-D209', 'SKY-S101', 'SKY-L014', 'SKY-R104', 'SKY-U001'}
    policy = by_rule['SKY-R104']
    assert policy.path == '.'
    assert policy.symbol == 'pre-commit-policy'
    assert policy.kind == 'quality'
    assert policy.severity == 'LOW'
    assert by_rule['SKY-L014'].symbol == 'API_TOKEN'
    assert by_rule['SKY-L014'].path == 'pkg/mod.py'
    assert by_rule['SKY-S101'].raw_excerpt is not None
    assert 'preview' not in json.loads(by_rule['SKY-S101'].raw_excerpt)
    assert by_rule['SKY-U001'].symbol == 'pkg.mod.bad'


def test_normalize_finding_path_allow_root_maps_the_root_to_dot() -> None:
    assert normalize_finding_path('/checkout', ROOT, allow_root=True) == '.'
    assert normalize_finding_path('.', ROOT, allow_root=True) == '.'
    with pytest.raises(AdapterError, match='outside the checkout'):
        normalize_finding_path('/elsewhere', ROOT, allow_root=True)


def test_skylos_quality_entries_map_name_to_symbol() -> None:
    document = {
        'quality': [
            {
                'rule_id': 'SKY-L014',
                'severity': 'HIGH',
                'message': 'Hardcoded credential',
                'file': 'a.py',
                'line': 4,
                'name': 'API_TOKEN',
                'kind': 'logic',
            }
        ]
    }
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT, analyses=('quality',))
    assert finding.symbol == 'API_TOKEN'
    assert finding.kind == 'quality'


def test_skylos_danger_entries_normalize_severity_and_keep_symbols() -> None:
    document = {
        'danger': [
            {
                'rule_id': 'SKY-D212',
                'severity': 'Critical!',
                'message': 'Possible command injection',
                'file': 'a.py',
                'line': 9,
                'symbol': 'run',
                'category': 'danger',
                'compliance_tags': [{'framework': 'OWASP_TOP10'}],
            }
        ]
    }
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT, analyses=('danger',))
    assert finding.severity == 'CRITICAL'
    assert finding.symbol == 'run'
    assert finding.start_line == 9
    assert finding.end_line == 9


def test_skylos_declares_the_severity_capability() -> None:
    assert SkylosAdapter.capabilities.has_severity is True
    assert VultureAdapter.capabilities.has_severity is False


def test_skylos_rejects_malformed_danger_entries() -> None:
    document = {'danger': [{'rule_id': 'SKY-D001', 'file': 'a.py', 'line': 1}]}
    with pytest.raises(AdapterError, match="malformed skylos entry in 'danger'"):
        SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT, analyses=('danger',))


def test_skylos_rejects_non_array_danger_bucket() -> None:
    with pytest.raises(AdapterError, match="key 'danger' is not an array"):
        SkylosAdapter.parse(raw('{"danger": {}}'), project='demo', root=ROOT, analyses=('danger',))


def test_skylos_clamps_danger_line_zero_to_one() -> None:
    document = {'danger': [{'rule_id': 'SKY-D001', 'message': 'eval', 'file': 'a.py', 'line': 0}]}
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT, analyses=('danger',))
    assert finding.start_line == 1


def test_skylos_falls_back_to_name_when_full_name_missing() -> None:
    document = {'unused_functions': [{'name': 'orphan', 'type': 'function', 'file': 'a.py', 'line': 3}]}
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT)
    assert finding.symbol == 'orphan'
    assert finding.confidence is None


def test_skylos_clamps_line_zero_to_one() -> None:
    document = {'unused_imports': [{'name': 'os', 'type': 'import', 'file': 'a.py', 'line': 0}]}
    (finding,) = SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT)
    assert finding.start_line == 1


def test_skylos_rejects_invalid_json() -> None:
    with pytest.raises(AdapterError, match='not valid JSON'):
        SkylosAdapter.parse(raw('Error during analysis: boom', returncode=2), project='demo', root=ROOT)


def test_skylos_rejects_non_object_document() -> None:
    with pytest.raises(AdapterError, match='not a JSON object'):
        SkylosAdapter.parse(raw('[1, 2]'), project='demo', root=ROOT)


def test_skylos_rejects_non_array_bucket() -> None:
    with pytest.raises(AdapterError, match="key 'unused_functions' is not an array"):
        SkylosAdapter.parse(raw('{"unused_functions": {}}'), project='demo', root=ROOT)


def test_skylos_rejects_malformed_entries() -> None:
    document = {'unused_functions': [{'type': 'function', 'file': 'a.py', 'line': 3}]}
    with pytest.raises(AdapterError, match="malformed skylos entry in 'unused_functions'"):
        SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT)
