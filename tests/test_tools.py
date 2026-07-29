"""Tests for the adapter protocol and the vulture/skylos adapters (contract §4, §15).

Copyright (C) 2026 Matthew C. Digman

Adapters are tested against recorded raw-output fixtures.
"""

import json
from pathlib import Path

import pytest

from liveness_primer.config import ToolSettings
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
from liveness_primer.tools.skylos import SkylosAdapter
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
    argv = build_invocation(VultureAdapter(), '/envs/base/bin/vulture', ToolSettings())
    assert argv == ['/envs/base/bin/vulture', '.']


def test_build_invocation_with_targets_and_args() -> None:
    settings = ToolSettings(args=('--min-confidence', '80'), targets=('src', 'tests'))
    argv = build_invocation(VultureAdapter(), '/envs/base/bin/vulture', settings)
    assert argv == ['/envs/base/bin/vulture', '--min-confidence', '80', 'src', 'tests']


def test_build_invocation_command_override_substitutes_exe() -> None:
    settings = ToolSettings(command=('{exe}', '--json'), targets=('pkg',))
    argv = build_invocation(SkylosAdapter(), '/envs/head/bin/skylos', settings)
    assert argv == ['/envs/head/bin/skylos', '--json', 'pkg']


def test_build_invocation_command_override_without_placeholder() -> None:
    settings = ToolSettings(command=('/opt/wrapper', '--mode', 'scan'))
    argv = build_invocation(SkylosAdapter(), '/ignored', settings)
    assert argv == ['/opt/wrapper', '--mode', 'scan', '.']


def test_normalize_finding_path_relative_and_absolute() -> None:
    assert normalize_finding_path('pkg/mod.py', ROOT) == 'pkg/mod.py'
    assert normalize_finding_path('./pkg/mod.py', ROOT) == 'pkg/mod.py'
    assert normalize_finding_path('/checkout/pkg/mod.py', ROOT) == 'pkg/mod.py'
    assert normalize_finding_path('/elsewhere/mod.py', ROOT) == '/elsewhere/mod.py'


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
    output = raw((FIXTURES / 'skylos_output.json').read_text(encoding='utf-8'))
    findings = SkylosAdapter.parse(output, project='demo', root=ROOT)
    assert len(findings) == 6
    by_symbol = {finding.symbol: finding for finding in findings}
    assert by_symbol['pkg.mod.orphan'].kind == 'function'
    assert by_symbol['pkg.mod.orphan'].confidence == 100
    assert by_symbol['pkg.mod.orphan'].message == "unused function 'orphan'"
    assert by_symbol['pkg.mod.Greeter.farewell'].kind == 'method'
    assert by_symbol['pkg.mod.os'].kind == 'import'
    assert by_symbol['pkg.shapes.Hexagon'].kind == 'class'
    assert by_symbol['pkg.consts.LEGACY_LIMIT'].kind == 'constant'
    assert by_symbol['pkg.mod.orphan.flag'].kind == 'parameter'
    assert by_symbol['pkg.mod.orphan.flag'].start_line == 4
    excerpt = by_symbol['pkg.mod.orphan'].raw_excerpt
    assert excerpt is not None
    assert json.loads(excerpt)['name'] == 'orphan'


def test_skylos_ignores_non_dead_code_categories() -> None:
    document: dict[str, list[dict[str, object]]] = {
        'unused_functions': [],
        'unused_imports': [],
        'unused_classes': [],
        'unused_variables': [],
        'unused_parameters': [],
        'danger': [{'rule_id': 'SKY-D001', 'message': 'eval', 'file': 'a.py', 'line': 1}],
        'secrets': [{'rule_id': 'SKY-S001'}],
        'quality': [{'rule_id': 'SKY-L001'}],
    }
    assert SkylosAdapter.parse(raw(json.dumps(document)), project='demo', root=ROOT) == []


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
        SkylosAdapter.parse(raw('Error during analysis: boom'), project='demo', root=ROOT)


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
