# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""AST-walking enforcement of the audited-launcher rule (contract §11, §15).

No call anywhere in the package may pass a ``shell`` keyword, and no module
outside the launcher may reach the raw subprocess APIs — including event-loop
instance methods (``loop.subprocess_exec``/``loop.subprocess_shell``), which
qualified-name banning in ``ruff.toml`` cannot see.
"""

import ast
from pathlib import Path

import liveness_primer

PACKAGE_ROOT = Path(liveness_primer.__file__).resolve().parent
LAUNCHER = PACKAGE_ROOT / 'launcher.py'

RAW_MODULES = {'subprocess', 'pty'}
RAW_OS_CALLABLES = {
    'system',
    'popen',
    'execl',
    'execle',
    'execlp',
    'execlpe',
    'execv',
    'execve',
    'execvp',
    'execvpe',
    'spawnl',
    'spawnle',
    'spawnlp',
    'spawnlpe',
    'spawnv',
    'spawnve',
    'spawnvp',
    'spawnvpe',
    'posix_spawn',
    'posix_spawnp',
}
RAW_ATTRIBUTES = {
    # asyncio module-level factories and event-loop instance methods; the
    # attribute name alone is banned because static analysis cannot resolve
    # the receiver of a ``loop.subprocess_exec`` call.
    'create_subprocess_exec',
    'create_subprocess_shell',
    'subprocess_exec',
    'subprocess_shell',
}


def package_sources() -> list[Path]:
    files = sorted(PACKAGE_ROOT.rglob('*.py'))
    assert LAUNCHER in files
    return files


def iter_calls(tree: ast.AST) -> list[ast.Call]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def test_no_call_passes_a_shell_keyword() -> None:
    offenders: list[str] = []
    for source in package_sources():
        tree = ast.parse(source.read_text(encoding='utf-8'))
        offenders.extend(
            f'{source.name}:{call.lineno}'
            for call in iter_calls(tree)
            if any(keyword.arg == 'shell' for keyword in call.keywords)
        )
    assert offenders == []


def import_offences(node: ast.Import) -> list[str]:
    return [f'imports {alias.name}' for alias in node.names if alias.name.split('.')[0] in RAW_MODULES]


def import_from_offences(node: ast.ImportFrom) -> list[str]:
    module_root = (node.module or '').split('.')[0]
    if module_root in RAW_MODULES:
        return [f'imports from {node.module}']
    if module_root in {'os', 'asyncio'}:
        return [
            f'imports {module_root}.{alias.name}'
            for alias in node.names
            if alias.name in RAW_OS_CALLABLES | RAW_ATTRIBUTES
        ]
    return []


def attribute_offences(node: ast.Attribute) -> list[str]:
    if node.attr in RAW_ATTRIBUTES:
        return [f'touches .{node.attr}']
    if node.attr in RAW_OS_CALLABLES and isinstance(node.value, ast.Name) and node.value.id == 'os':
        return [f'touches os.{node.attr}']
    return []


def node_offences(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return import_offences(node)
    if isinstance(node, ast.ImportFrom):
        return import_from_offences(node)
    if isinstance(node, ast.Attribute):
        return attribute_offences(node)
    return []


def test_raw_subprocess_apis_only_in_launcher() -> None:
    offenders: list[str] = []
    for source in package_sources():
        if source == LAUNCHER:
            continue
        tree = ast.parse(source.read_text(encoding='utf-8'))
        for node in ast.walk(tree):
            offenders.extend(f'{source.name}:{getattr(node, "lineno", 0)} {offence}' for offence in node_offences(node))
    assert offenders == []


def test_launcher_exposes_no_shell_parameter() -> None:
    tree = ast.parse(LAUNCHER.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            arg_names = {arg.arg for arg in [*node.args.args, *node.args.kwonlyargs, *node.args.posonlyargs]}
            assert 'shell' not in arg_names, f'launcher.{node.name} exposes a shell parameter'
