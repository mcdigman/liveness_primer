"""Export of the versioned JSON Schemas (contract §7).

Copyright (C) 2026 Matthew C. Digman

Pydantic models are the source of truth; the JSON Schema files under
``liveness_primer/schemas/`` are exported from them by ``schema export`` and
a CI check enforces that the files match the models.
"""

import json
from collections.abc import Mapping
from pathlib import Path

from pydantic import BaseModel

from liveness_primer.findings import (
    Annotation,
    ExplorerExport,
    ExplorerReview,
    Finding,
    FindingDiff,
    FindingOccurrence,
    HookEnvelope,
    Report,
    RunManifest,
)

EXPORTED_MODELS: Mapping[str, type[BaseModel]] = {
    'annotation': Annotation,
    'explorer-export': ExplorerExport,
    'explorer-review': ExplorerReview,
    'finding': Finding,
    'finding-diff': FindingDiff,
    'finding-occurrence': FindingOccurrence,
    'hook-envelope': HookEnvelope,
    'report': Report,
    'run-manifest': RunManifest,
}


def schemas_dir() -> Path:
    """Locate the in-package schema directory.

    Returns
    -------
    Path
        ``liveness_primer/schemas/``.
    """
    return Path(__file__).parent / 'schemas'


def render_schema(model: type[BaseModel]) -> str:
    """Serialize one model's JSON Schema deterministically.

    The format matches the repository's ``pretty-format-json`` hook
    (2-space indent, sorted keys, ASCII escapes) so exported files are
    hook-stable.

    Parameters
    ----------
    model : type[BaseModel]
        The model to serialize.

    Returns
    -------
    str
        The schema document, newline-terminated.
    """
    schema = model.model_json_schema(mode='serialization')
    # Exported documents declare their JSON Schema dialect so consumers
    # compile validators for it rather than guessing (explorer §4.3).
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=True) + '\n'


def export_schemas(target: Path | None = None) -> tuple[Path, ...]:
    """Regenerate the JSON Schema files (``schema export``, contract §12).

    Parameters
    ----------
    target : Path | None
        Output directory; the in-package schema directory by default.

    Returns
    -------
    tuple[Path, ...]
        The written files, in export order.
    """
    directory = target if target is not None else schemas_dir()
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in EXPORTED_MODELS.items():
        path = directory / f'{name}.schema.json'
        path.write_text(render_schema(model), encoding='utf-8')
        written.append(path)
    return tuple(written)


def stale_schemas(target: Path | None = None) -> tuple[str, ...]:
    """List schema files that do not match the models (contract §7).

    Parameters
    ----------
    target : Path | None
        Directory holding the exported files; the in-package schema
        directory by default.

    Returns
    -------
    tuple[str, ...]
        Names of missing or outdated schema files; empty when in sync.
    """
    directory = target if target is not None else schemas_dir()
    stale: list[str] = []
    for name, model in EXPORTED_MODELS.items():
        path = directory / f'{name}.schema.json'
        try:
            current = path.read_text(encoding='utf-8')
        except FileNotFoundError:
            stale.append(name)
            continue
        if current != render_schema(model):
            stale.append(name)
    return tuple(stale)
