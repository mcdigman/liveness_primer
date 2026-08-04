"""Tests for JSON Schema export and the sync rule (contract §7, §15).

Copyright (C) 2026 Matthew C. Digman
"""

import json
from pathlib import Path

from liveness_primer.findings import SCHEMA_VERSION
from liveness_primer.schema_export import EXPORTED_MODELS, export_schemas, schemas_dir, stale_schemas


def test_export_writes_every_contract_model(tmp_path: Path) -> None:
    written = export_schemas(tmp_path)
    assert [path.name for path in written] == [f'{name}.schema.json' for name in EXPORTED_MODELS]
    assert 'explorer-review.schema.json' in {path.name for path in written}
    for path in written:
        document = json.loads(path.read_text(encoding='utf-8'))
        assert document.get('title') or document.get('$defs')
        # Every exported document declares its dialect so validators are
        # compiled for it rather than a build-time guess (explorer §4.3).
        assert document['$schema'] == 'https://json-schema.org/draft/2020-12/schema'


def test_report_schema_embeds_schema_version_default(tmp_path: Path) -> None:
    export_schemas(tmp_path)
    document = json.loads((tmp_path / 'report.schema.json').read_text(encoding='utf-8'))
    assert document['properties']['schema_version']['default'] == SCHEMA_VERSION


def test_shipped_schemas_are_in_sync_with_the_models() -> None:
    assert stale_schemas() == ()
    assert schemas_dir().is_dir()


def test_stale_schemas_reports_missing_and_outdated(tmp_path: Path) -> None:
    assert set(stale_schemas(tmp_path)) == set(EXPORTED_MODELS)
    export_schemas(tmp_path)
    assert stale_schemas(tmp_path) == ()
    (tmp_path / 'report.schema.json').write_text('{}\n', encoding='utf-8')
    assert stale_schemas(tmp_path) == ('report',)
