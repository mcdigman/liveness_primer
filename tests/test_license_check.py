"""Tests for GitHub-API license verification (contract §6, §15).

Copyright (C) 2026 Matthew C. Digman
"""

import importlib
import json
import sys
from typing import TYPE_CHECKING, cast

import httpx
import pytest

import liveness_primer.license_check
from liveness_primer.config import CorpusProject
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.license_check import check_licenses

if TYPE_CHECKING:
    from types import ModuleType

PIN = 'a' * 40


def project(name: str = 'attrs', *, repo: str | None = None, spdx: str | None = 'MIT') -> CorpusProject:
    return CorpusProject(
        name=name,
        repo=repo if repo is not None else f'https://github.com/example/{name}',
        license=spdx,
        pin=PIN,
    )


def transport_returning(status_code: int, payload: object) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(status_code, json=payload)

    return httpx.MockTransport(handler)


def spdx_payload(spdx: str) -> dict[str, object]:
    return {'license': {'key': spdx.lower(), 'spdx_id': spdx}}


def test_confirmed_license() -> None:
    (result,) = check_licenses([project()], transport=transport_returning(200, spdx_payload('MIT')))
    assert result.ok
    assert result.detected == 'MIT'
    assert 'confirmed MIT' in result.detail


def test_requests_hit_the_expected_endpoint_with_token() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=spdx_payload('MIT'))

    bearer_value = 'not-a-real-credential'
    check_licenses([project()], token=bearer_value, transport=httpx.MockTransport(handler))
    (request,) = seen
    assert request.url.path == '/repos/example/attrs/license'
    assert request.headers['Authorization'] == f'Bearer {bearer_value}'
    assert request.headers['Accept'] == 'application/vnd.github+json'


def test_mismatch_fails() -> None:
    (result,) = check_licenses(
        [project(spdx='Apache-2.0')],
        transport=transport_returning(200, spdx_payload('MIT')),
    )
    assert not result.ok
    assert "declared 'Apache-2.0' but GitHub detects 'MIT'" in result.detail


def test_noassertion_requires_human_review() -> None:
    (result,) = check_licenses([project()], transport=transport_returning(200, spdx_payload('NOASSERTION')))
    assert not result.ok
    assert 'human review' in result.detail


def test_missing_license_is_a_hard_fail() -> None:
    (result,) = check_licenses([project()], transport=transport_returning(404, {'message': 'Not Found'}))
    assert not result.ok
    assert 'detects no license' in result.detail


def test_unexpected_status_is_reported() -> None:
    (result,) = check_licenses([project()], transport=transport_returning(403, {'message': 'rate limited'}))
    assert not result.ok
    assert 'license API returned 403' in result.detail


def test_transport_errors_are_reported_per_project() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        msg = 'boom'
        raise httpx.ConnectError(msg, request=request)

    (result,) = check_licenses([project()], transport=httpx.MockTransport(handler))
    assert not result.ok
    assert 'license API request failed' in result.detail


@pytest.mark.parametrize(
    'payload',
    ['not-a-dict', {'license': 'not-a-dict'}, {'license': {'spdx_id': 7}}, {}],
)
def test_malformed_payloads_require_human_review(payload: object) -> None:
    (result,) = check_licenses([project()], transport=transport_returning(200, payload))
    assert not result.ok
    assert 'human review' in result.detail


def test_invalid_json_body_requires_human_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, content=b'not json')

    (result,) = check_licenses([project()], transport=httpx.MockTransport(handler))
    assert not result.ok
    assert 'human review' in result.detail


def test_non_github_repository_fails() -> None:
    (result,) = check_licenses(
        [project(repo='https://gitlab.com/example/attrs')],
        transport=transport_returning(200, spdx_payload('MIT')),
    )
    assert not result.ok
    assert 'not GitHub-hosted' in result.detail


def test_results_preserve_input_order() -> None:
    results = check_licenses(
        [project('one'), project('two')],
        transport=transport_returning(200, spdx_payload('MIT')),
    )
    assert [result.project for result in results] == ['one', 'two']
    assert json.loads(json.dumps(results[0].detail)) == results[0].detail


def test_missing_httpx_extra_raises_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    module = liveness_primer.license_check
    monkeypatch.setitem(sys.modules, 'httpx', cast('ModuleType', None))
    try:
        reloaded = importlib.reload(module)
        with pytest.raises(LivenessPrimerError, match=r'\[license\]'):
            reloaded.check_licenses([project()])
    finally:
        monkeypatch.undo()
        importlib.reload(module)
