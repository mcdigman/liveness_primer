# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""GitHub-API license verification for corpus repositories (contract §6).

Queries the GitHub license API per repository and compares against the
declared SPDX identifier; mismatches fail the check. Detection is
advisory-strength (licensee is imperfect) but the check is binding in CI,
with PR review as the backstop. Requires the ``[license]`` extra (httpx).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from liveness_primer.config import LicenseStatus, classify_license, github_owner_repo
from liveness_primer.errors import LivenessPrimerError

if TYPE_CHECKING:
    from collections.abc import Sequence

    import httpx

    from liveness_primer.config import CorpusProject
else:
    try:
        import httpx
    except ImportError:
        httpx = None

_REQUEST_TIMEOUT = 30.0


class LicenseCheckError(LivenessPrimerError):
    """Raised when the license check cannot run at all."""


@dataclass(frozen=True, slots=True)
class LicenseCheckResult:
    """Outcome of checking one corpus repository (contract §6).

    Attributes
    ----------
    project : str
        Corpus project name.
    repo : str
        Repository URL.
    declared : str | None
        SPDX identifier declared in the corpus file.
    detected : str | None
        SPDX identifier the GitHub API reports, when available.
    ok : bool
        Whether the declaration is confirmed.
    detail : str
        Human-readable explanation.
    """

    project: str
    repo: str
    declared: str | None
    detected: str | None
    ok: bool
    detail: str


def _spdx_from_payload(response: httpx.Response) -> str | None:
    """Extract the SPDX identifier from a license API payload.

    Parameters
    ----------
    response : httpx.Response
        A 200 response from the license endpoint.

    Returns
    -------
    str | None
        The reported ``license.spdx_id``, or ``None`` when absent.
    """
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    license_info = payload.get('license')
    if not isinstance(license_info, dict):
        return None
    spdx = license_info.get('spdx_id')
    return spdx if isinstance(spdx, str) else None


def _result(project: CorpusProject, *, detected: str | None, ok: bool, detail: str) -> LicenseCheckResult:
    """Build a result for one project.

    Parameters
    ----------
    project : CorpusProject
        The corpus entry.
    detected : str | None
        SPDX identifier from the API, when available.
    ok : bool
        Whether the declaration is confirmed.
    detail : str
        Human-readable explanation.

    Returns
    -------
    LicenseCheckResult
        The assembled result.
    """
    return LicenseCheckResult(
        project=project.name,
        repo=project.repo,
        declared=project.license,
        detected=detected,
        ok=ok,
        detail=detail,
    )


def _compare(project: CorpusProject, detected: str | None) -> LicenseCheckResult:
    """Compare the declared and detected SPDX identifiers (contract §6).

    Parameters
    ----------
    project : CorpusProject
        The corpus entry.
    detected : str | None
        SPDX identifier from the API.

    Returns
    -------
    LicenseCheckResult
        The comparison outcome.
    """
    if detected is None or detected == 'NOASSERTION':
        return _result(
            project,
            detected=detected,
            ok=False,
            detail='GitHub could not determine an SPDX identifier; human review required (§6)',
        )
    if detected != project.license:
        return _result(
            project,
            detected=detected,
            ok=False,
            detail=f'declared {project.license!r} but GitHub detects {detected!r}',
        )
    status = classify_license(detected)
    if status is LicenseStatus.FORBIDDEN:
        return _result(
            project,
            detected=detected,
            ok=False,
            detail=f'GitHub confirms {detected}, which is copyleft or otherwise forbidden (§6)',
        )
    if status is LicenseStatus.UNRECOGNIZED:
        return _result(
            project,
            detected=detected,
            ok=False,
            detail=f'GitHub confirms {detected}, which is not on the allowlist; human review required (§6)',
        )
    return _result(
        project,
        detected=detected,
        ok=True,
        detail=f'confirmed {detected} ({status.value})',
    )


def _check_one(client: httpx.Client, project: CorpusProject) -> LicenseCheckResult:
    """Check one repository against the GitHub license API.

    Parameters
    ----------
    client : httpx.Client
        Client bound to the GitHub API.
    project : CorpusProject
        The corpus entry to verify.

    Returns
    -------
    LicenseCheckResult
        The comparison outcome.
    """
    parsed = github_owner_repo(project.repo)
    if parsed is None:
        return _result(project, detected=None, ok=False, detail='repository is not GitHub-hosted (§6)')
    owner, repo = parsed
    try:
        response = client.get(f'https://api.github.com/repos/{owner}/{repo}/license')
    except httpx.HTTPError as exc:
        return _result(project, detected=None, ok=False, detail=f'license API request failed: {exc}')
    if response.status_code == httpx.codes.NOT_FOUND:
        return _result(project, detected=None, ok=False, detail='GitHub detects no license: hard fail (§6)')
    if response.status_code != httpx.codes.OK:
        return _result(project, detected=None, ok=False, detail=f'license API returned {response.status_code}')
    detected = _spdx_from_payload(response)
    return _compare(project, detected)


def check_licenses(
    projects: Sequence[CorpusProject],
    *,
    token: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> tuple[LicenseCheckResult, ...]:
    """Verify declared licenses against the GitHub license API (contract §6).

    The API reports the default-branch license, which can differ from the
    tree at a pinned SHA; the check remains advisory-strength.

    Parameters
    ----------
    projects : Sequence[CorpusProject]
        Corpus entries to verify.
    token : str | None
        Optional GitHub token for rate limits.
    transport : httpx.BaseTransport | None
        Transport override, injectable for tests (contract §15).

    Returns
    -------
    tuple[LicenseCheckResult, ...]
        One result per project, in input order.

    Raises
    ------
    LicenseCheckError
        If httpx (the ``[license]`` extra) is not installed.
    """
    if httpx is None:
        msg = "license verification requires httpx; install the '[license]' extra"
        raise LicenseCheckError(msg)
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if token is not None:
        headers['Authorization'] = f'Bearer {token}'
    with httpx.Client(
        headers=headers,
        timeout=_REQUEST_TIMEOUT,
        transport=transport,
    ) as client:
        return tuple(_check_one(client, project) for project in projects)
