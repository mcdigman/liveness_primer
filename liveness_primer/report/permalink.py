# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Stable GitHub source permalinks for the pinned corpus tree (reporting §5).

Repository and path components are parsed and encoded, never interpolated
from an unvalidated raw detector path. Permalinks target the pinned corpus
SHA — never the detector base/head SHA, a moving corpus branch, or a local
checkout, cache, home, or temporary-directory path. For a non-GitHub ad-hoc
project no URL is fabricated: the escaped relative location remains the
copyable evidence.
"""

import re
from urllib.parse import quote

from liveness_primer.config import github_owner_repo
from liveness_primer.findings import CorpusPinRecord

_FULL_SHA = re.compile(r'^[0-9a-f]{40}$')


def _encoded_path(path: str) -> str | None:
    """Percent-encode a normalized repository-relative POSIX path.

    Parameters
    ----------
    path : str
        Adapter-normalized repository-relative POSIX path.

    Returns
    -------
    str | None
        The segment-wise encoded path, or ``None`` when a segment is empty,
        a dot segment, or carries a backslash or control character.
    """
    segments = path.split('/')
    for segment in segments:
        if segment in {'', '.', '..'} or '\\' in segment or any(not ch.isprintable() for ch in segment):
            return None
    return '/'.join(quote(segment, safe='') for segment in segments)


def _validated_repo(pin: CorpusPinRecord) -> tuple[str, str] | None:
    """Validate the pinned repository as GitHub-hosted with a full SHA.

    Parameters
    ----------
    pin : CorpusPinRecord
        Resolved corpus pin of the project.

    Returns
    -------
    tuple[str, str] | None
        ``(owner, repository)``, or ``None`` for a non-GitHub repository or
        an unresolved SHA.
    """
    owner_repo = github_owner_repo(pin.repo)
    if owner_repo is None or _FULL_SHA.match(pin.resolved_sha) is None:
        return None
    return owner_repo


def tree_reference(pin: CorpusPinRecord) -> tuple[str, str] | None:
    """Build the pinned corpus tree label and URL (reporting contract §4.1).

    Parameters
    ----------
    pin : CorpusPinRecord
        Resolved corpus pin of the project.

    Returns
    -------
    tuple[str, str] | None
        ``(owner/repository, pinned-tree URL)``, or ``None`` for a
        non-GitHub ad-hoc project.
    """
    owner_repo = _validated_repo(pin)
    if owner_repo is None:
        return None
    owner, repository = owner_repo
    return f'{owner}/{repository}', f'https://github.com/{owner}/{repository}/tree/{pin.resolved_sha}'


def tree_url(pin: CorpusPinRecord) -> str | None:
    """Build the pinned corpus tree URL for a project header (reporting §4.1).

    Parameters
    ----------
    pin : CorpusPinRecord
        Resolved corpus pin of the project.

    Returns
    -------
    str | None
        The pinned-tree URL, or ``None`` for a non-GitHub ad-hoc project.
    """
    reference = tree_reference(pin)
    return None if reference is None else reference[1]


def source_url(pin: CorpusPinRecord, path: str, start_line: int, end_line: int) -> str | None:
    """Build the pinned source permalink for one occurrence span (reporting §5).

    Parameters
    ----------
    pin : CorpusPinRecord
        Resolved corpus pin of the project.
    path : str
        Adapter-normalized repository-relative POSIX path.
    start_line : int
        Reported span start (1-based).
    end_line : int
        Reported span end (1-based, inclusive).

    Returns
    -------
    str | None
        The pinned permalink, or ``None`` for a non-GitHub ad-hoc project
        or an unencodable path.
    """
    owner_repo = _validated_repo(pin)
    encoded = _encoded_path(path)
    if owner_repo is None or encoded is None:
        return None
    owner, repository = owner_repo
    fragment = f'#L{start_line}' if end_line == start_line else f'#L{start_line}-L{end_line}'
    return f'https://github.com/{owner}/{repository}/blob/{pin.resolved_sha}/{encoded}{fragment}'
