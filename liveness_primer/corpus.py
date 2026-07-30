"""Checkout and pin resolution for corpus and detector repositories (contract §3, §5).

Copyright (C) 2026 Matthew C. Digman

Refs are resolved once per run and then pinned; checkout caches are keyed by
(repository, SHA) under the ``platformdirs`` cache directory and guarded by
``filelock``, so both detector revisions analyze byte-identical checkouts.
"""

import hashlib
import os
import re
import shutil
from pathlib import Path

import platformdirs
from filelock import FileLock, Timeout

from liveness_primer.config import CorpusProject
from liveness_primer.errors import LivenessPrimerError
from liveness_primer.findings import CorpusPinRecord
from liveness_primer.launcher import LaunchResult, SyncLauncher, run_sync, validate_sync_launcher

_SHA_RE = re.compile(r'^[0-9a-f]{40}$')

# Suffix of the sibling completion-marker file: kept *next to* the checkout,
# never inside it, so the analyzed tree is exactly the pristine repo tree.
_COMPLETE_SUFFIX = '.complete'


class CheckoutError(LivenessPrimerError):
    """Raised when a repository, ref, or checkout cannot be resolved."""


def cache_root() -> Path:
    """Locate the package cache directory (contract §3).

    Returns
    -------
    Path
        The ``platformdirs`` user cache directory for this package.
    """
    return Path(platformdirs.user_cache_dir('liveness_primer'))


def _slug(repo: str) -> str:
    """Derive a stable, filesystem-safe directory slug for a repository URL.

    Parameters
    ----------
    repo : str
        Repository URL.

    Returns
    -------
    str
        A readable tail plus a URL-hash prefix.
    """
    tail = re.sub(r'[^A-Za-z0-9._-]', '-', repo.rstrip('/').rsplit('/', maxsplit=1)[-1].removesuffix('.git'))[-40:]
    digest = hashlib.sha256(repo.encode('utf-8')).hexdigest()[:12]
    return f'{tail}-{digest}'


class CheckoutStore:
    """Cache of read-only checkouts keyed by (repository, SHA) (contract §3).

    Parameters
    ----------
    root : Path
        Cache directory holding checkouts and their locks.
    launcher : SyncLauncher
        Audited launcher used for every git invocation (contract §11).
    git_timeout : float
        Timeout in seconds for each git invocation.
    """

    def __init__(self, root: Path, *, launcher: SyncLauncher = run_sync, git_timeout: float = 600.0) -> None:
        validate_sync_launcher(launcher)
        self._root = root
        self._launcher = launcher
        self._git_timeout = git_timeout

    @property
    def checkout_root(self) -> Path:
        """Directory containing materialized checkouts.

        Returns
        -------
        Path
            Checkout cache directory.
        """
        return self._root / 'checkouts'

    def _git(self, args: list[str], *, cwd: Path | None = None, check: bool = True) -> LaunchResult:
        """Run one git command through the audited launcher.

        Parameters
        ----------
        args : list[str]
            Arguments after the ``git`` program name.
        cwd : Path | None
            Working directory for the invocation.
        check : bool
            Whether a failure raises instead of returning.

        Returns
        -------
        LaunchResult
            The captured outcome.

        Raises
        ------
        CheckoutError
            If ``check`` is set and git fails or times out.
        """
        env = dict(os.environ) | {'GIT_TERMINAL_PROMPT': '0'}
        result = self._launcher(['git', *args], cwd=cwd, env=env, timeout=self._git_timeout)
        if check and not result.ok:
            detail = result.stderr.strip()[:500] if not result.timed_out else 'timed out'
            msg = f'git {args[0]} failed: {detail}'
            raise CheckoutError(msg)
        return result

    def _ls_remote(self, repo: str, patterns: list[str]) -> dict[str, str]:
        """List remote refs matching the given patterns.

        Parameters
        ----------
        repo : str
            Repository URL.
        patterns : list[str]
            Ref patterns passed to ``git ls-remote``.

        Returns
        -------
        dict[str, str]
            Refname mapped to SHA.
        """
        result = self._git(['ls-remote', '--', repo, *patterns])
        listing: dict[str, str] = {}
        for line in result.stdout.splitlines():
            sha, _, refname = line.partition('\t')
            if sha and refname:
                listing[refname] = sha
        return listing

    def resolve_ref(self, repo: str, ref: str) -> str:
        """Resolve a ref name to a commit SHA without cloning (fetch step, §3).

        A 40-hex ref is taken as already resolved; otherwise branch and tag
        names are looked up remotely, preferring branches, and annotated tags
        are peeled.

        Parameters
        ----------
        repo : str
            Repository URL.
        ref : str
            Branch name, tag name, or full commit SHA.

        Returns
        -------
        str
            The resolved commit SHA.

        Raises
        ------
        CheckoutError
            If the ref does not exist in the remote repository.
        """
        if _SHA_RE.match(ref):
            return ref
        head_ref = f'refs/heads/{ref}'
        tag_ref = f'refs/tags/{ref}'
        # The exact tag pattern omits the peeled ^{} line, so glob and rely on
        # the exact-refname lookup below to discard any over-match.
        listing = self._ls_remote(repo, [head_ref, tag_ref + '*'])
        for candidate in (head_ref, tag_ref + '^{}', tag_ref):
            if candidate in listing:
                return listing[candidate]
        msg = f'ref {ref!r} not found in {repo}'
        raise CheckoutError(msg)

    def default_branch_sha(self, repo: str) -> str:
        """Resolve the remote default branch to a commit SHA (ad-hoc mode, §5).

        Parameters
        ----------
        repo : str
            Repository URL.

        Returns
        -------
        str
            The commit SHA of remote ``HEAD``.

        Raises
        ------
        CheckoutError
            If the remote advertises no ``HEAD``.
        """
        listing = self._ls_remote(repo, ['HEAD'])
        if 'HEAD' not in listing:
            msg = f'repository {repo} advertises no HEAD'
            raise CheckoutError(msg)
        return listing['HEAD']

    def resolve_project(self, project: CorpusProject) -> CorpusPinRecord:
        """Resolve one corpus project to its pinned SHA (contract §3, §5).

        Parameters
        ----------
        project : CorpusProject
            The corpus entry; a pin is used as-is, a branch is resolved to
            its current tip, and neither means latest on the default branch.

        Returns
        -------
        CorpusPinRecord
            The manifest record of the resolution.
        """
        if project.pin is not None:
            requested, sha = project.pin, project.pin
        elif project.branch is not None:
            requested = f'branch:{project.branch}'
            sha = self.resolve_ref(project.repo, project.branch)
        else:
            requested = 'HEAD'
            sha = self.default_branch_sha(project.repo)
        return CorpusPinRecord(name=project.name, repo=project.repo, requested=requested, resolved_sha=sha)

    def materialize(self, repo: str, sha: str) -> Path:
        """Produce the cached checkout of one (repository, SHA) pair (contract §3).

        The checkout is created on first use (network permitted: fetch step)
        and reused byte-identically afterwards; a completion marker guards
        against interrupted materializations, and ``filelock`` guards against
        concurrent runs.

        Parameters
        ----------
        repo : str
            Repository URL.
        sha : str
            Full commit SHA to check out.

        Returns
        -------
        Path
            Directory of the detached checkout.

        Raises
        ------
        CheckoutError
            If ``sha`` is not a full lowercase SHA or cannot be fetched.
        """
        if not _SHA_RE.match(sha):
            msg = f'checkout requires a full commit SHA, got {sha!r}'
            raise CheckoutError(msg)
        checkouts = self.checkout_root
        checkouts.mkdir(parents=True, exist_ok=True)
        dest = checkouts / Path(f'{_slug(repo)}-{sha}').name
        lock = FileLock(str(dest) + '.lock')
        try:
            lock.acquire(timeout=self._git_timeout)
        except Timeout as exc:
            msg = f'timed out waiting for the checkout lock of {dest.name}'
            raise CheckoutError(msg) from exc
        try:
            marker = dest.with_name(dest.name + _COMPLETE_SUFFIX)
            if marker.exists() and dest.is_dir():
                return dest
            marker.unlink(missing_ok=True)
            if dest.exists():
                shutil.rmtree(dest)
            self._git(['init', '--quiet', str(dest)])
            self._git(['remote', 'add', 'origin', repo], cwd=dest)
            fetched = self._git(['fetch', '--quiet', 'origin', sha], cwd=dest, check=False)
            if not fetched.ok:
                self._git(['fetch', '--quiet', '--tags', 'origin'], cwd=dest)
            exists = self._git(['cat-file', '-e', f'{sha}^{{commit}}'], cwd=dest, check=False)
            if not exists.ok:
                shutil.rmtree(dest)
                msg = f'commit {sha} not found in {repo}'
                raise CheckoutError(msg)
            self._git(['-c', 'advice.detachedHead=false', 'checkout', '--quiet', '--detach', sha], cwd=dest)
            marker.touch()
        finally:
            lock.release()
        return dest
