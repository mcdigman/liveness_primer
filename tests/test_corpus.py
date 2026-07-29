"""Tests for checkout and pin resolution against throwaway git repositories (contract §15).

Copyright (C) 2026 Matthew C. Digman
"""

import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

import pytest
from filelock import FileLock

from liveness_primer.config import CorpusProject
from liveness_primer.corpus import CheckoutError, CheckoutStore, cache_root
from liveness_primer.launcher import LauncherError, LaunchResult, SyncLauncher, run_async, run_sync

PIN_MISSING = 'd' * 40


def git(*args: str, cwd: Path | None = None) -> str:
    result = run_sync(['git', *args], cwd=cwd)
    assert result.ok, result.stderr
    return result.stdout.strip()


@dataclass
class RepoFixture:
    """A throwaway origin repository with two commits and a tag."""

    url: str
    path: Path
    first_sha: str = ''
    second_sha: str = ''
    tag_sha: str = ''


@pytest.fixture
def origin(tmp_path: Path) -> RepoFixture:
    repo_dir = tmp_path / 'origin'
    repo_dir.mkdir()
    git('init', '--quiet', str(repo_dir))
    git('symbolic-ref', 'HEAD', 'refs/heads/main', cwd=repo_dir)
    git('config', 'user.email', 'test@example.invalid', cwd=repo_dir)
    git('config', 'user.name', 'Test', cwd=repo_dir)
    (repo_dir / 'module.py').write_text('FIRST = 1\n', encoding='utf-8')
    git('add', 'module.py', cwd=repo_dir)
    git('commit', '--quiet', '-m', 'first', cwd=repo_dir)
    first_sha = git('rev-parse', 'HEAD', cwd=repo_dir)
    git('tag', '-a', 'v1', '-m', 'release v1', cwd=repo_dir)
    (repo_dir / 'module.py').write_text('SECOND = 2\n', encoding='utf-8')
    git('add', 'module.py', cwd=repo_dir)
    git('commit', '--quiet', '-m', 'second', cwd=repo_dir)
    second_sha = git('rev-parse', 'HEAD', cwd=repo_dir)
    return RepoFixture(
        url=repo_dir.as_uri(),
        path=repo_dir,
        first_sha=first_sha,
        second_sha=second_sha,
        tag_sha=first_sha,
    )


@pytest.fixture
def store(tmp_path: Path) -> CheckoutStore:
    return CheckoutStore(tmp_path / 'cache')


def test_cache_root_is_a_platformdirs_path() -> None:
    assert 'liveness_primer' in str(cache_root())


def test_checkout_store_rejects_async_launcher(tmp_path: Path) -> None:
    with pytest.raises(LauncherError, match='launcher must be synchronous'):
        CheckoutStore(tmp_path / 'cache', launcher=cast('SyncLauncher', run_async))


def test_resolve_ref_passes_full_shas_through(store: CheckoutStore) -> None:
    assert store.resolve_ref('unused', 'e' * 40) == 'e' * 40


def test_resolve_ref_resolves_branch(store: CheckoutStore, origin: RepoFixture) -> None:
    assert store.resolve_ref(origin.url, 'main') == origin.second_sha


def test_resolve_ref_peels_annotated_tags(store: CheckoutStore, origin: RepoFixture) -> None:
    assert store.resolve_ref(origin.url, 'v1') == origin.tag_sha


def test_resolve_ref_resolves_lightweight_tags(store: CheckoutStore, origin: RepoFixture) -> None:
    git('tag', 'light', origin.first_sha, cwd=origin.path)
    assert store.resolve_ref(origin.url, 'light') == origin.first_sha


def test_resolve_ref_rejects_unknown(store: CheckoutStore, origin: RepoFixture) -> None:
    with pytest.raises(CheckoutError, match='not found'):
        store.resolve_ref(origin.url, 'no-such-branch')


def test_default_branch_sha(store: CheckoutStore, origin: RepoFixture) -> None:
    assert store.default_branch_sha(origin.url) == origin.second_sha


def test_default_branch_sha_rejects_empty_repository(store: CheckoutStore, tmp_path: Path) -> None:
    empty = tmp_path / 'empty'
    empty.mkdir()
    git('init', '--quiet', str(empty))
    with pytest.raises(CheckoutError, match='no HEAD'):
        store.default_branch_sha(empty.as_uri())


def test_git_failure_raises_checkout_error(store: CheckoutStore, tmp_path: Path) -> None:
    with pytest.raises(CheckoutError, match='git ls-remote failed'):
        store.resolve_ref((tmp_path / 'nowhere').as_uri(), 'main')


def test_resolve_project_pin_branch_and_adhoc(store: CheckoutStore, origin: RepoFixture) -> None:
    pinned = CorpusProject(name='p', repo=origin.url, pin=origin.first_sha)
    branch = CorpusProject(name='b', repo=origin.url, branch='main')
    adhoc = CorpusProject(name='a', repo=origin.url)
    pin_record = store.resolve_project(pinned)
    assert (pin_record.requested, pin_record.resolved_sha) == (origin.first_sha, origin.first_sha)
    branch_record = store.resolve_project(branch)
    assert (branch_record.requested, branch_record.resolved_sha) == ('branch:main', origin.second_sha)
    adhoc_record = store.resolve_project(adhoc)
    assert (adhoc_record.requested, adhoc_record.resolved_sha) == ('HEAD', origin.second_sha)


def test_materialize_checks_out_requested_sha(store: CheckoutStore, origin: RepoFixture) -> None:
    checkout = store.materialize(origin.url, origin.first_sha)
    assert (checkout / 'module.py').read_text(encoding='utf-8') == 'FIRST = 1\n'


def test_materialize_direct_sha_fetch_when_server_allows(store: CheckoutStore, origin: RepoFixture) -> None:
    git('config', 'uploadpack.allowAnySHA1InWant', 'true', cwd=origin.path)
    checkout = store.materialize(origin.url, origin.first_sha)
    assert (checkout / 'module.py').read_text(encoding='utf-8') == 'FIRST = 1\n'


@dataclass
class CountingLauncher:
    """Forwarding launcher that records every argv it launches."""

    calls: list[tuple[str, ...]] = field(default_factory=list)

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        """Record the argv, then forward to the real launcher.

        Returns
        -------
        LaunchResult
            The forwarded launch outcome.
        """
        self.calls.append(tuple(argv))
        return run_sync(argv, cwd=cwd, env=env, timeout=timeout)


def test_materialize_reuses_completed_checkouts(tmp_path: Path, origin: RepoFixture) -> None:
    counting = CountingLauncher()
    store = CheckoutStore(tmp_path / 'cache', launcher=counting)
    first = store.materialize(origin.url, origin.first_sha)
    calls_after_first = len(counting.calls)
    second = store.materialize(origin.url, origin.first_sha)
    assert first == second
    assert len(counting.calls) == calls_after_first


def test_materialize_keeps_the_checkout_tree_pristine(store: CheckoutStore, origin: RepoFixture) -> None:
    # The completion marker lives *next to* the checkout, so the analyzed
    # tree is exactly the pristine repo tree (contract §3).
    checkout = store.materialize(origin.url, origin.first_sha)
    assert checkout.with_name(checkout.name + '.complete').exists()
    assert sorted(entry.name for entry in checkout.iterdir()) == ['.git', 'module.py']


def test_materialize_rebuilds_interrupted_checkouts(store: CheckoutStore, origin: RepoFixture) -> None:
    checkout = store.materialize(origin.url, origin.first_sha)
    marker = checkout.with_name(checkout.name + '.complete')
    marker.unlink()
    (checkout / 'stray.txt').write_text('leftover', encoding='utf-8')
    rebuilt = store.materialize(origin.url, origin.first_sha)
    assert rebuilt == checkout
    assert not (rebuilt / 'stray.txt').exists()
    assert (rebuilt / 'module.py').read_text(encoding='utf-8') == 'FIRST = 1\n'


def test_materialize_rebuilds_when_the_tree_vanished(store: CheckoutStore, origin: RepoFixture) -> None:
    checkout = store.materialize(origin.url, origin.first_sha)
    shutil.rmtree(checkout)
    rebuilt = store.materialize(origin.url, origin.first_sha)
    assert (rebuilt / 'module.py').exists()


def test_materialize_rejects_partial_shas(store: CheckoutStore, origin: RepoFixture) -> None:
    with pytest.raises(CheckoutError, match='full commit SHA'):
        store.materialize(origin.url, 'abc123')


def test_materialize_rejects_missing_commit(store: CheckoutStore, origin: RepoFixture) -> None:
    with pytest.raises(CheckoutError, match='not found'):
        store.materialize(origin.url, PIN_MISSING)


def test_materialize_propagates_fetch_failure(store: CheckoutStore, tmp_path: Path) -> None:
    with pytest.raises(CheckoutError, match='git fetch failed'):
        store.materialize((tmp_path / 'nowhere').as_uri(), 'e' * 40)


def test_materialize_lock_timeout(tmp_path: Path, origin: RepoFixture) -> None:
    store = CheckoutStore(tmp_path / 'cache')
    checkout = store.materialize(origin.url, origin.first_sha)
    impatient = CheckoutStore(tmp_path / 'cache', git_timeout=0.2)
    held = FileLock(str(checkout) + '.lock')
    held.acquire()
    try:
        with pytest.raises(CheckoutError, match='timed out waiting'):
            impatient.materialize(origin.url, origin.first_sha)
    finally:
        held.release()


def test_ls_remote_skips_untabbed_output_lines(tmp_path: Path) -> None:
    def junk_output(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        del cwd, env, timeout
        return LaunchResult(
            argv=tuple(argv),
            returncode=0,
            stdout='remark without a tab separator\n',
            stderr='',
            duration_seconds=0.0,
            timed_out=False,
        )

    store = CheckoutStore(tmp_path / 'cache', launcher=junk_output)
    with pytest.raises(CheckoutError, match='not found'):
        store.resolve_ref('https://example.invalid/repo.git', 'main')


def test_timed_out_git_reports_timeout(tmp_path: Path) -> None:
    def timing_out(
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> LaunchResult:
        del cwd, env, timeout
        return LaunchResult(
            argv=tuple(argv),
            returncode=None,
            stdout='',
            stderr='',
            duration_seconds=0.0,
            timed_out=True,
        )

    store = CheckoutStore(tmp_path / 'cache', launcher=timing_out)
    with pytest.raises(CheckoutError, match='timed out'):
        store.resolve_ref('https://example.invalid/repo.git', 'main')
