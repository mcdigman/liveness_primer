"""A factory for small synthetic corpus projects (contract §15).

Copyright (C) 2026 Matthew C. Digman

Produces throwaway projects with injected characteristics — optionally as
real ``git init`` repositories so checkout and pin resolution can be
exercised without the network.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from liveness_primer.errors import LivenessPrimerError
from liveness_primer.filesystem import FilesystemPolicyError, atomic_write_text, contained_path
from liveness_primer.launcher import SyncLauncher, run_sync, validate_sync_launcher

DEFAULT_FILES: Mapping[str, str] = {
    'pkg/__init__.py': '',
    'pkg/mod.py': ('def used() -> int:\n    return 1\n\n\ndef unused_helper() -> int:\n    return 2\n'),
}


class FakeProjectError(LivenessPrimerError):
    """Raised when the fake project factory cannot build a project."""


@dataclass(frozen=True, slots=True)
class FakeProject:
    """A synthetic project on disk.

    Attributes
    ----------
    path : Path
        Project directory.
    head_sha : str | None
        Commit SHA of the initial commit when git-initialized.
    """

    path: Path
    head_sha: str | None

    @property
    def url(self) -> str:
        """File URL of the project, usable as a repository URL.

        Returns
        -------
        str
            ``file://`` URL of the project directory.
        """
        return self.path.as_uri()


def _git(launcher: SyncLauncher, directory: Path, *args: str) -> str:
    """Run one git command for the factory.

    Parameters
    ----------
    launcher : SyncLauncher
        Audited launcher used for the invocation.
    directory : Path
        Repository directory.
    *args : str
        Arguments after the ``git`` program name.

    Returns
    -------
    str
        Stripped standard output.

    Raises
    ------
    FakeProjectError
        If the command fails.
    """
    result = launcher(['git', *args], cwd=directory)
    if not result.ok:
        msg = f'git {args[0]} failed while building a fake project: {result.stderr.strip()[:500]}'
        raise FakeProjectError(msg)
    return result.stdout.strip()


def create_fake_project(
    directory: Path,
    *,
    files: Mapping[str, str] | None = None,
    init_git: bool = False,
    launcher: SyncLauncher = run_sync,
) -> FakeProject:
    """Create a small synthetic project with injected characteristics.

    Parameters
    ----------
    directory : Path
        Directory to create the project in (created if missing).
    files : Mapping[str, str] | None
        Relative paths mapped to contents; a small package with one unused
        helper by default.
    init_git : bool
        Also initialize a git repository with one commit, so the project
        can serve as a corpus origin.
    launcher : SyncLauncher
        Audited launcher used for git operations.

    Returns
    -------
    FakeProject
        The created project.

    Raises
    ------
    FakeProjectError
        If an artifact path escapes the project or a Git command fails.
    """
    validate_sync_launcher(launcher)
    directory.mkdir(parents=True, exist_ok=True)
    contents = DEFAULT_FILES if files is None else files
    for relative, text in contents.items():
        try:
            target = contained_path(directory, relative)
        except FilesystemPolicyError as error:
            raise FakeProjectError(str(error)) from error
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(target, text)
    if not init_git:
        return FakeProject(path=directory, head_sha=None)
    _git(launcher, directory, 'init', '--quiet')
    _git(launcher, directory, 'symbolic-ref', 'HEAD', 'refs/heads/main')
    _git(launcher, directory, 'config', 'user.email', 'fake@example.invalid')
    _git(launcher, directory, 'config', 'user.name', 'Fake Project Factory')
    _git(launcher, directory, 'add', '--all')
    _git(launcher, directory, 'commit', '--quiet', '-m', 'fake project')
    return FakeProject(path=directory, head_sha=_git(launcher, directory, 'rev-parse', 'HEAD'))
