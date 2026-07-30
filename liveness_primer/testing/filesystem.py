"""Bounded filesystem helpers for shipped test utilities.

Copyright (C) 2026 Matthew C. Digman
"""

import os
import stat
import tempfile
from pathlib import Path

DEFAULT_MAX_ARTIFACT_BYTES = 1_048_576


class ArtifactFilesystemError(RuntimeError):
    """Raised when a test artifact violates its filesystem policy."""


def contained_path(root: Path, relative: str) -> Path:
    """Resolve one relative path beneath a trusted root.

    Parameters
    ----------
    root : Path
        Trusted containing directory.
    relative : str
        Relative artifact path.

    Returns
    -------
    Path
        Resolved path beneath ``root``.

    Raises
    ------
    ArtifactFilesystemError
        If the path is empty, absolute, traversing, or escapes through a
        symlink.
    """
    relative_path = Path(relative)
    if not relative_path.parts or relative_path.is_absolute() or '..' in relative_path.parts:
        msg = f'artifact path must be a non-empty relative path without traversal: {relative!r}'
        raise ArtifactFilesystemError(msg)
    resolved_root = root.resolve()
    candidate = (resolved_root / relative_path).resolve(strict=False)
    try:
        candidate.relative_to(resolved_root)
    except ValueError as error:
        msg = f'artifact path escapes its root: {relative!r}'
        raise ArtifactFilesystemError(msg) from error
    return candidate


def read_small_text(path: Path, *, max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES) -> str:
    """Read one bounded regular UTF-8 test artifact.

    Parameters
    ----------
    path : Path
        Artifact path.
    max_bytes : int
        Maximum encoded size.

    Returns
    -------
    str
        Decoded artifact contents.

    Raises
    ------
    ArtifactFilesystemError
        If the limit is negative, the path is not a regular non-symlink file,
        or the file exceeds the limit.
    """
    if max_bytes < 0:
        msg = 'max_bytes must be non-negative'
        raise ArtifactFilesystemError(msg)
    if path.is_symlink() or not path.is_file():
        msg = f'artifact is not a regular non-symlink file: {path}'
        raise ArtifactFilesystemError(msg)
    with path.open('rb') as stream:
        payload = stream.read(max_bytes + 1)
    if len(payload) > max_bytes:
        msg = f'artifact exceeds {max_bytes} bytes: {path}'
        raise ArtifactFilesystemError(msg)
    return payload.decode('utf-8')


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Atomically replace one binary artifact beneath a trusted parent.

    Parameters
    ----------
    path : Path
        Destination beneath a trusted parent directory.
    payload : bytes
        Bytes to write.
    """
    descriptor, temporary_name = tempfile.mkstemp(prefix='.liveness-primer-test-', dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
        try:
            destination_stat = path.lstat()
        except FileNotFoundError:
            destination_stat = None
        if destination_stat is not None and stat.S_ISREG(destination_stat.st_mode):
            temporary.chmod(stat.S_IMODE(destination_stat.st_mode))
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str) -> None:
    """Atomically replace one UTF-8 artifact beneath a trusted parent.

    Parameters
    ----------
    path : Path
        Destination beneath a trusted parent directory.
    text : str
        Text to write.
    """
    atomic_write_bytes(path, text.encode('utf-8'))
