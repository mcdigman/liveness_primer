# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Bounded, containment-enforcing filesystem helpers.

Shared by pinned-source evidence collection (reporting contract §3.3) and
the shipped test utilities: relative paths stay beneath their trusted root,
reads are size-bounded, and only regular non-symlink files are accepted.
"""

import os
import stat
import tempfile
from pathlib import Path

DEFAULT_MAX_ARTIFACT_BYTES = 1_048_576


class FilesystemPolicyError(RuntimeError):
    """Raised when a path or file violates its bounded filesystem policy."""


def contained_path(root: Path, relative: str) -> Path:
    """Resolve one relative path beneath a trusted root.

    Parameters
    ----------
    root : Path
        Trusted containing directory.
    relative : str
        Relative path beneath the root.

    Returns
    -------
    Path
        Resolved path beneath ``root``.

    Raises
    ------
    FilesystemPolicyError
        If the path is empty, absolute, traversing, unresolvable (including
        a symlink loop), or escapes through a symlink.
    """
    relative_path = Path(relative)
    if not relative_path.parts or relative_path.is_absolute() or '..' in relative_path.parts:
        msg = f'path must be a non-empty relative path without traversal: {relative!r}'
        raise FilesystemPolicyError(msg)
    try:
        resolved_root = root.resolve()
        candidate = (resolved_root / relative_path).resolve(strict=False)
    except (OSError, RuntimeError) as error:
        # A corpus-controlled symlink loop raises RuntimeError out of
        # Path.resolve() on the supported Python floor; the message names
        # the relative path only, never the disposable checkout prefix.
        msg = f'path could not be resolved: {relative!r}'
        raise FilesystemPolicyError(msg) from error
    try:
        candidate.relative_to(resolved_root)
    except ValueError as error:
        msg = f'path escapes its root: {relative!r}'
        raise FilesystemPolicyError(msg) from error
    return candidate


def read_small_text(path: Path, *, max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES) -> str:
    """Read one bounded regular UTF-8 file.

    Parameters
    ----------
    path : Path
        File path.
    max_bytes : int
        Maximum encoded size.

    Returns
    -------
    str
        Decoded file contents.

    Raises
    ------
    FilesystemPolicyError
        If the limit is negative, the path is not a regular non-symlink file,
        the file cannot be read, exceeds the limit, or is not valid UTF-8.
    """
    if max_bytes < 0:
        msg = 'max_bytes must be non-negative'
        raise FilesystemPolicyError(msg)
    if path.is_symlink() or not path.is_file():
        msg = f'not a regular non-symlink file: {path}'
        raise FilesystemPolicyError(msg)
    try:
        with path.open('rb') as stream:
            payload = stream.read(max_bytes + 1)
    except OSError as error:
        # An unreadable regular file must become a bounded warning, never
        # an uncaught PermissionError out of report assembly.
        msg = f'file could not be read: {path}'
        raise FilesystemPolicyError(msg) from error
    if len(payload) > max_bytes:
        msg = f'file exceeds {max_bytes} bytes: {path}'
        raise FilesystemPolicyError(msg)
    try:
        return payload.decode('utf-8')
    except UnicodeDecodeError as error:
        msg = f'file is not valid UTF-8: {path}'
        raise FilesystemPolicyError(msg) from error


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Atomically replace one binary file beneath a trusted parent.

    Parameters
    ----------
    path : Path
        Destination beneath a trusted parent directory.
    payload : bytes
        Bytes to write.
    """
    descriptor, temporary_name = tempfile.mkstemp(prefix='.liveness-primer-write-', dir=path.parent)
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
    """Atomically replace one UTF-8 file beneath a trusted parent.

    Parameters
    ----------
    path : Path
        Destination beneath a trusted parent directory.
    text : str
        Text to write.
    """
    atomic_write_bytes(path, text.encode('utf-8'))
