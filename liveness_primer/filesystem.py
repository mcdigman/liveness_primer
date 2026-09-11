# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Bounded, containment-enforcing filesystem helpers.

Shared by pinned-source evidence collection (reporting contract §3.3), native
helper admission and staging, and the shipped test utilities: relative paths
stay beneath their trusted root, reads are size-bounded, and only regular
non-symlink files are accepted.
"""

import contextlib
import os
import stat
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

DEFAULT_MAX_ARTIFACT_BYTES = 1_048_576

READ_CHUNK_BYTES = 1_048_576

# Hashing is already chunked, so this cap bounds admission I/O and time rather
# than peak memory. 256 MiB leaves room for ordinary native analyzer engines.
# Both the host admission path and the container staging path share it, so a
# helper can never pass one bound and fail the other.
MAX_NATIVE_TOOL_BYTES = 268_435_456

# Refusing to traverse a final-component symlink closes the lstat-to-open
# window outright wherever the platform offers the flag. Windows has neither
# O_NOFOLLOW nor an equivalent, so the inode comparison in
# ``open_bounded_regular`` stays the portable guarantee rather than a fallback.
_READ_ONLY_FLAGS = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)


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


@contextlib.contextmanager
def open_bounded_regular(path: Path, *, description: str, max_bytes: int) -> Iterator[BinaryIO]:
    """Open one bounded regular file, binding the opened bytes to the inspected ones.

    ``lstat`` rejects a symlink or non-regular path before the open, and the
    opened descriptor is then compared back against it, so a path swapped in
    the window between the two checks fails instead of being read. Passing
    ``O_NOFOLLOW`` closes that window outright wherever the platform offers it.

    Parameters
    ----------
    path : Path
        Host path to open without traversing a final-component symlink.
    description : str
        Operator-facing name of the file, prefixed onto every message.
    max_bytes : int
        Largest accepted size, enforced before and after the open.

    Yields
    ------
    BinaryIO
        Verified regular-file stream positioned at the start.

    Raises
    ------
    FilesystemPolicyError
        If the path is missing, is not a regular non-symlink file, exceeds
        ``max_bytes``, or is replaced while it is being opened.
    """
    try:
        inspected = path.lstat()
    except FileNotFoundError as error:
        msg = f'{description} is missing: {path.name}'
        raise FilesystemPolicyError(msg) from error
    # S_ISREG is false for every symlink, so this one test rejects both.
    if not stat.S_ISREG(inspected.st_mode):
        msg = f'{description} is not a regular non-symlink file: {path.name}'
        raise FilesystemPolicyError(msg)
    if inspected.st_size > max_bytes:
        msg = f'{description} exceeds {max_bytes} bytes'
        raise FilesystemPolicyError(msg)

    with os.fdopen(os.open(path, _READ_ONLY_FLAGS), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            inspected.st_dev,
            inspected.st_ino,
        ):
            msg = f'{description} changed while it was being opened'
            raise FilesystemPolicyError(msg)
        if opened.st_size > max_bytes:
            msg = f'{description} exceeds {max_bytes} bytes'
            raise FilesystemPolicyError(msg)
        yield stream


def read_bounded_chunks(
    stream: BinaryIO,
    *,
    description: str,
    max_bytes: int,
    already_read: int = 0,
) -> Iterator[bytes]:
    """Yield a stream's remaining chunks, stopping if it outgrows its bound.

    The size recorded around the open only bounds what the file was then; a
    file that grows while it is read has to fail rather than be admitted in
    part.

    Parameters
    ----------
    stream : BinaryIO
        Verified stream to read to exhaustion.
    description : str
        Operator-facing name of the file, prefixed onto every message.
    max_bytes : int
        Largest accepted total size.
    already_read : int
        Bytes taken from the stream before this call, counted against the bound.

    Yields
    ------
    bytes
        Successive chunks of at most ``READ_CHUNK_BYTES``.

    Raises
    ------
    FilesystemPolicyError
        If the total read exceeds ``max_bytes``.
    """
    bytes_read = already_read
    for chunk in iter(lambda: stream.read(READ_CHUNK_BYTES), b''):
        bytes_read += len(chunk)
        if bytes_read > max_bytes:
            msg = f'{description} exceeds {max_bytes} bytes'
            raise FilesystemPolicyError(msg)
        yield chunk


@contextlib.contextmanager
def atomic_write_stream(path: Path, *, mode: int | None = None) -> Iterator[BinaryIO]:
    """Replace one file beneath a trusted parent with whatever the body writes.

    Nothing appears at ``path`` until the body completes, so a body that
    raises part-way leaves any previous file untouched rather than publishing
    a truncated one.

    Parameters
    ----------
    path : Path
        Destination beneath an existing trusted parent directory.
    mode : int | None
        Permission bits for the replacement. ``None`` keeps the mode of the
        regular file already at ``path``, if any.

    Yields
    ------
    BinaryIO
        Stream whose contents become the new file.
    """
    descriptor, temporary_name = tempfile.mkstemp(prefix='.liveness-primer-write-', dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            descriptor = -1
            yield stream
        if mode is None:
            try:
                destination_stat = path.lstat()
            except FileNotFoundError:
                destination_stat = None
            if destination_stat is not None and stat.S_ISREG(destination_stat.st_mode):
                mode = stat.S_IMODE(destination_stat.st_mode)
        if mode is not None:
            temporary.chmod(mode)
        temporary.replace(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def atomic_write_bytes(path: Path, payload: bytes) -> None:
    """Atomically replace one binary file beneath a trusted parent.

    Parameters
    ----------
    path : Path
        Destination beneath a trusted parent directory.
    payload : bytes
        Bytes to write.
    """
    with atomic_write_stream(path) as stream:
        stream.write(payload)


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
