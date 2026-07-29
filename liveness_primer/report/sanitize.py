"""Mandatory sanitization of untrusted report text (contract §9).

Copyright (C) 2026 Matthew C. Digman

Excerpts and every other detector-derived string are untrusted data: length
caps, control-character stripping, and fenced/escaped quoting ensure
downstream LLM consumers structurally see them as data. Sanitization is
mandatory and not hook-removable — renderers call these helpers directly.
It is defense-in-depth, not detection; no component claims to detect prompt
injection reliably (contract §11).
"""

from collections.abc import Sequence

DEFAULT_INLINE_CAP = 300
DEFAULT_LINE_CAP = 200

_ELLIPSIS = '...'


def sanitize_inline(text: str, *, max_length: int = DEFAULT_INLINE_CAP) -> str:
    """Sanitize untrusted text for single-line rendering.

    Non-printable characters (controls, newlines, zero-width and separator
    exotica) become spaces; overlong text is truncated with a marker.

    Parameters
    ----------
    text : str
        Untrusted text.
    max_length : int
        Maximum rendered length.

    Returns
    -------
    str
        The sanitized single-line text.
    """
    cleaned = ''.join(ch if ch.isprintable() else ' ' for ch in text)
    if len(cleaned) > max_length:
        if max_length <= len(_ELLIPSIS):
            return cleaned[: max(0, max_length)]
        return cleaned[: max_length - len(_ELLIPSIS)] + _ELLIPSIS
    return cleaned


def sanitize_excerpt(text: str, *, max_lines: int, max_line_length: int = DEFAULT_LINE_CAP) -> tuple[str, ...]:
    """Sanitize an untrusted excerpt into capped, clean lines.

    Parameters
    ----------
    text : str
        Untrusted excerpt text.
    max_lines : int
        Maximum number of lines to keep (``--excerpt-lines``).
    max_line_length : int
        Maximum length per line.

    Returns
    -------
    tuple[str, ...]
        Sanitized lines; a final marker line notes dropped lines.
    """
    raw_lines = text.splitlines()
    kept = [sanitize_inline(line, max_length=max_line_length) for line in raw_lines[:max_lines]]
    if len(raw_lines) > max_lines:
        kept.append(f'{_ELLIPSIS} ({len(raw_lines) - max_lines} more excerpt line(s) omitted)')
    return tuple(kept)


def sanitize_cell(text: str, *, max_length: int = DEFAULT_LINE_CAP) -> str:
    """Sanitize untrusted text for markdown rendering (contract §9).

    Escapes every markdown metacharacter through which untrusted text
    could stop being data: table separators, code and formatting markers,
    raw HTML openers, and link/image syntax.

    Parameters
    ----------
    text : str
        Untrusted text.
    max_length : int
        Maximum rendered length.

    Returns
    -------
    str
        Inline-sanitized text with markdown metacharacters escaped.
    """
    inline = sanitize_inline(text, max_length=max_length)
    escaped = inline.replace('\\', '\\\\')
    for metacharacter in ('|', '`', '<', '[', '*', '_'):
        escaped = escaped.replace(metacharacter, '\\' + metacharacter)
    return escaped


def fenced_block(lines: Sequence[str]) -> str:
    """Quote already-sanitized excerpt lines as a fenced data block.

    The fence is longer than any backtick run in the content, so the
    content cannot escape the block (contract §9).

    Parameters
    ----------
    lines : Sequence[str]
        Sanitized excerpt lines.

    Returns
    -------
    str
        A fenced markdown block marked as plain text.
    """
    content = '\n'.join(lines)
    longest_run = 0
    run = 0
    for ch in content:
        run = run + 1 if ch == '`' else 0
        longest_run = max(longest_run, run)
    fence = '`' * max(3, longest_run + 1)
    return f'{fence}text\n{content}\n{fence}'
