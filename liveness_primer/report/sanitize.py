# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Mandatory sanitization of untrusted report text (contract §9, reporting §8).

Paths, messages, symbols, kinds, source text, detector rule IDs, errors,
and warnings are untrusted. Renderers replace terminal control characters,
apply independent per-cell length caps that state how much was omitted,
preserve the beginning and identifying portion of locations, and escape
markdown metacharacters at the GitHub structural boundary. Generated ANSI
and hyperlink sequences are applied only outside untrusted text. This is
defense-in-depth, not detection; no component claims to detect prompt
injection reliably (contract §11).
"""

DEFAULT_INLINE_CAP = 300


def _clean(text: str) -> str:
    """Replace non-printable characters (controls, separators) with spaces.

    Parameters
    ----------
    text : str
        Untrusted text.

    Returns
    -------
    str
        The text with every non-printable character replaced.
    """
    return ''.join(ch if ch.isprintable() else ' ' for ch in text)


def _end_truncated(cleaned: str, max_length: int) -> str:
    """Truncate at the end with a marker stating the omitted count.

    Parameters
    ----------
    cleaned : str
        Control-free text longer than the cap.
    max_length : int
        Maximum rendered length.

    Returns
    -------
    str
        Truncated text within the cap; tiny caps fall back to a hard cut.
    """
    # The marker length depends on the omitted count's digits, which in
    # turn depends on how much is kept: walk digit budgets upward until
    # the count fits its budget (it grows by at most one digit per step).
    digits = 1
    while True:
        kept = max_length - (6 + digits)
        if kept < 1:
            return cleaned[:max_length]
        omitted = len(cleaned) - kept
        if len(str(omitted)) <= digits:
            return f'{cleaned[:kept]}...(+{omitted})'
        digits += 1


def sanitize_inline(text: str, *, max_length: int = DEFAULT_INLINE_CAP) -> str:
    """Sanitize untrusted text for single-line rendering.

    Parameters
    ----------
    text : str
        Untrusted text.
    max_length : int
        Maximum rendered length.

    Returns
    -------
    str
        Control-free text; overlong text ends with a marker stating the
        omitted character count.
    """
    cleaned = _clean(text)
    if len(cleaned) <= max_length:
        return cleaned
    return _end_truncated(cleaned, max_length)


def sanitize_location(text: str, *, max_length: int) -> str:
    """Sanitize an untrusted location, preserving its beginning and ending.

    The leading directories and the trailing file name are the identifying
    portions of a path (reporting contract §8); overlong middles collapse
    into a marker stating the omitted character count.

    Parameters
    ----------
    text : str
        Untrusted path-like text.
    max_length : int
        Maximum rendered length.

    Returns
    -------
    str
        Control-free text within the cap.
    """
    cleaned = _clean(text)
    if len(cleaned) <= max_length:
        return cleaned
    digits = 1
    while True:
        kept = max_length - (9 + digits)
        if kept < 2:
            return _end_truncated(cleaned, max_length)
        omitted = len(cleaned) - kept
        if len(str(omitted)) <= digits:
            head = kept // 3
            tail = kept - head
            return f'{cleaned[:head]}...(+{omitted})...{cleaned[-tail:]}'
        digits += 1


def escape_markdown(text: str) -> str:
    """Escape markdown metacharacters in already-sanitized text (contract §9).

    Escapes every metacharacter through which untrusted text could stop
    being data: table separators, code and formatting markers, raw HTML
    openers, and link/image syntax.

    Parameters
    ----------
    text : str
        Control-free text.

    Returns
    -------
    str
        The text with markdown metacharacters backslash-escaped.
    """
    escaped = text.replace('\\', '\\\\')
    for metacharacter in ('|', '`', '<', '[', ']', '*', '_'):
        escaped = escaped.replace(metacharacter, '\\' + metacharacter)
    return escaped


def sanitize_cell(text: str, *, max_length: int = DEFAULT_INLINE_CAP) -> str:
    """Sanitize untrusted text for one markdown table cell (contract §9).

    Parameters
    ----------
    text : str
        Untrusted text.
    max_length : int
        Maximum rendered length before escaping.

    Returns
    -------
    str
        Inline-sanitized text with markdown metacharacters escaped.
    """
    return escape_markdown(sanitize_inline(text, max_length=max_length))


def code_span(text: str) -> str:
    """Quote one already-escaped line as a markdown inline code span.

    The backtick fence is longer than any backtick run in the content, so
    the content cannot terminate the span (contract §9).

    Parameters
    ----------
    text : str
        Control-free single-line text.

    Returns
    -------
    str
        An inline code span containing the text verbatim.
    """
    longest_run = 0
    run = 0
    for ch in text:
        run = run + 1 if ch == '`' else 0
        longest_run = max(longest_run, run)
    fence = '`' * max(1, longest_run + 1)
    if text.startswith('`') or text.endswith('`') or not text:
        return f'{fence} {text} {fence}'
    return f'{fence}{text}{fence}'


def code_cell(text: str, *, max_length: int = DEFAULT_INLINE_CAP) -> str:
    """Sanitize untrusted text as a code span inside a table cell (§8).

    A code span renders its content literally, so markdown structure, raw
    HTML, and link syntax inside it are inert; only the table's own cell
    separator still needs escaping, which GitHub honors inside code spans.

    Parameters
    ----------
    text : str
        Untrusted text.
    max_length : int
        Maximum rendered length before fencing.

    Returns
    -------
    str
        An inline code span safe to place in a markdown table cell.
    """
    return code_span(sanitize_inline(text, max_length=max_length).replace('|', '\\|'))


def escape_argv_text(text: str) -> str:
    """Escape control characters in trusted manifest argv text (reporting §3.5).

    Trusted escape-hatch commands are rendered faithfully — never
    path-shortened or rewritten — but raw control bytes must not reach a
    terminal, so each non-printable character becomes a visible escape.

    Parameters
    ----------
    text : str
        Shell-quoted trusted argv text.

    Returns
    -------
    str
        The text with non-printable characters visibly escaped.
    """
    escaped: list[str] = []
    for ch in text:
        if ch.isprintable() or ch == ' ':
            escaped.append(ch)
        elif ord(ch) < 256:
            escaped.append(f'\\x{ord(ch):02x}')
        else:
            escaped.append(f'\\u{ord(ch):04x}')
    return ''.join(escaped)
