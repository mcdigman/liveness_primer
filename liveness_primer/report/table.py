"""Borderless table layout for the terminal renderer (reporting contract §4).

Copyright (C) 2026 Matthew C. Digman

The layout engine measures sanitized cells with Rich's terminal cell
metrics — never Python string length — so combining and wide Unicode
characters cannot make the table ragged (reporting contract §4.6). Every
row in one section uses the same measured column widths; flexible columns
wrap onto indented continuation lines that preserve the original column
boundaries. Styling is expressed as abstract roles here; escape sequences
are applied by the emitter, outside untrusted text.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from rich.cells import cell_len, get_character_cell_size

# Two-space padding separates columns; there are no vertical borders.
COLUMN_SEPARATOR = '  '

# The confidence column measures to the widest value actually present and
# only reserves room for `NA` (reporting contract §4.3).
CONFIDENCE_MIN_WIDTH = 2

# How an over-wide flexible cell degrades (reporting contract §4.6).
Degrade = Literal['wrap-words', 'truncate-middle', 'truncate-end']


@dataclass(frozen=True, slots=True)
class Segment:
    """One styled run of already-sanitized text on a physical line.

    Attributes
    ----------
    text : str
        Sanitized display text.
    role : str
        Abstract style role the emitter maps to a terminal style.
    link : str | None
        Generated pinned permalink attached to the text, when any.
    """

    text: str
    role: str = 'plain'
    link: str | None = None


Line = tuple[Segment, ...]


@dataclass(frozen=True, slots=True)
class Cell:
    """One table cell: sanitized text plus presentation metadata.

    Attributes
    ----------
    text : str
        Sanitized cell text.
    role : str
        Abstract style role.
    link : str | None
        Generated pinned permalink for the cell text, when any.
    """

    text: str
    role: str = 'plain'
    link: str | None = None


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    """Layout constraints of one table column (reporting contract §4.6).

    Attributes
    ----------
    header : str
        Header text; blank for the class column.
    role : str
        Style role for ordinary cells of the column.
    minimum : int
        Minimum display width.
    maximum : int | None
        Maximum display width for flexible columns; ``None`` sizes the
        column to its content.
    degrade : Degrade | None
        How an over-wide cell of a flexible column is fitted.
    """

    header: str
    role: str
    minimum: int
    maximum: int | None = None
    degrade: Degrade | None = None


# Semantic column order (reporting contract §4.2). The class, rule,
# confidence, kind, and fields columns do not wrap; location, message, and
# symbol are the flexible columns, each with its own declared degradation
# (reporting contract §4.6).
COLUMNS: tuple[ColumnSpec, ...] = (
    ColumnSpec(header='', role='plain', minimum=1),
    ColumnSpec(header='rule', role='rule', minimum=4),
    ColumnSpec(header='%', role='confidence', minimum=CONFIDENCE_MIN_WIDTH),
    ColumnSpec(header='kind', role='kind', minimum=4),
    ColumnSpec(header='location', role='location', minimum=14, maximum=48, degrade='truncate-middle'),
    ColumnSpec(header='symbol', role='symbol', minimum=6, maximum=40, degrade='truncate-end'),
    ColumnSpec(header='message', role='message', minimum=16, maximum=64, degrade='wrap-words'),
    ColumnSpec(header='fields', role='fields', minimum=6),
)

# Flexible columns and their declared maximum widths, in column order.
_FLEXIBLE_MAXIMA: dict[int, int] = {
    index: column.maximum for index, column in enumerate(COLUMNS) if column.maximum is not None
}


def wrap_cells(text: str, width: int) -> tuple[str, ...]:
    """Chop text into chunks of at most ``width`` terminal cells.

    Parameters
    ----------
    text : str
        Sanitized text to wrap.
    width : int
        Maximum display width per chunk; positive.

    Returns
    -------
    tuple[str, ...]
        The chunks; empty text yields no chunks.
    """
    chunks: list[str] = []
    current: list[str] = []
    used = 0
    for character in text:
        size = get_character_cell_size(character)
        if current and used + size > width:
            chunks.append(''.join(current))
            current = []
            used = 0
        current.append(character)
        used += size
    if current:
        chunks.append(''.join(current))
    return tuple(chunks)


def wrap_words(text: str, width: int) -> tuple[str, ...]:
    """Wrap text at word boundaries (reporting contract §4.6).

    Parameters
    ----------
    text : str
        Sanitized text to wrap.
    width : int
        Maximum display width per line; positive.

    Returns
    -------
    tuple[str, ...]
        The wrapped lines; a single word wider than ``width`` falls back to
        cell chopping so no line ever exceeds the column.
    """
    lines: list[str] = []
    current = ''
    for word in text.split(' '):
        candidate = f'{current} {word}' if current else word
        if cell_len(candidate) <= width:
            current = candidate
            continue
        if current:
            lines.append(current)
        chunks = wrap_cells(word, width) or ('',)
        lines.extend(chunks[:-1])
        current = chunks[-1]
    if current:
        lines.append(current)
    return tuple(lines)


def prefix_within(text: str, width: int) -> str:
    """Take the longest prefix fitting in a display width.

    Parameters
    ----------
    text : str
        Sanitized text.
    width : int
        Available display cells.

    Returns
    -------
    str
        The prefix.
    """
    kept: list[str] = []
    used = 0
    for character in text:
        size = get_character_cell_size(character)
        if used + size > width:
            break
        kept.append(character)
        used += size
    return ''.join(kept)


def suffix_within(text: str, width: int) -> str:
    """Take the longest suffix fitting in a display width.

    Parameters
    ----------
    text : str
        Sanitized text.
    width : int
        Available display cells.

    Returns
    -------
    str
        The suffix.
    """
    kept: list[str] = []
    used = 0
    for character in reversed(text):
        size = get_character_cell_size(character)
        if used + size > width:
            break
        kept.append(character)
        used += size
    return ''.join(reversed(kept))


def truncate_end(text: str, width: int) -> str:
    """Truncate at the end with a counted marker (reporting §4.6, §8).

    Parameters
    ----------
    text : str
        Sanitized text.
    width : int
        Available display cells.

    Returns
    -------
    str
        Text fitting the width.
    """
    if cell_len(text) <= width:
        return text
    # The marker width depends on the omitted count's digits, which depends
    # on how much is kept: walk digit budgets upward until the count fits.
    digits = 1
    while True:
        budget = width - (6 + digits)
        if budget < 1:
            return prefix_within(text, width)
        head = prefix_within(text, budget)
        omitted = len(text) - len(head)
        if len(str(omitted)) <= digits:
            return f'{head}...(+{omitted})'
        digits += 1


def truncate_middle(text: str, width: int) -> str:
    """Truncate in the middle with a counted marker (reporting §4.6, §8).

    The leading directories and the trailing file name and line span are the
    identifying portions of a location, so both survive.

    Parameters
    ----------
    text : str
        Sanitized text.
    width : int
        Available display cells.

    Returns
    -------
    str
        Text fitting the width.
    """
    if cell_len(text) <= width:
        return text
    digits = 1
    while True:
        budget = width - (9 + digits)
        if budget < 3:
            # Too narrow to keep both ends: counted end truncation at least
            # preserves the leading directories.
            return truncate_end(text, width)
        head = prefix_within(text, budget // 3)
        tail = suffix_within(text, budget - cell_len(head))
        omitted = len(text) - len(head) - len(tail)
        if len(str(omitted)) <= digits:
            return f'{head}...(+{omitted})...{tail}'
        digits += 1


def fit_cell(text: str, width: int, degrade: Degrade | None) -> tuple[str, ...]:
    """Fit one cell into its measured column (reporting contract §4.6).

    Parameters
    ----------
    text : str
        Sanitized cell text.
    width : int
        Measured column width.
    degrade : Degrade | None
        The column's declared degradation; ``None`` chops by cells.

    Returns
    -------
    tuple[str, ...]
        The physical lines of the cell; only ``wrap-words`` yields more
        than one.
    """
    if degrade == 'wrap-words':
        return wrap_words(text, width)
    if degrade == 'truncate-middle':
        return (truncate_middle(text, width),) if text else ()
    if degrade == 'truncate-end':
        return (truncate_end(text, width),) if text else ()
    return wrap_cells(text, width)


def measure_widths(rows: Sequence[Sequence[Cell]], *, total_width: int) -> tuple[int, ...] | None:
    """Measure the shared column widths of one section (reporting §4.6).

    Fixed columns size to their largest cell; flexible columns receive
    widths between their declared minimum and maximum, shrinking toward the
    minimum only when the available width demands it.

    Parameters
    ----------
    rows : Sequence[Sequence[Cell]]
        Every finding row of the section.
    total_width : int
        Available display width.

    Returns
    -------
    tuple[int, ...] | None
        Per-column widths, or ``None`` when the minimum widths cannot be
        satisfied and the stacked layout must be used.
    """
    natural = [max(cell_len(column.header), column.minimum) for column in COLUMNS]
    for row in rows:
        for index, cell in enumerate(row):
            natural[index] = max(natural[index], cell_len(cell.text))
    widths = list(natural)
    for index, maximum in _FLEXIBLE_MAXIMA.items():
        widths[index] = min(widths[index], maximum)
    separators = len(COLUMN_SEPARATOR) * (len(COLUMNS) - 1)
    available = total_width - separators
    if sum(widths) <= available:
        return tuple(widths)
    floors = list(widths)
    for index in _FLEXIBLE_MAXIMA:
        floors[index] = min(widths[index], COLUMNS[index].minimum)
    if sum(floors) > available:
        return None
    # Grow flexible columns from their floors toward their wanted widths,
    # one cell at a time, largest deficit first (deterministic ties toward
    # earlier columns), until the available width is spent. The remaining
    # budget is strictly smaller than the total deficit here, because the
    # wanted widths did not fit.
    deficits = {index: widths[index] - floors[index] for index in _FLEXIBLE_MAXIMA}
    remaining = available - sum(floors)
    while remaining > 0:
        best = max(_FLEXIBLE_MAXIMA, key=lambda index: (deficits[index], -index))
        floors[best] += 1
        deficits[best] -= 1
        remaining -= 1
    return tuple(floors)


def _trimmed(segments: list[Segment]) -> Line:
    """Drop trailing padding so no physical line ends in whitespace.

    Parameters
    ----------
    segments : list[Segment]
        Segments of one physical line, in display order.

    Returns
    -------
    Line
        The line without trailing whitespace.
    """
    while segments and not segments[-1].text.strip():
        segments.pop()
    if segments:
        last = segments[-1]
        segments[-1] = Segment(text=last.text.rstrip(), role=last.role, link=last.link)
    return tuple(segments)


def header_line(widths: Sequence[int]) -> Line:
    """Render the column header row (reporting contract §4.2).

    Parameters
    ----------
    widths : Sequence[int]
        Measured column widths.

    Returns
    -------
    Line
        The header line with a blank first header cell.
    """
    segments: list[Segment] = []
    for index, column in enumerate(COLUMNS):
        if index:
            segments.append(Segment(text=COLUMN_SEPARATOR))
        pad = ' ' * (widths[index] - cell_len(column.header))
        segments.append(Segment(text=column.header + pad, role='header'))
    return _trimmed(segments)


def finding_lines(row: Sequence[Cell], widths: Sequence[int]) -> tuple[Line, ...]:
    """Lay one finding row out over as many physical lines as it needs.

    Continuation lines preserve the original column boundaries; columns
    other than the wrapping one stay blank (reporting contract §4.6).

    Parameters
    ----------
    row : Sequence[Cell]
        The eight cells of the finding row.
    widths : Sequence[int]
        Measured column widths.

    Returns
    -------
    tuple[Line, ...]
        The physical lines of the row.
    """
    wrapped = [fit_cell(cell.text, widths[index], COLUMNS[index].degrade) for index, cell in enumerate(row)]
    height = max([1, *(len(chunks) for chunks in wrapped)])
    lines: list[Line] = []
    for line_index in range(height):
        segments: list[Segment] = []
        for column_index, cell in enumerate(row):
            if column_index:
                segments.append(Segment(text=COLUMN_SEPARATOR))
            chunk = wrapped[column_index][line_index] if line_index < len(wrapped[column_index]) else ''
            pad = ' ' * (widths[column_index] - cell_len(chunk))
            if chunk:
                segments.append(Segment(text=chunk, role=cell.role, link=cell.link))
            if pad:
                segments.append(Segment(text=pad))
        lines.append(_trimmed(segments))
    return tuple(lines)


def continuation_lines(
    *,
    indent: int,
    prefix: Sequence[Segment] = (),
    body: Segment,
    total_width: int,
) -> tuple[Line, ...]:
    """Lay an indented continuation (source, values, links) out to width.

    Parameters
    ----------
    indent : int
        Leading display cells before the prefix.
    prefix : Sequence[Segment]
        Fixed prefix segments (e.g. a source line number and its gutter).
    body : Segment
        Body text, wrapped into the remaining width.
    total_width : int
        Available display width.

    Returns
    -------
    tuple[Line, ...]
        The physical lines; continuations align beneath the body.
    """
    prefix_width = sum(cell_len(segment.text) for segment in prefix)
    body_width = max(8, total_width - indent - prefix_width)
    chunks = wrap_cells(body.text, body_width) or ('',)
    lines: list[Line] = []
    for chunk_index, chunk in enumerate(chunks):
        segments: list[Segment] = [Segment(text=' ' * indent)]
        if prefix:
            if chunk_index == 0:
                segments.extend(prefix)
            else:
                segments.append(Segment(text=' ' * prefix_width))
        segments.append(Segment(text=chunk, role=body.role, link=body.link))
        lines.append(_trimmed(segments))
    return tuple(lines)


def aligned_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Segment]],
    *,
    indent: int,
    right_aligned: frozenset[int],
) -> tuple[Line, ...]:
    """Lay a small aligned table out (reporting contract §4.7).

    Parameters
    ----------
    headers : Sequence[str]
        Column headers.
    rows : Sequence[Sequence[Segment]]
        Row cells, one segment per column, already sanitized.
    indent : int
        Leading display cells.
    right_aligned : frozenset[int]
        Column indices padded on the left instead of the right.

    Returns
    -------
    tuple[Line, ...]
        The header line followed by one line per row.
    """
    widths = [cell_len(header) for header in headers]
    for row in rows:
        for index, segment in enumerate(row):
            widths[index] = max(widths[index], cell_len(segment.text))
    lines: list[Line] = []
    for cells in ((Segment(text=header, role='header') for header in headers), *rows):
        segments: list[Segment] = [Segment(text=' ' * indent)]
        for index, segment in enumerate(cells):
            if index:
                segments.append(Segment(text=COLUMN_SEPARATOR))
            pad = ' ' * (widths[index] - cell_len(segment.text))
            if index in right_aligned and pad:
                segments.append(Segment(text=pad))
            segments.append(segment)
            if index not in right_aligned and pad:
                segments.append(Segment(text=pad))
        lines.append(_trimmed(segments))
    return tuple(lines)


def column_offset(widths: Sequence[int], column_index: int) -> int:
    """Compute the x-offset of one column's left edge.

    Parameters
    ----------
    widths : Sequence[int]
        Measured column widths.
    column_index : int
        Index into :data:`COLUMNS`.

    Returns
    -------
    int
        Display cells before the column starts.
    """
    separator = len(COLUMN_SEPARATOR)
    return sum(widths[:column_index]) + separator * column_index
