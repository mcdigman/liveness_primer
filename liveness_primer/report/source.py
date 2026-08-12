"""Pinned-source evidence collection (reporting contract §3.3).

Copyright (C) 2026 Matthew C. Digman

Source evidence is derived from the byte-identical pinned corpus checkout
after the adapter has normalized and validated the reported path — never
from the detector's ``raw_excerpt``. Extraction goes through the bounded,
containment-enforcing filesystem helpers so corpus-controlled symlinks,
special files, oversized files, and undecodable bytes cannot bypass the
report trust boundary. Missing or out-of-range source produces no excerpt
and a bounded report warning rather than fabricated text.
"""

import re
from collections.abc import Sequence
from pathlib import Path

from liveness_primer.filesystem import FilesystemPolicyError, contained_path, read_small_text
from liveness_primer.findings import DiffClass, FindingDiff, FindingOccurrence, SourceExcerpt
from liveness_primer.report.common import excerpt_sides

# Bounded warning budget per project: the report stays scannable even when a
# corpus tree is missing wholesale (reporting contract §3.3).
MAX_SOURCE_WARNINGS = 20

# Source-location newline semantics (reporting contract §3.3): only LF, CRLF,
# and CR end a line. ``str.splitlines`` additionally breaks on form feed,
# vertical tab, NEL, and the Unicode separators, which Python and the
# detectors count as ordinary in-line characters — splitting on them would
# shift every following excerpt onto source that was never reported.
_SOURCE_NEWLINE = re.compile(r'\r\n|\r|\n')


def split_source_lines(text: str) -> tuple[str, ...]:
    """Split decoded source using source-location newline semantics (§3.3).

    Parameters
    ----------
    text : str
        Decoded file contents.

    Returns
    -------
    tuple[str, ...]
        The lines, without their terminators and without a spurious final
        empty line for text ending in a newline.
    """
    lines = _SOURCE_NEWLINE.split(text)
    if lines and not lines[-1]:
        lines.pop()
    return tuple(lines)


def extract_excerpt(
    lines: Sequence[str],
    *,
    start_line: int,
    end_line: int,
    budget: int,
) -> tuple[SourceExcerpt | None, str | None]:
    """Extract one bounded excerpt from decoded source lines (reporting §3.3).

    The excerpt begins at the reported start line, prioritizes lines in the
    reported span, and may use following existing lines to fill the
    ``budget``-line evidence budget. ``omitted_lines`` counts only existing
    reported-span lines dropped because the span exceeded the budget;
    context beyond the budget was never requested and is not counted.

    Parameters
    ----------
    lines : Sequence[str]
        Complete decoded source lines of the reported file.
    start_line : int
        Reported span start (1-based).
    end_line : int
        Reported span end (1-based, inclusive).
    budget : int
        Maximum lines to retain; positive.

    Returns
    -------
    tuple[SourceExcerpt | None, str | None]
        The excerpt and no warning, or no excerpt and the warning reason.
    """
    if start_line > len(lines):
        reason = f'reported line {start_line} is beyond the end of the file ({len(lines)} line(s))'
        return None, reason
    span_end = min(end_line, len(lines))
    span_existing = span_end - start_line + 1
    retained_span = min(span_existing, budget)
    retained = list(lines[start_line - 1 : start_line - 1 + retained_span])
    fill = budget - retained_span
    if fill > 0:
        retained.extend(lines[span_end : span_end + fill])
    excerpt = SourceExcerpt(
        start_line=start_line,
        lines=tuple(retained),
        omitted_lines=span_existing - retained_span,
    )
    return excerpt, None


def _sides_to_collect(diff: FindingDiff) -> tuple[tuple[str, FindingOccurrence], ...]:
    """Choose the occurrence sides whose evidence a diff needs (reporting §4.5).

    Parameters
    ----------
    diff : FindingDiff
        The classified diff.

    Returns
    -------
    tuple[tuple[str, FindingOccurrence], ...]
        ``(field name, occurrence)`` pairs: head for ``new``, else the
        reference-side base occurrence; both sides of a ``changed`` pair
        share their identity-pinned span.
    """
    field_name = 'head_occurrence' if diff.diff_class is DiffClass.NEW else 'base_occurrence'
    return tuple((field_name, occurrence) for occurrence in excerpt_sides(diff))


class _SourceCache:
    """Per-project cache of decoded source files and their read failures.

    Parameters
    ----------
    checkout : Path
        Pinned corpus checkout both revisions analyzed.
    """

    def __init__(self, checkout: Path) -> None:
        self._checkout = checkout
        self._files: dict[str, tuple[str, ...] | str] = {}

    def _read(self, path: str) -> tuple[str, ...] | str:
        """Read one contained, bounded, regular source file.

        Failure reasons never carry the local checkout prefix: warnings are
        report content and must stay free of disposable local paths.

        Parameters
        ----------
        path : str
            Normalized repository-relative POSIX path.

        Returns
        -------
        tuple[str, ...] | str
            The decoded lines, or the bounded failure reason.
        """
        try:
            resolved = contained_path(self._checkout, path)
        except FilesystemPolicyError as error:
            return str(error)
        # The reported path itself must be a regular file: a symlink is
        # checked on the unresolved path because containment resolution
        # follows links (reporting contract §3.3).
        if (self._checkout / path).is_symlink():
            return 'not a regular non-symlink file'
        try:
            text = read_small_text(resolved)
        except FilesystemPolicyError as error:
            return str(error).replace(f': {resolved}', '')
        return split_source_lines(text)

    def lines(self, path: str) -> tuple[str, ...] | str:
        """Fetch the decoded lines of one repository-relative file.

        Parameters
        ----------
        path : str
            Normalized repository-relative POSIX path.

        Returns
        -------
        tuple[str, ...] | str
            The decoded lines, or the bounded failure reason.
        """
        if path not in self._files:
            self._files[path] = self._read(path)
        return self._files[path]


def _bounded_warnings(warnings: dict[str, None]) -> tuple[str, ...]:
    """Cap collected warnings at the per-project budget (reporting §3.3).

    Parameters
    ----------
    warnings : dict[str, None]
        Deduplicated warnings in first-seen order.

    Returns
    -------
    tuple[str, ...]
        At most ``MAX_SOURCE_WARNINGS`` warnings plus an omission marker.
    """
    ordered = list(warnings)
    if len(ordered) <= MAX_SOURCE_WARNINGS:
        return tuple(ordered)
    omitted = len(ordered) - MAX_SOURCE_WARNINGS
    return (*ordered[:MAX_SOURCE_WARNINGS], f'({omitted} more source warning(s) omitted)')


def collect_source_evidence(
    diffs: Sequence[FindingDiff],
    *,
    checkout: Path,
    excerpt_lines: int,
) -> tuple[tuple[FindingDiff, ...], tuple[str, ...]]:
    """Attach pinned-source excerpts to retained diffs (reporting contract §3.3).

    Parameters
    ----------
    diffs : Sequence[FindingDiff]
        Retained diffs in report order.
    checkout : Path
        Pinned corpus checkout both revisions analyzed.
    excerpt_lines : int
        Evidence budget per occurrence; ``0`` disables source excerpts.

    Returns
    -------
    tuple[tuple[FindingDiff, ...], tuple[str, ...]]
        The enriched diffs and the bounded source warnings.
    """
    if excerpt_lines == 0:
        return tuple(diffs), ()
    cache = _SourceCache(checkout)
    warnings: dict[str, None] = {}
    enriched: list[FindingDiff] = []
    for diff in diffs:
        # Repository-level findings (path '.') name no file: there is no
        # source evidence to collect and none missing, so no warning.
        if diff.path == '.':
            enriched.append(diff)
            continue
        updates: dict[str, FindingOccurrence] = {}
        for field_name, occurrence in _sides_to_collect(diff):
            lines = cache.lines(diff.path)
            if isinstance(lines, str):
                warnings[f'{diff.path}: {lines}'] = None
                continue
            excerpt, reason = extract_excerpt(
                lines,
                start_line=occurrence.start_line,
                end_line=occurrence.end_line,
                budget=excerpt_lines,
            )
            if excerpt is None:
                warnings[f'{diff.path}:L{occurrence.start_line}: {reason}'] = None
                continue
            updates[field_name] = occurrence.model_copy(update={'source_excerpt': excerpt})
        enriched.append(diff.model_copy(update=updates) if updates else diff)
    return tuple(enriched), _bounded_warnings(warnings)
