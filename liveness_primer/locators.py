# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Serialized finding-locator assignment (explorer contract §4.2).

``line`` is the diff class's reference-side start line (head for ``new``,
base for ``dropped`` and ``changed``); the identity hash covers the start
line, so every diff sharing an identity shares ``line``, which stays
serialized as denormalized display data. ``occurrence`` is the diff's
zero-based position within the subsequence of the same serialized
``ProjectReport.diffs`` tuple whose identity and reference-side start line
equal ``(identity, line)``, without changing its serialized order.
Occurrences removed by the diff engine's equal-occurrence intersection are
not indexed, and truncation retains a canonical prefix, so retained indices
match the complete canonical sequence. Locators are assigned during
canonical assembly — after the canonical sort and any diff-transforming
hook, and before truncation and serialization. ``bisect --occurrence`` must
apply this identical rule.
"""

from collections.abc import Sequence

from liveness_primer.findings import FindingDiff, FindingLocator


def attach_locators(project: str, diffs: Sequence[FindingDiff]) -> tuple[FindingDiff, ...]:
    """Attach its unique serialized locator to each canonically ordered diff.

    Parameters
    ----------
    project : str
        Corpus project name of the containing project report.
    diffs : Sequence[FindingDiff]
        The complete canonical diff sequence, before truncation.

    Returns
    -------
    tuple[FindingDiff, ...]
        The same diffs, in order, each carrying its locator.
    """
    counters: dict[tuple[str, int], int] = {}
    located: list[FindingDiff] = []
    for diff in diffs:
        line = diff.reference_occurrence.start_line
        key = (diff.identity, line)
        ordinal = counters.get(key, 0)
        counters[key] = ordinal + 1
        locator = FindingLocator(project=project, identity=diff.identity, line=line, occurrence=ordinal)
        located.append(diff.model_copy(update={'locator': locator}))
    return tuple(located)
