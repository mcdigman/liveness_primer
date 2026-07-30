"""Finding-locator computation over serialized reports (contract §12, explorer §6.2).

Copyright (C) 2026 Matthew C. Digman

The serialized per-project diff sequence is the indexing set: ``line`` is
the diff class's reference-side start line (head for ``new``, base for
``dropped`` and ``changed``), and ``occurrence`` is the diff's zero-based
position within the subsequence of that same ``ProjectReport.diffs`` tuple
whose identity and reference-side start line equal ``(identity, line)``,
without changing its serialized order. Occurrences removed by the diff
engine's equal-occurrence intersection are not indexed, and result
truncation retains a canonical prefix, so retained indices match the
complete canonical diff sequence. ``bisect --occurrence`` and the browser
explorer must both apply this identical rule.
"""

from liveness_primer.findings import FindingDiff, FindingLocator, ProjectReport, Report


def diff_locator(project: str, diff: FindingDiff, *, occurrence: int) -> FindingLocator:
    """Build the locator of one serialized diff (explorer contract §6.2).

    Parameters
    ----------
    project : str
        Corpus project name of the containing project report.
    diff : FindingDiff
        The serialized diff.
    occurrence : int
        Zero-based position among diffs sharing ``(identity, line)``.

    Returns
    -------
    FindingLocator
        The locator.
    """
    return FindingLocator(
        project=project,
        identity=diff.identity,
        line=diff.reference_occurrence.start_line,
        occurrence=occurrence,
    )


def project_locators(project: ProjectReport) -> tuple[FindingLocator, ...]:
    """Compute the ordered locators of one project's serialized diffs.

    Parameters
    ----------
    project : ProjectReport
        The per-project report.

    Returns
    -------
    tuple[FindingLocator, ...]
        One locator per serialized diff, in serialized order.
    """
    counters: dict[tuple[str, int], int] = {}
    locators: list[FindingLocator] = []
    for diff in project.diffs:
        key = (diff.identity, diff.reference_occurrence.start_line)
        occurrence = counters.get(key, 0)
        counters[key] = occurrence + 1
        locators.append(diff_locator(project.project, diff, occurrence=occurrence))
    return tuple(locators)


def finding_locators(report: Report) -> tuple[FindingLocator, ...]:
    """Compute the ordered locators of every serialized diff in a report.

    Parameters
    ----------
    report : Report
        The validated report.

    Returns
    -------
    tuple[FindingLocator, ...]
        Locators in project run order, then serialized diff order; unique
        within one report by construction (explorer contract §6.2).
    """
    locators: list[FindingLocator] = []
    for project in report.projects:
        locators.extend(project_locators(project))
    return tuple(locators)
