# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""The JSON report renderer: the CI-consumable full report.

The JSON report is the full ``Report`` payload and retains detail the
rendered reports cap. JSON string escaping is the structural
guarantee that untrusted excerpt bytes reach consumers as data.
"""

from liveness_primer.findings import Report


def render_json(report: Report) -> str:
    """Serialize the full report as indented JSON.

    Parameters
    ----------
    report : Report
        The assembled report.

    Returns
    -------
    str
        The serialized ``Report`` payload, newline-terminated.
    """
    return report.model_dump_json(indent=2) + '\n'
