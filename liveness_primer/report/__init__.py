"""Report renderers: CLI text, JSON, and GitHub step summary (contract §9).

Copyright (C) 2026 Matthew C. Digman
"""

from liveness_primer.report.github import render_github
from liveness_primer.report.serialize import render_json
from liveness_primer.report.text import render_text

__all__ = ['render_github', 'render_json', 'render_text']
