"""Sphinx configuration for the `liveness_primer` HTML docs.

Built locally with ``sphinx-build -b html docs docs/_build/html`` and in CI by
.github/workflows/docs.yml, which additionally passes ``-W --keep-going`` so any
warning (broken reference, stale docstring) fails the build.
"""

from importlib.metadata import version as _version

project = 'liveness_primer'
author = 'Matthew C. Digman'
project_copyright = '2026, Matthew C. Digman'
release = _version('liveness_primer')

extensions = [
    'myst_parser',
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.intersphinx',
    'sphinx.ext.viewcode',
]

templates_path: list[str] = []
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'furo'
html_static_path: list[str] = []

# numpy-style docstrings, matching the [tool.pydoclint] style setting.
napoleon_google_docstring = False
napoleon_numpy_docstring = True

intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}
