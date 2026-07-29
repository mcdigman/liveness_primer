"""Smoke tests for the installed `liveness_primer` package.

These keep the suite non-empty while the implementation is still being written:
pytest exits 5 ("no tests collected") on an empty suite, which fails the Test
and Coverage workflows regardless of whether anything is actually broken.
"""

import importlib


def test_package_is_importable() -> None:
    assert importlib.import_module('liveness_primer') is not None
