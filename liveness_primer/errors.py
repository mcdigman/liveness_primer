"""Exception hierarchy shared across the package.

Copyright (C) 2026 Matthew C. Digman

Every domain error raised by this package subclasses
:class:`LivenessPrimerError`, so the CLI can distinguish run failures from
programming errors with a single catch.
"""


class LivenessPrimerError(Exception):
    """Base class for all domain errors raised by this package."""
