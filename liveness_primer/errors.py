# SPDX-FileCopyrightText: Copyright 2026 Matthew C. Digman
# SPDX-License-Identifier: Apache-2.0
"""Exception hierarchy shared across the package.

Every domain error raised by this package subclasses
:class:`LivenessPrimerError`, so the CLI can distinguish run failures from
programming errors with a single catch.
"""


class LivenessPrimerError(Exception):
    """Base class for all domain errors raised by this package."""
