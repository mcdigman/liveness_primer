"""Shipped test utilities: fake detector and fake project factory (contract §15).

Copyright (C) 2026 Matthew C. Digman
"""

from liveness_primer.testing.fake_detector import FakeFinding, fake_detector_command, write_fake_detector_script
from liveness_primer.testing.fake_project import FakeProject, create_fake_project

__all__ = [
    'FakeFinding',
    'FakeProject',
    'create_fake_project',
    'fake_detector_command',
    'write_fake_detector_script',
]
