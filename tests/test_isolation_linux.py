"""Linux-only integration tests for the real isolation boundary (contract §11, §15).

Copyright (C) 2026 Matthew C. Digman

These run against the actual rootless ``unshare`` on the Linux reference
platform (and therefore in CI), demonstrating that the sandbox denies
networking rather than trusting the probe's exit status. They skip — with
the reason visible — on hosts that cannot create user namespaces, where
managed runs refuse to execute at all (fail-closed, §11).
"""

import sys

import pytest

from liveness_primer.isolation import Isolation, IsolationError, require_isolation
from liveness_primer.launcher import run_sync

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux network namespaces only')

# Asserts inside the namespace: no non-loopback interface exists, and even a
# loopback connection attempt fails (the namespace's `lo` starts down).
_NETWORK_IS_SEVERED = """
import socket
import sys

names = {name for _, name in socket.if_nameindex()}
if not names <= {'lo'}:
    sys.exit(2)
try:
    socket.create_connection(('127.0.0.1', 9), timeout=2)
except OSError:
    sys.exit(0)
sys.exit(3)
"""


def real_isolation() -> Isolation:
    try:
        return require_isolation()
    except IsolationError:  # e.g. containers without user namespaces
        pytest.skip('rootless user namespaces are unavailable on this host')


def test_required_isolation_is_enforced_on_linux() -> None:
    isolation = real_isolation()
    assert isolation.enforced
    assert isolation.description.startswith('netns:unshare')


def test_sandboxed_subprocess_has_no_usable_network() -> None:
    isolation = real_isolation()
    result = run_sync(isolation.wrap([sys.executable, '-c', _NETWORK_IS_SEVERED]), timeout=60.0)
    assert result.ok, (result.returncode, result.stderr)


def test_unsandboxed_control_sees_a_real_interface() -> None:
    # Control experiment: outside the namespace the same check fails,
    # proving the sandboxed run above demonstrated isolation, not a
    # networkless host.
    real_isolation()
    result = run_sync([sys.executable, '-c', _NETWORK_IS_SEVERED], timeout=60.0)
    assert result.returncode == 2
