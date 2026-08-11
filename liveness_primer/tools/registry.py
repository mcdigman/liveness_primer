"""Registry of the detector adapters shipped in this build (contract §4).

Copyright (C) 2026 Matthew C. Digman
"""

from liveness_primer.tools.base import DetectorAdapter, UnknownToolError
from liveness_primer.tools.skylos import SkylosAdapter
from liveness_primer.tools.vulture import VultureAdapter

_ADAPTERS: dict[str, DetectorAdapter] = {adapter.name: adapter for adapter in (VultureAdapter(), SkylosAdapter())}


def adapter_names() -> tuple[str, ...]:
    """List the tool names with a registered adapter.

    Returns
    -------
    tuple[str, ...]
        Registered names in registration order.
    """
    return tuple(_ADAPTERS)


def adapter_analyses() -> dict[str, tuple[str, ...]]:
    """Map each registered tool to its declared opt-in analysis names.

    Returns
    -------
    dict[str, tuple[str, ...]]
        Analysis names by tool, for corpus ``analyses`` validation.
    """
    return {name: tuple(adapter.analyses) for name, adapter in _ADAPTERS.items()}


def get_adapter(name: str) -> DetectorAdapter:
    """Look up the adapter for a tool name.

    Parameters
    ----------
    name : str
        Tool name from the CLI or corpus file.

    Returns
    -------
    DetectorAdapter
        The registered adapter.

    Raises
    ------
    UnknownToolError
        If no adapter provides the name.
    """
    try:
        return _ADAPTERS[name]
    except KeyError as exc:
        known = ', '.join(sorted(_ADAPTERS))
        msg = f'unknown tool {name!r}; available: {known}'
        raise UnknownToolError(msg) from exc
