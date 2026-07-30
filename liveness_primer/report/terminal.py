"""Terminal capability controls for the text renderer (reporting contract §6.3).

Copyright (C) 2026 Matthew C. Digman

``--color`` and ``--hyperlinks`` both default to ``auto``. Hyperlink
support cannot be inferred from terminfo or Rich; ``auto`` therefore
requires one conservative capability signal and disables OSC-8 whenever a
signal is absent, malformed, or unrecognized, or a terminal multiplexer is
in the way.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

CapabilityMode = Literal['auto', 'always', 'never']

CAPABILITY_CHOICES: tuple[CapabilityMode, ...] = ('auto', 'always', 'never')

# Deterministic fallback width for redirected text: output must not depend
# on ambient developer terminal size (reporting contract §4.6).
DEFAULT_REDIRECTED_WIDTH = 120

# TERM_PROGRAM values accepted as conservative OSC-8 capability signals.
_TERM_PROGRAM_ALLOWLIST = frozenset({'ghostty', 'iTerm.app', 'WezTerm', 'vscode'})

_DECIMAL = re.compile(r'^[0-9]+$')
_MIN_VTE_VERSION = 5000


@dataclass(frozen=True, slots=True)
class TextRenderOptions:
    """Resolved presentation options of one text rendering.

    Attributes
    ----------
    color : bool
        Whether generated ANSI styling is enabled.
    hyperlinks : bool
        Whether generated OSC-8 hyperlinks are enabled.
    width : int
        Available display width in terminal cells.
    """

    color: bool = False
    hyperlinks: bool = False
    width: int = DEFAULT_REDIRECTED_WIDTH


def resolve_color(mode: CapabilityMode, *, interactive: bool, env: Mapping[str, str]) -> bool:
    """Resolve the effective ANSI-styling capability (reporting contract §6.3).

    Parameters
    ----------
    mode : CapabilityMode
        The ``--color`` choice.
    interactive : bool
        Whether standard output is an interactive terminal.
    env : Mapping[str, str]
        Process environment.

    Returns
    -------
    bool
        True when generated ANSI styling may be emitted.
    """
    if mode == 'always':
        return True
    if mode == 'never':
        return False
    return interactive and env.get('TERM') != 'dumb' and 'NO_COLOR' not in env


def _capability_signal(env: Mapping[str, str]) -> bool:
    """Check for one conservative OSC-8 capability signal (reporting §6.3).

    Parameters
    ----------
    env : Mapping[str, str]
        Process environment.

    Returns
    -------
    bool
        True when a recognized, well-formed signal is present.
    """
    if env.get('TERM_PROGRAM') in _TERM_PROGRAM_ALLOWLIST:
        return True
    # kitty does not set TERM_PROGRAM.
    if env.get('KITTY_WINDOW_ID'):
        return True
    vte_version = env.get('VTE_VERSION', '')
    if _DECIMAL.match(vte_version) is not None and int(vte_version) >= _MIN_VTE_VERSION:
        return True
    return bool(env.get('WT_SESSION'))


def resolve_hyperlinks(mode: CapabilityMode, *, interactive: bool, env: Mapping[str, str]) -> bool:
    """Resolve the effective OSC-8 hyperlink capability (reporting contract §6.3).

    Parameters
    ----------
    mode : CapabilityMode
        The ``--hyperlinks`` choice.
    interactive : bool
        Whether standard output is an interactive terminal.
    env : Mapping[str, str]
        Process environment.

    Returns
    -------
    bool
        True when generated OSC-8 hyperlinks may be emitted.
    """
    if mode == 'always':
        return True
    if mode == 'never':
        return False
    if not interactive or env.get('TERM') == 'dumb':
        return False
    # Multiplexer passthrough cannot be inferred (reporting contract §6.3).
    if 'TMUX' in env or 'STY' in env:
        return False
    return _capability_signal(env)


def resolve_text_options(
    *,
    color_mode: CapabilityMode,
    hyperlink_mode: CapabilityMode,
    interactive: bool,
    env: Mapping[str, str],
    terminal_width: int | None,
) -> TextRenderOptions:
    """Resolve the text renderer's presentation options (reporting §4.6, §6.3).

    Parameters
    ----------
    color_mode : CapabilityMode
        The ``--color`` choice.
    hyperlink_mode : CapabilityMode
        The ``--hyperlinks`` choice.
    interactive : bool
        Whether standard output is an interactive terminal.
    env : Mapping[str, str]
        Process environment.
    terminal_width : int | None
        Measured terminal width, when interactive output has one.

    Returns
    -------
    TextRenderOptions
        The resolved options; redirected output uses the deterministic
        fallback width.
    """
    width = terminal_width if interactive and terminal_width is not None else DEFAULT_REDIRECTED_WIDTH
    return TextRenderOptions(
        color=resolve_color(color_mode, interactive=interactive, env=env),
        hyperlinks=resolve_hyperlinks(hyperlink_mode, interactive=interactive, env=env),
        width=width,
    )
