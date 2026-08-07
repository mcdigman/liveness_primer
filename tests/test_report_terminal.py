"""Tests for terminal capabilities, styling, width, and layout (reporting §4.6, §6).

Copyright (C) 2026 Matthew C. Digman

Color and hyperlink tests assert capabilities and visible width separately
from the unstyled golden files (reporting contract §10).
"""

import re

import pytest
from rich.cells import cell_len

from liveness_primer.diffing import compute_rollups
from liveness_primer.findings import DiffClass, DiffTotals, ProjectReport
from liveness_primer.report import render_text
from liveness_primer.report.table import (
    CONFIDENCE_MIN_WIDTH,
    Cell,
    Segment,
    column_offset,
    continuation_lines,
    finding_lines,
    fit_cell,
    measure_widths,
    prefix_within,
    suffix_within,
    truncate_end,
    truncate_middle,
    wrap_cells,
    wrap_words,
)
from liveness_primer.report.terminal import (
    DEFAULT_REDIRECTED_WIDTH,
    TextRenderOptions,
    resolve_color,
    resolve_hyperlinks,
    resolve_text_options,
)
from tests.test_report import build_report, diff, occurrence, source_lines

_SGR = re.compile(r'\x1b\[[0-9;]*m')
_OSC8 = re.compile(r'\x1b]8;[^\x1b]*\x1b\\')


def strip_ansi(text: str) -> str:
    return _OSC8.sub('', _SGR.sub('', text))


def test_resolve_color_matrix() -> None:
    assert resolve_color('always', interactive=False, env={'NO_COLOR': '1', 'TERM': 'dumb'}) is True
    assert resolve_color('never', interactive=True, env={'TERM': 'xterm-256color'}) is False
    assert resolve_color('auto', interactive=True, env={'TERM': 'xterm-256color'}) is True
    assert resolve_color('auto', interactive=False, env={'TERM': 'xterm-256color'}) is False
    assert resolve_color('auto', interactive=True, env={'TERM': 'dumb'}) is False
    assert resolve_color('auto', interactive=True, env={'TERM': 'xterm', 'NO_COLOR': ''}) is False


@pytest.mark.parametrize(
    ('interactive', 'env', 'expected'),
    [
        # Explicit modes win regardless of the environment.
        (False, {}, False),
        (True, {'TERM_PROGRAM': 'ghostty'}, True),
        (True, {'TERM_PROGRAM': 'iTerm.app'}, True),
        (True, {'TERM_PROGRAM': 'WezTerm'}, True),
        (True, {'TERM_PROGRAM': 'vscode'}, True),
        (True, {'KITTY_WINDOW_ID': '1'}, True),
        (True, {'VTE_VERSION': '5000'}, True),
        (True, {'VTE_VERSION': '6003'}, True),
        (True, {'WT_SESSION': 'guid'}, True),
        # Unknown or absent capability signals default off.
        (True, {}, False),
        (True, {'TERM_PROGRAM': 'Apple_Terminal'}, False),
        (True, {'KITTY_WINDOW_ID': ''}, False),
        (True, {'WT_SESSION': ''}, False),
        # Malformed or too-old VTE versions default off.
        (True, {'VTE_VERSION': '4999'}, False),
        (True, {'VTE_VERSION': '0x1388'}, False),
        (True, {'VTE_VERSION': 'banana'}, False),
        (True, {'VTE_VERSION': ' 6003'}, False),
        (True, {'VTE_VERSION': '\u0665\u0660\u0660\u0660'}, False),
        (True, {'VTE_VERSION': ''}, False),
        # Multiplexers suppress OSC-8 even with a capable terminal.
        (True, {'TERM_PROGRAM': 'ghostty', 'TMUX': '/socket/tmux-1'}, False),
        (True, {'TERM_PROGRAM': 'ghostty', 'STY': '1234.pts-0'}, False),
        # A dumb or redirected terminal never gets hyperlinks in auto.
        (True, {'TERM_PROGRAM': 'ghostty', 'TERM': 'dumb'}, False),
        (False, {'TERM_PROGRAM': 'ghostty'}, False),
    ],
)
def test_resolve_hyperlinks_auto_matrix(*, interactive: bool, env: dict[str, str], expected: bool) -> None:
    # Reporting acceptance 16: every auto allowlist signal, malformed
    # VTE_VERSION, multiplexer suppression, and the default-off case.
    assert resolve_hyperlinks('auto', interactive=interactive, env=env) is expected


def test_resolve_hyperlinks_explicit_modes() -> None:
    assert resolve_hyperlinks('always', interactive=False, env={'TERM': 'dumb'}) is True
    assert resolve_hyperlinks('never', interactive=True, env={'TERM_PROGRAM': 'ghostty'}) is False


def test_resolve_text_options_width_selection() -> None:
    interactive = resolve_text_options(
        color_mode='auto',
        hyperlink_mode='auto',
        interactive=True,
        env={'TERM': 'xterm'},
        terminal_width=93,
    )
    assert interactive.width == 93
    assert interactive.color is True
    redirected = resolve_text_options(
        color_mode='auto',
        hyperlink_mode='auto',
        interactive=False,
        env={},
        terminal_width=93,
    )
    assert redirected.width == DEFAULT_REDIRECTED_WIDTH
    assert redirected.color is False
    assert redirected.hyperlinks is False


def test_color_never_and_redirected_auto_contain_no_ansi() -> None:
    # Reporting acceptance 14.
    report = build_report()
    for options in (
        resolve_text_options(
            color_mode='never', hyperlink_mode='never', interactive=True, env={'TERM': 'xterm'}, terminal_width=160
        ),
        resolve_text_options(color_mode='auto', hyperlink_mode='auto', interactive=False, env={}, terminal_width=None),
    ):
        assert '\x1b' not in render_text(report, options)


def test_color_always_strips_to_byte_equal_plain_report() -> None:
    # Reporting acceptance 15.
    report = build_report()
    plain = render_text(report, TextRenderOptions(color=False, hyperlinks=False, width=160))
    colored = render_text(report, TextRenderOptions(color=True, hyperlinks=False, width=160))
    assert '\x1b[' in colored
    assert strip_ansi(colored) == plain
    # Styles wrap only generated renderer elements: every escape sequence
    # sits outside the untrusted text it decorates.
    assert 'stderr said' in strip_ansi(colored)


def test_hyperlinks_wrap_visible_location_labels() -> None:
    report = build_report()
    linked = render_text(report, TextRenderOptions(color=False, hyperlinks=True, width=160))
    assert '\x1b]8;' in linked
    stripped = strip_ansi(linked)
    # The visible location label remains; the hidden link is never the only
    # representation of the target (reporting §5).
    assert 'pkg/mod.py:L9' in stripped
    assert 'url: https://github.com' not in stripped
    # Without hyperlinks the copyable relative location and the project's
    # corpus line remain; per-finding URL lines are opt-in (reporting §5).
    plain = render_text(report, TextRenderOptions(color=False, hyperlinks=False, width=160))
    assert 'pkg/mod.py:L9' in plain
    assert 'url: https://github.com' not in plain
    opted_in = render_text(report, TextRenderOptions(color=False, hyperlinks=False, width=160, source_urls=True))
    assert 'url: https://github.com' in opted_in


def test_wrap_cells_respects_display_width() -> None:
    assert wrap_cells('abcdef', 3) == ('abc', 'def')
    assert wrap_cells('', 3) == ()
    # Wide CJK characters occupy two cells each.
    assert wrap_cells('模块名字', 4) == ('模块', '名字')
    assert wrap_cells('模块名', 3) == ('模', '块', '名')
    # Combining characters occupy zero cells and stay with their base.
    combining = 'é' * 5
    assert wrap_cells(combining, 2) == ('éé', 'éé', 'é')


def test_measure_widths_returns_none_when_minimums_cannot_fit() -> None:
    rows = [tuple(Cell(text='x') for _ in range(8))]
    assert measure_widths(rows, total_width=30) is None
    widths = measure_widths(rows, total_width=200)
    assert widths is not None
    assert widths[2] == CONFIDENCE_MIN_WIDTH  # `NA` fits; nothing is reserved (§4.3)


def test_confidence_column_measures_to_its_widest_present_value() -> None:
    # Reporting acceptance 26: no fixed ten-cell reservation.
    def row(confidence: str) -> tuple[Cell, ...]:
        return (
            Cell(text='+'),
            Cell(text='SKY-U001'),
            Cell(text=confidence),
            Cell(text='function'),
            Cell(text='a/b.py:L1'),
            Cell(text='message'),
            Cell(text='symbol'),
            Cell(text='-'),
        )

    narrow = measure_widths([row('90%'), row('80%')], total_width=200)
    assert narrow is not None
    assert narrow[2] == 3
    wide = measure_widths([row('90%'), row('100%->100%')], total_width=200)
    assert wide is not None
    assert wide[2] == 10


def test_continuation_lines_align_beneath_prefix() -> None:
    lines = continuation_lines(
        indent=4,
        prefix=(Segment(text='12'), Segment(text=' | ', role='gutter')),
        body=Segment(text='a' * 20, role='source'),
        total_width=4 + 5 + 12,
    )
    rendered = [''.join(segment.text for segment in line) for line in lines]
    assert rendered[0] == '    12 | ' + 'a' * 12
    assert rendered[1] == '         ' + 'a' * 8


def test_rows_align_at_visible_column_boundaries_with_unicode() -> None:
    # Reporting acceptance 7: ASCII, combining Unicode, wide Unicode, long
    # paths, long messages, and long symbols share the same boundaries.
    entries = (
        diff(DiffClass.NEW, 'plain_symbol', kind='k1', head=occurrence(1, 'ascii message', confidence=None)),
        diff(
            DiffClass.NEW,
            'śymból',
            kind='k2',
            path='café/módule.py',
            head=occurrence(2, 'combining méssage', confidence=None),
        ),
        diff(
            DiffClass.NEW,
            '模块.符号',
            kind='k3',
            path='模块/文件.py',
            head=occurrence(3, '宽字符信息 wide message', confidence=None),
        ),
        diff(
            DiffClass.NEW,
            'very_long_symbol_name_' + 'x' * 60,
            kind='k4',
            path='deep/' * 30 + 'leaf.py',
            head=occurrence(4, 'long message ' + 'y' * 120, confidence=None),
        ),
    )
    project = ProjectReport(
        project='alpha',
        diffs=entries,
        totals=DiffTotals(new=4),
        rollups=compute_rollups(entries),
        truncated=False,
        base_findings=0,
        head_findings=4,
        measured_cost_seconds=None,
    )
    report = build_report().model_copy(update={'projects': (project,), 'truncated': False})
    text = render_text(report, TextRenderOptions(width=140))
    lines = text.splitlines()
    header = next(line for line in lines if 'location' in line and 'fields' in line)
    kind_offset = cell_len(header[: header.index('kind')])
    rows = [line for line in lines if line[:1] in {'+', '-', '~'}]
    assert len(rows) == 4
    for row, kind in zip(rows, ('k1', 'k2', 'k3', 'k4'), strict=True):
        assert cell_len(row[: row.index(kind)]) == kind_offset
    # No physical line exceeds the requested width.
    for line in lines:
        assert cell_len(line) <= 140


def test_narrow_output_uses_labelled_stacked_layout() -> None:
    # Reporting acceptance 8: no uncontrolled wrapping below minimum widths.
    entries = (
        diff(
            DiffClass.NEW,
            'stacked_symbol',
            head=occurrence(1, 'stacked message', confidence=80, rule_id='SKY-U001', source=source_lines(1, 'x = 1')),
        ),
        diff(
            DiffClass.NEW,
            'second_symbol',
            head=occurrence(2, 'second message', confidence=70, rule_id='SKY-U002', source=source_lines(2, 'y = 2')),
        ),
    )
    project = ProjectReport(
        project='alpha',
        diffs=entries,
        totals=DiffTotals(new=2),
        rollups=compute_rollups(entries),
        truncated=False,
        base_findings=0,
        head_findings=2,
        measured_cost_seconds=None,
    )
    report = build_report().model_copy(update={'projects': (project,), 'truncated': False})
    text = render_text(report, TextRenderOptions(width=40))
    assert '+ new' in text
    assert '  rule: SKY-U001' in text
    assert '  %: 80%' in text
    assert '  kind: function' in text
    assert '  location: pkg/mod.py:L1' in text
    assert '  message: stacked message' in text
    assert '  symbol: stacked_symbol' in text
    assert '  fields: -' in text
    assert '1 | x = 1' in text
    header_rows = [line for line in text.splitlines() if 'location' in line and 'fields' in line]
    assert header_rows == []
    # Stacked findings are separated by one blank line (reporting §4.5).
    lines = text.splitlines()
    glyphs = [index for index, line in enumerate(lines) if line == '+ new']
    assert len(glyphs) == 2
    assert not lines[glyphs[1] - 1]
    assert lines[glyphs[1] - 2].endswith('1 | x = 1')


def test_column_offset_matches_layout() -> None:
    widths = (1, 8, 10, 6, 20, 30, 10, 6)
    assert column_offset(widths, 0) == 0
    assert column_offset(widths, 1) == 3
    assert column_offset(widths, 4) == 1 + 8 + 10 + 6 + 4 * 2


def test_finding_lines_pad_and_wrap_preserving_boundaries() -> None:
    row = (
        Cell(text='+'),
        Cell(text='RULE'),
        Cell(text='NA'),
        Cell(text='kindx'),
        Cell(text='a/b.py:L1'),
        Cell(text='sym'),
        Cell(text='m' * 40),
        Cell(text='-'),
    )
    widths = measure_widths([row], total_width=90)
    assert widths is not None
    lines = finding_lines(row, widths)
    assert len(lines) > 1
    rendered = [''.join(segment.text for segment in line) for line in lines]
    message_offset = column_offset(widths, 6)
    assert rendered[0][message_offset:].startswith('m')
    # Continuation lines keep every other column blank.
    assert not rendered[1].strip().strip('m')
    assert rendered[1][message_offset:].startswith('m')


def test_finding_lines_trim_fully_blank_physical_lines() -> None:
    row = tuple(Cell(text='') for _ in range(8))
    widths = measure_widths([row], total_width=200)
    assert widths is not None
    (line,) = finding_lines(row, widths)
    assert line == ()


def test_wrap_words_breaks_at_word_boundaries() -> None:
    # Reporting acceptance 27: messages wrap on words, not mid-word.
    assert wrap_words('unused function example here', 16) == ('unused function', 'example here')
    assert wrap_words('', 10) == ()
    # A single word wider than the column falls back to cell chopping so no
    # line ever exceeds the measured width.
    assert wrap_words('short aaaaaaaaaa bb', 4) == ('shor', 't', 'aaaa', 'aaaa', 'aa', 'bb')


def test_truncate_end_counts_the_omitted_characters() -> None:
    assert truncate_end('symbol', 10) == 'symbol'
    assert truncate_end('s' * 30, 16) == 'ssssssss...(+22)'
    assert truncate_end('s' * 30, 12) == 'ssss...(+26)'
    # A cap too small for any marker degrades to a hard cut at the width.
    assert truncate_end('s' * 30, 5) == 'sssss'
    # Wide characters are counted in cells, not code points.
    assert cell_len(truncate_end('模' * 20, 14)) <= 14


def test_truncate_middle_preserves_both_ends_of_a_location() -> None:
    # Reporting acceptance 27.
    location = 'deep/' * 12 + 'leaf.py:L42'
    truncated = truncate_middle(location, 30)
    assert cell_len(truncated) <= 30
    assert truncated.startswith('deep/')
    assert truncated.endswith('leaf.py:L42')
    assert '...(+' in truncated
    assert truncate_middle('a/b.py:L1', 30) == 'a/b.py:L1'
    # Too narrow for a middle marker: fall back to counted end truncation.
    narrow = truncate_middle(location, 12)
    assert narrow == 'deep...(+67)'


def test_fit_cell_chops_columns_without_a_declared_degradation() -> None:
    assert fit_cell('abcdef', 3, None) == ('abc', 'def')
    assert fit_cell('', 8, 'truncate-end') == ()
    assert fit_cell('', 8, 'truncate-middle') == ()


def test_location_and_symbol_truncate_while_messages_wrap() -> None:
    # Reporting acceptance 27 end to end: only the message column produces
    # continuation lines.
    entry = diff(
        DiffClass.NEW,
        'symbol_' + 'z' * 80,
        path='deep/' * 20 + 'leaf.py',
        head=occurrence(1, 'a wordy diagnostic message that will not fit on one physical line at all'),
    )
    project = ProjectReport(
        project='alpha',
        diffs=(entry,),
        totals=DiffTotals(new=1),
        rollups=compute_rollups((entry,)),
        truncated=False,
        base_findings=0,
        head_findings=1,
        measured_cost_seconds=None,
    )
    report = build_report().model_copy(update={'projects': (project,), 'truncated': False})
    lines = render_text(report, TextRenderOptions(width=120)).splitlines()
    row = next(line for line in lines if line.startswith('+'))
    assert 'deep/' in row
    assert 'leaf.py' in row
    assert '...(+' in row
    continuation = lines[lines.index(row) + 1]
    # The continuation carries only the wrapped message.
    assert continuation.strip()
    assert 'deep/' not in continuation
    assert 'symbol_' not in continuation


def test_width_prefix_and_suffix_helpers_respect_cell_widths() -> None:
    assert prefix_within('abcdef', 3) == 'abc'
    assert prefix_within('abc', 10) == 'abc'
    assert suffix_within('abcdef', 3) == 'def'
    assert suffix_within('abc', 10) == 'abc'
    # A wide character is never split across the boundary.
    assert prefix_within('模块', 3) == '模'
    assert suffix_within('模块', 3) == '块'
