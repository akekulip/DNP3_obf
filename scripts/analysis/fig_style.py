#!/usr/bin/env python3
"""Figure style for the c72 evaluation, after P4USE (IEEE TDSC 2026) and the in-network ML survey (IEEE COMST 2024).

One message per figure and at most two panels: a single panel is 3.5 x 2.0 in (one IEEE column), a pair is
7.16 x 2.1 in side by side. Times New Roman 9 pt with embedded TrueType fonts, light horizontal gridlines only, no
top/right/left frame, one frameless legend row centred below the axes, panel labels "(a) ..." above each panel.

Arms keep P4USE's Office colours in every figure: no obfuscation blue #4472C4 (circle, solid), Timing+Size orange
#ED7D31 (diamond, dashed), Timing grey #A5A5A5 (square, dotted), Size gold #FFC000 (triangle, dash-dot). The light
grey and gold get dark-edged markers and their own line styles (dataviz relief for sub-3:1 contrast). Classes use a
separate trio that passes the dataviz palette checks: READ green #1B9E77 (solid), SELECT purple #7570B3 (dashed),
OPERATE crimson #C2185B (dotted). No shaded bands: spread is shown with error bars, boxes or per-block points.
"""
from pathlib import Path
import sys

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker as mticker  # noqa: E402
import matplotlib.transforms as mtransforms  # noqa: E402
import numpy as np  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import utils_mpl  # noqa: E402
from eval_tables import CLASSES, blocks_of  # noqa: E402

ARM_LABEL = {'off': 'No obfuscation', 'timing_only': 'Timing', 'size_only': 'Size', 'combined': 'Timing+Size'}
ARM_COLOR = {'off': '#4472C4', 'combined': '#ED7D31', 'timing_only': '#A5A5A5', 'size_only': '#FFC000'}
ARM_MARKER = {'off': 'o', 'combined': 'D', 'timing_only': 's', 'size_only': '^'}
ARM_STYLE = {'off': '-', 'combined': '--', 'timing_only': ':', 'size_only': '-.'}
ARM_WIDTH = {'off': 1.4, 'combined': 1.4, 'timing_only': 1.9, 'size_only': 1.9}   # light colours drawn thicker
ARM_ORDER = ('off', 'timing_only', 'size_only', 'combined')
CLASS_COLOR = {'READ': '#1B9E77', 'SELECT': '#7570B3', 'OPERATE': '#C2185B'}
CLASS_STYLE = {'READ': '-', 'SELECT': '--', 'OPERATE': ':'}
CLASS_MARKER = {'READ': 'P', 'SELECT': 'X', 'OPERATE': 'h'}
EDGE = '#404040'
GRID = '#D9D9D9'
CHANCE = dict(color='#7F7F7F', lw=0.9, ls=(0, (4, 2)), zorder=1)
ZERO = dict(color=EDGE, lw=0.7, zorder=1)
EVENT = dict(color='#C00000', lw=0.8, ls='--', zorder=1)
SINGLE, PAIR = (3.5, 2.0), (7.16, 2.1)
AXES_PER_FIGURE: dict = {}


def setup():
    utils_mpl.set_global()
    plt.rcParams.update({'pdf.fonttype': 42, 'ps.fonttype': 42, 'svg.fonttype': 'none', 'font.size': 9.0,
                         'axes.labelsize': 9.0, 'axes.titlesize': 9.0, 'xtick.labelsize': 9.0, 'ytick.labelsize': 9.0,
                         'legend.fontsize': 9.0, 'axes.labelweight': 'normal', 'axes.labelpad': 3.0,
                         'axes.grid': True, 'axes.grid.axis': 'y', 'grid.color': GRID, 'grid.linewidth': 0.6,
                         'grid.linestyle': '-', 'axes.axisbelow': True, 'axes.spines.top': False,
                         'axes.spines.right': False, 'axes.spines.left': False, 'axes.edgecolor': '#A6A6A6',
                         'axes.linewidth': 0.8, 'xtick.direction': 'out', 'ytick.direction': 'out',
                         'ytick.major.size': 0.0, 'xtick.major.size': 3.0, 'xtick.minor.visible': False,
                         'ytick.minor.visible': False, 'lines.linewidth': 1.4, 'lines.markersize': 4.5,
                         'legend.frameon': False, 'legend.handlelength': 2.4, 'axes.titlelocation': 'left',
                         'axes.titleweight': 'normal',
                         'axes.titlepad': 4.0, 'savefig.bbox': 'tight', 'savefig.pad_inches': 0.03})


def single(height=SINGLE[1]):
    return plt.subplots(figsize=(SINGLE[0], height))


def pair(width=PAIR[0], height=PAIR[1], **kw):
    return plt.subplots(1, 2, figsize=(width, height), **kw)


def panel_titles(axes, labels):
    for letter, ax, label in zip('ab', axes, labels):
        ax.set_title('(%s) %s' % (letter, label), loc='left')


def arm_handle(arm, line=True):
    return plt.Line2D([], [], color=ARM_COLOR[arm], ls=ARM_STYLE[arm] if line else 'none', marker=ARM_MARKER[arm],
                      lw=ARM_WIDTH[arm], markeredgecolor=EDGE, markeredgewidth=0.6, label=ARM_LABEL[arm])


def class_handle(c, marker=False):
    return plt.Line2D([], [], color=CLASS_COLOR[c], ls=CLASS_STYLE[c], marker=CLASS_MARKER[c] if marker else None,
                      label=c)


def class_handles(marker=False):
    return [class_handle(c, marker) for c in CLASSES]


def legend_below(fig, handles, ncol=None):
    """One frameless legend row centred below the axes (P4USE)."""
    fig.tight_layout()
    fig.legend(handles=handles, loc='upper center', bbox_to_anchor=(0.5, 0.0), ncol=ncol or len(handles),
               columnspacing=1.4, borderaxespad=0.0)


def event_line(ax, x, label='D'):
    """Dashed vertical marker with a short label, as P4USE marks 'Start of Attack'."""
    ax.axvline(x, **EVENT)
    ax.text(x, 1.0, label, color=EVENT['color'], ha='center', va='bottom', fontsize=8, clip_on=False,
            transform=mtransforms.blended_transform_factory(ax.transData, ax.transAxes))


def chance_line(ax):
    ax.axhline(1 / 3, **CHANCE)


def chance_handle():
    return plt.Line2D([], [], label='Chance (1/3)', **{k: v for k, v in CHANCE.items() if k != 'zorder'})


def thirds(ax):
    ax.set_ylim(0, 1.02)
    ax.yaxis.set_major_locator(mticker.FixedLocator([0, 1 / 3, 2 / 3, 1]))
    ax.yaxis.set_major_formatter(mticker.FixedFormatter(['0', '1/3', '2/3', '1']))


def plain_numbers(ax, n=4):
    ax.yaxis.set_major_locator(mticker.MaxNLocator(n))
    ax.yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:g}'))


def block_hist(cell, field, bins, clip=None):
    """Mean and std across blocks of the per-block fraction of rows in each bin."""
    per_block = []
    for b in blocks_of(cell):
        v = np.array([r[field] for r in cell if r['block_id'] == b], dtype=float)
        if clip is not None:
            v = np.where(v < clip[0], v, clip[1])
        per_block.append(np.histogram(v, bins)[0] / len(v))
    return (np.mean(per_block, axis=0), np.std(per_block, axis=0)) if per_block else (None, None)


def block_cdf(cell, grid_x):
    """Mean across blocks of the per-block empirical CDF on grid_x."""
    per_block = []
    for b in blocks_of(cell):
        v = np.sort([r['clrt_ms'] for r in cell if r['block_id'] == b])
        per_block.append(np.searchsorted(v, grid_x, side='right') / len(v))
    return np.mean(per_block, axis=0) if per_block else None


def save(fig, out, name):
    # No creation date or tool names: identical inputs give identical bytes, and there is no metadata to strip.
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    AXES_PER_FIGURE[name] = sum(1 for ax in fig.axes if ax.get_label() != '<colorbar>' and ax.has_data())
    fig.savefig(out / (name + '.pdf'), transparent=True,
                metadata={'CreationDate': None, 'Creator': None, 'Producer': None})
    with plt.rc_context({'svg.hashsalt': name}):           # fixed SVG element ids
        fig.savefig(out / (name + '.svg'), transparent=True, metadata={'Date': None, 'Creator': None})
    (out / 'preview').mkdir(exist_ok=True)
    fig.savefig(out / 'preview' / (name + '.png'), dpi=200, metadata={'Software': None})
    plt.close(fig)
