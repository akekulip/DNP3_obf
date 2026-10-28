#!/usr/bin/env python3
"""Evaluation figures F1-F10 (with zooms) from rows.csv and formby_results.json; tables come from eval_tables.py.

Every figure is broken out by D. Histograms and CDFs draw the mean across blocks as plain lines, with no shaded
bands; spread is shown by box plots, per-block markers and 95% block-bootstrap intervals. Layout follows IEEE
graphics guidance and recent S&P/USENIX/TDSC practice: 3.5/7.16 in widths, one 9 pt serif face with embedded
TrueType fonts, one frameless legend above each figure, no top/right spines, sentence-case axis labels with units,
(a)/(b) sub-captions instead of panel titles, no interpretation on the figure (captions in CAPTIONS.md describe what
is drawn).

One encoding throughout, greyscale-safe:
  classes  READ / SELECT / OPERATE: near-black / brick red / amber (luminance 31 / 97 / 166), solid / dashed /
           dotted lines, plain / '////' / '....' fills, plus / X / hexagon markers;
  arms     no obfuscation / timing+size / timing / size: navy / purple / blue / light blue (luminance 43 / 98 / 135 /
           180), circle / diamond / square / triangle markers, plain / cross / back-slash / horizontal fills,
           solid lines;
  hollow markers (white fill, arm-coloured edge) always mark a secondary statistic (minimum per-class recall, p95);
  chance is a solid grey line;
  zero references are thin black lines; box medians (lines) and means (crosses) are white on dark fills.
Request->ACK and request->response are descriptive only (outside the D contract).

  $RESEARCH_PYTHON scripts/analysis/eval_figures.py ROWS_CSV FORMBY_JSON --output OUT_DIR
"""
import argparse
import json
from pathlib import Path
import sys

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker as mticker  # noqa: E402
from matplotlib.patches import Ellipse  # noqa: E402
import numpy as np  # noqa: E402

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import formby_eval  # noqa: E402
import utils_mpl  # noqa: E402
from eval_tables import (DS, ARMS, CLASSES, blocks_of, ci, connection_rates, paired_block_delta,  # noqa: E402,F401
                         pick, size_verdict, stats, sufficiency, tables, timing_verdict)

__all__ = ['main', 'setup', 'f2_size_hist', 'f10_overhead', 'stats', 'sufficiency', 'tables', 'size_verdict',
           'timing_verdict']   # tables and verdicts live in eval_tables and are re-exported here

ARM_LABEL = {'off': 'No obfuscation', 'timing_only': 'Timing', 'size_only': 'Size', 'combined': 'Timing+Size'}
CLASS_COLOR = {'READ': '#1f1f1f', 'SELECT': '#c23b22', 'OPERATE': '#e9a400'}
CLASS_STYLE = {'READ': '-', 'SELECT': '--', 'OPERATE': ':'}
CLASS_HATCH = {'READ': '', 'SELECT': '////', 'OPERATE': '....'}
CLASS_MARKER = {'READ': 'P', 'SELECT': 'X', 'OPERATE': 'h'}
ARM_COLOR = {'off': '#08306b', 'combined': '#6a51a3', 'timing_only': '#3fa0c4', 'size_only': '#8fbfdc'}
ARM_MARKER = {'off': 'o', 'combined': 'D', 'timing_only': 's', 'size_only': '^'}
ARM_HATCH = {'off': '', 'combined': 'xxxx', 'timing_only': '\\\\\\\\', 'size_only': '----'}
LETTERS = 'abcdefgh'
CLRT_AXIS_MS = 30.0     # values above land in a separate overflow bin (Formby Eq. 1 style), so no mass is hidden
CHANCE = dict(color='0.65', lw=1.0, ls='-', zorder=0)
ZERO = dict(color='k', lw=0.6, ls='-', zorder=0)
NOTES: dict = {}        # measured facts the captions rely on (written to figure_notes.json)


def setup():
    utils_mpl.set_global()
    # IEEE Author Center: embedded fonts (no Type 3), one face, ~9 pt at full size
    plt.rcParams.update({'pdf.fonttype': 42, 'ps.fonttype': 42, 'svg.fonttype': 'none',
                         'font.size': 9.0, 'axes.labelsize': 9.0, 'axes.titlesize': 9.0, 'xtick.labelsize': 9.0,
                         'ytick.labelsize': 9.0, 'legend.fontsize': 9.0, 'axes.labelweight': 'normal',
                         'axes.labelpad': 3.0, 'axes.grid': False, 'axes.spines.top': False,
                         'axes.spines.right': False, 'xtick.direction': 'out', 'ytick.direction': 'out',
                         'lines.linewidth': 1.2, 'legend.borderaxespad': 0.3, 'legend.handlelength': 2.4,
                         'hatch.linewidth': 0.5, 'savefig.bbox': 'tight', 'savefig.pad_inches': 0.03})


def save(fig, out, name):
    # No creation date or tool names: identical inputs give identical bytes, and there is no metadata to strip.
    fig.savefig(out / (name + '.pdf'), transparent=True,
                metadata={'CreationDate': None, 'Creator': None, 'Producer': None})
    with plt.rc_context({'svg.hashsalt': name}):           # fixed SVG element ids
        fig.savefig(out / (name + '.svg'), transparent=True, metadata={'Date': None, 'Creator': None})
    (out / 'preview').mkdir(exist_ok=True)
    fig.savefig(out / 'preview' / (name + '.png'), dpi=200, metadata={'Software': None})
    plt.close(fig)


def grid(nrows, ncols, height, width=7.16, **kw):
    fig, axes = plt.subplots(nrows, ncols, figsize=(width, height), squeeze=False, **kw)
    return fig, axes


def subcaptions(axes_row, labels, pad=-0.38):
    """Sub-captions under the bottom row instead of panel titles."""
    for letter, ax, label in zip(LETTERS, axes_row, labels):
        ax.text(0.5, pad, '(%s) %s' % (letter, label), transform=ax.transAxes, ha='center', va='top', fontsize=9)


def tidy(ax, nx=4, ny=4):
    ax.xaxis.set_major_locator(mticker.MaxNLocator(nx))
    ax.yaxis.set_major_locator(mticker.MaxNLocator(ny))
    ax.yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:g}'))


def legend(fig, handles, ncol=None, y=1.0):
    fig.legend(handles=handles, loc='lower center', ncol=ncol or len(handles), frameon=False,
               bbox_to_anchor=(0.5, y), columnspacing=1.2)


def class_lines(markers=False):
    return [plt.Line2D([], [], color=CLASS_COLOR[c], ls=CLASS_STYLE[c], lw=1.4, label=c,
                       marker=CLASS_MARKER[c] if markers else None, ms=5) for c in CLASSES]


def class_patches():
    return [plt.Rectangle((0, 0), 1, 1, facecolor=CLASS_COLOR[c], edgecolor='k', lw=0.5, hatch=CLASS_HATCH[c],
                          label=c) for c in CLASSES]


def arm_markers(arms=ARMS):
    return [plt.Line2D([], [], color=ARM_COLOR[a], marker=ARM_MARKER[a], markeredgecolor='k', markeredgewidth=0.5,
                       ms=5, lw=1.2, label=ARM_LABEL[a]) for a in arms]


def arm_keys(arms=ARMS):
    """One key per arm showing both its box/bar fill and its marker (HandlerTuple)."""
    from matplotlib.legend_handler import HandlerTuple
    handles = [(plt.Rectangle((0, 0), 1, 1, facecolor=ARM_COLOR[a], edgecolor='k', lw=0.5, hatch=ARM_HATCH[a]),
                plt.Line2D([], [], color=ARM_COLOR[a], marker=ARM_MARKER[a], markeredgecolor='k',
                           markeredgewidth=0.5, ms=5, lw=1.2)) for a in arms]
    return handles, [ARM_LABEL[a] for a in arms], {tuple: HandlerTuple(ndivide=None, pad=0.4)}


def legend_keys(fig, keys, extra=(), ncol=None):
    handles, labels, handler_map = keys
    handles, labels = list(handles) + list(extra), list(labels) + [h.get_label() for h in extra]
    fig.legend(handles=handles, labels=labels, handler_map=handler_map, loc='lower center',
               ncol=ncol or len(handles), frameon=False, bbox_to_anchor=(0.5, 1.0), columnspacing=1.2,
               handlelength=3.0)


def arm_patches(arms=ARMS):
    return [plt.Rectangle((0, 0), 1, 1, facecolor=ARM_COLOR[a], edgecolor='k', lw=0.5, hatch=ARM_HATCH[a],
                          label=ARM_LABEL[a]) for a in arms]


def p50_p95_keys():
    return [plt.Line2D([], [], color='0.3', marker='o', ms=5, lw=1.2, label='p50'),
            plt.Line2D([], [], color='0.3', marker='o', ms=5, lw=0.8, markerfacecolor='white', label='p95')]


def block_hist(cell, field, bins, clip=None):
    """Mean and std across blocks of the per-block fraction of rows in each bin."""
    per_block = []
    for b in blocks_of(cell):
        v = np.array([r[field] for r in cell if r['block_id'] == b], dtype=float)
        if clip is not None:
            v = np.where(v < clip[0], v, clip[1])
        per_block.append(np.histogram(v, bins)[0] / len(v))
    return (np.mean(per_block, axis=0), np.std(per_block, axis=0)) if per_block else (None, None)


def draw_class_hist(ax, cell_of, bins, field='clrt_ms', clip=None):
    for c in CLASSES:
        m, _ = block_hist(cell_of(c), field, bins, clip)
        if m is None:
            continue
        ax.stairs(m, bins, color=CLASS_COLOR[c], ls=CLASS_STYLE[c], lw=1.1)


def f1_clrt_hist(rows, out):
    regular = np.arange(0, CLRT_AXIS_MS + 0.125, 0.25)
    bins = np.append(regular, [CLRT_AXIS_MS + 0.75, CLRT_AXIS_MS + 1.75])   # gap, then one overflow bin
    fig, axes = grid(4, 4, 6.6, sharex=True)
    for i, d in enumerate(DS):
        for j, arm in enumerate(ARMS):
            ax = axes[i, j]
            draw_class_hist(ax, lambda c: pick(rows, d_ms=d, arm=arm, operation=c), bins,
                            clip=(CLRT_AXIS_MS, CLRT_AXIS_MS + 1.25))
            tidy(ax)
            ax.set_xlim(-0.5, CLRT_AXIS_MS + 2)
            ax.set_xticks([0, 10, 20, CLRT_AXIS_MS + 1.25], ['0', '10', '20', '≥%d' % CLRT_AXIS_MS])
            if j == 0:
                ax.set_ylabel('D = %d ms\nFraction' % d)
            if i == 3:
                ax.set_xlabel('CLRT (ms)')
    subcaptions(axes[-1], [ARM_LABEL[a] for a in ARMS], pad=-0.42)
    legend(fig, class_lines())
    fig.tight_layout()
    save(fig, out, 'F1_clrt_histograms')


def zoom_hist(rows, out, name, arms, window, width, step):
    fig, axes = grid(4, 2, 6.4)
    for i, d in enumerate(DS):
        lo, hi = window(d)
        bins = np.arange(lo, hi + width / 2, width)
        for j, arm in enumerate(arms):
            ax = axes[i, j]
            draw_class_hist(ax, lambda c: pick(rows, d_ms=d, arm=arm, operation=c), bins)
            tidy(ax, 5, 4)
            ax.set_xticks(np.arange(lo, hi + step / 2, step))
            ax.xaxis.set_major_formatter(mticker.StrMethodFormatter('{x:g}'))
            ax.set_xlim(lo - width, hi + width)            # keeps the first bin off the axis spine
            if j == 0:
                ax.set_ylabel('D = %d ms\nFraction' % d)
            if i == 3:
                ax.set_xlabel('CLRT (ms)')
    subcaptions(axes[-1], [ARM_LABEL[a] for a in arms], pad=-0.42)
    legend(fig, class_lines())
    fig.tight_layout()
    save(fig, out, name)


def f1b_clrt_zoom(rows, out):
    zoom_hist(rows, out, 'F1b_clrt_histograms_zoom_timed', ('timing_only', 'combined'),
              lambda d: (d - 3, d + 3), 0.2, 1)


def f1c_clrt_zoom_untimed(rows, out):
    zoom_hist(rows, out, 'F1c_clrt_histograms_zoom_untimed', ('off', 'size_only'), lambda d: (0, 10), 0.1, 2)


def f2_size_hist(rows, out):
    fig, axes = grid(4, 4, 6.0, sharey=True)
    offsets = dict(zip(CLASSES, (-2.6, 0, 2.6)))
    worst_std = 0.0
    for i, d in enumerate(DS):
        for j, arm in enumerate(ARMS):
            ax = axes[i, j]
            tops = {}
            for c in CLASSES:
                cell = pick(rows, d_ms=d, arm=arm, operation=c)
                if not cell:
                    continue
                sizes = sorted({r['resp_len'] for r in cell})
                fractions = [[np.mean([r['resp_len'] == s for r in cell if r['block_id'] == b])
                              for b in blocks_of(cell)] for s in sizes]
                worst_std = max([worst_std] + [float(np.std(f)) for f in fractions])
                means = [np.mean(f) for f in fractions]
                ax.bar(np.array(sizes) + offsets[c], means, width=2.5, color=CLASS_COLOR[c], edgecolor='k', lw=0.4,
                       hatch=CLASS_HATCH[c])
                for size, mean in zip(sizes, means):
                    tops[size] = max(tops.get(size, 0), mean)
            for size, top in tops.items():          # exact size as a direct data label
                near = [s for s in tops if s != size and abs(s - size) < 30]
                ha = 'center' if not near else ('right' if size < near[0] else 'left')
                ax.text(size + {'center': 0, 'right': 2, 'left': -2}[ha], top + 0.04, '%d' % size, ha=ha,
                        va='bottom', fontsize=9)
            ax.set_xlim(40, 175)
            ax.set_ylim(0, 1.3)
            ax.set_xticks([50, 100, 150])
            ax.set_yticks([0, 0.5, 1.0], ['0', '0.5', '1'])
            if j == 0:
                ax.set_ylabel('D = %d ms\nFraction' % d)
            if i == 3:
                ax.set_xlabel('Response payload (B)')
    NOTES['F2_max_std_across_blocks'] = worst_std
    subcaptions(axes[-1], [ARM_LABEL[a] for a in ARMS], pad=-0.42)
    legend(fig, class_patches())
    fig.tight_layout()
    save(fig, out, 'F2_response_size_histograms')
    groups = [('READ', 'mixed', 'READ\n(mixed)'), ('READ', 'integrity', 'READ\n(integrity)'),
              ('SELECT', '', 'SELECT'), ('OPERATE', '', 'OPERATE')]
    fig, ax = plt.subplots(figsize=(3.5, 2.1))
    for i, (operation, read_class, label) in enumerate(groups):
        for size in sorted({r['req_len'] for r in pick(rows, operation=operation, read_class=read_class)}):
            ax.bar(i, size, width=0.6, color=CLASS_COLOR[operation], edgecolor='k', lw=0.4,
                   hatch=CLASS_HATCH[operation])
            ax.text(i, size + 1, '%d' % size, ha='center', va='bottom', fontsize=9)
    ax.set_xticks(range(len(groups)), [g[2] for g in groups])
    ax.set_ylabel('Request payload (B)')
    ax.set_ylim(0, 55)
    save(fig, out, 'F2b_request_sizes')


def luminance(color):
    r, g, b = (int(color[i:i + 2], 16) for i in (1, 3, 5))
    return 0.299 * r + 0.587 * g + 0.114 * b


def boxes(ax, data, positions, color, hatch):
    ink = 'white' if luminance(color) < 110 else 'k'      # median stays visible on dark fills
    bp = ax.boxplot(data, positions=positions, widths=0.8, whis=(5, 95), showfliers=False, showmeans=True,
                    patch_artist=True, meanprops=dict(marker='x', markeredgecolor=ink, ms=3.5, markeredgewidth=0.9),
                    medianprops=dict(color=ink, lw=1.2), whiskerprops=dict(lw=0.8), capprops=dict(lw=0.8))
    for patch in bp['boxes']:
        patch.set(facecolor=color, hatch=hatch, edgecolor='k', lw=0.6)


def f3_clrt_box(rows, out):
    fig, axes = grid(1, 4, 2.6, sharey=True)
    for j, arm in enumerate(ARMS):
        ax = axes[0, j]
        for k, c in enumerate(CLASSES):
            keep = [(i * 4 + k, [r['clrt_ms'] for r in pick(rows, d_ms=d, arm=arm, operation=c)])
                    for i, d in enumerate(DS)]
            keep = [(p, v) for p, v in keep if v]
            if keep:
                boxes(ax, [v for _, v in keep], [p for p, _ in keep], CLASS_COLOR[c], CLASS_HATCH[c])
        ax.set_xticks([i * 4 + 1 for i in range(len(DS))], ['%d' % d for d in DS])
        ax.set_xlabel('D (ms)')
        ax.yaxis.set_major_locator(mticker.MaxNLocator(5))
    axes[0, 0].set_ylabel('CLRT (ms)')
    subcaptions(axes[0], [ARM_LABEL[a] for a in ARMS], pad=-0.3)
    legend(fig, class_patches())
    fig.tight_layout()
    save(fig, out, 'F3_clrt_spread_per_d')


def f3b_residual(rows, out):
    timed = ('timing_only', 'combined')
    bins = np.arange(-3, 3.05, 0.1)
    fig, axes = grid(4, 2, 6.0, sharex=True)
    outside = {}
    for i, d in enumerate(DS):
        for j, arm in enumerate(timed):
            ax = axes[i, j]
            shifted = [dict(r, residual=r['clrt_ms'] - d) for r in pick(rows, d_ms=d, arm=arm)]
            for c in CLASSES:
                outside['D%d/%s/%s' % (d, arm, c)] = sum(1 for r in shifted if r['operation'] == c and
                                                         not -3 <= r['residual'] < 3)
            draw_class_hist(ax, lambda c: pick(shifted, operation=c), bins, field='residual')
            ax.set_xlim(-3, 3)
            tidy(ax, 6, 4)
            if j == 0:
                ax.set_ylabel('D = %d ms\nFraction' % d)
            if i == 3:
                ax.set_xlabel('CLRT − D (ms)')
    NOTES['F3b_F1b_values_outside_D_plus_minus_3ms'] = outside
    subcaptions(axes[-1], [ARM_LABEL[a] for a in timed], pad=-0.42)
    legend(fig, class_lines())
    fig.tight_layout()
    save(fig, out, 'F3b_clrt_minus_d')


def f4_signatures(rows, out, k=64):
    fig, axes = grid(4, 2, 6.2)
    highs = {}
    for i, d in enumerate(DS):
        for j, arm in enumerate(('off', 'combined')):
            ax = axes[i, j]
            arm_rows = pick(rows, d_ms=d, arm=arm)
            if not pick(arm_rows, split='train'):
                continue
            high = formby_eval.fit_high(arm_rows, 'clrt')
            highs['D%d/%s' % (d, arm)] = high
            edges = np.linspace(0, high, 200)
            gap = high * 0.04
            for c in CLASSES:
                sig = [formby_eval.histogram(w['values'], high) / k
                       for w in formby_eval.make_windows(arm_rows, 'clrt', k) if w['operation'] == c]
                if not sig:
                    continue
                m, s = np.mean(sig, axis=0), np.std(sig, axis=0)
                ax.stairs(m[:199], edges, color=CLASS_COLOR[c], ls=CLASS_STYLE[c], lw=1.0)
                ax.errorbar([high + gap + CLASSES.index(c) * gap], [m[199]], yerr=[s[199]], fmt=CLASS_MARKER[c],
                            color=CLASS_COLOR[c], ms=4.5, elinewidth=0.8, capsize=1.5, clip_on=False, zorder=4)
            regular = [t for t in mticker.MaxNLocator(4).tick_values(0, high) if 0 <= t <= high * 0.85]
            ax.set_xticks(regular + [high + gap * 2], ['%g' % t for t in regular] + ['≥H'])
            ax.set_xlim(0, high + gap * 3.5)
            ax.yaxis.set_major_locator(mticker.MaxNLocator(3))
            ax.yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:g}'))
            if j == 0:
                ax.set_ylabel('D = %d ms\nFraction' % d)
            if i == 3:
                ax.set_xlabel('CLRT bin (ms)')
    NOTES['F4_H_ms'] = highs
    subcaptions(axes[-1], [ARM_LABEL[a] for a in ('off', 'combined')], pad=-0.45)
    legend(fig, class_lines(markers=True))
    fig.tight_layout()
    save(fig, out, 'F4_formby_signatures_K%d' % k)


def f5_classifiers(results, out):
    by = {(r['d_ms'], r['arm'], r['feature'], r['k'], r['attacker']): r for r in results}
    panels = (('NB, retrained', 'retrained', 'nb'), ('NB, pre-deployment', 'pre_deployment', 'nb'),
              ('FF-ANN, retrained', 'retrained', 'ff_ann'), ('GMM, retrained', 'retrained', 'gmm'))
    ks = formby_eval.WINDOWS_K
    for feature in formby_eval.FEATURES:
        fig, axes = grid(len(panels), 4, 7.4, sharex=True, sharey=True)
        for i, (title, attacker, model) in enumerate(panels):
            for j, d in enumerate(DS):
                ax = axes[i, j]
                ax.axhline(1 / 3, **CHANCE)
                for arm in ARMS:
                    pts, low, high, mins = [], [], [], []
                    for k in ks:
                        m = (by.get((d, arm, feature, k, attacker)) or {}).get(model) or {}
                        ba, interval = m.get('balanced_accuracy'), m.get('ci') or {}
                        # NB/GMM: mean of per-test-block BA with its interval; FF-ANN: pooled (random split)
                        pts.append(np.nan if ba is None else interval.get('estimate', ba if model == 'ff_ann'
                                                                           else np.nan))
                        low.append(interval.get('lower', np.nan))
                        high.append(interval.get('upper', np.nan))
                        mins.append(m.get('min_recall', np.nan) if m else np.nan)
                    x = np.arange(len(ks)) + (ARMS.index(arm) - 1.5) * 0.13
                    pts = np.array(pts, dtype=float)
                    if not np.all(np.isnan(low)):
                        ax.errorbar(x, pts, yerr=[pts - np.array(low), np.array(high) - pts], fmt='none',
                                    ecolor=ARM_COLOR[arm], elinewidth=0.8, capsize=1.5, zorder=2)
                    ax.plot(x, np.array(mins, dtype=float), ls='none', marker=ARM_MARKER[arm], ms=4,
                            markerfacecolor='white', markeredgecolor=ARM_COLOR[arm], markeredgewidth=1.0, zorder=2)
                    ax.plot(x, pts, color=ARM_COLOR[arm], marker=ARM_MARKER[arm], markeredgecolor='k',
                            markeredgewidth=0.5, ms=4, lw=1.1, zorder=4)
                ax.set_ylim(-0.08, 1.08)
                ax.set_xticks(range(len(ks)), ['%d' % k for k in ks])
                ax.yaxis.set_major_locator(mticker.FixedLocator([0, 1 / 3, 2 / 3, 1]))
                ax.yaxis.set_major_formatter(mticker.FixedFormatter(['0', '1/3', '2/3', '1']))
                if j == 0:
                    ax.set_ylabel('%s\nBalanced accuracy' % title)
                if i == len(panels) - 1:
                    ax.set_xlabel('K (transactions)')
        subcaptions(axes[-1], ['D = %d ms' % d for d in DS], pad=-0.42)
        legend(fig, arm_markers() + [
            plt.Line2D([], [], ls='none', marker='o', ms=5, markerfacecolor='white', markeredgecolor='k',
                       label='Min-class recall'),
            plt.Line2D([], [], label='Chance', **{k: v for k, v in CHANCE.items() if k != 'zorder'})], ncol=6)
        fig.tight_layout()
        save(fig, out, 'F5_classifiers_%s' % feature)
    fig, axes = grid(2, 4, 4.0)
    image = None
    for i, arm in enumerate(('off', 'combined')):
        for j, d in enumerate(DS):
            ax = axes[i, j]
            m = ((by.get((d, arm, 'clrt', 64, 'retrained')) or {}).get('nb')) or {}
            if not m.get('confusion'):
                ax.axis('off')
                continue
            cm = np.array(m['confusion'], dtype=float)
            norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
            image = ax.imshow(norm, vmin=0, vmax=1, cmap='Greys')
            for (a, b), v in np.ndenumerate(cm):
                ax.text(b, a, '%d' % v, ha='center', va='center', fontsize=9,
                        color='white' if norm[a, b] > 0.55 else 'black')
            ax.set_xticks(range(3), CLASSES, rotation=45, ha='right')
            ax.set_yticks(range(3), CLASSES if j == 0 else [''] * 3)
            if j == 0:
                ax.set_ylabel('%s\nTrue class' % ARM_LABEL[arm])
            if i == 1:
                ax.set_xlabel('Predicted class')
    subcaptions(axes[-1], ['D = %d ms' % d for d in DS], pad=-0.72)
    if image is not None:
        fig.tight_layout(rect=(0, 0, 0.92, 1))
        bar = fig.colorbar(image, ax=axes.ravel().tolist(), fraction=0.025, pad=0.02)
        bar.set_label('Row-normalized fraction')
    save(fig, out, 'F5d_confusion_nb_clrt_K64')


def f6_latency(rows, out):
    fig, axes = grid(3, 3, 6.8)
    for j, c in enumerate(CLASSES):
        for row, field, label in ((0, 'rt_ms', 'Request-to-response (ms)'), (2, 'ack_ms', 'Request-to-ACK (ms)')):
            ax = axes[row, j]
            for k, arm in enumerate(ARMS):
                keep = [(i * 5 + k, [r[field] for r in pick(rows, d_ms=d, arm=arm, operation=c)])
                        for i, d in enumerate(DS)]
                keep = [(p, v) for p, v in keep if v]
                if keep:
                    boxes(ax, [v for _, v in keep], [p for p, _ in keep], ARM_COLOR[arm], ARM_HATCH[arm])
            ax.set_xticks([i * 5 + 1.5 for i in range(len(DS))], ['%d' % d for d in DS])
            ax.yaxis.set_major_locator(mticker.MaxNLocator(5))
            ax.yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:g}'))
            ax.set_xlabel('D (ms)')
            if j == 0:
                ax.set_ylabel(label)
        ax = axes[1, j]
        ax.axhline(0, **ZERO)
        for arm in ARMS[1:]:
            base = np.array(DS) + (ARMS.index(arm) - 2) * 0.9
            for stat, filled in ((np.median, True), (lambda v: np.percentile(v, 95), False)):
                x = base + (0 if filled else 0.35)             # p95 beside, not over, p50
                est = [ci(paired_block_delta(pick(rows, operation=c), d, arm, 'rt_ms', stat)) for d in DS]
                m = np.array([e[0] for e in est])
                ax.errorbar(x, m, yerr=[m - np.array([e[1] for e in est]), np.array([e[2] for e in est]) - m],
                            color=ARM_COLOR[arm], marker=ARM_MARKER[arm], ms=4.5, lw=1.2 if filled else 0.8,
                            markerfacecolor=ARM_COLOR[arm] if filled else 'white',
                            markeredgecolor='k' if filled else ARM_COLOR[arm],
                            markeredgewidth=0.5 if filled else 1.0, elinewidth=0.8, capsize=1.5)
        ax.set_xticks(DS)
        ax.yaxis.set_major_locator(mticker.MaxNLocator(5))
        ax.set_xlabel('D (ms)')
        if j == 0:
            ax.set_ylabel('Added request-to-\nresponse (ms)')
    subcaptions(axes[-1], CLASSES, pad=-0.36)
    legend_keys(fig, arm_keys(), p50_p95_keys(), ncol=6)
    fig.tight_layout()
    save(fig, out, 'F6_latency_overhead')


def f7_stability(rows, out):
    fig, axes = grid(4, 2, 6.4, sharex=True)
    for i, d in enumerate(DS):
        for j, (arms, residual) in enumerate(((('off', 'size_only'), False), (('timing_only', 'combined'), True))):
            ax = axes[i, j]
            for arm in arms:
                cell = pick(rows, d_ms=d, arm=arm)
                reps = sorted({r['repetition'] for r in cell})
                q = [np.percentile([r['clrt_ms'] - (d if residual else 0) for r in cell if r['repetition'] == rep],
                                   [25, 50, 75]) for rep in reps]
                x = np.array(reps) + (arms.index(arm) - 0.5) * 0.25
                med = np.array([v[1] for v in q])
                ax.errorbar(x, med, yerr=[med - np.array([v[0] for v in q]), np.array([v[2] for v in q]) - med],
                            color=ARM_COLOR[arm], marker=ARM_MARKER[arm], markeredgecolor='k', markeredgewidth=0.5,
                            ms=3.5, lw=0.8, elinewidth=0.8, capsize=1.2)
            tidy(ax, 8, 4)
            ax.set_xticks([1, 4, 8, 12, 16])
            if j == 0:
                ax.set_ylabel('D = %d ms\nCLRT (ms)' % d)
            else:
                ax.set_ylabel('CLRT − D (ms)')
            if i == 3:
                ax.set_xlabel('Block repetition at this D')
    subcaptions(axes[-1], ['No obfuscation and Size', 'Timing and Timing+Size'], pad=-0.42)
    legend(fig, arm_markers(), ncol=4)
    fig.tight_layout()
    save(fig, out, 'F7_block_stability')


def block_cdf(cell, grid_x):
    per_block = []
    for b in blocks_of(cell):
        v = np.sort([r['clrt_ms'] for r in cell if r['block_id'] == b])
        per_block.append(np.searchsorted(v, grid_x, side='right') / len(v))
    return np.mean(per_block, axis=0), np.std(per_block, axis=0)


def cdf_grid(rows, out, name, arms, window, step, tick):
    fig, axes = grid(4, len(arms), 6.4, sharey=True)
    for i, d in enumerate(DS):
        lo, hi = window(d)
        xs = np.arange(lo, hi + step / 2, step)
        for j, arm in enumerate(arms):
            ax = axes[i, j]
            for c in CLASSES:
                cell = pick(rows, d_ms=d, arm=arm, operation=c)
                if not cell:
                    continue
                m, _ = block_cdf(cell, xs)
                ax.step(xs, m, where='post', color=CLASS_COLOR[c], ls=CLASS_STYLE[c], lw=1.1)
            ax.set_xlim(lo, hi)
            ax.set_ylim(0, 1.02)
            ax.set_yticks([0, 0.5, 1], ['0', '0.5', '1'])
            ax.set_xticks(np.arange(lo, hi + tick / 2, tick))
            ax.xaxis.set_major_formatter(mticker.StrMethodFormatter('{x:g}'))
            if j == 0:
                ax.set_ylabel('D = %d ms\nCDF' % d)
            if i == 3:
                ax.set_xlabel('CLRT (ms)')
    subcaptions(axes[-1], [ARM_LABEL[a] for a in arms], pad=-0.42)
    legend(fig, class_lines())
    fig.tight_layout()
    save(fig, out, name)


def f8_cdf(rows, out):
    cdf_grid(rows, out, 'F8_clrt_cdfs', ARMS, lambda d: (0, CLRT_AXIS_MS), 0.05, 10)


def f8b_cdf_zoom(rows, out):
    cdf_grid(rows, out, 'F8b_clrt_cdfs_zoom_timed', ('timing_only', 'combined'), lambda d: (d - 3, d + 3), 0.01, 1)


def f8c_cdf_zoom_untimed(rows, out):
    cdf_grid(rows, out, 'F8c_clrt_cdfs_zoom_untimed', ('off', 'size_only'), lambda d: (0, 10), 0.01, 2)


def f9_mean_variance(rows, out, k=8):
    fig, axes = grid(2, 4, 4.2, sharey='row')
    clipped = {}
    for i, arm in enumerate(('off', 'combined')):
        for j, d in enumerate(DS):
            ax = axes[i, j]
            windows = formby_eval.make_windows(pick(rows, d_ms=d, arm=arm), 'clrt', k)
            spans = []                                     # x extent of each class's 2-std ellipse
            for c in CLASSES:
                pts = np.array([[np.mean(w['values']), np.log10(max(np.var(w['values'], ddof=1), 1e-6))]
                                for w in windows if w['operation'] == c])
                if len(pts) < 3:
                    continue
                ax.scatter(pts[:, 0], pts[:, 1], s=9, marker=CLASS_MARKER[c], color=CLASS_COLOR[c], alpha=0.55, lw=0)
                cov = np.cov(pts.T)
                spans.append((pts[:, 0].mean() - 2 * np.sqrt(cov[0, 0]), pts[:, 0].mean() + 2 * np.sqrt(cov[0, 0])))
                values, vectors = np.linalg.eigh(cov)
                angle = np.degrees(np.arctan2(vectors[1, -1], vectors[0, -1]))
                ax.add_patch(Ellipse(pts.mean(axis=0), 4 * np.sqrt(values[-1]), 4 * np.sqrt(max(values[0], 0)),
                                     angle=angle, fill=False, color=CLASS_COLOR[c], ls=CLASS_STYLE[c], lw=1.3))
            means = [np.mean(w['values']) for w in windows]
            if means:
                lo, hi = np.percentile(means, [1, 99])
                lo, hi = min([lo] + [a for a, _ in spans]), max([hi] + [b for _, b in spans])
                pad = 0.05 * (hi - lo)
                ax.set_xlim(lo - pad, hi + pad)
                clipped['D%d/%s' % (d, arm)] = int(sum(1 for m in means if not lo - pad <= m <= hi + pad))
            ax.xaxis.set_major_locator(mticker.MaxNLocator(4))
            ax.yaxis.set_major_locator(mticker.MultipleLocator(1))
            ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: '$10^{%d}$' % v))
            if i == 1:
                ax.set_xlabel('Window mean CLRT (ms)')
            if j == 0:
                ax.set_ylabel('%s\nWindow variance (ms²)' % ARM_LABEL[arm])   # plain text: no mathtext spaces
    NOTES['F9_windows_outside_x_range'] = clipped
    subcaptions(axes[-1], ['D = %d ms' % d for d in DS], pad=-0.42)
    legend(fig, [plt.Line2D([], [], color=CLASS_COLOR[c], ls=CLASS_STYLE[c], marker=CLASS_MARKER[c], ms=5, lw=1.3,
                            label=c) for c in CLASSES])
    fig.tight_layout()
    save(fig, out, 'F9_mean_variance_K%d' % k)


def f10_overhead(rows, out):
    fig, axes = plt.subplots(5, 1, figsize=(3.5, 7.8), sharex=True)
    labels = ('Padding per\nresponse (B)', 'Payload per\ntransaction (+%)', 'Added request-to-\nresponse (ms)',
              'Transactions per\nsecond per connection', 'Retransmitted\nsegments')
    for arm in ARMS:
        pad, pct, rate, retx, p50, p95 = [], [], [], [], [], []
        for d in DS:
            a, o = pick(rows, d_ms=d, arm=arm), pick(rows, d_ms=d, arm='off')
            pad.append(ci([np.mean([r['resp_len'] for r in a if r['block_id'] == b]) -
                           np.mean([r['resp_len'] for r in o if r['block_id'] == b]) for b in blocks_of(a)]))
            pct.append(ci([100 * (sum(r['req_len'] + r['resp_len'] for r in a if r['block_id'] == b) /
                                  sum(r['req_len'] + r['resp_len'] for r in o if r['block_id'] == b) - 1)
                           for b in blocks_of(a)]))
            p50.append(ci(paired_block_delta(rows, d, arm, 'rt_ms', np.median)))
            p95.append(ci(paired_block_delta(rows, d, arm, 'rt_ms', lambda v: np.percentile(v, 95))))
            rate.append(ci(connection_rates(rows, d, arm)))
            seen = {(r['block_id'], r['trial']): r['retx_out'] + r['retx_in'] for r in a}
            retx.append(sum(seen.values()))
        x = np.array(DS) + (ARMS.index(arm) - 1.5) * 0.75
        series = [(axes[3], rate, True)] + ([] if arm == 'off' else
                                            [(axes[0], pad, True), (axes[1], pct, True), (axes[2], p50, True),
                                             (axes[2], p95, False)])
        for ax, values, filled in series:
            m = np.array([s[0] for s in values], dtype=float)
            ax.errorbar(x + (0 if filled else 0.3), m,     # p95 beside, not over, p50
                        yerr=[m - np.array([s[1] for s in values]), np.array([s[2] for s in values]) - m],
                        color=ARM_COLOR[arm], marker=ARM_MARKER[arm], ms=4.5, lw=1.2 if filled else 0.8,
                        markerfacecolor=ARM_COLOR[arm] if filled else 'white',
                        markeredgecolor='k' if filled else ARM_COLOR[arm],
                        markeredgewidth=0.5 if filled else 1.0, elinewidth=0.8, capsize=1.5)
        axes[4].bar(x, retx, width=0.55, color=ARM_COLOR[arm], edgecolor='k', lw=0.4, hatch=ARM_HATCH[arm])
    for ax in axes[:3]:
        ax.axhline(0, **ZERO)
    for letter, ax, label in zip(LETTERS, axes, labels):
        ax.set_ylabel(label)
        ax.yaxis.set_major_locator(mticker.MaxNLocator(4, integer=ax is axes[4]))
        ax.yaxis.set_major_formatter(mticker.StrMethodFormatter('{x:g}'))
        ax.text(-0.36, 1.0, '(%s)' % letter, transform=ax.transAxes, ha='left', va='top', fontsize=9)
    axes[-1].set_xticks(DS)
    axes[-1].set_xlabel('D (ms)')
    legend_keys(fig, arm_keys(), p50_p95_keys(), ncol=3)
    fig.tight_layout()
    save(fig, out, 'F10_overhead_small_multiples')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('rows', type=Path)
    parser.add_argument('formby', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    setup()
    rows = formby_eval.load_rows(args.rows)
    for row in rows:
        for field in ('retx_out', 'retx_in', 'kernel_drops', 'app_ok', 'observed_at_ns'):
            row[field] = int(row[field])
    formby = json.loads(args.formby.read_text())
    results = formby['results']
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    clean = [r for r in rows if not r['piggyback']]   # descriptive figures; piggyback reported in T3
    for figure in (f1_clrt_hist, f1b_clrt_zoom, f1c_clrt_zoom_untimed, f2_size_hist, f3_clrt_box, f3b_residual,
                   f4_signatures, f6_latency, f7_stability, f8_cdf, f8b_cdf_zoom, f8c_cdf_zoom_untimed,
                   f9_mean_variance, f10_overhead):
        figure(clean, out)
    f5_classifiers(results, out)
    tables(rows, results, out)
    gate = sufficiency(rows)
    (out / 'sufficiency.json').write_text(json.dumps(gate, indent=1) + '\n')
    verdicts = dict(size=size_verdict(rows), timing=timing_verdict(rows, formby.get('comparisons', [])),
                    sufficiency_gate_passed=gate['gate_passed'])
    (out / 'verdicts.json').write_text(json.dumps(verdicts, indent=1, default=float) + '\n')
    (out / 'figure_notes.json').write_text(json.dumps(NOTES, indent=1, default=float) + '\n')
    print('figures and tables written to', out, '| sufficiency gate', 'PASS' if gate['gate_passed'] else 'FAIL')
    return 0 if gate['gate_passed'] else 3


if __name__ == '__main__':
    raise SystemExit(main())
