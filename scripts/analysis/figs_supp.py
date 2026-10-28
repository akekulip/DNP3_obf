#!/usr/bin/env python3
"""Supplementary evaluation figures S01-S12: one file per D where D matters, at most two panels each, in the same
P4USE style as the main figures. They carry the per-D detail that the main figures summarize.
"""
from pathlib import Path
import sys

from matplotlib.patches import Ellipse
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fig_style as fs  # noqa: E402
import figs_main as fm  # noqa: E402
import formby_eval  # noqa: E402
from eval_tables import CLASSES, DS, ci, pick  # noqa: E402

PAIR_ARMS = ('off', 'combined')
CLASSIFIER_PANELS = {'nb': (('Naive Bayes, retrained', 'retrained', 'nb'),
                            ('Naive Bayes, pre-deployment', 'pre_deployment', 'nb')),
                     'ann_gmm': (('FF-ANN, retrained', 'retrained', 'ff_ann'), ('GMM, retrained', 'retrained', 'gmm'))}


def cdf_pair(rows, out, name, d):
    fig, axes = fs.pair(sharey=True)
    for ax, arm in zip(axes, PAIR_ARMS):
        lo, hi = (d - 3, d + 3) if arm in fm.TIMED else (0, fm.UNTIMED_AXIS_MS)
        xs = np.arange(lo, hi + 0.005, 0.01)
        for c in CLASSES:
            m = fs.block_cdf(pick(rows, d_ms=d, arm=arm, operation=c), xs)
            if m is not None:
                ax.step(xs, m, where='post', color=fs.CLASS_COLOR[c], ls=fs.CLASS_STYLE[c], lw=1.3)
        if arm in fm.TIMED:
            fs.event_line(ax, d)
        ax.set_xlim(lo, hi)
        ax.set_ylim(0, 1.02)
        ax.set_yticks([0, 0.5, 1], ['0', '0.5', '1'])
        ax.set_xticks(np.arange(lo, hi + 0.5, 1 if arm in fm.TIMED else 2))
        ax.set_xlabel('CLRT (ms)')
    axes[0].set_ylabel('Cumulative fraction')
    fs.panel_titles(axes, [fs.ARM_LABEL[a] for a in PAIR_ARMS])
    fs.legend_below(fig, fs.class_handles())
    fs.save(fig, out, name)


def signature_pair(rows, out, name, d, notes, k=64):
    """Mean Formby Eq. 1 signature (199 bins on [0, H) plus overflow) of K-transaction windows per class."""
    fig, axes = fs.pair()
    for ax, arm in zip(axes, PAIR_ARMS):
        arm_rows = pick(rows, d_ms=d, arm=arm)
        if not pick(arm_rows, split='train'):
            continue
        high = formby_eval.fit_high(arm_rows, 'clrt')
        notes['%s/%s_H_ms' % (name, arm)] = high
        edges, gap = np.linspace(0, high, 200), high * 0.05
        for c in CLASSES:
            sig = [formby_eval.histogram(w['values'], high) / k
                   for w in formby_eval.make_windows(arm_rows, 'clrt', k) if w['operation'] == c]
            if not sig:
                continue
            m, s = np.mean(sig, axis=0), np.std(sig, axis=0)
            ax.stairs(m[:199], edges, color=fs.CLASS_COLOR[c], ls=fs.CLASS_STYLE[c], lw=1.1)
            ax.errorbar([high + gap * (1 + CLASSES.index(c))], [m[199]], yerr=[s[199]], fmt=fs.CLASS_MARKER[c],
                        color=fs.CLASS_COLOR[c], markeredgecolor=fs.EDGE, markeredgewidth=0.5, elinewidth=0.8,
                        capsize=1.5, clip_on=False, zorder=4)
        regular = [t for t in fs.mticker.MaxNLocator(4).tick_values(0, high) if 0 <= t <= high * 0.85]
        ax.set_xticks(regular + [high + gap * 2], ['%g' % t for t in regular] + ['≥H'])
        ax.set_xlim(0, high + gap * 3.5)
        fs.plain_numbers(ax, 3)
        ax.set_xlabel('CLRT bin (ms)')
    axes[0].set_ylabel('Mean fraction per bin')
    fs.panel_titles(axes, [fs.ARM_LABEL[a] for a in PAIR_ARMS])
    fs.legend_below(fig, fs.class_handles(marker=True))
    fs.save(fig, out, name)


def mean_variance_pair(rows, out, name, d, notes, k=8):
    """Formby Fig. 6a style: K-window mean against window variance, with a 2-std ellipse per class."""
    fig, axes = fs.pair()
    for ax, arm in zip(axes, PAIR_ARMS):
        windows = formby_eval.make_windows(pick(rows, d_ms=d, arm=arm), 'clrt', k)
        spans = []
        for c in CLASSES:
            pts = np.array([[np.mean(w['values']), np.log10(max(np.var(w['values'], ddof=1), 1e-6))]
                            for w in windows if w['operation'] == c])
            if len(pts) < 3:
                continue
            ax.scatter(pts[:, 0], pts[:, 1], s=7, marker=fs.CLASS_MARKER[c], color=fs.CLASS_COLOR[c], alpha=0.5,
                       lw=0, zorder=2)
            cov = np.cov(pts.T)
            spans.append((pts[:, 0].mean() - 2 * np.sqrt(cov[0, 0]), pts[:, 0].mean() + 2 * np.sqrt(cov[0, 0])))
            values, vectors = np.linalg.eigh(cov)
            angle = np.degrees(np.arctan2(vectors[1, -1], vectors[0, -1]))
            ax.add_patch(Ellipse(pts.mean(axis=0), 4 * np.sqrt(values[-1]), 4 * np.sqrt(max(values[0], 0)),
                                 angle=angle, fill=False, color=fs.CLASS_COLOR[c], ls=fs.CLASS_STYLE[c], lw=1.3,
                                 zorder=3))
        means = [np.mean(w['values']) for w in windows]
        if means:
            lo, hi = np.percentile(means, [1, 99])
            lo, hi = min([lo] + [a for a, _ in spans]), max([hi] + [b for _, b in spans])
            pad = 0.05 * (hi - lo)
            ax.set_xlim(lo - pad, hi + pad)
            notes['%s/%s_windows_outside_x_range' % (name, arm)] = int(sum(1 for m in means
                                                                           if not lo - pad <= m <= hi + pad))
        ax.yaxis.set_major_locator(fs.mticker.MultipleLocator(1))
        ax.yaxis.set_major_formatter(fs.mticker.FuncFormatter(lambda v, _: '$10^{%d}$' % v))
        ax.set_xlabel('Window mean CLRT (ms)')
    axes[0].set_ylabel('Window variance (ms²)')
    fs.panel_titles(axes, [fs.ARM_LABEL[a] for a in PAIR_ARMS])
    fs.legend_below(fig, fs.class_handles(marker=True))
    fs.save(fig, out, name)


def stability_pair(rows, out, name, d):
    """Per-block median CLRT with 25th-75th percentile whiskers, against block repetition at this D."""
    fig, axes = fs.pair()
    for ax, (arms, residual) in zip(axes, ((('off', 'size_only'), False), (fm.TIMED, True))):
        for i, arm in enumerate(arms):
            cell = pick(rows, d_ms=d, arm=arm)
            reps = sorted({r['repetition'] for r in cell})
            q = [np.percentile([r['clrt_ms'] - (d if residual else 0) for r in cell if r['repetition'] == rep],
                               [25, 50, 75]) for rep in reps]
            est = [(v[1], v[0], v[2]) for v in q]
            fm.errorbars(ax, np.array(reps) + (i - 0.5) * 0.25, est, arm, line=False)
        ax.set_xticks([1, 4, 8, 12, 16])
        ax.set_xlabel('Block repetition at D = %d ms' % d)
        fs.plain_numbers(ax)
        ax.set_ylabel('Median CLRT − D (ms)' if residual else 'Median CLRT (ms)')
    fs.panel_titles(axes, ['No obfuscation and Size', 'Timing and Timing+Size'])
    fs.legend_below(fig, [fs.arm_handle(a, line=False) for a in fs.ARM_ORDER])
    fs.save(fig, out, name)


def classifier_vs_k_pair(results, out, name, feature, ds=(5, 20)):
    by = {(r['d_ms'], r['arm'], r['feature'], r['k'], r['attacker']): r for r in results}
    ks = formby_eval.WINDOWS_K
    fig, axes = fs.pair(sharey=True)
    shift = fm.offsets(fs.ARM_ORDER, 0.12)
    for ax, d in zip(axes, ds):
        fs.chance_line(ax)
        for arm in fs.ARM_ORDER:
            est = [fm.classifier_value(by, d, arm, feature, k, 'retrained', 'nb') for k in ks]
            fm.errorbars(ax, np.arange(len(ks)) + shift[arm], est, arm)
        fs.thirds(ax)
        ax.set_xticks(range(len(ks)), ['%d' % k for k in ks])
        ax.set_xlabel('Window size K (transactions)')
    axes[0].set_ylabel('Balanced accuracy')
    fs.panel_titles(axes, ['D = %d ms' % d for d in ds])
    fs.legend_below(fig, [fs.arm_handle(a) for a in fs.ARM_ORDER] + [fs.chance_handle()], ncol=5)
    fs.save(fig, out, name)


def request_sizes(rows, out, notes):
    fig, ax = fs.single(height=1.9)
    groups = {'All arms': fm.class_sizes(rows, 'off', 'req_len')}
    notes['S11_request_sizes/equal_in_every_arm'] = all(fm.class_sizes(rows, arm, 'req_len') == groups['All arms']
                                                        for arm in fs.ARM_ORDER)
    fm.size_bars(ax, groups, ['#7F7F7F'], 'S11_request_sizes', notes)
    ax.set_ylabel('Request payload (B)')
    ax.set_ylim(0, 55)
    fig.tight_layout()
    fs.save(fig, out, 'S11_request_sizes')


def request_to_ack(rows, out, notes):
    fig, ax = fs.single()
    shift = fm.offsets(fs.ARM_ORDER, 0.35)
    for arm in fs.ARM_ORDER:
        est = []
        for d in DS:
            cell = pick(rows, d_ms=d, arm=arm)
            est.append(ci([float(np.median([r['ack_ms'] for r in cell if r['block_id'] == b]))
                           for b in sorted({r['block_id'] for r in cell})]))
        m = fm.errorbars(ax, np.array(DS) + shift[arm], est, arm)
        notes['S12_request_to_ack_vs_D/%s' % arm] = {'D%d' % d: float(v) for d, v in zip(DS, m)}
    ax.set_xticks(DS)
    ax.set_xlabel('D (ms)')
    ax.set_ylabel('Median request-to-ACK\ntime (ms)')
    fs.plain_numbers(ax)
    ax.set_ylim(0, 7)                                      # zero-based
    fs.legend_below(fig, [fs.arm_handle(a) for a in fs.ARM_ORDER], ncol=2)
    fs.save(fig, out, 'S12_request_to_ack_vs_D')


def render(rows, results, out, notes):
    out = Path(out) / 'supplementary'
    for d in DS:
        if not pick(rows, d_ms=d):
            continue
        fm.hist_pair(rows, out, 'S01_clrt_histogram_D%d' % d, d, PAIR_ARMS, notes)
        fm.hist_pair(rows, out, 'S02_clrt_histogram_D%d_timing_size' % d, d, ('timing_only', 'size_only'), notes)
        cdf_pair(rows, out, 'S03_clrt_cdf_D%d' % d, d)
        signature_pair(rows, out, 'S04_formby_signature_D%d' % d, d, notes)
        mean_variance_pair(rows, out, 'S05_mean_variance_D%d' % d, d, notes)
        fm.confusion_pair(results, out, 'S06_confusion_D%d' % d, d, notes)
        stability_pair(rows, out, 'S07_block_stability_D%d' % d, d)
    for feature in formby_eval.FEATURES:
        for suffix, panels in CLASSIFIER_PANELS.items():
            fm.classifier_pair(results, out, 'S%s_classifier_%s_%s' % ('08' if suffix == 'nb' else '09', feature,
                                                                       suffix), feature, panels, fs.ARM_ORDER, notes)
        classifier_vs_k_pair(results, out, 'S10_classifier_vs_K_%s' % feature, feature)
    request_sizes(rows, out, notes)
    request_to_ack(rows, out, notes)
