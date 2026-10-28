#!/usr/bin/env python3
"""Main evaluation figures fig01-fig08 (P4USE style, at most two panels each) and the pair builders they share with
the supplementary set. Every number a caption cites is recorded in the notes dict (written to figure_notes.json).
"""
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fig_style as fs  # noqa: E402
from eval_tables import CLASSES, DS, blocks_of, ci, connection_rates, paired_block_delta, pick  # noqa: E402

REPRESENTATIVE_D = 5           # reference D of the matrix and the D where the classifier criterion was falsified
TIMED = ('timing_only', 'combined')
UNTIMED_AXIS_MS = 10.0         # untimed histograms: 0.25 ms bins up to 10 ms, then one overflow bin
SIZE_CLASSES = (('READ', 'mixed', 'READ\nmixed'), ('READ', 'integrity', 'READ\nintegrity'),
                ('SELECT', '', 'SELECT'), ('OPERATE', '', 'OPERATE'))


def offsets(arms, width=0.45):
    return {arm: (i - (len(arms) - 1) / 2) * width for i, arm in enumerate(arms)}


def errorbars(ax, x, estimates, arm, line=True):
    m = np.array([e[0] for e in estimates], dtype=float)
    low = m - np.array([e[1] for e in estimates], dtype=float)
    high = np.array([e[2] for e in estimates], dtype=float) - m
    ax.errorbar(x, m, yerr=[np.nan_to_num(low), np.nan_to_num(high)], color=fs.ARM_COLOR[arm],
                ls=fs.ARM_STYLE[arm] if line else 'none', lw=fs.ARM_WIDTH[arm], marker=fs.ARM_MARKER[arm],
                markeredgecolor=fs.EDGE,
                markeredgewidth=0.6, elinewidth=0.8, capsize=2.0, zorder=3)
    return m


def hist_panel(ax, rows, d, arm, notes_key, notes):
    """Formby-style binned CLRT histogram, one line per class (mean per-block fraction)."""
    if arm in TIMED:
        bins = np.round(np.arange(d - 3, d + 3 + 0.125, 0.25), 6)      # same 0.25 ms bins as the untimed panels
        clip, ticks, labels = None, np.arange(d - 3, d + 4), None
        cells = {c: pick(rows, d_ms=d, arm=arm, operation=c) for c in CLASSES}
        notes[notes_key] = {c: sum(1 for r in cells[c] if not d - 3 <= r['clrt_ms'] < d + 3) for c in CLASSES}
    else:
        regular = np.arange(0, UNTIMED_AXIS_MS + 0.125, 0.25)
        bins = np.append(regular, [UNTIMED_AXIS_MS + 0.75, UNTIMED_AXIS_MS + 1.75])
        clip = (UNTIMED_AXIS_MS, UNTIMED_AXIS_MS + 1.25)
        ticks, labels = [0, 2, 4, 6, 8, UNTIMED_AXIS_MS + 1.25], ['0', '2', '4', '6', '8', '≥%g' % UNTIMED_AXIS_MS]
    for c in CLASSES:
        m, _ = fs.block_hist(pick(rows, d_ms=d, arm=arm, operation=c), 'clrt_ms', bins, clip)
        if m is not None:
            ax.stairs(m, bins, color=fs.CLASS_COLOR[c], ls=fs.CLASS_STYLE[c], lw=1.3)
    ax.set_xticks(ticks, labels)
    ax.set_xlim(bins[0] - 0.3, bins[-1] + 0.3)
    if arm in TIMED:
        fs.event_line(ax, d)
    fs.plain_numbers(ax)
    ax.set_xlabel('CLRT (ms)')


def hist_pair(rows, out, name, d, arms, notes):
    fig, axes = fs.pair()
    for ax, arm in zip(axes, arms):
        hist_panel(ax, rows, d, arm, '%s/%s_outside_D_plus_minus_3ms' % (name, arm), notes)
    axes[0].set_ylabel('Fraction of exchanges')
    fs.panel_titles(axes, [fs.ARM_LABEL[a] for a in arms])
    fs.legend_below(fig, fs.class_handles())
    fs.save(fig, out, name)


def confusion_pair(results, out, name, d, notes, feature='clrt', k=64):
    by = {(r['d_ms'], r['arm'], r['feature'], r['k'], r['attacker']): r for r in results}
    fig, axes = fs.pair(width=3.5, height=2.35)
    for ax, arm in zip(axes, ('off', 'combined')):
        ax.grid(False)
        m = ((by.get((d, arm, feature, k, 'retrained')) or {}).get('nb')) or {}
        if not m.get('confusion'):
            ax.axis('off')
            continue
        cm = np.array(m['confusion'], dtype=float)
        norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
        ax.imshow(norm, vmin=0, vmax=1, cmap='Blues')
        for (a, b), v in np.ndenumerate(cm):
            ax.text(b, a, '%d' % v, ha='center', va='center', color='white' if norm[a, b] > 0.55 else 'black')
        ax.set_xticks(range(3), CLASSES, rotation=30, ha='right', rotation_mode='anchor')
        ax.set_yticks(range(3), CLASSES if arm == 'off' else [''] * 3)
        ax.tick_params(length=0)
        ax.set_xlabel('Predicted')
        notes['%s/%s_correct_windows' % (name, arm)] = int(np.trace(cm))
        notes['%s/%s_windows' % (name, arm)] = int(cm.sum())
    axes[0].set_ylabel('True class')
    fs.panel_titles(axes, ['No obfuscation', 'Timing+Size'])
    fig.tight_layout()
    fs.save(fig, out, name)


def classifier_value(by, d, arm, feature, k, attacker, model):
    m = ((by.get((d, arm, feature, k, attacker)) or {}).get(model)) or {}
    interval = m.get('ci') or {}
    if 'estimate' in interval:
        return interval['estimate'], interval['lower'], interval['upper']
    ba = m.get('balanced_accuracy')
    return (np.nan,) * 3 if ba is None else (ba, ba, ba)       # FF-ANN: pooled random split, no block interval


def classifier_pair(results, out, name, feature, panels, arms, notes, k=64):
    by = {(r['d_ms'], r['arm'], r['feature'], r['k'], r['attacker']): r for r in results}
    fig, axes = fs.pair(sharey=True)
    shift = offsets(arms)
    for ax, (_, attacker, model) in zip(axes, panels):
        fs.chance_line(ax)
        for arm in arms:
            est = [classifier_value(by, d, arm, feature, k, attacker, model) for d in DS]
            m = errorbars(ax, np.array(DS) + shift[arm], est, arm)
            for d, v in zip(DS, m):
                notes['%s/%s/%s/D%d' % (name, model if attacker == 'retrained' else 'nb_pre', arm, d)] = float(v)
        fs.thirds(ax)
        ax.set_xticks(DS)
        ax.set_xlabel('D (ms)')
    axes[0].set_ylabel('Balanced accuracy')
    fs.panel_titles(axes, [p[0] for p in panels])
    fs.legend_below(fig, [fs.arm_handle(a) for a in arms] + [fs.chance_handle()])
    fs.save(fig, out, name)


def fig02_median_spread(rows, out, notes, verdict):
    """Spread (max - min) of the per-class median CLRT: the pooled value used by the timing verdict, plus one small
    point per block."""
    arms = ('off', 'timing_only', 'combined')
    fig, ax = fs.single()
    shift = offsets(arms, 0.6)
    for arm in arms:
        pooled = []
        for d in DS:
            cell = verdict['cells'].get('D%d/%s' % (d, 'combined' if arm == 'off' else arm), {})
            pooled.append(cell.get('off_median_spread_ms' if arm == 'off' else 'median_spread_ms', np.nan))
            per_block = []
            for b in blocks_of(pick(rows, d_ms=d, arm=arm)):
                medians = [np.median([r['clrt_ms'] for r in rows if r['block_id'] == b and r['arm'] == arm and
                                      r['operation'] == c]) for c in CLASSES]
                per_block.append(max(medians) - min(medians))
            if per_block:
                notes['fig02_median_spread_vs_D/%s/per_block/D%d' % (arm, d)] = dict(
                    min=float(np.min(per_block)), median=float(np.median(per_block)), max=float(np.max(per_block)))
            ax.plot(np.full(len(per_block), d + shift[arm]), per_block, ls='none', marker=fs.ARM_MARKER[arm],
                    ms=2.4, color=fs.ARM_COLOR[arm], alpha=0.55, markeredgewidth=0, zorder=2)
        ax.plot(np.array(DS) + shift[arm], pooled, color=fs.ARM_COLOR[arm], ls=fs.ARM_STYLE[arm],
                lw=fs.ARM_WIDTH[arm], marker=fs.ARM_MARKER[arm], markeredgecolor=fs.EDGE, markeredgewidth=0.6, zorder=3)
        notes['fig02_median_spread_vs_D/%s' % arm] = {'D%d' % d: v for d, v in zip(DS, pooled)}
    ax.set_xticks(DS)
    ax.set_xlabel('D (ms)')
    ax.set_ylabel('Spread of class\nmedian CLRT (ms)')
    fs.plain_numbers(ax)
    fs.legend_below(fig, [fs.arm_handle(a) for a in arms])
    fs.save(fig, out, 'fig02_median_spread_vs_D')


def class_sizes(rows, arm, field):
    sizes = {}
    for op, read_class, label in SIZE_CLASSES:
        values = sorted({r[field] for r in pick(rows, arm=arm, operation=op) if r.get('read_class', '') == read_class})
        if values:
            sizes[label] = values
    return sizes


def size_bars(ax, groups, colors, notes_key, notes):
    labels = [label for _, _, label in SIZE_CLASSES if any(label in g for g in groups.values())]
    x = np.arange(len(labels))
    width = 0.8 / len(groups)
    for i, (group, sizes) in enumerate(groups.items()):
        heights = [float(np.median(sizes[label])) if label in sizes else np.nan for label in labels]
        pos = x + (i - (len(groups) - 1) / 2) * width
        ax.bar(pos, heights, width * 0.92, color=colors[i], edgecolor=fs.EDGE, linewidth=0.5, label=group, zorder=2)
        for px, h in zip(pos, heights):
            if np.isfinite(h):
                ax.text(px, h, '%d' % h, ha='center', va='bottom', fontsize=8)
        notes['%s/%s' % (notes_key, group)] = {label: sizes.get(label) for label in labels}
    ax.set_xticks(x, labels)
    ax.tick_params(axis='x', length=0)
    fs.plain_numbers(ax)


def fig03_response_size(rows, out, notes):
    fig, ax = fs.single()
    groups = {'Native (No obfuscation, Timing)': class_sizes(rows, 'off', 'resp_len'),
              'Padded (Size, Timing+Size)': class_sizes(rows, 'combined', 'resp_len')}
    notes['fig03_response_size/native_equal_in_timing'] = class_sizes(rows, 'timing_only', 'resp_len') == \
        groups['Native (No obfuscation, Timing)']
    notes['fig03_response_size/padded_equal_in_size'] = class_sizes(rows, 'size_only', 'resp_len') == \
        groups['Padded (Size, Timing+Size)']
    size_bars(ax, groups, [fs.ARM_COLOR['off'], fs.ARM_COLOR['combined']], 'fig03_response_size', notes)
    ax.set_ylabel('Response payload (B)')
    ax.set_ylim(0, 185)
    handles = [fs.plt.Rectangle((0, 0), 1, 1, facecolor=c, edgecolor=fs.EDGE, linewidth=0.5, label=g)
               for g, c in zip(groups, [fs.ARM_COLOR['off'], fs.ARM_COLOR['combined']])]
    fs.legend_below(fig, handles, ncol=1)
    fs.save(fig, out, 'fig03_response_size')


def fig06_added_latency(rows, out, notes):
    arms = ('timing_only', 'size_only', 'combined')
    fig, axes = fs.pair(sharey=True)
    shift = offsets(arms)
    for ax, (label, stat) in zip(axes, (('median', np.median), ('p95', lambda v: np.percentile(v, 95)))):
        ax.axhline(0, **fs.ZERO)
        for arm in arms:
            est = [ci(paired_block_delta(rows, d, arm, 'rt_ms', stat)) for d in DS]
            m = errorbars(ax, np.array(DS) + shift[arm], est, arm)
            notes['fig06_added_latency_vs_D/%s/%s' % (label, arm)] = {'D%d' % d: float(v) for d, v in zip(DS, m)}
        ax.set_xticks(DS)
        ax.set_xlabel('D (ms)')
        fs.plain_numbers(ax, 5)
    axes[0].set_ylabel('Added request-to-response\ntime (ms)')
    fs.panel_titles(axes, ['Median (p50)', '95th percentile (p95)'])
    fs.legend_below(fig, [fs.arm_handle(a) for a in arms])
    fs.save(fig, out, 'fig06_added_latency_vs_D')


def fig07_rate(rows, out, notes):
    fig, ax = fs.single()
    shift = offsets(fs.ARM_ORDER, 0.35)
    for arm in fs.ARM_ORDER:
        m = errorbars(ax, np.array(DS) + shift[arm], [ci(connection_rates(rows, d, arm)) for d in DS], arm)
        notes['fig07_rate_vs_D/%s' % arm] = {'D%d' % d: float(v) for d, v in zip(DS, m)}
    ax.set_xticks(DS)
    ax.set_xlabel('D (ms)')
    ax.set_ylabel('Exchanges per second\nper connection')
    fs.plain_numbers(ax, 5)
    ax.set_ylim(0, 70)                                     # zero-based, so the drop is not exaggerated
    fs.legend_below(fig, [fs.arm_handle(a) for a in fs.ARM_ORDER], ncol=2)
    fs.save(fig, out, 'fig07_rate_vs_D')


def fig08_retransmissions(rows, out, notes):
    fig, ax = fs.single(height=1.9)
    for i, arm in enumerate(fs.ARM_ORDER):
        connections = {}
        for r in pick(rows, arm=arm):
            key = (r['block_id'], r['trial'])
            connections[key] = connections.get(key, 0) or (r['retx_out'] > 0)
        hit, total = sum(bool(v) for v in connections.values()), len(connections)
        ax.bar(i, hit, 0.6, color=fs.ARM_COLOR[arm], edgecolor=fs.EDGE, linewidth=0.5, zorder=2)
        ax.text(i, hit, '%d/%d' % (hit, total), ha='center', va='bottom', fontsize=8)
        notes['fig08_first_request_retransmissions/%s' % arm] = [hit, total]
    ax.set_xticks(range(len(fs.ARM_ORDER)), [fs.ARM_LABEL[a] for a in fs.ARM_ORDER])
    ax.tick_params(axis='x', length=0)
    ax.set_ylabel('Connections with a\nretransmitted request')
    ax.yaxis.set_major_locator(fs.mticker.MaxNLocator(4, integer=True))
    ax.set_ylim(0, max(1, ax.get_ylim()[1] * 1.15))
    fig.tight_layout()
    fs.save(fig, out, 'fig08_first_request_retransmissions')


def render(rows, results, out, notes, verdict):
    out = Path(out) / 'main'
    d = REPRESENTATIVE_D
    hist_pair(rows, out, 'fig01_clrt_histogram_D%d' % d, d, ('off', 'combined'), notes)
    fig02_median_spread(rows, out, notes, verdict)
    fig03_response_size(rows, out, notes)
    classifier_pair(results, out, 'fig04_classifier_vs_D', 'clrt',
                    (('Naive Bayes, retrained', 'retrained', 'nb'), ('FF-ANN, retrained', 'retrained', 'ff_ann')),
                    ('off', 'timing_only', 'combined'), notes)
    confusion_pair(results, out, 'fig05_confusion_D%d' % d, d, notes)
    fig06_added_latency(rows, out, notes)
    fig07_rate(rows, out, notes)
    fig08_retransmissions(rows, out, notes)
