"""Paper figures and tables for campaign eval_m11_09_20261018_02, from its exact outputs only.

The campaign's own results/ (39 hash-checked outputs) are evidence and are never rewritten. This
generator reads them, the release's per-exchange rows (hash-checked against the committed release
manifest) and the m11_09 compiler logs, and writes a separate, hash-checked paper directory:

    python paper_evidence.py CAMPAIGN_DIR OUT_DIR          # build
    python paper_evidence.py CAMPAIGN_DIR OUT_DIR --check  # rebuild in a temp dir, compare hashes

Run it in the campaign's pinned environment (results/requirements.lock.txt, Python 3.13.12).
Every figure is written with its caption, method, limitations, data CSV and provenance beside it.
"""
import argparse
import csv
import hashlib
import json
import re
import shutil
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

import paper_attacks
from paper_text import TEXT

ARMS = ('off', 'timing_only', 'size_only', 'combined')
LABEL = {'off': 'No obfuscation', 'timing_only': 'Timing', 'size_only': 'Size', 'combined': 'Timing+Size'}
COLOR = {'off': '#0072B2', 'timing_only': '#E69F00', 'size_only': '#009E73', 'combined': '#CC79A7'}
LINE = {'off': '-', 'timing_only': '--', 'size_only': '-.', 'combined': ':'}
MARK = {'off': 'o', 'timing_only': 's', 'size_only': '^', 'combined': 'D'}
OPS = ('READ', 'SELECT', 'OPERATE')
CONDITIONS = (('D05_J2p4', 5., 2.4), ('D10_J2p4', 10., 2.4), ('D15_J2p4', 15., 2.4), ('D20_J2p4', 20., 2.4),
              ('D10_J5', 10., 5.), ('D10_J10', 10., 10.), ('D10_J15', 10., 15.), ('D10_J20', 10., 20.))
PRIMARY = 'D10_J2p4'
COL1, COL2 = 3.5, 7.16
ROW_FIELDS = ('arm', 'condition_id', 'operation', 'split', 'round', 'block_id', 'ack_ms', 'clrt_ms', 'rt_ms',
              'resp_len', 'request_len', 'response_availability_ns', 'realized_j_ms', 'retransmitted',
              'attempts', 'master_timeout', 'complete')


def cond_label(cid, short=False):
    d, j = {c: (d, j) for c, d, j in CONDITIONS}[cid]
    return ('%g/%g' if short else 'D = %g ms, J = %g ms') % (d, j)


def style():
    plt.rcParams.update({'font.family': 'serif', 'font.serif': ['Times New Roman', 'DejaVu Serif'],
                         'font.size': 8, 'axes.titlesize': 8, 'axes.labelsize': 8, 'legend.fontsize': 7,
                         'xtick.labelsize': 7, 'ytick.labelsize': 7, 'axes.linewidth': .6,
                         'lines.linewidth': 1.0, 'pdf.fonttype': 42, 'svg.hashsalt': 'nomad',
                         'figure.dpi': 300})


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def read(path):
    with open(path, newline='') as f:
        return list(csv.DictReader(f))


def num(v):
    return None if v in ('', None, 'None', 'nan') else float(v)


def load_rows(path):
    csv.field_size_limit(sys.maxsize)
    out = []
    with open(path, newline='') as f:
        for r in csv.DictReader(f):
            out.append({k: r[k] for k in ROW_FIELDS})
    return out


class Writer:
    """Collects outputs and their sidecars; every figure has exactly one TEXT entry."""

    def __init__(self, out, inputs):
        self.out, self.inputs, self.items = Path(out), inputs, []
        for sub in ('figures', 'tables'):
            (self.out / sub).mkdir(parents=True, exist_ok=True)

    def figure(self, fig, name, data, sources, claims):
        path = self.out / 'figures' / (name + '.pdf')
        fig.tight_layout(pad=0.4, h_pad=0.8, w_pad=0.6)
        fig.savefig(path, metadata={'CreationDate': None, 'ModDate': None, 'Creator': None, 'Producer': None},
                    bbox_inches='tight', pad_inches=.02)
        plt.close(fig)
        self._sidecars('figures', name, data, sources, claims)

    def table(self, name, data, sources, claims):
        self._write_csv(self.out / 'tables' / (name + '.csv'), data)
        self._sidecars('tables', name, None, sources, claims)

    def _sidecars(self, sub, name, data, sources, claims):
        text = TEXT[name]
        base = self.out / sub / name
        for key in ('caption', 'method', 'limitations'):
            Path(str(base) + '.' + key + '.md').write_text(text[key].strip() + '\n')
        if data is not None:
            self._write_csv(Path(str(base) + '_data.csv'), data)
        Path(str(base) + '.provenance.json').write_text(json.dumps(
            {'output': name, 'claims': claims, 'sources': {s: self.inputs[s] for s in sources},
             'generator': 'seg61_02/analysis/paper_evidence.py', 'evidence_kind': 'hardware'},
            indent=2, sort_keys=True) + '\n')
        self.items.append(name)

    @staticmethod
    def _write_csv(path, data):
        keys = list(dict.fromkeys(k for r in data for k in r)) or ['empty']
        with open(path, 'w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=keys, lineterminator='\n', restval='')
            w.writeheader()
            for r in data:
                w.writerow({k: (repr(round(v, 9)) if isinstance(v, float) else v) for k, v in r.items()})


def legend_handles(ax, arms=ARMS):
    from matplotlib.lines import Line2D
    return [Line2D([], [], color=COLOR[a], linestyle=LINE[a], marker=MARK[a], markersize=3, label=LABEL[a])
            for a in arms]


# ---------------------------------------------------------------- figures

def fig_clrt(w, rows):
    """C4: master-visible CLRT, four arms, coarse and zoomed, at the primary condition."""
    sel = [r for r in rows if r['condition_id'] == PRIMARY]
    fig, ax = plt.subplots(2, 1, figsize=(COL1, 3.6))
    edges = np.arange(0, 22.25, .25)
    zoom = np.arange(9.9, 10.1001, .005)
    data = []
    for a in ARMS:
        v = np.array([float(r['clrt_ms']) for r in sel if r['arm'] == a])
        c, _ = np.histogram(np.clip(v, 0, edges[-1] - 1e-9), edges)
        ax[0].step(edges[:-1], 100 * c / len(v), where='post', color=COLOR[a], linestyle=LINE[a], label=LABEL[a])
        z, _ = np.histogram(v, zoom)
        if a in ('timing_only', 'combined'):
            ax[1].step(zoom[:-1], 100 * z / len(v), where='post', color=COLOR[a], linestyle=LINE[a], label=LABEL[a])
        data += [dict(arm=a, panel='a', left_ms=float(l), percent=float(100 * n / len(v)), n=len(v))
                 for l, n in zip(edges[:-1], c) if n]
        data += [dict(arm=a, panel='b', left_ms=float(l), percent=float(100 * n / len(v)), n=len(v))
                 for l, n in zip(zoom[:-1], z) if n]
    ax[0].set(xlabel='Master-visible CLRT (ms), 0.25 ms bins', ylabel='Exchanges (%)', yscale='log',
              title='(a) Full range, ' + cond_label(PRIMARY))
    ax[1].axvline(10, color='.4', linewidth=.6, linestyle='--')
    ax[1].set(xlabel='Master-visible CLRT (ms), 5 µs bins', ylabel='Exchanges (%)',
              title='(b) Within 0.1 ms of D = 10 ms')
    ax[0].legend(handles=legend_handles(ax[0]), loc='upper right', frameon=False)
    w.figure(fig, 'fig_clrt_four_arm', data, ['release/rows.csv'], ['C4'])


def fig_precision(w, residuals):
    """C4/C16: |CLRT - D| complementary CDF for the timed arms, per operation, all conditions."""
    fig, ax = plt.subplots(1, 3, figsize=(COL2, 1.9), sharey=True)
    data = []
    for i, op in enumerate(OPS):
        for a in ('timing_only', 'combined'):
            v = np.sort([max(float(r['abs_error_ms']) * 1000, 1.0) for r in residuals
                         if r['arm'] == a and r['operation'] == op])
            ccdf = 1 - np.arange(len(v)) / len(v)
            ax[i].step(v, ccdf, where='post', color=COLOR[a], linestyle=LINE[a], label=LABEL[a])
            for q in (.5, .99, .999, 1.):
                data.append(dict(arm=a, operation=op, quantile=q, abs_error_us=float(np.quantile(v, q)), n=len(v),
                                 within_100us=int((v <= 100).sum())))
        ax[i].axvline(100, color='.4', linewidth=.6, linestyle='--')
        ax[i].set(xscale='log', yscale='log', xlim=(1, 3000), ylim=(1e-5, 1.05), title=op,
                  xlabel='|CLRT − D| (µs), floor 1 µs')
    ax[0].set_ylabel('Fraction exceeding')
    ax[2].legend(handles=legend_handles(ax[2], ('timing_only', 'combined')), frameon=False, loc='lower left')
    w.figure(fig, 'fig_precision_tail', data, ['results/precision_residuals.csv'], ['C4', 'C16'])


def fig_precision_bias(w, residuals):
    """C4: signed median CLRT - D per condition and operation (operation-dependent only at D = 10 ms)."""
    fig, ax = plt.subplots(2, 1, figsize=(COL1, 3.6), sharex=True, sharey=True)
    x = np.arange(len(CONDITIONS))
    data = []
    opstyle = {'READ': ('o', '-'), 'SELECT': ('s', '--'), 'OPERATE': ('^', ':')}
    for i, a in enumerate(('timing_only', 'combined')):
        for op in OPS:
            y = []
            for c in CONDITIONS:
                v = [float(r['residual_ms']) * 1000 for r in residuals
                     if r['arm'] == a and r['operation'] == op and r['condition_id'] == c[0]]
                y.append(float(np.median(v)))
                data.append(dict(arm=a, operation=op, condition_id=c[0], n=len(v), median_signed_residual_us=y[-1],
                                 p25_us=float(np.quantile(v, .25)), p75_us=float(np.quantile(v, .75))))
            ax[i].plot(x, y, color='.15', marker=opstyle[op][0], linestyle=opstyle[op][1], markersize=3,
                       linewidth=.8, label=op)
        ax[i].axhline(0, color='.5', linewidth=.6)
        ax[i].set(title=LABEL[a], ylabel='Median CLRT − D (µs)')
        ax[i].set_xticks(x, [cond_label(c[0], True) for c in CONDITIONS], fontsize=6, rotation=90)
    ax[1].set_xlabel('D/J (ms)')
    ax[1].legend(frameon=False, fontsize=6, loc='upper left')
    w.figure(fig, 'fig_precision_bias', data, ['results/precision_residuals.csv'], ['C4', 'C9'])


def fig_replacement(w, rows, windows):
    """C5: measured replacement versus a constant-shift counterfactual, and per-window variance."""
    fig, ax = plt.subplots(2, 1, figsize=(COL1, 3.9))
    sel = [r for r in rows if r['condition_id'] == PRIMARY]
    clrt = {(a, op): np.sort([float(r['clrt_ms']) for r in sel if r['arm'] == a and r['operation'] == op])
            for a in ('off', 'combined') for op in OPS}
    pooled = np.median(np.concatenate([clrt['combined', op] for op in OPS]))
    offset = pooled - np.median(np.concatenate([clrt['off', op] for op in OPS]))
    data = []
    opstyle = {'READ': '-', 'SELECT': '--', 'OPERATE': ':'}
    for op in OPS:
        for v, lab, col in ((clrt['off', op] + offset, 'Constant shift', '.45'),
                            (clrt['combined', op], 'Timing+Size', COLOR['combined'])):
            ax[0].step(v, np.arange(1, len(v) + 1) / len(v), where='post', color=col, linestyle=opstyle[op],
                       label='%s, %s' % (lab, op))
            data.append(dict(panel='a', series=lab, operation=op, n=len(v), p01=float(np.quantile(v, .01)),
                             p50=float(np.median(v)), p99=float(np.quantile(v, .99)),
                             sample_sd_ms=float(np.std(v, ddof=1))))
    ax[0].set(xlim=(9.75, 10.25), xlabel='CLRT (ms), ' + cond_label(PRIMARY), ylabel='Cumulative fraction',
              title='(a) A shift keeps operations apart')
    ax[0].legend(frameon=False, loc='upper left', fontsize=5.5)
    test = [r for r in windows if r['split'] == 'testing' and r['k'] == '32']
    positions, groups = [], []
    for i, op in enumerate(OPS):
        for j, a in enumerate(ARMS):
            v = [max(float(r['variance_ms2']), 1e-7) for r in test if r['operation'] == op and r['arm'] == a]
            groups.append(v)
            positions.append(i * 5 + j)
            data.append(dict(panel='b', operation=op, arm=a, windows=len(v), median_variance_ms2=float(np.median(v)),
                             p90_variance_ms2=float(np.quantile(v, .9))))
    bp = ax[1].boxplot(groups, positions=positions, widths=.7, showfliers=False, patch_artist=True)
    for patch, pos in zip(bp['boxes'], positions):
        patch.set(facecolor=COLOR[ARMS[pos % 5]], alpha=.6, linewidth=.5)
    ax[1].set(yscale='log', xticks=[1.5, 6.5, 11.5], xticklabels=OPS, ylabel='Window CLRT variance (ms²)',
              title='(b) K = 32 held-out windows, all conditions')
    ax[1].legend(handles=[matplotlib.patches.Patch(color=COLOR[a], alpha=.6, label=LABEL[a]) for a in ARMS],
                 frameon=False, fontsize=6, ncol=4, loc='upper center', bbox_to_anchor=(.5, -.12))
    w.figure(fig, 'fig_replacement', data, ['release/rows.csv', 'results/oracle_windows.csv'], ['C5'])


def fig_operate(w, rows):
    """C6: the OPERATE hold J is applied on the outstation side and is invisible on the master side."""
    jconds = [c for c in CONDITIONS if c[1] == 10.]
    fig, ax = plt.subplots(2, 1, figsize=(COL1, 3.6), sharex=True)
    data = []
    for a in ARMS:
        hold, ack, rt = [], [], []
        for cid, _, j in jconds:
            s = [r for r in rows if r['condition_id'] == cid and r['arm'] == a and r['operation'] == 'OPERATE']
            hj = np.array([float(r['realized_j_ms']) for r in s])
            ak = np.array([float(r['ack_ms']) for r in s])
            rq = np.array([float(r['rt_ms']) for r in s])
            hold.append(np.median(hj)); ack.append(np.median(ak)); rt.append(np.median(rq))
            data.append(dict(arm=a, condition_id=cid, J_ms=j, n=len(s), realized_j_median_ms=float(np.median(hj)),
                             ack_median_ms=float(np.median(ak)), rt_median_ms=float(np.median(rq)),
                             ack_p99_ms=float(np.quantile(ak, .99)), rt_p99_ms=float(np.quantile(rq, .99))))
        js = np.array([c[2] for c in jconds]) + (ARMS.index(a) - 1.5) * .15
        ax[0].plot(js, hold, color=COLOR[a], linestyle=LINE[a], marker=MARK[a], markersize=3)
        ax[1].plot(js, rt, color=COLOR[a], linestyle=LINE[a], marker=MARK[a], markersize=3)
    ax[0].set(ylabel='Hold before delivery (ms)',
              title='(a) Outstation side: hold follows J')
    ax[1].set(xlabel='Configured J (ms), D = 10 ms', ylabel='Request→response (ms)',
              title='(b) Master side: independent of J', ylim=(0, 50))
    ax[1].legend(handles=legend_handles(ax[1]), frameon=False, fontsize=6, loc='center right')
    w.figure(fig, 'fig_operate_hold', data, ['release/rows.csv'], ['C6'])


def fig_attackers(w, attacks):
    """C8: fixed and adaptive Random Forest, four feature sets, every condition."""
    feats = (('clrt', 'CLRT'), ('ack_clrt', 'ACK + CLRT'), ('size', 'Response size'), ('joint', 'Joint'))
    fig, ax = plt.subplots(2, 4, figsize=(COL2, 3.3), sharey=True, sharex=True)
    data = []
    x = np.arange(len(CONDITIONS))
    for i, att in enumerate(('fixed', 'adaptive')):
        for j, (f, title) in enumerate(feats):
            for k, a in enumerate(ARMS):
                look = {r['condition_id']: float(r['balanced_accuracy']) for r in attacks
                        if r['attacker'] == att and r['feature'] == f and r['arm'] == a and num(r['balanced_accuracy']) is not None}
                y = [look.get(c[0], np.nan) for c in CONDITIONS]
                ax[i, j].plot(x + (k - 1.5) * .12, y, color=COLOR[a], linestyle='none', marker=MARK[a], markersize=2.6)
                data += [dict(attacker=att, feature=f, arm=a, condition_id=c[0], balanced_accuracy=v)
                         for c, v in zip(CONDITIONS, y)]
            ax[i, j].axhline(1 / 3, color='.4', linewidth=.6, linestyle='--')
            ax[i, j].set(ylim=(0, 1.02), title=('Fixed' if att == 'fixed' else 'Adaptive') + ': ' + title)
            ax[i, j].set_xticks(x, [cond_label(c[0], True) for c in CONDITIONS], fontsize=6, rotation=90)
        ax[i, 0].set_ylabel('Balanced accuracy')
    for j in range(4):
        ax[1, j].set_xlabel('D/J (ms)')
    fig.legend(handles=legend_handles(ax[0, 0]), loc='upper center', ncol=4, frameon=False, bbox_to_anchor=(.5, 1.04))
    w.figure(fig, 'fig_attackers', data, ['results/attack_summary.csv'], ['C8'])


def fig_confusion(w, attacks):
    """C8: confusion matrices of the joint attacker at the primary condition."""
    fig, ax = plt.subplots(1, 4, figsize=(COL2, 1.8))
    data = []
    panels = (('fixed', 'off'), ('fixed', 'combined'), ('adaptive', 'off'), ('adaptive', 'combined'))
    for axis, (att, a) in zip(ax, panels):
        r = next(r for r in attacks if r['attacker'] == att and r['feature'] == 'joint' and r['arm'] == a
                 and r['condition_id'] == PRIMARY)
        m = np.array(json.loads(r['confusion']), dtype=float)
        frac = m / m.sum(axis=1, keepdims=True)
        axis.imshow(frac, vmin=0, vmax=1, cmap='Greys')
        for (ii, jj), v in np.ndenumerate(frac):
            axis.text(jj, ii, '%.2f' % v, ha='center', va='center', fontsize=6, color='white' if v > .5 else 'black')
            data.append(dict(attacker=att, arm=a, truth=OPS_SORTED[ii], prediction=OPS_SORTED[jj], count=int(m[ii, jj]),
                             row_fraction=float(v)))
        axis.set_xticks(range(3), [SHORT[o] for o in OPS_SORTED], fontsize=6)
        axis.set_yticks(range(3), [SHORT[o] for o in OPS_SORTED], fontsize=6)
        axis.set_title('%s, %s\nBA = %.3f' % (att.capitalize(), LABEL[a], float(r['balanced_accuracy'])), fontsize=7)
        axis.set_xlabel('Predicted')
    ax[0].set_ylabel('True')
    w.figure(fig, 'fig_confusion', data, ['results/attack_summary.csv'], ['C8'])


# publication_analysis.confusion_scores orders rows (truth) and columns (prediction) by CLASSES
OPS_SORTED = OPS
SHORT = {'READ': 'READ', 'SELECT': 'SEL', 'OPERATE': 'OPR'}


def fig_residual(w, posthoc, attacks):
    """C9/C10: where the residual leakage sits (post hoc, adaptive, locked splits)."""
    fig, ax = plt.subplots(1, 2, figsize=(COL2, 2.7), sharey=True)
    x = np.arange(len(CONDITIONS))
    data = []
    groups = (('request', 'Request only (native)'), ('response', 'Defended response only'),
              ('master_link', 'Both, as on the master link'))
    gstyle = dict(zip([g for g, _ in groups], (('#555555', 'v'), (COLOR['combined'], 'D'), ('#000000', 'o'))))
    for g, lab in groups:
        y = []
        for c in CONDITIONS:
            r = next(r for r in posthoc if r['task'] == 'operation' and r['feature_group'] == g
                     and r['arm'] == 'combined' and r['condition_id'] == c[0])
            y.append(float(r['balanced_accuracy']))
            data.append(dict(panel='a', task='operation', feature_group=g, arm='combined', condition_id=c[0],
                             balanced_accuracy=y[-1], block_min=float(r['block_min']), block_max=float(r['block_max'])))
        ax[0].plot(x, y, color=gstyle[g][0], marker=gstyle[g][1], markersize=3, linewidth=.8, label=lab)
    pre = {r['condition_id']: float(r['balanced_accuracy']) for r in attacks if r['attacker'] == 'adaptive'
           and r['feature'] == 'metadata_diagnostic' and r['arm'] == 'combined'}
    ax[0].plot(x, [pre[c[0]] for c in CONDITIONS], color='.6', linestyle='--', linewidth=.8,
               label='Pre-registered metadata diagnostic')
    ax[0].axhline(1 / 3, color='.4', linewidth=.6, linestyle=':')
    ax[0].set(ylim=(0, 1.02), ylabel='Balanced accuracy', title='(a) Three operations, Timing+Size, by observed fields')
    ax[0].set_xticks(x, [cond_label(c[0], True) for c in CONDITIONS], fontsize=6, rotation=90)
    ax[0].legend(frameon=False, fontsize=5.5, loc='upper center', bbox_to_anchor=(.5, -.42), ncol=2)
    for k, a in enumerate(ARMS):
        for task, mk, fill in (('read_vs_select', MARK[a], COLOR[a]), ('read_preceding_gap', MARK[a], 'none')):
            y = [float(next(r for r in posthoc if r['task'] == task and r['arm'] == a and r['condition_id'] == c[0])['balanced_accuracy'])
                 for c in CONDITIONS]
            ax[1].plot(x + (k - 1.5) * .12, y, linestyle='none', marker=mk, markersize=3, markerfacecolor=fill,
                       markeredgecolor=COLOR[a], markeredgewidth=.6)
            data += [dict(panel='b', task=task, feature_group='joint', arm=a, condition_id=c[0], balanced_accuracy=v)
                     for c, v in zip(CONDITIONS, y)]
    ax[1].axhline(.5, color='.4', linewidth=.6, linestyle=':')
    ax[1].set(title='(b) Binary tasks: READ vs SELECT (filled), READ gap (open)')
    ax[1].set_xticks(x, [cond_label(c[0], True) for c in CONDITIONS], fontsize=6, rotation=90)
    ax[1].legend(handles=legend_handles(ax[1]), frameon=False, fontsize=5.5, loc='upper center', bbox_to_anchor=(.5, -.42), ncol=4)
    for axis in ax:
        axis.set_xlabel('D/J (ms)')
    w.figure(fig, 'fig_residual_sources', data, ['tables/posthoc_attacks.csv', 'results/attack_summary.csv'], ['C9', 'C10'])


def fig_dj(w, reductions, attacks):
    """C12: reduction of the fixed and adaptive joint attackers along D and along J."""
    fig, ax = plt.subplots(2, 1, figsize=(COL1, 3.6), sharey=True)
    data = []
    series = (('fixed', 'joint', 'Fixed, joint', '#000000', 'o'), ('adaptive', 'joint', 'Adaptive, joint', COLOR['combined'], 'D'),
              ('adaptive', 'metadata_diagnostic', 'Adaptive, metadata diagnostic', '.55', 's'))
    for i, (axis_cond, xlab) in enumerate(((lambda c: c[2] == 2.4, 'D (ms), J = 2.4 ms'), (lambda c: c[1] == 10., 'J (ms), D = 10 ms'))):
        cs = sorted([c for c in CONDITIONS if axis_cond(c)], key=lambda c: c[1 + i])
        for att, f, lab, col, mk in series:
            rows = [next(r for r in reductions if r['attacker'] == att and r['feature'] == f and r['arm'] == 'combined'
                         and r['metric'] == 'balanced_accuracy' and r['condition_id'] == c[0]) for c in cs]
            y = np.array([float(r['estimate']) for r in rows])
            lo = np.array([float(r['lower']) for r in rows]); hi = np.array([float(r['upper']) for r in rows])
            xs = [c[1 + i] for c in cs]
            ax[i].errorbar(xs, y, yerr=[y - lo, hi - y], color=col, marker=mk, markersize=3, capsize=2, linewidth=.8, label=lab)
            data += [dict(axis='D' if i == 0 else 'J', attacker=att, feature=f, condition_id=c[0], reduction=float(e),
                          lower=float(l), upper=float(h), primary=r['primary']) for c, e, l, h, r in zip(cs, y, lo, hi, rows)]
        ax[i].axhline(0, color='.4', linewidth=.6)
        ax[i].set(xlabel=xlab, ylim=(-.05, .75))
    for a_ in ax:
        a_.set_ylabel('Reduction in balanced\naccuracy')
    ax[1].legend(frameon=False, fontsize=6, loc='lower right')
    w.figure(fig, 'fig_dj_curves', data, ['results/paired_reductions.csv'], ['C12'])


def fig_windows(w, attacks, windows):
    """C11: windowed Naive Bayes (oracle-assisted), accuracy and support against K."""
    fig, ax = plt.subplots(1, 2, figsize=(COL2, 1.9))
    data = []
    ks = (8, 32, 64)
    for k_i, a in enumerate(ARMS):
        for att, fill in (('adaptive', COLOR[a]), ('fixed', 'none')):
            sel = [[r for r in attacks if r['feature'] == 'nb' and r['attacker'] == att and r['arm'] == a
                    and r['k'] == str(k) and num(r['balanced_accuracy']) is not None] for k in ks]
            vals = [[float(r['balanced_accuracy']) for r in rs] for rs in sel]
            for k, v, rs in zip(ks, vals, sel):
                xs = np.full(len(v), np.log2(k)) + (k_i - 1.5) * .1 + (.05 if att == 'fixed' else 0)
                ax[0].plot(xs, v, linestyle='none', marker=MARK[a], markersize=2.6, markerfacecolor=fill,
                           markeredgecolor=COLOR[a], markeredgewidth=.5)
                data += [dict(panel='a', attacker=att, arm=a, k=k, condition_id=r['condition_id'], balanced_accuracy=x)
                         for r, x in zip(rs, v)]
    ax[0].axhline(1 / 3, color='.4', linewidth=.6, linestyle='--')
    ax[0].set(xticks=np.log2(ks), xticklabels=[str(k) for k in ks], xlabel='Window size K (exchanges)',
              ylabel='Balanced accuracy', ylim=(0, 1.02), title='(a) Adaptive (filled), fixed (open)')
    ax[0].legend(handles=legend_handles(ax[0]), frameon=False, fontsize=5.5, ncol=2, loc='lower right')
    test = [r for r in windows if r['split'] == 'testing']
    for a in ARMS:
        n = [sum(1 for r in test if r['arm'] == a and r['k'] == str(k)) / len(CONDITIONS) for k in ks]
        dur = [np.median([float(r['elapsed_ms']) / 1000 for r in test if r['arm'] == a and r['k'] == str(k)]) for k in ks]
        ax[1].plot(dur, n, color=COLOR[a], linestyle=LINE[a], marker=MARK[a], markersize=3)
        data += [dict(panel='b', arm=a, k=k, windows_per_condition=x, median_window_duration_s=float(d)) for k, x, d in zip(ks, n, dur)]
    ax[1].set(xscale='log', xlabel='Median observation time per window (s)', yticks=[24, 48, 96, 192],
              ylabel='Windows per condition/arm', title='(b) Support shrinks as K grows')
    w.figure(fig, 'fig_windows', data, ['results/attack_summary.csv', 'results/oracle_windows.csv'], ['C11'])


def fig_envelope(w, rows, envelope):
    """C13: response availability at the outstation side against the frozen envelope."""
    eff = {k: v / 1e6 for k, v in envelope['effective_ns'].items()}
    L = envelope['response_availability_max_ns'] / 1e6
    fig, ax = plt.subplots(figsize=(COL1, 2.0))
    data = []
    for a, op, lab in (('off', 'READ', 'READ, No obfuscation'), ('off', 'SELECT', 'SELECT, No obfuscation'),
                       ('off', 'OPERATE', 'OPERATE, No obfuscation'), ('combined', 'OPERATE', 'OPERATE, Timing+Size (incl. J)')):
        v = np.sort([float(r['response_availability_ns']) / 1e6 for r in rows if r['arm'] == a and r['operation'] == op])
        ax.step(v, np.arange(1, len(v) + 1) / len(v), where='post', label=lab,
                color=COLOR[a] if op != 'SELECT' else '#56B4E9', linestyle={'READ': '-', 'SELECT': '--', 'OPERATE': ':'}[op])
        data.append(dict(arm=a, operation=op, n=len(v), max_ms=float(v[-1]), p99_ms=float(np.quantile(v, .99)),
                         above_da=int((v > eff['da']).sum())))
    for k, x in (('L (pilot)', L), ('da', eff['da']), ('pb', eff['pb']), ('readiness', eff['readiness']), ('cap', eff['cap'])):
        ax.axvline(x, color='.5', linewidth=.5, linestyle='--')
        ax.text(x, 1.04, k, rotation=90, fontsize=5.5, ha='center', va='bottom')
    ax.set(xlabel='Response availability after request (ms)', ylabel='Cumulative fraction', xlim=(0, 70), ylim=(0, 1.02))
    ax.legend(frameon=False, fontsize=5.5, loc='center right')
    for a in ARMS:
        for op in OPS:
            v = np.array([float(r['response_availability_ns']) / 1e6 for r in rows if r['arm'] == a and r['operation'] == op])
            data.append(dict(arm=a, operation=op, n=len(v), max_ms=float(v.max()), p99_ms=float(np.quantile(v, .99)),
                             above_da=int((v > eff['da']).sum()), series='all pairs'))
    data.append(dict(arm='envelope', operation='', n=0, max_ms=L, p99_ms=None, above_da=None))
    w.figure(fig, 'fig_envelope', data, ['release/rows.csv', 'release/audit/common_envelope.json'], ['C13'])


def fig_latency(w, rows, envelope):
    """C14: master-visible request-to-response time against the endpoint timers."""
    fig, ax = plt.subplots(figsize=(COL1, 2.0))
    x = np.arange(len(CONDITIONS))
    data = []
    for k, a in enumerate(ARMS):
        med, mx, p99 = [], [], []
        for c in CONDITIONS:
            v = np.array([float(r['rt_ms']) for r in rows if r['condition_id'] == c[0] and r['arm'] == a])
            med.append(np.median(v)); p99.append(np.quantile(v, .99)); mx.append(v.max())
            data.append(dict(arm=a, condition_id=c[0], n=len(v), median_ms=float(med[-1]), p99_ms=float(p99[-1]), max_ms=float(mx[-1])))
        xs = x + (k - 1.5) * .15
        ax.vlines(xs, med, mx, color=COLOR[a], linewidth=.6)
        ax.plot(xs, med, linestyle='none', marker=MARK[a], markersize=3, color=COLOR[a])
    for val, lab in ((envelope['min_observed_tcp_rto_ns'] / 1e6, 'min. observed TCP RTO'),
                     (envelope['endpoint_timeout_ns'] / 1e6, 'endpoint response timeout')):
        ax.axhline(val, color='.4', linewidth=.6, linestyle='--')
        ax.text(len(CONDITIONS) - .5, val * 1.08, '%s (%g ms)' % (lab, val), fontsize=5.5, ha='right')
    ax.set(yscale='log', ylim=(3, 900), ylabel='Request→response at master (ms)')
    ax.set_xticks(x, [cond_label(c[0], True) for c in CONDITIONS], fontsize=6, rotation=90)
    ax.legend(handles=legend_handles(ax), frameon=False, fontsize=5.5, ncol=4, loc='lower center', bbox_to_anchor=(.5, 1.0))
    ax.set_xlabel('D/J (ms)')
    w.figure(fig, 'fig_latency', data, ['release/rows.csv', 'release/audit/common_envelope.json'], ['C14'])


def fig_motivation(w, motivation):
    """C1: the same READ poll on two physical IEDs: separate ACK (SEL-751) versus delayed ACK (ION7550)."""
    rows = {}
    for dev in ('sel751', 'ion7550'):
        rows[dev] = []
        for r in (1, 2, 3, 4):
            rows[dev] += json.loads((motivation / ('%s_r%d.json' % (dev, r))).read_text().split(' ', 1)[1])['rows']
    fig, ax = plt.subplots(1, 2, figsize=(COL2, 1.9))
    data = []
    series = (('sel751', 'read_to_ack_ms', 'SEL-751: request→ACK', '#0072B2', '--'),
              ('sel751', 'read_to_resp_ms', 'SEL-751: request→response', '#0072B2', '-'),
              ('ion7550', 'read_to_resp_ms', 'ION7550: request→response (carries ACK)', '#D55E00', '-'))
    for dev, key, lab, col, ls in series:
        v = np.sort([r[key] for r in rows[dev] if r.get(key) is not None])
        ax[0].step(v, np.arange(1, len(v) + 1) / len(v), where='post', color=col, linestyle=ls, label=lab)
        data.append(dict(panel='a', device=dev, quantity=key, n=len(v), p50_ms=float(np.median(v)),
                         p05_ms=float(np.quantile(v, .05)), p95_ms=float(np.quantile(v, .95))))
    ax[0].set(xlim=(0, 10), xlabel='Time after READ request (ms)', ylabel='Cumulative fraction',
              title='(a) Where the acknowledgment travels')
    ax[0].legend(frameon=False, fontsize=5.5, loc='lower right')
    for i, dev in enumerate(('sel751', 'ion7550')):
        sep = sum(r['mode'] == 'SEPARATE' for r in rows[dev])
        ax[1].bar(i, 100 * sep / len(rows[dev]), color=('#0072B2', '#D55E00')[i], width=.5)
        ax[1].text(i, 100 * sep / len(rows[dev]) + 3, '%d/%d' % (sep, len(rows[dev])), ha='center', fontsize=7)
        clrt = [r['clrt_ms'] for r in rows[dev] if r.get('clrt_ms') is not None]
        data.append(dict(panel='b', device=dev, n=len(rows[dev]), separate_ack=sep,
                         clrt_p50_ms=float(np.median(clrt)) if clrt else None))
    ax[1].set(xticks=[0, 1], xticklabels=['SEL-751', 'ION7550'], ylim=(0, 115), ylabel='READs with a separate ACK (%)',
              title='(b) CLRT exists only with a separate ACK')
    w.figure(fig, 'fig_motivation', data, ['paper_inputs/motivation/SOURCES.txt'], ['C1'])


# ---------------------------------------------------------------- tables

def table_resources(w, compiler):
    rows = []
    table = [r for r in read(compiler / "compiler_table.csv")
             if r['build'] == 'm11_09' and r['sdk'] == 'compile_switch_9132']
    for r in table:
        rows.append(dict(program=r['role'], pipe=r['pipeline'], gress=r['direction'], stages=int(r['occupied_count']),
                         sram_blocks=int(r['sram']), tcam_blocks=int(r['tcam']), stateful_alus=int(r['stateful_alu']),
                         exact_xbar_bytes=int(r['crossbar_bytes'])))
    for pipe in ('p0', 'p1'):
        log = (compiler / (pipe + '_mau.resources.log')).read_text()
        head = next(l for l in log.splitlines() if l.startswith('| Stage Number |') and 'SRAM' in l)
        avg = next(l for l in log.splitlines() if l.startswith('|   Average'))
        cols = [c.strip() for c in head.strip('|').split('|')]
        vals = [c.strip() for c in avg.strip('|').split('|')]
        u = dict(zip(cols, vals))
        rows.append(dict(program='pipe %s, all programs: average per-stage utilization' % pipe, pipe=pipe, gress='all',
                         sram_utilization=u['SRAM'], tcam_utilization=u['TCAM'], meter_alu_utilization=u['Meter ALU'],
                         exact_xbar_utilization=u['Exact Match Input xbar']))
    w.table('table_resources', rows, ['compiler_table.csv', 'mau.resources.log'], ['C3'])


def table_sizes(w, rows):
    out = []
    for a in ARMS:
        for op in OPS:
            s = [r for r in rows if r['arm'] == a and r['operation'] == op]
            req = sorted({int(float(r['request_len'])) for r in s})
            resp = sorted({int(float(r['resp_len'])) for r in s})
            out.append(dict(arm=LABEL[a], operation=op, exchanges=len(s), request_payload_bytes='|'.join(map(str, req)),
                            response_payload_bytes='|'.join(map(str, resp))))
    w.table('table_sizes', out, ['release/rows.csv'], ['C7'])


def table_outcomes(w, utility, rows):
    keys = [k for k in utility[0] if k.startswith('outcome_OUT_') or k.startswith('outcome_RAW_') or k == 'outcome_STALE_BLOCKER']
    out = []
    for a in ARMS:
        u = [r for r in utility if r['arm'] == a]
        s = [r for r in rows if r['arm'] == a]
        rec = dict(arm=LABEL[a], trials=len(u), exchanges=len(s),
                   retransmitted=sum(r['retransmitted'] == 'True' for r in s),
                   multiple_attempts=sum(int(r['attempts']) > 1 for r in s),
                   master_timeouts=sum(r['master_timeout'] == 'True' for r in s),
                   incomplete=sum(r['complete'] != 'True' for r in s),
                   tcpdump_kernel_drops=sum(int(r['tcpdump_in_dropped_kernel']) + int(r['tcpdump_out_dropped_kernel']) for r in u))
        for k in keys:
            rec[k.replace('outcome_', '')] = int(sum(num(r[k]) or 0 for r in u))
        out.append(rec)
    w.table('table_outcomes', out, ['results/counter_utility.csv', 'release/rows.csv'], ['C13', 'C14'])


TIMELINE_CONDITION = 'D10_J10'


def table_timeline(w, rows, envelope):
    """Medians that place the instants of the release-timeline schematic (one condition)."""
    med = lambda a, op, k: float(np.median([float(r[k]) for r in rows if r['condition_id'] == TIMELINE_CONDITION
                                            and r['arm'] == a and r['operation'] == op]))
    out = []
    for op in ('READ', 'OPERATE'):
        hold = med('combined', op, 'realized_j_ms') if op == 'OPERATE' else 0.0
        native_ack, native_clrt = med('off', op, 'ack_ms'), med('off', op, 'clrt_ms')
        out += [dict(operation=op, quantity=q, value_ms=v, source=src) for q, v, src in (
            ('J_hold', hold, 'Timing+Size realized_j_ms'),
            ('native_ack_after_delivery', native_ack, 'No obfuscation ack_ms'),
            ('native_response_after_delivery', native_ack + native_clrt, 'No obfuscation ack_ms + clrt_ms'),
            ('released_ack', med('combined', op, 'ack_ms'), 'Timing+Size ack_ms'),
            ('released_response', med('combined', op, 'rt_ms'), 'Timing+Size rt_ms'))]
    for k in ('da', 'pb', 'readiness', 'cap'):
        out.append(dict(operation='envelope', quantity=k, value_ms=envelope['effective_ns'][k] / 1e6,
                        source='common_envelope.json'))
    out.append(dict(operation='envelope', quantity='D', value_ms=10.0, source='condition ' + TIMELINE_CONDITION))
    out.append(dict(operation='envelope', quantity='J', value_ms=10.0, source='condition ' + TIMELINE_CONDITION))
    w.table('table_timeline', out, ['release/rows.csv', 'release/audit/common_envelope.json'], ['C4', 'C6'])


def table_point_map(w, path):
    """C2: an SEL relay's DNP3 analog point map, as supplied (Background example of index mapping)."""
    rows = read(path)
    if [int(r['index']) for r in rows] != list(range(len(rows))):
        raise SystemExit('point map indices must run 0..n-1 without gaps')
    w.table('table_point_map', rows, ['paper_inputs/sel_point_map/sel_analog_point_map.csv'], ['C2'])


CRAWLER_SUPPORT = ('Encryption+Auth', 'Authentication', 'Opt-in (unconfirmed)', 'None')


def table_crawler(w, path):
    """C17: IED security support from the vendor-document crawler, by vendor and by generation."""
    with open(path, newline='') as f:
        devices = list(csv.DictReader(f, delimiter='\t'))
    if len(devices) != 55 or any(len(r) != 15 or None in r for r in devices):
        raise SystemExit('crawler rows malformed')
    out = []
    for key, values in (('vendor', ('SEL', 'GE', 'Siemens', 'Schneider', 'Rockwell')),
                        ('generation', ('current', 'mature', 'legacy'))):
        for v in values + ('Total',):
            sel = [r for r in devices if v == 'Total' or r[key] == v]
            rec = dict(grouping=key, group=v, devices=len(sel))
            rec.update({k: sum(r['security_support'] == k for r in sel) for k in CRAWLER_SUPPORT})
            rec['dnp3_native_security'] = sum(r['security_support'] != 'None' and 'via module' not in r['dnp3']
                                              and r['security_support'] != 'Opt-in (unconfirmed)' for r in sel)
            rec['not_dnp3_by_own_field'] = sum(r['dnp3'] in ('none/serial', 'serial') for r in sel)
            out.append(rec)
    w.table('table_crawler', out, ['paper_inputs/crawler/ied_security_devices.tsv'], ['C17'])


def table_conformance(w, trials):
    """C7: protocol conformance of every main trial, from the committed per-trial record."""
    out = []
    count = ('responses', 'verdicts_ok', 'transport_ok', 'app_seq_echoed', 'multi_segment', 'checker_failures',
             'wire_matched', 'unmatched', 'duplicates', 'reordered', 'dnp3_crc_bad', 'reads_completed',
             'outstation_select', 'outstation_operate')
    flags = ('checker_conformant', 'select_authorizes_operate', 'operate_success', 'standards_ok', 'reads_match_seed')
    for a in ARMS:
        t = [r for r in trials if r['arm'] == a]
        rec = dict(arm=LABEL[a], trials=len(t), wire_response_bytes='|'.join(sorted({r['wire_lengths'] for r in t})))
        rec.update({k: sum(int(r[k]) for r in t) for k in count})
        rec.update({k + '_trials': sum(r[k] == 'True' for r in t) for k in flags})
        out.append(rec)
    w.table('table_conformance', out, ['paper_inputs/conformance_trials.csv'], ['C7'])


def table_primary(w, reductions, attacks):
    p = next(r for r in reductions if r['primary'] == 'True')
    ba = {(r['attacker'], r['feature'], r['arm']): float(r['balanced_accuracy']) for r in attacks
          if r['condition_id'] == p['condition_id'] and num(r['balanced_accuracy']) is not None and r['k'] == ''}
    out = [dict(statistic='primary reduction: fixed joint attacker, No obfuscation minus Timing+Size', condition_id=p['condition_id'],
                estimate=float(p['estimate']), lower=float(p['lower']), upper=float(p['upper']), blocks=int(p['blocks']),
                resamples=int(p['resamples']), seed=int(p['seed']))]
    for att in ('fixed', 'adaptive'):
        for f in ('clrt', 'ack_clrt', 'size', 'joint', 'metadata_diagnostic'):
            for a in ARMS:
                if (att, f, a) in ba:
                    out.append(dict(statistic='balanced accuracy %s %s %s (pooled test rounds 9-16)' % (att, f, LABEL[a]),
                                    condition_id=p['condition_id'], estimate=ba[att, f, a], lower=None, upper=None,
                                    blocks=None, resamples=None, seed=None))
    w.table('table_primary', out, ['results/paired_reductions.csv', 'results/attack_summary.csv'], ['C8'])


# ---------------------------------------------------------------- driver

def build(campaign, out):
    campaign, out = Path(campaign).resolve(), Path(out)
    manifest = json.loads((campaign / 'release/release_manifest.json').read_text())
    rows_path = campaign / 'release/rows.csv'
    recorded = json.dumps(manifest)
    digest = sha256(rows_path)
    if digest not in recorded:
        raise SystemExit('release/rows.csv does not match the committed release manifest')
    inputs = {'release/rows.csv': digest}
    committed = json.loads((campaign / 'results/output_hashes.json').read_text())
    for name in ('attack_summary', 'paired_reductions', 'precision_residuals', 'oracle_windows', 'counter_utility'):
        inputs['results/%s.csv' % name] = sha256(campaign / 'results' / (name + '.csv'))
        if committed.get(name + '.csv') != inputs['results/%s.csv' % name]:
            raise SystemExit('results/%s.csv does not match results/output_hashes.json' % name)
    inputs['release/audit/common_envelope.json'] = sha256(campaign / 'release/audit/common_envelope.json')
    if inputs['release/audit/common_envelope.json'] not in recorded:
        raise SystemExit('common_envelope.json does not match the release manifest')
    paper_inputs = campaign.parent / (campaign.name + '_paper_inputs')
    trials_path = paper_inputs / 'conformance_trials.csv'
    inputs['paper_inputs/conformance_trials.csv'] = sha256(trials_path)
    motivation = paper_inputs / 'motivation'
    compiler = paper_inputs / 'compiler'
    for folder, listing in ((motivation, 'SOURCES.txt'), (compiler, 'SOURCES.sha256')):
        inputs['paper_inputs/%s/%s' % (folder.name, listing)] = sha256(folder / listing)
        for line in (folder / listing).read_text().splitlines():
            want, name = line.split()[:2]
            if sha256(folder / name) != want:
                raise SystemExit('paper input changed: %s/%s' % (folder.name, name))
    inputs['paper_inputs/motivation/CROSSCHECK.json'] = sha256(motivation / 'CROSSCHECK.json')
    point_map = paper_inputs / 'sel_point_map' / 'sel_analog_point_map.csv'
    crawler = paper_inputs / 'crawler' / 'ied_security_devices.tsv'
    inputs['paper_inputs/crawler/ied_security_devices.tsv'] = sha256(crawler)
    inputs['paper_inputs/sel_point_map/sel_analog_point_map.csv'] = sha256(point_map)
    build_manifest = (compiler / 'compile_switch_9132_manifest.json').read_text()
    for pipe in ('p0', 'p1'):
        if sha256(compiler / (pipe + '_mau.resources.log')) not in build_manifest:
            raise SystemExit(pipe + '_mau.resources.log does not match the compile manifest')
    inputs['compiler_table.csv'] = sha256(compiler / 'compiler_table.csv')
    inputs['mau.resources.log'] = '|'.join(sha256(compiler / (p + '_mau.resources.log')) for p in ('p0', 'p1'))
    style()
    w = Writer(out, inputs)
    rows = load_rows(rows_path)
    if len(rows) != 98816 or any(r['complete'] != 'True' for r in rows):
        raise SystemExit('unexpected main-campaign row set')
    attacks = read(campaign / 'results/attack_summary.csv')
    reductions = read(campaign / 'results/paired_reductions.csv')
    residuals = read(campaign / 'results/precision_residuals.csv')
    windows = read(campaign / 'results/oracle_windows.csv')
    utility = read(campaign / 'results/counter_utility.csv')
    envelope = json.loads((campaign / 'release/audit/common_envelope.json').read_text())
    posthoc = paper_attacks.run(campaign / 'release')
    paper_attacks.write(posthoc, out / 'tables' / 'posthoc_attacks.csv')
    w._sidecars('tables', 'posthoc_attacks', None, ['release/rows.csv'], ['C9', 'C10'])
    inputs['tables/posthoc_attacks.csv'] = sha256(out / 'tables' / 'posthoc_attacks.csv')
    posthoc = read(out / 'tables' / 'posthoc_attacks.csv')
    fig_motivation(w, motivation)
    fig_clrt(w, rows)
    fig_precision(w, residuals)
    fig_precision_bias(w, residuals)
    fig_replacement(w, rows, windows)
    fig_operate(w, rows)
    fig_attackers(w, attacks)
    fig_confusion(w, attacks)
    fig_residual(w, posthoc, attacks)
    fig_dj(w, reductions, attacks)
    fig_windows(w, attacks, windows)
    fig_envelope(w, rows, envelope)
    fig_latency(w, rows, envelope)
    table_resources(w, compiler)
    table_sizes(w, rows)
    table_outcomes(w, utility, rows)
    table_primary(w, reductions, attacks)
    table_conformance(w, read(trials_path))
    table_timeline(w, rows, envelope)
    table_point_map(w, point_map)
    table_crawler(w, crawler)
    (out / 'INPUTS.json').write_text(json.dumps(inputs, indent=2, sort_keys=True) + '\n')
    files = sorted(p for p in out.rglob('*') if p.is_file() and p.name != 'OUTPUTS.sha256')
    (out / 'OUTPUTS.sha256').write_text(''.join('%s  %s\n' % (sha256(p), p.relative_to(out)) for p in files))
    return out / 'OUTPUTS.sha256'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('campaign')
    ap.add_argument('out')
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()
    if not args.check:
        if Path(args.out).exists():
            raise SystemExit('output exists; remove it or use --check')
        print(build(args.campaign, args.out).read_text(), end='')
        return
    with tempfile.TemporaryDirectory() as tmp:
        fresh = build(args.campaign, Path(tmp) / 'out').read_text()
    committed = (Path(args.out) / 'OUTPUTS.sha256').read_text()
    if fresh != committed:
        import difflib
        sys.stdout.writelines(difflib.unified_diff(committed.splitlines(True), fresh.splitlines(True), 'committed', 'fresh'))
        raise SystemExit(1)
    print('check: %d outputs byte-identical' % len(committed.splitlines()))


if __name__ == '__main__':
    main()
