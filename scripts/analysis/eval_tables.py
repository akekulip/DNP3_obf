#!/usr/bin/env python3
"""Evaluation tables T1-T4, the pre-registered sufficiency gate and the size/timing verdicts (no plotting).

Split out of eval_figures.py; eval_figures.py imports these. Every value is computed from rows.csv and
formby_results.json; piggybacked exchanges are counted in T3 only.
"""
import csv
from pathlib import Path
import sys

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import eval_watchdog  # noqa: E402
import formby_eval  # noqa: E402

ROOT = HERE.parents[1]
DS = (5, 10, 15, 20)
ARMS, CLASSES = formby_eval.ARMS, formby_eval.CLASSES
SEED = formby_eval.SEED


def pick(rows, **filters):
    return [r for r in rows if all(r[k] == v for k, v in filters.items())]


def blocks_of(rows):
    return sorted({r['block_id'] for r in rows})


def ci(values):
    """Mean and 95% block-bootstrap interval of per-block values."""
    if not values:
        return np.nan, np.nan, np.nan
    b = formby_eval.block_bootstrap(dict(enumerate(values)), seed=SEED, resamples=2000)
    return b['estimate'], b['lower'], b['upper']


def paired_block_delta(rows, d, arm, field, stat):
    """Per-block stat(field) of arm minus the same block's off arm."""
    values = []
    for b in blocks_of(pick(rows, d_ms=d, arm=arm)):
        a = [r[field] for r in rows if r['block_id'] == b and r['arm'] == arm]
        o = [r[field] for r in rows if r['block_id'] == b and r['arm'] == 'off']
        if a and o:
            values.append(stat(a) - stat(o))
    return values


def connection_rates(rows, d, arm):
    rates = []
    for b in blocks_of(pick(rows, d_ms=d, arm=arm)):
        cell = [r for r in rows if r['block_id'] == b and r['arm'] == arm]
        start = min(r['observed_at_ns'] for r in cell)
        end = max(r['observed_at_ns'] + r['rt_ms'] * 1e6 for r in cell)
        rates.append(len(cell) / ((end - start) / 1e9))
    return rates


def stats(values):
    v = np.asarray(values, dtype=float)
    q = np.percentile(v, [5, 25, 50, 75, 95])
    return dict(n=len(v), mean=v.mean(), std=v.std(ddof=1) if len(v) > 1 else 0.0, median=q[2], q1=q[1], q3=q[3],
                p5=q[0], p95=q[4], min=v.min(), max=v.max())


def write_table(out, name, records):
    if not records:
        return
    fields = list(records[0])
    with (out / (name + '.csv')).open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    fmt = lambda v: ('%.3f' % v) if isinstance(v, float) else str(v)
    lines = ['| ' + ' | '.join(fields) + ' |', '|' + '---|' * len(fields)]
    lines += ['| ' + ' | '.join(fmt(r[f]) for f in fields) + ' |' for r in records]
    (out / (name + '.md')).write_text('\n'.join(lines) + '\n')


def tables(rows, results, out):
    clean = [r for r in rows if not r['piggyback']]   # piggybacked exchanges are counted in T3 only
    t1 = []
    for d in DS:
        for arm in ARMS:
            for c in CLASSES:
                cell = pick(clean, d_ms=d, arm=arm, operation=c)
                for field in ('clrt_ms', 'resp_len', 'rt_ms', 'ack_ms'):
                    if cell:
                        t1.append(dict(d_ms=d, arm=arm, operation=c, field=field, blocks=len(blocks_of(cell)),
                                       **stats([r[field] for r in cell])))
    write_table(out, 'T1_distribution_stats', t1)
    t2 = []
    for r in results:
        for model in ('nb', 'ff_ann', 'gmm'):
            base = dict(d_ms=r['d_ms'], arm=r['arm'], feature=r['feature'], k=r['k'], attacker=r['attacker'],
                        classifier=model)
            m = r.get(model)
            if not m or 'balanced_accuracy' not in m:
                reason = (r.get('unavailable') or r.get('%s_unavailable' % model) or (m or {}).get('unavailable')
                          or 'not computed')
                t2.append(dict(base, test_windows='', ba_pooled='', ba_block_mean='', ci_lower='', ci_upper='',
                               mean_accuracy='', min_accuracy='', mean_precision='', min_precision='',
                               mean_recall='', min_recall='', note=reason))
                continue
            interval = m.get('ci') or {}
            t2.append(dict(base, test_windows=m['n'], ba_pooled=m['balanced_accuracy'],
                           ba_block_mean=interval.get('estimate', ''), ci_lower=interval.get('lower', ''),
                           ci_upper=interval.get('upper', ''),
                           mean_accuracy=m['mean_accuracy'], min_accuracy=m['min_accuracy'],
                           mean_precision=m['mean_precision'], min_precision=m['min_precision'],
                           mean_recall=m['mean_recall'], min_recall=m['min_recall'],
                           note=m.get('ci_unavailable') or (m.get('split') or '')))
    write_table(out, 'T2_classifier_metrics', t2)
    t3, t4 = [], []
    for d in DS:
        for arm in ARMS:
            cell = pick(rows, d_ms=d, arm=arm)
            if not cell:
                continue
            trials = {(r['block_id'], r['trial']): r for r in cell}
            sbo = [r for r in cell if r['operation'] != 'READ']
            t3.append(dict(d_ms=d, arm=arm, blocks=len(blocks_of(cell)), exchanges=len(cell),
                           outcome_ok=sum(r['outcome'] == 'OK' for r in cell),
                           application_ok=sum(r['app_ok'] for r in cell),
                           crob_success=sum(r['crob'] == '1:SUCCESS;3:SUCCESS' for r in sbo), sbo=len(sbo),
                           retransmitted_segments=sum(t['retx_out'] + t['retx_in'] for t in trials.values()),
                           kernel_drops=sum(t['kernel_drops'] for t in trials.values()),
                           piggyback=sum(r['piggyback'] for r in cell)))
            off = pick(rows, d_ms=d, arm='off')
            record = dict(d_ms=d, arm=arm)
            for c in CLASSES:
                record['pad_%s_B' % c] = (np.mean([r['resp_len'] for r in pick(cell, operation=c)]) -
                                          np.mean([r['resp_len'] for r in pick(off, operation=c)])) if off else ''
            record['bytes_per_txn_pct'] = (100 * (sum(r['req_len'] + r['resp_len'] for r in cell) /
                                                  sum(r['req_len'] + r['resp_len'] for r in off) - 1)) if off else ''
            for name, stat in (('p50', np.median), ('p95', lambda v: np.percentile(v, 95))):
                est = ci(paired_block_delta(rows, d, arm, 'rt_ms', stat))
                record['added_%s_ms' % name], record['added_%s_ci' % name] = est[0], '[%.3f, %.3f]' % est[1:]
            record['txn_per_s'] = ci(connection_rates(rows, d, arm))[0]
            t4.append(record)
    write_table(out, 'T3_delivery', t3)
    write_table(out, 'T4_overhead', t4)
    resources = ROOT / 'results/analysis/stage_cut/final_resources.json'
    if resources.is_file():
        (out / 'T4b_switch_resources.json').write_text(resources.read_text())


def sufficiency(rows):
    report = {}
    for d in DS:
        for arm in ARMS:
            cell = pick(rows, d_ms=d, arm=arm)
            for c in CLASSES:
                test = pick(cell, operation=c, split='test')
                report['D%d/%s/%s' % (d, arm, c)] = dict(
                    train_blocks=len(blocks_of(pick(cell, operation=c, split='train'))),
                    test_blocks=len(blocks_of(test)),
                    test_windows_K8=len([w for w in formby_eval.make_windows(test, 'clrt', 8)]),
                    test_windows_K64=len([w for w in formby_eval.make_windows(test, 'clrt', 64)]))
    capture_clean = all(r['kernel_drops'] == 0 for r in rows)
    gate = capture_clean and all(v['train_blocks'] >= 8 and v['test_blocks'] >= 8 and v['test_windows_K64'] >= 8
                                 and v['test_windows_K8'] >= 64 for v in report.values())
    return dict(gate_passed=gate, capture_clean=capture_clean, cells=report,
                rule='per D/arm/class: >=8 train and >=8 test blocks, >=8 test windows at K=64 and >=64 at K=8; '
                     'every trial with zero kernel/interface capture drops')


def size_verdict(rows):
    """DESIGN size falsifier: any padded-arm response that is not its class image (incl. a native size)."""
    per_arm = {}
    for arm in sorted(eval_watchdog.PADDED_ARMS):
        cell = pick(rows, arm=arm)
        bad = [r for r in cell if eval_watchdog.PADDED.get((r['operation'], r['read_class'])) != r['resp_len']]
        per_arm[arm] = dict(responses=len(cell), violations=len(bad),
                            examples=sorted({(r['operation'], r['read_class'], r['resp_len']) for r in bad})[:5])
    violations = sum(v['violations'] for v in per_arm.values())
    return dict(falsified=violations > 0, violations=violations, arms=per_arm,
                rule='padded arms: READ mixed 141, READ integrity 158, SELECT/OPERATE 60 octets')


def timing_verdict(rows, comparisons):
    """DESIGN timing falsifier per D and timed arm: (1) the spread of per-class CLRT medians exceeds the off arm's
    spread of per-class medians at the same D; (2) the retrained NB on CLRT is not below off (paired block-bootstrap
    95% interval of off - arm BA not entirely above 0), per window size K."""
    clean = [r for r in rows if not r['piggyback']]
    def spread(cell):
        medians = [np.median([r['clrt_ms'] for r in cell if r['operation'] == c]) for c in CLASSES
                   if any(r['operation'] == c for r in cell)]
        return float(max(medians) - min(medians)) if len(medians) == 3 else None
    by = {(c['d_ms'], c['arm'], c['k']): c for c in comparisons
          if c.get('model') == 'nb' and c['feature'] == 'clrt' and c['attacker'] == 'retrained'}
    cells = {}
    for d in DS:
        off_spread = spread(pick(clean, d_ms=d, arm='off'))
        for arm in sorted(eval_watchdog.TIMED_ARMS):
            arm_spread = spread(pick(clean, d_ms=d, arm=arm))
            if arm_spread is None or off_spread is None:
                continue
            classifier = {}
            for k in formby_eval.WINDOWS_K:
                c = by.get((d, arm, k))
                if not c or 'off_minus_arm' not in c:
                    classifier[k] = dict(unavailable=(c or {}).get('unavailable', 'no comparison'))
                    continue
                interval = c['off_minus_arm']
                classifier[k] = dict(off_minus_arm=interval['estimate'], lower=interval['lower'],
                                     upper=interval['upper'], falsified=not interval['lower'] > 0)
            cells['D%d/%s' % (d, arm)] = dict(median_spread_ms=arm_spread, off_median_spread_ms=off_spread,
                                              spread_falsified=arm_spread > off_spread, classifier_by_k=classifier)
    return dict(cells=cells, rule=timing_verdict.__doc__.split('DESIGN timing falsifier per D and timed arm: ')[1])
