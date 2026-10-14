#!/usr/bin/env python3
"""Cross-block summary of a repeated four-arm evaluation (directive f813bc089 §6).

  python3 eval_summary.py RUN_DIR [RUN_DIR ...] [-o summary.json]

Per block and arm it reports protocol/hw_vepa/report.py's per-trial metrics (loop packets and bytes, master-visible
growth, READ precision against the configured gap). Per arm it then pools the blocks:
  eligible READs   complete, one attempt, not piggybacked, with a CLRT; every exclusion is counted by reason
  signed error     CLRT minus the configured gap, microseconds: n, min, median, p90, p99, max, mean, SD
  |error| p99      with a seeded percentile-bootstrap 95% interval (2000 resamples) as the tail uncertainty
Conventions: percentiles are nearest-rank (the ceil(q*n)-th smallest value; at q=0.99 this is the same order
statistic as the live gate's clrt_check.stats for every n used here); the median is statistics.median; SD is
the sample SD (n-1). Linear interpolation and the population SD are kept as separately named comparisons
(p99_interp, sd_population). The bootstrap resamples pooled packets; it is not a block-aware comparison.
The 100 us p99 bound is provisional (not an IEEE or advisor requirement). Host capture error is not ASIC
early-release correctness; that is gated separately by the switch counters in each trial. Stdlib only.
"""
import argparse
import json
import math
import random
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / 'protocol/hw_vepa'))
import report  # noqa: E402

BOUND_US = 100
SEED = 1815


def pct(values, q):
    """Nearest-rank percentile: the ceil(q*n)-th smallest value."""
    v = sorted(values)
    if not v:
        return None
    return v[max(0, math.ceil(q * len(v)) - 1)]


def pct_interp(values, q):
    """Linear interpolation between order statistics (comparison only; the pre-2026-10-14 convention)."""
    v = sorted(values)
    if not v:
        return None
    k = (len(v) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def sd_sample(values):
    return round(statistics.stdev(values), 2) if len(values) > 1 else None


def eligible_errors(root, fixture, arm, label, gap_us):
    t = report._json(str(Path(root) / fixture / arm / label / 'timing.json')) or {}
    errs, excluded = [], {'incomplete': 0, 'retransmitted': 0, 'piggyback': 0, 'missing_clrt': 0}
    for e in t.get('exchanges', []):
        if e.get('kind') != 'READ':
            continue
        if not e.get('complete'):
            excluded['incomplete'] += 1
        elif e.get('attempts', 1) != 1 or e.get('retransmitted'):
            excluded['retransmitted'] += 1
        elif e.get('piggyback'):
            excluded['piggyback'] += 1
        elif e.get('clrt_us') is None:
            excluded['missing_clrt'] += 1
        else:
            errs.append(e['clrt_us'] - gap_us)
    return errs, excluded


def describe(errs):
    if not errs:
        return None
    a = [abs(x) for x in errs]
    rng = random.Random(SEED)
    boots = sorted(pct([rng.choice(a) for _ in a], 0.99) for _ in range(2000))
    return {'n': len(errs), 'signed_us': {'min': min(errs), 'median': statistics.median(errs), 'p90': pct(errs, 0.9),
                                          'p99': pct(errs, 0.99), 'max': max(errs), 'mean': round(statistics.mean(errs), 2),
                                          'sd': sd_sample(errs), 'sd_population': round(statistics.pstdev(errs), 2),
                                          'p99_interp': pct_interp(errs, 0.99)},
            'abs_p99_us': pct(a, 0.99), 'abs_p99_interp_us': pct_interp(a, 0.99),
            'abs_p99_ci95_us': [pct(boots, 0.025), pct(boots, 0.975)],
            'abs_max_us': max(a), 'over_bound': sum(1 for x in a if x > BOUND_US)}


def summarize(run_dirs):
    blocks, pooled = [], {}
    for root in run_dirs:
        rec = json.load(open(Path(root) / 'campaign_run.json'))
        gap_ns = (rec.get('effective') or {}).get('timing_params_ns', {}).get('gap')
        gap_us = gap_ns / 1000.0
        rows = []
        for arm in rec['arms']:
            for tr in arm['trials']:
                m = report.trial_metrics(str(root), arm['fixture'], arm['arm'], tr, gap_ns)
                timed = bool(arm.get('T'))
                # T off: no configured release gap applies; report the raw CLRT (offset 0) instead of an error.
                errs, excluded = eligible_errors(root, arm['fixture'], arm['arm'], tr['label'], gap_us if timed else 0.0)
                d = describe(errs)
                rows.append({'arm': arm['arm'], 'label': tr['label'], 'ok': tr.get('ok'), 'gap_us': gap_us,
                             'metric': 'clrt_minus_gap_us' if timed else 'raw_clrt_us',
                             'reads_logical': m.get('logical'), 'complete': m.get('complete'),
                             'excluded': excluded, 'precision': d, 'loop_pkts': m.get('loop_pkts'),
                             'loop_bytes': m.get('loop_bytes'), 'growth_bytes': m.get('growth_bytes'),
                             'padding_coverage': m.get('padding_coverage'), 'stale': m.get('stale'),
                             'continuation': tr.get('continuation'), 'qualification': tr.get('qualification')})
                p = pooled.setdefault(arm['arm'], {'errs': [], 'excluded': {}, 'blocks': 0,
                                                   'metric': 'clrt_minus_gap_us' if timed else 'raw_clrt_us'})
                p['errs'] += errs
                p['blocks'] += 1
                for k, v in excluded.items():
                    p['excluded'][k] = p['excluded'].get(k, 0) + v
        blocks.append({'run': str(root), 'ok': rec.get('ok'), 'rows': rows})
    arms = {a: {'blocks': p['blocks'], 'metric': p['metric'], 'excluded': p['excluded'], 'pooled': describe(p['errs'])}
            for a, p in pooled.items()}
    return {'bound_us_provisional': BOUND_US, 'blocks': blocks, 'arms': arms}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('runs', nargs='+')
    ap.add_argument('-o', '--output')
    a = ap.parse_args(argv)
    res = summarize(a.runs)
    if a.output:
        Path(a.output).write_text(json.dumps(res, indent=1) + '\n')
    print('%-12s %-18s %6s %8s %8s %8s %8s %8s %16s %6s' % ('arm', 'metric (us)', 'n', 'min', 'med', 'p99', 'max',
                                                         '|p99|', '|p99| 95% CI', '>100'))
    for arm, v in res['arms'].items():
        d = v['pooled']
        if d:
            timed = v['metric'] == 'clrt_minus_gap_us'
            print('%-12s %-18s %6d %8.1f %8.1f %8.1f %8.1f %8s %16s %6s' % (
                arm, v['metric'], d['n'], d['signed_us']['min'], d['signed_us']['median'], d['signed_us']['p99'],
                d['signed_us']['max'], '%.1f' % d['abs_p99_us'] if timed else '-',
                '%.1f..%.1f' % tuple(d['abs_p99_ci95_us']) if timed else '-', d['over_bound'] if timed else '-'))
    print('\nper block: arm, n, |p99|, loop pkts, loop bytes, growth, ok')
    for b in res['blocks']:
        for r in b['rows']:
            d = r['precision'] or {}
            print('  %-40s %-12s %5s %7s %9s %11s %6s %s' % (Path(b['run']).name, r['arm'], d.get('n'), d.get('abs_p99_us'),
                                                           r['loop_pkts'], r['loop_bytes'], r['growth_bytes'], r['ok']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
