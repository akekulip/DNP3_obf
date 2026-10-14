#!/usr/bin/env python3
"""PLAN step 4 report for candidate61: timing and size evaluation across blocks.

  python3 step4_report.py --candidate RUN_DIR... --strict RUN_DIR... [--piggyback RUN_DIR] \
      [--rate RUN_DIR...] -o step4_summary.json

Builds on rearm_01/eval_summary.py (READ CLRT minus the configured gap, pooled per arm, bootstrap p99
interval) and adds what PLAN step 4 asks for and that summary does not carry:
  - p95 of the signed and absolute READ error, per block and pooled
  - every READ over the provisional 100 us bound, by run, label and application sequence
  - SELECT and OPERATE request-to-ACK, ACK-to-response and request-to-response, and full SBO completion
    (SELECT request to OPERATE response) per connection
  - internal loop packets and bytes, and external growth against 12 x READ + 24 x (SELECT + OPERATE) for
    newly delivered responses on padded arms (retransmitted exchanges reported separately)
SD is the population SD (statistics.pstdev), the convention eval_summary.py uses. Stdlib only.
"""
import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[5]
sys.path.insert(0, str(ARCH / 'integration/evidence/rearm_01'))
sys.path.insert(0, str(ARCH / 'protocol/hw_vepa'))
import eval_summary as es  # noqa: E402

GROWTH = {'READ': 12, 'SELECT': 24, 'OPERATE': 24}
PADDED_ARMS = ('size_only', 'combined')


def dist(values):
    if not values:
        return None
    return {'n': len(values), 'min': min(values), 'p50': es.pct(values, 0.5), 'p95': es.pct(values, 0.95),
            'p99': es.pct(values, 0.99), 'max': max(values), 'mean': round(statistics.mean(values), 2),
            'sd_population': round(statistics.pstdev(values), 2)}


def trial_dirs(root):
    rec = json.load(open(Path(root) / 'campaign_run.json'))
    for arm in rec['arms']:
        for tr in arm['trials']:
            yield rec, arm, tr, Path(root) / arm['fixture'] / arm['arm'] / tr['label']


def exchanges(d):
    t = json.load(open(d / 'timing.json'))
    return t['exchanges'], t.get('sd_convention')


def control_timing(ex):
    sel = [e for e in ex if e['kind'] == 'SELECT']
    op = [e for e in ex if e['kind'] == 'OPERATE']
    out = {}
    for kind, rows in (('SELECT', sel), ('OPERATE', op)):
        rows = [e for e in rows if e.get('complete')]
        out[kind] = {k: [e[k] for e in rows if isinstance(e.get(k), (int, float))]
                     for k in ('ack_lat_us', 'clrt_us', 'rt_us')}
    done = [(s, o) for s in sel for o in op if s.get('complete') and o.get('complete')
            and isinstance(o.get('rt_us'), (int, float))]
    out['sbo_completion_us'] = [o['t_req'] + o['rt_us'] - s['t_req'] for s, o in done]
    return out


def growth_check(arm, ex):
    """Expected growth from newly delivered, single-attempt responses; retransmitted ones are listed apart."""
    fresh = [e for e in ex if e.get('complete') and not e.get('retransmitted')]
    retx = [e for e in ex if e.get('retransmitted')]
    expected = sum(GROWTH[e['kind']] for e in fresh) if arm in PADDED_ARMS else 0
    return {'expected_fresh_bytes': expected, 'fresh': len(fresh), 'retransmitted_exchanges': len(retx)}


def tails(root, arm, label, ex, gap_us):
    out = []
    for e in ex:
        if e['kind'] != 'READ' or not e.get('complete') or e.get('retransmitted') or e.get('piggyback'):
            continue
        if not isinstance(e.get('clrt_us'), (int, float)):
            continue
        err = e['clrt_us'] - gap_us
        if abs(err) > es.BOUND_US:
            out.append({'run': Path(root).name, 'arm': arm, 'label': label, 'app_seq': e.get('app_seq'),
                        't_req': e.get('t_req'), 'clrt_us': e['clrt_us'], 'error_us': err})
    return out


def run_report(roots):
    base = es.summarize([str(r) for r in roots])
    pooled_ctl, per_trial, over = {}, [], []
    sd_conventions = set()
    for root in roots:
        for rec, arm, tr, d in trial_dirs(root):
            ex, sdc = exchanges(d)
            sd_conventions.add(sdc)
            timed = bool(arm.get('T'))
            gap_us = (rec['effective']['timing_params_ns']['gap'] / 1000.0) if timed else 0.0
            errs, _ = es.eligible_errors(root, arm['fixture'], arm['arm'], tr['label'], gap_us)
            ctl = control_timing(ex)
            agg = pooled_ctl.setdefault(arm['arm'], {'SELECT': {}, 'OPERATE': {}, 'sbo_completion_us': []})
            for kind in ('SELECT', 'OPERATE'):
                for k, v in ctl[kind].items():
                    agg[kind].setdefault(k, []).extend(v)
            agg['sbo_completion_us'].extend(ctl['sbo_completion_us'])
            row = next(r for b in base['blocks'] if b['run'] == str(root) for r in b['rows'] if r['label'] == tr['label'])
            per_trial.append({'run': Path(root).name, 'arm': arm['arm'], 'label': tr['label'], 'ok': tr.get('ok'),
                              'metric': row['metric'], 'signed': dist(errs),
                              'abs_p95_us': es.pct([abs(x) for x in errs], 0.95) if errs else None,
                              'excluded': row['excluded'], 'loop_pkts': row['loop_pkts'],
                              'loop_bytes': row['loop_bytes'], 'growth_bytes': row['growth_bytes'],
                              'growth_check': growth_check(arm['arm'], ex),
                              'resp_lens': sorted({(e['kind'], e['resp_len']) for e in ex if e.get('resp_len')}),
                              'sbo_completion_us': ctl['sbo_completion_us']})
            if timed:
                over.extend(tails(root, arm['arm'], tr['label'], ex, gap_us))
    arms = {}
    for a, s in base['arms'].items():
        pooled = s['pooled']
        arms[a] = dict(s, control={k: ({m: dist(v) for m, v in pooled_ctl[a][k].items()} if k != 'sbo_completion_us'
                                       else dist(pooled_ctl[a][k])) for k in ('SELECT', 'OPERATE', 'sbo_completion_us')})
    return {'runs': [Path(r).name for r in roots], 'bound_us_provisional': es.BOUND_US, 'arms': arms,
            'trials': per_trial, 'over_bound': over, 'timing_sd_conventions': sorted(map(str, sd_conventions))}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--candidate', nargs='+', required=True)
    ap.add_argument('--strict', nargs='*', default=[])
    ap.add_argument('--piggyback', nargs='*', default=[])
    ap.add_argument('--rate', nargs='*', default=[])
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args(argv)
    out = {'sd_convention': 'population SD (statistics.pstdev)',
           'candidate61': run_report([Path(r) for r in a.candidate])}
    for key, roots in (('strict_comparison', a.strict), ('piggyback', a.piggyback), ('rate', a.rate)):
        out[key] = {Path(r).name: run_report([Path(r)]) for r in roots} if key != 'strict_comparison' else (
            run_report([Path(r) for r in roots]) if roots else None)
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
