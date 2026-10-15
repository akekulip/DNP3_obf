#!/usr/bin/env python3
"""Asymmetric-shaping pilot: matched baseline/pilot blocks on the combined arm, unchanged binary (M5).

  python3 shaping_pilot.py --pair BASE_RUN PILOT_RUN [--pair ...] -o pilot.json

Per block (combined arm, separate-ACK fixture): achieved shaping read back from the switch, internal loop RX frames
and octets per exchange (cost_report.trial_cost: RX counted once across loop roles; pktgen seeds reported apart),
internal PPS and bit rate over the traffic interval, READ/SELECT/OPERATE CLRT precision (checks.kind_precision,
nearest-rank), the OPERATE hold (hold_check), request->ACK and request->response medians, and the trial verdict.
Per pair: changes in frames and octets per exchange, and the screening decision against the budget declared
before running (PLAN.md, requirement 7):
  stop       a correctness failure in the pilot that the matched baseline does not show (trial, CLRT, hold), or
             request->ACK median up by more than 1 ms for any kind
  promising  frames AND octets per exchange both lower by more than NOISE (5 %), budget met
  inconclusive  otherwise (a small or noisy difference neither wins nor loses)
"""
import argparse
import json
import math
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[5] / 'protocol/hw_vepa'))
import cost_report  # noqa: E402
import checks  # noqa: E402
import hold_check  # noqa: E402

ACK_BUDGET_US = 1000.0
NOISE = 0.05


def nearest_rank(values, q):
    v = sorted(values)
    return v[math.ceil(q * len(v)) - 1] if v else None


def host_tail(timing, gap_us):
    """Exchanges matching the documented host-path ACK delay (QUALIFICATION_9c4a2cfdc.md): request index 110-130,
    CLRT compressed by more than 800 us (the ACK arrived late), and the response NOT early (request->response no
    more than 200 us below its kind's median). An early switch release would make the response early; a delay
    after release can only make packets later, so this cannot excuse an early release."""
    rows = timing['exchanges']
    med = {k: statistics.median([r['rt_us'] for r in rows if r['kind'] == k and r.get('rt_us') is not None
                                 and not r.get('piggyback')] or [0]) for k in ('READ', 'SELECT', 'OPERATE')}
    return [i for i, r in enumerate(rows) if 110 <= i <= 130 and isinstance(r.get('clrt_us'), (int, float))
            and r['clrt_us'] < gap_us - 800 and r.get('rt_us') is not None and r['rt_us'] >= med[r['kind']] - 200]


def block(root):
    root = Path(root)
    rec = json.loads((root / 'campaign_run.json').read_text())
    cfg = rec.get('effective', {})
    arm = next(a for a in rec['arms'] if a['arm'] == 'combined')
    tr = arm['trials'][0]
    d = root / arm['fixture'] / arm['arm'] / tr['label']
    cost = cost_report.trial_cost(d, tr['label'])
    timing = json.loads((d / 'timing.json').read_text())
    rows = [r for r in timing['exchanges'] if r.get('complete') is True]
    t0 = min(r['t_req'] for r in rows)                        # clrt_check t_req: microseconds
    t1 = max(r['t_req'] + (r.get('rt_us') or 0) for r in rows)
    duration = (t1 - t0) / 1e6
    after = json.loads((d / 'snapshots' / ('%s_after.json' % tr['label'])).read_text())
    gap = cfg.get('timing_params_ns', {}).get('gap', 950000)
    lat = {}
    tail = host_tail(timing, gap / 1000.0)
    for kind in ('READ', 'SELECT', 'OPERATE'):
        ok = [r for r in rows if r['kind'] == kind and not r.get('piggyback') and r.get('attempts') == 1]
        ack = [r['ack_lat_us'] for r in ok if r.get('ack_lat_us') is not None]
        rt = [r['rt_us'] for r in ok if r.get('rt_us') is not None]
        p = checks.kind_precision(timing, gap, kind)
        # the documented host-path ACK delay (host_tail); reported beside, never instead of, the full p99
        errx = [abs(r['clrt_us'] - gap / 1000.0) for i, r in enumerate(timing['exchanges'])
                if r['kind'] == kind and i not in tail and r.get('complete') is True and not r.get('piggyback')
                and r.get('attempts') == 1 and isinstance(r.get('clrt_us'), (int, float))]
        px = nearest_rank(errx, 0.99)
        lat[kind] = {'clrt_p99_abs_error_us_excluding_host_tail': px,
                     'clrt_pass_excluding_host_tail': len(errx) >= 20 and px is not None and px <= 100,
                     'n': len(ok), 'ack_median_us': statistics.median(ack) if ack else None,
                     'ack_p99_us': nearest_rank(ack, 0.99), 'rt_median_us': statistics.median(rt) if rt else None,
                     'clrt_p99_abs_error_us': p.get('p99'), 'clrt_max_abs_error_us': p.get('max_absolute_error_us'),
                     'clrt_pass': p['pass']}
    hold = hold_check.analyze(d / 'out.pcap', d / 'in.pcap', tr['master_port'])
    op_j = cfg.get('timing_params_ns', {}).get('op_j')
    sbo = cfg.get('traffic', {}).get('sbo_cycles', 1)
    verdict = hold_check.operate_hold(hold, op_j, (timing['summary'].get('OPERATE') or {}).get('complete'), sbo) \
        if op_j else None
    trial = json.loads((d / 'trial.json').read_text())
    return {'run': root.name, 'trial_ok': trial.get('ok'), 'trial_failures': trial.get('failures'),
            'achieved_shaping': after.get('shaping'), 'requested_shaping': cfg.get('shaping_requested'),
            'cost': cost, 'duration_s': round(duration, 3),
            'internal_pps': round(cost['internal_rx_frames'] / duration, 1) if duration > 0 else None,
            'internal_mbps': round(cost['internal_rx_octets'] * 8 / duration / 1e6, 3) if duration > 0 else None,
            'latency': lat, 'operate_hold': verdict, 'host_tail_exchanges': tail}


def compare(base, pilot):
    bf, pf = base['cost']['per_exchange']['rx_frames'], pilot['cost']['per_exchange']['rx_frames']
    bo, po = base['cost']['per_exchange']['rx_octets'], pilot['cost']['per_exchange']['rx_octets']
    frames, octets = (pf - bf) / bf, (po - bo) / bo
    ack_up = {k: (pilot['latency'][k]['ack_median_us'] or 0) - (base['latency'][k]['ack_median_us'] or 0)
              for k in pilot['latency']}
    # correctness: CLRT judged without the documented host-path exchanges (listed per block), the hold, and every
    # non-precision trial failure; a failure the pilot shows and its matched baseline does not stops the pilot
    def failure_kinds(block):
        kinds = {k for k, v in block['latency'].items() if not v['clrt_pass_excluding_host_tail']}
        if not (block['operate_hold'] or {}).get('pass', True):
            kinds.add('operate_hold')
        kinds |= {f.split(':')[0] for f in (block['trial_failures'] or []) if 'precision' not in f}
        return kinds
    new_failures = sorted(failure_kinds(pilot) - failure_kinds(base))
    correct = not new_failures
    budget = all(v <= ACK_BUDGET_US for v in ack_up.values())
    if not correct or not budget:
        decision = 'stop'
    elif frames < -NOISE and octets < -NOISE:
        decision = 'promising'
    else:
        decision = 'inconclusive'
    return {'base': base['run'], 'pilot': pilot['run'], 'frames_change': round(frames, 4),
            'octets_change': round(octets, 4), 'ack_median_change_us': ack_up, 'pilot_correct': correct,
            'pilot_new_failures': new_failures,
            'within_ack_budget': budget, 'decision': decision}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--pair', nargs=2, action='append', required=True, metavar=('BASE', 'PILOT'))
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args(argv)
    out = {'budget': {'ack_median_increase_us_max': ACK_BUDGET_US, 'noise': NOISE}, 'pairs': []}
    for b, p in a.pair:
        base, pilot = block(b), block(p)
        out['pairs'].append({'base': base, 'pilot': pilot, 'comparison': compare(base, pilot)})
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    for pair in out['pairs']:
        print(json.dumps(pair['comparison']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
