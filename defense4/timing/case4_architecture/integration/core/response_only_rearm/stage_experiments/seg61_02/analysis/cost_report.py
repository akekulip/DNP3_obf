#!/usr/bin/env python3
"""Internal work per exchange from retained switch snapshots (Gate 5, cost accounting).

  python3 cost_report.py RUN_DIR [RUN_DIR ...] -o cost_summary.json

Per trial (after minus before snapshot):
  internal RX     frames and octets RECEIVED on the four loop roles (n_ack_return, t_in, hb_return,
                  held_return), each role counted once; a loop port's transmit and receive are the same packets,
                  so nothing is counted twice
  re-waits        OUT_HELD_REWAIT: laps of held originals (ACKs and responses waiting for their deadline)
  pktgen seeds    pktgen_seed_packets: packets the packet generator emitted (READ and OPERATE apps,
                  pkt_counter). They are generated seed packets, not blocker recirculation; the total loop-port
                  RX frames and octets above remain the authoritative internal-work figures
  exchanges       complete READ + SELECT + OPERATE exchanges from timing.json (external transactions)
External growth (master-visible bytes) is reported by step4_report/repeat_sbo_report, not here. Peak queue
watermarks are not used as occupancy. Retained snapshots are read only.
"""
import argparse
import json
import statistics
from pathlib import Path

ROLES = ('n_ack_return', 't_in', 'hb_return', 'held_return')


def delta(after, before, path):
    a, b = after, before
    for key in path:
        a, b = a[key], b[key]
    return a - b


def trial_cost(d, label):
    snap = d / 'snapshots'
    before = json.load(open(snap / ('%s_before.json' % label)))
    after = json.load(open(snap / ('%s_after.json' % label)))
    rx_frames = sum(delta(after, before, ('loop_ports', r, '$FramesReceivedAll')) for r in ROLES)
    rx_octets = sum(delta(after, before, ('loop_ports', r, '$OctetsReceived')) for r in ROLES)
    per_role = {r: delta(after, before, ('loop_ports', r, '$FramesReceivedAll')) for r in ROLES}
    rewait = delta(after, before, ('outcomes', 'OUT_HELD_REWAIT'))
    seeds = sum(delta(after, before, ('pktgen', app, 'pkt_counter')) for app in ('READ', 'OPERATE'))
    summary = json.load(open(d / 'timing.json'))['summary']
    exchanges = {k: (summary.get(k) or {}).get('complete', 0) for k in ('READ', 'SELECT', 'OPERATE')}
    n = sum(exchanges.values())
    return {'exchanges': exchanges, 'internal_rx_frames': rx_frames, 'internal_rx_octets': rx_octets,
            'rx_frames_by_role': per_role, 'held_rewaits': rewait, 'pktgen_seed_packets': seeds,
            'per_exchange': {'rx_frames': round(rx_frames / n, 1) if n else None,
                             'rx_octets': round(rx_octets / n, 1) if n else None,
                             'held_rewaits': round(rewait / n, 1) if n else None,
                             'pktgen_seed_packets': round(seeds / n, 2) if n else None}}


def report(roots):
    out = {'runs': [], 'arms': {}}
    for root in roots:
        rec = json.load(open(Path(root) / 'campaign_run.json'))
        for arm in rec['arms']:
            for tr in arm['trials']:
                d = Path(root) / arm['fixture'] / arm['arm'] / tr['label']
                try:
                    cost = trial_cost(d, tr['label'])
                except (OSError, KeyError, ValueError) as error:
                    cost = {'error': str(error)}
                out['runs'].append(dict(run=Path(root).name, arm=arm['arm'], fixture=arm['fixture'], label=tr['label'],
                                        trial_ok=tr.get('ok'), **cost))
                if 'error' not in cost:
                    agg = out['arms'].setdefault('%s/%s' % (arm['fixture'], arm['arm']), {'trials': 0, 'per_exchange': {}})
                    agg['trials'] += 1
                    for k, v in cost['per_exchange'].items():
                        agg['per_exchange'].setdefault(k, []).append(v)
    for agg in out['arms'].values():
        agg['per_exchange'] = {k: {'median': statistics.median(v), 'min': min(v), 'max': max(v)}
                               for k, v in agg['per_exchange'].items() if v}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('runs', nargs='+')
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args(argv)
    out = report(a.runs)
    Path(a.output).write_text(json.dumps(out, indent=1) + '\n')
    for name, agg in sorted(out['arms'].items()):
        pe = agg['per_exchange']
        print('%-28s trials=%d  rx frames/exch %s  rx octets/exch %s  re-waits/exch %s  pktgen seeds/exch %s' % (
            name, agg['trials'], pe['rx_frames']['median'], pe['rx_octets']['median'], pe['held_rewaits']['median'],
            pe['pktgen_seed_packets']['median']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
