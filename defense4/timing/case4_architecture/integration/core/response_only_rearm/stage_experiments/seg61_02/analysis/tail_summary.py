#!/usr/bin/env python3
"""Summarize tap-to-tap tail events per condition across many off-arm runs (Gate 5, tails).

  python3 tail_summary.py --condition control RUN_DIR... --condition tx-frames-irq=64 RUN_DIR... -o tails.json

For each run's off-arm trial it applies transit_report.trial_transit and records whether any transit exceeded
the threshold, the event positions (request index on the connection) and legs. Per condition it reports runs,
runs with events, the positions seen, and the Vision coalescing setting read back by tail_factor.py.
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import transit_report as tr  # noqa: E402


def run_events(root, threshold):
    trial = next(Path(root).glob('separate_ack/off/*_t0'))
    t = tr.trial_transit(trial, threshold)
    factor = Path(root) / 'tail_factor.json'
    record = json.load(open(factor)) if factor.is_file() else {}
    return {'run': Path(root).name, 'requests': t['requests'], 'events': [(e['leg'], e['after_request'], e['transit_us'])
                                                                           for e in t['events']],
            'applied': record.get('applied'), 'restore_ok': record.get('restore_ok')}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--condition', nargs='+', action='append', required=True, metavar='NAME RUN')
    ap.add_argument('--threshold-us', type=float, default=500.0)
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args(argv)
    out = {}
    for name, *runs in a.condition:
        rows = [run_events(r, a.threshold_us) for r in runs]
        positions = sorted({p for row in rows for _leg, p, _us in row['events']})
        out[name] = {'runs': len(rows), 'runs_with_events': sum(1 for r in rows if r['events']),
                     'positions': positions, 'rows': rows}
    Path(a.output).write_text(json.dumps(out, indent=1) + '\n')
    for name, c in out.items():
        print('%-18s runs=%d with_events=%d positions=%s' % (name, c['runs'], c['runs_with_events'], c['positions']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
