#!/usr/bin/env python3
"""Per-block, per-arm verdicts of the ctl_timing m4 silicon runs (9c4a2cfdc overnight), from retained evidence.

  python3 m4_summary.py -o m4_silicon_summary.json

For every hw_campaigns/ctl_m4_* run: the runner's block outcome, restore verification, and for each recorded
trial its ok flag, qualification, each timing objective's status and key numbers, the switch outcome counters
that identify recovery behaviour, and every failure string. CLRT tails beyond 100 us are listed with their
exchange index so the index-127 timing outlier of unresolved origin is visible.
"""
import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNS = HERE.parent / 'evidence/hw_campaigns'


def tails(timing_path, gap_us=950):
    if not timing_path.is_file():
        return None
    t = json.loads(timing_path.read_text())
    return [(i, r['kind'], r.get('ack_lat_us'), r['clrt_us'], r.get('rt_us'))
            for i, r in enumerate(t.get('exchanges', []))
            if isinstance(r.get('clrt_us'), (int, float)) and abs(r['clrt_us'] - gap_us) > 100]


def objective_view(artifact):
    out = {}
    for name, block in ((artifact.get('observed') or {}).get('objectives') or {}).items():
        ev = block.get('evidence') or {}
        out[name] = {'status': block.get('status'), 'p99': ev.get('p99'), 'n': ev.get('n') or ev.get('eligible'),
                     'min_transit_us': ev.get('min_transit_us'), 'exempted': block.get('exempted')}
    return out


def trial_view(d):
    tr = json.loads((d / 'trial.json').read_text()) if (d / 'trial.json').is_file() else {}
    sv = json.loads((d / 'standards_verdict.json').read_text()) if (d / 'standards_verdict.json').is_file() else {}
    art = json.loads((d / 'standards.json').read_text()) if (d / 'standards.json').is_file() else {}
    timed = tails(d / 'timing.json') if 'timing_only' in str(d) or 'combined' in str(d) else None
    return {'trial': d.name, 'ok': tr.get('ok'), 'qualification': sv.get('qualification'),
            'objectives': objective_view(art), 'failures': tr.get('failures'), 'clrt_tails_timed_arm': timed}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args(argv)
    out = []
    for root in sorted(RUNS.glob('ctl_m4_*')):
        rv = json.loads((root / 'restore_verify.json').read_text()) if (root / 'restore_verify.json').is_file() else {}
        rec = json.loads((root / 'campaign_run.json').read_text()) if (root / 'campaign_run.json').is_file() else {}
        trials = [trial_view(p.parent) for p in sorted(root.glob('*/*/*/trial.json'))]
        out.append({'run': root.name, 'restore_verified': rv.get('ok'), 'restore_failures': rv.get('failures'),
                    'runner_restore_ok': all(s.get('ok') for s in rec.get('restore', [])) if rec else None,
                    'trials': trials})
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    for run in out:
        print(run['run'], 'restore_verified=%s' % run['restore_verified'])
        for t in run['trials']:
            print('   %-60s ok=%-5s %-16s %s' % (t['trial'][-60:], t['ok'], t['qualification'],
                                                 {k: v['status'] for k, v in t['objectives'].items()}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
