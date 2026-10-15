#!/usr/bin/env python3
"""Per-block, per-arm verdicts of the ctl_timing m5 silicon runs (PLAN_m5.md S4), from retained evidence.

  python3 m5_summary.py -o m5_silicon_summary.json

As m4_summary.py, plus N's contention counters: for every trial, the before/after deltas of count_busy (0 busy
drop, 1 busy pass, 2 retry lap, 3 retry exhaustion, 4 stale retry) and count_term[0] (retried duplicate aborted),
read from the snapshots' n_counters. The contention gate is that every trial shows zero busy drops, zero
exhaustion and zero stale retries; a trial whose snapshots lack n_counters FAILS the gate (never assumed zero).
Timing tails beyond 100 us are listed with their exchange index; the index-127 outlier stays unexcluded.
"""
import argparse
import json
from pathlib import Path

from m4_summary import RUNS, objective_view, tails

GATED = {0: 'busy_drop', 3: 'retry_exhaustion', 4: 'stale_retry'}


def counter_delta(snapshots, label):
    try:
        before = json.loads((snapshots / ('%s_before.json' % label)).read_text())['n_counters']
        after = json.loads((snapshots / ('%s_after.json' % label)).read_text())['n_counters']
    except (OSError, KeyError, ValueError):
        return None
    out = {}
    for name in ('count_busy', 'count_term'):
        out[name] = [None if a is None or b is None else b - a for a, b in zip(before[name], after[name])]
    return out


def contention_gate(delta):
    if delta is None:
        return {'ok': False, 'failures': ['n_counters missing from the trial snapshots']}
    busy = delta['count_busy']
    failures = ['%s %s' % (name, busy[i]) for i, name in GATED.items() if busy[i] != 0]
    return {'ok': not failures, 'failures': failures, 'retry_laps': busy[2],
            'retried_duplicates_aborted': delta['count_term'][0]}


def trial_view(d):
    tr = json.loads((d / 'trial.json').read_text()) if (d / 'trial.json').is_file() else {}
    sv = json.loads((d / 'standards_verdict.json').read_text()) if (d / 'standards_verdict.json').is_file() else {}
    art = json.loads((d / 'standards.json').read_text()) if (d / 'standards.json').is_file() else {}
    timed = tails(d / 'timing.json') if 'timing_only' in str(d) or 'combined' in str(d) else None
    delta = counter_delta(d / 'snapshots', d.name)
    return {'trial': d.name, 'ok': tr.get('ok'), 'qualification': sv.get('qualification'),
            'objectives': objective_view(art), 'failures': tr.get('failures'), 'clrt_tails_timed_arm': timed,
            'n_counter_delta': delta, 'contention_gate': contention_gate(delta)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--prefix', default='ctl_m5_')
    a = ap.parse_args(argv)
    out = []
    for root in sorted(RUNS.glob(a.prefix + '*')):
        rv = json.loads((root / 'restore_verify.json').read_text()) if (root / 'restore_verify.json').is_file() else {}
        trials = [trial_view(p.parent) for p in sorted(root.glob('*/*/*/trial.json'))]
        out.append({'run': root.name, 'restore_verified': rv.get('ok'), 'restore_failures': rv.get('failures'),
                    'contention_gate_ok': bool(trials) and all(t['contention_gate']['ok'] for t in trials),
                    'trials': trials})
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    for run in out:
        print(run['run'], 'restore_verified=%s contention_gate_ok=%s' % (run['restore_verified'], run['contention_gate_ok']))
        for t in run['trials']:
            print('   %-60s ok=%-5s %-16s retries=%s %s' % (t['trial'][-60:], t['ok'], t['qualification'],
                  t['contention_gate'].get('retry_laps'), t['contention_gate']['failures'] or ''))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
