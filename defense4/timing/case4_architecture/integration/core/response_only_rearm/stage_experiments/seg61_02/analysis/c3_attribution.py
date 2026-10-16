#!/usr/bin/env python3
"""C3 attribution of stale-blocker retirements from the diagnostic poller (C3_DIAGNOSTIC_PLAN_20261016.md).

  python3 c3_attribution.py RUN_DIR [RUN_DIR ...] -o out.json [--md out.md]

Each RUN_DIR is a diagnostic isolation block. Its trial directory holds `diag_poll.jsonl`, written by
rearm_01/hw/diag_poll.py on the switch: one sample per period with all 25 T outcome cells, the generator app counters,
N's epoch/owner/work cell and T's cur_epoch/gen_alloc/op_gen_alloc. Every time is the switch's own monotonic clock.

For every increment of outcome 6 (OUT_TOKEN_STALE, stale-blocker retirement) it reports:
- the window, defined by register values only: the connection is the ordinal of N's epoch (c1, c2, c3); the
  exchange context is T's lane generations;
- the concurrent changes of the raw timer-stale cells 23/24 (stale raw token rejection, kept separate), the generator
  counters and the lane generations;
- the sample's position and duration.
It also checks the poller against the block's own before/after counter snapshots (explanation E3: accounting). A window
localizes an event; it does not name the blocker's generation.
"""
import argparse
import json
from pathlib import Path

STALE, RAW_OP, RAW_READ, REWAIT = 6, 23, 24, 1


def load(run):
    files = sorted(Path(run).glob('*/*/*/diag_poll.jsonl'))
    if len(files) != 1:
        raise SystemExit('%s: expected one diag_poll.jsonl, found %d' % (run, len(files)))
    rows = [json.loads(line) for line in files[0].read_text().splitlines() if line.strip()]
    samples = [r for r in rows if not r.get('summary') and isinstance(r.get('outcomes'), list)
               and all(isinstance(v, int) for v in r['outcomes'])]
    summary = next((r for r in rows if r.get('summary')), None)
    return files[0].parent, samples, summary, len(rows)


def snapshot_delta(trial_dir, index):
    snaps = trial_dir / 'snapshots'
    try:
        before = json.loads(next(snaps.glob('*_before.json')).read_text())
        after = json.loads(next(snaps.glob('*_after.json')).read_text())
    except (StopIteration, OSError, ValueError):
        return None
    names = {STALE: 'STALE_BLOCKER', RAW_OP: 'RAW_OPERATE_TIMER_STALE', RAW_READ: 'RAW_READ_TIMER_STALE'}
    b, a = before.get('outcomes', {}).get(names[index]), after.get('outcomes', {}).get(names[index])
    return a - b if isinstance(a, int) and isinstance(b, int) else None


def analyse(run):
    trial_dir, samples, summary, lines = load(run)
    if not samples:
        return dict(run=str(run), error='no complete samples')
    t0 = samples[0]['t_start_ns']
    epochs = []
    for s in samples:
        if s.get('n_epoch') not in epochs:
            epochs.append(s.get('n_epoch'))
    conn = {e: 'epoch#%d' % i for i, e in enumerate(epochs)}
    events, windows = [], {}
    for prev, cur in zip(samples, samples[1:]):
        d = [c - p for p, c in zip(prev['outcomes'], cur['outcomes'])]
        w = conn[cur.get('n_epoch')]
        acc = windows.setdefault(w, {'stale_retire': 0, 'raw_read': 0, 'raw_op': 0, 'samples': 0,
                                     'gen_alloc': set(), 'op_gen_alloc': set()})
        acc['samples'] += 1
        acc['stale_retire'] += d[STALE]
        acc['raw_read'] += d[RAW_READ]
        acc['raw_op'] += d[RAW_OP]
        acc['gen_alloc'].add(cur.get('t_gen_alloc'))
        acc['op_gen_alloc'].add(cur.get('t_op_gen_alloc'))
        if d[STALE]:
            events.append(dict(
                t_ms=round((cur['t_end_ns'] - t0) / 1e6, 3), window=w, increment=d[STALE],
                n_epoch=(prev.get('n_epoch'), cur.get('n_epoch')),
                t_gen_alloc=(prev.get('t_gen_alloc'), cur.get('t_gen_alloc')),
                t_op_gen_alloc=(prev.get('t_op_gen_alloc'), cur.get('t_op_gen_alloc')),
                raw_read_delta=d[RAW_READ], raw_op_delta=d[RAW_OP], rewait_delta=d[REWAIT],
                pktgen=(prev.get('pktgen'), cur.get('pktgen')),
                sample_ms=round((cur['t_end_ns'] - cur['t_start_ns']) / 1e6, 3)))
    for acc in windows.values():
        acc['gen_alloc'] = sorted(v for v in acc['gen_alloc'] if v is not None)
        acc['op_gen_alloc'] = sorted(v for v in acc['op_gen_alloc'] if v is not None)
    poll_total = {i: samples[-1]['outcomes'][i] - samples[0]['outcomes'][i] for i in (STALE, RAW_READ, RAW_OP)}
    snap_total = {i: snapshot_delta(trial_dir, i) for i in (STALE, RAW_READ, RAW_OP)}
    durations = [(s['t_end_ns'] - s['t_start_ns']) / 1e6 for s in samples]
    return dict(run=str(run), samples=len(samples), lines=lines, summary=summary,
                sample_ms=dict(min=round(min(durations), 2), max=round(max(durations), 2),
                               mean=round(sum(durations) / len(durations), 2)),
                connections=[conn[e] for e in epochs], windows=windows, stale_retirements=events,
                poll_totals={str(k): v for k, v in poll_total.items()},
                snapshot_totals={str(k): v for k, v in snap_total.items()},
                # the poller starts after the before snapshot and stops before the after snapshot, so it can miss
                # only events in those two gaps; any other disagreement is an accounting problem (E3)
                poll_within_snapshot=all(snap_total[i] is None or poll_total[i] <= snap_total[i]
                                         for i in poll_total))


def markdown(results):
    lines = ['| block | window | stale retirements (6) | raw READ (24) | raw OPERATE (23) | READ-lane gens | '
             'OPERATE-lane gens |', '|---|---|---:|---:|---:|---|---|']
    for r in results:
        for w, acc in r.get('windows', {}).items():
            lines.append('| %s | %s | %d | %d | %d | %s | %s |' % (Path(r['run']).name, w, acc['stale_retire'],
                         acc['raw_read'], acc['raw_op'], acc['gen_alloc'], acc['op_gen_alloc']))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('runs', nargs='+')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--md')
    a = ap.parse_args(argv)
    results = [analyse(r) for r in a.runs]
    Path(a.output).write_text(json.dumps(results, indent=1, default=list) + '\n')
    if a.md:
        Path(a.md).write_text(markdown(results))
    for r in results:
        print(r['run'], 'samples', r.get('samples'), 'stale retirements', len(r.get('stale_retirements', [])),
              'poll totals', r.get('poll_totals'), 'snapshot totals', r.get('snapshot_totals'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
