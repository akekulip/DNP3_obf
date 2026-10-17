"""m10 restart-path coverage of one silicon block: count_busy[5] (stage-1 RST restarts), after minus before.

  python3 restart_count.py RUN_DIR      -> prints one line and writes RUN_DIR/restart_coverage.json

Per trial (each */snapshots/*_before.json with its *_after.json), the delta of n_counters.count_busy[5]. The block
is 'exercised' if any trial's delta is > 0, 'not exercised' if every trial has both snapshots and delta 0, and
'unknown' otherwise (a snapshot or the cell missing): unknown is never read as not exercised, nor as a pass.
"""
import json
import sys
from pathlib import Path

CELL = 5


def cell(path):
    try:
        values = json.loads(path.read_text())['n_counters']['count_busy']
        return values[CELL] if isinstance(values, list) and len(values) > CELL else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def coverage(run):
    trials = []
    for before in sorted(Path(run).rglob('snapshots/*_before.json')):
        after = before.with_name(before.name[:-len('_before.json')] + '_after.json')
        b, a = cell(before), cell(after) if after.is_file() else None
        trials.append(dict(trial=before.parent.parent.name, before=b, after=a,
                           delta=(a - b) if isinstance(a, int) and isinstance(b, int) else None))
    if any(t['delta'] and t['delta'] > 0 for t in trials):
        verdict = 'exercised'
    elif trials and all(t['delta'] == 0 for t in trials):
        verdict = 'not exercised'
    else:
        verdict = 'unknown'
    return dict(run=Path(run).name, counter='count_busy[%d] stage-1 RST restart (m10)' % CELL, trials=trials,
                restart_path=verdict)


def main(argv):
    result = coverage(argv[1])
    (Path(argv[1]) / 'restart_coverage.json').write_text(json.dumps(result, indent=1) + '\n') \
        if Path(argv[1]).is_dir() else None
    print('RESTART_PATH %s %s %s' % (result['run'], result['restart_path'],
                                     [t['delta'] for t in result['trials']]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
