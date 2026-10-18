"""Transactions table for leakage_four_arm.py from four-arm silicon blocks (Part 2, 2026-10-18).

  python3 four_arm_transactions.py OUT.csv BLOCK_DIR [BLOCK_DIR ...]

Each BLOCK_DIR is one run_block campaign directory (e.g. hw_campaigns/part2_m10_da10_g100_b1_01) whose fixture
directory holds one trial per arm, each with the per-exchange timing.json the block's own extraction wrote. The
grouped run is the block: every block runs all four arms in its rotation order, so leave-one-run-out holds every
arm of one block out together.

One row per exchange: run, block_dir, arm (off -> baseline), trial, txn_class (READ/SELECT/OPERATE), ack_ms, clrt_ms,
rt_ms, resp_len, retransmitted, piggyback. Only complete exchanges with both intervals are written. Every other
exchange is counted in OUT.csv.counts.json, per block and arm, so no tail is dropped silently. The intervals are
host-capture-point times (timing.json's own note): the host-observed measurement, not switch-side time.
"""
import csv
import json
import sys
from pathlib import Path

ARM_NAMES = {'off': 'baseline', 'size_only': 'size_only', 'timing_only': 'timing_only', 'combined': 'combined'}
CLASSES = ('READ', 'SELECT', 'OPERATE')
FIELDS = ('run', 'block_dir', 'arm', 'trial', 'txn_class', 'ack_ms', 'clrt_ms', 'rt_ms', 'resp_len', 'retransmitted',
          'piggyback')


def block_rows(block_dir):
    block_dir = Path(block_dir)
    rows, counts = [], {}
    timings = sorted(block_dir.glob('*/*/*/timing.json'))           # fixture / arm / trial / timing.json
    if not timings:
        raise ValueError('%s: no per-arm timing.json' % block_dir)
    for t in timings:
        arm_dir = t.parent.parent.name
        if arm_dir not in ARM_NAMES:
            raise ValueError('%s: unknown arm directory %r' % (t, arm_dir))
        arm = ARM_NAMES[arm_dir]
        c = counts.setdefault(arm, dict(written=0, incomplete=0, missing_interval=0, other_kind=0))
        for e in json.loads(t.read_text())['exchanges']:
            if e.get('kind') not in CLASSES:
                c['other_kind'] += 1
            elif not e.get('complete'):
                c['incomplete'] += 1
            elif e.get('ack_lat_us') is None or e.get('clrt_us') is None:
                c['missing_interval'] += 1
            else:
                c['written'] += 1
                rows.append(dict(run=block_dir.name, block_dir=str(block_dir), arm=arm, trial=t.parent.name,
                                 txn_class=e['kind'], ack_ms=e['ack_lat_us'] / 1000.0, clrt_ms=e['clrt_us'] / 1000.0,
                                 rt_ms=(e['rt_us'] / 1000.0) if e.get('rt_us') is not None else '',
                                 resp_len=e.get('resp_len', ''), retransmitted=bool(e.get('retransmitted')),
                                 piggyback=bool(e.get('piggyback'))))
    return rows, counts


def main(argv):
    out, blocks = Path(argv[1]), argv[2:]
    rows, counts = [], {}
    for b in blocks:
        r, c = block_rows(b)
        rows += r
        counts[Path(b).name] = c
    with open(out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    Path(str(out) + '.counts.json').write_text(json.dumps(counts, indent=1) + '\n')
    print('%d exchanges from %d blocks -> %s' % (len(rows), len(blocks), out))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
