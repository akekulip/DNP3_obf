#!/usr/bin/env python3
"""Read-only counter snapshot to JSON, for before/after deltas per experiment block. Runs on the switch host.

T outcomes (p1.t_Ingress.outcomes, 16 indices), generator app counters, TM queue watermark/drops on the two ladder ports,
and $PORT_STAT for 9 and 64 (read from_hw without SyncCounters, which this SDE rejects for $PORT_STAT).

  python3 snapshot_counters.py --build-out <out/> -o before.json [--client-id 122]
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_ports  # noqa: E402
import readback  # noqa: E402
import t_config as tc  # noqa: E402

T_OUTCOMES = ('OUT_UNMATCHED', 'OUT_HELD_REWAIT', 'OUT_ACK_COMMIT', 'OUT_RESP_RELEASE', 'OUT_RESP_DUP_DROP',
              'OUT_OP_RELEASE', 'OUT_TOKEN_STALE', 'OUT_HELD_STALE_FLUSH', 'OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK',
              'OUT_TOKEN_TMO', 'OUT_HELD_OFF_FLUSH', 'OUT_TOKEN_OFF', 'OUT_REQ_BYPASS')   # t_OUT_* constants 0..13

# Residency diagnostic indices (read/make_diag_t.py). On the production build the outcomes register is 16
# wide, so these indices do not exist and read back absent -> reported as None. On the diag build they
# localize the held-original recirculation by role. Index 1 (OUT_HELD_REWAIT) is kept for OPERATE re-wait
# (so the composite OPERATE assertion stays green); ACK and RESP re-wait are at 14/15.
DIAG_OUTCOMES = {14: 'DIAG_ACK_REWAIT', 15: 'DIAG_RESP_REWAIT',
                 16: 'DIAG_ACK_BLOCKER_LAP', 17: 'DIAG_RESP_BLOCKER_LAP', 18: 'DIAG_OP_BLOCKER_LAP'}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--program', default='response_only')
    ap.add_argument('--client-id', type=int, default=122)
    ap.add_argument('--ports', default='9,64')
    ap.add_argument('--build-out', required=True, help="the loaded build's out/: T's ladder ports are read from it")
    a = ap.parse_args(argv)
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':      # read-only, but it binds a BF Runtime client
        print('REFUSED: needs DEFENSE4_HW_AUTHORIZED=1')
        return 3
    ports, errs = build_ports.read(a.build_out)
    if errs:
        print('REFUSED: %s' % errs)
        return 1
    from switch import Switch
    sw = Switch(a.program, a.client_id)
    try:
        snap = dict(time=time.time(), outcomes={}, diag=dict(rewait={}, blocker_laps={}), ports={})

        def read_outcome(i):
            try:
                return sum(sw.register('p1.t_Ingress.outcomes', tc.ALL_PIPES, i))
            except Exception:
                return None                               # index beyond the register (production build): absent

        for i in range(16):
            name = T_OUTCOMES[i] if i < len(T_OUTCOMES) else 'index_%d' % i
            snap['outcomes'][name] = read_outcome(i)
        # Role-split residency view. ACK re-wait is outcome index 1; on the diag build that is ACK-only, on the
        # production build it is the combined OUT_HELD_REWAIT (both are reported under the same key so a reader
        # of either build sees it). RESP/OP re-wait and the per-role blocker laps exist only on the diag build.
        diag_present = read_outcome(16) is not None       # a diag-only index: present iff the register is 32 wide
        snap['diag']['present'] = diag_present
        snap['diag']['rewait']['OPERATE'] = snap['outcomes']['OUT_HELD_REWAIT']   # index 1: OPERATE on the diag build
        for idx, label in DIAG_OUTCOMES.items():
            value = read_outcome(idx)
            bucket = 'rewait' if 'REWAIT' in label else 'blocker_laps'
            role = label.replace('DIAG_', '').replace('_REWAIT', '').replace('_BLOCKER_LAP', '')
            snap['diag'][bucket][role] = value            # None on the production build
        snap.update(readback.snapshot(sw, ports))
        for p in [int(x) for x in a.ports.split(',')]:
            snap['ports'][p] = sw.get('$PORT_STAT', tc.ALL_PIPES, [('$DEV_PORT', p, None)])
        Path(a.output).write_text(json.dumps(snap, indent=1, default=str) + '\n')
        print('wrote', a.output)
    finally:
        sw.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
