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

TIMING_CONTRACT = None  # source-bound candidate entrypoint selects the active resource ABI

T_OUTCOMES = ('OUT_UNMATCHED', 'OUT_HELD_REWAIT', 'OUT_ACK_COMMIT', 'OUT_RESP_RELEASE', 'OUT_RESP_DUP_DROP',
              'OUT_OP_RELEASE', 'OUT_TOKEN_STALE', 'OUT_HELD_STALE_FLUSH', 'OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK',
              'OUT_TOKEN_TMO', 'OUT_HELD_OFF_FLUSH', 'OUT_TOKEN_OFF', 'OUT_REQ_BYPASS')   # t_OUT_* constants 0..13

# Residency diagnostic indices (read/make_diag_t.py). On the production build the outcomes register is 16
# wide, so these indices do not exist and read back absent -> reported as None. On the diag build they
# localize the held-original recirculation by role. Index 1 (OUT_HELD_REWAIT) is kept for OPERATE re-wait
# (so the composite OPERATE assertion stays green); ACK and RESP re-wait are at 14/15.
DIAG_OUTCOMES = {14: 'DIAG_ACK_REWAIT', 15: 'DIAG_RESP_REWAIT',
                 16: 'DIAG_ACK_BLOCKER_LAP', 17: 'DIAG_RESP_BLOCKER_LAP', 18: 'DIAG_OP_BLOCKER_LAP'}
DIAG_STALE = {19: 'OP_BLOCKER_DEADLINE_PAST', 20: 'OP_BLOCKER_BEFORE_DEADLINE',
              21: 'ACK_BLOCKER', 22: 'RESP_BLOCKER', 23: 'OP_TOKEN', 24: 'READ_TOKEN'}


def read_diagnostics(read_outcome, outcomes, expected=False):
    """Read every diagnostic source. None remains visible if a diagnostic read fails."""
    diag = dict(present=bool(expected), rewait={}, blocker_laps={}, stale={}, read_errors=[])
    diag['rewait']['OPERATE'] = outcomes.get('OUT_HELD_REWAIT')
    for idx, label in DIAG_OUTCOMES.items():
        bucket = 'rewait' if 'REWAIT' in label else 'blocker_laps'
        role = label.replace('DIAG_', '').replace('_REWAIT', '').replace('_BLOCKER_LAP', '')
        value = read_outcome(idx)
        diag[bucket][role] = value
        if idx == 16 and value is not None:
            diag['present'] = True
        if value is None:
            diag['read_errors'].append(idx)
    for idx in DIAG_STALE:
        diag['stale'][str(idx)] = read_outcome(idx)
        if diag['stale'][str(idx)] is None:
            diag['read_errors'].append(idx)
    diag['stale_sources'] = {str(idx): name for idx, name in DIAG_STALE.items()}
    values = list(diag['stale'].values())
    diag['stale_total'] = sum(values) if all(isinstance(v, int) for v in values) else None
    return diag


def diagnostic_build(build_out):
    tables = json.loads((Path(build_out) / 'bfrt.json').read_text())['tables']
    return any(table['name'] == 'p1.t_Ingress.outcomes' and table['size'] >= 25 for table in tables)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--program', default='response_only')
    ap.add_argument('--client-id', type=int, default=122)
    ap.add_argument('--ports', default='9,64')
    ap.add_argument('--build-out', required=True, help="the loaded build's out/: T's ladder ports are read from it")
    for role in ('ack', 'resp'):
        ap.add_argument('--shape-%s-pps' % role, type=int, default=0, dest='shape_%s' % role,
                        help='requested %s HOLD-queue rate, recorded alongside the achieved rate' % role.upper())
        ap.add_argument('--shape-%s-blk-pps' % role, type=int, default=0, dest='block_%s' % role,
                        help='requested %s BLOCKER-queue rate, recorded alongside the achieved rate' % role.upper())
    a = ap.parse_args(argv)
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':      # read-only, but it binds a BF Runtime client
        print('REFUSED: needs DEFENSE4_HW_AUTHORIZED=1')
        return 3
    ports, errs = build_ports.read(a.build_out, timing_contract=TIMING_CONTRACT)
    if errs:
        print('REFUSED: %s' % errs)
        return 1
    from switch import Switch
    sw = Switch(a.program, a.client_id)
    try:
        snap = dict(time=time.time(), outcomes={}, diag=dict(rewait={}, blocker_laps={}), ports={})

        tables = None
        if TIMING_CONTRACT == tc.RESPONSE_READY_NO_J_CONTRACT:
            tables = {table['name'] for table in json.loads((Path(a.build_out) / 'bfrt.json').read_text())['tables']}

        def read_outcome(i):
            if tables is not None and 'p1.t_Ingress.outcomes' not in tables:
                return None
            try:
                return sum(sw.register('p1.t_Ingress.outcomes', tc.ALL_PIPES, i))
            except Exception:
                return None                               # index beyond the register (production build): absent

        for i in range(16):
            name = T_OUTCOMES[i] if i < len(T_OUTCOMES) else 'index_%d' % i
            snap['outcomes'][name] = read_outcome(i)
        snap['diag'] = read_diagnostics(read_outcome, snap['outcomes'], diagnostic_build(a.build_out))
        requested = {r: getattr(a, 'shape_' + r) for r in ('ack', 'resp')}
        requested_block = {r: getattr(a, 'block_' + r) for r in ('ack', 'resp')}
        snap.update(readback.snapshot(sw, ports, requested, requested_block, timing_contract=TIMING_CONTRACT))
        for p in [int(x) for x in a.ports.split(',')]:
            snap['ports'][p] = sw.get('$PORT_STAT', tc.ALL_PIPES, [('$DEV_PORT', p, None)])
        Path(a.output).write_text(json.dumps(snap, indent=1, default=str) + '\n')
        print('wrote', a.output)
        if snap['diag']['present'] and snap['diag']['read_errors']:
            print('FAILED: diagnostic indices unreadable:', snap['diag']['read_errors'])
            return 1
    finally:
        sw.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
