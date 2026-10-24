#!/usr/bin/env python3
"""Candidate counter snapshot using the installer's strict parser checks."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rearm_snapshot_installer', HERE / 'bringup_composite.py')
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)
snapshot = entry.module('rearm_base_snapshot', entry.BASE / 'hw' / 'snapshot_counters.py')
snapshot.build_ports = entry.installer.build_ports


original_diagnostics = snapshot.read_diagnostics
original_diagnostic_build = snapshot.diagnostic_build


def configure(build_out):
    sealed = entry.configure(build_out)
    snapshot.readback = entry.installer.readback
    snapshot.read_diagnostics = entry.profile.read_diagnostics if sealed else original_diagnostics
    snapshot.diagnostic_build = (lambda _out: False) if sealed else original_diagnostic_build
    return sealed


# N's diagnostic counters (ctl_timing m5, PLAN_m5.md S4): count_busy 0 busy drop, 1 busy pass, 2 retry lap,
# 3 retry exhaustion, 4 stale retry, 5 stage-1 RST restart (m10); count_term 0 retried duplicate
# aborted. Read-only; a cell the loaded build
# does not have (m4: count_busy has 4) reads back None.
N_COUNTERS = (('count_busy', 8), ('count_term', 4))


def read_n_counters(sw, all_pipes):
    out = {}
    for name, cells in N_COUNTERS:
        values = []
        for i in range(cells):
            try:
                values.append(sum(sw.register('p0.n_Ingress.' + name, all_pipes, i)))
            except Exception:
                values.append(None)
        out[name] = values
    return out


# N's connection state (2026-10-23, forwarding-loss diagnosis: the 10-22 m11_09 and 10-23 c26 failed trials lost every
# master packet after the handshake and the counters above could not say why). Read-only, per pipe (not summed): the
# work cell (generation, phase; 4 = free), the owner/lifecycle cell, and the per-connection sequence and epoch cells.
N_STATE = ('owner', 'counter', 'epoch', 'retry_epoch', 'client', 'server', 'read_app')


def read_n_state(sw, all_pipes):
    out = {}
    for name in N_STATE:
        try:
            out[name] = sw.register('p0.n_Ingress.' + name, all_pipes, 0)
        except Exception as error:
            out[name] = 'unreadable: %s' % type(error).__name__
    try:
        got = sw.must_get('p0.n_Ingress.work.work', all_pipes, [('$REGISTER_INDEX', 0, None)])
        out['work'] = {k.rsplit('.', 1)[-1]: v for k, v in got.items() if k.endswith(('.generation', '.phase'))}
    except Exception as error:
        out['work'] = 'unreadable: %s' % type(error).__name__
    first = []
    for i in range(4):
        try:
            first.append(sw.register('p0.n_Ingress.count_first', all_pipes, i))
        except Exception:
            first.append(None)
    out['count_first'] = first
    return out


# m9d diagnostic build only (ctl_timing_01 generate.transform_e_diag): E's egress-parser timestamps of master-bound
# ACKs (lo) and responses (hi), indexed by the master-visible ack[13:0]. Any other build has no such register, and
# the snapshot is then unchanged (key absent).
DIAG_EGRESS = 'p0.r_Egress.diag_egress_ts'


def read_egress_diag(sw):
    """Non-zero entries of the diagnostic register, {index: [lo, hi]} on pipe 0, read in one bulk call; None when
    the loaded build has no such register. BF Runtime names the data fields after bfrt.json, without the pipe
    prefix (r_Egress.diag_egress_ts.lo / .hi), so fields are matched by suffix (review of round 2: an exact
    'p0.' name raised KeyError on hardware)."""
    try:
        t = sw.table(DIAG_EGRESS)
    except KeyError:                    # BF Runtime: the loaded build has no such table; any other error propagates
        return None
    out = {}
    for data, key in t.entry_get(sw.target(0), None, {'from_hw': True}):
        d, k = data.to_dict(), key.to_dict()
        index = k['$REGISTER_INDEX']['value']
        lo = next(v for f, v in d.items() if f.endswith('diag_egress_ts.lo'))
        hi = next(v for f, v in d.items() if f.endswith('diag_egress_ts.hi'))
        lo = lo[0] if isinstance(lo, list) else lo
        hi = hi[0] if isinstance(hi, list) else hi
        if lo or hi:
            out[index] = [lo, hi]
    return out


def add_n_counters(args):
    """After the base snapshot wrote its file, add N's counters to it with a fresh read-only client."""
    import argparse
    import json
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('-o', '--output')
    ap.add_argument('--program', default='response_only')
    ap.add_argument('--client-id', type=int, default=122)
    a, _ = ap.parse_known_args(args)
    from switch import Switch
    sw = Switch(a.program, a.client_id)
    diag, diag_error = None, None
    try:
        counters = read_n_counters(sw, snapshot.tc.ALL_PIPES)
        state = read_n_state(sw, snapshot.tc.ALL_PIPES)
        # the diagnostic register only after a trial (never in a _before snapshot, so a m9d unit does not wait on a
        # 16,384-entry read between selecting T and starting traffic), and in its own try: whatever happens there,
        # n_counters are written and the snapshot does not fail
        if not Path(a.output).name.endswith('_before.json'):
            try:
                diag = read_egress_diag(sw)
            except Exception as error:
                diag_error = '%s: %s' % (type(error).__name__, str(error)[:300])
    finally:
        sw.close()
    path = Path(a.output)
    data = json.loads(path.read_text())
    data['n_counters'] = counters
    data['n_state'] = state
    if diag is not None:
        data['egress_diag'] = dict(register=DIAG_EGRESS, units='ns, egress parser global_tstamp[31:0], pipe 0',
                                   index='master-visible tcp.ack[13:0]', lo='pure ACK', hi='response', entries=diag)
    if diag_error is not None:
        data['egress_diag_error'] = diag_error
    path.write_text(json.dumps(data, indent=1, default=str) + '\n')
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if '--help' not in args and '-h' not in args:
        configure(entry.build_argument(args))
    rc = snapshot.main(args)
    if rc == 0 and '--help' not in args and '-h' not in args:
        rc = add_n_counters(args)
    return rc


if __name__ == '__main__':
    sys.exit(main())
