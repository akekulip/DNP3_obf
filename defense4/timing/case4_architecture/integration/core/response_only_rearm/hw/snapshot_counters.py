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
# 3 retry exhaustion, 4 stale retry; count_term 0 retried duplicate aborted. Read-only; a cell the loaded build
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
    try:
        counters = read_n_counters(sw, snapshot.tc.ALL_PIPES)
    finally:
        sw.close()
    path = Path(a.output)
    data = json.loads(path.read_text())
    data['n_counters'] = counters
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
