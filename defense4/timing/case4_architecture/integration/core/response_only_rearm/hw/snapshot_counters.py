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


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if '--help' not in args and '-h' not in args:
        configure(entry.build_argument(args))
    return snapshot.main(args)


if __name__ == '__main__':
    sys.exit(main())
