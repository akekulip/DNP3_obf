#!/usr/bin/env python3
"""
run_offline.py — minimal pytest-free runner for the pytest-style reference tests in this directory.

The research venv has no pytest; these test modules are plain `def test_*(): assert ...` functions with
no unittest/__main__ runner. This collects and runs every top-level `test_*` function in the named
modules (default: all `test_*.py` here), reports PASS/FAIL per test, and exits non-zero on any failure.
No environment change, no network, no switch. Usage: run_offline.py [module.py ...]
"""
import importlib.util
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))


def load(path):
    spec = importlib.util.spec_from_file_location(os.path.basename(path)[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_module(path):
    mod = load(path)
    fns = sorted((n, f) for n, f in vars(mod).items()
                 if n.startswith("test_") and callable(f) and f.__code__.co_argcount == 0)
    passed = failed = 0
    for name, fn in fns:
        try:
            fn()
            passed += 1
        except Exception:
            failed += 1
            print("  FAIL %s" % name)
            traceback.print_exc()
    print("  %s: %d passed, %d failed (%d fns)" % (os.path.basename(path), passed, failed, len(fns)))
    return failed


def main():
    mods = sys.argv[1:] or sorted(
        os.path.join(HERE, f) for f in os.listdir(HERE)
        if f.startswith("test_") and f.endswith(".py"))
    total_fail = 0
    for m in mods:
        m = m if os.path.isabs(m) else os.path.join(HERE, m)
        total_fail += run_module(m)
    print("\n=== %s ===" % ("ALL PASS" if total_fail == 0 else "%d FAILED" % total_fail))
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
