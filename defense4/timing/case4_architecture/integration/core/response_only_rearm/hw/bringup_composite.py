#!/usr/bin/env python3
"""Candidate-only installer entrypoint; baseline SHA/mirror gates retained."""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent.parent / 'response_only'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


# Load the unchanged installer and its dependencies, then choose candidate rows
# through one explicit module injection. The other hardware entrypoints stay on
# their existing baseline profile.
sys.path[:0] = [str(BASE), str(BASE / 'hw')]
installer = module('rearm_base_installer', BASE / 'hw' / 'bringup_composite.py')
candidate_cp = module('rearm_candidate_cp', HERE.parent / 'cp.py')
installer.rows.cp = candidate_cp


if __name__ == '__main__':
    sys.exit(installer.main())
