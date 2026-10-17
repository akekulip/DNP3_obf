"""Egress-timestamp model driver for the m9d diagnostic build: model_contention.py's 'egress_diag' section only.

The cases, helpers and acceptance are model_contention.py's; its sha256 is recorded in the results as driver_sha256,
this wrapper's by run_model.py, which also retains the wrapped driver.
"""
import importlib.util
import os
import sys
from pathlib import Path

os.environ['CONTENTION_SECTIONS'] = 'egress_diag'
spec = importlib.util.spec_from_file_location('model_contention', Path(__file__).resolve().parent / 'model_contention.py')
contention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contention)

if __name__ == '__main__':
    sys.exit(contention.main())
