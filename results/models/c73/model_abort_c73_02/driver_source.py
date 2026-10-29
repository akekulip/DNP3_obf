"""Outstation-abort model driver: model_contention.py with only its 'abort' section (completion plan gate 2).

An earlier contention case can block every later one (evidence/model_contention_m8_02_02), so the abort cases run on
their own here. The cases, helpers and acceptance are model_contention.py's; its own SHA is recorded in the results
as driver_sha256, and this wrapper's by run_model.py.
"""
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

os.environ['CONTENTION_SECTIONS'] = 'abort'
spec = importlib.util.spec_from_file_location('model_contention', Path(__file__).resolve().parent / 'model_contention.py')
contention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contention)

if __name__ == '__main__':
    sys.exit(contention.main())
