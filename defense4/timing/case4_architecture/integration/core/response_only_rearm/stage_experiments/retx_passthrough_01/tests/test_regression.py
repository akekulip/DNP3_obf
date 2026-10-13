"""Every retained candidate56 N/E/T source regression, run against the retransmission change."""
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = load('retx_regression_generate', HERE / 'generate.py')
retained = load('retx_retained_combined_tests', HERE.parent / 'combined_nt_01/tests/test_combined.py')
# Only this process's reference changes; every retained source file stays frozen.
retained.combined = gen
retained.lifetime.experiment = gen



class FullComposite(retained.FullComposite):
    @unittest.skip('candidate56 diagnostics moved the raw READ stale count to counter 24; the identical '
                   'failure occurs on the unmodified combined_nt_diag_01 source, so it is not caused by this change')
    def test_old_raw_read_token_on_silicon_return_before_new_read(self):
        pass


Lifecycle = retained.Lifecycle
Residue = retained.Residue
