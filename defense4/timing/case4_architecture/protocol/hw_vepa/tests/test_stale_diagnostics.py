"""Diagnostic stale counters cannot disappear behind production outcome index 6."""
import copy
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import checks
from test_checks import EXP, evidence

HW = HERE.parents[2] / 'integration' / 'core' / 'response_only' / 'hw'
sys.path.insert(0, str(HW))
spec = importlib.util.spec_from_file_location('snapshot_counters_for_test', HW / 'snapshot_counters.py')
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


def test_snapshot_reads_all_six_stale_sources_and_records_sum():
    calls = []
    def read(index):
        calls.append(index)
        return index - 18 if index >= 19 else 0
    diag = snapshot.read_diagnostics(read, {'OUT_HELD_REWAIT': 0})
    assert set(range(19, 25)).issubset(calls)
    assert diag['stale_total'] == 21
    assert len(diag['stale']) == 6


def test_diagnostic_stale_fails_even_when_production_index_six_is_zero():
    ev = evidence()
    diag = {'present': True, 'stale': {str(i): 0 for i in range(19, 25)}}
    ev['before']['diag'] = copy.deepcopy(diag)
    ev['after']['diag'] = copy.deepcopy(diag)
    ev['after']['diag']['stale']['19'] = 5
    fails, observed = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'separate_ack', 10, ev, mirror_k=2)
    assert observed['token_stale'] == 5
    assert any('OUT_TOKEN_STALE' in failure for failure in fails)


def test_incomplete_diagnostic_read_is_a_failure():
    ev = evidence()
    ev['before']['diag'] = {'present': True, 'stale': {str(i): 0 for i in range(19, 25)}}
    ev['after']['diag'] = copy.deepcopy(ev['before']['diag'])
    ev['after']['diag']['stale']['24'] = None
    fails, _ = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'separate_ack', 10, ev, mirror_k=2)
    assert any('diagnostic stale' in failure for failure in fails)


def test_pinned_diagnostic_build_cannot_fall_back_to_zero_index_six():
    ev = evidence()
    ev['before']['diag'] = {'present': False}
    ev['after']['diag'] = {'present': False}
    fails, observed = checks.evaluate(EXP, {'T': 1, 'padding': 1}, 'separate_ack', 10, ev,
                                     mirror_k=2, diagnostic=True)
    assert any('diagnostic stale' in failure for failure in fails)
    assert observed['token_stale'] is None


def test_snapshot_build_identity_requires_diagnostics_even_if_index16_read_fails():
    diag = snapshot.read_diagnostics(lambda index: None if index == 16 else 0,
                                     {'OUT_HELD_REWAIT': 0}, expected=True)
    assert diag['present']
    assert diag['read_errors'] == [16]
