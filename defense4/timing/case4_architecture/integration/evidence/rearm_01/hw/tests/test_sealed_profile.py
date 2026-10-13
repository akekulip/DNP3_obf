"""Sparse timer counters preserve the production stale sum and pinned profiles."""
import importlib.util
import shutil
from pathlib import Path

import pytest

ARCH = Path(__file__).resolve().parents[5]
CORE = ARCH / 'integration/core/response_only_rearm'
spec = importlib.util.spec_from_file_location('sealed_profile', CORE/'hw/sealed_profile.py')
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


def test_sparse_layout_keeps_blocker_rejections_in_ordinary_strict_total():
    counters = {6: 2, 23: 4, 24: 3}
    outcomes = {'OUT_TOKEN_STALE': 2, 'OUT_HELD_REWAIT': 7, 'index_14': 1, 'index_15': 0}
    diag = profile.read_diagnostics(counters.get, outcomes)
    assert outcomes['OUT_TOKEN_STALE'] == 9
    assert outcomes['RAW_READ_TIMER_STALE'] == 3
    assert outcomes['RAW_OPERATE_TIMER_STALE'] == 4
    assert outcomes['STALE_BLOCKER'] == 2
    assert diag['present'] is False and diag['read_errors'] == []
    assert outcomes['OUT_OP_DUP_DROP'] is None                  # index 16 unreadable: recorded as unknown
    with_dup = {**counters, 16: 5}
    seen = {'OUT_TOKEN_STALE': 2}
    profile.read_diagnostics(with_dup.get, seen)
    assert seen['OUT_OP_DUP_DROP'] == 5 and seen['OUT_TOKEN_STALE'] == 9   # dup drops never enter the stale sum
    for bad in (None, True, -1):
        counters[24] = bad
        with pytest.raises(ValueError, match='raw timer'):
            profile.read_diagnostics(counters.get, dict(OUT_TOKEN_STALE=2))


def test_only_pinned_schema_and_compiled_source_enable_the_sealed_profile(tmp_path):
    out = CORE/'stage_experiments/combined_nt_diag_01/evidence/full_01/compile_local/out'
    if not out.is_dir():
        pytest.skip('regenerate the isolated full compiler artifact first')
    assert profile.select(out) is True
    installed = out.parents[1]/'compile_switch_9132/out'
    if installed.is_dir():
        assert profile.select(installed) is True
    for name in ('bfrt.json', 'response_only.p4pp'):
        shutil.copyfile(out/name, tmp_path/name)
    with (tmp_path/'response_only.p4pp').open('ab') as stream:
        stream.write(b'\n// changed compiled source\n')
    with pytest.raises(ValueError, match='compiled source'):
        profile.select(tmp_path)


def test_original_16_counter_profile_stays_on_original_reset_contract():
    out = CORE/'evidence/incremental_55/compile_local/out'
    if not out.is_dir():
        pytest.skip('regenerate preserved checkpoint55 compiler artifacts first')
    assert profile.select(out) is False


def test_sealed_reset_profile_is_private_and_reversible():
    spec = importlib.util.spec_from_file_location('sealed_installer_test', CORE/'hw/bringup_composite.py')
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)
    original = entry.installer.readback
    sealed = CORE/'stage_experiments/combined_nt_diag_01/evidence/full_01/compile_local/out'
    baseline = CORE/'evidence/incremental_55/compile_local/out'
    entry.configure(sealed)
    assert entry.installer.readback is not original
    assert len(entry.installer.readback.T_REGISTER_INIT) == 13
    assert 'quarantine_reg' not in entry.installer.readback.T_REGISTER_INIT
    assert len(original.T_REGISTER_INIT) == 14
    entry.configure(baseline)
    assert entry.installer.readback is original


def test_sealed_snapshot_uses_sparse_reader_and_original_snapshot_module_is_unchanged():
    spec = importlib.util.spec_from_file_location('sealed_snapshot_test', CORE/'hw/snapshot_counters.py')
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)
    sealed = CORE/'stage_experiments/combined_nt_diag_01/evidence/full_01/compile_local/out'
    entry.configure(sealed)
    assert entry.snapshot.read_diagnostics is entry.entry.profile.read_diagnostics
    assert entry.snapshot.diagnostic_build(sealed) is False
    assert 'quarantine_reg' not in entry.snapshot.readback.T_REGISTER_INIT
