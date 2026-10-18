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
    if not (sealed.is_dir() and baseline.is_dir()):        # git-ignored compiler output, absent in a fresh clone
        pytest.skip('regenerate the isolated full and checkpoint55 compiler artifacts first')
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
    if not sealed.is_dir():                                # git-ignored compiler output, absent in a fresh clone
        pytest.skip('regenerate the isolated full compiler artifact first')
    entry.configure(sealed)
    assert entry.snapshot.read_diagnostics is entry.entry.profile.read_diagnostics
    assert entry.snapshot.diagnostic_build(sealed) is False
    assert 'quarantine_reg' not in entry.snapshot.readback.T_REGISTER_INIT


import hashlib
import json


def successor_build(tmp_path, children=1):
    """Small complete two-SDK artifact fixture; the expected layout is literal."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = b'new candidate source\n'
    source_hash = hashlib.sha256(source).hexdigest()
    (tmp_path / 'response_only.p4').write_bytes(source)
    tables = [{'name': 'p1.t_Ingress.child_seen%d_reg' % i} for i in range(children)]
    pins = {}
    for compile_name in ('compile_local', 'compile_switch_9132'):
        directory = tmp_path / compile_name
        out = directory / 'out'
        out.mkdir(parents=True)
        for name in ('bfrt.json', 'response_only.p4pp', 'p0/context.json', 'p1/context.json',
                     'p0/tofino.bin', 'p1/tofino.bin'):
            path = out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(json.dumps({'tables': tables}).encode() if name == 'bfrt.json' else name.encode())
        hashes = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in out.rglob('*') if p.is_file()}
        pins[compile_name] = hashes
        (directory / 'manifest.json').write_text(json.dumps({'source_sha256': source_hash,
            'exit_code': 0, 'artifact_sha256': {key: value for key, value in hashes.items() if key != 'response_only.p4pp'}}))
    supported = {'reset_restart_required': True, 't_child_count': children, 'candidate': {
        'source_sha256': source_hash, 'artifact_sha256': pins}}
    (tmp_path / 'response_only.inputs.json').write_text(json.dumps({
        'source_sha256': source_hash, 'supported_profile': supported}))
    return tmp_path / 'compile_local/out'


@pytest.mark.parametrize('children', [1, 3])
def test_successor_profile_selects_only_its_bound_child_schema(tmp_path, children):
    out = successor_build(tmp_path, children)
    descriptor = profile.describe(out)
    assert descriptor['sealed'] is True and descriptor['t_child_count'] == children
    assert profile.select(out) is True
    assert profile.child_registers(descriptor) == tuple('child_seen%d_reg' % i for i in range(children))


@pytest.mark.parametrize('tamper', ['source', 'inputs', 'manifest_source', 'compile_failed', 'p4pp', 'bfrt',
                                  'missing_pin', 'missing_other_sdk', 'missing_artifact'])
def test_successor_profile_rejects_unbound_or_incomplete_builds(tmp_path, tamper):
    out = successor_build(tmp_path)
    inputs_path = tmp_path / 'response_only.inputs.json'
    inputs = json.loads(inputs_path.read_text())
    manifest_path = tmp_path / 'compile_local/manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if tamper == 'source':
        (tmp_path / 'response_only.p4').write_text('changed source')
    elif tamper == 'inputs':
        inputs['source_sha256'] = '0' * 64
    elif tamper == 'manifest_source':
        manifest['source_sha256'] = '0' * 64
    elif tamper == 'compile_failed':
        manifest['exit_code'] = 1
    elif tamper in ('p4pp', 'bfrt'):
        (out / ('response_only.p4pp' if tamper == 'p4pp' else 'bfrt.json')).write_text('changed artifact')
    elif tamper == 'missing_pin':
        del inputs['supported_profile']['candidate']['artifact_sha256']['compile_local']['response_only.p4pp']
    elif tamper == 'missing_other_sdk':
        del inputs['supported_profile']['candidate']['artifact_sha256']['compile_switch_9132']
    else:
        (out / 'p1/tofino.bin').unlink()
    inputs_path.write_text(json.dumps(inputs))
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        profile.select(out)


@pytest.mark.parametrize('actual', [0, 2, 3])
def test_single_child_profile_rejects_missing_or_extra_child_banks(tmp_path, actual):
    out = successor_build(tmp_path, 1)
    # Rebind all artifact hashes, leaving only the semantic schema mismatch.
    tables = [{'name': 'p1.t_Ingress.child_seen%d_reg' % i} for i in range(actual)]
    (out / 'bfrt.json').write_text(json.dumps({'tables': tables}))
    digest = hashlib.sha256((out / 'bfrt.json').read_bytes()).hexdigest()
    path = tmp_path / 'response_only.inputs.json'
    inputs = json.loads(path.read_text())
    inputs['supported_profile']['candidate']['artifact_sha256']['compile_local']['bfrt.json'] = digest
    path.write_text(json.dumps(inputs))
    path = tmp_path / 'compile_local/manifest.json'
    manifest = json.loads(path.read_text())
    manifest['artifact_sha256']['bfrt.json'] = digest
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='child'):
        profile.select(out)


def test_installer_and_snapshot_restore_three_child_initialization_after_one_child(tmp_path):
    one = successor_build(tmp_path / 'one', 1)
    three = successor_build(tmp_path / 'three', 3)
    spec = importlib.util.spec_from_file_location('one_child_installer', CORE / 'hw/bringup_composite.py')
    entry = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(entry)
    entry.configure(one)
    assert 'child_seen0_reg' in entry.installer.readback.T_REGISTER_INIT
    assert 'child_seen1_reg' not in entry.installer.readback.T_REGISTER_INIT
    assert 'child_seen2_reg' not in entry.installer.readback.T_REGISTER_INIT
    assert 'quarantine_reg' not in entry.installer.readback.T_REGISTER_INIT
    entry.configure(three)
    assert all('child_seen%d_reg' % i in entry.installer.readback.T_REGISTER_INIT for i in range(3))
    spec = importlib.util.spec_from_file_location('one_child_snapshot', CORE / 'hw/snapshot_counters.py')
    snapshot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(snapshot)
    snapshot.configure(one)
    assert 'child_seen1_reg' not in snapshot.snapshot.readback.T_REGISTER_INIT
    snapshot.configure(three)
    assert all('child_seen%d_reg' % i in snapshot.snapshot.readback.T_REGISTER_INIT for i in range(3))


@pytest.mark.parametrize('driver', ['model_rearm.py', 'model_dup.py'])
@pytest.mark.parametrize('children', [1, 3])
def test_model_snapshots_read_every_selected_child_bank_and_no_others(driver, children):
    # Execute the real nested snapshot against a register-reader boundary double;
    # importing the model driver would require the BF SDK and running simulator.
    import ast
    path = CORE / 'stage_experiments/seg61_02' / driver
    tree = ast.parse(path.read_text())
    snapshot_node = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'snapshot')
    reads = []
    class Model:
        def register_read(self, name, index, pipe):
            reads.append(name)
            return [0]
    namespace = {'m': Model(), 'child_regs': profile.child_registers({'t_child_count': children})}
    exec(compile(ast.Module(body=[snapshot_node], type_ignores=[]), str(path), 'exec'), namespace)
    namespace['snapshot']()
    assert {name for name in reads if '.child_seen' in name} == {
        'p1.t_Ingress.child_seen%d_reg' % i for i in range(children)}


def test_deployed_build_retains_enough_bound_metadata_for_strict_profile_selection(tmp_path):
    out = successor_build(tmp_path / 'build', 1)
    inputs_path = tmp_path / 'build/response_only.inputs.json'
    inputs = json.loads(inputs_path.read_text())
    inputs['supported_profile'].update(encoding={'native_input_octets': {'READ': 49, 'SELECT': 37, 'OPERATE': 37},
                                                 'output_octets': 61},
        timing_ns={'D_release_budget': 950000, 'J_operate_hold': 2400000, 'pb_piggyback_bound': 4000000,
                   'readiness': 30000000, 'da': 2000000, 'cap': 40000000})
    inputs_path.write_text(json.dumps(inputs))
    hw = ARCH / 'integration/evidence/rearm_01/hw'
    spec = importlib.util.spec_from_file_location('profile_metadata_campaign', hw / 'candidate_campaign.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    campaign = module.CandidateCampaign.__new__(module.CandidateCampaign)
    build = {'out_dir': str(out), 'manifest': str(out.parent / 'manifest.json'),
             'source_sha256': inputs['source_sha256']}
    deployed = tmp_path / 'remote/out_successor'
    shutil.copytree(out, deployed)
    for relative, source in campaign._profile_files(build).items():
        target = deployed / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    descriptor = profile.describe(deployed)
    assert descriptor['t_child_count'] == 1 and descriptor['sealed'] is True
    (deployed / 'profile/response_only.p4').write_text('modified deployed source')
    with pytest.raises(ValueError, match='source'):
        profile.describe(deployed)


@pytest.mark.parametrize('field', ['t_child_count', 'artifact_sha256'])
def test_successor_schema_rejects_missing_profile_fields_clearly(tmp_path, field):
    out = successor_build(tmp_path)
    path = tmp_path / 'response_only.inputs.json'
    inputs = json.loads(path.read_text())
    if field == 'artifact_sha256':
        inputs['supported_profile']['candidate'][field] = None
    else:
        del inputs['supported_profile'][field]
    path.write_text(json.dumps(inputs))
    with pytest.raises(ValueError):
        profile.select(out)
