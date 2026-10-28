"""The current model entry must preserve all scenarios without historical imports."""
import importlib.util
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / 'scripts/model'
sys.path[:0] = [str(MODEL), str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_gate_requires_exact_seventeen_drivers(tmp_path):
    profile = load('current_package', ROOT / 'scripts/profile.py')
    build = tmp_path / 'candidate'
    profile.package(build)
    import run_model
    import model_summary
    expected = {'abandon', 'abort', 'contention', 'control_timing', 'dup', 'fin_busy', 'packets',
                'policy', 'policy_boundary', 'rearm', 'relay_sbo', 'repeat', 'response_ready',
                'select_lifecycle', 'smoke', 'smoke_sizeoff', 'two_read_robust'}
    assert set(run_model.DRIVERS) == set(model_summary.required_drivers(build)) == expected
    assert all(path.parent == MODEL for path in run_model.DRIVERS.values())


def test_all_driver_imports_and_packet_oracles_use_only_current_paths(tmp_path):
    profile = load('current_package', ROOT / 'scripts/profile.py')
    build = tmp_path / 'candidate'
    profile.package(build)
    program = '''
import sys
from pathlib import Path
root = Path.cwd()
sys.path[:0] = [str(root/'scripts/model'), str(root/'scripts/checks'), str(root/'scripts/hardware')]
import run_model
for name in run_model.REQUIRED:
    # Wrapper drivers execute main at import, so inspect them through their target.
    if name not in ('abort', 'policy_boundary', 'smoke_sizeoff'):
        __import__('model_' + name)
import model_packets
assert model_packets.run_vector_validation() == 0
for module in list(sys.modules.values()):
    filename = getattr(module, '__file__', '') or ''
    assert '/defense4/' not in filename and '/Archive/' not in filename, filename
'''
    # The installed SDE client is a Python3.8 extension; the test runner may be3.12.
    result = subprocess.run(['/usr/bin/python3', '-c', program], cwd=ROOT, env=dict(os.environ,
        PORT_MAP=str(build / 'response_only.inputs.json'), MILESTONE='current'), capture_output=True, text=True)
    assert result.returncode == 0, result.stdout[-5000:] + result.stderr


def test_action_observation_mapping_is_bound_to_current_action_bodies(tmp_path, monkeypatch):
    import telemetry_from_log as observation
    source = tmp_path / 'source.p4'
    body = ' md.committed = 1; '
    source.write_text('control n_Ingress() {}\ncontrol n_IgDeparser() {}\n'
        'control r_Egress() {}\ncontrol r_EgDeparser() {}\n'
        'control t_Ingress() { action release_ack_commit() {' + body + '} }\n'
        'control t_IngressDeparser() {}\n')
    mapping = tmp_path / 'observations.json'
    mapping.write_text(json.dumps({'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'actions': {'t_Ingress.release_ack_commit': ['event', 2]},
        'egress_results': {}, 'action_body_sha256': {
            't_Ingress.release_ack_commit': hashlib.sha256(body.encode()).hexdigest()}}))
    monkeypatch.setattr(observation, 'OBSERVATIONS', mapping)
    assert observation.verified_observations(source)['actions']
    changed = tmp_path / 'changed.p4'
    changed.write_text(source.read_text().replace('action release_ack_commit()',
                                                'action release_ack_commit_changed()', 1))
    import pytest
    with pytest.raises(ValueError, match='observation semantics need review'):
        observation.verified_observations(changed)


def test_t_configuration_has_only_current_fields_and_child():
    import t_config
    import sealed_profile
    assert t_config.t_units(dict(gap=5_000_000, budget=240_000, enabled=1)) == dict(
        gap=19534, budget=240_000, enabled=1)
    assert t_config.check_params(dict(gap=5_000_000, budget=240_000, enabled=1)) == []
    assert t_config.check_params(dict(gap=5_000_000, op_j=0, budget=240_000, enabled=1))
    assert sealed_profile.child_registers(dict(t_child_count=1)) == ('child_seen0_reg',)


def test_runtime_paths_do_not_reference_archived_module_locations():
    obsolete = ('ctl_timing_01/', 'seg61_01/', 'seg61_02/', 'response_only/', 'read_complete_01/')
    for path in MODEL.glob('*.py'):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and '\n' not in node.value:
                assert not any(prefix in node.value for prefix in obsolete), (path, node.lineno, node.value)


def test_model_provenance_rejects_a_replaced_compile_manifest(tmp_path, monkeypatch):
    import model_summary
    import record_closure
    import run_model
    build = tmp_path / 'candidate'
    (build / 'compile_local').mkdir(parents=True)
    manifest = build / 'compile_local/manifest.json'
    manifest.write_text('{"original_compile": true}\n')
    runs = tmp_path / 'runs'
    run = runs / 'model_smoke_candidate_01'
    run.mkdir(parents=True)
    monkeypatch.setattr(model_summary, 'model_root', lambda selected: runs)
    digest = model_summary._sha
    driver = run_model.DRIVERS['smoke']
    data = list(MODEL.glob('*.json')) + list((ROOT / 'tests/fixtures/vectors').glob('*.json'))
    files = {str(path.relative_to(ROOT)): digest(path) for path in [driver] + data}
    closure = run / 'dependency_closure.json'
    closure.write_text(json.dumps({'closure_version': record_closure.CLOSURE_VERSION, 'files': files}))
    retention = run / 'model_log_retention.json'
    retention.write_text('{}')
    libraries = [MODEL / 'action_observations.json', MODEL / 'model_driver.py',
                 ROOT / 'scripts/hardware/t_config.py']
    (run / 'launch_command.json').write_text(json.dumps({
        'dependency_closure_sha256': digest(closure), 'compile_manifest_sha256': digest(manifest),
        'model_log_retention_sha256': digest(retention),
        'library_sha256': {str(path.relative_to(ROOT)): digest(path) for path in libraries}}))
    record = {'run': run.name, 'driver': 'smoke', 'driver_sha256': digest(driver)}
    assert model_summary._closure_problems(build, record) == []
    manifest.write_text('{"replacement_compile": true}\n')
    assert 'launch does not bind the original compiled program manifest' in model_summary._closure_problems(build, record)


def test_qualifying_model_gate_does_not_inherit_coverage_reducing_diagnostics(tmp_path, monkeypatch):
    import run_model
    for name in ('CONTENTION_SECTIONS', 'POLICY_CASE', 'REPEAT_CYCLES', 'REPEAT_TIMED_CYCLES',
                 'ABANDON_T', 'CTL_CLOSURE_REPO', 'MODEL_SDE', 'MODEL_EXTRA', 'PYTHONPATH'):
        monkeypatch.setenv(name, 'diagnostic_override')
    env = run_model.gate_environment(tmp_path / 'inputs.json', {'milestone': 'current'},
                                    MODEL / 'model_repeat.py', tmp_path / 'out', '/sdk/9.13.2')
    assert 'CONTENTION_SECTIONS' not in env and 'POLICY_CASE' not in env and 'MODEL_EXTRA' not in env
    # abandon keeps its original T-disabled coverage (committed gate and c69); T-enabled is uncharacterized
    assert (env['REPEAT_CYCLES'], env['REPEAT_TIMED_CYCLES'], env['ABANDON_T']) == ('64', '3', '0')
    assert env['CTL_CLOSURE_REPO'] == str(ROOT)
    assert env['MODEL_SDE'] == '/sdk/9.13.2'
    assert 'PYTHONPATH' not in env


def test_independent_stream_splitter_retains_each_complete_frame():
    import dnp3_std
    import pad_oracle
    first = dnp3_std.frame(bytes.fromhex('0564084401000000'), b'\xc0\xc0\x81')
    second = dnp3_std.frame(bytes.fromhex('0564084401000000'), b'\xc1\xc1\x81')
    assert pad_oracle._split_frames(first + second) == [first, second]


def test_private_state_snapshot_uses_every_pinned_compiled_n_bank(tmp_path):
    import model_profile
    schema = tmp_path / 'compile_local/out/bfrt.json'
    schema.parent.mkdir(parents=True)
    schema.write_text(json.dumps({'tables': [
        {'name': 'p0.n_Ingress.application_state', 'table_type': 'Register', 'size': 1},
        {'name': 'p0.n_Ingress.retry_epoch', 'table_type': 'Register', 'size': 1},
        {'name': 'p0.n_Ingress.new_packed_bank', 'table_type': 'Register', 'size': 1},
        {'name': 'p0.n_Ingress.first_event', 'table_type': 'MatchAction_Direct', 'size': 401},
        {'name': 'p1.t_Ingress.gen_alloc_reg', 'table_type': 'Register', 'size': 1}]}))
    (tmp_path / 'response_only.inputs.json').write_text(json.dumps({'supported_profile': {'candidate': {
        'artifact_sha256': {'compile_local': {'bfrt.json': hashlib.sha256(schema.read_bytes()).hexdigest()}}}}}))
    assert model_profile.compiled_n_registers(tmp_path) == (
        'p0.n_Ingress.application_state', 'p0.n_Ingress.new_packed_bank', 'p0.n_Ingress.retry_epoch')
    schema.write_text('{"tables": []}')
    import pytest
    with pytest.raises(ValueError, match='pinned BFRT schema'):
        model_profile.compiled_n_registers(tmp_path)
