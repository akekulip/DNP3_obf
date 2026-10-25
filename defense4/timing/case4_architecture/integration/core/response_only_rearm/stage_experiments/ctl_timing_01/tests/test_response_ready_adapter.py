"""The emitted-source scheduler uses the four-field ABI without double conversion."""
import subprocess
import sys

import contention_source as cs


def test_scheduler_installs_actual_response_ready_parameters(tmp_path):
    generator = cs.CTL.parent / 'm12_fullsize/make_m12.py'
    subprocess.run([sys.executable, str(generator), str(tmp_path), '--policy', '--c3', 'cimg',
                    '--shapes', 'passthrough', '--two-read', '--reduce', '--ack-retry',
                    '--read-handshake', '--headroom', '--relay', '--relay-sbo', '--relay-ts',
                    '--response-ready-timing'], check=True, capture_output=True)
    pipeline = cs.LapPipeline(tmp_path / 'response_only.p4', gap=20_000_000)
    try:
        action = pipeline.t.src.controls['Ingress'].actions['set_params'][0]
        assert [name for name, width in action] == [
            'gap', 'op_j', 'budget', 'enabled']
        assert pipeline.t_time == dict(unit_ns=256, grid_ns=512)
        runtime = pipeline.t.src.controls['Ingress'].tables['params']['runtime']
        assert len(runtime) == 1
        # Shared t_units adds the clock grid before rounding: no exchange-age duration is programmed.
        expected = cs.t_config.t_units(dict(gap=20_000_000, op_j=2_400_000,
            budget=240_000, enabled=1), **pipeline.t_time)
        assert list(expected.values()) in [list(entry[2]) for entry in runtime]
    finally:
        pipeline.close()


def test_runtime_writer_translates_only_bound_successor_and_converts_once(tmp_path, monkeypatch):
    import ast
    import json
    generator = cs.CTL.parent / 'm12_fullsize/make_m12.py'
    subprocess.run([sys.executable, str(generator), str(tmp_path), '--policy', '--c3', 'cimg',
                    '--shapes', 'passthrough', '--two-read', '--reduce', '--ack-retry',
                    '--read-handshake', '--headroom', '--relay', '--relay-sbo', '--relay-ts',
                    '--response-ready-timing'], check=True, capture_output=True)
    # Execute the real writer in isolation from the unavailable BFRT gRPC connection.
    driver = cs.CTL.parents[2] / 'model_driver.py'
    function = next(node for node in ast.parse(driver.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == 't_params_for_build')
    namespace = dict(__file__=str(driver))
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(driver), 'exec'), namespace)
    monkeypatch.setenv('PORT_MAP', str(tmp_path / 'response_only.inputs.json'))
    monkeypatch.setenv('OUT', str(tmp_path))
    supplied = dict(da=1000000, readiness=2000000000, cap=1500000000, pb=1000000000,
                    gap=20000000, op_j=2400000, budget=240000, enabled=1)
    actual = namespace['t_params_for_build'](supplied)
    values = dict(gap=20000000, op_j=2400000, budget=240000, enabled=1)
    assert actual == cs.t_config.t_units(values, unit_ns=256, grid_ns=512)
    record = json.loads((tmp_path / 't_params_written.json').read_text())[-1]
    assert record['supplied_ns'] == supplied
    assert record['values_ns'] == values
    assert record['written'] == actual
