"""Every abort/restart delta uses the exact observed contract, preserving raw cell identities."""
import ast
from pathlib import Path

import pytest

DRIVER = Path(__file__).resolve().parents[1] / 'model_contention.py'
NO_J = 'response_ready_ack_d_no_j_v3'


def logic(contract):
    tree = ast.parse(DRIVER.read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    def selected(node, names):
        return isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in names
                                                    for target in node.targets)
    definitions = [node for node in tree.body if selected(node, {'NAMES', 'LANE', 'COMMITTED'})]
    selection = [node for node in main.body if selected(node, {'ready', 'names', 'out_indices', 'lane_keys', 'committed'})]
    namespace = dict(profile=dict(timing_contract=contract))
    exec(compile(ast.Module(body=definitions + selection, type_ignores=[]), str(DRIVER), 'exec'), namespace)
    deltas = [node for node in ast.walk(main) if selected(node, {'dt', 'dt2', 't_deltas'})]
    return namespace, deltas


def test_no_j_abort_and_restart_deltas_preserve_real_common_actions_without_J_keys():
    namespace, deltas = logic(NO_J)
    assert len(deltas) == 4  # initial abort, surviving response, restart, targeted restart
    before = {name: 0 for name in namespace['out_indices']}
    after = dict(before, ACK_COMMIT=1, RESP_RELEASE=1, OLD_EPOCH_DROP=1)
    namespace.update(t0=before, t1=after, t2=after, out0=before, out1=after)
    for node in deltas:
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(DRIVER), 'exec'), namespace)
        assert namespace[node.targets[0].id] == dict(ACK_COMMIT=1, RESP_RELEASE=1, OLD_EPOCH_DROP=1)
    assert set(namespace['names']) == set(namespace['out_indices'])
    assert 'OP_RELEASE' not in namespace['names'] and 'OP_DUP_DROP' not in namespace['names']
    assert {name: namespace['out_indices'][name] for name in
            ('ACK_COMMIT', 'RESP_RELEASE', 'REQ_DUP_DROP', 'REQ_DUP_FORWARD', 'OLD_EPOCH_DROP')} == {
        'ACK_COMMIT': 2, 'RESP_RELEASE': 3, 'REQ_DUP_DROP': 8, 'REQ_DUP_FORWARD': 9, 'OLD_EPOCH_DROP': 14}


@pytest.mark.parametrize('contract', [None, 'response_ready_ack_d_v2'])
def test_retained_contract_abort_deltas_keep_their_original_J_observation(contract):
    namespace, deltas = logic(contract)
    before = {name: 0 for name in namespace['out_indices']}
    after = dict(before, ACK_COMMIT=1, RESP_RELEASE=1, OP_RELEASE=1)
    namespace.update(t0=before, t1=after, t2=after, out0=before, out1=after)
    for node in deltas:
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(DRIVER), 'exec'), namespace)
        assert namespace[node.targets[0].id] == dict(ACK_COMMIT=1, RESP_RELEASE=1, OP_RELEASE=1)
    assert namespace['out_indices']['OP_RELEASE'] == 5
    assert namespace['out_indices']['OP_DUP_DROP'] == 16


def test_no_j_abort_still_refuses_an_unobserved_common_release_cell():
    namespace, deltas = logic(NO_J)
    before = {name: 0 for name in namespace['out_indices']}
    after = dict(before, ACK_COMMIT=1)
    del after['RESP_RELEASE']
    namespace.update(t0=before, t1=after)
    with pytest.raises(KeyError, match='RESP_RELEASE'):
        exec(compile(ast.Module(body=[deltas[0]], type_ignores=[]), str(DRIVER), 'exec'), namespace)
