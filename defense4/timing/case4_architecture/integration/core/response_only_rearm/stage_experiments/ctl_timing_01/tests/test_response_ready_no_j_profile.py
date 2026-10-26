"""No-J expectations require an explicit source-bound contract and absent J state."""
import hashlib
import sys
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CTL))
import model_profile

CONTRACT = 'response_ready_ack_d_no_j_v3'


def profile():
    return dict(reset_restart_required=True, t_child_count=1, endpoint_profile='sel751',
                timing_contract=CONTRACT, timing_ns=dict(D_release_budget=5_000_000),
                clock=dict(t_unit_ns=256, t_grid_ns=512))


def test_explicit_no_j_profile_translates_retained_stimuli_without_inventing_J():
    p = profile()
    model_profile.validate_timing_contract(p)
    supplied = dict(da=1, readiness=2, cap=3, pb=4, gap=20_000_000,
                    op_j=2_400_000, budget=240_000, enabled=1)
    assert model_profile.model_params(p, supplied) == dict(gap=20_000_000, budget=240_000, enabled=1)
    assert model_profile.model_params({}, supplied) == supplied
    with pytest.raises(ValueError):
        model_profile.model_params(p, dict(gap=20_000_000, enabled=1))
    with pytest.raises(ValueError):
        model_profile.model_params(p, dict(supplied, response_wait_timeout=500_000_000))


def test_no_j_profile_rejects_an_invented_J_timing():
    p = profile()
    p['timing_ns']['J_operate_hold'] = 2_400_000
    with pytest.raises(ValueError):
        model_profile.validate_timing_contract(p)


def test_compiled_no_j_audit_rejects_J_register_or_parameter_even_with_unique_banks():
    common = dict(name='t_Ingress.ack_done_reg', table_type='stateful',
                  stage_tables=[dict(stage_number=5)])
    assert model_profile.compiled_t_state_audit(dict(tables=[common]), CONTRACT)['problems'] == []
    for table in (
        dict(name='t_Ingress.op_t0_reg', table_type='stateful', stage_tables=[dict(stage_number=6)]),
        dict(name='t_Ingress.params', actions=[dict(name='t_Ingress.set_params',
             p4_parameters=[dict(name='op_j', bit_width=32)])]),
    ):
        assert model_profile.compiled_t_state_audit(dict(tables=[common, table]), CONTRACT)['problems']

import model_response_ready as ready
from test_response_ready_profile import point, retry_point


def no_j_point():
    p = point()
    p.update(timing_contract=CONTRACT, fc=4, request_relay_observed_before_response=True,
             request_admission_actions=['t_Ingress.admit_request'], wait_response_target_ns=10_000_000)
    p['response_arrival_units'] = 50_000
    p['ack_release_units'] = 50_002
    p['response_release_units'] = 75_000
    p['written_units'].pop('op_j')
    p['lane'].pop('OP_DUP_DROP')
    return p


def test_no_j_OPERATE_must_reach_relay_before_response_withheld_beyond_old_J():
    p = no_j_point()
    assert ready.no_j_operate_problems(p) == []
    for field, value in [('request_relay_observed_before_response', False),
                         ('request_arrival_units', None), ('response_arrival_units', 1500),
                         ('request_admission_actions', ['t_Ingress.hold_operate'])]:
        bad = dict(p, **{field: value})
        assert ready.no_j_operate_problems(bad)
    p['written_units']['op_j'] = 0
    assert ready.no_j_operate_problems(p)


@pytest.mark.parametrize('phase', ('waiting', 'response_D', 'after_release', 'disabled'))
def test_no_j_OPERATE_retries_use_common_generation_and_response_retention(phase):
    p = retry_point(phase)
    p.update(timing_contract=CONTRACT, fc=4)
    p['lane'].pop('OP_DUP_DROP')
    for key in ('op_generation_before', 'op_generation_after', 'operate_release_count'):
        p.pop(key, None)
    assert ready.retry_problems(p) == []
    p['generation_after'] += 1
    assert ready.retry_problems(p)

from test_response_ready_profile import child_results
import copy


def test_no_j_child_probes_require_common_state_and_reject_removed_roles():
    row = copy.deepcopy(child_results()['meta']['single_child_probes'][0])
    row['timing_contract'] = CONTRACT
    row.pop('operate_generation')
    for state in ('before', 'after', 'expected_after'):
        for register in ('op_gen_alloc_reg', 'op_t0_reg', 'op_done_reg'):
            row[state]['T'].pop(register)
    assert ready.child_ingress_problems(row) == []
    row['before']['T']['gen_alloc_reg']['f1'][0] += 1
    assert ready.child_ingress_problems(row)


def test_no_j_child_proof_cannot_invent_removed_operate_generation():
    row = copy.deepcopy(child_results()['meta']['single_child_probes'][0])
    row['timing_contract'] = CONTRACT
    assert ready.child_ingress_problems(row)

import json
import model_summary


def test_no_j_gate_keeps_all_seventeen_drivers(tmp_path):
    (tmp_path / 'supported_profile.json').write_text(json.dumps(profile()))
    assert model_summary.required_drivers(tmp_path) == model_summary.RELAY_REQUIRED + ('response_ready',)


def no_j_children():
    results = child_results()
    results['meta']['timing_contract'] = CONTRACT
    rows = results['meta']['single_child_probes']
    results['meta']['single_child_probes'] = [row for row in rows if row['role'] not in (13, 16)]
    for row in results['meta']['single_child_probes']:
        row['timing_contract'] = CONTRACT
        row.pop('operate_generation')
        for state in ('before', 'after', 'expected_after'):
            for register in ('op_gen_alloc_reg', 'op_t0_reg', 'op_done_reg'):
                row[state]['T'].pop(register)
    return results


def test_no_j_child_gate_requires_every_surviving_child_probe_without_J_state():
    results = no_j_children()
    assert len(results['meta']['single_child_probes']) == 17
    assert model_summary._single_child_problems(results) == []
    results['meta']['single_child_probes'].pop()
    assert model_summary._single_child_problems(results)


def obsolete_token_row():
    before = no_j_children()['meta']['single_child_probes'][0]['before']
    before['E']['acct'] = {'hi': [0], 'lo': [7]}
    frame = bytes.fromhex('0d0000090003a980') + bytes(60)
    return dict(name='role13_port182', before=before, after=copy.deepcopy(before), output_frames=0,
                stimulus_port=182, stimulus_frame_hex=frame.hex(),
                model_ingress=[dict(pipe=1, port=182, frame=(frame + bytes(4)).hex(), actions=[])])


def test_removed_OPERATE_tokens_need_actual_ingress_and_unchanged_state():
    row = obsolete_token_row()
    assert ready.removed_operate_token_problems(row) == []
    for changed in ({'model_ingress': []}, {'output_frames': 1}, {'after': {}},
                    {'model_ingress': [dict(row['model_ingress'][0], actions=['t_Ingress.seed_ack_blocker'])]}):
        assert ready.removed_operate_token_problems(dict(row, **changed))


def test_obsolete_token_drop_observation_does_not_mask_functional_state_mutation():
    row = obsolete_token_row()
    row['after']['T']['outcomes'][14] = 1
    row['model_ingress'][0]['actions'] = ['t_Ingress.drop_old_epoch']
    assert ready.removed_operate_token_problems(row) == []
    row['after']['T']['gen_alloc_reg']['f1'][0] = 10
    assert ready.removed_operate_token_problems(row)


@pytest.mark.parametrize('mutation', ('zero_frame', 'partial_state', 'wrong_generation', 'wrong_port', 'unknown_name'))
def test_obsolete_token_proof_rejects_unbound_format_and_partial_functional_state(mutation):
    row = obsolete_token_row()
    if mutation == 'zero_frame':
        row['stimulus_frame_hex'] = bytes(68).hex()
        row['model_ingress'][0]['frame'] = bytes(72).hex()
    elif mutation == 'partial_state':
        row['before'] = row['after'] = {'N': {'owner': 7}}
    elif mutation == 'wrong_generation':
        row['before']['T']['gen_alloc_reg']['f1'][0] += 1
        row['after'] = copy.deepcopy(row['before'])
    elif mutation == 'wrong_port':
        row['stimulus_port'] = row['model_ingress'][0]['port'] = 181
    else:
        row['name'] = 'unqualified_token'
    assert ready.removed_operate_token_problems(row)


import run_model


def test_obsolete_HB_port_exists_only_for_private_no_j_model_probes():
    inputs = dict(supported_profile=dict(timing_contract=CONTRACT, ports=dict(t_in=180, held_return=182)))
    assert '181' not in run_model.model_ports(inputs).split()
    assert '181' in run_model.model_ports(inputs, driver='response_ready').split()
    assert '181' in run_model.model_ports(inputs, driver='control_timing').split()
    assert '181' not in run_model.model_ports(inputs, driver='smoke').split()


@pytest.mark.parametrize('name,port,header', [
    ('role13_port181', 181, '0d0000090003a980'), ('role13_port182', 182, '0d0000090003a980'),
    ('role16_port181', 181, '1000000900000007'), ('role16_port182', 182, '1000000900000007'),
    ('app1', 196, '090100090000'), ('E101', 196, 'e10100090000000700000000000000000c000000'),
])
def test_each_removed_token_format_is_bound_to_live_common_state(name, port, header):
    row = obsolete_token_row()
    frame = bytes.fromhex(header) + bytes(60)
    row.update(name=name, stimulus_port=port, stimulus_frame_hex=frame.hex())
    row['model_ingress'] = [dict(pipe=1, port=port, frame=(frame + bytes(4)).hex(), actions=[])]
    assert ready.removed_operate_token_problems(row) == []
    altered = bytes((frame[0] ^ 1,)) + frame[1:]
    row['stimulus_frame_hex'] = altered.hex()
    row['model_ingress'][0]['frame'] = (altered + bytes(4)).hex()
    assert ready.removed_operate_token_problems(row)
