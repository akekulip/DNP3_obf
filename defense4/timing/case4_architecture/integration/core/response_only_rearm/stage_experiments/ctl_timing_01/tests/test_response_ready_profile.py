"""The new timing contract selects strict, source-bound model expectations."""
import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CTL))
import model_profile
import model_summary
import run_model


def successor(tmp_path):
    source = tmp_path / 'response_only.p4'
    source.write_text('''// timing_contract: response_ready_ack_d_v1
    action set_params(bit<32> gap, bit<32> op_j, bit<32> response_wait_timeout,
                      bit<32> budget, bit<32> enabled) {}
    action clock_sample() { md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe; }
    ''')
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    profile = dict(reset_restart_required=True, t_child_count=1,
                   candidate=dict(source_sha256=sha), endpoint_profile='sel751',
                   timing_contract='response_ready_ack_d_v1',
                   timing_ns=dict(D_release_budget=5000000, J_operate_hold=2400000,
                                  response_wait_timeout=500000000),
                   clock=dict(t_unit_ns=256, t_grid_ns=512))
    inputs = dict(source_sha256=sha, milestone='response_ready', supported_profile=profile)
    (tmp_path / 'response_only.inputs.json').write_text(json.dumps(inputs))
    return source, inputs


def test_response_ready_requires_seventeenth_compiled_driver(tmp_path):
    successor(tmp_path)
    assert model_summary.required_drivers(tmp_path) == model_summary.RELAY_REQUIRED + ('response_ready',)
    assert run_model.DRIVERS['response_ready'].name == 'model_response_ready.py'
    assert 'readiness' not in run_model.DRIVERS


@pytest.mark.parametrize('mutation', ['timeout', 'old_parameter', 'software', 'clock', 'unknown_contract'])
def test_contract_cannot_select_incompatible_semantics(tmp_path, mutation):
    source, inputs = successor(tmp_path)
    p = inputs['supported_profile']
    if mutation == 'timeout':
        p['timing_ns']['response_wait_timeout'] = 2000000000
    elif mutation == 'old_parameter':
        p['timing_ns']['readiness'] = 2000000000
    elif mutation == 'software':
        p['endpoint_profile'] = 'software'
    elif mutation == 'clock':
        p['clock']['t_unit_ns'] = 1
    else:
        p['timing_contract'] = 'unchecked'
    with pytest.raises(ValueError):
        model_profile.resolve(inputs, source)


def test_legacy_driver_translation_is_explicit_and_does_not_mask_expiry(tmp_path):
    source, inputs = successor(tmp_path)
    profile = model_profile.resolve(inputs, source)
    legacy = dict(da=1000000, readiness=2000000000, cap=1500000000,
                  pb=1000000000, gap=50000000, op_j=200000000, budget=240000, enabled=1)
    saved = copy.deepcopy(legacy)
    actual = model_profile.model_params(profile, legacy)
    assert actual == dict(gap=50000000, op_j=200000000,
                          response_wait_timeout=500000000, budget=240000, enabled=1)
    assert legacy == saved
    assert model_profile.model_params(dict(milestone='m10'), legacy) == legacy
    with pytest.raises(ValueError):
        model_profile.model_params(profile, dict(actual, mystery=1))
    with pytest.raises(ValueError):
        model_profile.model_params(profile, dict(actual, response_wait_timeout=2000000000))


def point():
    return dict(t0_units=1000, response_arrival_units=2000, ack_release_units=2002,
                order='ack_first', held_ack_units=1500, ack_arrival_ordinal=1, response_arrival_ordinal=2,
                response_release_units=22002,
                lane=dict(ACK_COMMIT=1, RESP_RELEASE=1, WAIT_EXPIRED=0, EXPIRED_DROP=0),
                master_frames=['ack', 'response'])


def test_clock_proof_accepts_full_D_crossing_expiry():
    from model_response_ready import committed_problems
    row = point()
    row.update(response_arrival_units=1900, ack_release_units=1999, response_release_units=21999)
    assert committed_problems(row, gap_units=20000, wait_units=1000) == []


@pytest.mark.parametrize('mutation', ('early_ack', 'short_D', 'expiry_race', 'extra_commit', 'wire_order', 'missing'))
def test_clock_proof_rejects_every_incomplete_causal_path(mutation):
    from model_response_ready import committed_problems
    row = point()
    if mutation == 'early_ack':
        row['response_arrival_units'] = 2003
    elif mutation == 'short_D':
        row['response_release_units'] -= 1
    elif mutation == 'expiry_race':
        row['ack_release_units'] = row['t0_units'] + 30000
    elif mutation == 'extra_commit':
        row['lane']['ACK_COMMIT'] = 2
    elif mutation == 'wire_order':
        row['master_frames'] = ['response', 'ack']
    else:
        row['t0_units'] = None
    assert committed_problems(row, gap_units=20000, wait_units=30000)


def test_bound_profile_cannot_mislabel_legacy_source(tmp_path):
    source, inputs = successor(tmp_path)
    source.write_text('legacy source')
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    inputs['source_sha256'] = inputs['supported_profile']['candidate']['source_sha256'] = sha
    with pytest.raises(ValueError):
        model_profile.resolve(inputs, source)


def test_new_gate_rejects_a_partial_positive_only_results_file():
    result = dict(meta=dict(timing_contract=model_profile.RESPONSE_READY, points=[]),
                  summary=dict(passed=1, total=1, failed=[]))
    assert model_summary._response_ready_problems(result)


def test_atomic_status_transition_timestamp_is_ingress_clock_not_egress_interleave():
    from model_response_ready import completion_transitions
    def line(text, pipe=1):
        return ':10-25 12:00:00.000001: :0x1:-:<0,%d,5>:%s\n' % (pipe, text)
    lines = [line('========== Ingress Pkt from port 182 =========='),
             line('global_tstamp[39:8] to value 0x1001'),
             line('----- register: t_Ingress.ack_done_reg -----'),
             line('Before stateful alu execution: 0x00000007'),
             line('========== Egress Pkt from TM to port 9 ==========', pipe=0),
             line('After stateful alu execution: 0x00020007')]
    assert completion_transitions(lines) == [dict(t_units=0x1000, before=7, after=0x20007)]


def test_successor_cannot_drop_the_full_invalid_child_matrix():
    assert model_summary._single_child_problems(dict(meta={}))


def test_successor_cannot_omit_generation_a_to_b_isolation():
    assert model_summary._generation_isolation_problems(dict(meta=dict(points=[])))


def child_proof_results():
    names = {'N': ('owner', 'epoch', 'client', 'server'),
             'E': ('epoch', 'mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend'),
             'T': ('cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg', 't0_reg', 'op_t0_reg',
                   'ack_done_reg', 'resp_done_reg', 'op_done_reg', 'child_seen0_reg',
                   'ack_commit_at_reg', 'ack_commit_gen_reg')}
    before = {domain: {name: {'f1': [7]} for name in registers} for domain, registers in names.items()}
    before['T']['outcomes'] = [0] * 25
    cases = [('response', None, child) for child in (1, 2, 255)] + [
        ('held', role, child) for role in (14, 15, 16) for child in (1, 2, 255)] + [
        ('blocker', role, child) for role in (11, 12, 13) for child in (0, 1, 2, 255)]
    rows = []
    for kind, role, child in cases:
        after = copy.deepcopy(before)
        if kind == 'blocker' and child == 0:
            after['T']['outcomes'][12] += 1
        rows.append(dict(kind=kind, role=role, child=child, policy_off=kind == 'blocker',
            epoch=7, read_generation=9, operate_generation=10, before=copy.deepcopy(before),
            expected_after=copy.deepcopy(after), after=after, output_frames=0))
    return dict(meta=dict(single_child_probes=rows))


def test_full_child_matrix_has_independent_positive_and_negative_controls():
    assert model_summary._single_child_problems(child_proof_results()) == []


@pytest.mark.parametrize('mutation', ('missing_response', 'missing_held', 'missing_blocker', 'missing_positive',
    'N_mutation', 'E_mutation', 'T_mutation', 'outcome_mutation', 'missing_register', 'removed_register',
    'output', 'not_live', 'no_positive_effect'))
def test_child_gate_rejects_coverage_loss_and_every_observable_mutation(mutation):
    result = child_proof_results()
    rows = result['meta']['single_child_probes']
    if mutation.startswith('missing_') and mutation in ('missing_response', 'missing_held', 'missing_blocker', 'missing_positive'):
        kind = {'missing_response': 'response', 'missing_held': 'held',
                'missing_blocker': 'blocker', 'missing_positive': 'blocker'}[mutation]
        row = next(row for row in rows if row['kind'] == kind and
                   (mutation != 'missing_positive' or row['child'] == 0))
        rows.remove(row)
    elif mutation in ('N_mutation', 'E_mutation', 'T_mutation'):
        domain = mutation[0]
        register = next(key for key in rows[0]['after'][domain] if key != 'outcomes')
        rows[0]['after'][domain][register]['f1'][0] += 1
    elif mutation == 'outcome_mutation':
        rows[0]['after']['T']['outcomes'][2] += 1
    elif mutation == 'missing_register':
        rows[0]['before']['T'].pop('ack_done_reg')
    elif mutation == 'removed_register':
        rows[0]['before']['T']['ack_seen_reg'] = {'f1': [7]}
    elif mutation == 'output':
        rows[0]['output_frames'] = 1
    elif mutation == 'not_live':
        rows[0]['operate_generation'] = 0
    else:
        row = next(row for row in rows if row['kind'] == 'blocker' and row['child'] == 0)
        row['expected_after'] = copy.deepcopy(row['before'])
        row['after'] = copy.deepcopy(row['before'])
    assert model_summary._single_child_problems(result)


def generation_point(kind, phase):
    row = point()
    row.update(tag='generation_A_%s_%s_B' % (kind, phase), generation_before=8, generation_after=9, epoch=7,
               written_units=dict(gap=78127, op_j=9377, response_wait_timeout=1953127, budget=240000, enabled=1),
               response_release_units=80129, atomic_commit_units=[2002], atomic_expiry_units=[],
               stale_probe=dict(kind=kind, phase=phase, source_generation=8,
                   source_epoch=6 if kind == 'expired_token' else 7,
                   ingress_ordinal=2 if phase == 'waiting' else 5,
                   ingress_t_units=1500 if phase == 'waiting' else 3000,
                   held_ack_ordinal=1, response_arrival_ordinal=3, ack_commit_ordinal=4,
                   response_release_ordinal=9, source_tag='A_' + kind + '_' + phase, frame_hex='aabb'))
    row['lane_registers'] = {name: [dict(t_units=2002, before=value, after=value)] for name, value in
                            (('t0_reg', 1000), ('gen_alloc_reg', 9), ('cur_epoch_reg', 7),
                             ('ack_commit_at_reg', 2002), ('ack_commit_gen_reg', 9))}
    row['ack_state_transitions'] = [dict(t_units=1000, before=0x10008, after=9),
                                    dict(t_units=2002, before=9, after=0x10009)]
    return row


@pytest.mark.parametrize('kind', ('late_ACK', 'stale_response', 'expired_token'))
@pytest.mark.parametrize('phase', ('waiting', 'committed'))
def test_generation_proof_accepts_only_actual_a_ingress_during_b_phase(kind, phase):
    from model_response_ready import generation_isolation_problems
    assert generation_isolation_problems(generation_point(kind, phase)) == []


@pytest.mark.parametrize('mutation', ('wrong_generation', 'extra_allocation', 'not_observed', 'wrong_phase',
    'no_new_epoch', 'missing_token_clock', 'early_commit', 'short_D', 'early_expiry',
    't0_corrupted', 'generation_corrupted', 'epoch_corrupted', 'commit_clock_corrupted',
    'commit_generation_corrupted', 'transient_completion_corruption'))
def test_generation_proof_rejects_stale_a_effects_and_unmeasured_constructions(mutation):
    from model_response_ready import generation_isolation_problems
    row = generation_point('expired_token', 'committed')
    probe = row['stale_probe']
    if mutation == 'wrong_generation':
        probe['source_generation'] = 9
    elif mutation == 'extra_allocation':
        row['generation_before'] = 7
    elif mutation == 'not_observed':
        probe['ingress_ordinal'] = None
    elif mutation == 'wrong_phase':
        probe['ingress_ordinal'] = 10
    elif mutation == 'no_new_epoch':
        probe['source_epoch'] = 7
    elif mutation == 'missing_token_clock':
        probe['ingress_t_units'] = None
    elif mutation == 'early_commit':
        row['ack_release_units'] = 1999
    elif mutation == 'short_D':
        row['response_release_units'] -= 1
    elif mutation == 'early_expiry':
        row['atomic_expiry_units'] = [1500]
    elif mutation == 'transient_completion_corruption':
        row['ack_state_transitions'].insert(1, dict(t_units=1500, before=9, after=0x20009))
    else:
        name = {'t0_corrupted': 't0_reg', 'generation_corrupted': 'gen_alloc_reg',
                'epoch_corrupted': 'cur_epoch_reg', 'commit_clock_corrupted': 'ack_commit_at_reg',
                'commit_generation_corrupted': 'ack_commit_gen_reg'}[mutation]
        row['lane_registers'][name][0]['after'] += 1
    assert generation_isolation_problems(row)


def generation_results():
    points = []
    for kind in ('late_ACK', 'stale_response', 'expired_token'):
        for phase in ('waiting', 'committed'):
            row = generation_point(kind, phase)
            old = point()
            old.update(tag=row['stale_probe']['source_tag'], generation_after=8,
                       epoch=row['stale_probe']['source_epoch'],
                       written_units=copy.deepcopy(row['written_units']), response_release_units=80129,
                       artifacts=dict(ack='aa01', response='bb02', token='0b00000800000004aabb'))
            if kind == 'expired_token':
                old.update(master_frames=[], atomic_expiry_units=[1954127],
                           lane=dict(ACK_COMMIT=0, RESP_RELEASE=0, WAIT_EXPIRED=1, EXPIRED_DROP=0))
                provenance = source_token_fixture()
                old['artifacts'].update(provenance['artifacts'])
                old['token_source'] = provenance['token_source']
            row['stale_probe']['frame_hex'] = old['artifacts'][
                {'late_ACK': 'ack', 'stale_response': 'response', 'expired_token': 'token'}[kind]]
            points.extend((old, row))
    return dict(meta=dict(points=points))


def test_generation_gate_requires_complete_matrix_with_actual_a_provenance():
    assert model_summary._generation_isolation_problems(generation_results()) == []


@pytest.mark.parametrize('mutation', ('missing_case', 'duplicate_case', 'wrong_artifact', 'wrong_token_generation',
                                    'not_expired', 'premature_expiry', 'missing_source_A'))
def test_generation_gate_rejects_partial_or_unbound_a_to_b_cases(mutation):
    result = generation_results()
    points = result['meta']['points']
    row = next(point for point in points if point['tag'] == 'generation_A_expired_token_committed_B')
    old = next(point for point in points if point['tag'] == row['stale_probe']['source_tag'])
    if mutation == 'missing_case':
        points.remove(row)
    elif mutation == 'duplicate_case':
        points.append(copy.deepcopy(row))
    elif mutation == 'wrong_artifact':
        row['stale_probe']['frame_hex'] += 'ff'
    elif mutation == 'wrong_token_generation':
        row['stale_probe']['frame_hex'] = old['artifacts']['token'] = '0b00000900000004aabb'
    elif mutation == 'not_expired':
        old['lane']['WAIT_EXPIRED'] = 0
    elif mutation == 'premature_expiry':
        old['atomic_expiry_units'] = [1954126]
    else:
        points.remove(old)
    assert model_summary._generation_isolation_problems(result)


@pytest.mark.parametrize('order,ack,response,ack_ordinal,response_ordinal,accepted', [
    ('ack_first', 100, 101, 1, 2, True),
    ('response_first', 101, 100, 2, 1, True),
    ('ack_first', 101, 100, 1, 2, False),
    ('response_first', 100, 101, 2, 1, False),
    ('ack_first', 100, 100, 1, 2, True),
    ('response_first', 100, 100, 2, 1, True),
    ('ack_first', 100, 100, 2, 1, False),
    ('response_first', 100, 100, 1, 2, False),
    ('ack_first', (1 << 32) - 1, 0, 1, 2, True),
])
def test_declared_arrival_order_requires_actual_t_clock_and_tie_breaking_ordinal(
        order, ack, response, ack_ordinal, response_ordinal, accepted):
    from model_response_ready import arrival_order_problems
    row = dict(order=order, held_ack_units=ack, response_arrival_units=response,
               ack_arrival_ordinal=ack_ordinal, response_arrival_ordinal=response_ordinal)
    assert (arrival_order_problems(row) == []) == accepted


def test_gate_cannot_fill_response_first_coverage_with_an_ack_first_observation():
    row = point()
    row.update(tag='D5_response_first_mixed', native_octets=91, image_octets=141,
               written_units=dict(gap=19534, op_j=9377, response_wait_timeout=1953127, budget=240000, enabled=1))
    problems = model_summary._response_ready_problems(dict(meta=dict(points=[row])))
    assert any('D5_response_first_mixed: observed order does not match required response_first' in problem
               for problem in problems)


def test_legitimate_post_release_replay_has_one_replay_and_no_second_growth_or_t_commit():
    from model_response_ready import post_release_replay_problems
    row = dict(exact_frame=True, output_frames=1, encoding_delta=dict(commit=0, replay=1, growth=0),
               lane_delta=dict(ACK_COMMIT=0, RESP_RELEASE=0, WAIT_EXPIRED=0, EXPIRED_DROP=0),
               primary_release_units=1000, replay_arrival_units=1001)
    assert post_release_replay_problems(row) == []
    for field, key in (('encoding_delta', 'commit'), ('encoding_delta', 'growth'), ('lane_delta', 'ACK_COMMIT'),
                       ('lane_delta', 'RESP_RELEASE'), ('lane_delta', 'WAIT_EXPIRED')):
        bad = copy.deepcopy(row)
        bad[field][key] += 1
        assert post_release_replay_problems(bad)


def test_valid_model_timer_is_derived_from_actual_read_clone_generation():
    import struct
    from model_response_ready import timer_from_read_seed
    seed = bytes.fromhex('e1000007') + struct.pack('!IIIBBH', 9, 0, 0, 9, 0, 0) + b'original request'
    calls = []
    def builder(**kwargs):
        calls.append(kwargs)
        return bytes.fromhex('080000070000') + bytes(58)
    buffer = bytes.fromhex('000000000800') + bytes(54)
    assert timer_from_read_seed(seed, builder, buffer) == bytes.fromhex('080000070000') + buffer
    assert calls == [dict(gen=7, packet_id=0, profile=0, pipe=1)]
    for bad in (bytes(20), seed[:16] + b'\x0c' + seed[17:], seed[:2] + b'\xff\xff' + seed[4:]):
        with pytest.raises(ValueError):
            timer_from_read_seed(bad, builder, buffer)


def test_gate_requires_legitimate_replay_after_normal_duplicate_delivery():
    row = point()
    row.update(tag='duplicate_ack_response', written_units=dict(gap=19534, response_wait_timeout=1953127))
    problems = model_summary._response_ready_problems(dict(meta=dict(points=[row])))
    assert any('duplicate_ack_response: missing post-release replay proof' in problem for problem in problems)


def test_expired_a_blocker_requires_compiled_source_provenance():
    from model_response_ready import token_source_problems
    assert token_source_problems(dict(artifacts=dict(token='0b00000800000004aabb')))



def source_token_fixture():
    import struct
    buffer = bytes.fromhex('000000000800') + bytes(54)
    seed = bytes.fromhex('e1000008') + struct.pack('!IIIBBH', 6, 0, 0, 9, 0, 0) + b'original request'
    timer = bytes.fromhex('080000080000') + buffer
    timer_ingress = timer + bytes(4)
    blocker = struct.pack('!BBHI', 11, 0, 8, 240000) + timer_ingress[6:]
    return dict(generation_after=8, t0_units=1000, atomic_expiry_units=[1954127],
        artifacts=dict(seed=seed.hex(), token=blocker.hex()),
        token_source=dict(seed_frame_hex=seed.hex(), timer_frame_hex=timer.hex(),
            timer_ingress_frame_hex=timer_ingress.hex(), blocker_frame_hex=blocker.hex(),
            source_action='t_Ingress.seed_ack_blocker', timer_port=196, blocker_port=182,
            source_t_units=1954200, blocker_t_units=1954300, state_after=0x20008,
            lane_delta=dict(ACK_COMMIT=0, RESP_RELEASE=0, WAIT_EXPIRED=0)))


def test_source_produced_stale_blocker_has_complete_model_provenance():
    from model_response_ready import token_source_problems
    assert token_source_problems(source_token_fixture()) == []


@pytest.mark.parametrize('mutation', ('seed', 'timer_batch', 'timer_app', 'timer_child', 'blocker_role',
                                    'blocker_body', 'source_action', 'source_port', 'blocker_port',
                                    'source_before_expiry', 'blocker_before_source', 'reopened', 'extra_commit'))
def test_source_produced_blocker_gate_rejects_forged_or_unmeasured_artifacts(mutation):
    from model_response_ready import token_source_problems
    point = source_token_fixture()
    source = point['token_source']
    if mutation == 'seed':
        point['artifacts']['seed'] = 'ffff' + point['artifacts']['seed'][4:]
    elif mutation in ('timer_batch', 'timer_app', 'timer_child'):
        raw = bytearray.fromhex(source['timer_frame_hex'])
        raw[{'timer_batch': 3, 'timer_app': 0, 'timer_child': 5}[mutation]] += 1
        source['timer_frame_hex'] = raw.hex()
    elif mutation in ('blocker_role', 'blocker_body'):
        raw = bytearray.fromhex(source['blocker_frame_hex'])
        raw[0 if mutation == 'blocker_role' else 20] += 1
        source['blocker_frame_hex'] = point['artifacts']['token'] = raw.hex()
    elif mutation == 'source_action':
        source['source_action'] = 'constructed header'
    elif mutation == 'source_port':
        source['timer_port'] = 182
    elif mutation == 'blocker_port':
        source['blocker_port'] = 196
    elif mutation == 'source_before_expiry':
        source['source_t_units'] = 1954126
    elif mutation == 'blocker_before_source':
        source['blocker_t_units'] = 1954199
    elif mutation == 'reopened':
        source['state_after'] = 8
    else:
        source['lane_delta']['ACK_COMMIT'] = 1
    assert token_source_problems(point)


def test_compiled_t_state_requires_one_physical_stage_per_logical_register():
    context = dict(tables=[dict(name='t_Ingress.ack_done_reg', table_type='stateful',
                               stage_tables=[dict(stage_number=5)]),
                           dict(name='t_Ingress.resp_done_reg', table_type='stateful',
                                stage_tables=[dict(stage_number=7), dict(stage_number=8)])])
    audit = model_profile.compiled_t_state_audit(context)
    assert audit['banks_by_register']['t_Ingress.resp_done_reg'] == [7, 8]
    assert any('resp_done_reg' in problem and '[7, 8]' in problem for problem in audit['problems'])
    context['tables'][1]['stage_tables'] = [dict(stage_number=7)]
    assert model_profile.compiled_t_state_audit(context)['problems'] == []


@pytest.mark.parametrize('context', ({}, dict(tables=[]), dict(tables=[dict(
    name='t_Ingress.resp_done_reg', table_type='stateful', stage_tables=[])])))
def test_compiled_t_state_cannot_qualify_absent_or_unplaced_registers(context):
    assert model_profile.compiled_t_state_audit(context)['problems']


def test_source_blocker_preserves_actual_ingress_timer_payload_including_model_trailer():
    from model_response_ready import token_source_problems
    point = source_token_fixture()
    source = point['token_source']
    assert len(bytes.fromhex(source['timer_frame_hex'])) == 66
    assert len(bytes.fromhex(source['timer_ingress_frame_hex'])) == 70
    assert len(bytes.fromhex(source['blocker_frame_hex'])) == 72
    assert token_source_problems(point) == []
    source['timer_ingress_frame_hex'] = source['timer_ingress_frame_hex'][:-2] + '01'
    assert token_source_problems(point)
