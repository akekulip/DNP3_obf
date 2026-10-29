"""E4b select-only plan in the receiver checkers (generated captures; no historical capture dependency).

A planned OPERATE count of 0 is accepted only when the config declares traffic.sbo_select_only true. In that plan any
OPERATE (a master record or a request in the captured master stream) fails, and every SELECT must carry CROB SUCCESS
decoded from the captured bytes. Normal plans are unchanged: the golden values were recorded from commit ca0db02d1,
before the select-only path existed.
"""
import copy
import hashlib
import json
import struct

from pathlib import Path

import pytest

from scripts.checks import checks, relay_check, standards
from fixtures import control, conversation, link, packet, pcap

INTEGRITY_REQUEST = bytes([60, 2, 6, 60, 3, 6, 60, 4, 6, 60, 1, 6])
INTEGRITY_RESPONSE = (bytes([1, 2, 0, 0, 15]) + b'\x01' * 16 + bytes([10, 2, 0, 0, 31]) + b'\x01' * 32 +
                      bytes([30, 4, 0, 0, 20]) + struct.pack('<h', 7) * 21)
PORT = 59410
ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / 'results/hardware/campaigns/rc01_hw_c72_20261027_02/configs/02_d5_reference.json'
# Recorded from ca0db02d1 (sha256 of json.dumps with the generated directory replaced by <D>).
GOLDEN = {'standards_artifact_wo_checker': '965edafc66106437b03275692dd87447b5bea053be320794c03954a6c3c5636e',
          'standards_verdict': '264a0718b902377a222ea6a1fe5fddd10675476f04d310bfb8c8e8f441e6b980',
          'relay_check_report': 'a40cd708583c32e4962c65ab344b83d39ce9551040dc310d46bfca8a94a914f9',
          'standards_expected_ref': '2f3884e5396bd8cecd0c6872b36f6a1414f76dc6e2aee6966cbf73afb5bfdb40',
          'standards_expected_nosbo': '7d28a28fa72d4ab88196e39832352f8897766902ebd1a493904a0744f437e19b',
          'standards_expected_one': '7546f65d3a6a90ad35928c844a490eeac87c231856168b866eedcedae670877d'}


def h(value):
    return hashlib.sha256(json.dumps(value, default=str).encode()).hexdigest()


def read(seq):
    """A native integrity READ request and its 134-octet relay response."""
    app = bytes([0xc0 | seq, 1]) + INTEGRITY_REQUEST
    response = bytes([0xc0 | seq, 0x81, 0, 0]) + INTEGRITY_RESPONSE
    return link(b'\xc0' + app, request=True), [link(b'\xc0' + response)], app, response


def select_only_conversation(root, steps=('SELECT', 'READ', 'SELECT', 'READ'), select_status=0, wire_only=(),
                             master_flag=True):
    """A select-only connection on the full schedule. steps name the requests in wire order; indexes in wire_only are
    sent and answered on the wire but left out of the master records."""
    root.mkdir(exist_ok=True)
    outgoing = [(1, packet(True, 100, 0, 2)), (3, packet(True, 101, 201, 16))]
    incoming = [(2, packet(False, 200, 101, 18))]
    records, tx, rx = [], 101, 201
    for index, operation in enumerate(steps):
        seq = index & 15
        if operation == 'READ':
            request, frames, request_app, response_app = read(seq)
            points = []
        else:
            status = select_status if operation == 'SELECT' else 0
            request, _, request_app, _ = control(operation, seq, 0, padded=False)
            _, frames, _, response_app = control(operation, seq, status, padded=False)
            points = [[point, 'SUCCESS' if status == 0 else 'TIMEOUT'] for point in (1, 3)]
        response = b''.join(frames)
        if index not in wire_only:
            record = dict(operation=operation, outcome='OK' if not points or points[0][1] == 'SUCCESS' else 'INVALID',
                          local_address=['192.168.10.1', PORT], peer_address=['192.168.10.7', 20000],
                          request_wire_hex=request.hex(), request_frames_hex=[request.hex()],
                          request_app_hex=request_app.hex(), response_wire_hex=response.hex(),
                          response_frames_hex=[frame.hex() for frame in frames], response_app_hex=response_app.hex(),
                          points=points)
            if operation == 'READ':
                record['workload'] = 'integrity'
            records.append(record)
        timestamp = 10 + index * 20
        outgoing.append((timestamp, packet(True, tx, rx, 24, request)))
        tx += len(request)
        incoming.append((timestamp + 1, packet(False, rx, tx, 16)))
        incoming.append((timestamp + 2, packet(False, rx, tx, 24, response)))
        rx += len(response)
    counts = {name: sum(r['operation'] == name and r['outcome'] == 'OK' for r in records)
              for name in ('READ', 'SELECT', 'OPERATE')}
    planned = dict(READ=steps.count('READ'), SELECT=steps.count('SELECT'), OPERATE=0)
    master = dict(ok=counts == planned, counts=counts, planned=planned, records=records)
    if master_flag:
        master['sbo_select_only'] = True
    for name, value in [('master.json', master), ('result.json', {'tcpdump': {
            'out': {'dropped_kernel': 0}, 'in': {'dropped_kernel': 0}}}),
                        ('capture_offloads.json', {'restore_ok': True}), ('relay_wire.json', {})]:
        (root / name).write_text(json.dumps(value))
    pcap(root / 'out.pcap', outgoing)
    pcap(root / 'in.pcap', incoming)
    return {key: {'path': str(root / filename)} for key, filename in standards.SEL751_CAPTURE_FILES.items()}


PLAN = dict(READ=2, SELECT=2, OPERATE=0)


def select_only_expected():
    return dict(counts=dict(PLAN), read_schedule='full', read_classes={'integrity': {'count': 2, 'image': 134}},
                padded=False, select_only=True)


def select_only_context(select_only=True):
    arm = dict(name='combined', build='current', padding=0, T=1)
    traffic = dict(run_sbo=True, sbo_cycles=2, read_schedule='full')
    if select_only:
        traffic['sbo_select_only'] = True
    return dict(config=dict(endpoint_profile='sel751', arms=[arm], traffic=traffic, builds={'current': dict(
                    profile='current_sel751', hashes={'p0/tofino.bin': 'a' * 64})}), arm=arm,
                run_id='synthetic_select_only', connection_id='single', master_port=PORT,
                trial=dict(label='select_only', reads=2), candidate_source_sha256='b' * 64,
                checker_files=[standards.__file__, relay_check.__file__, checks.__file__])


# ------------------------------------------------------------------------------------------------ plan derivation
def test_planned_controls_are_pairs_unless_select_only_is_declared():
    assert checks.planned_controls({}) == dict(SELECT=1, OPERATE=1)
    assert checks.planned_controls(dict(run_sbo=True, sbo_cycles=64)) == dict(SELECT=64, OPERATE=64)
    assert checks.planned_controls(dict(run_sbo=False)) == dict(SELECT=0, OPERATE=0)
    assert checks.planned_controls(dict(run_sbo=True, sbo_cycles=4, sbo_select_only=True)) == dict(SELECT=4, OPERATE=0)
    assert checks.sbo_select_only({}) is False
    assert checks.sbo_select_only(dict(sbo_cycles=4, sbo_select_only=True)) is True


@pytest.mark.parametrize('traffic', [dict(sbo_cycles=4, sbo_select_only=False), dict(sbo_cycles=4, sbo_select_only=1),
                                     dict(sbo_cycles=4, sbo_select_only='true'), dict(sbo_select_only=True),
                                     dict(run_sbo=False, sbo_cycles=4, sbo_select_only=True)])
def test_a_select_only_declaration_that_is_not_explicit_and_complete_is_refused(traffic):
    with pytest.raises(ValueError, match='sbo_select_only'):
        checks.planned_controls(traffic)


def test_standards_expected_counts_carry_an_explicit_zero_operate_only_for_select_only():
    assert standards.expected_counts(select_only_context()) == dict(READ=2, SELECT=2, OPERATE=0)
    assert standards.expected_counts(select_only_context(False)) == dict(READ=2, SELECT=2, OPERATE=2)
    expected = standards._sel751_expected(select_only_context())
    assert expected['select_only'] is True and expected['planned_exchanges'] == 4
    assert expected['lengths'] == {'READ': [134], 'SELECT': [49]}
    assert 'select_only' not in standards._sel751_expected(select_only_context(False))


# ------------------------------------------------------------------------------------------------ switch counters
K = 2
EXP = {'mirror_fix': {'T0': {'zero_triggers': ['READ', 'OPERATE']}}}


def snapshot(triggers):
    loop = {role: {'$OctetsReceived': 1000, '$OctetsReceivedinGoodFrames': 1000} for role in checks.LOOP_ROLES}
    return {'loop_ports': loop, 'pktgen': {'READ': {'trigger_counter': triggers, 'pkt_counter': 2 * K * triggers}}}


def switch(lane, operate_count=None, T=1):
    kwargs = {} if operate_count is None else dict(operate_count=operate_count)
    return checks.evaluate_switch(EXP, {'T': T, 'padding': 1}, 20, {'before': snapshot(0), 'after': snapshot(lane)},
                                  mirror_k=K, sbo_count=4, timing_contract=checks.NO_J_CONTRACT, **kwargs)


def test_select_only_switch_lane_counts_reads_and_selects_only():
    assert switch(20 + 4, operate_count=0)[0] == []
    fails, _ = switch(20 + 2 * 4, operate_count=0)
    assert any('READ trigger delta 28, expected 24' in f for f in fails), fails


def test_switch_lane_without_operate_count_is_unchanged():
    assert switch(20 + 2 * 4)[0] == []
    assert switch(20 + 2 * 4, operate_count=4)[0] == []
    assert any('expected 28' in f for f in switch(24)[0])
    assert switch(0, operate_count=0, T=0)[0] == []


# ------------------------------------------------------------------------------------------------ relay_check
def test_select_only_master_and_wire_pass_only_with_the_explicit_plan(tmp_path):
    select_only_conversation(tmp_path)
    master = json.loads((tmp_path / 'master.json').read_text())
    assert relay_check.master_checks(master, PORT, PLAN, 'full', select_only=True) == []
    report = relay_check.analyze(tmp_path, PORT, PLAN, 'full', select_only=True)
    assert report['failures'] == [] and report['ok'], report['failures']
    assert [row['operation'] for row in report['exchanges']] == ['SELECT', 'READ', 'SELECT', 'READ']
    assert [row['application']['points'] for row in report['exchanges'] if row['operation'] == 'SELECT'] == \
        [[[1, 'SUCCESS'], [3, 'SUCCESS']]] * 2
    unflagged = relay_check.master_checks(master, PORT, PLAN, 'full')
    assert any('without an explicit select-only plan' in f for f in unflagged), unflagged


def test_select_only_plan_needs_the_master_to_have_run_select_only(tmp_path):
    select_only_conversation(tmp_path, master_flag=False)
    master = json.loads((tmp_path / 'master.json').read_text())
    findings = relay_check.master_checks(master, PORT, PLAN, 'full', select_only=True)
    assert any('select-only' in f for f in findings), findings


def test_a_normal_master_claiming_select_only_fails(tmp_path):
    conversation(tmp_path)
    master = json.loads((tmp_path / 'master.json').read_text())
    master['sbo_select_only'] = True
    findings = relay_check.master_checks(master, PORT, dict(READ=0, SELECT=1, OPERATE=1), 'full')
    assert any('select-only' in f for f in findings), findings


def test_an_operate_request_on_the_wire_fails_the_select_only_plan(tmp_path):
    select_only_conversation(tmp_path, steps=('SELECT', 'OPERATE', 'READ', 'SELECT', 'READ'), wire_only=(1,))
    master = json.loads((tmp_path / 'master.json').read_text())
    assert relay_check.master_checks(master, PORT, PLAN, 'full', select_only=True) == []   # the records look fine
    report = relay_check.analyze(tmp_path, PORT, PLAN, 'full', select_only=True)
    assert not report['ok']
    assert any('select-only plan: 1 OPERATE request(s) in the captured master stream' in f
               for f in report['failures']), report['failures']


def test_a_recorded_operate_fails_the_select_only_plan(tmp_path):
    select_only_conversation(tmp_path, steps=('SELECT', 'OPERATE', 'READ', 'SELECT', 'READ'))
    report = relay_check.analyze(tmp_path, PORT, PLAN, 'full', select_only=True)
    assert not report['ok']
    assert any('denominators' in f for f in report['failures'])
    assert any('OPERATE request(s) in the captured master stream' in f for f in report['failures'])


@pytest.mark.parametrize('plan', [dict(READ=2, SELECT=2, OPERATE=2), dict(READ=2, SELECT=0, OPERATE=0)])
def test_select_only_plan_itself_must_be_selects_with_zero_operate(tmp_path, plan):
    select_only_conversation(tmp_path)
    master = json.loads((tmp_path / 'master.json').read_text())
    findings = relay_check.master_checks(master, PORT, plan, 'full', select_only=True)
    assert any('select-only plan' in f for f in findings), findings


def test_relay_check_cli_derives_the_select_only_plan(tmp_path):
    select_only_conversation(tmp_path)
    argv = [str(tmp_path), '--master-port', str(PORT), '--reads', '2', '--sbo', '2', '--read-schedule', 'full']
    import contextlib
    import io
    with contextlib.redirect_stdout(io.StringIO()):
        assert relay_check.main(argv + ['--select-only']) == 0
        assert relay_check.main(argv) == 1


def test_normal_relay_check_report_is_byte_identical(tmp_path):
    root = tmp_path / 'c'
    conversation(root)
    report = relay_check.analyze(root, PORT, dict(READ=0, SELECT=1, OPERATE=1), 'full')
    assert h(json.loads(json.dumps(report).replace(str(root), '<D>'))) == GOLDEN['relay_check_report']


# ------------------------------------------------------------------------------------------------ standards
def test_select_only_observed_verdict_passes_with_select_success_and_no_operate(tmp_path):
    captures = select_only_conversation(tmp_path)
    observed = standards._sel751_observed({'master_port': PORT}, captures, select_only_expected())
    assert observed['aggregate_verdict'] is True, observed
    assert observed['select_authorizes_operate'] is True and observed['operate_absent'] is True
    assert 'operate_success' not in observed
    assert observed['exchanges']['SELECT'] == dict(count=2, ok=2, resp_len=[49])
    assert observed['exchanges']['READ:integrity'] == dict(count=2, ok=2, resp_len=[134])


@pytest.mark.parametrize('wire_only', [(), (1,)])
def test_select_only_observed_verdict_fails_on_any_operate(tmp_path, wire_only):
    captures = select_only_conversation(tmp_path, steps=('SELECT', 'OPERATE', 'READ', 'SELECT', 'READ'),
                                        wire_only=wire_only)
    observed = standards._sel751_observed({'master_port': PORT}, captures, select_only_expected())
    assert observed['aggregate_verdict'] is False and observed['operate_absent'] is False
    assert any('OPERATE' in f and 'select-only' in f for f in observed['application_failures']), observed


@pytest.mark.parametrize('status', [1, 4])
def test_select_only_select_must_carry_captured_crob_success(tmp_path, status):
    captures = select_only_conversation(tmp_path, select_status=status)
    observed = standards._sel751_observed({'master_port': PORT}, captures, select_only_expected())
    assert observed['aggregate_verdict'] is False and observed['select_authorizes_operate'] is False
    assert observed['operate_absent'] is False
    assert any('SELECT captured CROB not successful' in f for f in observed['application_failures'])


def test_public_select_only_validation_binds_the_declared_plan(tmp_path):
    captures = select_only_conversation(tmp_path)
    ctx = select_only_context()
    artifact = standards.build_standards_artifact(ctx, captures)
    verdict = standards.validate_standards(artifact, ctx, captures)
    assert verdict['ok'], verdict['failures']
    assert verdict['expected']['counts'] == PLAN and verdict['expected']['select_only'] is True
    assert verdict['verdicts'] == dict(transport=True, application=True, size=True)
    normal = select_only_context(False)
    refused = standards.validate_standards(standards.build_standards_artifact(normal, captures), normal, captures)
    assert not refused['ok'] and refused['verdicts']['application'] is False


def test_select_only_artifact_cannot_be_replayed_as_a_normal_plan(tmp_path):
    captures = select_only_conversation(tmp_path)
    artifact = standards.build_standards_artifact(select_only_context(), captures)
    verdict = standards.validate_standards(copy.deepcopy(artifact), select_only_context(False), captures)
    assert not verdict['ok']
    assert any('expected.counts mismatch' in f for f in verdict['failures'])


def test_normal_standards_artifact_and_verdict_are_byte_identical(tmp_path):
    import test_captured_crob
    root = tmp_path / 'c'
    captures = conversation(root)
    ctx = test_captured_crob.context()
    artifact = standards.build_standards_artifact(ctx, captures)
    norm = lambda value: json.loads(json.dumps(value).replace(str(root), '<D>'))  # noqa: E731
    assert h(norm({k: v for k, v in artifact.items() if k != 'checker'})) == GOLDEN['standards_artifact_wo_checker']
    assert h(norm(standards.validate_standards(artifact, ctx, captures))) == GOLDEN['standards_verdict']


@pytest.mark.parametrize('label', ['ref', 'nosbo', 'one'])
def test_normal_standards_expectation_of_the_reference_block_is_byte_identical(label):
    cfg = json.loads(REFERENCE.read_text())
    traffic = dict(cfg['traffic'])
    if label == 'nosbo':
        traffic['run_sbo'] = False
    elif label == 'one':
        del traffic['sbo_cycles']
    config = dict(cfg, traffic=traffic)
    context = dict(config=config, arm=config['arms'][3], trial=dict(reads=65, label='x'))
    assert h(standards._sel751_expected(context)) == GOLDEN['standards_expected_' + label]


def wire_stream(*apps):
    """The reassembled master stream (relay_check's {'runs': [(offset, bytes)]}) of the given request fragments."""
    return dict(runs=[(0, b''.join(link(b'\xc0' + app, request=True) for app in apps))])


def test_a_wire_only_direct_operate_fails_the_select_only_wire_check():
    # review M2: DIRECT_OPERATE (0x05) must count as an OPERATE-class request even if no master record shows it
    _, _, select_app, _ = control('SELECT', 1, 0, padded=False)
    direct = bytes([select_app[0], 0x05]) + select_app[2:]
    records = [dict(operation='READ')]
    failures = relay_check.select_only_wire_checks(wire_stream(read(0)[2], direct), records)
    assert any('1 OPERATE request(s) in the captured master stream' in f for f in failures), failures


def test_an_extra_wire_only_request_fails_the_select_only_sequence_check():
    # review M2: a request on the wire that the master records do not show breaks the recorded sequence
    failures = relay_check.select_only_wire_checks(wire_stream(read(0)[2], read(1)[2]), [dict(operation='READ')])
    assert failures == ['select-only plan: captured request sequence differs from the master records']
