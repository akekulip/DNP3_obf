"""Strict-cycle plan in the receiver checkers (generated captures; no historical capture dependency).

traffic.sbo_strict_cycle true plans [READ mixed, SELECT, OPERATE, READ integrity] x N. The strict gate derives the
logical application transactions from the captured streams (first-arrival TCP reassembly anchored at the single SYN,
then DNP3 link/transport reassembly), so a TCP retransmission of delivered bytes is not a transaction and a repeated
request with new stream bytes is. Each response is bound to its request by stream order and TCP acknowledgement,
never by the 4-bit application sequence alone, and must be complete and successful from the captured bytes. Counts
alone cannot pass it. Normal plans are unchanged (goldens in test_select_only_checks.py).
"""
import contextlib
import copy
import io
import json

import pytest

from scripts.analysis.preservation_dnp3 import P4_READ
from scripts.checks import checks, relay_check, standards
from scripts.hardware.active_harness import dnp3_codec as codec
from fixtures import control, link, packet, pcap, read

PORT = 59410
STRICT = 'strict-cycle plan: '
STEPS = (('READ', 'mixed'), ('SELECT', None), ('OPERATE', None), ('READ', 'integrity'))
# today's workload with reads = 2N and sbo_cycles = N (relay_master l.71 before the strict path), N = 2
STUB_INTERLEAVE = (('READ', 'mixed'), ('SELECT', None), ('OPERATE', None), ('READ', 'integrity'), ('SELECT', None),
                   ('OPERATE', None), ('READ', 'mixed'), ('READ', 'integrity'))


def plan(n):
    return dict(READ=2 * n, SELECT=n, OPERATE=n)


def strict_conversation(root, cycles=2, steps=None, padded=True, statuses=None, wire_only=(), master_flag=True,
                        retransmit=(), drop_response=(), truncate_last=False, hole=(), stale_ack=None, late=(),
                        early=(), conflict=(), fir_only_last=False, split_ack=None, request_override=None,
                        request_crob=None):
    """One connection whose requests follow steps in wire order (default STEPS x cycles), seq nibble = index & 15.

    statuses: {index: CROB status of that control response}; wire_only: indexes sent and answered on the wire but not
    in the master records; retransmit: indexes whose request segment is captured twice (a TCP retransmission of the
    same bytes); drop_response: indexes the relay never answers on the wire; truncate_last: the last response stops
    half way; hole: indexes whose response loses its first 20 octets on the wire; stale_ack: {index: earlier index}
    whose response acknowledges that earlier request's end (a stale image replayed with its original ACK); late:
    indexes whose response is captured only after the next request left the master; early: indexes whose response
    is captured before its request left; conflict: indexes whose request is retransmitted with one octet changed;
    fir_only_last: the last response carries only its first (FIR, no FIN) link frame; split_ack: {index: earlier
    index} whose response comes in two segments, the first acknowledging the earlier request's end;
    request_override: {index: request wire bytes sent instead}; request_crob: {index: control() keyword arguments of
    that control request only (its response stays the guarded SUCCESS echo)}."""
    steps = list(STEPS * cycles if steps is None else steps)
    statuses, stale_ack = statuses or {}, stale_ack or {}
    split_ack, request_override, request_crob = split_ack or {}, request_override or {}, request_crob or {}
    root.mkdir(exist_ok=True)
    outgoing = [(1, packet(True, 100, 0, 2)), (3, packet(True, 101, 201, 16))]
    incoming = [(2, packet(False, 200, 101, 18))]
    records, ends, tx, rx = [], [], 101, 201
    for index, (operation, workload) in enumerate(steps):
        seq = index & 15
        if operation == 'READ':
            request, frames, request_app, response_app = read(workload, seq, padded)
            points = []
        else:
            status = statuses.get(index, 0)
            request, _, request_app, _ = control(operation, seq, padded=False,
                                                 **dict(dict(status=0), **request_crob.get(index, {})))
            _, frames, _, response_app = control(operation, seq, status, padded=padded)
            points = [[point, codec.STATUS_NAMES[status]] for point in (1, 3)]
        response = b''.join(frames)
        if index not in wire_only:
            record = dict(operation=operation, outcome='OK' if all(p[1] == 'SUCCESS' for p in points) else 'INVALID',
                          local_address=['192.168.10.1', PORT], peer_address=['192.168.10.7', 20000],
                          request_wire_hex=request.hex(), request_frames_hex=[request.hex()],
                          request_app_hex=request_app.hex(), response_wire_hex=response.hex(),
                          response_frames_hex=[frame.hex() for frame in frames], response_app_hex=response_app.hex(),
                          points=points)
            if operation == 'READ':
                record['workload'] = workload
            records.append(record)
        timestamp = 10 + index * 20
        request = request_override.get(index, request)
        outgoing.append((timestamp, packet(True, tx, rx, 24, request)))
        if index in retransmit:
            outgoing.append((timestamp + 1, packet(True, tx, rx, 24, request)))
        if index in conflict:
            outgoing.append((timestamp + 1, packet(True, tx, rx, 24, request[:-1] + bytes([request[-1] ^ 0xff]))))
        tx += len(request)
        ends.append(tx)
        incoming.append((timestamp + 2, packet(False, rx, tx, 16)))
        if index in drop_response:
            continue
        ack = ends[stale_ack[index]] if index in stale_ack else tx
        payload = response[:len(response) // 2] if truncate_last and index == len(steps) - 1 else response
        if fir_only_last and index == len(steps) - 1:
            payload = frames[0]
        when = timestamp + (25 if index in late else -1 if index in early else 3)
        if index in hole:
            incoming.append((when, packet(False, rx + 20, ack, 24, payload[20:])))
        elif index in split_ack:
            incoming.extend([(when, packet(False, rx, ends[split_ack[index]], 24, payload[:20])),
                             (when + 1, packet(False, rx + 20, ack, 24, payload[20:]))])
        else:
            incoming.append((when, packet(False, rx, ack, 24, payload)))
        rx += len(payload)
    counts = {name: sum(r['operation'] == name and r['outcome'] == 'OK' for r in records)
              for name in ('READ', 'SELECT', 'OPERATE')}
    master = dict(ok=counts == plan(cycles), counts=counts, planned=plan(cycles), records=records)
    if master_flag:
        master['sbo_strict_cycle'] = True
    for name, value in [('master.json', master), ('result.json', {'tcpdump': {
            'out': {'dropped_kernel': 0}, 'in': {'dropped_kernel': 0}}}),
                        ('capture_offloads.json', {'restore_ok': True}), ('relay_wire.json', {})]:
        (root / name).write_text(json.dumps(value))
    pcap(root / 'out.pcap', outgoing)
    pcap(root / 'in.pcap', incoming)
    return {key: {'path': str(root / filename)} for key, filename in standards.SEL751_CAPTURE_FILES.items()}


def strict(root, cycles=2, padded=True):
    return relay_check.analyze(root, PORT, plan(cycles), 'mixed_full', strict_cycle=True,
                               images=standards.SEL751_IMAGES[padded])


def strict_findings(report):
    return [f for f in report['failures'] if f.startswith(STRICT)]


# ------------------------------------------------------------------------------------------------ fixtures
@pytest.mark.parametrize('workload,native,image', [('mixed', 91, 141), ('integrity', 134, 158)])
def test_generated_read_fixture_matches_the_native_and_declared_padded_images(workload, native, image):
    for padded, size in ((False, native), (True, image)):
        request, frames, app, response = read(workload, 5, padded)
        assert len(b''.join(frames)) == size == standards.SEL751_IMAGES[padded][workload]
        assert len(request) == {'mixed': 25, 'integrity': 27}[workload]
        assert relay_check.application_from_wire(b''.join(frames)) == response
        assert codec.read_workload_for_request(app) == workload
        decoded = codec.parse_application_response(response)
        assert codec.validate_response(decoded, expect_seq=5, expect_function=codec.FUNC_READ, require_success=True,
                                       expect_read_workload=workload) == []
    header = {'mixed': 'mixed_g1v2_g30v1_91', 'integrity': 'integrity_134'}[workload]
    prefix = read(workload, 5, True)[1][0]
    assert prefix[2] == P4_READ[header]['link_len'] and read(workload, 5, True)[3][4:11].hex() == \
        P4_READ[header]['header']
    assert image - native == P4_READ[header]['growth']


# ------------------------------------------------------------------------------------------------ declaration
def test_the_strict_finding_prefix_is_relay_checks():
    assert relay_check.STRICT_CYCLE == STRICT


def test_strict_cycle_is_declared_only_by_an_explicit_true_with_mixed_full_sbo_cycles():
    assert checks.sbo_strict_cycle({}) is False
    traffic = dict(run_sbo=True, sbo_cycles=32, read_schedule='mixed_full', sbo_strict_cycle=True)
    assert checks.sbo_strict_cycle(traffic) is True
    assert checks.planned_controls(traffic) == dict(SELECT=32, OPERATE=32)


@pytest.mark.parametrize('change', [dict(sbo_strict_cycle=False), dict(sbo_strict_cycle=1),
                                    dict(sbo_strict_cycle='true'), dict(run_sbo=False), dict(read_schedule='full'),
                                    dict(read_schedule='mixed'), dict(sbo_select_only=True)])
def test_a_strict_cycle_declaration_that_is_not_explicit_and_complete_is_refused(change):
    traffic = dict(dict(run_sbo=True, sbo_cycles=32, read_schedule='mixed_full', sbo_strict_cycle=True), **change)
    with pytest.raises(ValueError, match='sbo_strict_cycle'):
        checks.sbo_strict_cycle(traffic)
    without_cycles = dict(run_sbo=True, read_schedule='mixed_full', sbo_strict_cycle=True)
    with pytest.raises(ValueError, match='sbo_strict_cycle'):
        checks.sbo_strict_cycle(without_cycles)


# ------------------------------------------------------------------------------------------------ relay_check
@pytest.mark.parametrize('cycles,padded', [(2, True), (2, False), (5, True)])
def test_a_strict_conversation_passes_the_strict_gate(tmp_path, cycles, padded):
    strict_conversation(tmp_path, cycles=cycles, padded=padded)
    master = json.loads((tmp_path / 'master.json').read_text())
    assert relay_check.master_checks(master, PORT, plan(cycles), 'mixed_full', strict_cycle=True) == []
    report = strict(tmp_path, cycles, padded)
    assert report['failures'] == [] and report['ok'], report['failures']
    assert [(r['operation'], r['workload']) for r in report['exchanges']] == list(STEPS) * cycles


def test_philips_stub_interleave_passes_counts_but_fails_the_strict_plan(tmp_path):
    """Today's workload with reads 2N and sbo_cycles N: mixed,S,O,integrity,S,O,mixed,integrity. Every count and the
    READ schedule match, so the normal gate passes; the strict gate must not."""
    strict_conversation(tmp_path, steps=STUB_INTERLEAVE, master_flag=False)
    normal = relay_check.analyze(tmp_path, PORT, plan(2), 'mixed_full')
    assert normal['ok'] and normal['failures'] == []                     # counts alone pass
    report = strict(tmp_path)
    assert not report['ok']
    assert any(f.startswith(STRICT + 'captured request transactions are not') for f in report['failures']), \
        report['failures']
    master = json.loads((tmp_path / 'master.json').read_text())
    master['sbo_strict_cycle'] = True                                     # even with the flag, the order fails
    findings = relay_check.master_checks(master, PORT, plan(2), 'mixed_full', strict_cycle=True)
    assert any(f.startswith(STRICT + 'master record sequence') for f in findings), findings


@pytest.mark.parametrize('steps', [
    (('READ', 'mixed'), ('OPERATE', None), ('SELECT', None), ('READ', 'integrity')) + STEPS,
    (('READ', 'integrity'), ('SELECT', None), ('OPERATE', None), ('READ', 'mixed')) + STEPS,
    STEPS[1:] + STEPS[:1] + STEPS,
])
def test_reordered_transactions_fail(tmp_path, steps):
    strict_conversation(tmp_path, steps=steps)
    assert any('captured request transactions are not' in f for f in strict_findings(strict(tmp_path)))


def test_a_missing_response_fails(tmp_path):
    strict_conversation(tmp_path, drop_response=(6,))
    findings = strict_findings(strict(tmp_path))
    assert any('7 relay response transaction(s) for 8 request transaction(s)' in f for f in findings), findings


@pytest.mark.parametrize('index,status', [(1, 1), (2, 1), (5, 4), (6, 2)])
def test_a_failed_select_or_operate_response_fails(tmp_path, index, status):
    strict_conversation(tmp_path, statuses={index: status})
    findings = strict_findings(strict(tmp_path))
    name = codec.STATUS_NAMES[status]
    assert any(('transaction %d' % index) in f and ('status ' + name) in f for f in findings), findings


def test_an_incomplete_last_response_fails(tmp_path):
    strict_conversation(tmp_path, truncate_last=True)
    findings = strict_findings(strict(tmp_path))
    assert any('relay stream cannot be decoded' in f and 'incomplete DNP3 link frame' in f for f in findings), findings


def test_a_response_with_a_hole_in_the_stream_fails(tmp_path):
    strict_conversation(tmp_path, hole=(3,))
    findings = strict_findings(strict(tmp_path))
    assert any('relay stream cannot be decoded' in f and 'gap' in f for f in findings), findings


@pytest.mark.parametrize('extra', [('READ', 'integrity'), ('SELECT', None), ('OPERATE', None)])
def test_an_extra_wire_only_request_fails(tmp_path, extra):
    steps = STEPS + (extra,) + STEPS
    strict_conversation(tmp_path, steps=steps, wire_only=(4,))
    master = json.loads((tmp_path / 'master.json').read_text())
    assert relay_check.master_checks(master, PORT, plan(2), 'mixed_full', strict_cycle=True) == []  # records look fine
    findings = strict_findings(strict(tmp_path))
    assert any('captured request transactions are not' in f for f in findings), findings
    assert any('master records' in f for f in findings), findings


@pytest.mark.parametrize('duplicate', [1, 2])
@pytest.mark.parametrize('recorded', [False, True])
def test_a_genuinely_duplicated_select_or_operate_fails(tmp_path, duplicate, recorded):
    """A repeated application request is new stream bytes and is counted, never deduplicated by content: the copy
    here is byte-identical (same sequence nibble) to the request it repeats."""
    steps = list(STEPS * 2)
    steps.insert(duplicate + 1, steps[duplicate])
    root = tmp_path / 'c'
    strict_conversation(root, steps=steps, wire_only=() if recorded else (duplicate + 1,))
    # make the repeat byte-identical to the request it repeats, including its nibble: rewrite the out capture
    out = (root / 'out.pcap').read_bytes()
    first, _, _, _ = control(steps[duplicate][0], duplicate & 15, 0, padded=False)
    second, _, _, _ = control(steps[duplicate][0], (duplicate + 1) & 15, 0, padded=False)
    assert second in out
    (root / 'out.pcap').write_bytes(out.replace(second, first))
    report = relay_check.analyze(root, PORT, plan(2), 'mixed_full', strict_cycle=True,
                                 images=standards.SEL751_IMAGES[True])
    findings = strict_findings(report)
    assert any('captured request transactions are not' in f for f in findings), findings


def test_a_tcp_retransmitted_request_segment_is_one_transaction(tmp_path):
    strict_conversation(tmp_path, cycles=2, retransmit=(0, 1, 2, 3))
    report = strict(tmp_path)
    assert report['failures'] == [] and report['ok'], report['failures']
    assert report['retransmissions']['out'] == 4
    transactions = relay_check.application_transactions(relay_check.tcp_stream(
        [s for s in relay_check.wc.parse(tmp_path / 'out.pcap')[0] if s['sport'] == PORT]))
    assert len(transactions) == 8


def test_a_response_bound_by_nibble_alone_across_a_sequence_wrap_is_caught(tmp_path):
    """Five cycles wrap the 4-bit application sequence: transaction 19 has transaction 3's nibble and class, so a
    stale replay of response 3 (identical bytes) answers request 19 by nibble and content. Its TCP acknowledgement
    is request 3's end, so the transaction identity binds it to request 3, not 19."""
    strict_conversation(tmp_path, cycles=5, stale_ack={19: 3})
    records = json.loads((tmp_path / 'master.json').read_text())['records']
    assert records[19]['response_wire_hex'] == records[3]['response_wire_hex'] and 19 & 15 == 3
    response = relay_check.application_from_wire(bytes.fromhex(records[19]['response_wire_hex']))
    assert codec.validate_response(codec.parse_application_response(response), expect_seq=19 & 15,
                                   expect_function=codec.FUNC_READ, require_success=True,
                                   expect_read_workload='integrity') == []        # the nibble-only view accepts it
    findings = strict_findings(strict(tmp_path, cycles=5))
    assert any('response 19 does not acknowledge exactly request 19' in f for f in findings), findings


def test_a_response_captured_after_the_next_request_is_not_bound_to_its_request(tmp_path):
    strict_conversation(tmp_path, late=(2,))
    findings = strict_findings(strict(tmp_path))
    assert any('response 2 is not between request 2 and the next request' in f for f in findings), findings


def test_a_response_that_begins_before_its_request_completes_is_not_bound_to_it(tmp_path):
    strict_conversation(tmp_path, early=(2,))
    findings = strict_findings(strict(tmp_path))
    assert any('response 2 is not between request 2 and the next request' in f for f in findings), findings


def test_a_response_split_across_segments_must_acknowledge_exactly_its_request_in_every_segment(tmp_path):
    """Response 5's first segment acknowledges request 4's end and only its last segment covers request 5: the
    exact rule (every first-arriving packet acknowledges exactly request 5's end) refuses it."""
    strict_conversation(tmp_path, split_ack={5: 4})
    findings = strict_findings(strict(tmp_path))
    assert any('response 5 does not acknowledge exactly request 5' in f for f in findings), findings


def test_a_stream_with_a_conflicting_retransmitted_copy_fails(tmp_path):
    strict_conversation(tmp_path, conflict=(1,))
    findings = strict_findings(strict(tmp_path))
    assert any('master stream cannot be decoded' in f and 'retransmitted copy conflicts' in f for f in findings), \
        findings


def test_a_stream_ending_inside_a_transport_fragment_fails_with_that_reason(tmp_path):
    strict_conversation(tmp_path, fir_only_last=True)
    findings = strict_findings(strict(tmp_path))
    assert any('relay stream cannot be decoded' in f and 'unfinished transport fragment at the end of the stream' in f
               for f in findings), findings


@pytest.mark.parametrize('field', ['request_wire_hex', 'response_wire_hex'])
def test_master_records_must_equal_the_captured_bytes_not_only_their_kinds(tmp_path, field):
    """Record 4 (READ mixed) claims record 0's bytes (also READ mixed, another nibble): same kinds, other bytes."""
    strict_conversation(tmp_path)
    master = json.loads((tmp_path / 'master.json').read_text())
    master['records'][4][field] = master['records'][0][field]
    (tmp_path / 'master.json').write_text(json.dumps(master))
    findings = strict_findings(strict(tmp_path))
    assert any(f.startswith(STRICT + 'master records differ from the captured transactions at 1 of 8, first at '
                            'transaction 4') for f in findings), findings


def test_a_control_request_that_is_not_the_guarded_crob_fails_its_request_validation(tmp_path):
    """The SELECT request carries CROB status TIMEOUT; the relay's response is the SUCCESS echo (the echo
    comparison ignores the status octet), so only the request's own validation can refuse it."""
    strict_conversation(tmp_path, request_crob={1: dict(status=1)})
    findings = strict_findings(strict(tmp_path))
    assert any(f.startswith(STRICT + 'transaction 1 SELECT: request: point 1 status TIMEOUT') for f in findings), \
        findings


def test_a_response_crob_that_does_not_echo_the_request_fails_the_echo_comparison(tmp_path):
    """The OPERATE request asks on_ms 100; the response is the guarded 200 ms CROB. (Every echoed field is also
    pinned by the two validations, so the echo finding is asserted by its own message.)"""
    strict_conversation(tmp_path, request_crob={2: dict(on_ms=100)})
    findings = strict_findings(strict(tmp_path))
    assert any('transaction 2 OPERATE' in f and 'response CROB echo differs from the captured request' in f
               for f in findings), findings


@pytest.mark.parametrize('app', [b'', b'\xc1'])
def test_a_request_fragment_without_an_application_header_is_a_finding_not_a_crash(tmp_path, app):
    strict_conversation(tmp_path, request_override={1: link(b'\xc0' + app, request=True)})
    findings = strict_findings(strict(tmp_path))
    assert any('transaction 1 is malformed request' in f for f in findings), findings
    assert any(f == STRICT + 'transaction 1 malformed request: malformed request' for f in findings), findings
    assert relay_check._strict_response_problems(app, b'', ('malformed request', None)) == ['malformed request']


def test_a_response_whose_size_is_not_the_arm_image_fails(tmp_path):
    strict_conversation(tmp_path, padded=False)
    report = relay_check.analyze(tmp_path, PORT, plan(2), 'mixed_full', strict_cycle=True,
                                 images=standards.SEL751_IMAGES[True])
    findings = strict_findings(report)
    assert any('transaction 0 READ mixed response 91 octets, expected the mixed image 141' in f for f in findings)


def test_strict_gate_without_image_sizes_fails_closed(tmp_path):
    strict_conversation(tmp_path)
    report = relay_check.analyze(tmp_path, PORT, plan(2), 'mixed_full', strict_cycle=True)
    assert any('class image sizes' in f for f in strict_findings(report))


# ------------------------------------------------------------------------------------------------ master records
def test_master_records_must_show_the_captured_sequence(tmp_path):
    strict_conversation(tmp_path)
    master = json.loads((tmp_path / 'master.json').read_text())
    master['records'][1], master['records'][2] = master['records'][2], master['records'][1]
    (tmp_path / 'master.json').write_text(json.dumps(master))
    report = strict(tmp_path)
    assert any(f.startswith(STRICT + 'master record sequence') for f in report['failures'])
    assert any(f.startswith(STRICT + 'master records differ from the captured transactions') for f in
               report['failures']), report['failures']


def test_a_normal_master_claiming_the_strict_cycle_fails(tmp_path):
    strict_conversation(tmp_path)
    master = json.loads((tmp_path / 'master.json').read_text())
    findings = relay_check.master_checks(master, PORT, plan(2), 'mixed_full')
    assert findings == [STRICT + 'the master ran the strict cycle but the frozen plan is not strict']


def test_the_strict_plan_needs_the_master_to_have_run_the_strict_workload(tmp_path):
    strict_conversation(tmp_path, master_flag=False)
    master = json.loads((tmp_path / 'master.json').read_text())
    findings = relay_check.master_checks(master, PORT, plan(2), 'mixed_full', strict_cycle=True)
    assert findings == [STRICT + 'the master did not run the strict-cycle workload']


@pytest.mark.parametrize('expected,schedule', [(dict(READ=4, SELECT=1, OPERATE=1), 'mixed_full'),
                                               (dict(READ=4, SELECT=2, OPERATE=0), 'mixed_full'),
                                               (plan(2), 'full')])
def test_the_strict_plan_itself_must_be_mixed_full_with_two_reads_per_pair(tmp_path, expected, schedule):
    strict_conversation(tmp_path)
    master = json.loads((tmp_path / 'master.json').read_text())
    findings = relay_check.master_checks(master, PORT, expected, schedule, strict_cycle=True)
    assert any(f.startswith(STRICT + 'needs') for f in findings), findings


def test_strict_cycle_is_refused_together_with_select_only(tmp_path):
    strict_conversation(tmp_path)
    master = json.loads((tmp_path / 'master.json').read_text())
    findings = relay_check.master_checks(master, PORT, plan(2), 'mixed_full', select_only=True, strict_cycle=True)
    assert STRICT + 'refused together with select-only' in findings


def test_normal_analysis_of_a_plain_capture_has_no_strict_findings(tmp_path):
    strict_conversation(tmp_path, master_flag=False)
    report = relay_check.analyze(tmp_path, PORT, plan(2), 'mixed_full')
    assert report['ok'] and not strict_findings(report)


def test_relay_check_cli_derives_the_strict_plan(tmp_path):
    strict_conversation(tmp_path)
    argv = [str(tmp_path), '--master-port', str(PORT), '--reads', '4', '--sbo', '2', '--read-schedule', 'mixed_full']
    with contextlib.redirect_stdout(io.StringIO()):
        assert relay_check.main(argv + ['--strict-cycle', '--padded', '1']) == 0
        assert relay_check.main(argv + ['--strict-cycle', '--padded', '0']) == 1
        assert relay_check.main(argv) == 1                          # the strict master under a normal plan
    with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
        relay_check.main(argv + ['--strict-cycle'])                 # the arm's image is required


# ------------------------------------------------------------------------------------------------ standards
def strict_context(declared=True, padding=1):
    arm = dict(name='combined', build='current', padding=padding, T=1)
    traffic = dict(run_sbo=True, sbo_cycles=2, read_schedule='mixed_full')
    if declared:
        traffic['sbo_strict_cycle'] = True
    return dict(config=dict(endpoint_profile='sel751', arms=[arm], traffic=traffic, builds={'current': dict(
                    profile='current_sel751', hashes={'p0/tofino.bin': 'a' * 64})}), arm=arm,
                run_id='synthetic_strict_cycle', connection_id='single', master_port=PORT,
                trial=dict(label='strict_cycle', reads=4), candidate_source_sha256='b' * 64,
                checker_files=[standards.__file__, relay_check.__file__, checks.__file__])


def test_standards_expected_carries_strict_cycle_only_when_declared():
    expected = standards._sel751_expected(strict_context())
    assert expected['strict_cycle'] is True and expected['counts'] == plan(2) and expected['padded'] is True
    assert 'strict_cycle' not in standards._sel751_expected(strict_context(False))
    bad = strict_context()
    bad['config']['traffic']['sbo_strict_cycle'] = 1
    with pytest.raises(ValueError, match='sbo_strict_cycle'):
        standards._sel751_expected(bad)


def test_strict_observed_verdict_passes_a_strict_capture(tmp_path):
    captures = strict_conversation(tmp_path)
    observed = standards._sel751_observed({'master_port': PORT}, captures, standards._sel751_expected(strict_context()))
    assert observed['aggregate_verdict'] is True, observed
    assert observed['exchanges']['SELECT'] == dict(count=2, ok=2, resp_len=[60])


def test_strict_findings_are_application_findings(tmp_path):
    captures = strict_conversation(tmp_path, steps=STUB_INTERLEAVE)
    observed = standards._sel751_observed({'master_port': PORT}, captures, standards._sel751_expected(strict_context()))
    assert observed['aggregate_verdict'] is False and observed['transport_ok'] is True
    assert any(f.startswith(STRICT + 'captured request transactions') for f in observed['application_failures'])
    assert not any(f.startswith(STRICT) for f in observed['transport_failures'])


def test_public_strict_validation_binds_the_declared_plan(tmp_path):
    captures = strict_conversation(tmp_path)
    ctx = strict_context()
    verdict = standards.validate_standards(standards.build_standards_artifact(ctx, captures), ctx, captures)
    assert verdict['ok'], verdict['failures']
    assert verdict['expected']['strict_cycle'] is True
    assert verdict['verdicts'] == dict(transport=True, application=True, size=True)
    normal = strict_context(False)
    refused = standards.validate_standards(standards.build_standards_artifact(normal, captures), normal, captures)
    assert not refused['ok'] and refused['verdicts']['application'] is False


def test_strict_artifact_cannot_be_replayed_as_a_normal_plan(tmp_path):
    captures = strict_conversation(tmp_path)
    artifact = standards.build_standards_artifact(strict_context(), captures)
    verdict = standards.validate_standards(copy.deepcopy(artifact), strict_context(False), captures)
    assert not verdict['ok'] and any('expected.strict_cycle mismatch' in f or 'observed SEL-751 verdicts differ' in f
                                     for f in verdict['failures']), verdict['failures']
