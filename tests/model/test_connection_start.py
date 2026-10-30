"""Connection-start loss scenario (labelled, outside the model gate): case table, verdict rule, log parser, state
checks. Pure functions only; the model run itself is scripts/model/run_connection_start.py."""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/model'))

import model_connection_start as cs  # noqa: E402

MASTER_MAC, RELAY_MAC = bytes.fromhex('3cfdfecc5dc0'), bytes.fromhex('0030a7024ca2')


def frame(seq, ack, flags, payload=b'', reverse=False, prefix=b''):
    """A minimal Ethernet/IPv4/TCP frame with the timestamp option block, optionally behind an N envelope prefix."""
    tcp_options = bytes.fromhex('0101080a') + struct.pack('!II', 7, 8)
    tcp = struct.pack('!HHIIBBHHH', 20000 if reverse else 59410, 59410 if reverse else 20000, seq, ack,
                      ((20 + len(tcp_options)) // 4) << 4, flags, 4096, 0, 0) + tcp_options
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000, 64, 6, 0,
                     bytes([192, 168, 10, 7 if reverse else 1]), bytes([192, 168, 10, 1 if reverse else 7]))
    macs = MASTER_MAC + RELAY_MAC if reverse else RELAY_MAC + MASTER_MAC
    return prefix + macs + b'\x08\x00' + ip + tcp + payload


def dump(pid, data):
    lines = []
    for i in range(0, len(data), 16):
        chunk = ' '.join('%02x' % b for b in data[i:i + 16]) + ' '
        lines.append(':10-29 10:00:00.000001:        :%s:-:<0,0,0>:%s' % (pid, chunk))
    return lines


def ingress(pid, port, data, steps):
    """One ingress pass: header, packet dump, the parser's own dump (must not be taken), then table steps.
    steps: (stage, table, status, action, default, salu_before, salu_after)."""
    out = [':10-29 10:00:00.000001:    :%s:-:<0,0,0>:========== Ingress Pkt from port %d (%d bytes)  =========='
           % (pid, port, len(data)), ':10-29 10:00:00.000002:    :%s:-:<0,0,0>:Packet :' % pid]
    out += dump(pid, data)
    out.append(':10-29 10:00:00.000003:    :%s:-:<0,0,->:========== Packet to input parser: from port %d '
               '(%d bytes)  ==========' % (pid, port, len(data) + 16))
    out.append(':10-29 10:00:00.000003:    :%s:-:<0,0,->:Packet :' % pid)
    out += dump(pid, bytes(16) + data)
    for stage, table, status, action, default, before, after in steps:
        out.append(':10-29 10:00:00.000004:    :%s:-:<0,0,%d>:Ingress : Table %s is %s' % (pid, stage, table, status))
        out.append(':10-29 10:00:00.000005:        :%s:-:<0,0,%d>:Execute %sAction: %s'
                   % (pid, stage, 'Default ' if default else '', action))
        if before is not None:
            out.append(':10-29 10:00:00.000006:        :%s:-:<0,0,%d>:\t   Register Index: 0x20000' % (pid, stage))
            out.append(':10-29 10:00:00.000006:        :%s:-:<0,0,%d>:\t     Before stateful alu execution: 0x%x'
                       % (pid, stage, before))
            out.append(':10-29 10:00:00.000007:        :%s:-:<0,0,%d>:\t     After stateful alu execution: 0x%x'
                       % (pid, stage, after))
    # an egress line of another packet must not be attributed to this ingress pass
    out.append(':10-29 10:00:00.000008:    :-:%s:<0,0,1>:Execute Action: n_Ingress.busy_drop' % pid)
    return out


def cell(phase, generation):
    return (phase << 32) | generation


PREFIX_48 = bytes.fromhex('00000001' '00000365' '00000000' 'e1000000')
ACK = dict(direction='m2r', seq=101, flags=0x10, payload_len=0)
READ = dict(direction='m2r', seq=101, flags=0x18, payload_len=25)


def test_case_table_covers_every_scenario_for_both_read_classes():
    names = [(case['scenario'], case['read_class']) for case in cs.CASES]
    assert sorted(names) == sorted((s, c) for s in cs.SCENARIO_ORDER for c in ('mixed', 'integrity'))
    assert len({case['case'] for case in cs.CASES}) == len(cs.CASES)
    assert set(cs.SCENARIO_ORDER) == {'H1', 'H2', 'H2r', 'H1prime', 'collision'}
    for case in cs.CASES:
        assert case['read_length'] == {'mixed': 25, 'integrity': 27}[case['read_class']]
        assert case['evidence_kind'] == ('forced_register' if case['scenario'] == 'H1prime' else 'genuine_processing')
    lost = {case['scenario']: case['lost_frame'] for case in cs.CASES}
    assert lost == {'H1': 'READ', 'H2': 'final_ACK', 'H2r': 'final_ACK', 'H1prime': 'READ', 'collision': 'OPERATE'}
    order = {case['scenario']: case['send_order'] for case in cs.CASES}
    assert order['H1'] == ('final_ACK', 'READ') and order['H2'] == order['H2r'] == ('READ', 'final_ACK')
    assert order['collision'] == ('SELECT_response', 'OPERATE')
    decisive = {case['scenario']: case['decisive_action'] for case in cs.CASES}
    assert decisive == {'H1': 'busy_drop', 'H2': 'terminal_abort', 'H2r': 'terminal_abort', 'H1prime': 'busy_drop',
                        'collision': 'busy_drop'}


def test_verdict_rule_never_turns_an_unreached_state_into_a_disproof():
    assert cs.verdict(True, True) == 'reproduced'
    assert cs.verdict(True, False) == 'falsified_for_this_path'
    assert cs.verdict(False, True) == 'not_reproduced_state_not_reached'
    assert cs.verdict(False, False) == 'not_reproduced_state_not_reached'


def test_work_cell_decoding_matches_the_model_log_layout():
    # c72 abandon_t1 log: claim 'Before 0x0000000400000003' -> 'After 0x0000000100000004' after allocate 3->4
    assert cs.decode_work(0x0000000400000003) == dict(phase=4, generation=3)
    assert cs.decode_work(0x0000000100000004) == dict(phase=1, generation=4)


def test_parser_keeps_ingress_frame_actions_and_salu_and_ignores_egress_lines():
    lines = ingress('0x11', 48, frame(101, 901, 0x10, prefix=PREFIX_48), [
        (3, 'n_Ingress.guard', 'hit', 'n_Ingress.go_new', False, 3, 4),
        (4, 'n_Ingress.work.dispatch', 'hit', 'n_Ingress.work.claim_work', False, cell(4, 3), cell(1, 4)),
        (9, 'n_Ingress.first_event', 'miss', 'NoAction', True, None, None)])
    passes = cs.parse_passes(lines)
    assert len(passes) == 1
    p = passes[0]
    assert p['port'] == 48 and p['id'] == '0x11'
    assert p['segment'] == dict(direction='m2r', seq=101, ack=901, flags=0x10, payload_len=0)
    assert p['event'] == [0xe1, 0]
    assert cs.action_names(p) == ['go_new', 'claim_work', 'NoAction']
    assert cs.salu(p, 'claim_work') == (cell(4, 3), cell(1, 4))
    assert cs.table_step(p, 'n_Ingress.first_event') == dict(table='n_Ingress.first_event', status='miss',
                                                             action='NoAction', default=True, salu=None)
    assert 'busy_drop' not in cs.action_names(p)


def claim_pass(pid, port, data, before, after, extra=()):
    return ingress(pid, port, data, [(4, 'n_Ingress.work.dispatch', 'hit', 'n_Ingress.work.claim_work', False,
                                      before, after)] + list(extra))


def test_cell_held_state_requires_the_holders_generation_at_the_victims_stage0_claim():
    held = (claim_pass('0x20', 48, frame(101, 901, 0x10, prefix=PREFIX_48), cell(4, 3), cell(1, 4))
            + claim_pass('0x21', 48, frame(101, 901, 0x18, b'x' * 25, prefix=PREFIX_48), cell(1, 4), cell(1, 4),
                         [(7, 'n_Ingress.busy_t', 'hit', 'n_Ingress.busy_drop', False, None, None)]))
    state = cs.cell_held_state(cs.parse_passes(held), ACK, READ)
    assert state['reached'] is True and state['holder_generation'] == 4
    assert state['victim_cell_before'] == dict(phase=1, generation=4)
    assert 'busy_drop' in state['victim_actions']
    free = (claim_pass('0x20', 48, frame(101, 901, 0x10, prefix=PREFIX_48), cell(4, 3), cell(1, 4))
            + claim_pass('0x21', 48, frame(101, 901, 0x18, b'x' * 25, prefix=PREFIX_48), cell(4, 4), cell(1, 5)))
    assert cs.cell_held_state(cs.parse_passes(free), ACK, READ)['reached'] is False
    other = (claim_pass('0x20', 48, frame(101, 901, 0x10, prefix=PREFIX_48), cell(4, 3), cell(1, 4))
             + claim_pass('0x21', 48, frame(101, 901, 0x18, b'x' * 25, prefix=PREFIX_48), cell(2, 9), cell(2, 9)))
    assert cs.cell_held_state(cs.parse_passes(other), ACK, READ)['reached'] is False   # another generation
    assert cs.cell_held_state([], ACK, READ)['reached'] is False


def test_forced_state_requires_the_seeded_cell_at_the_victims_claim():
    lines = claim_pass('0x30', 48, frame(101, 901, 0x18, b'x' * 25, prefix=PREFIX_48), cell(1, 0x7ffffffe),
                       cell(1, 0x7ffffffe))
    assert cs.forced_state(cs.parse_passes(lines), READ, 0x7ffffffe)['reached'] is True
    assert cs.forced_state(cs.parse_passes(lines), READ, 5)['reached'] is False


def test_late_ack_state_needs_advanced_owner_and_client_then_reads_the_abort_laps():
    lap = bytes.fromhex('00000001' '00000007' '000e0001' '01ff0000') + bytes(8)
    lines = (claim_pass('0x40', 48, frame(101, 901, 0x10, prefix=PREFIX_48), cell(4, 6), cell(1, 7), [
                (6, 'n_Ingress.client_t', 'miss', 'n_Ingress.load_client', True, 126, 126),
                (7, 'n_Ingress.owner_t', 'hit', 'n_Ingress.owner_read', False, 0x000e0001, 0x000e0001),
                (9, 'n_Ingress.first_event', 'miss', 'NoAction', True, None, None)])
             + ingress('0x41', 68, frame(101, 901, 0x10, prefix=lap), [
                (9, 'n_Ingress.continuation_t', 'hit', 'n_Ingress.abort_work', False, None, None)])
             + ingress('0x42', 68, frame(101, 901, 0x10, prefix=lap), [
                (9, 'n_Ingress.continuation_t', 'hit', 'n_Ingress.terminal_abort', False, None, None)]))
    state = cs.late_ack_state(cs.parse_passes(lines), ACK, expected_client=126)
    assert state['reached'] is True and state['owner_state'] == 0xe and state['client'] == 126
    assert state['first_event'] == dict(table='n_Ingress.first_event', status='miss', action='NoAction',
                                        default=True, salu=None)
    assert [lap['actions'] for lap in state['laps']] == [['abort_work'], ['terminal_abort']]
    assert state['laps'][0]['event'] == [1, 255]
    assert cs.late_ack_outcome(state) == dict(first_event_default_noaction=True, event_code_255_on_lap=True,
                                              abort_work=True, terminal_abort=True)
    assert cs.late_ack_state(cs.parse_passes(lines), ACK, expected_client=101)['reached'] is False
    established = [line.replace('execution: 0xe0001', 'execution: 0x50001') for line in lines]
    assert established != lines
    assert cs.late_ack_state(cs.parse_passes(established), ACK, expected_client=126)['reached'] is False


def test_captured_frames_are_labelled_by_tcp_segment():
    sent = {'final_ACK': ACK, 'READ': READ}
    got = {64: [frame(101, 901, 0x10)], 9: []}
    assert cs.label_frames(got, sent) == {'64': [dict(label='final_ACK', segment=dict(
        direction='m2r', seq=101, ack=901, flags=0x10, payload_len=0), hex=frame(101, 901, 0x10).hex())], '9': []}


def test_parser_attributes_lines_that_also_carry_an_active_egress_id():
    """The model tags an ingress pass's lines ':0x4c:0x4b:' while egress packet 0x4b is in the pipe (c72 run 01).
    Ingress tables and their SALU values belong to the ingress pass; interleaved egress tables do not."""
    lines = [line.replace(':0x4c:-:', ':0x4c:0x4b:') for line in ingress('0x4c', 68, frame(101, 901, 0x10, prefix=PREFIX_48), [
        (3, 'n_Ingress.guard', 'hit', 'n_Ingress.go_retry', False, None, None),
        (4, 'n_Ingress.work.dispatch', 'hit', 'n_Ingress.work.claim_work', False, cell(4, 6), cell(1, 7))])]
    egress = [':10-29 10:00:00.000009:    :0x4c:0x4b:<0,0,4>:Egress : Table r_Egress.acct_t is hit',
              ':10-29 10:00:00.000009:        :0x4c:0x4b:<0,0,4>:Execute Action: r_Egress.acct_add',
              ':10-29 10:00:00.000009:        :0x4c:0x4b:<0,0,4>:\t     Before stateful alu execution: 0x5',
              ':10-29 10:00:00.000009:        :0x4c:0x4b:<0,0,4>:\t     After stateful alu execution: 0x6',
              ':10-29 10:00:00.000009:        :0x4c:0x4b:<0,0,4>:Execute Default Action: NoAction']
    tail = [line for line in ingress('0x4c', 68, b'', [(9, 'n_Ingress.first_event', 'miss', 'NoAction', True,
                                                       None, None)]) if ':0x4c:-:' in line and ('Table' in line or 'Execute' in line)]
    assert len(tail) == 2
    tail = [line.replace(':0x4c:-:', ':0x4c:0x4b:') for line in tail]
    passes = cs.parse_passes(lines[:-1] + egress + tail)
    assert len(passes) == 1 and passes[0]['segment']['flags'] == 0x10
    assert cs.action_names(passes[0]) == ['go_retry', 'claim_work', 'NoAction']
    assert cs.salu(passes[0], 'claim_work') == (cell(4, 6), cell(1, 7))
    assert cs.table_step(passes[0], 'n_Ingress.first_event')['default'] is True
