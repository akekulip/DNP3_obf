"""D3a-D3d and E2 of the diagnostic-mirror design on synthetic trials built with scapy.

Each trial directory holds what the hardware run will hold: out.pcap / in.pcap (master NIC), mirror.pcap (capture
interface: egress copies of frames toward the relay, ingress copies of frames from it), port counter snapshots for
dev9/dev64/dev10, mirror_iface_before/after.json, mirror_capture.json (tcpdump statistics), trial.json and
relay_wire.json. Payloads are the captured SEL-751 READ templates, so the E1 entry (preservation_check) sees real
DNP3 frames.
"""
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, Raw
from scapy.utils import PcapWriter

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/analysis'), str(ROOT / 'scripts/model'), str(ROOT / 'scripts/checks')]
import dnp3_std as std  # noqa: E402
import wire_check as wc  # noqa: E402
import diag_mirror_capture as cap  # noqa: E402
import diag_mirror_d3 as d3  # noqa: E402

LABEL = 'c72_diag_mirror'
DESIGN = json.loads((ROOT / 'results/analysis/diag_mirror_d3/DESIGN.json').read_text())
SHA = DESIGN['build']['source_sha256']
TEMPLATES = json.loads((ROOT / 'tests/fixtures/vectors/two_read_templates_relay.json').read_text())
TEMPLATES = TEMPLATES['variants']['v0']['classes']
MASTER, RELAY = ('192.168.10.1', '02:00:00:00:00:01'), ('192.168.10.7', '02:00:00:00:00:07')
SYN, ACK, PSHACK, SYNACK = 0x02, 0x10, 0x18, 0x12
MS, T0, M32 = 1_000_000, 1_800_000_000 * 10 ** 9, 0xffffffff
COPY_DELAY_NS = 5000
HEADERS = 54                                   # Ethernet 14 + IPv4 20 + TCP 20 (scapy, no options)


def renumber(frame, k):
    """A captured template frame with transport sequence k mod 64 and application sequence k mod 16."""
    head, user = std.deframe(bytes.fromhex(frame))
    return std.frame(head, bytes([(user[0] & 0xc0) | (k & 63), (user[1] & 0xf0) | (k & 15)]) + user[2:])


def event(t, d, flags, seq, ack, payload=b'', **extra):
    return dict(t=t, d=d, flags=flags, seq=seq & M32, ack=ack & M32, payload=payload, **extra)


def connection(n=4, client=1000, server=0xfffff000):
    """Nominal events of one fresh connection: handshake, then n READs (relay ACK, response, master ACK)."""
    events, clock = [], [T0]

    def add(d, flags, seq, ack, payload=b'', gap=MS):
        clock[0] += gap
        events.append(event(clock[0], d, flags, seq, ack, payload))
    add('to_relay', SYN, client, 0)
    add('from_relay', SYNACK, server, client + 1)
    add('to_relay', ACK, client + 1, server + 1)
    q = r = 0
    for k in range(n):
        item = TEMPLATES[('mixed', 'integrity')[k % 2]]
        request, response = renumber(item['request'], k), renumber(item['native'], k)
        add('to_relay', PSHACK, client + 1 + q, server + 1 + r, request)
        q += len(request)
        add('from_relay', ACK, server + 1 + r, client + 1 + q)
        add('from_relay', PSHACK, server + 1 + r, client + 1 + q, response, gap=4 * MS)
        r += len(response)
        add('to_relay', ACK, client + 1 + q, server + 1 + r)
    return events


def frame(e, port):
    (sip, smac), (dip, dmac), sport, dport = ((MASTER, RELAY, port, 20000) if e['d'] == 'to_relay'
                                              else (RELAY, MASTER, 20000, port))
    packet = (Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip, id=1, flags='DF') /
              TCP(sport=sport, dport=dport, flags=e['flags'], seq=e['seq'], ack=e['ack'], window=4096))
    return bytes(packet / Raw(e['payload']) if e['payload'] else packet)


def write_pcap(path, items):
    """items: (t_ns, captured frame, wire length); classic pcap with nanosecond timestamps, in time order."""
    writer = PcapWriter(str(path), linktype=1, nano=True)
    writer.write_header(None)
    for t, raw, wirelen in sorted(items, key=lambda item: item[0]):
        writer.write_packet(raw, sec=t // 10 ** 9, usec=t % 10 ** 9, caplen=len(raw), wirelen=wirelen)
    writer.close()


def port_stats(rx, tx):
    return {'$FramesReceivedOK': rx, '$FramesTransmittedOK': tx, '$FramesReceivedAll': rx, '$FramesTransmittedAll': tx}


def write_trial(root, arm, name, events, port=60000, wire=None, counters=None, stats=None, interface=None):
    """One trial directory. Event keys: master=False (absent at the master NIC), copy=False (no mirror copy),
    flip=OFFSET (copy byte inverted), snap=N (copy captured to N bytes, wire length kept), cut=N (copy itself N
    bytes), master_frame=BYTES (master NIC frame differs from the frame on the wire)."""
    trial = root / arm / name
    (trial / 'snapshots').mkdir(parents=True)
    out, inn, mirror = [], [], []
    for e in events:
        raw = frame(e, port)
        if e.get('master', True):
            (out if e['d'] == 'to_relay' else inn).append((e['t'], e.get('master_frame', raw), len(raw)))
        if e.get('copy', True):
            copy, wirelen = bytearray(raw), len(raw)
            if 'flip' in e:
                copy[e['flip']] ^= 0xff
            if 'snap' in e:
                copy = copy[:e['snap']]
            if 'cut' in e:
                copy = copy[:e['cut']]
                wirelen = len(copy)
            shift = COPY_DELAY_NS if e['d'] == 'to_relay' else -COPY_DELAY_NS
            mirror.append((e['t'] + shift, bytes(copy), wirelen))
    for name_, items in (('out.pcap', out), ('in.pcap', inn), ('mirror.pcap', mirror)):
        write_pcap(trial / name_, items)
    to_relay = sum(e['d'] == 'to_relay' for e in events)
    delta = dict(dict(rx64=len(events) - to_relay, tx64=to_relay, tx10=len(events)), **(counters or {}))
    before = {'9': port_stats(500, 400), '64': port_stats(100, 200), '10': port_stats(0, 300)}
    after = {'9': port_stats(500 + to_relay, 400 + delta['rx64']),
             '64': port_stats(100 + delta['rx64'], 200 + delta['tx64']), '10': port_stats(0, 300 + delta['tx10'])}
    for when, ports in (('before', before), ('after', after)):
        (trial / 'snapshots' / ('%s_%s.json' % (name, when))).write_text(json.dumps(dict(time=0, ports=ports)))
    identity = dict(dict(interface='enp59s0f1np1', driver='i40e', bus_info='0000:3b:00.1'), **(interface or {}))

    def iface(rx):         # vision_run.MirrorCapture.identity format
        return dict(interface=identity['interface'],
                    driver={'driver': identity['driver'], 'bus-info': identity['bus_info']},
                    link=[dict(ifname=identity['interface'], stats64=dict(rx=dict(packets=rx)))])
    (trial / 'mirror_iface_before.json').write_text(json.dumps(iface(1000)))
    (trial / 'mirror_iface_after.json').write_text(json.dumps(iface(1000 + len(mirror))))
    tcpdump = dict(dict(captured=len(mirror), received=len(mirror), dropped_kernel=0, dropped_interface=0),
                   **(stats or {}))
    (trial / 'mirror_capture.json').write_text(json.dumps(dict(ok=True, tcpdump=tcpdump)))
    (trial / 'trial.json').write_text(json.dumps(dict(label=name, master_port=port, fixture='physical_relay')))
    (trial / 'relay_wire.json').write_text(json.dumps(wire or relay_wire()))
    return trial


WIRE_CLASSES = (('READ', 'mixed', 91), ('READ', 'integrity', 134), ('SELECT', None, 49), ('OPERATE', None, 49))


def relay_wire(shift=0.0, size_delta=0):
    """relay_check v3 shape: four exchanges per class, CLRT 4000-4300 us (+shift); first READ mixed size changed."""
    rows = [dict(operation=op, workload=workload, response=dict(wire_hex='00' * size), application=dict(ok=True),
                 complete_clrt_us=4000.0 + 100 * i + shift, piggyback=False)
            for op, workload, size in WIRE_CLASSES for i in range(4)]
    rows[0]['response']['wire_hex'] = '00' * (91 + size_delta)
    return dict(schema='sel751-wire-v3', ok=True, failures=[], exchanges=rows)


def trial(tmp_path, events=None, arm='off', **kwargs):
    return cap.load(write_trial(tmp_path, arm, 'd3_on_%s_t0' % arm, events or connection(), **kwargs))


N_TO, N_FROM = 10, 9                           # connection(4): frames toward / from the relay


def test_identical_copies_pass(tmp_path):
    t = trial(tmp_path)
    fidelity = cap.fidelity(t, 0)
    assert fidelity['ok'], fidelity['failures']
    assert fidelity['to_relay']['identical'] == {'n': N_TO, 'of': N_TO}
    assert fidelity['from_relay']['identical'] == {'n': N_FROM, 'of': N_FROM}
    assert fidelity['to_relay']['missing'] == {'n': 0, 'of': N_TO}
    complete = d3.completeness(t)
    assert complete['ok'], complete['failures']
    assert complete['truncated'] == {'n': 0, 'of': N_TO + N_FROM}
    assert complete['directions']['from_relay']['copies_attributed'] == N_FROM
    mapped = d3.mapping(t)
    assert mapped['mapped'] and not mapped['falsified']
    assert mapped['copies_received'] == {'n': N_TO + N_FROM, 'of': N_TO + N_FROM}
    assert mapped['interface']['identity']['interface'] == 'enp59s0f1np1'


def test_one_changed_byte_is_detected_with_its_offset_and_field(tmp_path):
    events = connection()
    events[5]['flip'] = HEADERS + 20           # first READ response, payload octet 20
    fidelity = cap.fidelity(trial(tmp_path, events), 0)
    assert not fidelity['ok']
    assert fidelity['from_relay']['identical'] == {'n': N_FROM - 1, 'of': N_FROM}
    [row] = fidelity['from_relay']['differences']
    assert row['offsets'] == [HEADERS + 20] and row['fields'] == ['tcp.payload'] and not row['shorter']
    assert fidelity['to_relay']['identical'] == {'n': N_TO, 'of': N_TO}


@pytest.mark.parametrize('kind', ['snap', 'cut'])
def test_a_truncated_copy_is_detected(tmp_path, kind):
    events = connection()
    events[5][kind] = 100                      # the 145-octet response frame copied as 100 octets
    t = trial(tmp_path, events)
    fidelity = cap.fidelity(t, 0)
    assert not fidelity['ok']
    assert fidelity['from_relay']['shorter'] == {'n': 1, 'of': N_FROM}
    complete = d3.completeness(t)
    assert not complete['ok']
    key = 'truncated' if kind == 'snap' else 'ip_length_short'
    assert complete[key] == {'n': 1, 'of': N_TO + N_FROM}


@pytest.mark.parametrize('switch_sent', [False, True])
def test_a_missing_copy_is_detected(tmp_path, switch_sent):
    events = connection()
    events[3]['copy'] = False                  # first request: no egress copy captured
    counters = None if switch_sent else dict(tx10=N_TO + N_FROM - 1)
    t = trial(tmp_path, events, counters=counters)
    complete = d3.completeness(t)
    fidelity = cap.fidelity(t, complete['uncaptured'])
    assert fidelity['to_relay']['missing'] == {'n': 1, 'of': N_TO}
    assert fidelity['missing_unaccounted'] == {'n': 0 if switch_sent else 1, 'of': 1}
    assert fidelity['ok'] is switch_sent       # a copy the switch sent but the capture lost is a D3c failure
    assert not complete['ok']
    failed = {c['check'] for c in complete['checks'] if not c['equal']}
    common = {'egress copies / switch dev64 TX', 'connection to_relay copies / frames at the master NIC (out.pcap)'}
    assert failed == common | ({'copies captured / switch dev10 TX'} if switch_sent else
                               {'switch dev10 TX / switch dev64 RX + TX'})


@pytest.mark.parametrize('counters, stats, failed', [
    (dict(rx64=N_FROM + 1), None, {'switch dev10 TX / switch dev64 RX + TX', 'ingress copies / switch dev64 RX'}),
    (dict(tx10=N_TO + N_FROM + 1), None,
     {'copies captured / switch dev10 TX', 'switch dev10 TX / switch dev64 RX + TX'}),
    (None, dict(dropped_kernel=2), set()),
    (None, dict(captured=N_TO + N_FROM + 3), {'copies in mirror.pcap / tcpdump captured'}),
])
def test_a_counter_mismatch_or_capture_drop_is_detected(tmp_path, counters, stats, failed):
    complete = d3.completeness(trial(tmp_path, counters=counters, stats=stats))
    assert not complete['ok']
    assert {c['check'] for c in complete['checks'] if not c['equal']} == failed
    if stats and 'dropped_kernel' in stats:
        assert any('dropped_kernel' in f for f in complete['failures'])


def test_counter_window_wider_than_the_capture_is_a_bound_not_a_failure(tmp_path):
    # two relay frames crossed dev64 outside the mirror capture window: counted by the switch, not captured
    complete = d3.completeness(trial(tmp_path, counters=dict(rx64=N_FROM + 2, tx10=N_TO + N_FROM + 2)))
    assert complete['ok'], complete['failures']
    assert complete['uncaptured'] == 2
    over = d3.completeness(trial(tmp_path / 'over', counters=dict(rx64=N_FROM - 1, tx10=N_TO + N_FROM - 1)))
    assert not over['ok']                    # more copies than the switch counted is impossible: a failure


def test_d3a_is_falsified_when_dev10_advances_and_no_copy_arrives(tmp_path):
    events = [dict(e, copy=False) for e in connection()]
    mapped = d3.mapping(trial(tmp_path, events))
    assert mapped['falsified'] and not mapped['mapped']
    assert mapped['switch_dev10_tx'] == N_TO + N_FROM and mapped['relay_leg_copies']['n'] == 0


def test_a_tx_offload_placeholder_checksum_in_out_pcap_is_not_a_difference(tmp_path):
    events = connection()
    raw = bytearray(frame(events[3], 60000))
    pseudo = raw[26:34] + struct.pack('!BBH', 0, 6, len(raw) - 34)
    raw[50:52] = (wc._sum16(pseudo) ^ 0xffff).to_bytes(2, 'big')      # what tcpdump -Q out sees before the NIC
    events[3]['master_frame'] = bytes(raw)
    fidelity = cap.fidelity(trial(tmp_path, events), 0)
    assert fidelity['ok'], fidelity['failures']
    assert fidelity['to_relay']['reference_checksum_offloaded'] == {'n': 1, 'of': N_TO}
    events[3]['flip'] = 50                    # now the copy's checksum is wrong as well
    fidelity = cap.fidelity(trial(tmp_path / 'b', events), 0)
    assert [row['fields'] for row in fidelity['to_relay']['differences']] == [['tcp.checksum']]


def on_off(tmp_path, arm, on_wire, off_wire):
    on = cap.load(write_trial(tmp_path / 'on', arm, 'on_%s_t0' % arm, connection(1), wire=on_wire))
    off = cap.load(write_trial(tmp_path / 'off', arm, 'off_%s_t0' % arm, connection(1), wire=off_wire))
    return d3.on_off([on], [off])


def test_on_off_flags_a_response_size_difference(tmp_path):
    result = on_off(tmp_path, 'size_only', relay_wire(size_delta=2), relay_wire())
    classes = result['arms']['size_only']['classes']
    assert classes['READ mixed']['size_differs'] and not classes['READ mixed']['delivery_differs']
    assert not any(classes[c]['size_differs'] for c in ('READ integrity', 'SELECT', 'OPERATE'))
    assert not result['ok'] and any('READ mixed' in flag and 'size' in flag for flag in result['flags'])


@pytest.mark.parametrize('arm, shift, flagged', [('timing_only', 60.0, True), ('timing_only', 30.0, False),
                                                 ('combined', -60.0, True), ('size_only', 60.0, None)])
def test_on_off_flags_a_timed_arm_clrt_shift_above_50_us_only(tmp_path, arm, shift, flagged):
    result = on_off(tmp_path, arm, relay_wire(shift=shift), relay_wire())
    for cls in d3.CLASSES:
        row = result['arms'][arm]['classes'][cls]
        assert row['clrt_median_difference_us'] == shift
        assert row['clrt_flag'] is flagged
        assert not row['size_differs'] and not row['delivery_differs']
    assert result['ok'] is (not flagged)


def first_request_case(case):
    """One READ on a fresh connection; the first request is retransmitted 210 ms later except in case 'none'."""
    c, s = 5000, 9000
    request, response = renumber(TEMPLATES['mixed']['request'], 0), renumber(TEMPLATES['mixed']['native'], 0)
    q = c + 1 + len(request)
    lost_at_master = dict(master=False) if case == 'class3' else {}
    events = [event(T0 + 1 * MS, 'to_relay', SYN, c, 0), event(T0 + 2 * MS, 'from_relay', SYNACK, s, c + 1),
              event(T0 + 3 * MS, 'to_relay', ACK, c + 1, s + 1),
              event(T0 + 10 * MS, 'to_relay', PSHACK, c + 1, s + 1, request, copy=case != 'class1')]
    if case in ('none', 'class3'):
        events += [event(T0 + 12 * MS, 'from_relay', ACK, s + 1, q, **lost_at_master),
                   event(T0 + 32 * MS, 'from_relay', PSHACK, s + 1, q, response, **lost_at_master)]
    end = 33
    if case != 'none':
        end = 401 if case == 'class3' else 243
        events += [event(T0 + 220 * MS, 'to_relay', PSHACK, c + 1, s + 1, request),
                   event(T0 + 222 * MS, 'from_relay', ACK, s + 1, q),
                   event(T0 + (end - 1) * MS, 'from_relay', PSHACK, s + 1, q, response)]
    return events + [event(T0 + end * MS, 'to_relay', ACK, q, s + 1 + len(response))]


E2_EXPECTED = dict(none='no_retransmission', class1='lost_before_or_inside_switch',
                   class2='lost_after_switch_egress', class3='lost_between_switch_ingress_and_master')


def test_e2_classifies_each_registered_class_and_no_retransmission(tmp_path):
    trials = [cap.load(write_trial(tmp_path, 'off', 'e2_%s' % case, first_request_case(case), port=61000 + k))
              for k, case in enumerate(E2_EXPECTED)]
    result = d3.first_requests(trials, [])
    rows = {row['trial']: row for row in result['connections']}
    for case, key in E2_EXPECTED.items():
        row = rows['e2_' + case]
        assert row['class'] == key, (case, row)
        assert row['retransmitted'] is (case != 'none')
        if case != 'none':
            assert row['retransmission_delay_ms'] == pytest.approx(210.0)
            assert row['second_egress_copy'] is (case != 'class1')
    assert rows['e2_class1']['egress_copy_ns'] is None
    assert rows['e2_class3']['ingress_response_ns'] == T0 + 32 * MS - COPY_DELAY_NS
    for key in E2_EXPECTED.values():
        assert result['classes'][key]['n'] == 1 and result['classes'][key]['of'] == 4
    assert result['classes']['unclassified'] == dict(n=0, of=4, text=result['classes']['unclassified']['text'])
    assert result['retransmitted_mirror_on'] == {'n': 3, 'of': 4}


def test_e2_mirror_off_connections_count_retransmissions_without_a_location(tmp_path):
    t = cap.load(write_trial(tmp_path, 'off', 'off_t0', first_request_case('class2')))
    result = d3.first_requests([], [t])
    [row] = result['connections']
    assert row['class'] is None and row['retransmitted']
    assert result['retransmitted_all_connections'] == {'n': 1, 'of': 1}
    assert result['classes']['lost_after_switch_egress']['of'] == 0


def test_e2_class_texts_are_the_registered_design_classes():
    assert list(cap.E2_CLASSES.values()) == DESIGN['experiments']['E2_first_request']['classification']


def test_e2_no_egress_copy_but_a_relay_reply_is_a_contradiction_not_a_switch_loss(tmp_path):
    # the capture missed the egress copy, yet the relay acknowledged and answered the request before the
    # retransmission (neither reached the master): the switch cannot have lost it
    events = first_request_case('class3')
    for e in events:
        if e['t'] == T0 + 10 * MS:
            e['copy'] = False
    row = cap.first_request(cap.load(write_trial(tmp_path, 'off', 'e2_contra', events)))
    assert row['retransmitted'] and row['egress_copy_ns'] is None
    assert row['ingress_replies_before_retransmission'] == 2
    assert row['class'] == 'unclassified'


def test_e2_is_not_usable_when_an_e2_block_capture_is_incomplete(tmp_path):
    on, off, _ = synthetic_set(tmp_path)
    e2 = [write_trial(tmp_path / 'e2_first_request_d20', 'off', 'e2_drop', first_request_case('class2'),
                      port=60030, stats=dict(dropped_kernel=1))]
    result = d3.analyze(on, off, e2, LABEL, SHA, tmp_path / 'out' / 'd3.json')
    assert result['verdicts']['D3c_e2_block'] is False
    assert result['E2']['usable'] is False and result['E2']['precondition']['D3c_e2_block'] is False


def test_d3a_requires_the_registered_bus_address(tmp_path):
    mapped = d3.mapping(trial(tmp_path, interface=dict(bus_info='0000:3b:00.0')))
    assert not mapped['mapped'] and any('0000:3b:00.0' in f for f in mapped['failures'])


def test_copies_above_the_interface_rx_count_fail_and_nic_loss_counters_are_reported(tmp_path):
    t = write_trial(tmp_path, 'off', 'd3_on_off_t0', connection())
    before = json.loads((t / 'mirror_iface_before.json').read_text())
    after = json.loads((t / 'mirror_iface_after.json').read_text())
    before['rx_counters'], after['rx_counters'] = dict(rx_dropped=5, rx_bytes=0), dict(rx_dropped=8, rx_bytes=900)
    after['link'][0]['stats64']['rx']['packets'] = before['link'][0]['stats64']['rx']['packets'] + 1
    (t / 'mirror_iface_before.json').write_text(json.dumps(before))
    (t / 'mirror_iface_after.json').write_text(json.dumps(after))
    complete = d3.completeness(cap.load(t))
    assert not complete['ok']
    assert any(f.startswith('copies captured / capture interface RX packets') for f in complete['failures'])
    assert complete['nic_loss_counter_deltas'] == {'rx_dropped': 3}


def cli_argv(on, off, e2, out):
    return (['--on'] + [str(p) for p in on] + ['--off'] + [str(p) for p in off] + ['--e2'] + [str(p) for p in e2] +
            ['--out', str(out), '--build-label', LABEL, '--source-sha256', SHA])


@pytest.mark.parametrize('drop', ['--build-label', '--source-sha256'])
def test_missing_build_label_is_refused(tmp_path, drop, capsys):
    t = write_trial(tmp_path, 'off', 'on_off_t0', connection(1))
    out = tmp_path / 'd3.json'
    argv = cli_argv([t], [], [], out)
    del argv[argv.index(drop):argv.index(drop) + 2]
    assert d3.main(argv) == 2 and not out.exists()
    assert 'REFUSED' in capsys.readouterr().err


def test_a_label_that_disagrees_with_the_build_inputs_is_refused(tmp_path):
    t = write_trial(tmp_path, 'off', 'on_off_t0', connection(1))
    out = tmp_path / 'd3.json'
    argv = cli_argv([t], [], [], out)
    argv[argv.index('--source-sha256') + 1] = '0' * 64
    assert d3.main(argv) == 2 and not out.exists()


def synthetic_set(root):
    arms = ('off', 'timing_only', 'size_only', 'combined')
    on = [write_trial(root / 'd3_mirror_on_d20', arm, 'on_%s_t0' % arm, connection(), port=60000 + k)
          for k, arm in enumerate(arms)]
    off = [write_trial(root / 'd3_mirror_off_d20', arm, 'off_%s_t0' % arm, connection(), port=60010 + k)
           for k, arm in enumerate(arms)]
    e2 = [write_trial(root / 'e2_first_request_d20', 'off', 'e2_%s' % case, first_request_case(case), port=60020 + k)
          for k, case in enumerate(('none', 'class2'))]
    return on, off, e2


def test_command_line_run_on_a_synthetic_trial_set_writes_the_json(tmp_path):
    on, off, e2 = synthetic_set(tmp_path)
    out = tmp_path / 'result' / 'diag_mirror_d3.json'
    script = str(ROOT / 'scripts/analysis/diag_mirror_d3.py')
    done = subprocess.run([sys.executable, script] + cli_argv(on, off, e2, out), capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    result = json.loads(out.read_text())
    assert result['schema'] == d3.SCHEMA and result['ok']
    assert result['build'] == dict(label=LABEL, source_sha256=SHA)
    assert LABEL in result['evidence_label']
    assert result['verdicts'] == dict(D3a=True, D3b=True, D3c=True, D3c_e2_block=True, D3d=True, E1=True,
                                      E2_evaluable=True)
    assert result['D3a']['trials'] == {'n': 4, 'of': 4}
    assert result['D3b']['trials'] == {'n': 1, 'of': 1}
    assert result['D3b']['totals']['to_relay']['identical'] == {'n': N_TO, 'of': N_TO}
    assert result['D3c']['trials'] == {'n': 4, 'of': 4}
    assert sorted(result['D3d']['arms']) == ['combined', 'off', 'size_only', 'timing_only']
    assert result['E1']['trials'] == {'n': 2, 'of': 2}
    assert result['E1']['totals']['responses_identical'] == {'n': 8, 'of': 8}
    assert result['E1']['usable'] and result['E2']['usable']
    assert result['E2']['classes']['lost_after_switch_egress'] == dict(
        n=1, of=6, text=cap.E2_CLASSES['lost_after_switch_egress'])
    assert result['E2']['retransmitted_all_connections'] == {'n': 1, 'of': 10}
    assert Path(result['E1']['rows'][0]['output']).is_file()
