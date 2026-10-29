"""E1 same-transaction preservation check on synthetic connections built from the repository's own encoders.

Relay-side frames are native SEL-751 responses (captured READ templates, relay_sbo_vectors); master-side frames are
the declared images (read_policy_expect.construct, relay_sbo_vectors.control_image) with translated TCP sequence
numbers, as the c72 padder emits them.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/analysis'), str(ROOT / 'scripts/model')]
import dnp3_std as std  # noqa: E402
import read_policy_expect as rpe  # noqa: E402
import relay_sbo_vectors as sbo  # noqa: E402
import vectors  # noqa: E402
import preservation_check as pc  # noqa: E402
import preservation_dnp3 as pd  # noqa: E402

LABEL = 'c72_diag_mirror'
INPUTS = ROOT / 'results/builds' / LABEL / 'response_only.inputs.json'
SHA = json.loads(INPUTS.read_text())['source_sha256']
VECTORS = ROOT / 'tests/fixtures/vectors'
TEMPLATES = json.loads((VECTORS / 'two_read_templates_relay.json').read_text())['variants']
SHAPES = json.loads((VECTORS / 'constants_two_read_relay.json').read_text())['shapes']
SHAPE = {'mixed': SHAPES['mixed_g1v2_g30v1_91'], 'integrity': SHAPES['integrity_134']}
TUPLE = (0xc0a80a01, 0xc0a80a07, 59410, 20000)       # SEL-751 master and relay endpoints
SYN, PSHACK, ACK = 0x02, 0x18, 0x10


def renumber(frame, transport, app):
    """The captured frame with its transport and application sequences set (as read_policy_expect.read_frames)."""
    head, user = std.deframe(frame)
    return std.frame(head, bytes([(user[0] & 0xc0) | (transport & 63), (user[1] & 0xf0) | (app & 15)]) + user[2:])


def edit(frame, change):
    """A native frame with its user octets changed by change(bytearray) and every CRC (and LEN) recomputed."""
    head, user = std.deframe(frame)
    user = bytearray(user)
    change(user)
    return std.frame(head[:2] + bytes([5 + len(user)]) + head[3:], bytes(user))


def read_txn(cls, transport, app, change=None, **extra):
    item = TEMPLATES['v0']['classes'][cls]
    request = renumber(bytes.fromhex(item['request']), transport, app)
    native = renumber(bytes.fromhex(item['native']), transport, app)
    delivered = edit(native, change) if change else native
    return dict(request=request, native=native, image=rpe.construct(delivered, SHAPE[cls]), **extra)


def sbo_txn(fc, transport, app, **extra):
    native = sbo.control_frame(transport, app, fc, response=True)
    return dict(request=sbo.control_frame(transport, app, fc), native=native, image=sbo.control_image(native), **extra)


def cycle(n, transport=0, app=0):
    """READ mixed, SELECT, OPERATE, READ integrity, ... with consecutive transport and application sequences."""
    makers = (lambda t, a: read_txn('mixed', t, a), lambda t, a: sbo_txn(3, t, a),
              lambda t, a: sbo_txn(4, t, a), lambda t, a: read_txn('integrity', t, a))
    return [makers[k % 4]((transport + k) & 63, (app + k) & 15) for k in range(n)]


def write_pcap(path, packets):
    from scapy.all import Ether, wrpcap
    out = []
    for t, raw in packets:
        pkt = Ether(raw)
        assert bytes(pkt) == raw
        pkt.time = 1_800_000_000 + t / 1000
        out.append(pkt)
    wrpcap(str(path), out)


def build(tmp, txns, client=1000, server=0xffffff00):
    """relay.pcap (mirror, both directions) and trial/{out,in}.pcap for one connection; server ISN wraps 2**32."""
    relay, out, inn, clock = [], [], [], [0]

    def emit(where, flags, seq, ack, reverse=False, payload=b''):
        clock[0] += 1
        for packets in where:
            packets.append((clock[0], vectors.packet(flags, seq, ack, reverse=reverse, payload=payload, tuple4=TUPLE)))

    emit([relay, out], SYN, client, 0)
    emit([relay, inn], SYN | ACK, server, client + 1, True)
    emit([relay, out], ACK, client + 1, server + 1)
    q = r = m = err = 0
    for x in txns:
        emit([out], PSHACK, client + 1 + q, server + 1 + m + err, payload=x['request'])
        if x.get('master_only'):
            q += len(x['request'])
            continue
        emit([relay], PSHACK, client + 1 + q, server + 1 + r + x.get('ack_error', 0), payload=x['request'])
        q += len(x['request'])
        emit([relay], PSHACK, server + 1 + r, client + 1 + q, True, x['native'])
        if x.get('retransmit') == 'relay':
            emit([relay], PSHACK, server + 1 + r, client + 1 + q, True, x['native'])
        r += len(x['native'])
        if x.get('relay_only'):
            continue
        err += x.get('seq_error', 0)
        emit([inn], PSHACK, server + 1 + m + err, client + 1 + q, True, x['image'])
        if x.get('retransmit') == 'master':
            emit([inn], PSHACK, server + 1 + m + err, client + 1 + q, True, x['image'])
        m += len(x['image'])
    trial = tmp / 'trial'
    trial.mkdir()
    write_pcap(tmp / 'relay.pcap', relay)
    write_pcap(trial / 'out.pcap', out)
    write_pcap(trial / 'in.pcap', inn)
    return tmp / 'relay.pcap', trial


def run(tmp, txns, label=True):
    relay, trial = build(tmp, txns)
    out = tmp / 'preservation.json'
    argv = ['--relay-pcap', str(relay), '--trial-dir', str(trial), '--master-port', str(TUPLE[2]),
            '--master-ip', '192.168.10.1', '--relay-ip', '192.168.10.7', '--out', str(out)]
    if label:
        argv += ['--build-label', LABEL, '--source-sha256', SHA]
    code = pc.main(argv)
    return code, (json.loads(out.read_text()) if out.exists() else None)


def fields(connection, kind='responses'):
    return [d['field'] for row in connection[kind]['differences'] for d in row['differences']]


def test_declared_construction_equals_the_repository_oracles_and_the_captured_images():
    declared = pd.load_declared(INPUTS)
    for variant in TEMPLATES.values():
        for cls, item in variant['classes'].items():
            name = 'mixed_g1v2_g30v1_91' if cls == 'mixed' else 'integrity_134'
            native = bytes.fromhex(item['native'])
            assert pd.read_image(native, declared['shapes'][name]) == bytes.fromhex(item['expected'])
            for transport in (0, 62, 63):
                renumbered = renumber(native, transport, 5)
                assert pd.read_image(renumbered, declared['shapes'][name]) == rpe.construct(renumbered, SHAPE[cls])
    for transport in (0, 63):
        native = sbo.control_frame(transport, 7, 4, response=True)
        assert pd.control_image(native, declared['control']['partition']) == sbo.control_image(native)


def test_a_identical_content_across_padding_passes(tmp_path):
    code, result = run(tmp_path, cycle(8))
    connection = result['connections'][0]
    assert code == 0 and result['ok'] and connection['ok']
    assert connection['responses']['identical'] == {'n': 8, 'of': 8}
    assert connection['requests']['identical'] == {'n': 8, 'of': 8}
    assert connection['responses']['forms'] == {'read_mixed_g1v2_g30v1_91': 2, 'control_image': 4,
                                                'read_integrity_134': 2}
    rows = connection['translation']
    assert [row['declared'] for row in rows] == [0, 0, 50, 61, 72, 96, 146, 157, 168]
    assert all(row['consistent'] for row in rows)
    assert connection['request_segments']['ack_consistent'] == {'n': 8, 'of': 8}
    assert result['build'] == dict(label=LABEL, source_sha256=SHA, inputs=str(INPUTS),
                                   inputs_sha256=result['build']['inputs_sha256'])
    assert result['totals']['responses_identical'] == {'n': 8, 'of': 8}


@pytest.mark.parametrize('change, field', [
    (lambda u: u.__setitem__(32, u[32] ^ 1), 'objects[1] g30v1 index 0 value'),
    (lambda u: u.__setitem__(12, 0x03), 'objects[0] g1v2 index 2 flags'),
    (lambda u: u.__setitem__(3, u[3] ^ 0x02), 'iin.IIN1.1 class_1_events'),
])
def test_b_a_changed_value_flag_or_iin_bit_is_detected_and_named(tmp_path, change, field):
    txns = cycle(4)
    txns[0] = read_txn('mixed', 0, 0, change=change)
    code, result = run(tmp_path, txns)
    connection = result['connections'][0]
    assert code == 1 and not connection['ok']
    assert connection['responses']['different'] == {'n': 1, 'of': 4}
    assert field in fields(connection)
    assert connection['responses']['differences'][0]['index'] == 0
    assert all(row['consistent'] for row in connection['translation'])


def drop_g30(user):
    del user[26:]


def swap_g10_g30(user):
    a, b = user[5:26], user[26:63]
    user[5:] = a + bytes(user[63:]) + b


@pytest.mark.parametrize('cls, change, kind', [('mixed', drop_g30, 'dropped'),
                                               ('integrity', swap_g10_g30, 'reordered')])
def test_c_a_dropped_or_reordered_object_is_detected(tmp_path, cls, change, kind):
    txns = cycle(4)
    txns[3 if cls == 'integrity' else 0] = read_txn(cls, 3 if cls == 'integrity' else 0,
                                                    3 if cls == 'integrity' else 0, change=change)
    code, result = run(tmp_path, txns)
    connection = result['connections'][0]
    assert code == 1
    headers = [d for row in connection['responses']['differences'] for d in row['differences']
               if d['field'] == 'object_headers']
    assert len(headers) == 1 and headers[0]['kind'] == kind


def test_d_a_wrong_sequence_translation_is_detected(tmp_path):
    txns = cycle(4)
    txns[2]['seq_error'] = 7
    code, result = run(tmp_path, txns)
    connection = result['connections'][0]
    assert code == 1 and not connection['ok']
    bad = [row for row in connection['translation'] if row['consistent'] is False]
    assert [(row['response'], row['observed'] - row['declared']) for row in bad] == [(2, 7), (3, 7)]
    assert connection['responses']['identical'] == {'n': 4, 'of': 4}


def test_d_a_request_ack_not_translated_is_detected(tmp_path):
    txns = cycle(4)
    txns[2]['ack_error'] = 5
    code, result = run(tmp_path, txns)
    segments = result['connections'][0]['request_segments']
    assert code == 1
    assert segments['ack_consistent'] == {'n': 3, 'of': 4}
    assert [m['relay_ack'] - m['expected'][0] for m in segments['mismatches']] == [5]


def test_e_transport_wrap_inside_a_padded_fragment_reassembles_and_passes(tmp_path):
    txns = cycle(5, transport=62)             # SELECT at 63 is reframed FIR|63 + FIN|0 as well
    txns[0] = read_txn('mixed', 63, 0)        # padded READ: prefix FIR|63, native FIN|0
    prefix, rest = pd.codec.parse_frame(txns[0]['image'])
    assert prefix.user_data[0] == 0x7f and pd.codec.parse_frame(rest)[0].user_data[0] == 0x80
    code, result = run(tmp_path, txns)
    connection = result['connections'][0]
    assert code == 0 and connection['ok']
    assert connection['responses']['identical'] == {'n': 5, 'of': 5}
    assert connection['tcp']['master_side']['from_relay']['framing_errors'] == []


def test_f_application_sequence_wrap_is_matched(tmp_path):
    txns = cycle(6, app=13)                  # application sequences 13, 14, 15, 0, 1, 2
    code, result = run(tmp_path, txns)
    connection = result['connections'][0]
    assert code == 0 and connection['ok']
    assert [row['app_seq'] for row in connection['responses']['transactions']] == [13, 14, 15, 0, 1, 2]
    assert connection['responses']['unmatched']['relay_side'] == {'n': 0, 'of': 6}


@pytest.mark.parametrize('side', ['relay', 'master'])
def test_g_a_retransmitted_segment_is_reported_not_a_difference(tmp_path, side):
    txns = cycle(4)
    txns[1]['retransmit'] = side
    code, result = run(tmp_path, txns)
    connection = result['connections'][0]
    assert code == 0 and connection['ok']
    stream = connection['tcp'][side + '_side']['from_relay']
    assert stream['retransmitted_segments'] == 1 and len(stream['retransmitted']) == 1
    other = connection['tcp'][('master' if side == 'relay' else 'relay') + '_side']['from_relay']
    assert other['retransmitted_segments'] == 0
    assert result['totals']['retransmitted_segments_' + side + '_side']['n'] == 1


def test_h_an_unmatched_transaction_on_either_side_is_reported(tmp_path):
    txns = cycle(5)
    txns[1]['relay_only'] = True             # the relay answered; no image reached the master
    txns[4]['master_only'] = True            # the master sent a request that never left toward the relay
    code, result = run(tmp_path, txns)
    connection = result['connections'][0]
    assert code == 1 and not connection['ok']
    assert connection['responses']['unmatched']['relay_side'] == {'n': 1, 'of': 4}
    assert [u['app_seq'] for u in connection['responses']['unmatched_items']['relay_side']] == [1]
    assert connection['requests']['unmatched']['master_side'] == {'n': 1, 'of': 5}
    assert [u['app_seq'] for u in connection['requests']['unmatched_items']['master_side']] == [4]
    assert connection['responses']['identical'] == {'n': 3, 'of': 3}
    assert [row['consistent'] for row in connection['translation'][2:]] == [None, None]


@pytest.mark.parametrize('drop', ['--build-label', '--source-sha256'])
def test_i_missing_build_label_is_refused(tmp_path, drop, capsys):
    relay, trial = build(tmp_path, cycle(2))
    out = tmp_path / 'preservation.json'
    argv = ['--relay-pcap', str(relay), '--trial-dir', str(trial), '--master-port', str(TUPLE[2]),
            '--master-ip', '192.168.10.1', '--relay-ip', '192.168.10.7', '--out', str(out),
            '--build-label', LABEL, '--source-sha256', SHA]
    del argv[argv.index(drop):argv.index(drop) + 2]
    assert pc.main(argv) == 2 and not out.exists()
    assert 'REFUSED' in capsys.readouterr().err


def test_i_a_label_that_disagrees_with_the_build_inputs_is_refused(tmp_path):
    relay, trial = build(tmp_path, cycle(2))
    out = tmp_path / 'preservation.json'
    argv = ['--relay-pcap', str(relay), '--trial-dir', str(trial), '--master-port', str(TUPLE[2]),
            '--master-ip', '192.168.10.1', '--relay-ip', '192.168.10.7', '--out', str(out),
            '--build-label', LABEL, '--source-sha256', '0' * 64]
    assert pc.main(argv) == 2 and not out.exists()


def test_command_line_end_to_end_writes_the_json(tmp_path):
    relay, trial = build(tmp_path, cycle(4))
    out = tmp_path / 'cli.json'
    done = subprocess.run([sys.executable, str(ROOT / 'scripts/analysis/preservation_check.py'),
                           '--relay-pcap', str(relay), '--trial-dir', str(trial), '--master-port', str(TUPLE[2]),
                           '--master-ip', '192.168.10.1', '--relay-ip', '192.168.10.7', '--out', str(out),
                           '--build-label', LABEL, '--source-sha256', SHA], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    result = json.loads(out.read_text())
    assert result['schema'] == pc.SCHEMA and result['ok'] and result['build']['label'] == LABEL
    assert result['totals']['responses_identical'] == {'n': 4, 'of': 4}
