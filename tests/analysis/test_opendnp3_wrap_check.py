"""opendnp3 (pydnp3) replay of the retained c72 padded READ responses, including the 63 -> 0 transport wraps."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import opendnp3_wrap_check as owc  # noqa: E402

E01 = next((ROOT / 'results/hardware/blocks/rc01_hw_c72_eval_20261027_01_e01_d5_r01/physical_relay/combined'
            ).glob('*_t0'))


def exchanges():
    return json.loads((E01 / 'relay_wire.json').read_text())['exchanges']


def read_wires():
    return [bytes.fromhex(e['response']['wire_hex']) for e in exchanges() if e['operation'] == 'READ']


def allowed_offsets(wire):
    """The first segment's application control byte and the two CRC octets of the data block holding it."""
    p, length = owc.idec.link_frames(wire)[0]
    block = min(16, length - 12)
    return {p + 11, p + 10 + block, p + 11 + block}


def test_app_seq_rewrite_changes_only_the_nibble_and_its_block_crc():
    for wire in read_wires():
        old = wire[owc.idec.link_frames(wire)[0][0] + 11]
        new_seq = (old + 5) & 15
        out, changes = owc.set_app_seq(wire, new_seq)
        p = owc.idec.link_frames(wire)[0][0]
        assert len(out) == len(wire)
        assert out[p + 11] == (old & 0xf0) | new_seq
        diff = [i for i, (a, b) in enumerate(zip(wire, out)) if a != b]
        assert set(diff) <= allowed_offsets(wire) and p + 11 in diff
        assert [c['offset'] for c in changes] == diff
        assert all(bytes.fromhex(c['old'])[0] == wire[c['offset']] and bytes.fromhex(c['new'])[0] == out[c['offset']]
                   for c in changes)
        assert {c['field'] for c in changes} <= {'app_ctrl', 'block_crc'}
        for q, length in owc.idec.link_frames(out):
            frame, _ = owc.dnp3_codec.parse_frame(out[q:q + length], verify_crc=True)
            assert frame is not None
        assert owc.dnp3_codec.parse_application_response(
            owc.application_fragment(out)).app_seq == new_seq


def test_app_seq_rewrite_is_empty_when_the_sequence_already_matches():
    wire = read_wires()[0]
    out, changes = owc.set_app_seq(wire, wire[11] & 15)
    assert out == wire and changes == []


def test_transport_header_bytes_are_never_rewritten():
    wraps = [w for w in read_wires() if owc.idec.wraps(w)]
    assert wraps
    for wire in read_wires():
        out, _ = owc.set_app_seq(wire, (wire[11] + 1) & 15)
        assert [out[p + 10] for p, _ in owc.idec.link_frames(out)] == [wire[p + 10] for p, _ in
                                                                        owc.idec.link_frames(wire)]
    for wire in wraps:
        out, _ = owc.set_app_seq(wire, (wire[11] + 1) & 15)
        assert [out[p + 10] for p, _ in owc.idec.link_frames(out)] == [0x7f, 0x80]


def test_wrap_detector_finds_the_three_known_wraps_in_e01():
    ex = exchanges()
    assert owc.wrap_indices(ex) == [28, 92, 156]
    assert [ex[i]['operation'] for i in owc.wrap_indices(ex)] == ['SELECT', 'OPERATE', 'READ']


def test_control_changes_are_labelled_transport_and_keep_valid_crcs():
    wire = next(w for w in read_wires() if owc.idec.wraps(w))
    sent, changes = owc.prepare(wire, (wire[11] + 3) & 15, control=True)
    assert [sent[p + 10] & 0x3f for p, _ in owc.idec.link_frames(sent)] == [0, 1]
    assert {c['field'] for c in changes} == {'transport', 'app_ctrl', 'block_crc'}
    for q, length in owc.idec.link_frames(sent):
        assert owc.dnp3_codec.parse_frame(sent[q:q + length], verify_crc=True)[0] is not None


def test_recorded_read_requests_map_to_opendnp3_headers():
    assert owc.scan_headers('c001010200000f1e01000007') == [('range8', 1, 2, 0, 15), ('range8', 30, 1, 0, 7)]
    assert owc.scan_headers('c3013c02063c03063c04063c0106') == [('all', 60, 2), ('all', 60, 3), ('all', 60, 4),
                                                                ('all', 60, 1)]
    with pytest.raises(ValueError):
        owc.scan_headers('c0030c0117')


def test_codec_view_lists_every_object_header_and_point():
    e = next(e for e in exchanges() if e['operation'] == 'READ')
    problems, objects = owc.codec_view(e['application']['response_app_hex'])
    assert problems == []
    assert [(o['group'], o['variation'], o['qualifier'], len(o['points'])) for o in objects] == [
        (1, 2, 1, 26), (1, 2, 0, 16), (30, 1, 0, 8)]
    assert objects[0]['points'][0] == [1024, False] and objects[2]['points'][0] == [0, 5]


def pydnp3_import_error():
    run = subprocess.run([sys.executable, '-c', 'import pydnp3'], capture_output=True, text=True)
    return None if run.returncode == 0 else run.stderr.strip().splitlines()[-1]


def in_subprocess(body):
    """Run pydnp3 work in a child (pydnp3 double-frees at interpreter teardown); `body` assigns `r`."""
    error = pydnp3_import_error()
    if error:
        pytest.skip('BLOCKER: pydnp3 does not import: %s' % error)
    code = ('import json, os, sys; sys.path.insert(0, %r); import opendnp3_wrap_check as m; E01 = %r\n%s\n'
            'print("RESULT" + json.dumps(r)); sys.stdout.flush(); os._exit(0)'
            % (str(ROOT / 'scripts/analysis'), str(E01), body))
    run = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=120,
                         env=dict(os.environ, PYTHONUNBUFFERED='1'))
    line = next((x for x in run.stdout.splitlines() if x.startswith('RESULT')), None)
    assert line is not None, run.stderr[-2000:]
    return json.loads(line[len('RESULT'):])


def test_harness_detects_a_broken_transport_sequence():
    """Negative control: the e01 wrap response with its second segment renumbered 63 -> 5 must be rejected."""
    report = in_subprocess('r = m.negative_control(E01)')
    run, row = report['run'], report['run']['responses'][0]
    assert report['read_index'] == 52 and report['rejected'] and not run['run_ok']
    assert row['sent_transport_seqs'] == [63, 5] and row['completion'] == 'FAILURE_RESPONSE_TIMEOUT'
    assert any('bad sequence' in w for w in row['warnings']), row['warnings']
    assert run['stack_error_counters']['numTransportIgnore'] >= 1


def test_end_to_end_opendnp3_replay_around_the_e01_wrap():
    report = in_subprocess('r = m.check_connection(E01, reads=range(50, 55))')
    for run_name in ('test', 'control'):
        r = report[run_name]
        assert (r['replayed'], r['wrap'], r['delivered_ok'], r['errors']) == (5, 1, 5, 0), r
        assert r['unexpected_requests'] == [] and r['server_errors'] == [] and r['run_ok']
    wrap = next(x for x in report['test']['responses'] if x['wrap'])
    assert wrap['read_index'] == 52 and wrap['sent_transport_seqs'] == [63, 0] and wrap['ok']
    assert {c['field'] for c in wrap['byte_changes']} <= {'app_ctrl', 'block_crc'}
    assert any('SEQ: 63' in line for line in wrap['transport_rx'])
    control = next(x for x in report['control']['responses'] if x['wrap'])
    assert control['sent_transport_seqs'] == [0, 1] and control['ok']
