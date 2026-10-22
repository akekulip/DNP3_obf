"""Regressions for the d531918e2 review's readout counterexamples (Python >= 3.10, research venv).

Every case works on a COPY of retained evidence in tmp_path; the original block is only read.
"""
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
READOUT = ROOT / 'analysis/hw_read_readout.py'
BLOCK = ROOT / 'evidence/hw_blocks/rc01_hw_b08_20261021_01_reference'
CONFIG = ROOT / 'hw/config/rc01_m12p_b08_reference.json'
OFF = 'rc01_hw_b08_20261021_01_reference_separate_ack_off_t0'


def copy_off(tmp_path):
    block = tmp_path / BLOCK.name
    shutil.copytree(BLOCK / 'separate_ack/off' / OFF, block / 'separate_ack/off' / OFF)
    for name in ('campaign_run.json', 'freeze_check.json'):
        shutil.copy(BLOCK / name, block / name)
    return block, block / 'separate_ack/off' / OFF


def readout(block, *extra):
    out = block / 'readout.json'
    r = subprocess.run([sys.executable, str(READOUT), str(block), '--config', str(CONFIG), '--out', str(out)]
                       + list(extra), capture_output=True, text=True)
    return r.returncode, json.loads(out.read_text())


def records(pcap):
    data = pcap.read_bytes()
    out, pos = [], 24
    while pos + 16 <= len(data):
        incl = struct.unpack_from('<I', data, pos + 8)[0]
        out.append(data[pos:pos + 16 + incl])
        pos += 16 + incl
    return data[:24], out


def o2m_payload(rec):
    """TCP payload length of an outstation->master packet record (0 for any other packet)."""
    f = rec[16:]
    if len(f) < 54 or f[26:30] != bytes([192, 168, 10, 62]) or f[23] != 6:
        return 0
    ihl = (f[14] & 15) * 4
    return int.from_bytes(f[16:18], 'big') - ihl - (f[14 + ihl + 12] >> 4) * 4


def test_the_retained_native_arm_passes_with_every_planned_exchange(tmp_path):
    block, _ = copy_off(tmp_path)
    rc, report = readout(block, '--arms', 'off')
    assert rc == 0 and report['ok'] is True
    kinds = report['trials'][0]['summary']['by_kind']
    assert {k: (v['n'], v['exact']) for k, v in kinds.items()} == {'READ': (65, 65), 'SELECT': (64, 64),
                                                                   'OPERATE': (64, 64)}


def test_valid_but_empty_captures_fail(tmp_path):
    block, trial = copy_off(tmp_path)
    header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for name in ('in.pcap', 'out.pcap'):
        (trial / name).write_bytes(header)
    rc, report = readout(block, '--arms', 'off')
    assert rc == 1 and report['ok'] is False


def test_a_capture_missing_its_final_response_fails(tmp_path):
    block, trial = copy_off(tmp_path)
    head, recs = records(trial / 'in.pcap')
    resp = [i for i, r in enumerate(recs) if o2m_payload(r) > 0]
    (trial / 'in.pcap').write_bytes(head + b''.join(r for i, r in enumerate(recs) if i != resp[-1]))
    rc, report = readout(block, '--arms', 'off')
    assert rc == 1 and any('exchange counts differ' in f or 'by kind' in f for f in report['failures'])


def test_a_truncated_capture_fails(tmp_path):
    block, trial = copy_off(tmp_path)
    data = (trial / 'in.pcap').read_bytes()
    (trial / 'in.pcap').write_bytes(data[:-7])
    rc, report = readout(block, '--arms', 'off')
    assert rc == 1 and any('truncated' in f for f in report['failures'])


def test_a_planned_arm_that_never_ran_fails(tmp_path):
    block, _ = copy_off(tmp_path)
    rc, report = readout(block, '--arms', 'off,combined')
    assert rc == 1 and any('combined' in f and 'absent' in f for f in report['failures'])


# ---- review of the rewrite (B1-B3, B5, B11): positive padded case and further fail-closed cases ----
import importlib.util  # noqa: E402

SIZE = 'rc01_hw_b08_20261021_01_reference_separate_ack_size_only_t0'


def module():
    spec = importlib.util.spec_from_file_location('readout_under_test', READOUT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def rewrite_o2m(pcap, transform):
    """Rewrite every outstation->master payload with transform(payload) -> bytes, shifting later sequence numbers
    by the cumulative length change (IP length updated; checksums are not checked by the readout)."""
    head, recs = records(pcap)
    out, shift = [], 0
    for r in recs:
        f = bytearray(r[16:])
        if len(f) >= 54 and f[26:30] == bytes([192, 168, 10, 62]) and f[23] == 6:
            ihl = (f[14] & 15) * 4
            o = 14 + ihl
            doff = (f[o + 12] >> 4) * 4
            total = int.from_bytes(f[16:18], 'big')
            payload = bytes(f[o + doff:14 + total])
            seq = (int.from_bytes(f[o + 4:o + 8], 'big') + shift) & 0xFFFFFFFF
            f[o + 4:o + 8] = seq.to_bytes(4, 'big')
            if payload:
                new = transform(payload)
                shift += len(new) - len(payload)
                f = f[:o + doff] + new
                f[16:18] = (ihl + doff + len(new)).to_bytes(2, 'big')
        hdr = bytearray(r[:16])
        hdr[8:12] = struct.pack('<I', len(f))
        hdr[12:16] = struct.pack('<I', len(f))
        out.append(bytes(hdr) + bytes(f))
    pcap.write_bytes(head + b''.join(out))


def padded_size_only_block(tmp_path):
    """The retained native capture with each master-received response replaced by its expected padded image:
    what a working padder would have delivered, as an independent positive control for the readout."""
    m = module()
    block, trial = copy_off(tmp_path)
    size_trial = block / 'separate_ack/size_only' / SIZE
    shutil.copytree(trial, size_trial)
    req = [f for f in m.fragments(*m.stream(m.tcp_packets(size_trial / 'in.pcap'),
                                             ('192.168.10.61', 60000), ('192.168.10.62', 20000))[:3])
           if f['app'][1] != 0]
    it = iter(req)

    def pad(payload):
        q = next(it)
        kind = m.KINDS[q['app'][1]]
        return m.expected_image(kind, bytes(q['bytes']), payload, 1)[0]
    rewrite_o2m(size_trial / 'in.pcap', pad)
    return block


def test_a_correctly_padded_size_arm_passes(tmp_path):
    block = padded_size_only_block(tmp_path)
    rc, report = readout(block, '--arms', 'size_only')
    assert rc == 0 and report['ok'] is True, report['failures'][:5]
    kinds = report['trials'][0]['summary']['by_kind']
    assert kinds['READ']['master_lens'] == [[141, 65]] and kinds['SELECT']['master_lens'] == [[61, 64]]
    assert report['partial_arms_omitted'] == ['combined', 'off', 'timing_only']


def test_a_substituted_config_fails(tmp_path):
    block, _ = copy_off(tmp_path)
    other = tmp_path / 'other.json'
    cfg = json.loads(CONFIG.read_text())
    cfg['arms'] = [dict(a, padding=0) for a in cfg['arms']]
    other.write_text(json.dumps(cfg))
    out = block / 'r.json'
    r = subprocess.run([sys.executable, str(READOUT), str(block), '--config', str(other), '--arms', 'off',
                        '--out', str(out)], capture_output=True, text=True)
    assert r.returncode == 1 and any('not the config this block ran' in f for f in json.loads(out.read_text())['failures'])


def test_a_padding_on_read_the_policy_cannot_pad_fails(monkeypatch):
    m = module()
    monkeypatch.setattr(m.gp, 'pad_read', lambda *a, **k: m.gp.Result('unreachable', b'x', None, 1, reason='test'))
    try:
        m.expected_image('READ', b'q', b'x', 1)
    except m.ReadoutError as error:
        assert 'unreachable' in str(error)
    else:
        raise AssertionError('an unreachable READ was accepted')


def test_a_capture_without_the_handshake_fails(tmp_path):
    block, trial = copy_off(tmp_path)
    head, recs = records(trial / 'in.pcap')
    keep = [r for r in recs if not (len(r) > 16 + 54 and r[16 + 47] & 0x02)]
    (trial / 'in.pcap').write_bytes(head + b''.join(keep))
    rc, report = readout(block, '--arms', 'off')
    assert rc == 1 and any('SYN' in f for f in report['failures'])


def test_a_retransmission_with_different_bytes_fails(tmp_path):
    block, trial = copy_off(tmp_path)
    head, recs = records(trial / 'in.pcap')
    i = next(i for i, r in enumerate(recs) if o2m_payload(r) > 0)
    dup = bytearray(recs[i])
    end = 16 + 14 + int.from_bytes(dup[16 + 16:16 + 18], 'big')
    dup[end - 1] ^= 0xFF                                          # last TCP payload octet, not Ethernet padding
    (trial / 'in.pcap').write_bytes(head + b''.join(recs[:i + 1] + [bytes(dup)] + recs[i + 1:]))
    rc, report = readout(block, '--arms', 'off')
    assert rc == 1 and any('disagree' in f for f in report['failures'])


def test_an_extra_response_fails(tmp_path):
    block, trial = copy_off(tmp_path)
    rewrite_o2m(trial / 'in.pcap', lambda payload: payload * 2)      # every response delivered twice in-stream
    rc, report = readout(block, '--arms', 'off')
    assert rc == 1 and any('exchange counts differ' in f for f in report['failures'])


# ---- READ-class schedule (fixture endpoint rotate4) ----
ENDPOINT_EVIDENCE = ROOT.parents[3] / 'evidence/rearm_01/repeat_sbo_endpoint/loopback_evidence_20261021'


def test_the_schedule_counts_follow_the_endpoint_formula():
    m = module()
    assert m.schedule_counts('rotate4', 65) == {'range': 17, 'analog': 16, 'class0': 16, 'integrity': 16}
    assert m.schedule_counts(None, 65) == {'range': 65}


def test_read_classes_are_taken_from_real_request_bytes():
    m = module()
    sys.path.insert(0, str(ROOT / 'software/source/read_reencode_01'))
    import capture
    import dnp3_std as std
    runs = sorted(p for p in ENDPOINT_EVIDENCE.iterdir() if p.is_dir() and 'rotate4_base' in p.name)
    assert runs, 'loopback evidence of the scheduled endpoint is missing'
    pcap = runs[0] / 'capture.pcap'
    seen = []
    for rec in capture.tcp_records(pcap):
        p = rec['payload']
        if rec['dst'][1] == 20000 and p[:2] == b'\x05\x64':
            user = std.deframe(p[:std.frame_length(p[2] - 5)])[1]
            if user[2] == 0x01:                                 # application function READ
                seen.append(m.read_class(user[1:]))
    assert seen[:8] == list(m.ROTATE4) * 2


# ---- two-READ-target profile (mixed 91 -> 141, full 247 -> 271) ----
TWO = json.loads((ROOT / 'vectors/two_read_templates.json').read_text())
TWO_DECL = ({'mixed': 141, 'integrity': 271}, {'mixed': 26, 'integrity': 4})


def test_two_read_schedule_counts():
    m = module()
    assert m.schedule_counts('mixed_full', 65) == {'mixed': 33, 'integrity': 32}
    assert m.schedule_counts('mixed', 20) == {'mixed': 20}
    assert m.schedule_counts('full', 20) == {'integrity': 20}


def test_two_read_classes_from_the_captured_requests():
    m = module()
    sys.path.insert(0, str(ROOT / 'software/source/read_reencode_01'))
    import dnp3_std as std
    for cls in ('mixed', 'integrity'):
        user = std.deframe(bytes.fromhex(TWO['variants']['v0']['classes'][cls]['request']))[1]
        assert m.read_class(user[1:]) == cls


def test_two_read_expected_images_and_declaration():
    m = module()
    targets = m.read_targets(TWO_DECL)
    assert targets == [141, 271]
    for name, variant in TWO['variants'].items():
        for cls, t in variant['classes'].items():
            want, info = m.expected_image('READ', bytes.fromhex(t['request']), bytes.fromhex(t['native']), 1, targets)
            assert want.hex() == t['expected'], (name, cls)
            assert m.check_read_encoding(cls, info, len(want), TWO_DECL) == []
            # the frozen policy's targets would leave the 247 full READ native: the declaration catches it
            frozen, finfo = m.expected_image('READ', bytes.fromhex(t['request']), bytes.fromhex(t['native']), 1)
            if cls == 'integrity':
                assert len(frozen) == 247 and m.check_read_encoding(cls, finfo, len(frozen), TWO_DECL)
            # a wrong declared count or image fails
            assert m.check_read_encoding(cls, dict(info, padding_points=info['padding_points'] + 1), len(want),
                                         TWO_DECL)
            assert m.check_read_encoding(cls, info, len(want) + 1, TWO_DECL)


def test_two_read_declaration_comes_from_the_frozen_config():
    m = module()
    cfg = {'arms': [{'name': 'combined', 'build': 'b'}, {'name': 'off', 'build': 'b'}],
           'builds': {'b': {'read_images': {'mixed': 141, 'integrity': 271}, 'read_padding': {'mixed': 26,
                                                                                               'integrity': 4}}}}
    assert m.two_read_declaration(cfg, 'combined') == TWO_DECL
    del cfg['builds']['b']['read_padding']
    assert m.two_read_declaration(cfg, 'combined') is None and m.read_targets(None) == m.TARGETS
