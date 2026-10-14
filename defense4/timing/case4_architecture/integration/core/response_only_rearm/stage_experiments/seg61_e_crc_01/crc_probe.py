#!/usr/bin/env python3
"""Independent check of the control-tail CRC factorization before any P4 change (f0baa724a audit, Gate 4).

For a zero-status eligible control response with native transport sequence s, candidate61 segment 2 carries
user octets TH2(s) || B (B = the six unchanged CROB tail octets on_lo[2] || off[4]) and segment 3 carries
TH3(s) || 0x00. The DNP3 CRC is affine over GF(2) (reflected 0x3D65, init 0, complemented), so for equal-length
inputs CRC(a ^ b ^ c) = CRC(a) ^ CRC(b) ^ CRC(c). With a = 0x00||B, b = TH2||0^6, c = 0^7:
    base     = CRC(0x00 || B)                       computable before the sequence lookup
    delta[s] = CRC(TH2(s) || 0^6) ^ CRC(0^7)          a per-sequence constant
    CRC2     = base ^ delta[s]
    CRC3[s]  = CRC(TH3(s) || 0x00)                    a per-sequence constant
TH2/TH3 are read from the qualified P4's ctl_sequences_t entries, not recomputed. Every sequence is checked
against RANDOM_TAILS seeded random tails numerically, and a subset is checked as emitted little-endian bytes
inside the full 61-octet image built by the seg61_01 encode61 oracle.
"""
import json
import random
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
P4 = HERE.parent / 'seg61_02/evidence/full_04/response_only.p4'
sys.path.insert(0, str(HERE.parent / 'read_reencode_01'))
sys.path.insert(0, str(HERE.parent / 'seg61_01'))
import dnp3_std as std  # noqa: E402
import encode61  # noqa: E402

RANDOM_TAILS = 65536
EMITTED_PER_SEQUENCE = 256
SEED = 1815

_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA6BC if _c & 1 else _c >> 1
    _TABLE.append(_c)


def crc(data):
    """Table form of dnp3_std.crc (checked against it below)."""
    c = 0
    for b in data:
        c = (c >> 8) ^ _TABLE[(c ^ b) & 0xFF]
    return (~c) & 0xFFFF


def sequence_table():
    text = P4.read_text()
    body = text[text.index('table ctl_sequences_t'):]
    body = body[:body.index('}', body.index('const entries'))]
    rows = {int(k): (int(a), int(b)) for k, a, b in re.findall(r'8w(\d+):ctl_sequences\(8w(\d+),8w(\d+)\)', body)}
    assert sorted(rows) == list(range(192, 256)), 'ctl_sequences_t must hold the 64 FIR|FIN control bytes'
    return {k - 192: v for k, v in rows.items()}


def control_frame(s, tail6, app_seq=0):
    """Native 37-octet zero-status SELECT response with transport sequence s and the given six tail octets."""
    head = bytes.fromhex('05641c4401000a00')
    user = bytes((0xC0 | s, 0xC0 | app_seq, 0x81, 0, 0)) + bytes.fromhex('0c012801000100') + b'\x01\x01' + \
        b'\x64\x00' + tail6 + b'\x00'
    return std.frame(head[:2] + bytes([5 + len(user)]) + head[3:], user)


def main():
    rng = random.Random(SEED)
    for _ in range(1000):                                   # the table CRC is the standard CRC
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 17)))
        assert crc(data) == std.crc(data)
    seqs = sequence_table()
    zero7 = crc(bytes(7))
    tails = [bytes(rng.randrange(256) for _ in range(6)) for _ in range(RANDOM_TAILS)]
    constants, numeric, emitted = {}, 0, 0
    for s, (th2, th3) in sorted(seqs.items()):
        assert th2 == (s + 1) & 0x3F and th3 == 0x80 | ((s + 2) & 0x3F), (s, th2, th3)
        delta = crc(bytes([th2]) + bytes(6)) ^ zero7
        crc3 = crc(bytes([th3, 0]))
        constants[s] = {'th2': th2, 'th3': th3, 'delta': delta, 'crc3': crc3}
        for tail in tails:
            assert crc(bytes([th2]) + tail) == crc(b'\x00' + tail) ^ delta, (s, tail.hex())
            numeric += 1
        for tail in tails[s * EMITTED_PER_SEQUENCE:(s + 1) * EMITTED_PER_SEQUENCE]:
            image = encode61.ctl61(control_frame(s, tail))
            frames = encode61.split_frames(image)
            assert [len(f) for f in frames] == [28, 19, 14]
            seg2, seg3 = frames[1], frames[2]
            assert seg2[10:17] == bytes([th2]) + tail
            assert seg2[17:19] == struct.pack('<H', crc(b'\x00' + tail) ^ delta)        # little-endian on the wire
            assert seg3[10:12] == bytes([th3, 0]) and seg3[12:14] == struct.pack('<H', crc3)
            emitted += 1
    result = {'p4': str(P4.relative_to(HERE.parents[4])), 'sequences': len(seqs), 'random_tails': RANDOM_TAILS,
              'numeric_checks': numeric, 'emitted_image_checks': emitted, 'seed': SEED, 'zero7_crc': zero7,
              'constants': constants, 'result': 'PASS'}
    out = HERE / 'crc_probe_result.json'
    out.write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps({k: result[k] for k in ('sequences', 'random_tails', 'numeric_checks', 'emitted_image_checks',
                                             'result')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
