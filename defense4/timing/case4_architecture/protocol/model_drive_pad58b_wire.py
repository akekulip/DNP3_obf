"""Local Tofino-1 model run of case4_pad58b_wire.p4: native-CRC gate in front of the 58-byte pad.

Functional model execution only: not hardware, not timing, not a combined pipe-0 fit.

  integration/core/launch_model.sh -p protocol/evidence/pad58b_wire_02/out \
     -o protocol/evidence/pad58b_wire_02/model_NN -P "1 2" -d protocol/model_drive_pad58b_wire.py

Every input frame and every expected output is produced here by the software oracle
(framework/size/case4_pad58b.py over case4_padding.build_frame), never hand-copied:
  - a CRC-valid native READ / CONTROL frame must leave byte-identical to the oracle's padded image
    (with the IPv4 length/checksum and TCP checksum the egress deparser recomputes);
  - a frame with any one native link CRC wrong must leave byte-identical to what went in, which is
    exactly what the oracle returns for it (asserted here too, so the oracle and the P4 are held to
    the same verdict).
"""
import os
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent
sys.path[:0] = [str(CASE4 / 'integration' / 'core'), str(CASE4.parent / 'framework' / 'size')]
from model_driver import Model, Report  # noqa: E402
import case4_pad58b as b  # noqa: E402
import case4_padding as pad  # noqa: E402

IN, OUT = 1, 2
ETH = bytes.fromhex('0a0000000002' '0a0000000001') + b'\x08\x00'
LINK_HEAD = bytes.fromhex('056419c40a000100')     # len byte is rewritten by build_frame
READ_USER = bytes([0xc7, 0xc5, 0x81, 0x80, 0x00]) + b.HEADER_READ23 + bytes(range(1, 24))
CTL_USER = bytes([0xc3, 0xc2, 0x81, 0x00, 0x00]) + b.HEADER_CROB28 + bytes(
    [0x05, 0x00, 0x03, 0x01, 0x64, 0, 0, 0, 0x64, 0, 0, 0, 0x00])
# The P4's CONTROL filler is a compile-time constant (ctl_eligible's filler_a/filler_b); these are the
# two G41V3 points it encodes. If they were wrong, the CONTROL-valid case below would fail.
CTL_POINTS = [b.AnalogFloatPoint(301, 10.0, 0), b.AnalogFloatPoint(302, 20.0, 0)]


def csum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def packet(dnp3):
    src, dst = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
    tcp = struct.pack('!HHIIBBHHH', 20000, 40000, 0x11111111, 0x22222222, 0x50, 0x18, 8192, 0, 0)
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(dnp3))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + dnp3)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(dnp3), 0x1234, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ETH + ip + tcp + dnp3


def flip(frame, i):
    f = bytearray(frame)
    f[i] ^= 0x01
    return bytes(f)


m = Model(ports=[IN, OUT])
rep = Report(os.environ['PROG'])
rep.add('ports_enabled', {}, m.port_errors, ok=not m.port_errors)
m.add('Ingress.forwarding', {'ig.ingress_port': IN}, 'Ingress.route', {'port': OUT})

read_native = pad.build_frame(LINK_HEAD, READ_USER)
ctl_native = pad.build_frame(LINK_HEAD, CTL_USER)
read_img, read_grow = b.pad_read_response(read_native)
ctl_img, ctl_grow = b.pad_control_response(ctl_native, CTL_POINTS)
rep.add('oracle_read_grows_9', 9, read_grow)
rep.add('oracle_ctl_grows_21', 21, ctl_grow)


def run(name, dnp3_in, dnp3_expected):
    sent = packet(dnp3_in)
    want = packet(dnp3_expected)
    got = m.exchange(IN, sent, [OUT], timeout=2.0, quiet=0.5)[OUT]
    rep.add(name, 1, len(got), sent=sent, want=want, received=[g.hex() for g in got])
    rep.add(name + '_byte_identical', True, bool(got) and got[0] == want,
            first_diff=(next((i for i, (x, y) in enumerate(zip(got[0], want)) if x != y),
                             min(len(got[0]), len(want))) if got and got[0] != want else None))


run('read_valid_padded', read_native, read_img)
run('ctl_valid_padded', ctl_native, ctl_img)

# One corruption per validated CRC site. Offsets are within the DNP3 link frame:
# READ  = head[0:8] crc[8:10] | blk0[10:26] crc[26:28] | blk1[28:44] crc[44:46] | tail[46] crc[47:49]
# CTRL  = head[0:8] crc[8:10] | blk0[10:26] crc[26:28] | tail[28:35] crc[35:37]
corrupt = [('read', read_native, 'head_crc', 8), ('read', read_native, 'head_byte_dst', 4),
           ('read', read_native, 'blk0_data', 20), ('read', read_native, 'blk0_crc', 27),
           ('read', read_native, 'blk1_data', 30), ('read', read_native, 'blk1_crc', 44),
           ('read', read_native, 'tail_data', 46), ('read', read_native, 'tail_crc', 48),
           ('ctl', ctl_native, 'head_crc', 9), ('ctl', ctl_native, 'head_byte_src', 6),
           ('ctl', ctl_native, 'blk0_data', 15), ('ctl', ctl_native, 'blk0_crc', 26),
           ('ctl', ctl_native, 'tail_data', 30), ('ctl', ctl_native, 'tail_crc', 36)]
for role, native, site, i in corrupt:
    bad = flip(native, i)
    o, g = (b.pad_read_response(bad) if role == 'read' else b.pad_control_response(bad, CTL_POINTS))
    rep.add('oracle_%s_%s_unchanged' % (role, site), (True, 0), (o == bad, g))
    run('%s_corrupt_%s_passthrough' % (role, site), bad, bad)

sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)
