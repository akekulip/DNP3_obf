"""Independent byte builders/oracles for model tests (no P4 semantics inside).

Checksums are the RFC 1071 reference; DNP3 CRC and link framing come from framework/size/rrc.py and
case4_padding.py (the software codec the paper line already uses), so the model is compared to code
that shares nothing with the P4 sources.
"""
import struct
import sys
from pathlib import Path

_FW = Path(__file__).resolve().parents[3] / 'framework' / 'size'
if str(_FW) not in sys.path:
    sys.path.insert(0, str(_FW))
import rrc  # noqa: E402
from case4_padding import build_frame as dnp3_build, decode_frame as dnp3_decode  # noqa: E402

ETH_DST, ETH_SRC = bytes.fromhex('001122334455'), bytes.fromhex('aabbccddeeff')
CLIENT = (0x0a000001, 30001)
SERVER = (0x0a000002, 20000)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def tcp_frame(src, dst, flags, seq, ack, payload=b'', mss=None, *, ttl=64, ip_id=1, window=4096,
              bad_ip=False, bad_tcp=False, ip_len=None, ip_flags_frag=0x4000, urgent=0):
    """Ethernet+IPv4+TCP frame. src/dst are (ip, port). bad_* flip one checksum bit."""
    opt = b'' if mss is None else struct.pack('!BBH', 2, 4, mss)
    tcp = struct.pack('!HHIIBBHHH', src[1], dst[1], seq, ack, ((20 + len(opt)) // 4) << 4, flags,
                      window, 0, urgent) + opt + payload
    pseudo = struct.pack('!IIBBH', src[0], dst[0], 0, 6, len(tcp))
    c = checksum(pseudo + tcp) ^ (1 if bad_tcp else 0)
    tcp = tcp[:16] + struct.pack('!H', c) + tcp[18:]
    ip = struct.pack('!BBHHHBBHII', 0x45, 0, ip_len if ip_len is not None else 20 + len(tcp), ip_id,
                     ip_flags_frag, ttl, 6, 0, src[0], dst[0])
    c = checksum(ip) ^ (1 if bad_ip else 0)
    ip = ip[:10] + struct.pack('!H', c) + ip[12:]
    return ETH_DST + ETH_SRC + b'\x08\x00' + ip + tcp


def link_header(ctrl, dst, src):
    return bytes([0x05, 0x64, 0, ctrl]) + struct.pack('<HH', dst, src)


def dnp3(ctrl, dst, src, user):
    """Complete link frame, length and every CRC recomputed (framework codec)."""
    return dnp3_build(link_header(ctrl, dst, src), user)


def corrupt(frame, offset):
    b = bytearray(frame)
    b[offset] ^= 0x01
    return bytes(b)
