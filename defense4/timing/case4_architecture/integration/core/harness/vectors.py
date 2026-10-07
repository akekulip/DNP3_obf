"""Frame and topology builders for the harness tests.

Frames come from the retained step-1 generator (ownership/review/counterexamples.frame, imported
only for that function) and from an independent builder that follows connection/reference.py's
wire contract and framework/size/case4_padding for DNP3 link CRCs.
"""
import importlib.util
import struct
import sys
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ARCH.parent / 'framework/size'))
import case4_padding  # noqa: E402
from driver import Config  # noqa: E402

SOURCE_PATH = ARCH / 'integration/connection/binding/native_binding.p4'
CLIENT, SERVER = 0x0a000001, 0x0a000002
CLIENT_PORT, SERVER_PORT, FLOW_PORTS = 30001, 20000, (30001, 20000)
IN_CLIENT, IN_SERVER = 1, 2     # harness-chosen front-panel ports for the two sides


def source_text():
    return SOURCE_PATH.read_text()


def _counterexamples():
    spec = importlib.util.spec_from_file_location('retained_counterexamples', ARCH / 'ownership/review/counterexamples.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


frame = _counterexamples().frame   # frame(flags, seq, ack, reverse=False, mss=None)


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def packet(flags, seq, ack=0, reverse=False, payload=b'', mss=None, ttl=64, tuple4=None):
    src, dst, sport, dport = tuple4 or (CLIENT, SERVER, CLIENT_PORT, SERVER_PORT)
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    options = b'' if mss is None else struct.pack('!BBH', 2, 4, mss)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      ((20 + len(options)) // 4) << 4, flags, 4096, 0, 0) + options + payload
    pseudo = struct.pack('!IIBBH', src, dst, 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBHII', 0x45, 0, 20 + len(tcp), 1, 0x4000, ttl, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800') + ip + tcp


def native_select(app=0, fc=3):
    """The 35-byte native SELECT link frame (same bytes connection/tests use)."""
    return case4_padding.build_frame(
        bytes.fromhex('05641ac40a000100'),
        bytes((0xc0, 0xc0 | app, fc)) + bytes.fromhex('0c0128010001000101640000006400000000'))


def topology():
    flows = [(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 'forward', IN_SERVER),
             (SERVER, CLIENT, SERVER_PORT, CLIENT_PORT, 'reverse', IN_CLIENT)]
    data = [(CLIENT, SERVER, CLIENT_PORT, SERVER_PORT, 0x0001, 0x03, 0x01, 100, 200)]
    return Config(ports={IN_CLIENT: IN_SERVER, IN_SERVER: IN_CLIENT, 68: 68}, flows=flows, data_connections=data)
