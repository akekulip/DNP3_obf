"""Edit 1 precondition: the outgoing link-header CRC after a length-byte change equals the native CRC
XOR a constant, in the P4 wire-order representation (hdr.dl.crc = first wire byte in bits 15:8).
Uses this repository's own codec (framework/size/rrc.py dnp3_crc, the one case4_padding.build_frame uses)
and cross-checks against implementation/harness/dnp3_wire.py dnp3_crc (validated on the SEL-751)."""
import importlib.util, random, sys
from pathlib import Path
T = Path(__file__).resolve().parents[5]   # .../defense4/timing
def load(p, n):
    s = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
rrc = load(T / 'framework/size/rrc.py', 'rrc')
wire = load(T / 'implementation/harness/dnp3_wire.py', 'dnp3_wire')
def wire16(c):          # wire bytes are little-endian CRC; P4 field holds them big-endian
    return ((c & 0xff) << 8) | (c >> 8)
CASES = {'READ 0x26->0x2f': (0x26, 0x3b2f), 'CONTROL 0x1c->0x2f': (0x1c, 0x131a)}
rng = random.Random(20261010)
N = 200000
ok = True
for name, (old, const) in CASES.items():
    bad = 0
    for i in range(N):
        rest = bytes(rng.getrandbits(8) for _ in range(5))      # ctrl, dst(2), src(2)
        start = b'\x05\x64' if i % 2 == 0 else bytes(rng.getrandbits(8) for _ in range(2))
        h_old = start + bytes([old]) + rest
        h_new = start + bytes([0x2f]) + rest
        c_old, c_new = rrc.dnp3_crc(h_old), rrc.dnp3_crc(h_new)
        assert c_old == wire.dnp3_crc(h_old) and c_new == wire.dnp3_crc(h_new)
        if wire16(c_old) ^ const != wire16(c_new):
            bad += 1
    print('%-20s const=0x%04x samples=%d mismatches=%d' % (name, const, N, bad))
    ok &= bad == 0
# Concrete frames the drivers use (link headers from model_drive_composite / model_drive_response_path)
for hx in ('05641c4401000a00', '056426c40a000100', '056426440a000100'):
    h = bytes.fromhex(hx); new = h[:2] + b'\x2f' + h[3:]
    const = CASES['READ 0x26->0x2f'][1] if h[2] == 0x26 else CASES['CONTROL 0x1c->0x2f'][1]
    print(hx, 'old', hex(wire16(rrc.dnp3_crc(h))), 'new', hex(wire16(rrc.dnp3_crc(new))),
          'xor ok', wire16(rrc.dnp3_crc(h)) ^ const == wire16(rrc.dnp3_crc(new)))
sys.exit(0 if ok else 1)
