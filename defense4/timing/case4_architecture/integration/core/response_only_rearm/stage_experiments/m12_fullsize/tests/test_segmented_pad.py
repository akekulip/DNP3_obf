"""Faithful segmented 377 -> 401 READ padder (make_m12.py --segmented-pad), on the repository P4 source
interpreter. The two native TCP segments of the large-DB integrity/class0 READ are injected into the pipe-1
egress padder (x_Egress) and the emitted DNP3 payload is checked BYTE-EXACT against the proven oracle
derive.construct() == general_read_padding.pad_read (512 varied samples: every transport/app sequence, IIN,
point values, link addresses).

Source-interpreter tier only. The deparser IP/TCP Checksum externs are NOT executed by the interpreter, so
their incremental correctness is bounded here to the compiled model/ASIC (interp.checksum_oracle gives the
checksum a correct deparser must emit for the byte-exact payload); T's two-child hold/release and packet
replication are not modelled at this tier (see the explicit bound in the module docstring of the harness).

Run with the research venv (derive.py / general_read_padding need Python >= 3.10):
  ~/.venvs/research/bin/python -m pytest -q m12_fullsize/tests/test_segmented_pad.py
"""
import importlib.util
import json
import re
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
STAGE = HERE.parents[1]
BASE = STAGE.parent
INTEG = BASE.parent.parent
VEC = STAGE / 'read_complete_01/vectors'

shim = types.ModuleType('baseline')
shim.INTEG = INTEG
sys.modules.setdefault('baseline', shim)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


interp = _module('segpad_interp', BASE / 'interpreter.py')
derive = _module('segpad_derive', VEC / 'derive.py')
gp, std = derive.gp, derive.std
CSEG = json.loads((VEC / 'constants_segmented.json').read_text())['shapes']['segmented_integrity_377']
CRANGE = json.loads((VEC / 'constants.json').read_text())['shapes']['range_g10v2_23']

SRCIP, DSTIP = bytes([192, 168, 10, 7]), bytes([192, 168, 10, 1])
SPORT, DPORT = 20000, 56857
ETH = bytes.fromhex('001122334455aabbccddeeff0800')
OFF = 16 + 14 + 20 + 20                      # tev(16) + eth(14) + ip(20) + tcp(20)


def generate():
    out = Path(tempfile.mkdtemp(prefix='segpad_'))
    subprocess.run([sys.executable, str(STAGE / 'm12_fullsize/make_m12.py'), str(out),
                    '--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--segmented-pad'],
                   check=True, capture_output=True)
    return (out / 'response_only.p4').read_text()


def padder_source(text):
    """Isolate the pipe-1 egress padder (x_*) as a single-gress source for interp.ESource (which renames the
    egress gress to IgParser/Ingress). The dummy IgParser is e_source's prefix/body boundary marker."""
    hdr = text[text.index('/* ==== pipe-1 egress: READ prefix padder'):text.index('parser x_EgParser(')]
    gress = text[text.index('parser x_EgParser('):text.index('Pipeline(n_IgParser')]
    tev = 'header t_tev_t { bit<32> epoch; bit<32> wgen; bit<32> t0q; bit<8> kind; bit<8> stage; bit<16> reserved; }\n'
    eth = 'header t_ethernet_t { bit<48> dst; bit<48> src; bit<16> type; }\n'
    body = re.sub(r'\bx_(\w+)', r'\1', hdr + gress)
    body = re.sub(r'Counter<[^;]*p1_outcome;', '', body)        # interp e_source strips `outcome`, not p1_outcome
    body = body.replace('p1_outcome.count(m.p1_res);', '')
    return ('#include <core.p4>\n#include <tna.p4>\n' + tev + eth + body +
            '\nparser IgParser() { state start { transition accept; } }\nPipeline() marker;\n')


def frame(payload, seq, stage):
    iplen = 40 + len(payload)
    ip = bytearray([0x45, 0, (iplen >> 8) & 0xff, iplen & 0xff, 0, 0, 0x40, 0, 0x40, 6, 0, 0]) + SRCIP + DSTIP
    tcp = bytearray(struct.pack('!HHIIBBHHH', SPORT, DPORT, seq, 0x22222222, 0x50, 0x18, 4096, 0, 0))
    tev = bytearray(16)
    tev[12], tev[13] = 11, stage
    return bytes(tev) + ETH + bytes(ip) + bytes(tcp) + payload


def dnp3(out):
    return out[OFF:]


def ip_len(out):
    return int.from_bytes(out[16 + 14 + 2:16 + 14 + 4], 'big')


def tcp_seq(out):
    return int.from_bytes(out[16 + 14 + 20 + 4:16 + 14 + 20 + 8], 'big')


def range_native(rng):
    """One native 49-B range READ response frame with a random transport/app seq, IIN, points, addresses."""
    seq = rng.randrange(64)
    appseq = rng.randrange(16)
    iin = bytes([rng.randrange(256) & 0xfe, rng.randrange(256) & 0x3f])
    dst, src = rng.randrange(1, 0xfff0), rng.randrange(1, 0xfff0)
    user = bytes([0xc0 | seq, 0xc0 | appseq, 0x81]) + iin + bytes.fromhex('0a02000016') + bytes(rng.randrange(256) for _ in range(23))
    return std.frame(bytes([0x05, 0x64, 5 + len(user), 0x44]) + dst.to_bytes(2, 'little') + src.to_bytes(2, 'little'), user)


class SegmentedPadder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = generate()
        cls.e = interp.ESource(padder_source(cls.text))
        cls.conn = [int.from_bytes(SRCIP, 'big'), int.from_bytes(DSTIP, 'big'), SPORT, DPORT]

    def enable(self):
        self.e.install('p1_conn', self.conn, 'p1_pad_ok', [])

    def test_source_regenerates_and_isolates_the_padder(self):
        self.assertEqual(self.e.header_order[:5], ['tev', 'eth', 'ip', 'tcp', 'pll'])
        self.assertIn('plu2', self.e.header_order)

    def test_byte_exact_vs_pad_read_512(self):
        import random
        self.enable()
        ok = 0
        for t in range(512):
            req, native = derive.segmented_sample(random.Random(5000 + t))()
            expect = gp.pad_read(req, native, derive.TARGETS, pad_start=derive.PAD_START, pad_stop=derive.PAD_STOP).output
            self.assertEqual(derive.construct(native, CSEG), expect)        # oracle self-consistency
            n0, n1 = gp.split_frames(native)
            seq0 = (0x30000000 + t * 997) & 0xffffffff
            out0 = self.e.inject(180, frame(n0, seq0, 0))
            out1 = self.e.inject(180, frame(n1, (seq0 + len(n0)) & 0xffffffff, 1))
            self.assertIsNotNone(out0, ('seg0 dropped', t))
            self.assertIsNotNone(out1, ('seg1 dropped', t))
            self.assertEqual(dnp3(out0) + dnp3(out1), expect, ('byte-exact', t))
            self.assertEqual(ip_len(out0), 356, t)                          # 332 + 24
            self.assertEqual(ip_len(out1), 125, t)                          # unchanged
            self.assertEqual(tcp_seq(out0), seq0, t)                        # seg0 seq unchanged
            self.assertEqual(tcp_seq(out1), (seq0 + len(n0) + 24) & 0xffffffff, t)  # seg1 seq += 24
            ok += 1
        self.assertEqual(ok, 512)

    def test_frames_out_are_24_292_85(self):
        import random
        self.enable()
        req, native = derive.segmented_sample(random.Random(9))()
        n0, n1 = gp.split_frames(native)
        out0 = self.e.inject(180, frame(n0, 0x40000000, 0))
        out1 = self.e.inject(180, frame(n1, 0x40000000 + len(n0), 1))
        self.assertEqual([len(f) for f in gp.split_frames(dnp3(out0) + dnp3(out1))], [24, 292, 85])

    def test_block0_crcs_and_transport_are_valid_dnp3(self):
        """Every emitted link frame deframes cleanly (all block CRCs valid) and the transport octets renumber
        prefix(FIR s) -> seg0(middle s+1) -> seg1(FIN s+2)."""
        import random
        self.enable()
        req, native = derive.segmented_sample(random.Random(77))()
        n0, n1 = gp.split_frames(native)
        seq = std.deframe(n0)[1][0] & 63
        out0 = self.e.inject(180, frame(n0, 0x50000000, 0))
        out1 = self.e.inject(180, frame(n1, 0x50000000 + len(n0), 1))
        pfx, o0, o1 = gp.split_frames(dnp3(out0) + dnp3(out1))
        for f in (pfx, o0, o1):
            std.deframe(f)                                                  # raises if any block CRC is wrong
        self.assertEqual(std.deframe(pfx)[1][0], 0x40 | seq)               # prefix FIR, same seq
        self.assertEqual(std.deframe(o0)[1][0], (seq + 1) & 63)            # middle (no FIR/FIN)
        self.assertEqual(std.deframe(o1)[1][0], 0x80 | ((seq + 2) & 63))   # FIN, seq+2

    def test_checksum_oracle_defines_the_wire_checksum(self):
        """Interp does not execute the deparser Checksum externs; the correct TCP/IP checksum a compiled
        deparser must emit is interp.checksum_oracle of the byte-exact frame. Here we only assert the frame is
        well-formed enough that the oracle produces a definite checksum (bound: equality to the extern is a
        model/ASIC check, not an interpreter one)."""
        import random
        self.enable()
        req, native = derive.segmented_sample(random.Random(3))()
        n0, _ = gp.split_frames(native)
        out0 = self.e.inject(180, frame(n0, 0x60000000, 0))
        fixed = interp.checksum_oracle(out0[16:])                           # oracle works on eth/ip/tcp (strip tev)
        self.assertEqual(len(fixed), len(out0) - 16)

    def test_unenabled_connection_is_not_padded(self):
        """Without a p1_conn row the padder must leave the native frame unchanged (size-off / native path)."""
        self.e.controls['Ingress'].tables['p1_conn']['runtime'].clear()
        import random
        req, native = derive.segmented_sample(random.Random(11))()
        n0, n1 = gp.split_frames(native)
        out0 = self.e.inject(180, frame(n0, 0x70000000, 0))
        out1 = self.e.inject(180, frame(n1, 0x70000000 + len(n0), 1))
        self.assertEqual(dnp3(out0), n0)                                    # unchanged
        self.assertEqual(dnp3(out1), n1)
        self.assertEqual(ip_len(out0), 332)
        self.assertEqual(tcp_seq(out1), (0x70000000 + len(n0)) & 0xffffffff)

    def test_range_path_still_pads_49_to_141(self):
        """The apply() restructure must not change the range (49->141) path: a native 49-B range READ still
        pads byte-exact to the range target."""
        import random
        self.enable()
        ok = 0
        for t in range(64):
            rng = random.Random(800 + t)
            # rebuild the matching request so pad_read selects the range shape
            req, native = derive.range_sample(random.Random(800 + t))()
            expect = gp.pad_read(req, native, derive.TARGETS, pad_start=derive.PAD_START, pad_stop=derive.PAD_STOP).output
            out = self.e.inject(180, frame(native, 0x20000000 + t, 0))
            self.assertIsNotNone(out, ('range dropped', t))
            self.assertEqual(dnp3(out), expect, ('range byte-exact', t))
            ok += 1
        self.assertEqual(ok, 64)


if __name__ == '__main__':
    unittest.main(verbosity=2)
