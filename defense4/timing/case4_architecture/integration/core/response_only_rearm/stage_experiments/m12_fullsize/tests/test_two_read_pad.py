"""Two-READ-target pipe-1 egress padder (make_m12.py --two-read, candidate m12p_c21) on the repository P4 source
interpreter.

The mixed (91 B) and full (247 B) native READ responses are injected into the pipe-1 egress padder (x_Egress) and
the emitted DNP3 payload is checked BYTE-EXACT against the proven oracle derive.construct() ==
general_read_padding.pad_read(targets=[141, 271]) on 512 varied samples per shape (every link address, transport and
application sequence, IIN, measurement value and flag octet) and on the two live captures (fixture variants v0/v1).
Also: valid link/block CRCs and transport renumbering of every emitted frame; the declared non-padding dispositions
(no size-enabled connection, a bad block-0 CRC, the range 49 and analog 141 responses) leave the frame unchanged.

Source-interpreter tier only. The deparser IP/TCP Checksum externs are NOT executed here, so checksum correctness is
bounded to the compiled model/ASIC (interp.checksum_oracle gives the checksum a correct deparser must emit).
  ~/.venvs/research/bin/python -m pytest -q m12_fullsize/tests/test_two_read_pad.py
"""
import importlib.util
import json
import random
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


interp = _module('tworead_interp', BASE / 'interpreter.py')
d2 = _module('tworead_derive2', VEC / 'derive_two_read.py')
derive, gp, std = d2.derive, d2.gp, d2.std
C2 = json.loads((VEC / 'constants_two_read.json').read_text())['shapes']
CM, CF = C2['mixed_g1v2_g30v1_91'], C2['integrity_247']
TEMPLATES = json.loads((VEC / 'two_read_templates.json').read_text())

SRCIP, DSTIP = bytes([192, 168, 10, 7]), bytes([192, 168, 10, 1])
SPORT, DPORT = 20000, 56857
ETH = bytes.fromhex('001122334455aabbccddeeff0800')
OFF = 16 + 14 + 20 + 20                      # tev(16) + eth(14) + ip(20) + tcp(20)


def generate(extra=()):
    out = Path(tempfile.mkdtemp(prefix='tworead_'))
    subprocess.run([sys.executable, str(STAGE / 'm12_fullsize/make_m12.py'), str(out),
                    '--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--two-read'] + list(extra), check=True, capture_output=True)
    return (out / 'response_only.p4').read_text()


def padder_source(text):
    """Isolate the pipe-1 egress padder (x_*) as a single-gress source for interp.ESource."""
    hdr = text[text.index('/* ==== pipe-1 egress:'):text.index('parser x_EgParser(')]
    gress = text[text.index('parser x_EgParser('):text.index('Pipeline(n_IgParser')]
    tev = 'header t_tev_t { bit<32> epoch; bit<32> wgen; bit<32> t0q; bit<8> kind; bit<8> stage; bit<16> reserved; }\n'
    eth = 'header t_ethernet_t { bit<48> dst; bit<48> src; bit<16> type; }\n'
    body = re.sub(r'\bx_(\w+)', r'\1', hdr + gress)
    body = re.sub(r'Counter<[^;]*p1_outcome;', '', body)
    body = body.replace('p1_outcome.count(m.p1_res);', '')
    return ('#include <core.p4>\n#include <tna.p4>\n' + tev + eth + body +
            '\nparser IgParser() { state start { transition accept; } }\nPipeline() marker;\n')


def frame(payload, seq, stage=0):
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


SAMPLERS = {'mixed': (d2.MIXED_OBJECTS, d2.MIXED_REQ_OBJS, 91), 'full': (d2.FULL_OBJECTS, d2.FULL_REQ_OBJS, 247)}


class TwoReadPadder(unittest.TestCase):
    EXTRA = ()   # generator flags beyond --two-read; the Reduced subclass adds --reduce (m12p_c26)
    CRC_COND = 'm.conn_ok == 1w1 && hdr.c0.crc == (m.in_rb0[7:0] ++ m.in_rb0[15:8])'   # the block-0 CRC guard

    @classmethod
    def setUpClass(cls):
        cls.text = generate(cls.EXTRA)
        cls.e = interp.ESource(padder_source(cls.text))
        cls.conn = [int.from_bytes(SRCIP, 'big'), int.from_bytes(DSTIP, 'big'), SPORT, DPORT]

    def setUp(self):
        self.e.controls['Ingress'].tables['p1_conn']['runtime'].clear()
        self.e.install('p1_conn', self.conn, 'p1_pad_ok', [])

    def pad(self, native, seq=0x30000000):
        out = self.e.inject(180, frame(native, seq))
        self.assertIsNotNone(out, 'dropped')
        return out

    def test_generated_constants_are_the_derived_ones(self):
        """No stale length or CRC constant: the prefix LEN and link-CRC delta in the generated P4 are the derived ones."""
        for c in (CM, CF):
            self.assertIn('hdr.pll.len = 8w%d;' % c['prefix_link_len'], self.text)
            self.assertIn('hdr.pll.crc = hdr.dl.crc ^ 16w%d;' % c['link_crc_delta'], self.text)
        self.assertIn('16w%d: ip_frag; 16w%d: ip_frag;' % (CM['native_ip_len'], CF['native_ip_len']), self.text)

    def test_byte_exact_vs_pad_read_512_per_shape(self):
        for name, (objs, req_objs, n) in SAMPLERS.items():
            sample = d2.sampler(random.Random(7000 + n), objs, req_objs, n)
            c = CM if name == 'mixed' else CF
            for t in range(512):
                req, native = sample()
                expect = gp.pad_read(req, native, d2.TARGETS, pad_start=d2.PAD_START, pad_stop=d2.PAD_STOP).output
                seq = (0x10000000 + t * 7919) & 0xffffffff
                out = self.pad(native, seq)
                self.assertEqual(dnp3(out), expect, (name, t, 'byte-exact'))
                self.assertEqual(ip_len(out), 40 + c['target'], (name, t))
                self.assertEqual(tcp_seq(out), seq, (name, t))           # one segment: seq unchanged

    def test_live_captures_pad_exactly(self):
        for variant, rec in TEMPLATES['variants'].items():
            for cls in ('mixed', 'integrity'):
                t = rec['classes'][cls]
                out = self.pad(bytes.fromhex(t['native']))
                self.assertEqual(dnp3(out).hex(), t['expected'], (variant, cls))

    def test_frames_crcs_and_transport(self):
        for name, (objs, req_objs, n) in SAMPLERS.items():
            req, native = d2.sampler(random.Random(n), objs, req_objs, n)()
            seq = std.deframe(native)[1][0] & 63
            frames = gp.split_frames(dnp3(self.pad(native)))
            self.assertEqual([len(f) for f in frames], (CM if name == 'mixed' else CF)['frames_out'])
            for f in frames:
                std.deframe(f)                                          # raises on any bad header/block CRC
            self.assertEqual(std.deframe(frames[0])[1][0], 0x40 | seq)  # prefix: FIR, same transport seq
            self.assertEqual(std.deframe(frames[1])[1][0], 0x80 | ((seq + 1) & 63))   # continuation: FIN, seq+1
            frags, events = std.reassemble(frames)
            self.assertEqual((len(frags), events), (1, []))

    def test_size_off_connection_is_not_padded(self):
        self.e.controls['Ingress'].tables['p1_conn']['runtime'].clear()
        for name, (objs, req_objs, n) in SAMPLERS.items():
            _, native = d2.sampler(random.Random(3), objs, req_objs, n)()
            out = self.pad(native)
            self.assertEqual(dnp3(out), native, name)
            self.assertEqual(ip_len(out), 40 + n, name)

    def test_bad_block0_crc_is_not_padded(self):
        """A frame whose block-0 CRC does not verify is declined (forwarded unchanged), never rewritten -- whether a
        MEASUREMENT octet inside block 0 changed (CRC left stale) or the block-0 CRC itself is wrong. Neither touches
        the profile's keys (review of m12p_c23: corrupting the object header was declined by the profile instead, so
        the CRC condition was untested; test_crc_condition_is_load_bearing removes it and must see this fail)."""
        for name, (objs, req_objs, n) in SAMPLERS.items():
            _, native = d2.sampler(random.Random(5), objs, req_objs, n)()
            for where, off in (('point_octet', 10 + 12), ('block0_crc', 10 + 16)):
                bad = bytearray(native)
                bad[off] ^= 0x01
                out = self.pad(bytes(bad))
                self.assertEqual(dnp3(out), bytes(bad), (name, where))

    def test_shape_is_the_exact_ip_len_link_len_pair(self):
        """A frame whose IP length belongs to one shape and link LEN to the other is not padded (review of m12p_c23:
        the profile keyed LEN alone)."""
        _, native = d2.sampler(random.Random(9), *SAMPLERS['full'])()          # IP 287
        crossed = bytearray(native)
        crossed[2] = CM['native_link_len']                                      # LEN 0x4c (mixed) on an IP-287 frame
        out = self.pad(bytes(crossed))
        self.assertEqual(dnp3(out), bytes(crossed))

    def test_crc_condition_is_load_bearing(self):
        """Mutation: without the block-0 CRC condition the padder rewrites a corrupted frame (re-making its CRC), so
        the check above is what refuses it."""
        cond = self.CRC_COND
        self.assertIn(cond, self.text)
        mutant = interp.ESource(padder_source(self.text.replace(cond, 'm.conn_ok == 1w1')))
        mutant.install('p1_conn', self.conn, 'p1_pad_ok', [])
        _, native = d2.sampler(random.Random(5), *SAMPLERS['mixed'])()
        bad = bytearray(native)
        bad[10 + 12] ^= 0x01
        out = mutant.inject(180, frame(bytes(bad), 0x30000000))
        self.assertNotEqual(dnp3(out), bytes(bad))                       # the mutant padded the corrupted frame

    def test_other_read_lengths_are_not_padded(self):
        """Declared disposition: the range 49 and analog 141 responses are not this profile's shapes."""
        range_user = bytes([0xc0 | 5, 0xc3, 0x81, 0x90, 0x00]) + bytes.fromhex('0a02000016') + bytes(23)
        range_native = std.frame(bytes([0x05, 0x64, 5 + len(range_user), 0x44, 1, 0, 0, 0]), range_user)
        self.assertEqual(len(range_native), 49)
        self.assertEqual(dnp3(self.pad(range_native)), range_native)
        analog_user = bytes([0xc0 | 9, 0xc4, 0x81, 0x90, 0x00]) + bytes.fromhex('1e01000014') + bytes(21 * 5)
        analog_native = std.frame(bytes([0x05, 0x64, 5 + len(analog_user), 0x44, 1, 0, 0, 0]), analog_user)
        self.assertEqual(len(analog_native), 141)
        self.assertEqual(dnp3(self.pad(analog_native)), analog_native)

    def test_checks_can_fail(self):
        """The byte-exact assertion distinguishes: an unpadded output and an output with one original octet changed
        both differ from the expected image."""
        req, native = d2.sampler(random.Random(11), *SAMPLERS['mixed'])()
        expect = gp.pad_read(req, native, d2.TARGETS, pad_start=d2.PAD_START, pad_stop=d2.PAD_STOP).output
        self.assertNotEqual(native, expect)
        tampered = bytearray(dnp3(self.pad(native)))
        tampered[-3] ^= 0x01
        self.assertNotEqual(bytes(tampered), expect)

    def test_checksum_oracle_bound(self):
        """Interp does not execute the deparser Checksum externs; the oracle defines the checksum a correct deparser
        must emit (equality to the extern is a compiled-model/ASIC check, not an interpreter one)."""
        req, native = d2.sampler(random.Random(13), *SAMPLERS['full'])()
        out = self.pad(native)
        self.assertEqual(len(interp.checksum_oracle(out[16:])), len(out) - 16)


class TwoReadPadderReduced(TwoReadPadder):
    """Every padder test again on the resource-reduced build (make_m12.py --reduce, candidate m12p_c26)."""
    EXTRA = ('--reduce',)
    CRC_COND = 'm.conn_ok == 1w1 && m.in_rb0 == 16w0x993a'   # residue form of the same guard


if __name__ == '__main__':
    unittest.main()
