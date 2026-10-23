"""Two-READ-target build (make_m12.py --two-read, m12p_c21+) in N (pipe-0 ingress) and E (pipe-0 egress), on the
repository's P4 source interpreter.

Frames: one real exchange per READ class from the hardware workload's own loopback capture
(read_complete_01/evidence/m1_two_read_01/native_capture_v0/capture.pcap), re-wrapped in an option-free IPv4/TCP
header with correct checksums (the loopback capture carries the TCP timestamp option; the hardware workload does not).

N, per class (mixed 25/91, integrity 27/247): the parser recognises the frame, the profile marks it eligible, the real
block-0 CRC verifies, the guard admits it, next_seq_t advances by the native length and the application sequence is
read from the right header. A corrupted block-0 octet or block-0 CRC is refused. Checksums, stated exactly: the
REQUEST is fully parsed and a bad TCP checksum is refused; the RESPONSE is parsed first block only and its TCP checksum
is WAIVED (m.tcp_sum = 0xffeb is written, not computed), so a response with a bad TCP checksum -- or a corrupted
block-1 octet -- is admitted by N: a recorded limitation, not validation.

E: the pre-padded first frame of each shape (prefix LEN 0x27 mixed / 0x11 full) is recognised as a READ shape, its
native length is ip.len - 40 - added (91 / 247), and the commit image (ina) and wire advance (m.t) are the shape's own
image (141 / 271); SBO keeps 61. Source-interpreter tier only: not the compiled model or hardware.
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
CAPTURE = STAGE / 'read_complete_01/evidence/m1_two_read_01/native_capture_v0/capture.pcap'
DECODER = STAGE / 'read_complete_01/software/source/read_reencode_01'

shim = types.ModuleType('baseline')
shim.INTEG = INTEG
sys.modules.setdefault('baseline', shim)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


interp = _module('tworead_ne_interpreter', BASE / 'interpreter.py')
combined = _module('tworead_ne_segments', STAGE / 'combined_nt_01/generate.py')
capture = _module('tworead_ne_capture', DECODER / 'capture.py')
std = _module('tworead_ne_std', DECODER / 'dnp3_std.py')
N_TESTS = _module('tworead_ne_nshapes', HERE / 'test_n_read_shapes.py')
d2 = _module('tworead_ne_derive2', VEC / 'derive_two_read.py')
C2 = json.loads((VEC / 'constants_two_read.json').read_text())['shapes']
CM, CF = C2['mixed_g1v2_g30v1_91'], C2['integrity_247']

# class -> (request octets, response octets, request dl.len, response dl.len)
CLASSES = {'mixed': (25, 91, 0x12, 0x4c), 'integrity': (27, 247, 0x14, 0xd6)}
HEADER = {'mixed': 'rd_req_mx', 'integrity': 'rd_req_full'}
GOOD = N_TESTS.GOOD
frame, corrupt_block0, corrupt_crc0, corrupt_block1 = (N_TESTS.frame, N_TESTS.corrupt_block0, N_TESTS.corrupt_crc0,
                                                       N_TESTS.corrupt_block1)


def generate(extra=()):
    out = Path(tempfile.mkdtemp(prefix='tworead_ne_'))
    subprocess.run([sys.executable, str(STAGE / 'm12_fullsize/make_m12.py'), str(out),
                    '--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--two-read'] + list(extra), check=True, capture_output=True)
    return (out / 'response_only.p4').read_text()


def exchanges():
    want = {(v[0], v[1]): k for k, v in CLASSES.items()}
    found, prev = {}, None
    for r in capture.tcp_records(CAPTURE):
        if not r['payload']:
            continue
        if r['dst'][1] == 20000:
            prev = r
            continue
        if prev is not None:
            k = want.get((len(prev['payload']), len(r['payload'])))
            if k and k not in found:
                found[k] = (prev, r)
    return found


def admit(n, text, req, rsp, payload_of, which, tcp_bad=False):
    """N on one frame; the N_TESTS.admit harness with the mixed header added to the observed validity set and an
    optional corrupted TCP checksum (the DNP3 bytes unchanged)."""
    real_frame = N_TESTS.frame

    def frame_maybe_bad(rec, payload=None):
        f = bytearray(real_frame(rec, payload))
        if tcp_bad:
            f[14 + 20 + 16] ^= 0x01
        return bytes(f)
    N_TESTS.frame = frame_maybe_bad
    try:
        out = N_TESTS.admit(n, text, req, rsp, payload_of, which)
    finally:
        N_TESTS.frame = real_frame
    out['valid_mx'] = bool(n.valid.get('rd_req_mx'))
    return out


class TwoReadN(unittest.TestCase):
    EXTRA = ()   # generator flags beyond --two-read; the Reduced subclass adds --reduce (m12p_c26)

    @classmethod
    def setUpClass(cls):
        cls.text = generate(cls.EXTRA)
        cls.n = N_TESTS.n_source(cls.text)
        cls.ex = exchanges()

    def run_class(self, name, which, payload_of=lambda p: p, tcp_bad=False):
        req, rsp = self.ex[name]
        return admit(self.n, self.text, req, rsp, payload_of, which, tcp_bad)

    def test_capture_has_both_classes(self):
        self.assertEqual(sorted(self.ex), sorted(CLASSES))
        for name, (q, r, qdl, rdl) in CLASSES.items():
            req, rsp = self.ex[name]
            self.assertEqual((len(req['payload']), req['payload'][2], len(rsp['payload']), rsp['payload'][2]), (q, qdl, r, rdl))

    def check_admitted(self, name, which, got):
        req, rsp = self.ex[name]
        rec = req if which == 'req' else rsp
        self.assertTrue(got['accepted'] and got['parsed'] == 1, got)
        self.assertEqual(got['kind'], 9 if which == 'req' else 11, got)
        self.assertEqual(got['profile'], 1, got)
        self.assertEqual((got['hcrc'], got['bcrc'], got['badh']), (GOOD, GOOD, 0), got)
        self.assertEqual((got['network'], got['go'], got['go_kind']), (1, 1, got['kind']), got)
        self.assertEqual(got['new_seq'], (rec['seq'] + CLASSES[name][0 if which == 'req' else 1]) & 0xFFFFFFFF, got)
        self.assertEqual(got['read_app'], rec['payload'][11] & 0x0F, got)

    def test_requests_admitted(self):
        for name in CLASSES:
            with self.subTest(name):
                got = self.run_class(name, 'req')
                self.check_admitted(name, 'req', got)
                self.assertEqual(got['valid_mx'], name == 'mixed', got)
                # 0xffeb is the residual N's network table accepts; for a request it is COMPUTED by the parser's TCP
                # checksum over the whole segment (a bad checksum gives another value: see the next test)
                self.assertEqual(got['tcp_sum'], 0xffeb, got)

    def test_responses_admitted_first_block_only(self):
        for name in CLASSES:
            with self.subTest(name):
                got = self.run_class(name, 'rsp')
                self.check_admitted(name, 'rsp', got)
                self.assertEqual(got['valid'], ['first'], got)
                self.assertEqual(got['tcp_sum'], 0xffeb, got)              # the WAIVER value, not a computed checksum

    def test_corrupt_block0_refused(self):
        for name in CLASSES:
            for which in ('req', 'rsp'):
                for corrupt in (corrupt_block0, corrupt_crc0):
                    with self.subTest((name, which, corrupt.__name__)):
                        got = self.run_class(name, which, corrupt)
                        self.assertEqual((got['parsed'], got['network']), (1, 1), got)
                        self.assertNotEqual(got['bcrc'], GOOD, got)
                        self.assertEqual(got['go'], 0, got)

    def test_bad_tcp_checksum_refused_on_requests(self):
        """A request's TCP checksum is really verified: a wrong checksum yields a residual other than 0xffeb and N's
        network table refuses the segment (network_valid 0 -- the read-lane branch requires network_valid 1)."""
        for name in CLASSES:
            with self.subTest(name):
                got = self.run_class(name, 'req', tcp_bad=True)
                self.assertNotEqual(got['tcp_sum'], 0xffeb, got)
                self.assertEqual(got['network'], 0, got)

    def test_waiver_limitation_on_responses(self):
        """RECORDED LIMITATION (correction 2), not a property: the shallow response path WRITES m.tcp_sum = 0xffeb
        (finish_shallow) -- the residual the network table accepts -- instead of computing it, so N admits a response
        whose TCP checksum is wrong, and one whose block-1 octet is corrupted. This is a validation waiver, not a
        verified checksum; integrity of the unparsed tail rests on the master's stack, not on the switch."""
        for name in CLASSES:
            got = self.run_class(name, 'rsp', tcp_bad=True)
            self.assertEqual((got['tcp_sum'], got['network'], got['go']), (0xffeb, 1, 1), (name, got))
            self.assertEqual(self.run_class(name, 'rsp', corrupt_block1)['go'], 1, name)

    def test_replaced_classes_are_not_admitted_and_range_still_is(self):
        """Declared disposition (m12p_c23): the analog and class0 READ admission was replaced by the mixed one, so
        their requests are not recognised as READs (not parsed, not admitted); the range READ keeps m11_09's admission."""
        old = N_TESTS.exchanges()                        # c12's per-class frames from the rotate4 base capture
        for name in ('analog', 'class0'):
            req, rsp = old[name]
            got = N_TESTS.admit(self.n, self.text, req, rsp, lambda p: p, 'req')
            self.assertNotEqual(got['parsed'], 1, (name, got))
        req, rsp = old['range']
        for which in ('req', 'rsp'):
            got = N_TESTS.admit(self.n, self.text, req, rsp, lambda p: p, which)
            self.assertEqual((got['parsed'], got['profile'], got['go']), (1, 1, 1), (which, got))

    def test_mixed_request_profile_is_exact(self):
        """A one-header or reordered mixed request is not admitted as the mixed READ."""
        req, rsp = self.ex['mixed']
        q = bytearray(req['payload'])
        user = std.deframe(bytes(q))[1]
        swapped = user[:3] + user[8:13] + user[3:8]                       # g30v1 header before g1v2
        q2 = std.frame(bytes(q[:8]), swapped)
        got = admit(self.n, self.text, dict(req, payload=q2), rsp, lambda p: p, 'req')
        self.assertEqual(got.get('go', 0), 0, got)


def e_frame(native, padded, seq=0x40000000):
    """The pre-padded response as E sees it on egress port 9 (provenance header + Ethernet/IPv4/TCP + payload)."""
    rec = dict(src=(bytes([192, 168, 10, 7]), 20000), dst=(bytes([192, 168, 10, 1]), 56857), seq=seq, ack=0x1111,
               flags=0x18, payload=padded)
    return struct.pack('!IIIBBH', 1, 0, 0, 0x0b, 0, 0) + frame(rec)


class TwoReadE(unittest.TestCase):
    EXTRA = ()   # generator flags beyond --two-read; the Reduced subclass adds --reduce (m12p_c26)

    @classmethod
    def setUpClass(cls):
        cls.text = generate(cls.EXTRA)
        cls.e = interp.ESource(N_TESTS.role(cls.text, 'E'))

    def run_e(self, padded):
        self.e.begin_pass(0)
        self.e.env['eg.egress_port'] = 9
        accepted, _ = self.e.packet_parser(e_frame(None, padded))
        self.assertTrue(accepted)
        for t in ('leff_t', 'read_profile', 'ina_img_t'):
            self.e.table(t)
        self.e.env['m.q'] = 0x1000
        self.e.env['m.p'] = 0x1000
        self.e.table('fwd_prep_t')
        env = self.e.env
        return dict(leff=env.get('m.leff'), read_shape=env.get('m.read_shape', 0), ina=env.get('m.ina'),
                    t=(env.get('m.t') - 0x1000) & 0xFFFFFFFF if env.get('m.t') is not None else None)

    def test_both_prepadded_shapes_map_to_their_own_image(self):
        for name, c, objs, n in (('mixed', CM, d2.MIXED_OBJECTS, 91), ('full', CF, d2.FULL_OBJECTS, 247)):
            req_objs = d2.MIXED_REQ_OBJS if name == 'mixed' else d2.FULL_REQ_OBJS
            req, native = d2.sampler(random.Random(n), objs, req_objs, n)()
            padded = d2.gp.pad_read(req, native, d2.TARGETS, pad_start=d2.PAD_START, pad_stop=d2.PAD_STOP).output
            with self.subTest(name):
                got = self.run_e(padded)
                self.assertEqual(got, dict(leff=n, read_shape=1, ina=c['target'], t=c['target']), got)

    def test_native_unpadded_read_is_not_a_read_shape(self):
        """A native (size-off) mixed or full response is mapped natively: not a READ shape, native length."""
        for objs, req_objs, n in ((d2.MIXED_OBJECTS, d2.MIXED_REQ_OBJS, 91), (d2.FULL_OBJECTS, d2.FULL_REQ_OBJS, 247)):
            _, native = d2.sampler(random.Random(n + 1), objs, req_objs, n)()
            got = self.run_e(native)
            self.assertEqual((got['read_shape'], got['leff'], got['t']), (0, n, n), got)

    def test_generated_mapper_rows(self):
        """Every per-image site carries both READ images and SBO's, keyed on the committed native (no max image)."""
        t = self.text
        self.assertIn('(1, 0, 8w0x27) : set_ina(141); (1, 0, 8w0x11) : set_ina(271); (0, 1, _) : set_ina(61);', t)
        self.assertIn('fwd_prep_read(32w0xffffff73, 32w141)', t)
        self.assertIn('fwd_prep_read(32w0xfffffef1, 32w271)', t)
        for n in (91, 247):
            self.assertIn(', %d, 1, _, 0, 0, 0, 0, _, _): do_acct_try();' % n, t)
        self.assertNotIn(', 49, 1, _, 0, 0, 0, 0, _, _): do_acct_try();', t)
        for img in (61, 141, 271):
            self.assertIn('out_zero_img_%d' % img, t)
        rev = t[t.index('    table classify_rev {'):]
        rev = rev[:rev.index('    }\n')]
        for n in (91, 247, 37, 61):
            self.assertIn('8w%d) : rev_withhold_open();' % (n & 0xFF), rev)


class TwoReadNReduced(TwoReadN):
    """Every N test again on the resource-reduced build (make_m12.py --reduce, candidate m12p_c26)."""
    EXTRA = ('--reduce',)


class TwoReadEReduced(TwoReadE):
    """Every E test again on the resource-reduced build (make_m12.py --reduce, candidate m12p_c26)."""
    EXTRA = ('--reduce',)


if __name__ == '__main__':
    unittest.main(verbosity=2)
