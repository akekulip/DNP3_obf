"""Committed-image reverse-ACK contract of the policy build, on the repository's P4 source interpreter.

Review of d531918e2, finding 2: m12p_b08's classify_rev withheld ACKs 62..141 octets before the end of a committed
61-octet SBO image (it used the largest image's ladder). The contract, per committed image I of native length N,
for a reverse ACK at distance d before the image's wire end and advertised window w:
  d <= 0           translate (rev_translate);
  1 <= d <= I      withhold: ack rewritten to the image's native start, window 0 if w < d else N + w - d;
  d >  I           stale: dropped (rev_drop).
m11_09 (image 61 for every shape) is the independent oracle for the 61 image. Source-interpreter tier only: this
is not the compiled model or hardware.
"""
import importlib.util
import re
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
M11_09 = STAGE / 'ctl_timing_01/evidence/m11_09/response_only.p4'

shim = types.ModuleType('baseline')
shim.INTEG = INTEG
sys.modules.setdefault('baseline', shim)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


interp = _module('contract_interpreter', BASE / 'interpreter.py')
combined = _module('contract_segments', STAGE / 'combined_nt_01/generate.py')
OUT_TRANSLATE = OUT_WITHHOLD = OUT_STALE = None


class E(interp.ESource):
    def __init__(self, text):
        super().__init__(text)
        self.source_text_for_order = text


def e_role(text):
    result = re.sub(r'\br_(\w+)', r'\1', combined.segment(text, 'E'))
    return result + '\nPipeline() source_adapter_marker;\n'


def generate(c3):
    out = Path(tempfile.mkdtemp(prefix='contract_'))
    subprocess.run([sys.executable, str(STAGE / 'm12_fullsize/make_m12.py'), str(out), '--policy', '--c3', c3],
                   check=True, capture_output=True)
    return (out / 'response_only.p4').read_text()


def constants(text):
    return {k: int(v, 0) for k, v in re.findall(r'const bit<8>\s+r_(OUT_REV_\w+)\s*=\s*(\w+);', text)}


def reverse(e, native, d, window):
    """Run E's reverse classification for an ACK at distance d before a committed image of native length N."""
    e.begin_pass(0)
    e.valid['tcp'] = True
    e.env.update({'m.p': 5000, 'm.q': 5000 + native, 'hdr.tcp.window': window, 'm.r': (-d) & 0xFFFFFFFF,
                  'hdr.tcp.ack': 77, 'm.wide': 0, 'md.drop_ctl': 0, 'm.result': 0})
    e.action('reverse_gap')
    e.action('reverse_window_base')
    e.table('classify_rev')
    if e.env.get('m.wide') == 1:
        e.table('window_t')
    return e.env.get('m.result'), e.env.get('md.drop_ctl', 0), e.env.get('hdr.tcp.ack'), e.env.get('hdr.tcp.window')


def expected(native, image, d, window, k):
    if d <= 0:
        return k['OUT_REV_TRANSLATE'], 0
    if d > image:
        return k['OUT_REV_DROP_STALE'], 1
    return k['OUT_REV_WITHHOLD'], 0


def expected_window(native, d, window):
    if window < d:
        return 0
    w = native + window - d
    return w if w <= 0xFFFF else 0xFFFF


class CommittedImageBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = generate('cimg')
        cls.k = constants(cls.text)
        cls.e = E(e_role(cls.text))
        m11 = M11_09.read_text()
        cls.m11 = E(e_role(m11))

    def cases(self, image):
        ds = sorted({0, 1, 2, image - 1, image, image + 1, image + 2, 142, 300, 402, 600} - {-1})
        return [(d, w) for d in ds for w in (0, 1, d - 1 if d > 0 else 0, d, d + 1, 400, 4096, 65535)]

    def check_image(self, native, image):
        for d, w in self.cases(image):
            got = reverse(self.e, native, d, w)
            want_result, want_drop = expected(native, image, d, w, self.k)
            self.assertEqual((got[0], got[1]), (want_result, want_drop), (native, image, d, w, got))
            if want_result == self.k['OUT_REV_WITHHOLD']:
                self.assertEqual(got[2], 5000, ('withheld ACK rewritten to the native start', native, d, w))
                self.assertEqual(got[3], expected_window(native, d, w), ('window', native, image, d, w))

    def test_sbo_61_image_stale_beyond_61(self):
        self.check_image(37, 61)

    def test_handshake_virtual_61_image(self):
        self.check_image(61, 61)

    def test_range_read_141_image(self):
        self.check_image(49, 141)

    def test_61_image_matches_m11_09(self):
        for d, w in self.cases(61):
            if d > 70:
                continue
            ours, theirs = reverse(self.e, 37, d, w), reverse(self.m11, 37, d, w)
            self.assertEqual(ours, theirs, (d, w))

    def test_transition_directions_use_the_current_committed_image(self):
        # READ (141) then SBO (61): an ACK 100 before the SBO image end is stale; SBO then READ: withheld.
        self.assertEqual(reverse(self.e, 37, 100, 4096)[1], 1)
        self.assertEqual(reverse(self.e, 49, 100, 4096)[0], self.k['OUT_REV_WITHHOLD'])

    def test_unknown_committed_length_is_stale_not_withheld(self):
        self.assertEqual(reverse(self.e, 50, 10, 4096)[1], 1)


def forward_pure_ack(e, native, q_offset, leff=0):
    """E's forward classification of an outstation pure ACK (leff 0) whose sequence lies q_offset from the native
    end of the last committed image (m.q), with m.p = 0 (no native data after the image start)."""
    e.begin_pass(0)
    e.valid['tcp'] = True
    e.env.update({'m.front_ret': (-10) & 0xFFFFFFFF,     # behind the frontier: a delayed segment
                  'm.grant': 0, 'm.q': q_offset & 0xFFFFFFFF, 'm.leff': leff, 'm.p': 0,
                  'm.y': 0, 'm.z': 0, 'm.read_shape': 0, 'm.ctl_shape': 0, 'm.badh': 0, 'm.rbad0': 0, 'm.rbad1': 0,
                  'm.rbadt': 0, 'm.cbad0': 0, 'm.cbadt': 0, 'hdr.tcp.flags': 0x10, 'm.result': 0, 'md.drop_ctl': 0})
    e.table('classify_fwd')
    return e.env.get('m.result'), e.env.get('m.qx'), e.env.get('md.drop_ctl', 0)


class DelayedPureAckForwardMapping(unittest.TestCase):
    """Review finding 6: the C5 model probe emitted no frame (N refused it upstream), so E's mapping was never
    exercised. Here classify_fwd runs directly: a pure ACK carrying the committed image's NATIVE START (m.q = -N,
    m.p = 0) must map to that image's WIRE START (m.qx = -I, so wend_fwd emits wire_end - I), not its wire end."""
    @classmethod
    def setUpClass(cls):
        cls.text = generate('cimg')
        cls.e = E(e_role(cls.text))
        cls.zero = int(re.search(r'const bit<8>\s+r_OUT_ZERO\s*=\s*(\w+);', cls.text).group(1), 0)

    def test_native_start_maps_to_wire_start_for_each_committed_image(self):
        for native, image in ((37, 61), (49, 141), (61, 61)):
            result, qx, drop = forward_pure_ack(self.e, native, -native)
            self.assertEqual((result, drop), (self.zero, 0), native)
            self.assertEqual(qx, (-image) & 0xFFFFFFFF, (native, image))

    def test_a_pure_ack_at_the_native_end_still_maps_to_the_wire_end(self):
        result, qx, drop = forward_pure_ack(self.e, 49, 0)
        self.assertEqual(drop, 0)
        self.assertNotEqual(qx, (-141) & 0xFFFFFFFF)


class LadderBuildFinding(unittest.TestCase):
    def test_m12p_b08_ladder_withholds_where_the_61_image_must_stale(self):
        """The recorded d531918e2 finding, kept as evidence: b08's max-image ladder withholds at d 62..141."""
        e = E(e_role(generate('ladder')))
        k = constants(generate('ladder'))
        self.assertEqual(reverse(e, 37, 62, 4096)[0], k['OUT_REV_WITHHOLD'])
        self.assertEqual(reverse(e, 37, 141, 4096)[0], k['OUT_REV_WITHHOLD'])
        self.assertEqual(reverse(e, 37, 142, 4096)[1], 1)

if __name__ == '__main__':
    unittest.main()
