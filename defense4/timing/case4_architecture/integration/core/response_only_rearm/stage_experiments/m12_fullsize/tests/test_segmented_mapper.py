"""E (pipe-0 egress) reverse-ACK remap for the committed 401-octet segmented image (make_m12.py
--segmented-full), on the repository P4 source interpreter. Mirrors test_mapper_contract: for a reverse ACK at
distance d before the end of the committed image I (native length N), E must translate (d<=0), withhold
(1<=d<=I, ACK rewritten to the image's native start, window rule), or stale-drop (d>I).

This checks step 4's reverse direction for the 401 image specifically (native 377 -> image 401), which the
full path adds to classify_rev. The forward two-frame commit (seg0 commits 401, seg1 maps as a continuation
without a 5th acct RegisterAction) is a property of the compiled MAU ordering and is not exercised here; this
test asserts the reverse-ACK boundary only.

Run with the research venv:
  ~/.venvs/research/bin/python -m pytest -q m12_fullsize/tests/test_segmented_mapper.py
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

shim = types.ModuleType('baseline')
shim.INTEG = INTEG
sys.modules.setdefault('baseline', shim)


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


interp = _module('segmap_interp', BASE / 'interpreter.py')
combined = _module('segmap_segments', STAGE / 'combined_nt_01/generate.py')


def generate():
    out = Path(tempfile.mkdtemp(prefix='segmap_'))
    subprocess.run([sys.executable, str(STAGE / 'm12_fullsize/make_m12.py'), str(out),
                    '--policy', '--c3', 'cimg', '--shapes', 'passthrough', '--segmented-full'],
                   check=True, capture_output=True)
    return (out / 'response_only.p4').read_text()


def e_role(text):
    return re.sub(r'\br_(\w+)', r'\1', combined.segment(text, 'E')) + '\nPipeline() source_adapter_marker;\n'


def constants(text):
    return {k: int(v, 0) for k, v in re.findall(r'const bit<8>\s+r_(OUT_REV_\w+)\s*=\s*(\w+);', text)}


def reverse(e, native, d, window):
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


class SegmentedReverseBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = generate()
        cls.k = constants(cls.text)
        cls.e = interp.ESource(e_role(cls.text))

    def test_401_image_withhold_translate_stale(self):
        native, image = 377, 401
        for d in (0, 1, 2, 24, 141, 200, image - 1, image, image + 1, image + 2, 600):
            for w in (0, 1, d - 1 if d > 0 else 0, d, d + 1, 4096, 65535):
                result, drop, ack, win = reverse(self.e, native, d, w)
                if d <= 0:
                    self.assertEqual((result, drop), (self.k['OUT_REV_TRANSLATE'], 0), (d, w))
                elif d > image:
                    self.assertEqual(drop, 1, ('stale beyond 401', d, w))
                else:
                    self.assertEqual((result, drop), (self.k['OUT_REV_WITHHOLD'], 0), (d, w))
                    self.assertEqual(ack, 5000, ('withheld ACK to native start', d, w))
                    exp_win = 0 if w < d else min(native + w - d, 0xFFFF)
                    self.assertEqual(win, exp_win, ('window rule', d, w))

    def test_141_range_image_still_correct(self):
        """The segmented 401 window must not break the existing 141 range image boundary."""
        native, image = 49, 141
        for d in (0, 1, image, image + 1, 300):
            result, drop, ack, win = reverse(self.e, native, d, 4096)
            if d <= 0:
                self.assertEqual(result, self.k['OUT_REV_TRANSLATE'], d)
            elif d > image:
                self.assertEqual(drop, 1, d)
            else:
                self.assertEqual((result, drop), (self.k['OUT_REV_WITHHOLD'], 0), d)


if __name__ == '__main__':
    unittest.main(verbosity=2)
