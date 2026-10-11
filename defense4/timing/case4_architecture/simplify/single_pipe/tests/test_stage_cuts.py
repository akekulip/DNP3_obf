"""Edits S3 (reverse window fold) and S4 (grouped CRC tables): equivalence and structure.

S3 is checked by running the reverse path as the response path wrote it and as S3 rewrites it, on the same
register and header values, and comparing the outcome, the emitted ACK and the emitted window. S4 only
regroups existing actions into tables; the test checks every hash action is still applied under the same
header validity it had. Run from case4_architecture/:  python3 -m pytest -q simplify/single_pipe/tests
"""
import random
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import make_single_pipe as msp  # noqa: E402

M32 = 0xFFFFFFFF
IMAGE_LEN = 58


def neg(x):
    return bool(x & 0x80000000)


def reverse_original(qx, v, q, p, window):
    """case4_response_path.p4: img_wend (r) -> rev_prep -> classify_rev -> window_t."""
    r = (qx - v) & M32
    y = (r + window) & M32
    z = (r + IMAGE_LEN) & M32
    pm = (q + r) & M32
    t = (q - p) & M32
    if not neg(r):
        return 'translate', pm, window
    if not neg(z) and neg(y):
        return 'withhold', p, 0
    if not neg(z) and not neg(y):
        s_end = (y + t) & M32
        return 'withhold', p, (s_end & 0xFFFF) if (s_end & 0xFFFF0000) == 0 else 0xFFFF
    return 'drop', None, None


def reverse_s3(qx, v, q, p, window):
    """S3: u = q - p (rev_qp_t), u += window (img_wend_t), rev_prep u = r + u, classify_rev keyed on u."""
    win32 = window
    u = (q - p) & M32
    r = (qx - v) & M32
    u = (u + win32) & M32
    y = (r + win32) & M32
    z = (r + IMAGE_LEN) & M32
    pm = (q + r) & M32
    u = (r + u) & M32
    if not neg(r):
        return 'translate', pm, window
    if not neg(z) and neg(y):
        return 'withhold', p, 0
    if not neg(z) and not neg(y) and (u & 0xFFFF0000) == 0:
        return 'withhold', p, u & 0xFFFF
    if not neg(z) and not neg(y):
        return 'withhold', p, 0xFFFF
    return 'drop', None, None


class ReverseFoldEquivalence(unittest.TestCase):
    def check(self, *args):
        self.assertEqual(reverse_original(*args), reverse_s3(*args), args)

    def test_random(self):
        rng = random.Random(20261011)
        for _ in range(200000):
            qx = rng.getrandbits(32)
            # half the draws put v within 128 of qx, where r is small and the withhold rows are reachable
            v = (qx + rng.randint(-128, 128)) & M32 if rng.random() < 0.5 else rng.getrandbits(32)
            self.check(qx, v, rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(16))

    def test_edges(self):
        edges = [0, 1, 57, 58, 59, 0x7FFFFFFF, 0x80000000, 0xFFFFFFC6, 0xFFFFFFFF, 0xFFFF, 0x10000]
        wins = [0, 1, 0x7FFF, 0xFFFF]
        for qx in edges:
            for v in edges:
                for q in (0, 0xFFFF, 0xFFFFFFFF):
                    for p in (0, 1, 0xFFFFFFF0):
                        for w in wins:
                            self.check(qx, v, q, p, w)

    def test_every_outcome_is_reached(self):
        q, p = 1000, 900
        cases = {(5, 0): 'translate', (0, 30): 'withhold', (0, 500): 'drop'}
        for (qx, v), want in cases.items():
            self.assertEqual(reverse_s3(qx, v, q, p, 100)[0], want)
        # withhold: window 0 when r + window < 0; exact when r + u fits 16 bits; clamped when it does not
        self.assertEqual(reverse_s3(0, 30, q, p, 10), ('withhold', p, 0))
        self.assertEqual(reverse_s3(0, 30, q, p, 100), ('withhold', p, (100 + 100 - 30) & 0xFFFF))
        self.assertEqual(reverse_s3(0, 30, 0x20000, 0, 100), ('withhold', 0, 0xFFFF))


class GeneratedSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src, _ = msp.generate()
        s = src.index('control r_Egress'); e = src.index('control r_EgDeparser')
        cls.egress = msp.COMMENTS.sub(' ', src[s:e])

    def test_window_t_is_gone(self):
        self.assertNotIn('window_t', self.egress)
        self.assertNotIn('window_exact', self.egress)

    def test_classify_rev_counts_its_outcomes_and_count_t_is_exclusive(self):
        for code in ('r_OUT_REV_TRANSLATE', 'r_OUT_REV_WITHHOLD', 'r_OUT_REV_DROP_STALE'):
            self.assertIn('outcome.count(%s)' % code, self.egress)
        block = re.search(r'if \(m\.dir == 2 && m\.shape == r_SH_ACK && m\.mode == 1\) \{\s*rev_prep_t\.apply\(\); '
                          r'classify_rev\.apply\(\);\s*\} else \{(.*?)\n        \}', self.egress, re.S)
        self.assertIsNotNone(block)
        self.assertIn('count_t.apply();', block[1])
        self.assertIn('syn_scrub_t.apply();', block[1])
        self.assertEqual(self.egress.count('count_t.apply();'), 1)
        self.assertEqual(self.egress.count('Counter<bit<32>, bit<8>>(32, CounterType_t.PACKETS) outcome;'), 1)

    def test_changed_is_set_before_classify_rev(self):
        self.assertIn('action rev_qp() { m.u = m.q - m.p; m.win32 = widen_win.get({hdr.tcp.window}); m.changed = 1; }',
                      self.egress)
        rev_actions = re.findall(r'action rev_(translate|withhold_zero|withhold_open|withhold_clamp|drop)\(\) \{([^}]*)\}', self.egress)
        self.assertEqual(len(rev_actions), 5)
        for name, body in rev_actions:
            self.assertNotIn('m.changed', body, name)

    def test_crc_hashes_regrouped_under_the_same_validity(self):
        e = self.egress
        self.assertIn('if (hdr.dl.isValid()) { crc_dl_t.apply(); }', e)
        self.assertIn('if (hdr.rb0.isValid()) { read_profile.apply(); crc_read_a_t.apply(); crc_read_b_t.apply(); }', e)
        self.assertIn('if (hdr.cb0.isValid()) { ctl_profile.apply(); crc_ctl_a_t.apply(); }', e)
        self.assertIn('true:crc_dl_ctl();false:in_dl();', e)
        for action, parts in (('crc_dl_ctl', 'in_dl();crc_ctl_tail1();'), ('crc_read_a', 'in_rb0();in_rb1();'),
                              ('crc_read_b', 'in_rt();crc_read_tail();'), ('crc_ctl_a', 'in_cb0();in_ct();')):
            self.assertIn('action %s(){%s}' % (action, parts), e)
        for old in ('in_dl_t', 'in_rb0_t', 'in_rb1_t', 'in_rt_t', 'in_cb0_t', 'in_ct_t', 'crc_read_tail_t', 'crc_ctl_tail1_t'):
            self.assertNotRegex(e, r'\b%s\b' % old)
        # every original hash action is still called exactly once, through the grouped actions
        for action in ('in_dl', 'in_rb0', 'in_rb1', 'in_rt', 'in_cb0', 'in_ct', 'crc_read_tail', 'crc_ctl_tail1'):
            self.assertGreaterEqual(len(re.findall(r'\b%s\(\);' % action, e)), 1, action)


if __name__ == '__main__':
    unittest.main()


class HoldOkDefined(unittest.TestCase):
    """Edit S5: the three level-3 readers of meta.hold_ok see 0 on every pass, not undefined metadata."""

    def test_parser_zeroes_hold_ok_before_any_transition(self):
        src, _ = msp.generate()
        start = src.index('    state start {', src.index('parser d_IgParser'))
        block = src[start:src.index('transition', start)]
        self.assertIn('meta.hold_ok         = 8w0;', block)

    def test_frozen_timing_source_is_unchanged(self):
        self.assertNotIn('meta.hold_ok         = 8w0;', msp.TIMING_SRC.read_text())

    def test_early_readers_still_key_on_hold_ok(self):
        # S5 defines the value; it does not remove the keys, so tbl_hold_ok's later write is still what
        # tbl_decide_fresh / tbl_decide_deq see.
        code = msp.COMMENTS.sub(' ', msp.generate()[0])
        for table in ('tbl_select_deadlines', 'tbl_state_decode', 'tbl_resp_deadline'):
            decl = code[code.index('table %s' % table):]
            self.assertIn('meta.hold_ok', decl[:decl.index('actions')], table)
