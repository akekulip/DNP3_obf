"""Diagnostic transaction anchors (m12p_c52d): a separate evidence tier on top of the c52 measured baseline.

Contract (Philip, 2026-10-25): per-transaction, write-once records on T's switch clock, keyed by epoch and
generation; no change to forwarding, protocol bytes or timers. These tests pin the generator side: without the
flag the build is c52 byte for byte; with it the emitted source only ADDS instrumentation lines.
"""
import difflib
import hashlib
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from m12gen.build import build
from m12gen import diag_anchor
import test_relay_ts as ts

C52 = Path(__file__).resolve().parents[2] / 'ctl_timing_01/evidence/m12p_c52_sdk9132/response_only.p4'
C52_SHA = '8f37f70240ffa03daf887349e5e52a6abf7e32eb4b43ec559e35077902e3dce4'


def lines(text):
    return text.replace(';', ';\n').splitlines()


class DiagAnchor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c52 = C52.read_text()
        cls.plain, cls.plain_applied = build(**ts.FLAGS, relay_ts=True)
        cls.diag, cls.diag_applied = build(**ts.FLAGS, relay_ts=True, diag_anchors=True)

    def test_baseline_is_c52_byte_for_byte_without_the_flag(self):
        self.assertEqual(hashlib.sha256(self.c52.encode()).hexdigest(), C52_SHA)
        self.assertEqual(self.plain, self.c52)
        self.assertNotIn('diag_anchor', self.plain_applied)
        self.assertEqual(self.diag_applied, self.plain_applied + ['diag_anchor'])

    def test_requires_the_relay_timestamp_profile(self):
        with self.assertRaises(ValueError):
            build(**ts.FLAGS, relay_ts=False, diag_anchors=True)

    def test_emitted_change_only_adds_lines(self):
        diff = list(difflib.unified_diff(lines(self.c52), lines(self.diag), lineterm='', n=0))
        removed = [l for l in diff if l.startswith('-') and not l.startswith('---')]
        self.assertEqual(removed, [])
        # every added hunk belongs to the recorder: it names a d_ identifier (t_d_pair_t, md.d_*, d_p*, d_rec_*)
        hunks = '\n'.join(diff).split('\n@@')[1:]
        self.assertTrue(hunks)
        for hunk in hunks:
            added = [l[1:] for l in hunk.splitlines() if l.startswith('+')]
            self.assertTrue(any(re.search(r'(?<![A-Za-z0-9])(t_)?d_\w+', l) for l in added), hunk)

    def test_no_forwarding_or_timer_statement_added(self):
        added = '\n'.join(l[1:] for l in difflib.unified_diff(lines(self.c52), lines(self.diag), lineterm='', n=0)
                          if l.startswith('+') and not l.startswith('+++'))
        for forbidden in ('ucast_egress_port', 'drop_ctl', 'mirror_type', 'clone_ses', 'qid', 'setValid',
                          'setInvalid', 'set_params', 'bypass_egress', 'count(', 'hdr.ladder.generation =',
                          'hdr.ladder.role =', 'md.now =', 'md.outcome_code ='):
            self.assertNotIn(forbidden, added, forbidden)

    def test_registers_points_and_ring(self):
        for name in diag_anchor.POINTS:
            self.assertIn('Register<t_d_pair_t, bit<8>>(%d) %s;' % (diag_anchor.RING, name), self.diag)
            self.assertIn('RegisterAction<t_d_pair_t, bit<8>, bit<32>>(%s) %s_rec' % (name, name), self.diag)
        self.assertEqual(diag_anchor.RING, 256)

    def test_record_is_write_once_with_sticky_collision_and_duplicate_marks(self):
        body = re.search(r'RegisterAction<t_d_pair_t, bit<8>, bit<32>>\(d_p1\) d_p1_rec = \{(.*?)\n    \};',
                         self.diag, re.S).group(1)
        self.assertIn('if (v.hi == 0) { v.hi = md.d_tag; v.lo = md.now; }', body)
        self.assertIn('else if (v.hi != md.d_tag) { v.hi = v.hi | 32w0x80000000; }', body)
        self.assertIn('else { v.lo = v.lo | 32w1; }', body)

    def test_each_point_is_recorded_after_the_verdict(self):
        apply = self.diag[self.diag.index('        outcome_count.apply();'):]
        apply = apply[:apply.index('\n    }\n}')]
        for name in diag_anchor.POINTS:
            self.assertIn(name + '_rec.execute', self.diag)
            if name != 'd_p2':
                self.assertIn('d_rec_' + name[2:] + '.apply()', apply)
        # P2 (genuine ACK commit) is recorded in the held branch right after the commit registers, keyed like
        # commit_at_access, while the ladder header is still valid
        self.assertIn('commit_at_access.apply(); commit_generation_access.apply();\n            d_rec_p2.apply();',
                      self.diag)


if __name__ == '__main__':
    unittest.main()
