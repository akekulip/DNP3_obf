"""read_timing.p4 timing parameters come from table action data (ticket T6).

Fragment-level source tests (protocol/source_eval.Source on a mechanically rewritten copy of
the P4 text). They execute the actual tables of read_timing.p4 in apply order; they are not
the parser, the compiler, the traffic manager or the target. The whole program is run by
test_read_timing_whole_program.py.
"""
import hashlib
import importlib.util
import re
import sys
import unittest
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]
READ = ARCH / 'integration/read'
from read_fragment import MASK, TEXT, source  # noqa: E402

spec = importlib.util.spec_from_file_location('join_reference', READ / 'join_reference.py')
jr = importlib.util.module_from_spec(spec)
sys.modules['join_reference'] = jr
spec.loader.exec_module(jr)


def offsets(d_ms, ready=jr.READINESS_NS, gap=jr.GAP_NS, cap=jr.CAP_NS):
    return {'deadline_offsets': ('prepare_deadlines', (jr.DA_NS[d_ms], ready, gap, cap))}


def run_timing(now, t0, d_ms, seen, runtime=None, service=True):
    """Apply anchor_timestamp, deadline_offsets, deadline_deltas, heartbeat_eligibility in order."""
    s = source({'m.now': now & MASK, 'hdr.service.anchor': (t0 & MASK) | 1, 'hdr.service.seen': seen,
                'm.eligible_mask': 0}, runtime or offsets(d_ms))
    for table in ('anchor_timestamp', 'deadline_offsets', 'deadline_deltas', 'heartbeat_eligibility'):
        s.table(table)
    return s


class Params(unittest.TestCase):
    T0 = 0x01000000

    def test_probe_constants_appear_only_as_installable_defaults(self):
        code = re.sub(r'/\*.*?\*/|//[^\n]*', '', TEXT, flags=re.S)
        for literal in ('4999936', '29999872', '999936', '40000000'):
            hits = [m.start() for m in re.finditer(r'\b' + literal + r'\b', code)]
            self.assertEqual(len(hits), 1, literal)
            line = code[code.rfind('\n', 0, hits[0]) + 1:code.index('\n', hits[0])]
            self.assertIn('default_action', line)
            self.assertNotIn('const default_action', line)

    def test_deadline_offsets_is_a_parametrized_action(self):
        self.assertRegex(TEXT, r'action prepare_deadlines\(bit<32> \w+,\s*bit<32> \w+,\s*bit<32> \w+,\s*bit<32> \w+\)')

    def test_each_d_a_offset_is_installable_and_exact(self):
        for d_ms in (5, 10, 15, 20):
            s = run_timing(self.T0, self.T0, d_ms, 3)
            self.assertEqual(s.env['m.normal_deadline'], self.T0 + jr.DA_NS[d_ms], d_ms)
            self.assertEqual(s.env['m.readiness_deadline'], self.T0 + jr.READINESS_NS)
            self.assertEqual(s.env['m.cap_deadline'], self.T0 + jr.CAP_NS)
            self.assertEqual(s.env['m.response_anchor'], self.T0 + jr.GAP_NS)

    def test_gap_comes_from_action_data(self):
        s = run_timing(self.T0 + 512, self.T0, 5, 3, offsets(5, gap=1_999_872))
        self.assertEqual(s.env['m.response_anchor'], self.T0 + 512 + 1_999_872)

    def test_ack_eligibility_flips_exactly_at_each_d_a_and_matches_the_oracle(self):
        for base in (self.T0, (MASK - 2_000_000) & ~0xFF):      # second base wraps within D_A
            for d_ms in (5, 10, 15, 20):
                oracle = jr.ideal(base, d_ms, base + 256, base + 512).e_ack
                before = run_timing(oracle - 256, base, d_ms, 3)
                at = run_timing(oracle, base, d_ms, 3)
                self.assertEqual(before.env['m.eligible_mask'] & 2, 0, (base, d_ms))
                self.assertEqual(at.env['m.eligible_mask'], 3, (base, d_ms))

    def test_readiness_releases_ack_when_response_unseen(self):
        ready = self.T0 + jr.READINESS_NS
        self.assertEqual(run_timing(ready - 256, self.T0, 5, 1).env['m.eligible_mask'] & 2, 0)
        self.assertEqual(run_timing(ready, self.T0, 5, 1).env['m.eligible_mask'], 3)

    def test_cap_row_releases_ack_even_if_readiness_is_pushed_past_it(self):
        runtime = offsets(5, ready=50_000_000)
        cap = self.T0 + jr.CAP_NS
        self.assertEqual(run_timing(cap - 256, self.T0, 5, 1, runtime).env['m.eligible_mask'] & 2, 0)
        self.assertEqual(run_timing(cap, self.T0, 5, 1, runtime).env['m.eligible_mask'] & 2, 2)

    def test_unarmed_anchor_never_releases(self):
        s = source({'m.now': self.T0 + 60_000_000, 'hdr.service.anchor': self.T0, 'hdr.service.seen': 3,
                    'm.eligible_mask': 0}, offsets(5))
        for table in ('anchor_timestamp', 'deadline_offsets', 'deadline_deltas', 'heartbeat_eligibility'):
            s.table(table)
        self.assertEqual(s.env['m.eligible_mask'], 0)


def run_response(now, t0, deadline, runtime=None):
    s = source({'m.now': now & MASK, 'hdr.service.anchor': (t0 & MASK) | 1,
                'hdr.service.response_deadline': deadline, 'm.response_eligible': 0},
               runtime or offsets(5))
    for table in ('anchor_timestamp', 'deadline_offsets', 'deadline_deltas', 'response_snapshot',
                  'response_age', 'response_eligibility'):
        s.table(table)
    return s.env['m.response_eligible']


class ResponseRelease(unittest.TestCase):
    T0 = 0x01000000

    def test_armed_deadline_releases_only_when_due(self):
        deadline = (self.T0 + 5_000_000 + jr.GAP_NS) | 1
        self.assertEqual(run_response(deadline - 256 - 1, self.T0, deadline), 0)
        self.assertEqual(run_response(deadline & ~0xFF, self.T0, deadline), 1)

    def test_fallback_no_ack_at_readiness_when_deadline_unarmed(self):
        ready = self.T0 + jr.READINESS_NS
        self.assertEqual(run_response(ready - 256, self.T0, 0), 0)
        self.assertEqual(run_response(ready, self.T0, 0), 1)

    def test_armed_deadline_in_the_future_is_not_overridden_by_readiness(self):
        ready = self.T0 + jr.READINESS_NS
        deadline = (ready + jr.GAP_NS) | 1
        self.assertEqual(run_response(ready, self.T0, deadline), 0)

    def test_cap_releases_response_even_with_a_far_deadline(self):
        cap = self.T0 + jr.CAP_NS
        deadline = (cap + 5_000_000) | 1
        self.assertEqual(run_response(cap - 256, self.T0, deadline), 0)
        self.assertEqual(run_response(cap, self.T0, deadline), 1)

    def test_unarmed_anchor_never_releases_response(self):
        s = source({'m.now': self.T0 + 60_000_000, 'hdr.service.anchor': self.T0,
                    'hdr.service.response_deadline': 0, 'm.response_eligible': 0}, offsets(5))
        for table in ('anchor_timestamp', 'deadline_offsets', 'deadline_deltas', 'response_snapshot',
                      'response_age', 'response_eligibility'):
            s.table(table)
        self.assertEqual(s.env['m.response_eligible'], 0)


class Includes(unittest.TestCase):
    def test_local_include_copies_are_byte_identical_to_the_ownership_originals(self):
        for name in ('expected_work_record.p4', 'original_credit.p4', 'probe_shell.p4'):
            self.assertEqual((READ / name).read_bytes(), (ARCH / 'ownership/p4' / name).read_bytes(), name)

    def test_probe_is_untouched(self):
        # Hash of the probe as committed at HEAD when this ticket was written.
        probe = (ARCH / 'ownership/p4/held_timing_expected_probe.p4').read_bytes()
        self.assertEqual(hashlib.sha256(probe).hexdigest()[:12], PROBE_SHA_PREFIX)


PROBE_SHA_PREFIX = '1af31bc97a4b'

if __name__ == '__main__':
    unittest.main()
