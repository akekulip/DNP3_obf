"""c68 (--strip-telemetry): only write-only measurement state leaves c67; every other line is unchanged."""
import difflib
import hashlib
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from m12gen.build import build

EVIDENCE = HERE.parent / 'ctl_timing_01/evidence'
C67, C68 = EVIDENCE / 'm12p_c67_sdk9132/response_only.p4', EVIDENCE / 'm12p_c68_sdk9132/response_only.p4'
FLAGS = dict(c3='cimg', shapes='passthrough', two_read_build=True, reduce=True, ack_retry=True, read_handshake=True,
             headroom=True, relay=True, relay_sbo=True, relay_ts=True, response_ready_timing=True)
# every c67 statement c68 drops or rewrites names one of these
TELEMETRY = re.compile(r'count_first|count_busy|count_term|count_retry_duplicate|retry_dup_t|outcome_count|'
                       r'outcome_code|bump_outcome|outcomes|p1_outcome|count_t\b|outcome\.count|\bcount\(|'
                       r'\bbump\(|actioncount\(|actionbump\(|t_OUT_|drop_timer_stale|Counter<')


def statements(text):
    """Statements with comments and whitespace removed, split at ; { and }."""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    text = re.sub(r'//[^\n]*', '', text)
    text = re.sub(r'\s+', '', text)
    return [part for part in re.split(r'(?<=[;{}])', text) if part]


class StripTelemetry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c67 = build(None, **FLAGS)[0]
        cls.c68 = build(None, strip_telemetry=True, **FLAGS)[0]

    def test_sources_match_committed_builds(self):
        self.assertEqual(hashlib.sha256(self.c67.encode()).hexdigest(),
                         hashlib.sha256(C67.read_bytes()).hexdigest())
        self.assertEqual(self.c68, C68.read_text())

    def test_no_measurement_state_left(self):
        for name in ('count_first', 'count_busy', 'count_term', 'retry_dup_t', 'outcome_count', 'outcome_code',
                     'bump_outcome', 'p1_outcome', 'count_t', 'outcome.count', 't_Ingress.outcomes', 'Register<bit<32>, bit<5>>(25'):
            self.assertNotIn(name, self.c68)
        self.assertIsNone(re.search(r'\bcount\(', self.c68))

    def test_only_telemetry_statements_change(self):
        """A deleted run is telemetry: each statement names telemetry or sits inside a block a telemetry
        declaration opened in that run. A rewritten statement is its c67 statement minus the count call."""
        drop = re.compile(r'count_\w+_bump\.execute\(4w\d\);|count\([^;]*\);|retry_dup_t\.apply\(\);')
        old, new = statements(self.c67), statements(self.c68)
        matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            removed, added = old[i1:i2], new[j1:j2]
            depth = 0
            for statement in removed:
                inside = depth > 0
                if statement.endswith('{') and (inside or TELEMETRY.search(statement)):
                    depth += 1
                elif statement == '}' and depth:
                    depth -= 1
                elif not (inside or TELEMETRY.search(statement) or drop.sub('', statement) in added or
                          statement in ('{', '}', ';')):
                    self.fail('a non-telemetry statement changed: ' + statement)
            split = any('drop_timer_stale_' in statement for statement in added)   # the split action's copied body
            for statement in added:
                if statement in ('{', '}', ';') or 'drop_timer_stale_' in statement or (split and statement in old):
                    continue
                self.assertIn(statement, [drop.sub('', s) for s in removed],
                              'c68 statement is not a c67 statement minus telemetry: ' + statement)


if __name__ == '__main__':
    unittest.main()
