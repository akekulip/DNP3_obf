"""t_register_reset: the five 0xffffffff registers are restored, never cleared to 0."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import t_register_reset as tr  # noqa: E402

EXPECTED_NONZERO = ['ack_commit_gen_reg', 'child_seen0_reg', 'child_seen1_reg', 'child_seen2_reg', 'quarantine_reg']


class ResetPlan(unittest.TestCase):
    def test_nonzero_resets_match_the_documented_rule(self):
        self.assertEqual(tr.nonzero_resets(), EXPECTED_NONZERO)

    def test_plan_values_follow_declarations(self):
        plan = {row[0]: row[3] for row in tr.reset_plan()}
        for name in EXPECTED_NONZERO:
            self.assertEqual(plan['pipe.t_Ingress.%s' % name], 0xFFFFFFFF)
        self.assertEqual(plan['pipe.t_Ingress.gen_alloc_reg'], 0)
        self.assertEqual(plan['pipe.t_Ingress.resp_done_reg'], 0)

    def test_outcome_counter_register_covers_every_cell(self):
        cells = [r for r in tr.reset_plan() if r[0] == 'pipe.t_Ingress.outcomes']
        self.assertEqual([r[1] for r in cells], list(range(16)))

    def test_a_cleared_table_is_caught(self):
        zeroed = {(t, i): 0 for t, i, _f, _v in tr.reset_plan()}
        bad = {b[0].rsplit('.', 1)[1] for b in tr.check_readback(zeroed)}
        self.assertEqual(sorted(bad), EXPECTED_NONZERO)

    def test_a_correct_readback_passes(self):
        good = {(t, i): v for t, i, _f, v in tr.reset_plan()}
        self.assertEqual(tr.check_readback(good), [])

    def test_commented_declarations_are_ignored(self):
        p = Path(self.id().replace('.', '_') + '.p4')
        tmp = Path(__file__).resolve().parent / p.name
        try:
            tmp.write_text('/* Register<bit<32>, bit<1>>(1, 0xffffffff) ghost_reg; */\n'
                           'Register<bit<32>, bit<1>>(1, 0xffffffff) real_reg;\n')
            self.assertEqual(tr.nonzero_resets(tmp), ['real_reg'])
        finally:
            tmp.unlink(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
