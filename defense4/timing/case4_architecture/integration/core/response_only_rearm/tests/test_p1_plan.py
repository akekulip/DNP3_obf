"""The installer's write plan carries the pipe-1 READ padder row (read_complete_01 policy builds).

rc01_hw_b08_20261021_01_reference (2026-10-21): rows.build returned the p1_conn row, but the baseline plan()
keeps only p0.r_ and p0.n_ rows, so the switch ran the size-on arm without the padder (READ 49 on the wire).
"""
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE.parent / 'response_only' / 'hw' / 'tests'))
import fixture as fx  # noqa: E402

# The fixture imports the baseline bringup_composite under that name; load the candidate entrypoint by path.
_spec = importlib.util.spec_from_file_location('rearm_bringup_composite', HERE / 'hw' / 'bringup_composite.py')
rbc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rbc)

P1 = 'p1.x_Egress.p1_conn'


class P1Plan(unittest.TestCase):
    def plan(self, enabled, *extra):
        saved = rbc.P1_PAD['enabled']
        rbc.P1_PAD['enabled'] = enabled
        self.addCleanup(rbc.P1_PAD.__setitem__, 'enabled', saved)
        return rbc.installer.plan(fx.args(*extra), fx.PORTS)

    def test_a_policy_build_with_padding_on_writes_the_p1_row_before_any_N_row(self):
        ops = self.plan(True)
        tables = [op.get('table') for op in ops]
        self.assertEqual(tables.count(P1), 1)
        first_n = min(i for i, t in enumerate(tables) if t and t.startswith('p0.n_'))
        self.assertLess(tables.index(P1), first_n)

    def test_padding_off_writes_no_p1_row(self):
        self.assertNotIn(P1, [op.get('table') for op in self.plan(True, '--pad-enable', '0')])

    def test_a_build_without_the_padder_plans_exactly_as_before(self):
        self.assertEqual(self.plan(False), rbc.original_plan(fx.args(), fx.PORTS))


if __name__ == '__main__':
    unittest.main()
