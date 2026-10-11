"""reservoir_sizing.py and the --bor-loopback-speed option (offline; no switch)."""
import importlib.util
import sys
import unittest
from pathlib import Path

CONTROL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONTROL))
import reservoir_sizing as rs  # noqa: E402


def load_setup():
    spec = importlib.util.spec_from_file_location('timing_setup_for_sizing', CONTROL / 'defense4_timing_setup.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Sizing(unittest.TestCase):
    def test_selftest(self):
        self.assertIn('pass', rs.selftest())

    def test_shipped_k_against_a_loop(self):
        self.assertTrue(rs.size(1000, 25, k=64)['k_sufficient'])   # 1500 ns needed, 1720 covered
        self.assertFalse(rs.size(1200, 50, k=64)['k_sufficient'])   # faster port: same K covers less

    def test_slower_port_needs_fewer_tokens(self):
        self.assertLess(rs.size(1000, 10)['k_min'], rs.size(1000, 25)['k_min'])


class SetupOption(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = load_setup()

    def test_default_keeps_25g(self):
        a = self.setup.build_argparser().parse_args(['dry-run'])
        self.assertEqual(self.setup.BOR_LOOPBACK_SPEEDS[a.bor_loopback_speed], 'BF_SPEED_25G')

    def test_10g_maps_to_bfrt_speed(self):
        a = self.setup.build_argparser().parse_args(['dry-run', '--bor-loopback-speed', '10G'])
        self.assertEqual(self.setup.BOR_LOOPBACK_SPEEDS[a.bor_loopback_speed], 'BF_SPEED_10G')

    def test_unknown_speed_refused(self):
        with self.assertRaises(SystemExit):
            self.setup.build_argparser().parse_args(['dry-run', '--bor-loopback-speed', '40G'])


if __name__ == '__main__':
    unittest.main()
