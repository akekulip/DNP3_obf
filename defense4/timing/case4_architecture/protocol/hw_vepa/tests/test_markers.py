"""Build-dependent tests are marked, and skip (never fail) when the compiled evidence tree is absent, so the
pure-source set always runs on a bare checkout. The nested runs are skipped inside themselves."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
NESTED = os.environ.get('HW_VEPA_NESTED') == '1'


def pytest(args, root=None):
    env = dict(os.environ, HW_VEPA_NESTED='1')
    if root is not None:
        env['HW_VEPA_EVIDENCE_ROOT'] = root
    return subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', str(HERE), '--ignore', str(Path(__file__))] + args,
                          capture_output=True, text=True, env=env)


@unittest.skipIf(NESTED, 'nested run')
class Markers(unittest.TestCase):
    def test_the_build_dependent_tests_carry_the_markers(self):
        out = pytest(['--collect-only', '-m', 'build_tree or evidence_tree']).stdout
        for name in ('test_shipped_config_is_fully_bound_with_the_real_pins', 'test_validate_passes_with_the_real_pins',
                     'test_run_deploys_before_it_observes_the_switch', 'RealEvidence'):
            self.assertIn(name, out)

    def test_without_the_tree_they_skip_and_nothing_fails(self):
        with tempfile.TemporaryDirectory() as empty:
            r = pytest([], root=empty)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:])
        self.assertIn('skipped', r.stdout)
        self.assertNotIn('failed', r.stdout)

    def test_the_pure_source_set_needs_no_tree_and_skips_nothing(self):
        with tempfile.TemporaryDirectory() as empty:
            r = pytest(['-m', 'not build_tree and not evidence_tree'], root=empty)
        self.assertEqual(r.returncode, 0, r.stdout[-1500:])
        self.assertNotIn('skipped', r.stdout)

    def test_with_the_tree_present_nothing_is_skipped(self):
        r = pytest([])
        self.assertEqual(r.returncode, 0, r.stdout[-1500:])
        self.assertNotIn('skipped', r.stdout)


if __name__ == '__main__':
    unittest.main()
