"""run.evaluate() gates a run: a normal run fails on a nonzero endpoint, a missing artifact, or a wire/clrt
extractor failure; a declared negative control passes only when the endpoint fails in the declared way."""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import run  # noqa: E402

ALL_PRESENT = {'out.pcap': True, 'in.pcap': True, 'wire.json': True, 'timing.json': True}


class Evaluate(unittest.TestCase):
    def test_clean_normal_run_passes(self):
        ok, fails = run.evaluate(False, 0, {'ok': True, 'master_rc': 0}, 0, 0, ALL_PRESENT)
        self.assertTrue(ok, fails)
        self.assertEqual(fails, [])

    def test_nonzero_endpoint_fails(self):
        ok, fails = run.evaluate(False, 1, {'ok': False, 'error': 'crash'}, 0, 0, ALL_PRESENT)
        self.assertFalse(ok)
        self.assertTrue(any('endpoint returned nonzero' in f for f in fails), fails)

    def test_endpoint_not_ok_fails_even_with_zero_rc(self):
        ok, fails = run.evaluate(False, 0, {'ok': False, 'master_rc': 3}, 0, 0, ALL_PRESENT)
        self.assertFalse(ok)
        self.assertTrue(any('endpoint run not ok' in f for f in fails), fails)

    def test_wire_extractor_failure_fails(self):
        ok, fails = run.evaluate(False, 0, {'ok': True}, 1, 0, ALL_PRESENT)
        self.assertFalse(ok)
        self.assertTrue(any('wire extractor' in f for f in fails), fails)

    def test_clrt_extractor_failure_fails(self):
        ok, fails = run.evaluate(False, 0, {'ok': True}, 0, 1, ALL_PRESENT)
        self.assertFalse(ok)
        self.assertTrue(any('clrt extractor' in f for f in fails), fails)

    def test_missing_artifact_fails(self):
        art = dict(ALL_PRESENT, **{'timing.json': False})
        ok, fails = run.evaluate(False, 0, {'ok': True}, 0, 0, art)
        self.assertFalse(ok)
        self.assertTrue(any('timing.json' in f for f in fails), fails)

    def test_negative_control_passes_when_it_fails_correctly(self):
        # extractor rcs are not gated for a declared negative control
        ok, fails = run.evaluate(True, 0, {'ok': True, 'master_rc': 2}, 1, 1, ALL_PRESENT)
        self.assertTrue(ok, fails)

    def test_negative_control_that_connects_is_a_failure(self):
        ok, fails = run.evaluate(True, 0, {'ok': False, 'master_rc': 0}, 0, 0, ALL_PRESENT)
        self.assertFalse(ok)
        self.assertTrue(any('negative control' in f for f in fails), fails)

    def test_negative_control_still_requires_artifacts(self):
        art = dict(ALL_PRESENT, **{'out.pcap': False})
        ok, fails = run.evaluate(True, 0, {'ok': True, 'master_rc': 2}, 0, 0, art)
        self.assertFalse(ok)
        self.assertTrue(any('out.pcap' in f for f in fails), fails)

    def test_non_dict_vision_result_is_not_ok(self):
        ok, fails = run.evaluate(False, 0, 'segfault text', 0, 0, ALL_PRESENT)
        self.assertFalse(ok)


if __name__ == '__main__':
    unittest.main()
