"""Reject duplicates and reordering before any protected producer write."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ExpectedWorkTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('expected_work_reference', ROOT / 'reference.py')
        self.m = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.m
        spec.loader.exec_module(self.m)
        self.w = self.m.ExpectedPinnedWork(7)

    def test_duplicate_phase_cannot_advance_or_authorize_a_second_write(self):
        ref = self.w.claim(7)
        self.assertEqual(self.w.advance_expected(ref, 1), 1)
        self.assertEqual(self.w.advance_expected(ref, 1), 0)
        self.assertEqual(self.w.phase, 2)
        self.assertFalse(self.w.can_retire())

    def test_reordered_terminal_cannot_release_a_live_writer(self):
        ref = self.w.claim(7)
        self.assertEqual(self.w.advance_expected(ref, 3), 0)
        self.assertEqual(self.w.phase, 1)
        self.assertIsNone(self.w.claim(7))
        for phase in (1, 2, 3):
            self.assertEqual(self.w.advance_expected(ref, phase), phase)
        self.assertTrue(self.w.can_retire())

    def test_quarantine_preserves_expected_phase_until_actual_terminal(self):
        ref = self.w.claim(7)
        self.assertEqual(self.w.advance_expected(ref, 1), 1)
        self.assertFalse(self.w.quarantine(self.m.WorkRef(8, ref.generation), 2))
        self.assertTrue(self.w.quarantine(ref, self.w.phase))
        self.assertEqual(self.w.phase, 2)
        self.assertFalse(self.w.can_retire())
        self.assertEqual(self.w.advance_expected(ref, 2), 2)
        self.assertFalse(self.w.can_retire())
        self.assertEqual(self.w.advance_expected(ref, 3), 3)
        self.assertTrue(self.w.can_retire())

    def test_full_generation_and_epoch_guard_survive_record_reuse(self):
        old = self.w.claim(7)
        for phase in (1, 2, 3):
            self.w.advance_expected(old, phase)
        current = self.w.claim(7)
        self.assertEqual(self.w.advance_expected(old, 1), 0)
        self.assertEqual(self.w.advance_expected(self.m.WorkRef(8, current.generation), 1), 0)
        self.assertEqual(self.w.phase, 1)
        self.assertEqual(self.w.advance_expected(current, 1), 1)

    def test_stale_close_and_duplicate_close_never_advance_phase(self):
        ref = self.w.claim(7)
        self.w.advance_expected(ref, 1)
        self.assertFalse(self.w.close(self.m.WorkRef(7, ref.generation + 1), 2))
        self.assertFalse(self.w.close(ref, 1))
        self.assertEqual(self.w.phase, 2)
        self.assertTrue(self.w.close(ref, 2))
        self.assertTrue(self.w.close(ref, 2))
        self.assertEqual(self.w.phase, 2)
        self.assertFalse(self.w.can_retire())

    def test_lost_return_and_invalid_phase_never_create_a_terminal(self):
        ref = self.w.claim(7)
        for phase in (0, 4, 0xFFFFFFFF):
            self.assertEqual(self.w.advance_expected(ref, phase), 0)
        self.assertEqual(self.w.phase, 1)
        self.w.quarantine(ref, self.w.phase)
        self.assertFalse(self.w.can_retire())
        self.assertIsNone(self.w.claim(7))


if __name__ == '__main__':
    unittest.main()
