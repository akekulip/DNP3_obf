"""Literal event/byte fixtures for the atomic pinned work-record alternative."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkReferenceTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("work_reference", ROOT / "reference.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.assertTrue(hasattr(module, "PinnedWork"), "atomic pair model is missing")
        self.m = module
        self.w = module.PinnedWork(1)

    def test_real_fourth_return_is_the_only_normal_terminal(self):
        ref = self.w.claim(1)
        self.assertEqual(ref.to_bytes(), bytes.fromhex("0000000100000001"))
        self.assertEqual(self.w.phase, 1)
        self.assertEqual(self.w.advance(ref), 1)
        self.assertFalse(self.w.can_retire())
        self.assertEqual(self.w.advance(ref), 2)
        self.assertFalse(self.w.can_retire())
        self.assertEqual(self.w.advance(ref), 3)
        self.assertTrue(self.w.can_retire())
        self.assertEqual(self.w.advance(ref), 0)

    def test_busy_claim_burns_counter_without_reusing_protected_record(self):
        first = self.w.claim(1)
        self.assertIsNone(self.w.claim(1))
        self.assertEqual(self.w.reference, first)
        self.assertEqual(self.w.phase, 1)
        for _ in range(3):
            self.w.advance(first)
        second = self.w.claim(1)
        self.assertEqual(second.to_bytes(), bytes.fromhex("0000000100000003"))
        self.assertEqual(self.w.advance(first), 0)
        self.assertEqual(self.w.phase, 1)

    def test_generation_check_and_phase_change_are_one_atomic_decision(self):
        first = self.w.claim(1)
        self.assertEqual(self.w.advance(self.m.WorkRef(1, 2)), 0)
        self.assertEqual(self.w.advance(self.m.WorkRef(2, 1)), 0)
        self.assertEqual(self.w.phase, 1)
        self.assertEqual(self.w.advance(first), 1)

    def test_close_pins_until_real_return_without_publication_pass(self):
        ref = self.w.claim(1)
        self.w.advance(ref)
        self.assertFalse(self.w.close(2))
        self.assertEqual(self.w.phase, 2)
        self.assertTrue(self.w.close(1))
        self.assertEqual(self.w.phase, 3)
        self.assertFalse(self.w.can_retire())
        self.assertEqual(self.w.advance(ref), 3)
        self.assertTrue(self.w.can_retire())

    def test_last_full_32_bit_generation_is_usable_then_no_wrap(self):
        self.w.counter = 0xFFFFFFFE
        last = self.w.claim(1)
        self.assertEqual(last.to_bytes(), bytes.fromhex("00000001ffffffff"))
        for _ in range(3):
            self.w.advance(last)
        self.assertIsNone(self.w.claim(1))
        self.assertEqual(self.w.counter, 0xFFFFFFFF)
        self.assertEqual(self.w.phase, 4)

    def test_exact_recirculation_envelope_preserves_inner_bytes(self):
        prefix = self.m.RecircEnvelope(1, 1, 0x00010001, 1).to_bytes()
        self.assertEqual(prefix, bytes.fromhex("00000001000000010001000100010000"))
        inner = bytes.fromhex("ffffffffffff00112233445588d400000001000000011234567801000000")
        packet = prefix + inner
        self.assertEqual(len(prefix), 16)
        self.assertEqual(packet[16:], inner)
        self.assertEqual(self.m.RecircEnvelope.from_bytes(packet[:16]).expected, 0x00010001)


if __name__ == "__main__":
    unittest.main()
