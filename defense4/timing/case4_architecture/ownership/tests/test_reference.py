"""Independent behavioral fixtures for the ownership experiment.

These tests do not execute a P4 pipeline. Their expected words/bytes are literal
fixtures so a missing credit or stale transition cannot hide behind a codec.
"""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OwnershipReferenceTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("ownership_reference", ROOT / "reference.py")
        self.assertTrue((ROOT / "reference.py").is_file(), "ownership reference is not implemented")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        self.module = module
        self.a = module.Authority(1)

    def test_stale_readiness_snapshot_cannot_retire_committed_ack(self):
        self.assertEqual(self.a.begin(1), 1)
        self.assertEqual(self.a.word, 0x00010001)
        stale = self.a.word
        self.assertTrue(self.a.compare_swap(stale, 0x00020001))
        self.assertFalse(self.a.compare_swap(stale, 0x00030001))
        self.assertEqual(self.a.word, 0x00020001)

    def test_old_scan_on_same_connection_cannot_cancel_new_association(self):
        self.a.begin(1)
        old_snapshot = self.a.word
        self.a.reset(1)
        self.a.finish()
        self.assertEqual(self.a.begin(1), 2)
        self.assertFalse(self.a.compare_swap(old_snapshot, 0x00030001))
        self.assertEqual(self.a.word, 0x00010002)

    def test_reset_blocks_rearm_until_producer_terminal(self):
        self.a.begin(1)
        ref = self.a.acquire_work(1, "request")
        self.assertEqual(ref.to_bytes(), bytes.fromhex("0000000100000001"))
        self.assertEqual(self.a.word, 0x00A10001)
        self.a.reset(1)
        self.assertEqual(self.a.word, 0x00A30001)
        self.assertIsNone(self.a.begin(1))
        self.assertFalse(self.a.publish(ref, b"old image"))
        self.assertFalse(self.a.finish())
        self.assertTrue(self.a.terminal_work(ref))
        self.assertTrue(self.a.finish())
        self.assertEqual(self.a.begin(1), 2)
        self.assertFalse(self.a.terminal_work(ref))

    def test_same_owner_producer_slot_cannot_reuse_after_terminal(self):
        self.a.begin(1)
        ref = self.a.acquire_work(1, "request")
        self.assertTrue(self.a.terminal_work(ref))
        self.assertIsNone(self.a.acquire_work(1, "request"))
        other = self.a.acquire_work(1, "response")
        self.assertEqual(other.to_bytes(), bytes.fromhex("0000000100000002"))
        self.assertFalse(self.a.terminal_work(ref))
        self.assertEqual(self.a.word & 0x00400000, 0x00400000)

    def test_policy_off_debits_ack_response_and_aborts_unsent_operate(self):
        self.a.begin(1)
        for original in ("ack", "response", "operate"):
            self.assertTrue(self.a.hold(1, original))
        self.assertEqual(self.a.word, 0x001D0001)
        self.a.disable()
        self.assertEqual(self.a.word, 0x001F0001)
        self.assertEqual(self.a.terminal_original(1, "ack"), "forward")
        self.assertEqual(self.a.terminal_original(1, "response"), "forward")
        self.assertEqual(self.a.terminal_original(1, "operate"), "abort")
        self.assertTrue(self.a.finish())
        self.assertEqual(self.a.word, 1)

    def test_lost_original_keeps_quarantine_without_blockers(self):
        self.a.begin(1)
        self.a.hold(1, "response")
        self.a.reset(1)
        self.assertFalse(self.a.finish())
        self.assertIsNone(self.a.begin(1))
        self.assertEqual(self.a.word, 0x000B0001)

    def test_duplicate_foreign_original_and_work_do_not_change_credits(self):
        self.a.begin(1)
        self.assertTrue(self.a.hold(1, "ack"))
        self.assertFalse(self.a.hold(1, "ack"))
        ref = self.a.acquire_work(1, "request")
        before = self.a.word
        foreign = self.module.WorkRef(2, ref.generation)
        self.assertFalse(self.a.publish(foreign, b"foreign"))
        self.assertFalse(self.a.terminal_work(foreign))
        self.assertEqual(self.a.terminal_original(2, "ack"), "reject")
        self.assertEqual(self.a.word, before)

    def test_timing_cookie_exhaustion_refuses_wrap(self):
        self.a.word = 65535
        self.assertIsNone(self.a.begin(1))
        self.assertEqual(self.a.word, 65535)

    def test_work_generation_exhaustion_refuses_wrap(self):
        self.a.begin(1)
        self.a.next_work = 0xFFFFFFFF
        self.assertIsNone(self.a.acquire_work(1, "request"))
        self.assertEqual(self.a.word, 0x00010001)

    def test_verified_connection_retirement_preserves_old_ref_rejection(self):
        self.a.begin(1)
        ref = self.a.acquire_work(1, "request")
        self.assertFalse(self.a.retire_connection(1))
        self.a.reset(1)
        self.a.terminal_work(ref)
        self.a.finish()
        self.assertTrue(self.a.retire_connection(1))
        self.assertEqual(self.a.epoch, 2)
        self.assertEqual(self.a.begin(2), 2)
        self.assertFalse(self.a.publish(ref, b"old"))

    def test_modular_deadline_full_32_bit_wrap(self):
        due = self.module.due
        self.assertFalse(due(0xFFFFFF00, 0x00000300))
        self.assertFalse(due(0x00000200, 0x00000300))
        self.assertTrue(due(0x00000300, 0x00000300))
        self.assertTrue(due(0x00000400, 0x00000300))

    def test_operate_deadline_does_not_depend_on_blockers(self):
        schedule = self.module.Schedule(0xFFFF0000, 5_000_000)
        self.assertFalse(schedule.operate_due((0xFFFF0000 + 4_999_680) & 0xFFFFFFFF))
        self.assertTrue(schedule.operate_due((0xFFFF0000 + 4_999_936) & 0xFFFFFFFF))
        self.assertFalse(schedule.ack_due((0xFFFF0000 + 5_000_000) & 0xFFFFFFFF))
        self.assertTrue(schedule.fallback_due((0xFFFF0000 + 30_000_000) & 0xFFFFFFFF))

    def test_full_gap_is_reanchored_to_actual_commit_near_expiry(self):
        s = self.module.Schedule(0, 5_000_000)
        s.ack_seen = True
        s.response_seen = True
        s.commit_ack(29_999_872)
        self.assertEqual(s.response_deadline, 30_999_808)
        self.assertFalse(s.readiness_expired(30_000_000))
        self.assertFalse(s.response_due(30_999_552))
        self.assertTrue(s.response_due(30_999_808))


if __name__ == "__main__":
    unittest.main()
