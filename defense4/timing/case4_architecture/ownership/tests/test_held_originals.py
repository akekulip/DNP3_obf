import unittest
import importlib.util
from pathlib import Path
import sys
import json

spec = importlib.util.spec_from_file_location("held_reference", Path(__file__).resolve().parents[1] / "reference.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class HeldCreditTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(module, "HeldCredits"), "held credit model is missing")
        global HeldCredits, PinnedWork
        HeldCredits, PinnedWork = module.HeldCredits, module.PinnedWork

    def test_literal_credit_words_and_terminal_after_policy_off(self):
        credits = HeldCredits(0x12345678, 0x4321)
        self.assertEqual(credits.word, 0x43210000)
        self.assertTrue(credits.admit(0x12345678, 0x43210000, 1))
        self.assertEqual(credits.word, 0x43210101)
        self.assertTrue(credits.admit(0x12345678, 0x43210101, 2))
        self.assertEqual(credits.word, 0x43210303)
        self.assertIsNone(credits.terminal(0x12345678, 0x43210101, 1, False))
        self.assertEqual(credits.terminal(0x12345678, 0x43210303, 1, False), "forward")
        self.assertEqual(credits.word, 0x43210302)
        self.assertEqual(credits.terminal(0x12345678, 0x43210302, 2, False), "forward")
        self.assertEqual(credits.word, 0x43210300)

    def test_duplicate_kind_never_reuses_within_cookie(self):
        credits = HeldCredits(1, 1)
        self.assertTrue(credits.admit(1, 0x10000, 1))
        self.assertEqual(credits.terminal(1, 0x10101, 1, False), "forward")
        self.assertFalse(credits.admit(1, 0x10100, 1))
        self.assertIsNone(credits.terminal(1, 0x10100, 1, False))
        self.assertEqual(credits.word, 0x10100)

    def test_operate_aborts_and_policy_on_holds(self):
        credits = HeldCredits(1, 2)
        self.assertTrue(credits.admit(1, 0x20000, 3))
        self.assertIsNone(credits.terminal(1, 0x20404, 3, True))
        self.assertEqual(credits.word, 0x20404)
        self.assertEqual(credits.terminal(1, 0x20404, 3, False), "abort")
        self.assertEqual(credits.word, 0x20400)

    def test_full_epoch_and_cookie_reject_stale_terminal(self):
        credits = HeldCredits(0x87654321, 0xABCD)
        self.assertTrue(credits.admit(0x87654321, 0xABCD0000, 2))
        self.assertIsNone(credits.terminal(0x7654321, 0xABCD0202, 2, False))
        self.assertIsNone(credits.terminal(0x87654321, 0x0BCD0202, 2, False))
        self.assertEqual(credits.word, 0xABCD0202)

    def test_lost_original_and_producer_both_block_reuse(self):
        work = PinnedWork(1)
        ref = work.claim(1)
        credits = HeldCredits(1, 1)
        self.assertTrue(credits.admit(1, 0x10000, 1))
        self.assertFalse(credits.can_reuse(work))
        self.assertEqual(credits.terminal(1, 0x10101, 1, False), "forward")
        self.assertFalse(credits.can_reuse(work))
        self.assertEqual([work.advance(ref) for _ in range(3)], [1, 2, 3])
        self.assertTrue(credits.can_reuse(work))


class ActualHolderFixtureTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(module, "HeldPacketLoop"), "held packet loop model is missing")
        self.loop = module.HeldPacketLoop(0x12345678, 0x4321)
        self.packet = bytes.fromhex("00112233445566778899aabb0800") + bytes(range(64))

    def make_held(self, kind):
        token = self.loop.begin(self.packet, kind)
        self.assertEqual(token.stage, 1)
        for expected in (2, 3, 4):
            token = self.loop.return_packet(token)
            self.assertEqual(token.stage, expected)
            self.assertEqual(token.packet, self.packet)
        return token

    def test_original_is_preserved_through_actual_three_work_returns(self):
        token = self.make_held(1)
        self.assertEqual(self.loop.receipts, [0x43210101, 0x43210000, 0x43210000])
        self.assertFalse(self.loop.can_reuse())
        self.loop.enabled = False
        outcome, actual_bytes = self.loop.return_packet(token)
        self.assertEqual((outcome, actual_bytes), ("forward", self.packet))
        self.assertEqual(self.loop.receipts, [0x43210100, 0x43210000, 0x43210000])
        self.assertTrue(self.loop.can_reuse())
        duplicate = self.loop.return_packet(token)
        self.assertEqual(duplicate.stage, 5)
        duplicate = self.loop.return_packet(duplicate)
        self.assertEqual(duplicate.stage, 4)
        self.assertEqual(duplicate.expected, 0x43210100)
        self.assertEqual(self.loop.return_packet(duplicate), ("suppress", None))

    def test_three_originals_debit_after_holding_flag_is_disabled(self):
        tokens = [self.make_held(kind) for kind in (1, 2, 3)]
        self.assertEqual(self.loop.receipts, [0x43210101] * 3)
        self.loop.enabled = False
        self.assertEqual([self.loop.return_packet(token)[0] for token in tokens], ["forward", "forward", "abort"])
        self.assertEqual(self.loop.receipts, [0x43210100] * 3)
        self.assertTrue(self.loop.can_reuse())

    def test_lost_original_and_lost_producer_are_independent_barriers(self):
        token = self.loop.begin(self.packet, 1)
        self.assertFalse(self.loop.can_reuse())
        token = self.loop.return_packet(token)
        self.assertEqual(self.loop.receipts[0], 0x43210101)
        self.assertFalse(self.loop.can_reuse())
        token = self.loop.return_packet(token)
        token = self.loop.return_packet(token)
        self.assertTrue(self.loop.work.can_retire())
        self.assertFalse(self.loop.can_reuse())

    def test_canonical_cookie_and_literal_twenty_byte_envelope(self):
        token = module.HeldPacket(0x12345678, 0x89ABCDEF, 0x1234, 0x12340101, 2, 4, self.packet)
        expected = bytes.fromhex("1234567889abcdef000012341234010102040000")
        self.assertEqual(token.to_bytes(), expected + self.packet)
        self.assertEqual(module.HeldPacket.from_bytes(token.to_bytes()), token)

    def test_close_before_admission_conserves_original_after_real_terminal(self):
        token = self.loop.begin(self.packet, 1)
        self.loop.work.close(0x12345678)
        self.assertFalse(self.loop.can_reuse())
        self.assertEqual(self.loop.return_packet(token), ("forward", self.packet))
        self.assertTrue(self.loop.can_reuse())

    def test_literal_valid_ack_bytes_and_complete_holder_prefixes(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / "fixtures/held_ack_off.json").read_text())
        packet = bytes.fromhex(fixture["native_packet_hex"])
        self.assertEqual(len(packet), 64)
        ip, tcp = packet[14:34], packet[34:54]
        def folded_sum(data):
            total = sum(int.from_bytes(data[index:index + 2], "big") for index in range(0, len(data), 2))
            while total >> 16:
                total = (total & 0xFFFF) + (total >> 16)
            return total
        self.assertEqual(folded_sum(ip), 0xFFFF)
        self.assertEqual(folded_sum(ip[12:20] + bytes.fromhex("00060014") + tcp), 0xFFFF)
        loop = module.HeldPacketLoop(1, 1)
        token = loop.begin(packet, 1)
        self.assertEqual(token.to_bytes(), bytes.fromhex(fixture["source_prefix_hex"]) + packet)
        token = loop.return_packet(token)
        self.assertEqual(token.to_bytes(), bytes.fromhex(fixture["after_claim_prefix_hex"]) + packet)
        token = loop.return_packet(token)
        token = loop.return_packet(token)
        self.assertEqual(token.to_bytes(), bytes.fromhex(fixture["held_prefix_hex"]) + packet)
        loop.enabled = False
        self.assertEqual(loop.return_packet(token), ("forward", packet))
        self.assertEqual(loop.receipts[0], fixture["terminal_receipt_word"])


if __name__ == "__main__":
    unittest.main()
