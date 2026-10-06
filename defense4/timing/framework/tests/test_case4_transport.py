"""Bounded cached replacement-image oracle. Software, no TCP endpoint evidence."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'size'))
import case4_padding as pad
try:
    import case4_transport as tr
except ImportError:
    tr = None


class Transport(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(tr, 'actual replacement-image transport ledger is missing')
        self.native = pad.build_frame(bytes.fromhex('056400c40a000100'), bytes.fromhex('c0c0030c0128010001000101640000006400000000'))
        self.image = pad.expand_control(self.native, pad.Decoy(201, bytes.fromhex('0101640000006400000000')))[0]
        self.ledger = tr.RequestLedger(1000)

    def test_two_requests_ack_and_capacity_freeze_translation(self):
        a = self.ledger.forward(1000, self.native, replacement=self.image)
        b = self.ledger.forward(1035, self.native, replacement=self.image)
        c = self.ledger.forward(1070, self.native, replacement=self.image)
        self.assertEqual((a.seq, a.payload, a.inserted), (1000, self.image, True))
        self.assertEqual((b.seq, b.payload, b.inserted), (1055, self.image, True))
        self.assertEqual((c.seq, c.payload, c.inserted), (1110, self.native, False))
        self.assertEqual(self.ledger.reverse(1110, 50), (1070, 50))
        self.assertEqual(len(self.ledger.entries), 2)

    def test_resegmented_overlapping_and_reordered_retransmissions_match_image(self):
        self.ledger.forward(1000, self.native, replacement=self.image)
        self.ledger.forward(1035, self.native, replacement=self.image)
        stream = self.native * 2
        reconstructed = {}
        for start, end in ((20, 45), (0, 20), (40, 70), (0, 35), (30, 70), (5, 15)):
            result = self.ledger.forward(1000 + start, stream[start:end])
            for i, byte in enumerate(result.payload):
                offset = result.seq - 1000 + i
                if offset in reconstructed:
                    self.assertEqual(reconstructed[offset], byte)
                reconstructed[offset] = byte
        self.assertEqual(bytes(reconstructed[i] for i in range(110)), self.image * 2)
        self.assertEqual(len(self.ledger.entries), 2)

    def test_every_partial_ack_and_window_maps_with_independent_piecewise_oracle(self):
        self.ledger.forward(1000, self.native, replacement=self.image)
        self.ledger.forward(1035, self.native, replacement=self.image)
        def inverse(offset):
            if offset < 35: return offset
            if offset < 55: return 34
            if offset < 90: return offset - 20
            if offset < 110: return 69
            return offset - 40
        for a in range(151):
            for w in (0, 1, 10, 40, 100):
                self.assertEqual(self.ledger.reverse(1000 + a, w),
                                 (1000 + inverse(a), inverse(a + w) - inverse(a)))

    def test_inserted_tail_ack_withholding_and_window_edges_at_both_boundaries_and_wrap(self):
        def inverse(offset):
            if offset < 35:return offset
            if offset < 55:return 34
            if offset < 90:return offset-20
            if offset < 110:return 69
            return offset-40
        for base in (1000,0xfffffff0):
            ledger=tr.RequestLedger(base)
            ledger.forward(base,self.native,replacement=self.image)
            ledger.forward((base+35)&tr.MASK,self.native,replacement=self.image)
            for start,complete,native_end in ((35,55,35),(90,110,70)):
                for offset in range(start,complete):
                    for window in (0,1,19,20,21,40,65535):
                        ack,win=ledger.reverse((base+offset)&tr.MASK,window)
                        self.assertEqual(ack,(base+native_end-1)&tr.MASK)
                        self.assertEqual(win,inverse(offset+window)-inverse(offset))
                        self.assertGreaterEqual(win,0)
                        self.assertLessEqual(win,window)
                self.assertEqual(ledger.reverse((base+complete)&tr.MASK,0),
                                 ((base+native_end)&tr.MASK,0))

    def test_last_native_byte_replays_each_truncated_inserted_tail_until_complete_ack(self):
        for base in (1000,0xfffffff0):
            ledger=tr.RequestLedger(base)
            ledger.forward(base,self.native,replacement=self.image)
            ledger.forward((base+35)&tr.MASK,self.native,replacement=self.image)
            for native_start,wire_start in ((0,0),(35,55)):
                for received in range(35,55):
                    # A downstream prefix ACK must leave an upstream native byte
                    # outstanding. This models retransmission of that byte; it
                    # does not assert a kernel timer or autonomously send traffic.
                    ack,window=ledger.reverse((base+wire_start+received)&tr.MASK,0)
                    self.assertEqual((ack,window),((base+native_start+34)&tr.MASK,0))
                    retry=ledger.forward(ack,self.native[-1:])
                    self.assertEqual(retry.seq,(base+wire_start+34)&tr.MASK)
                    self.assertEqual(retry.payload,self.image[34:])
                    self.assertFalse(retry.inserted)
                    self.assertEqual(self.image[:received]+retry.payload[received-34:],self.image)
                    self.assertEqual(ledger.reverse((base+wire_start+55)&tr.MASK,0),
                                     ((base+native_start+35)&tr.MASK,0))
                self.assertEqual(len(ledger.entries),2)

    def test_wrap_duplicate_loss_recovery_and_reset(self):
        ledger = tr.RequestLedger(0xfffffff0)
        first = ledger.forward(0xfffffff0, self.native, replacement=self.image)
        duplicate = ledger.forward(0xfffffff0, self.native, replacement=self.image)
        self.assertEqual((first.seq, first.payload), (duplicate.seq, duplicate.payload))
        self.assertFalse(duplicate.inserted)
        self.assertEqual(ledger.reverse(39, 0), (19, 0))
        self.assertEqual(ledger.forward(19, b'z').seq, 39)
        reset = ledger.reset(19, b'')
        self.assertEqual(reset.seq, 39)
        self.assertEqual(ledger.entries, [])
        self.assertEqual(ledger.forward(19, b'z').seq, 19)

    def test_unsupported_negotiation_prevents_insert_before_epoch(self):
        for feature in ('sack', 'window_scale', 'urgent', 'unknown'):
            ledger = tr.RequestLedger(1000, excluded_features={feature})
            out = ledger.forward(1000, self.native, replacement=self.image)
            self.assertEqual((out.seq, out.payload, out.inserted), (1000, self.native, False))

    def test_active_ledger_continues_translation_for_unsupported_new_request(self):
        self.ledger.forward(1000, self.native, replacement=self.image)
        self.ledger.exclude('sack')
        out = self.ledger.forward(1035, self.native, replacement=self.image)
        self.assertEqual((out.seq, out.payload, out.inserted), (1055, self.native, False))
        self.assertEqual(self.ledger.reverse(1090, 10), (1070, 10))

    def test_conflicting_overlap_refused_without_losing_translation(self):
        self.ledger.forward(1000, self.native, replacement=self.image)
        with self.assertRaises(ValueError):
            self.ledger.forward(1000, b'X' + self.native[1:])
        self.assertEqual(self.ledger.reverse(1055, 0), (1035, 0))
        with self.assertRaises(ValueError):
            self.ledger.forward(1000, self.native, replacement=b'Q' + self.image[1:])
        self.assertEqual(len(self.ledger.entries), 1)

    def test_out_of_order_new_insert_refused_still_translates_committed_template(self):
        self.ledger.forward(1035, self.native, replacement=self.image)
        old = self.ledger.forward(1000, self.native, replacement=self.image)
        self.assertFalse(old.inserted)
        self.assertEqual((old.seq, old.payload), (1000, self.native))
        self.assertEqual(self.ledger.forward(1035, self.native).payload, self.image)


class ControlConnection(unittest.TestCase):
    def test_only_one_matching_select_operate_pair_ever_grows(self):
        self.assertTrue(hasattr(tr, "ControlConnection"), "one-SBO connection profile is missing")
        d = pad.Decoy(201, bytes.fromhex('0101640000006400000000'))
        conn = tr.ControlConnection(1000, d)
        select = pad.build_frame(bytes.fromhex('056400c40a000100'), bytes.fromhex('c0c0030c0128010001000101640000006400000000'))
        head, user = pad.decode_frame(select)
        operate = pad.build_frame(head, bytes([0xc1, 0xc1, 4]) + user[3:])
        a = conn.forward(1000, select)
        b = conn.forward(1035, operate)
        c = conn.forward(1070, select)
        self.assertEqual((len(a.payload), len(b.payload), len(c.payload)), (55,55,35))
        self.assertEqual((a.seq,b.seq,c.seq), (1000,1055,1110))
        self.assertEqual(conn.forward(1000,select).payload,a.payload)
        self.assertEqual(conn.forward(1035,operate).payload,b.payload)

    def test_operate_first_and_mismatched_native_fields_never_insert(self):
        self.assertTrue(hasattr(tr, "ControlConnection"), "one-SBO connection profile is missing")
        d = pad.Decoy(201, bytes.fromhex('0101640000006400000000'))
        select = pad.build_frame(bytes.fromhex('056400c40a000100'), bytes.fromhex('c0c0030c0128010001000101640000006400000000'))
        head,user = pad.decode_frame(select)
        operate = pad.build_frame(head, bytes([0xc1,0xc1,4])+user[3:])
        conn = tr.ControlConnection(1000,d)
        self.assertFalse(conn.forward(1000,operate).inserted)
        self.assertTrue(conn.forward(1035,select).inserted)
        changed = bytearray(pad.decode_frame(operate)[1]); changed[12] ^= 1
        wrong = pad.build_frame(head, bytes(changed))
        out = conn.forward(1070,wrong)
        self.assertEqual((out.seq,out.payload,out.inserted),(1090,wrong,False))


if __name__ == '__main__': unittest.main()
