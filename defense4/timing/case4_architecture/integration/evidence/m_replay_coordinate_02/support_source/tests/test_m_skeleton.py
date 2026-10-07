"""Source-level execution of the S3-3 M canary against the independent transport oracle.

Executed by the whole-program source interpreter (integration/core/harness). Not the compiler, not
the model, not the ASIC. NOT executed by the interpreter, hence NOT checked here: the TCP checksum
rewrite (the interpreter does not run the deparser checksum and models subtract/get additively), the
bypass/egress semantics, table sizes, one-register-per-table and stage fit. Those are compiler
evidence or later tickets. Historical m_canary_10 compiled the previous source;
the current admission repair must qualify independently and may fail placement.
Expected values come from framework/size/case4_transport.RequestLedger over case4_padding images,
not from a second transcription of the P4.
"""
import unittest

import support_m as s
from support_m import (KIND_FWD, KIND_OPERATE, KIND_RESPONSE, KIND_REPLAY, KIND_REV, KIND_SELECT,
                       MASK, decoded, native, oracle, send, tcp_frame)

BASES = (1000, 0, 0xffffffd0, 0xffffffeb, 0xffffffe0, 0xffffffff)   # last four put a boundary on the 32-bit wrap
FWD_OFFSETS = (-5, 0, 34, 35, 36, 69, 70, 71, 72, 100, 100000, 0x7fffff00)
REV_OFFSETS = (-3, 0, 34, 35, 36, 54, 55, 56, 89, 90, 91, 109, 110, 111, 5000)
WINDOWS = (0, 1, 20, 65535)


def establish(base, epoch=17):
    """SELECT then OPERATE produce through M (the only writers of the geometry)."""
    pipe = s.m_pipeline()
    select = send(pipe, KIND_SELECT, tcp_frame(native(3), base, 5, 20, 0x18), epoch=epoch, generation=1, phase=9)
    operate = send(pipe, KIND_OPERATE, tcp_frame(native(4), (base + 35) & MASK, 5, 20, 0x18),
                   epoch=epoch, generation=2, phase=12)
    return pipe, select, operate


class Produce(unittest.TestCase):
    def test_select_keeps_sequence_and_envelope_and_arms_geometry(self):
        pipe, select, _ = establish(1000)
        self.assertEqual(decoded(select)[0], 1000)
        self.assertEqual(select.emitted[0][1][:16], s.envelope(17, 1, KIND_SELECT, 9))
        self.assertEqual(pipe.reg('geo_first'), 1000)

    def test_operate_gets_the_constant_plus_20_the_second_image_start(self):
        for base in BASES:
            with self.subTest(base=hex(base)):
                _, _, operate = establish(base)
                _, first, second = oracle(base)
                self.assertEqual(decoded(operate)[0], second.seq)
                self.assertEqual(second.seq, (base + 35 + 20) & MASK)
                self.assertEqual(first.seq, base)

    def test_operate_not_contiguous_with_select_is_refused(self):
        pipe = s.m_pipeline()
        send(pipe, KIND_SELECT, tcp_frame(native(3), 1000, 5, 20, 0x18), generation=1, phase=9)
        out = send(pipe, KIND_OPERATE, tcp_frame(native(4), 1000 + 36, 5, 20, 0x18), generation=2, phase=12)
        self.assertTrue(out.dropped)

    def test_operate_without_select_in_this_epoch_is_refused(self):
        pipe = s.m_pipeline()
        out = send(pipe, KIND_OPERATE, tcp_frame(native(4), 1035, 5, 20, 0x18), generation=2, phase=12)
        self.assertTrue(out.dropped)

    def test_stale_generation_in_the_same_epoch_is_refused_and_leaves_the_ledger(self):
        pipe, _, _ = establish(1000)
        before = dict(pipe.reg('led_id', 0))
        out = send(pipe, KIND_SELECT, tcp_frame(native(3), 5000, 5, 20, 0x18), generation=1, phase=9)
        self.assertTrue(out.dropped)
        self.assertEqual(pipe.reg('led_id', 0), before)

    def test_wrong_phase_for_the_kind_is_refused(self):
        pipe = s.m_pipeline()
        self.assertTrue(send(pipe, KIND_SELECT, tcp_frame(native(3), 1000, 5, 20, 0x18), phase=12).dropped)


class ForwardMapping(unittest.TestCase):
    def test_pure_ack_sequence_matches_the_oracle_across_both_boundaries_and_wrap(self):
        for base in BASES:
            pipe, _, _ = establish(base)
            ledger, _, _ = oracle(base)
            for off in FWD_OFFSETS:
                with self.subTest(base=hex(base), offset=off):
                    seq = (base + off) & MASK
                    out = send(pipe, KIND_FWD, tcp_frame(b'', seq, 7, 20, 0x10), generation=3)
                    self.assertEqual(decoded(out)[0], ledger.forward(seq, b'').seq)

    def test_ack_and_window_are_untouched_in_the_forward_direction(self):
        pipe, _, _ = establish(1000)
        out = send(pipe, KIND_FWD, tcp_frame(b'', 1100, 7777, 4321, 0x10), generation=3)
        self.assertEqual(decoded(out)[1:], (7777, 4321))

    def test_epoch_without_geometry_is_the_identity(self):
        pipe, _, _ = establish(1000, epoch=17)
        out = send(pipe, KIND_FWD, tcp_frame(b'', 1100, 7, 20, 0x10), epoch=18, generation=3)
        self.assertEqual(decoded(out)[0], 1100)

    def test_select_only_geometry_shifts_by_one_boundary(self):
        pipe = s.m_pipeline()
        send(pipe, KIND_SELECT, tcp_frame(native(3), 1000, 5, 20, 0x18), generation=1, phase=9)
        ledger = s.case4_transport.RequestLedger(1000)
        ledger.forward(1000, native(3), s.image(3))
        for off in (0, 34, 35, 36, 500):
            out = send(pipe, KIND_FWD, tcp_frame(b'', 1000 + off, 7, 20, 0x10), generation=3)
            self.assertEqual(decoded(out)[0], ledger.forward(1000 + off, b'').seq, off)

    def test_wrong_direction_for_the_kind_is_refused(self):
        pipe, _, _ = establish(1000)
        self.assertTrue(send(pipe, KIND_FWD, tcp_frame(b'', 1100, 7, 20, 0x10, reverse=True), generation=3).dropped)
        self.assertTrue(send(pipe, KIND_REV, tcp_frame(b'', 77, 1100, 20, 0x10), generation=3).dropped)


class ReverseMapping(unittest.TestCase):
    def test_ack_and_window_clamp_match_the_oracle_on_both_window_edges_and_wrap(self):
        for base in BASES:
            pipe, _, _ = establish(base)
            ledger, _, _ = oracle(base)
            for off in REV_OFFSETS:
                for window in WINDOWS:
                    with self.subTest(base=hex(base), offset=off, window=window):
                        ack = (base + off) & MASK
                        out = send(pipe, KIND_REV, tcp_frame(b'', 77, ack, window, 0x10, reverse=True), generation=3)
                        _, got_ack, got_window = decoded(out)
                        self.assertEqual((got_ack, got_window), ledger.reverse(ack, window))

    def test_response_kind_6_maps_like_kind_13(self):
        pipe, _, _ = establish(1000)
        ledger, _, _ = oracle(1000)
        out = send(pipe, KIND_RESPONSE, tcp_frame(b'', 77, 1000 + 120, 20, 0x10, reverse=True), generation=3)
        self.assertEqual(decoded(out)[1:], ledger.reverse(1000 + 120, 20))

    def test_sequence_of_the_server_segment_is_untouched(self):
        pipe, _, _ = establish(1000)
        out = send(pipe, KIND_REV, tcp_frame(b'', 4242, 1100, 20, 0x10, reverse=True), generation=3)
        self.assertEqual(decoded(out)[0], 4242)


class ReplayCompare(unittest.TestCase):
    def replay(self, pipe, byte, phase, epoch=17):
        # OPERATE's native tail follows the 35-byte SELECT in the sender stream.
        tail_sequence = 1000 + (69 if phase == 12 else 34)
        return send(pipe, KIND_REPLAY, tcp_frame(bytes([byte]), tail_sequence, 7, 20, 0x10), epoch=epoch,
                    generation=9, phase=phase)

    def test_matching_last_native_byte_is_forwarded_for_each_slot(self):
        pipe, _, _ = establish(1000)
        for phase, fc in ((9, 3), (12, 4)):
            out = self.replay(pipe, native(fc)[-1], phase)
            self.assertFalse(out.dropped, out.drop_reason)

    def test_mismatching_byte_wrong_epoch_or_wrong_phase_is_refused(self):
        pipe, _, _ = establish(1000)
        good = native(3)[-1]
        self.assertTrue(self.replay(pipe, good ^ 1, 9).dropped)
        self.assertTrue(self.replay(pipe, good, 9, epoch=18).dropped)
        self.assertTrue(self.replay(pipe, good, 5).dropped)

    def test_replay_does_not_mutate_the_ledger(self):
        pipe, _, _ = establish(1000)
        before = (dict(pipe.reg('led_id', 0)), dict(pipe.reg('led_pos', 0)), pipe.reg('geo_first'))
        self.replay(pipe, native(3)[-1], 9)
        self.assertEqual((dict(pipe.reg('led_id', 0)), dict(pipe.reg('led_pos', 0)), pipe.reg('geo_first')), before)


class Gating(unittest.TestCase):
    def test_unknown_kind_and_zero_generation_are_refused_without_state_change(self):
        pipe, _, _ = establish(1000)
        before = (pipe.reg('geo_first'), dict(pipe.reg('geo_tag')))
        self.assertTrue(send(pipe, 3, tcp_frame(b'', 1100, 7, 20, 0x10), generation=3).dropped)
        self.assertTrue(send(pipe, KIND_SELECT, tcp_frame(native(3), 9999, 5, 20, 0x18), generation=0, phase=9).dropped)
        self.assertEqual((pipe.reg('geo_first'), dict(pipe.reg('geo_tag'))), before)

    def test_bad_ip_checksum_is_refused_and_does_not_arm_geometry(self):
        pipe = s.m_pipeline()
        frame = bytearray(tcp_frame(native(3), 1000, 5, 20, 0x18))
        frame[24] ^= 1
        out = send(pipe, KIND_SELECT, bytes(frame), generation=1, phase=9)
        self.assertTrue(out.dropped)
        self.assertEqual(pipe.reg('geo_tag'), {'lo': 0, 'hi': 0})


if __name__ == '__main__':
    unittest.main()
