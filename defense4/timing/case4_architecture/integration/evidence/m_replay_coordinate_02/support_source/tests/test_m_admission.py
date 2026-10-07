"""Execute actual M source: every refused handoff must leave every bank intact."""
import copy
import unittest

import support_m as s
from test_m_skeleton import establish


def banks(pipe):
    return copy.deepcopy(pipe.src.cells)


def altered(frame, **fields):
    packet = s.Ether(frame)
    for name, value in fields.items():
        setattr(packet[s.IP], name, value)
    del packet[s.IP].chksum
    del packet[s.TCP].chksum
    return bytes(packet)


class Admission(unittest.TestCase):
    def refuse_without_writes(self, pipe, kind, frame, **kwargs):
        before = banks(pipe)
        out = s.send(pipe, kind, frame, **kwargs)
        self.assertTrue(out.dropped, out.emitted)
        self.assertEqual(banks(pipe), before)

    def test_foreign_tuple_ttl_and_route_denial_leave_every_bank_unchanged(self):
        frame = s.tcp_frame(s.native(3), 1000, 5, 20, 0x18)
        for reason in ('tuple', 'ttl', 'route'):
            with self.subTest(reason=reason):
                pipe = s.m_pipeline()
                raw = frame
                if reason == 'tuple':
                    raw = altered(frame, src='10.0.0.99')
                elif reason == 'ttl':
                    raw = altered(frame, ttl=0)
                else:
                    pipe.src.controls['Ingress'].tables['forwarding']['runtime'].clear()
                    pipe.src.install('forwarding', (s.M_IN,), 'deny', ())
                self.refuse_without_writes(pipe, s.KIND_SELECT, raw, phase=9)

    def test_bad_ip_checksum_leaves_every_bank_unchanged(self):
        raw = bytearray(s.tcp_frame(s.native(3), 1000, 5, 20, 0x18))
        raw[24] ^= 1
        self.refuse_without_writes(s.m_pipeline(), s.KIND_SELECT, bytes(raw), phase=9)

    def test_wrong_phase_direction_shape_and_zero_authority_cannot_publish(self):
        for kwargs, frame in (
            ({'phase': 12}, s.tcp_frame(s.native(3), 1000, 5, 20, 0x18)),
            ({'phase': 9}, s.tcp_frame(s.native(3), 1000, 5, 20, 0x18, reverse=True)),
            ({'phase': 9}, s.tcp_frame(b'', 1000, 5, 20, 0x10)),
            ({'phase': 9, 'epoch': 0}, s.tcp_frame(s.native(3), 1000, 5, 20, 0x18)),
            ({'phase': 9, 'generation': 0}, s.tcp_frame(s.native(3), 1000, 5, 20, 0x18)),
        ):
            with self.subTest(kwargs=kwargs, length=len(frame)):
                self.refuse_without_writes(s.m_pipeline(), s.KIND_SELECT, frame, **kwargs)

    def test_noncontiguous_foreign_epoch_and_stale_operate_cannot_publish(self):
        for seq, epoch, generation in ((1036, 17, 2), (1035, 18, 2), (1035, 17, 2)):
            with self.subTest(seq=seq, epoch=epoch, generation=generation):
                pipe, _, _ = establish(1000)
                self.refuse_without_writes(pipe, s.KIND_OPERATE,
                    s.tcp_frame(s.native(4), seq, 5, 20, 0x18),
                    epoch=epoch, generation=generation, phase=12)

    def test_operate_without_select_leaves_every_bank_unchanged(self):
        self.refuse_without_writes(s.m_pipeline(), s.KIND_OPERATE,
            s.tcp_frame(s.native(4), 1035, 5, 20, 0x18), generation=2, phase=12)

    def test_stale_select_cannot_overwrite_geometry_or_byte(self):
        pipe, _, _ = establish(1000)
        self.refuse_without_writes(pipe, s.KIND_SELECT,
            s.tcp_frame(s.native(3), 5000, 5, 20, 0x18), generation=1, phase=9)

    def test_old_epoch_select_lower_or_equal_global_generation_cannot_mutate(self):
        for generation in (5, 10):
            with self.subTest(generation=generation):
                pipe = s.m_pipeline()
                frame = s.tcp_frame(s.native(3), 1000, 5, 20, 0x18)
                self.assertFalse(s.send(pipe, s.KIND_SELECT, frame, epoch=17,
                    generation=5, phase=9).dropped)
                self.assertFalse(s.send(pipe, s.KIND_SELECT, frame, epoch=18,
                    generation=10, phase=9).dropped)
                self.refuse_without_writes(pipe, s.KIND_SELECT, frame,
                    epoch=17, generation=generation, phase=9)

    def test_operate_work_generation_must_follow_selected_generation(self):
        pipe = s.m_pipeline()
        self.assertFalse(s.send(pipe, s.KIND_SELECT,
            s.tcp_frame(s.native(3), 1000, 5, 20, 0x18), generation=5, phase=9).dropped)
        for generation in (4, 5):
            with self.subTest(generation=generation):
                self.refuse_without_writes(pipe, s.KIND_OPERATE,
                    s.tcp_frame(s.native(4), 1035, 5, 20, 0x18), generation=generation, phase=12)

    def test_unknown_kind_cannot_mutate(self):
        for kind in (0, 3, 16, 255):
            with self.subTest(kind=kind):
                self.refuse_without_writes(s.m_pipeline(), kind,
                    s.tcp_frame(s.native(3), 1000, 5, 20, 0x18), phase=9)

    def test_wrong_operate_phase_or_function_cannot_mutate(self):
        for phase, function in ((9, 4), (0, 4), (12, 3)):
            with self.subTest(phase=phase, function=function):
                pipe, _, _ = establish(1000)
                self.refuse_without_writes(pipe, s.KIND_OPERATE,
                    s.tcp_frame(s.native(function), 1035, 5, 20, 0x18),
                    generation=3, phase=phase)


class LedgerCoordinates(unittest.TestCase):
    def test_same_byte_at_wrong_tail_sequence_is_refused_without_any_bank_write(self):
        for base in (1000, 0, 0xffffffc9, 0xfffffff0):
            pipe, _, _ = establish(base)
            for phase, function, native_offset in ((9, 3, 34), (12, 4, 69)):
                tail = (base + native_offset) & s.MASK
                for sequence in ((tail - 1) & s.MASK, (tail + 1) & s.MASK,
                                 (tail + 0x10000) & s.MASK, tail ^ 0x80000000, 999999):
                    with self.subTest(base=base, phase=phase, sequence=sequence):
                        before = banks(pipe)
                        out = s.send(pipe, s.KIND_REPLAY,
                            s.tcp_frame(s.native(function)[-1:], sequence, 7, 20, 0x10),
                            generation=9, phase=phase)
                        self.assertTrue(out.dropped, out.emitted)
                        self.assertEqual(banks(pipe), before)

    def test_actual_tail_sequence_retains_full_candidate_wire_start_across_wrap(self):
        for base in (1000, 0, 0xffffffc9, 0xfffffff0, 0xffffffff):
            pipe, _, _ = establish(base)
            for phase, function, native_offset, wire_offset in ((9, 3, 34, 0), (12, 4, 69, 55)):
                with self.subTest(base=base, phase=phase):
                    before = banks(pipe)
                    out = s.send(pipe, s.KIND_REPLAY,
                        s.tcp_frame(s.native(function)[-1:], (base + native_offset) & s.MASK,
                                    7, 20, 0x10), generation=9, phase=phase)
                    self.assertFalse(out.dropped, out.drop_reason)
                    self.assertEqual(pipe.src.env.get('m.replay_wire_start'), (base + wire_offset) & s.MASK)
                    self.assertEqual(banks(pipe), before)

    def test_operate_position_is_shifted_wire_coordinate_including_wrap(self):
        for base in (1000, 0, 0xffffffc9, 0xffffffff):
            with self.subTest(base=base):
                pipe, _, operate = establish(base)
                self.assertFalse(operate.dropped, operate.drop_reason)
                self.assertEqual(pipe.reg('led_pos', 1)['lo'], (base + 55) & s.MASK)

    def test_select_and_operate_zero_wire_start_are_valid_replay_positions(self):
        for base, phase, function in ((0, 9, 3), (0xffffffc9, 12, 4)):
            with self.subTest(base=base, phase=phase):
                pipe, _, _ = establish(base)
                slot = 0 if phase == 9 else 1
                self.assertEqual(pipe.reg('led_pos', slot)['lo'], 0)
                out = s.send(pipe, s.KIND_REPLAY,
                    s.tcp_frame(s.native(function)[-1:], (base + (34 if slot == 0 else 69)) & s.MASK,
                                7, 20, 0x10), generation=9, phase=phase)
                self.assertFalse(out.dropped, out.drop_reason)


if __name__ == '__main__':
    unittest.main()
