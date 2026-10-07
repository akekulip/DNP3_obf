"""Absolute invariants of native_binding.p4 (no oracle): bounded passes, no private header on a
front-panel egress, WorkRecord released, no endless recirculation. Source-level harness only.

H1  power-on epoch register 0 must not produce an envelope the parser rejects (endless loop).
H2  a return pass whose guard misses (profile or flow entry removed mid-flight) is denied, never
    forwarded with the private envelope.
M2  a busy WorkRecord leaves the claimed packet unbound: it is forwarded transparently (pinned
    behaviour, documented in LEDGER.md; no design change).
"""
import unittest

import read_support as rs
import vectors
from read_support import ReadPipeline, assert_invariants

FRESH = dict(owner=0, client=0, server=0, epoch=0)


def syn():
    return vectors.frame(2, 100, 0, False, 1500)


def select_packet(seq=101, ack=901):
    return vectors.packet(24, seq, ack, payload=vectors.native_select())


def final_ack():
    return vectors.frame(16, 101, 901)


class EpochZero(unittest.TestCase):
    """H1: fresh registers, nothing preseeded by a control plane."""

    def run_fresh(self, port, frame, **preset):
        pipe = ReadPipeline().start(**{**FRESH, **preset})
        out = pipe.inject(port, frame)
        assert_invariants(self, pipe, out, frame)
        self.assertEqual(pipe.state()['work']['phase'], 4, 'WorkRecord back to free')
        return pipe, out

    def test_fresh_syn_is_forwarded_unchanged_and_installs_a_nonzero_epoch(self):
        frame = syn()
        pipe, out = self.run_fresh(1, frame)
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(out.emitted, [(2, frame)])
        self.assertNotEqual(pipe.state()['epoch'], 0)

    def test_fresh_ack_and_select_are_bounded_and_release_the_work_record(self):
        for port, frame in ((1, final_ack()), (1, select_packet()), (1, rs.request_packet()),
                            (2, rs.ack_packet()), (2, rs.response_packet())):
            pipe, out = self.run_fresh(port, frame)
            self.assertEqual(pipe.state()['owner'], 0, 'a stray packet never claims an owner')
            self.assertLessEqual(out.passes, 4)

    def test_snapshot_never_writes_epoch_zero(self):
        for port, frame in ((1, final_ack()), (1, select_packet())):
            pipe = ReadPipeline().start(**FRESH)
            out = pipe.inject(port, frame)
            for events in out.trace:
                self.assertNotIn('hdr.envelope.epoch=0', ' '.join(events))
            self.assertNotEqual(out.passes, 8)
            self.assertGreaterEqual(out.passes, 2, 'went through the private passes, did not stall at pass 1')


    def test_close_with_a_live_owner_but_epoch_zero_is_bounded(self):
        # first_close copied m.epoch into the work generation; with epoch 0 that is a generation the
        # parser rejects, so the close would have looped on the return port.
        for flags in (17, 20, 4):
            frame = vectors.frame(flags, 136, 958)
            pipe = ReadPipeline().start(0x90001, 136, 958, epoch=0)
            out = pipe.inject(1, frame)
            assert_invariants(self, pipe, out, frame)
            self.assertEqual(pipe.state()['work']['phase'], 4)


class GuardMiss(unittest.TestCase):
    """H2."""

    def test_removed_data_profile_entry_mid_flight_is_denied_and_work_released(self):
        frame = select_packet()
        pipe = ReadPipeline().start(0x40001, 101, 901)
        pipe.mutate[2] = lambda p: rs.drop_runtime(p, 'data_connection')
        before = pipe.state()
        out = pipe.inject(1, frame)
        assert_invariants(self, pipe, out, frame)
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])
        self.assertEqual(pipe.state()['owner'], before['owner'])
        self.assertEqual(pipe.state()['work']['phase'], 4, 'work released by the abort path')

    def test_removed_read_link_entry_mid_flight_is_denied_and_work_released(self):
        frame = rs.request_packet()
        pipe = ReadPipeline().start(0x50001, 1000, 2000)
        pipe.mutate[2] = lambda p: rs.drop_runtime(p, 'read_connection')
        before = pipe.state()
        out = pipe.inject(1, frame)
        assert_invariants(self, pipe, out, frame)
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])
        self.assertEqual(pipe.state()['owner'], before['owner'])
        self.assertEqual(pipe.state()['work']['phase'], 4)

    def test_removed_flow_entry_mid_flight_is_denied_and_never_forwards_the_envelope(self):
        for frame, port, owner, client, server in ((select_packet(), 1, 0x40001, 101, 901),
                                                   (rs.request_packet(), 1, 0x50001, 1000, 2000)):
            pipe = ReadPipeline().start(owner, client, server)
            pipe.mutate[2] = lambda p: rs.drop_runtime(p, 'connection')
            before = pipe.state()
            out = pipe.inject(port, frame)
            assert_invariants(self, pipe, out, frame)
            self.assertTrue(out.dropped)
            self.assertEqual(out.emitted, [])
            self.assertEqual(pipe.state()['owner'], before['owner'])
            # Quarantine path (documented): with no flow there is no guard, so the pin stays at the
            # phase the last honest pass left it. Only the controller register reset frees it.
            self.assertNotEqual(pipe.state()['work']['phase'], 4)

    def test_relabelled_private_event_is_aborted_not_forwarded_with_envelope(self):
        import struct
        raw = vectors.packet(24, 101, 901, payload=vectors.native_select())
        envelope = struct.pack('>IIIHH', 17, 1, 0x40001, 0x0107, 0)      # kind 7 claimed on a SELECT packet
        pipe = ReadPipeline().start(0x40001, 101, 901, work=(1, 1))
        out = pipe.inject(68, envelope + raw)
        assert_invariants(self, pipe, out, raw)
        self.assertTrue(out.dropped)
        self.assertEqual(pipe.state()['owner'], 0x40001)
        self.assertEqual(pipe.state()['work']['phase'], 4)


class BusyWorkRecord(unittest.TestCase):
    """M2: pinned current behaviour. A busy WorkRecord means the claimed packet is not bound to a
    private pass at all; it leaves transparently, in one pass, with no owner or bank change."""

    def test_busy_record_forwards_select_operate_read_and_ack_transparently(self):
        cases = ((1, select_packet(), 0x40001, 101, 901), (1, rs.request_packet(), 0x50001, 1000, 2000),
                 (2, rs.ack_packet(), 0xe0001, 1020, 2000), (2, rs.response_packet(), 0xe0001, 1020, 2000))
        for port, frame, owner, client, server in cases:
            pipe = ReadPipeline().start(owner, client, server, work=(7, 2))
            before = pipe.state()
            out = pipe.inject(port, frame)
            self.assertFalse(out.dropped, out.drop_reason)
            self.assertEqual(out.passes, 1)
            self.assertEqual(out.emitted, [(2 if port == 1 else 1, frame)])
            after = pipe.state()
            for key in ('owner', 'client', 'server', 'epoch', 'work'):
                self.assertEqual(after[key], before[key], key)


if __name__ == '__main__':
    unittest.main()
