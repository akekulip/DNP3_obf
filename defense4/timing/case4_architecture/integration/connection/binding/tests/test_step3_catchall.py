"""S3-2: busy WorkRecord, explicit counted outcomes, and the one-byte tail replay (kind 12) in N.

PI decisions applied here: (2) with the WorkRecord busy, data packets (SELECT, OPERATE, response, READ
request and response) are DROPPED and COUNTED; pure ACKs are still tracked/forwarded (counted); (3)
whole-segment loss recovery remains open, so a resent whole segment is an explicit COUNTED drop.
The free-record preset below is a diagnostic fixture, not a verified controller rearm procedure.
Lost producers retain quarantine until actual termination or a separately verified drain.

NOT done in N (needs M, step 3 later tickets): translation of the replayed frame; the supported-tuple
catch-all for IP lengths the parser does not classify (no checksum can be validated on unparsed bytes,
so it needs the M mapping-only path). Foreign-epoch bank writes are repaired by Task1.
"""
import re
import struct
import unittest

import read_support as rs
import test_step3_exchange as ex
import vectors
from read_support import ReadPipeline, assert_invariants

COUNTER = {'busy_drop': ('count_busy', 0), 'busy_ack_passed': ('count_busy', 1), 'data_refused': ('count_first', 0),
           'segment_resent': ('count_first', 1), 'replay_refused': ('count_first', 2), 'replay_bound': ('count_term', 0)}


class Counters:
    def __init__(self, pipe):
        self.pipe = pipe

    def __getitem__(self, key):
        name, index = COUNTER[key] if isinstance(key, str) else key
        return self.pipe.src.cells[('', name)][index]

    def all(self):
        return [v for n in ('count_first', 'count_busy', 'count_term') for v in self.pipe.src.cells[('', n)]]


def counters(pipe):
    return Counters(pipe)


def m_port():
    return int(re.search(r'const\s+PortId_t\s+STEP3_M_PORT\s*=\s*9w(\d+)', rs.SOURCE.read_text())[1])


class Busy(unittest.TestCase):
    def test_busy_record_drops_and_counts_every_data_packet(self):
        cases = ((rs.IN_CLIENT, ex.select_packet(), 0x40001, 101, 901),
                 (rs.IN_CLIENT, ex.operate_packet(), 0xa0001, 136, 958),
                 (rs.IN_SERVER, ex.response1(), 0x90001, 136, 901),
                 (rs.IN_CLIENT, rs.request_packet(), 0x50001, 1000, 2000),
                 (rs.IN_SERVER, rs.response_packet(), 0xe0001, 1020, 2000))
        for port, frame, owner, client, server in cases:
            with self.subTest(len(frame)):
                pipe = ReadPipeline().start(owner, client, server, work=(7, 2))
                before = pipe.state()
                out = pipe.inject(port, frame)
                self.assertTrue(out.dropped)
                self.assertEqual(out.emitted, [])
                self.assertEqual(out.passes, 1)
                self.assertEqual(counters(pipe)[COUNTER['busy_drop']], 1)
                for key in ('owner', 'client', 'server', 'epoch', 'work'):
                    self.assertEqual(pipe.state()[key], before[key], key)
                # the generation is minted before the busy record is known, so a busy drop burns one
                self.assertEqual(pipe.state()['counter'], before['counter'] + 1)

    def test_busy_record_still_forwards_pure_acks_and_counts_them(self):
        for port, frame, owner in ((rs.IN_CLIENT, vectors.frame(16, 136, 958), 0x90001),
                                   (rs.IN_SERVER, rs.ack_packet(), 0xe0001)):
            pipe = ReadPipeline().start(owner, 136, 958, work=(7, 2))
            out = pipe.inject(port, frame)
            self.assertFalse(out.dropped, out.drop_reason)
            self.assertEqual(out.emitted, [(2 if port == rs.IN_CLIENT else 1, frame)])
            self.assertEqual(out.passes, 1)
            self.assertEqual(counters(pipe)[COUNTER['busy_ack_passed']], 1)
            self.assertEqual(counters(pipe)[COUNTER['busy_drop']], 0)

    def test_a_free_record_counts_nothing_for_a_good_exchange(self):
        pipe = ex.fresh()
        for port, frame in ((rs.IN_CLIENT, ex.select_packet()), (rs.IN_SERVER, ex.response1()),
                            (rs.IN_CLIENT, ex.operate_packet()), (rs.IN_SERVER, ex.response2())):
            self.assertFalse(pipe.inject(port, frame).dropped)
        self.assertEqual(set(counters(pipe).all()), {0})

    def test_diagnostic_free_record_fixture_restores_source_service(self):
        pipe = ReadPipeline().start(0x40001, 101, 901, work=(7, 2))
        self.assertTrue(pipe.inject(rs.IN_CLIENT, ex.select_packet()).dropped)
        pipe.preset(work=(0, 4))                    # fixture only; no producer-drain proof
        self.assertFalse(pipe.inject(rs.IN_CLIENT, ex.select_packet()).dropped)
        self.assertEqual(pipe.state()['owner'], 0x90001)
        self.assertEqual(counters(pipe)[COUNTER['busy_drop']], 1, 'counters survive the reset')


class ExplicitOutcomes(unittest.TestCase):
    def test_a_resent_whole_select_is_dropped_and_counted_not_silent(self):
        pipe = ex.fresh()
        self.assertFalse(pipe.inject(rs.IN_CLIENT, ex.select_packet()).dropped)
        before = pipe.state()
        out = pipe.inject(rs.IN_CLIENT, ex.select_packet())          # the sender resends all 35 bytes
        self.assertTrue(out.dropped)
        self.assertEqual(counters(pipe)[COUNTER['segment_resent']], 1)
        self.assertEqual(pipe.state()['owner'], before['owner'])
        self.assertEqual(pipe.state()['work']['phase'], 4)

    def test_a_resent_whole_operate_is_counted(self):
        pipe = ex.fresh()
        for port, frame in ((rs.IN_CLIENT, ex.select_packet()), (rs.IN_SERVER, ex.response1()), (rs.IN_CLIENT, ex.operate_packet())):
            self.assertFalse(pipe.inject(port, frame).dropped)
        self.assertTrue(pipe.inject(rs.IN_CLIENT, ex.operate_packet()).dropped)
        self.assertEqual(counters(pipe)[COUNTER['segment_resent']], 1)

    def test_other_unqualified_data_is_counted_as_refused(self):
        pipe = ReadPipeline().start(0x60001, 101, 901)                  # select with the owner closing: not a valid state
        self.assertTrue(pipe.inject(rs.IN_CLIENT, ex.select_packet()).dropped)
        self.assertEqual(counters(pipe)[COUNTER['data_refused']], 1)


def replay_packet(seq=135, ack=901, byte=None):
    last = vectors.native_select()[-1:] if byte is None else byte
    return vectors.packet(16, seq, ack, payload=last)


class Replay(unittest.TestCase):
    """Kind 12: the sender resends only the final native byte (the mapping withholds exactly that byte)."""

    def bound(self, owner, client=136, server=901):
        pipe = ReadPipeline().start(owner, client, server)
        frame = replay_packet(seq=client - 1, ack=server)
        out = pipe.inject(rs.IN_CLIENT, frame)
        return pipe, frame, out

    def test_replay_after_select_and_after_operate_is_bound_and_handed_to_m_unmutated(self):
        for owner, client in ((0x90001, 136), (0xc0001, 171)):
            pipe, frame, out = self.bound(owner, client, 901 if owner == 0x90001 else 958)
            self.assertFalse(out.dropped, out.drop_reason)
            self.assertEqual(out.passes, 4)
            self.assertEqual(len(out.emitted), 1)
            port, data = out.emitted[0]
            self.assertEqual(port, m_port())
            self.assertEqual(data[16:], frame, 'the original behind the private envelope, unchanged')
            self.assertEqual(struct.unpack('>H', data[12:14])[0] & 0xff, 12)
            state = pipe.state()
            self.assertEqual((state['owner'], state['client']), (owner, client), 'nonmutating')
            self.assertEqual(state['work']['phase'], 4)
            self.assertEqual(counters(pipe)[COUNTER['replay_bound']], 1)

    def test_replay_without_a_forwarded_native_segment_is_refused_and_counted(self):
        for owner in (0x50001, 0x40001, 0xa0001, 0x0):
            pipe, frame, out = self.bound(owner)
            self.assertTrue(out.dropped, hex(owner))
            self.assertEqual(out.emitted, [])
            self.assertEqual(counters(pipe)[COUNTER['replay_refused']], 1, hex(owner))
            self.assertEqual(pipe.state()['owner'], owner)
            self.assertEqual(pipe.state()['work']['phase'], 4)

    def test_replay_at_the_wrong_position_or_ack_is_refused_and_counted(self):
        for seq, ack in ((134, 901), (136, 901), (135, 900)):
            pipe = ReadPipeline().start(0x90001, 136, 901)
            out = pipe.inject(rs.IN_CLIENT, replay_packet(seq=seq, ack=ack))
            self.assertTrue(out.dropped, (seq, ack))
            self.assertEqual(pipe.state()['owner'], 0x90001)
            self.assertEqual(pipe.state()['work']['phase'], 4)
            self.assertEqual(counters(pipe)[COUNTER['replay_refused']], 1)

    def test_replay_is_never_forwarded_natively_and_never_mutates_banks(self):
        pipe, frame, out = self.bound(0x90001)
        self.assertNotIn(frame, [d for _, d in out.emitted])
        self.assertEqual(pipe.banks(), ReadPipeline().start(0x90001, 136, 901).banks())


class Interleave(unittest.TestCase):
    """Every packet class injected while a chain is pinned at every pass: nothing leaves native-forwarded
    except the pure ACKs the PI decision keeps, and every drop is counted."""

    CLASSES = (('select', rs.IN_CLIENT, ex.select_packet(), 0x40001, 101, 901, True),
               ('operate', rs.IN_CLIENT, ex.operate_packet(), 0xa0001, 136, 958, True),
               ('response1', rs.IN_SERVER, ex.response1(), 0x90001, 136, 901, True),
               ('response2', rs.IN_SERVER, ex.response2(), 0xc0001, 171, 958, True),
               ('read request', rs.IN_CLIENT, rs.request_packet(), 0x50001, 1000, 2000, True),
               ('read response', rs.IN_SERVER, rs.response_packet(), 0xe0001, 1020, 2000, True),
               ('replay', rs.IN_CLIENT, replay_packet(), 0x90001, 136, 901, True),
               ('client ack', rs.IN_CLIENT, vectors.frame(16, 136, 958), 0x90001, 136, 958, False),
               ('server ack', rs.IN_SERVER, rs.ack_packet(), 0xe0001, 1020, 2000, False))

    def test_matrix(self):
        total = 0
        for phase in (1, 2, 3):
            for label, port, frame, owner, client, server, data in self.CLASSES:
                with self.subTest(label=label, pinned_phase=phase):
                    pipe = ReadPipeline().start(owner, client, server, work=(5, phase))
                    before = pipe.state()
                    out = pipe.inject(port, frame)
                    if data:
                        self.assertTrue(out.dropped)
                        self.assertEqual(out.emitted, [])
                        self.assertEqual(counters(pipe)['busy_drop'], 1)
                    else:
                        self.assertEqual(out.emitted, [(2 if port == rs.IN_CLIENT else 1, frame)])
                        self.assertEqual(counters(pipe)['busy_ack_passed'], 1)
                    for key in ('owner', 'client', 'server', 'work'):
                        self.assertEqual(pipe.state()[key], before[key], key)
                    total += 1
        self.assertEqual(total, 27)


if __name__ == '__main__':
    unittest.main()
