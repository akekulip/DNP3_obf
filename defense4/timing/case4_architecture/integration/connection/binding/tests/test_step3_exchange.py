"""S3-1: the full SELECT, response, OPERATE, response exchange through N, whole-program source-level.

Independent oracle: connection/reference.py + framework codec (`SelectedPublisher`, `expand_control`,
`decode_frame`) decide what must be accepted and which byte positions the banks must hold. The
second response needs two facts the retained oracle does not model and that are written down here
from the mapping REPORT: after one insertion the server acknowledges native + 20, after two native + 40,
and the owner returns to idle (5) after the second response.
"""
import sys
import unittest
from pathlib import Path

import read_support as rs
import vectors
from read_support import ReadPipeline, assert_invariants

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / 'tests'))
import case4_padding as codec  # noqa: E402

SELECT_SEQ, SERVER_SEQ = 101, 901
OWNER = {'after_ack': 0x40001, 'select': 0x90001, 'response': 0xa0001, 'operate': 0xc0001, 'idle': 0x50001}


def select_packet(app=0):
    return vectors.packet(24, SELECT_SEQ, SERVER_SEQ, payload=vectors.native_select(app, 3))


def response1(app=0, ack=SELECT_SEQ + 35 + 20):
    return vectors.packet(24, SERVER_SEQ, ack, reverse=True, payload=vectors.native_response(app, 3))


def operate_packet(app=1, seq=SELECT_SEQ + 35, ack=SERVER_SEQ + 57):
    return vectors.packet(24, seq, ack, payload=vectors.native_select(app, 4))


def response2(app=1, ack=SELECT_SEQ + 70 + 40, seq=SERVER_SEQ + 57):
    return vectors.packet(24, seq, ack, reverse=True, payload=vectors.native_response(app, 4))


def fresh():
    return ReadPipeline().start(OWNER['after_ack'], SELECT_SEQ, SERVER_SEQ)


class Oracle(unittest.TestCase):
    """The retained independent oracle accepts exactly this exchange (so the vectors are real)."""

    def test_codec_oracle_accepts_select_response_and_operate(self):
        import test_connection as fixture
        import selected_reference as api
        helper = fixture.Connection(); helper.setUp(); helper.established()
        publisher = api.SelectedPublisher(helper.c, vectors.DECOY)
        work = publisher.begin_select(fixture.packet(24, 101, 901, payload=vectors.native_select()), 9)
        for _ in range(3):
            work = publisher.advance(work)
        self.assertEqual(work.outcome, 'forward')
        # The oracle sees the response after inverse mapping, so its ack is native_end (136), not 156.
        self.assertTrue(publisher.accept_select_response(
            fixture.packet(24, 901, 136, reverse=True, payload=vectors.native_response()), 12))
        self.assertTrue(publisher.admit_operate(fixture.packet(24, 136, 958, payload=vectors.native_select(1, 4)), 9))


class Exchange(unittest.TestCase):
    def step(self, pipe, port, frame, owner_after, passes=4, client=None, server=None):
        out = pipe.inject(port, frame)
        assert_invariants(self, pipe, out, frame)
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(out.passes, passes)
        if owner_after == OWNER['operate']:
            # An admitted OPERATE goes to T (2026-10-09 N->T OPERATE handoff), tev kind 12 + original, never natively.
            self.assertEqual([p for p, _ in out.emitted], [rs.handoff_port()])
            self.assertEqual(out.emitted[0][1][16:], frame, 'original unchanged behind the tev')
            self.assertEqual(out.emitted[0][1][12], 12, 'tev kind = T KIND_OPERATE')
        else:
            self.assertEqual(out.emitted, [(2 if port == rs.IN_CLIENT else 1, frame)], 'native frame forwarded unchanged')
        state = pipe.state()
        self.assertEqual(state['owner'], owner_after)
        self.assertEqual(state['work']['phase'], 4)
        if client is not None:
            self.assertEqual(state['client'], client)
        if server is not None:
            self.assertEqual(state['server'], server)
        return out

    def test_select_response_operate_response_ends_at_idle_with_oracle_positions(self):
        pipe = fresh()
        self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'], client=136)
        self.step(pipe, rs.IN_SERVER, response1(), OWNER['response'], server=958)
        self.step(pipe, rs.IN_CLIENT, operate_packet(), OWNER['operate'], client=171)
        out = self.step(pipe, rs.IN_SERVER, response2(), OWNER['idle'], client=171, server=1015)
        self.assertEqual(pipe.state()['counter'], 4, 'four bound packets, four minted generations')
        self.assertIn('table owner_command -> claim_response_op ', pipe.trace_text(out))

    def test_response_after_select_only_is_acked_at_offset_20_not_40(self):
        for ack, ok in ((SELECT_SEQ + 35 + 20, True), (SELECT_SEQ + 35 + 40, False), (SELECT_SEQ + 35, False)):
            pipe = fresh()
            self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
            out = pipe.inject(rs.IN_SERVER, response1(ack=ack))
            self.assertEqual(out.dropped, not ok, ack)
            self.assertEqual(pipe.state()['owner'], OWNER['response'] if ok else OWNER['select'])
            self.assertEqual(pipe.state()['work']['phase'], 4)

    def test_response_after_operate_is_acked_at_offset_40_not_20(self):
        for ack, ok in ((SELECT_SEQ + 70 + 40, True), (SELECT_SEQ + 70 + 20, False), (SELECT_SEQ + 70, False)):
            pipe = fresh()
            self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
            self.step(pipe, rs.IN_SERVER, response1(), OWNER['response'])
            self.step(pipe, rs.IN_CLIENT, operate_packet(), OWNER['operate'])
            out = pipe.inject(rs.IN_SERVER, response2(ack=ack))
            self.assertEqual(out.dropped, not ok, ack)
            self.assertEqual(pipe.state()['owner'], OWNER['idle'] if ok else OWNER['operate'])
            self.assertEqual(pipe.state()['work']['phase'], 4)

    def test_second_response_needs_the_operate_application_sequence_and_exact_object(self):
        for kwargs in (dict(app=0), dict(app=2)):
            pipe = fresh()
            self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
            self.step(pipe, rs.IN_SERVER, response1(), OWNER['response'])
            self.step(pipe, rs.IN_CLIENT, operate_packet(), OWNER['operate'])
            out = pipe.inject(rs.IN_SERVER, response2(**kwargs))
            self.assertTrue(out.dropped, kwargs)
            self.assertEqual(pipe.state()['owner'], OWNER['operate'])
            self.assertEqual(pipe.state()['work']['phase'], 4)

    def test_wrong_exchange_responses_are_refused(self):
        # a response2-shaped frame while the owner is at 9, and a response1-shaped one at 12
        pipe = fresh()
        self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
        self.assertTrue(pipe.inject(rs.IN_SERVER, response2(ack=SELECT_SEQ + 35 + 40, seq=SERVER_SEQ)).dropped)
        pipe = fresh()
        self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
        self.step(pipe, rs.IN_SERVER, response1(), OWNER['response'])
        self.step(pipe, rs.IN_CLIENT, operate_packet(), OWNER['operate'])
        self.assertTrue(pipe.inject(rs.IN_SERVER, response1(ack=SELECT_SEQ + 70 + 20, app=0)).dropped)
        self.assertEqual(pipe.state()['owner'], OWNER['operate'])

    def test_a_second_operate_after_the_exchange_is_not_bound(self):
        pipe = fresh()
        for port, frame, owner in ((rs.IN_CLIENT, select_packet(), OWNER['select']), (rs.IN_SERVER, response1(), OWNER['response']),
                                   (rs.IN_CLIENT, operate_packet(), OWNER['operate']), (rs.IN_SERVER, response2(), OWNER['idle'])):
            self.step(pipe, port, frame, owner)
        out = pipe.inject(rs.IN_CLIENT, operate_packet(app=2, seq=171, ack=1015))
        self.assertTrue(out.dropped)
        self.assertEqual(pipe.state()['owner'], OWNER['idle'])


class Topology(unittest.TestCase):
    def test_reverse_orientation_data_connection_exists_and_binds_the_response(self):
        pipe = fresh()
        pipe.inject(rs.IN_CLIENT, select_packet())
        out = pipe.inject(rs.IN_SERVER, response1())
        self.assertEqual(out.passes, 4, 'was 1 pass (unbound) with only the forward tuple configured')
        self.assertIn('table data_connection -> configure (runtime)', pipe.trace_text(out))


if __name__ == '__main__':
    unittest.main()
