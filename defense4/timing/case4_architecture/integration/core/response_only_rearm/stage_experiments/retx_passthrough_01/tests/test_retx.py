"""Actual-source regressions: a retransmitted copy of a segment N already forwarded is forwarded again."""
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
INTEG = HERE.parents[3]
sys.dont_write_bytecode = True
sys.path[:0] = [str(INTEG / 'core/response_only_rearm'), str(INTEG / 'core/response_only_rearm/tests'),
                str(INTEG / 'core/response_only/tests'), str(INTEG / 'core/response_only'),
                str(INTEG / 'connection/binding/tests'), str(INTEG / 'read/tests'), str(INTEG / 'core/harness')]
import read_support as rs
from interpreter import source_text
import test_response_only_binding as h
import test_rearm as tr


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = load('retx_generate', HERE / 'generate.py')
ORIGINAL = source_text(gen.diag.source_role('N'))
PATCHED = source_text(gen.source_role('N'))
EPOCH = 17


def pipeline(text, owner=0x40001, client=101, server=901):
    p = rs.ReadPipeline(text=text).start(owner, client, server, epoch=EPOCH)
    p.src.cells[('', 'counter')][0] = EPOCH
    return p


def snapshot(p):
    st = p.state()
    return (st['owner'], st['client'], st['server'], st['epoch']), st['work']['phase']


class Identity(unittest.TestCase):
    def test_only_n_changes_and_the_edit_is_reversible(self):
        base, source = gen.frozen(), gen.full_source()
        self.assertNotEqual(base, source)
        for role in ('E', 'T'):
            self.assertEqual(gen.combined.segment(source, role), gen.combined.segment(base, role))
        self.assertEqual(source.replace(gen.combined.segment(source, 'N'), gen.combined.segment(base, 'N'), 1), base)
        self.assertEqual(gen.source_role('E'), gen.diag.source_role('E'))
        self.assertEqual(gen.source_role('T'), gen.diag.source_role('T'))


class Retransmission(unittest.TestCase):
    def flow(self, text):
        p = pipeline(text)
        return p, h.select_packet(), h.response1(), h.operate_packet(), h.response2()

    def forwarded(self, p, frame, master, port):
        before = snapshot(p)
        out = tr.normalized(p, frame, EPOCH) if master else p.inject(rs.IN_SERVER, frame)
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual([pt for pt, _ in out.emitted], [port])
        self.assertEqual(snapshot(p), (before[0], 4), 'authority or Work changed by a retransmission')
        return out

    def test_select_and_its_response_are_forwarded_again(self):
        p, select, response1, operate, response2 = self.flow(PATCHED)
        tr.normalized(p, select, EPOCH)
        self.forwarded(p, select, True, 2)
        p.inject(rs.IN_SERVER, response1)
        self.forwarded(p, response1, False, 1)

    def test_operate_and_its_response_are_forwarded_again(self):
        p, select, response1, operate, response2 = self.flow(PATCHED)
        tr.normalized(p, select, EPOCH)
        p.inject(rs.IN_SERVER, response1)
        tr.normalized(p, operate, EPOCH)
        self.forwarded(p, operate, True, 2)
        self.forwarded(p, response1, False, 1)   # the SELECT response again, with a stale ack
        p.inject(rs.IN_SERVER, response2)
        self.forwarded(p, response2, False, 1)

    def test_read_request_and_response_are_forwarded_again(self):
        p = pipeline(PATCHED, 0x50001, 1000, 2000)
        req = rs.request_packet(seq=1000, ack=2000)
        ack = rs.ack_packet(seq=2000, ack=1020)
        rsp = rs.response_packet(seq=2000, ack=1020)
        tr.normalized(p, req, EPOCH)
        self.forwarded(p, req, True, 2)
        p.inject(rs.IN_SERVER, ack)
        p.inject(rs.IN_SERVER, rsp)
        self.forwarded(p, rsp, False, 1)

    def test_candidate56_without_the_change_drops_every_one_of_them(self):
        p, select, response1, operate, response2 = self.flow(ORIGINAL)
        tr.normalized(p, select, EPOCH)
        self.assertTrue(tr.normalized(p, select, EPOCH).dropped)
        p.inject(rs.IN_SERVER, response1)
        self.assertTrue(p.inject(rs.IN_SERVER, response1).dropped)

    def test_a_new_sequence_operate_and_an_operate_after_its_response_stay_refused(self):
        p, select, response1, operate, response2 = self.flow(PATCHED)
        tr.normalized(p, select, EPOCH)
        p.inject(rs.IN_SERVER, response1)
        tr.normalized(p, operate, EPOCH)
        p.inject(rs.IN_SERVER, response2)
        before = snapshot(p)
        self.assertTrue(tr.normalized(p, operate, EPOCH).dropped)
        self.assertEqual(snapshot(p), (before[0], 4))

    def test_copies_that_do_not_end_exactly_at_the_frontier_stay_refused(self):
        p = pipeline(PATCHED, 0x50001, 1000, 2000)
        req = rs.request_packet(seq=1000, ack=2000)
        ack = rs.ack_packet(seq=2000, ack=1020)
        rsp = rs.response_packet(seq=2000, ack=1020)
        tr.normalized(p, req, EPOCH)
        p.inject(rs.IN_SERVER, ack)
        p.inject(rs.IN_SERVER, rsp)
        before = snapshot(p)
        for frame, master in ((rs.request_packet(seq=990, ack=2000), True), (rs.request_packet(seq=1001, ack=2000), True),
                              (rs.response_packet(seq=1990, ack=1020), False), (rs.response_packet(seq=2001, ack=1020), False)):
            out = tr.normalized(p, frame, EPOCH) if master else p.inject(rs.IN_SERVER, frame)
            self.assertTrue(out.dropped, frame[34:54].hex())
        self.assertEqual(snapshot(p), (before[0], 4))


if __name__ == '__main__':
    unittest.main()
