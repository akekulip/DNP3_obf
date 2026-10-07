"""Whole-source cancellation immediately before the genuine terminal return."""
import unittest
import read_support as rs
import vectors


class CancelledTerminal(unittest.TestCase):
    def test_read_terminals_recheck_full_owner_after_genuine_close(self):
        for kind in (9, 10, 11):
            with self.subTest(kind=kind):
                pipe = rs.ReadPipeline().start(0x50001 if kind == 9 else 0xe0001,
                    1000 if kind == 9 else 1020, 2000, app=0)
                raw = {9: rs.request_packet(), 10: rs.ack_packet(), 11: rs.response_packet()}[kind]
                closed = []
                def close(p):
                    del p.mutate[4]
                    before = dict(p.state()['work'])
                    closed.append(p.inject(rs.IN_CLIENT, vectors.frame(17,
                        p.state()['client'], p.state()['server'])))
                    self.assertEqual(p.state()['work'], before)
                pipe.mutate[4] = close
                out = pipe.inject(rs.IN_CLIENT if kind == 9 else rs.IN_SERVER, raw)
                self.assertEqual(len(closed[0].emitted), 1)
                self.assertTrue(out.dropped)
                self.assertEqual(out.emitted, [])
                self.assertEqual(pipe.state()['work']['phase'], 4)
                self.assertIn(pipe.state()['owner'] >> 16, (6, 7))

    def test_stale_expected_owner_cannot_publish_even_with_current_epoch(self):
        for kind in (9, 10, 11):
            with self.subTest(kind=kind):
                pipe = rs.ReadPipeline().start(0x50001 if kind == 9 else 0xe0001,
                    1000 if kind == 9 else 1020, 2000, app=0)
                raw = {9: rs.request_packet(), 10: rs.ack_packet(), 11: rs.response_packet()}[kind]
                pipe.mutate[4] = lambda p: p.src.cells[('', 'owner')].__setitem__(0, 0x60002)
                out = pipe.inject(rs.IN_CLIENT if kind == 9 else rs.IN_SERVER, raw)
                self.assertTrue(out.dropped)
                self.assertEqual(out.emitted, [])
                self.assertEqual(pipe.state()['owner'], 0x60002)
                self.assertEqual(pipe.state()['work']['phase'], 4)
