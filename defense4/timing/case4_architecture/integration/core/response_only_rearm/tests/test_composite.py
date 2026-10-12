"""Candidate source composition, including the private ACK commit lap."""
import copy
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from source_pipeline import SourcePipeline, rs, qs, vectors


class Composite(unittest.TestCase):
    def fresh(self, **kw):
        s = SourcePipeline(**kw)
        self.addCleanup(s.close)
        return s.handshake()

    def test_handshake_rst_reconnect_and_fresh_mapping(self):
        s = self.fresh()
        self.assertEqual(s.e.cells[('', 'mode')][0], 1)
        old = s.n.state()['epoch']
        s.send(vectors.packet(20, 101, 901))
        self.assertEqual(s.n.state()['owner'] >> 16, 0x200)
        s.handshake(4000, 7000)
        self.assertGreater(s.n.state()['epoch'], old)
        self.assertEqual(s.e.cells[('', 'epoch')][0] & 0x7fffffff, s.n.state()['epoch'])
        self.assertTrue(s.e.cells[('', 'epoch')][0] & 0x80000000)
        self.assertEqual(s.e.cells[('', 'front')][0], 7001)
        self.assertEqual(s.e.cells[('', 'acct')][0], {'lo': 7001, 'hi': 0})
        self.assertEqual(s.t.cell('cur_epoch_reg'), s.n.state()['epoch'])
        self.assertTrue(all(raw[:14] == bytes.fromhex('001122334455aabbccddeeff0800')
                            for _, _, raw in s.wire))

    def test_graceful_close_after_padded_read_preserves_mapping_until_ack(self):
        s = self.fresh()
        s.send(rs.request_packet(seq=101, ack=901))
        s.send(rs.ack_packet(seq=901, ack=121), master=False)
        s.send(rs.response_packet(seq=901, ack=121), master=False)
        s.run(s.now + 8_000_000)
        old_epoch = s.n.state()['epoch']
        s.send(vectors.packet(17, 121, 959))
        self.assertEqual(s.n.state()['owner'] >> 16, 0x101)
        s.send(vectors.packet(17, 950, 122, reverse=True), master=False)
        self.assertEqual(s.n.state()['owner'] >> 16, 0x10b)
        self.assertEqual(int.from_bytes(s.wire[-1][2][38:42], 'big'), 959)
        s.send(vectors.packet(16, 122, 960))
        self.assertEqual(s.n.state()['owner'] >> 16, 0x10f)
        self.assertEqual(s.n.state()['work']['phase'], 4)
        self.assertEqual(s.t.cell('quarantine_reg'), old_epoch)
        s.handshake(4000, 7000)
        self.assertGreater(s.n.state()['epoch'], old_epoch)
        self.assertEqual(s.e.cells[('', 'acct')][0], {'lo': 7001, 'hi': 0})

    def test_ambiguous_server_isn_can_abort_then_handshake_fresh(self):
        s = self.fresh()
        s.send(vectors.packet(20, 101, 901))
        s.send(vectors.packet(2, 4000, mss=1460))
        before_e = copy.deepcopy(s.e.cells)
        s.send(vectors.packet(18, 900, 4001, reverse=True, mss=1460), master=False)
        self.assertEqual(s.n.state()['owner'] >> 16, 2)
        self.assertEqual(s.e.cells, before_e)
        s.send(vectors.packet(20, 0, 4001, reverse=True), master=False)
        self.assertEqual(s.n.state()['owner'] >> 16, 0x200)
        s.handshake(8000, 10000)
        self.assertEqual(s.e.cells[('', 'front')][0], 10001)

    def test_exact_syn_and_synack_retries_never_rearm_e(self):
        s = SourcePipeline()
        self.addCleanup(s.close)
        syn = vectors.packet(2, 100, mss=1460)
        synack = vectors.packet(18, 900, 101, reverse=True, mss=1460)
        s.send(syn)
        before = copy.deepcopy(s.e.cells)
        s.send(syn)
        self.assertEqual(s.e.cells, before)
        s.send(synack, master=False)
        self.assertEqual(s.n.state()['owner'] >> 16, 4)
        self.assertEqual(s.e.cells[('', 'mode')][0], 1)
        s.wire.pop()  # The first SYNACK did not reach the endpoint.
        before = copy.deepcopy(s.e.cells)
        s.send(synack, master=False)
        self.assertEqual(s.e.cells, before)
        self.assertEqual(s.wire[-1][2], synack)
        self.assertEqual([raw[12] for role, _, _, raw, _ in s.trace if role == 'E'][-1], 0xe3)
        s.send(vectors.packet(16, 101, 901))
        self.assertEqual(s.n.state()['owner'] >> 16, 5)
        before = copy.deepcopy(s.e.cells)
        s.send(synack, master=False)  # ACK reached N but was lost downstream.
        self.assertEqual(s.e.cells, before)
        self.assertEqual(s.wire[-1][2], synack)
        for phase in (4, 5, 9):
            s.n.preset(owner=(phase << 16) | 1)
            count = len(s.wire)
            s.send(vectors.packet(18, 901, 101, reverse=True, mss=1460), master=False)
            self.assertEqual(len(s.wire), count)
            self.assertEqual(s.e.cells, before)
        s.n.preset(owner=0x90001)
        count = len(s.wire)
        s.send(synack, master=False)
        self.assertEqual(len(s.wire), count)
        self.assertEqual(s.e.cells, before)

    def test_read_commit_lap_hold_release_and_padding(self):
        s = self.fresh()
        s.send(rs.request_packet(seq=101, ack=901))
        self.assertEqual(s.n.state()['owner'] >> 16, 14)
        s.send(rs.ack_packet(seq=901, ack=121), master=False)
        s.send(rs.response_packet(seq=901, ack=121), master=False)
        s.run(s.now + 8_000_000)
        self.assertEqual(s.t.counter(0), 0)
        self.assertEqual(s.t.counter(2), 1)
        self.assertEqual(s.t.counter(3), 1)
        responses = [raw for _, port, raw in s.wire if port == 9 and raw[47] == 24]
        self.assertEqual(len(responses), 1)
        self.assertEqual(int.from_bytes(responses[0][16:18], 'big'), 98)
        self.assertEqual(len(responses[0]), 112)
        self.assertEqual(s.e.cells[('', 'acct')][0]['hi'], 58)
        # Master ACKs padded end 959; N validates native end 950 before E
        # performs the accounting commit using the immutable original ACK.
        s.send(vectors.packet(16, 121, 959))
        self.assertEqual(s.e.cells[('', 'acct')][0]['hi'], 0)

    def test_sbo_native_requests_padded_responses_and_operate_hold(self):
        s = self.fresh()
        def response(app, fc):
            # Existing model vector's 37-byte control response construction.
            _, user = rs.case4_padding.decode_frame(vectors.native_select(app, fc))
            objects = bytearray(user[3:])
            objects[17] = 0
            return rs.case4_padding.build_frame(bytes.fromhex('05641c4401000a00'),
                                               user[:2] + bytes((0x81, 0, 0)) + bytes(objects))
        select = vectors.packet(24, 101, 901, payload=vectors.native_select(0, 3))
        s.send(select)
        self.assertEqual(s.n.state()['owner'] >> 16, 9)
        self.assertEqual(s.wire[-1][2], select)
        s.send(vectors.packet(24, 901, 136, reverse=True, payload=response(0, 3)), master=False)
        self.assertEqual(s.n.state()['owner'] >> 16, 10)
        self.assertEqual(int.from_bytes(s.wire[-1][2][16:18], 'big'), 98)
        rs.case4_padding.decode_frame(s.wire[-1][2][54:112])
        operate = vectors.packet(24, 136, 959, payload=vectors.native_select(1, 4))
        s.send(operate)
        admitted = s.now
        self.assertEqual(s.n.state()['owner'] >> 16, 12)
        self.assertFalse([raw for _, _, raw in s.wire if raw[54:] == operate[54:]])
        s.run(admitted + 8_000_000)
        departures = [(stamp, raw) for stamp, port, raw in s.wire
                      if port == 64 and raw[54:] == operate[54:]]
        self.assertEqual(len(departures), 1)
        self.assertEqual(int.from_bytes(departures[0][1][42:46], 'big'), 938)
        self.assertEqual(departures[0][1][54:], operate[54:])
        self.assertGreaterEqual(departures[0][0] - admitted, qs.OP_J)
        self.assertEqual(s.t.counter(s.t.consts()['OUT_OP_RELEASE']), 1)
        s.send(vectors.packet(24, 938, 171, reverse=True, payload=response(1, 4)), master=False)
        self.assertEqual(s.n.state()['owner'] >> 16, 5)
        self.assertEqual(int.from_bytes(s.wire[-1][2][38:42], 'big'), 959)
        self.assertEqual(int.from_bytes(s.wire[-1][2][16:18], 'big'), 98)
        rs.case4_padding.decode_frame(s.wire[-1][2][54:112])

    def test_old_external_packets_and_qualified_envelopes_cannot_dirty_new_mapping(self):
        s = self.fresh()
        old = s.n.state()['epoch']
        s.send(vectors.packet(20, 101, 901))
        s.handshake(4000, 7000)
        before_n = {k: s.n.state()[k] for k in ('owner', 'client', 'server', 'epoch')}
        before_e = copy.deepcopy(s.e.cells)
        for packet, master in ((vectors.packet(16, 101, 901), True),
                               (vectors.packet(17, 101, 901), True),
                               (vectors.packet(20, 101, 901), True),
                               (rs.response_packet(seq=901, ack=121), False),
                               (vectors.packet(18, 900, 101, reverse=True, mss=1460), False)):
            s.send(packet, master=master)
            self.assertEqual({k: s.n.state()[k] for k in before_n}, before_n)
            self.assertEqual(s.e.cells, before_e)
        for kind, port, packet in ((0xe4, 64, vectors.packet(16, 101, 959)),
                                   (0xe3, 9, rs.response_packet(seq=901, ack=121))):
            prefix = struct.pack('!IIIBBH', old, 959, 0, kind, 0, 0)
            self.assertIsNone(s.e.inject(port, prefix + packet))
            self.assertEqual(s.e.cells, before_e)

    def test_all_old_work_return_phases_cannot_write_after_new_open(self):
        s = self.fresh()
        s.send(rs.request_packet(seq=101, ack=901))
        s.send(rs.ack_packet(seq=901, ack=121), master=False)
        s.send(rs.response_packet(seq=901, ack=121), master=False)
        old_returns = list(s.n.returns)
        self.assertTrue({raw[12] for raw in old_returns}.issuperset({1, 2, 3}))
        s.send(vectors.packet(20, 121, 950))
        old_returns.extend(s.n.returns[len(old_returns):])
        s.handshake(4000, 7000)
        before_n = copy.deepcopy(s.n.src.cells)
        before_e = copy.deepcopy(s.e.cells)
        for raw in old_returns:
            out = s.ingress(s.now + 1000, 68, raw)
            self.assertFalse(out.emitted)
            self.assertEqual(s.n.src.cells, before_n)
            self.assertEqual(s.e.cells, before_e)

    def test_delayed_accounting_commit_return_cannot_dirty_new_t_lifetime(self):
        s = self.fresh()
        s.send(rs.request_packet(seq=101, ack=901))
        old_returns = [result for role, _, port, _, result in s.trace
                       if role == 'E' and port == 70 and result and result[12] == 0xe6]
        self.assertTrue(old_returns)
        s.send(vectors.packet(20, 121, 901))
        s.handshake(4000, 7000)
        before_n, before_e = copy.deepcopy(s.n.src.cells), copy.deepcopy(s.e.cells)
        before_t = {k: copy.deepcopy(v) for k, v in s.t.src.cells.items() if k[1] != 'outcomes'}
        for raw in old_returns:
            s.ingress(s.now + 1000, 70, raw)
            s.t.run(s.now + 20_000)
            self.assertEqual(s.n.src.cells, before_n)
            self.assertEqual(s.e.cells, before_e)
            self.assertEqual({k: v for k, v in s.t.src.cells.items() if k[1] != 'outcomes'}, before_t)
        self.assertGreater(s.t.counter(14), 0)

    def test_old_held_originals_blockers_and_tokens_cannot_change_new_t_state(self):
        s = self.fresh(service_ns=100_000)
        epoch = s.n.state()['epoch']
        base = s.now + 100_000
        s.t.read(base, epoch=epoch)
        s.t.operate(base + 10_000, epoch=epoch)
        s.t.run(base + 120_000)
        old = list(s.t.enqueued)
        old_gen, old_op = s.t.cell('gen_alloc_reg'), s.t.cell('op_gen_alloc_reg')
        s.t.reset(base + 130_000, epoch=epoch)
        s.t.event(base + 140_000, 14, qs.REQ_FRAME, epoch=epoch + 10)
        s.t.run(base + 140_000)
        before = {k: copy.deepcopy(v) for k, v in s.t.src.cells.items() if k[1] != 'outcomes'}
        for _, port, _, raw in old:
            s.t.ingress(base + 150_000, port, raw)
            self.assertEqual({k: v for k, v in s.t.src.cells.items() if k[1] != 'outcomes'}, before)
        # Exercise token profiles and both packet-id parity classes directly.
        for profile, generation in ((1, old_op), (0, old_gen)):
            for packet_id in range(4):
                raw = bytes((qs.PKTGEN_PIPE << 3 | profile, profile)) + struct.pack('!HH', generation, packet_id) + bytes(10)
                s.t.ingress(base + 160_000, 0, raw)
                self.assertEqual({k: v for k, v in s.t.src.cells.items() if k[1] != 'outcomes'}, before)
        self.assertGreater(s.t.counter(14), 0)


if __name__ == '__main__':
    unittest.main()
