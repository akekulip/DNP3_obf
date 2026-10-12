"""Whole-source regressions for the isolated reconnect candidate."""
import sys
import struct
import random
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
import baseline
import make_n
import make_t
import make_e
from interpreter import ESource, source_text
sys.path[:0] = [str(baseline.INTEG / 'connection' / 'binding' / 'tests'),
                str(baseline.INTEG / 'read' / 'tests')]
import read_support as rs
import vectors
import queue_sim as qs


def normalized(pipe, frame, epoch, same_syn=0):
    """Trusted E return, byte format used by the candidate parser."""
    pipe.src.install('ports', (70, (0, 0), (0, 0), (0, 0)), 'route', (rs.IN_SERVER,), priority=1)
    pipe.src.install('connection', (vectors.CLIENT, vectors.SERVER, vectors.CLIENT_PORT,
                                   vectors.SERVER_PORT, 70), 'forward_flow', (rs.IN_SERVER,))
    ack = int.from_bytes(frame[42:46], 'big')
    return pipe.inject(70, struct.pack('!IIIHH', epoch, ack, same_syn, 0xe100, 0) + frame)


class ProtectedRearm(unittest.TestCase):
    def fresh(self, owner=0x50001, client=101, server=901, epoch=17):
        p = rs.ReadPipeline(text=source_text(make_n.generate())).start(owner, client, server, epoch=epoch)
        p.src.cells[('', 'counter')][0] = epoch
        return p

    def authority(self, p):
        return {k: p.state()[k] for k in ('owner', 'client', 'server', 'epoch')}

    def test_bilateral_fin_ack_both_orders_and_simultaneous_ack(self):
        for first_server in (False, True):
            with self.subTest(first_server=first_server):
                p = self.fresh()
                # The second FIN also acknowledges the first FIN.
                sequence = [(17, 101, 901, False), (17, 901, 102, True), (16, 102, 902, False)]
                if first_server:
                    sequence = [(17, 901, 101, True), (17, 101, 902, False), (16, 902, 102, True)]
                for i, (flags, seq, ack, reverse) in enumerate(sequence):
                    out = p.inject(rs.IN_SERVER if reverse else rs.IN_CLIENT,
                                   vectors.packet(flags, seq, ack, reverse=reverse))
                    self.assertTrue(out.emitted)
                    if i < 2:
                        self.assertNotEqual(p.state()['owner'] >> 16, 0x10f)
                self.assertEqual(p.state()['owner'] >> 16, 0x10f)
                self.assertEqual(p.state()['work']['phase'], 4)
                before = self.authority(p)
                flags, seq, ack, reverse = sequence[-1]
                self.assertTrue(p.inject(rs.IN_SERVER if reverse else rs.IN_CLIENT,
                                        vectors.packet(flags, seq, ack, reverse=reverse)).emitted)
                self.assertEqual(self.authority(p), before)
                self.assertTrue(normalized(p, vectors.packet(2, 4000, 0, mss=1460), 17).emitted)
                self.assertEqual(p.state()['owner'] >> 16, 2)
                self.assertEqual(p.state()['owner'] & 0xffff, 2)

    def test_first_fin_and_unqualified_rst_cannot_rearm(self):
        for packet in (vectors.packet(17, 101, 901), vectors.packet(20, 100, 901)):
            p = self.fresh()
            p.inject(rs.IN_CLIENT, packet)
            before = self.authority(p)
            self.assertFalse(normalized(p, vectors.packet(2, 4000, 0, mss=1460), 17).emitted)
            self.assertEqual(self.authority(p), before)

    def test_exact_pending_syn_retry_and_changed_syn_denial(self):
        p = self.fresh(owner=0x20001)
        before = self.authority(p)
        self.assertTrue(normalized(p, vectors.packet(2, 100, 0, mss=1460), 17, same_syn=1).emitted)
        self.assertEqual(self.authority(p), before)
        self.assertFalse(normalized(p, vectors.packet(2, 4000, 0, mss=1460), 17).emitted)
        self.assertEqual(self.authority(p), before)

    def test_same_isn_retired_and_busy_work_cannot_overwrite(self):
        for same, work in ((1, (17, 4)), (0, (17, 1)), (0, (17, 2)), (0, (17, 3))):
            p = self.fresh(owner=0x2000001)
            p.preset(work=work)
            before = self.authority(p)
            self.assertFalse(normalized(p, vectors.packet(2, 100 if same else 4000, 0, mss=1460),
                                        17, same_syn=same).emitted)
            self.assertEqual(self.authority(p), before)
            if work[1] != 4:
                self.assertEqual(p.state()['work'], {'generation': work[0], 'phase': work[1]})
            else:
                self.assertEqual(p.state()['work']['phase'], 4)

    def test_n_counter_and_owner_generation_exhaustion_fail_closed(self):
        for owner, counter in ((0x200ffff, 17), (0x2000001, 0x7ffffffe)):
            p = self.fresh(owner=owner)
            p.src.cells[('', 'counter')][0] = counter
            before = self.authority(p)
            self.assertFalse(normalized(p, vectors.packet(2, 4000, 0, mss=1460), 17).emitted)
            self.assertEqual(self.authority(p), before)
            self.assertEqual(p.state()['work']['phase'], 4)

    def test_reused_client_and_server_isns_must_follow_previous_frontier(self):
        for isn in (0, 100, 120, 135, 136):
            p = self.fresh(owner=0x2000001, client=136, server=938)
            before = self.authority(p)
            self.assertFalse(normalized(p, vectors.packet(2, isn, 0, mss=1460), 17).emitted)
            self.assertEqual(self.authority(p), before)
        for isn in (0, 900, 920, 937, 938):
            p = self.fresh(owner=0x2000001, client=136, server=938)
            self.assertTrue(normalized(p, vectors.packet(2, 137, 0, mss=1460), 17).emitted)
            before = self.authority(p)
            self.assertFalse(p.inject(rs.IN_SERVER, vectors.packet(18, isn, 138, reverse=True, mss=1460)).emitted)
            self.assertEqual(self.authority(p), before)
        p = self.fresh(owner=0x2000001, client=136, server=938)
        normalized(p, vectors.packet(2, 137, 0, mss=1460), 17)
        self.assertTrue(p.inject(rs.IN_SERVER, vectors.packet(18, 939, 138, reverse=True, mss=1460)).emitted)

    def test_pending_abort_closed_port_rst_ack_and_master_reset(self):
        for reverse in (False, True):
            p = self.fresh(owner=0x20002, client=4001, server=938)
            stale = vectors.packet(20, 0, 101, reverse=True)
            before = self.authority(p)
            self.assertFalse(p.inject(rs.IN_SERVER, stale).emitted)
            self.assertEqual(self.authority(p), before)
            packet = vectors.packet(20, 0, 4001, reverse=True) if reverse else vectors.packet(4, 4001, 0)
            out = p.inject(rs.IN_SERVER if reverse else rs.IN_CLIENT, packet)
            self.assertTrue(out.emitted)
            self.assertEqual(p.state()['owner'] >> 16, 0x200)
            self.assertEqual(p.state()['work']['phase'], 4)
            self.assertTrue(normalized(p, vectors.packet(2, 8000, 0, mss=1460), 17).emitted)

    def test_pending_abort_waits_for_genuine_work_free(self):
        p = self.fresh(owner=0x20002, client=4001, server=938)
        p.preset(work=(17, 2))
        before = self.authority(p)
        self.assertFalse(p.inject(rs.IN_SERVER, vectors.packet(20, 0, 4001, reverse=True)).emitted)
        self.assertEqual(self.authority(p), before)
        self.assertEqual(p.state()['work'], {'generation': 17, 'phase': 2})

    def test_close_racing_a_new_work_claim_cannot_retire_the_owner(self):
        p = self.fresh()
        before = self.authority(p)
        p.mutate[2] = lambda pipe: pipe.preset(work=(91, 2))
        out = p.inject(rs.IN_CLIENT, vectors.packet(20, 101, 901))
        self.assertFalse(out.emitted)
        self.assertEqual(self.authority(p), before)
        self.assertEqual(p.state()['work'], {'generation': 91, 'phase': 2})

    def test_reuse_boundary_supports_modular_wrap_and_rejects_halfspace(self):
        p = self.fresh(owner=0x2000001, client=0xfffffff0, server=0xffffff00)
        self.assertTrue(normalized(p, vectors.packet(2, 0x20, mss=1460), 17).emitted)
        self.assertTrue(p.inject(rs.IN_SERVER,
                                vectors.packet(18, 0x80, 0x21, reverse=True, mss=1460)).emitted)
        for delta in (0, 1, 0x80000000, 0xffffffff):
            p = self.fresh(owner=0x2000001, client=0xfffffff0, server=0xffffff00)
            isn = (0xfffffff0 + delta - 1) & 0xffffffff
            before = self.authority(p)
            self.assertFalse(normalized(p, vectors.packet(2, isn, mss=1460), 17).emitted)
            self.assertEqual(self.authority(p), before)

    def test_qualified_rst_then_same_tuple_syn_claims_fresh_epoch(self):
        p = rs.ReadPipeline(text=source_text(make_n.generate())).start(0x50001, 101, 901, epoch=17)
        p.src.cells[('', 'counter')][0] = 17
        p.inject(rs.IN_CLIENT, vectors.packet(0x14, 101, 901))
        old = p.state()['epoch']
        out = normalized(p, vectors.packet(2, 4000, 0, mss=1460), old)
        self.assertTrue(out.emitted, 'a retired tuple must admit a fresh SYN')
        self.assertGreater(p.state()['epoch'], old)
        self.assertEqual(p.state()['client'], 4001)

    def test_old_reset_does_not_change_live_t_generation_or_anchor(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 't.p4'
            src.write_text(make_t.generate())
            s = qs.QueueSim(source=src)
            s.event(qs.T0, 14, qs.REQ_FRAME, epoch=17)
            s.request(qs.T0 + 50_000, epoch=17)
            s.run(qs.T0 + 100_000)
            before = {k: list(v) for k, v in s.src.cells.items()}
            s.reset(qs.T0 + 150_000, epoch=16)
            s.run(qs.T0 + 200_000)
            for name in ('gen_alloc_reg', 'op_gen_alloc_reg', 't0_reg', 'ack_done_reg', 'resp_done_reg'):
                key = ('', name)
                self.assertIn(key, before)
                self.assertEqual(s.src.cells[key], before[key], name)

    def test_retired_held_response_is_dropped_even_when_policy_is_off(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 't.p4'
            src.write_text(make_t.generate())
            s = qs.QueueSim(source=src, service_ns=100_000)
            s.event(qs.T0, 14, qs.REQ_FRAME, epoch=17)
            s.read(qs.T0 + 50_000, epoch=17)
            s.reset(qs.T0 + 160_000, epoch=17)
            s.event(qs.T0 + 170_000, 14, qs.REQ_FRAME, epoch=18)
            s.call(qs.T0 + 180_000, lambda sim: sim.set_params(enabled=0))
            s.run(qs.T0 + 8_000_000)
            self.assertFalse([raw for _, _, raw in s.emitted if raw[16:] == qs.RSP_FRAME],
                             'old original must not flush into the new connection')
            self.assertGreater(s.counter(14), 0)

    def test_out_of_bound_open_cannot_write_t_epoch_or_generation(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 't.p4'
            path.write_text(make_t.generate())
            for epoch in (0x7fffffff, 0x80000000, 0xffffffff):
                s = qs.QueueSim(source=path)
                s.event(qs.T0, 14, qs.REQ_FRAME, epoch=17)
                s.run(qs.T0)
                before = {k: list(v) for k, v in s.src.cells.items() if k[1] != 'outcomes'}
                s.event(qs.T0 + 1000, 14, qs.REQ_FRAME, epoch=epoch)
                s.run(qs.T0 + 1000)
                self.assertEqual({k: list(v) for k, v in s.src.cells.items() if k[1] != 'outcomes'}, before)

    def test_t_exhaustion_does_not_arm_anchor_or_alias_token(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 't.p4'
            path.write_text(make_t.generate())
            for kind, allocator, anchor in ((9, 'gen_alloc_reg', 't0_reg'),
                                            (12, 'op_gen_alloc_reg', 'op_t0_reg')):
                s = qs.QueueSim(source=path)
                s.event(qs.T0, 14, qs.REQ_FRAME, epoch=17)
                s.run(qs.T0)
                s.src.cells[('', allocator)][0] = 0xfffe
                before = s.cell(anchor)
                s.event(qs.T0 + 1000, kind, qs.REQ_FRAME, epoch=17)
                s.token(qs.T0 + 2000, 0xffff, 0, profile=0 if kind == 9 else 1)
                s.run(qs.T0 + 3000)
                self.assertEqual(s.cell(allocator), 0xffff)
                self.assertEqual(s.cell(anchor), before)
                self.assertEqual(s.counter(15), 1)
                self.assertFalse(s.enqueued)

    def test_timer_never_reads_an_invalid_tev_discriminator(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 't.p4'
            path.write_text(make_t.generate())
            for poison in (12, 13, 14, 255):
                s = qs.QueueSim(source=path)
                s.event(qs.T0, 14, qs.REQ_FRAME, epoch=17)
                s.request(qs.T0 + 1000, epoch=17)
                s.run(qs.T0 + 1000)
                parse = s.src.packet_parser
                def poisoned(raw):
                    result = parse(raw)
                    # The program must tolerate any bits in the invalid header.
                    s.src.env['hdr.tev.kind'] = poison
                    s.src.env['hdr.tev.epoch'] = 0x7ffffffe
                    return result
                s.src.packet_parser = poisoned
                generation = s.cell('gen_alloc_reg')
                raw = bytes((qs.PKTGEN_PIPE << 3, 0)) + struct.pack('!HH', generation, 0) + bytes(10)
                before = len(s.enqueued)
                s.ingress(qs.T0 + 2000, qs.PKTGEN_PORT, raw)
                self.assertEqual(len(s.enqueued), before + 1)
                self.assertEqual(s.enqueued[-1][3][0], 11)
                self.assertEqual(s.cell('cur_epoch_reg'), 17)
                self.assertEqual(s.cell('gen_alloc_reg'), generation)
                self.assertEqual(s.src.env['m.event_kind'], 0)

    def test_current_owner_policy_off_flushes_held_originals(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 't.p4'
            path.write_text(make_t.generate())
            for operate in (False, True):
                s = qs.QueueSim(source=path, service_ns=20_000)
                s.event(qs.T0, 14, qs.REQ_FRAME, epoch=17)
                if operate:
                    s.operate(qs.T0 + 1000, epoch=17)
                    original = qs.OP_FRAME
                else:
                    s.read(qs.T0 + 1000, epoch=17)
                    original = qs.RSP_FRAME
                s.call(qs.T0 + 160_000, lambda sim: sim.set_params(enabled=0))
                s.run(qs.T0 + 8_000_000)
                sent = [raw for _, _, raw in s.emitted if raw[16:] == original]
                self.assertEqual(len(sent), 1)
                self.assertEqual(sent[0][12], 0xe3)
                self.assertEqual(s.counter(14), 0)


class EAccounting(unittest.TestCase):
    def fresh(self):
        s = ESource(make_e.generate())
        forward = (vectors.SERVER, vectors.CLIENT, vectors.SERVER_PORT, vectors.CLIENT_PORT, 9)
        reverse = (vectors.CLIENT, vectors.SERVER, vectors.CLIENT_PORT, vectors.SERVER_PORT)
        s.install('conn', forward, 'fwd_conn', (0, 1))
        for port in (70, 64):
            s.install('conn', reverse + (port,), 'rev_conn', (0,))
        self.send(s, 64, 14, vectors.packet(2, 100, 0, mss=1460))
        self.send(s, 9, 0xe7, vectors.packet(18, 900, 101, reverse=True, mss=1460))
        return s

    def send(self, source, port, kind, frame, epoch=17, wire_ack=0):
        return source.inject(port, struct.pack('!IIIBBH', epoch, wire_ack, 0, kind, 0, 0) + frame)

    def snapshot(self, s):
        import copy
        return copy.deepcopy(s.cells)

    def control_response(self, tail):
        _, user = rs.case4_padding.decode_frame(vectors.native_select(0, 3))
        objects = bytearray(user[3:])
        objects[17] = 0
        user = user[:2] + bytes((0x81, 0, 0)) + bytes(objects)
        return rs.case4_padding.build_frame(bytes.fromhex('05641c4401000a00'), user[:-7] + tail)

    def test_control_output_crc_matches_codec_for_complete_affine_basis(self):
        # Zero plus every input basis vector proves the affine 56-bit CRC map.
        # Random bodies also exercise the actual source hash and byte ordering.
        rng = random.Random(0)
        tails = [bytes(7), bytes((255,)) * 7]
        tails += [(1 << bit).to_bytes(7, 'little') for bit in range(56)]
        tails += [rng.getrandbits(56).to_bytes(7, 'little') for _ in range(256)]
        filler = bytes.fromhex('29032802002d010000')
        s = self.fresh()
        for tail in tails:
            with self.subTest(tail=tail.hex()):
                payload = self.control_response(tail)
                out = self.send(s, 9, 0xe3, vectors.packet(24, 901, 101, reverse=True, payload=payload))
                self.assertEqual(s.env['m.ctcrc1'], rs.case4_padding.rrc.dnp3_crc(tail + filler))
                self.assertEqual(s.env['m.cbadt'], 0)
                if s.valid.get('ctp1', False):
                    self.assertIsNotNone(out)
                    _, user = rs.case4_padding.decode_frame(out[54:])
                    self.assertEqual(user[16:32], tail + filler)

    def test_malformed_control_crc_cannot_commit_padded_image(self):
        for corruption in ('wire_crc', 'tail_body'):
            with self.subTest(corruption=corruption):
                s = self.fresh()
                payload = bytearray(self.control_response(bytes(7)))
                payload[-1 if corruption == 'wire_crc' else -4] ^= 1
                before = {name: list(s.cells[('', name)])
                          for name in ('img_start', 'img_end', 'img_wend')}
                out = self.send(s, 9, 0xe3,
                                vectors.packet(24, 901, 101, reverse=True, payload=bytes(payload)))
                self.assertEqual(s.env['m.cbadt'], 1)
                self.assertEqual(s.env['m.pad'], 0)
                self.assertFalse(s.valid.get('ctp1', False))
                self.assertEqual({name: s.cells[('', name)] for name in before}, before)
                self.assertIsNotNone(out)
                self.assertEqual(out[54:], payload)
                self.assertEqual(s.cells[('', 'acct')][0]['hi'], 37)

    def test_reverse_window_inverse_boundaries_and_modular_endpoints(self):
        s = self.fresh()
        rng = random.Random(1)
        cases = []
        # Both sides of every byte boundary within the fixed 58-byte image.
        for distance in range(1, 59):
            for window in sorted({0, distance - 1, distance, distance + 1, 65535}):
                cases.append((950, 901, 959, -distance, window))
                cases.append((0x20, 0xfffffff0, 0x90, -distance, window))
        for offset in (0, 1, 58, 0x7fffffff, 0x80000000, 0x80000001, -59, -65535):
            for window in (0, 1, 58, 65535):
                cases.append((950, 901, 959, offset, window))
        cases += [(rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(32),
                   rng.getrandbits(32), rng.getrandbits(16)) for _ in range(256)]
        for end, start, wire_end, offset, window in cases:
            with self.subTest(end=end, start=start, offset=offset, window=window):
                s.cells[('', 'img_end')][0] = end
                s.cells[('', 'img_start')][0] = start
                s.cells[('', 'img_wend')][0] = wire_end
                before = self.snapshot(s)
                raw = bytearray(vectors.packet(16, 101, (wire_end + offset) & 0xffffffff))
                raw[48:50] = struct.pack('!H', window)
                raw[50:52] = bytes(2)
                pseudo = raw[26:34] + bytes((0, 6)) + struct.pack('!H', len(raw) - 34)
                raw[50:52] = struct.pack('!H', vectors.checksum(pseudo + raw[34:]))
                out = self.send(s, 70, 0xe0, bytes(raw))
                offset &= 0xffffffff
                if offset < 0x80000000:
                    expected_ack, expected_window, result = (end + offset) & 0xffffffff, window, 9
                else:
                    distance = (-offset) & 0xffffffff
                    if distance > 58:
                        self.assertIsNone(out)
                        self.assertEqual(s.env['m.result'], 11)
                        self.assertEqual(s.cells, before)
                        continue
                    expected_ack, result = start, 10
                    if window < distance:
                        expected_window = 0
                    else:
                        endpoint = (end - start + window - distance) & 0xffffffff
                        expected_window = min(endpoint, 65535)
                self.assertIsNotNone(out)
                self.assertEqual(int.from_bytes(out[58:62], 'big'), expected_ack)
                self.assertEqual(int.from_bytes(out[64:66], 'big'), expected_window)
                self.assertEqual(s.env['m.result'], result)
                self.assertEqual(s.cells, before, 'normalization remains readonly')

    def test_normalize_reads_accounting_and_images_without_writes(self):
        s = self.fresh()
        before = self.snapshot(s)
        raw = vectors.packet(16, 101, 901)
        out = self.send(s, 70, 0xe0, raw, wire_ack=901)
        self.assertEqual(out[12], 0xe1)
        self.assertEqual(int.from_bytes(out[0:4], 'big'), 17)
        self.assertEqual(int.from_bytes(out[4:8], 'big'), 901)
        self.assertEqual(s.cells, before)

    def test_normalization_captures_untouched_ack_before_translation(self):
        s = self.fresh()
        before = self.snapshot(s)
        raw = vectors.packet(16, 101, 901)
        out = self.send(s, 70, 0xe0, raw, wire_ack=123)
        self.assertEqual(int.from_bytes(out[4:8], 'big'), 901)
        self.assertEqual(s.cells, before)

    def test_stale_qualified_ack_and_first_synack_do_not_mutate_mapping(self):
        s = self.fresh()
        for port, kind, frame, epoch in ((64, 0xe4, vectors.packet(16, 101, 901), 16),
                                        (9, 0xe7, vectors.packet(18, 900, 101, reverse=True, mss=1460), 17),
                                        (64, 14, vectors.packet(2, 99, 0, mss=1460), 16)):
            before = self.snapshot(s)
            self.assertIsNone(self.send(s, port, kind, frame, epoch))
            self.assertEqual(s.cells, before)

    def test_invalid_tcp_with_matching_poisoned_tuple_cannot_open_epoch(self):
        s = self.fresh()
        before = self.snapshot(s)
        frame = bytearray(vectors.packet(2, 4000, reverse=True, mss=1460))
        frame[23] = 17  # The parser accepts IPv4 without extracting TCP.
        raw = struct.pack('!IIIBBH', 18, 0, 0, 14, 0, 0) + bytes(frame)
        s.begin_pass(0)
        s.env['eg.egress_port'] = 9
        accepted, _ = s.packet_parser(raw)
        self.assertTrue(accepted)
        self.assertFalse(s.valid.get('tcp', False))
        # Invalid-header bits are unspecified. Give them a matching bound
        # tuple and a SYN so connection lookup hits despite TCP being invalid.
        s.env.update({'hdr.tcp.sport': vectors.SERVER_PORT,
                      'hdr.tcp.dport': vectors.CLIENT_PORT,
                      'hdr.tcp.flags': 2, 'hdr.tcp.seq': 4000, 'hdr.tcp.ack': 0})
        s.apply_control('Ingress')
        self.assertEqual(s.env['m.dir'], 1)
        self.assertEqual(s.cells, before)

    def test_unbound_tcp_cannot_write_epoch_even_for_open_kind(self):
        s = self.fresh()
        before = self.snapshot(s)
        frame = bytearray(vectors.packet(2, 4000, mss=1460))
        frame[34:36] = struct.pack('!H', vectors.CLIENT_PORT + 1)
        for epoch in (18, 0x7fffffff, 0x80000000, 0xffffffff):
            self.send(s, 70, 14, bytes(frame), epoch)
            self.assertEqual(s.env['m.dir'], 0)
            self.assertEqual(s.cells, before)

    def test_first_latch_rejects_zero_and_encoded_epoch_inputs(self):
        s = self.fresh()
        self.assertEqual(s.cells[('', 'epoch')][0], 0x80000011)
        synack = vectors.packet(18, 900, 101, reverse=True, mss=1460)
        for epoch in (0, 0x80000011, 0x7fffffff, 0xffffffff):
            before = self.snapshot(s)
            self.assertIsNone(self.send(s, 9, 0xe7, synack, epoch))
            self.assertEqual(s.cells, before)

    def test_commit_uses_original_wire_ack_once_without_reverse_translation(self):
        s = self.fresh()
        s.cells[('', 'acct')][0] = {'lo': 959, 'hi': 58}
        raw = vectors.packet(16, 136, 938)
        out = self.send(s, 64, 0xe4, raw, wire_ack=959)
        self.assertEqual(out, raw)
        self.assertEqual(s.cells[('', 'acct')][0], {'lo': 959, 'hi': 0})

    def test_unbound_normalization_returns_native_packet_through_trusted_lap(self):
        s = ESource(make_e.generate())
        frame = vectors.packet(16, 101, 901)
        out = self.send(s, 70, 0xe0, frame)
        self.assertEqual(out[12], 0xe1)
        self.assertEqual(out[16:], frame)

    def test_e_epoch_exhaustion_and_duplicate_close_are_fail_closed(self):
        s = self.fresh()
        close = vectors.packet(20, 101, 901)
        self.send(s, 64, 13, close, wire_ack=901)
        before = self.snapshot(s)
        self.send(s, 64, 13, close, wire_ack=901)
        self.assertEqual(s.cells, before)
        syn = vectors.packet(2, 4000, mss=1460)
        synack = vectors.packet(18, 7000, 4001, reverse=True, mss=1460)
        self.assertIsNotNone(self.send(s, 64, 14, syn, epoch=0x7ffffffe))
        self.assertIsNotNone(self.send(s, 9, 0xe7, synack, epoch=0x7ffffffe))
        before = self.snapshot(s)
        for epoch in (17, 0x7ffffffe, 0x7fffffff, 0x80000000, 0xffffffff):
            self.assertIsNone(self.send(s, 64, 14, syn, epoch=epoch))
            self.assertEqual(s.cells, before)
        self.assertIsNone(self.send(s, 64, 13, close, epoch=17, wire_ack=901))
        self.assertEqual(s.cells, before)


if __name__ == '__main__':
    unittest.main()
