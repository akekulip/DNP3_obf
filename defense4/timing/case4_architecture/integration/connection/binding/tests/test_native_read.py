"""Native READ kinds 9 (request), 10 (ack), 11 (response): whole-program, source-level.

Frames are real Ethernet/IPv4/TCP/DNP3 bytes (checksums, link CRCs and application CRCs from the
framework helpers). A passing packet is held by the private four-pass work protocol and leaves N
unchanged behind a 16-byte `tev` (epoch32, wgen32, t0q32, kind8, stage8, reserved16), addressed to
the handoff port. This is source-level evidence, not compiler or target evidence.
"""
import re
import unittest

import read_support as rs
from read_support import ReadPipeline

HANDOFF = rs.handoff_port() if rs.SOURCE.exists() and 'READ_HANDOFF_PORT' in rs.SOURCE.read_text() else None
OWNER_IDLE, OWNER_OUTSTANDING = 0x50001, 0xe0001


def expect_tev(case, pipe, out, frame, kind, wgen=1):
    case.assertFalse(out.dropped, out.drop_reason)
    case.assertEqual(out.passes, 4)
    case.assertEqual(len(out.emitted), 1)
    port, data = out.emitted[0]
    case.assertEqual(port, HANDOFF)
    t0q = int.from_bytes(data[8:12], 'big')
    case.assertEqual(t0q & 0xff, 0, 'low 8 bits of t0q are zero')
    case.assertEqual(t0q, (rs.T0_BASE + 0x5b) & 0xffffff00, 't0q is the pass-0 timestamp, not a later pass')
    case.assertEqual(data, rs.tev(17, wgen, t0q, kind) + frame, 'tev then the original, byte for byte')
    return t0q


class ReadTransitions(unittest.TestCase):
    def test_request_claims_5_13_publishes_14_and_hands_off_the_unchanged_original(self):
        frame = rs.request_packet(app=0xc3)
        pipe = ReadPipeline().start(OWNER_IDLE, 1000, 2000)
        out = pipe.inject(rs.IN_CLIENT, frame)
        expect_tev(self, pipe, out, frame, 9)
        state = pipe.state()
        self.assertEqual(state['owner'], OWNER_OUTSTANDING)
        self.assertEqual(state['client'], 1020)
        self.assertEqual(pipe.read_app(), 3)
        trace = pipe.trace_text(out)
        self.assertIn('table owner_command -> claim_read ', trace)
        self.assertIn('table owner_command -> publish_read ', trace)
        self.assertEqual(state['work']['phase'], 4)

    def test_ack_is_nonmutating_at_14_and_hands_off(self):
        frame = rs.ack_packet()
        pipe = ReadPipeline().start(OWNER_OUTSTANDING, 1020, 2000)
        before = pipe.state()
        out = pipe.inject(rs.IN_SERVER, frame)
        expect_tev(self, pipe, out, frame, 10)
        after = pipe.state()
        for key in ('owner', 'client', 'server', 'epoch'):
            self.assertEqual(after[key], before[key], key)
        self.assertNotIn('table owner_command -> ', pipe.trace_text(out).replace('owner_command -> NoAction', ''))

    def test_response_claims_14_15_publishes_5_and_hands_off(self):
        frame = rs.response_packet(app=0xc3)
        pipe = ReadPipeline().start(OWNER_OUTSTANDING, 1020, 2000, app=3)
        out = pipe.inject(rs.IN_SERVER, frame)
        expect_tev(self, pipe, out, frame, 11)
        state = pipe.state()
        self.assertEqual(state['owner'], OWNER_IDLE)
        self.assertEqual(state['server'], 2049)
        self.assertEqual(state['client'], 1020)
        trace = pipe.trace_text(out)
        self.assertIn('table owner_command -> claim_read_rsp ', trace)
        self.assertIn('table owner_command -> publish_read_rsp ', trace)

    def test_full_exchange_on_one_pipeline_returns_to_idle_and_tevs_are_ordered(self):
        pipe = ReadPipeline().start(OWNER_IDLE, 1000, 2000)
        kinds = []
        for port, frame, kind in ((rs.IN_CLIENT, rs.request_packet(app=0xc5), 9),
                                  (rs.IN_SERVER, rs.ack_packet(), 10),
                                  (rs.IN_SERVER, rs.response_packet(app=0xc5), 11)):
            out = pipe.inject(port, frame)
            expect_tev(self, pipe, out, frame, kind, wgen=len(kinds) + 1)
            kinds.append(kind)
        self.assertEqual(pipe.state()['owner'], OWNER_IDLE)
        self.assertEqual((pipe.state()['client'], pipe.state()['server']), (1020, 2049))

    def test_read_never_enters_the_select_operate_binding_chain(self):
        pipe = ReadPipeline().start(OWNER_IDLE, 1000, 2000)
        banks = pipe.banks()
        for port, frame in ((rs.IN_CLIENT, rs.request_packet()), (rs.IN_SERVER, rs.ack_packet()),
                            (rs.IN_SERVER, rs.response_packet())):
            out = pipe.inject(port, frame)
            trace = pipe.trace_text(out)
            for table in ('real_links_t', 'real_tcp_dst_t', 'application_t', 'object_match',
                          'compare_response_inputs_t', 'compare_select_inputs_t', 'compare_operate_inputs_t',
                          'calculate_native_end_t'):
                self.assertNotIn('table %s ' % table, trace, table)
            self.assertEqual(pipe.banks(), banks)


class ReadNeverMutates(unittest.TestCase):
    def untouched(self, pipe, before, out):
        after = pipe.state()
        for key in ('owner', 'client', 'server', 'epoch'):
            self.assertEqual(after[key], before[key], key)
        self.assertEqual(after['work']['phase'], 4, 'work pin released')

    def passthrough(self, frame, port, owner=OWNER_IDLE, client=1000, server=2000):
        pipe = ReadPipeline().start(owner, client, server)
        before, app = pipe.state(), pipe.read_app()
        out = pipe.inject(port, frame)
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(out.passes, 1)
        self.assertEqual(out.emitted, [(2 if port == rs.IN_CLIENT else 1, frame)])
        self.assertEqual(pipe.state()['counter'], before['counter'])
        self.untouched(pipe, before, out)
        self.assertEqual(pipe.read_app(), app)

    def test_foreign_tuple_is_passed_untouched(self):
        import vectors
        frame = vectors.packet(24, 1000, 2000, payload=rs.request_frame(), tuple4=(rs.CLIENT, rs.SERVER, 30002, rs.SPORT))
        self.passthrough(frame, rs.IN_CLIENT)

    def test_foreign_link_address_is_passed_untouched_even_with_valid_crcs(self):
        for kwargs in (dict(dst=0x0001), dict(src=0x0101)):
            self.passthrough(rs.request_packet(**kwargs), rs.IN_CLIENT)
        for kwargs in (dict(dst=0x0101), dict(src=0x0001)):
            self.passthrough(rs.response_packet(**kwargs), rs.IN_SERVER, OWNER_OUTSTANDING, 1020, 2000)

    def test_every_bad_crc_is_passed_untouched(self):
        for build, offset_list, owner, port, client, server in (
                (rs.request_packet, (8, 18), OWNER_IDLE, rs.IN_CLIENT, 1000, 2000),
                (rs.response_packet, (8, 26, 44, 47), OWNER_OUTSTANDING, rs.IN_SERVER, 1020, 2000)):
            good = bytearray(build())
            for offset in offset_list:
                bad = bytearray(good)
                bad[54 + offset] ^= 1                      # 14 eth + 20 ip + 20 tcp
                bad = self.repair_tcp(bytes(bad))
                self.passthrough(bad, port, owner, client, server)

    @staticmethod
    def repair_tcp(raw):
        import vectors
        ip_len = 20
        pseudo = raw[26:34] + bytes([0, 6]) + (len(raw) - 34).to_bytes(2, 'big')
        tcp = bytearray(raw[34:])
        tcp[16:18] = b'\0\0'
        tcp[16:18] = vectors.checksum(pseudo + bytes(tcp)).to_bytes(2, 'big')
        return raw[:34] + bytes(tcp)

    def test_wrong_application_sequence_response_is_denied_without_owner_or_server_change(self):
        pipe = ReadPipeline().start(OWNER_OUTSTANDING, 1020, 2000, app=3)
        before = pipe.state()
        out = pipe.inject(rs.IN_SERVER, rs.response_packet(app=0xc4))
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])
        self.untouched(pipe, before, out)
        self.assertEqual(pipe.read_app(), 3)

    def test_request_outside_idle_owner_state_is_denied_without_mutation(self):
        for owner in (0x40001, 0x90001, 0xe0001, 0x0, 0x60001):
            pipe = ReadPipeline().start(owner, 1000, 2000)
            before = pipe.state()
            out = pipe.inject(rs.IN_CLIENT, rs.request_packet())
            self.assertTrue(out.dropped, hex(owner))
            self.assertEqual(out.emitted, [])
            self.untouched(pipe, before, out)

    def test_out_of_sequence_request_and_response_are_denied_without_mutation(self):
        pipe = ReadPipeline().start(OWNER_IDLE, 999, 2000)
        before = pipe.state()
        self.assertTrue(pipe.inject(rs.IN_CLIENT, rs.request_packet()).dropped)
        self.untouched(pipe, before, None)
        pipe = ReadPipeline().start(OWNER_OUTSTANDING, 1020, 1999, app=0)
        before = pipe.state()
        self.assertTrue(pipe.inject(rs.IN_SERVER, rs.response_packet()).dropped)
        self.untouched(pipe, before, None)

    def test_foreign_epoch_on_a_private_pass_never_mutates_the_owner(self):
        import struct
        raw = rs.request_packet()
        # A private pass-1 frame (stage 1, kind 9) whose epoch (18) is not the installed epoch (17).
        envelope = struct.pack('>IIIHH', 18, 1, OWNER_IDLE, 0x0109, 0) + struct.pack('>I', rs.T0_BASE & 0xffffff00)
        pipe = ReadPipeline().start(OWNER_IDLE, 1000, 2000, work=(1, 1))
        before = pipe.state()
        out = pipe.inject(68, envelope + raw)
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])
        self.assertEqual(pipe.state()['owner'], before['owner'])
        self.assertEqual(pipe.state()['client'], before['client'])
        self.assertEqual(pipe.read_app(), 0)
        self.assertEqual(pipe.state()['work']['phase'], 4, 'abort passes release the work pin')

    def test_ack_without_an_outstanding_read_is_forwarded_unchanged(self):
        for owner, client, server in ((OWNER_IDLE, 1020, 2000), (OWNER_OUTSTANDING, 1019, 2000), (OWNER_OUTSTANDING, 1020, 1999)):
            frame = rs.ack_packet()
            pipe = ReadPipeline().start(owner, client, server)
            before = pipe.state()
            out = pipe.inject(rs.IN_SERVER, frame)
            self.assertFalse(out.dropped, out.drop_reason)
            self.assertEqual(out.emitted, [(rs.IN_CLIENT, frame)])
            self.assertEqual(out.passes, 4)
            self.untouched(pipe, before, out)


class ReadStructure(unittest.TestCase):
    def setUp(self):
        self.text = rs.SOURCE.read_text()

    def test_network_admits_every_read_private_pass(self):
        for kind, flags_ok in ((9, (16, 24)), (10, (16,)), (11, (16, 24))):
            for flags in (2, 18, 16, 24, 17, 20, 4):
                self.assertEqual(bool(re.search(r'\(8w1,8w%d,8w%d,false,16w0xffeb' % (kind, flags), self.text)),
                                 flags in flags_ok, (kind, flags))

    def test_selectop_chain_predicates_are_explicit_not_ordered(self):
        body = self.text[self.text.index(' apply{\n  m.return_abort='):]
        self.assertNotIn('m.packet_kind>=8w5', body)
        self.assertNotIn('m.packet_kind>8w', body)

    def test_event_values_and_parser_selectors_exist(self):
        for event in ('0109', '010a', '010b', '0209', '020a', '020b', '0309', '030a', '030b'):
            self.assertIn('16w0x%s:' % event, self.text)
        self.assertIn('16w60', self.text)
        self.assertIn('16w89', self.text)


if __name__ == '__main__':
    unittest.main()
