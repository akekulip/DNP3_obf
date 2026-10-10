"""The response-only N (core/response_only/n_response_only.p4), whole-program source level.

Runs through the same connection-binding harness as connection/binding/tests/test_step3_exchange.py
(read_support.ReadPipeline), on the execution document's native-coordinate exchange vector:

  SELECT    client SEQ 101, length 35, end 136
  response  server SEQ 901, length 37, ACK 136, end 938
  OPERATE   client SEQ 136, length 35, ACK 938 (already normalized), end 171
  response  server SEQ 938, length 37, ACK 171, end 975

Packets here enter N on plain `route` rows, i.e. as N sees them after N_ACK_RETURN normalization. The
normalization early route itself is tested separately (a `route_master` row). Source-level only: not the
compiler, the model or hardware.
"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RO = HERE.parent
BINDING_TESTS = RO.parent.parent / 'connection' / 'binding' / 'tests'
sys.path[:0] = [str(RO), str(BINDING_TESTS)]
import cp  # noqa: E402
import make_e  # noqa: E402
import make_n  # noqa: E402
import response_path_cp as rp  # noqa: E402  (protocol/, on cp's path)
import read_support as rs  # noqa: E402
import vectors  # noqa: E402  (core/harness, on read_support's path)
from read_support import ReadPipeline, assert_invariants, drop_runtime  # noqa: E402
import case4_padding as codec  # noqa: E402

SELECT_SEQ, SERVER_SEQ = 101, 901
OWNER = {'after_ack': 0x40001, 'select': 0x90001, 'response': 0xa0001, 'operate': 0xc0001, 'idle': 0x50001}
N_ACK_RETURN = 70
TEXT = make_n.generate()


def native_response37(app=0, fc=3, status=0):
    """The 37-byte native response to the unexpanded 35-byte SELECT (fc 3) / OPERATE (fc 4): 0x81, the
    request's own object block echoed, no decoy. Link header length 0x1c = 5 + 23 user bytes."""
    _head, user = codec.decode_frame(vectors.native_select(app, fc))
    objects = bytearray(user[3:])
    objects[17] = status
    return codec.build_frame(bytes.fromhex('05641c4401000a00'), user[:2] + bytes((0x81, 0, 0)) + bytes(objects))


def select_packet(app=0, seq=SELECT_SEQ, ack=SERVER_SEQ):
    return vectors.packet(24, seq, ack, payload=vectors.native_select(app, 3))


def response1(app=0, seq=SERVER_SEQ, ack=SELECT_SEQ + 35):
    return vectors.packet(24, seq, ack, reverse=True, payload=native_response37(app, 3))


def operate_packet(app=1, seq=SELECT_SEQ + 35, ack=SERVER_SEQ + 37):
    return vectors.packet(24, seq, ack, payload=vectors.native_select(app, 4))


def response2(app=1, seq=SERVER_SEQ + 37, ack=SELECT_SEQ + 70):
    return vectors.packet(24, seq, ack, reverse=True, payload=native_response37(app, 4))


MASTER = rp.Endpoint('10.0.0.1', vectors.CLIENT_PORT, rs.IN_CLIENT)        # vectors.CLIENT
OUTSTATION = rp.Endpoint('10.0.0.2', vectors.SERVER_PORT, rs.IN_SERVER)    # vectors.SERVER


def fresh():
    """Every test runs with port-bound connection rows from cp.py (not the driver's wildcard column), so
    the direction-provenance check is exercised by the whole suite. The master's packets are injected as
    already normalized, on its own port; lap_pipe() moves forward provenance to N_ACK_RETURN."""
    pipe = ReadPipeline(text=TEXT).start(OWNER['after_ack'], SELECT_SEQ, SERVER_SEQ)
    drop_runtime(pipe, 'connection')
    cp.install_ingress(pipe.src, cp.n_connection_rows(OUTSTATION, MASTER, master_ingress=rs.IN_CLIENT))
    return pipe


class NativeExchange(unittest.TestCase):
    def step(self, pipe, port, frame, owner_after, client=None, server=None):
        out = pipe.inject(port, frame)
        assert_invariants(self, pipe, out, frame)
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(out.passes, 4)
        if owner_after == OWNER['operate']:
            self.assertEqual([p for p, _ in out.emitted], [rs.handoff_port()], 'admitted OPERATE goes to T')
            self.assertEqual(out.emitted[0][1][16:], frame)
            self.assertEqual(out.emitted[0][1][12], 12, 'tev kind = T KIND_OPERATE')
        else:
            self.assertEqual(out.emitted, [(2 if port == rs.IN_CLIENT else 1, frame)], 'native frame forwarded unchanged')
        state = pipe.state()
        self.assertEqual(state['owner'], owner_after)
        if client is not None:
            self.assertEqual(state['client'], client)
        if server is not None:
            self.assertEqual(state['server'], server)
        return out

    def test_vector_lengths(self):
        self.assertEqual(len(vectors.native_select(0, 3)), 35)
        self.assertEqual(len(native_response37(0, 3)), 37)

    def test_document_vector_select_response_operate_response_ends_idle(self):
        pipe = fresh()
        self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'], client=136)
        self.step(pipe, rs.IN_SERVER, response1(), OWNER['response'], server=938)
        self.step(pipe, rs.IN_CLIENT, operate_packet(), OWNER['operate'], client=171)
        self.step(pipe, rs.IN_SERVER, response2(), OWNER['idle'], client=171, server=975)

    def test_response_must_ack_the_native_select_end(self):
        """136 accepted; the legacy +20 position 156 refused."""
        for ack, ok in ((SELECT_SEQ + 35, True), (SELECT_SEQ + 55, False), (SELECT_SEQ + 35 + 1, False)):
            pipe = fresh()
            self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
            out = pipe.inject(rs.IN_SERVER, response1(ack=ack))
            self.assertEqual(out.dropped, not ok, ack)
            self.assertEqual(pipe.state()['owner'], OWNER['response'] if ok else OWNER['select'])

    def test_operate_must_ack_the_native_response_end(self):
        """ACK 938 (normalized) accepted; the padded 959 and the legacy 958 refused."""
        for ack, ok in ((SERVER_SEQ + 37, True), (SERVER_SEQ + 58, False), (SERVER_SEQ + 57, False)):
            pipe = fresh()
            self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
            self.step(pipe, rs.IN_SERVER, response1(), OWNER['response'])
            out = pipe.inject(rs.IN_CLIENT, operate_packet(ack=ack))
            self.assertEqual(out.dropped, not ok, ack)

    def test_second_response_needs_the_operate_application_sequence(self):
        for app in (0, 2):
            pipe = fresh()
            self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
            self.step(pipe, rs.IN_SERVER, response1(), OWNER['response'])
            self.step(pipe, rs.IN_CLIENT, operate_packet(), OWNER['operate'])
            self.assertTrue(pipe.inject(rs.IN_SERVER, response2(app=app)).dropped, app)
            self.assertEqual(pipe.state()['owner'], OWNER['operate'])

    def test_shared_crc_table_still_refuses_bad_head_and_first_block_crcs(self):
        """crc_t replaced five CRC tables; a flipped link-header CRC (payload 8) or first-block CRC
        (payload 26) must still be refused on the request and on the response."""
        def flip(payload, at):
            out = bytearray(payload)
            out[at] ^= 0x01
            return bytes(out)
        for at in (8, 26):
            pipe = fresh()
            bad = vectors.packet(24, SELECT_SEQ, SERVER_SEQ, payload=flip(vectors.native_select(0, 3), at))
            pipe.inject(rs.IN_CLIENT, bad)
            self.assertEqual(pipe.state()['owner'], OWNER['after_ack'], ('select', at))
            pipe = fresh()
            self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
            bad = vectors.packet(24, SERVER_SEQ, SELECT_SEQ + 35, reverse=True, payload=flip(native_response37(0, 3), at))
            pipe.inject(rs.IN_SERVER, bad)
            self.assertEqual(pipe.state()['owner'], OWNER['select'], ('response', at))

    def test_refused_select_never_advances_n(self):
        """Review C1: a SELECT response with non-zero CROB status (the outstation refused it) is not a bound
        response; N stays in select and a following OPERATE is not admitted."""
        for status in (1, 2, 4, 0x7f):
            pipe = fresh()
            self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
            refused = vectors.packet(24, SERVER_SEQ, SELECT_SEQ + 35, reverse=True,
                                     payload=native_response37(0, 3, status=status))
            pipe.inject(rs.IN_SERVER, refused)
            self.assertEqual(pipe.state()['owner'], OWNER['select'], status)
            out = pipe.inject(rs.IN_CLIENT, operate_packet())
            self.assertNotIn(rs.handoff_port(), [p for p, _ in out.emitted], status)

    def test_legacy_57_byte_response_is_not_a_bound_response(self):
        pipe = fresh()
        self.step(pipe, rs.IN_CLIENT, select_packet(), OWNER['select'])
        legacy = vectors.packet(24, SERVER_SEQ, SELECT_SEQ + 55, reverse=True, payload=vectors.native_response())
        pipe.inject(rs.IN_SERVER, legacy)
        self.assertEqual(pipe.state()['owner'], OWNER['select'])


ANY = (0, 0)


def lap_pipe(reverse_order=False):
    """fresh() with the response-only control plane's real ports and connection rows (core/response_only/cp.py)."""
    pipe = fresh()
    drop_runtime(pipe, 'ports')
    drop_runtime(pipe, 'connection')
    rows = cp.n_ports_rows(MASTER.dev_port, OUTSTATION.dev_port) + cp.n_connection_rows(OUTSTATION, MASTER)
    cp.install_ingress(pipe.src, list(reversed(rows)) if reverse_order else rows)
    return pipe


class Normalization(unittest.TestCase):
    """N_ACK_RETURN lap. Every master-side IPv4 TCP packet leaves on N_ACK_RETURN after one pass, unchanged,
    with no N state touched; re-entering on N_ACK_RETURN it is admitted (forward direction is granted only
    there). Rows come from cp.py with explicit $MATCH_PRIORITY."""

    def assert_lap(self, pipe, frame):
        before = pipe.state()
        out = pipe.inject(rs.IN_CLIENT, frame)
        self.assertEqual(out.passes, 1)
        self.assertEqual(out.emitted, [(N_ACK_RETURN, frame)])
        self.assertEqual(pipe.state(), before, 'no N state mutated on the normalization pass')

    def test_endpoints_match_the_harness_topology(self):
        flows = vectors.topology().flows
        self.assertIn((MASTER.ip_int, OUTSTATION.ip_int, MASTER.port, OUTSTATION.port, 'forward', OUTSTATION.dev_port), flows)

    def test_master_ack_bearing_packet_takes_the_lap(self):
        self.assert_lap(lap_pipe(), select_packet())

    def test_master_segment_of_an_unparsed_length_takes_the_lap(self):
        """Review C2: N's parser does not extract TCP at this IP length; the mapper must still see it."""
        frame = vectors.packet(16, SELECT_SEQ, SERVER_SEQ + 37, payload=bytes(range(10)))
        self.assert_lap(lap_pipe(), frame)

    def test_master_syn_takes_the_lap(self):
        self.assert_lap(lap_pipe(), vectors.packet(2, SELECT_SEQ - 1, 0, mss=1460))

    def test_master_non_tcp_is_routed_without_the_lap(self):
        frame = bytearray(select_packet())
        frame[23] = 17   # IP protocol UDP
        out = lap_pipe().inject(rs.IN_CLIENT, bytes(frame))
        self.assertNotIn(N_ACK_RETURN, [p for p, _ in out.emitted])

    def test_from_n_ack_return_the_packet_is_admitted(self):
        pipe = lap_pipe()
        out = pipe.inject(N_ACK_RETURN, select_packet())
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(out.emitted, [(rs.IN_SERVER, select_packet())])
        self.assertEqual(pipe.state()['owner'], OWNER['select'])

    def test_unparsed_segment_after_the_lap_is_forwarded_natively(self):
        pipe = lap_pipe()
        before = pipe.state()
        frame = vectors.packet(16, SELECT_SEQ, SERVER_SEQ, payload=bytes(range(10)))
        out = pipe.inject(N_ACK_RETURN, frame)
        self.assertEqual(out.emitted, [(rs.IN_SERVER, frame)])
        self.assertEqual(pipe.state()['owner'], before['owner'])

    def test_priority_not_install_order_decides(self):
        """Review W1: the same rows installed in reverse order behave identically."""
        self.assert_lap(lap_pipe(reverse_order=True), select_packet())
        pipe = lap_pipe(reverse_order=True)
        out = pipe.inject(N_ACK_RETURN, select_packet())
        self.assertEqual(out.emitted, [(rs.IN_SERVER, select_packet())])

    def test_ternary_row_without_priority_is_rejected(self):
        """Also with plain-integer terms: the table has ternary keys, so the hardware needs a priority."""
        pipe = fresh()
        for keys in ((rs.IN_CLIENT, (1, 1), (6, 0xff)), (rs.IN_CLIENT, 1, 6)):
            with self.assertRaises(ValueError):
                pipe.src.install('ports', keys, 'normalize_ack', ())

    def test_a_wrong_normalize_row_on_n_ack_return_cannot_loop(self):
        """Review W2: the P4 itself drops a non-route packet on N_ACK_RETURN, whatever the rows say."""
        pipe = lap_pipe()
        pipe.src.install('ports', (N_ACK_RETURN, (1, 1), (6, 0xff)), 'normalize_ack', (), priority=0)
        out = pipe.inject(N_ACK_RETURN, select_packet())
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])

    def test_a_mistaken_route_to_n_ack_return_cannot_loop(self):
        """W2 residual 1: a (70, *, *) -> route(70) row takes a route (port_valid = 1), so only the head
        gateway on the ports target stops it re-entering on 70 forever."""
        pipe = lap_pipe()
        pipe.src.install('ports', (N_ACK_RETURN, ANY, ANY), 'route', (N_ACK_RETURN,), priority=0)
        for frame in (select_packet(), vectors.packet(16, SELECT_SEQ, SERVER_SEQ, payload=bytes(range(10)))):
            out = pipe.inject(N_ACK_RETURN, frame)
            self.assertTrue(out.dropped)
            self.assertEqual((out.passes, out.emitted), (1, []))

    def test_a_connection_rewrite_to_n_ack_return_cannot_loop(self):
        """Follow-up review: connection's own forward_flow can set the egress port AFTER the head guard. With
        a (bypassing cp.check_no_loop) forward_flow(70) row, a bound SELECT re-entering on 70 runs N's passes
        and is dropped at the tail instead of leaving on 70; the same packet with the correct row is
        admitted and forwarded (the guard does not fire on legitimate traffic)."""
        key = (MASTER.ip_int, OUTSTATION.ip_int, MASTER.port, OUTSTATION.port)
        pipe = lap_pipe()
        drop_runtime(pipe, 'connection')
        for port in (N_ACK_RETURN, 68):
            pipe.src.install('connection', key + (port,), 'forward_flow', (N_ACK_RETURN,))
        out = pipe.inject(N_ACK_RETURN, select_packet())
        self.assertTrue(out.dropped, out.drop_reason)
        self.assertNotIn(N_ACK_RETURN, [p for p, _ in out.emitted])
        good = lap_pipe().inject(N_ACK_RETURN, select_packet())
        self.assertEqual(good.emitted, [(rs.IN_SERVER, select_packet())])

    def test_generation_zero_envelope_on_return_port_cannot_loop(self):
        """W2 residual 2: an envelope with epoch 0 on RETURN_PORT parses with m.stage == 0 and is dropped."""
        out = lap_pipe().inject(68, bytes(4) + select_packet())
        self.assertTrue(out.dropped)
        self.assertEqual((out.passes, out.emitted), (1, []))

    def test_control_plane_refuses_rows_that_target_n_ack_return(self):
        good = cp.n_ports_rows(MASTER.dev_port, OUTSTATION.dev_port)
        k = (('ig.ingress_port', N_ACK_RETURN), ('hdr.ip.$valid', ANY), ('hdr.ip.proto', ANY))
        for bad in (('Ingress.ports', k, 'Ingress.route', (('port', N_ACK_RETURN),), 0),
                    ('Ingress.ports', k, 'Ingress.normalize_ack', (), 0),
                    ('Ingress.ports', (('ig.ingress_port', 68),) + k[1:], 'Ingress.route', (('port', 2),), 0)):
            with self.assertRaises(ValueError):
                cp.check_no_loop(good + [bad])
        with self.assertRaises(ValueError):
            cp.n_connection_rows(OUTSTATION, rp.Endpoint('10.0.0.1', vectors.CLIENT_PORT, N_ACK_RETURN))

    def test_outstation_tuple_on_n_ack_return_gets_no_direction(self):
        """Review C3: a response forged on the master link (so it re-enters on N_ACK_RETURN) is not admitted
        as the outstation's response and never reaches the master; the same bytes from the outstation are."""
        pipe = lap_pipe()
        pipe.inject(N_ACK_RETURN, select_packet())
        self.assertEqual(pipe.state()['owner'], OWNER['select'])
        out = pipe.inject(N_ACK_RETURN, response1())
        self.assertEqual(pipe.state()['owner'], OWNER['select'])
        self.assertNotIn(rs.IN_CLIENT, [p for p, _ in out.emitted])
        out = pipe.inject(rs.IN_SERVER, response1())
        self.assertEqual(pipe.state()['owner'], OWNER['response'])
        self.assertEqual(out.emitted, [(rs.IN_CLIENT, response1())])

    def test_ports_table_is_the_only_normalization_site(self):
        self.assertEqual(TEXT.count('normalize_ack'), 2, 'declared once, listed once in ports.actions')
        self.assertNotIn('m.normalize', TEXT)


class EgressProvenance(unittest.TestCase):
    """Review C3, E side (source text and rows; E's egress is not run by this interpreter -- the model run is)."""

    def test_e_conn_is_keyed_on_egress_port(self):
        self.assertIn('hdr.tcp.dport : exact; eg.egress_port : exact; }', make_e.generate())

    def test_tcp_checksum_sums_only_the_padding_header_that_is_present(self):
        """make_e.py edit 3 (model run route_ab_01/response_only_07/model_03: c111 instead of c496). Three
        mutually exclusive single-term updates; an absent padding header is never summed."""
        text = make_e.generate()
        dep = text[text.index('control EgDeparser'):]
        blocks = {}
        for cond in ('m.changed == 1w1', 'hdr.rtp.isValid()', 'hdr.ctp1.isValid()'):
            start = dep.index('if (%s) {' % cond)
            blocks[cond] = dep[start:dep.index('m.residual});', start)]
        self.assertEqual(dep.count('hdr.tcp.checksum ='), 3)
        self.assertNotIn('hdr.rtp.', blocks['m.changed == 1w1'])
        self.assertNotIn('hdr.ctp', blocks['m.changed == 1w1'])
        self.assertIn('hdr.rtp.filler', blocks['hdr.rtp.isValid()'])
        self.assertNotIn('hdr.ctp', blocks['hdr.rtp.isValid()'])
        self.assertIn('hdr.ctp2.filler_b', blocks['hdr.ctp1.isValid()'])
        self.assertNotIn('hdr.rtp.', blocks['hdr.ctp1.isValid()'])
        # exclusivity: a padded (pad = 1) verdict no longer sets m.changed
        for action in ('out_commit', 'out_replay'):
            body = text[text.index('action %s()' % action):]
            body = body[:body.index('}')]
            self.assertIn('m.pad = 1', body)
            self.assertNotIn('m.changed', body)

    def test_fwd_only_at_master_port_rev_only_at_n_ack_return(self):
        rows = [r for r in cp.e_conn_rows(0, OUTSTATION, MASTER) if r[0] == 'Egress.conn']
        got = {r[2]: dict(r[1])['eg.egress_port'] for r in rows}
        self.assertEqual(got, {'Egress.fwd_conn': MASTER.dev_port, 'Egress.rev_conn': N_ACK_RETURN})
        fwd = dict(next(r[1] for r in rows if r[2] == 'Egress.fwd_conn'))
        self.assertEqual((fwd['hdr.ip.src'], fwd['hdr.tcp.sport']), (OUTSTATION.ip_int, OUTSTATION.port))


if __name__ == '__main__':
    unittest.main()
