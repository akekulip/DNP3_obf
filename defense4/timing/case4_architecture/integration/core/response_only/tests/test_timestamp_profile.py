"""N admits the real stack's TCP profile (make_n.py edit 9), tested with the capture's own bytes.

Source-level run of N alone, rows from cp.py for the capture's own endpoints. A master frame takes the lap
(master port -> N_ACK_RETURN) and is then injected on N_ACK_RETURN; E's reverse pass in between leaves a
native connection's bytes alone, and is not run here (the model run of the composite covers it).
"""
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RO = HERE.parent
sys.path[:0] = [str(RO), str(RO.parent.parent / 'connection' / 'binding' / 'tests')]
import cp  # noqa: E402
import make_n  # noqa: E402
import real_profile as rp_  # noqa: E402
import response_path_cp as rp  # noqa: E402
import read_support as rs  # noqa: E402
import vectors  # noqa: E402
from read_support import ReadPipeline, drop_runtime  # noqa: E402

TEXT = make_n.generate()
MASTER = rp.Endpoint(rp_.MASTER_IP, rp_.MASTER_TCP, 9)
RELAY = rp.Endpoint(rp_.RELAY_IP, rp_.RELAY_TCP, 64)
LAP, T_IN = cp.N_ACK_RETURN, rs.handoff_port(TEXT)
PHASE = {'syn': 0x2, 'synack': 0x4, 'idle': 0x5, 'read': 0xe, 'closed': 0x7}
KIND_RESET = int(__import__('re').search(r'const\s+bit<8>\s+KIND_RESET\s*=\s*(\d+)',
                (RO.parent.parent / 'read' / 'read_queue_timing.p4').read_text())[1])   # T's own value
KIND = {'request': 9, 'ack': 10, 'response': 11, 'reset': KIND_RESET}


def pipe():
    p = ReadPipeline(text=TEXT)
    for table in ('ports', 'connection', 'read_connection', 'data_connection'):
        drop_runtime(p, table)
    cp.install_ingress(p.src, cp.n_ports_rows(MASTER.dev_port, RELAY.dev_port) + cp.n_connection_rows(RELAY, MASTER)
                       + cp.n_read_rows(RELAY, MASTER))
    for key in ((MASTER.ip_int, RELAY.ip_int, MASTER.port, RELAY.port), (RELAY.ip_int, MASTER.ip_int, RELAY.port, MASTER.port)):
        p.src.install('data_connection', key, 'configure', vectors.decoy_config())
    return p


def send(p, master, frame):
    """One endpoint frame through N. Returns the pipeline outcome of the admitting pass sequence."""
    if not master:
        return p.inject(RELAY.dev_port, frame)
    lap = p.inject(MASTER.dev_port, frame)
    assert (lap.passes, lap.emitted) == (1, [(LAP, frame)]), (lap.passes, lap.emitted, lap.drop_reason)
    return p.inject(LAP, frame)


def phase(p):
    return p.state()['owner'] >> 16


def handoff(out, frame):
    """(kind, stage) of the one event N handed to T, after checking the original follows it byte for byte."""
    (port, raw), = out.emitted
    assert port == T_IN and raw[16:] == frame, (port, len(raw))
    return raw[12], raw[13]


def bound(reads=1):
    p = pipe()
    script = rp_.session(reads=reads, close=False)
    for _name, master, frame in script[:3]:
        send(p, master, frame)
    assert phase(p) == PHASE['idle']
    return p, script[3:]


class RealCapture(unittest.TestCase):
    def test_capture_checksums(self):
        """Sender-side capture: exactly the five offloaded master segments fail their TCP checksum as captured."""
        raw, wire = rp_.read_pcap(), rp_.wire()
        bad = [i for i, f in enumerate(raw) if struct.unpack('!H', f[50:52])[0] != rp_.tcp_checksum(f)]
        self.assertEqual(bad, [0, 2, 3, 6, 7])
        self.assertTrue(all(rp_.from_master(raw[i]) for i in bad))
        self.assertEqual([i for i in range(11) if raw[i] != wire[i]], bad)
        self.assertEqual([len(a) for a in raw], [len(b) for b in wire])

    def test_capture_has_the_profile_the_edit_names(self):
        shape = [(struct.unpack('!H', f[16:18])[0], f[46] >> 4, f[47]) for f in rp_.wire()]
        self.assertEqual(shape, [(60, 10, 0x02), (64, 11, 0x12), (52, 8, 0x10), (72, 8, 0x18), (52, 8, 0x10),
                                 (101, 8, 0x18), (52, 8, 0x10), (52, 8, 0x11), (52, 8, 0x10), (52, 8, 0x19), (52, 8, 0x10)])

    def test_whole_capture_handshake_read_close(self):
        p = pipe()
        cap = rp_.wire()
        want = [('syn', MASTER, None), ('synack', RELAY, None), ('idle', MASTER, None),
                ('read', MASTER, ('request', 0)), ('read', RELAY, ('ack', 0)), ('idle', RELAY, ('response', 0)),
                ('idle', MASTER, None), ('closed', MASTER, ('reset', 1))]
        for i, (state, sender, event) in enumerate(want):
            out = send(p, sender is MASTER, cap[i])
            self.assertFalse(out.dropped, (i, out.drop_reason))
            self.assertEqual(phase(p), PHASE[state], i)
            if event is None:
                peer = RELAY if sender is MASTER else MASTER
                self.assertEqual(out.emitted, [(peer.dev_port, cap[i])], i)      # forwarded unchanged, options and all
            else:
                self.assertEqual(handoff(out, cap[i]), (KIND[event[0]], event[1]), i)
        st = p.state()
        self.assertEqual((st['client'], st['server']), (3808428054 + 20, 3591468921 + 49))

    def test_repeated_reads_in_the_same_profile(self):
        p, rest = bound(reads=5)
        for n in range(5):
            (_, _, req), (_, _, rack), (_, _, rsp), (_, _, mack) = rest[4 * n:4 * n + 4]
            self.assertEqual(handoff(send(p, True, req), req), (KIND['request'], 0), n)
            self.assertEqual(phase(p), PHASE['read'])
            self.assertEqual(p.cell('', 'read_app'), n)
            self.assertEqual(handoff(send(p, False, rack), rack), (KIND['ack'], 0), n)
            self.assertEqual(handoff(send(p, False, rsp), rsp), (KIND['response'], 0), n)
            self.assertEqual(phase(p), PHASE['idle'])
            self.assertEqual(send(p, True, mack).emitted, [(RELAY.dev_port, mack)], n)
        st = p.state()
        self.assertEqual((st['client'], st['server']), (3808428054 + 100, 3591468921 + 245))

    def test_session_frames_verify(self):
        for name, _master, frame in rp_.session(reads=4):
            self.assertEqual(struct.unpack('!H', frame[50:52])[0], rp_.tcp_checksum(frame), name)
            self.assertEqual(rp_.checksummed(frame), frame, name)


class Negatives(unittest.TestCase):
    """Each starts from the bound, idle connection and sends ONE bad frame in place of the first READ request
    (or, for the response, after a good request and its ACK). None may reach T or move owner, client, server,
    epoch or the READ application sequence; after each, the good frame is still admitted.

    The expected outcome per case is the clean profile's own contract (connection/binding/tests/
    test_native_read.py): a frame that is not a valid READ (bad DNP3 CRC, foreign tuple, unparsed shape) is
    PASSED UNTOUCHED in one pass with no counter change (test_every_bad_crc_is_passed_untouched); a valid READ
    shape out of sequence is DROPPED with owner/client/server/epoch unchanged and the work pin released
    (test_out_of_sequence_request_and_response_are_denied_without_mutation, untouched()). That test does not
    hold the work allocator still, and neither does N here: a dropped admission consumes one work generation.
    Both outcomes are asserted against the clean profile too, so the edit cannot diverge from it."""

    def frozen(self, p):
        st = p.state()
        return dict(owner=st['owner'], client=st['client'], server=st['server'], epoch=st['epoch'],
                    read_app=p.cell('', 'read_app'))

    def passed_untouched(self, p, out, frame, before_full, to_port):
        self.assertFalse(out.dropped, out.drop_reason)
        self.assertEqual(out.passes, 1)
        self.assertEqual(out.emitted, [(to_port, frame)])
        self.assertEqual(p.state(), before_full, 'no register moves, counter included')

    def denied(self, p, out, before):
        self.assertTrue(out.dropped)
        self.assertEqual(out.emitted, [])
        self.assertEqual(self.frozen(p), before)
        self.assertEqual(p.state()['work']['phase'], 4, 'work pin released')

    def parsed_as_read(self, out, state):
        states = out.trace[-1][0]
        self.assertIn(state, states, 'the frame was parsed as a READ, so the outcome is the check, not a parse miss')

    def request_case(self, mutate):
        p, rest = bound()
        good = rest[0][2]
        bad = mutate(good)
        lap = p.inject(MASTER.dev_port, bad)
        self.assertEqual(lap.emitted, [(LAP, bad)])
        return p, good, bad

    def readmit(self, p, good):
        self.assertEqual(handoff(send(p, True, good), good), (KIND['request'], 0))

    def test_wrong_crc_read_request_is_passed_untouched(self):
        for offset in (8, 18):          # link header CRC, request block CRC (as test_every_bad_crc_is_passed_untouched)
            def mutate(frame, offset=offset):
                body = bytearray(frame[66:])
                body[offset] ^= 0x01
                return rp_.edit(frame, payload=bytes(body))
            p, good, bad = self.request_case(mutate)
            before = p.state()
            out = p.inject(LAP, bad)
            self.parsed_as_read(out, 'read_request')
            self.passed_untouched(p, out, bad, before, RELAY.dev_port)
            self.readmit(p, good)

    def test_wrong_sequence_read_request_is_denied(self):
        p, good, bad = self.request_case(lambda f: rp_.edit(f, seq=struct.unpack('!I', f[38:42])[0] + 1))
        before = self.frozen(p)
        out = p.inject(LAP, bad)
        self.parsed_as_read(out, 'read_request')
        self.denied(p, out, before)
        self.readmit(p, good)

    def test_wrong_length_segment(self):
        """IP length 73 and 71: not whitelisted, so N parses nothing past IP and forwards it untouched."""
        for delta in (1, -1):
            def mutate(frame, delta=delta):
                frame = bytearray(frame + b'\0' if delta > 0 else frame[:-1])
                frame[16:18] = struct.pack('!H', 72 + delta)
                return rp_.checksummed(bytes(frame))
            p, good, bad = self.request_case(mutate)
            before = p.state()
            out = p.inject(LAP, bad)
            self.assertNotIn('ts_read_tcp', out.trace[-1][0])
            self.passed_untouched(p, out, bad, before, RELAY.dev_port)
            self.readmit(p, good)

    def test_length_and_offset_must_agree(self):
        """A 72-byte segment claiming offset 5, or a NOP NOP SACK block in place of the timestamp: not parsed as
        a READ, forwarded untouched."""
        def offset5(frame):
            frame = bytearray(frame)
            frame[46] = 0x50
            return rp_.checksummed(bytes(frame))

        def not_timestamp(frame):
            frame = bytearray(frame)
            frame[54:58] = b'\x01\x01\x05\x0a'
            return rp_.checksummed(bytes(frame))
        for mutate in (offset5, not_timestamp):
            p, good, bad = self.request_case(mutate)
            before = p.state()
            out = p.inject(LAP, bad)
            self.assertNotIn('read_request', out.trace[-1][0])
            self.passed_untouched(p, out, bad, before, RELAY.dev_port)
            self.readmit(p, good)

    def test_different_four_tuple_is_passed_untouched(self):
        p, good, bad = self.request_case(lambda f: rp_.edit(f, sport=rp_.MASTER_TCP + 1))
        before = p.state()
        out = p.inject(LAP, bad)
        self.parsed_as_read(out, 'read_request')
        self.passed_untouched(p, out, bad, before, RELAY.dev_port)
        self.readmit(p, good)

    def test_bad_tcp_checksum_is_passed_untouched(self):
        """The capture's own offloaded request (pseudo-header sum in the checksum field)."""
        p, good, bad = self.request_case(lambda _f: rp_.read_pcap()[rp_.REQUEST])
        before = p.state()
        self.passed_untouched(p, p.inject(LAP, bad), bad, before, RELAY.dev_port)
        self.readmit(p, good)

    def test_wrong_crc_read_response_is_passed_untouched(self):
        for offset in (8, 26, 44, 47):    # as the clean profile's response offsets
            p, rest = bound()
            send(p, True, rest[0][2])
            send(p, False, rest[1][2])
            good = rest[2][2]
            body = bytearray(good[66:])
            body[offset] ^= 0x01
            bad = rp_.edit(good, payload=bytes(body))
            before = p.state()
            out = p.inject(RELAY.dev_port, bad)
            self.parsed_as_read(out, 'read_response_tail')
            self.passed_untouched(p, out, bad, before, MASTER.dev_port)
            self.assertEqual(handoff(send(p, False, good), good), (KIND['response'], 0))

    def test_clean_profile_has_the_same_two_outcomes(self):
        """The reference: the clean profile, same program text, same mutations."""
        p = rs.ReadPipeline(text=TEXT).start(0x50001, 1000, 2000)
        before = p.state()
        bad = bytearray(rs.request_packet())
        bad[54 + 18] ^= 1
        bad = rp_.checksummed(bytes(bad))
        out = p.inject(rs.IN_CLIENT, bad)
        self.passed_untouched(p, out, bad, before, rs.IN_SERVER)
        p = rs.ReadPipeline(text=TEXT).start(0x50001, 999, 2000)
        before = self.frozen(p)
        counter = p.state()['counter']
        self.denied(p, p.inject(rs.IN_CLIENT, rs.request_packet()), before)
        self.assertEqual(p.state()['counter'], counter + 1, 'the clean profile also consumes a work generation')


if __name__ == '__main__':
    unittest.main()
