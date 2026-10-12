"""Close path and event wire types, source level (N interpreter; E is not run here - the model vectors
model_drive_sbo_toff.py CLOSE=client|client_sepack|server|rst cover the composite).

route_ab_01/close_defect_01 localized two N defects; make_n.py edits 10-13 fix them:
  * the second FIN of a close (phase 7) left through close_forward in one pass with snapshot()'s
    bypass_egress=1 still set, so an outstation FIN/RST skipped E and kept native coordinates;
  * N does not count a FIN's sequence byte, so the master's ACKs after a FIN ((1,0), (1,1), and (0,1) after an
    outstation-first FIN) missed sequence_guard and were aborted.
And the RESET event N hands to T carried kind 4, so wire bytes 12-13 on the MAC-loopback T_IN were an 802.3
length (0x0401/0x0402); silicon counted it received-not-good (p2_production_01). It is kind 13 now.
"""
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
RO = HERE.parent
sys.path[:0] = [str(HERE), str(RO)]
import compose  # noqa: E402
import port_map as pm  # noqa: E402
import test_response_only_binding as h  # noqa: E402

T_SRC = (RO.parent.parent / 'read' / 'read_queue_timing.p4').read_text()
TIN = h.rs.handoff_port(h.TEXT)
C, S = h.rs.IN_CLIENT, h.rs.IN_SERVER
CLIENT, SERVER = h.SELECT_SEQ, h.SERVER_SEQ        # fresh(): stored native positions 101 / 901
CLOSED = 0x7


def phase(p):
    return p.state()['owner'] >> 16


def last_pass_bypass(out):
    """bypass_egress of the pass that emitted the frame (driver.run_pass: '... egress=%d bypass=%d ...')."""
    for events in reversed(out.trace):
        for e in events:
            m = re.search(r'egress=(\d+) bypass=(\d+)', e)
            if m:
                return int(m[2])
    return None


def pkt(flags, seq, ack, reverse=False):
    return h.vectors.packet(flags, seq, ack, reverse=reverse)


class EventWireTypes(unittest.TestCase):
    def test_every_event_n_hands_to_t_is_an_ethertype(self):
        """read_terminal_t's emit_tev values and emit_reset for both directions: wire bytes 12-13 (kind, stage)
        must be >= 0x0600 and not a reserved type on the MAC-loopback T_IN."""
        values = [int(v, 16) for v in re.findall(r'emit_tev\(16w0x([0-9a-f]+)\)', h.TEXT)]
        kind = int(re.search(r'hdr\.event\.event=8w(\d+)\+\+m\.direction', h.TEXT)[1])
        values += [kind << 8 | d for d in (1, 2)]
        self.assertGreaterEqual(len(values), 6)
        self.assertEqual({hex(v): pm.type_violation(v) for v in values if pm.type_violation(v)}, {})

    def test_n_reset_kind_equals_t_kind_reset(self):
        compose.check_reset_kind(h.TEXT, T_SRC)

    def test_close_handoffs_carry_kind_13(self):
        """The handed-off RESET event really carries 0x0d01 (client close) / 0x0d02 (outstation close)."""
        for port, frame, want in ((C, pkt(17, CLIENT, SERVER), 0x0d01), (S, pkt(17, SERVER, CLIENT, True), 0x0d02)):
            out = h.fresh().inject(port, frame)
            (eport, raw), = out.emitted
            self.assertEqual((eport, int.from_bytes(raw[12:14], 'big')), (TIN, want))


class ClosePath(unittest.TestCase):
    def client_closed(self):
        p = h.fresh()
        p.inject(C, pkt(17, CLIENT, SERVER))
        self.assertEqual(phase(p), CLOSED)
        return p

    def test_second_fin_from_the_outstation_crosses_egress(self):
        """The outstation FIN in phase 7 leaves toward the master once, with bypass_egress = 0 so E translates
        it. Before edit 10 the same pass carried bypass_egress = 1."""
        p = self.client_closed()
        out = p.inject(S, pkt(17, SERVER, CLIENT + 1, True))
        self.assertEqual([port for port, _ in out.emitted], [C])
        self.assertEqual(last_pass_bypass(out), 0)

    def test_outstation_rst_in_phase_7_crosses_egress(self):
        p = self.client_closed()
        out = p.inject(S, pkt(0x14, SERVER, CLIENT + 1, True))
        self.assertEqual([port for port, _ in out.emitted], [C])
        self.assertEqual(last_pass_bypass(out), 0)

    def test_master_acks_after_its_fin_are_forwarded(self):
        """(1,0): the master's ACK after its own FIN; (1,1): its ACK of the outstation FIN. Both reach the
        outstation once, unchanged (the lap already reverse-mapped them), and N stays closed."""
        for ack in (SERVER, SERVER + 1):
            p = self.client_closed()
            if ack == SERVER + 1:
                p.inject(S, pkt(17, SERVER, CLIENT + 1, True))
            frame = pkt(16, CLIENT + 1, ack)
            out = p.inject(C, frame)
            self.assertEqual(out.emitted, [(S, frame)], hex(ack))
            self.assertEqual(phase(p), CLOSED)

    def test_outstation_first_close(self):
        """Outstation FIN first (handed to T), then the master's ACK of it (0,1), then the master's FIN, which
        leaves through close_forward and crosses egress."""
        p = h.fresh()
        out = p.inject(S, pkt(17, SERVER, CLIENT, True))
        self.assertEqual([port for port, _ in out.emitted], [TIN])
        self.assertEqual(phase(p), CLOSED)
        ack = pkt(16, CLIENT, SERVER + 1)
        self.assertEqual(p.inject(C, ack).emitted, [(S, ack)])
        out = p.inject(C, pkt(17, CLIENT, SERVER + 1))
        self.assertEqual([port for port, _ in out.emitted], [S])
        self.assertEqual(last_pass_bypass(out), 0)

    def test_fin_accounting_is_inert_outside_phase_7(self):
        """seq_fin (code 5) is accepted only by the phase-7 row: before any FIN, an ACK claiming a sequence byte
        on each side ((1,1) or (1,0)) is not forwarded and moves no state."""
        for ack in (SERVER, SERVER + 1):
            p = h.fresh()
            before = p.state()
            out = p.inject(C, pkt(16, CLIENT + 1, ack))
            self.assertEqual(out.emitted, [], hex(ack))
            self.assertEqual(p.state()['owner'], before['owner'])

    def test_ack_two_bytes_ahead_in_phase_7_is_refused(self):
        """Only one sequence byte per FIN is granted: (2,0) is still refused after the client FIN."""
        p = self.client_closed()
        self.assertEqual(p.inject(C, pkt(16, CLIENT + 2, SERVER)).emitted, [])


if __name__ == '__main__':
    unittest.main()
