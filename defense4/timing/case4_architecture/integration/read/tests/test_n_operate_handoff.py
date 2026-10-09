"""N's real OPERATE handoff to T, and what T does with it (the SELECT->OPERATE integration gap in
TIMING_QUEUE_MIGRATION_STATUS.md).

Same pattern as test_t_queue_invariants.H_NRealisticAssociation: every T_IN frame is produced by running
N's own source through the connection-binding harness, then replayed into T with QueueSim.handoff().
Nothing at T_IN is built by hand except where a test says "bypassing N".

Which N source. The complete native SELECT, response, OPERATE, response exchange exists only in
connection/binding/native_binding.p4 (test_step3_exchange.py). In core/ordinary/n.p4 a SELECT goes to M and
the protected-SELECT response path is unfinished (core/ordinary/README.md "Next"), so no packet sequence
brings n.p4's owner to state 10, where OPERATE is admitted. Both sources carry the same OPERATE arm;
J_NOperateArm runs n.p4's arm from the register state real N packets produced, and pins the gap.

Duplicate admission is N's existing machinery, not new code, and it covers CANONICAL-LENGTH copies only
(IP length 75, the one shape N's parser admits as an OPERATE): a TCP retransmission of the OPERATE has
client difference -35 (seq_resent, count_first[1]); any other copy finds the owner off state 10 or a
sequence that does not match the live banks (count_refused); a copy that arrives while the original is
still in N's passes meets the busy work pin (busy_drop). An OPERATE segment of any other length is not
parsed as an OPERATE at all and is forwarded natively in one pass, bypassing N's admission and T's hold
(pre-existing at HEAD, pinned by K_NonCanonicalLengthBypass). Source-level only, not compiler, model or
timing evidence.

The cost of dropping every retransmission, stated plainly: N refuses the master's own TCP retransmission
of an admitted OPERATE, so if the OPERATE is lost AFTER N handed it to T (in T's hold queue, on the
HB_RETURN/OP_LADDER recirculation, on the mirror/generator token path, or on the relay-facing link), the
master's retransmission cannot recover it. This is the risk recorded in
audit_current/OPERATE_RETRANSMISSION_RISK_20260916.md, and this handoff adds the T-side places where the
command can be lost, so it makes that risk larger, not smaller. Exactly-once delivery is not claimed.
"""
import copy
import struct
import sys
import unittest
from pathlib import Path

from queue_sim import OP_J, RELAY, T0, QueueSim, q
from test_t_queue_invariants import INTEGRATION, finished, n_support, out

KIND_OPERATE = 12           # read_queue_timing.p4 KIND_OPERATE (read only here)
N_KIND_OPERATE = 7          # N's own packet kind for an OPERATE (n.p4 operate_finish)


def binding():
    """N's harness plus the S3-1 exchange vectors (connection/binding/tests/test_step3_exchange.py)."""
    rs = n_support()
    import test_step3_exchange as ex
    import vectors
    return rs, ex, vectors


def exchange_table():
    """Labelled native frames for two complete SBO exchanges on one connection."""
    rs, ex, v = binding()
    s, c = ex.SERVER_SEQ, ex.SELECT_SEQ
    c2, s2 = c + 70, s + 57 + 57            # banks after exchange 1 (test_step3_exchange end state)
    return {
        'sel': ('client', ex.select_packet()),
        'rsp1': ('server', ex.response1()),
        'op': ('client', ex.operate_packet()),
        'rsp2': ('server', ex.response2()),
        'sel2': ('client', v.packet(24, c2, s2, payload=v.native_select(2, 3))),
        'rsp1_2': ('server', v.packet(24, s2, c2 + 35 + 20, reverse=True, payload=v.native_response(2, 3))),
        'op2': ('client', v.packet(24, c2 + 35, s2 + 57, payload=v.native_select(3, 4))),
        'rsp2_2': ('server', v.packet(24, s2 + 57, c2 + 70 + 40, reverse=True, payload=v.native_response(3, 4))),
    }


def n_run(labels, source='connection/binding/native_binding.p4', pipe=None):
    """Run labelled frames through N in order (label~note repeats the same bytes). Returns
    ({label: T_IN frame or None, label+':out': outcome}, pipe)."""
    rs, ex, _ = binding()
    table = exchange_table()
    if pipe is None:
        pipe = rs.ReadPipeline(text=(INTEGRATION / source).read_text()).start(ex.OWNER['after_ack'], ex.SELECT_SEQ, ex.SERVER_SEQ)
    handoff, got = rs.handoff_port(), {}
    for label in labels:
        side, frame = table[label.split('~')[0]]
        outcome = pipe.inject(rs.IN_CLIENT if side == 'client' else rs.IN_SERVER, frame)
        tevs = [raw for port, raw in outcome.emitted if port == handoff]
        got[label], got[label + ':out'] = (tevs[0] if tevs else None), outcome
    return got, pipe


def tev(raw):
    epoch, wgen, t0q, kind, stage, reserved = struct.unpack('!IIIBBH', raw[:16])
    return dict(epoch=epoch, wgen=wgen, t0q=t0q, kind=kind, stage=stage, reserved=reserved)


def count_first(pipe, index):
    return pipe.src.cells[('', 'count_first')][index]


class J_NRealisticOperate(unittest.TestCase):
    """The three OPERATE scenarios, real N output replayed into T."""

    def assert_operate_tev(self, raw, original, pipe):
        t = tev(raw)
        self.assertEqual(raw[16:], original, 'the original OPERATE rides unchanged behind the tev')
        self.assertEqual((t['kind'], t['stage'], t['reserved']), (KIND_OPERATE, 0, 0))
        self.assertEqual(t['t0q'] & 0xff, 0, 't0q on the 256 ns grid, as for READ')
        self.assertNotEqual(t['t0q'], 0, 'pass-0 t0q carried to the terminal')
        self.assertEqual(t['epoch'], pipe.state()['epoch'])

    def test_select_then_operate_hands_only_the_operate_to_t_once(self):
        """Scenario 1. SELECT and both responses are forwarded natively; the OPERATE leaves N only
        on T_IN, as a kind-12 tev, after the same four passes as a READ request. T holds it on its own
        ladder and releases it to the relay once, no earlier than q(arrival) + op_j."""
        rs, ex, _ = binding()
        n, pipe = n_run(['sel', 'rsp1', 'op', 'rsp2'])
        table = exchange_table()
        for label in ('sel', 'rsp1', 'rsp2'):
            self.assertIsNone(n[label], label + ' is not handed to T')
            self.assertEqual([p for p, _ in n[label + ':out'].emitted], [2 if table[label][0] == 'client' else 1])
        self.assertEqual([p for p, _ in n['op:out'].emitted], [rs.handoff_port()], 'no native copy of the OPERATE')
        self.assertEqual(n['op:out'].passes, 4, 'pass 0 plus three recirculations, like a READ request')
        self.assert_operate_tev(n['op'], table['op'][1], pipe)
        self.assertEqual(pipe.state()['owner'], ex.OWNER['idle'])
        sim = QueueSim()
        sim.handoff(T0, n['op'])
        sim.run(T0 + OP_J + 2_000_000)
        finished(self, sim)
        relay = sim.emissions(table['op'][1], RELAY)
        self.assertEqual(len(relay), 1)
        self.assertGreaterEqual(relay[0], q(T0) + OP_J)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1)
        self.assertEqual([r[3] for r in sim.held_records(table['op'][1])], ['OP_HELD'])

    def test_policy_off_t_relays_n_operate_once_unheld(self):
        n, _ = n_run(['sel', 'rsp1', 'op'])
        sim = QueueSim(enabled=0)
        sim.handoff(T0, n['op'])
        sim.run(T0 + OP_J + 2_000_000)
        finished(self, sim)
        self.assertEqual(sim.emissions(exchange_table()['op'][1], RELAY), [T0])

    def test_retransmitted_operate_is_refused_by_n_and_t_releases_once(self):
        """Scenario 2. A TCP retransmission of the admitted OPERATE (same bytes) is refused by N
        (seq_resent, counted in count_first[1]) and never reaches T; the owner keeps waiting for the
        OPERATE response. T, fed what N really emitted, releases the OPERATE once. Tradeoff: the same
        refusal means a retransmission can never replace an OPERATE that T (or the relay link) lost after
        the handoff (OPERATE_RETRANSMISSION_RISK_20260916.md); this test shows suppression, not recovery."""
        n, pipe = n_run(['sel', 'rsp1', 'op', 'op~again', 'op~third'])
        self.assertIsNotNone(n['op'])
        for label in ('op~again', 'op~third'):
            self.assertIsNone(n[label])
            self.assertTrue(n[label + ':out'].dropped)
            self.assertIn('first_event -> count_resent', '\n'.join(e for t in n[label + ':out'].trace for e in t))
        self.assertEqual(count_first(pipe, 1), 2)
        self.assertEqual(pipe.state()['owner'], 0xc0001, 'still waiting for the OPERATE response')
        n2, _ = n_run(['rsp2'], pipe=pipe)
        self.assertIsNotNone(n2['rsp2:out'].emitted, 'the exchange still completes')
        self.assertFalse(n2['rsp2:out'].dropped)
        sim = QueueSim()
        sim.handoff(T0, n['op'])
        for k, label in enumerate(('op~again', 'op~third')):
            if n[label] is not None:
                sim.handoff(T0 + 100_000 * (k + 1), n[label])
        sim.run(T0 + OP_J + 2_000_000)
        finished(self, sim)
        self.assertEqual(len(sim.emissions(exchange_table()['op'][1], RELAY)), 1)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1)

    def test_copy_arriving_while_the_original_is_in_n_meets_the_busy_pin(self):
        """Scenario 2, in flight: a copy that arrives between the original's passes is dropped by the
        work pin (busy_drop), and the original still completes to T exactly once."""
        rs, _, _ = binding()
        _, pipe = n_run(['sel', 'rsp1'])
        op = exchange_table()['op'][1]
        _, first, reason = pipe.run_pass(1, rs.IN_CLIENT, op)
        self.assertIsNotNone(first, reason)
        self.assertEqual(first[0], 68, 'the original is between passes')
        copy_out = pipe.inject(rs.IN_CLIENT, op)
        self.assertTrue(copy_out.dropped)
        self.assertEqual(copy_out.emitted, [])
        self.assertIn('busy_t -> busy_drop', '\n'.join(e for t in copy_out.trace for e in t))
        rest = pipe.inject(68, first[1])
        self.assertEqual([p for p, _ in rest.emitted], [rs.handoff_port()])
        self.assertEqual(rest.emitted[0][1][16:], op)

    def test_late_operate_copy_never_reaches_t(self):
        """Scenario 3. A delayed copy of exchange 1's OPERATE arrives (a) after the exchange ended
        (owner idle) and (b) inside exchange 2, at owner state 10 where an OPERATE is admissible. N
        refuses both: the owner is wrong in (a) and the sequence does not match the live banks in (b).
        T, fed N's output, releases each real OPERATE once at its own deadline."""
        n, pipe = n_run(['sel', 'rsp1', 'op', 'rsp2', 'op~late_idle',
                         'sel2', 'rsp1_2', 'op~late_in_exchange2', 'op2', 'rsp2_2'])
        for label in ('op~late_idle', 'op~late_in_exchange2'):
            self.assertIsNone(n[label], label)
            self.assertTrue(n[label + ':out'].dropped, label)
            self.assertIn('first_event -> count_refused', '\n'.join(e for t in n[label + ':out'].trace for e in t))
        self.assertIsNotNone(n['op2'])
        self.assertNotEqual(tev(n['op'])['wgen'], tev(n['op2'])['wgen'])
        table = exchange_table()
        second = T0 + 3_000_000
        sim = QueueSim()
        sim.handoff(T0, n['op'])
        sim.handoff(second, n['op2'])
        for label, at in (('op~late_idle', T0 + 1_500_000), ('op~late_in_exchange2', second - 100_000)):
            if n[label] is not None:
                sim.handoff(at, n[label])
        sim.run(second + OP_J + 2_000_000)
        finished(self, sim)
        first_rel, second_rel = sim.emissions(table['op'][1], RELAY), sim.emissions(table['op2'][1], RELAY)
        self.assertEqual((len(first_rel), len(second_rel)), (1, 1))
        self.assertGreaterEqual(first_rel[0], q(T0) + OP_J)
        self.assertGreaterEqual(second_rel[0], q(second) + OP_J)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 2)

    def test_t_alone_releases_a_late_copy_that_bypasses_n(self):
        """The trust boundary, recorded: the same late copy N refuses, wrapped in N's own tev and put
        directly on T_IN, is held and released again. T has no OPERATE association check; the
        once-per-command property is N's. If T gains one, this test is expected to change."""
        n, _ = n_run(['sel', 'rsp1', 'op', 'rsp2'])
        late = T0 + 1_500_000
        sim = QueueSim()
        sim.handoff(T0, n['op'])
        sim.handoff(late, n['op'])                  # synthetic: N refuses this copy
        sim.run(late + OP_J + 2_000_000)
        finished(self, sim)
        self.assertEqual(len(sim.emissions(exchange_table()['op'][1], RELAY)), 2)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 2)


class K_NonCanonicalLengthBypass(unittest.TestCase):
    """KNOWN GAP, pre-existing at HEAD and not introduced by the handoff: N's parser recognises an
    OPERATE only at IP length 75. The same OPERATE with one extra byte (IP length 76) is not an OPERATE to
    N: it leaves natively on the outstation port in one pass, with no admission, no duplicate check and no
    T hold. Pinned so the gap is visible; expected to change when N handles non-canonical lengths."""

    @staticmethod
    def long_operate():
        _, ex, v = binding()
        return v.packet(24, ex.SELECT_SEQ + 35, ex.SERVER_SEQ + 57, payload=v.native_select(1, 4) + b'\x00')

    def assert_bypass(self, outcome, frame):
        rs, _, _ = binding()
        self.assertFalse(outcome.dropped)
        self.assertEqual(outcome.passes, 1, 'never entered N work passes')
        self.assertEqual(outcome.emitted, [(2, frame)], 'forwarded natively to the outstation side')
        self.assertFalse(any(p == rs.handoff_port() for p, _ in outcome.emitted), 'T never sees it')

    def test_one_byte_longer_first_copy_bypasses_admission_and_hold(self):
        rs, ex, _ = binding()
        _, pipe = n_run(['sel', 'rsp1'])
        frame = self.long_operate()
        self.assert_bypass(pipe.inject(rs.IN_CLIENT, frame), frame)
        self.assertEqual(pipe.state()['owner'], 0xa0001, 'owner never moved: N did not admit it')

    def test_one_byte_longer_retransmission_bypasses_duplicate_refusal(self):
        rs, _, _ = binding()
        n, pipe = n_run(['sel', 'rsp1', 'op'])
        self.assertIsNotNone(n['op'], 'the canonical original went to T')
        frame = self.long_operate()
        self.assert_bypass(pipe.inject(rs.IN_CLIENT, frame), frame)
        self.assertEqual(pipe.state()['owner'], 0xc0001)
        self.assertEqual(count_first(pipe, 1), 0, 'not counted as a resend: N never saw an OPERATE')


class J_NOperateArm(unittest.TestCase):
    """core/ordinary/n.p4's OPERATE arm, and why it cannot be reached by packets today."""

    def test_n_p4_operate_arm_matches_native_binding_from_real_n_state(self):
        """n.p4 run from the register state real N packets produced (native_binding: SELECT and its
        response, owner 10), not from presets: the OPERATE tev is byte-identical to native_binding's,
        and the retransmitted, late and in-exchange copies are refused the same way."""
        rs, ex, _ = binding()
        _, nb = n_run(['sel', 'rsp1'])
        state = copy.deepcopy(nb.src.cells)
        reference, _ = n_run(['op', 'op~again', 'rsp2', 'op~late'], pipe=nb)
        npipe = rs.ReadPipeline(text=(INTEGRATION / 'core/ordinary/n.p4').read_text()).start(ex.OWNER['after_ack'], 0, 0)
        only_n = set(npipe.src.cells) - set(state)
        self.assertEqual(only_n, {('', 'active_work_generation')}, 'n.p4 adds only this register; it stays 0')
        for key, cells in state.items():
            npipe.src.cells[key] = copy.deepcopy(cells)
        got, _ = n_run(['op', 'op~again', 'rsp2', 'op~late'], pipe=npipe)
        self.assertIsNotNone(got['op'])
        self.assertEqual(got['op'], reference['op'])
        self.assertEqual(tev(got['op'])['kind'], KIND_OPERATE)
        for label in ('op~again', 'op~late'):
            self.assertIsNone(got[label])
            self.assertTrue(got[label + ':out'].dropped)
        self.assertFalse(got['rsp2:out'].dropped)
        self.assertEqual(npipe.state()['owner'], ex.OWNER['idle'])

    def test_n_p4_alone_does_not_reach_operate_today(self):
        """The gap upstream of this handoff, pinned. In n.p4 a SELECT goes to M and E; after the genuine
        completion the owner is 18 (0x120001), and neither the SELECT response nor an OPERATE is admitted,
        so nothing reaches T. Expected to change when the protected-SELECT response path lands."""
        ordinary = str(INTEGRATION / 'core/ordinary/tests')
        if ordinary not in sys.path:
            sys.path.insert(0, ordinary)
        import test_n_complete as nc
        import test_n_ready as nr
        import test_m_prepare as mp
        v = mp.vectors
        pipe, raw = nc.NComplete().completion()
        terminal, reason = nr.NativeReady().one(pipe, raw)
        self.assertIsNotNone(terminal, reason)
        nr.NativeReady().one(pipe, terminal[1])
        self.assertEqual(pipe.state()['owner'], 0x120001)
        start = 100                                     # test_e_emit.qualified's default coordinate
        rsp1 = v.packet(24, 901, start + 35 + 20, reverse=True, payload=v.native_response(0, 3))
        op = v.packet(24, start + 35, 958, payload=v.native_select(1, 4))
        for port, frame in ((2, rsp1), (1, op)):
            result = pipe.inject(port, frame)
            self.assertTrue(result.dropped)
            self.assertFalse(any(p == 325 for p, _ in result.emitted))
        self.assertEqual(pipe.state()['owner'], 0x120001)


if __name__ == '__main__':
    unittest.main()
