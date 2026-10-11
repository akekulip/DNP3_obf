"""The seven Phase C invariants (DNP3_Timing_Size_Integration_Prompt.md section 4, Phase C) for T's
queue-resident timing role, read_queue_timing.p4.

Whole-program SOURCE-LEVEL runs under queue_sim.QueueSim (strict-priority ladder, mirror and
generator modelled in the test, see its docstring). Expectations come from the invariant text and
the contract's equations (INTEGRATION_CONTRACT.md section 4: response_eligibility = a_commit +
configured CLRT_new), never from reading the P4. Outcome counters are read by their OUT_* names.

a_commit in these tests is the ingress pass at which the held ACK returns from its hold queue and
is released (an INTERNAL held-ACK return, not an externally measured departure). The simulator
emits a released packet at that pass's time, so a_commit == the ACK's emission time here.
"""
import struct
import sys
import unittest
from pathlib import Path

from queue_sim import (ACK_FRAME, CAP, CHILD1, CHILD2, DA, FORWARD, GAP, LADDER, OP_FRAME, OP_J,
                       OP_LADDER, READINESS, RELAY, REQ_FRAME, RSP_FRAME, T0, QueueSim, q)


INTEGRATION = Path(__file__).resolve().parents[2]


def n_support():
    """N's own READ source harness (connection/binding/tests/read_support.py)."""
    path = str(INTEGRATION / 'connection/binding/tests')
    if path not in sys.path:
        sys.path.insert(0, path)
    import read_support
    return read_support


def ladder_token(role, gen, budget=1000):
    """A blocker token as it sits in a ladder queue: role, child, generation16, budget32, filler."""
    return struct.pack('!BBHI', role, 0, gen, budget) + bytes(10)

ACK_OFF, RSP_OFF = 50_000, 100_000
HORIZON = T0 + CAP + 2_000_000


def out(sim, name):
    return sim.counter(sim.consts()[name])


def finished(test, sim):
    """Every run: no unmatched decision and every injected original accounted for."""
    test.assertEqual(out(sim, 'OUT_UNMATCHED'), 0, 'a pass matched no decision row')


class A_Residency(unittest.TestCase):
    """(a) Real ACK/response are resident in their hold queues during normal waiting; only blocker
    tokens repeat the timing circulation."""

    def test_originals_enter_their_hold_queue_once_and_return_once(self):
        sim = QueueSim()
        sim.read(T0)
        sim.run(HORIZON)
        finished(self, sim)
        for frame, qid in ((ACK_FRAME, 6), (RSP_FRAME, 4)):
            held = sim.held_records(frame)
            self.assertEqual([(p, x) for _, p, x, *_ in held], [(LADDER, qid)], 'one enqueue into its hold queue')
            self.assertEqual(len(sim.ladder_passes(frame)), 1, 'one return pass: its release')
            self.assertEqual(len(sim.emissions(frame, FORWARD)), 1)
        self.assertEqual(sim.emissions(REQ_FRAME, RELAY), [T0])
        tokens = sim.token_enqueues()
        self.assertGreater(len(sim.token_passes()), 4 * sim.k, 'blockers circulated repeatedly')
        self.assertEqual({qid for _, _, qid, _ in tokens}, {7, 5})
        self.assertEqual(out(sim, 'OUT_HELD_REWAIT'), 0)

    def test_blocker_reservoir_below_continuity_floor_is_reported(self):
        """One token cannot keep qid7 backlogged across its own loop (service 30us < 50us round trip):
        the held ACK is served early and must be re-held. Residency is a reservoir-size property, and
        the program reports the violation instead of hiding it."""
        sim = QueueSim(k=1)
        sim.read(T0)
        sim.run(HORIZON)
        finished(self, sim)
        self.assertGreater(out(sim, 'OUT_HELD_REWAIT'), 0)
        self.assertGreaterEqual(sim.emissions(ACK_FRAME)[0], q(T0) + DA, 'still never early')


class B_NoEarlyResponse(unittest.TestCase):
    """(b) No response is externally visible before the authorized response release."""

    SCENARIOS = {
        'early': (ACK_OFF, RSP_OFF),
        'response_after_ack_deadline': (ACK_OFF, 1_200_000),
        'ack_after_ack_deadline': (900_000, RSP_OFF),
        'response_after_ack_and_gap': (ACK_OFF, 2_000_000),
    }

    def test_response_follows_ack_commit_by_the_configured_gap(self):
        for name, (ack_off, rsp_off) in self.SCENARIOS.items():
            with self.subTest(name):
                sim = QueueSim()
                sim.read(T0, ack_off, rsp_off)
                sim.run(HORIZON)
                finished(self, sim)
                ack, rsp = sim.emissions(ACK_FRAME, FORWARD), sim.emissions(RSP_FRAME, FORWARD)
                self.assertEqual((len(ack), len(rsp)), (1, 1))
                a_commit = ack[0]
                # ACK: request-anchored deadline AND a matching response available
                self.assertGreaterEqual(a_commit, q(T0) + DA)
                self.assertGreaterEqual(a_commit, T0 + rsp_off)
                # response_eligibility = a_commit + configured CLRT_new, also when the response is late
                self.assertGreaterEqual(rsp[0], a_commit + GAP)
                self.assertEqual(out(sim, 'OUT_ACK_COMMIT'), 1)
                self.assertEqual(out(sim, 'OUT_RESP_RELEASE'), 1)


class C_Children(unittest.TestCase):
    """(c) Both children inherit the same admitted transaction, role, policy and release decision."""

    def test_two_response_children_are_held_and_released_together(self):
        sim = QueueSim()
        sim.request(T0)
        sim.ack(T0 + ACK_OFF)
        sim.response(T0 + RSP_OFF, frame=CHILD1, child=1)
        sim.response(T0 + RSP_OFF + 5_000, frame=CHILD2, child=2)
        sim.run(HORIZON)
        finished(self, sim)
        first, second = sim.held_records(CHILD1), sim.held_records(CHILD2)
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertEqual(first[0][1:5], second[0][1:5], 'same port, hold queue, role and generation')
        self.assertEqual((first[0][5], second[0][5]), (1, 2))
        a_commit = sim.emissions(ACK_FRAME)[0]
        e1, e2 = sim.emissions(CHILD1, FORWARD), sim.emissions(CHILD2, FORWARD)
        self.assertEqual((len(e1), len(e2)), (1, 1))
        self.assertGreaterEqual(min(e1[0], e2[0]), a_commit + GAP)
        self.assertLess(e1[0], e2[0], 'children leave in order')
        self.assertEqual(out(sim, 'OUT_RESP_RELEASE'), 2, 'one decision class for both')
        self.assertEqual(out(sim, 'OUT_RESP_DUP_DROP'), 0, 'a second child is not a duplicate')


class D_SeparateGates(unittest.TestCase):
    """(d) ACK and response have their own gates; the OPERATE hold domain is separate."""

    def test_operate_is_held_on_its_own_ladder_and_does_not_move_read_timing(self):
        plain = QueueSim()
        plain.read(T0)
        plain.run(HORIZON)
        mixed = QueueSim()
        mixed.read(T0)
        mixed.operate(T0 + 20_000, epoch=2)
        mixed.run(HORIZON)
        finished(self, mixed)
        for frame in (ACK_FRAME, RSP_FRAME):
            self.assertEqual(mixed.emissions(frame), plain.emissions(frame), 'READ timing unchanged by OPERATE')
        held = mixed.held_records(OP_FRAME)
        self.assertEqual([(p, x) for _, p, x, *_ in held], [(OP_LADDER, 2)])
        self.assertEqual({(p, x) for _, p, x, r in mixed.token_enqueues() if r == 'OP_BLK'}, {(OP_LADDER, 3)})
        relay = mixed.emissions(OP_FRAME, RELAY)
        self.assertEqual(len(relay), 1)
        self.assertGreaterEqual(relay[0], q(T0 + 20_000) + OP_J)
        self.assertEqual(out(mixed, 'OUT_OP_RELEASE'), 1)

    @staticmethod
    def _release_then_inject_same_generation_copy():
        """One OPERATE released normally, then a second held-OPERATE ladder record carrying the SAME
        generation the real one carried (read back, not assumed: the ladder field is 16 bits, written
        as (bit<16>)md.op_gen from the 32-bit op_gen_alloc_reg)."""
        sim = QueueSim()
        sim.operate(T0)
        sim.run(T0 + OP_J + 1_000_000)
        (_, _, _, role, gen, _), = sim.held_records(OP_FRAME)
        inject = T0 + OP_J + 1_100_000
        copy = struct.pack('!BBHI', 16, 0, gen, 0) + OP_FRAME
        sim.call(inject, lambda s: s.enqueue(inject, OP_LADDER, 2, copy))
        return sim, role, gen, inject

    def test_same_generation_copy_is_not_released_while_its_generation_is_current(self):
        """op_done_reg records the released generation, so a same-generation copy of a released OPERATE
        is held (re-waited), not released, for as long as that generation is current. Without the
        record (op_done_try never writing) the copy passes the generation check, its deadline has long
        passed, and it is released. This is NOT exactly-once delivery, which the project does not claim:
        the next OPERATE makes the copy stale and it is flushed to the relay (next test)."""
        sim, role, gen, inject = self._release_then_inject_same_generation_copy()
        self.assertEqual(role, 'OP_HELD')
        self.assertEqual(gen, sim.cell('op_gen_alloc_reg') & 0xffff)
        self.assertEqual(len(sim.emissions(OP_FRAME, RELAY)), 1)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1)
        sim.run(inject + 2_000_000)                     # no further OPERATE arrives
        finished(self, sim)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1, 'the same-generation copy was released')
        self.assertEqual(len(sim.emissions(OP_FRAME, RELAY)), 1, 'a second relay emission appeared')

    def test_same_generation_copy_is_flushed_to_the_relay_when_the_next_operate_arrives(self):
        """Known, accepted behavior (exactly-once is not claimed): once a later OPERATE opens a new
        generation, the circulating copy is stale and flush_operate_stale sends it to the relay. Pinned
        here so the behavior is recorded by a test rather than only observed by accident."""
        sim, _, _, inject = self._release_then_inject_same_generation_copy()
        second = inject + 500_000
        sim.operate(second)
        sim.run(second + OP_J + 2_000_000)
        finished(self, sim)
        relay = sim.emissions(OP_FRAME, RELAY)
        self.assertEqual(len(relay), 3, 'first release, stale-flushed copy, second release')
        self.assertLess(relay[0], inject)
        self.assertTrue(second <= relay[1] < second + 100_000, 'copy flushed on its first pass after the new generation')
        self.assertGreaterEqual(relay[2], q(second) + OP_J, 'the second OPERATE keeps its own deadline')
        self.assertEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 1)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 2)

    def test_ack_and_response_gates_are_distinct(self):
        """The ACK opens on (deadline and response pending); the response opens on a_commit + gap.
        Without a response the ACK gate stays shut until readiness even though D_A has passed."""
        sim = QueueSim()
        sim.read(T0, ACK_OFF, None)
        sim.run(HORIZON)
        finished(self, sim)
        self.assertGreaterEqual(sim.emissions(ACK_FRAME)[0], q(T0) + READINESS)
        self.assertEqual(out(sim, 'OUT_RESP_RELEASE'), 0)


class E_StaleAndDuplicate(unittest.TestCase):
    """(e) A stale blocker cannot release or hold a new transaction; duplicates cannot re-arm."""

    def test_stale_tokens_die_on_first_pass_and_do_not_move_the_new_transaction(self):
        second = T0 + CAP + 1_000_000
        clean = QueueSim()
        clean.read(T0)
        clean.read(second)
        clean.run(T0 + 2 * CAP + 4_000_000)
        dirty = QueueSim()
        dirty.read(T0)
        dirty.read(second)
        for i in range(2):                       # generation 1 tokens offered by the generator...
            dirty.token(second + 30_000 + 1_000 * i, gen=1, packet_id=i)
        for i in range(2):                       # ...and generation 1 tokens left inside qid7 / qid5
            raw = ladder_token(11 + i, gen=1)
            dirty.call(second + 60_000, lambda s, raw=raw, qid=7 - 2 * i: s.enqueue(second + 60_000, LADDER, qid, raw))
        dirty.run(T0 + 2 * CAP + 4_000_000)
        finished(self, dirty)
        self.assertEqual(out(dirty, 'OUT_TOKEN_STALE') - out(clean, 'OUT_TOKEN_STALE'), 4)
        stale = [e for e in dirty.enqueued if e[3][0] in (11, 12) and e[3][2:4] == b'\x00\x01' and e[0] > second]
        self.assertEqual(len(stale), 2, 'only the two injections; no stale token was re-enqueued')
        ack, clean_ack = dirty.emissions(ACK_FRAME)[1], clean.emissions(ACK_FRAME)[1]
        self.assertGreaterEqual(ack, q(second) + DA, 'a stale token cannot release the new ACK early')
        self.assertLess(abs(ack - clean_ack), 100_000, 'nor hold it beyond one token round')
        self.assertGreaterEqual(dirty.emissions(RSP_FRAME)[1], ack + GAP)

    def test_superseding_request_flushes_old_originals_without_loss(self):
        sim = QueueSim()
        sim.read(T0, ACK_OFF, None)                    # generation 1: ACK held, no response
        sim.read(T0 + 300_000, 350_000, 400_000)        # generation 2 begins while gen 1 ACK is held
        sim.run(HORIZON + 1_000_000)
        finished(self, sim)
        self.assertEqual(len(sim.emissions(ACK_FRAME)), 2, 'both ACKs delivered once each')
        self.assertEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 1)
        self.assertEqual(out(sim, 'OUT_ACK_COMMIT'), 1)

    def test_duplicate_ack_records_a_commit_once(self):
        """The response deadline is a_commit + gap, and a_commit is what ack_commit_at_reg holds (the
        separate resp_deadline register, armed but never read by any decision, was removed 2026-10-09).
        A duplicate ACK's later commit must not move a_commit, so it cannot move the response deadline."""
        sim = QueueSim()
        sim.read(T0)
        sim.ack(T0 + ACK_OFF + 10_000)                  # duplicate ACK while the first is held
        recorded = []
        sim.call(T0 + DA + 150_000, lambda s: recorded.append(s.cell('ack_commit_at_reg')))
        sim.run(HORIZON)
        finished(self, sim)
        acks = sim.emissions(ACK_FRAME)
        self.assertEqual(len(acks), 2)
        self.assertEqual(sim.cell('ack_commit_at_reg'), recorded[0], 'second commit did not move a_commit')
        self.assertEqual(recorded[0], q(acks[0]), 'a_commit is the first ACK commit pass (quantized)')
        self.assertEqual(sim.cell('ack_commit_gen_reg'), sim.cell('gen_alloc_reg'), 'tagged with the generation that committed')
        self.assertGreaterEqual(sim.emissions(RSP_FRAME)[0], acks[0] + GAP)

    def test_duplicate_response_is_suppressed_only_while_the_original_is_held(self):
        sim = QueueSim()
        sim.read(T0)
        sim.response(T0 + RSP_OFF + 20_000)             # duplicate while held: suppressed
        sim.response(T0 + DA + 900_000)                 # after release: passes through
        sim.run(HORIZON)
        finished(self, sim)
        self.assertEqual(out(sim, 'OUT_RESP_DUP_DROP'), 1)
        emitted = sim.emissions(RSP_FRAME)
        self.assertEqual(len(emitted), 2)
        self.assertEqual(emitted[1], T0 + DA + 900_000)


class F_BoundedFallback(unittest.TestCase):
    """(f) Missing response or lost blocker service cannot stall without bound; fallback is
    distinguishable from a normal completion."""

    def test_missing_response_releases_ack_at_readiness_as_fallback(self):
        sim = QueueSim()
        sim.read(T0, ACK_OFF, None)
        sim.run(HORIZON)
        finished(self, sim)
        ack = sim.emissions(ACK_FRAME)
        self.assertEqual(len(ack), 1)
        self.assertGreaterEqual(ack[0], q(T0) + READINESS)
        self.assertLessEqual(ack[0], q(T0) + CAP)
        self.assertEqual((out(sim, 'OUT_ACK_COMMIT'), out(sim, 'OUT_ACK_FALLBACK')), (0, 1))

    def test_missing_ack_releases_response_at_readiness_as_fallback(self):
        sim = QueueSim()
        sim.read(T0, None, RSP_OFF)
        sim.run(HORIZON)
        finished(self, sim)
        rsp = sim.emissions(RSP_FRAME)
        self.assertEqual(len(rsp), 1)
        self.assertGreaterEqual(rsp[0], q(T0) + READINESS)
        self.assertLessEqual(rsp[0], q(T0) + CAP)
        self.assertEqual((out(sim, 'OUT_RESP_RELEASE'), out(sim, 'OUT_RESP_FALLBACK')), (0, 1))

    def test_replies_arriving_after_the_readiness_window_are_delivered_once_each_promptly(self):
        """A genuinely late outstation: ACK and response both arrive after READINESS. Each is released exactly
        once, in order, to the master, within one service lap of its own arrival (no extra hold): the ACK as
        a commit (its deadline has already passed), the response as a fallback. Deterministic source-level
        time; the local model's clock cannot rank these paths (route_ab_01/response_only_17 model_01 vs 02)."""
        ack_off, rsp_off = READINESS + 1_000_000, READINESS + 1_050_000
        sim = QueueSim()
        sim.read(T0, ack_off=ack_off, rsp_off=rsp_off)
        sim.run(T0 + 3 * CAP + 10_000_000)
        finished(self, sim)
        ack, rsp = sim.emissions(ACK_FRAME, FORWARD), sim.emissions(RSP_FRAME, FORWARD)
        self.assertEqual((len(ack), len(rsp)), (1, 1))
        self.assertLess(ack[0], rsp[0])
        self.assertLessEqual(ack[0] - (T0 + ack_off), 100_000, 'released promptly, not held for another window')
        self.assertLessEqual(rsp[0] - (T0 + rsp_off), 100_000)
        self.assertEqual((out(sim, 'OUT_ACK_COMMIT'), out(sim, 'OUT_ACK_FALLBACK')), (1, 0))
        self.assertEqual((out(sim, 'OUT_RESP_RELEASE'), out(sim, 'OUT_RESP_FALLBACK')), (0, 1))

    def test_lost_blocker_service_is_bounded_and_marked(self):
        sim = QueueSim()
        sim.lose = lambda time, port, qid, raw: qid in (7, 5)       # every blocker token lost
        sim.read(T0)
        sim.run(HORIZON)
        finished(self, sim)
        ack, rsp = sim.emissions(ACK_FRAME), sim.emissions(RSP_FRAME)
        self.assertEqual((len(ack), len(rsp)), (1, 1))
        self.assertGreaterEqual(ack[0], q(T0) + DA, 'the held-return recheck still enforces the ACK gate')
        self.assertGreaterEqual(rsp[0], ack[0] + GAP, 'and the response gap')
        self.assertLessEqual(rsp[0], q(T0) + CAP + 100_000)
        self.assertGreater(out(sim, 'OUT_HELD_REWAIT'), 0, 'degraded service is visible')

    def test_blocker_budget_exhaustion_is_counted_and_next_read_recovers(self):
        sim = QueueSim(budget=3)
        sim.read(T0)
        sim.read(T0 + CAP + 1_000_000)
        sim.run(T0 + 2 * CAP + 4_000_000)
        finished(self, sim)
        self.assertGreater(out(sim, 'OUT_TOKEN_TMO'), 0)
        self.assertEqual(len(sim.emissions(ACK_FRAME)), 2)
        self.assertEqual(len(sim.emissions(RSP_FRAME)), 2)
        second = sim.emissions(ACK_FRAME)[1]
        self.assertGreaterEqual(second, q(T0 + CAP + 1_000_000) + DA)


class G_PassThroughAndRecovery(unittest.TestCase):
    """(g) Traffic without insertion keeps pass-through; held originals keep their delivery
    obligation through policy-off and recovery."""

    def test_policy_off_forwards_every_event_unchanged_in_one_pass(self):
        sim = QueueSim(enabled=0)
        sim.read(T0)
        sim.operate(T0 + 150_000)
        sim.run(HORIZON)
        finished(self, sim)
        self.assertEqual(sim.enqueued, [], 'nothing entered a ladder queue')
        self.assertEqual(sim.emissions(REQ_FRAME, RELAY), [T0])
        self.assertEqual(sim.emissions(ACK_FRAME, FORWARD), [T0 + ACK_OFF])
        self.assertEqual(sim.emissions(RSP_FRAME, FORWARD), [T0 + RSP_OFF])
        self.assertEqual(sim.emissions(OP_FRAME, RELAY), [T0 + 150_000])

    def test_policy_off_while_held_delivers_each_original_once_in_order(self):
        sim = QueueSim()
        sim.read(T0)
        sim.call(T0 + 300_000, lambda s: s.set_params(enabled=0))
        sim.run(HORIZON)
        finished(self, sim)
        ack, rsp = sim.emissions(ACK_FRAME, FORWARD), sim.emissions(RSP_FRAME, FORWARD)
        self.assertEqual((len(ack), len(rsp)), (1, 1))
        self.assertLess(ack[0], rsp[0])
        self.assertLess(rsp[0], T0 + DA, 'flushed, not held to the deadline')
        self.assertEqual(out(sim, 'OUT_HELD_OFF_FLUSH'), 2)
        self.assertGreater(out(sim, 'OUT_TOKEN_OFF'), 0)

    def test_reset_flushes_held_originals_and_quarantines_the_epoch(self):
        sim = QueueSim()
        sim.read(T0)
        sim.reset(T0 + 200_000)
        sim.read(T0 + CAP + 1_000_000)                  # same epoch after the reset: not inserted
        sim.run(T0 + 2 * CAP + 4_000_000)
        finished(self, sim)
        ack, rsp = sim.emissions(ACK_FRAME), sim.emissions(RSP_FRAME)
        self.assertEqual((len(ack), len(rsp)), (2, 2))
        self.assertLess(ack[0], T0 + DA, 'held originals flushed at the reset, not dropped')
        self.assertEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 2)
        base = T0 + CAP + 1_000_000
        self.assertEqual((ack[1], rsp[1]), (base + ACK_OFF, base + RSP_OFF), 'quarantined epoch passes through')
        self.assertEqual(out(sim, 'OUT_REQ_BYPASS'), 1)

    def test_other_epoch_traffic_is_not_inserted(self):
        sim = QueueSim()
        sim.read(T0, ACK_OFF, None)                     # this transaction never gets its response
        other = T0 + 20_000
        sim.ack(other, epoch=7, frame=CHILD1)
        sim.response(other + 10_000, epoch=7, frame=CHILD2)
        sim.run(HORIZON)
        finished(self, sim)
        self.assertEqual(sim.emissions(CHILD1, FORWARD), [other])
        self.assertEqual(sim.emissions(CHILD2, FORWARD), [other + 10_000])
        self.assertEqual(out(sim, 'OUT_ACK_FALLBACK'), 1, "another epoch's response did not open this ACK gate")
        self.assertGreaterEqual(sim.emissions(ACK_FRAME)[0], q(T0) + READINESS)


class H_NRealisticAssociation(unittest.TestCase):
    """What N actually hands T, and what T does with it.

    Every T_IN frame here is produced by running N's own source (connection/binding/native_binding.p4
    and core/ordinary/n.p4, through the connection-binding READ harness), not built by hand. N
    allocates a fresh wgen for every packet it starts processing (`go_new` -> `allocate`), including
    packets it then refuses, so one transaction's request, ACK and response never share a wgen; T
    must not and does not compare it. Transaction association comes from N instead: a READ request is
    admitted only from owner state 5 (idle), a response only at state 14 with seq/ack equal to the live
    banks, and the single work pin serialises their hand-offs onto one T_IN port. Source-level only;
    the cross-pipe N->T path's FIFO order is an assumption, not a target measurement."""

    N_SOURCES = ('connection/binding/native_binding.p4', 'core/ordinary/n.p4')
    IDLE = 0x50001

    @staticmethod
    def n_run(source, steps):
        """Run (label, side, frame) through N in order; return {label: T_IN frame or None, label + ':out': outcome}."""
        rs = n_support()
        pipe = rs.ReadPipeline(text=(INTEGRATION / source).read_text()).start(H_NRealisticAssociation.IDLE, 1000, 2000)
        handoff, got = rs.handoff_port(), {}
        for label, side, frame in steps:
            outcome = pipe.inject(rs.IN_CLIENT if side == 'client' else rs.IN_SERVER, frame)
            tevs = [raw for port, raw in outcome.emitted if port == handoff]
            got[label] = tevs[0] if tevs else None
            got[label + ':out'] = outcome
        return got

    @staticmethod
    def steps(*labels):
        """Labels are a packet name, optionally suffixed '~note' for a repeat of the same bytes."""
        rs = n_support()
        table = {
            'req1': ('client', rs.request_packet(app=0xc1)),
            'ack1': ('server', rs.ack_packet()),
            'rsp1': ('server', rs.response_packet(app=0xc1)),
            'req2': ('client', rs.request_packet(seq=1020, ack=2049, app=0xc2)),
            'ack2': ('server', rs.ack_packet(seq=2049, ack=1040)),
            'rsp2': ('server', rs.response_packet(seq=2049, ack=1040, app=0xc2)),
        }
        return [(label,) + table[label.split('~')[0]] for label in labels]

    @staticmethod
    def wgen(raw):
        return struct.unpack('!I', raw[4:8])[0]

    def test_one_transaction_with_n_wgens_completes(self):
        """Scenario 1: request, ACK and response each carry the distinct wgen N really assigns."""
        for source in self.N_SOURCES:
            with self.subTest(source):
                n = self.n_run(source, self.steps('req1', 'ack1', 'rsp1'))
                wgens = [self.wgen(n[k]) for k in ('req1', 'ack1', 'rsp1')]
                self.assertEqual(len(set(wgens)), 3, 'N gives each packet of one transaction its own wgen')
                self.assertEqual(wgens, sorted(wgens))
                sim = QueueSim()
                sim.handoff(T0, n['req1'])
                sim.handoff(T0 + ACK_OFF, n['ack1'])
                sim.handoff(T0 + RSP_OFF, n['rsp1'])
                sim.run(HORIZON)
                finished(self, sim)
                ack, rsp = sim.emissions(n['ack1'][16:], FORWARD), sim.emissions(n['rsp1'][16:], FORWARD)
                self.assertEqual((len(ack), len(rsp)), (1, 1))
                self.assertEqual(sim.emissions(n['req1'][16:], RELAY), [T0])
                self.assertGreaterEqual(ack[0], q(T0) + DA)
                self.assertGreaterEqual(rsp[0], ack[0] + GAP)
                self.assertEqual((out(sim, 'OUT_ACK_COMMIT'), out(sim, 'OUT_RESP_RELEASE')), (1, 1))
                self.assertEqual((out(sim, 'OUT_ACK_FALLBACK'), out(sim, 'OUT_RESP_FALLBACK')), (0, 0))

    def test_retransmissions_n_really_produces(self):
        """Scenario 2: a TCP-retransmitted request never reaches T (N refuses it outside owner state
        5); a duplicate ACK reaches T with its own wgen and does not disturb the transaction; a
        retransmitted response after N accepted the first is refused by N."""
        for source in self.N_SOURCES:
            with self.subTest(source):
                n = self.n_run(source, self.steps('req1', 'req1~again', 'ack1', 'ack1~dup', 'rsp1', 'rsp1~again'))
                self.assertIsNone(n['req1~again'], 'retransmitted request is not handed to T')
                self.assertTrue(n['req1~again:out'].dropped)
                self.assertIsNone(n['rsp1~again'], 'retransmitted response is not handed to T')
                self.assertTrue(n['rsp1~again:out'].dropped)
                self.assertNotEqual(self.wgen(n['ack1']), self.wgen(n['ack1~dup']))
                self.assertEqual(n['ack1'][8:], n['ack1~dup'][8:], 'same original, only wgen differs')
                sim = QueueSim()
                sim.handoff(T0, n['req1'])
                sim.handoff(T0 + ACK_OFF, n['ack1'])
                sim.handoff(T0 + ACK_OFF + 10_000, n['ack1~dup'])
                sim.handoff(T0 + RSP_OFF, n['rsp1'])
                sim.run(HORIZON)
                finished(self, sim)
                self.assertEqual(sim.cell('gen_alloc_reg'), 1, 'one admitted transaction')
                acks, rsp = sim.emissions(n['ack1'][16:], FORWARD), sim.emissions(n['rsp1'][16:], FORWARD)
                self.assertEqual((len(acks), len(rsp)), (2, 1))
                self.assertGreaterEqual(min(acks), q(T0) + DA)
                self.assertGreaterEqual(rsp[0], min(acks) + GAP)
                self.assertEqual(out(sim, 'OUT_RESP_RELEASE'), 1)

    def test_old_response_cannot_reach_t_after_a_newer_request(self):
        """Scenario 3: after transaction 2's request is admitted, the old response (and its ACK)
        arriving late at N are refused (response) or forwarded natively around T (pure ACK); T's view
        of transaction 2 is identical to a run without the late packets."""
        for source in self.N_SOURCES:
            with self.subTest(source):
                n = self.n_run(source, self.steps('req1', 'ack1', 'rsp1', 'req2', 'rsp1~late', 'ack1~late',
                                                  'ack2', 'rsp2'))
                self.assertIsNone(n['rsp1~late'])
                self.assertTrue(n['rsp1~late:out'].dropped, 'N refuses the stale response')
                self.assertIsNone(n['ack1~late'])
                self.assertEqual([p for p, _ in n['ack1~late:out'].emitted], [1], 'stale ACK bypasses T natively')
                second = T0 + CAP + 1_000_000
                runs = []
                for late in (False, True):
                    sim = QueueSim()
                    for base, (req, ack, rsp) in ((T0, ('req1', 'ack1', 'rsp1')), (second, ('req2', 'ack2', 'rsp2'))):
                        sim.handoff(base, n[req])
                        sim.handoff(base + ACK_OFF, n[ack])
                        sim.handoff(base + RSP_OFF, n[rsp])
                    if late:   # what N handed T for the late packets: nothing
                        for label in ('rsp1~late', 'ack1~late'):
                            if n[label] is not None:
                                sim.handoff(second + 20_000, n[label])
                    sim.run(second + CAP + 2_000_000)
                    finished(self, sim)
                    runs.append(sim)
                clean, dirty = runs
                for frame in (n['ack2'][16:], n['rsp2'][16:]):
                    self.assertEqual(dirty.emissions(frame), clean.emissions(frame))
                self.assertEqual(out(dirty, 'OUT_HELD_STALE_FLUSH'), 0)
                self.assertEqual((out(dirty, 'OUT_ACK_COMMIT'), out(dirty, 'OUT_RESP_RELEASE')), (2, 2))

    def test_old_response_still_held_does_not_open_the_new_ack_gate(self):
        """Scenario 3, the only real-path overlap: N returns to idle when the old response passes
        it, so a new request can be admitted while T still holds that response. The held old response
        is flushed as stale and its admission (generation 1) does not satisfy generation 2's ACK gate:
        with no response of its own, the new ACK waits for readiness and leaves as a fallback."""
        for source in self.N_SOURCES:
            with self.subTest(source):
                n = self.n_run(source, self.steps('req1', 'ack1', 'rsp1', 'req2', 'ack2'))
                self.assertTrue(all(n[k] is not None for k in ('req1', 'ack1', 'rsp1', 'req2', 'ack2')))
                req2_at = T0 + RSP_OFF + 20_000             # before rsp1's a_commit + gap release
                sim = QueueSim()
                sim.handoff(T0, n['req1'])
                sim.handoff(T0 + ACK_OFF, n['ack1'])
                sim.handoff(T0 + RSP_OFF, n['rsp1'])
                sim.handoff(req2_at, n['req2'])
                sim.handoff(req2_at + ACK_OFF, n['ack2'])
                sim.run(req2_at + CAP + 2_000_000)
                finished(self, sim)
                self.assertGreaterEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 1, 'generation-1 originals flushed')
                self.assertEqual(len(sim.emissions(n['rsp1'][16:], FORWARD)), 1, 'old response delivered once')
                ack2 = sim.emissions(n['ack2'][16:], FORWARD)
                self.assertEqual(len(ack2), 1)
                self.assertGreaterEqual(ack2[0], q(req2_at) + READINESS, 'old response did not open the new gate')
                self.assertEqual(out(sim, 'OUT_ACK_FALLBACK'), 1)

    def test_t_alone_does_not_associate_a_response_bypassing_n(self):
        """The trust boundary, recorded rather than hidden: the same stale response N refuses in
        scenario 3, injected directly at T_IN (bypassing N), IS admitted into generation 2 and opens
        its ACK gate. T has no association check of its own; the guarantee above is N's. If T ever
        gains one, this test is expected to change."""
        n = self.n_run(self.N_SOURCES[0], self.steps('req1', 'ack1', 'rsp1', 'req2', 'ack2'))
        second = T0 + CAP + 1_000_000
        sim = QueueSim()
        sim.handoff(T0, n['req1'])
        sim.handoff(T0 + ACK_OFF, n['ack1'])
        sim.handoff(T0 + RSP_OFF, n['rsp1'])
        sim.handoff(second, n['req2'])
        sim.handoff(second + ACK_OFF, n['ack2'])
        sim.handoff(second + RSP_OFF, n['rsp1'])        # synthetic: N would have dropped this
        sim.run(second + CAP + 2_000_000)
        finished(self, sim)
        self.assertEqual(out(sim, 'OUT_ACK_FALLBACK'), 0)
        self.assertEqual(out(sim, 'OUT_ACK_COMMIT'), 2, 'the bypassing stale response opened generation 2')


CLOCK_WRAP = 1 << 32           # md.now is the 32-bit truncation of the 48-bit global timestamp
RESET_OFF = 200_000            # OPERATE -> RESET spacing of Philip's 2026-10-08 temporary-copy run


class I_OperateDeadlineAnchor(unittest.TestCase):
    """The OPERATE hold is anchored on the arrival of the operation being held. RESET flushes a held
    OPERATE promptly by bumping the OPERATE generation (since 2026-10-09; it used to zero the anchor),
    so the held original fails its generation check and leaves as a stale flush."""

    def test_second_operate_is_held_to_its_own_deadline(self):
        """Regression: op_t0_arm used to write only when op_t0_reg was zero, so a second OPERATE
        with no RESET in between inherited the first one's anchor and left 200,000 ns after its
        own arrival instead of no earlier than q(arrival) + OP_J (599,808 ns)."""
        sim = QueueSim()
        second = T0 + 2_000_000
        sim.operate(T0)
        sim.operate(second)
        sim.run(second + 2_000_000)
        finished(self, sim)
        releases = sim.emissions(OP_FRAME, RELAY)
        self.assertEqual(len(releases), 2)
        self.assertGreaterEqual(releases[0], q(T0) + OP_J)
        self.assertGreaterEqual(releases[1], q(second) + OP_J, 'second OPERATE released before its own deadline')

    def test_reset_flushes_a_held_operate_150us_after_the_reset(self):
        """Non-regression for the RESET path: RESET bumps the OPERATE generation, so the held OPERATE
        fails its generation check and is flushed on the next ladder round (150,000 ns here) instead of
        waiting for the full hold (570,000 ns). (Before 2026-10-09 the same timing came from a zeroed
        op_t0_reg read as overdue, which broke near the clock wrap, next test.)"""
        sim = QueueSim()
        sim.operate(T0)
        sim.reset(T0 + RESET_OFF)
        sim.run(T0 + 3_000_000)
        finished(self, sim)
        releases = sim.emissions(OP_FRAME, RELAY)
        self.assertEqual(len(releases), 1)
        self.assertEqual(releases[0] - (T0 + RESET_OFF), 150_000)

    def test_operate_deadline_crossing_the_clock_wrap_is_honored(self):
        """Arm op_t0 300 us below the 32-bit wrap so the deadline sum wraps: the release offset must
        equal the same run far from the wrap, not leave early or stall."""
        reference = QueueSim()
        reference.operate(T0)
        reference.run(T0 + 3_000_000)
        base = CLOCK_WRAP - 300_000
        sim = QueueSim()
        sim.operate(base)
        sim.run(base + 3_000_000)
        finished(self, sim)
        self.assertGreater((sim.cell('op_t0_reg') & ~1) + OP_J, CLOCK_WRAP - 1, 'the deadline sum really wraps')
        releases = sim.emissions(OP_FRAME, RELAY)
        self.assertEqual(len(releases), 1)
        self.assertGreaterEqual(releases[0], q(base) + OP_J)
        self.assertEqual(releases[0] - base, reference.emissions(OP_FRAME, RELAY)[0] - T0)

    def test_reset_flush_near_the_clock_wrap(self):
        """Formerly a KNOWN DEFECT (expectedFailure): a cleared op_t0_reg made op_delta = now - OP_J,
        whose sign bit is set in the upper half of the 32-bit clock, so the flush was late (870,000 ns at
        CLOCK_WRAP - 300 us, 1.074 s at 0xC0000000). Fixed 2026-10-09 by the generation-scoped RESET. The
        flush must happen by the generation mechanism (a stale flush, not a timed release) at every clock
        phase, including both phases the old defect was measured at."""
        for base in (CLOCK_WRAP - 300_000, 0xC0000000):
            with self.subTest(base=hex(base)):
                sim = QueueSim()
                sim.operate(base)
                sim.reset(base + RESET_OFF)
                sim.run(base + 3_000_000)
                finished(self, sim)
                releases = sim.emissions(OP_FRAME, RELAY)
                self.assertEqual(len(releases), 1)
                self.assertEqual(releases[0] - (base + RESET_OFF), 150_000)
                self.assertEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 1, 'flushed by its stale generation')
                self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 0, 'not a timed release')

class J_GenerationScopedReset(unittest.TestCase):
    """RESET and readiness fallback under generation-scoped state (2026-10-09): a_commit is usable only
    when ack_commit_gen_reg is the current READ generation, and RESET invalidates OPERATE by bumping its own
    generation allocator. Release times are unchanged from the zero-clear design in every case here; what
    changes is that a fallback or stale a_commit can no longer masquerade as a genuine one."""

    def test_fallback_ack_does_not_supply_a_commit_to_the_response(self):
        """The ACK finishes by readiness fallback (no response yet), so no a_commit is recorded. The late
        response must open by readiness and be counted as a fallback, not as a gap release computed from
        an a_commit that never happened (the zero-clear design counted OUT_RESP_RELEASE here)."""
        sim = QueueSim()
        sim.request(T0)
        sim.ack(T0 + ACK_OFF)
        late = T0 + READINESS + 400_000
        sim.response(late)
        sim.run(T0 + CAP + 3_000_000)
        finished(self, sim)
        self.assertEqual(out(sim, 'OUT_ACK_FALLBACK'), 1)
        self.assertGreaterEqual(sim.emissions(ACK_FRAME)[0], q(T0) + READINESS)
        self.assertEqual(len(sim.emissions(RSP_FRAME, FORWARD)), 1)
        self.assertGreaterEqual(sim.emissions(RSP_FRAME)[0], late)
        self.assertEqual((out(sim, 'OUT_RESP_FALLBACK'), out(sim, 'OUT_RESP_RELEASE')), (1, 0))

    def test_stale_a_commit_from_an_earlier_generation_is_not_used(self):
        """Generation 1 commits genuinely; generation 2's ACK finishes by fallback. Generation 1's a_commit
        is still in ack_commit_at_reg, but its tag is not the current generation, so generation 2's
        response is a fallback, not a gap release from the old timestamp."""
        sim = QueueSim()
        sim.read(T0)
        second = T0 + CAP + 1_000_000
        sim.request(second)
        sim.ack(second + ACK_OFF)
        sim.response(second + READINESS + 400_000)
        sim.run(second + CAP + 3_000_000)
        finished(self, sim)
        self.assertEqual((out(sim, 'OUT_ACK_COMMIT'), out(sim, 'OUT_ACK_FALLBACK')), (1, 1))
        self.assertEqual((out(sim, 'OUT_RESP_RELEASE'), out(sim, 'OUT_RESP_FALLBACK')), (1, 1))
        self.assertNotEqual(sim.cell('ack_commit_gen_reg'), sim.cell('gen_alloc_reg'))

    def test_reset_invalidates_a_held_operate_by_its_own_generation(self):
        """RESET bumps the OPERATE allocator (separate from READ's): the held OPERATE is flushed to the
        relay as stale (released, not dropped, not counted as a timed release) and its blockers die
        stale instead of continuing to circulate."""
        sim = QueueSim()
        sim.operate(T0)
        sim.reset(T0 + 20_000)
        sim.run(T0 + 3_000_000)
        finished(self, sim)
        self.assertEqual(sim.cell('op_gen_alloc_reg'), 2, 'admission 1, RESET 2')
        self.assertEqual(len(sim.emissions(OP_FRAME, RELAY)), 1, 'the held original is not lost')
        self.assertEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 1)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 0)
        self.assertGreater(out(sim, 'OUT_TOKEN_STALE'), 0, 'old-generation OPERATE blockers die stale')

    def test_reset_just_after_an_operate_flushes_it_as_stale(self):
        """RESET inside the window between the OPERATE's admission and its clone's return (pktgen_ns/2 in
        the simulator). The held original must carry the admitted OPERATE's generation (the clone's tag),
        not the generation current when the clone returns: otherwise it passes the generation check after
        the RESET and is released on its old deadline (630,000 ns, counted OUT_OP_RELEASE)."""
        for dt in (1_000, 3_000, 5_000):
            with self.subTest(dt=dt):
                sim = QueueSim()
                sim.operate(T0)
                sim.reset(T0 + dt)
                sim.run(T0 + 3_000_000)
                finished(self, sim)
                relay = sim.emissions(OP_FRAME, RELAY)
                self.assertEqual(len(relay), 1, 'the held original is not lost')
                self.assertLess(relay[0], q(T0) + OP_J, 'flushed, not held to its old deadline')
                self.assertEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 1)
                self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 0)

    def test_two_operates_inside_the_clone_window_both_reach_the_relay(self):
        """A second OPERATE 1 us after the first, inside the first one's clone window. The first held
        original carries its own generation (the clone's tag), so it is flushed as stale once superseded,
        and the second is released on its own deadline. Before 2026-10-09 the first original took the
        second's generation from a fresh register read and was never released at all (one relay emission)."""
        sim = QueueSim()
        sim.operate(T0)
        sim.operate(T0 + 1_000)
        sim.run(T0 + 3_000_000)
        finished(self, sim)
        relay = sim.emissions(OP_FRAME, RELAY)
        self.assertEqual(len(relay), 2, 'neither OPERATE is lost')
        self.assertEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 1)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1)
        self.assertGreaterEqual(max(relay), q(T0 + 1_000) + OP_J, 'the second keeps its own deadline')

    def test_after_reset_both_domains_start_from_their_own_anchors(self):
        """After a RESET that superseded a held OPERATE and a held READ transaction, a new OPERATE and a
        new-epoch READ are each held to their own deadlines, and the new READ's response follows its own
        new a_commit by the configured gap: no state from before the RESET moves them."""
        sim = QueueSim()
        sim.operate(T0)
        sim.read(T0, epoch=1)
        sim.reset(T0 + 200_000, epoch=1)
        later = T0 + 1_000_000
        sim.operate(later, epoch=2)
        sim.read(later, epoch=2)
        sim.run(later + CAP + 3_000_000)
        finished(self, sim)
        relay = sim.emissions(OP_FRAME, RELAY)
        self.assertEqual(len(relay), 2)
        self.assertLess(relay[0], later, 'the pre-RESET OPERATE was flushed at the RESET')
        self.assertGreaterEqual(relay[1], q(later) + OP_J, 'the new OPERATE keeps its own deadline')
        acks, rsps = sim.emissions(ACK_FRAME), sim.emissions(RSP_FRAME)
        self.assertEqual((len(acks), len(rsps)), (2, 2))
        self.assertGreaterEqual(acks[1], q(later) + DA)
        self.assertGreaterEqual(rsps[1], acks[1] + GAP, 'gap measured from the new a_commit')
        self.assertEqual(sim.cell('ack_commit_at_reg'), q(acks[1]))
        self.assertEqual((out(sim, 'OUT_OP_RELEASE'), out(sim, 'OUT_RESP_RELEASE')), (1, 1))



class L_QualifiedCloseForwarded(unittest.TestCase):
    """N hands a close it qualified (RST / FIN on the bound connection) to T as tev kind 4 with the original
    behind it and stage = direction (1 client, 2 server). T must forward that original exactly once -- client
    close to the relay, server close to the master -- as read_timing.p4 did, and still quarantine the epoch.
    Stage 0 is a synthetic reset with no original and is dropped. (Found by the response-only composite model
    run, route_ab_01/response_only_15/model_02: the master's RST reached neither endpoint.)"""

    def frames(self):
        """Genuine endpoint teardown segments, as N forwards them behind the tev (vectors.packet)."""
        v = n_support().vectors
        return {'master_rst': v.packet(0x14, 1020, 2000),                  # RST|ACK from the master
                'outstation_fin': v.packet(0x11, 2000, 1020, reverse=True)}  # FIN|ACK from the outstation

    def run_close(self, stage, frame):
        sim = QueueSim()
        sim.reset(T0, stage=stage, frame=frame)
        sim.run(T0 + 1_000_000)
        return sim

    def test_genuine_master_rst_reaches_the_outstation_once(self):
        frame = self.frames()['master_rst']
        sim = self.run_close(1, frame)
        self.assertEqual(len(sim.emissions(frame, RELAY)), 1)
        self.assertEqual(sim.emissions(frame, FORWARD), [])
        self.assertEqual(sim.cell('quarantine_reg'), 1, 'the epoch is still quarantined')

    def test_genuine_outstation_fin_reaches_the_master_once(self):
        frame = self.frames()['outstation_fin']
        sim = self.run_close(2, frame)
        self.assertEqual(len(sim.emissions(frame, FORWARD)), 1)
        self.assertEqual(sim.emissions(frame, RELAY), [])
        self.assertEqual(sim.cell('quarantine_reg'), 1)

    def test_synthetic_reset_reaches_neither_endpoint(self):
        """Stage 0: a control-plane/synthetic reset, not an endpoint teardown. Same quarantine, no output -- a
        separate case from the genuine closes above, with a frame that would be forwarded at stage 1 or 2."""
        frame = self.frames()['master_rst']
        sim = self.run_close(0, frame)
        self.assertEqual(sim.emissions(frame), [])
        self.assertEqual(sim.cell('quarantine_reg'), 1)
        default = self.run_close(0, None)          # QueueSim's own synthetic reset frame
        self.assertEqual(default.emitted, [])


from queue_sim import PKTGEN_PIPE, PORTS  # noqa: E402  (ports.p4, via whole_program)


class M_CloneOrTokenByContent(unittest.TestCase):
    """On this switch the generator's tokens arrive on the pipe's local 68 (pipe_local_source_port = 68), which
    is PKTGEN_RETURN (196), where T's mirror clones also arrive. T must tell them apart by content: every clone
    tag starts with CLONE_MARKER 0xE1 (exact 8-bit match); a timer header's first byte is <= 0x1F."""

    @staticmethod
    def token_bytes(gen, packet_id, profile=1, pipe=1):
        # pktgen timer header as Tofino-1 delivers it from T's pipe 1: pad(3)=0 | pipe(2) | app(3), pad, batch, packet
        return bytes([pipe << 3 | profile]) + bytes([profile]) + struct.pack('!HH', gen, packet_id) + bytes(10)

    def stale_token_run(self, port):
        second = T0 + CAP + 1_000_000
        sim = QueueSim()
        sim.read(T0)
        sim.read(second)
        if port is not None:
            sim.at(second + 30_000, port, self.token_bytes(gen=1, packet_id=0))
        sim.run(T0 + 2 * CAP + 4_000_000)
        finished(self, sim)
        return sim

    def test_a_generator_token_on_pktgen_return_is_handled_as_a_token(self):
        clean = out(self.stale_token_run(None), 'OUT_TOKEN_STALE')
        on_196 = out(self.stale_token_run(PORTS['PKTGEN_RETURN']), 'OUT_TOKEN_STALE')
        on_0 = out(self.stale_token_run(0), 'OUT_TOKEN_STALE')    # the model's own pktgen ingress port
        self.assertEqual((on_196 - clean, on_0 - clean), (1, 1), 'reaches the token verdict on 196 as on 0')

    def test_a_clone_on_pktgen_return_is_marked_and_handled_as_a_clone(self):
        sim = QueueSim()
        clones = []
        at = sim.at
        sim.at = lambda time, port, raw, kind='ingress': (clones.append(raw) if port == PORTS['PKTGEN_RETURN']
                                                          else None, at(time, port, raw, kind))[1]
        sim.operate(T0)
        sim.run(T0 + OP_J + 4_000_000)
        finished(self, sim)
        self.assertTrue(clones, 'the OPERATE admission produced a clone')
        self.assertEqual({c[0] for c in clones}, {0xE1}, 'every clone tag starts with CLONE_MARKER')
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1, 'the clone was admitted as a clone and released')

    def test_an_unmarked_frame_on_pktgen_return_is_not_taken_for_a_clone(self):
        """A frame shaped like a pre-marker clone (tag 0x0001xxxx + a kind-12 tev + the OPERATE) is not a clone:
        no held OPERATE, no release."""
        sim = QueueSim()
        unmarked = struct.pack('!I', 0x00010001) + struct.pack('!IIIBBH', 1, 0, 0, 12, 0, 0) + OP_FRAME
        sim.at(T0, PORTS['PKTGEN_RETURN'], unmarked)
        sim.run(T0 + OP_J + 4_000_000)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 0)
        self.assertEqual(sim.emissions(OP_FRAME), [])


class N_CloneMarkerAcrossGenerationRollover(unittest.TestCase):
    """The OPERATE clone tag's bits 31:16 must be exactly 0xE101 at every op_gen: the parser matches the 0xE1
    marker byte exactly, and the packet generator's OPERATE trigger pattern is 0xE101xxxx / mask 0xFFFF0000.
    `op_gen | 0xE1010000` corrupted bits 31:16 from op_gen = 0x20000 and the marker byte from 0x2000000."""

    OP_GENS = (0xFFFF, 0x10000, 0x20000, 0xFFFFFF, 0x1000000, 0x2000000, 0xFFFFFFFF)

    @staticmethod
    def operate_at(op_gen, done=0):
        """One OPERATE admitted with generation op_gen (the allocator is preloaded to op_gen - 1)."""
        sim = QueueSim()
        sim.src.cells[('', 'op_gen_alloc_reg')][0] = (op_gen - 1) & 0xFFFFFFFF
        sim.src.cells[('', 'op_done_reg')][0] = done
        clones = []
        at = sim.at
        sim.at = lambda time, port, raw, kind='ingress': (clones.append(raw) if port == PORTS['PKTGEN_RETURN']
                                                          else None, at(time, port, raw, kind))[1]
        sim.operate(T0)
        sim.run(T0 + OP_J + 4_000_000)
        return sim, clones

    def test_operate_clone_tag_top_half_is_exactly_e101_and_released_once(self):
        for op_gen in self.OP_GENS:
            with self.subTest(op_gen=hex(op_gen)):
                sim, clones = self.operate_at(op_gen)
                finished(self, sim)
                self.assertTrue(clones)
                self.assertEqual({c[0] for c in clones}, {0xE1}, 'marker byte')
                self.assertEqual({c[:2] for c in clones}, {b'\xe1\x01'}, 'pktgen trigger pattern 0xE101xxxx')
                self.assertEqual({struct.unpack('!I', c[:4])[0] & 0xFFFF for c in clones}, {op_gen & 0xFFFF})
                self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1)
                self.assertEqual(len(sim.emissions(OP_FRAME)), 1)

    def test_read_clone_keeps_its_marker_at_any_generation(self):
        for alloc in (0x0000FFFF, 0x01FFFFFF, 0xFFFFFFF0):
            with self.subTest(read_generation=hex(alloc)):
                sim = QueueSim()
                sim.src.cells[('', 'gen_alloc_reg')][0] = alloc
                clones = []
                at = sim.at
                sim.at = lambda time, port, raw, kind='ingress': (clones.append(raw) if port == PORTS['PKTGEN_RETURN']
                                                                  else None, at(time, port, raw, kind))[1]
                sim.read(T0)
                sim.run(T0 + CAP + 4_000_000)
                finished(self, sim)
                self.assertTrue(clones)
                self.assertEqual({c[0] for c in clones}, {0xE1})


class O_OperateGenerationBoundary(unittest.TestCase):
    """The clone tag, the ladder and the generator token carry 16 generation bits; op_gen / op_done compare 32.
    Across 0xFFFF -> 0x10000 (low 16 = 0) every superseded or delayed OPERATE item must be flushed or dropped
    as stale: never released as current, never released twice. Comparisons: op_lgen_diff (ladder ^ op_gen, 16
    bit), op_tok_diff (token batch ^ op_gen, 16 bit), clone-tag low 16 -> ladder, op_done ^ op_gen (32 bit).
    A 16-bit alias needs an item delayed by exactly 65,536 generations; held items and tokens live for
    milliseconds, and the only long-lived state, op_done_reg, compares 32 bits."""

    OP_B = OP_FRAME[:-1] + b'\x77'

    @staticmethod
    def at_generation(alloc):
        sim = QueueSim()
        sim.src.cells[('', 'op_gen_alloc_reg')][0] = alloc
        return sim

    def assert_flushed_once(self, sim, frame=OP_FRAME):
        self.assertEqual(len(sim.emissions(frame, RELAY)), 1, 'reaches the relay exactly once')
        self.assertEqual(out(sim, 'OUT_HELD_STALE_FLUSH'), 1)

    def clone_from_generation_ffff(self):
        sim = self.at_generation(0xFFFE)
        clones = []
        at = sim.at
        sim.at = lambda time, port, raw, kind='ingress': (clones.append(raw) if port == PORTS['PKTGEN_RETURN']
                                                          else None, at(time, port, raw, kind))[1]
        sim.operate(T0)
        sim.run(T0 + OP_J + 4_000_000)
        self.assertEqual(len(clones), 1)
        self.assertEqual(clones[0][:4], b'\xe1\x01\xff\xff')
        return clones[0]

    def test_operate_at_ffff_superseded_by_reset_to_10000_is_flushed_not_released(self):
        sim = self.at_generation(0xFFFE)
        sim.operate(T0)
        sim.reset(T0 + 20_000)
        sim.run(T0 + 3_000_000)
        finished(self, sim)
        self.assertEqual(sim.cell('op_gen_alloc_reg'), 0x10000)
        self.assert_flushed_once(sim)
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 0)
        self.assertGreater(out(sim, 'OUT_TOKEN_STALE'), 0, 'its 0xFFFF blockers die stale at 0x10000')

    def test_operate_at_ffff_superseded_by_operate_at_10000(self):
        sim = self.at_generation(0xFFFE)
        sim.operate(T0)
        sim.operate(T0 + 1_000, frame=self.OP_B)
        sim.run(T0 + OP_J + 4_000_000)
        finished(self, sim)
        self.assert_flushed_once(sim)                                   # A (0xFFFF): stale flush
        self.assertEqual(len(sim.emissions(self.OP_B, RELAY)), 1)        # B (0x10000): released once
        self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1)

    def test_delayed_clone_from_ffff_at_10000_and_after_a_reset_is_not_released(self):
        clone = self.clone_from_generation_ffff()
        for reset in (False, True):
            with self.subTest(reset_bump_to_10001=reset):
                sim = self.at_generation(0x10000)
                if reset:
                    sim.reset(T0 - 50_000)
                sim.at(T0, PORTS['PKTGEN_RETURN'], clone)
                sim.run(T0 + OP_J + 4_000_000)
                finished(self, sim)
                self.assertEqual(sim.cell('op_gen_alloc_reg'), 0x10001 if reset else 0x10000)
                self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 0, 'never released as current')
                self.assert_flushed_once(sim)

    def test_delayed_operate_token_from_ffff_at_10000_dies_stale(self):
        sim = self.at_generation(0x10000)
        token = bytes([1 << 3 | 1, 1]) + struct.pack('!HH', 0xFFFF, 0) + bytes(10)    # app 1 = OPERATE domain
        sim.at(T0, PORTS['PKTGEN_RETURN'], token)
        sim.run(T0 + 1_000_000)
        finished(self, sim)
        self.assertEqual(out(sim, 'OUT_TOKEN_STALE'), 1)
        self.assertEqual(sim.enqueued, [], 'no OPERATE blocker seeded')

    def test_op_done_compares_32_bits_across_the_16_bit_alias(self):
        """op_done_reg = 0 is its load-time value (no OPERATE ever committed); after 65,535 RESET bumps the next
        OPERATE gets 0x10000, whose low 16 bits are 0. A 16-bit op_done comparison would read it as already
        done and never release it; the 32-bit one releases it once. Also with op_done = 1 (a committed one)."""
        for done in (0, 1):
            with self.subTest(op_done=done):
                sim = self.at_generation(0xFFFF)
                sim.src.cells[('', 'op_done_reg')][0] = done
                sim.operate(T0)
                sim.run(T0 + OP_J + 4_000_000)
                finished(self, sim)
                self.assertEqual(out(sim, 'OUT_OP_RELEASE'), 1)
                self.assertEqual(len(sim.emissions(OP_FRAME, RELAY)), 1)


class P_ForeignIngressIsInert(unittest.TestCase):
    """Only PKTGEN_RETURN (and the model's generator port 0) may carry tokens, only in the expected format
    (pipe PKTGEN_PIPE, app 0/1), and only PKTGEN_RETURN may carry clones (exact 0xE1 marker). Any other pipe-1
    ingress -- front-panel 164-191 are enabled on the switch -- is dropped explicitly and must change nothing:
    no blocker seeded, no register, no counter, no emission. Each case is compared with the same run without
    the foreign frame, with live READ and OPERATE state at the time it arrives."""

    FRONT = (164, 177, 191)

    def scenario(self, injections):
        sim = QueueSim()
        sim.read(T0)
        sim.operate(T0 + 10_000)
        for port, raw in injections:
            sim.at(T0 + 40_000, port, raw)
        sim.run(T0 + CAP + OP_J + 4_000_000)
        return sim

    @staticmethod
    def snapshot(sim):
        cells = {k: list(v) for k, v in sim.src.cells.items()}
        return cells, list(sim.enqueued), [(p, raw) for _, p, raw in sim.emitted]

    def assert_inert(self, injections):
        clean, dirty = self.scenario([]), self.scenario(injections)
        finished(self, dirty)
        c_cells, c_enq, c_out = self.snapshot(clean)
        d_cells, d_enq, d_out = self.snapshot(dirty)
        for key in c_cells:
            self.assertEqual(d_cells[key], c_cells[key], 'register/counter %s changed' % (key,))
        self.assertEqual(len(d_enq), len(c_enq), 'a foreign frame seeded a blocker')
        self.assertEqual(d_out, c_out, 'emissions differ')
        for _, raw in injections:
            self.assertNotIn(raw, [r for _, r in d_out], 'a foreign frame was forwarded')

    @staticmethod
    def frames():
        timer_like = bytes([PKTGEN_PIPE << 3 | 1, 1]) + struct.pack('!HH', 1, 0) + bytes(54)   # current op gen 1
        read_timer_like = bytes([PKTGEN_PIPE << 3 | 0, 0]) + struct.pack('!HH', 1, 0) + bytes(54)
        marked = struct.pack('!I', 0xE1010001) + struct.pack('!IIIBBH', 1, 0, 0, 12, 0, 0) + OP_FRAME
        return {'ordinary': REQ_FRAME[:-1] + bytes([REQ_FRAME[-1] ^ 0xFF]), 'timer_like': timer_like, 'read_timer_like': read_timer_like,
                'starts_0xE1': marked}

    def test_front_panel_traffic_changes_nothing(self):
        for port in self.FRONT:
            for name, raw in self.frames().items():
                with self.subTest(port=port, frame=name):
                    self.assert_inert([(port, raw)])

    def test_wrong_format_token_on_the_generator_port_changes_nothing(self):
        wrong_pipe = bytes([2 << 3 | 1, 1]) + struct.pack('!HH', 1, 0) + bytes(10)
        wrong_app = bytes([PKTGEN_PIPE << 3 | 3, 3]) + struct.pack('!HH', 1, 0) + bytes(10)
        for name, raw in (('wrong_pipe', wrong_pipe), ('wrong_app', wrong_app)):
            for port in (PORTS['PKTGEN_RETURN'], PORTS['MODEL_PKTGEN_IN']):
                with self.subTest(frame=name, port=port):
                    self.assert_inert([(port, raw)])


class K_ResetValues(unittest.TestCase):
    """Registers whose reset value must NOT be 0 (control-plane rule, TIMING_QUEUE_MIGRATION_STATUS.md).
    Each holds a generation or epoch that is compared for equality with a live one, and 0 is a live READ
    generation (before the first request) and a possible epoch. Any control-plane clear or re-init of
    these registers must restore 0xffffffff, never 0."""

    NONZERO = ('child_seen0_reg', 'child_seen1_reg', 'child_seen2_reg', 'ack_commit_gen_reg', 'quarantine_reg')

    def test_generation_and_epoch_registers_reset_to_all_ones(self):
        sim = QueueSim()
        for name in self.NONZERO:
            with self.subTest(register=name):
                self.assertEqual(sim.cell(name), 0xffffffff)

    def test_generation_zero_response_is_delivered_once_not_dropped(self):
        """Generation 0 is live only before the first request. resp_done_reg also resets to 0, so a
        generation-0 response takes the "already released in this generation" row and passes straight
        through, before any duplicate check: it is delivered once and never dropped as a duplicate, even
        if the child registers were zeroed. The all-ones reset values above remain the guard; this pins
        the generation-0 behavior they protect."""
        sim = QueueSim()
        sim.response(T0, epoch=0)
        sim.run(T0 + CAP + 2_000_000)
        finished(self, sim)
        self.assertEqual(len(sim.emissions(RSP_FRAME, FORWARD)), 1)
        self.assertEqual(out(sim, 'OUT_RESP_DUP_DROP'), 0)


if __name__ == '__main__':
    unittest.main()
