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
import unittest

from queue_sim import (ACK_FRAME, CAP, CHILD1, CHILD2, DA, FORWARD, GAP, LADDER, OP_FRAME, OP_J,
                       OP_LADDER, READINESS, RELAY, REQ_FRAME, RSP_FRAME, T0, QueueSim, q)


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

    def test_duplicate_ack_arms_the_response_deadline_once(self):
        sim = QueueSim()
        sim.read(T0)
        sim.ack(T0 + ACK_OFF + 10_000)                  # duplicate ACK while the first is held
        armed = []
        sim.call(T0 + DA + 150_000, lambda s: armed.append(s.cell('resp_deadline')))
        sim.run(HORIZON)
        finished(self, sim)
        acks = sim.emissions(ACK_FRAME)
        self.assertEqual(len(acks), 2)
        self.assertEqual(sim.cell('resp_deadline'), armed[0], 'second commit did not re-arm')
        self.assertEqual(armed[0], q(acks[0]) + GAP | 1)
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


if __name__ == '__main__':
    unittest.main()
