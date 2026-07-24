#!/usr/bin/env python3
"""
Phase-2 transaction-core reference-model tests (END_TO_END_IMPLEMENTATION_PLAN.md §6, Phase 2 DoD).

These encode the frozen transaction-core semantics of dcrn_defense1.p4 PLUS the one thing Phase 2
adds: **generation freshness** (the staleness guard the frozen file deferred — `reg_gen` dropped,
`hdr.bridge.gen` hardcoded 0, dcrn_defense1.p4:365,581,618). No switch, no relay, no P4 — pure model.

DoD cases exercised: request/response correlation, DNP3 direction, TCP retransmission, duplicate
packets, unrelated/stale ACKs, resp-before-ACK (combined bypass), FIN/RST abort, timeout/expiration,
a second request while active, TCP seq-number wraparound, generation rollover, hash-collision
disambiguation, and pass-through of non-target traffic. "No stale state" is asserted after each
terminal transition.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from txncore_refmodel import (  # noqa: E402
    TxnCore, Pkt, Ev, DNP3_PORT, GEN_MOD, MASK32,
    tcp_read, tcp_pure_ack, tcp_response, tcp_fin, tcp_rst, tcp_syn,
)

# canonical flow key (client_ip, server_ip, client_port); the DNP3 master is the client.
KEY_A = (0x0A0A3613, 0x0A0A369E, 40000)   # 10.10.54.19 -> 10.10.54.158:20000, cport 40000
KEY_B = (0x0A0A3613, 0x0A0A369E, 40001)   # a second flow (different client port)


class TestArmAndCorrelation(unittest.TestCase):
    def setUp(self):
        self.tc = TxnCore()

    def test_read_arms_flow(self):
        ev = self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        self.assertEqual(ev.kind, Ev.ARM)
        st = self.tc.flow_state(KEY_A)
        self.assertEqual(st.armed, 1)
        self.assertEqual(st.exp_ack, (1000 + 20) & MASK32)  # request end-seq
        self.assertEqual(st.gen, 1)                          # first arm bumps gen 0 -> 1

    def test_read_wrong_direction_not_armed(self):
        # a "READ" arriving from dir==1 (outstation side) must NOT arm (physical direction contract)
        p = tcp_read(KEY_A, seq=1000, plen=20)
        p.dir = 1
        ev = self.tc.process(p)
        self.assertEqual(ev.kind, Ev.PASSTHRU)
        self.assertEqual(self.tc.flow_state(KEY_A).armed, 0)

    def test_arm_bypass_when_fc_not_allowed(self):
        p = tcp_read(KEY_A, seq=1000, plen=20)
        p.fc_ok = False
        ev = self.tc.process(p)
        self.assertEqual(ev.kind, Ev.ARM_BYPASS)
        self.assertEqual(self.tc.flow_state(KEY_A).armed, 0)

    def test_qualified_ack_is_held_once(self):
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        ev = self.tc.process(tcp_pure_ack(KEY_A, ack=1020))   # acks the request end-seq
        self.assertEqual(ev.kind, Ev.ACK_HELD)
        self.assertEqual(self.tc.held_frame(KEY_A).role, "ACK")
        self.assertEqual(self.tc.held_frame(KEY_A).gen, 1)     # stamped with the arm generation

    def test_response_admitted_behind_held_ack(self):
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        self.tc.process(tcp_pure_ack(KEY_A, ack=1020))
        ev = self.tc.process(tcp_response(KEY_A, seq=5000, plen=100))
        self.assertEqual(ev.kind, Ev.RESP_HELD)
        self.assertEqual(self.tc.flow_state(KEY_A).armed, 0)   # committed -> armed cleared
        self.assertEqual(self.tc.flow_state(KEY_A).resp_seen, 1)


class TestStaleAndDuplicateAcks(unittest.TestCase):
    def setUp(self):
        self.tc = TxnCore()
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))

    def test_ack_wrong_ackno_not_held(self):
        ev = self.tc.process(tcp_pure_ack(KEY_A, ack=999))     # keepalive/window-update: wrong ack
        self.assertEqual(ev.kind, Ev.ACK_PASSTHRU)
        self.assertIsNone(self.tc.held_frame(KEY_A))

    def test_duplicate_ack_after_hold_is_forwarded(self):
        self.assertEqual(self.tc.process(tcp_pure_ack(KEY_A, ack=1020)).kind, Ev.ACK_HELD)
        ev = self.tc.process(tcp_pure_ack(KEY_A, ack=1020))    # dup ACK -> one-shot occupancy forwards
        self.assertEqual(ev.kind, Ev.ACK_DUP_FORWARD)

    def test_ack_without_arm_is_forwarded(self):
        tc = TxnCore()                                         # no prior READ
        ev = tc.process(tcp_pure_ack(KEY_A, ack=1020))
        self.assertEqual(ev.kind, Ev.ACK_PASSTHRU)


class TestRetransmitAndSecondRequest(unittest.TestCase):
    def setUp(self):
        self.tc = TxnCore()

    def test_retransmitted_read_rearms_same_expack(self):
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        g1 = self.tc.flow_state(KEY_A).gen
        ev = self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))  # identical retransmit
        self.assertEqual(ev.kind, Ev.ARM)
        st = self.tc.flow_state(KEY_A)
        self.assertEqual(st.exp_ack, (1020) & MASK32)            # unchanged end-seq
        self.assertEqual(st.gen, (g1 + 1) % GEN_MOD)             # generation advances on re-arm
        # the retransmit's ACK (same ack_no) is still held exactly once
        self.assertEqual(self.tc.process(tcp_pure_ack(KEY_A, ack=1020)).kind, Ev.ACK_HELD)

    def test_second_distinct_request_rearms_and_stales_prior_hold(self):
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        self.tc.process(tcp_pure_ack(KEY_A, ack=1020))          # ACK held under gen=1
        held1 = self.tc.held_frame(KEY_A)
        self.assertEqual(held1.gen, 1)
        # a new request on the same flow before the old txn drained -> re-arm, gen=2
        self.tc.process(tcp_read(KEY_A, seq=2000, plen=20))
        self.assertEqual(self.tc.flow_state(KEY_A).gen, 2)
        # the still-in-loop ACK from gen=1 is now stale and must be discarded on its next pass
        ev = self.tc.release_pass(KEY_A)
        self.assertEqual(ev.kind, Ev.STALE_DISCARD)
        self.assertIsNone(self.tc.held_frame(KEY_A))


class TestRespBeforeAckAndAbort(unittest.TestCase):
    def setUp(self):
        self.tc = TxnCore()

    def test_response_before_ack_is_combined_bypass(self):
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        ev = self.tc.process(tcp_response(KEY_A, seq=5000, plen=100))  # no pure ACK was held
        self.assertEqual(ev.kind, Ev.COMBINED_BYPASS)
        self.assertEqual(self.tc.flow_state(KEY_A).armed, 0)           # armed cleared, no stale state
        self.assertIsNone(self.tc.held_frame(KEY_A))

    def test_pure_fin_clears_arm_and_forwards(self):
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        ev = self.tc.process(tcp_fin(KEY_A, ack=1020))
        self.assertEqual(ev.kind, Ev.ABORT_FORWARD)
        self.assertEqual(self.tc.flow_state(KEY_A).armed, 0)

    def test_pure_rst_clears_arm_and_forwards(self):
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        ev = self.tc.process(tcp_rst(KEY_A))
        self.assertEqual(ev.kind, Ev.ABORT_FORWARD)
        self.assertEqual(self.tc.flow_state(KEY_A).armed, 0)

    def test_response_with_fin_is_bypass_not_admitted(self):
        self.tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        self.tc.process(tcp_pure_ack(KEY_A, ack=1020))
        p = tcp_response(KEY_A, seq=5000, plen=100)
        p.flags |= 0x01                                                # FIN set on the data frame
        ev = self.tc.process(p)
        self.assertEqual(ev.kind, Ev.COMBINED_BYPASS)                  # abort-with-data -> not admitted


class TestTimeout(unittest.TestCase):
    def test_held_ack_releases_at_maxpass(self):
        tc = TxnCore(ack_max_pass=4)
        tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        tc.process(tcp_pure_ack(KEY_A, ack=1020))
        evs = [tc.release_pass(KEY_A) for _ in range(4)]
        self.assertEqual(evs[-1].kind, Ev.ACK_RELEASED_TIMEOUT)        # fail-open release
        self.assertIsNone(tc.held_frame(KEY_A))

    def test_held_response_releases_after_ack_gone(self):
        tc = TxnCore(ack_max_pass=2, guard_passes=1)
        tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        tc.process(tcp_pure_ack(KEY_A, ack=1020))
        tc.process(tcp_response(KEY_A, seq=5000, plen=100))           # RESP admitted behind ACK
        # drive passes: ACK releases first, then RESP releases after the guard
        seen = []
        for _ in range(8):
            ev = tc.release_pass(KEY_A)
            if ev is not None:
                seen.append(ev.kind)
            if tc.held_frame(KEY_A) is None and not tc.pending(KEY_A):
                break
        self.assertIn(Ev.ACK_RELEASED, seen + [Ev.ACK_RELEASED_TIMEOUT])
        self.assertIn(Ev.RESP_RELEASED, seen)
        self.assertFalse(tc.pending(KEY_A))                           # no stale state


class TestSeqWrapAndGenRollover(unittest.TestCase):
    def test_expack_wraps_32bit(self):
        tc = TxnCore()
        seq = MASK32 - 5                       # request near the 32-bit boundary
        tc.process(tcp_read(KEY_A, seq=seq, plen=20))
        exp = (seq + 20) & MASK32              # wraps past 2^32
        self.assertEqual(tc.flow_state(KEY_A).exp_ack, exp)
        ev = tc.process(tcp_pure_ack(KEY_A, ack=exp))   # ACK carries the wrapped value
        self.assertEqual(ev.kind, Ev.ACK_HELD)

    def test_generation_rolls_over_mod_256(self):
        tc = TxnCore()
        for _ in range(GEN_MOD):               # 256 arms -> gen wraps 255 -> 0
            tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        self.assertEqual(tc.flow_state(KEY_A).gen, 0)
        tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        self.assertEqual(tc.flow_state(KEY_A).gen, 1)


class TestHashCollision(unittest.TestCase):
    def test_collision_stale_frame_discarded_not_misreleased(self):
        # force two distinct flows to the SAME flow_id
        collide = lambda key: 0x1234
        tc = TxnCore(hash_fn=collide)
        # flow A arms and gets an ACK held
        tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        tc.process(tcp_pure_ack(KEY_A, ack=1020))
        heldA = tc.held_frame(KEY_A)
        self.assertEqual(heldA.role, "ACK")
        genA = heldA.gen
        # flow B (same flow_id) arms -> bumps the shared generation
        tc.process(tcp_read(KEY_B, seq=7000, plen=20))
        self.assertNotEqual(tc.flow_state(KEY_B).gen, genA)
        # A's held frame is now stale; a pass must DISCARD it, never release it against B's txn
        ev = tc.release_pass(KEY_A)
        self.assertEqual(ev.kind, Ev.STALE_DISCARD)
        self.assertIsNone(tc.held_frame(KEY_A))

    def test_no_collision_flows_independent(self):
        tc = TxnCore()                          # real hash -> A and B distinct
        tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        tc.process(tcp_read(KEY_B, seq=2000, plen=20))
        self.assertNotEqual(tc.flow_id(KEY_A), tc.flow_id(KEY_B))
        self.assertEqual(tc.flow_state(KEY_A).exp_ack, 1020)
        self.assertEqual(tc.flow_state(KEY_B).exp_ack, 2020)


class TestPassThrough(unittest.TestCase):
    def test_non_dnp3_forwarded_no_state(self):
        tc = TxnCore()
        p = tcp_read(KEY_A, seq=1000, plen=20)
        p.dst_port = 22            # not DNP3
        p.is_dnp3_app = False
        ev = tc.process(p)
        self.assertEqual(ev.kind, Ev.PASSTHRU)
        self.assertEqual(tc.flow_state(KEY_A).armed, 0)

    def test_syn_not_treated_as_pure_ack(self):
        tc = TxnCore()
        tc.process(tcp_read(KEY_A, seq=1000, plen=20))
        ev = tc.process(tcp_syn(KEY_A, ack=1020))   # SYN+ACK: flags_ok must be false
        self.assertEqual(ev.kind, Ev.ACK_PASSTHRU)
        self.assertIsNone(tc.held_frame(KEY_A))


if __name__ == "__main__":
    unittest.main(verbosity=2)
