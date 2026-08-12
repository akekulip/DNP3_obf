#!/usr/bin/env python3
"""Adversarial suite for transport_oracle.py.

Each test asserts that the RECEIVER's TCP view (seq and cumulative ack) stays
byte/seq-consistent after byte insertion, under a specific hazard. Every assertion
is checked against hand-computed constants, not against the oracle's own ledger, so
the reference is independent of the implementation.

Run:  python3 test_transport_oracle.py
      python3 test_transport_oracle.py --json      # + machine-readable summary line
"""
from __future__ import annotations

import json
import sys
import unittest

from transport_oracle import (
    Dir, Flags, Segment, Outcome, TransportOracle, SEQ_MOD, WRAP_GUARD, mod32,
)

PAD = 7
ISN_F = 1000          # outstation -> master ISN
ISN_R = 5000          # master -> outstation ISN


def fwd(flow, seq, ack, plen=0, insert=0, supported=True, fin=False, rst=False):
    return Segment(flow, Dir.FWD, seq, ack, plen, Flags(fin=fin, rst=rst),
                   supported=supported, insert=insert)


def rev(flow, seq, ack, plen=0, insert=0, supported=True, fin=False, rst=False):
    return Segment(flow, Dir.REV, seq, ack, plen, Flags(fin=fin, rst=rst),
                   supported=supported, insert=insert)


class TransportOracleTests(unittest.TestCase):

    def setUp(self):
        self.o = TransportOracle(table_size=64, ledger_depth=4)
        self.F = "flow1"

    # -- baseline padded response (used by several tests) ------------------ #
    def _pad_resp1(self):
        return self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=PAD))

    # 1. retransmission of a transformed segment: idempotent, no double delta
    def test_retransmission_no_double_offset(self):
        r1 = self._pad_resp1()
        self.assertEqual(r1.seq, 1000)                # resp#1 head unshifted
        self.assertEqual(r1.outcome, Outcome.TRANSLATED_INSERTED)
        self.assertEqual(r1.inserted, PAD)
        # second, third response so a later retransmit is genuinely "old"
        r2 = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r2.seq, 1054 + PAD)          # shifted by prior 7
        # RETRANSMIT resp#2 -> identical wire seq, NOT inserted again
        rr = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rr.seq, r2.seq)
        self.assertEqual(rr.inserted, 0)
        self.assertEqual(rr.outcome, Outcome.TRANSLATED)
        # retransmit resp#1 (older) -> still 1000, delta not double counted
        r1r = self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r1r.seq, 1000)
        self.assertEqual(r1r.inserted, 0)

    # 2. two sequential transformed responses: cumulative delta
    def test_two_sequential_transforms_cumulative(self):
        self._pad_resp1()                              # delta -> 7
        r2 = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r2.seq, 1054 + PAD)           # cumulative shift 7
        r3 = self.o.process(fwd(self.F, ISN_F + 108, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r3.seq, 1108 + 2 * PAD)       # cumulative shift 14

    # 3. an ACK crossing an insertion boundary: exact inverse
    def test_ack_crossing_boundary_exact(self):
        self._pad_resp1()                              # delta_fwd = 7 at boundary 54
        # master saw 54 orig + 7 pad = 61 bytes -> acks 1000+61
        a = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0))
        self.assertEqual(a.ack, 1054)                  # de-shifted to native next-byte
        self.assertFalse(a.partial_ack)

    def test_ack_inside_pad_snaps_to_boundary(self):
        self._pad_resp1()
        # master acks only 3 of the 7 pad bytes: 1000+54+3 -> snap to boundary 1054
        a = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + 3, plen=0))
        self.assertEqual(a.ack, 1054)
        self.assertTrue(a.partial_ack)

    # 4. a duplicate (data) packet: idempotent translate, no new boundary
    def test_duplicate_data_packet(self):
        r1 = self._pad_resp1()
        dup = self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(dup.seq, r1.seq)
        self.assertEqual(dup.inserted, 0)

    # 5. a duplicate ACK: same original, no state change
    def test_duplicate_ack(self):
        self._pad_resp1()
        a1 = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0))
        a2 = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0))
        a3 = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0))
        self.assertEqual(a1.ack, 1054)
        self.assertEqual(a2.ack, 1054)
        self.assertEqual(a3.ack, 1054)

    # 6. an out-of-order packet: correct per-seq delta regardless of arrival order
    def test_out_of_order_packet(self):
        self._pad_resp1()                              # boundary at off 54
        self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))   # boundary off 108
        self.o.process(fwd(self.F, ISN_F + 108, ISN_R, plen=54, insert=PAD))  # boundary off 162
        # now an OLD segment arrives out of order -> must use ITS seq's delta
        ooo = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(ooo.seq, 1054 + PAD)          # delta below off 54 is 7
        # and the very first, even more out of order
        ooo0 = self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(ooo0.seq, 1000)               # delta below off 0 is 0

    # 7. hash/register collision: detected, not corrupted
    def test_collision_detected_not_corrupted(self):
        # force two distinct flows to the same slot
        o = TransportOracle(table_size=64, ledger_depth=4, hash_fn=lambda f: 0)
        A, B = "flowA", "flowB"
        rA = o.process(fwd(A, ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rA.outcome, Outcome.TRANSLATED_INSERTED)
        # B hashes to the same slot, owned by A -> B must be DENIED, passed native
        rB = o.process(fwd(B, 9000, 9500, plen=40, insert=PAD))
        self.assertEqual(rB.outcome, Outcome.DENIED_COLLISION)
        self.assertEqual(rB.seq, 9000)                 # B unchanged (never modified)
        self.assertEqual(rB.ack, 9500)
        self.assertEqual(rB.inserted, 0)
        # A's state is uncorrupted: its next packet still translates with delta 7
        rA2 = o.process(fwd(A, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rA2.seq, 1054 + PAD)

    # 8. FIN and RST: translated, then state cleaned up
    def test_rst_translates_then_retires(self):
        self._pad_resp1()
        # RST from the outstation carries a seq in the padded FWD stream
        r = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=0, rst=True))
        self.assertEqual(r.outcome, Outcome.RETIRED)
        self.assertEqual(r.seq, 1054 + PAD)            # translated before teardown
        # slot is freed: a later packet on the same identity is a fresh native flow
        after = self.o.process(fwd(self.F, 2000, 6000, plen=10))   # no insert
        self.assertEqual(after.outcome, Outcome.NATIVE)
        self.assertEqual(after.seq, 2000)

    def test_fin_both_sides_retires(self):
        self._pad_resp1()                              # delta_fwd = 7
        # FWD FIN -> half close, still translated
        f1 = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=0, fin=True))
        self.assertEqual(f1.outcome, Outcome.TRANSLATED)
        self.assertEqual(f1.seq, 1054 + PAD)
        # REV FIN -> both seen -> retire; its ack (of padded FWD stream) de-shifts
        f2 = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0, fin=True))
        self.assertEqual(f2.outcome, Outcome.RETIRED)
        self.assertEqual(f2.ack, 1054)
        # freed: fresh native afterwards
        after = self.o.process(rev(self.F, 6000, 2000, plen=0))
        self.assertEqual(after.outcome, Outcome.NATIVE)

    # 9a. explicit eligibility rejection BEFORE the offset window becomes ambiguous
    def test_wrap_eligibility_rejection(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "wrapflow"
        isn = 1000
        # establish the ISN with a small padded response (boundary at off 10)
        o.process(fwd(F, isn, ISN_R, plen=10, insert=PAD))
        # a segment far advanced -> offset past the half-space guard -> new insert refused
        far = mod32(isn + WRAP_GUARD + 5)              # offset ~2^31 + 5
        r = o.process(fwd(F, far, ISN_R, plen=5, insert=PAD))
        self.assertEqual(r.outcome, Outcome.TRANSLATED_FROZEN)
        self.assertEqual(r.inserted, 0)
        self.assertIn("wrap", r.note)

    # 9b. modular translation is correct THROUGH a wire-seq wrap for a committed delta
    def test_modular_translation_across_wrap(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "wrapflow2"
        isn = mod32(-50)                               # 2^32 - 50 (ISN just below wrap)
        r1 = o.process(fwd(F, isn, ISN_R, plen=10, insert=PAD))   # boundary off 10
        self.assertEqual(r1.seq, isn)                  # head unshifted
        # in-order segment at original offset 45 (wire seq = 2^32-5), no NEW insertion:
        # translated off 45 + committed delta 7 = 52 -> wire = isn+52 mod 2^32 = 2
        r2 = o.process(fwd(F, mod32(isn + 45), ISN_R, plen=5))
        self.assertEqual(r2.seq, mod32(isn + 45 + PAD))
        self.assertEqual(r2.seq, 2)                    # wrapped past 0 cleanly

    # 10. safety contract: an UNSUPPORTED packet AFTER the epoch is STILL translated
    def test_unsupported_post_epoch_still_translated(self):
        self._pad_resp1()                              # epoch begun, delta_fwd = 7
        # an unsupported FWD data packet must NOT pass raw; it must be seq-translated
        u = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=20,
                               insert=0, supported=False))
        self.assertNotEqual(u.outcome, Outcome.NATIVE)
        self.assertEqual(u.seq, 1054 + PAD)            # translated by the live delta
        # an unsupported REV packet acking the padded FWD stream is also de-shifted
        ur = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0,
                                supported=False))
        self.assertEqual(ur.ack, 1054)

    # safety contract: BEFORE any insertion, an unsupported flow MAY pass native
    def test_unsupported_pre_epoch_native_ok(self):
        r = self.o.process(fwd(self.F, ISN_F, ISN_R, plen=30,
                               insert=0, supported=False))
        self.assertEqual(r.outcome, Outcome.NATIVE)
        self.assertEqual(r.seq, ISN_F)
        self.assertEqual(r.ack, ISN_R)

    # 11. safe degradation: ledger depth cap -> FREEZE new insertions, keep translating
    def test_depth_cap_freezes_but_keeps_translating(self):
        o = TransportOracle(table_size=64, ledger_depth=2)   # only 2 insertions
        F = "deep"
        r1 = o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        r2 = o.process(fwd(F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r1.inserted, PAD)
        self.assertEqual(r2.inserted, PAD)
        # third insertion exceeds depth 2 -> frozen, NOT inserted, but still translated
        r3 = o.process(fwd(F, ISN_F + 108, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r3.inserted, 0)
        self.assertEqual(r3.outcome, Outcome.TRANSLATED_FROZEN)
        self.assertEqual(r3.seq, 1108 + 2 * PAD)             # translated by committed 14
        # and the reverse ack of the padded stream is still consistent
        a = o.process(rev(F, ISN_R, ISN_F + 108 + 2 * PAD, plen=0))
        self.assertEqual(a.ack, 1108)

    # 12. LIMITATION: an active-epoch flow is NON-evictable (never raw pass-through)
    def test_active_epoch_flow_is_non_evictable(self):
        self._pad_resp1()                              # F is now active-epoch
        self.assertFalse(self.o.table.force_evict(self.F))   # protected
        # a native (no-epoch) or retired flow CAN be evicted
        o2 = TransportOracle(table_size=64, ledger_depth=4)
        o2.process(fwd("native", 1, 2, plen=10))       # native pass, no slot claimed
        self.assertTrue(o2.table.force_evict("native"))      # nothing to protect

    # 12b. LIMITATION: under table pressure a colliding NEW flow is denied (native),
    #      the incumbent active flow is never evicted -> no raw post-insertion pass.
    def test_table_pressure_denies_newcomer_not_incumbent(self):
        o = TransportOracle(table_size=64, ledger_depth=4, hash_fn=lambda f: 0)
        o.process(fwd("incumbent", ISN_F, ISN_R, plen=54, insert=PAD))
        rN = o.process(fwd("newcomer", 8000, 8500, plen=54, insert=PAD))
        self.assertEqual(rN.outcome, Outcome.DENIED_COLLISION)
        self.assertEqual(rN.seq, 8000)                 # newcomer native (unmodified)
        # incumbent keeps translating correctly
        rI = o.process(fwd("incumbent", ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rI.seq, 1054 + PAD)

    # 13. two directions carry INDEPENDENT deltas (Delta_fwd vs Delta_rev)
    def test_bidirectional_independent_deltas(self):
        F = "bidir"
        # REV: expand a request by 11 bytes (SBO CROB expansion)
        DR = 11
        rR = self.o.process(rev(F, ISN_R, ISN_F, plen=20, insert=DR))
        self.assertEqual(rR.seq, ISN_R)                # request head unshifted
        # FWD: pad the response by 7
        rF = self.o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rF.seq, ISN_F)
        # A FWD packet's ack (of the REV/request stream) de-shifts by Delta_rev=11;
        # the outstation saw padded request bytes (20+11) and acked ISN_R+20+11.
        aF = self.o.process(fwd(F, ISN_F + 54, ISN_R + 20 + DR, plen=0))
        self.assertEqual(aF.ack, ISN_R + 20)           # de-shifted by 11 (Delta_rev), not 7
        self.assertEqual(aF.seq, ISN_F + 54 + PAD)     # its own seq shifted by 7 (Delta_fwd)
        # A REV packet's ack (of the FWD/response stream) de-shifts by Delta_fwd=7.
        aR = self.o.process(rev(F, ISN_R + 20, ISN_F + 54 + PAD, plen=0))
        self.assertEqual(aR.ack, ISN_F + 54)           # de-shifted by 7 (Delta_fwd), not 11
        self.assertEqual(aR.seq, ISN_R + 20 + DR)      # its own seq shifted by 11 (Delta_rev)

    # sanity: the mainline demo in the model file is internally consistent
    def test_demo_mainline_consistent(self):
        from transport_oracle import _demo
        d = _demo()
        self.assertEqual(d["pass"], d["total"])


def _machine_summary() -> None:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TransportOracleTests)
    result = unittest.TestResult()
    suite.run(result)
    total = suite.countTestCases()
    failed = len(result.failures) + len(result.errors)
    summary = {
        "suite": "test_transport_oracle",
        "total": total,
        "passed": total - failed,
        "failed": failed,
        "failures": [str(t) for t, _ in result.failures],
        "errors": [str(t) for t, _ in result.errors],
    }
    print("MACHINE_SUMMARY " + json.dumps(summary))


if __name__ == "__main__":
    if "--json" in sys.argv:
        sys.argv.remove("--json")
        _machine_summary()
    unittest.main(verbosity=2)
