#!/usr/bin/env python3
"""Adversarial suite for transport_oracle.py + stream_reconstruction.py.

Every assertion is checked against hand-computed constants or an INDEPENDENTLY built
canonical stream, never against the oracle's own ledger, so the reference does not move
with the implementation. Tests are grouped by transport-gate area via their method-name
prefix; `--json` prints a per-area PASS/FAIL and the overall gate verdict.

Areas and the property each defends:
  retx    -- a retransmit RE-EMITS identical inserted bytes without growing the offset
  overlap -- an overlapping/resegmented retransmit reproduces EVERY committed insertion
  recon   -- the receiver-visible transformed stream reassembles byte-for-byte
  teardown-- state survives until both FINs are acked; the final ACK is translated, never native
  owner   -- slot ownership detects collisions; a compressed-tag false hit is detected/flagged
  sack    -- SACK is gated (rejected before first insertion) or edge-translated, explicitly
  seqack  -- the core seq/ack step-function translation (cumulative, inverse, wrap, bidir)
  degrade -- bounded-limit behaviors (depth cap, non-eviction, unsupported) stay safe

Run:  python3 test_transport_oracle.py
      python3 test_transport_oracle.py --json      # + machine-readable area/gate summary
"""
from __future__ import annotations

import json
import sys
import unittest

from transport_oracle import (
    Dir, Flags, Segment, Outcome, TransportOracle, SEQ_MOD, WRAP_GUARD, mod32,
    render_insertion,
)
from stream_reconstruction import StreamReassembler, build_canonical

PAD = 7
ISN_F = 1000          # outstation -> master ISN
ISN_R = 5000          # master -> outstation ISN


def fwd(flow, seq, ack, plen=0, insert=0, tid=0, payload=None, supported=True,
        fin=False, rst=False, syn=False, sack_permitted=False, sack=None):
    return Segment(flow, Dir.FWD, seq, ack, plen, Flags(fin=fin, rst=rst, syn=syn),
                   supported=supported, insert=insert, template_id=tid, payload=payload,
                   sack_permitted=sack_permitted, sack=sack)


def rev(flow, seq, ack, plen=0, insert=0, tid=0, payload=None, supported=True,
        fin=False, rst=False, syn=False, sack_permitted=False, sack=None):
    return Segment(flow, Dir.REV, seq, ack, plen, Flags(fin=fin, rst=rst, syn=syn),
                   supported=supported, insert=insert, template_id=tid, payload=payload,
                   sack_permitted=sack_permitted, sack=sack)


class TransportOracleTests(unittest.TestCase):

    def setUp(self):
        self.o = TransportOracle(table_size=64, ledger_depth=4)
        self.F = "flow1"

    def _pad_resp1(self):
        return self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=PAD))

    # ===================================================================== #
    # AREA retx -- retransmission re-emits the bytes; offset does not grow
    # ===================================================================== #

    def test_retx_exact_reemits_bytes_no_offset_growth(self):
        """The audit bug, closed: an exact retransmit re-emits identical inserted
        bytes (inserted_len == PAD) while NOT growing the cumulative offset
        (committed_len == 0), at the same translated seq."""
        self._pad_resp1()
        r2 = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r2.seq, 1054 + PAD)
        self.assertEqual(r2.committed_len, PAD)
        self.assertEqual(r2.inserted_len, PAD)
        # exact retransmit of resp#2
        rr = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rr.seq, r2.seq)               # identical translated seq
        self.assertEqual(rr.committed_len, 0)          # offset NOT double-counted
        self.assertEqual(rr.inserted_len, PAD)         # bytes RE-EMITTED (the fix)
        self.assertEqual(rr.emitted, r2.emitted)       # byte-identical image
        self.assertEqual([e.boundary for e in rr.emitted_insertions], [108])

    def test_retx_switch_reinserts_when_segment_carries_no_insert(self):
        """A real outstation retransmits its ORIGINAL bytes (insert=0); the switch must
        still re-insert from its ledger. Re-emission is driven by the ledger, not by the
        segment carrying insert>0."""
        self._pad_resp1()
        rr = self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=0))
        self.assertEqual(rr.committed_len, 0)
        self.assertEqual(rr.inserted_len, PAD)         # re-emitted despite insert=0
        self.assertEqual([e.boundary for e in rr.emitted_insertions], [54])

    def test_retx_does_not_grow_cumulative_offset(self):
        """After N retransmits of resp#1, a genuinely new resp#2 still shifts by exactly
        one PAD, proving the retransmits never advanced the offset."""
        self._pad_resp1()
        for _ in range(4):
            self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=PAD))
        r2 = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r2.seq, 1054 + PAD)           # single cumulative PAD, not 5

    def test_retx_emitted_bytes_are_reproducible(self):
        """The re-emitted inserted bytes equal the template's reproducible bytes."""
        self._pad_resp1()
        gen = self.o.flow(self.F).generation
        rr = self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=PAD))
        want = render_insertion(0, PAD, 54, gen)
        self.assertEqual(rr.emitted_insertions[0].data, want)

    # ===================================================================== #
    # AREA overlap -- reproduce EVERY committed insertion in the interval,
    #   under one convention: boundary b re-emitted iff start < b <= end.
    # ===================================================================== #

    def _three_responses(self, o=None, F="ovl"):
        o = o or TransportOracle(table_size=64, ledger_depth=8)
        for k in range(3):                             # boundaries 50, 100, 150
            o.process(fwd(F, ISN_F + 50 * k, ISN_R, plen=50, insert=5, tid=k))
        return o, F

    def test_overlap_boundary_at_segment_start_belongs_to_prev(self):
        o, F = self._three_responses()
        # retransmit exactly [50,100): boundary 50 is at the start -> excluded; 100 tail -> in
        r = o.process(fwd(F, ISN_F + 50, ISN_R, plen=50, insert=0))
        self.assertEqual([e.boundary for e in r.emitted_insertions], [100])

    def test_overlap_boundary_interior_reemitted(self):
        o, F = self._three_responses()
        # retransmit [40,110): interior boundary 50, tail-region 100 -> both re-emitted
        r = o.process(fwd(F, ISN_F + 40, ISN_R, plen=70, insert=0))
        self.assertEqual(sorted(e.boundary for e in r.emitted_insertions), [50, 100])
        self.assertEqual(r.inserted_len, 10)
        self.assertEqual(r.committed_len, 0)

    def test_overlap_boundary_at_segment_end_reemitted(self):
        o, F = self._three_responses()
        r = o.process(fwd(F, ISN_F + 60, ISN_R, plen=40, insert=0))   # [60,100], tail=100
        self.assertEqual([e.boundary for e in r.emitted_insertions], [100])

    def test_overlap_adjacent_segments_emit_shared_boundary_once(self):
        o, F = self._three_responses()
        a = o.process(fwd(F, ISN_F, ISN_R, plen=50, insert=0))        # [0,50], boundary 50
        b = o.process(fwd(F, ISN_F + 50, ISN_R, plen=50, insert=0))   # [50,100], boundary 100
        self.assertEqual([e.boundary for e in a.emitted_insertions], [50])
        self.assertEqual([e.boundary for e in b.emitted_insertions], [100])   # NOT 50 again

    def test_overlap_multiple_boundaries_all_reproduced(self):
        o, F = self._three_responses()
        r = o.process(fwd(F, ISN_F, ISN_R, plen=150, insert=0))       # whole stream
        self.assertEqual(sorted(e.boundary for e in r.emitted_insertions), [50, 100, 150])
        self.assertEqual(r.inserted_len, 15)

    def test_overlap_new_insert_into_committed_history_refused_not_suppressed(self):
        """A NEW insertion whose boundary falls inside already-committed history is
        refused (conflict) -- never corrupting the stream -- yet the committed insertion
        in range is still re-emitted (never silently suppressed)."""
        o, F = self._three_responses()
        r = o.process(fwd(F, ISN_F + 40, ISN_R, plen=20, insert=5, tid=9))  # boundary 60 < 150
        self.assertEqual(r.committed_len, 0)                 # not newly committed
        self.assertFalse(r.newly_recorded)
        self.assertIn("committed history", r.note)
        self.assertEqual([e.boundary for e in r.emitted_insertions], [50])   # still re-emitted

    def test_overlap_out_of_order_first_insert_refused_but_safe(self):
        """A FIRST-TIME insertion arriving out of order (an earlier boundary than one
        already committed) is REFUSED rather than retroactively shifting bytes the switch
        has already forwarded. The segment is still translated and its bytes emitted, so
        the reconstructed stream stays consistent with the ACTUALLY committed plan -- a
        documented coverage limitation, never a corruption."""
        o = TransportOracle(table_size=64, ledger_depth=8)
        F = "ooo"
        reasm = StreamReassembler(ISN_F)
        o.process(fwd(F, ISN_F, ISN_R, syn=True))
        late = o.process(fwd(F, ISN_F + 100, ISN_R, plen=50, insert=5, tid=2))  # boundary 150
        reasm.deliver(late.seq, late.emitted)
        early = o.process(fwd(F, ISN_F, ISN_R, plen=50, insert=5, tid=0))       # 50 < 150 -> refuse
        self.assertEqual(early.committed_len, 0)
        self.assertIn("committed history", early.note)
        reasm.deliver(early.seq, early.emitted)
        mid = o.process(fwd(F, ISN_F + 50, ISN_R, plen=50, insert=5, tid=1))    # 100 < 150 -> refuse
        reasm.deliver(mid.seq, mid.emitted)
        gen = o.flow(F).generation
        canon = build_canonical(Dir.FWD, 150, [(150, 5, 2)], gen)               # only 150 committed
        self.assertTrue(reasm.ok_against(canon))

    # ===================================================================== #
    # AREA recon -- byte-for-byte stream reconstruction under every hazard
    # ===================================================================== #

    def _feed_and_check(self, segs, total_len, plan, isn=ISN_F, direction=Dir.FWD,
                        o=None, F="rc"):
        o = o or TransportOracle(table_size=64, ledger_depth=8)
        reasm = StreamReassembler(isn)
        for s in segs:
            r = o.process(s)
            reasm.deliver(r.seq, r.emitted)
        gen = o.flow(F).generation
        canon = build_canonical(direction, total_len, plan, generation=gen)
        return reasm, canon, o

    def test_recon_in_order(self):
        F = "rc1"
        segs = [fwd(F, ISN_F + 50 * k, ISN_R, plen=50, insert=5, tid=k) for k in range(3)]
        reasm, canon, _ = self._feed_and_check(segs, 150, [(50, 5, 0), (100, 5, 1), (150, 5, 2)], F=F)
        self.assertTrue(reasm.ok_against(canon))

    def test_recon_exact_retransmits(self):
        F = "rc2"
        base = [fwd(F, ISN_F + 50 * k, ISN_R, plen=50, insert=5, tid=k) for k in range(3)]
        segs = base + [base[1], base[0], base[2]]      # duplicate whole segments
        reasm, canon, _ = self._feed_and_check(segs, 150, [(50, 5, 0), (100, 5, 1), (150, 5, 2)], F=F)
        self.assertTrue(reasm.ok_against(canon))

    def test_recon_overlapping_retransmits(self):
        F = "rc3"
        base = [fwd(F, ISN_F + 50 * k, ISN_R, plen=50, insert=5, tid=k) for k in range(3)]
        segs = base + [fwd(F, ISN_F + 40, ISN_R, plen=70, insert=0),      # overlap [40,110)
                       fwd(F, ISN_F + 90, ISN_R, plen=60, insert=0)]      # overlap [90,150)
        reasm, canon, _ = self._feed_and_check(segs, 150, [(50, 5, 0), (100, 5, 1), (150, 5, 2)], F=F)
        self.assertTrue(reasm.ok_against(canon))

    def test_recon_different_segmentation(self):
        F = "rc4"
        base = [fwd(F, ISN_F + 50 * k, ISN_R, plen=50, insert=5, tid=k) for k in range(3)]
        # a totally different segmentation of the same original stream (insert=0)
        reseg = [fwd(F, ISN_F + 0, ISN_R, plen=30, insert=0),
                 fwd(F, ISN_F + 30, ISN_R, plen=45, insert=0),
                 fwd(F, ISN_F + 75, ISN_R, plen=75, insert=0)]
        reasm, canon, _ = self._feed_and_check(base + reseg, 150,
                                               [(50, 5, 0), (100, 5, 1), (150, 5, 2)], F=F)
        self.assertTrue(reasm.ok_against(canon))

    def test_recon_out_of_order_and_duplicates(self):
        """Insertions commit in forwarding order (the switch sees each direction in
        order). Out-of-order/duplicate then applies to RETRANSMITS of committed data,
        which re-emit and reassemble regardless of arrival order."""
        F = "rc5"
        o = TransportOracle(table_size=64, ledger_depth=8)
        reasm = StreamReassembler(ISN_F)
        o.process(fwd(F, ISN_F, ISN_R, syn=True))                  # anchor ISN from SYN
        base = [fwd(F, ISN_F + 50 * k, ISN_R, plen=50, insert=5, tid=k) for k in range(3)]
        for s in base:                                             # commit in order
            r = o.process(s); reasm.deliver(r.seq, r.emitted)
        for s in [base[2], base[0], base[1], base[2], base[0]]:    # reordered retransmits
            r = o.process(s); reasm.deliver(r.seq, r.emitted)
        gen = o.flow(F).generation
        canon = build_canonical(Dir.FWD, 150, [(50, 5, 0), (100, 5, 1), (150, 5, 2)], gen)
        self.assertTrue(reasm.ok_against(canon))

    def test_recon_inconsistent_retransmit_detected(self):
        """A retransmit that carries DIFFERENT original bytes for the same seq is caught
        by the reassembler as a conflict (no silent corruption)."""
        F = "rc6"
        o = TransportOracle(table_size=64, ledger_depth=4)
        reasm = StreamReassembler(ISN_F)
        good = fwd(F, ISN_F, ISN_R, plen=8, insert=5, payload=bytes(range(8)))
        bad = fwd(F, ISN_F, ISN_R, plen=8, insert=5, payload=bytes(range(100, 108)))
        r1 = o.process(good); reasm.deliver(r1.seq, r1.emitted)
        r2 = o.process(bad); reasm.deliver(r2.seq, r2.emitted)
        self.assertTrue(reasm.conflicts)               # inconsistent data DETECTED

    def test_recon_bidirectional_streams(self):
        F = "rc7"
        o = TransportOracle(table_size=64, ledger_depth=8)
        rf = StreamReassembler(ISN_F)
        rr = StreamReassembler(ISN_R)
        fwd_segs = [fwd(F, ISN_F + 40 * k, ISN_R, plen=40, insert=6, tid=k) for k in range(2)]
        rev_segs = [rev(F, ISN_R + 30 * k, ISN_F, plen=30, insert=9, tid=k) for k in range(2)]
        for s in fwd_segs + rev_segs + fwd_segs:       # interleave + FWD retransmits
            r = o.process(s)
            (rf if s.direction is Dir.FWD else rr).deliver(r.seq, r.emitted)
        gen = o.flow(F).generation
        canon_f = build_canonical(Dir.FWD, 80, [(40, 6, 0), (80, 6, 1)], gen)
        canon_r = build_canonical(Dir.REV, 60, [(30, 9, 0), (60, 9, 1)], gen)
        self.assertTrue(rf.ok_against(canon_f))
        self.assertTrue(rr.ok_against(canon_r))

    # ===================================================================== #
    # AREA teardown -- retain state until both FINs acked; final ACK translated
    # ===================================================================== #

    def _bidir_epoch(self, o, F):
        """REV padded by 11, FWD padded by 7; both ISNs learned. Returns nothing."""
        o.process(rev(F, ISN_R, ISN_F, plen=20, insert=11))     # boundary_rev 20
        o.process(fwd(F, ISN_F, ISN_R + 20 + 11, plen=54, insert=PAD))   # boundary_fwd 54

    def test_teardown_full_chain_final_ack_translated(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "td"
        self._bidir_epoch(o, F)
        # (1) FWD FIN -> translated, not retired
        f1 = o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, fin=True))
        self.assertEqual(f1.outcome, Outcome.TRANSLATED)
        self.assertEqual(f1.seq, 1061)
        self.assertFalse(f1.retired)
        # (2) REV ack-of-FWD-FIN -> translated (ack de-shifted to 1055), not retired
        a1 = o.process(rev(F, ISN_R + 20, ISN_F + 54 + PAD + 1, plen=0))
        self.assertEqual(a1.ack, 1055)
        self.assertFalse(a1.retired)
        # (3) REV FIN -> translated, not retired (its own ack pending)
        f2 = o.process(rev(F, ISN_R + 20, ISN_F + 54 + PAD + 1, plen=0, fin=True))
        self.assertEqual(f2.seq, 5031)
        self.assertFalse(f2.retired)
        # (4) a lingering FWD data retransmit AFTER both FINs but before final ack:
        #     state MUST still be alive and translating/re-emitting
        ling = o.process(fwd(F, ISN_F, ISN_R + 31, plen=54, insert=PAD))
        self.assertEqual(ling.outcome, Outcome.TRANSLATED)
        self.assertEqual(ling.inserted_len, PAD)
        self.assertFalse(ling.retired)
        # (5) final ACK-of-REV-FIN -> TRANSLATED (ack de-shifted to 5021, NOT native 5032),
        #     then retired
        fin_ack = o.process(fwd(F, ISN_F + 54, ISN_R + 20 + 11 + 1, plen=0))
        self.assertEqual(fin_ack.outcome, Outcome.RETIRED)
        self.assertEqual(fin_ack.ack, 5021)            # de-shifted, i.e. NOT passed native
        self.assertNotEqual(fin_ack.ack, ISN_R + 20 + 11 + 1)
        self.assertTrue(fin_ack.retired)
        # (6) state freed: a later packet is a fresh native flow
        after = o.process(fwd(F, 2000, 6000, plen=10))
        self.assertEqual(after.outcome, Outcome.NATIVE)

    def test_teardown_not_retired_before_final_ack(self):
        """Both FINs seen but only one acked -> state persists (regression for the audit
        fix: the old model retired on both-FINs-seen and passed the final ACK native)."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "td2"
        self._bidir_epoch(o, F)
        o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, fin=True))     # FWD FIN
        o.process(rev(F, ISN_R + 20, ISN_F + 62, plen=0, fin=True))     # REV FIN, acks FWD FIN
        self.assertIsNotNone(o.flow(F))                # still alive (REV FIN not acked yet)

    def test_teardown_safe_retirement_timeout(self):
        """If the final ACK never arrives, a bounded timeout retires the state."""
        o = TransportOracle(table_size=64, ledger_depth=4, retire_timeout=2)
        F = "td3"
        self._bidir_epoch(o, F)
        o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, fin=True))     # FWD FIN
        o.process(rev(F, ISN_R + 20, ISN_F + 62, plen=0, fin=True))     # REV FIN (arms deadline)
        # stale dup-acks that do NOT advance past the pending REV FIN -> only timeout can fire
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=0))                    # tick 1
        last = o.process(fwd(F, ISN_F + 54, ISN_R, plen=0))             # tick 2 -> timeout
        self.assertEqual(last.outcome, Outcome.RETIRED)
        self.assertIn("timeout", last.note)
        self.assertIsNone(o.flow(F))

    def test_teardown_rst_before_retirement(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "td4"
        self._bidir_epoch(o, F)
        o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, fin=True))     # half close
        r = o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, rst=True))
        self.assertEqual(r.outcome, Outcome.RETIRED)
        self.assertEqual(r.seq, 1061)                  # translated before teardown
        self.assertIsNone(o.flow(F))

    def test_teardown_delayed_duplicate_after_fin_still_translated(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "td5"
        self._bidir_epoch(o, F)
        o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, fin=True))     # FWD FIN
        # a delayed duplicate of resp#1 arrives after the FIN -> translated + re-emitted
        dup = o.process(fwd(F, ISN_F, ISN_R + 31, plen=54, insert=PAD))
        self.assertEqual(dup.seq, 1000)
        self.assertEqual(dup.inserted_len, PAD)
        self.assertNotEqual(dup.outcome, Outcome.NATIVE)

    def test_teardown_tuple_reuse_syn_preserves_old_state(self):
        """A SYN reusing the tuple while old state is quarantined must NOT reuse/destroy
        it; the old flow keeps translating its own lingering packets. After the old flow
        retires, a fresh epoch claims a NEW generation (no alias to old deltas)."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "td6"
        self._bidir_epoch(o, F)
        gen_old = o.flow(F).generation
        o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, fin=True))     # FWD FIN
        o.process(rev(F, ISN_R + 20, ISN_F + 62, plen=0, fin=True))     # REV FIN (not yet acked)
        syn = o.process(fwd(F, 9000, 9000, plen=0, syn=True))           # tuple reuse SYN
        self.assertEqual(syn.outcome, Outcome.NATIVE)
        self.assertIsNotNone(o.flow(F))                                 # old state preserved
        ling = o.process(fwd(F, ISN_F, ISN_R + 31, plen=54, insert=PAD))  # old lingering pkt
        self.assertEqual(ling.inserted_len, PAD)                        # still translating
        # retire old flow (final ack), then a fresh epoch gets a new generation
        o.process(fwd(F, ISN_F + 54, ISN_R + 32, plen=0))               # acks REV FIN -> retire
        self.assertIsNone(o.flow(F))
        o.process(fwd(F, 9000, 9500, plen=20, insert=PAD))              # new epoch claims
        self.assertGreater(o.flow(F).generation, gen_old)

    # ===================================================================== #
    # AREA owner -- collision detection, compressed-tag false hits, generations
    # ===================================================================== #

    def test_owner_full_key_detects_collision_denies_intruder(self):
        o = TransportOracle(table_size=64, ledger_depth=4, hash_fn=lambda f: 0)
        rA = o.process(fwd("A", ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rA.outcome, Outcome.TRANSLATED_INSERTED)
        rB = o.process(fwd("B", 9000, 9500, plen=40, insert=PAD))   # same slot, other key
        self.assertEqual(rB.outcome, Outcome.DENIED_COLLISION)
        self.assertEqual(rB.seq, 9000)                              # B unmodified
        self.assertEqual(o.table.false_hits_undetected, 0)          # no aliasing possible
        # A uncorrupted
        rA2 = o.process(fwd("A", ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rA2.seq, 1054 + PAD)

    def test_owner_hashonly_false_hit_is_detected_and_recorded(self):
        """Hash-only ownership (no full-key compare) with colliding COMPRESSED tags: the
        second flow is an UNDETECTED false hit on silicon. The model, holding the true
        key, detects and RECORDS it -> hash-only ownership is a BLOCKING hardware limit."""
        o = TransportOracle(table_size=64, ledger_depth=4,
                            hash_fn=lambda f: 0, compress_fn=lambda f: 0,
                            verify_full_key=False)
        o.process(fwd("A", ISN_F, ISN_R, plen=54, insert=PAD))
        o.process(fwd("B", 9000, 9500, plen=40, insert=PAD))        # false hit (same tag)
        self.assertGreater(o.table.false_hits_undetected, 0)        # detected & recorded

    def test_owner_full_key_avoids_the_false_hit(self):
        """The same colliding-tag scenario is SAFE with full-key verification: the
        collision is detected and the intruder denied, zero false hits."""
        o = TransportOracle(table_size=64, ledger_depth=4,
                            hash_fn=lambda f: 0, compress_fn=lambda f: 0,
                            verify_full_key=True)
        o.process(fwd("A", ISN_F, ISN_R, plen=54, insert=PAD))
        rB = o.process(fwd("B", 9000, 9500, plen=40, insert=PAD))
        self.assertEqual(rB.outcome, Outcome.DENIED_COLLISION)
        self.assertEqual(o.table.false_hits_undetected, 0)

    def test_owner_generation_reuse_no_alias(self):
        """Retiring a flow and reclaiming its slot bumps the generation; the new flow has
        empty ledgers (no alias to the old deltas). The new incarnation opens with a SYN
        (a real new connection always does), which clears the retired tuple's TIME_WAIT
        tombstone so the fresh epoch can claim."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "gen"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        g1 = o.flow(F).generation
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=0, rst=True))      # retire
        self.assertIsNone(o.flow(F))
        o.process(fwd(F, 7000, 7500, syn=True))                    # new connection SYN
        r = o.process(fwd(F, 7000, 7500, plen=20, insert=PAD))      # fresh claim
        self.assertGreater(o.flow(F).generation, g1)
        self.assertEqual(r.seq, 7000)                              # head unshifted, new ISN

    def test_owner_active_epoch_not_evictable(self):
        self._pad_resp1()
        self.assertFalse(self.o.table.force_evict(self.F))         # protected
        o2 = TransportOracle(table_size=64, ledger_depth=4)
        o2.process(fwd("native", 1, 2, plen=10))                   # no epoch claimed
        self.assertTrue(o2.table.force_evict("native"))

    def test_owner_table_pressure_denies_newcomer_not_incumbent(self):
        o = TransportOracle(table_size=64, ledger_depth=4, hash_fn=lambda f: 0)
        o.process(fwd("incumbent", ISN_F, ISN_R, plen=54, insert=PAD))
        rN = o.process(fwd("newcomer", 8000, 8500, plen=54, insert=PAD))
        self.assertEqual(rN.outcome, Outcome.DENIED_COLLISION)
        self.assertEqual(rN.seq, 8000)
        rI = o.process(fwd("incumbent", ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rI.seq, 1054 + PAD)

    # ===================================================================== #
    # AREA sack -- strict eligibility (default) and optional edge translation
    # ===================================================================== #

    def test_sack_permitted_rejected_before_first_insertion(self):
        """Default 'reject' policy: a SACK-permitted connection (learned at the SYN, the
        only place the option appears) is refused an epoch before its first insertion, so
        it stays native (unmodified, safe). The data segment carries NO SACK option
        (sack_permitted=False); eligibility comes from the handshake, not the data."""
        o = TransportOracle(table_size=64, ledger_depth=4)      # sack_policy='reject'
        o.process(fwd("sflow", ISN_F, ISN_R, syn=True, sack_permitted=True))   # negotiate SACK
        r = o.process(fwd("sflow", ISN_F, ISN_R, plen=54, insert=PAD, sack_permitted=False))
        self.assertEqual(r.outcome, Outcome.NATIVE)
        self.assertEqual(r.committed_len, 0)
        self.assertIsNone(o.flow("sflow"))                      # no epoch ever begins

    def test_sack_permitted_flow_never_reaches_post_insertion(self):
        """Because a SACK flow (negotiated at the SYN) never inserts, no post-insertion
        SACK can appear -- the invariant the strict rule guarantees for the P4 claim."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        o.process(fwd("sflow2", ISN_F, ISN_R, syn=True, sack_permitted=True))  # negotiate SACK
        for k in range(3):
            r = o.process(fwd("sflow2", ISN_F + 54 * k, ISN_R, plen=54, insert=PAD,
                              sack_permitted=False))
            self.assertEqual(r.outcome, Outcome.NATIVE)
        self.assertIsNone(o.flow("sflow2"))                     # still no epoch/insertion

    def test_sack_translate_policy_edges(self):
        """Optional 'translate' policy: both SACK edges invert through the opposite
        ledger, consistently with the cumulative ack."""
        o = TransportOracle(table_size=64, ledger_depth=4, sack_policy="translate")
        F = "st"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))    # FWD boundary 54, delta 7
        # a REV segment SACKs padded FWD bytes [1010, 1061): left below pad, right at pad end
        r = o.process(rev(F, ISN_R, ISN_F, plen=0, sack=(ISN_F + 10, ISN_F + 54 + PAD)))
        self.assertEqual(r.sack, (ISN_F + 10, ISN_F + 54))      # right edge de-shifted by 7

    def test_sack_translate_policy_edge_inside_pad_snaps(self):
        o = TransportOracle(table_size=64, ledger_depth=4, sack_policy="translate")
        F = "st2"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        r = o.process(rev(F, ISN_R, ISN_F, plen=0, sack=(ISN_F + 10, ISN_F + 54 + 3)))
        self.assertEqual(r.sack, (ISN_F + 10, ISN_F + 54))      # right edge snapped to boundary

    # ===================================================================== #
    # AREA seqack -- the core step-function translation
    # ===================================================================== #

    def test_seqack_two_sequential_transforms_cumulative(self):
        self._pad_resp1()
        r2 = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r2.seq, 1054 + PAD)
        r3 = self.o.process(fwd(self.F, ISN_F + 108, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r3.seq, 1108 + 2 * PAD)

    def test_seqack_ack_crossing_boundary_exact(self):
        self._pad_resp1()
        a = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0))
        self.assertEqual(a.ack, 1054)
        self.assertFalse(a.partial_ack)

    def test_seqack_ack_inside_pad_snaps(self):
        self._pad_resp1()
        a = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + 3, plen=0))
        self.assertEqual(a.ack, 1054)
        self.assertTrue(a.partial_ack)

    def test_seqack_duplicate_ack_same_original(self):
        self._pad_resp1()
        for _ in range(3):
            a = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0))
            self.assertEqual(a.ack, 1054)

    def test_seqack_out_of_order_per_seq_delta(self):
        self._pad_resp1()
        self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.o.process(fwd(self.F, ISN_F + 108, ISN_R, plen=54, insert=PAD))
        ooo = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(ooo.seq, 1054 + PAD)
        ooo0 = self.o.process(fwd(self.F, ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(ooo0.seq, 1000)

    def test_seqack_bidirectional_independent_deltas(self):
        F = "bidir"
        DR = 11
        rR = self.o.process(rev(F, ISN_R, ISN_F, plen=20, insert=DR))
        self.assertEqual(rR.seq, ISN_R)
        rF = self.o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(rF.seq, ISN_F)
        aF = self.o.process(fwd(F, ISN_F + 54, ISN_R + 20 + DR, plen=0))
        self.assertEqual(aF.ack, ISN_R + 20)           # de-shifted by Delta_rev=11
        self.assertEqual(aF.seq, ISN_F + 54 + PAD)     # own seq by Delta_fwd=7
        aR = self.o.process(rev(F, ISN_R + 20, ISN_F + 54 + PAD, plen=0))
        self.assertEqual(aR.ack, ISN_F + 54)           # de-shifted by Delta_fwd=7
        self.assertEqual(aR.seq, ISN_R + 20 + DR)      # own seq by Delta_rev=11

    def test_seqack_wrap_eligibility_rejection(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "wrapflow"
        o.process(fwd(F, 1000, ISN_R, plen=10, insert=PAD))
        far = mod32(1000 + WRAP_GUARD + 5)
        r = o.process(fwd(F, far, ISN_R, plen=5, insert=PAD))
        self.assertEqual(r.outcome, Outcome.TRANSLATED_FROZEN)
        self.assertEqual(r.committed_len, 0)
        self.assertIn("wrap", r.note)

    def test_seqack_modular_translation_across_wrap(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "wrapflow2"
        isn = mod32(-50)
        r1 = o.process(fwd(F, isn, ISN_R, plen=10, insert=PAD))
        self.assertEqual(r1.seq, isn)
        r2 = o.process(fwd(F, mod32(isn + 45), ISN_R, plen=5))
        self.assertEqual(r2.seq, mod32(isn + 45 + PAD))
        self.assertEqual(r2.seq, 2)

    # ===================================================================== #
    # AREA degrade -- bounded-limit behaviors stay safe (never raw pass-through)
    # ===================================================================== #

    def test_degrade_depth_cap_freezes_keeps_translating(self):
        o = TransportOracle(table_size=64, ledger_depth=2)
        F = "deep"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=54, insert=PAD))
        r3 = o.process(fwd(F, ISN_F + 108, ISN_R, plen=54, insert=PAD))
        self.assertEqual(r3.committed_len, 0)
        self.assertEqual(r3.outcome, Outcome.TRANSLATED_FROZEN)
        self.assertEqual(r3.seq, 1108 + 2 * PAD)
        a = o.process(rev(F, ISN_R, ISN_F + 108 + 2 * PAD, plen=0))
        self.assertEqual(a.ack, 1108)

    def test_degrade_unsupported_post_epoch_still_translated(self):
        self._pad_resp1()
        u = self.o.process(fwd(self.F, ISN_F + 54, ISN_R, plen=20, insert=0, supported=False))
        self.assertNotEqual(u.outcome, Outcome.NATIVE)
        self.assertEqual(u.seq, 1054 + PAD)
        ur = self.o.process(rev(self.F, ISN_R, ISN_F + 54 + PAD, plen=0, supported=False))
        self.assertEqual(ur.ack, 1054)

    def test_degrade_unsupported_pre_epoch_native_ok(self):
        r = self.o.process(fwd(self.F, ISN_F, ISN_R, plen=30, insert=0, supported=False))
        self.assertEqual(r.outcome, Outcome.NATIVE)
        self.assertEqual(r.seq, ISN_F)

    def test_degrade_demo_mainline_consistent(self):
        from transport_oracle import _demo
        d = _demo()
        self.assertEqual(d["pass"], d["total"])
        self.assertTrue(d["retransmit_reemits_pad"])
        self.assertTrue(d["reconstruction_byte_exact"])


# --------------------------------------------------------------------------- #
# Per-area PASS/FAIL + overall transport-gate verdict
# --------------------------------------------------------------------------- #
AREA_OF_PREFIX = {
    "test_retx_": "retx", "test_overlap_": "overlap", "test_recon_": "recon",
    "test_teardown_": "teardown", "test_owner_": "owner", "test_sack_": "sack",
    "test_seqack_": "seqack", "test_degrade_": "degrade",
}
# Areas that must ALL pass for the transport gate to open (P4 may begin):
REQUIRED = ["retx", "overlap", "recon", "teardown", "owner", "sack"]


def _area_of(test_id: str) -> str:
    name = test_id.rsplit(".", 1)[-1]
    for pfx, area in AREA_OF_PREFIX.items():
        if name.startswith(pfx):
            return area
    return "other"


def _flatten(suite) -> list:
    out = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            out.extend(_flatten(item))
        elif item is not None:
            out.append(item)
    return out


def _machine_summary() -> None:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TransportOracleTests)
    tests = _flatten(suite)                    # capture ids BEFORE run (run() nulls the suite)
    result = unittest.TestResult()
    suite.run(result)

    areas: dict = {}
    for test in tests:
        areas.setdefault(_area_of(test.id()), {"total": 0, "failed": 0})["total"] += 1
    bad = [t.id() for t, _ in result.failures] + [t.id() for t, _ in result.errors]
    for tid in bad:
        areas.setdefault(_area_of(tid), {"total": 0, "failed": 0})["failed"] += 1

    area_pass = {a: (v["failed"] == 0) for a, v in areas.items()}
    gate = all(area_pass.get(a, False) for a in REQUIRED)
    total = suite.countTestCases()
    summary = {
        "suite": "test_transport_oracle",
        "total": total,
        "passed": total - len(bad),
        "failed": len(bad),
        "areas": {a: {"total": v["total"], "failed": v["failed"], "pass": area_pass[a]}
                  for a, v in sorted(areas.items())},
        "required_areas": REQUIRED,
        "transport_gate": "PASS" if gate else "FAIL",
        "failing_tests": bad,
    }
    print("MACHINE_SUMMARY " + json.dumps(summary))


if __name__ == "__main__":
    if "--json" in sys.argv:
        sys.argv.remove("--json")
        _machine_summary()
    unittest.main(verbosity=2)
