#!/usr/bin/env python3
"""Repair-regression + comprehensive coverage suite for transport_oracle.py.

This suite was written to CLOSE the false-green audit: the legacy 46/46 passed while five
safety-critical transport hazards were unhandled or mis-tested. Every test here fails on the
pre-repair behavior (the mutation_harness.py reverts each fix and proves a NAMED test here
dies) and passes on the repaired source. Assertions are against hand-computed constants or an
INDEPENDENTLY built canonical stream, never the oracle's own ledger.

Areas (method-name prefix -> gate area):
  reuse     -- concurrent 5-tuple reuse: new-epoch packets never translated with old state
  template  -- same boundary+size, different template_id = CONFLICT, not idempotent
  sacklearn -- SACK eligibility LEARNED at SYN/SYN-ACK, retained per epoch, data field ignored
  sweep     -- wall-clock / sweepable retirement horizon reclaims a silent flow
  timewait  -- delayed duplicates after retirement quarantined (no phantom epoch)
  fin       -- FIN each side, ack of each FIN, final ACK translated (never native)
  rst       -- RST translate-before-retire, both directions
  wrap      -- sequence wrap: eligibility refused, modular translation across 2^32
  reorder   -- older-response retransmit after newer responses; overlap/resegment
  ackpos    -- ACK before / at / inside / after a pad; dup + out-of-order ACK both directions
  owner2    -- hash collision denies intruder, incumbent preserved; table pressure
  notnative -- NO silent native pass once translation has begun on an epoch

Run:  python3 test_transport_repairs.py
      python3 test_transport_repairs.py --json     # + machine-readable area/gate summary
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
ISN_F = 1000
ISN_R = 5000


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


class RepairTests(unittest.TestCase):

    # ===================================================================== #
    # AREA reuse -- the MANDATORY counterexample and its neighbours
    # ===================================================================== #

    def test_reuse_new_epoch_not_translated_with_old_ledger(self):
        """MANDATORY. Old flow inserts 7 bytes after payload ending at seq 1010; a reused
        5-tuple SYN at 9000 arrives BEFORE the old flow retires; new-epoch data at 9001
        must NEVER be translated with the old ledger (the pre-repair bug shifted it to
        9008). Both old lingering and new-epoch packets are exercised while they coexist."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "reuse"
        old = o.process(fwd(F, 1000, 5000, plen=10, insert=7))     # boundary 10, pad 7
        self.assertEqual(old.outcome, Outcome.TRANSLATED_INSERTED)
        syn = o.process(fwd(F, 9000, 9000, plen=0, syn=True))      # reused-tuple SYN
        self.assertEqual(syn.outcome, Outcome.NATIVE)
        # new-epoch data: MUST stay native/identity, NOT 9008
        new = o.process(fwd(F, 9001, 9500, plen=10, insert=0))
        self.assertEqual(new.seq, 9001)
        self.assertEqual(new.outcome, Outcome.NATIVE)
        self.assertNotEqual(new.seq, 9008)
        # old lingering retransmit: MUST still translate and re-emit its pad
        lin = o.process(fwd(F, 1000, 5000, plen=10, insert=0))
        self.assertEqual(lin.seq, 1000)
        self.assertEqual(lin.inserted_len, 7)
        self.assertNotEqual(lin.outcome, Outcome.NATIVE)

    def test_reuse_new_epoch_insert_failed_closed(self):
        """A new-incarnation packet that itself wants an insertion is failed CLOSED to
        native (no coverage) until the old epoch retires -- never a second overlapping
        ledger on the same slot."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "reuse2"
        o.process(fwd(F, 1000, 5000, plen=10, insert=7))
        o.process(fwd(F, 9000, 9000, plen=0, syn=True))
        new = o.process(fwd(F, 9000, 9500, plen=20, insert=7))     # new epoch wants a pad
        self.assertEqual(new.outcome, Outcome.NATIVE)
        self.assertEqual(new.seq, 9000)
        self.assertEqual(new.committed_len, 0)

    def test_reuse_old_stream_reconstructs_byte_exact_during_quarantine(self):
        """While the tuple is quarantined, the OLD epoch's transformed stream still
        reassembles byte-for-byte from its emissions; the new-incarnation native packet
        does not corrupt it."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "reuse3"
        reasm = StreamReassembler(ISN_F)
        r1 = o.process(fwd(F, 1000, 5000, plen=10, insert=7, tid=0)); reasm.deliver(r1.seq, r1.emitted)
        o.process(fwd(F, 9000, 9000, plen=0, syn=True))
        o.process(fwd(F, 9001, 9500, plen=10, insert=0))           # new epoch (native, ignored)
        rr = o.process(fwd(F, 1000, 5000, plen=10, insert=0)); reasm.deliver(rr.seq, rr.emitted)
        gen = o.flow(F).generation
        canon = build_canonical(Dir.FWD, 10, [(10, 7, 0)], gen)
        self.assertTrue(reasm.ok_against(canon))

    def test_reuse_after_old_retires_new_incarnation_claims_fresh(self):
        """Once the old epoch retires, the anchored new incarnation claims a NEW generation
        with empty ledgers (no alias to old deltas)."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "reuse4"
        o.process(fwd(F, 1000, 5000, plen=10, insert=7))
        g_old = o.flow(F).generation
        o.process(fwd(F, 9000, 9000, plen=0, syn=True))
        o.process(fwd(F, 1010, 5000, plen=0, rst=True))            # retire old epoch
        self.assertIsNone(o.flow(F))
        new = o.process(fwd(F, 9000, 9500, plen=20, insert=7))     # new incarnation claims
        self.assertEqual(new.outcome, Outcome.TRANSLATED_INSERTED)
        self.assertGreater(o.flow(F).generation, g_old)
        self.assertEqual(new.seq, 9000)

    def test_reuse_old_epoch_packets_never_native_during_quarantine(self):
        """During quarantine, EVERY genuinely-old-epoch packet (data, retransmit, pure ack)
        keeps being translated -- never a silent native pass for the old epoch."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "reuse5"
        o.process(rev(F, ISN_R, ISN_F, plen=20, insert=11))                 # REV epoch
        o.process(fwd(F, ISN_F, ISN_R + 31, plen=54, insert=PAD))           # FWD epoch
        o.process(fwd(F, 9000, 9000, plen=0, syn=True))                     # reuse SYN
        for s in [fwd(F, ISN_F, ISN_R + 31, plen=54, insert=0),             # old FWD retransmit
                  rev(F, ISN_R, ISN_F + 54 + PAD, plen=0),                  # old REV pure ack
                  rev(F, ISN_R + 20, ISN_F + 54 + PAD, plen=0)]:            # old REV ack dup
            r = o.process(s)
            self.assertNotEqual(r.outcome, Outcome.NATIVE)

    # ===================================================================== #
    # AREA template -- same boundary+size, different template_id = CONFLICT
    # ===================================================================== #

    def test_template_conflict_different_id_not_idempotent(self):
        """A committed boundary re-hit with the SAME size but a DIFFERENT template_id is a
        CONFLICT -- it must NOT be silently re-emitted as the old template, and must not
        commit a new boundary. The COMMITTED template's bytes are what is re-emitted."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "tpl"
        o.process(fwd(F, 1000, 5000, plen=10, insert=5, tid=0))    # commit boundary 10 tid 0
        r = o.process(fwd(F, 1000, 5000, plen=10, insert=5, tid=9))
        self.assertIn("conflict", r.note)
        self.assertEqual(r.committed_len, 0)
        self.assertFalse(r.newly_recorded)
        # the re-emitted bytes are the COMMITTED template (tid 0), never the conflicting 9
        self.assertEqual([e.template_id for e in r.emitted_insertions], [0])
        gen = o.flow(F).generation
        self.assertEqual(r.emitted_insertions[0].data, render_insertion(0, 5, 10, gen))

    def test_template_same_id_still_idempotent_and_reemits(self):
        """A genuine retransmit re-derives the SAME template; that stays idempotent (no new
        offset) and STILL re-emits the pad bytes."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "tpl2"
        o.process(fwd(F, 1000, 5000, plen=10, insert=5, tid=3))
        r = o.process(fwd(F, 1000, 5000, plen=10, insert=5, tid=3))
        self.assertEqual(r.committed_len, 0)
        self.assertEqual(r.inserted_len, 5)
        self.assertNotIn("conflict", r.note)

    def test_template_conflict_reconstruction_matches_committed(self):
        """After a template conflict the reconstructed stream matches the ORIGINALLY
        committed plan (tid 0), proving the conflict never corrupted committed history."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "tpl3"
        reasm = StreamReassembler(ISN_F)
        r1 = o.process(fwd(F, 1000, 5000, plen=10, insert=5, tid=0)); reasm.deliver(r1.seq, r1.emitted)
        r2 = o.process(fwd(F, 1000, 5000, plen=10, insert=5, tid=9)); reasm.deliver(r2.seq, r2.emitted)
        gen = o.flow(F).generation
        canon = build_canonical(Dir.FWD, 10, [(10, 5, 0)], gen)
        self.assertTrue(reasm.ok_against(canon))

    # ===================================================================== #
    # AREA sacklearn -- eligibility learned at handshake, retained per epoch
    # ===================================================================== #

    def test_sacklearn_syn_negotiated_rejects_insertion(self):
        """SACK-permitted learned from the client SYN (FWD) rejects insertion; the data
        segment carries no option (sack_permitted=False) yet is still refused."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "sl1"
        o.process(fwd(F, ISN_F, ISN_R, syn=True, sack_permitted=True))
        r = o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD, sack_permitted=False))
        self.assertEqual(r.outcome, Outcome.NATIVE)
        self.assertEqual(r.committed_len, 0)
        self.assertIsNone(o.flow(F))

    def test_sacklearn_synack_negotiated_rejects_insertion(self):
        """SACK-permitted learned from the server SYN-ACK (REV direction) equally rejects
        insertion on the FWD data stream."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "sl2"
        o.process(rev(F, ISN_R, ISN_F, syn=True, sack_permitted=True))     # SYN-ACK negotiates
        r = o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD, sack_permitted=False))
        self.assertEqual(r.outcome, Outcome.NATIVE)
        self.assertIsNone(o.flow(F))

    def test_sacklearn_data_field_never_trusted(self):
        """A data segment that spuriously sets sack_permitted=True, with NO SACK negotiated
        at the handshake, is treated as ELIGIBLE (the data field is ignored) -- proving the
        eligibility decision is not driven by an untrusted data-segment boolean."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "sl3"
        o.process(fwd(F, ISN_F, ISN_R, syn=True, sack_permitted=False))    # no SACK negotiated
        r = o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD, sack_permitted=True))  # data lies
        self.assertEqual(r.outcome, Outcome.TRANSLATED_INSERTED)
        self.assertEqual(r.committed_len, PAD)

    def test_sacklearn_retained_across_segments(self):
        """Eligibility learned at the SYN is RETAINED for every later segment of the epoch,
        not re-decided per packet."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "sl4"
        o.process(fwd(F, ISN_F, ISN_R, syn=True, sack_permitted=True))
        for k in range(3):
            r = o.process(fwd(F, ISN_F + 54 * k, ISN_R, plen=54, insert=PAD, sack_permitted=False))
            self.assertEqual(r.outcome, Outcome.NATIVE)
        self.assertIsNone(o.flow(F))

    # ===================================================================== #
    # AREA sweep -- wall-clock / sweepable retirement horizon
    # ===================================================================== #

    def test_sweep_reclaims_silent_flow(self):
        """A flow that receives NO later packet is still reclaimable by a wall-clock sweep
        (the pre-repair per-segment clock leaked such state forever)."""
        o = TransportOracle(table_size=64, ledger_depth=4, idle_horizon=100)
        F = "sw1"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD), now=0)
        self.assertIsNotNone(o.flow(F))
        reclaimed = o.sweep(now=100)
        self.assertIn(F, reclaimed)
        self.assertIsNone(o.flow(F))

    def test_sweep_keeps_recently_seen_flow(self):
        """A flow seen within the idle horizon is NOT swept."""
        o = TransportOracle(table_size=64, ledger_depth=4, idle_horizon=100)
        F = "sw2"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD), now=0)
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=54, insert=PAD), now=80)
        o.sweep(now=120)                       # 120 - 80 = 40 < 100
        self.assertIsNotNone(o.flow(F))

    def test_sweep_reclaims_mid_epoch_flow_without_fin(self):
        """An epoch that began and never sent a FIN (no teardown deadline armed) is still
        reclaimable by the horizon -- the specific leak the audit flagged."""
        o = TransportOracle(table_size=64, ledger_depth=4, idle_horizon=10)
        F = "sw3"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD), now=0)
        self.assertIsNone(o.flow(F).teardown_deadline)          # no FIN -> no in-band deadline
        o.sweep(now=10)
        self.assertIsNone(o.flow(F))

    def test_sweep_purges_expired_tombstone(self):
        """sweep() also bounds tombstone memory: a tombstone older than time_wait is purged
        so it no longer quarantines (a much later packet is a fresh flow)."""
        o = TransportOracle(table_size=64, ledger_depth=4, time_wait=50, idle_horizon=1 << 30)
        F = "sw4"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD), now=0)
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=0, rst=True), now=1)   # retire -> tombstone
        self.assertIn(F, o._tombstones)
        o.sweep(now=100)                                                # 100 - 1 >= 50
        self.assertNotIn(F, o._tombstones)

    # ===================================================================== #
    # AREA timewait -- delayed duplicates after retirement
    # ===================================================================== #

    def test_timewait_delayed_dup_after_rst_native(self):
        """A delayed duplicate of the old response arriving after RST-retire (even carrying
        insert>0) is quarantined to native -- it must NOT spawn a phantom TRANSLATED epoch."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "tw1"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=0, rst=True))
        dd = o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(dd.outcome, Outcome.NATIVE)
        self.assertEqual(dd.seq, ISN_F)
        self.assertIsNone(o.flow(F))

    def test_timewait_delayed_dup_after_full_teardown_native(self):
        """Same quarantine after a full FIN/ACK teardown."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "tw2"
        o.process(rev(F, ISN_R, ISN_F, plen=20, insert=11))
        o.process(fwd(F, ISN_F, ISN_R + 31, plen=54, insert=PAD))
        o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, fin=True))            # FWD FIN
        o.process(rev(F, ISN_R + 20, ISN_F + 62, plen=0, fin=True))           # REV FIN acks FWD FIN
        o.process(fwd(F, ISN_F + 54, ISN_R + 32, plen=0))                     # acks REV FIN -> retire
        self.assertIsNone(o.flow(F))
        dd = o.process(fwd(F, ISN_F, ISN_R + 31, plen=54, insert=PAD))        # delayed dup
        self.assertEqual(dd.outcome, Outcome.NATIVE)

    def test_timewait_new_incarnation_after_reuse_syn_still_claims(self):
        """A tombstone must NOT block a genuine new incarnation: after a reuse SYN anchored
        the new ISN and the old flow retired, new-ISN data claims a fresh epoch."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "tw3"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        o.process(fwd(F, 9000, 9000, plen=0, syn=True))                      # reuse SYN
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=0, rst=True))               # retire old
        r = o.process(fwd(F, 9000, 9500, plen=20, insert=PAD))               # new ISN -> claim
        self.assertEqual(r.outcome, Outcome.TRANSLATED_INSERTED)

    def test_timewait_expires_then_normal_native(self):
        """After time_wait elapses the tombstone stops quarantining; a much-later insert-free
        packet in the old window is a plain native flow again."""
        o = TransportOracle(table_size=64, ledger_depth=4, time_wait=50)
        F = "tw4"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD), now=0)
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=0, rst=True), now=1)
        late = o.process(fwd(F, ISN_F, ISN_R, plen=10, insert=0), now=100)   # tombstone expired
        self.assertEqual(late.outcome, Outcome.NATIVE)

    # ===================================================================== #
    # AREA fin -- FIN each side, ack of each FIN, final ACK translated
    # ===================================================================== #

    def test_fin_each_side_acked_final_ack_translated(self):
        """Both directions FIN; each FIN is cumulatively acked; the FINAL ack-of-FIN is
        TRANSLATED (de-shifted), never passed native, and then the state retires."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "fin1"
        o.process(rev(F, ISN_R, ISN_F, plen=20, insert=11))                  # REV pad 11 @20
        o.process(fwd(F, ISN_F, ISN_R + 31, plen=54, insert=PAD))            # FWD pad 7 @54
        f_fwd = o.process(fwd(F, ISN_F + 54, ISN_R + 31, plen=0, fin=True))  # FWD FIN
        self.assertEqual(f_fwd.seq, ISN_F + 54 + PAD)
        self.assertFalse(f_fwd.retired)
        a_fwdfin = o.process(rev(F, ISN_R + 20, ISN_F + 54 + PAD + 1, plen=0))   # ack FWD FIN
        self.assertEqual(a_fwdfin.ack, ISN_F + 54 + 1)                       # de-shifted by 7
        f_rev = o.process(rev(F, ISN_R + 20, ISN_F + 54 + PAD + 1, plen=0, fin=True))  # REV FIN
        self.assertEqual(f_rev.seq, ISN_R + 20 + 11)
        self.assertFalse(f_rev.retired)
        final = o.process(fwd(F, ISN_F + 54, ISN_R + 20 + 11 + 1, plen=0))   # ack REV FIN
        self.assertEqual(final.outcome, Outcome.RETIRED)
        self.assertEqual(final.ack, ISN_R + 20 + 1)                          # de-shifted by 11
        self.assertNotEqual(final.ack, ISN_R + 20 + 11 + 1)                  # NOT native
        self.assertIsNone(o.flow(F))

    def test_fin_half_close_data_still_translated(self):
        """After one side's FIN, lingering data on the other side is still translated and
        re-emitted (half-close)."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "fin2"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=0, fin=True))               # FWD FIN
        d = o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))             # lingering retransmit
        self.assertEqual(d.inserted_len, PAD)
        self.assertNotEqual(d.outcome, Outcome.NATIVE)

    # ===================================================================== #
    # AREA rst -- RST translate-before-retire, both directions
    # ===================================================================== #

    def test_rst_fwd_translated_before_retire(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "rst1"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        r = o.process(fwd(F, ISN_F + 54, ISN_R, plen=0, rst=True))
        self.assertEqual(r.outcome, Outcome.RETIRED)
        self.assertEqual(r.seq, ISN_F + 54 + PAD)                            # translated
        self.assertIsNone(o.flow(F))

    def test_rst_rev_ack_translated_before_retire(self):
        """A REV RST carries an ack for the FWD stream; that ack is de-shifted before the
        state is freed."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "rst2"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))                 # FWD pad 7
        r = o.process(rev(F, ISN_R, ISN_F + 54 + PAD, plen=0, rst=True))
        self.assertEqual(r.outcome, Outcome.RETIRED)
        self.assertEqual(r.ack, ISN_F + 54)                                  # de-shifted
        self.assertIsNone(o.flow(F))

    # ===================================================================== #
    # AREA wrap -- sequence wrap
    # ===================================================================== #

    def test_wrap_eligibility_refused(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "wr1"
        o.process(fwd(F, 1000, ISN_R, plen=10, insert=PAD))
        far = mod32(1000 + WRAP_GUARD + 5)
        r = o.process(fwd(F, far, ISN_R, plen=5, insert=PAD))
        self.assertEqual(r.outcome, Outcome.TRANSLATED_FROZEN)
        self.assertEqual(r.committed_len, 0)

    def test_wrap_modular_translation_across_2e32(self):
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "wr2"
        isn = mod32(-50)
        r1 = o.process(fwd(F, isn, ISN_R, plen=10, insert=PAD))
        self.assertEqual(r1.seq, isn)
        r2 = o.process(fwd(F, mod32(isn + 45), ISN_R, plen=5))
        self.assertEqual(r2.seq, mod32(isn + 45 + PAD))
        self.assertEqual(r2.seq, 2)                                          # wrapped past 2^32

    # ===================================================================== #
    # AREA reorder -- older-response retransmit after newer; overlap/resegment
    # ===================================================================== #

    def test_reorder_older_response_after_newer_reemits_correct(self):
        """After resp#1, resp#2, resp#3 commit, a retransmit of the OLDER resp#1 re-emits
        its pad at the LOWER translated seq with the offset unchanged."""
        o = TransportOracle(table_size=64, ledger_depth=8)
        F = "ro1"
        for k in range(3):
            o.process(fwd(F, ISN_F + 50 * k, ISN_R, plen=50, insert=5, tid=k))  # 50,100,150
        older = o.process(fwd(F, ISN_F, ISN_R, plen=50, insert=0))              # retransmit resp#1
        self.assertEqual(older.seq, ISN_F)
        self.assertEqual([e.boundary for e in older.emitted_insertions], [50])
        self.assertEqual(older.committed_len, 0)

    def test_reorder_resegmented_retransmit_reconstructs(self):
        """A different segmentation of already-committed data reassembles byte-for-byte."""
        o = TransportOracle(table_size=64, ledger_depth=8)
        F = "ro2"
        reasm = StreamReassembler(ISN_F)
        for k in range(3):
            r = o.process(fwd(F, ISN_F + 50 * k, ISN_R, plen=50, insert=5, tid=k))
            reasm.deliver(r.seq, r.emitted)
        for s in [fwd(F, ISN_F, ISN_R, plen=75, insert=0),
                  fwd(F, ISN_F + 75, ISN_R, plen=75, insert=0)]:              # re-cut
            r = o.process(s); reasm.deliver(r.seq, r.emitted)
        gen = o.flow(F).generation
        canon = build_canonical(Dir.FWD, 150, [(50, 5, 0), (100, 5, 1), (150, 5, 2)], gen)
        self.assertTrue(reasm.ok_against(canon))

    # ===================================================================== #
    # AREA ackpos -- ACK before/at/inside/after a pad; dup + OOO both dirs
    # ===================================================================== #

    def _two_fwd_pads(self, F="ap"):
        o = TransportOracle(table_size=64, ledger_depth=4)
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))            # boundary 54
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=54, insert=PAD))       # boundary 108
        return o, F

    def test_ackpos_before_pad(self):
        o, F = self._two_fwd_pads("ap1")
        a = o.process(rev(F, ISN_R, ISN_F + 30, plen=0))               # acks 30 orig bytes
        self.assertEqual(a.ack, ISN_F + 30)
        self.assertFalse(a.partial_ack)

    def test_ackpos_at_pad_start(self):
        o, F = self._two_fwd_pads("ap2")
        a = o.process(rev(F, ISN_R, ISN_F + 54, plen=0))               # acks exactly 54 orig
        self.assertEqual(a.ack, ISN_F + 54)
        self.assertFalse(a.partial_ack)

    def test_ackpos_inside_pad(self):
        o, F = self._two_fwd_pads("ap3")
        a = o.process(rev(F, ISN_R, ISN_F + 54 + 3, plen=0))           # 3 bytes into pad1
        self.assertEqual(a.ack, ISN_F + 54)
        self.assertTrue(a.partial_ack)

    def test_ackpos_after_pad(self):
        o, F = self._two_fwd_pads("ap4")
        a = o.process(rev(F, ISN_R, ISN_F + 54 + PAD + 1, plen=0))     # past pad1 + 1 orig byte
        self.assertEqual(a.ack, ISN_F + 55)
        self.assertFalse(a.partial_ack)

    def test_ackpos_dup_ack_both_directions(self):
        """Duplicate acks translate to the same de-shifted value in each direction."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "ap5"
        o.process(rev(F, ISN_R, ISN_F, plen=20, insert=11))            # REV pad 11
        o.process(fwd(F, ISN_F, ISN_R + 31, plen=54, insert=PAD))      # FWD pad 7
        for _ in range(3):
            a = o.process(rev(F, ISN_R + 20, ISN_F + 54 + PAD, plen=0))
            self.assertEqual(a.ack, ISN_F + 54)
        for _ in range(3):
            b = o.process(fwd(F, ISN_F + 54, ISN_R + 20 + 11, plen=0))
            self.assertEqual(b.ack, ISN_R + 20)

    def test_ackpos_out_of_order_ack_both_directions(self):
        """A higher ack followed by a stale lower ack each translate by their own position."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "ap6"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        o.process(fwd(F, ISN_F + 54, ISN_R, plen=54, insert=PAD))      # boundaries 54, 108
        high = o.process(rev(F, ISN_R, ISN_F + 108 + 2 * PAD, plen=0)) # acks both pads
        self.assertEqual(high.ack, ISN_F + 108)
        low = o.process(rev(F, ISN_R, ISN_F + 54 + PAD, plen=0))       # stale lower ack
        self.assertEqual(low.ack, ISN_F + 54)

    # ===================================================================== #
    # AREA owner2 -- hash collision + table pressure
    # ===================================================================== #

    def test_owner2_hash_collision_denies_intruder_preserves_incumbent(self):
        o = TransportOracle(table_size=64, ledger_depth=4, hash_fn=lambda f: 0)
        a1 = o.process(fwd("A", ISN_F, ISN_R, plen=54, insert=PAD))
        self.assertEqual(a1.outcome, Outcome.TRANSLATED_INSERTED)
        b = o.process(fwd("B", 9000, 9500, plen=40, insert=PAD))       # same slot, other key
        self.assertEqual(b.outcome, Outcome.DENIED_COLLISION)
        self.assertEqual(b.seq, 9000)                                  # intruder unmodified
        self.assertEqual(o.table.false_hits_undetected, 0)             # full-key: no aliasing
        a2 = o.process(fwd("A", ISN_F + 54, ISN_R, plen=54, insert=PAD))
        self.assertEqual(a2.seq, ISN_F + 54 + PAD)                     # incumbent uncorrupted

    def test_owner2_table_pressure_denies_newcomer(self):
        o = TransportOracle(table_size=64, ledger_depth=4, hash_fn=lambda f: 0)
        o.process(fwd("inc", ISN_F, ISN_R, plen=54, insert=PAD))
        n = o.process(fwd("new", 8000, 8500, plen=54, insert=PAD))
        self.assertEqual(n.outcome, Outcome.DENIED_COLLISION)
        self.assertEqual(n.seq, 8000)

    # ===================================================================== #
    # AREA notnative -- NO silent native pass after translation begins
    # ===================================================================== #

    def test_notnative_after_epoch_various_packets(self):
        """Once an epoch has begun (a ledger is non-empty), no same-epoch packet in either
        direction may be passed native. Covers data, retransmit, pure ack, out-of-order,
        duplicate, and an UNSUPPORTED (unparsed) segment."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "nn1"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))           # FWD epoch begins
        probes = [
            fwd(F, ISN_F, ISN_R, plen=54, insert=PAD),                 # retransmit
            fwd(F, ISN_F + 54, ISN_R, plen=54, insert=PAD),            # new data
            rev(F, ISN_R, ISN_F + 54 + PAD, plen=0),                   # REV pure ack
            rev(F, ISN_R, ISN_F + 54 + PAD, plen=0),                   # dup ack
            fwd(F, ISN_F, ISN_R, plen=54, insert=0),                   # OOO retransmit
            fwd(F, ISN_F + 108, ISN_R, plen=20, insert=0, supported=False),  # unsupported
        ]
        for s in probes:
            r = o.process(s)
            self.assertNotEqual(r.outcome, Outcome.NATIVE,
                               msg=f"native leak after epoch for {s.direction.name} seq={s.seq}")

    def test_notnative_unsupported_post_epoch_translated(self):
        """An UNSUPPORTED segment after the epoch is still translated (seq/ack), never a raw
        native pass."""
        o = TransportOracle(table_size=64, ledger_depth=4)
        F = "nn2"
        o.process(fwd(F, ISN_F, ISN_R, plen=54, insert=PAD))
        u = o.process(fwd(F, ISN_F + 54, ISN_R, plen=20, insert=0, supported=False))
        self.assertNotEqual(u.outcome, Outcome.NATIVE)
        self.assertEqual(u.seq, ISN_F + 54 + PAD)


# --------------------------------------------------------------------------- #
# Per-area PASS/FAIL + gate verdict (mirrors the legacy runner's shape)
# --------------------------------------------------------------------------- #
AREA_OF_PREFIX = {
    "test_reuse_": "reuse", "test_template_": "template", "test_sacklearn_": "sacklearn",
    "test_sweep_": "sweep", "test_timewait_": "timewait", "test_fin_": "fin",
    "test_rst_": "rst", "test_wrap_": "wrap", "test_reorder_": "reorder",
    "test_ackpos_": "ackpos", "test_owner2_": "owner2", "test_notnative_": "notnative",
}
# Every repair area is required: the gate opens only if all of them pass.
REQUIRED = sorted(set(AREA_OF_PREFIX.values()))


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
    suite = loader.loadTestsFromTestCase(RepairTests)
    tests = _flatten(suite)
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
        "suite": "test_transport_repairs",
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
