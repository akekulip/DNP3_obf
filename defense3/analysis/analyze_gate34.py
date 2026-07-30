#!/usr/bin/env python3
"""
analyze_gate34.py — score §13 GATE 3 and GATE 4.

GATE 3 is five consecutive normal transactions with no P4 reload and no
transaction-state reset between them. GATE 4 is three boundary cases, three
repetitions each, plus one normal transaction to prove recovery.

EVERY transaction is scored with the SAME 17 requirements Gate 2 passed —
`analyze_defense3.score_trial` is imported, not reimplemented — and then the
Gate-3 sequence requirements and the Gate-4 per-case requirements are added on
top. A second, weaker rubric for the later gates is exactly how a regression
gets through, so there isn't one.

Gate 3 passes only if all five transactions pass.
Gate 4 passes only if all three repetitions of all three cases pass, and the
recovery transaction passes.

STDLIB ONLY. Touches no hardware.

    python3 analysis/analyze_gate34.py <gate3.json|gate4.json> [...]
    python3 analysis/analyze_gate34.py --self-test
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import analyze_defense3 as G2                                  # noqa: E402

TAG_INACTIVE = G2.TAG_INACTIVE
dt = G2.dt


def _cf(rec, name):
    v = G2._get(rec, "counters", "fresh", name)
    return None if v is None else int(v)


def _cd(rec, name):
    v = G2._get(rec, "counters", "deq", name)
    return None if v is None else int(v)


def _reg(rec, name):
    v = G2._get(rec, "registers", name)
    return None if v is None else int(v)


def _ts(rec, name):
    """Write-if-zero registers: 0 means NEVER WRITTEN, not t = 0."""
    v = _reg(rec, name)
    return None if v in (None, 0) else v


def per_txn_trace(rec):
    """The direction's per-transaction record list, in its order."""
    t_read = _ts(rec, "reg_ts_read")
    t_full = _ts(rec, "reg_ts_last_block")
    t_arm = _ts(rec, "reg_ts_ack_arm")
    t_t1 = _ts(rec, "reg_ts_block_term")
    t_tN = _ts(rec, "reg_ts_last_term")
    t_rel = _ts(rec, "reg_ts_ack_release")
    t_rrel = _ts(rec, "reg_ts_resp_release")
    dl = _reg(rec, "reg_deadline")
    hold = dt(t_arm, t_rel)
    k = G2._get(rec, "params", "k", default=64)
    rate = G2._get(rec, "params", "rate_dp8_pps", default=37.4e6)
    tau = G2.tau_ns(k, rate)
    d_ns = G2._get(rec, "params", "d_realized_ns")
    return {
        "txn": rec.get("txn_index"),
        "label": rec.get("label"),
        "generation": rec.get("generation"),
        "read_ingress_ns": t_read,
        "reservoir_standing_ns": dt(t_read, t_full),
        "ack_ingress_ns": t_arm,
        "configured_deadline": dl,
        "first_blocker_termination_ns": t_t1,
        "final_blocker_termination_ns": t_tN,
        "ack_commitment_ns": t_rel,
        "response_commitment_ns": t_rrel,
        "hold_ns": hold,
        # detection error: how long after the deadline the FIRST blocker noticed it.
        # The deadline word carries the ARMED marker in bit 0, so it is not a bare
        # timestamp; masking the low byte recovers the tick-aligned instant.
        "detection_error_ns": (None if (t_t1 is None or dl is None)
                               else dt(dl & 0xFFFFFF00, t_t1)),
        "drain_ns": dt(t_t1, t_tN),
        "release_tail_ns": dt(t_tN, t_rel),
        "ack_to_response_separation_ns": dt(t_rel, t_rrel),
        "read_to_ack_ns": dt(t_read, t_arm),
        "hold_minus_D_plus_tau_ns": (None if (hold is None or d_ns is None)
                                     else hold - (d_ns + tau)),
    }


def score_common(rec, label, res):
    """The per-transaction requirements the direction lists for Gate 3, which are
    also the ones every Gate-4 case must keep."""
    def add(rid, text, ok, detail):
        res.append((rid, text, ("INDETERMINATE" if ok is None
                                else "PASS" if ok else "FAIL"), detail))

    gen = rec.get("generation")
    add("T-01", "one fresh NONZERO generation, freshly armed",
        None if None in (_cf(rec, "ARM_FRESH"), _cf(rec, "ARM_DUP"),
                         _cf(rec, "ARM_BUSY")) or gen is None
        else (_cf(rec, "ARM_FRESH") == 1 and _cf(rec, "ARM_DUP") == 0
              and _cf(rec, "ARM_BUSY") == 0 and gen != TAG_INACTIVE),
        "gen=0x%02X ARM_FRESH=%s DUP=%s BUSY=%s (BUSY means the PREVIOUS "
        "transaction did not retire)"
        % (gen or 0, _cf(rec, "ARM_FRESH"), _cf(rec, "ARM_DUP"),
           _cf(rec, "ARM_BUSY")))

    ab = G2._get(rec, "pktgen_after", "app_block_pipe0", default={}) or {}
    add("T-02", "one and only one pktgen trigger",
        None if ab.get("trigger_counter") is None
        else (int(ab.get("trigger_counter")) == 1
              and int(ab.get("batch_counter") or -1) == 1),
        "app1 trigger=%s batch=%s pkt=%s"
        % (ab.get("trigger_counter"), ab.get("batch_counter"),
           ab.get("pkt_counter")))

    k = G2._get(rec, "params", "k", default=64)
    add("T-03", "exactly %d blockers admitted" % k,
        None if _cf(rec, "PKTGEN_ADMIT") is None
        else (_cf(rec, "PKTGEN_ADMIT") == k and _cf(rec, "PKTGEN_DROP") == 0),
        "admitted=%s dropped=%s" % (_cf(rec, "PKTGEN_ADMIT"),
                                    _cf(rec, "PKTGEN_DROP")))

    tr = per_txn_trace(rec)
    add("T-04", "full reservoir standing BEFORE ACK arrival",
        None if None in (tr["reservoir_standing_ns"], tr["read_to_ack_ns"])
        else (0 < tr["reservoir_standing_ns"] < tr["read_to_ack_ns"]),
        "full reservoir at %s ns, ACK at %s ns after the READ"
        % (tr["reservoir_standing_ns"], tr["read_to_ack_ns"]))

    add("T-05", "one ACK admitted to Q_HOLD",
        None if _cf(rec, "ACK_HOLD") is None
        else (_cf(rec, "ACK_HOLD") == 1 and _cf(rec, "ACK_DUP_HOLD") == 0
              and _cf(rec, "ACK_REJECT") == 0),
        "ACK_HOLD=%s DUP=%s REJECT=%s" % (_cf(rec, "ACK_HOLD"),
                                          _cf(rec, "ACK_DUP_HOLD"),
                                          _cf(rec, "ACK_REJECT")))

    add("T-06", "ACK_RELEASE_FAILOPEN == 0",
        None if None in (_cd(rec, "BLOCK_TERM_TMO"), _cd(rec, "RELEASE_FAILOPEN"))
        else (_cd(rec, "BLOCK_TERM_TMO") + _cd(rec, "RELEASE_FAILOPEN") == 0),
        "BLOCK_TERM_TMO=%s RELEASE_FAILOPEN=%s"
        % (_cd(rec, "BLOCK_TERM_TMO"), _cd(rec, "RELEASE_FAILOPEN")))

    add("T-07", "blocker budget expiry == 0",
        None if _cd(rec, "BLOCK_TERM_TMO") is None
        else _cd(rec, "BLOCK_TERM_TMO") == 0,
        "BLOCK_TERM_TMO=%s" % (_cd(rec, "BLOCK_TERM_TMO"),))

    add("T-08", "stale blocker termination == 0",
        None if _cd(rec, "BLOCK_TERM_STALE") is None
        else _cd(rec, "BLOCK_TERM_STALE") == 0,
        "BLOCK_TERM_STALE=%s" % (_cd(rec, "BLOCK_TERM_STALE"),))

    add("T-09", "all %d blockers terminate on the DEADLINE" % k,
        None if _cd(rec, "BLOCK_TERM_DL") is None
        else _cd(rec, "BLOCK_TERM_DL") == k,
        "BLOCK_TERM_DL=%s (stale=%s budget=%s)"
        % (_cd(rec, "BLOCK_TERM_DL"), _cd(rec, "BLOCK_TERM_STALE"),
           _cd(rec, "BLOCK_TERM_TMO")))

    d_ns = G2._get(rec, "params", "d_realized_ns")
    add("T-10", "no ACK commitment before the deadline",
        None if None in (tr["hold_ns"], d_ns) else tr["hold_ns"] >= d_ns,
        "hold=%s ns, D=%s ns" % (tr["hold_ns"], d_ns))

    # ►► SEE the note on _pre_state_verdict in run/poll_defense3.py. This asserts
    # the generation RETIRED and that reg_ack_rel cannot collide with the new
    # generation; it deliberately does NOT demand that reg_deadline be zero, because
    # the fresh ARM disarms it unconditionally and a stale armed word cannot let a
    # duplicate ACK re-arm. That the inherited state was harmless is not asserted —
    # T-05 and T-10 below measure it in the same transaction.
    ps = G2._get(rec, "pre_state", default={}) or {}
    add("T-11", "began from a clean state: previous generation RETIRED",
        None if ps.get("reg_tag") is None else ps.get("reg_tag") == TAG_INACTIVE,
        "inherited reg_tag = 0x%02X (want 0x%02X)%s"
        % (ps.get("reg_tag") or 0, TAG_INACTIVE,
           "  [a control-plane state reset was performed for this repetition]"
           if rec.get("state_reset_performed") else ""))
    add("T-15", "inherited reg_ack_rel does not collide with this generation",
        None if (ps.get("reg_ack_rel") is None or gen is None)
        else ps.get("reg_ack_rel") != gen,
        "inherited reg_ack_rel = 0x%02X, this generation = 0x%02X (equal would "
        "invert the RESPONSE's early/late classification)"
        % (ps.get("reg_ack_rel") or 0, gen or 0))
    add("T-16", "this transaction's ARM SUPERSEDED any inherited deadline",
        None if (_reg(rec, "reg_deadline") is None
                 or ps.get("reg_deadline") is None)
        else (_reg(rec, "reg_deadline") != ps.get("reg_deadline")
              and (_reg(rec, "reg_deadline") & 0x1) == 1),
        "inherited %s -> armed %s (must differ, and bit 0 must be set = ARMED)"
        % (ps.get("reg_deadline"), _reg(rec, "reg_deadline")))
    return tr


def score_normal(rec):
    """A NORMAL transaction: the common requirements plus the ordering pair and
    complete retirement, plus the full Gate-2 rubric."""
    res = []
    tr = score_common(rec, "normal", res)

    def add(rid, text, ok, detail):
        res.append((rid, text, ("INDETERMINATE" if ok is None
                                else "PASS" if ok else "FAIL"), detail))

    add("T-12", "one RESPONSE admitted AFTER the ACK (early, queued behind it)",
        None if _cf(rec, "RESP_HOLD_EARLY") is None
        else (_cf(rec, "RESP_HOLD_EARLY") == 1
              and _cf(rec, "RESP_HOLD_LATE") == 0
              and _cf(rec, "RESP_BYPASS") == 0),
        "RESP_HOLD_EARLY=%s LATE=%s BYPASS=%s"
        % (_cf(rec, "RESP_HOLD_EARLY"), _cf(rec, "RESP_HOLD_LATE"),
           _cf(rec, "RESP_BYPASS")))
    add("T-13", "ACK commitment BEFORE RESPONSE commitment",
        None if tr["ack_to_response_separation_ns"] is None
        else tr["ack_to_response_separation_ns"] > 0,
        "separation = %s ns (must be > 0)"
        % (tr["ack_to_response_separation_ns"],))
    # E1: with an early RESPONSE queued the ACK release must NOT retire; the queued
    # RESPONSE's release must. The counter split is the SALU's own decision, read back.
    add("T-17", "ACK release did NOT retire (a RESPONSE was pending) and the queued "
                "RESPONSE release did",
        None if _cd(rec, "ACK_RELEASE") is None
        else (_cd(rec, "ACK_RELEASE") == 1
              and (_cd(rec, "ACK_REL_RETIRE") or 0) == 0),
        "CD_ACK_RELEASE=%s (want 1: pending, so no retire) "
        "CD_ACK_REL_RETIRE=%s (want 0). This is the direct evidence that the first "
        "RESPONSE MARKED the tag 0xCn -> 0x1n."
        % (_cd(rec, "ACK_RELEASE"), _cd(rec, "ACK_REL_RETIRE")))
    tb = _ts(rec, "reg_ts_resp_bypass")
    add("T-18", "NO RESPONSE copy committed before the ACK",
        None if tr["ack_commitment_ns"] is None
        else (tb is None or dt(tr["ack_commitment_ns"], tb) > 0),
        "bypass-commit timestamp %s (None = nothing forwarded early), ACK at %s"
        % (tb, tr["ack_commitment_ns"]))
    add("T-14", "transaction state retires COMPLETELY",
        None if _reg(rec, "reg_tag") is None
        else (_reg(rec, "reg_tag") == TAG_INACTIVE
              and _cf(rec, "BAD_PORT") in (0, None)),
        "reg_tag after = 0x%02X (want 0x%02X), BAD_PORT=%s"
        % (_reg(rec, "reg_tag") or 0, TAG_INACTIVE, _cf(rec, "BAD_PORT")))

    # the full Gate-2 rubric, unchanged
    g2v, g2res, g2der = G2.score_trial(rec)
    return res, tr, g2v, g2res, g2der


def score_case_A(rec):
    """RESPONSE just before the ACK deadline. Same as a normal transaction — the
    point of the case is that nothing changes when the margin shrinks."""
    return score_normal(rec)


def score_case_B(rec):
    """RESPONSE after the ACK has committed."""
    res = []
    tr = score_common(rec, "B", res)

    def add(rid, text, ok, detail):
        res.append((rid, text, ("INDETERMINATE" if ok is None
                                else "PASS" if ok else "FAIL"), detail))

    d_ns = G2._get(rec, "params", "d_realized_ns")
    add("B-01", "ACK releases AT the configured deadline",
        None if None in (tr["hold_ns"], d_ns)
        else abs(tr["hold_minus_D_plus_tau_ns"]) <= G2.TOL_NS_DEFAULT,
        "hold=%s ns, D=%s ns, corrected error=%s ns"
        % (tr["hold_ns"], d_ns,
           None if tr["hold_minus_D_plus_tau_ns"] is None
           else round(tr["hold_minus_D_plus_tau_ns"], 1)))
    # ►► E1 CHANGES THIS CASE'S EXPECTED CLASSIFICATION, deliberately. The ACK
    # release now retires the transaction when nothing is pending, so a RESPONSE
    # arriving afterwards finds txn_active == 0 and takes the NORMAL FORWARDING PATH
    # (RESP_BYPASS) instead of being held for one traversal. That is what the direction
    # asks for — "leave late RESPONSE traffic on the normal forwarding path" — and it
    # is strictly better: the late RESPONSE is no longer enqueued behind anything.
    add("B-02", "RESPONSE is NOT treated as an early queued response",
        None if _cf(rec, "RESP_HOLD_EARLY") is None
        else (_cf(rec, "RESP_HOLD_EARLY") == 0
              and _cf(rec, "RESP_HOLD_LATE") == 0
              and _cf(rec, "RESP_BYPASS") == 1),
        "RESP_HOLD_EARLY=%s (want 0) RESP_HOLD_LATE=%s (want 0) RESP_BYPASS=%s "
        "(want 1: E1 retires at ACK commitment, so a late RESPONSE takes the normal "
        "forwarding path)"
        % (_cf(rec, "RESP_HOLD_EARLY"), _cf(rec, "RESP_HOLD_LATE"),
           _cf(rec, "RESP_BYPASS")))
    add("B-03", "RESPONSE forwarded EXACTLY ONCE, and NOT held",
        None if _cf(rec, "RESP_BYPASS") is None
        else ((_cf(rec, "RESP_BYPASS") or 0)
              + (_cf(rec, "RESP_HOLD_LATE") or 0)
              + (_cf(rec, "RESP_HOLD_EARLY") or 0) == 1),
        "EARLY=%s LATE=%s BYPASS=%s -> exactly one disposition"
        % (_cf(rec, "RESP_HOLD_EARLY"), _cf(rec, "RESP_HOLD_LATE"),
           _cf(rec, "RESP_BYPASS")))
    add("B-07", "the ACK release RETIRED the transaction (nothing was pending)",
        None if _cd(rec, "ACK_REL_RETIRE") is None
        else (_cd(rec, "ACK_REL_RETIRE") == 1
              and (_cd(rec, "ACK_RELEASE") or 0) == 0),
        "CD_ACK_REL_RETIRE=%s (want 1) CD_ACK_RELEASE=%s (want 0)"
        % (_cd(rec, "ACK_REL_RETIRE"), _cd(rec, "ACK_RELEASE")))
    add("B-04", "no RE-HOLD (the deadline is not armed a second time)",
        None if _cf(rec, "ACK_DUP_HOLD") is None
        else (_cf(rec, "ACK_DUP_HOLD") == 0 and _cf(rec, "ACK_HOLD") == 1),
        "ACK_HOLD=%s ACK_DUP_HOLD=%s"
        % (_cf(rec, "ACK_HOLD"), _cf(rec, "ACK_DUP_HOLD")))
    add("B-05", "clean retirement",
        None if _reg(rec, "reg_tag") is None
        else _reg(rec, "reg_tag") == TAG_INACTIVE,
        "reg_tag after = 0x%02X" % (_reg(rec, "reg_tag") or 0,))
    # ►► CORRECTED FOR E1, and this is not a relaxation. The pre-E1 test used
    # (t_resp_release - t_ack_release) > 0, but reg_ts_resp_release is written on the
    # DEQUEUED ROLE_RESP path — and under E1 a late RESPONSE is never queued at all: it
    # finds the transaction already retired and takes the normal forwarding path. So
    # that timestamp is CORRECTLY absent, and asserting on it would be asserting that
    # the old behaviour still happens.
    # The property still has to be proved, so it is proved from what E1 leaves behind:
    # RESP_BYPASS == 1 means txn_active read ZERO when the RESPONSE arrived, and under
    # E1 the only thing that clears the tag while an ACK is in flight is the ACK's own
    # commitment. Together with B-07 (the ACK release retired) and the offline
    # ipg > D + drain check, that pins the ordering.
    add("B-06", "the RESPONSE arrived AFTER the ACK committed (bypass proves the tag "
                "was already retired)",
        None if (_cf(rec, "RESP_BYPASS") is None
                 or tr["ack_commitment_ns"] is None)
        else (_cf(rec, "RESP_BYPASS") == 1
              and (_cd(rec, "ACK_REL_RETIRE") or 0) == 1),
        "RESP_BYPASS=%s, ACK committed at %s, CD_ACK_REL_RETIRE=%s. A queued-response "
        "release timestamp is CORRECTLY absent (%s): under E1 a late RESPONSE is never "
        "enqueued."
        % (_cf(rec, "RESP_BYPASS"), tr["ack_commitment_ns"],
           _cd(rec, "ACK_REL_RETIRE"), tr["response_commitment_ns"]))
    add("B-08", "the late RESPONSE did not alter the retired generation",
        None if _reg(rec, "reg_tag") is None
        else _reg(rec, "reg_tag") == TAG_INACTIVE,
        "reg_tag after = 0x%02X" % (_reg(rec, "reg_tag") or 0,))
    return res, tr, None, [], {}


def score_case_C(rec):
    """MISSING RESPONSE. READ and ACK only."""
    res = []
    tr = score_common(rec, "C", res)

    def add(rid, text, ok, detail):
        res.append((rid, text, ("INDETERMINATE" if ok is None
                                else "PASS" if ok else "FAIL"), detail))

    d_ns = G2._get(rec, "params", "d_realized_ns")
    add("C-01", "ACK still releases at the configured deadline",
        None if None in (tr["hold_ns"], d_ns)
        else abs(tr["hold_minus_D_plus_tau_ns"]) <= G2.TOL_NS_DEFAULT,
        "hold=%s ns, D=%s ns, corrected error=%s ns"
        % (tr["hold_ns"], d_ns,
           None if tr["hold_minus_D_plus_tau_ns"] is None
           else round(tr["hold_minus_D_plus_tau_ns"], 1)))
    k = G2._get(rec, "params", "k", default=64)
    add("C-02", "no indefinite blocker circulation",
        None if _cd(rec, "BLOCK_TERM_DL") is None
        else (_cd(rec, "BLOCK_TERM_DL") == k
              and (_cf(rec, "PKTGEN_ADMIT") ==
                   (_cd(rec, "BLOCK_TERM_DL") + (_cd(rec, "BLOCK_TERM_STALE") or 0)
                    + (_cd(rec, "BLOCK_TERM_TMO") or 0)))),
        "admitted=%s terminated on deadline=%s stale=%s budget=%s"
        % (_cf(rec, "PKTGEN_ADMIT"), _cd(rec, "BLOCK_TERM_DL"),
           _cd(rec, "BLOCK_TERM_STALE"), _cd(rec, "BLOCK_TERM_TMO")))
    add("C-03", "no RESPONSE was generated or forwarded",
        None if _cf(rec, "RESP_HOLD_EARLY") is None
        else ((_cf(rec, "RESP_HOLD_EARLY") or 0)
              + (_cf(rec, "RESP_HOLD_LATE") or 0)
              + (_cf(rec, "RESP_BYPASS") or 0) == 0),
        "EARLY=%s LATE=%s BYPASS=%s"
        % (_cf(rec, "RESP_HOLD_EARLY"), _cf(rec, "RESP_HOLD_LATE"),
           _cf(rec, "RESP_BYPASS")))
    # ►► THE ONE THAT MATTERS. On the data path only the released RESPONSE and the
    # fail-open budget retire a generation, so with neither the transaction can only
    # be retired by something else. This scores what actually happened.
    add("C-05", "the ACK COMMITMENT retired the transaction (E1's repair)",
        None if _cd(rec, "ACK_REL_RETIRE") is None
        else (_cd(rec, "ACK_REL_RETIRE") == 1
              and (_cd(rec, "ACK_RELEASE") or 0) == 0),
        "CD_ACK_REL_RETIRE=%s (want 1: nothing pending, so the ACK retired) "
        "CD_ACK_RELEASE=%s (want 0)"
        % (_cd(rec, "ACK_REL_RETIRE"), _cd(rec, "ACK_RELEASE")))
    add("C-06", "no pending marker remains",
        None if _reg(rec, "reg_tag") is None
        else not (0x10 <= _reg(rec, "reg_tag") <= 0x1F),
        "reg_tag after = 0x%02X; 0x10..0x1F would mean a RESPONSE is still recorded "
        "as pending" % (_reg(rec, "reg_tag") or 0,))
    add("C-04", "the transaction RETIRED (reg_tag inactive)",
        None if _reg(rec, "reg_tag") is None
        else _reg(rec, "reg_tag") == TAG_INACTIVE,
        "reg_tag after the trial = 0x%02X (want 0x%02X). Before E1 neither retire "
        "path fired here: there is no RESPONSE, and the deadline pre-empts the "
        "fail-open budget."
        % (_reg(rec, "reg_tag") or 0, TAG_INACTIVE))
    return res, tr, None, [], {}


def score_case_D(rec):
    """DUPLICATE EARLY RESPONSE. Two RESPONSEs inside D; only the first may mark."""
    res = []
    tr = score_common(rec, "D", res)

    def add(rid, text, ok, detail):
        res.append((rid, text, ("INDETERMINATE" if ok is None
                                else "PASS" if ok else "FAIL"), detail))

    add("D-01", "only the FIRST RESPONSE was held and marked the tag",
        None if _cf(rec, "RESP_HOLD_EARLY") is None
        else _cf(rec, "RESP_HOLD_EARLY") == 1,
        "RESP_HOLD_EARLY=%s (want exactly 1)" % (_cf(rec, "RESP_HOLD_EARLY"),))
    add("D-02", "the SECOND RESPONSE was SUPPRESSED, not forwarded",
        None if _cf(rec, "RESP_DUP_SUPP") is None
        else (_cf(rec, "RESP_DUP_SUPP") == 1
              and (_cf(rec, "RESP_BYPASS") or 0) == 0
              and (_cf(rec, "RESP_HOLD_LATE") or 0) == 0),
        "RESP_DUP_SUPP=%s (want 1) RESP_BYPASS=%s (want 0: forwarding it let it "
        "OVERTAKE the held ACK by a measured 1.0014 ms) RESP_HOLD_LATE=%s (want 0)"
        % (_cf(rec, "RESP_DUP_SUPP"), _cf(rec, "RESP_BYPASS"),
           _cf(rec, "RESP_HOLD_LATE")))
    # ►► THE ORDERING INVARIANT, measured rather than assumed. reg_ts_resp_bypass is
    # write-if-zero on the fresh-RESPONSE bypass arm, so a NON-ZERO value means some
    # RESPONSE copy was forwarded straight out — and that copy commits immediately,
    # while the ACK is still held.
    tb = _ts(rec, "reg_ts_resp_bypass")
    add("D-06", "NO RESPONSE copy commits before the ACK",
        None if tr["ack_commitment_ns"] is None
        else (tb is None or dt(tr["ack_commitment_ns"], tb) > 0),
        "bypass-commit timestamp %s, ACK commitment %s -> %s"
        % (tb, tr["ack_commitment_ns"],
           "no copy was forwarded early" if tb is None
           else "%s ns relative to the ACK" % dt(tr["ack_commitment_ns"], tb)))
    add("D-03", "the marker was NOT applied a second time",
        None if _cd(rec, "ACK_RELEASE") is None
        else (_cd(rec, "ACK_RELEASE") == 1
              and (_cd(rec, "ACK_REL_RETIRE") or 0) == 0),
        "CD_ACK_RELEASE=%s CD_ACK_REL_RETIRE=%s — the ACK saw the tag in the PENDING "
        "domain exactly once. A double marker would have pushed it out of 0x10..0x1F "
        "and the ACK would have retired instead."
        % (_cd(rec, "ACK_RELEASE"), _cd(rec, "ACK_REL_RETIRE")))
    add("D-04", "no tag value outside the defined domains was produced",
        None if _reg(rec, "reg_tag") is None
        else _reg(rec, "reg_tag") in ([TAG_INACTIVE] + list(range(0xC0, 0xD0))
                                      + list(range(0x10, 0x20))),
        "reg_tag after = 0x%02X" % (_reg(rec, "reg_tag") or 0,))
    add("D-05", "no duplicate could retire or corrupt the generation",
        None if _reg(rec, "reg_tag") is None
        else _reg(rec, "reg_tag") == TAG_INACTIVE,
        "reg_tag after = 0x%02X (the queued RESPONSE's release retired it)"
        % (_reg(rec, "reg_tag") or 0,))
    return res, tr, None, [], {}


def score_case_E(rec):
    """STALE RESPONSE against an idle transaction: no READ, no ACK, no blockers.
    Deliberately does NOT use score_common — there is no transaction to score."""
    res = []
    tr = per_txn_trace(rec)

    def add(rid, text, ok, detail):
        res.append((rid, text, ("INDETERMINATE" if ok is None
                                else "PASS" if ok else "FAIL"), detail))

    ps = G2._get(rec, "pre_state", default={}) or {}
    add("E-01", "the stale RESPONSE was BYPASSED, not held",
        None if _cf(rec, "RESP_BYPASS") is None
        else (_cf(rec, "RESP_BYPASS") == 1
              and (_cf(rec, "RESP_HOLD_EARLY") or 0) == 0
              and (_cf(rec, "RESP_HOLD_LATE") or 0) == 0),
        "RESP_BYPASS=%s EARLY=%s LATE=%s"
        % (_cf(rec, "RESP_BYPASS"), _cf(rec, "RESP_HOLD_EARLY"),
           _cf(rec, "RESP_HOLD_LATE")))
    add("E-02", "reg_tag UNCHANGED",
        None if _reg(rec, "reg_tag") is None or ps.get("reg_tag") is None
        else _reg(rec, "reg_tag") == ps.get("reg_tag"),
        "before 0x%02X -> after 0x%02X"
        % (ps.get("reg_tag") or 0, _reg(rec, "reg_tag") or 0))
    add("E-03", "the deadline UNCHANGED",
        None if _reg(rec, "reg_deadline") is None
        else _reg(rec, "reg_deadline") == (ps.get("reg_deadline") or 0),
        "before %s -> after %s"
        % (ps.get("reg_deadline"), _reg(rec, "reg_deadline")))
    add("E-04", "no blockers involved",
        None if _cf(rec, "PKTGEN_ADMIT") is None
        else ((_cf(rec, "PKTGEN_ADMIT") or 0) == 0
              and (_cd(rec, "BLOCK_LOOP") or 0) == 0),
        "PKTGEN_ADMIT=%s BLOCK_LOOP=%s"
        % (_cf(rec, "PKTGEN_ADMIT"), _cd(rec, "BLOCK_LOOP")))
    add("E-05", "nothing armed and nothing was held",
        None if _cf(rec, "ARM_FRESH") is None
        else ((_cf(rec, "ARM_FRESH") or 0) == 0
              and (_cf(rec, "ACK_HOLD") or 0) == 0),
        "ARM_FRESH=%s ACK_HOLD=%s" % (_cf(rec, "ARM_FRESH"), _cf(rec, "ACK_HOLD")))
    return res, tr, None, [], {}


def score_case_F(rec):
    """STALE RESPONSE DURING A NEW ACTIVE TRANSACTION. N+1 must be untouched, and the
    transaction itself must still complete normally — so it keeps every normal
    requirement AND adds the isolation ones."""
    # score_common, NOT score_normal. A normal transaction requires RESP_BYPASS == 0
    # (T-12) and the Gate-2 rubric requires the same (G-04); this case has a
    # LEGITIMATE extra bypass — the foreign copy — so those two would fail on the
    # thing the case exists to produce. Everything else a normal transaction must do
    # is still required, and F-01..F-05 add the isolation properties.
    res = []
    tr = score_common(rec, "F", res)
    g2v, g2res, g2d = None, [], {}

    def add(rid, text, ok, detail):
        res.append((rid, text, ("INDETERMINATE" if ok is None
                                else "PASS" if ok else "FAIL"), detail))

    add("F-06", "N+1's OWN RESPONSE was still held, and released after the ACK",
        None if tr["ack_to_response_separation_ns"] is None
        else tr["ack_to_response_separation_ns"] > 0,
        "queued RESPONSE released %s ns after the ACK (must be > 0)"
        % (tr["ack_to_response_separation_ns"],))
    add("F-07", "N+1 retired cleanly",
        None if _reg(rec, "reg_tag") is None
        else _reg(rec, "reg_tag") == TAG_INACTIVE,
        "reg_tag after = 0x%02X" % (_reg(rec, "reg_tag") or 0,))
    add("F-01", "the stale RESPONSE was BYPASSED, not held as N+1's RESPONSE",
        None if _cf(rec, "RESP_BYPASS") is None
        else (_cf(rec, "RESP_BYPASS") == 1
              and _cf(rec, "RESP_HOLD_EARLY") == 1),
        "RESP_BYPASS=%s (want 1: the stale copy) RESP_HOLD_EARLY=%s (want 1: N+1's OWN "
        "RESPONSE was still held normally)"
        % (_cf(rec, "RESP_BYPASS"), _cf(rec, "RESP_HOLD_EARLY")))
    add("F-02", "the stale RESPONSE was NOT suppressed as a duplicate",
        None if _cf(rec, "RESP_DUP_SUPP") is None
        else _cf(rec, "RESP_DUP_SUPP") == 0,
        "RESP_DUP_SUPP=%s (want 0: it is a DIFFERENT identity, so it must take the "
        "bypass path, not the suppression path)" % (_cf(rec, "RESP_DUP_SUPP"),))
    add("F-03", "N+1's blocker counts unchanged (64 admitted, all deadline-terminated)",
        None if _cf(rec, "PKTGEN_ADMIT") is None
        else (_cf(rec, "PKTGEN_ADMIT") == 64
              and _cd(rec, "BLOCK_TERM_DL") == 64
              and (_cd(rec, "BLOCK_TERM_STALE") or 0) == 0),
        "admitted=%s DL=%s STALE=%s"
        % (_cf(rec, "PKTGEN_ADMIT"), _cd(rec, "BLOCK_TERM_DL"),
           _cd(rec, "BLOCK_TERM_STALE")))
    add("F-04", "the stale RESPONSE could not retire N+1 (its ACK was still held for D)",
        None if tr["hold_ns"] is None
        else abs(tr["hold_minus_D_plus_tau_ns"]) <= G2.TOL_NS_DEFAULT,
        "hold=%s ns, corrected error=%s ns — a premature retirement would have "
        "collapsed the hold"
        % (tr["hold_ns"],
           None if tr["hold_minus_D_plus_tau_ns"] is None
           else round(tr["hold_minus_D_plus_tau_ns"], 1)))
    add("F-05", "N+1's pending marker survived: the ACK did NOT retire",
        None if _cd(rec, "ACK_RELEASE") is None
        else (_cd(rec, "ACK_RELEASE") == 1
              and (_cd(rec, "ACK_REL_RETIRE") or 0) == 0),
        "CD_ACK_RELEASE=%s CD_ACK_REL_RETIRE=%s — the ACK found the tag in the PENDING "
        "domain. NOTE: this shows only that SOME response marked it, NOT which one; "
        "F-08/F-09 are what identify the two copies"
        % (_cd(rec, "ACK_RELEASE"), _cd(rec, "ACK_REL_RETIRE")))

    # ---- F-08/F-09: the two checks whose ABSENCE made the 2026-07-29 run
    # unscorable. F-05 above was the whole of the old isolation argument, and it is
    # an inference that cannot distinguish the two RESPONSES: the marker being set
    # proves only that one of them set it. These two identify them.
    pg = (rec.get("pktgen_after") or {}).get("app_event3")
    add("F-08", "the stale injector (app 4) actually fired, exactly once",
        None if not isinstance(pg, dict) or pg.get("pkt_counter") is None
        else (pg.get("trigger_counter") == 1 and pg.get("pkt_counter") == 1),
        ("app_event3 not read back — the case cannot be scored"
         if not isinstance(pg, dict) or pg.get("pkt_counter") is None
         else "app_event3 trigger=%s batch=%s pkt=%s (want 1/1/1)"
              % (pg.get("trigger_counter"), pg.get("batch_counter"),
                 pg.get("pkt_counter"))))

    cfg = rec.get("config") or {}
    def _timer(k):
        d = cfg.get(k) or {}
        return d.get("timer_ns_requested")
    t_read, t_stale = _timer("app_event"), _timer("app_event3")
    ts_read = _reg(rec, "reg_ts_read")
    ts_byp = _reg(rec, "reg_ts_resp_bypass")
    want = None if (t_read is None or t_stale is None) else (t_stale - t_read)
    got = None if (ts_read in (None, 0) or ts_byp in (None, 0)) else (ts_byp - ts_read)
    # 60 us: far tighter than the 200 us discrepancy that invalidated the old run,
    # far looser than the ~10 ns reproducibility of the generator's own timers.
    add("F-09", "the packet that BYPASSED is the stale copy, by its arrival time",
        None if (want is None or got is None) else abs(got - want) <= 60000,
        ("no bypass timestamp recorded" if got is None else
         "bypass at READ+%d ns; the stale injector is scheduled at READ+%d ns and "
         "N+1's own RESPONSE at READ+%s ns. A bypass at the OWN-RESPONSE offset means "
         "the legitimate copy was the one forwarded, i.e. the test is inverted"
         % (got, want,
            None if _timer("app_event2") is None else
            (_timer("app_event2") - t_read
             + ((cfg.get("app_event2") or {}).get("ipg_ns_readback") or 0)))))
    return res, tr, g2v, g2res, g2d


def _verdict(res):
    if any(st == "FAIL" for _i, _t, st, _d in res):
        return "FAIL"
    if any(st == "INDETERMINATE" for _i, _t, st, _d in res):
        return "INDETERMINATE"
    return "PASS"


TRACE_FIELDS = (
    ("read_ingress_ns", "READ ingress"),
    ("reservoir_standing_ns", "reservoir standing (READ->full K)"),
    ("ack_ingress_ns", "ACK ingress"),
    ("configured_deadline", "configured deadline"),
    ("first_blocker_termination_ns", "first blocker termination"),
    ("final_blocker_termination_ns", "final blocker termination"),
    ("ack_commitment_ns", "ACK commitment"),
    ("response_commitment_ns", "RESPONSE commitment"),
    ("hold_ns", "hold duration"),
    ("detection_error_ns", "detection error"),
    ("drain_ns", "drain duration"),
    ("release_tail_ns", "release tail"),
    ("ack_to_response_separation_ns", "ACK->RESPONSE separation"),
)


def _fmt_trace(tr):
    out = []
    for key, label in TRACE_FIELDS:
        v = tr.get(key)
        out.append("    %-36s %s" % (label, "n/a" if v is None else v))
    return out


def render_gate3(rec, L):
    g3 = rec["gate3"]
    L.append("=" * 78)
    L.append("§13 GATE 3 — %d CONSECUTIVE NORMAL TRANSACTIONS, no P4 reload"
             % g3["n_requested"])
    L.append("=" * 78)
    L.append("scenario %s  ipg %s ns  D %s ms  generations %s"
             % (g3["scenario"], g3["ipg_ns"], g3["d_ms"],
                ["0x%02X" % g for g in g3["generations"]]))
    L.append("transaction state (reg_tag / reg_deadline / reg_ack_rel) is NEVER "
             "written between transactions")
    L.append("")
    allpass = True
    traces = []
    for t in g3["transactions"]:
        res, tr, g2v, g2res, _d = score_normal(t)
        v = _verdict(res)
        g2fail = [r.rid for r in g2res if r.status == "FAIL"] if g2res else []
        ok = (v == "PASS" and g2v == "PASS")
        allpass = allpass and ok
        traces.append(tr)
        L.append("-" * 78)
        L.append("TRANSACTION %s  gen 0x%02X  ->  %s   (Gate-2 rubric: %s%s)"
                 % (t.get("txn_index"), t.get("generation") or 0,
                    v, g2v, ("  FAILED: " + ",".join(g2fail)) if g2fail else ""))
        for rid, text, st, detail in res:
            if st != "PASS":
                L.append("  %-6s %-6s %s" % (st, rid, text))
                L.append("           %s" % detail)
        L.append("  requirements: %d PASS, %d FAIL, %d INDETERMINATE"
                 % (sum(1 for r in res if r[2] == "PASS"),
                    sum(1 for r in res if r[2] == "FAIL"),
                    sum(1 for r in res if r[2] == "INDETERMINATE")))
        L.extend(_fmt_trace(tr))
    L.append("-" * 78)
    if len(g3["transactions"]) < g3["n_requested"]:
        allpass = False
        L.append("STOPPED after %d of %d: %s"
                 % (len(g3["transactions"]), g3["n_requested"],
                    g3.get("stop_reason", "?")))
    # stability across the five, which is the thing five transactions add
    for key, label in (("hold_ns", "hold"), ("drain_ns", "drain"),
                       ("release_tail_ns", "release tail"),
                       ("reservoir_standing_ns", "reservoir standing"),
                       ("read_to_ack_ns", "READ->ACK")):
        vals = [t[key] for t in traces if t.get(key) is not None]
        if vals:
            L.append("  %-22s n=%d  min %d  max %d  spread %d ns"
                     % (label, len(vals), min(vals), max(vals),
                        max(vals) - min(vals)))
    L.append("")
    L.append("GATE 3 VERDICT: %s" % ("PASS" if allpass else "FAIL"))
    return allpass


CASE_SCORERS = {"A_response_just_before_deadline": score_case_A,
                "B_response_after_ack_release": score_case_B,
                "C_missing_response": score_case_C,
                "D_duplicate_early_response": score_case_D,
                "E_stale_response": score_case_E,
                "F_stale_during_active_txn": score_case_F}


def render_gate4(rec, L):
    g4 = rec["gate4"]
    L.append("=" * 78)
    L.append("§13 GATE 4 — THREE BOUNDARY CASES x %d, then a recovery transaction"
             % g4["reps"])
    L.append("=" * 78)
    L.append("D realized = %s ns" % g4["d_realized_ns"])
    allpass = True
    for case in g4["cases"]:
        L.append("")
        L.append("#" * 78)
        L.append("CASE %s   ipg %s ns   %s"
                 % (case["case"], case["ipg_ns"], case["why"]))
        if case.get("reset_state"):
            L.append("  (each repetition gets a control-plane state reset so it is "
                     "an INDEPENDENT observation; the recovery transaction does not)")
        scorer = CASE_SCORERS[case["case"]]
        for t in case["transactions"]:
            # case C interleaves an IMMEDIATE RECOVERY transaction after each
            # repetition; those are NORMAL transactions and are scored as such.
            sc_use = (score_normal if "IMMEDIATE RECOVERY" in (t.get("label") or "")
                      else scorer)
            res, tr, g2v, g2res, _d = sc_use(t)
            v = _verdict(res)
            ok = (v == "PASS") and (g2v in (None, "PASS"))
            allpass = allpass and ok
            L.append("-" * 78)
            L.append("  rep %s  gen 0x%02X  ->  %s%s"
                     % (t.get("txn_index"), t.get("generation") or 0, v,
                        "" if g2v is None else "   (Gate-2 rubric: %s)" % g2v))
            for rid, text, st, detail in res:
                if st != "PASS":
                    L.append("    %-6s %-6s %s" % (st, rid, text))
                    L.append("             %s" % detail)
            L.extend(_fmt_trace(tr))
    recs = [("RECOVERY 1 — one NORMAL transaction, NO state reset before it",
             g4.get("recovery"), True),
            ("RECOVERY 2 — a SECOND normal transaction, still no state reset",
             g4.get("recovery2"), False)]
    for title, rc, counts_toward_verdict in recs:
        if not rc:
            continue
        L.append("")
        L.append("#" * 78)
        L.append(title)
        res, tr, g2v, g2res, _d = score_normal(rc)
        v = _verdict(res)
        g2fail = [r.rid for r in g2res if r.status == "FAIL"] if g2res else []
        ok = (v == "PASS" and g2v == "PASS")
        if counts_toward_verdict:
            allpass = allpass and ok
        else:
            L.append("  (diagnostic: measures HOW MANY transactions a lost RESPONSE "
                     "costs; not part of the Gate 4 verdict)")
        L.append("  verdict %s   (Gate-2 rubric: %s%s)"
                 % (v, g2v, ("  FAILED: " + ",".join(g2fail)) if g2fail else ""))
        for rid, text, st, detail in res:
            if st != "PASS":
                L.append("    %-6s %-6s %s" % (st, rid, text))
                L.append("             %s" % detail)
        L.extend(_fmt_trace(tr))
    L.append("")
    L.append("GATE 4 VERDICT: %s" % ("PASS" if allpass else "FAIL"))
    return allpass


def self_test():
    """Controls: the scorers must be able to FAIL, and specifically must catch the
    three things the direction lists as stop conditions."""
    def txn(**over):
        base = {
            "txn_index": 1, "generation": 0xC0,
            "pre_state": {"reg_tag": 0x00, "reg_deadline": 0,
                          "reg_ack_rel": 0xBF},
            "verdict": "COMPLETE",
            "params": {"d_realized_ns": 1999872, "k": 64,
                       "rate_dp8_pps": 37.4e6, "ipg_ns": 500000},
            "registers": {"reg_tag": 0x00, "reg_deadline": 1288574721,
                          "reg_ts_read": 1286074000,
                          "reg_ts_last_block": 1286075195,
                          "reg_ts_ack_arm": 1286574958,
                          "reg_ts_block_term": 1288574744,
                          "reg_ts_last_term": 1288576436,
                          "reg_ts_ack_release": 1288576463,
                          "reg_ts_resp_release": 1288576491},
            "counters": {"fresh": {"ARM_FRESH": 1, "ARM_DUP": 0, "ARM_BUSY": 0,
                                   "PKTGEN_ADMIT": 64, "PKTGEN_DROP": 0,
                                   "ACK_HOLD": 1, "ACK_DUP_HOLD": 0,
                                   "ACK_REJECT": 0, "RESP_HOLD_EARLY": 1,
                                   "RESP_HOLD_LATE": 0, "RESP_BYPASS": 0,
                                   "BAD_PORT": 0, "CLONE_SEEN": 1},
                         "deq": {"BLOCK_TERM_STALE": 0, "BLOCK_TERM_DL": 64,
                                 "BLOCK_TERM_TMO": 0, "RELEASE_DEADLINE": 1,
                                 "RELEASE_FAILOPEN": 0, "ACK_RELEASE": 1}},
            "pktgen_after": {"app_block_pipe0": {"trigger_counter": 1,
                                                 "batch_counter": 1,
                                                 "pkt_counter": 64}},
        }
        for k, v in over.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                for k2, v2 in v.items():
                    if isinstance(v2, dict) and isinstance(base[k].get(k2), dict):
                        base[k][k2].update(v2)
                    else:
                        base[k][k2] = v2
            else:
                base[k] = v
        return base

    cases = [
        ("nominal normal transaction", txn(), "PASS"),
        ("ACK released BEFORE the deadline",
         txn(registers={"reg_ts_ack_release": 1286574958 + 1000}), "FAIL"),
        ("RESPONSE committed BEFORE the ACK",
         txn(registers={"reg_ts_resp_release": 1288576400}), "FAIL"),
        ("second transaction inherited a LIVE generation",
         txn(pre_state={"reg_tag": 0xC0, "reg_deadline": 0, "reg_ack_rel": 0xBF}),
         "FAIL"),
        ("inherited reg_ack_rel COLLIDES with this generation",
         txn(pre_state={"reg_tag": 0x00, "reg_deadline": 0, "reg_ack_rel": 0xC0}),
         "FAIL"),
        ("the ARM did not supersede the inherited deadline",
         txn(pre_state={"reg_tag": 0x00, "reg_deadline": 1288574721,
                        "reg_ack_rel": 0xBF}), "FAIL"),
        ("a benign inherited deadline + previous generation is CLEAN",
         txn(pre_state={"reg_tag": 0x00, "reg_deadline": 652185089,
                        "reg_ack_rel": 0xBF}), "PASS"),
        ("63 blockers admitted",
         txn(counters={"fresh": {"PKTGEN_ADMIT": 63}}), "FAIL"),
        ("65 blockers admitted",
         txn(counters={"fresh": {"PKTGEN_ADMIT": 65}}), "FAIL"),
        ("fail-open fired",
         txn(counters={"deq": {"BLOCK_TERM_TMO": 64, "BLOCK_TERM_DL": 0}}),
         "FAIL"),
        ("transaction did not retire",
         txn(registers={"reg_tag": 0xC0}), "FAIL"),
        ("two pktgen triggers",
         txn(pktgen_after={"app_block_pipe0": {"trigger_counter": 2}}), "FAIL"),
        ("reservoir stood AFTER the ACK arrived",
         txn(registers={"reg_ts_last_block": 1286574958 + 5000}), "FAIL"),
        ("generation is the inactive marker",
         txn(generation=0x00), "FAIL"),
    ]
    bad = 0
    print("=" * 74)
    for label, rec, want in cases:
        res, _tr, _g2v, _g2r, _d = score_normal(rec)
        got = _verdict(res)
        ok = got == want
        bad += 0 if ok else 1
        print("%-6s %-48s %s" % ("PASS" if ok else "FAIL", label,
                                 got if ok else "%s (want %s)" % (got, want)))
    # case B must REQUIRE a late response, and reject an early one
    # E1: a late RESPONSE now BYPASSES and the ACK release retires.
    b_ok = _verdict(score_case_B(txn(
        counters={"fresh": {"RESP_HOLD_EARLY": 0, "RESP_HOLD_LATE": 0,
                            "RESP_BYPASS": 1},
                  "deq": {"ACK_RELEASE": 0, "ACK_REL_RETIRE": 1}},
        registers={"reg_ts_resp_release": 0}))[0])   # never queued, so never written
    b_bad = _verdict(score_case_B(txn())[0])          # early response
    b_heldlate = _verdict(score_case_B(txn(
        counters={"fresh": {"RESP_HOLD_EARLY": 0, "RESP_HOLD_LATE": 1},
                  "deq": {"ACK_RELEASE": 0, "ACK_REL_RETIRE": 1}}))[0])
    for label, got, want in (("case B accepts a LATE response (bypass)", b_ok, "PASS"),
                             ("case B REJECTS an early response", b_bad, "FAIL"),
                             ("case B REJECTS the pre-E1 held-late classification",
                              b_heldlate, "FAIL")):
        ok = got == want
        bad += 0 if ok else 1
        print("%-6s %-48s %s" % ("PASS" if ok else "FAIL", label, got))
    # case C must fail when the generation is left live
    c_live = _verdict(score_case_C(txn(
        registers={"reg_tag": 0xC0, "reg_ts_resp_release": 0},
        counters={"fresh": {"RESP_HOLD_EARLY": 0},
                  "deq": {"ACK_RELEASE": 1, "ACK_REL_RETIRE": 0}}))[0])
    c_ok = _verdict(score_case_C(txn(
        registers={"reg_tag": 0x00, "reg_ts_resp_release": 0},
        counters={"fresh": {"RESP_HOLD_EARLY": 0},
                  "deq": {"ACK_RELEASE": 0, "ACK_REL_RETIRE": 1}}))[0])
    c_pend = _verdict(score_case_C(txn(
        registers={"reg_tag": 0x10, "reg_ts_resp_release": 0},
        counters={"fresh": {"RESP_HOLD_EARLY": 0},
                  "deq": {"ACK_RELEASE": 0, "ACK_REL_RETIRE": 1}}))[0])
    for label, got, want in (
            ("case C FAILS when the generation stays live", c_live, "FAIL"),
            ("case C PASSES when the ACK retires (E1)", c_ok, "PASS"),
            ("case C FAILS when a pending marker is left behind", c_pend, "FAIL")):
        ok = got == want
        bad += 0 if ok else 1
        print("%-6s %-48s %s" % ("PASS" if ok else "FAIL", label, got))
    print("-" * 74)
    print("SELF-TEST: %d control(s), %d bad" % (len(cases) + 6, bad))
    return 1 if bad else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="*")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--json-out", default=None)
    a = ap.parse_args(argv if argv is not None else sys.argv[1:])
    if a.self_test:
        return self_test()
    if not a.files:
        print("no input", file=sys.stderr)
        return 2
    rc = 0
    payload = []
    for p in a.files:
        try:
            rec = json.load(open(p))
        except Exception as e:                                    # noqa: BLE001
            print("%s: unreadable (%s)" % (p, e), file=sys.stderr)
            rc = 1
            continue
        L = []
        if rec.get("gate3"):
            ok = render_gate3(rec, L)
        elif rec.get("gate4"):
            ok = render_gate4(rec, L)
        else:
            print("%s: no gate3/gate4 payload" % p, file=sys.stderr)
            rc = 2
            continue
        print("\n".join(L))
        payload.append({"file": p, "pass": bool(ok)})
        if not ok:
            rc = 1
    if a.json_out and payload:
        with open(a.json_out, "w") as fh:
            json.dump({"schema": "d3_gate34/1", "results": payload}, fh, indent=2,
                      default=str)
    return rc


if __name__ == "__main__":
    sys.exit(main())
