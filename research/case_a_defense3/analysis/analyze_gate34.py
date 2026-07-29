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
    add("B-02", "RESPONSE is NOT treated as an early queued response",
        None if _cf(rec, "RESP_HOLD_EARLY") is None
        else (_cf(rec, "RESP_HOLD_EARLY") == 0
              and _cf(rec, "RESP_HOLD_LATE") == 1),
        "RESP_HOLD_EARLY=%s (must be 0) RESP_HOLD_LATE=%s (must be 1)"
        % (_cf(rec, "RESP_HOLD_EARLY"), _cf(rec, "RESP_HOLD_LATE")))
    add("B-03", "RESPONSE forwarded EXACTLY ONCE",
        None if _cf(rec, "RESP_HOLD_LATE") is None
        else (_cf(rec, "RESP_HOLD_LATE") + (_cf(rec, "RESP_BYPASS") or 0) == 1
              and tr["response_commitment_ns"] is not None),
        "RESP_HOLD_LATE=%s RESP_BYPASS=%s, commitment timestamp %s"
        % (_cf(rec, "RESP_HOLD_LATE"), _cf(rec, "RESP_BYPASS"),
           tr["response_commitment_ns"]))
    add("B-04", "no RE-HOLD (the deadline is not armed a second time)",
        None if _cf(rec, "ACK_DUP_HOLD") is None
        else (_cf(rec, "ACK_DUP_HOLD") == 0 and _cf(rec, "ACK_HOLD") == 1),
        "ACK_HOLD=%s ACK_DUP_HOLD=%s"
        % (_cf(rec, "ACK_HOLD"), _cf(rec, "ACK_DUP_HOLD")))
    add("B-05", "clean retirement",
        None if _reg(rec, "reg_tag") is None
        else _reg(rec, "reg_tag") == TAG_INACTIVE,
        "reg_tag after = 0x%02X" % (_reg(rec, "reg_tag") or 0,))
    add("B-06", "the RESPONSE really did arrive after the ACK committed",
        None if tr["ack_to_response_separation_ns"] is None
        else tr["ack_to_response_separation_ns"] > 0,
        "ACK -> RESPONSE = %s ns" % (tr["ack_to_response_separation_ns"],))
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
    add("C-04", "a watchdog or bounded cleanup retired the transaction",
        None if _reg(rec, "reg_tag") is None
        else _reg(rec, "reg_tag") == TAG_INACTIVE,
        "reg_tag after the trial = 0x%02X (want 0x%02X). The data path retires a "
        "generation on the released RESPONSE or on the fail-open budget; with no "
        "RESPONSE and a deadline release, NEITHER fires."
        % (_reg(rec, "reg_tag") or 0, TAG_INACTIVE))
    return res, tr, None, [], {}


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
                "C_missing_response": score_case_C}


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
            res, tr, g2v, g2res, _d = scorer(t)
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
    b_ok = _verdict(score_case_B(txn(
        counters={"fresh": {"RESP_HOLD_EARLY": 0, "RESP_HOLD_LATE": 1}},
        registers={"reg_ts_resp_release": 1288576491}))[0])
    b_bad = _verdict(score_case_B(txn())[0])          # early response
    for label, got, want in (("case B accepts a LATE response", b_ok, "PASS"),
                             ("case B REJECTS an early response", b_bad, "FAIL")):
        ok = got == want
        bad += 0 if ok else 1
        print("%-6s %-48s %s" % ("PASS" if ok else "FAIL", label, got))
    # case C must fail when the generation is left live
    c_live = _verdict(score_case_C(txn(
        registers={"reg_tag": 0xC0, "reg_ts_resp_release": 0},
        counters={"fresh": {"RESP_HOLD_EARLY": 0}}))[0])
    ok = c_live == "FAIL"
    bad += 0 if ok else 1
    print("%-6s %-48s %s" % ("PASS" if ok else "FAIL",
                             "case C FAILS when the generation stays live", c_live))
    print("-" * 74)
    print("SELF-TEST: %d control(s), %d bad" % (len(cases) + 3, bad))
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
