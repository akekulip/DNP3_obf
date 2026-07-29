#!/usr/bin/env python3
# =============================================================================
#  analyze_case_a_dual_min.py — verdict engine for the MINIMAL SYNTHETIC
#  DUAL-RELEASE GATE.
#
#  Consumes the per-transaction JSON written by
#  setup/case_a_dual_min_setup.py --txn --out <file>, and decides:
#
#    INVALID  the transaction never established its preconditions — the
#             generator did not fire, the blocker counts are wrong, the TM
#             dropped something, tokens are still circulating, the cleanup did
#             not verify clean, or nothing ran at all. This is NOT an ordering
#             failure and must never be reported as one.
#    PASS     every deadline and ordering property holds, including the ones
#             DERIVED from this transaction's own scenario parameters.
#    FAIL     a property does not hold. Each FAIL names the stop condition it
#             corresponds to.
#
#  ---------------------------------------------------------------------------
#  THE EXPECTATION IS DERIVED FROM THE SCENARIO, NOT HARDCODED PER MODE
#
#  A scenario is only (ipg, event role map). The generator emits packet_id
#  0, 1, 2 at t_READ, t_READ + ipg, t_READ + 2*ipg, so the NOMINAL arrival of
#  the ACK and of the RESPONSE follow from the role map alone:
#
#      ack_arrival_nominal  = ipg * (1 if pid1 == ACK  else 2)
#      resp_arrival_nominal = ipg * (1 if pid1 == RESP else 2)
#
#  and the three regimes that matter follow from comparing those against A and
#  R rather than from the scenario's NAME:
#
#      ack_late         ack_arrival  > A   the ACK misses its own deadline
#      ack_after_dresp  ack_arrival  > R   the ACK misses the RESPONSE deadline
#                                          too, so the response blockers reach
#                                          their deadline with NOTHING committed
#      resp_late        resp_arrival > R
#
#  The last one is the whole point of the late-ack test: it is the only regime
#  in which the response blockers can be OBSERVED refusing to terminate on
#  their own deadline, because in that regime the generation-bound ACK
#  commitment is the ONLY thing still holding them. Change ipg and the
#  expectation moves with it; rename the scenario and nothing changes.
#
#  ---------------------------------------------------------------------------
#  32-BIT WRAP IS HANDLED, NOT ASSUMED AWAY
#
#  ingress_mac_tstamp[31:0] is nanoseconds and wraps every ~4.295 s, about
#  fourteen times a minute. A plain signed subtraction would silently fabricate
#  the headline number, and the ACK hold is measurable ONLY on chip — the relay
#  leg is untappable — so there is no second source to catch it. Every interval
#  here goes through delta32(), and the self-test pins the design's own case:
#      delta32(0xFFFFF000, 0x00001000) == 8192
#
#  ---------------------------------------------------------------------------
#  WHAT THE DEADLINE REGISTERS CONTAIN
#
#  reg_d_ack / reg_d_resp hold the deadline WORD: 24 bits of 256 ns ticks in
#  [31:8] with the ARMED marker in bit 0. So the deadline instant is
#  word & 0xFFFFFF00, and the anchoring arithmetic can be RECONSTRUCTED and
#  checked exactly:
#      d_word == ((t_READ & 0xFFFFFF00) | 1) + offset_word
#  That check is what proves the deadline was computed from t_READ on chip and
#  not from the ACK's or the RESPONSE's own arrival, which is the entire claim
#  of a READ-anchored release.
#
#  ---------------------------------------------------------------------------
#  SCOPE. This decides the DUAL-RELEASE MECHANISM on synthetic traffic. It says
#  nothing about DNP3, about the SEL-751, about reservoir depth, or about
#  whether four-level strict priority works — that last one is the CLOSED
#  four-queue dequeue oracle's result and is a precondition here, not an output.
#
#  Self-test:  python3 analyze_case_a_dual_min.py --self-test
#  Expectations for every scenario:
#              python3 analyze_case_a_dual_min.py --show-expectations
# =============================================================================
"""Verdict engine for the minimal synthetic dual-release gate."""
import argparse
import glob
import json
import os
import sys

WRAP = 1 << 32
HALF = 1 << 31

N_PER_CLASS = 64        # blockers of each class in the single 128-token batch
TICK_MASK = 0xFFFFFF00  # the deadline word's tick field
ARMED = 0x1             # the deadline word's armed marker, bit 0

ROLE_NAME = {0: "NONE", 1: "ABLOCK", 2: "ACK", 3: "RBLOCK", 4: "RESP", 5: "READ"}

# Tolerances, in nanoseconds.
#   TAIL_MAX   an upper bound on "the release happened as soon as the gate
#              opened". The measured IBSPG release tail is ~1.72 us; 200 us is
#              two orders above it and still two orders below A = 3 ms, so it
#              separates "released at the deadline" from "released at an event
#              milliseconds later" without pretending to a precision this
#              synthetic gate does not have.
#   SLACK      allowance when checking that a LATE arrival really did dominate
#              the deadline. Generous on purpose: it guards a direction, not a
#              magnitude.
TAIL_MAX_NS = 200000
SLACK_NS = 500000


def delta32(a, b):
    """Wrap-correct signed (b - a) on a 32-bit nanosecond counter.

    Positive means b is AFTER a. Results are correct while |b - a| < 2^31 ns
    (~2.147 s); every interval in this experiment is three orders inside that.
    """
    if a is None or b is None:
        return None
    d = (int(b) - int(a)) & 0xFFFFFFFF
    return d - WRAP if d >= HALF else d


def deadline_instant(word):
    """The deadline instant (ns) carried in a deadline word."""
    return None if word is None else (int(word) & TICK_MASK)


def reconstruct(t_read, offset_word):
    """The deadline word a READ at t_read with this offset MUST have produced.

    now_word = (t_read & TICK_MASK) | ARMED ; deadline = now_word + offset_word.
    The offset word's low byte is zero, which is what lets the ARMED marker
    survive the addition.
    """
    if t_read is None or offset_word is None:
        return None
    return (((int(t_read) & TICK_MASK) | ARMED) + int(offset_word)) & 0xFFFFFFFF


class Result(object):
    """PASS / FAIL / INVALID accumulator.

    INVALID is kept STRUCTURALLY separate from FAIL, not folded into it. A
    transaction whose generator never fired has no ordering opinion to offer,
    and reporting that as an ordering failure is how a harness bug gets written
    up as a mechanism result.
    """

    def __init__(self, name):
        self.name = name
        self.rows = []       # (kind, ok, check, detail)   kind: PRE | ORD
        self.notes = []

    def pre(self, ok, check, detail=""):
        self.rows.append(("PRE", bool(ok), check, str(detail)))

    def ord(self, ok, check, detail=""):
        self.rows.append(("ORD", bool(ok), check, str(detail)))

    def note(self, s):
        self.notes.append(str(s))

    def failures(self, kind=None):
        return [r for r in self.rows
                if not r[1] and (kind is None or r[0] == kind)]

    @property
    def verdict(self):
        if self.failures("PRE"):
            return "INVALID"
        return "FAIL" if self.failures("ORD") else "PASS"

    def render(self, verbose=True):
        w = max([len(r[2]) for r in self.rows] + [5])
        lines = ["", "%-8s  %-4s  %-*s  %s" % ("KIND", "RES", w, "CHECK", "DETAIL"),
                 "%-8s  %-4s  %-*s  %s" % ("-" * 8, "-" * 4, w, "-" * w, "-" * 40)]
        for kind, ok, check, detail in self.rows:
            if not verbose and ok:
                continue
            lines.append("%-8s  %-4s  %-*s  %s"
                         % (kind, "PASS" if ok else "FAIL", w, check, detail))
        for n in self.notes:
            lines.append("NOTE      %s" % n)
        lines.append("")
        lines.append("%s: %s  (%d precondition failure(s), %d ordering failure(s))"
                     % (self.name, self.verdict, len(self.failures("PRE")),
                        len(self.failures("ORD"))))
        return "\n".join(lines)


def scenario_regimes(ipg_ns, pid1, a_ns, r_ns):
    """The derived regime flags for one (ipg, role map, A, R).

    This is the whole per-scenario expectation. Nothing downstream branches on
    the scenario's NAME.
    """
    ack_k = 1 if pid1 == "ACK" else 2
    resp_k = 2 if pid1 == "ACK" else 1
    ack_arr = ipg_ns * ack_k
    resp_arr = ipg_ns * resp_k
    return {
        "ack_arrival_nominal_ns": ack_arr,
        "resp_arrival_nominal_ns": resp_arr,
        "ack_late": ack_arr > a_ns,
        "resp_late": resp_arr > r_ns,
        "ack_after_dresp": ack_arr > r_ns,
        "response_parked_before_ack": resp_arr < ack_arr,
    }


def analyze(t, name="txn"):
    """Score ONE transaction JSON. Returns (Result, derived metrics dict)."""
    r = Result(name)
    m = {}

    regs = t.get("registers") or {}
    ctrs = t.get("counters") or {}
    cons = t.get("conservation") or {}
    pg = t.get("pktgen") or {}
    guard = t.get("guard") or {}
    emap = t.get("event_map") or {}

    # =====================================================================
    # PRECONDITIONS. Everything that must have happened before an ordering
    # question is even meaningful.
    # =====================================================================
    if t.get("refused_dirty_start"):
        r.pre(False, "clean start", "the transaction REFUSED to start: %s"
              % str(t["refused_dirty_start"])[:120])
        return r, m

    r.pre(t.get("completed") is True, "transaction completed on chip",
          "completed=%s elapsed=%ss" % (t.get("completed"), t.get("elapsed_s")))

    blk = pg.get("blocker") or {}
    evt = pg.get("event") or {}
    r.pre(blk.get("trigger_counter") == 1,
          "the READ fired the blocker batch exactly once",
          "trigger_counter=%s (0 here with arm_fresh=1 would mean the mirror "
          "clone did not survive the READ's drop)" % blk.get("trigger_counter"))
    r.pre(blk.get("pkt_counter") == 128, "128 blocker tokens generated",
          "pkt_counter=%s" % blk.get("pkt_counter"))
    r.pre(evt.get("pkt_counter") == 3, "3 synthetic events generated",
          "pkt_counter=%s" % evt.get("pkt_counter"))

    r.pre(ctrs.get("arm_fresh") == 1, "exactly one fresh READ",
          "arm_fresh=%s arm_dup=%s" % (ctrs.get("arm_fresh"), ctrs.get("arm_dup")))
    r.pre(ctrs.get("admit_ablock") == N_PER_CLASS,
          "exactly %d ACK blockers admitted" % N_PER_CLASS,
          "admit_ablock=%s" % ctrs.get("admit_ablock"))
    r.pre(ctrs.get("admit_rblock") == N_PER_CLASS,
          "exactly %d response blockers admitted" % N_PER_CLASS,
          "admit_rblock=%s" % ctrs.get("admit_rblock"))
    r.pre(ctrs.get("ack_held") == 1, "exactly one ACK admitted",
          "ack_held=%s ack_notxn=%s" % (ctrs.get("ack_held"), ctrs.get("ack_notxn")))
    r.pre(ctrs.get("resp_held") == 1, "exactly one RESPONSE admitted",
          "resp_held=%s resp_notxn=%s"
          % (ctrs.get("resp_held"), ctrs.get("resp_notxn")))
    r.pre(ctrs.get("ack_commit") == 1, "exactly one ACK commitment",
          "ack_commit=%s" % ctrs.get("ack_commit"))
    r.pre(ctrs.get("resp_commit") == 1, "exactly one RESPONSE commitment",
          "resp_commit=%s" % ctrs.get("resp_commit"))

    # Token conservation IS the drain test. usage_cells is deliberately not
    # used: the four-queue oracle measured it reading 0 on every dp8 queue in
    # all five shaper settings including one that demonstrably leaked.
    r.pre(cons.get("ablock_closed") is True and cons.get("rblock_closed") is True,
          "token conservation closes (nothing still circulating)",
          "ABLOCK %s/%s  RBLOCK %s/%s"
          % (cons.get("ablock_admitted"), cons.get("ablock_terminated"),
             cons.get("rblock_admitted"), cons.get("rblock_terminated")))
    r.pre(ctrs.get("drop_bad_port") == 0, "zero frames on a non-topology port",
          "drop_bad_port=%s" % ctrs.get("drop_bad_port"))
    r.pre(ctrs.get("drop_non_dual") == 0, "zero generated frames misparsed",
          "drop_non_dual=%s (nonzero would mean the buffer template layout or "
          "pkt_len is wrong)" % ctrs.get("drop_non_dual"))
    r.pre(ctrs.get("fresh_bad") == 0 and ctrs.get("deq_bad") == 0,
          "zero unclassified frames",
          "fresh_bad=%s deq_bad=%s" % (ctrs.get("fresh_bad"), ctrs.get("deq_bad")))
    r.pre(t.get("zero_queue_drops") is not False, "zero TM queue drops",
          "zero_queue_drops=%s" % t.get("zero_queue_drops"))

    cl = t.get("cleanup") or {}
    r.pre(cl.get("clean") is True, "cleanup verified the switch clean",
          "clean=%s" % cl.get("clean"))

    t_read = regs.get("t_read")
    d_ack_w = regs.get("d_ack_word")
    d_resp_w = regs.get("d_resp_word")
    ts_ab_f = regs.get("ts_ablock_first")
    ts_ab_l = regs.get("ts_ablock_last")
    ts_ack = regs.get("ts_ack_commit")
    ts_rb_f = regs.get("ts_rblock_first")
    ts_rb_l = regs.get("ts_rblock_last")
    ts_resp = regs.get("ts_resp_commit")
    have = [t_read, d_ack_w, d_resp_w, ts_ab_f, ts_ab_l, ts_ack, ts_rb_f,
            ts_rb_l, ts_resp]
    # A register that reads 0 was never written. That is "nothing ran", which
    # is INVALID — not an ordering failure.
    r.pre(all(v is not None and v != 0 for v in have),
          "every instrumentation register was written",
          "t_read=%s d_ack=%s d_resp=%s ablock=%s/%s ack=%s rblock=%s/%s resp=%s"
          % (t_read, d_ack_w, d_resp_w, ts_ab_f, ts_ab_l, ts_ack, ts_rb_f,
             ts_rb_l, ts_resp))

    if r.failures("PRE"):
        return r, m

    # =====================================================================
    # DERIVED METRICS
    # =====================================================================
    a_word = int(guard.get("A", {}).get("word", "0x0"), 16) \
        if isinstance(guard.get("A", {}).get("word"), str) else None
    r_word = int(guard.get("R", {}).get("word", "0x0"), 16) \
        if isinstance(guard.get("R", {}).get("word"), str) else None
    a_ns = guard.get("A", {}).get("programmed_ns")
    r_ns = guard.get("R", {}).get("programmed_ns")

    d_ack_ns = deadline_instant(d_ack_w)
    d_resp_ns = deadline_instant(d_resp_w)

    m.update({
        "A_ns": a_ns, "R_ns": r_ns,
        "d_ack_ns": d_ack_ns, "d_resp_ns": d_resp_ns,
        # deadline errors: how far AFTER its deadline each release committed
        "ack_deadline_error_ns": delta32(d_ack_ns, ts_ack),
        "resp_deadline_error_ns": delta32(d_resp_ns, ts_resp),
        # the reservoirs' own drain windows
        "ablock_drain_ns": delta32(ts_ab_f, ts_ab_l),
        "rblock_drain_ns": delta32(ts_rb_f, ts_rb_l),
        # release tails: last blocker out -> the frame it was gating commits
        "ack_release_tail_ns": delta32(ts_ab_l, ts_ack),
        "resp_release_tail_ns": delta32(ts_rb_l, ts_resp),
        # the first termination of each reservoir, relative to its deadline
        "ablock_first_vs_dack_ns": delta32(d_ack_ns, ts_ab_f),
        "rblock_first_vs_dresp_ns": delta32(d_resp_ns, ts_rb_f),
        # the generation-bound gate's own observable
        "rblock_first_vs_ack_commit_ns": delta32(ts_ack, ts_rb_f),
        # the end-to-end ordering interval
        "ack_to_resp_ns": delta32(ts_ack, ts_resp),
        "read_to_ack_ns": delta32(t_read, ts_ack),
        "read_to_resp_ns": delta32(t_read, ts_resp),
        "blocker_counts": {"ablock": ctrs.get("admit_ablock"),
                           "rblock": ctrs.get("admit_rblock")},
        "final_first_role": ROLE_NAME.get(regs.get("final_first_role")),
    })

    ipg = emap.get("ipg_ns")
    pid1 = (emap.get("mapping") or {}).get("1")
    reg = None
    if ipg is not None and pid1 is not None and a_ns and r_ns:
        reg = scenario_regimes(ipg, pid1, a_ns, r_ns)
        m["regimes"] = reg

    # =====================================================================
    # ORDERING AND DEADLINE PROPERTIES — one per stop condition
    # =====================================================================

    # The anchoring arithmetic, reconstructed exactly. This is what makes the
    # release READ-anchored rather than arrival-anchored: both deadline words
    # must be exactly t_READ's tick word plus their own offset word.
    if a_word is not None and r_word is not None:
        ra = reconstruct(t_read, a_word)
        rr = reconstruct(t_read, r_word)
        r.ord(ra == d_ack_w, "d_ACK == (t_READ | armed) + A",
              "measured 0x%08X, reconstructed 0x%08X" % (d_ack_w, ra))
        r.ord(rr == d_resp_w, "d_RESP == (t_READ | armed) + R",
              "measured 0x%08X, reconstructed 0x%08X" % (d_resp_w, rr))
    else:
        r.note("A/R words absent from the manifest; the anchoring "
               "reconstruction was skipped")

    # STOP: ACK releases before d_ACK
    r.ord(m["ack_deadline_error_ns"] >= 0, "no ACK release before d_ACK",
          "ack_commit - d_ACK = %+d ns" % m["ack_deadline_error_ns"])
    # STOP: Q_ABLOCK empty before d_ACK  (a blocker that terminated early is
    # the mechanism by which the reservoir could empty early)
    r.ord(m["ablock_first_vs_dack_ns"] >= 0,
          "no ACK blocker terminated before d_ACK",
          "first ABLOCK termination - d_ACK = %+d ns"
          % m["ablock_first_vs_dack_ns"])
    # STOP: RESPONSE releases before d_RESP
    r.ord(m["resp_deadline_error_ns"] >= 0, "no RESPONSE release before d_RESP",
          "resp_commit - d_RESP = %+d ns" % m["resp_deadline_error_ns"])
    # STOP: Q_RBLOCK ineffective before d_RESP
    r.ord(m["rblock_first_vs_dresp_ns"] >= 0,
          "no response blocker terminated before d_RESP",
          "first RBLOCK termination - d_RESP = %+d ns"
          % m["rblock_first_vs_dresp_ns"])
    # STOP: response blockers terminate without matching ack_commit_gen
    r.ord(m["rblock_first_vs_ack_commit_ns"] >= 0,
          "no response blocker terminated before the ACK was committed",
          "first RBLOCK termination - ack_commit = %+d ns  <- this is the "
          "generation-bound gate's observable"
          % m["rblock_first_vs_ack_commit_ns"])
    # STOP: RESPONSE releases before ACK
    r.ord(m["ack_to_resp_ns"] > 0, "ACK committed before RESPONSE",
          "resp_commit - ack_commit = %+d ns" % m["ack_to_resp_ns"])
    r.ord(m["final_first_role"] == "ACK",
          "ACK left the shared final FIFO first",
          "final_first_role=%s" % m["final_first_role"])
    # STOP: blocker counts != 64/64
    r.ord(ctrs.get("term_ablock_dl") == N_PER_CLASS,
          "all %d ACK blockers terminated on the deadline" % N_PER_CLASS,
          "term_ablock_dl=%s tmo=%s stale=%s"
          % (ctrs.get("term_ablock_dl"), ctrs.get("term_ablock_tmo"),
             ctrs.get("term_ablock_stale")))
    r.ord(ctrs.get("term_rblock_dl") == N_PER_CLASS,
          "all %d response blockers terminated on the deadline" % N_PER_CLASS,
          "term_rblock_dl=%s tmo=%s stale=%s"
          % (ctrs.get("term_rblock_dl"), ctrs.get("term_rblock_tmo"),
             ctrs.get("term_rblock_stale")))
    # STOP: stale tokens affect the next transaction
    r.ord((ctrs.get("term_ablock_stale") or 0) == 0
          and (ctrs.get("term_rblock_stale") or 0) == 0,
          "no stale-generation token appeared",
          "ablock_stale=%s rblock_stale=%s"
          % (ctrs.get("term_ablock_stale"), ctrs.get("term_rblock_stale")))
    # A fail-open expiry means the defense turned itself OFF rather than
    # holding. It is not a crash, but it is not a pass either.
    r.ord((ctrs.get("term_ablock_tmo") or 0) == 0
          and (ctrs.get("term_rblock_tmo") or 0) == 0,
          "no fail-open budget expiry",
          "ablock_tmo=%s rblock_tmo=%s"
          % (ctrs.get("term_ablock_tmo"), ctrs.get("term_rblock_tmo")))
    r.ord(ctrs.get("final_drain") == 2,
          "both committed frames left the shared final FIFO",
          "final_drain=%s" % ctrs.get("final_drain"))

    # ---- the DERIVED, scenario-specific expectations ----------------------
    if reg is not None:
        if reg["ack_late"]:
            # The ACK arrived after its own deadline, so the ACK-blocker
            # reservoir drained and then Q_ACK sat EMPTY until it arrived. The
            # gap between the last ACK-blocker termination and the commit is
            # therefore the arrival lateness, not a release tail.
            want = reg["ack_arrival_nominal_ns"] - m["A_ns"] - SLACK_NS
            r.ord(m["ack_release_tail_ns"] >= want,
                  "late ACK: the commit trails d_ACK by the arrival lateness",
                  "tail %d ns >= %d ns (nominal arrival %d ns, A %d ns)"
                  % (m["ack_release_tail_ns"], want,
                     reg["ack_arrival_nominal_ns"], m["A_ns"]))
        else:
            r.ord(0 <= m["ack_release_tail_ns"] <= TAIL_MAX_NS,
                  "ACK released as soon as Q_ABLOCK drained",
                  "tail %d ns (bound %d ns)"
                  % (m["ack_release_tail_ns"], TAIL_MAX_NS))

        if reg["ack_after_dresp"]:
            # THE load-bearing case. The response blockers reached d_RESP with
            # nothing committed, so only the generation-bound gate could have
            # kept them circulating. Their first termination must trail d_RESP
            # by roughly the ACK's own lateness.
            want = reg["ack_arrival_nominal_ns"] - m["R_ns"] - SLACK_NS
            r.ord(m["rblock_first_vs_dresp_ns"] >= want,
                  "generation-bound gate HELD the response blockers past d_RESP",
                  "first RBLOCK termination trails d_RESP by %d ns >= %d ns "
                  "(nominal ACK arrival %d ns, R %d ns). In this regime nothing "
                  "else could have held them."
                  % (m["rblock_first_vs_dresp_ns"], want,
                     reg["ack_arrival_nominal_ns"], m["R_ns"]))
            r.note("this transaction EXERCISES the generation-bound ACK "
                   "commitment: the response blockers hit their deadline with "
                   "ack_commit_gen still unset")
        else:
            r.ord(0 <= m["resp_release_tail_ns"] <= TAIL_MAX_NS,
                  "RESPONSE released as soon as Q_RBLOCK drained",
                  "tail %d ns (bound %d ns)"
                  % (m["resp_release_tail_ns"], TAIL_MAX_NS))
            r.note("the generation-bound gate is SATISFIED here but not "
                   "STRESSED: the ACK committed before d_RESP, so the deadline "
                   "and the commit condition became true at nearly the same "
                   "instant. --late-ack is the mode that separates them.")

        if reg["response_parked_before_ack"]:
            r.note("early-response regime: the RESPONSE was generated %d ns "
                   "before the ACK, so it was already parked in Q_RESP when the "
                   "ACK arrived"
                   % (reg["ack_arrival_nominal_ns"]
                      - reg["resp_arrival_nominal_ns"]))
    else:
        r.note("scenario parameters absent from the manifest; the derived "
               "per-scenario expectations were skipped")

    return r, m


# ===========================================================================
# reporting
# ===========================================================================
def print_txn(t, res, m, verbose=True):
    print("=" * 78)
    print("%s   scenario=%s  gen=0x%02X  txn_index=%s  utc=%s"
          % (res.name, t.get("scenario"), t.get("generation") or 0,
             t.get("txn_index"), t.get("utc")))
    if m:
        print("  A = %s ns   R = %s ns   d_ACK = %s   d_RESP = %s"
              % (m.get("A_ns"), m.get("R_ns"), m.get("d_ack_ns"),
                 m.get("d_resp_ns")))
        print("  deadline error : ACK %+d ns   RESPONSE %+d ns"
              % (m.get("ack_deadline_error_ns") or 0,
                 m.get("resp_deadline_error_ns") or 0))
        print("  release tail   : ACK %+d ns   RESPONSE %+d ns"
              % (m.get("ack_release_tail_ns") or 0,
                 m.get("resp_release_tail_ns") or 0))
        print("  reservoir drain: ABLOCK %d ns over %s tokens   "
              "RBLOCK %d ns over %s tokens"
              % (m.get("ablock_drain_ns") or 0,
                 (m.get("blocker_counts") or {}).get("ablock"),
                 m.get("rblock_drain_ns") or 0,
                 (m.get("blocker_counts") or {}).get("rblock")))
        print("  ordering       : ACK -> RESPONSE %+d ns   final FIFO first out = %s"
              % (m.get("ack_to_resp_ns") or 0, m.get("final_first_role")))
        print("  observed       : READ -> ACK %+d ns   READ -> RESPONSE %+d ns"
              % (m.get("read_to_ack_ns") or 0, m.get("read_to_resp_ns") or 0))
    print(res.render(verbose=verbose))


def show_expectations():
    """Print the derived expectation for every scenario the setup ships."""
    a_ns, r_ns = 2999808, 12999936      # A = 3 ms, R = 13 ms, 256 ns quantized
    scen = [("normal", 500000, "ACK"),
            ("early-response", 500000, "RESP"),
            ("late-ack", 7000000, "RESP")]
    print("Derived expectations at A = %d ns, R = %d ns" % (a_ns, r_ns))
    print("(nothing below is keyed on the scenario NAME — change ipg and the "
          "regime moves)")
    print("")
    print("  %-16s %10s %6s %14s %14s %10s %10s %16s"
          % ("scenario", "ipg_ns", "pid1", "ack_arr_ns", "resp_arr_ns",
             "ack_late", "resp_late", "ack_after_dRESP"))
    for name, ipg, pid1 in scen:
        g = scenario_regimes(ipg, pid1, a_ns, r_ns)
        print("  %-16s %10d %6s %14d %14d %10s %10s %16s"
              % (name, ipg, pid1, g["ack_arrival_nominal_ns"],
                 g["resp_arrival_nominal_ns"], g["ack_late"], g["resp_late"],
                 g["ack_after_dresp"]))
    print("")
    print("Only the ack_after_dRESP regime STRESSES the generation-bound ACK")
    print("commitment: it is the one in which the response blockers reach their")
    print("own deadline with nothing committed, so their continued circulation")
    print("has no other possible cause.")


# ===========================================================================
# self-test
# ===========================================================================
def _mk(scenario="normal", ipg=500000, pid1="ACK", pid2="RESP",
        a_ns=2999808, r_ns=12999936, t_read=1000000, **over):
    """A synthetic transaction JSON that PASSES, unless `over` breaks it.

    Timestamps are built from the same arithmetic the chip uses, so the fixture
    exercises the real reconstruction rather than agreeing with itself.
    """
    # The fixture is built on an UNWRAPPED timeline and each register is masked
    # to 32 bits only at the end. Mixing wrapped and unwrapped magnitudes in the
    # ordering arithmetic here would make the wrap case fail for a reason that
    # lives in the fixture rather than in the analyzer — which is exactly the
    # mistake the wrap case exists to catch.
    a_word = (a_ns // 256) << 8
    r_word = (r_ns // 256) << 8
    base_word = ((t_read & TICK_MASK) | ARMED)
    d_ack_u = base_word + a_word          # unwrapped deadline words
    d_resp_u = base_word + r_word
    d_ack_w = d_ack_u & 0xFFFFFFFF        # what the register actually holds
    d_resp_w = d_resp_u & 0xFFFFFFFF
    d_ack = d_ack_u & ~0xFF               # unwrapped deadline INSTANTS
    d_resp = d_resp_u & ~0xFF

    # The causal chain the chip actually produces, in order:
    #   the 64 ACK blockers terminate over a ~40 us drain starting at d_ACK;
    #   Q_ACK is served once the LAST of them is gone, so the ACK commits one
    #   release tail after that -- or after its own arrival, if it is later;
    #   the response blockers then terminate once BOTH d_RESP has passed AND
    #   the ACK has committed; the RESPONSE follows the last of them.
    ack_arr = t_read + ipg * (1 if pid1 == "ACK" else 2)
    resp_arr = t_read + ipg * (2 if pid1 == "ACK" else 1)
    ab_first = d_ack + 800
    ab_last = d_ack + 40000
    ack_commit = max(ab_last, ack_arr) + 1720        # the measured release tail
    rb_first = max(d_resp, ack_commit) + 900
    rb_last = rb_first + 40000
    resp_commit = max(rb_last, resp_arr) + 1720
    regs = {
        "tag": 0xC1, "d_ack_word": d_ack_w, "d_resp_word": d_resp_w,
        "ack_commit_gen": 0xC1,
        "t_read": t_read & 0xFFFFFFFF,
        "ts_ablock_first": ab_first & 0xFFFFFFFF,
        "ts_ablock_last": ab_last & 0xFFFFFFFF,
        "ts_ack_commit": ack_commit & 0xFFFFFFFF,
        "ts_rblock_first": rb_first & 0xFFFFFFFF,
        "ts_rblock_last": rb_last & 0xFFFFFFFF,
        "ts_resp_commit": resp_commit & 0xFFFFFFFF,
        "final_first_role": 2,                       # ROLE_ACK
    }
    ctrs = {
        "drop_bad_port": 0, "drop_non_dual": 0, "arm_fresh": 1, "arm_dup": 0,
        "admit_ablock": 64, "admit_rblock": 64, "pgen_notxn": 0,
        "ack_held": 1, "ack_notxn": 0, "resp_held": 1, "resp_notxn": 0,
        "fresh_bad": 0, "loop_ablock": 111600, "loop_rblock": 372000,
        "term_ablock_dl": 64, "term_ablock_tmo": 0, "term_ablock_stale": 0,
        "term_rblock_dl": 64, "term_rblock_tmo": 0, "term_rblock_stale": 0,
        "ack_commit": 1, "resp_commit": 1, "final_drain": 2, "deq_bad": 0,
    }
    t = {
        "scenario": scenario, "generation": 0xC1, "txn_index": 1,
        "utc": "2026-07-29T00:00:00Z", "completed": True, "elapsed_s": 0.4,
        "registers": regs, "counters": ctrs,
        "conservation": {"ablock_admitted": 64, "ablock_terminated": 64,
                         "ablock_closed": True, "rblock_admitted": 64,
                         "rblock_terminated": 64, "rblock_closed": True,
                         "ack_commits": 1, "resp_commits": 1, "final_drains": 2},
        "pktgen": {"blocker": {"trigger_counter": 1, "pkt_counter": 128},
                   "event": {"trigger_counter": 1, "pkt_counter": 3}},
        "guard": {"A": {"programmed_ns": a_ns, "word": "0x%08X" % a_word},
                  "R": {"programmed_ns": r_ns, "word": "0x%08X" % r_word}},
        "event_map": {"scenario": scenario, "ipg_ns": ipg,
                      "mapping": {"0": "READ", "1": pid1, "2": pid2}},
        "zero_queue_drops": True,
        "cleanup": {"clean": True},
    }
    for k, v in over.items():
        if k.startswith("reg_"):
            t["registers"][k[4:]] = v
        elif k.startswith("ctr_"):
            t["counters"][k[4:]] = v
        else:
            t[k] = v
    return t


def self_test(verbose=False):
    """Positive cases, wrap arithmetic, and NEGATIVE CONTROLS.

    The negative controls are the part that matters: an analyzer that only ever
    sees good input cannot be shown to detect anything. Each one below is a
    named stop condition, injected into an otherwise-passing transaction, and
    each MUST change the verdict.
    """
    n_bad = 0

    def case(name, t, want, want_sub=None):
        nonlocal n_bad
        res, m = analyze(t, name)
        got = res.verdict
        ok = (got == want)
        if ok and want_sub:
            texts = " | ".join(c for _k, o, c, _d in res.rows if not o)
            ok = want_sub in texts
        if not ok:
            n_bad += 1
            print("SELFTEST FAIL: %-46s got %-8s want %-8s %s"
                  % (name, got, want, ("(missing %r)" % want_sub) if want_sub else ""))
            if verbose:
                print(res.render())
        else:
            print("  ok  %-46s -> %s" % (name, got))
        return res

    print("--- wrap-correct 32-bit arithmetic ---")
    for a, b, want in ((0xFFFFF000, 0x00001000, 8192),   # design §5.3's own case
                       (0, 1000, 1000),
                       (1000, 0, -1000),
                       (0x00001000, 0xFFFFF000, -8192)):
        got = delta32(a, b)
        if got != want:
            n_bad += 1
            print("SELFTEST FAIL: delta32(0x%08X, 0x%08X) = %s, want %s"
                  % (a, b, got, want))
        else:
            print("  ok  delta32(0x%08X, 0x%08X) = %d" % (a, b, got))

    print("--- positive controls ---")
    case("normal", _mk("normal", 500000, "ACK", "RESP"), "PASS")
    case("early-response", _mk("early-response", 500000, "RESP", "ACK"), "PASS")
    case("late-ack", _mk("late-ack", 7000000, "RESP", "ACK"), "PASS")
    # The same transaction placed so that every interval crosses the 32-bit
    # wrap. It must still PASS; if delta32 were a plain subtraction it would
    # not.
    case("normal across the 32-bit wrap",
         _mk("normal", 500000, "ACK", "RESP", t_read=0xFFFF0000), "PASS")

    print("--- negative controls (each MUST change the verdict) ---")
    good = _mk("normal", 500000, "ACK", "RESP")
    d_ack = good["registers"]["d_ack_word"] & TICK_MASK
    d_resp = good["registers"]["d_resp_word"] & TICK_MASK

    case("STOP: ACK releases before d_ACK",
         _mk("normal", reg_ts_ack_commit=d_ack - 5000),
         "FAIL", "no ACK release before d_ACK")
    case("STOP: an ACK blocker terminates before d_ACK",
         _mk("normal", reg_ts_ablock_first=d_ack - 5000),
         "FAIL", "no ACK blocker terminated before d_ACK")
    case("STOP: RESPONSE releases before d_RESP",
         _mk("normal", reg_ts_resp_commit=d_resp - 5000),
         "FAIL", "no RESPONSE release before d_RESP")
    case("STOP: RESPONSE commits before the ACK",
         _mk("normal", reg_ts_resp_commit=good["registers"]["ts_ack_commit"] - 1000),
         "FAIL", "ACK committed before RESPONSE")
    case("STOP: RESPONSE leaves the shared FIFO first",
         _mk("normal", reg_final_first_role=4),
         "FAIL", "ACK left the shared final FIFO first")
    case("STOP: response blockers terminate before the ACK commit",
         _mk("late-ack", 7000000, "RESP", "ACK",
             reg_ts_rblock_first=d_resp + 100),
         "FAIL", "no response blocker terminated before the ACK was committed")
    case("STOP: blocker counts are 63/64",
         _mk("normal", ctr_term_ablock_dl=63),
         "FAIL", "all 64 ACK blockers terminated on the deadline")
    case("STOP: a stale-generation token appeared",
         _mk("normal", ctr_term_rblock_stale=3, ctr_term_rblock_dl=61),
         "FAIL", "no stale-generation token appeared")
    case("STOP: the fail-open budget fired (defense turned itself off)",
         _mk("normal", ctr_term_rblock_tmo=64, ctr_term_rblock_dl=0),
         "FAIL", "no fail-open budget expiry")
    case("STOP: the anchoring is not READ-anchored",
         _mk("normal", reg_d_ack_word=0x12345600),
         "FAIL", "d_ACK == (t_READ | armed) + A")

    print("--- INVALID must stay separate from FAIL ---")
    case("INVALID: tokens still circulating",
         _mk("normal", conservation={"ablock_admitted": 64,
                                     "ablock_terminated": 60,
                                     "ablock_closed": False,
                                     "rblock_admitted": 64,
                                     "rblock_terminated": 64,
                                     "rblock_closed": True}),
         "INVALID", "token conservation closes")
    case("INVALID: the blocker batch never fired",
         _mk("normal", pktgen={"blocker": {"trigger_counter": 0, "pkt_counter": 0},
                               "event": {"trigger_counter": 1, "pkt_counter": 3}},
             ctr_admit_ablock=0, ctr_admit_rblock=0),
         "INVALID", "the READ fired the blocker batch exactly once")
    case("INVALID: nothing ran (all instrumentation zero)",
         _mk("normal", reg_ts_ack_commit=0, reg_ts_resp_commit=0,
             reg_ts_rblock_first=0),
         "INVALID", "every instrumentation register was written")
    case("INVALID: the TM dropped a token",
         _mk("normal", zero_queue_drops=False),
         "INVALID", "zero TM queue drops")
    case("INVALID: cleanup did not verify clean",
         _mk("normal", cleanup={"clean": False}),
         "INVALID", "cleanup verified the switch clean")
    case("INVALID: the transaction refused a dirty start",
         _mk("normal", refused_dirty_start="counters were nonzero"),
         "INVALID", "clean start")

    print("--- the self-test's own negative control ---")
    # If this one ever PASSES, the derived per-scenario expectation has stopped
    # discriminating and every late-ack verdict above is worthless. It is a
    # late-ack transaction in which the response blockers terminated exactly at
    # d_RESP — i.e. the generation-bound gate did nothing.
    lax = _mk("late-ack", 7000000, "RESP", "ACK")
    dr = lax["registers"]["d_resp_word"] & TICK_MASK
    lax["registers"]["ts_rblock_first"] = dr + 900
    lax["registers"]["ts_rblock_last"] = dr + 40000
    lax["registers"]["ts_resp_commit"] = dr + 41720
    case("late-ack with the generation gate DEFEATED must FAIL", lax, "FAIL")

    print("")
    if n_bad:
        print("SELF-TEST: %d FAILURE(S)" % n_bad)
    else:
        print("SELF-TEST: all cases behaved as specified")
    return 1 if n_bad else 0


# ===========================================================================
# main
# ===========================================================================
def main(argv=None):
    p = argparse.ArgumentParser(
        description="verdict engine for the minimal synthetic dual-release gate")
    p.add_argument("--evidence-dir", default=None,
                   help="directory of txn_*.json files")
    p.add_argument("files", nargs="*", help="individual transaction JSON files")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--show-expectations", action="store_true")
    p.add_argument("--quiet", action="store_true",
                   help="print only the failing checks")
    p.add_argument("--json-out", default=None)
    a = p.parse_args(argv)

    if a.self_test:
        return self_test(verbose=not a.quiet)
    if a.show_expectations:
        show_expectations()
        return 0

    paths = list(a.files)
    if a.evidence_dir:
        paths += sorted(glob.glob(os.path.join(a.evidence_dir, "txn_*.json")))
    if not paths:
        print("nothing to analyze: pass files, --evidence-dir, --self-test or "
              "--show-expectations", file=sys.stderr)
        return 2

    summary = []
    for path in paths:
        try:
            with open(path) as fh:
                t = json.load(fh)
        except Exception as e:
            print("could not read %s: %s" % (path, e), file=sys.stderr)
            summary.append({"file": path, "verdict": "INVALID",
                            "error": str(e)[:120]})
            continue
        res, m = analyze(t, os.path.basename(path))
        print_txn(t, res, m, verbose=not a.quiet)
        summary.append({"file": path, "scenario": t.get("scenario"),
                        "verdict": res.verdict, "metrics": m,
                        "failures": [c for _k, o, c, _d in res.rows if not o]})

    n = {"PASS": 0, "FAIL": 0, "INVALID": 0}
    for s in summary:
        n[s["verdict"]] = n.get(s["verdict"], 0) + 1
    print("=" * 78)
    print("SUMMARY: %d transaction(s) — %d PASS, %d FAIL, %d INVALID"
          % (len(summary), n["PASS"], n["FAIL"], n["INVALID"]))
    print("INVALID is NOT a mechanism failure: it means the transaction never "
          "established its preconditions.")
    if a.json_out:
        with open(a.json_out, "w") as fh:
            json.dump({"summary": summary, "counts": n}, fh, indent=2, default=str)
        print("wrote %s" % a.json_out)
    return 0 if (n["FAIL"] == 0 and n["INVALID"] == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
