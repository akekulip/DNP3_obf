#!/usr/bin/env python3
"""
analyze_defense3.py — score a DEFENSE 3 §13 GATE 2 trial.

Reads the `D3GATE2 {json}` manifests written by run/poll_defense3.py and decides,
per trial, whether §13 Gate 2 is met — with the CONSENSUS §7 additions that turn
a plausible-looking run into an interpretable one.

STDLIB ONLY, python3.8-compatible: it runs on the switch, on Hulk, or here.
Nothing in it touches hardware.

---------------------------------------------------------------------------
THE THREE THINGS THIS FILE EXISTS TO GET RIGHT

1. THE DEADLINE INSTANT IS NOT THE RELEASE INSTANT (CONSENSUS §7 R5).
   The held ACK leaves when the LAST blocker terminates, and the reservoir
   drains at the dp8 loop rate, so the release trails the deadline by a
   DETERMINISTIC bias

       tau = K / rate_dp8 = 64 / 37.4e6 = 1.711 us

   (Part 12 measured 1.72 us with ~23 ns of spread — one dp8 dequeue slot).
   Scoring the hold against D alone reports 1.7 us of SYSTEMATIC OFFSET as if it
   were jitter, on every single transaction. This file reports BOTH:
       err_raw  = hold - D
       err_corr = hold - (D + tau)      <- the one that is scored
   and it takes K and rate_dp8 from the trial manifest, not from a constant
   here, because tau scales with dp8's port speed.

2. EVERY TIMESTAMP DIFFERENCE IS MOD 2^32.
   The instrument is ingress_mac_tstamp[31:0] in nanoseconds, which wraps every
   ~4.295 s. A plain subtraction across a wrap FABRICATES the headline number.
   All differences go through dt(), a signed 32-bit difference, and the
   self-test contains a wrap case that must still pass.

3. A SILENT ZERO-HOLD READS AS A WORKING RUN (CONSENSUS §7 R2).
   The ACK arrives a measured minimum of 0.400 ms after the READ — about 4x
   sooner than the packet Defense 2 held. If the K=64 reservoir is not standing
   by then, the ACK enters an unblocked Q_HOLD and leaves immediately, and every
   counter still reads exactly as it would on a good run. So
   `t_first_blocker_admitted - t_READ < 100 us` is a BLOCKING requirement here,
   not a diagnostic.

---------------------------------------------------------------------------
USAGE
    python3 analyze_defense3.py --evidence-dir <dir>
    python3 analyze_defense3.py trial.json [trial2.json ...]
    python3 analyze_defense3.py --self-test        # negative controls; no input

Exit 0 if every scored trial PASSES (and, under --self-test, if every control
behaved as required); 1 otherwise.
"""

import argparse
import glob
import json
import os
import sys

SCHEMA = "d3_gate2/1"

TWO32 = 1 << 32
TWO31 = 1 << 31

# CONSENSUS §7 R2: the reservoir-standing bound.
R2_BOUND_NS_DEFAULT = 100000          # 100 us

# How far the CORRECTED deadline error may sit from zero. Part 12 measured the
# release landing on the deadline to within ~1.7 us with 23 ns of spread, so
# 1 us is already ~40x the observed spread; it is a bound on the MODEL being
# wrong, not on hardware jitter.
TOL_NS_DEFAULT = 1000

K_DEFAULT = 64
RATE_DP8_PPS_DEFAULT = 37.4e6
REQUIRED_SPEED = "BF_SPEED_25G"

# const bit<8> TAG_INACTIVE = 8w0x00 — "no transaction". MIRRORED from the P4.
# It was 0xFF until the F02 repair, and this analyzer hard-coded 0xFF in G-10, which
# meant "transaction returns clean" could never pass again. Kept as a NAMED constant
# so the next change to the marker is a one-line change in each file rather than a
# literal hunt. See p4/case_a_defense3_fixed_ack_delay.p4 at TAG_INACTIVE.
TAG_INACTIVE = 0x00


# ---------------------------------------------------------------------------
def dt(a, b):
    """b - a as a SIGNED 32-bit nanosecond difference.

    The 32-bit ns counter wraps every ~4.295 s (~14x in a 60 s run). Every
    interval Gate 2 measures is microseconds to milliseconds, i.e. far below
    2^31, so interpreting the modular difference as signed recovers the true
    interval across a wrap and makes "b happened before a" a NEGATIVE number
    rather than a number close to 2^32.
    """
    if a is None or b is None:
        return None
    return ((int(b) - int(a) + TWO31) % TWO32) - TWO31


def tau_ns(k, rate_pps):
    """The release bias: one full drain of the reservoir at the dp8 loop rate."""
    return (float(k) / float(rate_pps)) * 1e9


def _speed_verdict(rec):
    """(ok_or_None, detail) for CONSENSUS R1.

    The trial manifest carries whatever assert_dp8_speed() recorded, which is
    a NESTED dict with two independent authorities:

        {"mac": {"$SPEED": ...}, "tm": {"scheduling_speed": ...}}

    BOTH are required, and that is not belt-and-braces: they are configured
    separately and have disagreed on this switch before. A TM that believes dp8
    is 10G shapes it as 10G whatever the MAC says, and tau = K/rate_dp8 — the
    bias every deadline number here is corrected by — is a function of the rate
    the TM actually serves. A plain string is also accepted, for hand-written
    records and for the self-test.
    """
    sp = rec.get("dp8_speed")
    if sp is None:
        sp = _get(rec, "snapshot", "ports", "dp8", "$SPEED")
    if sp is None:
        return None, "no dp8 speed recorded in the manifest"
    if isinstance(sp, str):
        return (sp == REQUIRED_SPEED), "read %r (single authority)" % (sp,)
    if isinstance(sp, dict):
        mac = _get(sp, "mac", "$SPEED")
        tm = _get(sp, "tm", "scheduling_speed")
        if mac is None and tm is None:
            return None, "dp8_speed present but neither authority readable: %r" % (sp,)
        detail = "MAC $SPEED=%r, TM scheduling_speed=%r (both must be %s)" \
                 % (mac, tm, REQUIRED_SPEED)
        return (mac == REQUIRED_SPEED and tm == REQUIRED_SPEED), detail
    return None, "unrecognised dp8_speed shape: %r" % (sp,)


class Result(object):
    """One scored requirement."""

    __slots__ = ("rid", "text", "status", "detail", "blocking")

    def __init__(self, rid, text, status, detail, blocking=True):
        self.rid = rid
        self.text = text
        self.status = status          # PASS | FAIL | INDETERMINATE | INFO
        self.detail = detail
        self.blocking = blocking

    def as_dict(self):
        return {"id": self.rid, "requirement": self.text, "status": self.status,
                "detail": self.detail, "blocking": self.blocking}


def _get(d, *path, **kw):
    default = kw.get("default")
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


# ---------------------------------------------------------------------------
def score_trial(rec, r2_bound_ns=R2_BOUND_NS_DEFAULT, tol_ns=TOL_NS_DEFAULT):
    """Score ONE Gate-2 manifest. Returns (verdict, [Result], derived dict)."""
    res = []
    cf = _get(rec, "counters", "fresh", default={}) or {}
    cd = _get(rec, "counters", "deq", default={}) or {}
    regs = _get(rec, "registers", default={}) or {}
    params = _get(rec, "params", default={}) or {}

    k = params.get("k", K_DEFAULT)
    rate = params.get("rate_dp8_pps", RATE_DP8_PPS_DEFAULT)
    d_ns = params.get("d_realized_ns")
    tau = tau_ns(k, rate)

    def C(name):
        v = cf.get(name)
        return None if v is None else int(v)

    def Q(name):
        v = cd.get(name)
        return None if v is None else int(v)

    def add(rid, text, ok, detail, blocking=True):
        if ok is None:
            res.append(Result(rid, text, "INDETERMINATE", detail, blocking))
        else:
            res.append(Result(rid, text, "PASS" if ok else "FAIL", detail, blocking))

    # ---- derived quantities, all mod 2^32 -------------------------------
    # ZERO MEANS "NEVER WRITTEN", NOT "t = 0". Every timestamp register in this
    # program is write-if-zero (`if (v == 32w0) { v = meta.ts32; }`), so the
    # value 0 is the P4's own sentinel for "this event did not happen". Feeding
    # it to dt() as a real instant FABRICATES an interval: the F01 run reported
    # a 291.77 ms "reservoir standing" and a 291.77 ms "READ -> ACK" purely
    # because reg_ts_first_block and reg_ts_ack_arm were 0 and reg_ts_read was
    # 4 003 197 740 — (0 - 4003197740) mod 2^32 = 291 769 556. The correct
    # reading is INDETERMINATE, which is what mapping 0 -> None produces.
    def ts(name):
        v = regs.get(name)
        if v is None:
            return None
        v = int(v)
        return None if v == 0 else v

    t_read = ts("reg_ts_read")
    t_blk = ts("reg_ts_first_block")
    t_arm = ts("reg_ts_ack_arm")
    t_rel = ts("reg_ts_ack_release")
    t_rrel = ts("reg_ts_resp_release")

    hold = dt(t_arm, t_rel)
    reservoir = dt(t_read, t_blk)
    read_to_ack = dt(t_read, t_arm)
    order_gap = dt(t_rel, t_rrel)
    err_raw = None if (hold is None or d_ns is None) else hold - d_ns
    err_corr = None if err_raw is None else err_raw - tau

    derived = {
        "t_read_ns": t_read, "t_first_block_ns": t_blk, "t_ack_arm_ns": t_arm,
        "t_ack_release_ns": t_rel, "t_resp_release_ns": t_rrel,
        "hold_ns": hold,
        "D_ns": d_ns,
        "tau_ns": tau,
        "D_plus_tau_ns": None if d_ns is None else d_ns + tau,
        "deadline_error_raw_ns": err_raw,
        "deadline_error_corrected_ns": err_corr,
        "reservoir_standing_ns": reservoir,
        "read_to_ack_ns": read_to_ack,
        "ack_to_resp_release_ns": order_gap,
        "blockers_admitted": C("PKTGEN_ADMIT"),
        "blockers_terminated": (None if None in (Q("BLOCK_TERM_STALE"),
                                                 Q("BLOCK_TERM_DL"),
                                                 Q("BLOCK_TERM_TMO"))
                                else Q("BLOCK_TERM_STALE") + Q("BLOCK_TERM_DL")
                                + Q("BLOCK_TERM_TMO")),
        "ack_release_failopen": (None if None in (Q("BLOCK_TERM_TMO"),
                                                  Q("RELEASE_FAILOPEN"))
                                 else Q("BLOCK_TERM_TMO") + Q("RELEASE_FAILOPEN")),
    }

    # ---- schema / trial validity ----------------------------------------
    verdict_field = rec.get("verdict")
    add("V-01", "trial ran to completion (verdict COMPLETE)",
        verdict_field == "COMPLETE",
        "verdict=%r" % (verdict_field,))
    add("V-02", "trial asserted a CLEAN START and was not refused",
        bool(_get(rec, "clean_start", "clean")),
        "reasons=%s" % (_get(rec, "clean_start", "reasons", default=[]),))
    add("V-03", "mandatory cleanup ran (from the `finally`)",
        _get(rec, "cleanup_synth") is not None,
        "cleanup_synth present=%s" % (_get(rec, "cleanup_synth") is not None,))

    # ---- CONSENSUS §7 R1: dp8 speed is a CORRECTNESS parameter ----------
    speed_ok, speed_detail = _speed_verdict(rec)
    add("C-R1", "dp8 speed == %s on BOTH the MAC and the TM" % REQUIRED_SPEED,
        speed_ok, speed_detail)

    # ---- §13 Gate 2, requirement by requirement -------------------------
    add("G-01", "one READ",
        None if None in (C("ARM_FRESH"), C("ARM_DUP"), C("ARM_BUSY"))
        else (C("ARM_FRESH") == 1 and C("ARM_DUP") == 0 and C("ARM_BUSY") == 0),
        "ARM_FRESH=%s ARM_DUP=%s ARM_BUSY=%s"
        % (C("ARM_FRESH"), C("ARM_DUP"), C("ARM_BUSY")))

    add("G-02", "one K=%d blocker burst" % k,
        None if None in (C("PKTGEN_ADMIT"), C("PKTGEN_DROP"))
        else (C("PKTGEN_ADMIT") == k and C("PKTGEN_DROP") == 0),
        "PKTGEN_ADMIT=%s (want %d) PKTGEN_DROP=%s"
        % (C("PKTGEN_ADMIT"), k, C("PKTGEN_DROP")))

    add("G-03", "one ACK admitted to Q_HOLD",
        None if None in (C("ACK_HOLD"), C("ACK_DUP_HOLD"), C("ACK_REJECT"))
        else (C("ACK_HOLD") == 1 and C("ACK_DUP_HOLD") == 0
              and C("ACK_REJECT") == 0),
        "ACK_HOLD=%s ACK_DUP_HOLD=%s ACK_REJECT=%s"
        % (C("ACK_HOLD"), C("ACK_DUP_HOLD"), C("ACK_REJECT")))

    # RESP_HOLD_EARLY is the P4's own statement that rel_diff != 0 when the
    # RESPONSE arrived, i.e. the ACK of this generation had NOT yet left Q_HOLD.
    # That is the direct evidence for "early ... admitted BEHIND the ACK", and it
    # needs no timestamp of its own.
    add("G-04", "one EARLY RESPONSE admitted behind the ACK",
        None if None in (C("RESP_HOLD_EARLY"), C("RESP_HOLD_LATE"),
                         C("RESP_BYPASS"))
        else (C("RESP_HOLD_EARLY") == 1 and C("RESP_HOLD_LATE") == 0
              and C("RESP_BYPASS") == 0),
        "RESP_HOLD_EARLY=%s (the ACK had not yet been released) "
        "RESP_HOLD_LATE=%s RESP_BYPASS=%s"
        % (C("RESP_HOLD_EARLY"), C("RESP_HOLD_LATE"), C("RESP_BYPASS")))

    add("G-05", "no ACK before t_ACK + D",
        None if (hold is None or d_ns is None) else (hold >= d_ns),
        "hold=%s ns, D=%s ns, raw error=%s ns (must be >= 0)"
        % (hold, d_ns, err_raw))

    add("G-06", "no RESPONSE before the ACK",
        None if order_gap is None else (order_gap > 0),
        "t_resp_release - t_ack_release = %s ns (must be > 0; a negative value "
        "is the wire order INVERTED)" % (order_gap,))

    add("G-07", "ACK released FIRST",
        None if Q("ACK_RELEASE") is None or order_gap is None
        else (Q("ACK_RELEASE") == 1 and order_gap > 0),
        "CD_ACK_RELEASE=%s, ordering gap=%s ns" % (Q("ACK_RELEASE"), order_gap))

    add("G-08", "RESPONSE released SECOND",
        None if None in (Q("RELEASE_DEADLINE"), Q("RELEASE_FAILOPEN"))
        else (Q("RELEASE_DEADLINE") + Q("RELEASE_FAILOPEN") == 1),
        "RELEASE_DEADLINE=%s RELEASE_FAILOPEN=%s (the two causes partition the "
        "releases, so the sum is the release count)"
        % (Q("RELEASE_DEADLINE"), Q("RELEASE_FAILOPEN")))

    # Token conservation. NOT usage_cells: the four-queue oracle measured
    # usage_cells reading 0 on every dp8 queue in all five shaper settings
    # INCLUDING one that demonstrably leaked, so a drain check built on it can
    # never fail. Admitted == stale + deadline + budget closes if and only if
    # nothing is still circulating.
    adm, term = derived["blockers_admitted"], derived["blockers_terminated"]
    add("G-09", "all blockers terminate (admitted == stale + deadline + budget)",
        None if None in (adm, term) else (adm == term and adm > 0),
        "admitted=%s terminated=%s (stale=%s deadline=%s budget=%s)"
        % (adm, term, Q("BLOCK_TERM_STALE"), Q("BLOCK_TERM_DL"),
           Q("BLOCK_TERM_TMO")))

    # "Returns clean" must be judged on the reg_tag the TRANSACTION left, which
    # is registers.reg_tag — read before the `finally`. It must NOT be judged on
    # cleanup.reg_tag_after: cleanup WRITES TAG_INACTIVE unconditionally, so
    # that field reads TAG_INACTIVE on a transaction that never retired its
    # generation and the requirement would be vacuous. The distinction is the whole
    # point: the generation is retired by the RELEASED RESPONSE, so
    # reg_tag != TAG_INACTIVE here means the response never came back out.
    #
    # ►► TAG_INACTIVE IS 0x00, NOT 0xFF. This test hard-coded 0xFF and so could
    # never pass once the F02 repair moved the marker — a retired transaction leaves
    # 0x00. Caught by the CHECK 1 marker-consistency audit, not by a run.
    tag_after = regs.get("reg_tag")
    qdrops = []
    for qn, q in (_get(rec, "queue_counters_after", default={}) or {}).items():
        if isinstance(q, dict):
            qdrops.append((qn, q.get("drop_count_packets")))
    add("G-10", "transaction returns clean (generation retired by the released "
                "RESPONSE, no drops, no off-topology packets)",
        None if tag_after is None
        else (int(tag_after) == TAG_INACTIVE
              and (C("BAD_PORT") in (0, None))
              and all((v in (0, None)) for _qn, v in qdrops)),
        "reg_tag BEFORE cleanup = 0x%s (want 0x%02X = TAG_INACTIVE); BAD_PORT=%s "
        "(the trigger CLONE is counted as CLONE_SEEN=%s, NOT as BAD_PORT); "
        "queue drops=%s"
        % ("%02X" % int(tag_after) if tag_after is not None else "??",
           TAG_INACTIVE, C("BAD_PORT"), C("CLONE_SEEN"), qdrops))

    # ---- CONSENSUS §7 R2 — reservoir standing ---------------------------
    add("C-R2", "reservoir standing: t_first_blocker - t_READ < %d ns"
        % r2_bound_ns,
        None if reservoir is None else (0 < reservoir < r2_bound_ns),
        "t_first_block - t_READ = %s ns (bound %d). A LATE reservoir is a SILENT "
        "ZERO-HOLD: the ACK arrives min 0.400 ms after the READ, so an unblocked "
        "Q_HOLD releases it immediately and every counter still reads normal."
        % (reservoir, r2_bound_ns))

    # ---- CONSENSUS §7 R4 — no fail-open release -------------------------
    fo = derived["ack_release_failopen"]
    add("C-R4", "ACK_RELEASE_FAILOPEN == 0",
        None if fo is None else (fo == 0),
        "BLOCK_TERM_TMO + RELEASE_FAILOPEN = %s. Non-zero means the reservoir "
        "drained on the pass budget B, so the trial measured H = B*K/rate, "
        "NOT D." % (fo,))

    # ---- CONSENSUS §7 R5 — score against D + K/rate ---------------------
    add("C-R5", "corrected deadline error |hold - (D + K/rate)| <= %d ns" % tol_ns,
        None if err_corr is None else (abs(err_corr) <= tol_ns),
        "hold=%s ns; D=%s ns; K/rate=%.3f ns; raw error=%s ns; CORRECTED "
        "error=%s ns. The raw error carries a deterministic +%.3f ns bias; "
        "reporting it as jitter is the default failure of this measurement."
        % (hold, d_ns,
           tau,
           ("%+.3f" % err_raw) if err_raw is not None else None,
           ("%+.3f" % err_corr) if err_corr is not None else None,
           tau))

    # ---- informational ---------------------------------------------------
    ipg = params.get("ipg_ns")
    res.append(Result("I-01", "READ -> ACK interval (should track the hardware ipg)",
                      "INFO", "t_ack_arm - t_READ = %s ns, ipg = %s ns"
                      % (read_to_ack, ipg), blocking=False))
    res.append(Result("I-02", "release tail: ACK -> RESPONSE on the wire",
                      "INFO", "%s ns" % (order_gap,), blocking=False))
    res.append(Result("I-03", "blocker loops (dp8 traversals consumed)",
                      "INFO", "CD_BLOCK_LOOP = %s" % (Q("BLOCK_LOOP"),),
                      blocking=False))

    blocking = [r for r in res if r.blocking]
    verdict = "PASS" if all(r.status == "PASS" for r in blocking) else "FAIL"
    return verdict, res, derived


# ---------------------------------------------------------------------------
def render(name, verdict, results, derived):
    lines = []
    lines.append("=" * 78)
    lines.append("DEFENSE 3 — §13 GATE 2 — %s" % name)
    lines.append("=" * 78)
    lines.append("%-6s %-6s %s" % ("RES", "ID", "REQUIREMENT"))
    lines.append("%-6s %-6s %s" % ("-" * 6, "-" * 6, "-" * 58))
    for r in results:
        lines.append("%-6s %-6s %s" % (r.status, r.rid, r.text))
        if r.detail:
            for chunk in _wrap(str(r.detail), 62):
                lines.append("%-6s %-6s   %s" % ("", "", chunk))
    lines.append("")
    lines.append("DERIVED")
    for kk in ("hold_ns", "D_ns", "tau_ns", "D_plus_tau_ns",
               "deadline_error_raw_ns", "deadline_error_corrected_ns",
               "reservoir_standing_ns", "read_to_ack_ns",
               "ack_to_resp_release_ns", "blockers_admitted",
               "blockers_terminated", "ack_release_failopen"):
        lines.append("  %-30s %s" % (kk, derived.get(kk)))
    lines.append("")
    lines.append("VERDICT: %s" % verdict)
    lines.append("")
    return "\n".join(lines)


def _wrap(s, width):
    out, cur = [], ""
    for word in s.split():
        if cur and len(cur) + 1 + len(word) > width:
            out.append(cur)
            cur = word
        else:
            cur = (cur + " " + word) if cur else word
    if cur:
        out.append(cur)
    return out or [""]


def load_records(paths):
    recs = []
    for p in paths:
        with open(p) as fh:
            txt = fh.read()
        rec = None
        try:
            rec = json.loads(txt)
        except ValueError:
            # tolerate a raw log: pull the last `D3GATE2 {...}` line out of it
            for line in txt.splitlines():
                if line.startswith("D3GATE2 "):
                    try:
                        rec = json.loads(line[len("D3GATE2 "):])
                    except ValueError:
                        pass
        if rec is None:
            print("WARN: no D3GATE2 record in %s" % p, file=sys.stderr)
            continue
        recs.append((os.path.basename(p), rec))
    return recs


# ===========================================================================
# SELF-TEST — a positive control and the negative controls that matter
# ===========================================================================
def _pass_record(**over):
    """A synthetic manifest that MUST score PASS. Every negative control below
    is this record with exactly one fact changed, so a control that fails proves
    the analyzer is sensitive to that one fact and nothing else."""
    d_ns = 1999872                       # D = 2 ms quantized to 256 ns ticks
    tau = tau_ns(K_DEFAULT, RATE_DP8_PPS_DEFAULT)      # 1711.23 ns
    t_read = 1000000
    t_blk = t_read + 12000               # 12 us: reservoir standing well inside R2
    t_arm = t_read + 500000              # ipg
    t_rel = t_arm + d_ns + int(round(tau))
    t_rrel = t_rel + 420                 # one dp8 loop traversal behind the ACK
    rec = {
        "schema": SCHEMA, "verdict": "COMPLETE",
        "clean_start": {"clean": True, "reasons": []},
        "cleanup_synth": {"order": ["disable_event_app", "d3.cleanup_trial"]},
        "cleanup": {"reg_tag_after": 0xFF},
        # the REAL shape assert_dp8_speed() records: two independent authorities
        "dp8_speed": {"mac": {"$SPEED": REQUIRED_SPEED, "$PORT_UP": True},
                      "tm": {"scheduling_speed": REQUIRED_SPEED}},
        "params": {"d_realized_ns": d_ns, "k": K_DEFAULT,
                   "rate_dp8_pps": RATE_DP8_PPS_DEFAULT, "ipg_ns": 500000},
        "registers": {
            "reg_tag": TAG_INACTIVE, "reg_deadline": 0,
            "reg_ts_read": t_read, "reg_ts_first_block": t_blk,
            "reg_ts_ack_arm": t_arm, "reg_ts_ack_release": t_rel,
            "reg_ts_resp_release": t_rrel, "reg_ts_block_term": t_rel,
        },
        "counters": {
            "fresh": {"BYPASS_FWD": 0, "BAD_PORT": 0, "ARM_FRESH": 1,
                      "ARM_DUP": 0, "ARM_BUSY": 0, "ACK_HOLD": 1,
                      "ACK_DUP_HOLD": 0, "ACK_REJECT": 0,
                      "RESP_HOLD_EARLY": 1, "RESP_HOLD_LATE": 0,
                      "RESP_BYPASS": 0, "UNSUP_SEG": 0, "BLOCK_ENQ": 0,
                      "PKTGEN_ADMIT": 64, "PKTGEN_DROP": 0,
                      # exactly one trigger clone per fresh ARM
                      "CLONE_SEEN": 1},
            "deq": {"BLOCK_LOOP": 74000, "BLOCK_TERM_STALE": 0,
                    "BLOCK_TERM_DL": 64, "BLOCK_TERM_TMO": 0,
                    "RELEASE_DEADLINE": 1, "RELEASE_FAILOPEN": 0,
                    "ACK_RELEASE": 1},
        },
        "queue_counters_after": {"qid7": {"drop_count_packets": 0},
                                 "qid1": {"drop_count_packets": 0}},
    }
    for path, val in over.items():
        cur = rec
        parts = path.split(".")
        for p in parts[:-1]:
            cur = cur[p]
        cur[parts[-1]] = val
    return rec


def self_test():
    d_ns = 1999872
    tau = tau_ns(K_DEFAULT, RATE_DP8_PPS_DEFAULT)
    t_read, t_arm = 1000000, 1500000
    t_rel_ok = t_arm + d_ns + int(round(tau))

    cases = []

    # ---- POSITIVE CONTROL ------------------------------------------------
    cases.append(("POSITIVE  nominal Gate-2 transaction",
                  _pass_record(), "PASS", []))

    # ---- NEGATIVE CONTROL 1: ACK released BEFORE the deadline ------------
    # 50 us early. Nothing else changes; the counters all still read normal,
    # which is precisely the failure mode a counter-only analyzer misses.
    early = _pass_record()
    early["registers"]["reg_ts_ack_release"] = t_arm + d_ns - 50000
    early["registers"]["reg_ts_resp_release"] = t_arm + d_ns - 50000 + 420
    cases.append(("NEGATIVE  ACK released 50 us BEFORE t_ACK + D",
                  early, "FAIL", ["G-05", "C-R5"]))

    # ---- NEGATIVE CONTROL 1b: early by LESS than the K/rate bias ---------
    # Released at exactly the deadline, i.e. tau EARLY relative to D + tau.
    # G-05 still passes (hold >= D); only the corrected score catches it. This
    # is the case that proves the correction is doing real work.
    biasonly = _pass_record()
    biasonly["registers"]["reg_ts_ack_release"] = t_arm + d_ns
    biasonly["registers"]["reg_ts_resp_release"] = t_arm + d_ns + 420
    cases.append(("NEGATIVE  release at D exactly (misses the K/rate bias)",
                  biasonly, "FAIL", ["C-R5"]))

    # ---- NEGATIVE CONTROL 2: RESPONSE released BEFORE the ACK ------------
    inverted = _pass_record()
    inverted["registers"]["reg_ts_resp_release"] = t_rel_ok - 500
    cases.append(("NEGATIVE  RESPONSE released BEFORE the ACK (order inverted)",
                  inverted, "FAIL", ["G-06", "G-07"]))

    # ---- NEGATIVE CONTROL 3: blocker count != 64 -------------------------
    short = _pass_record()
    short["counters"]["fresh"]["PKTGEN_ADMIT"] = 63
    cases.append(("NEGATIVE  blocker burst is 63, not K=64",
                  short, "FAIL", ["G-02", "G-09"]))

    # ---- NEGATIVE CONTROL 3b: a blocker never terminates -----------------
    leak = _pass_record()
    leak["counters"]["deq"]["BLOCK_TERM_DL"] = 63
    cases.append(("NEGATIVE  one blocker still circulating (conservation open)",
                  leak, "FAIL", ["G-09"]))

    # ---- NEGATIVE CONTROL 4: a FAIL-OPEN release -------------------------
    # The reservoir drained on the pass budget. The hold is then H = B*K/rate,
    # not D, and the run measured the budget.
    failopen = _pass_record()
    failopen["counters"]["deq"]["BLOCK_TERM_DL"] = 0
    failopen["counters"]["deq"]["BLOCK_TERM_TMO"] = 64
    failopen["counters"]["deq"]["RELEASE_DEADLINE"] = 0
    failopen["counters"]["deq"]["RELEASE_FAILOPEN"] = 1
    h_ns = int(18000 * tau)
    failopen["registers"]["reg_ts_ack_release"] = t_arm + h_ns
    failopen["registers"]["reg_ts_resp_release"] = t_arm + h_ns + 420
    cases.append(("NEGATIVE  fail-open release (measured B, not D)",
                  failopen, "FAIL", ["C-R4", "C-R5"]))

    # ---- NEGATIVE CONTROL 5: reservoir NOT standing in time --------------
    late = _pass_record()
    late["registers"]["reg_ts_first_block"] = t_read + 250000   # 250 us
    cases.append(("NEGATIVE  reservoir stands 250 us after the READ (R2)",
                  late, "FAIL", ["C-R2"]))

    # ---- NEGATIVE CONTROL 5b: the event NEVER HAPPENED -------------------
    # A write-if-zero timestamp register that reads 0 was never written. It is
    # NOT an instant, and subtracting it from a real one manufactures a plausible
    # interval out of nothing: F01 reported 291.77 ms of "reservoir standing"
    # from reg_ts_first_block = 0. The correct scoring is INDETERMINATE.
    never = _pass_record()
    never["registers"]["reg_ts_first_block"] = 0
    cases.append(("NEGATIVE  reservoir timestamp never written (0 != t=0)",
                  never, "FAIL", ["C-R2"]))

    # ---- NEGATIVE CONTROL 6: dp8 at the wrong speed ----------------------
    slow = _pass_record()
    slow["dp8_speed"]["mac"]["$SPEED"] = "BF_SPEED_10G"
    slow["dp8_speed"]["tm"]["scheduling_speed"] = "BF_SPEED_10G"
    cases.append(("NEGATIVE  dp8 at 10G (K margin and H both rescale)",
                  slow, "FAIL", ["C-R1"]))

    # ---- NEGATIVE CONTROL 6b: the MAC and the TM DISAGREE ----------------
    # The MAC reads 25G and everything looks right, but the TM is scheduling
    # dp8 as 10G — so the reservoir drains at 2.5x the assumed period and tau,
    # the bias every deadline number is corrected by, is wrong. Both
    # authorities are required precisely because they have disagreed here.
    split = _pass_record()
    split["dp8_speed"]["tm"]["scheduling_speed"] = "BF_SPEED_10G"
    cases.append(("NEGATIVE  MAC says 25G, TM schedules 10G (they disagree)",
                  split, "FAIL", ["C-R1"]))

    # ---- NEGATIVE CONTROL 6c: no speed recorded at all -------------------
    nospeed = _pass_record()
    del nospeed["dp8_speed"]
    cases.append(("NEGATIVE  dp8 speed not recorded (unreadable != clean)",
                  nospeed, "FAIL", ["C-R1"]))

    # ---- NEGATIVE CONTROL 6d: the generation was never retired -----------
    # The transaction left reg_tag holding a live generation, i.e. the released
    # RESPONSE never came back out of Q_HOLD. cleanup.reg_tag_after still reads
    # TAG_INACTIVE because cleanup writes it unconditionally, so this control is
    # what proves G-10 is scored on the PRE-cleanup value and is not vacuous.
    stuck = _pass_record()
    stuck["registers"]["reg_tag"] = 0xC0
    stuck["cleanup"]["reg_tag_after"] = TAG_INACTIVE
    cases.append(("NEGATIVE  generation still live after the transaction",
                  stuck, "FAIL", ["G-10"]))

    # ---- NEGATIVE CONTROL 6f: a REAL off-topology packet ------------------
    # Guards the other half of the clone-accounting repair. With the clone charged
    # to BAD_PORT (as it was before CF_CLONE_SEEN existed) this case was
    # indistinguishable from a correct run, so the isolation clause was dead.
    offtopo = _pass_record()
    offtopo["counters"]["fresh"]["BAD_PORT"] = 1
    cases.append(("NEGATIVE  one genuinely off-topology packet (BAD_PORT=1)",
                  offtopo, "FAIL", ["G-10"]))

    # ---- NEGATIVE CONTROL 6e: packets dropped in a dp8 queue -------------
    dropped = _pass_record()
    dropped["queue_counters_after"]["qid1"]["drop_count_packets"] = 2
    cases.append(("NEGATIVE  2 packets dropped out of Q_HOLD",
                  dropped, "FAIL", ["G-10"]))

    # ---- NEGATIVE CONTROL 7: dirty start ---------------------------------
    dirty = _pass_record()
    dirty["clean_start"] = {"clean": False, "reasons": ["reg_tag = 0xC0"]}
    dirty["verdict"] = "INVALID"
    cases.append(("NEGATIVE  refused dirty start",
                  dirty, "FAIL", ["V-01", "V-02"]))

    # ---- POSITIVE CONTROL 2: the 32-bit counter WRAPS mid-transaction ----
    # t_READ near 2^32, every later stamp past the wrap. A plain subtraction
    # would report ~-4.29e9 ns and fabricate the headline number; dt() must
    # recover the true intervals and this must still PASS.
    wrap = _pass_record()
    w_read = TWO32 - 200000                     # 200 us before the wrap
    w_blk = (w_read + 12000) % TWO32
    w_arm = (w_read + 500000) % TWO32
    w_rel = (w_arm + d_ns + int(round(tau))) % TWO32
    w_rrel = (w_rel + 420) % TWO32
    wrap["registers"].update({"reg_ts_read": w_read, "reg_ts_first_block": w_blk,
                              "reg_ts_ack_arm": w_arm,
                              "reg_ts_ack_release": w_rel,
                              "reg_ts_resp_release": w_rrel})
    cases.append(("POSITIVE  identical transaction across a 2^32 ns wrap",
                  wrap, "PASS", []))

    # ---- run them --------------------------------------------------------
    n_fail = 0
    print("=" * 78)
    print("analyze_defense3.py SELF-TEST — positive and negative controls")
    print("=" * 78)
    print("%-6s %-58s %s" % ("RES", "CONTROL", "MUST NOT PASS"))
    print("%-6s %-58s %s" % ("-" * 6, "-" * 58, "-" * 13))
    for name, rec, want_verdict, must_notpass in cases:
        verdict, results, _derived = score_trial(rec)
        by_id = {r.rid: r.status for r in results}
        ok = (verdict == want_verdict)
        # "not PASS" rather than "FAIL": an UNREADABLE fact is INDETERMINATE, not
        # false, and the distinction is worth keeping — but either one must stop
        # the trial from passing.
        missing = [rid for rid in must_notpass if by_id.get(rid) == "PASS"]
        # A negative control must disturb the requirement it targets AND NOTHING
        # ELSE, or it is not isolating that fact.
        extra = sorted(rid for rid, st in by_id.items()
                       if st in ("FAIL", "INDETERMINATE") and rid not in must_notpass)
        if missing or extra:
            ok = False
        print("%-6s %-58s %s" % ("PASS" if ok else "FAIL", name,
                                 ",".join(must_notpass) or "(nothing: %s)" % want_verdict))
        if not ok:
            n_fail += 1
            print("       got verdict=%s (wanted %s)" % (verdict, want_verdict))
            if missing:
                print("       still PASSED but should not have: %s" % ", ".join(missing))
            if extra:
                print("       collaterally disturbed: %s"
                      % ", ".join("%s=%s" % (r, by_id[r]) for r in extra))
        else:
            targeted = ["%s=%s" % (r, by_id.get(r)) for r in must_notpass]
            if targeted:
                print("       %s" % ", ".join(targeted))
    print("")
    print("SELF-TEST: %d control(s), %d bad" % (len(cases), n_fail))
    return 1 if n_fail else 0


# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="Score a Defense 3 §13 Gate 2 trial.")
    ap.add_argument("files", nargs="*", help="D3GATE2 json manifests (or logs)")
    ap.add_argument("--evidence-dir", default=None,
                    help="score every *.json in this directory")
    ap.add_argument("--self-test", action="store_true",
                    help="run the positive and negative controls; no input needed")
    ap.add_argument("--r2-bound-ns", type=int, default=R2_BOUND_NS_DEFAULT)
    ap.add_argument("--tol-ns", type=int, default=TOL_NS_DEFAULT)
    ap.add_argument("--json-out", default=None)
    a = ap.parse_args(argv)

    if a.self_test:
        return self_test()

    paths = list(a.files)
    if a.evidence_dir:
        paths += sorted(glob.glob(os.path.join(a.evidence_dir, "*.json")))
    if not paths:
        print("nothing to score: pass files, --evidence-dir or --self-test",
              file=sys.stderr)
        return 2

    recs = load_records(paths)
    if not recs:
        print("no scorable records found", file=sys.stderr)
        return 2

    all_out, n_fail = [], 0
    for name, rec in recs:
        verdict, results, derived = score_trial(rec, a.r2_bound_ns, a.tol_ns)
        print(render(name, verdict, results, derived))
        if verdict != "PASS":
            n_fail += 1
        all_out.append({"file": name, "verdict": verdict, "derived": derived,
                        "results": [r.as_dict() for r in results]})

    print("GATE 2 SUMMARY: %d trial(s), %d PASS, %d FAIL"
          % (len(recs), len(recs) - n_fail, n_fail))
    if a.json_out:
        with open(a.json_out, "w") as fh:
            json.dump({"schema": "d3_gate2_analysis/1", "trials": all_out},
                      fh, indent=2, default=str)
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
