#!/usr/bin/env python3
# =============================================================================
#  analyze_four_queue_dequeue.py — verdict engine for the FOUR-QUEUE on-chip
#  dequeue-order oracle.
#
#  Consumes the per-trial JSON written by
#  setup/four_queue_dequeue_oracle_setup.py --trial --out <file>, and decides:
#
#    INVALID  the trial never established the preconditions (a queue was empty,
#             the TM dropped something, frames escaped before the release, the
#             trace was truncated, the on-chip roles disagree with the control
#             plane's map). NOT an ordering failure, and must never be reported
#             as one.
#    PASS     the observed dequeue order matches what the CONFIGURED priorities
#             predict for this control mode.
#    FAIL     it does not.
#
#  ---------------------------------------------------------------------------
#  THE EXPECTATION IS DERIVED FROM THE PRIORITIES, NOT HARDCODED PER MODE
#
#  Roles are partitioned into PRIORITY CLASSES by their max_priority readback.
#  Two rules follow, and between them they cover all five control modes:
#
#    ORDERING (hard). For any two roles with different priority, every packet of
#    the higher-priority role must dequeue before every packet of the lower:
#        max(pos(r_hi)) < min(pos(r_lo))
#    With the intended ladder that is exactly the three predicates in the brief:
#        max(pos(ABLOCK)) < min(pos(ACK))
#        max(pos(ACK))    < min(pos(RBLOCK))
#        max(pos(RBLOCK)) < min(pos(RESP))
#    Under mode C the priorities are REVERSED, so the derived predicates reverse
#    with them and a trace that still came out ABLOCK-first now FAILS. That is
#    the point of control C: the expectation follows the configuration.
#
#    INTERLEAVING (hard). Roles that SHARE a priority class have no priority
#    difference to separate them, so the scheduler falls back to DWRR and they
#    must interleave. A class of size > 1 that comes out as clean per-role blocks
#    is a FAIL — it would mean something other than priority was ordering them.
#    This is what judges mode A (all four tied) and mode D (ABLOCK and ACK tied).
#
#  A singleton class has no interleaving expectation; the ordering rule already
#  forces its packets into one contiguous block.
#
#  ---------------------------------------------------------------------------
#  SCOPE. This decides SCHEDULER PRIORITY only. It says nothing about reservoir
#  depth or recirculation empty gaps.
#
#  Self-test:  python3 analyze_four_queue_dequeue.py --self-test
#  Expectations for all five modes:
#              python3 analyze_four_queue_dequeue.py --show-expectations
# =============================================================================
"""Verdict engine for the four-queue on-chip dequeue-order oracle."""
import argparse
import glob
import json
import os
import sys

ROLES = ["ABLOCK", "ACK", "RBLOCK", "RESP"]
ROLE_ID = {"ABLOCK": 1, "ACK": 2, "RBLOCK": 3, "RESP": 4}
N_PACKETS = 128
N_PER_ROLE = 32

# Mirrors PRIORITY_MODES in setup/four_queue_dequeue_oracle_setup.py.
PRIORITY_MODES = {
    "ladder":   {"ABLOCK": "7", "ACK": "6", "RBLOCK": "5", "RESP": "4"},
    "reversed": {"ABLOCK": "4", "ACK": "5", "RBLOCK": "6", "RESP": "7"},
    "equal":    {"ABLOCK": "4", "ACK": "4", "RBLOCK": "4", "RESP": "4"},
    "tied":     {"ABLOCK": "6", "ACK": "6", "RBLOCK": "5", "RESP": "4"},
}

# The five mandatory pilot controls, in the order the pilot runs them.
PILOT_CONTROLS = [
    ("A",  "equal",    "all four priorities EQUAL -> DWRR interleaving"),
    ("B1", "ladder",   "intended 7>6>5>4 ladder, mapping seed 1"),
    ("B2", "ladder",   "intended 7>6>5>4 ladder, a DIFFERENT mapping seed"),
    ("C",  "reversed", "REVERSED ladder -> the observed order must reverse too"),
    ("D",  "tied",     "ABLOCK and ACK tied above RBLOCK above RESP"),
]


def pnorm(v):
    """'LOW'|'0'..'7'|'HIGH' -> int."""
    if v is None:
        return None
    s = str(v).upper()
    if s == "HIGH":
        return 7
    if s == "LOW":
        return 0
    try:
        return int(s)
    except ValueError:
        return None


# ===========================================================================
# Expectation derivation
# ===========================================================================
def priority_classes(prio):
    """{role: priority} -> [(priority, [roles])] sorted HIGHEST priority first."""
    byp = {}
    for role in ROLES:
        p = pnorm(prio.get(role))
        byp.setdefault(p, []).append(role)
    return [(p, sorted(byp[p])) for p in sorted(byp.keys(), reverse=True)]


def ordering_predicates(prio):
    """The (hi_role, lo_role) pairs that must satisfy max(pos hi) < min(pos lo)."""
    preds = []
    classes = priority_classes(prio)
    for i, (_phi, hi_roles) in enumerate(classes):
        for _plo, lo_roles in classes[i + 1:]:
            for rh in hi_roles:
                for rl in lo_roles:
                    preds.append((rh, rl))
    return preds


def describe_expectation(prio):
    """Human-readable expectation for a priority assignment."""
    classes = priority_classes(prio)
    parts = []
    for p, roles in classes:
        if len(roles) == 1:
            parts.append("%s*" % roles[0])
        else:
            parts.append("{%s interleaved}" % "/".join(roles))
    return {
        "classes": [{"priority": p, "roles": roles} for p, roles in classes],
        "pattern": " ".join(parts),
        "ordering_predicates": ["max(pos(%s)) < min(pos(%s))" % (a, b)
                                for a, b in ordering_predicates(prio)],
        "interleave_required_in": [roles for _p, roles in classes if len(roles) > 1],
    }


# ===========================================================================
# Trace measurements
# ===========================================================================
def role_seq(trace):
    return [e.get("role") for e in trace]


def positions(trace):
    pos = {}
    for i, e in enumerate(trace):
        pos.setdefault(e.get("role"), []).append(i)
    return pos


def n_transitions(seq):
    """Adjacent positions whose role differs."""
    return sum(1 for i in range(1, len(seq)) if seq[i] != seq[i - 1])


def longest_run(seq, role):
    best = cur = 0
    for r in seq:
        cur = cur + 1 if r == role else 0
        best = max(best, cur)
    return best


def compact(seq, maxlen=72):
    """One-letter-per-packet rendering, run-length collapsed when long."""
    letters = {"ABLOCK": "A", "ACK": "K", "RBLOCK": "R", "RESP": "P"}
    s = "".join(letters.get(r, "?") for r in seq)
    if len(s) <= maxlen:
        return s
    runs, cur, n = [], None, 0
    for ch in s:
        if ch == cur:
            n += 1
        else:
            if cur is not None:
                runs.append("%s%d" % (cur, n) if n > 1 else cur)
            cur, n = ch, 1
    runs.append("%s%d" % (cur, n) if n > 1 else cur)
    return " ".join(runs)


# ===========================================================================
# The verdict
# ===========================================================================
class Result(object):
    def __init__(self, name):
        self.name = name
        self.rows = []          # (kind, result, check, detail)
        self.verdict = None

    def add(self, kind, ok, check, detail=""):
        self.rows.append((kind, "PASS" if ok else "FAIL", check, str(detail)))
        return ok

    def failures(self, kind=None):
        return [r for r in self.rows
                if r[1] == "FAIL" and (kind is None or r[0] == kind)]

    def render(self):
        w = max([len(r[2]) for r in self.rows] + [5])
        lines = ["", "  %-10s %-4s %-*s %s" % ("CLASS", "RES", w, "CHECK", "DETAIL"),
                 "  %-10s %-4s %-*s %s" % ("-" * 10, "-" * 4, w, "-" * w, "-" * 34)]
        for kind, res, check, detail in self.rows:
            lines.append("  %-10s %-4s %-*s %s" % (kind, res, w, check, detail))
        return "\n".join(lines)


def check_integrity(t, r):
    """Preconditions. Any failure makes the trial INVALID, not FAILED."""
    trace = t.get("trace") or []
    seq = role_seq(trace)

    ev = t.get("event_ctr")
    r.add("integrity", ev == N_PACKETS, "event_ctr == %d" % N_PACKETS, ev)
    r.add("integrity", len(trace) == N_PACKETS,
          "trace length == %d" % N_PACKETS, len(trace))

    ov = t.get("reg_overflow")
    r.add("integrity", ov == 0, "reg_overflow == 0", ov)

    counts = dict((role, seq.count(role)) for role in ROLES)
    r.add("integrity", all(counts[x] == N_PER_ROLE for x in ROLES),
          "exactly %d events per role" % N_PER_ROLE, counts)

    unknown = [e for e in trace if e.get("role") not in ROLES]
    r.add("integrity", not unknown, "zero unknown roles",
          "%d unknown" % len(unknown))

    pids = [e.get("pkt_id") for e in trace]
    dup = len(pids) - len(set(pids))
    r.add("integrity", dup == 0, "zero duplicate pkt_id", "%d duplicate(s)" % dup)

    # Every recorded frame must belong to THIS trial. Trace arrays are not
    # cleared between trials (only the index counter is), so this is what turns
    # a stale entry into a detected error rather than a silent one.
    tid = t.get("trial_id")
    bad_tid = [e for e in trace if e.get("trial_id") != tid]
    r.add("integrity", not bad_tid, "every event carries trial_id %s" % tid,
          "%d foreign" % len(bad_tid))

    # The on-chip role (what tbl_role actually did) against the control plane's
    # map (what it was told to do). A disagreement means the mapping file does
    # not describe the silicon, and every ordering conclusion drawn from it would
    # be unsound.
    mapping = ((t.get("role_map") or {}).get("mapping")) or []
    if mapping and len(mapping) >= N_PACKETS:
        mism = [e for e in trace
                if e.get("pkt_id") is not None and 0 <= e["pkt_id"] < len(mapping)
                and mapping[e["pkt_id"]] != e.get("role")]
        r.add("integrity", not mism, "on-chip role matches the control-plane map",
              "%d mismatch(es)" % len(mism))
    else:
        r.add("integrity", False, "on-chip role matches the control-plane map",
              "no mapping recorded in the trial JSON")

    occ = t.get("occupancy") or {}
    drops = dict((k, (v or {}).get("drop_count_packets")) for k, v in occ.items())
    r.add("integrity", all((d or 0) == 0 for d in drops.values()),
          "zero TM queue drops", drops)

    r.add("integrity", t.get("preload_gate_ok") is True,
          "preload gate satisfied", t.get("preload_gate"))
    r.add("integrity", t.get("event_ctr_before_release") == 0,
          "zero escapes before release", t.get("event_ctr_before_release"))
    r.add("integrity", t.get("released") is True, "release performed",
          t.get("released"))


def check_ordering(t, r, prio):
    """The mode-derived ordering and interleaving expectations."""
    trace = t.get("trace") or []
    seq = role_seq(trace)
    pos = positions(trace)
    classes = priority_classes(prio)

    for rh, rl in ordering_predicates(prio):
        ph, pl = pos.get(rh) or [], pos.get(rl) or []
        if not ph or not pl:
            r.add("ordering", False, "max(pos(%s)) < min(pos(%s))" % (rh, rl),
                  "a role is absent from the trace")
            continue
        r.add("ordering", max(ph) < min(pl),
              "max(pos(%s)) < min(pos(%s))" % (rh, rl),
              "max=%d min=%d" % (max(ph), min(pl)))

    if not ordering_predicates(prio):
        r.add("ordering", True, "ordering predicates",
              "none: all four roles share one priority class (nothing to order)")

    for p, roles in classes:
        if len(roles) == 1:
            role = roles[0]
            lr = longest_run(seq, role)
            r.add("blocking", lr == N_PER_ROLE,
                  "%s (priority %s, alone) forms one block" % (role, p),
                  "longest run %d of %d" % (lr, N_PER_ROLE))
            continue
        # A shared priority class must interleave: with no priority difference
        # the scheduler falls back to DWRR. Clean per-role blocks inside a class
        # would mean something other than priority did the ordering.
        idx = [i for i, x in enumerate(seq) if x in roles]
        sub = [seq[i] for i in idx]
        tr = n_transitions(sub)
        minimal = len(roles) - 1     # the fully blocked layout
        r.add("interleave", tr > minimal,
              "class {%s} (priority %s) interleaves" % ("/".join(roles), p),
              "%d transitions within the class (blocked would be %d)" % (tr, minimal))


def analyze_trial(t, name="trial", mode_override=None):
    """Full verdict for one trial dict."""
    r = Result(name)
    mode = mode_override or t.get("priority_mode") or "ladder"
    # Prefer the READBACK priorities: they are what the hardware was actually
    # configured with. Fall back to what was requested, then to the mode table.
    prio = t.get("priority_got") or t.get("priority_want") or PRIORITY_MODES.get(mode)
    if not prio or any(pnorm(prio.get(x)) is None for x in ROLES):
        prio = PRIORITY_MODES.get(mode, PRIORITY_MODES["ladder"])
    r.mode = mode
    r.prio = prio
    r.expectation = describe_expectation(prio)

    check_integrity(t, r)
    if r.failures("integrity"):
        r.verdict = "INVALID"
        return r
    check_ordering(t, r, prio)
    r.verdict = "FAIL" if r.failures() else "PASS"
    return r


# ===========================================================================
# Reporting
# ===========================================================================
def print_trial(t, r, verbose=True):
    trace = t.get("trace") or []
    print("")
    print("=" * 78)
    print("%s   mode=%s  trial_id=%s  seed=%s" % (r.name, r.mode, t.get("trial_id"),
                                                  t.get("seed")))
    print("  configured priorities : %s"
          % ", ".join("%s=%s" % (x, r.prio.get(x)) for x in ROLES))
    print("  EXPECTED pattern      : %s" % r.expectation["pattern"])
    for p in r.expectation["ordering_predicates"]:
        print("    predicate           : %s" % p)
    for cls in r.expectation["interleave_required_in"]:
        print("    must interleave     : {%s}" % "/".join(cls))
    if trace:
        print("  OBSERVED order        : %s" % compact(role_seq(trace)))
    if verbose:
        print(r.render())
    print("")
    print("  VERDICT: %s" % r.verdict)
    return r.verdict


# ===========================================================================
# Synthetic traces (used by --self-test)
# ===========================================================================
def _mk_trace(role_list, trial_id=1, ts0=1000):
    """A trace from a role order, with pkt_ids consistent with a mapping."""
    trace, mapping, nxt = [], [None] * N_PACKETS, 0
    for i, role in enumerate(role_list):
        pid = nxt
        nxt += 1
        mapping[pid] = role
        trace.append({"pos": i, "trial_id": trial_id, "role_id": ROLE_ID[role],
                      "role": role, "pkt_id": pid, "ts_ns": ts0 + i * 84})
    return trace, mapping


def _mk_trial(role_list, mode, trial_id=1, seed=1, **over):
    trace, mapping = _mk_trace(role_list, trial_id=trial_id)
    t = {
        "trial_id": trial_id, "seed": seed, "priority_mode": mode,
        "priority_want": dict(PRIORITY_MODES[mode]),
        "priority_got": dict(PRIORITY_MODES[mode]),
        "role_map": {"seed": seed, "mapping": mapping},
        "trace": trace, "event_ctr": len(trace), "reg_overflow": 0,
        "occupancy": dict((x, {"usage_cells": 10, "watermark_cells": 10,
                               "drop_count_packets": 0}) for x in ROLES),
        "preload_gate_ok": True, "event_ctr_before_release": 0, "released": True,
    }
    t.update(over)
    return t


def _blocks(order):
    out = []
    for role in order:
        out.extend([role] * N_PER_ROLE)
    return out


def _round_robin(roles):
    out = []
    for _i in range(N_PER_ROLE):
        out.extend(roles)
    return out


def _tied_then_blocks():
    """ABLOCK/ACK interleaved (64), then RBLOCK (32), then RESP (32)."""
    out = []
    for _i in range(N_PER_ROLE):
        out.extend(["ABLOCK", "ACK"])
    out.extend(["RBLOCK"] * N_PER_ROLE)
    out.extend(["RESP"] * N_PER_ROLE)
    return out


def self_test(verbose=False):
    """Positive AND negative controls. A negative control that PASSES is itself
    a failure of the analyzer, and is reported as such."""
    cases = []

    # ---- positives: the trace matches the configuration --------------------
    cases.append(("POS ladder: 4 clean blocks in priority order",
                  _mk_trial(_blocks(["ABLOCK", "ACK", "RBLOCK", "RESP"]), "ladder"),
                  "PASS"))
    cases.append(("POS reversed: blocks in the REVERSED order",
                  _mk_trial(_blocks(["RESP", "RBLOCK", "ACK", "ABLOCK"]), "reversed"),
                  "PASS"))
    cases.append(("POS equal: round-robin interleaving",
                  _mk_trial(_round_robin(ROLES), "equal"), "PASS"))
    cases.append(("POS tied: {ABLOCK,ACK} interleaved, then RBLOCK, then RESP",
                  _mk_trial(_tied_then_blocks(), "tied"), "PASS"))

    # ---- negatives: each MUST fail, and for the stated reason ---------------
    # The headline negative control: a DWRR interleave under the LADDER
    # configuration. If the analyzer passes this it cannot tell strict priority
    # from a fair split, which is the exact failure the IBSPG root-cause repair
    # was about.
    cases.append(("NEG ladder configured but the trace is DWRR-interleaved",
                  _mk_trial(_round_robin(ROLES), "ladder"), "FAIL"))
    # Reversal blindness: mode C with a trace that still came out ABLOCK-first.
    cases.append(("NEG reversed configured but the trace is still ABLOCK-first",
                  _mk_trial(_blocks(["ABLOCK", "ACK", "RBLOCK", "RESP"]), "reversed"),
                  "FAIL"))
    # Equal priorities cannot produce clean blocks.
    cases.append(("NEG equal configured but the trace is 4 clean blocks",
                  _mk_trial(_blocks(["ABLOCK", "ACK", "RBLOCK", "RESP"]), "equal"),
                  "FAIL"))
    # Mode D with the tied pair NOT interleaved.
    cases.append(("NEG tied configured but ABLOCK and ACK form clean blocks",
                  _mk_trial(_blocks(["ABLOCK", "ACK", "RBLOCK", "RESP"]), "tied"),
                  "FAIL"))
    # One role out of place inside an otherwise perfect ladder.
    swapped = _blocks(["ABLOCK", "ACK", "RBLOCK", "RESP"])
    swapped[0], swapped[127] = swapped[127], swapped[0]
    cases.append(("NEG ladder with one RESP dequeued first",
                  _mk_trial(swapped, "ladder"), "FAIL"))

    # ---- invalids: preconditions broken; must be INVALID, never FAIL --------
    cases.append(("INV overflow nonzero",
                  _mk_trial(_blocks(ROLES), "ladder", reg_overflow=3), "INVALID"))
    cases.append(("INV a TM queue dropped a packet",
                  _mk_trial(_blocks(ROLES), "ladder",
                            occupancy={"ABLOCK": {"usage_cells": 10,
                                                  "watermark_cells": 10,
                                                  "drop_count_packets": 2}}),
                  "INVALID"))
    cases.append(("INV frames escaped before the release",
                  _mk_trial(_blocks(ROLES), "ladder",
                            event_ctr_before_release=5), "INVALID"))
    short = _mk_trial(_blocks(ROLES), "ladder")
    short["trace"] = short["trace"][:100]
    short["event_ctr"] = 100
    cases.append(("INV short trace (100 of 128)", short, "INVALID"))
    dup = _mk_trial(_blocks(ROLES), "ladder")
    dup["trace"][5]["pkt_id"] = dup["trace"][4]["pkt_id"]
    cases.append(("INV duplicate pkt_id", dup, "INVALID"))
    stale = _mk_trial(_blocks(ROLES), "ladder", trial_id=7)
    stale["trace"][0]["trial_id"] = 6
    cases.append(("INV a stale entry from a previous trial", stale, "INVALID"))
    mis = _mk_trial(_blocks(ROLES), "ladder")
    mis["role_map"]["mapping"][0] = "RESP"     # map says RESP, chip says ABLOCK
    cases.append(("INV on-chip role disagrees with the control-plane map",
                  mis, "INVALID"))

    print("")
    print("SELF-TEST — %d synthetic case(s)" % len(cases))
    print("  %-4s %-62s %-8s %s" % ("RES", "CASE", "WANT", "GOT"))
    print("  %-4s %-62s %-8s %s" % ("-" * 4, "-" * 62, "-" * 8, "-" * 8))
    n_bad = 0
    for name, trial, want in cases:
        r = analyze_trial(trial, name=name)
        ok = (r.verdict == want)
        if not ok:
            n_bad += 1
        print("  %-4s %-62s %-8s %s" % ("ok" if ok else "BAD", name[:62], want,
                                        r.verdict))
        if verbose or not ok:
            print(r.render())
    print("")
    if n_bad:
        print("SELF-TEST FAILED: %d of %d case(s) gave the wrong verdict." % (n_bad,
                                                                             len(cases)))
        print("A negative control that PASSES means the analyzer cannot "
              "discriminate, and no verdict it produces can be trusted.")
        return 1
    print("SELF-TEST PASSED: %d/%d, including %d negative control(s) that "
          "correctly FAILED and %d precondition case(s) that correctly came out "
          "INVALID."
          % (len(cases), len(cases),
             len([c for c in cases if c[2] == "FAIL"]),
             len([c for c in cases if c[2] == "INVALID"])))
    return 0


def show_expectations():
    """Print the derived expectation for every control mode, side by side.

    This is the demonstration that the analyzer's expectation genuinely DIFFERS
    per mode rather than being one hardcoded pattern with a mode label on it.
    """
    print("")
    print("EXPECTATIONS PER CONTROL MODE (derived from the priorities, not hardcoded)")
    for tag, mode, why in PILOT_CONTROLS:
        prio = PRIORITY_MODES[mode]
        e = describe_expectation(prio)
        print("")
        print("  control %-3s mode=%-9s %s" % (tag, mode, why))
        print("    priorities : %s" % ", ".join("%s=%s" % (x, prio[x]) for x in ROLES))
        print("    classes    : %s"
              % " > ".join("[%s]@%s" % ("/".join(c["roles"]), c["priority"])
                           for c in e["classes"]))
        print("    pattern    : %s" % e["pattern"])
        if e["ordering_predicates"]:
            for p in e["ordering_predicates"]:
                print("    ordering   : %s" % p)
        else:
            print("    ordering   : (none — one class, nothing to order)")
        if e["interleave_required_in"]:
            for cls in e["interleave_required_in"]:
                print("    interleave : {%s} MUST interleave" % "/".join(cls))
        else:
            print("    interleave : (none required — every class is a singleton)")
    print("")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def main(argv=None):
    p = argparse.ArgumentParser(
        description="verdict engine for the four-queue on-chip dequeue oracle")
    p.add_argument("--trial-json", action="append", default=[],
                   help="a per-trial JSON file (repeatable)")
    p.add_argument("--evidence-dir", default=None,
                   help="directory of *.trial.json files")
    p.add_argument("--mode", default=None,
                   help="override the priority mode recorded in the JSON")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--show-expectations", action="store_true")
    p.add_argument("--quiet", action="store_true", help="verdict lines only")
    p.add_argument("--out", default=None, help="write a summary JSON here")
    a = p.parse_args(argv)

    if a.show_expectations:
        return show_expectations()
    if a.self_test:
        return self_test(verbose=not a.quiet and False)

    files = list(a.trial_json)
    if a.evidence_dir:
        files.extend(sorted(glob.glob(os.path.join(a.evidence_dir, "*.trial.json"))))
    if not files:
        print("nothing to analyze: pass --trial-json, --evidence-dir, --self-test "
              "or --show-expectations", file=sys.stderr)
        return 2

    summary, n_pass, n_fail, n_invalid = [], 0, 0, 0
    for f in files:
        try:
            with open(f) as fh:
                t = json.load(fh)
        except Exception as e:
            print("SKIP %s: %s" % (f, e), file=sys.stderr)
            n_invalid += 1
            continue
        r = analyze_trial(t, name=os.path.basename(f), mode_override=a.mode)
        print_trial(t, r, verbose=not a.quiet)
        summary.append({"file": f, "mode": r.mode, "trial_id": t.get("trial_id"),
                        "seed": t.get("seed"), "verdict": r.verdict,
                        "expected_pattern": r.expectation["pattern"],
                        "failures": [{"class": k, "check": c, "detail": d}
                                     for k, _res, c, d in r.failures()]})
        if r.verdict == "PASS":
            n_pass += 1
        elif r.verdict == "FAIL":
            n_fail += 1
        else:
            n_invalid += 1

    print("")
    print("=" * 78)
    print("SUMMARY: %d trial(s) — %d PASS, %d FAIL, %d INVALID"
          % (len(summary), n_pass, n_fail, n_invalid))
    print("  %-28s %-9s %-8s %s" % ("FILE", "MODE", "VERDICT", "EXPECTED PATTERN"))
    for s in summary:
        print("  %-28s %-9s %-8s %s" % (os.path.basename(s["file"])[:28], s["mode"],
                                        s["verdict"], s["expected_pattern"]))
    print("")
    print("NOTE: INVALID means the trial never established its preconditions. It is")
    print("      NOT an ordering failure and must never be reported as one.")
    if a.out:
        with open(a.out, "w") as fh:
            json.dump({"trials": summary, "n_pass": n_pass, "n_fail": n_fail,
                       "n_invalid": n_invalid}, fh, indent=2)
        print("wrote %s" % a.out)
    return 0 if (n_fail == 0 and n_invalid == 0 and n_pass > 0) else 1


if __name__ == "__main__":
    sys.exit(main())
