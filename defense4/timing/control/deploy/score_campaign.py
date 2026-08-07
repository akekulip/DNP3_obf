#!/usr/bin/env python3
"""Fail-closed correctness scorer for one Defense 4 campaign block.

This is a CORRECTNESS detector, not the distributional analysis (that is analyze_campaign.py). It
consumes the sustained driver's block JSON (rows + token_escapes_on_wire) and the switch-side pre/post
evidence dumps, checks the block against its DECLARED scenario, and exits nonzero on any hard anomaly.

The old scorer swallowed every load error into an empty dict and always returned 0, so a missing file,
malformed JSON, empty rows, or a real RESPONSE bypass all scored "clean". This version fails closed:

  - a missing argument, unreadable file, malformed JSON, or empty JSON is a hard IO failure (exit 2);
  - a hard correctness anomaly sets verdict=FAIL and exits 1;
  - exit 0 only for a fully valid block that matches its declared scenario.

A scenario/expectation schema (SCENARIOS) distinguishes a normal block from a deliberately
missing-ACK, missing-RESPONSE, late-response, combined-response, multi-segment, teardown, or fail-open
test, so a declared negative is not judged like a normal block and a normal block cannot hide a
negative.

  score_campaign.py <block.json> <ev_pre.json> <ev_post.json>
       [--scenario NAME] [--mode MODE] [--n-expected N] [--expected-protected N] [--pcap PATH]

Back-compat: a bare 4th positional integer is still accepted as --expected-protected (normal scenario).
"""
import argparse
import json
import os
import sys

# ----- required counters (a dump missing any of these is a hard failure) --------------------------
REQUIRED_CF = ["ARM_FRESH", "RESP_HOLD_EARLY", "RESP_HOLD_LATE", "RESP_BYPASS",
               "ACK_REJECT", "PKTGEN_ADMIT"]
REQUIRED_CD = ["RELEASE_DEADLINE", "RELEASE_FAILOPEN", "ACK_RELEASE", "ACK_REL_RETIRE",
               "BLOCK_TERM_TMO", "BLOCK_TERM_STALE"]

KNOWN_MODES = {"OFF", "D1", "D2", "D3", "D4", "FAIL_OPEN"}
PROTECTED_MODES = {"D1", "D2", "D3", "D4"}
MUST_HOLD_MODES = {"D2", "D4"}   # every RESPONSE must be held; any RESP_BYPASS here is unplanned

# ----- scenario/expectation schema ----------------------------------------------------------------
# Each scenario declares what the block is allowed to show. A field left at its strict default makes
# the corresponding condition a hard anomaly. Scenarios are how a deliberately negative test is told
# apart from a normal block: the driver/spec labels the block, and the scorer judges it accordingly.
#   expect_ack      : every protected poll must observe a pure-ACK; a missing ACK is hard
#   expect_resp     : every protected poll must observe a RESPONSE; a missing RESPONSE is hard
#   responded_eq_sent: responded must equal sent (no silent drops)
#   allow_bypass    : a D2/D4 RESP_BYPASS is permitted (only combined/fail-open, never normal)
#   allow_multiseg  : resp_segments > 1 is permitted
#   allow_teardown  : FIN/RST is permitted
#   allow_late      : a RESPONSE after T_RESP (late safe release) is expected, not an error
SCENARIOS = {
    "normal":            dict(expect_ack=True,  expect_resp=True,  responded_eq_sent=True,
                              allow_bypass=False, allow_multiseg=False, allow_teardown=False, allow_late=False),
    "missing_ack":       dict(expect_ack=False, expect_resp=True,  responded_eq_sent=False,
                              allow_bypass=False, allow_multiseg=False, allow_teardown=False, allow_late=False),
    "missing_resp":      dict(expect_ack=True,  expect_resp=False, responded_eq_sent=False,
                              allow_bypass=False, allow_multiseg=False, allow_teardown=False, allow_late=False),
    "missing_both":      dict(expect_ack=False, expect_resp=False, responded_eq_sent=False,
                              allow_bypass=False, allow_multiseg=False, allow_teardown=False, allow_late=False),
    "late_response":     dict(expect_ack=True,  expect_resp=True,  responded_eq_sent=True,
                              allow_bypass=False, allow_multiseg=False, allow_teardown=False, allow_late=True),
    "combined_response": dict(expect_ack=False, expect_resp=True,  responded_eq_sent=True,
                              allow_bypass=True,  allow_multiseg=False, allow_teardown=False, allow_late=False),
    "multi_segment":     dict(expect_ack=True,  expect_resp=True,  responded_eq_sent=True,
                              allow_bypass=False, allow_multiseg=True,  allow_teardown=False, allow_late=False),
    "teardown":          dict(expect_ack=False, expect_resp=False, responded_eq_sent=False,
                              allow_bypass=False, allow_multiseg=False, allow_teardown=True,  allow_late=False),
    "fail_open":         dict(expect_ack=True,  expect_resp=True,  responded_eq_sent=False,
                              allow_bypass=True,  allow_multiseg=False, allow_teardown=False, allow_late=True),
}


class HardIO(Exception):
    """A load/parse/usage failure: bad input the scorer must reject, exit 2."""


def load_required(path, what):
    """Load a JSON object that MUST exist, be readable, be valid JSON, and be non-empty."""
    if not os.path.exists(path):
        raise HardIO("%s file missing: %s" % (what, path))
    try:
        with open(path) as f:
            text = f.read()
    except OSError as e:
        raise HardIO("%s unreadable: %s (%s)" % (what, path, e))
    if not text.strip():
        raise HardIO("%s empty: %s" % (what, path))
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        raise HardIO("%s malformed JSON: %s (%s)" % (what, path, e))
    if not isinstance(obj, dict):
        raise HardIO("%s is not a JSON object: %s" % (what, path))
    return obj


def cval(dump, group, name):
    v = (dump.get(group) or {}).get(name)
    return v if isinstance(v, (int, float)) else None


def cdelta(pre, post, group, name):
    a = cval(pre, group, name)
    b = cval(post, group, name)
    return (b - a) if (a is not None and b is not None) else None


def require_counters(dump, label, hard):
    for name in REQUIRED_CF:
        if cval(dump, "cf", name) is None:
            hard.append("%s missing counter cf.%s" % (label, name))
    for name in REQUIRED_CD:
        if cval(dump, "cd", name) is None:
            hard.append("%s missing counter cd.%s" % (label, name))


def parse_args(argv):
    ap = argparse.ArgumentParser(description="fail-closed Defense 4 block scorer")
    ap.add_argument("block")
    ap.add_argument("pre")
    ap.add_argument("post")
    ap.add_argument("compat_protected", nargs="?", default=None,
                    help="back-compat: bare integer = --expected-protected (normal scenario)")
    ap.add_argument("--scenario", default=None, choices=sorted(SCENARIOS))
    ap.add_argument("--mode", default=None, help="override block mode (else read from block JSON)")
    ap.add_argument("--n-expected", type=int, default=None, help="rows/sent expected (row-count check)")
    ap.add_argument("--expected-protected", type=int, default=None,
                    help="protected polls expected to ARM_FRESH (re-arm reconciliation)")
    ap.add_argument("--pcap", default=None, help="PCAP that must exist and be non-empty")
    args = ap.parse_args(argv)
    if args.scenario is None:
        args.scenario = "normal"
    if args.expected_protected is None and args.compat_protected is not None:
        try:
            args.expected_protected = int(args.compat_protected)
        except ValueError:
            ap.error("compat positional protected count is not an integer: %r" % args.compat_protected)
    return args


def main(argv):
    args = parse_args(argv)

    # ---- hard IO: these raise HardIO (exit 2) before any scoring ----
    block = load_required(args.block, "block")
    pre = load_required(args.pre, "pre-evidence")
    post = load_required(args.post, "post-evidence")

    mode = args.mode or block.get("mode", "?")
    scenario = args.scenario
    sc = SCENARIOS[scenario]
    protected = mode in PROTECTED_MODES

    hard = []   # every entry here is a hard anomaly -> exit 1

    if mode not in KNOWN_MODES:
        hard.append("unrecognized mode %r" % mode)

    rows = block.get("rows")
    if not isinstance(rows, list) or len(rows) == 0:
        hard.append("block has no rows")
        rows = rows if isinstance(rows, list) else []

    # ---- capture integrity ----
    if block.get("capture_ok") is not True:
        hard.append("capture_ok is not true")
    if args.pcap is not None:
        if not os.path.exists(args.pcap):
            hard.append("PCAP missing: %s" % args.pcap)
        elif os.path.getsize(args.pcap) == 0:
            hard.append("PCAP empty: %s" % args.pcap)

    attempted = block.get("attempted")
    sent = block.get("sent")
    responded = block.get("responded")
    for k, v in (("attempted", attempted), ("sent", sent), ("responded", responded)):
        if not isinstance(v, int):
            hard.append("block field %s is not an int (%r)" % (k, v))

    # ---- row count vs expectation ----
    if args.n_expected is not None and len(rows) != args.n_expected:
        hard.append("row count %d != expected %d" % (len(rows), args.n_expected))

    # ---- attempted/sent/responded agreement (scenario-aware) ----
    if isinstance(attempted, int) and isinstance(sent, int) and attempted != sent:
        # a mid-block send failure leaves attempted > sent; only teardown may legitimately stop early
        if not sc["allow_teardown"]:
            hard.append("attempted %d != sent %d (partial block)" % (attempted, sent))
    if sc["responded_eq_sent"] and isinstance(sent, int) and isinstance(responded, int) and responded != sent:
        hard.append("responded %d != sent %d (silent drop)" % (responded, sent))

    # ---- required counters present in both dumps ----
    require_counters(pre, "pre", hard)
    require_counters(post, "post", hard)

    # ---- per-poll wire anomalies ----
    missing_ack = [r.get("poll") for r in rows if r.get("t_resp") is not None and r.get("t_ack") is None]
    missing_resp = [r.get("poll") for r in rows if r.get("t_resp") is None]
    resp_before_ack = [r.get("poll") for r in rows
                       if isinstance(r.get("clrt_ms"), (int, float)) and r["clrt_ms"] < 0]
    order_inconclusive = [r.get("poll") for r in rows if r.get("order_inconclusive") is True]
    dup_ack = [r.get("poll") for r in rows if r.get("dup_ack", 0) > 0]
    dup_resp = [r.get("poll") for r in rows if r.get("dup_resp", 0) > 0]
    retransmit = [r.get("poll") for r in rows if r.get("retransmit", 0) > 0]
    tcp_reset = [r.get("poll") for r in rows if r.get("rst")]
    fin = [r.get("poll") for r in rows if r.get("fin")]
    multi_segment = [r.get("poll") for r in rows if r.get("resp_segments", 0) > 1]

    if resp_before_ack:
        hard.append("RESPONSE-before-ACK at polls %s (ordering inversion)" % resp_before_ack)
    if sc["expect_ack"] and missing_ack:
        hard.append("missing ACK outside declared negative at polls %s" % missing_ack)
    if protected and sc["expect_resp"] and mode != "D1" and missing_resp:
        hard.append("missing RESPONSE outside declared negative at polls %s" % missing_resp)
    if multi_segment and not sc["allow_multiseg"]:
        hard.append("multi-segment RESPONSE outside declared negative at polls %s" % multi_segment)
    # A FIN on the LAST poll is the normal block-end socket close (the driver keeps one connection and
    # closes it after the final READ), not a teardown fault. Only a mid-block FIN, or any RST, is
    # anomalous outside a declared teardown scenario.
    last_poll = max((r.get("poll") for r in rows), default=None) if rows else None
    fin_bad = [p for p in fin if p != last_poll]
    if not sc["allow_teardown"] and (tcp_reset or fin_bad):
        hard.append("unexpected FIN/RST (rst=%s mid-block-fin=%s)" % (tcp_reset, fin_bad))

    # ---- token / EtherType escape ----
    token_escapes = block.get("token_escapes_on_wire")
    if token_escapes is None:
        hard.append("token_escapes_on_wire not reported by the driver")
    elif token_escapes:
        hard.append("0x88C1 token escaped to the master-facing wire (%s)" % token_escapes)

    # ---- TM drops (per-queue + port) ----
    queue_drops = {}
    for q in ("qid7", "qid6", "qid5", "qid4"):
        a = ((pre.get("queues") or {}).get(q) or {}).get("drop_count_packets")
        b = ((post.get("queues") or {}).get(q) or {}).get("drop_count_packets")
        if isinstance(a, int) and isinstance(b, int) and b - a != 0:
            queue_drops[q] = b - a
    if queue_drops:
        hard.append("queue TM drops %s" % queue_drops)
    port_drops = {}
    for tname in (pre.get("port_tm_drops") or {}):
        a = (pre.get("port_tm_drops") or {}).get(tname)
        b = (post.get("port_tm_drops") or {}).get(tname)
        if isinstance(a, int) and isinstance(b, int) and b - a != 0:
            port_drops[tname] = b - a
    if port_drops:
        hard.append("port TM drops %s" % port_drops)

    # ---- release causes + arming ----
    deltas = {
        "deadline_release_delta": cdelta(pre, post, "cd", "RELEASE_DEADLINE"),
        "failopen_release_delta": cdelta(pre, post, "cd", "RELEASE_FAILOPEN"),
        "block_term_tmo_delta": cdelta(pre, post, "cd", "BLOCK_TERM_TMO"),
        "block_term_stale_delta": cdelta(pre, post, "cd", "BLOCK_TERM_STALE"),
        "ack_release_delta": cdelta(pre, post, "cd", "ACK_RELEASE"),
        "ack_rel_retire_delta": cdelta(pre, post, "cd", "ACK_REL_RETIRE"),
        "arm_fresh_delta": cdelta(pre, post, "cf", "ARM_FRESH"),
        "ack_reject_delta": cdelta(pre, post, "cf", "ACK_REJECT"),
        "pktgen_admit_delta": cdelta(pre, post, "cf", "PKTGEN_ADMIT"),
        "resp_hold_early_delta": cdelta(pre, post, "cf", "RESP_HOLD_EARLY"),
        "resp_hold_late_delta": cdelta(pre, post, "cf", "RESP_HOLD_LATE"),
        "resp_bypass_delta": cdelta(pre, post, "cf", "RESP_BYPASS"),
    }

    # ---- protected must-hold: any D2/D4 RESP_BYPASS not permitted by the scenario is the defect ----
    rbd = deltas["resp_bypass_delta"]
    if mode in MUST_HOLD_MODES and not sc["allow_bypass"] and isinstance(rbd, int) and rbd > 0:
        hard.append("unplanned RESPONSE bypass on %s (%d) -- must hold" % (mode, rbd))

    # ---- re-arm reconciliation: each protected poll must charge ARM_FRESH ----
    afd = deltas["arm_fresh_delta"]
    rearm_ok = None
    if protected and args.expected_protected is not None:
        if not isinstance(afd, int):
            hard.append("ARM_FRESH delta unavailable for re-arm check")
        else:
            rearm_ok = afd >= args.expected_protected
            if not rearm_ok:
                hard.append("insufficient re-arm: ARM_FRESH delta %d < expected %d"
                            % (afd, args.expected_protected))

    # ---- counter reconciliation on the RESPONSE disposition (D2/D4 normal) ----
    if mode in MUST_HOLD_MODES and scenario == "normal" and isinstance(responded, int):
        e, l, b = deltas["resp_hold_early_delta"], deltas["resp_hold_late_delta"], rbd
        if all(isinstance(x, int) for x in (e, l, b)):
            if e + l + b != responded:
                hard.append("counter mismatch: RESP_HOLD_EARLY+LATE+BYPASS (%d) != responded (%d)"
                            % (e + l + b, responded))

    # ---- stale state after the block ----
    tag_after = (post.get("regs") or {}).get("reg_tag")
    if tag_after not in (0, None):
        hard.append("stale reg_tag after block (%r)" % tag_after)

    det = {
        "scenario": scenario, "mode": mode, "protected": protected,
        "n_rows": len(rows), "attempted": attempted, "sent": sent, "responded": responded,
        "missing_ack": missing_ack, "missing_response": missing_resp,
        "resp_before_ack": resp_before_ack, "order_inconclusive": order_inconclusive,
        "dup_ack": dup_ack, "dup_resp": dup_resp, "retransmit": retransmit,
        "tcp_reset": tcp_reset, "fin": fin, "multi_segment_resp": multi_segment,
        "token_escapes_on_wire": token_escapes,
        "queue_drop_deltas": queue_drops, "port_drop_deltas": port_drops,
        "reg_tag_after": tag_after, "rearm_ok": rearm_ok,
    }
    det.update(deltas)
    det["hard_anomalies"] = hard
    det["verdict"] = "FAIL" if hard else "PASS"
    det["exit_code"] = 1 if hard else 0

    print(json.dumps(det, default=str))
    return det["exit_code"]


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except HardIO as e:
        print(json.dumps({"verdict": "IO_FAIL", "error": str(e), "exit_code": 2}))
        sys.exit(2)
