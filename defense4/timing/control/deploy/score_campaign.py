#!/usr/bin/env python3
"""Fail-closed correctness scorer for one Defense 4 campaign block.

Checks a block against its DECLARED scenario and exits nonzero on any hard anomaly. Unlike the earlier
version, a declared negative must actually be exercised, every register/counter/queue/port field the
verdict uses must be present in both snapshots, counters must reconcile exactly where the scenario
permits, and the PCAP is validated by its file magic (not just its size).

  score_campaign.py <block.json> <ev_pre.json> <ev_post.json>
       --scenario NAME --mode MODE [--label L] [--n-expected N] [--expected-protected N]
       [--d-a-ms D_A] [--d-r-ms D_R] [--expect-negative K] [--pcap PATH]

Exit 2: usage / missing / unreadable / malformed / empty input (HardIO).
Exit 1: any hard correctness anomaly.
Exit 0: only a fully valid block that matches its declared scenario.

Scenarios. A NORMAL block must complete cleanly: N ACKs, N RESPONSEs, no duplicate, no retransmit, no
inconclusive ordering, no multi-segment, no mid-block teardown, no protected bypass, idle tag, exact
counter reconciliation, empty driver errors. Each NEGATIVE scenario must actually contain its defining
signal (a missing_ack block with zero missing ACKs is rejected as "not exercised"); `--expect-negative`
sets the exact required count, otherwise at least one instance is required.
"""
import argparse
import json
import os
import sys

REQUIRED_CF = ["ARM_FRESH", "RESP_HOLD_EARLY", "RESP_HOLD_LATE", "RESP_BYPASS", "ACK_REJECT", "PKTGEN_ADMIT"]
REQUIRED_CD = ["RELEASE_DEADLINE", "RELEASE_FAILOPEN", "ACK_RELEASE", "ACK_REL_RETIRE", "BLOCK_TERM_TMO", "BLOCK_TERM_STALE"]
REQUIRED_QUEUES = ["qid7", "qid6", "qid5", "qid4"]

KNOWN_MODES = {"OFF", "D1", "D2", "D3", "D4", "FAIL_OPEN"}
PROTECTED_MODES = {"D1", "D2", "D3", "D4"}
MUST_HOLD_MODES = {"D2", "D4"}   # every RESPONSE must be held; any RESP_BYPASS here is unplanned

# scenario -> defining negative signal name (None = a clean-completing scenario)
NEGATIVE = {
    "normal": None, "late_response": None, "duplicate": "dup", "retransmit": "retransmit",
    "multi_segment": "multiseg", "missing_ack": "missing_ack", "missing_resp": "missing_resp",
    "missing_both": "missing_both", "teardown": "teardown", "fail_open": "failopen",
    "combined_response": "combined",
}
# scenarios that must still deliver every RESPONSE and finish all N polls cleanly
CLEAN_COMPLETE = {"normal", "late_response", "duplicate", "retransmit", "multi_segment"}
# scenarios where a RESP_BYPASS is legitimate
ALLOW_BYPASS = {"combined_response", "fail_open"}
# scenarios where the driver may record errors / a short block
ALLOW_PARTIAL = {"missing_ack", "missing_resp", "missing_both", "teardown", "fail_open", "combined_response"}

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class HardIO(Exception):
    """A load/parse/usage failure: bad input the scorer must reject, exit 2."""


def load_required(path, what):
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


def validate_pcap(path):
    """True only if the file starts with a pcap or pcapng magic and has at least a global header."""
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return False
    if head in PCAP_MAGIC:
        return os.path.getsize(path) >= 24
    if head == PCAPNG_MAGIC:
        return os.path.getsize(path) >= 12
    return False


def get_field(dump, path):
    """Fetch dump[a][b]... ; return (value, present). present=False if any level is absent."""
    cur = dump
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None, False
        cur = cur[key]
    return cur, True


def require_int_delta(pre, post, path, hard, label):
    a, pa = get_field(pre, path)
    b, pb = get_field(post, path)
    dotted = ".".join(path)
    if not pa:
        hard.append("%s pre missing %s" % (label, dotted)); return None
    if not pb:
        hard.append("%s post missing %s" % (label, dotted)); return None
    if not isinstance(a, int) or not isinstance(b, int):
        hard.append("%s %s not integer (pre=%r post=%r)" % (label, dotted, a, b)); return None
    d = b - a
    if d < 0:
        hard.append("%s %s negative delta (%d)" % (label, dotted, d)); return None
    return d


def parse_args(argv):
    ap = argparse.ArgumentParser(description="fail-closed Defense 4 block scorer")
    ap.add_argument("block")
    ap.add_argument("pre")
    ap.add_argument("post")
    ap.add_argument("--scenario", required=True, choices=sorted(NEGATIVE))
    ap.add_argument("--mode", required=True, choices=sorted(KNOWN_MODES))
    ap.add_argument("--label", default=None)
    ap.add_argument("--n-expected", type=int, default=None)
    ap.add_argument("--expected-protected", type=int, default=None)
    ap.add_argument("--d-a-ms", default=None)
    ap.add_argument("--d-r-ms", default=None)
    ap.add_argument("--expect-negative", type=int, default=None,
                    help="exact required count of the scenario's defining negative signal")
    ap.add_argument("--pcap", default=None)
    return ap.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    block = load_required(args.block, "block")
    pre = load_required(args.pre, "pre-evidence")
    post = load_required(args.post, "post-evidence")

    mode = args.mode
    scenario = args.scenario
    protected = mode in PROTECTED_MODES
    hard = []

    # ---- spec / label / mode / param reconciliation ----
    if block.get("mode") != mode:
        hard.append("block mode %r != --mode %r" % (block.get("mode"), mode))
    if args.label is not None and block.get("label") != args.label:
        hard.append("block label %r != --label %r" % (block.get("label"), args.label))
    if args.n_expected is not None and block.get("N") not in (args.n_expected, None):
        hard.append("block N %r != --n-expected %r" % (block.get("N"), args.n_expected))
    if args.d_a_ms is not None and str(block.get("d_a_ms")) not in (str(args.d_a_ms), "None"):
        hard.append("block d_a_ms %r != --d-a-ms %r" % (block.get("d_a_ms"), args.d_a_ms))
    if args.d_r_ms is not None and str(block.get("d_r_ms")) not in (str(args.d_r_ms), "None"):
        hard.append("block d_r_ms %r != --d-r-ms %r" % (block.get("d_r_ms"), args.d_r_ms))

    rows = block.get("rows")
    if not isinstance(rows, list) or len(rows) == 0:
        hard.append("block has no rows")
        rows = rows if isinstance(rows, list) else []

    if block.get("capture_ok") is not True:
        hard.append("capture_ok is not true")

    # ---- PCAP: validate the magic, not just the size ----
    if args.pcap is not None:
        if not os.path.exists(args.pcap):
            hard.append("PCAP missing: %s" % args.pcap)
        elif os.path.getsize(args.pcap) == 0:
            hard.append("PCAP empty: %s" % args.pcap)
        elif not validate_pcap(args.pcap):
            hard.append("PCAP not a valid pcap/pcapng file: %s" % args.pcap)

    attempted, sent, responded = block.get("attempted"), block.get("sent"), block.get("responded")
    for k, v in (("attempted", attempted), ("sent", sent), ("responded", responded)):
        if not isinstance(v, int):
            hard.append("block field %s is not an int (%r)" % (k, v))

    if args.n_expected is not None and len(rows) != args.n_expected and scenario not in ALLOW_PARTIAL:
        hard.append("row count %d != expected %d" % (len(rows), args.n_expected))

    # driver errors: only tolerated for partial/negative scenarios
    errs = block.get("errors") or []
    if errs and scenario not in ALLOW_PARTIAL:
        hard.append("driver reported errors on a clean-complete scenario: %s" % errs[:3])

    # attempted/sent agreement (a partial send is only OK for teardown/partial scenarios)
    if isinstance(attempted, int) and isinstance(sent, int) and attempted != sent and scenario not in ALLOW_PARTIAL:
        hard.append("attempted %d != sent %d (partial block)" % (attempted, sent))
    if scenario in CLEAN_COMPLETE and isinstance(sent, int) and isinstance(responded, int) and responded != sent:
        hard.append("responded %d != sent %d (a clean-complete scenario must deliver every RESPONSE)" % (responded, sent))

    # ---- required counter/register/queue/port fields present + integer + nonneg delta ----
    d = {}
    for name in REQUIRED_CF:
        d["cf." + name] = require_int_delta(pre, post, ["cf", name], hard, "counter")
    for name in REQUIRED_CD:
        d["cd." + name] = require_int_delta(pre, post, ["cd", name], hard, "counter")
    for q in REQUIRED_QUEUES:
        dd = require_int_delta(pre, post, ["queues", q, "drop_count_packets"], hard, "queue")
        if isinstance(dd, int) and dd != 0:
            hard.append("queue %s TM drop delta %d" % (q, dd))
    # port drops: the whole map must be present in both, every value an int, no positive delta
    pre_pd, pre_pd_ok = get_field(pre, ["port_tm_drops"])
    post_pd, post_pd_ok = get_field(post, ["port_tm_drops"])
    if not pre_pd_ok or not post_pd_ok:
        hard.append("port_tm_drops snapshot missing (pre=%s post=%s)" % (pre_pd_ok, post_pd_ok))
    else:
        for tname in set(pre_pd) | set(post_pd):
            a = pre_pd.get(tname); b = post_pd.get(tname)
            if not isinstance(a, int) or not isinstance(b, int):
                hard.append("port_tm_drops %s not integer" % tname)
            elif b - a != 0:
                hard.append("port TM drop %s delta %d" % (tname, b - a))
    # reg_tag must be PRESENT and idle (0) after; missing is NOT zero
    tag_after, tag_present = get_field(post, ["regs", "reg_tag"])
    if not tag_present:
        hard.append("post snapshot missing regs.reg_tag")
    elif tag_after != 0:
        hard.append("stale reg_tag after block (%r)" % tag_after)

    # ---- per-poll wire signals ----
    def polls(pred):
        return [r.get("poll") for r in rows if pred(r)]
    last_poll = max((r.get("poll") for r in rows), default=None) if rows else None
    missing_ack = polls(lambda r: r.get("t_resp") is not None and r.get("t_ack") is None)
    missing_resp = polls(lambda r: r.get("t_resp") is None and r.get("t_ack") is not None)
    missing_both = polls(lambda r: r.get("t_resp") is None and r.get("t_ack") is None)
    resp_before_ack = polls(lambda r: isinstance(r.get("clrt_ms"), (int, float)) and r["clrt_ms"] < 0)
    inconclusive = polls(lambda r: r.get("order_inconclusive") is True)
    dup_ack = sum(r.get("dup_ack", 0) or 0 for r in rows)
    dup_resp = sum(r.get("dup_resp", 0) or 0 for r in rows)
    retransmit = sum(r.get("retransmit", 0) or 0 for r in rows)
    multiseg = polls(lambda r: (r.get("resp_segments", 0) or 0) > 1)
    rst_polls = polls(lambda r: r.get("rst"))
    fin_midblock = [p for p in polls(lambda r: r.get("fin")) if p != last_poll]
    late = polls(lambda r: r.get("late") is True or r.get("arrival_bucket") == "after_tresp")

    # ordering inversion is always hard
    if resp_before_ack:
        hard.append("RESPONSE-before-ACK at polls %s" % resp_before_ack)

    # signals that are anomalies UNLESS the scenario is defined by them
    signal_counts = {
        "dup": dup_ack + dup_resp, "retransmit": retransmit, "multiseg": len(multiseg),
        "missing_ack": len(missing_ack), "missing_resp": len(missing_resp),
        "missing_both": len(missing_both), "teardown": len(rst_polls) + len(fin_midblock),
        "failopen": None,  # filled after counter deltas below
        "combined": len(missing_ack),  # combined ACK-bearing response looks like a missing separate ACK
    }
    fod = d.get("cd.RELEASE_FAILOPEN")
    signal_counts["failopen"] = fod if isinstance(fod, int) else 0

    this_signal = NEGATIVE[scenario]
    # in a clean-complete scenario, EVERY off-signal must be zero
    if scenario in CLEAN_COMPLETE:
        for sig in ("dup", "retransmit", "missing_ack", "missing_resp", "missing_both", "teardown"):
            if sig != this_signal and signal_counts[sig] > 0:
                hard.append("%s present (%d) on a %s block" % (sig, signal_counts[sig], scenario))
        if inconclusive and scenario != "normal":
            pass
        if inconclusive:
            hard.append("inconclusive ACK/RESPONSE ordering at polls %s" % inconclusive)
        if len(multiseg) > 0 and scenario != "multi_segment":
            hard.append("multi-segment RESPONSE at polls %s" % multiseg)
    # a declared negative must actually be exercised
    if this_signal is not None:
        got = signal_counts[this_signal]
        need = args.expect_negative
        if need is not None:
            if got != need:
                hard.append("%s not exercised as declared: observed %d != expected %d" % (scenario, got, need))
        elif got < 1:
            hard.append("%s declared but not exercised (observed 0 of the %s signal)" % (scenario, this_signal))
    # late_response must actually exercise an after-T_RESP arrival
    if scenario == "late_response":
        need = args.expect_negative
        if need is not None and len(late) != need:
            hard.append("late_response not exercised: observed %d late != expected %d" % (len(late), need))
        elif need is None and len(late) < 1:
            hard.append("late_response declared but no after-T_RESP arrival observed")

    # ---- token / EtherType escape (always hard) ----
    token_escapes = block.get("token_escapes_on_wire")
    if token_escapes is None:
        hard.append("token_escapes_on_wire not reported by the driver")
    elif token_escapes:
        hard.append("0x88C1 token escaped to the master-facing wire (%s)" % token_escapes)

    # ---- protected must-hold ----
    rbd = d.get("cf.RESP_BYPASS")
    if mode in MUST_HOLD_MODES and scenario not in ALLOW_BYPASS and isinstance(rbd, int) and rbd > 0:
        hard.append("unplanned RESPONSE bypass on %s (%d) -- must hold" % (mode, rbd))

    # ---- re-arm + exact counter reconciliation where the scenario permits ----
    afd = d.get("cf.ARM_FRESH")
    rearm_ok = None
    if protected and args.expected_protected is not None and isinstance(afd, int):
        rearm_ok = afd >= args.expected_protected
        if not rearm_ok:
            hard.append("insufficient re-arm: ARM_FRESH delta %d < expected %d" % (afd, args.expected_protected))
    if protected and scenario == "normal" and isinstance(responded, int):
        e, l, b = d.get("cf.RESP_HOLD_EARLY"), d.get("cf.RESP_HOLD_LATE"), rbd
        if all(isinstance(x, int) for x in (e, l, b)):
            if e + l + b != responded:
                hard.append("counter mismatch: RESP_HOLD_EARLY+LATE+BYPASS (%d) != responded (%d)" % (e + l + b, responded))
        if args.expected_protected is not None and isinstance(afd, int) and afd != args.expected_protected:
            hard.append("counter mismatch: ARM_FRESH (%d) != protected polls (%d)" % (afd, args.expected_protected))
        if mode in MUST_HOLD_MODES:
            arr, arrr = d.get("cd.ACK_RELEASE"), d.get("cd.ACK_REL_RETIRE")
            rd, rf = d.get("cd.RELEASE_DEADLINE"), d.get("cd.RELEASE_FAILOPEN")
            if isinstance(arrr, int) and arrr != 0:
                hard.append("D2/D4 normal: ACK_REL_RETIRE should be 0, got %d" % arrr)
            if isinstance(arr, int) and isinstance(responded, int) and arr != responded:
                hard.append("counter mismatch: ACK_RELEASE (%d) != responded (%d)" % (arr, responded))
            if isinstance(rd, int) and isinstance(responded, int) and rd != responded:
                hard.append("counter mismatch: RELEASE_DEADLINE (%d) != responded (%d)" % (rd, responded))
            if isinstance(rf, int) and rf != 0:
                hard.append("D2/D4 normal: RELEASE_FAILOPEN should be 0, got %d" % rf)

    det = {
        "scenario": scenario, "mode": mode, "label": block.get("label"), "protected": protected,
        "n_rows": len(rows), "attempted": attempted, "sent": sent, "responded": responded,
        "missing_ack": missing_ack, "missing_response": missing_resp, "missing_both": missing_both,
        "resp_before_ack": resp_before_ack, "order_inconclusive": inconclusive,
        "dup_ack": dup_ack, "dup_resp": dup_resp, "retransmit": retransmit,
        "rst_polls": rst_polls, "fin_midblock": fin_midblock, "multi_segment_resp": multiseg,
        "late": late, "token_escapes_on_wire": token_escapes, "rearm_ok": rearm_ok,
        "reg_tag_after": tag_after if tag_present else "MISSING",
        "signal_counts": signal_counts,
    }
    det.update({"delta_" + k.replace(".", "_"): v for k, v in d.items()})
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
