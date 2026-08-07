#!/usr/bin/env python3
"""B4 campaign scorer: correctness detections over one campaign block.

Consumes the sustained driver's block JSON (rows + token_escapes_on_wire) and the switch-side
pre/post evidence dumps, and reports every anomaly class the overnight spec requires. This is a
CORRECTNESS detector, not the distributional analysis (that is D6). It never rewrites a failure:
a detected anomaly is reported, and hard anomalies set verdict=ATTENTION.

  python3 score_campaign.py <block.json> <ev_pre.json> <ev_post.json> [expected_protected]
"""
import json, sys


def load(p):
    try:
        with open(p) as f:
            t = f.read().strip()
        return json.loads(t) if t else {}
    except Exception:
        return {}


def cdelta(pre, post, group, name):
    a = (pre.get(group) or {}).get(name)
    b = (post.get(group) or {}).get(name)
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return b - a
    return None


def main():
    block = load(sys.argv[1]); pre = load(sys.argv[2]); post = load(sys.argv[3])
    expected_protected = int(sys.argv[4]) if len(sys.argv) > 4 else None
    rows = block.get("rows") or []
    mode = block.get("mode", "?")
    protected = mode not in ("OFF", "FAIL_OPEN", "?")

    det = {"mode": mode, "n_rows": len(rows), "responded": block.get("responded"),
           "attempted": block.get("attempted"), "sent": block.get("sent")}

    # ---- per-poll wire anomalies ----
    det["missing_ack"] = [r["poll"] for r in rows if r.get("t_resp") is not None and r.get("t_ack") is None]
    det["missing_response"] = [r["poll"] for r in rows if r.get("t_resp") is None]
    det["resp_before_ack"] = [r["poll"] for r in rows
                              if isinstance(r.get("clrt_ms"), (int, float)) and r["clrt_ms"] < 0]
    det["order_inconclusive"] = [r["poll"] for r in rows if r.get("order_inconclusive") is True]
    det["dup_ack"] = [r["poll"] for r in rows if r.get("dup_ack", 0) > 0]
    det["dup_resp"] = [r["poll"] for r in rows if r.get("dup_resp", 0) > 0]
    det["retransmit"] = [r["poll"] for r in rows if r.get("retransmit", 0) > 0]
    det["tcp_reset"] = [r["poll"] for r in rows if r.get("rst")]
    det["fin"] = [r["poll"] for r in rows if r.get("fin")]
    det["multi_segment_resp"] = [r["poll"] for r in rows if r.get("resp_segments", 0) > 1]

    # ---- token / EtherType escape (wire + counter) ----
    det["token_escapes_on_wire"] = block.get("token_escapes_on_wire")
    det["cf_block_reject_delta"] = cdelta(pre, post, "cf", "BLOCK_REJECT")  # R3: fresh 0x88C1 rejected (good)

    # ---- TM drops (per-queue + port level) ----
    qd = {}
    for q in ("qid7", "qid6", "qid5", "qid4"):
        a = ((pre.get("queues") or {}).get(q) or {}).get("drop_count_packets")
        b = ((post.get("queues") or {}).get(q) or {}).get("drop_count_packets")
        if isinstance(a, int) and isinstance(b, int) and b - a != 0:
            qd[q] = b - a
    det["queue_drop_deltas"] = qd
    pd = {}
    for tname in (pre.get("port_tm_drops") or {}):
        a = (pre.get("port_tm_drops") or {}).get(tname)
        b = (post.get("port_tm_drops") or {}).get(tname)
        if isinstance(a, int) and isinstance(b, int) and b - a != 0:
            pd[tname] = b - a
    det["port_drop_deltas"] = pd

    # ---- release causes + arming (from ctr_deq / ctr_fresh) ----
    det["deadline_release_delta"] = cdelta(pre, post, "cd", "RELEASE_DEADLINE")
    det["failopen_release_delta"] = cdelta(pre, post, "cd", "RELEASE_FAILOPEN")
    det["block_term_tmo_delta"] = cdelta(pre, post, "cd", "BLOCK_TERM_TMO")
    det["block_term_stale_delta"] = cdelta(pre, post, "cd", "BLOCK_TERM_STALE")
    det["ack_release_delta"] = cdelta(pre, post, "cd", "ACK_RELEASE")        # RESPONSE was pending
    det["ack_rel_retire_delta"] = cdelta(pre, post, "cd", "ACK_REL_RETIRE")  # nothing pending, ACK retired txn
    det["arm_fresh_delta"] = cdelta(pre, post, "cf", "ARM_FRESH")
    det["ack_reject_delta"] = cdelta(pre, post, "cf", "ACK_REJECT")
    det["pktgen_admit_delta"] = cdelta(pre, post, "cf", "PKTGEN_ADMIT")
    # RESPONSE disposition: held early (before ACK release), held late (after), or bypassed
    det["resp_hold_early_delta"] = cdelta(pre, post, "cf", "RESP_HOLD_EARLY")
    det["resp_hold_late_delta"] = cdelta(pre, post, "cf", "RESP_HOLD_LATE")
    det["resp_bypass_delta"] = cdelta(pre, post, "cf", "RESP_BYPASS")

    # ---- stale state after completion + next-arm ability ----
    tag_after = (post.get("regs") or {}).get("reg_tag")
    det["stale_reg_tag_after"] = (tag_after not in (0, None))
    det["reg_tag_after"] = tag_after
    # re-arm evidence: protected polls should each charge ARM_FRESH
    if protected and expected_protected is not None and isinstance(det["arm_fresh_delta"], int):
        det["rearm_ok"] = det["arm_fresh_delta"] >= expected_protected
    else:
        det["rearm_ok"] = None

    # ---- verdict: hard anomalies vs expected/soft ----
    hard = []
    if det["resp_before_ack"]:
        hard.append("RESPONSE-before-ACK")
    if qd:
        hard.append("queue TM drops")
    if pd:
        hard.append("port TM drops")
    if det["token_escapes_on_wire"]:
        hard.append("0x88C1 token escaped to the wire")
    if det["stale_reg_tag_after"]:
        hard.append("stale reg_tag after block")
    if protected and det["missing_response"] and mode not in ("D1",):
        hard.append("missing RESPONSE on a protected non-D1 block")
    if det["rearm_ok"] is False:
        hard.append("insufficient re-arm (ARM_FRESH)")
    # The RESPONSE-deadline modes D2 and D4 MUST hold every RESPONSE (early, late, or the measured
    # after-T_RESP path), so any RESP_BYPASS there is the unplanned bypass the lifecycle defect
    # produced -- a hard failure, the check the old scorer lacked. D3 (D_R=0, ACK-only) legitimately
    # forwards a RESPONSE that arrives after the ACK deadline, and D1 (event) bypass is the separate
    # missing-RESPONSE fail-open; neither is a must-hold violation, so they are not flagged here.
    if mode in ("D2", "D4") and isinstance(det["resp_bypass_delta"], int) and det["resp_bypass_delta"] > 0:
        hard.append("unplanned RESPONSE bypass on %s (%d) -- must hold" % (mode, det["resp_bypass_delta"]))
    det["hard_anomalies"] = hard
    det["verdict"] = "ATTENTION" if hard else "clean"

    print(json.dumps(det, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
