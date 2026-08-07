#!/usr/bin/env python3
"""Score one bring-up transaction. Emits ONE compact JSON line to stdout.

argv: <txn_index> <mode> <strict 0|1> <ev_pre.json> <ev_post.json> <block.json>

Evidence semantics (from the frozen Defense 3 reader notes):
  - pktgen.pkt_counter and cf_pktgen_admit are CUMULATIVE: this txn's contribution is
    post-minus-pre. A D4 seed emits 2K=128 tokens and admits all 128.
  - queue watermark_cells is LATCHED / one-way (max occupancy ever seen). It can prove a
    queue WAS occupied (watermark>0), never that it is now empty. For THIS txn we require a
    strict INCREASE (post>pre) to attribute occupancy to this transaction.
  - drop_count_packets is cumulative; any increase this txn is a TM drop -> hard abort.
  - block.rows[0].ack_before_resp is the WIRE proof that the ACK (qid6) left before the
    RESPONSE (qid4). false => RESPONSE-before-ACK (immediate rollback trigger).
"""
import json, sys


def load(p):
    try:
        with open(p) as f:
            t = f.read().strip()
        return json.loads(t) if t else None
    except Exception:
        return None


def qwm(ev, qid):
    try:
        return ev["queues"]["qid%d" % qid]["watermark_cells"]
    except Exception:
        return None


def qdrop(ev, qid):
    try:
        return ev["queues"]["qid%d" % qid]["drop_count_packets"]
    except Exception:
        return None


def num(x):
    return x if isinstance(x, (int, float)) else None


def main():
    txn = int(sys.argv[1]); mode = sys.argv[2]; strict = sys.argv[3] == "1"
    pre = load(sys.argv[4]); post = load(sys.argv[5]); blk = load(sys.argv[6])
    r = {"txn": txn, "mode": mode, "strict": strict, "strict_pass": None, "hard_abort": False,
         "notes": []}

    # ---- switch-side deltas -------------------------------------------------
    def delta(key_pre, key_post):
        a = num(key_pre); b = num(key_post)
        return None if (a is None or b is None) else (b - a)

    pkt_d = adm_d = None
    if pre and post:
        pkt_d = delta((pre.get("pktgen") or {}).get("pkt_counter"),
                      (post.get("pktgen") or {}).get("pkt_counter"))
        adm_d = delta(pre.get("cf_pktgen_admit"), post.get("cf_pktgen_admit"))
    r["pktgen_pkt_delta"] = pkt_d
    r["cf_pktgen_admit_delta"] = adm_d

    # per-queue watermark increase + drop increase
    qinfo = {}
    for qid in (7, 6, 5, 4):
        wpre, wpost = num(qwm(pre, qid)), num(qwm(post, qid))
        dpre, dpost = num(qdrop(pre, qid)), num(qdrop(post, qid))
        winc = None if (wpre is None or wpost is None) else (wpost - wpre)
        dinc = None if (dpre is None or dpost is None) else (dpost - dpre)
        qinfo["qid%d" % qid] = {"wm_pre": wpre, "wm_post": wpost, "wm_inc": winc, "drop_inc": dinc}
        if isinstance(dinc, int) and dinc > 0:
            r["hard_abort"] = True
            r["notes"].append("TM drop on qid%d (+%d)" % (qid, dinc))
    r["queues"] = qinfo

    # ---- wire evidence ------------------------------------------------------
    rows = (blk or {}).get("rows") or []
    responded = (blk or {}).get("responded")
    r["responded"] = responded
    ack_before_resp = clrt = r2r = None
    if rows:
        row = rows[0]
        ack_before_resp = row.get("ack_before_resp")
        clrt = row.get("clrt_ms"); r2r = row.get("read_to_resp_ms")
    r["ack_before_resp"] = ack_before_resp
    r["clrt_ms"] = clrt
    r["read_to_resp_ms"] = r2r

    protected = mode not in ("OFF", "FAIL_OPEN")
    # RESPONSE-before-ACK on a protected txn -> immediate rollback trigger
    if protected and ack_before_resp is False:
        r["hard_abort"] = True
        r["notes"].append("RESPONSE observed before ACK (ordering violation)")
    # a protected txn that never got a response -> possible unbounded hold / escape
    if protected and responded == 0:
        r["hard_abort"] = True
        r["notes"].append("no RESPONSE returned for a protected txn (possible unbounded hold)")

    # ---- strict check on the FIRST protected READ --------------------------
    if strict:
        checks = {
            "pktgen_pkt_delta==128": pkt_d == 128,
            "cf_pktgen_admit_delta==128": adm_d == 128,
            "qid7_watermark_increased": isinstance(qinfo["qid7"]["wm_inc"], int) and qinfo["qid7"]["wm_inc"] > 0,
            "qid5_watermark_increased": isinstance(qinfo["qid5"]["wm_inc"], int) and qinfo["qid5"]["wm_inc"] > 0,
            "qid4_watermark_increased_held": isinstance(qinfo["qid4"]["wm_inc"], int) and qinfo["qid4"]["wm_inc"] > 0,
            "ack_before_resp_true": ack_before_resp is True,
            "no_tm_drops": all((qinfo["qid%d" % q]["drop_inc"] in (0, None)) for q in (7, 6, 5, 4))
                           and not any(isinstance(qinfo["qid%d" % q]["drop_inc"], int) and qinfo["qid%d" % q]["drop_inc"] > 0 for q in (7, 6, 5, 4)),
        }
        r["strict_checks"] = checks
        r["strict_pass"] = all(checks.values())

    print(json.dumps(r, default=str))


if __name__ == "__main__":
    main()
