"""Classify the §5.8 hold-continuity K-sweep trials (ksweep_hold.sh output).

Per trial, from gate2_txn.json:
    hold_ns  = (reg_ts_ack_release - reg_ts_ack_arm) & 0xFFFFFFFF   (32-bit wrap-safe)
    delta_ns = hold_ns - d_realized_ns
Classes:
    CLEAN     RELEASE_DEADLINE == 1, TMO == 0, delta_ns >= -TOL  (deadline-governed;
              expected delta ~= +tau(K) + tail)
    EARLY     delta_ns < -TOL and no fail-open: the reservoir left a gap and
              Q_HOLD was served before the deadline (the coverage failure)
    FAILOPEN  RELEASE_FAILOPEN == 1 or TMO > 0: budget expired first (should not
              happen in this sweep -- B was scaled to clear the deadline)
    INVALID   verdict != COMPLETE, or admitted != K

Prints a per-(D, K) table and writes summary.json next to the manifest.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

TOL_NS = 1000.0


def classify(rec):
    if rec.get("verdict") != "COMPLETE":
        return "INVALID", None, "verdict=%s" % rec.get("verdict")
    k = rec["params"]["k"]
    regs = rec.get("registers", {})
    deq = rec.get("counters", {}).get("deq", {})
    fresh = rec.get("counters", {}).get("fresh", {})
    if fresh.get("PKTGEN_ADMIT") != k:
        return "INVALID", None, "admitted=%s want %d" % (fresh.get("PKTGEN_ADMIT"), k)
    d_ns = rec["params"]["d_realized_ns"]
    hold = (regs.get("reg_ts_ack_release", 0) - regs.get("reg_ts_ack_arm", 0)) & 0xFFFFFFFF
    delta = hold - d_ns
    if deq.get("RELEASE_FAILOPEN", 0) or deq.get("BLOCK_TERM_TMO", 0):
        return "FAILOPEN", delta, "TMO=%s" % deq.get("BLOCK_TERM_TMO")
    if delta < -TOL_NS:
        return "EARLY", delta, "released %.0f ns before the deadline" % -delta
    return "CLEAN", delta, ""


def main(sweep_dir):
    root = Path(sweep_dir)
    rows = []
    for line in open(root / "manifest.jsonl"):
        m = json.loads(line)
        rec_path = root / m["dir"] / "gate2_txn.json"
        if not rec_path.exists():
            rows.append({**m, "cls": "INVALID", "why": "no gate2_txn.json"})
            continue
        rec = json.load(open(rec_path))
        cls, delta, why = classify(rec)
        rows.append({**m, "cls": cls, "delta_ns": delta, "why": why,
                     "stale": rec.get("counters", {}).get("deq", {}).get("BLOCK_TERM_STALE"),
                     "dl": rec.get("counters", {}).get("deq", {}).get("BLOCK_TERM_DL")})

    by = defaultdict(list)
    for r in rows:
        by[(r["d_ms"], r["k"])].append(r)
    print("%6s %4s | %-22s | %s" % ("D(ms)", "K", "classes", "delta_ns per rep"))
    summary = []
    for (d, k) in sorted(by):
        rs = by[(d, k)]
        cls = [r["cls"] for r in rs]
        deltas = [None if r["delta_ns"] is None else round(r["delta_ns"]) for r in rs]
        print("%6s %4s | %-22s | %s" % (d, k, ",".join(cls), deltas))
        summary.append({"d_ms": d, "k": k, "classes": cls, "deltas_ns": deltas,
                        "n_clean": cls.count("CLEAN"), "n": len(rs)})
    # the measured floor per D: smallest K with ALL reps clean, given every larger K clean
    floors = {}
    for d in sorted({s["d_ms"] for s in summary}):
        ks = sorted([s["k"] for s in summary if s["d_ms"] == d])
        ok = {s["k"]: s["n_clean"] == s["n"] for s in summary if s["d_ms"] == d}
        floor = None
        for k in ks:
            if ok[k] and all(ok[k2] for k2 in ks if k2 >= k):
                floor = k
                break
        floors[str(d)] = floor
        print("D=%-3s ms: measured continuity floor K = %s" % (d, floor))
    out = {"rows": rows, "summary": summary, "floors": floors, "tol_ns": TOL_NS}
    with open(root / "summary.json", "w") as f:
        json.dump(out, f, indent=1)
    print("wrote", root / "summary.json")


if __name__ == "__main__":
    main(sys.argv[1])
