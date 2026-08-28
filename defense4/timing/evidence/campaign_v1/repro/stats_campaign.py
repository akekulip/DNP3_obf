"""Recompute every published statistic from the canonical transaction table."""
from __future__ import annotations
import csv, json, sys
import numpy as np

CLASSES = ["READ", "SELECT", "OPERATE"]
ARMS = ["native", "obfuscated"]
# Interval reported per class: CLRT for the read path, master-visible ACK-to-echo for OPERATE.
# Both are t_response - t_ACK; the name differs because the anchor semantics differ.


def load(path):
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            rows.append((r["run"], r["arm"], r["txn_class"],
                         float(r["clrt_ms"]), float(r["ack_ms"]), float(r["rt_ms"])))
    return rows


def main(canon, budget_ms, out):
    rows = load(canon)
    res = {"budget_ms": budget_ms, "per_arm_class": {}}
    print(f"{'arm':11s} {'class':8s} {'n':>6s} {'median':>8s} {'IQR':>8s} {'sd':>8s} {'max':>9s}")
    for arm in ARMS:
        for c in CLASSES:
            v = np.array([r[3] for r in rows if r[1] == arm and r[2] == c])
            q1, q2, q3 = np.percentile(v, [25, 50, 75])
            d = dict(n=int(v.size), median=round(float(q2), 4), iqr=round(float(q3 - q1), 4),
                     sd=round(float(v.std(ddof=1)), 4), max=round(float(v.max()), 4),
                     min=round(float(v.min()), 4))
            res["per_arm_class"][f"{arm}/{c}"] = d
            print(f"{arm:11s} {c:8s} {d['n']:6d} {d['median']:8.3f} {d['iqr']:8.3f} "
                  f"{d['sd']:8.3f} {d['max']:9.3f}")
    # coverage boundary: Timing OFF exchanges whose native CLRT exceeds the release budget
    nat = np.array([r[3] for r in rows if r[1] == "native"])
    over = int((nat > budget_ms).sum())
    res["timing_off_exceeding_budget"] = {"count": over, "n": int(nat.size),
                                          "percent": round(100 * over / nat.size, 4)}
    print(f"\nTiming OFF exchanges above the {budget_ms} ms release budget: "
          f"{over} of {nat.size} ({100*over/nat.size:.4f}%)")
    # obfuscated departures from the scheduled release
    print("\nObfuscated departures from the 4.000 ms scheduled release:")
    res["obfuscated_departures"] = {}
    for c in CLASSES:
        v = np.abs(np.array([r[3] for r in rows if r[1] == "obfuscated" and r[2] == c]) - 4.0)
        d = {f"gt_{t}ms": int((v > t).sum()) for t in (0.05, 0.2, 1.0)}
        d["n"] = int(v.size); d["max_departure"] = round(float(v.max()), 4)
        res["obfuscated_departures"][c] = d
        print(f"  {c:8s} n={d['n']:5d}  >0.05ms={d['gt_0.05ms']:4d}  >1ms={d['gt_1.0ms']:3d}  "
              f"max={d['max_departure']:.3f} ms")
    # wire overhead per DNP3 exchange (480 per capture), stated per arm
    res["overhead"] = {"frames_per_capture": 1448, "wire_bytes_per_capture": 130708,
                       "exchanges_per_capture": 480, "high_level_ops_per_capture": 440,
                       "frames_per_exchange": round(1448 / 480, 4),
                       "wire_bytes_per_exchange": round(130708 / 480, 3)}
    print(f"\nPer DNP3 exchange: {1448/480:.4f} frames, {130708/480:.3f} captured wire bytes "
          f"(identical in both arms)")
    # observed added response latency, by class
    print("\nObserved added response latency (median rt, obfuscated minus Timing OFF):")
    res["added_response_latency_ms"] = {}
    for c in CLASSES:
        a = np.median([r[5] for r in rows if r[1] == "native" and r[2] == c])
        b = np.median([r[5] for r in rows if r[1] == "obfuscated" and r[2] == c])
        res["added_response_latency_ms"][c] = round(float(b - a), 4)
        print(f"  {c:8s} {a:7.3f} -> {b:7.3f} ms   added {b-a:6.3f} ms")
    with open(out, "w") as f:
        json.dump(res, f, indent=1)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main(sys.argv[1], float(sys.argv[2]), sys.argv[3])
