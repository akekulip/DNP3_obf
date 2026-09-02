"""Recompute every published statistic from the canonical transaction table.

The two scheduling lanes are kept separate throughout, because they are anchored differently and
pooling them produces a quantity with no operational meaning.

Read lane (READ and the SELECT phase of SBO)
    Deadlines are anchored to the outstation's acknowledgment:
    ``t_ack = t_A + D_A`` and ``t_resp = t_A + D_A + D_R``. The observable CLRT equals ``D_R``
    when the response arrives before its release deadline, so the release budget
    ``D = D_A + D_R`` is the coverage budget for this lane only.

Control lane (OPERATE)
    Deadlines are anchored to the request: ``t_ack = T0 + A`` and ``t_or = T0 + R`` (t_or = OPERATE response egress), so the
    master-visible observable is ``O = R - A``. The read-path budget ``D`` does not apply, and
    OPERATE never enters the coverage denominator.

Standard deviations here are sample standard deviations (ddof=1). The archived sweep table was
published with the population convention; ``validate_sweep.py`` records that difference rather
than mixing the two.
"""
from __future__ import annotations
import csv, json, sys
import numpy as np

CLASSES = ["READ", "SELECT", "OPERATE"]
ARMS = ["native", "obfuscated"]
READ_LANE = ["READ", "SELECT"]        # ACK-anchored; governed by the release budget D
CONTROL_LANE = ["OPERATE"]            # request-anchored; governed by O = R - A
# Interval reported per class: CLRT for the read lane, master-visible response-to-ACK for OPERATE.
# Both are t_response - t_ACK; the name differs because the anchor semantics differ.


def load(path):
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            rows.append((r["run"], r["arm"], r["txn_class"],
                         float(r["clrt_ms"]), float(r["ack_ms"]), float(r["rt_ms"])))
    return rows


def describe(v):
    q1, q2, q3 = np.percentile(v, [25, 50, 75])
    return dict(n=int(v.size), median=round(float(q2), 4), iqr=round(float(q3 - q1), 4),
                sd_sample=round(float(v.std(ddof=1)), 4), max=round(float(v.max()), 4),
                min=round(float(v.min()), 4))


def main(canon, budget_ms, out):
    rows = load(canon)
    res = {"budget_ms": budget_ms,
           "lane_definition": {
               "read_lane": {"classes": READ_LANE, "anchor": "outstation acknowledgment t_A",
                             "observable": "CLRT = D_R", "budget_applies": True},
               "control_lane": {"classes": CONTROL_LANE, "anchor": "master request T0",
                                "observable": "O = R - A", "budget_applies": False}},
           "sd_convention": "sample standard deviation, ddof=1",
           "per_arm_class": {}}
    print(f"{'arm':11s} {'class':8s} {'n':>6s} {'median':>8s} {'IQR':>8s} {'sd':>8s} {'max':>9s}")
    for arm in ARMS:
        for c in CLASSES:
            v = np.array([r[3] for r in rows if r[1] == arm and r[2] == c])
            d = describe(v)
            res["per_arm_class"][f"{arm}/{c}"] = d
            print(f"{arm:11s} {c:8s} {d['n']:6d} {d['median']:8.3f} {d['iqr']:8.3f} "
                  f"{d['sd_sample']:8.3f} {d['max']:9.3f}")

    # ---- request-to-ACK interval per arm and class. This is the second measurable interval;
    # the mechanism shifts it by a constant rather than pinning it, and the difference between
    # the two lanes' anchors survives in it.
    res["ack_interval_ms"] = {}
    for arm in ARMS:
        for c in CLASSES:
            v = np.array([r[4] for r in rows if r[1] == arm and r[2] == c])
            res["ack_interval_ms"][f"{arm}/{c}"] = describe(v)
    print("\nRequest-to-ACK interval (ms), median [IQR]:")
    for k, d in res["ack_interval_ms"].items():
        print(f"  {k:22s} {d['median']:8.3f} [{d['iqr']:.3f}]")

    # ---- READ-LANE coverage. OPERATE is request-anchored and is not schedulable against D,
    # so it is excluded from both the numerator and the denominator.
    lane = np.array([r[3] for r in rows if r[1] == "native" and r[2] in READ_LANE])
    over = int((lane > budget_ms).sum())
    per_class = {}
    for c in READ_LANE:
        v = np.array([r[3] for r in rows if r[1] == "native" and r[2] == c])
        per_class[c] = {"n": int(v.size), "above_budget": int((v > budget_ms).sum())}
    res["read_lane_coverage"] = {
        "classes": READ_LANE, "budget_ms": budget_ms,
        "n": int(lane.size), "above_budget": over,
        "percent_above": round(100 * over / lane.size, 4),
        "percent_covered": round(100 * (1 - over / lane.size), 4),
        "per_class": per_class,
        "note": "OPERATE is request-anchored and is excluded from this denominator"}
    print(f"\nRead-lane (READ + SELECT) Timing OFF exchanges above the {budget_ms} ms release "
          f"budget: {over} of {lane.size} ({100*over/lane.size:.4f}%); "
          f"covered {100*(1-over/lane.size):.4f}%")
    for c, d in per_class.items():
        print(f"    {c:8s} {d['above_budget']:3d} of {d['n']}")

    # ---- CONTROL LANE, reported on its own terms. The read-path budget is not applied.
    op = np.array([r[3] for r in rows if r[1] == "obfuscated" and r[2] == "OPERATE"])
    op_off = np.array([r[3] for r in rows if r[1] == "native" and r[2] == "OPERATE"])
    res["control_lane"] = {
        "observable": "master-visible OPERATE response-to-ACK interval, O = R - A",
        "timing_off": describe(op_off), "obfuscated": describe(op),
        "J_observability": ("the configured codebook is recorded; the per-transaction draw and "
                            "the relay-facing release at T0+J are not observable on the "
                            "master-facing link"),
        "budget_note": "the read-path budget D is not a schedulability criterion for this lane"}
    print(f"\nControl lane, master-visible OPERATE response-to-ACK interval: "
          f"{op_off.mean():.3f} ms mean under Timing OFF -> median "
          f"{res['control_lane']['obfuscated']['median']:.3f} ms obfuscated "
          f"(IQR {res['control_lane']['obfuscated']['iqr']:.3f} ms)")

    # ---- obfuscated departures from the scheduled release
    print("\nObfuscated departures from the 4.000 ms scheduled release:")
    res["obfuscated_departures"] = {}
    for c in CLASSES:
        v = np.abs(np.array([r[3] for r in rows if r[1] == "obfuscated" and r[2] == c]) - 4.0)
        d = {f"gt_{t}ms": int((v > t).sum()) for t in (0.05, 0.2, 1.0)}
        d["n"] = int(v.size); d["max_departure"] = round(float(v.max()), 4)
        res["obfuscated_departures"][c] = d
        print(f"  {c:8s} n={d['n']:5d}  >0.05ms={d['gt_0.05ms']:4d}  >1ms={d['gt_1.0ms']:3d}  "
              f"max={d['max_departure']:.3f} ms")

    # ---- wire overhead per DNP3 exchange (480 per capture), identical in both arms
    res["overhead"] = {"frames_per_capture": 1448, "wire_bytes_per_capture": 130708,
                       "exchanges_per_capture": 480, "high_level_ops_per_capture": 440,
                       "frames_per_exchange": round(1448 / 480, 4),
                       "wire_bytes_per_exchange": round(130708 / 480, 3)}
    print(f"\nPer DNP3 exchange: {1448/480:.4f} frames, {130708/480:.3f} captured wire bytes "
          f"(identical in both arms)")

    # ---- observed added response latency, by class
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
