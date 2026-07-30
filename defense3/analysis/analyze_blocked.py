#!/usr/bin/env python3
"""Block-clustered re-analysis of the D-sweep.

WHY THIS EXISTS. The first analysis treated the 80 transactions in an arm as 80
independent observations. They are not: they come from FOUR TCP connections of 20 polls
each, and polls inside one connection share the relay's scheduler state, the connection's
congestion state, host load and clock drift. The effective replication is 4, not 80.

So every interval here resamples CONNECTIONS (the whole 20-poll block), not transactions,
and every held-out score is leave-one-ROUND-out rather than a single 2/2 split. The point
estimates are unchanged -- this does not re-do the measurement, it puts an honest width
on it.

Usage:  analyze_blocked.py <dsweep_blocks.jsonl> <out.json> [--boot 10000]
        analyze_blocked.py --self-test
"""
import argparse, json, random, statistics as st, sys

ARMS = [("native", None), ("d1", 1), ("d2", 2), ("d4", 4), ("d8", 8), ("d16", 16)]
FEATURES = ("read_to_ack_ms", "clrt_ms", "read_to_resp_ms")


def sep(x, y):
    """Folded AUROC (Mann-Whitney), the same statistic the sweep analysis reports."""
    if not x or not y:
        return float("nan")
    gt = eq = 0
    for a in x:
        for b in y:
            if a > b:
                gt += 1
            elif a == b:
                eq += 1
    a = (gt + 0.5 * eq) / (len(x) * len(y))
    return max(a, 1.0 - a)


def bal_acc(thr, defended, native):
    """Balanced accuracy of the rule 'value > thr => defended'."""
    tpr = sum(1 for v in defended if v > thr) / len(defended)
    tnr = sum(1 for v in native if v <= thr) / len(native)
    return 0.5 * (tpr + tnr)


def best_threshold(defended, native):
    cand = sorted(set(defended) | set(native))
    mids = [(cand[i] + cand[i + 1]) / 2 for i in range(len(cand) - 1)] or cand
    return max(mids, key=lambda t: bal_acc(t, defended, native))


def load(path):
    """-> {arm: [block, block, ...]}, each block a list of per-transaction dicts."""
    by = {}
    for line in open(path):
        r = json.loads(line)
        by.setdefault(r["arm"], []).append(r["block"]["rows"])
    return by


def block_bootstrap(bx, by_, feat, n_boot, rng):
    """Resample WHOLE BLOCKS with replacement from each arm, recompute separability."""
    out = []
    for _ in range(n_boot):
        a = [v for b in (rng.choice(bx) for _ in bx) for v in (r[feat] for r in b)]
        b = [v for b in (rng.choice(by_) for _ in by_) for v in (r[feat] for r in b)]
        out.append(sep(a, b))
    out.sort()
    lo = out[int(0.025 * len(out))]
    hi = out[min(len(out) - 1, int(0.975 * len(out)))]
    return lo, hi


class _RNG:
    def __init__(self, seed): self.r = random.Random(seed)
    def choice(self, seq):    return self.r.choice(seq)


def analyse(path, n_boot=10000, seed=20260730):
    by = load(path)
    rng = _RNG(seed)
    nat_blocks = by["native"]
    res = {"n_boot": n_boot, "seed": seed, "blocks_per_arm": {k: len(v) for k, v in by.items()},
           "note": "intervals resample CONNECTIONS, not transactions", "arms": {}}

    for arm, D in ARMS:
        if arm == "native":
            continue
        blocks = by[arm]
        entry = {"D_ms": D, "n_blocks": len(blocks),
                 "n_txn": sum(len(b) for b in blocks), "features": {}}
        for feat in FEATURES:
            d = [r[feat] for b in blocks for r in b]
            n = [r[feat] for b in nat_blocks for r in b]
            point = sep(d, n)
            lo, hi = block_bootstrap(blocks, nat_blocks, feat, n_boot, rng)
            entry["features"][feat] = {"separability": round(point, 4),
                                       "ci95_block_bootstrap": [round(lo, 4), round(hi, 4)]}
        # leave-one-round-out held-out balanced accuracy on READ->ACK
        loo = []
        for i in range(len(blocks)):
            tr_d = [r["read_to_ack_ms"] for j, b in enumerate(blocks) if j != i for r in b]
            tr_n = [r["read_to_ack_ms"] for j, b in enumerate(nat_blocks) if j != i for r in b]
            te_d = [r["read_to_ack_ms"] for r in blocks[i]]
            te_n = [r["read_to_ack_ms"] for r in nat_blocks[i]]
            thr = best_threshold(tr_d, tr_n)
            loo.append({"held_out_round": i + 1, "threshold_ms": round(thr, 4),
                        "balanced_accuracy": round(bal_acc(thr, te_d, te_n), 4)})
        accs = [x["balanced_accuracy"] for x in loo]
        entry["leave_one_round_out"] = {
            "folds": loo, "mean": round(sum(accs) / len(accs), 4),
            "min": round(min(accs), 4), "max": round(max(accs), 4)}
        res["arms"][arm] = entry

    # the drift floor, also block-resampled: native split into two halves BY BLOCK
    half = len(nat_blocks) // 2
    res["drift_floor_by_block"] = {
        f: round(sep([r[f] for b in nat_blocks[:half] for r in b],
                     [r[f] for b in nat_blocks[half:] for r in b]), 4) for f in FEATURES}

    # the D=16 distribution, stated as a distribution rather than as a constant
    d16 = [r["clrt_ms"] for b in by["d16"] for r in b]
    res["d16_clrt_distribution"] = {
        "n": len(d16), "distinct_values": len(set(round(v, 4) for v in d16)),
        "median_ms": round(st.median(d16), 4), "sd_ms": round(st.pstdev(d16), 4),
        "min_ms": round(min(d16), 4), "max_ms": round(max(d16), 4),
        "within_0.5us_of_median": sum(1 for v in d16 if abs(v - 0.032) < 0.0005),
        "at_or_below_capture_resolution": sum(1 for v in d16 if v <= 0.001)}

    # the fail-open margin, per arm, from the measured ACK latencies
    H_ms = 18000 * 64 / 37.4e6 * 1e3
    res["failopen"] = {"H_ms": round(H_ms, 3), "B": 18000, "K": 64, "rate_pps": 37.4e6,
                       "constraint": "H > a + D + detection + drain + tail", "arms": {}}
    for arm, D in ARMS:
        if D is None:
            continue
        a_max = max(r["read_to_ack_ms"] - D for b in by[arm] for r in b)
        res["failopen"]["arms"][arm] = {
            "D_ms": D, "a_max_ms": round(a_max, 3), "a_plus_D_ms": round(a_max + D, 3),
            "margin": round(H_ms / (a_max + D), 2)}
    res["failopen"]["clamp_check"] = {
        "D_max_ms_configured": 40.0, "H_ms": round(H_ms, 3),
        "feasible": 40.0 + 0.0 < H_ms,
        "note": "at D = D_max the budget expires before the deadline even with a = 0"}
    return res


def self_test():
    """Negative controls: every statistic must be able to fail."""
    fails = []
    if abs(sep([1, 2, 3], [1, 2, 3]) - 0.5) > 1e-9:
        fails.append("sep of identical samples is not 0.5")
    if abs(sep([10, 11], [1, 2]) - 1.0) > 1e-9:
        fails.append("sep of disjoint samples is not 1.0")
    if abs(sep([1, 2], [10, 11]) - 1.0) > 1e-9:
        fails.append("sep is not folded")
    if abs(bal_acc(5, [10, 11], [1, 2]) - 1.0) > 1e-9:
        fails.append("bal_acc of a perfect threshold is not 1.0")
    if abs(bal_acc(0, [10, 11], [1, 2]) - 0.5) > 1e-9:
        fails.append("bal_acc of an all-positive rule is not 0.5")
    r = _RNG(1)
    lo, hi = block_bootstrap([[{"x": 1.0}] * 5] * 4, [[{"x": 1.0}] * 5] * 4, "x", 200, r)
    if not (lo == hi == 0.5):
        fails.append("degenerate bootstrap does not collapse to 0.5")
    lo, hi = block_bootstrap([[{"x": 9.0}] * 5] * 4, [[{"x": 1.0}] * 5] * 4, "x", 200, r)
    if not (lo == hi == 1.0):
        fails.append("separated bootstrap does not collapse to 1.0")
    if fails:
        print("SELF-TEST FAIL"); [print("  -", f) for f in fails]; return 1
    print("SELF-TEST PASS (7 controls)"); return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("blocks", nargs="?")
    ap.add_argument("out", nargs="?")
    ap.add_argument("--boot", type=int, default=10000)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        sys.exit(self_test())
    if not (a.blocks and a.out):
        ap.error("need <blocks.jsonl> <out.json>")
    r = analyse(a.blocks, a.boot)
    json.dump(r, open(a.out, "w"), indent=1)
    print("blocks per arm:", r["blocks_per_arm"])
    print("drift floor (by block):", r["drift_floor_by_block"])
    for arm, e in r["arms"].items():
        f = e["features"]
        print("%-4s D=%-2s  READ->ACK %.3f %s | CLRT %.3f %s | LORO bal.acc mean %.3f (%.3f-%.3f)"
              % (arm, e["D_ms"],
                 f["read_to_ack_ms"]["separability"], f["read_to_ack_ms"]["ci95_block_bootstrap"],
                 f["clrt_ms"]["separability"], f["clrt_ms"]["ci95_block_bootstrap"],
                 e["leave_one_round_out"]["mean"], e["leave_one_round_out"]["min"],
                 e["leave_one_round_out"]["max"]))
    print("D=16 CLRT:", r["d16_clrt_distribution"])
    print("fail-open:", json.dumps(r["failopen"]["arms"]))
    print("clamp feasible:", r["failopen"]["clamp_check"])
