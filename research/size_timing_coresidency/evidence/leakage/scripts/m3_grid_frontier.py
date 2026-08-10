"""M3 -- the quantised grid frontier (H1).

Transform every captured response into K segments of exactly c bytes with the
tail padded up, and sweep (c, K).

Two emission policies:

  adaptive-K : K = ceil(L / c).  The grid quantises the byte dimension but the
               segment COUNT still moves with L, so K is the residual observable.
  fixed-K    : K = K_fix >= ceil(L_max / c) for every response.  The emitted
               shape is constant by construction; leakage is zero and the whole
               question is what the byte overhead costs.

Readouts per (policy, c, K):
  * mean / max / p95 added bytes and relative overhead
  * I(emitted shape ; native response size)   -- within-flow block-shift null
  * I(emitted shape ; device)                 -- exhaustive flow-label null
  * device balanced accuracy over the emitted size features (LOFO CV)
  * anonymity k = min over emitted shapes of the number of DEVICES sharing it,
    and the count of transactions in the rarest shape

Then a Pareto frontier (overhead vs residual MI) with a Kneedle-style
max-distance-to-chord knee, or a documented absence of one.
"""

import json
import math
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from leakage_lib import (SEED, eval_featureset, mi_mm, perm_null_block,
                         perm_null_flowlabel, joint_key,
                         stratified_bootstrap_ci)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")

C_GRID = [16, 18, 24, 32, 36, 48, 54, 61, 64, 72, 96, 128, 192, 256]


def emitted(L, c, policy, k_fix=None):
    """Return (K, total_emitted_bytes) for one response of L payload bytes."""
    k_min = max(1, math.ceil(L / c))
    K = k_min if policy == "adaptive" else k_fix
    if K < k_min:
        return None
    return K, K * c


def frontier_row(M, c, policy, k_fix=None):
    L = M["native_size"].astype(int).values
    res = [emitted(int(x), c, policy, k_fix) for x in L]
    if any(r is None for r in res):
        return None
    K = np.array([r[0] for r in res])
    tot = np.array([r[1] for r in res])
    add = tot - L
    g = M["flow_id"].values
    label_of_flow = M.groupby("flow_id")["device"].first().to_dict()

    shape = joint_key([K, np.full(len(K), c)])
    mi_size = perm_null_block(shape, L, g, B=1000, seed=SEED)
    mi_dev = perm_null_flowlabel(shape, g, label_of_flow, seed=SEED)

    X = np.column_stack([tot, K, np.full(len(K), c),
                         M["req_bytes"].astype(int).values])
    clf = eval_featureset(X, M["device"].values, g, model="rf", seed=SEED, B=500)

    # anonymity: devices per emitted shape, and rarest shape occupancy
    tmp = pd.DataFrame({"shape": shape, "device": M["device"].values})
    per_shape = tmp.groupby("shape")["device"].nunique()
    occ = tmp.groupby("shape").size()

    return {
        "policy": policy, "c": c, "K": (None if policy == "adaptive" else k_fix),
        "n": int(len(L)),
        "mean_added_bytes": float(add.mean()),
        "p95_added_bytes": float(np.percentile(add, 95)),
        "max_added_bytes": int(add.max()),
        "mean_overhead_pct": float(100.0 * add.sum() / L.sum()),
        "mean_emitted_bytes": float(tot.mean()),
        "n_distinct_shapes": int(len(per_shape)),
        "anonymity_k_devices": int(per_shape.min()),
        "rarest_shape_txns": int(occ.min()),
        "frac_txns_in_k1_shapes": float(
            occ[per_shape[occ.index] == 1].sum() / len(L)),
        "MI_shape_vs_native_size_bits": mi_size["mi"],
        "MI_shape_vs_native_size_null_p95": mi_size["null_p95"],
        "MI_shape_vs_native_size_p": mi_size["p_value"],
        "MI_shape_vs_device_bits": mi_dev["mi"],
        "MI_shape_vs_device_null_p95": mi_dev["null_p95"],
        "MI_shape_vs_device_p": mi_dev["p_value"],
        "device_BA": clf["balanced_accuracy"],
        "device_BA_ci95_lo": clf["ci95_lo"],
        "device_BA_ci95_hi": clf["ci95_hi"],
    }


def knee(points):
    """Kneedle-style max perpendicular distance to the chord of a sorted
    (x=overhead, y=leakage) frontier.  Returns None when the frontier has fewer
    than 3 distinct interior points (i.e. no knee can exist)."""
    pts = sorted(points, key=lambda p: p[0])
    if len(pts) < 3:
        return None
    x = np.array([p[0] for p in pts], dtype=float)
    y = np.array([p[1] for p in pts], dtype=float)
    if x.max() == x.min() or y.max() == y.min():
        return None
    xn = (x - x.min()) / (x.max() - x.min())
    yn = (y - y.min()) / (y.max() - y.min())
    # distance to the chord from (0,1) to (1,0) style decreasing frontier
    d = np.abs(yn - (1 - xn)) / math.sqrt(2)
    i = int(np.argmax(d))
    if i in (0, len(pts) - 1):
        return None
    return {"index": i, "x_overhead": float(x[i]), "y_leakage": float(y[i]),
            "distance_to_chord": float(d[i]), "point": pts[i][2]}


def main():
    df = pd.read_csv(os.path.join(OUT, "transactions.csv"))
    pay = json.load(open(os.path.join(OUT, "response_payloads.json")))
    real = df[df.role == "real"].reset_index(drop=True)
    M = pd.DataFrame({
        "txn_id": real.txn_id, "device": real.device, "flow_id": real.flow_id,
        "native_size": [len(bytes.fromhex(pay[t])) for t in real.txn_id],
        "req_bytes": real.sz_req_bytes.astype(int),
    })
    Lmax = int(M.native_size.max())
    print("n=%d  native sizes: %s  Lmax=%d"
          % (len(M), M.native_size.value_counts().sort_index().to_dict(), Lmax))
    H_size = mi_mm(M.native_size.values, M.native_size.values)
    print("H(native response size) = %.4f bits" % H_size)

    rows = []
    # native reference
    g = M["flow_id"].values
    label_of_flow = M.groupby("flow_id")["device"].first().to_dict()
    nat_shape = M.native_size.astype(int).values
    nat_mi_size = perm_null_block(nat_shape, nat_shape, g, B=1000, seed=SEED)
    nat_mi_dev = perm_null_flowlabel(nat_shape, g, label_of_flow, seed=SEED)
    nat_clf = eval_featureset(
        np.column_stack([nat_shape, np.ones(len(M)), M.req_bytes.values]),
        M.device.values, g, model="rf", seed=SEED, B=500)
    rows.append({"policy": "native", "c": None, "K": None, "n": int(len(M)),
                 "mean_added_bytes": 0.0, "p95_added_bytes": 0.0,
                 "max_added_bytes": 0, "mean_overhead_pct": 0.0,
                 "mean_emitted_bytes": float(M.native_size.mean()),
                 "n_distinct_shapes": int(M.native_size.nunique()),
                 "anonymity_k_devices": int(
                     M.groupby("native_size")["device"].nunique().min()),
                 "rarest_shape_txns": int(M.groupby("native_size").size().min()),
                 "frac_txns_in_k1_shapes": float(
                     M.groupby("native_size").size()[
                         M.groupby("native_size")["device"].nunique() == 1].sum()
                     / len(M)),
                 "MI_shape_vs_native_size_bits": nat_mi_size["mi"],
                 "MI_shape_vs_native_size_null_p95": nat_mi_size["null_p95"],
                 "MI_shape_vs_native_size_p": nat_mi_size["p_value"],
                 "MI_shape_vs_device_bits": nat_mi_dev["mi"],
                 "MI_shape_vs_device_null_p95": nat_mi_dev["null_p95"],
                 "MI_shape_vs_device_p": nat_mi_dev["p_value"],
                 "device_BA": nat_clf["balanced_accuracy"],
                 "device_BA_ci95_lo": nat_clf["ci95_lo"],
                 "device_BA_ci95_hi": nat_clf["ci95_hi"]})

    for c in C_GRID:
        r = frontier_row(M, c, "adaptive")
        if r:
            rows.append(r)
            print("adaptive c=%-4d overhead=%7.2f B (%6.1f%%)  MI(shape;L)=%.4f "
                  "(null p95 %.4f)  MI(shape;dev)=%.4f  BA=%.4f  k=%d"
                  % (c, r["mean_added_bytes"], r["mean_overhead_pct"],
                     r["MI_shape_vs_native_size_bits"],
                     r["MI_shape_vs_native_size_null_p95"],
                     r["MI_shape_vs_device_bits"], r["device_BA"],
                     r["anonymity_k_devices"]))
    for c in C_GRID:
        kfix = math.ceil(Lmax / c)
        r = frontier_row(M, c, "fixed", k_fix=kfix)
        if r:
            rows.append(r)
            print("fixed    c=%-4d K=%-3d overhead=%7.2f B (%6.1f%%)  "
                  "MI(shape;L)=%.4f  MI(shape;dev)=%.4f  BA=%.4f"
                  % (c, kfix, r["mean_added_bytes"], r["mean_overhead_pct"],
                     r["MI_shape_vs_native_size_bits"],
                     r["MI_shape_vs_device_bits"], r["device_BA"]))

    F = pd.DataFrame(rows)
    F.to_csv(os.path.join(OUT, "m3_grid_frontier.csv"), index=False)

    # Pareto frontier + knee, over the adaptive family (the only one with a
    # leakage/overhead trade-off; fixed-K is leakage-free by construction).
    ad = F[F.policy == "adaptive"].copy()
    pts = []
    for _, r in ad.sort_values("mean_added_bytes").iterrows():
        if not pts or r["MI_shape_vs_native_size_bits"] < pts[-1][1]:
            pts.append((r["mean_added_bytes"], r["MI_shape_vs_native_size_bits"],
                        {"c": int(r["c"])}))
    kn = knee(pts)
    print("\nPareto points (overhead B, MI bits, c):")
    for p in pts:
        print("   %8.2f  %.4f  c=%d" % (p[0], p[1], p[2]["c"]))
    print("knee:", kn)

    summary = {
        "seed": SEED, "n": int(len(M)), "H_native_size_bits": float(H_size),
        "Lmax": Lmax,
        "native_size_distribution": {int(k): int(v) for k, v in
                                     M.native_size.value_counts().items()},
        "pareto_points": [{"overhead_B": p[0], "MI_bits": p[1], **p[2]} for p in pts],
        "knee": kn,
        "zero_leakage_min_overhead": {
            "adaptive": (None if ad[ad.MI_shape_vs_native_size_bits <=
                                    ad.MI_shape_vs_native_size_null_p95].empty
                         else float(ad[ad.MI_shape_vs_native_size_bits <=
                                       ad.MI_shape_vs_native_size_null_p95]
                                    .mean_added_bytes.min())),
            "fixed": float(F[F.policy == "fixed"].mean_added_bytes.min()),
        },
    }
    with open(os.path.join(OUT, "m3_grid_frontier.json"), "w") as fh:
        json.dump({"summary": summary, "rows": rows}, fh, indent=1)
    print("\nwrote", os.path.join(OUT, "m3_grid_frontier.json"))


if __name__ == "__main__":
    main()
