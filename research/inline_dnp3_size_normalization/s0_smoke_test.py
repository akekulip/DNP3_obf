#!/usr/bin/env python3
"""S0 -- offline byte-transform smoke test for in-network DNP3 response size-normalization.

Unprivileged, no switch, no P4. Applies quantile-bucketed UP-ONLY padding to the six replayed
device captures (via the Phase-01 characterization CSV) and measures whether bucketing collapses
the size fingerprint, plus the append-only heavy-tail residual.

Primary readout (per bucket count B):
  * size-only classifier balanced accuracy (grouped CV over the 6 pcaps)  -- adversary-instantiated
  * I(padded_resp_size ; device_label)  Miller-Madow-corrected + permutation null  -- mechanism-independent
  * per-bucket anonymity k, and the heavy-tail residual (fraction of each device in a k=1 bucket)
  * overhead (added bytes; and constant-block-quantized overhead)
Offline correctness-gate subset: G1 (up-only prefix), G2 (constant-block trailer), G9 (no MSS crossing).

Interpreter: system python3 3.8 (sklearn 1.3.2). Deterministic seeds throughout.
"""
import json
import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score

CSV = os.path.join(os.path.dirname(__file__), "..", "..",
                   "dnp3_split_harness", "reports", "ack_trace_characterization.csv")
OUTDIR = os.path.join(os.path.dirname(__file__), "s0_results")
SEED = 20260718
BUCKETS = [None, 1, 2, 4, 8]          # None = native (no padding)
BLOCK_BYTES = 18                      # constant DNP3 filler block on-wire: 16 data octets + 2-octet CRC
MSS = 1460
CHANCE = 1.0 / 3.0


def load():
    df = pd.read_csv(CSV)
    df = df[["device_label", "outstation_ip", "pcap", "req_size", "resp_size"]].copy()
    df = df.dropna(subset=["resp_size", "device_label"])
    df["resp_size"] = df["resp_size"].astype(int)
    df["req_size"] = df["req_size"].astype(int)
    return df


def bucket_targets(sizes, B):
    """Quantile bucket boundaries over the pooled size distribution; pad each member UP to its
    bucket's ceiling (max native size in that bucket). Returns an array of padded sizes."""
    if B is None:
        return sizes.copy()
    if B == 1:
        return np.full_like(sizes, sizes.max())
    # quantile edges; unique to avoid degenerate empty buckets on discrete data
    qs = np.quantile(sizes, np.linspace(0, 1, B + 1))
    edges = np.unique(qs)
    # assign each size to a bucket by the right edge it falls under
    idx = np.digitize(sizes, edges[1:-1], right=True) if len(edges) > 2 else np.zeros_like(sizes)
    padded = sizes.copy()
    for b in np.unique(idx):
        m = idx == b
        padded[m] = sizes[m].max()          # pad up to this bucket's ceiling
    return padded


def block_quantized(original, padded):
    """A CONSTANT-block padder can only add whole blocks -> the reachable padded size is
    original + ceil((target-original)/BLOCK)*BLOCK. Returns the realizable padded size."""
    add = padded - original
    blocks = np.ceil(add / BLOCK_BYTES).astype(int)
    return original + blocks * BLOCK_BYTES


def mutual_information_bits(x, y):
    """Plug-in MI (bits) between discrete x (padded size) and y (device label), Miller-Madow corrected."""
    xs = pd.Series(x).astype("category").cat.codes.values
    ys = pd.Series(y).astype("category").cat.codes.values
    n = len(xs)
    nx, ny = xs.max() + 1, ys.max() + 1
    joint = np.zeros((nx, ny))
    for a, b in zip(xs, ys):
        joint[a, b] += 1
    joint /= n
    px = joint.sum(1, keepdims=True)
    py = joint.sum(0, keepdims=True)
    with np.errstate(divide="ignore", invalid="ignore"):
        terms = joint * (np.log2(joint) - np.log2(px) - np.log2(py))
    mi = np.nansum(terms)
    nonempty = int((joint > 0).sum())
    mi_mm = mi + (nonempty - 1) / (2 * n * np.log(2))   # Miller-Madow bias correction
    return float(mi), float(mi_mm)


def mi_null_band(x, y, reps=1000, seed=SEED):
    rng = np.random.default_rng(seed)
    y = np.asarray(y)
    vals = []
    for _ in range(reps):
        _, mm = mutual_information_bits(x, rng.permutation(y))
        vals.append(mm)
    return float(np.mean(vals)), float(np.percentile(vals, 97.5))


def anonymity(padded, labels):
    """Per padded-size value: which devices occupy it (k), and the heavy-tail residual = fraction of
    each device's responses that land on a size value occupied by only that one device (k==1)."""
    dfp = pd.DataFrame({"s": padded, "d": labels})
    k_by_size = dfp.groupby("s")["d"].nunique()
    k1_sizes = set(k_by_size[k_by_size == 1].index)
    k_vals = k_by_size.values
    residual = {}
    for dev, g in dfp.groupby("d"):
        residual[dev] = round(float(np.mean([s in k1_sizes for s in g["s"]])), 4)
    return {
        "min_k": int(k_vals.min()),
        "mean_k_response_weighted": round(float(dfp["s"].map(k_by_size).mean()), 3),
        "n_size_values": int(len(k_by_size)),
        "n_k1_size_values": int(len(k1_sizes)),
        "heavytail_residual_frac_by_device": residual,
    }


def grouped_cv_balacc(df, feat_cols, seed=SEED, reps=40):
    """Repeated stratified GROUP split: each device has 2 pcaps -> put 1 pcap/device in train, the
    other in test (all 3 classes present both sides). Report mean + [2.5,97.5]% balanced accuracy.
    SMOKE number only (2 groups/device is too few for a CI-bearing claim -- see eval design)."""
    rng = np.random.default_rng(seed)
    devs = sorted(df["device_label"].unique())
    dev_pcaps = {d: sorted(df[df.device_label == d]["pcap"].unique()) for d in devs}
    if any(len(v) < 2 for v in dev_pcaps.values()):
        return {"note": "not enough pcap groups/device for grouped split"}
    accs = []
    for _ in range(reps):
        test_p, train_p = [], []
        for d in devs:
            order = rng.permutation(dev_pcaps[d])
            test_p.append(order[0]); train_p.extend(order[1:])
        tr = df[df["pcap"].isin(train_p)]
        te = df[df["pcap"].isin(test_p)]
        clf = RandomForestClassifier(n_estimators=200, random_state=0)
        clf.fit(tr[feat_cols].values, tr["device_label"].values)
        pred = clf.predict(te[feat_cols].values)
        accs.append(balanced_accuracy_score(te["device_label"].values, pred))
    accs = np.array(accs)
    return {"mean": round(float(accs.mean()), 4),
            "ci95": [round(float(np.percentile(accs, 2.5)), 4),
                     round(float(np.percentile(accs, 97.5)), 4)],
            "chance": round(CHANCE, 4)}


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    df = load()
    labels = df["device_label"].values
    sizes = df["resp_size"].values.astype(int)
    reqs = df["req_size"].values.astype(int)

    results = {"dataset": {"n": int(len(df)),
                           "devices": df["device_label"].value_counts().to_dict(),
                           "native_resp_size_by_device": {
                               d: sorted(g.resp_size.unique().tolist())
                               for d, g in df.groupby("device_label")},
                           "block_bytes": BLOCK_BYTES, "seed": SEED},
               "by_bucket": []}

    print("=" * 78)
    print("S0 OFFLINE SMOKE TEST -- DNP3 response size-normalization (read-response traces)")
    print("=" * 78)
    print("n=%d  devices=%s" % (len(df), results["dataset"]["devices"]))
    print("native resp_size by device: %s" % results["dataset"]["native_resp_size_by_device"])
    print("-" * 78)
    print("%-8s %-18s %-14s %-10s %-22s %s" %
          ("B", "size-only bal-acc", "MI_bits(MM)", "MI_null97.5", "anon min_k / k1-vals", "mean/max add B"))

    for B in BUCKETS:
        padded = bucket_targets(sizes, B)
        padded_q = block_quantized(sizes, padded)          # constant-block-realizable
        df2 = df.copy()
        df2["padded"] = padded
        df2["padded_q"] = padded_q

        # --- privacy: classifier on [req_size, padded_resp_size] ---
        feat = np.column_stack([reqs, padded])
        cv = grouped_cv_balacc(pd.DataFrame({"pcap": df["pcap"].values,
                                             "device_label": labels,
                                             "f0": reqs, "f1": padded}),
                               ["f0", "f1"])
        # --- privacy: mutual information (mechanism-independent) ---
        mi, mi_mm = mutual_information_bits(padded, labels)
        nmean, n975 = mi_null_band(padded, labels)
        anon = anonymity(padded, labels)
        # --- privacy on the CONSTANT-BLOCK-REALIZABLE sizes (granular padder) ---
        _, mi_mm_q = mutual_information_bits(padded_q, labels)
        cv_q = grouped_cv_balacc(pd.DataFrame({"pcap": df["pcap"].values,
                                               "device_label": labels,
                                               "f0": reqs, "f1": padded_q}),
                                 ["f0", "f1"])
        anon_q = anonymity(padded_q, labels)
        # --- overhead ---
        add = padded - sizes
        add_q = padded_q - sizes
        # --- gates ---
        g1 = bool(np.all(padded >= sizes))                       # up-only prefix invariant
        g2 = bool(np.all((add_q % BLOCK_BYTES) == 0))            # constant-block trailer realizable
        g9 = bool(np.all(padded_q <= MSS))                       # no MSS crossing -> no new segment

        row = {"B": ("native" if B is None else B),
               "size_only_balacc": cv,
               "mi_bits_plugin": round(mi, 4), "mi_bits_mm": round(mi_mm, 4),
               "mi_null_mean": round(nmean, 4), "mi_null_p975": round(n975, 4),
               "mi_above_null": bool(mi_mm > n975),
               "constant_block_realizable": {"mi_bits_mm": round(mi_mm_q, 4),
                                             "size_only_balacc": cv_q,
                                             "anonymity": anon_q,
                                             "padded_size_values": sorted(np.unique(padded_q).tolist())},
               "anonymity": anon,
               "overhead_added_bytes": {"mean": round(float(add.mean()), 2),
                                        "p95": int(np.percentile(add, 95)),
                                        "max": int(add.max())},
               "overhead_block_quantized": {"mean": round(float(add_q.mean()), 2),
                                            "max": int(add_q.max())},
               "padded_size_values": sorted(np.unique(padded).tolist()),
               "gates": {"G1_up_only": g1, "G2_constant_block": g2, "G9_no_mss_crossing": g9}}
        results["by_bucket"].append(row)

        bacc = cv.get("mean", None)
        baccs = ("%.3f" % bacc) if bacc is not None else "n/a"
        bacc_q = cv_q.get("mean", None)
        baccs_q = ("%.3f" % bacc_q) if bacc_q is not None else "n/a"
        print("%-8s ideal:balacc=%-6s MI=%-8.4f | block:balacc=%-6s MI=%-8.4f | k(ideal)=%d k1=%d | add mean/max=%.1f/%d" %
              (str("native" if B is None else B), baccs, mi_mm, baccs_q, mi_mm_q,
               anon["min_k"], anon["n_k1_size_values"], add.mean(), int(add.max())))

    with open(os.path.join(OUTDIR, "s0_results.json"), "w") as f:
        json.dump(results, f, indent=2)
    print("-" * 78)
    print("wrote %s" % os.path.join(OUTDIR, "s0_results.json"))
    return results


if __name__ == "__main__":
    main()
