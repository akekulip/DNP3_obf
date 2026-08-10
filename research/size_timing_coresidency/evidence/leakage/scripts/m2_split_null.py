"""M2 -- the split null (H2).

Does CRC-boundary splitting, unpadded, actually reduce leakage?

Runs the EXISTING splitter (`dnp3_split_harness/split_server.py::DNP3CRCSplitter`,
imported read-only, byte-identity assertion active) over every captured response
in the corpus, then compares, native vs split:

  * device-classification balanced accuracy over the size feature family,
  * I(size observable ; native response size)   -- the "secret" the split is
    supposed to hide, with a within-flow block-shift permutation null,
  * I(size observable ; device),                 -- exhaustive flow-label null,

for two observer models:
  A. AGGREGATING observer (realistic): groups packets into transactions and sums.
  B. NON-AGGREGATING observer (bounding case): sees one packet's length only.
"""

import json
import logging
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, "/home/philip/Projects/DNP3/dnp3_split_harness")
import split_server as _ss                                    # noqa: E402
logging.getLogger().setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from leakage_lib import (SEED, eval_featureset, mi_mm, perm_null_block,        # noqa: E402
                         perm_null_flowlabel, stratified_bootstrap_ci,
                         paired_bootstrap_delta, joint_key)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
SPLITTER = _ss.DNP3CRCSplitter()


def chunk_features(chunks):
    n = len(chunks)
    return {"n_segments": n, "total_bytes": int(sum(chunks)),
            "first_seg": chunks[0], "max_seg": max(chunks),
            "min_seg": min(chunks), "mean_seg": float(np.mean(chunks)),
            "last_seg": chunks[-1]}


def build(df, payloads):
    rows = []
    for _, r in df.iterrows():
        raw = bytes.fromhex(payloads[r.txn_id])
        if not raw:
            continue
        base = {"txn_id": r.txn_id, "device": r.device, "flow_id": r.flow_id,
                "role": r.role, "native_size": int(len(raw)),
                "req_bytes": int(r.sz_req_bytes)}
        # native = the wire truth from the capture
        rows.append(dict(base, mode="native", n_segments=int(r.sz_n_segments),
                         total_bytes=int(r.sz_resp_bytes),
                         first_seg=int(r.sz_first_seg), max_seg=int(r.sz_max_seg),
                         min_seg=int(r.sz_min_seg), mean_seg=float(r.sz_mean_seg),
                         last_seg=int(r.sz_resp_bytes) if r.sz_n_segments == 1
                         else int(r.sz_min_seg)))
        for bpc in (1, 2, 4):
            ch = [len(c) for c in SPLITTER.split(raw, bpc)]
            assert sum(ch) == len(raw), "split changed the byte total"
            rows.append(dict(base, mode="split_bpc%d" % bpc, **chunk_features(ch)))
    return pd.DataFrame(rows)


SIZE_FEATS = ["total_bytes", "n_segments", "first_seg", "max_seg", "min_seg",
              "mean_seg", "last_seg", "req_bytes"]


def main():
    df = pd.read_csv(os.path.join(OUT, "transactions.csv"))
    payloads = json.load(open(os.path.join(OUT, "response_payloads.json")))
    real = df[df.role == "real"].reset_index(drop=True)
    S = build(real, payloads)
    S.to_csv(os.path.join(OUT, "m2_split_features.csv"), index=False)

    out = {"seed": SEED, "n_transactions": int(real.shape[0]),
           "byte_identity_assertion": "split_server.DNP3CRCSplitter.split "
                                      "raises unless b''.join(chunks)==data; all "
                                      "%d responses passed" % int(real.shape[0]),
           "modes": {}}

    modes = ["native", "split_bpc1", "split_bpc2", "split_bpc4"]
    base_stat = {}
    for mode in modes:
        M = S[S["mode"] == mode].reset_index(drop=True)
        g = M["flow_id"].values
        label_of_flow = M.groupby("flow_id")["device"].first().to_dict()

        print("=" * 78)
        print(mode, " n=", len(M))

        # ---- observer A: aggregating -------------------------------------
        clf = eval_featureset(M[SIZE_FEATS].values, M["device"].values, g,
                              model="rf", seed=SEED, B=2000)
        print("  device BA (size family, aggregating) = %.4f  CI95=[%.4f, %.4f]"
              % (clf["balanced_accuracy"], clf["ci95_lo"], clf["ci95_hi"]))

        obsA = joint_key([M["total_bytes"].astype(int), M["n_segments"].astype(int)])
        mi_size_A = perm_null_block(obsA, M["native_size"].astype(int).values, g,
                                    B=2000, seed=SEED)
        mi_dev_A = perm_null_flowlabel(obsA, M["flow_id"].values, label_of_flow,
                                       seed=SEED)
        # count-only observable (the "relocated" leak the record predicts)
        mi_count = perm_null_block(M["n_segments"].astype(int).values,
                                   M["native_size"].astype(int).values, g,
                                   B=2000, seed=SEED)

        # ---- observer B: single packet, no aggregation --------------------
        rng = np.random.default_rng(SEED)
        onepkt = []
        for _, r in M.iterrows():
            if r["n_segments"] == 1:
                onepkt.append(int(r["total_bytes"]))
            else:
                # uniformly pick one of the emitted segments; sizes are known
                # exactly only for the split modes, so use first/last/mean set
                cand = [int(r["first_seg"]), int(r["last_seg"]), int(r["max_seg"]),
                        int(r["min_seg"])]
                onepkt.append(int(rng.choice(cand)))
        onepkt = np.array(onepkt)
        mi_size_B = perm_null_block(onepkt, M["native_size"].astype(int).values, g,
                                    B=2000, seed=SEED)

        H_S = mi_mm(M["native_size"].astype(int).values,
                    M["native_size"].astype(int).values)

        def mi_stat(rows):
            return mi_mm(obsA[rows], M["native_size"].astype(int).values[rows])

        lo, hi, _ = stratified_bootstrap_ci(mi_stat, g, B=1000, seed=SEED)

        rec = {
            "n": int(len(M)),
            "device_BA_size_family": clf,
            "H_native_size_bits": float(H_S),
            "MI_obsA_vs_native_size": dict(mi_size_A, ci95_lo=lo, ci95_hi=hi),
            "MI_segment_count_vs_native_size": mi_count,
            "MI_obsA_vs_device": mi_dev_A,
            "MI_single_packet_vs_native_size": mi_size_B,
            "segment_count_distribution":
                M["n_segments"].value_counts().sort_index().to_dict(),
            "total_bytes_equals_native": bool(
                (M["total_bytes"].values == M["native_size"].values).all()),
        }
        out["modes"][mode] = rec
        base_stat[mode] = (obsA, M, g)
        print("  H(native size)                      = %.4f bits" % H_S)
        print("  I(total,count ; native size)        = %.4f bits  (null p95 %.4f, p=%.4f)"
              % (mi_size_A["mi"], mi_size_A["null_p95"], mi_size_A["p_value"]))
        print("  I(segment count ; native size)      = %.4f bits  (null p95 %.4f, p=%.4f)"
              % (mi_count["mi"], mi_count["null_p95"], mi_count["p_value"]))
        print("  I(one packet len ; native size)     = %.4f bits  (null p95 %.4f)"
              % (mi_size_B["mi"], mi_size_B["null_p95"]))
        print("  I(total,count ; device)             = %.4f bits  (null p95 %.4f, p=%.4f)"
              % (mi_dev_A["mi"], mi_dev_A["null_p95"], mi_dev_A["p_value"]))
        print("  total bytes preserved exactly:", rec["total_bytes_equals_native"])

    # ---- paired native-vs-split deltas -----------------------------------
    print("=" * 78)
    print("paired cluster-bootstrap deltas (split - native)")
    nat_obs, nat_M, nat_g = base_stat["native"]
    nat_S = nat_M["native_size"].astype(int).values
    out["paired_deltas"] = {}
    for mode in modes[1:]:
        sp_obs, sp_M, _ = base_stat[mode]
        sp_S = sp_M["native_size"].astype(int).values
        d_mi = paired_bootstrap_delta(lambda r: mi_mm(sp_obs[r], sp_S[r]),
                                      lambda r: mi_mm(nat_obs[r], nat_S[r]),
                                      nat_g, B=1000, seed=SEED)
        out["paired_deltas"][mode + "_minus_native_MI_obsA"] = d_mi
        print("  %-12s dMI = %+.4f bits  CI95=[%+.4f, %+.4f]"
              % (mode, d_mi["mean"], d_mi["ci95_lo"], d_mi["ci95_hi"]))

    with open(os.path.join(OUT, "m2_split_null.json"), "w") as fh:
        json.dump(out, fh, indent=1)
    print("\nwrote", os.path.join(OUT, "m2_split_null.json"))


if __name__ == "__main__":
    main()
