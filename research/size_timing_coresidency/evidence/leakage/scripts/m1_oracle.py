"""M1 -- the perfect-defense oracle (H5).

Replace EVERY size feature and EVERY timing feature with a constant, simulating a
flawless size+timing defense, and re-run the device classifier over the full
realistic passive feature set.  Whatever balanced accuracy survives is the hard
ceiling on the program's achievable benefit.

Also reports:
  * a per-feature-family breakdown,
  * a deterministic (training-free) lookup rule over the TCP-stack signature,
  * a further ladder in which the TCP stack, then ACK mode, are ALSO normalised,
  * the two label sets (real-device flows only vs. real+software-twin pooled),
  * the timing-family missingness confound (NaN(req->ACK) encodes ACK mode).
"""

import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from leakage_lib import (SEED, eval_featureset, balanced_accuracy,
                         cluster_bootstrap_ci, mi_mm, perm_null_flowlabel,
                         joint_key)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")

# NOTE on family hygiene: `sz_resp_ip_bytes` (= sum of 20 + 4*data_offset +
# payload over the response segments) is deliberately NOT in the size family.
# On the wire ip.len = payload + 20 + 4*data_offset, so its device-discriminating
# content beyond the payload length is the TCP *option* length -- a stack
# property.  Leaving it in "size" made the size-only classifier read 0.838
# instead of 0.667 purely by smuggling data_offset across the family boundary.
SIZE = ["sz_req_bytes", "sz_resp_bytes", "sz_n_segments", "sz_first_seg",
        "sz_max_seg", "sz_min_seg", "sz_mean_seg"]
TIMING = ["tm_req_to_first_resp_ms", "tm_req_to_ack_ms", "tm_ack_to_resp_ms",
          "tm_duration_ms", "tm_mean_gap_ms", "tm_max_gap_ms", "tm_gap_prev_req_ms"]
# Timing features that EXIST for every device.  tm_req_to_ack_ms /
# tm_ack_to_resp_ms are defined only for a separate-ACK device, so including
# them lets the "timing" family carry the ACK-mode categorical through its own
# missingness pattern.  This subset is the honest timing-magnitude channel.
TIMING_MAGNITUDE = ["tm_req_to_first_resp_ms", "tm_duration_ms",
                    "tm_mean_gap_ms", "tm_max_gap_ms", "tm_gap_prev_req_ms"]
STACK = ["st_ttl", "st_tos", "st_df", "st_win", "st_dataofs", "st_n_opts",
         "st_sackok", "st_tsopt", "st_opt_kinds_code"]
ACKMODE = ["am_separate_ack", "sz_n_pure_acks"]
DPI = ["dpi_req_fc", "dpi_resp_fc", "dpi_resp_iin", "dpi_resp_nframes",
       "dpi_resp_user_bytes", "dpi_resp_src", "dpi_resp_dst",
       "dpi_resp_fir", "dpi_resp_fin"]


def prepare(df, timing_missing="sentinel"):
    d = df.copy()
    d["st_opt_kinds_code"] = pd.factorize(d["st_opt_kinds"].fillna(""))[0]
    for c in SIZE + TIMING + STACK + ACKMODE + DPI:
        if c not in d:
            d[c] = 0.0
        d[c] = pd.to_numeric(d[c], errors="coerce")
    if timing_missing == "sentinel":
        for c in TIMING:
            d[c] = d[c].fillna(-1.0)
    else:                                   # mask the missingness signal
        for c in TIMING:
            d[c] = d[c].fillna(d[c].median())
    for c in SIZE + STACK + ACKMODE + DPI:
        d[c] = d[c].fillna(-1.0)
    return d


def blanked(d, families):
    """Return a copy where every column of every named family is a constant 0."""
    d = d.copy()
    for fam in families:
        for c in fam:
            d[c] = 0.0
    return d


def run_conditions(d, label_col, tag, results, models=("rf",)):
    y = d[label_col].values
    g = d["flow_id"].values
    conditions = {
        # name                     : (feature list,        blanked families)
        "full_metadata":            (SIZE + TIMING + STACK + ACKMODE, []),
        "ORACLE_size+timing_const": (SIZE + TIMING + STACK + ACKMODE, [SIZE, TIMING]),
        "ORACLE_+stack_const":      (SIZE + TIMING + STACK + ACKMODE, [SIZE, TIMING, STACK]),
        "ORACLE_+ackmode_const":    (SIZE + TIMING + STACK + ACKMODE,
                                     [SIZE, TIMING, STACK, ACKMODE]),
        "size_only":                (SIZE, []),
        "timing_magnitude_only":    (TIMING_MAGNITUDE, []),
        "timing_only":              (TIMING, []),
        "stack_only":               (STACK, []),
        "ackmode_only":             (ACKMODE, []),
        "size+timing_only":         (SIZE + TIMING, []),
        "full_metadata+dpi":        (SIZE + TIMING + STACK + ACKMODE + DPI, []),
        "dpi_only":                 (DPI, []),
    }
    for name, (feats, blanks) in conditions.items():
        dd = blanked(d, blanks) if blanks else d
        X = dd[feats].values
        for m in models:
            r = eval_featureset(X, y, g, model=m, seed=SEED, B=2000)
            r["condition"] = name
            r["labelset"] = tag
            r["features"] = feats
            r["blanked_families"] = [f[0].split("_")[0] for f in blanks]
            results.append(r)
            print("  %-28s %-6s BA=%.4f  CI95=[%.4f, %.4f]  n=%d flows=%d"
                  % (name, m, r["balanced_accuracy"], r["ci95_lo"], r["ci95_hi"],
                     r["n"], r["n_flows"]))
    return results


def deterministic_stack_rule(d, label_col):
    """Training-free identification: is device -> (TTL, data_offset) injective?"""
    sig = list(zip(d["st_ttl"].astype(int), d["st_dataofs"].astype(int)))
    d = d.assign(_sig=sig)
    table = d.groupby("_sig")[label_col].agg(
        lambda s: sorted(set(s))).to_dict()
    counts = d.groupby(["_sig", label_col]).size().unstack(fill_value=0)
    # majority-vote decoder built from the signature table
    decode = counts.idxmax(axis=1).to_dict()
    pred = np.array([decode[s] for s in sig])
    ba = balanced_accuracy(d[label_col].values, pred)
    injective = all(len(v) == 1 for v in table.values())
    return {"signature_to_labels": {str(k): v for k, v in table.items()},
            "injective": bool(injective),
            "balanced_accuracy": float(ba),
            "n": int(len(d))}


def main():
    df = pd.read_csv(os.path.join(OUT, "transactions.csv"))
    results = []
    summary = {"seed": SEED, "n_total_transactions": int(len(df))}

    for tag, sub in [("D-REAL(real device flows only)", df[df.role == "real"]),
                     ("D-ALL(real+software twin pooled)", df)]:
        print("=" * 78)
        print(tag, " n=", len(sub), " flows=", sub.flow_id.nunique())
        d = prepare(sub, timing_missing="sentinel")
        run_conditions(d, "device", tag, results)

        print("  -- timing family with missingness MASKED (median-imputed) --")
        d2 = prepare(sub, timing_missing="median")
        r = eval_featureset(d2[TIMING].values, d2["device"].values,
                            d2["flow_id"].values, model="rf", seed=SEED, B=2000)
        r.update({"condition": "timing_only_missingness_masked", "labelset": tag,
                  "features": TIMING, "blanked_families": []})
        results.append(r)
        print("  %-28s %-6s BA=%.4f  CI95=[%.4f, %.4f]"
              % ("timing_only_masked", "rf", r["balanced_accuracy"],
                 r["ci95_lo"], r["ci95_hi"]))

        summary.setdefault("deterministic_stack_rule", {})[tag] = \
            deterministic_stack_rule(d, "device")

    # sensitivity: other models on the two headline conditions, D-REAL only
    print("=" * 78)
    print("model sensitivity (D-REAL)")
    d = prepare(df[df.role == "real"], timing_missing="sentinel")
    for name, blanks in [("full_metadata", []),
                         ("ORACLE_size+timing_const", [SIZE, TIMING])]:
        dd = blanked(d, blanks) if blanks else d
        X = dd[SIZE + TIMING + STACK + ACKMODE].values
        for m in ("dt", "logreg"):
            r = eval_featureset(X, d["device"].values, d["flow_id"].values,
                                model=m, seed=SEED, B=1000)
            r.update({"condition": name + "|sensitivity", "labelset": "D-REAL",
                      "features": SIZE + TIMING + STACK + ACKMODE,
                      "blanked_families": [f[0].split("_")[0] for f in blanks]})
            results.append(r)
            print("  %-28s %-6s BA=%.4f CI95=[%.4f, %.4f]"
                  % (name, m, r["balanced_accuracy"], r["ci95_lo"], r["ci95_hi"]))

    # information-theoretic version of the oracle, with the exact flow-label null
    print("=" * 78)
    print("MI(stack signature ; device) with exhaustive flow-label permutation null")
    d = prepare(df[df.role == "real"], timing_missing="sentinel")
    label_of_flow = d.groupby("flow_id")["device"].first().to_dict()
    x = joint_key([d["st_ttl"].astype(int), d["st_dataofs"].astype(int),
                   d["st_n_opts"].astype(int)])
    mi_stack = perm_null_flowlabel(x, d["flow_id"].values, label_of_flow, seed=SEED)
    mi_stack["H_device_bits"] = float(mi_mm(d["device"].values, d["device"].values))
    print("  MI=%.4f bits (H(device)=%.4f)  null p95=%.4f  p=%.4f  (%d assignments)"
          % (mi_stack["mi"], mi_stack["H_device_bits"], mi_stack["null_p95"],
             mi_stack["p_value"], mi_stack["B"]))
    summary["mi_stack_vs_device"] = mi_stack

    with open(os.path.join(OUT, "m1_oracle.json"), "w") as fh:
        json.dump({"summary": summary, "results": results}, fh, indent=1)
    print("\nwrote", os.path.join(OUT, "m1_oracle.json"))
    print(json.dumps(summary["deterministic_stack_rule"], indent=1))


if __name__ == "__main__":
    main()
