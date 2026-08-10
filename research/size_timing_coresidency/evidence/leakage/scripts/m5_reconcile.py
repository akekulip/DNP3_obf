"""M5 -- reconciliation of the 0.99 vs 0.493 size-classifier contradiction.

`research/inline_dnp3_size_normalization/research_design.md:54-55` reports a
size-only classifier at ~0.99.
`research/ibspg_dnp3_replay/PANEL_SYNTHESIS_WAY_FORWARD.md:38` reports size at
0.493 against a 0.333 chance line.

This script settles it by (a) computing the analytic Bayes-optimal balanced
accuracy of ANY size-only device classifier on this corpus -- the number no
classifier can beat -- and (b) reproducing the prior 2-feature classifier under
both the prior capture-level split and leave-one-flow-out CV.

The 0.99 side is settled by provenance, not by re-measurement: it is traced to a
regression R-squared on a different dataset with a different secret (see the
module docstring output).
"""

import itertools
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from leakage_lib import (SEED, eval_featureset, balanced_accuracy,
                         cluster_bootstrap_ci, make_model, mi_mm)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")


def bayes_optimal_ba(df, obs_cols):
    """Balanced-accuracy-optimal decision rule under a balanced class prior.

    For balanced accuracy the optimal decision at an observation o is
    argmax_c P(o | c) (class-conditional likelihood, equal priors).  Whatever a
    classifier achieves, it cannot exceed this.
    """
    devices = sorted(df.device.unique())
    obs = df[obs_cols].astype(int).apply(tuple, axis=1)
    d = df.assign(_o=obs)
    cond = {}
    for c in devices:
        sub = d[d.device == c]
        cond[c] = (sub["_o"].value_counts() / len(sub)).to_dict()
    rule = {}
    for o in d["_o"].unique():
        rule[o] = max(devices, key=lambda c: cond[c].get(o, 0.0))
    pred = np.array([rule[o] for o in d["_o"]])
    per_class = {c: float(np.mean(pred[d.device.values == c] == c)) for c in devices}
    return {"balanced_accuracy": float(np.mean(list(per_class.values()))),
            "per_class_recall": per_class,
            "decision_rule": {str(k): v for k, v in rule.items()},
            "observation": obs_cols,
            "n": int(len(d))}


def capture_level_split(df, feats, seed=SEED):
    """The prior scheme: train on the base pcaps, test on the L pcaps."""
    tr = df[~df.pcap.str.contains("L.pcap")]
    te = df[df.pcap.str.contains("L.pcap")]
    m = make_model("rf", seed)
    m.fit(tr[feats].values, tr.device.values)
    p = m.predict(te[feats].values)
    return {"balanced_accuracy": balanced_accuracy(te.device.values, p),
            "accuracy": float(np.mean(p == te.device.values)),
            "n_train": int(len(tr)), "n_test": int(len(te)), "features": feats}


def main():
    df = pd.read_csv(os.path.join(OUT, "transactions.csv"))
    real = df[df.role == "real"].reset_index(drop=True)
    out = {"seed": SEED, "n": int(len(real))}

    print("=" * 78)
    print("size-only device identification -- what is actually achievable")
    print("per-device response byte-total distributions (real device flows):")
    for dev, g in real.groupby("device"):
        print("  %-8s %s" % (dev, g.sz_resp_bytes.value_counts().sort_index().to_dict()))

    for cols in (["sz_resp_bytes"],
                 ["sz_resp_bytes", "sz_req_bytes"],
                 ["sz_resp_bytes", "sz_req_bytes", "sz_n_segments"]):
        b = bayes_optimal_ba(real, cols)
        out.setdefault("bayes_optimal", {})["+".join(cols)] = b
        print("  Bayes-optimal BA over %-46s = %.4f  %s"
              % ("+".join(cols), b["balanced_accuracy"], b["per_class_recall"]))

    print("=" * 78)
    print("reproduction of the prior measurement")
    feats2 = ["sz_req_bytes", "sz_resp_bytes"]
    cap = capture_level_split(real, feats2)
    out["prior_scheme_capture_level_split"] = cap
    print("  prior scheme (train=base pcaps, test=L pcaps), features %s:" % feats2)
    print("    balanced accuracy = %.4f   accuracy = %.4f  (n_train=%d n_test=%d)"
          % (cap["balanced_accuracy"], cap["accuracy"], cap["n_train"], cap["n_test"]))
    lofo = eval_featureset(real[feats2].values, real.device.values,
                           real.flow_id.values, model="rf", seed=SEED, B=2000)
    out["lofo_two_feature"] = lofo
    print("  leave-one-flow-out CV, same 2 features:")
    print("    balanced accuracy = %.4f  CI95=[%.4f, %.4f]"
          % (lofo["balanced_accuracy"], lofo["ci95_lo"], lofo["ci95_hi"]))

    print("=" * 78)
    print("the '0.99' side -- provenance, not measurement")
    prov = {
        "claim_text": "size-only classifier ~= 0.99, driven by ~14.6 B/CROB "
                      "(control) and ~5.7 B/analog-point (read) [M]",
        "claim_location": "research/inline_dnp3_size_normalization/"
                          "research_design.md:55 (repeated verbatim at "
                          "agent_contributions/pi_framing.md:6)",
        "traced_to": [
            {"artifact": "research/split_pad_timing_policy/measured_evidence.md:26",
             "statistic": "R^2 = 0.9999",
             "what_it_is": "coefficient of determination of a LINEAR REGRESSION of "
                           "operate-response size on CROB count N (slope 14.6 B/CROB, "
                           "intercept 22.5 B, 37->256 B over N=1..16)",
             "dataset": "dnp3_multicrob_harness/captures/sweep/multicrob_n{N}.pcapng "
                        "-- the multi-CROB SBO sweep against the harness outstation, "
                        "NOT the six device captures",
             "secret": "CROB count N (operator action complexity)",
             "n": "1 SBO per N level, N=1..16 (16 points, one device)"},
            {"artifact": "research/split_pad_timing_policy/GROUNDING.md:49-51",
             "statistic": "R^2 ~= 0.99",
             "what_it_is": "coefficient of determination of response TIMING on CROB "
                           "count (0.179 / 0.214 ms per CROB)",
             "secret": "CROB count N", "n": "1 per N level, one device"},
        ],
        "verdict": "There is no measured size-only DEVICE classifier at 0.99 anywhere "
                   "in the tree.  The 0.99 is a regression R^2 for a different secret "
                   "(CROB count) on a different dataset (the multi-CROB SBO sweep), "
                   "restated as a classifier balanced accuracy and then propagated. "
                   "0.493 is the correct number for size-only DEVICE identification on "
                   "the six-capture corpus, and it is at the analytic ceiling.",
    }
    out["provenance_of_0_99"] = prov
    print(json.dumps(prov, indent=1)[:1600])

    print("=" * 78)
    print("what the corpus actually contains (a third correction)")
    fc = real.groupby(["device", "dpi_req_fc"]).size().unstack(fill_value=0)
    print(fc.to_string())
    print("  DNP3 function code 1 = READ, 5 = DIRECT_OPERATE.")
    out["request_function_code_mix"] = json.loads(fc.to_json())
    out["request_size_by_fc"] = json.loads(
        real.groupby("dpi_req_fc")["sz_req_bytes"].agg(
            ["min", "max", "count"]).to_json())
    out["response_size_by_fc"] = json.loads(
        real.groupby(["device", "dpi_req_fc"])["sz_resp_bytes"].agg(
            lambda s: sorted(set(s))).to_json())
    print("  request bytes by fc:", out["request_size_by_fc"])
    print("  response bytes by fc:", out["response_size_by_fc"])

    # request-direction leak: an outstation-edge RESPONSE shaper cannot touch it
    reqclf = eval_featureset(real[["sz_req_bytes"]].values,
                             (real.dpi_req_fc == 5).astype(int).values,
                             real.flow_id.values, model="rf", seed=SEED, B=1000)
    out["control_vs_read_from_request_size"] = reqclf
    print("  control-vs-read recovered from REQUEST size alone: BA=%.4f CI95=[%.4f,%.4f]"
          % (reqclf["balanced_accuracy"], reqclf["ci95_lo"], reqclf["ci95_hi"]))

    with open(os.path.join(OUT, "m5_reconcile.json"), "w") as fh:
        json.dump(out, fh, indent=1)
    print("\nwrote", os.path.join(OUT, "m5_reconcile.json"))


if __name__ == "__main__":
    main()
