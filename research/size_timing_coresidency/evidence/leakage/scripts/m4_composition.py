"""M4 -- the cross-axis composition test (H3).

Every efficacy number in the repository is single-channel.  This applies a size
transform (split / quantised grid) to the corpus, then applies the timing release
policy on top in software, and emits a feature vector containing BOTH size and
timing features.

The question: does the composed defense push size information into the timing
channel?  Concretely, does transaction duration or inter-segment gap structure
predict the native response size above chance?

--------------------------------------------------------------------------- #
Release model (from `defense4/TIMING_SPEC.md` sections 2 and 5)

    T_A        = t_A + D_A                     (ACK deadline)
    t_RESP,out ~ max(t_R, T_RESP) + release_error
    D3 (D_R=0) : T_RESP = T_A                  -- response pinned to the ACK deadline
    D1 (event) : release on the matching-RESPONSE event, t_R + ordering_gap

Segments 2..K leave at t_first + sum(delta_i).  NOTHING in the timing engine
governs segments 2..K -- that is the whole point of the test.

Three first-byte policies are simulated:

  OFF        t_first = t_R (native).
  D3_SEPACK  the real D3 policy, applied ONLY to the separate-ACK device
             (SEL-751).  Case B / combined-ACK devices have no CLRT and are
             explicitly out of scope (CLAUDE.md, CASE_A_TERMINOLOGY), so applying
             an ACK-hold to them would manufacture a device-discriminating
             offset that is a modelling artifact, not a defense property.
  PERFECT    t_first = a single constant for every transaction and every device:
             an IDEALISED, better-than-achievable first-byte normaliser.  This
             is the headline condition for H3, because any residual
             I(timing ; response size) under it can only have come from the
             segment structure the size axis introduced.

Grounding of delta: the corpus contains 93 natively multi-segment responses whose
inter-segment gaps (median 13.554 ms, range 0.033-24.060 ms) supply the empirical
gap distribution; the configured alternative is the split harness default
DEFAULT_CHUNK_DELAY_MS = 10 ms (dnp3_split_harness/lab_config.py:40).

Effect size: raw plug-in MI over a fine discretisation has a large positive bias,
so every MI is reported BOTH raw and as an excess over the permutation-null mean,
and every MI CI is the pivotal (basic) bootstrap interval, which removes the
resampling bias that makes a naive percentile interval miss the point estimate.
"""

import json
import logging
import math
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, "/home/philip/Projects/DNP3/dnp3_split_harness")
import split_server as _ss                                       # noqa: E402
logging.getLogger().setLevel(logging.ERROR)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from leakage_lib import (SEED, eval_featureset, mi_mm, perm_null_block,        # noqa: E402
                         quantile_bin, joint_key, paired_bootstrap_delta)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "out")
SPLITTER = _ss.DNP3CRCSplitter()

ORDERING_GAP_MS = 0.05      # loopback / ordering tail, model-level (TIMING_SPEC 5)
D_A_MS = 25.0               # ACK hold offset >= native p99 req->ACK (COMPREHENSIVE_REPORT 3.4)
PERFECT_T_FIRST_MS = 50.0   # the idealised constant release instant
NBINS = 16


def segments_for(raw, policy, c=64, k_fix=None):
    L = len(raw)
    if policy == "native":
        return [L]
    if policy == "split_bpc1":
        return [len(x) for x in SPLITTER.split(raw, 1)]
    if policy == "grid_adaptive":
        return [c] * max(1, math.ceil(L / c))
    if policy == "grid_fixed":
        return [c] * k_fix
    raise ValueError(policy)


def simulate(M, policy, timing_mode, delta_model, rng, c=64, k_fix=None,
             jitter_sd_ms=None, emp_gaps=None):
    recs = []
    for _, r in M.iterrows():
        raw = bytes.fromhex(r.payload_hex)
        segs = segments_for(raw, policy, c=c, k_fix=k_fix)
        K = len(segs)
        t_R = r.tm_req_to_first_resp_ms
        has_ack = np.isfinite(r.tm_req_to_ack_ms)
        if timing_mode == "OFF":
            t_first = t_R
        elif timing_mode == "PERFECT":
            t_first = PERFECT_T_FIRST_MS
        elif timing_mode == "D3_SEPACK":
            t_first = (max(t_R, r.tm_req_to_ack_ms + D_A_MS) + ORDERING_GAP_MS
                       if has_ack else t_R)
        else:
            raise ValueError(timing_mode)

        if K == 1:
            gaps = []
        elif delta_model == "native_observed":
            gaps = [r.tm_mean_gap_ms] * (K - 1)
        elif delta_model == "empirical":
            gaps = list(rng.choice(emp_gaps, size=K - 1, replace=True))
        elif delta_model == "configured_10ms":
            sd = 0.0 if jitter_sd_ms is None else jitter_sd_ms
            gaps = list(np.maximum(0.0, 10.0 + rng.normal(0.0, sd, size=K - 1)))
        elif delta_model == "backtoback":
            base = float(np.min(emp_gaps))
            sd = 0.0 if jitter_sd_ms is None else jitter_sd_ms
            gaps = list(np.maximum(0.0, base + rng.normal(0.0, sd, size=K - 1)))
        else:
            raise ValueError(delta_model)

        duration = float(sum(gaps))
        recs.append({
            "txn_id": r.txn_id, "device": r.device, "flow_id": r.flow_id,
            "native_size": len(raw),
            "obs_total_bytes": int(sum(segs)), "obs_n_segments": K,
            "obs_first_seg": segs[0], "obs_max_seg": max(segs),
            "obs_min_seg": min(segs),
            "obs_t_first_ms": float(t_first),
            "obs_duration_ms": duration,
            "obs_mean_gap_ms": float(np.mean(gaps)) if gaps else 0.0,
            "obs_max_gap_ms": float(max(gaps)) if gaps else 0.0,
            "obs_t_last_ms": float(t_first + duration),
        })
    return pd.DataFrame(recs)


TIMING_OBS = ["obs_t_first_ms", "obs_duration_ms", "obs_mean_gap_ms",
              "obs_max_gap_ms", "obs_t_last_ms"]
SIZE_OBS = ["obs_total_bytes", "obs_n_segments", "obs_first_seg",
            "obs_max_seg", "obs_min_seg"]


def pivotal_mi_ci(x, y, groups, B=800, seed=SEED, alpha=0.05):
    """Basic (pivotal) bootstrap CI for MI, stratified within flow.

    Resampling with replacement thins the joint support and biases plug-in MI
    upward, so the percentile interval can sit entirely above the point
    estimate.  The pivotal form [2*theta - q_hi, 2*theta - q_lo] removes that.
    """
    rng = np.random.default_rng(seed)
    groups = np.asarray(groups)
    idx_by_g = {g: np.where(groups == g)[0] for g in np.unique(groups)}
    theta = mi_mm(x, y)
    vals = []
    for _ in range(B):
        rows = np.concatenate([rng.choice(i, size=len(i), replace=True)
                               for i in idx_by_g.values()])
        vals.append(mi_mm(x[rows], y[rows]))
    vals = np.array(vals)
    lo = 2 * theta - np.percentile(vals, 100 * (1 - alpha / 2))
    hi = 2 * theta - np.percentile(vals, 100 * alpha / 2)
    return float(lo), float(hi)


def timing_channel_mi(E, seed=SEED):
    g = E["flow_id"].values
    L = E["native_size"].astype(int).values
    tb = joint_key([quantile_bin(E[c].values, NBINS) for c in TIMING_OBS])
    res = perm_null_block(tb, L, g, B=1000, seed=seed)
    res["mi_excess_over_null_mean"] = res["mi"] - res["null_mean"]
    lo, hi = pivotal_mi_ci(tb, L, g, B=800, seed=seed)
    res["ci95_lo_pivotal"], res["ci95_hi_pivotal"] = lo, hi
    dur = quantile_bin(E["obs_duration_ms"].values, NBINS)
    res_dur = perm_null_block(dur, L, g, B=1000, seed=seed)
    res_dur["mi_excess_over_null_mean"] = res_dur["mi"] - res_dur["null_mean"]
    return res, res_dur


def main():
    df = pd.read_csv(os.path.join(OUT, "transactions.csv"))
    pay = json.load(open(os.path.join(OUT, "response_payloads.json")))
    real = df[df.role == "real"].reset_index(drop=True)
    emp_gaps = df.loc[df.sz_n_segments > 1, "tm_mean_gap_ms"].values
    print("empirical inter-segment gaps: n=%d median=%.3f ms range=[%.3f, %.3f]"
          % (len(emp_gaps), float(np.median(emp_gaps)), float(emp_gaps.min()),
             float(emp_gaps.max())))

    M = real[["txn_id", "device", "flow_id", "tm_req_to_ack_ms",
              "tm_req_to_first_resp_ms", "tm_mean_gap_ms"]].copy()
    M["payload_hex"] = [pay[t] for t in real.txn_id]
    Lmax = max(len(bytes.fromhex(h)) for h in M.payload_hex)
    C, KFIX = 64, math.ceil(Lmax / 64)
    print("grid c=%d  fixed K=%d (Lmax=%d)" % (C, KFIX, Lmax))

    out = {"seed": SEED, "n": int(len(M)), "D_A_ms": D_A_MS,
           "perfect_t_first_ms": PERFECT_T_FIRST_MS,
           "ordering_gap_ms": ORDERING_GAP_MS, "Lmax": Lmax, "grid_c": C,
           "grid_K_fixed": KFIX, "nbins": NBINS,
           "empirical_gap_ms": {"n": int(len(emp_gaps)),
                                "median": float(np.median(emp_gaps)),
                                "min": float(emp_gaps.min()),
                                "max": float(emp_gaps.max())},
           "conditions": {}}

    conds = [
        # headline: idealised first-byte normalisation isolates the re-encoding
        ("P0_native_PERFECT",       "native",        "PERFECT",   "native_observed", None),
        ("P1_split_PERFECT_10ms",   "split_bpc1",    "PERFECT",   "configured_10ms", 0.0),
        ("P2_split_PERFECT_emp",    "split_bpc1",    "PERFECT",   "empirical",       None),
        ("P3_split_PERFECT_b2b",    "split_bpc1",    "PERFECT",   "backtoback",      0.0),
        ("P4_gridadapt_PERFECT",    "grid_adaptive", "PERFECT",   "configured_10ms", 0.0),
        ("P5_gridfixed_PERFECT",    "grid_fixed",    "PERFECT",   "configured_10ms", 0.0),
        ("P6_gridfixed_PERFECT_emp", "grid_fixed",   "PERFECT",   "empirical",       None),
        # sensitivity: native timing, and the real D3 on the separate-ACK device
        ("S0_native_OFF",           "native",        "OFF",       "native_observed", None),
        ("S1_split_OFF_10ms",       "split_bpc1",    "OFF",       "configured_10ms", 0.0),
        ("S2_split_D3sepack_10ms",  "split_bpc1",    "D3_SEPACK", "configured_10ms", 0.0),
        ("S3_gridfixed_D3sepack",   "grid_fixed",    "D3_SEPACK", "configured_10ms", 0.0),
    ]

    sims = {}
    for name, pol, tmode, dmodel, jit in conds:
        rng = np.random.default_rng(SEED)
        E = simulate(M, pol, tmode, dmodel, rng, c=C, k_fix=KFIX,
                     jitter_sd_ms=jit, emp_gaps=emp_gaps)
        sims[name] = E
        res, res_dur = timing_channel_mi(E)
        g = E["flow_id"].values
        clf_joint = eval_featureset(E[SIZE_OBS + TIMING_OBS].values,
                                    E["device"].values, g, model="rf",
                                    seed=SEED, B=500)
        clf_timing = eval_featureset(E[TIMING_OBS].values, E["device"].values, g,
                                     model="rf", seed=SEED, B=500)
        H_L = mi_mm(E["native_size"].astype(int).values,
                    E["native_size"].astype(int).values)
        out["conditions"][name] = {
            "size_policy": pol, "timing_mode": tmode, "delta_model": dmodel,
            "jitter_sd_ms": jit, "n": int(len(E)), "H_native_size_bits": float(H_L),
            "MI_timing_vs_size": res, "MI_duration_vs_size": res_dur,
            "frac_of_H_recovered_by_timing_excess":
                float(res["mi_excess_over_null_mean"] / H_L),
            "device_BA_size+timing": clf_joint,
            "device_BA_timing_only": clf_timing,
            "mean_segments": float(E.obs_n_segments.mean()),
            "mean_emitted_bytes": float(E.obs_total_bytes.mean()),
            "duration_distinct_values": int(E.obs_duration_ms.round(3).nunique()),
        }
        print("%-26s MI=%.4f [piv CI %.4f,%.4f] null_mean=%.4f p95=%.4f p=%.4f "
              "| excess=%.4f (%.1f%% of H=%.3f) | devBA(sz+tm)=%.4f"
              % (name, res["mi"], res["ci95_lo_pivotal"], res["ci95_hi_pivotal"],
                 res["null_mean"], res["null_p95"], res["p_value"],
                 res["mi_excess_over_null_mean"],
                 100 * out["conditions"][name]["frac_of_H_recovered_by_timing_excess"],
                 H_L, clf_joint["balanced_accuracy"]))

    # ---- paired bootstrap of the composed-vs-undefended MI delta ------------
    print("\npaired cluster-bootstrap delta of I(timing ; response size), "
          "reference = P0_native_PERFECT (perfect timing defense, no size axis)")
    ref = sims["P0_native_PERFECT"]
    L = ref["native_size"].astype(int).values
    g = ref["flow_id"].values
    tb_ref = joint_key([quantile_bin(ref[c].values, NBINS) for c in TIMING_OBS])
    out["paired_deltas_vs_P0"] = {}
    for name in ("P1_split_PERFECT_10ms", "P2_split_PERFECT_emp",
                 "P3_split_PERFECT_b2b", "P4_gridadapt_PERFECT",
                 "P5_gridfixed_PERFECT", "P6_gridfixed_PERFECT_emp"):
        E = sims[name]
        tb = joint_key([quantile_bin(E[c].values, NBINS) for c in TIMING_OBS])
        d = paired_bootstrap_delta(lambda r: mi_mm(tb[r], L[r]),
                                   lambda r: mi_mm(tb_ref[r], L[r]),
                                   g, B=800, seed=SEED)
        out["paired_deltas_vs_P0"][name] = d
        verdict = "CI EXCLUDES 0" if d["ci95_lo"] > 0 or d["ci95_hi"] < 0 else "CI contains 0"
        print("  %-26s dMI = %+.4f bits  CI95=[%+.4f, %+.4f]   %s"
              % (name, d["mean"], d["ci95_lo"], d["ci95_hi"], verdict))

    # ---- jitter sweep: can gap randomisation close the re-encoded channel? --
    print("\njitter sweep: split_bpc1 + PERFECT first byte, delta = 10 ms + N(0,sd)")
    out["jitter_sweep"] = []
    for sd in (0.0, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0):
        rng = np.random.default_rng(SEED)
        E = simulate(M, "split_bpc1", "PERFECT", "configured_10ms", rng, c=C,
                     k_fix=KFIX, jitter_sd_ms=sd, emp_gaps=emp_gaps)
        dur = quantile_bin(E["obs_duration_ms"].values, NBINS)
        res = perm_null_block(dur, E["native_size"].astype(int).values,
                              E["flow_id"].values, B=1000, seed=SEED)
        res["mi_excess_over_null_mean"] = res["mi"] - res["null_mean"]
        res["jitter_sd_ms"] = sd
        out["jitter_sweep"].append(res)
        print("  sd=%6.1f ms  I(duration;L)=%.4f  excess=%.4f  null p95=%.4f  "
              "p=%.4f  %s" % (sd, res["mi"], res["mi_excess_over_null_mean"],
                              res["null_p95"], res["p_value"],
                              "INSIDE NULL" if res["mi"] <= res["null_p95"]
                              else "above null"))

    with open(os.path.join(OUT, "m4_composition.json"), "w") as fh:
        json.dump(out, fh, indent=1)
    print("\nwrote", os.path.join(OUT, "m4_composition.json"))


if __name__ == "__main__":
    main()
