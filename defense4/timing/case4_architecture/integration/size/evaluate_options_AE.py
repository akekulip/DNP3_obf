#!/usr/bin/env python3
"""
evaluate_options_AE.py -- scores the new TCP-payload-byte common-pattern options (A-E, integration
prompt Phase B) against the recovered RRC hardware pool (inventory_v2/rrc_pool.json), reusing the
SAME manually-implemented MI / Miller-Madow / flow-grouped-bootstrap / permutation-null / grouped-CV
machinery as evaluate_candidates.py (imported, not reimplemented) so the new TCP-payload-byte
evaluation is methodologically identical to the historical Ethernet-byte evaluation it sits beside.

This script answers ONE question precisely: on the RESPONSE direction (the mismatch the integration
contract names -- [28,21] READ vs [28,29] control), does mapping both roles' responses through a
SHARED size-state vector leave the resulting state statistically informative about which DNP3
operation produced it? It does NOT re-litigate device/ack-mode leakage (not applicable: this pool is
one physical device, one ack mode) and it does NOT fabricate OPERATE hardware samples that do not
exist (physical OPERATE was never run -- see RRC_HW_RESULTS.md).

Two evaluation granularities, used for different option shapes:
  - PER-SEGMENT (what a passive observer actually counts on the wire): used for split profiles
    (Option A/C). Each carved child (e.g. 28B prefix, 21B suffix) is its own observation.
  - PER-TRANSACTION, reassembled: used for no-split profiles (Option B/D), where the observer sees
    exactly one response packet per transaction, so the per-segment pool must first be reassembled
    back to one native size per transaction before a "single uniform pad" state can be applied.
"""
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate_candidates import (mutual_information_bits, miller_madow_mi_bits,
                                  bootstrap_mi_ci_grouped, permutation_mi_pvalue,
                                  grouped_balanced_accuracy, map_state)


def load_pool(path):
    with open(path) as f:
        doc = json.load(f)
    return doc["records"]


def reassemble_transactions(records):
    """One record per (flow, transaction_id) RESPONSE, size = sum of that transaction's response
    segment bytes (the native, pre-split payload size a no-split profile would actually carry)."""
    groups = defaultdict(list)
    for r in records:
        if r["direction"] == "outstation_to_master":
            groups[(r["flow"], r["transaction_id"])].append(r)
    out = []
    for (flow, txn), segs in groups.items():
        total = sum(s["tcp_payload_bytes"] for s in segs)
        op = segs[0]["_operation"]
        out.append({"flow": flow, "transaction_id": txn, "tcp_payload_bytes": total, "_operation": op})
    return out


def response_leakage(records, states, label, size_key="tcp_payload_bytes"):
    feat = [map_state(states, r[size_key]) for r in records]
    op = [r["_operation"] for r in records]
    grp = [r["flow"] for r in records]
    mi = mutual_information_bits(feat, op)
    mi_mm = miller_madow_mi_bits(feat, op)
    ci = bootstrap_mi_ci_grouped(feat, op, grp, B=300, seed=1)
    null_mean, pval = permutation_mi_pvalue(feat, op, B=1000, seed=2)
    ba = grouped_balanced_accuracy(feat, op, grp)
    n_unfit = sum(1 for f in feat if f is None)
    print("== %s : states=%s ==" % (label, states))
    print("   n_observations=%d  n_flow_groups=%d  unfit(exceeds top state, passed through natively)=%d"
          % (len(records), len(set(grp)), n_unfit))
    print("   MI(plug-in)=%.4f bits  MI(Miller-Madow)=%.4f bits  flow-grouped-CI95=%s" % (mi, mi_mm, ci))
    print("   permutation-null mean=%.4f bits  p=%.4f" % (null_mean, pval))
    print("   grouped balanced accuracy (operation from size-state) = %s  chance=%s  folds=%s(%s)"
          % (ba["balanced_accuracy"], ba["chance"], ba["n_folds"], ba["fold_scheme"]))
    return {"states": states, "n_observations": len(records), "n_flow_groups": len(set(grp)),
            "unfit_packets": n_unfit, "mi_bits": round(mi, 4), "mi_miller_madow_bits": round(mi_mm, 4),
            "mi_flow_grouped_ci95": list(ci), "mi_permutation_p": pval,
            "grouped_balanced_accuracy": ba["balanced_accuracy"], "grouped_chance": ba["chance"],
            "fold_scheme": ba["fold_scheme"], "n_folds": ba["n_folds"]}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    records = load_pool(os.path.join(here, "inventory_v2", "rrc_pool.json"))
    resp_segments = [r for r in records if r["direction"] == "outstation_to_master"]
    resp_txn = reassemble_transactions(records)

    out = {}
    # Option A / C: split profile, shared states = [21, 28] (the already hardware-proven RRC carve).
    # A cut-point choice (Option C, e.g. 24/25 instead of 28/21) changes which physical bytes land in
    # which child but not the SET of state sizes reported here when both roles share one native size;
    # this evaluation is therefore representative of A and of any same-two-state C variant.
    out["option_A_and_C_split_21_28"] = response_leakage(
        resp_segments, [21, 28], "Option A/C: per-segment states=[21,28] (49B payload, cut28 family)")
    # Option B seed: single padded state covering the full native range including the 58B background
    # state-reads, evaluated at TRANSACTION (reassembled) granularity since no split occurs.
    out["option_B_single_58_no_split"] = response_leakage(
        resp_txn, [58], "Option B: per-transaction, single no-split state=58 (covers 49B+58B)")
    # Option D: single uniform pad target = 49B, no split -- excludes the 58B background class, which
    # must then pass through NATIVELY (unfit) and is therefore its own, fully distinguishable residual
    # state; reported at transaction granularity.
    out["option_D_single_49_no_split"] = response_leakage(
        resp_txn, [49], "Option D: per-transaction, single no-split state=49 (excludes 58B background)")

    with open(os.path.join(here, "evaluation_options_AE.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("\nwrote evaluation_options_AE.json")


if __name__ == "__main__":
    main()
