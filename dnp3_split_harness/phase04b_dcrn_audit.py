#!/usr/bin/env python3
"""phase04b_dcrn_audit.py -- pre-rig audit of a DCRN paired campaign (corrective.md sec 14-16).

Runs UNPRIVILEGED on a campaign run-dir (the same PCAPs + spec.json the analyze/attacker tools use).
Produces the audit the rig run requires BEFORE it is meaningful -- and the same report format the rig
captures will get. It answers, per condition:

  1. PER-PROFILE timing table (SEL-/AB1400-/ION7550-derived), NOT pooled: native ACK structure,
     request->response, request->ACK-event, separate ACK->response gap, deadline misses.
  2. SCHEDULER ERROR by profile e_i = t_release - (t_request + D_i)  [FIXED: D_i = target].
     Permutation test for a device-correlated error distribution (a new timing fingerprint).
  3. ORDERING: zero response-before-pure-ACK for every separate transaction.
  4. FEATURE-FAMILY PURITY: the pure-timing family is request->response ONLY. request->ACK-event
     is MODE-COUPLED (pure-ACK time for separate vs response time for combined) and is reported
     separately, never folded into the pure-timing claim. No is_separate / packet-count /
     missingness / size leaks into the timing family.
  5. BOUNDED-target independence: per-profile request->response for the bounded condition + a
     permutation test that the target is independent of profile.
  6. REPEATED grouped-CV uncertainty: mean / std / 95% CI of balanced accuracy per family across
     K repeated disjoint session splits (not a single split).

Old-scheduler (Phase-02 application-write delay) condition: deliberately NOT re-run here -- it is a
different mechanism characterized in Phase 02; its removal is documented in the audit writeup.

  python3 phase04b_dcrn_audit.py --run-dir /tmp/phase04b_campaign_local --out audit.json
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import Counter, defaultdict

import numpy as np

HARNESS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS)
import characterize_ack_traces as C

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import balanced_accuracy_score
    _SK = True
except ImportError:
    _SK = False

TARGET_MS = 32.39
BOUND_LO, BOUND_HI = 32.39, 42.39
DEVICES = ["AB1400", "ION7550", "SEL751"]
DEADLINE_TOL_MS = 1.0  # scheduler jitter+guard band above the target before we call it a deadline miss

# Feature families. PURE timing = response only. ack_event is MODE-COUPLED (kept separate, flagged).
FAMILIES = {
    "mode_only": (["is_separate"], "categorical ACK mode (context)"),
    "size": (["resp_size"], "response size (context)"),
    "response_timing_PURE": (["req_to_resp_ms"], "PURE timing feature"),
    "ack_event_timing_MODECOUPLED": (["req_to_ack_event_ms"], "MODE-COUPLED (ACK time vs resp time)"),
    "timing_all": (["req_to_ack_event_ms", "req_to_resp_ms"], "both timing cols (inherits mode-coupling)"),
    "all": (["is_separate", "req_to_ack_event_ms", "req_to_resp_ms", "resp_size"], "every channel"),
}
PURITY_FORBIDDEN = {"is_separate", "resp_size", "packet_count", "n_packets", "missing", "sentinel"}


def qstats(vals):
    a = np.asarray([v for v in vals if v is not None], float)
    if a.size == 0:
        return {"n": 0, "median": None, "p95": None, "mean": None, "std": None, "min": None, "max": None}
    return {"n": int(a.size), "median": round(float(np.median(a)), 4), "p95": round(float(np.percentile(a, 95)), 4),
            "mean": round(float(a.mean()), 4), "std": round(float(a.std(ddof=0)), 4),
            "min": round(float(a.min()), 4), "max": round(float(a.max()), 4)}


def rows_for_capture(pcap: str, spec: dict) -> list:
    """Map streams->sessions (connection order == spec order) -> device; per-txn rows, first-per-stream excluded."""
    txns = C.build_transactions(C.run_tshark(pcap), os.path.basename(pcap), "SEL751")
    streams = defaultdict(list)
    for t in txns:
        streams[t.stream].append(t)
    order = sorted(streams, key=lambda s: min(x.req_frame for x in streams[s]))
    sess = list(spec["pcaps"])
    rows = []
    for k, s in enumerate(order):
        dev = C.device_from_pcap(sess[k % len(sess)])
        first = min(x.req_frame for x in streams[s])
        for t in streams[s]:
            if t.classification not in (C.CLS_COMBINED, C.CLS_SEPARATE) or t.req_frame == first:
                continue
            if t.req_to_resp_ms is None:
                continue
            sep = bool(t.first_rev_is_pure_ack)
            ack_event = t.req_to_ack_ms if (sep and t.req_to_ack_ms is not None) else t.req_to_resp_ms
            rows.append({"device": dev, "session": k, "is_separate": 1 if sep else 0,
                         "classification": t.classification,
                         "req_to_ack_event_ms": ack_event, "req_to_resp_ms": t.req_to_resp_ms,
                         "ack_to_resp_ms": t.ack_to_resp_ms, "resp_size": t.resp_size,
                         "retransmission": int(t.retransmission), "reset": int(t.reset),
                         "duplicate_ack": int(t.duplicate_ack)})
    return rows


def perm_test_median_diff(groups: dict, iters=5000, seed=0) -> dict:
    """Permutation test: is the LARGEST pairwise |median difference| across profiles > chance?"""
    rng = np.random.RandomState(seed)
    labels, vals = [], []
    for g, xs in groups.items():
        for x in xs:
            labels.append(g); vals.append(x)
    labels = np.array(labels); vals = np.array(vals, float)
    if len(set(labels)) < 2 or vals.size < 6:
        return {"observed_max_median_diff_ms": None, "p_value": None, "note": "insufficient data"}

    def max_pair_diff(lab):
        meds = [np.median(vals[lab == g]) for g in groups if (lab == g).sum()]
        return float(max(meds) - min(meds)) if len(meds) >= 2 else 0.0
    obs = max_pair_diff(labels)
    ge = 0
    for _ in range(iters):
        ge += max_pair_diff(rng.permutation(labels)) >= obs - 1e-12
    return {"observed_max_median_diff_ms": round(obs, 4), "p_value": round((ge + 1) / (iters + 1), 4),
            "per_profile_median_ms": {g: round(float(np.median(groups[g])), 4) for g in groups if groups[g]}}


def per_profile(rows: list, condition: str) -> dict:
    """Point 1 (per-profile timing table) + point 3 (ordering) + deadline misses."""
    by = defaultdict(list)
    for r in rows:
        by[r["device"]].append(r)
    target = TARGET_MS if condition == "DCRN_FIXED" else (BOUND_HI if condition == "DCRN_COMMON_BOUNDED" else None)
    out = {}
    for dev in DEVICES:
        rs = by.get(dev, [])
        if not rs:
            continue
        seps = [r for r in rs if r["is_separate"]]
        struct = Counter(r["classification"] for r in rs).most_common(1)[0][0]
        gap = [r["ack_to_resp_ms"] for r in seps if r["ack_to_resp_ms"] is not None]
        order_viol = sum(1 for r in seps if r["ack_to_resp_ms"] is not None and r["ack_to_resp_ms"] < 0)
        dmiss = sum(1 for r in rs if target is not None and r["req_to_resp_ms"] > target + DEADLINE_TOL_MS)
        out[dev] = {
            "native_ack_structure": "SEPARATE" if struct == C.CLS_SEPARATE else "COMBINED",
            "n": len(rs),
            "request_to_response_ms": qstats([r["req_to_resp_ms"] for r in rs]),
            "request_to_ack_event_ms": qstats([r["req_to_ack_event_ms"] for r in rs]),
            "separate_ack_to_response_gap_ms": (qstats(gap) if seps else "N/A (combined)"),
            "deadline_misses": {"count": dmiss, "of_n": len(rs),
                                "definition": (f"req_to_resp > {target}+{DEADLINE_TOL_MS} ms" if target else "N/A native")},
            "ordering_response_before_pure_ack": {"separate_txns": len(seps), "violations": order_viol},
        }
    return out


def scheduler_error(rows: list, condition: str) -> dict:
    """Point 2: e_i = req_to_resp - D_i (FIXED: D_i=target). Device-correlated error => new fingerprint."""
    if condition != "DCRN_FIXED":
        return {"applicable": False, "reason": "e_i needs a known per-txn D_i; FIXED (D=target) is the clean test. "
                                                "BOUNDED target independence is tested separately (point 5)."}
    groups = defaultdict(list)
    for r in rows:
        groups[r["device"]].append(r["req_to_resp_ms"] - TARGET_MS)
    per = {d: qstats(v) for d, v in groups.items()}
    pt = perm_test_median_diff({d: v for d, v in groups.items()}, seed=1)
    flag = pt["p_value"] is not None and pt["p_value"] < 0.05
    return {"applicable": True, "D_ms": TARGET_MS, "per_profile_error_ms": per,
            "device_correlated_error_test": pt,
            "device_correlated_error": bool(flag),
            "interpretation": ("device-correlated scheduler error present (a residual timing fingerprint) -- "
                               "quantified above" if flag else "no device-correlated scheduler error")}


def bounded_independence(rows: list) -> dict:
    """Point 5: bounded target independent of profile? range coverage + per-profile permutation test."""
    rr = [r["req_to_resp_ms"] for r in rows]
    groups = defaultdict(list)
    for r in rows:
        groups[r["device"]].append(r["req_to_resp_ms"])
    within = sum(BOUND_LO - DEADLINE_TOL_MS <= x <= BOUND_HI + DEADLINE_TOL_MS for x in rr)
    pt = perm_test_median_diff({d: v for d, v in groups.items()}, seed=2)
    return {"intended_window_ms": [BOUND_LO, BOUND_HI],
            "observed_range_ms": [round(min(rr), 4), round(max(rr), 4)] if rr else None,
            "fraction_within_window": round(within / len(rr), 4) if rr else None,
            "per_profile_response_ms": {d: qstats(v) for d, v in groups.items()},
            "profile_independence_test": pt,
            "target_independent_of_profile": bool(pt["p_value"] is not None and pt["p_value"] >= 0.05)}


def purity_check() -> dict:
    """Point 4: static audit that no forbidden feature contaminates the pure-timing family."""
    pure = set(FAMILIES["response_timing_PURE"][0])
    leaks = sorted(pure & PURITY_FORBIDDEN)
    return {"pure_timing_family": sorted(pure), "forbidden": sorted(PURITY_FORBIDDEN),
            "contamination": leaks, "pure_timing_is_clean": not leaks,
            "note": "request_to_ack_event_ms is MODE-COUPLED by construction (pure-ACK time for separate, "
                    "response time for combined) and is EXCLUDED from the pure-timing claim; reported as its "
                    "own family and inside timing_all (which therefore inherits mode-coupling)."}


def repeated_cv(all_rows: dict, K=100, seed=20260717) -> dict:
    """Point 6: repeated disjoint session splits -> mean/std/95%CI of balanced accuracy per family."""
    if not _SK:
        return {"error": "scikit-learn required"}
    import pandas as pd
    rng = np.random.RandomState(seed)
    out = {}
    for cond, rows in all_rows.items():
        df = pd.DataFrame(rows)
        sess_ids = sorted(df["session"].unique())
        fam_scores = {f: [] for f in FAMILIES}
        for _ in range(K):
            perm = rng.permutation(sess_ids)
            half = len(perm) // 2
            tr_s, te_s = set(perm[:half]), set(perm[half:])
            tr, te = df[df["session"].isin(tr_s)], df[df["session"].isin(te_s)]
            if tr.empty or te.empty or te["device"].nunique() < 2 or tr["device"].nunique() < 2:
                continue
            for fam, (cols, _d) in FAMILIES.items():
                sc = StandardScaler().fit(tr[cols].values)
                clf = RandomForestClassifier(n_estimators=120, random_state=0).fit(sc.transform(tr[cols].values),
                                                                                    tr["device"].values)
                pred = clf.predict(sc.transform(te[cols].values))
                fam_scores[fam].append(balanced_accuracy_score(te["device"].values, pred))
        out[cond] = {}
        for fam, sc in fam_scores.items():
            a = np.asarray(sc, float)
            out[cond][fam] = ({"mean": round(float(a.mean()), 4), "std": round(float(a.std(ddof=1)), 4),
                               "ci95": [round(float(np.percentile(a, 2.5)), 4), round(float(np.percentile(a, 97.5)), 4)],
                               "n_splits": int(a.size)} if a.size else {"error": "no valid split"})
    return {"chance": round(1 / 3, 4), "K": K, "per_condition": out}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--out")
    ap.add_argument("--cv-iters", type=int, default=100)
    args = ap.parse_args()
    spec_path = os.path.join(args.run_dir, "spec.json")
    if not os.path.exists(spec_path):
        sys.stderr.write("spec.json missing in run-dir\n"); return 2
    spec = json.load(open(spec_path))

    all_rows = {}
    audit = {"run_dir": args.run_dir, "target_ms": TARGET_MS, "bounded_window_ms": [BOUND_LO, BOUND_HI],
             "feature_purity": purity_check(), "conditions": {}}
    for pcap in sorted(glob.glob(os.path.join(args.run_dir, "*.pcap"))):
        cond = os.path.splitext(os.path.basename(pcap))[0]
        rows = rows_for_capture(pcap, spec)
        all_rows[cond] = rows
        c = {"n_txns": len(rows), "per_profile": per_profile(rows, cond),
             "scheduler_error": scheduler_error(rows, cond)}
        if cond == "DCRN_COMMON_BOUNDED":
            c["bounded_independence"] = bounded_independence(rows)
        audit["conditions"][cond] = c
    audit["repeated_cv"] = repeated_cv(all_rows, K=args.cv_iters)

    dst = args.out or os.path.join(args.run_dir, "phase04b_audit.json")
    json.dump(audit, open(dst, "w"), indent=2)

    # readable summary
    print("== FEATURE PURITY ==")
    fp = audit["feature_purity"]
    print(f"  pure-timing family = {fp['pure_timing_family']} | clean={fp['pure_timing_is_clean']} "
          f"| contamination={fp['contamination']}")
    for cond, c in audit["conditions"].items():
        print(f"\n== {cond} (n={c['n_txns']}) ==")
        for dev, p in c["per_profile"].items():
            g = p["separate_ack_to_response_gap_ms"]
            gm = g["median"] if isinstance(g, dict) else g
            print(f"  {dev:8s} [{p['native_ack_structure']:8s}] req->resp med={p['request_to_response_ms']['median']} "
                  f"ackEvt med={p['request_to_ack_event_ms']['median']} gap={gm} "
                  f"dmiss={p['deadline_misses']['count']}/{p['deadline_misses']['of_n']} "
                  f"order_viol={p['ordering_response_before_pure_ack']['violations']}")
        se = c["scheduler_error"]
        if se.get("applicable"):
            print(f"  scheduler-error device-correlated={se['device_correlated_error']} "
                  f"(max median diff={se['device_correlated_error_test']['observed_max_median_diff_ms']} ms, "
                  f"p={se['device_correlated_error_test']['p_value']})")
        if "bounded_independence" in c:
            bi = c["bounded_independence"]
            print(f"  bounded: range={bi['observed_range_ms']} within={bi['fraction_within_window']} "
                  f"profile-independent={bi['target_independent_of_profile']} (p={bi['profile_independence_test']['p_value']})")
    print("\n== REPEATED GROUPED CV (balanced acc, chance=0.333) ==")
    for cond, fam in audit["repeated_cv"].get("per_condition", {}).items():
        rt = fam.get("response_timing_PURE", {}); ta = fam.get("timing_all", {})
        if "mean" in rt:
            print(f"  {cond:22s} response_timing(PURE) {rt['mean']}±{rt['std']} CI{rt['ci95']} | "
                  f"timing_all {ta['mean']}±{ta['std']} CI{ta['ci95']}")
    print("\nwrote", dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
