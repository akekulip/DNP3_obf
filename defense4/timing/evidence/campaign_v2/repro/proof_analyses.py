"""Where timing evidence remains after obfuscation.

The released-interval statistics show that the obfuscated CLRT is a configured value. What they do
not show on their own is which observable timing contrasts still separate classes or request
contexts. Three descriptive checks answer that question without assigning causality.

1. **READ against SELECT.** Both run on the read lane and differ in the outstation work needed
   to answer them, but they are observational classes in a measured trace rather than a
   controlled execution-time-only experiment.
2. **READ against READ by preceding arrival gap.** One transaction class is split at the arm's
   median preceding gap (the request timestamp minus the previous exchange's response timestamp
   in the same capture). This tests whether request-arrival context remains predictive within
   READ traffic.
3. **The arrival gap by class**, so the difference in arrival spacing between OPERATE and the
   read-lane classes is a measured quantity rather than a description.

Every forest is the one the leakage analysis uses (``leakage_campaign.RF``), scored by balanced
accuracy under leave-one-grouped-run-out, trained and tested within one arm. The reported scores
are held-out-run summaries of these two-class contrasts; chance is 0.5.

It also records the release tail's support at the shipped policy and the campaign's wall-clock
span, both of which the findings quoted without an artefact until now.

    proof_analyses.py CANONICAL_CSV POLICY_JSON OUT_JSON
"""
from __future__ import annotations
import csv, json, sys
from collections import defaultdict
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score

from leakage_campaign import RF, spread

TICK_NS = 256
FEATURES = {"clrt": [1], "ack_clrt": [0, 1]}


def load(path):
    rows = list(csv.DictReader(open(path)))
    by_cap = defaultdict(list)
    for r in rows:
        by_cap[r["capture"]].append(r)
    out = []
    for cap, v in by_cap.items():
        v.sort(key=lambda r: int(r["idx"]))
        prev_resp = None
        for r in v:
            t_req = int(r["t_req_ns"])
            gap_ns = None if prev_resp is None else t_req - prev_resp
            out.append(dict(run=r["run"], arm=r["arm"], cap=cap, cls=r["txn_class"],
                            ack_ms=float(r["ack_ms"]), clrt_ms=float(r["clrt_ms"]),
                            ack_ns=int(r["ack_ns"]), t_req_ns=t_req,
                            t_resp_ns=int(r["t_resp_ns"]), gap_ns=gap_ns))
            prev_resp = int(r["t_resp_ns"])
    return out


def loro(runs, y, X):
    """Leave-one-grouped-run-out balanced accuracy, one score per held-out run."""
    scores = []
    for r in sorted(set(runs)):
        te, tr = runs == r, runs != r
        if len(set(y[te])) < 2 or len(set(y[tr])) < 2:
            continue
        m = RandomForestClassifier(**RF).fit(X[tr], y[tr])
        scores.append(balanced_accuracy_score(y[te], m.predict(X[te])))
    return spread(scores)


def arrays(rows):
    return (np.array([r["run"] for r in rows]),
            np.array([[r["ack_ms"], r["clrt_ms"]] for r in rows], dtype=float))


def main(canon, policy, out):
    rows = load(canon)
    cfg = json.load(open(policy))
    res = {"classifier": "RandomForest " + json.dumps(RF),
           "protocol": ("leave-one-grouped-run-out, trained and tested within one arm; "
                        "balanced accuracy; chance 0.5 for every two-class contrast"),
           "chance_balanced_accuracy": 0.5}

    # ---- 1. execution time alone: READ against SELECT ------------------------------------------
    res["read_vs_select"] = {}
    for arm in ("native", "obfuscated"):
        sub = [r for r in rows if r["arm"] == arm and r["cls"] in ("READ", "SELECT")]
        runs, X = arrays(sub)
        y = np.array([r["cls"] for r in sub])
        med = {c: {"clrt_ms": round(float(np.median([r["clrt_ms"] for r in sub if r["cls"] == c])), 4),
                   "ack_ms": round(float(np.median([r["ack_ms"] for r in sub if r["cls"] == c])), 4)}
               for c in ("READ", "SELECT")}
        res["read_vs_select"][arm] = {
            "n": {c: int((y == c).sum()) for c in ("READ", "SELECT")},
            "medians": med,
            "balanced_accuracy": {f: loro(runs, y, X[:, idx]) for f, idx in FEATURES.items()}}

    # ---- 2. arrival spacing alone: READ against READ -------------------------------------------
    res["read_arrival_split"] = {}
    for arm in ("native", "obfuscated"):
        sub = [r for r in rows if r["arm"] == arm and r["cls"] == "READ" and r["gap_ns"] is not None]
        gaps = np.array([r["gap_ns"] for r in sub], dtype=float)
        cut = float(np.median(gaps))
        y = np.where(gaps > cut, "late", "early")
        runs, X = arrays(sub)
        res["read_arrival_split"][arm] = {
            "split": "READ exchanges with a preceding gap above versus at or below the arm median",
            "median_gap_ms": round(cut / 1e6, 4),
            "half_median_gap_ms": {h: round(float(np.median(gaps[y == h])) / 1e6, 4)
                                   for h in ("early", "late")},
            "half_median_gap_difference_us": round(
                (float(np.median(gaps[y == "late"])) - float(np.median(gaps[y == "early"]))) / 1e3, 1),
            "n": {h: int((y == h).sum()) for h in ("early", "late")},
            "balanced_accuracy": {f: loro(runs, y, X[:, idx]) for f, idx in FEATURES.items()}}

    # ---- 3. the arrival gap by class -----------------------------------------------------------
    res["arrival_gap_ms"] = {
        arm: {c: round(float(np.median([r["gap_ns"] for r in rows
                                        if r["arm"] == arm and r["cls"] == c
                                        and r["gap_ns"] is not None])) / 1e6, 4)
              for c in ("READ", "SELECT", "OPERATE")}
        for arm in ("native", "obfuscated")}
    res["arrival_gap_definition"] = ("median of the request timestamp minus the previous "
                                     "exchange's response timestamp in the same capture")

    # ---- the release tail at the shipped policy ------------------------------------------------
    d_a_ns = int(round(cfg["D_A_ms"] * 1e6)) // TICK_NS * TICK_NS
    obf = [r for r in rows if r["arm"] == "obfuscated"]
    tail_us = np.array([(r["ack_ns"] - d_a_ns) / 1e3 for r in obf])
    res["release_tail_us"] = {
        "definition": ("request-to-acknowledgment interval minus the acknowledgment hold as the "
                       "switch stores it (whole 256 ns ticks), obfuscated arm, every class"),
        "n": int(tail_us.size),
        "min": round(float(tail_us.min()), 1), "max": round(float(tail_us.max()), 1),
        "p0_5": round(float(np.percentile(tail_us, 0.5)), 1),
        "p99_5": round(float(np.percentile(tail_us, 99.5)), 1),
        "distinct_whole_us_values": int(np.unique(np.round(tail_us)).size),
        "median_by_class": {c: round(float(np.median([t for t, r in zip(tail_us, obf)
                                                      if r["cls"] == c])), 1)
                            for c in ("READ", "SELECT", "OPERATE")}}

    # ---- campaign wall-clock span --------------------------------------------------------------
    t0 = min(r["t_req_ns"] for r in rows)
    t1 = max(r["t_resp_ns"] for r in rows)
    res["campaign_span"] = {"first_request_to_last_response_s": round((t1 - t0) / 1e9, 1),
                            "hours": round((t1 - t0) / 3.6e12, 3)}

    json.dump(res, open(out, "w"), indent=1)
    for arm in ("native", "obfuscated"):
        a = res["read_vs_select"][arm]["balanced_accuracy"]
        b = res["read_arrival_split"][arm]
        print(f"{arm:11s} READ vs SELECT  clrt {a['clrt']['mean']:.4f}  ack_clrt {a['ack_clrt']['mean']:.4f}"
              f"   | READ early vs late ({b['half_median_gap_difference_us']} us apart)"
              f"  clrt {b['balanced_accuracy']['clrt']['mean']:.4f}"
              f"  ack_clrt {b['balanced_accuracy']['ack_clrt']['mean']:.4f}")
    print("arrival gap medians (ms):", json.dumps(res["arrival_gap_ms"]))
    print("release tail (us):", json.dumps({k: v for k, v in res["release_tail_us"].items()
                                           if k != "definition"}))
    print("campaign span:", res["campaign_span"])
    print(f"wrote {out}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
