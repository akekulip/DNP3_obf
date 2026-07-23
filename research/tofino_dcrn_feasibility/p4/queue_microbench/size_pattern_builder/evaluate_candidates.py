#!/usr/bin/env python3
"""
evaluate_candidates.py — DNP3 size-pattern candidate evaluation, v1.1 (OFF-SWITCH only).

Charter autunomous.md §6.10/§6.11. Rewritten to report MEASURED leakage instead of log2(#states):

 §6.10  For each candidate, the mapped size-STATE is the single observable feature. Against it we measure
        - empirical MUTUAL INFORMATION (bits) with {device, operation, ack_mode_observed, direction};
        - grouped-CV BALANCED ACCURACY of a majority-vote classifier predicting {device, operation,
          ack_mode} from the mapped size-state, cross-validated with folds GROUPED BY flow (a flow never
          appears in both train and test — no memorizing repeated transactions).
        MI and grouped balanced accuracy are implemented MANUALLY (numpy only; no sklearn).
        log2(k) is kept ONLY as a labelled theoretical state-capacity upper bound.
        Sanity invariant (verified in output): single-state candidates -> MI==0 and balanced
        accuracy == chance (1/n_classes), because a constant feature carries no information.
        Ranking sensitivity is run across several leakage weights (not a single hard-coded 20), and a
        Pareto frontier is reported over (mean padding, MI-device, #states, queue count, max latency,
        cover overhead).

 §6.11  Overhead is computed from ACTUAL packets/transactions, reported SEPARATELY master->outstation and
        outstation->master: per transaction, per second at the measured cadence, per day; for cover=OFF
        (padding only), transaction-window (padding + the added combined-ACK cover slot) and continuous
        (upper bound). Mean packet padding is NOT multiplied by a 6-slot window.

Feasibility is checked per link {64kbps,1Mbps,100Mbps,1Gbps}; the TCP RTO ceiling is 211 ms.

Usage: $RESEARCH_PYTHON evaluate_candidates.py [--scope base] [--rto-ms 211] [--out evaluation.json]
"""
import argparse
import json
import math
import os
from collections import defaultdict, Counter

import numpy as np

SZ = "ethernet_frame_bytes_no_fcs_min_applied"
LINKS_KBPS = {"64kbps": 64, "1Mbps": 1000, "100Mbps": 100000, "1Gbps": 1000000}
LEAKAGE_WEIGHTS = [0, 1, 5, 20, 100]      # ranking sensitivity sweep (§6.10)


# --------------------------------------------------------------------------- labels & feature
def op_of_role(role):
    if role is None:
        return None
    if "READ" in role:
        return "READ"
    if "DIRECT_OPERATE" in role:
        return "DIRECT_OPERATE"
    if role in ("SELECT", "OPERATE"):
        return "SBO"
    if "WRITE" in role:
        return "WRITE"
    return None


def annotate_operation(records):
    """Assign every packet the operation of the transaction it belongs to (so ACKs and responses inherit
    the opening request's operation). transaction_id<=0 (handshake/close) -> None."""
    groups = defaultdict(list)
    for r in records:
        if r["transaction_id"] > 0:
            groups[(r["device"], r["capture_id"], r["flow"], r["transaction_id"])].append(r)
    op_by_key = {}
    for k, pkts in groups.items():
        op = None
        for r in sorted(pkts, key=lambda r: (r["ts"], r["capture_index"])):
            o = op_of_role(r["role"])
            if o:
                op = o; break
        op_by_key[k] = op
    for r in records:
        k = (r["device"], r["capture_id"], r["flow"], r["transaction_id"])
        r["_operation"] = op_by_key.get(k) if r["transaction_id"] > 0 else None


def map_state(states, size):
    for s in states:
        if size <= s:
            return s
    return None


# --------------------------------------------------------------------------- MI (bits), manual
def mutual_information_bits(feature, label):
    """MI(feature; label) in bits over paired lists. Constant feature or constant label -> 0."""
    n = len(feature)
    if n == 0:
        return 0.0
    joint = Counter(zip(feature, label))
    fx = Counter(feature)
    fy = Counter(label)
    mi = 0.0
    for (x, y), nxy in joint.items():
        pxy = nxy / n
        px = fx[x] / n
        py = fy[y] / n
        mi += pxy * math.log2(pxy / (px * py))
    return max(0.0, mi)


def bootstrap_mi_ci(feature, label, B=200, seed=0):
    """Percentile 95% CI for MI by resampling record indices with replacement."""
    n = len(feature)
    if n == 0:
        return (0.0, 0.0)
    f = np.array(feature, dtype=object)
    y = np.array(label, dtype=object)
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(B):
        idx = rng.integers(0, n, n)
        vals.append(mutual_information_bits(list(f[idx]), list(y[idx])))
    return (round(float(np.percentile(vals, 2.5)), 4), round(float(np.percentile(vals, 97.5)), 4))


# ----------------------------------------------------- grouped balanced accuracy, manual GroupKFold
def stratified_group_folds(groups, group_major_class, k):
    """Assign each group entirely to one fold (group integrity), spreading each class's groups across
    folds round-robin so a test fold contains all classes when each class has >= k groups."""
    byclass = defaultdict(list)
    for g in sorted(groups):
        byclass[group_major_class[g]].append(g)
    folds = [set() for _ in range(k)]
    for _c, gs in byclass.items():
        for i, g in enumerate(gs):
            folds[i % k].add(g)
    return [f for f in folds if f]


def balanced_accuracy(y_true, y_pred):
    """Mean per-class recall over the classes present in y_true."""
    classes = set(y_true)
    recalls = []
    for c in classes:
        tot = sum(1 for t in y_true if t == c)
        hit = sum(1 for t, p in zip(y_true, y_pred) if t == c and p == c)
        recalls.append(hit / tot if tot else 0.0)
    return sum(recalls) / len(recalls) if recalls else 0.0


def grouped_balanced_accuracy(feature, label, group, k=2):
    """Majority-vote-per-feature-value classifier, cross-validated with folds grouped by `group`.
    Returns (mean_bal_acc, ci_lo, ci_hi, chance, per_fold_list). chance = mean per-fold 1/#classes."""
    n = len(feature)
    if n == 0:
        return (float("nan"), float("nan"), float("nan"), float("nan"), [])
    groups = sorted(set(group))
    k = min(k, len(groups))
    if k < 2:
        return (float("nan"), float("nan"), float("nan"), float("nan"), [])
    # majority class per group (for stratified assignment)
    gc = defaultdict(Counter)
    for g, y in zip(group, label):
        gc[g][y] += 1
    group_major = {g: gc[g].most_common(1)[0][0] for g in groups}
    folds = stratified_group_folds(groups, group_major, k)

    idx_by_group = defaultdict(list)
    for i, g in enumerate(group):
        idx_by_group[g].append(i)

    per_fold, chances = [], []
    for test_groups in folds:
        test_idx = [i for g in test_groups for i in idx_by_group[g]]
        train_idx = [i for i in range(n) if group[i] not in test_groups]
        if not test_idx or not train_idx:
            continue
        # train: majority label per feature value + global majority fallback
        by_val = defaultdict(Counter)
        glob = Counter()
        for i in train_idx:
            by_val[feature[i]][label[i]] += 1
            glob[label[i]] += 1
        vote = {v: c.most_common(1)[0][0] for v, c in by_val.items()}
        gmaj = glob.most_common(1)[0][0]
        y_true = [label[i] for i in test_idx]
        y_pred = [vote.get(feature[i], gmaj) for i in test_idx]
        per_fold.append(balanced_accuracy(y_true, y_pred))
        chances.append(1.0 / len(set(y_true)))
    if not per_fold:
        return (float("nan"), float("nan"), float("nan"), float("nan"), [])
    arr = np.array(per_fold)
    ci = 1.96 * arr.std(ddof=1) / math.sqrt(len(arr)) if len(arr) > 1 else 0.0
    return (float(arr.mean()), float(arr.mean() - ci), float(arr.mean() + ci),
            float(np.mean(chances)), [round(x, 4) for x in per_fold])


# --------------------------------------------------------------------------- leakage per candidate
def leakage(cand, records, k=2, bootstrap=200):
    states = [s["target_frame_bytes"] for s in cand["size_states"]]
    feat_all = [map_state(states, r[SZ]) for r in records]

    targets = {
        "device":    [(f, r["device"], r["flow"]) for f, r in zip(feat_all, records)],
        "operation": [(f, r["_operation"], r["flow"]) for f, r in zip(feat_all, records)
                      if r["_operation"] in ("READ", "DIRECT_OPERATE", "SBO", "WRITE")],
        "ack_mode":  [(f, r["ack_mode_observed"], r["flow"]) for f, r in zip(feat_all, records)
                      if r["ack_mode_observed"] in ("separate", "combined")],
        "direction": [(f, r["direction"], r["flow"]) for f, r in zip(feat_all, records)],
    }
    out = {}
    n_states_used = len(set(f for f in feat_all if f is not None))
    log2k_upper = round(math.log2(max(1, n_states_used)), 4)
    for name, rows in targets.items():
        if not rows:
            out[name] = {"note": "no samples for this target in scope"}
            continue
        f = [x[0] for x in rows]
        y = [x[1] for x in rows]
        g = [x[2] for x in rows]
        mi = mutual_information_bits(f, y)
        mi_ci = bootstrap_mi_ci(f, y, B=bootstrap, seed=1) if bootstrap else (None, None)
        n_classes = len(set(y))
        blk = {"mutual_information_bits": round(mi, 4),
               "mi_bootstrap_ci95": mi_ci,
               "n_classes": n_classes,
               "class_prior_chance": round(1.0 / n_classes, 4),
               "log2_states_upper_bound_bits": log2k_upper}
        if name in ("device", "operation", "ack_mode"):
            bacc, lo, hi, chance, folds = grouped_balanced_accuracy(f, y, g, k=k)
            blk["grouped_balanced_accuracy"] = None if math.isnan(bacc) else round(bacc, 4)
            blk["grouped_bal_acc_ci95"] = None if math.isnan(lo) else [round(lo, 4), round(hi, 4)]
            blk["grouped_chance"] = None if math.isnan(chance) else round(chance, 4)
            blk["per_fold_bal_acc"] = folds
            blk["n_groups"] = len(set(g))
        out[name] = blk
    out["_size_states_used"] = n_states_used
    out["_log2_states_upper_bound_bits"] = log2k_upper
    return out


# --------------------------------------------------------------------------- overhead (§6.11)
def measured_cadence(records):
    """Median transactions/second per flow, from request inter-arrival times."""
    byflow = defaultdict(list)
    for r in records:
        if r["role"] in ("READ_REQUEST", "DIRECT_OPERATE_REQUEST", "SELECT", "WRITE_REQUEST"):
            byflow[(r["device"], r["capture_id"], r["flow"])].append(r["ts"])
    deltas = []
    for _k, ts in byflow.items():
        ts = sorted(ts)
        deltas += [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]
    if not deltas:
        return 1.0
    med = float(np.median(deltas))
    return 1.0 / med if med > 0 else 1.0


def overhead(cand, records, txn_per_sec):
    """Actual padding overhead per direction (§6.11). Padding is summed per transaction, then averaged
    over transactions — never mean-packet-padding times a reconstructed 6-slot window."""
    states = [s["target_frame_bytes"] for s in cand["size_states"]]

    # per-transaction padding by direction
    groups = defaultdict(list)
    for r in records:
        if r["transaction_id"] > 0:
            groups[(r["device"], r["capture_id"], r["flow"], r["transaction_id"])].append(r)
    dir_pad = {"master_to_outstation": [], "outstation_to_master": []}
    n_txn = 0
    n_combined = 0
    for _k, pkts in groups.items():
        n_txn += 1
        am = pkts[0]["ack_mode_observed"]
        if am == "combined":
            n_combined += 1
        acc = {"master_to_outstation": 0, "outstation_to_master": 0}
        for r in pkts:
            s = map_state(states, r[SZ])
            if s is None:
                continue
            acc[r["direction"]] += (s - r[SZ])
        for d in acc:
            dir_pad[d].append(acc[d])
    mean_pad = {d: (sum(v) / len(v) if v else 0.0) for d, v in dir_pad.items()}

    # transaction-window cover: each COMBINED transaction gets ONE added outstation->master ACK cover
    # frame so it matches the 4-slot separate template. Cover frame = state the ACK size maps to.
    ack_size = next((r[SZ] for r in records if r["role"] == "ACK" and
                     r["direction"] == "outstation_to_master"), 66)
    cover_frame = map_state(states, ack_size) or states[-1]
    p_combined = n_combined / max(1, n_txn)

    def per_dir(pad_out, pad_in):
        # returns per-transaction / per-second / per-day dicts (bytes and kbps)
        def block(bytes_per_txn):
            per_s = bytes_per_txn * txn_per_sec
            return {"bytes_per_txn": round(bytes_per_txn, 3),
                    "bytes_per_sec": round(per_s, 3),
                    "kbps": round(per_s * 8 / 1000.0, 4),
                    "bytes_per_day": round(per_s * 86400, 1)}
        return {"master_to_outstation": block(pad_out), "outstation_to_master": block(pad_in)}

    cover_off = per_dir(mean_pad["master_to_outstation"], mean_pad["outstation_to_master"])
    # transaction-window: master direction unchanged (padding only); outstation direction adds the
    # expected cover ACK frame for the combined fraction of transactions.
    tw_in = mean_pad["outstation_to_master"] + p_combined * cover_frame
    txn_window = per_dir(mean_pad["master_to_outstation"], tw_in)
    # continuous upper bound: every transaction slot, BOTH directions, carries a top-state frame.
    top = states[-1]
    cont = per_dir(top, top)

    total_kbps = {
        "cover_off": round(cover_off["master_to_outstation"]["kbps"] +
                           cover_off["outstation_to_master"]["kbps"], 4),
        "transaction_window": round(txn_window["master_to_outstation"]["kbps"] +
                                    txn_window["outstation_to_master"]["kbps"], 4),
        "continuous_upper_bound": round(cont["master_to_outstation"]["kbps"] +
                                        cont["outstation_to_master"]["kbps"], 4),
    }
    return {
        "n_transactions": n_txn, "combined_fraction": round(p_combined, 4),
        "txn_per_sec": round(txn_per_sec, 4),
        "cover_frame_bytes_added_per_combined_txn": cover_frame,
        "mean_padding_bytes_per_txn_by_direction": {d: round(v, 3) for d, v in mean_pad.items()},
        "cover_off_padding_only": cover_off,
        "transaction_window_padding_plus_cover_ack": txn_window,
        "continuous_upper_bound": cont,
        "total_added_kbps": total_kbps,
    }


def feasibility(total_kbps, rto_ms):
    def rate(kbps):
        return {ln: ("ok" if kbps <= 0.10 * cap else "heavy" if kbps <= cap else "INFEASIBLE")
                for ln, cap in LINKS_KBPS.items()}
    return {mode: rate(kbps) for mode, kbps in total_kbps.items()} | \
           {"rto_ceiling_ms": rto_ms,
            "note": "padding adds ~0 transaction latency; the transaction-window worst-case slot wait "
                    "and the recirc hold deadline must both stay < RTO ceiling."}


def mean_padding_per_packet(cand, records):
    states = [s["target_frame_bytes"] for s in cand["size_states"]]
    pads = [(map_state(states, r[SZ]) - r[SZ]) for r in records if map_state(states, r[SZ]) is not None]
    return round(sum(pads) / max(1, len(pads)), 3), (max(pads) if pads else 0)


# --------------------------------------------------------------------------- ranking & Pareto
def ranking_sensitivity(evals, weights):
    """For each leakage weight w: score = mean_pad_per_packet + w * MI(size;device). Lower is better.
    Returns {w: ordered list of candidate_ids}."""
    out = {}
    for w in weights:
        scored = []
        for e in evals:
            mi_dev = e["leakage"]["device"].get("mutual_information_bits", 0.0)
            score = e["mean_padding_per_packet"] + w * mi_dev
            scored.append((score, e["candidate_id"]))
        scored.sort()
        out[str(w)] = [{"candidate": c, "score": round(s, 4)} for s, c in scored]
    return out


def pareto_frontier(evals):
    """Non-dominated set over (mean padding, MI-device, #states, queue count, max latency, cover
    overhead) — all minimized. A candidate is dominated if another is <= on every axis and < on one."""
    pts = []
    for e in evals:
        pts.append((e["candidate_id"], [
            e["mean_padding_per_packet"],
            e["leakage"]["device"].get("mutual_information_bits", 0.0),
            e["n_states"],
            e["queue_count"],
            e["max_latency_ms"],
            e["overhead"]["total_added_kbps"]["transaction_window"],
        ]))
    frontier = []
    for cid, v in pts:
        dominated = False
        for _cid2, v2 in pts:
            if v2 == v:
                continue
            if all(a <= b for a, b in zip(v2, v)) and any(a < b for a, b in zip(v2, v)):
                dominated = True
                break
        if not dominated:
            frontier.append(cid)
    return {"axes": ["mean_padding", "MI_device_bits", "n_states", "queue_count",
                     "max_latency_ms", "cover_overhead_kbps(txn_window)"],
            "pareto_optimal_candidates": sorted(set(frontier)),
            "points": {cid: v for cid, v in pts}}


# --------------------------------------------------------------------------- driver
def evaluate_candidate(cand, records, txn_per_sec, rto_ms, k, bootstrap):
    lk = leakage(cand, records, k=k, bootstrap=bootstrap)
    ov = overhead(cand, records, txn_per_sec)
    mean_pad, max_pad = mean_padding_per_packet(cand, records)
    n_states = len(cand["size_states"])
    queue_count = cand["real_queues_required"] + cand["cover_queues_required"]
    # max latency: transaction-window worst-case slot wait at a nominal 17 ms slot (CLRT-scale);
    # padding-only adds ~0. Bounded by RTO ceiling.
    win = cand["transaction_window_schedules"]["common_ackmode_hiding"]
    wlen = max((blk.get("window_len_slots", 0) for blk in win.values() if isinstance(blk, dict)),
               default=0)
    max_latency_ms = round(max(0, wlen - 1) * 17.0, 3)
    return {
        "candidate_id": cand["candidate_id"],
        "corpus_scope": cand["corpus_scope"],
        "states": [s["target_frame_bytes"] for s in cand["size_states"]],
        "n_states": n_states,
        "covers_largest_frame": cand["covers_largest_frame"],
        "fits_existing_p4": cand["fits_existing_p4"],
        "real_queues_required": cand["real_queues_required"],
        "cover_queues_required": cand["cover_queues_required"],
        "queue_count": queue_count,
        "mean_padding_per_packet": mean_pad,
        "max_padding_per_packet": max_pad,
        "max_latency_ms": max_latency_ms,
        "leakage": lk,
        "overhead": ov,
        "feasibility": feasibility(ov["total_added_kbps"], rto_ms),
    }


def sanity_check(evals):
    """Verify: any single-state candidate has MI==0 for every target and grouped balanced accuracy at
    chance (1/n_classes)."""
    results = []
    for e in evals:
        if e["n_states"] != 1:
            continue
        ok = True
        details = []
        for name in ("device", "operation", "ack_mode", "direction"):
            blk = e["leakage"].get(name, {})
            mi = blk.get("mutual_information_bits", None)
            if mi is None:
                continue
            if abs(mi) > 1e-9:
                ok = False
                details.append("%s MI=%.4f (expected 0)" % (name, mi))
        for name in ("device", "operation", "ack_mode"):
            blk = e["leakage"].get(name, {})
            ba = blk.get("grouped_balanced_accuracy")
            ch = blk.get("grouped_chance")
            if ba is None or ch is None:
                continue
            if abs(ba - ch) > 1e-6:
                ok = False
                details.append("%s bal_acc=%.4f != chance=%.4f" % (name, ba, ch))
        results.append({"candidate": e["candidate_id"], "single_state_invariant_holds": ok,
                        "violations": details})
    return results


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--scope", default="base", choices=["base", "long", "multicrob"])
    ap.add_argument("--invdir", default=os.path.join(here, "inventory"))
    ap.add_argument("--candir", default=os.path.join(here, "queue_pattern_candidates"))
    ap.add_argument("--rto-ms", type=float, default=211.0)
    ap.add_argument("--kfolds", type=int, default=2)
    ap.add_argument("--bootstrap", type=int, default=200)
    ap.add_argument("--out", default=os.path.join(here, "evaluation.json"))
    a = ap.parse_args()

    with open(os.path.join(a.invdir, "%s_analysis.json" % a.scope)) as f:
        doc_inv = json.load(f)
    records = doc_inv["records"]
    annotate_operation(records)
    txn_per_sec = measured_cadence(records)

    candir = os.path.join(a.candir, a.scope)
    evals = []
    for fn in sorted(os.listdir(candir)):
        if fn.endswith(".json"):
            with open(os.path.join(candir, fn)) as f:
                cand = json.load(f)
            assert os.path.splitext(fn)[0] == cand["candidate_id"], "filename must equal candidate_id"
            evals.append(evaluate_candidate(cand, records, txn_per_sec, a.rto_ms, a.kfolds, a.bootstrap))

    rank_sens = ranking_sensitivity(evals, LEAKAGE_WEIGHTS)
    pareto = pareto_frontier(evals)
    sanity = sanity_check(evals)

    out = {"schema_version": "1.1.0", "scope": a.scope, "rto_ms": a.rto_ms,
           "measured_txn_per_sec": round(txn_per_sec, 4), "kfolds": a.kfolds,
           "leakage_note": "MEASURED empirical MI (bits) + grouped balanced accuracy (folds grouped by "
                           "flow); log2(#states) kept only as a labelled theoretical upper bound.",
           "ranking_sensitivity_weights": LEAKAGE_WEIGHTS,
           "ranking_sensitivity": rank_sens,
           "pareto_frontier": pareto,
           "single_state_sanity": sanity,
           "evaluations": {e["candidate_id"]: e for e in evals}}
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)

    # ---- console report ----
    print("== scope %s == measured cadence = %.3f txn/s ==" % (a.scope, txn_per_sec))
    print("\nLEAKAGE (mapped size-state vs target): MI bits [95%% CI] | grouped balanced acc vs chance")
    hdr = "  %-26s %-6s %-22s %-22s %-22s %-16s"
    print(hdr % ("candidate(states)", "#st", "MI_device", "MI_operation", "MI_ackmode", "MI_direction"))
    for e in evals:
        L = e["leakage"]
        def cell(name):
            b = L.get(name, {})
            if "mutual_information_bits" not in b:
                return "n/a"
            ci = b.get("mi_bootstrap_ci95", (None, None))
            return "%.3f[%.2f,%.2f]" % (b["mutual_information_bits"], ci[0], ci[1])
        print(hdr % ("%s%s" % (e["candidate_id"][:18], e["states"]), e["n_states"],
                     cell("device"), cell("operation"), cell("ack_mode"), cell("direction")))
    print("\nGROUPED BALANCED ACCURACY (predict target from size-state; folds grouped by flow):")
    for e in evals:
        L = e["leakage"]
        parts = []
        for name in ("device", "operation", "ack_mode"):
            b = L.get(name, {})
            ba = b.get("grouped_balanced_accuracy"); ch = b.get("grouped_chance")
            if ba is None:
                parts.append("%s=n/a" % name)
            else:
                parts.append("%s=%.3f(chance %.3f)" % (name, ba, ch))
        print("  %-26s %s" % ("%s%s" % (e["candidate_id"][:18], e["states"]), "  ".join(parts)))
    print("\nSINGLE-STATE SANITY INVARIANT (MI==0, bal_acc==chance):")
    for s in sanity:
        print("  %-26s holds=%s %s" % (s["candidate"], s["single_state_invariant_holds"],
                                       s["violations"] or ""))
    print("\nPER-DIRECTION OVERHEAD (bytes/txn | kbps at %.2f txn/s):" % txn_per_sec)
    for e in evals:
        ov = e["overhead"]
        co = ov["cover_off_padding_only"]; tw = ov["transaction_window_padding_plus_cover_ack"]
        print("  %-26s cover=OFF m->o %.1fB/%.4gkbps  o->m %.1fB/%.4gkbps | txn-window o->m %.1fB/%.4gkbps"
              % ("%s%s" % (e["candidate_id"][:18], e["states"]),
                 co["master_to_outstation"]["bytes_per_txn"], co["master_to_outstation"]["kbps"],
                 co["outstation_to_master"]["bytes_per_txn"], co["outstation_to_master"]["kbps"],
                 tw["outstation_to_master"]["bytes_per_txn"], tw["outstation_to_master"]["kbps"]))
    print("\nRANKING SENSITIVITY (score = mean_pad + w*MI_device; lower better):")
    for w in LEAKAGE_WEIGHTS:
        order = " > ".join("%s(%.2f)" % (x["candidate"], x["score"]) for x in rank_sens[str(w)])
        print("  w=%-4s %s" % (w, order))
    print("\nPARETO-OPTIMAL candidates over %s:" % pareto["axes"])
    print("  ", pareto["pareto_optimal_candidates"])
    print("\nwrote", a.out)


if __name__ == "__main__":
    main()
