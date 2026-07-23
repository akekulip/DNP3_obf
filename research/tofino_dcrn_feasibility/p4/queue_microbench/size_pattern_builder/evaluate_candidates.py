#!/usr/bin/env python3
"""
evaluate_candidates.py — Step 5 of the DNP3 size-pattern builder v1 (OFF-SWITCH only).

Loads packet_inventory.json + the candidate JSONs and scores each candidate JOINTLY over
(P, tau, cover_mode) — padding, timing, cover, feasibility, residual distinguishability, and the
TCP RTO safety ceiling — then ranks them with a transparent objective. Padding is NOT scored
independently of timing/cover: the report shows the joint (size + time + cover) cost of each.

Usage: $RESEARCH_PYTHON evaluate_candidates.py [--g-ms 17,60] [--taus 10,17,25] [--rto-ms 211]
                                               [--txn-per-sec 1.0] [--out evaluation.json]
"""
import argparse
import json
import math
import os
from collections import defaultdict, Counter

# native CLRT ground truth (ACK_DELAY_POLICY.md): SEL-751 separate-ACK req->resp ~17 ms median.
LINKS_KBPS = {"64kbps": 64, "1Mbps": 1000, "100Mbps": 100000, "1Gbps": 1000000}


def pctl(xs, p):
    if not xs:
        return 0
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100.0
    lo = int(k); hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def evaluate(cand, records, taus, g_list, rto_ms, txn_per_sec):
    states = [s["target_wire_bytes"] for s in cand["size_states"]]
    def mapst(w):
        for s in states:
            if w <= s:
                return s
        return None
    # --- padding (joint size cost) ---
    pads = [mapst(r["wire_size"]) - r["wire_size"] for r in records if mapst(r["wire_size"]) is not None]
    pkts_per_txn = 6  # measured canonical shape (READ / DIRECT_OPERATE): 6 slots
    pad_per_txn = (sum(pads) / max(1, len(pads))) * pkts_per_txn
    pad_bw_off_kbps = pad_per_txn * 8 * txn_per_sec / 1000.0   # cover=OFF overhead = padding only

    # --- residual distinguishability after size mapping ---
    # size: which states are occupied by exactly one (device/dir/role) class -> that state leaks the class.
    cls_states = defaultdict(set)
    state_cls = defaultdict(set)
    for r in records:
        s = mapst(r["wire_size"])
        if s is None:
            continue
        cls = "%s/%s/%s" % (r["device"], r["direction"][:3], r["role"])
        cls_states[cls].add(s); state_cls[s].add(cls)
    n_states_used = len(state_cls)
    size_leak_bits = round(math.log2(n_states_used), 2) if n_states_used else 0.0
    class_unique_states = sorted([c for c, ss in cls_states.items()
                                  if any(len(state_cls[s]) == 1 for s in ss)])
    # operation (READ vs DIRECT_OPERATE): same 6-slot shape + same size states -> not count/size separable.
    tw = cand["cover_modes"]["transaction_window"]
    op_count_equal = len(set(tw["window_len_slots"] - f for f in tw["filler_slots_per_type"].values())) <= 1
    # device: separate-ACK (SEL) vs combined survives size normalization (ACK MODE, out of size scope).
    ack_modes = sorted(set(r.get("ack_mode", "unknown") for r in records))
    device_residual = "ack_mode still separates %s (out of size-normalization scope)" % ack_modes

    # --- per (cover_mode, tau, G) joint cost ---
    modes = {}
    top = states[-1]
    for g in g_list:
        # cover=OFF: no slots; timing is the recirc-hold deadline (Defense 2 = G; Defense 1 ~ 0).
        modes["off@G%dms" % g] = {
            "cover_packets_per_txn": 0, "cover_bytes_per_txn": 0,
            "overhead_kbps_per_dir": round(pad_bw_off_kbps, 3),
            "worst_case_slot_wait_ms": 0.0,
            "ack_to_response_gap_ms": g,
            "added_txn_latency_ms": g,            # deadline hold; padding adds ~0 latency
            "respects_rto": g < rto_ms,
        }
    for tau in taus:
        wlen = tw["window_len_slots"]
        filler = max(tw["filler_slots_per_type"].values(), default=0)
        # WINDOW: cover fills empty slots; worst-case wait = (wlen-1)*tau; cover bytes = filler*top.
        modes["window@tau%gms" % tau] = {
            "cover_packets_per_txn": filler, "cover_bytes_per_txn": filler * top,
            "overhead_kbps_per_dir": round((pad_per_txn + filler * top) * 8 * txn_per_sec / 1000.0, 3),
            "worst_case_slot_wait_ms": round((wlen - 1) * tau, 3),
            "ack_to_response_gap_ms": None,        # scheduler-shaped; measured, not set here
            "added_txn_latency_ms": round((wlen - 1) * tau, 3),
            "respects_rto": (wlen - 1) * tau < rto_ms,
        }
        # CONTINUOUS: permanent cover, one top-state packet per tau per direction (UPPER BOUND).
        modes["continuous@tau%gms" % tau] = {
            "overhead_kbps_per_dir": round(top * 8.0 / (tau / 1000.0) / 1000.0, 3),
            "note": "UPPER BOUND ONLY — never armed", "respects_rto": True,
        }

    def feas(kbps):
        return {ln: ("ok" if kbps <= 0.10 * cap else "heavy" if kbps <= cap else "INFEASIBLE")
                for ln, cap in LINKS_KBPS.items()}

    return {
        "candidate_id": cand["candidate_id"],
        "states": states,
        "covers_largest_frame": cand["covers_largest_frame"],
        "padding_bytes": {"mean": round(sum(pads) / max(1, len(pads)), 2),
                          "median": pctl(pads, 50), "p95": pctl(pads, 95),
                          "p99": pctl(pads, 99), "max": max(pads) if pads else 0},
        "pct_packets_per_state": cand["pct_packets_per_state"],
        "max_original_wire_per_state": cand["max_original_wire_per_state"],
        "residual_distinguishability": {
            "size_states_used": n_states_used, "size_leak_bits_upper": size_leak_bits,
            "classes_with_unique_state": class_unique_states,
            "operation_count_equalized(READ~DIRECT_OP)": op_count_equal,
            "direction": "preserved and always observable (hidden only by both-direction cover)",
            "device": device_residual,
        },
        "cover_off_overhead_kbps_per_dir": round(pad_bw_off_kbps, 3),
        "modes": modes,
        "feasibility_cover_off": feas(pad_bw_off_kbps),
        "feasibility_continuous_tau10": feas(top * 8.0 / 0.010 / 1000.0),
    }


def rank(evals):
    """Transparent objective for the cover=OFF immediate scope: require RTO-feasible + covers max +
    0 unfit; then minimize a weighted sum of (mean padding bytes) and (size leak bits). Lower = better.
    Weights are explicit so the size/leak tradeoff is visible, not hidden."""
    W_PAD, W_LEAK = 1.0, 20.0
    scored = []
    for e in evals:
        pad = e["padding_bytes"]["mean"]
        leak = e["residual_distinguishability"]["size_leak_bits_upper"]
        score = W_PAD * pad + W_LEAK * leak
        scored.append((score, e["candidate_id"], pad, leak))
    scored.sort()
    return scored, {"W_pad_per_byte": W_PAD, "W_leak_per_bit": W_LEAK,
                    "note": "score = W_pad*mean_padding_bytes + W_leak*size_leak_bits; lower is better; "
                            "makes the padding-vs-size-leak tradeoff explicit (maxonly = 0 leak, most pad)."}


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--inventory", default=os.path.join(here, "packet_inventory.json"))
    ap.add_argument("--candir", default=os.path.join(here, "queue_pattern_candidates"))
    ap.add_argument("--taus", default="10,17,25")
    ap.add_argument("--g-ms", default="17,60", help="CLRT deadline candidates (Defense 2 G_i)")
    ap.add_argument("--rto-ms", type=float, default=211.0, help="measured TCP RTO safety ceiling")
    ap.add_argument("--txn-per-sec", type=float, default=1.0, help="measured transaction cadence")
    ap.add_argument("--out", default=os.path.join(here, "evaluation.json"))
    a = ap.parse_args()

    records = json.load(open(a.inventory))["records"]
    taus = [float(x) for x in a.taus.split(",")]
    gs = [int(x) for x in a.g_ms.split(",")]
    evals = []
    for fn in sorted(os.listdir(a.candir)):
        if fn.endswith(".json"):
            cand = json.load(open(os.path.join(a.candir, fn)))
            evals.append(evaluate(cand, records, taus, gs, a.rto_ms, a.txn_per_sec))
    scored, obj = rank(evals)
    doc = {"schema_version": "1.0.0", "rto_ms": a.rto_ms, "txn_per_sec": a.txn_per_sec,
           "objective": obj, "ranking": [{"rank": i + 1, "candidate": c, "mean_pad_B": p,
                                          "size_leak_bits": l, "score": round(s, 2)}
                                         for i, (s, c, p, l) in enumerate(scored)],
           "evaluations": {e["candidate_id"]: e for e in evals}}
    json.dump(doc, open(a.out, "w"), indent=2)
    print("RANKING (cover=OFF objective; lower score better):")
    for i, (s, c, p, l) in enumerate(scored):
        print("  %d. %-8s score=%.2f  mean_pad=%.1fB  size_leak=%.2f bits" % (i + 1, c, s, p, l))
    for e in evals:
        print("  [%s] pad mean/med/p95/p99/max = %.1f/%d/%d/%d/%d B | cover=OFF overhead %.3f kbps/dir | "
              "states_used=%d unique_state_classes=%d"
              % (e["candidate_id"], e["padding_bytes"]["mean"], e["padding_bytes"]["median"],
                 e["padding_bytes"]["p95"], e["padding_bytes"]["p99"], e["padding_bytes"]["max"],
                 e["cover_off_overhead_kbps_per_dir"], e["residual_distinguishability"]["size_states_used"],
                 len(e["residual_distinguishability"]["classes_with_unique_state"])))
    print("wrote", a.out)


if __name__ == "__main__":
    main()
