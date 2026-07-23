#!/usr/bin/env python3
"""
generate_candidates.py — Steps 3 & 4 of the DNP3 size-pattern builder v1 (OFF-SWITCH only).

Reads packet_inventory.json and produces several CANDIDATE size-state sets + per-mode schedule
descriptors, written to queue_pattern_candidates/<candidate>.json. Nothing is locked; each candidate
carries its explicit selection rule. Timing/cover are kept distinct per operating mode.

Design rules honored (CASE_A_QUEUE_DESIGN.md §0):
 - size states derive from the EMPIRICAL wire-size distribution (no illustrative 128/256);
 - always include a state >= the largest unsplit Tofino-path frame;
 - map smaller packets UPWARD only; no on-switch splitting;
 - cover=OFF is a size mapping for transmitted packets only (NO metronome / slot grid);
 - TRANSACTION_WINDOW builds direction-aware slots (direction,size,timing_position) + filler;
 - CONTINUOUS is computed as an optional upper bound only (never armed).

Usage: $RESEARCH_PYTHON generate_candidates.py [--inventory packet_inventory.json] [--taus 10,17,25]
"""
import argparse
import json
import math
import os
from collections import defaultdict, Counter

SCHEMA_VERSION = "1.0.0"


def pct(sorted_vals, p):
    if not sorted_vals:
        return 0
    k = (len(sorted_vals) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def roundup(x, m=1):
    # m=1 => raw empirical byte value (states are the actual observed sizes, NOT illustrative 128/256).
    # A hardware pad target would round up to a convenient boundary; kept raw here for transparency.
    return int(math.ceil(x / float(m)) * m)


def state_sets(wire_sorted):
    """Deterministic candidate size-state sets over the empirical wire-size distribution.
    Each is an ascending list of target wire sizes; the last is >= the global max (no splitting)."""
    mx = wire_sorted[-1]
    p50 = pct(wire_sorted, 50)
    p90 = pct(wire_sorted, 90)
    top = roundup(mx)
    sets = {}
    # C1: single state = pad everything to the max frame. Maximum size hiding, maximum padding.
    sets["maxonly"] = (
        [top],
        "single state at the largest frame (roundup8); every packet padded to one size — maximum "
        "size-indistinguishability, maximum padding overhead.")
    # C2: two states at ~p90 and max. Fewer padding bytes; the small (ACK) cluster keeps its own size.
    sets["quant2"] = (
        sorted(set([roundup(p90), top])),
        "two states at ceil8(p90) and the max frame — quantile split; lowers padding vs maxonly but a "
        "distinct small state means ACK-sized packets stay size-separable from responses.")
    # C3: three states at p50/p90/max.
    sets["quant3"] = (
        sorted(set([roundup(p50), roundup(p90), top])),
        "three states at ceil8(p50/p90/max) — lowest padding of the three; most size classes preserved "
        "(highest residual size-distinguishability).")
    # de-dup any set that collapsed to one value
    return {k: (v[0], v[1]) for k, v in sets.items() if v[0]}


def map_state(states, wire):
    """Smallest state >= wire (upward-only). If wire exceeds the top state -> None (would need split)."""
    for s in states:
        if wire <= s:
            return s
    return None


def txn_shapes(records):
    """Ordered (direction, role) sequence per (device, capture, transaction_id) — the transaction
    'shape' used to build TRANSACTION_WINDOW slot patterns and the filler needed to equalize types."""
    groups = defaultdict(list)
    for r in records:
        if r["transaction_id"] <= 0:
            continue
        key = (r["device"], r["capture_id"], r["transaction_id"])
        groups[key].append(r)
    shapes = defaultdict(Counter)   # txn_type -> Counter(shape_tuple)
    for key, pkts in groups.items():
        pkts = sorted(pkts, key=lambda r: (r["response_fragment_index"] if r["is_response"] else -2))
        # transaction type = the opening request role
        req = next((p["role"] for p in pkts if "REQUEST" in p["role"] or p["role"] in
                    ("SELECT", "OPERATE", "APP_CONFIRM")), "unknown")
        shape = tuple((p["direction"][:3], p["role"]) for p in pkts)
        shapes[req][shape] += 1
    return shapes


def build_candidate(cid, states, rule, records, taus):
    wires = [r["wire_size"] for r in records]
    mapped = [(r, map_state(states, r["wire_size"])) for r in records]
    unfit = [r for r, s in mapped if s is None]
    # per-class -> state assignment (device/direction/role) and per-state population
    class_state = defaultdict(Counter)
    state_pop = Counter()
    pad_bytes = []
    for r, s in mapped:
        if s is None:
            continue
        cls = "%s/%s/%s" % (r["device"], r["direction"][:3], r["role"])
        class_state[cls][s] += 1
        state_pop[s] += 1
        pad_bytes.append(s - r["wire_size"])
    # a class is "uniquely size-identifiable" if it maps to a state NO other class uses,
    # OR it is the only class in its state.
    state_classes = defaultdict(set)
    for cls, cnt in class_state.items():
        for s in cnt:
            state_classes[s].add(cls)
    uniq = sorted([cls for cls, cnt in class_state.items()
                   if any(len(state_classes[s]) == 1 for s in cnt)])

    size_states = [{"state": "S%d" % (i + 1), "target_wire_bytes": s} for i, s in enumerate(states)]

    # cover=OFF: size mapping only (transmitted packets); no slots.
    off = {
        "description": "pad each transmitted packet up to its state; timing = recirc-hold deadline "
                       "(dcrn); NO metronome, NO slot grid.",
        "class_to_state": {cls: ("S%d" % (states.index(list(cnt)[0]) + 1))
                           for cls, cnt in class_state.items() if len(cnt) == 1},
        "multi_state_classes": {cls: {("S%d" % (states.index(s) + 1)): n for s, n in cnt.items()}
                                for cls, cnt in class_state.items() if len(cnt) > 1},
    }

    # TRANSACTION_WINDOW: direction-aware canonical slots per transaction type + filler to equalize.
    shapes = txn_shapes(records)
    # canonical (most common) shape per type, expressed as slots (direction,size_state,timing_position)
    canon = {}
    for typ, cnt in shapes.items():
        best = cnt.most_common(1)[0][0] if cnt else ()
        slots = [{"timing_position": i, "direction": ("out" if d == "out" else "in"),
                  "role": role} for i, (d, role) in enumerate(best)]
        canon[typ] = slots
    maxlen = max((len(s) for s in canon.values()), default=0)
    window = {
        "description": "direction-aware slot pattern slot=(direction,size,timing_position); the "
                       "window is padded to the longest transaction shape with COVER filler slots so "
                       "different transaction types present an identical slot sequence.",
        "canonical_slots_per_type": canon,
        "window_len_slots": maxlen,
        "filler_slots_per_type": {typ: maxlen - len(sl) for typ, sl in canon.items()},
    }

    # CONTINUOUS: optional upper-bound bandwidth (one max-state packet per tau, each direction).
    top = states[-1]
    continuous = {tau: {"per_dir_kbps": round(top * 8.0 / (tau / 1000.0) / 1000.0, 2),
                        "note": "UPPER BOUND ONLY — never armed on the switch"}
                  for tau in taus}

    cand = {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": cid,
        "selection_rule": rule,
        "largest_frame_bytes": max(wires),
        "size_states": size_states,
        "covers_largest_frame": states[-1] >= max(wires),
        "unfit_packets": len(unfit),           # must be 0 (upward-only + top>=max)
        "pct_packets_per_state": {("S%d" % (i + 1)): round(100.0 * state_pop[s] / max(1, sum(state_pop.values())), 2)
                                  for i, s in enumerate(states)},
        "max_original_wire_per_state": {("S%d" % (i + 1)):
                                        max([r["wire_size"] for r, ss in mapped if ss == s], default=0)
                                        for i, s in enumerate(states)},
        "uniquely_size_identifiable_classes": uniq,
        "cover_modes": {"off": off, "transaction_window": window, "continuous": continuous},
    }
    return cand


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--inventory", default=os.path.join(here, "packet_inventory.json"))
    ap.add_argument("--outdir", default=os.path.join(here, "queue_pattern_candidates"))
    ap.add_argument("--taus", default="10,17,25", help="candidate slot intervals ms (cover modes)")
    a = ap.parse_args()

    inv = json.load(open(a.inventory))
    records = inv["records"]
    taus = [float(x) for x in a.taus.split(",")]
    wire_sorted = sorted(r["wire_size"] for r in records)
    os.makedirs(a.outdir, exist_ok=True)

    print("empirical wire size: min=%d p50=%.0f p90=%.0f max=%d (n=%d)"
          % (wire_sorted[0], pct(wire_sorted, 50), pct(wire_sorted, 90), wire_sorted[-1], len(wire_sorted)))
    sets = state_sets(wire_sorted)
    written = []
    for cid, (states, rule) in sets.items():
        cand = build_candidate(cid, states, rule, records, taus)
        path = os.path.join(a.outdir, cid + ".json")
        json.dump(cand, open(path, "w"), indent=2)
        written.append(path)
        print("  %-8s states=%s covers_max=%s unfit=%d uniq_classes=%d -> %s"
              % (cid, states, cand["covers_largest_frame"], cand["unfit_packets"],
                 len(cand["uniquely_size_identifiable_classes"]), os.path.basename(path)))
    print("wrote %d candidate JSONs to %s" % (len(written), a.outdir))


if __name__ == "__main__":
    main()
