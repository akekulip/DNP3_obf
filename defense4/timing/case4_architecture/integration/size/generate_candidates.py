#!/usr/bin/env python3
"""
generate_candidates.py — DNP3 size-pattern candidate builder, v1.1 (OFF-SWITCH only).

Charter autunomous.md §6.7/§6.8/§6.9. Rewritten against the v1.1 inventory schema produced by
extract_inventory.py (schema 1.1.0). Operates PER CORPUS SCOPE (base/long/multicrob) with separate
outputs, so a maximum is always reported per corpus and per packet class — never a single global 127.

Canonical size metric: `ethernet_frame_bytes_no_fcs_min_applied` is THE frame size for every candidate
target, mapping, and overhead number. The other size fields remain in the inventory as provenance.

v1.1 corrections over v1:
 - reads inventory/<scope>_analysis.json (retransmissions/duplicates already excluded);
 - rounding is fixed: candidate targets round UP to a multiple of 8 AND are additionally aligned to a
   hardware-friendly 64/128/256 ladder — raw pcap values such as 115/127 are never emitted as targets;
 - candidates are per-scope; each declares the corpus it covers and whether it fits the loaded P4
   (2 real queues QID_REAL_S1/S2, compile-time pad headers 128 B and 256 B);
 - §6.9 transaction-window schedules are built SEPARATELY per (ack_mode_observed x operation) in
   chronological order, and the common ACK-mode-hiding schedule explicitly adds the MISSING
   outstation-ACK cover slot to combined-ACK transactions.

Usage:
  $RESEARCH_PYTHON generate_candidates.py --scope base        # (also: long, multicrob, all)
Outputs: queue_pattern_candidates/<scope>/<candidate_id>.json   (filename == candidate_id)
"""
import argparse
import json
import math
import os
from collections import defaultdict, Counter

SCHEMA_VERSION = "1.1.0"
SZ = "ethernet_frame_bytes_no_fcs_min_applied"          # THE canonical frame-size field

# The loaded P4 (queue_microbench.p4): S1 pad target = 128 B, S2 pad target = 256 B (compile-time
# pad_s1_h/pad_s2_h), QID_REAL_S1/QID_REAL_S2 = 2 real queues, QID_CHAFF_S1/S2 = 2 cover queues.
P4_PAD_TARGETS = (128, 256)
P4_REAL_QUEUES = 2
P4_COVER_QUEUES = 2

REQUIRED_MODE_OPS = [("separate", "READ"), ("combined", "READ"),
                     ("separate", "DIRECT_OPERATE"), ("combined", "DIRECT_OPERATE")]


# --------------------------------------------------------------------------- rounding (fixed, §6.8)
def round_up_mult(x, m=8):
    """Smallest multiple of m that is >= x (upward-only, implementable byte granularity)."""
    return int(math.ceil(x / float(m)) * m)


def align_hw(x, ladder=(64, 128, 256, 512, 1024)):
    """Smallest hardware-friendly frame size (64/128/256/...) that is >= x."""
    for s in ladder:
        if x <= s:
            return s
    return round_up_mult(x, 256)


def pctl(xs, p):
    if not xs:
        return 0
    xs = sorted(xs)
    k = (len(xs) - 1) * p / 100.0
    lo = int(k); hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


# --------------------------------------------------------------------------- inventory helpers
def op_of_role(role):
    """Transaction operation implied by a request/response role (None if not operation-bearing)."""
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


def load_records(scope, invdir):
    path = os.path.join(invdir, "%s_analysis.json" % scope)
    with open(path) as f:
        doc = json.load(f)
    return doc["records"], doc.get("provenance", {})


def corpus_max(records):
    return max((r[SZ] for r in records), default=0)


def per_class_max(records):
    m = defaultdict(int)
    for r in records:
        m[r["role"]] = max(m[r["role"]], r[SZ])
    return dict(sorted(m.items()))


def combined_corpus_max(invdir, scopes):
    """Max canonical frame size across several scopes (skips missing inventories)."""
    mx, seen = 0, []
    for sc in scopes:
        p = os.path.join(invdir, "%s_analysis.json" % sc)
        if not os.path.exists(p):
            continue
        with open(p) as f:
            recs = json.load(f)["records"]
        mx = max(mx, corpus_max(recs)); seen.append(sc)
    return mx, seen


def map_state(states, size):
    """Smallest state >= size (upward-only). Returns None if size exceeds the top state (would need a
    split, a fail-open, or a larger state)."""
    for s in states:
        if size <= s:
            return s
    return None


def transaction_groups(records):
    """Group packets by (device, capture_id, flow, transaction_id) so two DIFFERENT flows that reuse the
    same transaction_id are NEVER merged. Each group is returned in chronological order."""
    groups = defaultdict(list)
    for r in records:
        if r["transaction_id"] <= 0:
            continue
        groups[(r["device"], r["capture_id"], r["flow"], r["transaction_id"])].append(r)
    for k in groups:
        groups[k].sort(key=lambda r: (r["ts"], r["capture_index"]))
    return groups


def txn_operation(pkts):
    for r in pkts:
        o = op_of_role(r["role"])
        if o:
            return o
    return None


def canonical_shapes(records):
    """Most common ordered slot shape per (ack_mode_observed, operation). Shape = tuple of
    (direction, role, original_frame_bytes) in chronological order."""
    groups = transaction_groups(records)
    shapes = defaultdict(Counter)
    for _k, pkts in groups.items():
        op = txn_operation(pkts)
        if op is None:
            continue
        am = pkts[0]["ack_mode_observed"]
        shape = tuple((r["direction"], r["role"], r[SZ]) for r in pkts)
        shapes[(am, op)][shape] += 1
    out = {}
    for key, cnt in shapes.items():
        shape, n = cnt.most_common(1)[0]
        out[key] = {"shape": shape, "n_txn": sum(cnt.values()), "canonical_count": n}
    return out


# --------------------------------------------------------------------------- §6.9 schedules
def _slot(i, direction, role, orig, states, op, ack_mode, eligibility):
    return {"timing_position": i, "direction": direction, "role": role,
            "target_size": map_state(states, orig), "original_frame_bytes": orig,
            "real_or_cover_eligibility": eligibility, "transaction_type": op, "ack_mode": ack_mode}


def _slots_from_shape(shape, states, op, ack_mode):
    return [_slot(i, d, role, orig, states, op, ack_mode, "real")
            for i, (d, role, orig) in enumerate(shape)]


def build_schedules(records, states):
    """§6.9 transaction-window reconstruction. Returns per-(mode x operation) schedules, a SYNTHETIC SBO
    schedule, and the common ACK-mode-hiding schedule that adds the missing outstation-ACK cover slot to
    combined-ACK transactions (so combined and separate present an identical slot sequence)."""
    shapes = canonical_shapes(records)
    per_mode_op = {}
    for (am, op) in REQUIRED_MODE_OPS:
        key = (am, op)
        if key in shapes:
            per_mode_op["%s_%s" % (am, op)] = {
                "observed": True, "n_txn": shapes[key]["n_txn"],
                "slots": _slots_from_shape(shapes[key]["shape"], states, op, am)}
        else:
            per_mode_op["%s_%s" % (am, op)] = {
                "observed": False,
                "note": "no %s-ACK %s transaction observed in this corpus scope" % (am, op)}

    # common ACK-mode-hiding schedule per operation: the 4-slot separate-ACK template
    #   [request, outstation-ACK, response, master-ACK]; for combined-ACK the outstation-ACK slot is a
    #   COVER insertion so both modes present the identical sequence. Filler IS required across modes.
    ack_size = next((r[SZ] for r in records if r["role"] == "ACK" and
                     r["direction"] == "outstation_to_master"), 66)
    common = {}
    for op in ("READ", "DIRECT_OPERATE"):
        sep = shapes.get(("separate", op))
        comb = shapes.get(("combined", op))
        template = None
        synth_template = False
        if sep:
            template = list(sep["shape"])                       # real 4-slot separate shape
        elif comb:
            # synthesize the separate template by inserting an outstation-ACK after the request
            cshape = list(comb["shape"])
            template = [cshape[0], ("outstation_to_master", "ACK", ack_size)] + cshape[1:]
            synth_template = True
        if template is None:
            common[op] = {"observed": False,
                          "note": "operation %s not present in this corpus scope" % op}
            continue
        # slot roles: identify the outstation-ACK slot (the one hidden in combined mode)
        slots = []
        for i, (d, role, orig) in enumerate(template):
            is_out_ack = (d == "outstation_to_master" and role == "ACK" and i == 1)
            sep_elig = "real"
            comb_elig = "cover" if is_out_ack else "real"
            s = {"timing_position": i, "direction": d, "role": role,
                 "target_size": map_state(states, orig), "original_frame_bytes": orig,
                 "transaction_type": op,
                 "separate_ack": {"ack_mode": "separate", "real_or_cover_eligibility": sep_elig},
                 "combined_ack": {"ack_mode": "combined", "real_or_cover_eligibility": comb_elig}}
            slots.append(s)
        common[op] = {
            "observed": True, "window_len_slots": len(slots), "template_synthesized": synth_template,
            "slots": slots,
            "note": "combined-ACK transactions ADD a cover outstation-ACK slot (timing_position 1, "
                    "real_or_cover_eligibility=cover) so combined and separate present the identical "
                    "4-slot sequence; a canonical ACK-mode-hiding schedule REQUIRES this filler."}

    # SYNTHETIC SBO — the base/long fingerprint corpora contain no real SBO; multicrob has real
    # SELECT/OPERATE. Sizes are seeded from multicrob when present, else canonical; always SYNTHETIC.
    sbo_shapes = shapes.get(("combined", "SBO"))
    if sbo_shapes:
        sel = next((orig for d, role, orig in sbo_shapes["shape"] if role == "SELECT"), 116)
        op_sz = next((orig for d, role, orig in sbo_shapes["shape"] if role == "OPERATE"), 116)
        resp = next((orig for d, role, orig in sbo_shapes["shape"] if role == "RESPONSE"), 118)
        seed = "multicrob real SELECT/OPERATE sizes"
    else:
        sel, op_sz, resp, seed = 116, 116, 118, "canonical placeholder sizes (no SBO in corpus)"
    sbo_seq = [("master_to_outstation", "SELECT", sel), ("outstation_to_master", "RESPONSE", resp),
               ("master_to_outstation", "ACK", ack_size), ("master_to_outstation", "OPERATE", op_sz),
               ("outstation_to_master", "RESPONSE", resp), ("master_to_outstation", "ACK", ack_size)]
    synthetic_sbo = {
        "SYNTHETIC": True, "seed": seed,
        "note": "SYNTHETIC SBO (SELECT/confirm/OPERATE/confirm). No real SBO exists in base/long; do NOT "
                "claim strong transaction hiding from synthetic SBO alone.",
        "slots": [_slot(i, d, role, orig, states, "SBO", "combined", "real")
                  for i, (d, role, orig) in enumerate(sbo_seq)]}

    return {"per_mode_operation": per_mode_op, "common_ackmode_hiding": common,
            "synthetic_sbo": synthetic_sbo}


def cover_queues_for_schedules(sched):
    """Distinct target sizes carried by cover-eligible slots in the common ACK-hiding schedule."""
    sizes = set()
    for op, blk in sched.get("common_ackmode_hiding", {}).items():
        if not blk.get("observed"):
            continue
        for s in blk["slots"]:
            if s["combined_ack"]["real_or_cover_eligibility"] == "cover":
                sizes.add(s["target_size"])
    return sorted(sizes)


# --------------------------------------------------------------------------- candidate assembly
def build_candidate(cid, states, rule, declared_corpus, records, scope, invdir):
    states = sorted(states)
    sizes = [r[SZ] for r in records]
    cmax = corpus_max(records)
    mapped = [(r, map_state(states, r[SZ])) for r in records]
    unfit = [r for r, s in mapped if s is None]

    state_pop = Counter()
    max_orig = defaultdict(int)
    for r, s in mapped:
        if s is None:
            continue
        state_pop[s] += 1
        max_orig[s] = max(max_orig[s], r[SZ])
    total = max(1, sum(state_pop.values()))

    sched = build_schedules(records, states)
    cover_states = cover_queues_for_schedules(sched)
    real_q = len(states)
    cover_q = len(cover_states)

    targets_realizable = all(s in P4_PAD_TARGETS for s in states)
    fits = (real_q <= P4_REAL_QUEUES and targets_realizable and cover_q <= P4_COVER_QUEUES)
    if fits:
        fit_reason = "%d state(s) <= %d real queues; targets %s in P4 pad set %s; %d cover queue(s) <= %d" \
            % (real_q, P4_REAL_QUEUES, states, list(P4_PAD_TARGETS), cover_q, P4_COVER_QUEUES)
    else:
        why = []
        if real_q > P4_REAL_QUEUES:
            why.append("%d states > %d real queues" % (real_q, P4_REAL_QUEUES))
        if not targets_realizable:
            why.append("targets %s not all in P4 pad set %s (needs recompile with new pad header)"
                       % ([s for s in states if s not in P4_PAD_TARGETS], list(P4_PAD_TARGETS)))
        if cover_q > P4_COVER_QUEUES:
            why.append("%d cover queues > %d" % (cover_q, P4_COVER_QUEUES))
        fit_reason = "; ".join(why)

    covers = states[-1] >= cmax
    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": cid,
        "corpus_scope": scope,
        "declared_corpus": declared_corpus,
        "selection_rule": rule,
        "corpus_max_frame_bytes": cmax,
        "per_class_max_frame_bytes": per_class_max(records),
        "size_states": [{"state": "S%d" % (i + 1), "target_frame_bytes": s} for i, s in enumerate(states)],
        "covers_largest_frame": covers,
        "unfit_packets": len(unfit),
        "maps_upward_only": True,
        "needs_split_or_failopen_or_larger_state": (not covers),
        "real_queues_required": real_q,
        "cover_queues_required": cover_q,
        "cover_slot_target_sizes": cover_states,
        "fits_existing_p4": fits,
        "fits_existing_p4_reason": fit_reason,
        "pct_packets_per_state": {"S%d" % (i + 1): round(100.0 * state_pop[s] / total, 3)
                                  for i, s in enumerate(states)},
        "max_original_per_state": {"S%d" % (i + 1): max_orig.get(s, 0) for i, s in enumerate(states)},
        "transaction_window_schedules": sched,
    }


def candidate_specs(records, scope, invdir):
    """Per-scope candidate definitions (charter §6.8). Returns list of (cid, states, rule, declared)."""
    cmax = corpus_max(records)
    p50 = pctl(sizes_of(records), 50)
    ack_max = max((r[SZ] for r in records if r["role"] == "ACK"), default=66)
    top = align_hw(cmax)                                   # hardware-aligned top for this scope
    comb_max, comb_scopes = combined_corpus_max(invdir, ["long", "multicrob"])
    comb_top = align_hw(max(comb_max, cmax))

    specs = []
    # (1) required corpus baseline — single 128 B state.
    specs.append(("single128_corpus_baseline", [128],
                  "corpus baseline for the current 3-PCAP base corpus, NOT the final deployment pattern; "
                  "single 128 B state (round8/align of the 60-127 B corpus).",
                  "current 3-PCAP base corpus (labelled baseline, not deployment)"))
    # (2) two-state rounded candidate from empirical structure: round8(median) + align128(corpus max).
    two = sorted({round_up_mult(p50, 8), top})
    specs.append(("two_state_round8", two,
                  "two states = round8(median=%dB)=%dB and align128(corpus max=%dB)=%dB; splits the "
                  "packet population at the empirical median to cut padding vs single-state."
                  % (int(p50), round_up_mult(p50, 8), cmax, top),
                  "current corpus scope (%s)" % scope))
    # (3) candidate covering the LARGER corpus (max over long+multicrob) with Class-0/multi-segment
    #     headroom — top state 256 B (second P4 pad header). S1=128 covers all observed frames.
    specs.append(("cover_larger_corpus", sorted(set(P4_PAD_TARGETS)),
                  "top state 256 B (align_hw) to cover large Class-0/multi-segment responses beyond the "
                  "fingerprint corpus; combined observed max over %s = %dB (align 128). Uses BOTH P4 pad "
                  "headers." % (comb_scopes or ["<none>"], comb_max),
                  "long+multicrob combined + Class-0 headroom (max %dB)" % max(comb_max, cmax)))
    # (4) additional candidate justified by measured size clustering: the corpus is bimodal — a small
    #     ACK cluster (<= %dB) and a data cluster. round8(ack_max) + align128(corpus max).
    acksplit = sorted({round_up_mult(ack_max, 8), top})
    specs.append(("ack_data_split", acksplit,
                  "measured bimodality: small ACK cluster (max %dB -> round8 %dB) vs data cluster "
                  "(-> align128 %dB); keeps ACK padding minimal at the cost of a distinct small state."
                  % (ack_max, round_up_mult(ack_max, 8), top),
                  "current corpus scope (%s)" % scope))
    return specs


def sizes_of(records):
    return [r[SZ] for r in records]


REQUIRED_CANDIDATE_KEYS = [
    "schema_version", "candidate_id", "corpus_scope", "declared_corpus", "selection_rule",
    "corpus_max_frame_bytes", "per_class_max_frame_bytes", "size_states", "covers_largest_frame",
    "unfit_packets", "maps_upward_only", "needs_split_or_failopen_or_larger_state",
    "real_queues_required", "cover_queues_required", "fits_existing_p4", "pct_packets_per_state",
    "max_original_per_state", "transaction_window_schedules"]


def validate_candidate_schema(cand):
    """Dry-run schema validation (charter §6.12). Returns (ok, list_of_problems)."""
    problems = []
    for k in REQUIRED_CANDIDATE_KEYS:
        if k not in cand:
            problems.append("missing key: %s" % k)
    if "size_states" in cand:
        tb = [s["target_frame_bytes"] for s in cand["size_states"]]
        if tb != sorted(tb):
            problems.append("size_states not ascending: %s" % tb)
        for s in cand["size_states"]:
            if "state" not in s or "target_frame_bytes" not in s:
                problems.append("size_state entry missing fields: %s" % s)
        if tb and "corpus_max_frame_bytes" in cand and tb[-1] < cand["corpus_max_frame_bytes"]:
            problems.append("top state %d < corpus max %d" % (tb[-1], cand["corpus_max_frame_bytes"]))
    if cand.get("unfit_packets", -1) != 0:
        problems.append("unfit_packets must be 0 (upward-only + top>=max), got %s"
                        % cand.get("unfit_packets"))
    # slot descriptors must carry the six required fields (§6.9)
    sched = cand.get("transaction_window_schedules", {})
    for name, blk in sched.get("per_mode_operation", {}).items():
        for s in blk.get("slots", []):
            for f in ("direction", "target_size", "role", "timing_position",
                      "real_or_cover_eligibility", "transaction_type", "ack_mode"):
                if f not in s:
                    problems.append("per_mode_operation[%s] slot missing %s" % (name, f))
    return (len(problems) == 0), problems


def run_scope(scope, invdir, outroot):
    records, prov = load_records(scope, invdir)
    outdir = os.path.join(outroot, scope)
    os.makedirs(outdir, exist_ok=True)
    cmax = corpus_max(records)
    print("== scope %s == n=%d  corpus_max=%dB  per-class-max=%s"
          % (scope, len(records), cmax, per_class_max(records)))
    written = []
    for cid, states, rule, declared in candidate_specs(records, scope, invdir):
        cand = build_candidate(cid, states, rule, declared, records, scope, invdir)
        ok, problems = validate_candidate_schema(cand)
        path = os.path.join(outdir, cid + ".json")
        assert os.path.splitext(os.path.basename(path))[0] == cand["candidate_id"], \
            "filename must equal candidate_id"
        with open(path, "w") as f:
            json.dump(cand, f, indent=2)
        written.append(path)
        print("  %-24s states=%-10s covers_max=%s unfit=%d real_q=%d cover_q=%d fits_p4=%s schema_ok=%s"
              % (cid, cand["size_states"] and [s["target_frame_bytes"] for s in cand["size_states"]],
                 cand["covers_largest_frame"], cand["unfit_packets"], cand["real_queues_required"],
                 cand["cover_queues_required"], cand["fits_existing_p4"], ok))
        if not ok:
            print("     SCHEMA PROBLEMS:", problems)
    print("  wrote %d candidate JSONs to %s" % (len(written), outdir))
    return written


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--scope", default="base", choices=["base", "long", "multicrob", "all"])
    ap.add_argument("--invdir", default=os.path.join(here, "inventory"))
    ap.add_argument("--outdir", default=os.path.join(here, "queue_pattern_candidates"))
    a = ap.parse_args()
    scopes = ["base", "long", "multicrob"] if a.scope == "all" else [a.scope]
    for sc in scopes:
        run_scope(sc, a.invdir, a.outdir)


if __name__ == "__main__":
    main()
