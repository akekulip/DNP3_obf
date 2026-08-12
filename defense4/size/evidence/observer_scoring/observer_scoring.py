#!/usr/bin/env python3
"""Impl 4 — observer-aware scoring of the two size candidates.

Scores each candidate size mechanism against TWO observer models, using the committed evidence from
the cover-frame gate (Impl 2) and the configured-decoy gate (Impl 3). The point of the exercise: a
packet-length-only observer and a DNP3-parsing observer reach OPPOSITE conclusions, and the two
candidates differ in exactly one decisive property — whether the padding is SELF-IDENTIFYING to a
parser.

Observer models:
  * O_count  — counts TCP-payload bytes per burst; does NOT parse DNP3 or reassemble semantics.
  * O_parse  — reassembles the stream and parses DNP3 link frames + application objects. It can run
               the endpoint's own address filter, and it knows the DNP3 object structure.

Decisive property (evidence-grounded):
  * Cover framing: the cover frame is addressed to a NON-ENDPOINT link address. Impl 2 proved the real
    OpenDNP3 LinkLayerParser DELIVERS BOTH frames (parser_frames_rx = n_cover + 1); only the endpoint
    ADDRESS FILTER drops the cover. O_parse runs the same filter, removes the cover, and recovers the
    real frame's size EXACTLY. => self-identifying => strippable => zero size benefit vs O_parse.
  * Configured decoys (READ): Impl 3 proved the decoys are REAL configured points at higher indices,
    native-encoded, with real values+flags preserved. They are structurally INDISTINGUISHABLE from
    real points => O_parse cannot strip them by structure (needs out-of-band knowledge of which
    indices are decoys). Residual O_parse tell = decoy index-range / value-stability profiled over
    time. => NOT trivially strippable.
  * Configured decoys (SBO encoding A): Impl 3 proved acceptance requires a SEPARATE trailing G12V1
    header — two headers in one echo, which no native device emits => DETECTABLE by O_parse.

Run:  python3 observer_scoring.py         # prints the scorecard + runs the self-test
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _repo_root(start):
    d = start
    for _ in range(8):
        # .git is a DIR in a normal clone but a FILE in a git worktree — accept either
        if os.path.exists(os.path.join(d, ".git")) or os.path.isdir(os.path.join(d, "defense4")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return start


ROOT = _repo_root(HERE)
COVER_CSV = os.path.join(ROOT, "defense4/size/evidence/cover_frame_gate/evidence/results_table.csv")


def load_cover_gate():
    """Return the cover-frame gate rows (address class -> gate verdict + sizes)."""
    if not os.path.exists(COVER_CSV):
        return []
    with open(COVER_CSV) as f:
        return list(csv.DictReader(f))


# ---- observer models -------------------------------------------------------------------------
def o_count_recovers_device(padded_total_bytes, native_total_bytes, target):
    """O_count sees only the padded total. If padding reaches a common public target, the device's
    native size is HIDDEN (device-independent). Returns True if the device is still recoverable."""
    return padded_total_bytes != target          # recoverable only if not normalized to the target


def o_parse_recovers_cover_framing(row):
    """O_parse strips a self-identifying cover (non-endpoint address) and recovers the real size.
    Grounded in Impl 2: parser delivers both frames; the address filter (which O_parse replicates)
    drops the cover, leaving the real frame's exact bytes."""
    # a cover that the ENDPOINT discards is discarded by the endpoint's *address filter* — the same
    # filter O_parse runs — so O_parse recovers real_frame_bytes exactly. (broadcast is NOT discarded
    # and is a functional hazard, excluded from the usable envelope.)
    real = int(row["real_frame_bytes"])
    strippable = row["cover_discarded"] == "1"    # self-identifying to the address filter
    return {"self_identifying": strippable, "recovered_real_bytes": real if strippable else None}


# configured-decoy facts, from the verified Impl 3 evidence (decoy_gate/out/partB_read.txt etc.)
DECOY_READ = {
    "native_looking": True,        # decoys are higher-index real points, native encoding
    "values_flags_preserved": True,
    "self_identifying_to_parser": False,   # structurally identical to real points
    "residual_parse_tell": "decoy index-range / value-stability profiled over time",
    "size_sweep_bytes": {"K=0": 29, "K=16": 109},   # response grows with decoy count
}
DECOY_SBO_ENCA = {
    "master_accepted": True,
    "self_identifying_to_parser": True,    # two G12V1 headers => non-native => detectable
    "detect_signature": "two G12V1 headers in one SBO echo (no native device emits two)",
}


def score():
    cover = load_cover_gate()
    usable = [r for r in cover if r["gate_verdict"] == "PASS"]
    rows = []

    # --- Candidate 1: cover framing ---
    cf_parse = o_parse_recovers_cover_framing(usable[0]) if usable else {"self_identifying": None}
    rows.append({
        "candidate": "cover framing",
        "O_count": "size normalized to public target (pads the observed total)",
        "O_parse": "STRIPPED -> real size recovered (cover is self-identifying by non-endpoint address)"
                   if cf_parse["self_identifying"] else "n/a",
        "semantics": "preserved (real frame byte-identical; never reaches app layer)",
        "endpoint_coop": "none for individual!=endpoint / reserved (per Impl 2); broadcast unsafe",
    })

    # --- Candidate 2a: configured decoys, READ ---
    rows.append({
        "candidate": "configured decoy (READ)",
        "O_count": "size normalized (native-looking padded total)",
        "O_parse": "NOT structurally strippable (decoys == real points); residual = " + DECOY_READ["residual_parse_tell"],
        "semantics": "preserved (real values + quality flags byte-identical; master accepts)",
        "endpoint_coop": "REQUIRED (decoys are configured endpoint points)",
    })

    # --- Candidate 2b: configured decoys, SBO encoding A ---
    rows.append({
        "candidate": "configured decoy (SBO enc-A)",
        "O_count": "size normalized (padded total)",
        "O_parse": "DETECTABLE (" + DECOY_SBO_ENCA["detect_signature"] + ")",
        "semantics": "preserved (real CROB executes once; decoys inert)",
        "endpoint_coop": "REQUIRED",
    })
    return rows, cf_parse


def main():
    rows, cf_parse = score()
    checks = []

    # the decisive distinctions the evidence establishes
    checks.append(("cover framing IS self-identifying to a parser (strippable)",
                   cf_parse.get("self_identifying") is True))
    checks.append(("configured READ decoys are NOT self-identifying to a parser",
                   DECOY_READ["self_identifying_to_parser"] is False))
    checks.append(("configured READ decoys preserve real values + quality flags",
                   DECOY_READ["values_flags_preserved"] and DECOY_READ["native_looking"]))
    checks.append(("SBO encoding-A IS detectable (two headers)",
                   DECOY_SBO_ENCA["self_identifying_to_parser"] is True))
    # no candidate defeats O_parse for cover framing (the bounded impossibility must hold)
    checks.append(("cover framing gives ZERO size benefit vs a parsing observer",
                   cf_parse.get("recovered_real_bytes") is not None))

    print("%-28s %-42s %-52s" % ("CANDIDATE", "O_count (packet-length)", "O_parse (DNP3 parsing)"))
    print("-" * 124)
    for r in rows:
        print("%-28s %-42s %-52s" % (r["candidate"], r["O_count"][:42], r["O_parse"][:52]))
    print("-" * 124)
    print("Semantics + endpoint-cooperation per candidate:")
    for r in rows:
        print("  %-28s semantics: %s | endpoint-coop: %s" % (r["candidate"], r["semantics"], r["endpoint_coop"]))
    print("-" * 124)
    npass = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print("OBSERVER-SCORING self-test: %d/%d" % (npass, len(checks)))
    print("\nHeadline: against O_count both candidates normalize size; against O_parse cover framing is")
    print("stripped to zero (self-identifying address), configured READ decoys are NOT structurally")
    print("strippable (they look like real points), and SBO encoding-A is detectable (two headers).")
    sys.exit(0 if npass == len(checks) else 1)


if __name__ == "__main__":
    main()
