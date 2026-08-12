#!/usr/bin/env python3
"""Synthesise REPEATED class-0 reads for the temporal observer (O_parse_profile).

The emitted C++ vectors are a single snapshot; a temporal observer needs many reads with process
dynamics. Those dynamics do not exist in the static evidence, so they are a DECLARED MODEL INPUT
here (labelled synthetic). The wire SERIALIZATION is the real format, proven byte-exact by
serializer.selftest(), which this generator asserts before writing anything.

Five scenarios over R=4 real points (idx 0..3) + K=6 configured decoys (idx 4..9), 30 reads each:
  S1 varying_legit / constant_decoy   — active plant, inert decoys (the intended operating point)
  S2 constant_legit / constant_decoy  — quiescent plant: constant REAL points look like decoys (FP)
  S3 varying_legit / varying_decoy    — animated decoys: temporal id of decoys degrades
  S4 constant_legit / varying_decoy   — worst case: reals look like decoys, decoys look real
  S5 noise_missing                    — S1 dynamics but ~40% of reads are missed by the observer

Values are int32 (Group30Var1). No randomness beyond a fixed arithmetic pattern (reproducible).
No git, no hardware, no absolute home paths.
"""
import datetime
import json
import os

import serializer as S

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.path.join(HERE, "vectors")
R = 4                       # real points 0..3
DECOYS = [4, 5, 6, 7, 8, 9] # configured decoys
N = 30                      # reads per scenario
POLL_S = 2                  # seconds between polls
REAL_BASE = 1000
DECOY_BASE = 50000
MISSING = {2, 5, 6, 11, 14, 17, 20, 23, 24, 27, 29, 8}  # dropped read numbers for S5 (~40%)


def real_val(i, n, varying):
    # (n+i)%5 cycles through all 5 residues as n advances -> a varying point is NEVER constant;
    # a constant point is exactly its base. No index collapses to a degenerate series.
    return REAL_BASE + i + (((n + i) % 5) if varying else 0)


def decoy_val(j, n, varying):
    return DECOY_BASE + j + (((n + j) % 5) if varying else 0)


def build_reads(varying_legit, varying_decoy, drop=None):
    drop = drop or set()
    t0 = datetime.datetime(2026, 8, 12, 3, 0, 0)
    reads = []
    for n in range(N):
        ts = (t0 + datetime.timedelta(seconds=POLL_S * n)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if n in drop:
            reads.append({"read_no": n, "ts": ts, "present": False, "response_hex": None, "values": None})
            continue
        vals = {}
        for i in range(R):
            vals[i] = real_val(i, n, varying_legit)
        for j in DECOYS:
            vals[j] = decoy_val(j, n, varying_decoy)
        reads.append({"read_no": n, "ts": ts, "present": True,
                      "response_hex": S.serialize_class0(vals), "values": vals})
    return reads


def scenario(name, desc, varying_legit, varying_decoy, drop=None):
    truth = {str(i): "real" for i in range(R)}
    truth.update({str(j): "decoy" for j in DECOYS})
    return {
        "name": name, "description": desc,
        "varying_legit": varying_legit, "varying_decoy": varying_decoy,
        "real_indices": list(range(R)), "decoy_indices": list(DECOYS),
        "n_reads": N, "index_truth": truth,
        "reads": build_reads(varying_legit, varying_decoy, drop),
    }


def main():
    n = S.selftest()  # refuse to synthesise unless the serializer is proven faithful
    os.makedirs(OUTDIR, exist_ok=True)
    doc = {
        "_meta": {
            "provenance": "SYNTHETIC process dynamics (declared model input) rendered through the "
            "FAITHFUL serializer proven byte-exact against the emitted C++ read vectors "
            "(%d/%d) in this run. Wire format is real; the value time-series is a model, not a "
            "capture." % (n, n),
            "serializer_selftest": "%d/%d emitted read vectors reproduced" % (n, n),
            "generated_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "R_real": R, "decoys": DECOYS, "n_reads": N,
        },
        "scenarios": [
            scenario("S1_varying_legit_constant_decoy",
                     "active plant, inert decoys — the intended operating point", True, False),
            scenario("S2_constant_legit_constant_decoy",
                     "quiescent plant — constant real points are indistinguishable from decoys", False, False),
            scenario("S3_varying_legit_varying_decoy",
                     "animated decoys — temporal identification of decoys degrades", True, True),
            scenario("S4_constant_legit_varying_decoy",
                     "worst case — reals look like decoys, decoys look real", False, True),
            scenario("S5_noise_missing",
                     "S1 dynamics but the observer misses ~40% of polls", True, False, MISSING),
        ],
    }
    out = os.path.join(OUTDIR, "read_timeseries.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)
    present = {s["name"]: sum(1 for r in s["reads"] if r["present"]) for s in doc["scenarios"]}
    print("wrote %s" % out)
    for k, v in present.items():
        print("  %-34s reads_present=%d/%d" % (k, v, N))


if __name__ == "__main__":
    main()
