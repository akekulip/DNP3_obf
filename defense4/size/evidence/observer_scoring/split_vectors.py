#!/usr/bin/env python3
"""Extract the ##VEC## JSON lines emitted by the C++ decoy-gate binary into committed vector files.

Provenance is EMITTED (a real opendnp3 build ran and serialized these bytes), not reconstructed.
Called by emit_vectors.sh. No git, no absolute home paths.
"""
import argparse
import datetime
import json
import os
import platform

TAG = "##VEC## "


def load_vec_lines(path):
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            i = line.find(TAG)
            if i >= 0:
                out.append(json.loads(line[i + len(TAG):].strip()))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--read", required=True)
    ap.add_argument("--sbo", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--src", default="unknown")
    ap.add_argument("--head", default="unknown")
    ap.add_argument("--iso", default="unknown")
    a = ap.parse_args()

    read_vecs = load_vec_lines(a.read)
    sbo_vecs = load_vec_lines(a.sbo)

    prov = {
        "provenance": "EMITTED — serialized by a real opendnp3 master/outstation in an isolated "
        "C++ build (software only, no hardware/relay/switch/network). Not reconstructed.",
        "opendnp3_source": os.path.basename(a.src.rstrip("/")),
        "opendnp3_head": a.head,
        "isolated_build": a.iso,
        "host": platform.node(),
        "emitted_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "emitter": "decoy_gate/tests/TestDecoyGate{ReadSize,RoundTrip}.cpp -> ##VEC## lines",
    }

    read_doc = {"_meta": dict(prov, axis="READ (class-0 G30V1 decoy padding)"), "vectors": read_vecs}
    sbo_doc = {"_meta": dict(prov, axis="SBO (G12V1 CROB Encoding-A decoy header)"), "vectors": sbo_vecs}

    with open(os.path.join(a.outdir, "read_vectors.json"), "w") as f:
        json.dump(read_doc, f, indent=2)
    with open(os.path.join(a.outdir, "sbo_vectors.json"), "w") as f:
        json.dump(sbo_doc, f, indent=2)

    print("  read vectors : %d  (kinds: %s)" % (len(read_vecs), sorted({v["kind"] for v in read_vecs})))
    print("  sbo vectors  : %d" % len(sbo_vecs))


if __name__ == "__main__":
    main()
