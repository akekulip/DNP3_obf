#!/usr/bin/env python3
"""finalize_session.py <session_dir> <order_csv> <seed_csv>
Compute sha256, master-facing timing summary, integrity counts, and a per-session MANIFEST.
order_csv/seed_csv are comma lists aligned to blocks b1..bN, e.g. OFF,D4,D4,OFF,D4,OFF and
2001,2002,...  Shared facts live in ../PROVENANCE_CONSTANTS.json."""
import json, sys, os, glob, hashlib, statistics as st, importlib.util
D = sys.argv[1].rstrip("/")
order = sys.argv[2].split(","); seeds = sys.argv[3].split(",")
sess = os.path.basename(D)
here = os.path.dirname(os.path.abspath(__file__))
ex_spec = importlib.util.spec_from_file_location("ex", os.path.join(here, "extract_clrt.py"))
ex = importlib.util.module_from_spec(ex_spec); ex_spec.loader.exec_module(ex)

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""): h.update(c)
    return h.hexdigest()

os.makedirs(os.path.join(D, "provenance"), exist_ok=True)
# sha256 over data + tools
lines = []
for p in sorted(glob.glob(D + "/raw_pcaps/*.pcap") + glob.glob(D + "/app_jsonl/*.jsonl")):
    lines.append("%s  %s" % (sha(p), os.path.relpath(p, D)))
open(D + "/provenance/DATASET.sha256", "w").write("\n".join(lines) + "\n")
# timing summary
timing = {}
for pc in sorted(glob.glob(D + "/raw_pcaps/*.pcap")):
    timing[os.path.basename(pc)[:-5]] = ex.main(pc)
json.dump(timing, open(D + "/provenance/TIMING_SUMMARY.json", "w"), indent=1)
# integrity over jsonl
tot = {"READ": 0, "SELECT": 0, "OPERATE": 0}; anomalies = []
for jf in sorted(glob.glob(D + "/app_jsonl/*.jsonl")):
    for l in open(jf):
        r = json.loads(l); op = r["operation"]; tot[op] = tot.get(op, 0) + 1
        if op == "READ" and not r["valid"]: anomalies.append([os.path.basename(jf), r["txn_id"], "read_invalid"])
        if op in ("SELECT", "OPERATE") and r["status"] != "SUCCESS":
            anomalies.append([os.path.basename(jf), r["txn_id"], r["status"]])
blocks = [{"id": "b%d" % (i + 1), "arm": "native" if order[i] == "OFF" else "obfuscated",
           "mode": order[i], "seed": int(seeds[i])} for i in range(len(order))]
man = {"session": sess, "blocks": blocks,
       "integrity": {"totals": tot, "anomalies": anomalies,
                     "note": "anomalies (timeouts/NO_SELECT/malformed/invalid) preserved verbatim in JSONL, never filtered."},
       "timing_summary": "provenance/TIMING_SUMMARY.json",
       "hashes": "provenance/DATASET.sha256",
       "constants": "../PROVENANCE_CONSTANTS.json"}
json.dump(man, open(D + "/provenance/MANIFEST.json", "w"), indent=1)
# one-line result
def med(name, arm):
    xs = [timing[k].get(name, {}).get("clrt_med") for k in timing if arm in k]
    xs = [x for x in xs if x is not None]
    return round(st.median(xs), 3) if xs else None
print("%s  READ n/o=%s/%s  SEL n/o=%s/%s  OP n/o=%s/%s  totals=%s anomalies=%d"
      % (sess, med("READ","native"), med("READ","obfuscated"), med("SELECT","native"),
         med("SELECT","obfuscated"), med("OPERATE","native"), med("OPERATE","obfuscated"),
         tot, len(anomalies)))
