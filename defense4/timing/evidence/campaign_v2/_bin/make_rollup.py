#!/usr/bin/env python3
"""Roll the 22 per-session manifests up into one dataset summary.

`DATASET_ROLLUP.json` is the dataset's own account of itself -- how many sessions, captures and
transactions it holds, how many anomalies the driver recorded, which sessions are incomplete, and
the spread of each class's median released CLRT across the 132 captures. The figure generators read
the anomaly and incomplete-session counts from it rather than recomputing them, so that a figure
cannot be drawn from a corpus that the collection itself flagged.

Schema matches campaign_v1's file exactly, so anything that reads one reads the other.

    python3 _bin/make_rollup.py
"""
from __future__ import annotations
import collections, csv, json, pathlib, statistics as st, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "repro"))
import pcap_dnp3 as P                                          # noqa: E402


def main() -> int:
    sessions = sorted(p for p in ROOT.glob("s[0-9][0-9]") if p.is_dir())
    pcaps = sorted(ROOT.glob("s[0-9][0-9]/raw_pcaps/*.pcap"))
    jsonl = sorted(ROOT.glob("s[0-9][0-9]/app_jsonl/*.jsonl"))
    totals, anomalies, incomplete, missing = collections.Counter(), [], [], []
    for s in sessions:
        man = s / "provenance" / "MANIFEST.json"
        if not man.exists():
            missing.append(s.name); continue
        d = json.loads(man.read_text())
        for k, v in d["integrity"]["totals"].items():
            totals[k] += v
        anomalies.extend(d["integrity"]["anomalies"])
        if len(list((s / "raw_pcaps").glob("*.pcap"))) != 6:
            incomplete.append(s.name)

    # Per class and arm: the median released CLRT of each capture, then the median, minimum and
    # maximum of those 66 per-capture medians. A spread across captures is what says the value is
    # a property of the configuration and not of one run.
    per = collections.defaultdict(lambda: collections.defaultdict(list))
    for cap in pcaps:
        arm = "native" if "native" in cap.name else "obfuscated"
        by = collections.defaultdict(list)
        for x in P.extract(str(cap)).exchanges:
            by[P.FUNC_NAME.get(x.func, str(x.func))].append(x.clrt_ns / 1e6)
        for cls, v in by.items():
            per[cls][arm].append(st.median(v))
    rollup = {
        "sessions": len(sessions), "pcaps": len(pcaps), "jsonl": len(jsonl),
        "transactions": {k: totals[k] for k in ("READ", "SELECT", "OPERATE")},
        "total_transactions": sum(totals.values()),
        "anomalies_count": len(anomalies), "anomalies": anomalies,
        "incomplete_sessions": incomplete, "missing_provenance": missing,
        "per_arm_clrt_median_minmax_n": {
            cls: {arm: [round(st.median(v), 3), round(min(v), 3), round(max(v), 3), len(v)]
                  for arm, v in arms.items()}
            for cls, arms in per.items()},
    }
    (ROOT / "DATASET_ROLLUP.json").write_text(json.dumps(rollup, indent=1) + "\n")
    print("sessions %d  pcaps %d  jsonl %d  transactions %d  anomalies %d  incomplete %d"
          % (rollup["sessions"], rollup["pcaps"], rollup["jsonl"],
             rollup["total_transactions"], rollup["anomalies_count"],
             len(rollup["incomplete_sessions"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
