"""Build the canonical per-exchange table for the anchor-fix validation run.

The columns are the ones ``evidence/campaign_v1/repro/leakage_campaign.py`` reads, so the
validation is scored by the campaign's own evaluator rather than by a new one written for the
occasion. ``run`` is the round, which holds one block of each arm, so every leave-one-run-out
fold drops an OFF block and its paired obfuscated blocks together.

    python3 build_canonical.py           -> canonical_<arm>.csv, one per obfuscated arm,
                                            each holding that arm's blocks plus every OFF block
"""
from __future__ import annotations
import csv, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
TIMING = HERE.parents[1]
sys.path.insert(0, str(TIMING / "evidence" / "campaign_v1" / "repro"))
import pcap_dnp3 as P                                             # noqa: E402

PCAPS = HERE.parent / "raw_pcaps"


def read_all():
    rows = []
    for cap in sorted(PCAPS.glob("r*_*.pcap")):
        stem = cap.name[: -len(".pcap")]
        run, arm = stem.split("_", 1)                              # r01, OFF|A0|A1
        rep = P.extract(str(cap))
        prev_end = None
        for i, x in enumerate(rep.exchanges):
            idle = "" if prev_end is None else (x.t_req_ns - prev_end) / 1e6
            rows.append(dict(
                run=run, block=stem, anchor_arm=arm,
                arm="native" if arm == "OFF" else "obfuscated",
                txn_class=P.FUNC_NAME.get(x.func, str(x.func)),
                idx=i,
                ack_ms=x.ack_gap_ns / 1e6,
                clrt_ms=x.clrt_ns / 1e6,
                rt_ms=(x.t_resp_ns - x.t_req_ns) / 1e6,
                idle_before_ms=idle))
            prev_end = x.t_resp_ns
    return rows


def main() -> int:
    rows = read_all()
    if not rows:
        sys.exit("no r*_*.pcap under %s" % PCAPS)
    cols = ["run", "block", "anchor_arm", "arm", "txn_class", "idx",
            "ack_ms", "clrt_ms", "rt_ms", "idle_before_ms"]
    allp = HERE / "exchanges_all.csv"
    with open(allp, "w", newline="") as f:
        w = csv.DictWriter(f, cols); w.writeheader(); w.writerows(rows)
    print("wrote %s  n=%d" % (allp, len(rows)))
    for obf in ("A0", "A1"):
        sub = [r for r in rows if r["anchor_arm"] in ("OFF", obf)]
        p = HERE / ("canonical_%s.csv" % obf)
        with open(p, "w", newline="") as f:
            w = csv.DictWriter(f, cols); w.writeheader(); w.writerows(sub)
        print("wrote %s  n=%d  runs=%d" % (p, len(sub), len({r["run"] for r in sub})))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
