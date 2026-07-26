#!/usr/bin/env python3
"""Cross-check pipeline (a) against pipeline (b), transaction by transaction.

Any disagreement on frame numbers or on CLRT (tolerance 1 ns, i.e. the
timestamp resolution of the capture) is reported as an ambiguous transaction.
Nothing is silently reconciled.
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

CAMPAIGNS = {
    "campaignA": {
        "native": "campaignA_native_n10.pcap",
        "protected": "campaignA_protected_n11.pcap",
    },
    "campaignB": {
        "native": "campaignB_native_n13.pcap",
        "protected": "campaignB_protected_n13.pcap",
    },
}

TOLERANCE_NS = 1


def run_pipeline_b(pcap: str):
    res = subprocess.run(
        [os.path.join(HERE, "pipeline_b_tshark.sh"), pcap],
        capture_output=True,
        text=True,
        check=True,
    )
    rows = list(csv.DictReader(res.stdout.splitlines()))
    return {int(r["app_seq"]): r for r in rows}


def main() -> int:
    report = {"tolerance_ns": TOLERANCE_NS, "campaigns": {}}
    total_disagree = 0

    for camp, arms in CAMPAIGNS.items():
        report["campaigns"][camp] = {}
        for arm, pcap_name in arms.items():
            pcap = os.path.join(ROOT, "pcaps", pcap_name)
            a_csv = os.path.join(ROOT, "transactions", camp, "%s_transactions.csv" % arm)
            with open(a_csv) as fh:
                a_rows = list(csv.DictReader(fh))
            b_rows = run_pipeline_b(pcap)

            diffs = []
            compared = 0
            for ar in a_rows:
                s = int(ar["read_dnp3_al_seq"])
                br = b_rows.get(s)
                if br is None:
                    diffs.append({"app_seq": s, "issue": "present in pipeline a, absent in pipeline b"})
                    continue
                compared += 1
                for a_field, b_field in (
                    ("read_frame", "read_frame"),
                    ("ack_frame", "ack_frame"),
                    ("resp_frame", "resp_frame"),
                ):
                    if str(ar[a_field]) != str(br[b_field]):
                        diffs.append(
                            {
                                "app_seq": s,
                                "issue": "%s differs: a=%s b=%s" % (a_field, ar[a_field], br[b_field]),
                            }
                        )
                # CLRT compared as integer nanoseconds
                a_ns = int(ar["clrt_ns"])
                b_ns = int(round(float(br["clrt_ms"]) * 1e6))
                if abs(a_ns - b_ns) > TOLERANCE_NS:
                    diffs.append(
                        {
                            "app_seq": s,
                            "issue": "clrt differs: a=%d ns b=%d ns (delta %d ns)"
                            % (a_ns, b_ns, a_ns - b_ns),
                        }
                    )
                if br["note"]:
                    diffs.append({"app_seq": s, "issue": "pipeline b note: %s" % br["note"]})

            extra_b = sorted(set(b_rows) - {int(r["read_dnp3_al_seq"]) for r in a_rows})
            for s in extra_b:
                diffs.append({"app_seq": s, "issue": "present in pipeline b, absent in pipeline a"})

            report["campaigns"][camp][arm] = {
                "pcap": pcap_name,
                "n_pipeline_a": len(a_rows),
                "n_pipeline_b": len(b_rows),
                "transactions_compared": compared,
                "disagreements": diffs,
                "agreement": "FULL" if not diffs else "PARTIAL",
            }
            total_disagree += len(diffs)
            print(
                "%-12s %-10s  a=%2d  b=%2d  compared=%2d  disagreements=%d"
                % (camp, arm, len(a_rows), len(b_rows), compared, len(diffs))
            )

    report["total_disagreements"] = total_disagree
    report["verdict"] = (
        "Pipelines (a) and (b) agree on every transaction in all four captures."
        if total_disagree == 0
        else "DISAGREEMENTS PRESENT - see per-campaign detail."
    )
    out = os.path.join(ROOT, "transactions", "pipeline_crosscheck.json")
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)
    print("\n%s\nwritten: %s" % (report["verdict"], out))
    return 0 if total_disagree == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
