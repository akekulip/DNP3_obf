"""Per-exchange records with order and idle gap, for the anchor diagnosis.

The frozen `derived/transactions.csv` carries one row per exchange but no ordering and no
timestamps, so it cannot answer why the release tail differs between two classes that share a
lane. This script re-reads the campaign captures with the repository's own dependency-free
extractor and keeps, for every exchange: its class, its master-visible request-to-ACK interval and
CLRT, its index within the capture, and the idle gap since the previous exchange finished.

    python3 extract_ordered.py            -> ordered_exchanges.csv

Read-only with respect to the captures. Nanosecond integers throughout; milliseconds only on
output, as pcap_dnp3 requires.
"""
from __future__ import annotations
import csv, pathlib, sys

CAMPAIGN = pathlib.Path(__file__).resolve().parents[2] / "evidence" / "campaign_v1"
sys.path.insert(0, str(CAMPAIGN / "repro"))
import pcap_dnp3 as P                                          # noqa: E402

OUT = pathlib.Path(__file__).resolve().parent / "ordered_exchanges.csv"


def main() -> int:
    rows = []
    # s*/raw_pcaps also holds the policy sweep's own captures, named sw_*; the campaign's own
    # blocks are the s<NN>_b<N>_<arm> ones and are the only ones this diagnosis reads.
    caps = [c for c in sorted(CAMPAIGN.glob("s*/raw_pcaps/*.pcap"))
            if len(c.name[:-len(".pcap")].split("_")) == 3 and c.name.startswith("s")]
    if not caps:
        sys.exit("no captures found under %s" % CAMPAIGN)
    for cap in caps:
        name = cap.name                                        # s01_b2_obfuscated.pcap
        stem = name[:-len(".pcap")]
        session, block, arm = stem.split("_", 2)
        rep = P.extract(str(cap))
        prev_end = None
        for i, x in enumerate(rep.exchanges):
            idle_ms = "" if prev_end is None else (x.t_req_ns - prev_end) / 1e6
            rows.append(dict(
                session=session, block=block, arm=arm, capture=stem, idx=i,
                txn_class=P.FUNC_NAME.get(x.func, "F%d" % x.func),
                ack_gap_ms=x.ack_gap_ns / 1e6,
                clrt_ms=x.clrt_ns / 1e6,
                rt_ms=(x.t_resp_ns - x.t_req_ns) / 1e6,
                idle_before_ms=idle_ms,
                t_req_ns=x.t_req_ns,
            ))
            prev_end = x.t_resp_ns
    with OUT.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print("%d exchanges from %d captures -> %s" % (len(rows), len(caps), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
