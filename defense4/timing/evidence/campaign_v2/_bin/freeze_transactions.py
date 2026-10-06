#!/usr/bin/env python3
"""Write campaign_v2's frozen transaction table with an INDEPENDENT extractor.

`repro/validate_campaign.py` rebuilds the canonical table from the raw captures with the
repository's own dependency-free reader, `repro/pcap_dnp3.py`, and then checks it row by row
against a frozen table produced by different code. The point of that check is that two
implementations written against the same captures agree; a frozen table produced by the same
reader would make it a tautology.

So this reads the captures with **scapy**, which shares no code with `pcap_dnp3.py`, and emits the
schema campaign_v1's frozen table uses:

    session,block,arm,txn_class,clrt_ms,ack_ms,rt_ms

The pairing rule is the one campaign_v1's `_bin/extract_clrt.py` used, kept deliberately: a
master-to-outstation frame with payload opens a transaction and its DNP3 function code names it;
the outstation's first payload-free segment is the transport acknowledgment; its next frame with
payload is the application response and closes the transaction. CLRT is response minus
acknowledgment, `ack_ms` is acknowledgment minus request, and `rt_ms` is response minus request.

    RESEARCH_PYTHON=~/.venvs/research/bin/python $RESEARCH_PYTHON freeze_transactions.py

Read-only with respect to the captures.
"""
from __future__ import annotations
import csv
import pathlib
import sys

from scapy.all import PcapReader, TCP, IP, Raw           # noqa: E402

MASTER, OUTSTATION, PORT = "192.168.10.1", "192.168.10.7", 20000
FUNC = {1: "READ", 3: "SELECT", 4: "OPERATE"}
ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "derived" / "transactions.csv"


def app_func(payload: bytes):
    """The DNP3 application function code, or None if this is not an application frame."""
    b = bytes(payload)
    if len(b) >= 13 and b[0] == 0x05 and b[1] == 0x64:
        return b[12]            # link header 10, transport 1, application control 1, then func
    return None


def exchanges(path: pathlib.Path):
    """(txn_class, clrt_ms, ack_ms, rt_ms) per completed transaction, in capture order."""
    out = []
    t_req = func = t_ack = None
    for pkt in PcapReader(str(path)):
        if IP not in pkt or TCP not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        ts = float(pkt.time)
        plen = len(tcp.payload) if Raw in pkt else 0
        to_outstation = ip.src == MASTER and ip.dst == OUTSTATION and tcp.dport == PORT
        to_master = ip.src == OUTSTATION and ip.dst == MASTER and tcp.sport == PORT
        if to_outstation and plen > 0:
            t_req, func, t_ack = ts, app_func(pkt[Raw].load), None
        elif to_master and t_req is not None:
            if plen == 0 and t_ack is None:
                t_ack = ts
            elif plen > 0:
                if t_ack is not None:
                    out.append((FUNC.get(func, "F%s" % func),
                                (ts - t_ack) * 1e3, (t_ack - t_req) * 1e3, (ts - t_req) * 1e3))
                t_req = func = t_ack = None
    return out


def main() -> int:
    caps = sorted(ROOT.glob("s[0-9][0-9]/raw_pcaps/*.pcap"))
    if not caps:
        sys.exit("no captures under %s" % ROOT)
    rows = []
    for cap in caps:
        session, block, arm = cap.name[: -len(".pcap")].split("_", 2)
        for cls, clrt, ack, rt in exchanges(cap):
            rows.append(dict(session=session, block=block, arm=arm, txn_class=cls,
                             clrt_ms="%.6f" % clrt, ack_ms="%.6f" % ack, rt_ms="%.6f" % rt))
        print("  %-28s %d" % (cap.name, len(rows)), end="\r", flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, ["session", "block", "arm", "txn_class",
                               "clrt_ms", "ack_ms", "rt_ms"])
        w.writeheader()
        w.writerows(rows)
    print("\nwrote %s  %d captures  %d transactions" % (OUT, len(caps), len(rows)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
