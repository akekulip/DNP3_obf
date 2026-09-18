#!/usr/bin/env python3
"""Per-transaction extraction for the release-tail sweep.

campaign_v1's `extract_clrt.py` returns one summary per capture, which is enough to plot a median
but not enough to bootstrap one. The pairing logic here is that script's, unchanged: a request
from the master opens a transaction, the outstation's first payload-free segment is the transport
acknowledgment, its first payload-bearing segment is the application response, and the transaction
closes there. What differs is only that every transaction is written out rather than reduced.

    python3 extract_tail_sweep.py            fetch new captures, extract, write transactions.csv
    python3 extract_tail_sweep.py --local    extract what is already in raw_pcaps/

Output columns: block, pass, series, mode, D_A_ms, CLRT_new_ms, D_ms, A_ms, R_ms, j_set,
txn_class, ack_ms, clrt_ms, rt_ms.
"""
from __future__ import annotations

import csv
import subprocess
import sys
from pathlib import Path

from scapy.all import IP, TCP, Raw, PcapReader

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PCAPS = ROOT / "raw_pcaps"
MANIFEST = ROOT / "blocks.csv"
OUT = ROOT / "transactions.csv"
# The separation series is a second run with its own manifest; --sep points both
# the manifest and the output at it so the two never mix in one table.
MANIFEST_SEP = ROOT / "blocks_sep.csv"
OUT_SEP = ROOT / "transactions_sep.csv"

REMOTE = "decps@10.10.54.166"
REMOTE_DIR = "/home/decps/tail_sweep_20260918"
MASTER, OUTSTATION = "192.168.10.1", "192.168.10.7"
FUNC = {1: "READ", 3: "SELECT", 4: "OPERATE"}


def app_func(payload):
    b = bytes(payload)
    if len(b) >= 13 and b[0] == 0x05 and b[1] == 0x64:
        return b[12]
    return None


def transactions(path: Path):
    state = None
    t_ack = None
    for pkt in PcapReader(str(path)):
        if IP not in pkt or TCP not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        ts = float(pkt.time)
        plen = len(tcp.payload) if Raw in pkt else 0
        m2r = ip.src == MASTER and ip.dst == OUTSTATION and tcp.dport == 20000
        r2m = ip.src == OUTSTATION and ip.dst == MASTER and tcp.sport == 20000
        if m2r and plen > 0:
            state = (ts, app_func(pkt[Raw].load) if Raw in pkt else None)
            t_ack = None
        elif r2m and state is not None:
            if plen == 0 and t_ack is None:
                t_ack = ts
            elif plen > 0:
                if t_ack is not None:
                    yield (FUNC.get(state[1], "F%s" % state[1]),
                           (t_ack - state[0]) * 1e3,          # request -> acknowledgment
                           (ts - t_ack) * 1e3,                # acknowledgment -> response
                           (ts - state[0]) * 1e3)             # request -> response
                state = None
                t_ack = None


def fetch():
    PCAPS.mkdir(parents=True, exist_ok=True)
    have = {p.name for p in PCAPS.glob("*.pcap")}
    listing = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", REMOTE, f"ls {REMOTE_DIR}/*.pcap 2>/dev/null"],
        capture_output=True, text=True).stdout.split()
    want = [n for n in listing if Path(n).name not in have]
    if not want:
        return 0
    # One scp for the batch: a call per capture spends more time in ssh setup than in transfer.
    subprocess.run(["scp", "-o", "BatchMode=yes",
                    *[f"{REMOTE}:{n}" for n in want], str(PCAPS)], check=False)
    return len(want)


def main(argv) -> int:
    global MANIFEST, OUT
    if "--sep" in argv:
        MANIFEST, OUT = MANIFEST_SEP, OUT_SEP
    if "--local" not in argv:
        n = fetch()
        print(f"fetched {n} new capture(s)")
    if not MANIFEST.exists():
        sys.exit(f"{MANIFEST} not found; the sweep has not written its manifest yet")
    meta = {r["tag"]: r for r in csv.DictReader(MANIFEST.open())}

    rows, skipped = [], []
    for tag, m in meta.items():
        if m["status"] != "ok":
            skipped.append((tag, m["status"]))
            continue
        p = PCAPS / f"{tag}.pcap"
        if not p.exists():
            skipped.append((tag, "no capture"))
            continue
        n = 0
        for cls, ack, clrt, rt in transactions(p):
            rows.append([tag, m["pass"], m["series"], m["mode"], m["D_A_ms"], m["CLRT_new_ms"],
                         m["D_ms"], m["A_ms"], m["R_ms"], m["j_set"], cls,
                         round(ack, 6), round(clrt, 6), round(rt, 6)])
            n += 1
        if n == 0:
            skipped.append((tag, "no transactions paired"))

    with OUT.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["block", "pass", "series", "mode", "D_A_ms", "CLRT_new_ms", "D_ms",
                    "A_ms", "R_ms", "j_set", "txn_class", "ack_ms", "clrt_ms", "rt_ms"])
        w.writerows(rows)
    print(f"{len(rows)} transactions from {len(meta) - len(skipped)} block(s) -> {OUT}")
    if skipped:
        print(f"skipped {len(skipped)}:")
        for tag, why in skipped[:10]:
            print(f"  {tag}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
