#!/usr/bin/env python3
"""Report the TCP options every SYN and SYN-ACK carries in a set of captures.

The response-path mapper (protocol/case4_response_path.p4) arms only on a handshake without
timestamps, SACK-permitted or window scaling. This reads existing captures, never writes them,
and says per endpoint whether its handshakes would arm the mapper.

    python3 syn_option_audit.py [--json OUT] PCAP_OR_DIR ...
"""
import argparse
import json
import pathlib
import sys

from scapy.all import PcapReader, TCP, IP  # noqa: E402

BLOCKING = {"Timestamp", "SAckOK", "WScale"}


def captures(paths):
    for p in map(pathlib.Path, paths):
        if p.is_dir():
            yield from sorted(q for q in p.rglob("*") if q.suffix in (".pcap", ".pcapng"))
        else:
            yield p


def scan(path):
    out = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            if IP not in pkt or TCP not in pkt:
                continue
            t = pkt[TCP]
            if not t.flags & 0x02:  # SYN
                continue
            names = [o[0] for o in t.options]
            out.append({
                "src": f"{pkt[IP].src}:{t.sport}",
                "dst": f"{pkt[IP].dst}:{t.dport}",
                "synack": bool(t.flags & 0x10),
                "options": names,
                "blocking": sorted(BLOCKING.intersection(names)),
            })
    return out


def summarize(records):
    by_host = {}
    for r in records:
        host = r["src"].rsplit(":", 1)[0]
        s = by_host.setdefault(host, {"handshake_segments": 0, "option_sets": {}, "blocking": set()})
        s["handshake_segments"] += 1
        key = ",".join(r["options"]) or "(none)"
        s["option_sets"][key] = s["option_sets"].get(key, 0) + 1
        s["blocking"].update(r["blocking"])
    for s in by_host.values():
        s["blocking"] = sorted(s["blocking"])
        s["mapper_arms"] = not s["blocking"]
    return by_host


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", help="write the full result here")
    a = ap.parse_args(argv)
    records, files = [], 0
    for cap in captures(a.paths):
        files += 1
        for r in scan(cap):
            r["capture"] = str(cap)
            records.append(r)
    summary = summarize(records)
    result = {"captures_scanned": files, "handshake_segments": len(records), "by_host": summary}
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(result | {"records": records}, indent=1) + "\n")
    json.dump(result, sys.stdout, indent=1)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
