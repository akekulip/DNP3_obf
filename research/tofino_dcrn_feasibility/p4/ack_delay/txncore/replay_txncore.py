#!/usr/bin/env python3
"""
Phase-2 replay verification: drive the generation-safe transaction-core reference model over the
committed physical-relay 300-poll pcap and check the transaction accounting end to end. Read-only;
no switch, no relay. Complements the synthetic unit tests (tests/test_txncore.py) with real traffic.

Expectation for the clean 300-poll capture (one flow, separate-ACK / Case A):
  - 300 transactions ARM (one per DNP3 READ)
  - 300 qualifying outstation pure ACKs HELD (each acks its request's end-seq)
  - 300 responses ADMITTED behind their held ACK (separate mode)
  - every held frame drains via release passes; NO stale state remains; NO stale-discard on this
    single-flow, well-ordered trace (generation freshness never has to fire here — that path is
    covered by the collision/second-request unit tests).
"""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "shadow"))
from txncore_refmodel import TxnCore, Pkt, Ev, DNP3_PORT  # noqa: E402
from shadow_refmodel import classify as dnp3_classify  # noqa: E402
from scapy.all import PcapReader, IP, TCP, raw  # noqa: E402

PCAP = ("/home/philip/Projects/DNP3/research/physical_sel751/"
        "clrt_300poll_20260723T152242/evidence/clrt_300poll_20260723T152242.pcap")


def to_pkt(sp):
    if IP not in sp or TCP not in sp:
        return None
    ip, tcp = sp[IP], sp[TCP]
    payload = bytes(tcp.payload)
    plen = len(payload)
    # Faithful DNP3 gate (same parser as the shadow classifier): only a frame with a valid DNP3
    # APPLICATION header counts as dnp3_app; only function code READ(1) is fc-allowlisted for arming.
    cls, _ = dnp3_classify(str(ip.src), str(ip.dst), int(tcp.sport), int(tcp.dport),
                           int(tcp.flags), payload)
    is_dnp3 = cls in ("DNP3_READ", "DNP3_RESPONSE")
    fc_ok = (cls == "DNP3_READ")
    if tcp.dport == DNP3_PORT:
        dir_, ckey = 0, (int(ip.src) if isinstance(ip.src, int) else _ip2int(ip.src),
                          _ip2int(ip.dst), tcp.sport)
    elif tcp.sport == DNP3_PORT:
        dir_, ckey = 1, (_ip2int(ip.dst), _ip2int(ip.src), tcp.dport)
    else:
        dir_, ckey = 0, (_ip2int(ip.src), _ip2int(ip.dst), tcp.sport)
    return Pkt(dir=dir_, src_port=int(tcp.sport), dst_port=int(tcp.dport), seq=int(tcp.seq),
               ack=int(tcp.ack), flags=int(tcp.flags), payload_len=plen, is_dnp3_app=is_dnp3,
               flow_key=ckey, fc_ok=fc_ok)


def _ip2int(s):
    a, b, c, d = (int(x) for x in str(s).split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def main():
    tc = TxnCore()
    counts = Counter()
    seen_flows = set()
    for sp in PcapReader(PCAP):
        p = to_pkt(sp)
        if p is None:
            counts["non_ip_tcp"] += 1
            continue
        seen_flows.add(tc.flow_id(p.flow_key))
        ev = tc.process(p)
        counts[ev.kind.value] += 1
        # single outstanding per flow: drive the loop to drain whenever a response has been admitted,
        # so the next transaction starts clean (mirrors the recirc release + one-outstanding invariant)
        if ev.kind == Ev.RESP_HELD:
            for _ in range(tc.guard_passes + 4):
                r = tc.release_pass(p.flow_key)
                if r is not None:
                    counts["drain_" + r.kind.value] += 1
                if not tc.pending(p.flow_key):
                    break

    # any residue still held (should be none for the clean trace)
    residue = sum(1 for f in tc.held.values() if f) + sum(1 for f in tc.queued_resp.values() if f)

    checks = {
        "arm_300": counts.get("ARM", 0) == 300,
        "ack_held_300": counts.get("ACK_HELD", 0) == 300,
        "resp_held_300": counts.get("RESP_HELD", 0) == 300,
        "ack_released_300": counts.get("drain_ACK_RELEASED", 0) == 300,
        "resp_released_300": counts.get("drain_RESP_RELEASED", 0) == 300,
        "no_stale_discard": counts.get("STALE_DISCARD", 0) == 0,
        "no_residue_state": residue == 0,
        "single_flow": len(seen_flows) == 1,
    }
    out = {
        "pcap": os.path.basename(PCAP),
        "flows": len(seen_flows),
        "counts": dict(counts),
        "residue_held": residue,
        "checks": checks,
        "PASS": all(checks.values()),
    }
    import json
    print(json.dumps(out, indent=1))
    return 0 if out["PASS"] else 1


if __name__ == "__main__":
    sys.exit(main())
