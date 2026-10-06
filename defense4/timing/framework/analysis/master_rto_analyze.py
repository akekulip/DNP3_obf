"""Read a master-RTO capture and probe record: when did the master repeat its request, and what did the kernel say its RTO was.

A repeat is a packet from the master on the 4-tuple that carries the same sequence number and payload as the first request. Gaps are in milliseconds,
from the first transmission. The first gap is an OBSERVED repeat threshold; it is compared with the kernel's TCP_INFO rto, not assumed equal to it."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "size"))
import rrc  # noqa: E402


def repeats(pcap, relay_port=20000):
    first, times = None, []
    for ts, raw in rrc.read_records(pcap):
        p = rrc.parse(raw)
        if p and p.dport == relay_port and p.payload:
            if first is None:
                first = (p.seq, p.payload)
            if (p.seq, p.payload) == first:
                times.append(ts)
    return [(t - times[0]) / 1e6 for t in times] if times else []


def analyze(pcap, record=None):
    at = repeats(pcap)
    out = {"transmissions": len(at), "offsets_ms": [round(x, 3) for x in at],
           "gaps_ms": [round(b - a, 3) for a, b in zip(at, at[1:])]}
    out["first_repeat_ms"] = out["offsets_ms"][1] if len(at) > 1 else None
    if record:
        idle = record["tcp_info_idle"]
        out["kernel_idle"] = {"rto_ms": idle["rto_us"] / 1000, "rtt_ms": idle["rtt_us"] / 1000, "rttvar_ms": idle["rttvar_us"] / 1000}
        out["kernel_rto_ms_over_time"] = sorted({round(s["rto_us"] / 1000, 1) for s in record["tcp_info_samples"]})
        out["kernel_max_backoff"] = max((s["backoff"] for s in record["tcp_info_samples"]), default=None)
        out["kernel_max_retransmits"] = max((s["retransmits"] for s in record["tcp_info_samples"]), default=None)
        out["cleanup_verified"] = record.get("cleanup_verified")
    return out


if __name__ == "__main__":
    print(json.dumps(analyze(sys.argv[1], json.load(open(sys.argv[2])) if len(sys.argv) > 2 else None), indent=1))
