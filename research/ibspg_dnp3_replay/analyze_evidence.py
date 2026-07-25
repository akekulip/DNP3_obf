#!/usr/bin/env python3
"""analyze_evidence.py — before/after evidence for the DNP3 in-network normalizer.

Takes one or more captures, classifies every DNP3 frame, and produces the three things the
end-to-end demonstration has to show:

  1. TIMING   — the ACK->RESPONSE interval (Formby CLRT) distribution, before vs after
  2. SIZE     — the on-wire frame-size distribution, before vs after
  3. CLASSIFY — per-role counts, checked against ground truth where available

Emits a machine-readable JSON and, when matplotlib is available, figures. Pure stdlib for the
parsing and statistics so it runs anywhere; figures need the research venv
(/home/philip/.venvs/research/bin/python).

Usage:
  analyze_evidence.py --label native:before.pcap --label defended:after.pcap \
                      [--json out.json] [--figdir figs/]

Frame classification mirrors the silicon classifier so the two can be compared directly:
  READ      = DNP3 application function 1, master -> outstation
  RESPONSE  = DNP3 application function 129, outstation -> master
  PURE_ACK  = zero payload, ACK set, SYN/FIN/RST clear, outstation -> master
  LINK_OTHER= valid DNP3 link frame with LEN == 5 (no transport/application payload)
  BYPASS    = anything else that is well-formed
"""
import argparse
import json
import os
import struct
import sys
from collections import Counter, defaultdict

DNP3_MAGIC = b"\x05\x64"
DNP3_PORT = 20000


def read_pcap(path):
    """Yield (ts, frame_bytes) from a classic pcap. Handles both endiannesses and SLL."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        end = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts, tu, incl, orig = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                break
            if linktype == 113 and len(data) >= 16:        # LINUX_SLL
                data = b"\x00" * 6 + data[6:12] + data[14:16] + data[16:]
            yield ts + tu / 1e6, data, orig


def classify(frame):
    """Return a dict describing one frame, or None if it is not IPv4/TCP."""
    if len(frame) < 34 or struct.unpack(">H", frame[12:14])[0] != 0x0800:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != 6 or len(frame) < 14 + ihl + 20:
        return None
    tcp = 14 + ihl
    doff = ((frame[tcp + 12] >> 4) & 0x0F) * 4
    total_len = struct.unpack(">H", frame[16:18])[0]
    payload = frame[14 + ihl + doff:14 + ihl + doff + max(0, total_len - ihl - doff)]
    sport, dport = struct.unpack(">H", frame[tcp:tcp + 2])[0], struct.unpack(">H", frame[tcp + 2:tcp + 4])[0]
    flags = frame[tcp + 13]
    from_outstation = (sport == DNP3_PORT)

    role, func = "BYPASS", None
    if len(payload) == 0 and (flags & 0x10) and not (flags & 0x07):
        role = "PURE_ACK" if from_outstation else "PURE_ACK_MASTER"
    elif payload[:2] == DNP3_MAGIC and len(payload) >= 5:
        link_len = payload[2]
        if link_len == 5:
            role = "LINK_OTHER"
        elif link_len >= 8 and len(payload) >= 13:
            func = payload[12]                       # link(10) + transport(1) + app ctrl(1) -> func
            if func == 1 and not from_outstation:
                role = "READ"
            elif func == 129 and from_outstation:
                role = "RESPONSE"
            else:
                role = "DNP3_OTHER"
    return {"role": role, "func": func, "wire_len": len(frame), "payload_len": len(payload),
            "from_outstation": from_outstation, "flags": flags, "tcp_hdr_len": doff}


def analyze(path):
    frames, roles, sizes = [], Counter(), Counter()
    for ts, data, orig in read_pcap(path):
        c = classify(data)
        if c is None:
            roles["NON_IPV4_TCP"] += 1
            continue
        c["ts"] = ts
        frames.append(c)
        roles[c["role"]] += 1
        sizes[c["wire_len"]] += 1

    # pair transactions in wire order: a pure ACK, then the next RESPONSE, is one CLRT sample
    clrt, req_resp, pending_ack, pending_read = [], [], None, None
    for c in frames:
        if c["role"] == "READ":
            pending_read = c["ts"]; pending_ack = None
        elif c["role"] == "PURE_ACK":
            pending_ack = c["ts"]
        elif c["role"] == "RESPONSE":
            if pending_ack is not None:
                clrt.append((c["ts"] - pending_ack) * 1000.0)
                pending_ack = None
            if pending_read is not None:
                req_resp.append((c["ts"] - pending_read) * 1000.0)
                pending_read = None
    return {"path": path, "frames": len(frames), "roles": dict(roles),
            "sizes": {str(k): v for k, v in sorted(sizes.items())},
            "clrt_ms": clrt, "req_resp_ms": req_resp,
            "resp_wire_sizes": [c["wire_len"] for c in frames if c["role"] == "RESPONSE"],
            "all_wire_sizes": [c["wire_len"] for c in frames]}


def stats(xs):
    xs = sorted(xs)
    if not xs:
        return {"n": 0}
    n = len(xs)
    mean = sum(xs) / n
    var = sum((x - mean) ** 2 for x in xs) / n

    def p(q):
        return xs[min(n - 1, int(round(q * (n - 1))))]
    return {"n": n, "min": round(xs[0], 6), "p50": round(p(0.5), 6), "p95": round(p(0.95), 6),
            "max": round(xs[-1], 6), "mean": round(mean, 6), "sd": round(var ** 0.5, 6),
            "range": round(xs[-1] - xs[0], 6), "distinct": len(set(round(x, 6) for x in xs))}


def figures(results, figdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  (matplotlib unavailable — skipping figures; rerun with the research venv)")
        return []
    os.makedirs(figdir, exist_ok=True)
    made = []
    labels = list(results.keys())

    # Fig 1 — CLRT ECDF, before vs after: the timing normalization result
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for lb in labels:
        xs = sorted(results[lb]["clrt_ms"])
        if not xs:
            continue
        ys = [(i + 1) / len(xs) for i in range(len(xs))]
        ax.step(xs, ys, where="post", label="%s (n=%d)" % (lb, len(xs)), linewidth=1.8)
    ax.set_xlabel("ACK → RESPONSE interval (CLRT), ms")
    ax.set_ylabel("empirical CDF")
    ax.set_title("Timing channel: CLRT distribution before vs after normalization")
    ax.grid(alpha=0.3); ax.legend()
    f = os.path.join(figdir, "fig1_clrt_ecdf.png"); fig.tight_layout(); fig.savefig(f, dpi=150)
    plt.close(fig); made.append(f)

    # Fig 2 — wire-size histogram, before vs after: the size normalization result
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for lb in labels:
        xs = results[lb]["all_wire_sizes"]
        if not xs:
            continue
        ax.hist(xs, bins=range(min(xs), max(xs) + 6, 2), alpha=0.55,
                label="%s (%d distinct)" % (lb, len(set(xs))))
    ax.set_xlabel("on-wire frame size, bytes")
    ax.set_ylabel("frames")
    ax.set_title("Size channel: frame-size distribution before vs after normalization")
    ax.grid(alpha=0.3); ax.legend()
    f = os.path.join(figdir, "fig2_size_hist.png"); fig.tight_layout(); fig.savefig(f, dpi=150)
    plt.close(fig); made.append(f)

    # Fig 3 — joint size/timing scatter: what an observer actually sees
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for lb in labels:
        r = results[lb]
        n = min(len(r["clrt_ms"]), len(r["resp_wire_sizes"]))
        if n:
            ax.scatter(r["clrt_ms"][:n], r["resp_wire_sizes"][:n], s=22, alpha=0.6, label=lb)
    ax.set_xlabel("CLRT, ms"); ax.set_ylabel("response frame size, bytes")
    ax.set_title("Joint observation space: an observer sees one point per transaction")
    ax.grid(alpha=0.3); ax.legend()
    f = os.path.join(figdir, "fig3_joint_scatter.png"); fig.tight_layout(); fig.savefig(f, dpi=150)
    plt.close(fig); made.append(f)

    # Fig 4 — classification counts per role
    fig, ax = plt.subplots(figsize=(7, 4.2))
    allroles = sorted({r for lb in labels for r in results[lb]["roles"]})
    w = 0.8 / max(1, len(labels))
    for i, lb in enumerate(labels):
        vals = [results[lb]["roles"].get(r, 0) for r in allroles]
        ax.bar([x + i * w for x in range(len(allroles))], vals, width=w, label=lb)
    ax.set_xticks([x + 0.4 - w / 2 for x in range(len(allroles))])
    ax.set_xticklabels(allroles, rotation=20, ha="right")
    ax.set_ylabel("frames"); ax.set_title("Classification: per-role frame counts")
    ax.grid(alpha=0.3, axis="y"); ax.legend()
    f = os.path.join(figdir, "fig4_classification.png"); fig.tight_layout(); fig.savefig(f, dpi=150)
    plt.close(fig); made.append(f)
    return made


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", action="append", required=True,
                    help="label:path.pcap (repeatable; e.g. native:before.pcap defended:after.pcap)")
    ap.add_argument("--json", default=None)
    ap.add_argument("--figdir", default=None)
    a = ap.parse_args()

    results = {}
    for spec in a.label:
        lb, _, path = spec.partition(":")
        if not os.path.exists(path):
            sys.exit("missing capture: %s" % path)
        results[lb] = analyze(path)

    summary = {}
    for lb, r in results.items():
        summary[lb] = {"frames": r["frames"], "roles": r["roles"],
                       "clrt_ms": stats(r["clrt_ms"]),
                       "req_resp_ms": stats(r["req_resp_ms"]),
                       "wire_size": stats([float(x) for x in r["all_wire_sizes"]]),
                       "distinct_wire_sizes": sorted(set(r["all_wire_sizes"]))}
        s = summary[lb]
        print("%-12s frames=%-5d roles=%s" % (lb, r["frames"], r["roles"]))
        print("   CLRT ms      n=%-4s p50=%-10s sd=%-10s range=%-10s distinct=%s"
              % (s["clrt_ms"].get("n"), s["clrt_ms"].get("p50"), s["clrt_ms"].get("sd"),
                 s["clrt_ms"].get("range"), s["clrt_ms"].get("distinct")))
        print("   wire size    n=%-4s p50=%-10s distinct sizes=%s"
              % (s["wire_size"].get("n"), s["wire_size"].get("p50"), s["distinct_wire_sizes"][:12]))

    out = {"summary": summary, "raw": {lb: {k: v for k, v in r.items() if k != "sizes"}
                                       for lb, r in results.items()}}
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1)
        print("wrote", a.json)
    if a.figdir:
        for f in figures(results, a.figdir):
            print("figure:", f)


if __name__ == "__main__":
    main()
