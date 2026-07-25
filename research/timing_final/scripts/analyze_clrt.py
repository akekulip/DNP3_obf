#!/usr/bin/env python3
"""analyze_clrt.py — the single reproducible CLRT analysis pipeline (directive §6 + §22).

From a raw PCAP (+ optional switch evidence), produces:
  <out>.transactions.csv   one row per transaction (§22)
  <out>.summary.json       full statistics + multi-resolution leakage (§6)
  <out>.validation.json    per-transaction validity + ambiguity flags (§22)

Design rules from the directive:
  - reject ambiguous pairings rather than silently picking a packet (§22);
  - the headline CLRT must be cross-checkable against tshark (§22) — see --tshark-crosscheck;
  - separate CLRT magnitude / ACK mode / TCP-stack / size channels (§6);
  - never claim normalization if the response arrives at/after the deadline (§3/§6).

Classification mirrors the silicon classifier:
  READ      = DNP3 app function 1, master->outstation
  RESPONSE  = DNP3 app function 129, outstation->master
  PURE_ACK  = TCP payload 0, ACK set, SYN/FIN/RST clear, outstation->master

Stdlib only (parsing + stats); matplotlib only if --figdir is given (use the research venv then).
"""
import argparse
import json
import math
import os
import struct
import subprocess
import sys

DNP3_MAGIC = b"\x05\x64"
DNP3_PORT = 20000


# ----------------------------------------------------------------- pcap ----
def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = gh[:4]
        end = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        linktype = struct.unpack(end + "I", gh[20:24])[0]
        idx = 0
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            ts, tu, incl, _ = struct.unpack(end + "IIII", rh)
            data = f.read(incl)
            if len(data) < incl:
                break
            if linktype == 113 and len(data) >= 16:      # LINUX_SLL
                data = b"\x00" * 6 + data[6:12] + data[14:16] + data[16:]
            yield idx, ts + tu / 1e6, data
            idx += 1


def classify(frame):
    if len(frame) < 34 or struct.unpack(">H", frame[12:14])[0] != 0x0800:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != 6 or len(frame) < 14 + ihl + 20:
        return None
    tcp = 14 + ihl
    doff = ((frame[tcp + 12] >> 4) & 0x0F) * 4
    total_len = struct.unpack(">H", frame[16:18])[0]
    plen = max(0, total_len - ihl - doff)
    payload = frame[14 + ihl + doff:14 + ihl + doff + plen]
    sport = struct.unpack(">H", frame[tcp:tcp + 2])[0]
    dport = struct.unpack(">H", frame[tcp + 2:tcp + 4])[0]
    seq = struct.unpack(">I", frame[tcp + 4:tcp + 8])[0]
    ack = struct.unpack(">I", frame[tcp + 8:tcp + 12])[0]
    flags = frame[tcp + 13]
    from_out = (sport == DNP3_PORT)
    role, func = "OTHER", None
    if plen == 0 and (flags & 0x10) and not (flags & 0x07):
        role = "PURE_ACK" if from_out else "PURE_ACK_MASTER"
    elif payload[:2] == DNP3_MAGIC and plen >= 13:
        func = payload[12]
        if func == 1 and not from_out:
            role = "READ"
        elif func == 129 and from_out:
            role = "RESPONSE"
        else:
            role = "DNP3_OTHER"
    return {"role": role, "func": func, "wire": len(frame), "plen": plen, "doff": doff,
            "from_out": from_out, "seq": seq, "ack": ack, "flags": flags,
            "ip_len": total_len, "retrans": False}


# --------------------------------------------------------- transactions ----
def build_transactions(frames):
    """Pair READ -> pure ACK -> RESPONSE in wire order. Flag, never silently resolve, ambiguity."""
    def fresh(idx=None, ts=None, seq=None):
        return {"read_idx": idx, "read_ts": ts, "read_seq": seq, "ack_idx": None,
                "ack_ts": None, "resp_idx": None, "resp_ts": None, "resp_wire": None,
                "resp_plen": None, "flags": []}
    txns, cur = [], None
    for idx, ts, c in frames:
        r = c["role"]
        if r == "READ":
            if cur:
                txns.append(cur)
            cur = fresh(idx, ts, c["seq"])
        elif r == "PURE_ACK":
            # A pure ACK opens a CLRT pair. Required for an inbound-only capture (e.g. Vision
            # `-Q in`), which sees the outstation's ACK+RESPONSE but not the master's own READ:
            # the ACK->RESPONSE interval is the CLRT and is fully measurable without the READ.
            if cur is None or cur["ack_idx"] is not None or cur["resp_idx"] is not None:
                if cur:
                    txns.append(cur)
                cur = fresh()
            cur["ack_idx"] = idx
            cur["ack_ts"] = ts
        elif r == "RESPONSE" and cur is not None:
            if cur["resp_idx"] is None:
                cur["resp_idx"] = idx
                cur["resp_ts"] = ts
                cur["resp_wire"] = c["wire"]
                cur["resp_plen"] = c["plen"]
            else:
                cur["flags"].append("multiple_response")
    if cur:
        txns.append(cur)
    for t in txns:
        if t["ack_ts"] is not None and t["resp_ts"] is not None:
            t["clrt_ms"] = (t["resp_ts"] - t["ack_ts"]) * 1000.0
        else:
            t["clrt_ms"] = None
            if t["resp_ts"] is None:
                t["flags"].append("missing_response")
            if t["ack_ts"] is None:
                t["flags"].append("missing_pure_ack")
        t["ambiguous"] = bool(t["flags"])
    return txns


# ---------------------------------------------------------------- stats ----
def stats(xs):
    xs = sorted(x for x in xs if x is not None)
    n = len(xs)
    if n == 0:
        return {"count": 0}
    mean = sum(xs) / n
    var = sum((x - mean) ** 2 for x in xs) / n

    def p(q):
        return xs[min(n - 1, int(round(q * (n - 1))))]
    return {"count": n, "min": round(xs[0], 6), "p5": round(p(.05), 6), "p25": round(p(.25), 6),
            "median": round(p(.5), 6), "p75": round(p(.75), 6), "p95": round(p(.95), 6),
            "p99": round(p(.99), 6), "max": round(xs[-1], 6), "mean": round(mean, 6),
            "sd": round(var ** 0.5, 6), "range": round(xs[-1] - xs[0], 6),
            "distinct": len(set(round(x, 6) for x in xs))}


def entropy_bits(xs, binw_ms):
    if not xs:
        return 0.0, 0
    b = {}
    for x in xs:
        k = round(x / binw_ms)
        b[k] = b.get(k, 0) + 1
    n = len(xs)
    h = -sum((c / n) * math.log2(c / n) for c in b.values())
    return round(h, 4), len(b)


def leakage_table(xs):
    """Timing leakage (observer entropy) at the resolutions the directive lists (§6)."""
    out = {}
    for label, binw in (("10us", 0.010), ("50us", 0.050), ("100us", 0.100),
                        ("500us", 0.500), ("1ms", 1.000)):
        h, k = entropy_bits(xs, binw)
        out[label] = {"entropy_bits": h, "occupied_bins": k}
    return out


# --------------------------------------------------- tshark cross-check ----
def tshark_clrt_median(pcap, outstation_ip):
    """Independent CLRT median via tshark: pure ACK (len 0) -> next RESPONSE (dnp3.al.func==129)."""
    try:
        out = subprocess.run(
            ["tshark", "-r", pcap, "-Y", "tcp.port==20000",
             "-T", "fields", "-e", "frame.time_epoch", "-e", "ip.src",
             "-e", "tcp.len", "-e", "dnp3.al.func"],
            capture_output=True, text=True, timeout=120).stdout.strip().split("\n")
    except Exception as e:
        return {"available": False, "error": str(e)[:80]}
    clrt, last_ack = [], None
    for line in out:
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        ts, src, tlen, func = parts[0], parts[1], parts[2], parts[3]
        if src != outstation_ip:
            continue
        try:
            ts = float(ts); tlen = int(tlen or 0)
        except ValueError:
            continue
        if tlen == 0:
            last_ack = ts
        elif "129" in func and last_ack is not None:
            clrt.append((ts - last_ack) * 1000.0); last_ack = None
    clrt.sort()
    if not clrt:
        return {"available": True, "n": 0}
    return {"available": True, "n": len(clrt), "median_ms": round(clrt[len(clrt) // 2], 6)}


# ----------------------------------------------------------------- main ----
def main():
    ap = argparse.ArgumentParser(description="CLRT analysis pipeline (directive §6/§22)")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--outstation-ip", default="192.168.10.7")
    ap.add_argument("--label", default="run")
    ap.add_argument("--g-ms", type=float, default=None, help="configured G, for protection check")
    ap.add_argument("--out", default=None, help="output prefix (default: alongside the pcap)")
    ap.add_argument("--tshark-crosscheck", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(a.pcap):
        sys.exit("missing pcap: %s" % a.pcap)
    out = a.out or os.path.splitext(a.pcap)[0]

    frames = [(i, ts, classify(fr)) for i, ts, fr in read_pcap(a.pcap)]
    frames = [(i, ts, c) for i, ts, c in frames if c]
    txns = build_transactions(frames)

    clean = [t for t in txns if not t["ambiguous"] and t["clrt_ms"] is not None]
    clrt = [t["clrt_ms"] for t in clean]
    resp_sizes = [t["resp_wire"] for t in clean if t["resp_wire"]]

    # per-transaction CSV
    cols = ["txn", "read_idx", "ack_idx", "resp_idx", "clrt_ms", "resp_wire", "ambiguous", "flags",
            "protection_applied", "low_G_warning", "effective_hold_ms"]
    with open(out + ".transactions.csv", "w") as f:
        f.write(",".join(cols) + "\n")
        for i, t in enumerate(txns):
            pa = lw = eh = ""
            if a.g_ms is not None and t["clrt_ms"] is not None:
                nat = t["clrt_ms"]
                pa = "true" if nat < a.g_ms else "false"
                lw = "false" if nat < a.g_ms else "true"
                eh = round(a.g_ms - nat, 6) if nat < a.g_ms else 0.0
            f.write(",".join(str(x) for x in [
                i, t["read_idx"], t["ack_idx"], t["resp_idx"],
                "" if t["clrt_ms"] is None else round(t["clrt_ms"], 6),
                t["resp_wire"] or "", t["ambiguous"], ";".join(t["flags"]), pa, lw, eh]) + "\n")

    # ACK-mode channel: fraction of transactions with a separate pure ACK
    n_sep = sum(1 for t in txns if t["ack_idx"] is not None)
    roles = {}
    for _, _, c in frames:
        roles[c["role"]] = roles.get(c["role"], 0) + 1

    summary = {
        "label": a.label, "pcap": os.path.abspath(a.pcap), "g_ms": a.g_ms,
        "transactions_total": len(txns), "transactions_clean": len(clean),
        "transactions_ambiguous": sum(1 for t in txns if t["ambiguous"]),
        "roles": roles,
        "clrt_ms": stats(clrt),
        "clrt_leakage": leakage_table(clrt),
        "response_wire_size": stats([float(s) for s in resp_sizes]),
        "response_wire_distinct": sorted(set(resp_sizes)),
        "channels": {
            "clrt_magnitude": stats(clrt),
            "ack_mode": {"separate_ack_txns": n_sep, "total_txns": len(txns),
                         "separate_ack_fraction": round(n_sep / len(txns), 4) if txns else 0},
            "size": {"distinct_response_wire_sizes": len(set(resp_sizes))},
        },
    }
    if a.g_ms is not None and clrt:
        summary["protection"] = {
            "protection_applied_txns": sum(1 for c in clrt if c < a.g_ms),
            "low_G_warning_txns": sum(1 for c in clrt if c >= a.g_ms),
            "note": "protection_applied requires native_clrt < G; else zero hold + low_G_warning",
        }
    if a.tshark_crosscheck:
        summary["tshark_crosscheck"] = tshark_clrt_median(a.pcap, a.outstation_ip)
        own = summary["clrt_ms"].get("median")
        ts = summary["tshark_crosscheck"].get("median_ms")
        if own is not None and ts is not None:
            summary["tshark_crosscheck"]["agrees_within_us"] = round(abs(own - ts) * 1000, 3)

    json.dump(summary, open(out + ".summary.json", "w"), indent=1)
    json.dump({"transactions": txns}, open(out + ".validation.json", "w"), indent=1)

    s = summary["clrt_ms"]
    print("%s: %d txns (%d clean, %d ambiguous)" % (
        a.label, len(txns), len(clean), summary["transactions_ambiguous"]))
    if s.get("count"):
        print("  CLRT ms: n=%d median=%s sd=%s p99=%s range=%s distinct=%s" % (
            s["count"], s["median"], s["sd"], s["p99"], s["range"], s["distinct"]))
        print("  leakage @1ms=%s bits, @50us=%s bits" % (
            summary["clrt_leakage"]["1ms"]["entropy_bits"],
            summary["clrt_leakage"]["50us"]["entropy_bits"]))
    if a.tshark_crosscheck and summary["tshark_crosscheck"].get("median_ms") is not None:
        print("  tshark cross-check median=%s ms (agrees within %s us)" % (
            summary["tshark_crosscheck"]["median_ms"],
            summary["tshark_crosscheck"].get("agrees_within_us")))
    print("  wrote %s.{transactions.csv,summary.json,validation.json}" % os.path.basename(out))


if __name__ == "__main__":
    main()
