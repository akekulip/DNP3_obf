#!/usr/bin/env python3
"""Characterize DNP3-over-TCP ACK/response timing from real-device PCAPs.

Parses six per-device captures directly (no reliance on filenames for the
transaction logic), reconstructs request/response TRANSACTIONS for every TCP
flow that uses DNP3 port 20000, and classifies each transaction by how the
outstation delivers its DNP3 application RESPONSE relative to the TCP ACK of
the master's request:

  A. COMBINED_ACK_RESPONSE  -- first reverse packet carries BOTH the TCP ACK
                               and the DNP3 payload (piggyback).
  B. SEPARATE_ACK_RESPONSE  -- a PURE TCP ACK (len 0, ACK, no SYN/FIN/RST)
                               appears first, then a later DNP3 payload response.
  C. OTHER_OR_AMBIGUOUS     -- anything that cannot be cleanly classified
                               (no response found, RST/FIN first, etc.).

Terminology is strict: "pure TCP ACK" is a zero-payload TCP acknowledgement;
"ACK-bearing DNP3 RESPONSE" is a DNP3 response packet that also acknowledges;
"DNP3 application CONFIRM" is reserved for an actual DNP3 CONFIRM function code.
The DNP3 response is NEVER called an "application ACK".

Outputs (all overwritten on each run):
  reports/ack_trace_characterization.csv   -- one row per transaction
  reports/ack_trace_characterization.json  -- transactions + per-device summary
  reports/ack_trace_summary.md             -- human-readable report
  profiles/sel751_separate_ack.json        -- descriptive measured profile
  profiles/ab1400_combined_ack.json        -- descriptive measured profile
  profiles/ion7550_combined_ack.json       -- descriptive measured profile

This script reads only the PCAPs; it issues no traffic and modifies no capture.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# --- Fixed lab facts (used only for device labelling / profile grouping) -----
# The transaction reconstruction itself does NOT assume these; it discovers the
# outstation endpoint per flow as whichever side listens on DNP3 port 20000.
DNP3_PORT = 20000
REFERENCE_IP = "10.0.0.2"  # shared reference outstation present in every capture
DEVICE_OUTSTATION_IP = {
    "SEL751": "10.0.0.1",
    "AB1400": "10.0.0.12",
    "ION7550": "10.0.0.11",
}
DEVICE_DISPLAY = {"SEL751": "SEL-751", "AB1400": "AB1400", "ION7550": "ION7550"}

# tshark field list, in dump order.
TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.ack",
    "tcp.analysis.retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "dnp3.al.func",
    "frame.len",
]

CLS_COMBINED = "COMBINED_ACK_RESPONSE"
CLS_SEPARATE = "SEPARATE_ACK_RESPONSE"
CLS_OTHER = "OTHER_OR_AMBIGUOUS"


# ---------------------------------------------------------------------------
# Packet parsing
# ---------------------------------------------------------------------------
@dataclass
class Packet:
    frame: int
    t: float
    stream: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    tlen: int
    flags: str
    syn: bool
    fin: bool
    rst: bool
    ackf: bool
    retrans: bool
    dup_ack: bool
    ooo: bool
    dnp3_func: Optional[int]
    dnp3_present: bool
    frame_len: int


def _b(v: str) -> bool:
    """tshark boolean field -> Python bool ('True'/'False' or '1'/'0')."""
    return v.strip() in ("True", "1")


def _flag_set(v: str) -> bool:
    """Analysis flag field (non-empty when the condition holds)."""
    return v.strip() != ""


def _int(v: str, default: int = 0) -> int:
    v = v.strip()
    if v == "":
        return default
    # multi-value fields (comma separated) -> take first
    v = v.split(",")[0]
    try:
        return int(v)
    except ValueError:
        return default


def run_tshark(pcap: str) -> list[Packet]:
    """Dump every DNP3-port-20000 packet of a capture into Packet records."""
    cmd = [
        "tshark",
        "-r",
        pcap,
        "-Y",
        f"tcp.port=={DNP3_PORT}",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",  # first occurrence only for multi-value fields
    ]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    # dnp3 presence is derived from frame.protocols (appended last, separately)
    cmd += ["-e", "frame.protocols"]

    logger.info("tshark parsing %s", os.path.basename(pcap))
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    packets: list[Packet] = []
    ncol = len(TSHARK_FIELDS) + 1
    for line in proc.stdout.splitlines():
        cols = line.split("\t")
        if len(cols) < ncol:
            cols += [""] * (ncol - len(cols))
        (
            f_num, f_t, f_stream, f_src, f_dst, f_sport, f_dport, f_seq, f_ack,
            f_len, f_flags, f_syn, f_fin, f_rst, f_ackf, f_retr, f_dup, f_ooo,
            f_func, f_flen, f_proto,
        ) = cols[:ncol]

        func_raw = f_func.strip().split(",")[0]
        dnp3_func = int(func_raw) if func_raw.isdigit() else None
        packets.append(
            Packet(
                frame=_int(f_num),
                t=float(f_t) if f_t.strip() else 0.0,
                stream=_int(f_stream, -1),
                src_ip=f_src.strip(),
                dst_ip=f_dst.strip(),
                src_port=_int(f_sport),
                dst_port=_int(f_dport),
                seq=_int(f_seq),
                ack=_int(f_ack),
                tlen=_int(f_len),
                flags=f_flags.strip(),
                syn=_b(f_syn),
                fin=_b(f_fin),
                rst=_b(f_rst),
                ackf=_b(f_ackf),
                retrans=_flag_set(f_retr),
                dup_ack=_flag_set(f_dup),
                ooo=_flag_set(f_ooo),
                dnp3_func=dnp3_func,
                dnp3_present=("dnp3" in f_proto),
                frame_len=_int(f_flen),
            )
        )
    packets.sort(key=lambda p: p.frame)
    return packets


# ---------------------------------------------------------------------------
# Transaction reconstruction
# ---------------------------------------------------------------------------
@dataclass
class Transaction:
    pcap: str
    device_label: str
    stream: int
    flow_id: str
    master: str
    outstation: str
    outstation_ip: str
    req_frame: int
    req_size: int
    req_func: Optional[int]
    first_rev_frame: Optional[int]
    first_rev_is_pure_ack: bool
    resp_frame: Optional[int]
    resp_size: Optional[int]
    resp_func: Optional[int]
    resp_flags: Optional[str]
    resp_seq: Optional[int]
    resp_ack: Optional[int]
    req_to_ack_ms: Optional[float]
    req_to_resp_ms: Optional[float]
    ack_to_resp_ms: Optional[float]
    retransmission: bool
    duplicate_ack: bool
    reset: bool
    out_of_order: bool
    classification: str
    note: str = ""


def _is_pure_tcp_ack(p: Packet) -> bool:
    return p.tlen == 0 and p.ackf and not p.syn and not p.fin and not p.rst


def build_transactions(packets: list[Packet], pcap: str, device_label: str) -> list[Transaction]:
    """Walk each flow and reconstruct request-anchored transactions."""
    # group by TCP stream
    flows: dict[int, list[Packet]] = {}
    for p in packets:
        flows.setdefault(p.stream, []).append(p)

    txns: list[Transaction] = []
    for stream, pkts in sorted(flows.items()):
        pkts.sort(key=lambda p: p.frame)

        # Identify outstation endpoint = the side with DNP3 port 20000.
        out_ip = out_port = None
        mst_ip = mst_port = None
        for p in pkts:
            if p.dst_port == DNP3_PORT:
                out_ip, out_port = p.dst_ip, p.dst_port
                mst_ip, mst_port = p.src_ip, p.src_port
                break
            if p.src_port == DNP3_PORT:
                out_ip, out_port = p.src_ip, p.src_port
                mst_ip, mst_port = p.dst_ip, p.dst_port
                break
        if out_ip is None:
            continue

        def is_request(p: Packet) -> bool:
            return (
                p.dst_ip == out_ip
                and p.dst_port == DNP3_PORT
                and p.tlen > 0
                and p.dnp3_present
            )

        def is_reverse(p: Packet) -> bool:
            return p.src_ip == out_ip and p.src_port == DNP3_PORT

        # indices of request packets
        req_idx = [i for i, p in enumerate(pkts) if is_request(p)]
        for k, i in enumerate(req_idx):
            req = pkts[i]
            end = req_idx[k + 1] if k + 1 < len(req_idx) else len(pkts)
            window = pkts[i + 1:end]

            rev = [p for p in window if is_reverse(p)]
            first_rev = rev[0] if rev else None
            first_ack = next((p for p in rev if p.ackf), None)
            first_resp = next((p for p in rev if p.tlen > 0 and p.dnp3_present), None)

            retrans = any(p.retrans for p in window)
            dup_ack = any(p.dup_ack for p in window)
            reset = any(p.rst for p in window)
            ooo = any(p.ooo for p in window)

            req_to_ack = (first_ack.t - req.t) * 1000.0 if first_ack else None
            req_to_resp = (first_resp.t - req.t) * 1000.0 if first_resp else None
            ack_to_resp = (
                (first_resp.t - first_ack.t) * 1000.0
                if (first_resp and first_ack)
                else None
            )

            first_rev_pure = bool(first_rev and _is_pure_tcp_ack(first_rev))

            # --- classification ------------------------------------------------
            note = ""
            if first_resp is None:
                cls = CLS_OTHER
                note = "no DNP3 response found in window"
            elif first_rev is not None and (first_rev.syn or first_rev.fin or first_rev.rst):
                cls = CLS_OTHER
                note = "first reverse packet is a TCP control (SYN/FIN/RST)"
            elif first_rev_pure:
                if first_resp is not first_rev:
                    cls = CLS_SEPARATE
                else:
                    cls = CLS_OTHER
                    note = "pure-ACK packet also flagged as response (inconsistent)"
            elif first_rev is not None and first_rev.tlen > 0 and first_rev.dnp3_present:
                if first_resp is first_rev:
                    cls = CLS_COMBINED
                else:
                    cls = CLS_OTHER
                    note = "first reverse payload differs from first DNP3 response"
            else:
                cls = CLS_OTHER
                note = "first reverse packet neither pure ACK nor DNP3 payload"

            txns.append(
                Transaction(
                    pcap=pcap,
                    device_label=device_label,
                    stream=stream,
                    flow_id=f"{mst_ip}:{mst_port}<->{out_ip}:{out_port}#s{stream}",
                    master=f"{mst_ip}:{mst_port}",
                    outstation=f"{out_ip}:{out_port}",
                    outstation_ip=out_ip,
                    req_frame=req.frame,
                    req_size=req.tlen,
                    req_func=req.dnp3_func,
                    first_rev_frame=first_rev.frame if first_rev else None,
                    first_rev_is_pure_ack=first_rev_pure,
                    resp_frame=first_resp.frame if first_resp else None,
                    resp_size=first_resp.tlen if first_resp else None,
                    resp_func=first_resp.dnp3_func if first_resp else None,
                    resp_flags=first_resp.flags if first_resp else None,
                    resp_seq=first_resp.seq if first_resp else None,
                    resp_ack=first_resp.ack if first_resp else None,
                    req_to_ack_ms=req_to_ack,
                    req_to_resp_ms=req_to_resp,
                    ack_to_resp_ms=ack_to_resp,
                    retransmission=retrans,
                    duplicate_ack=dup_ack,
                    reset=reset,
                    out_of_order=ooo,
                    classification=cls,
                    note=note,
                )
            )
    return txns


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------
def dist(values: list[float]) -> dict:
    vals = [v for v in values if v is not None]
    if not vals:
        return {"n": 0, "median": None, "p95": None, "max": None,
                "mean": None, "std": None}
    arr = np.asarray(vals, dtype=float)
    return {
        "n": int(arr.size),
        "median": round(float(np.median(arr)), 4),
        "p95": round(float(np.percentile(arr, 95)), 4),
        "max": round(float(arr.max()), 4),
        "mean": round(float(arr.mean()), 4),
        "std": round(float(arr.std(ddof=0)), 4),
    }


def size_hist(values: list[Optional[int]]) -> dict[str, int]:
    hist: dict[int, int] = {}
    for v in values:
        if v is None:
            continue
        hist[v] = hist.get(v, 0) + 1
    return {str(k): hist[k] for k in sorted(hist)}


def pct(part: int, total: int) -> float:
    return round(100.0 * part / total, 2) if total else 0.0


def group_summary(txns: list[Transaction]) -> dict:
    total = len(txns)
    n_comb = sum(t.classification == CLS_COMBINED for t in txns)
    n_sep = sum(t.classification == CLS_SEPARATE for t in txns)
    n_oth = sum(t.classification == CLS_OTHER for t in txns)
    return {
        "total_transactions": total,
        "combined": n_comb,
        "separate": n_sep,
        "other": n_oth,
        "combined_pct": pct(n_comb, total),
        "separate_pct": pct(n_sep, total),
        "other_pct": pct(n_oth, total),
        "req_to_ack_ms": dist([t.req_to_ack_ms for t in txns]),
        "req_to_resp_ms": dist([t.req_to_resp_ms for t in txns]),
        "ack_to_resp_ms": dist([t.ack_to_resp_ms for t in txns]),
        "request_sizes": size_hist([t.req_size for t in txns]),
        "response_sizes": size_hist([t.resp_size for t in txns]),
        "request_funcs": size_hist([t.req_func for t in txns]),
        "response_funcs": size_hist([t.resp_func for t in txns]),
        "retransmissions": sum(t.retransmission for t in txns),
        "duplicate_acks": sum(t.duplicate_ack for t in txns),
        "resets": sum(t.reset for t in txns),
        "out_of_order": sum(t.out_of_order for t in txns),
        "pure_ack_first_count": sum(t.first_rev_is_pure_ack for t in txns),
    }


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------
CSV_COLUMNS = [
    "pcap", "device_label", "outstation_ip", "classification",
    "flow_id", "stream", "master", "outstation",
    "req_frame", "req_size", "req_func",
    "first_rev_frame", "first_rev_is_pure_ack",
    "resp_frame", "resp_size", "resp_func", "resp_flags", "resp_seq", "resp_ack",
    "req_to_ack_ms", "req_to_resp_ms", "ack_to_resp_ms",
    "retransmission", "duplicate_ack", "reset", "out_of_order", "note",
]


def write_csv(path: str, txns: list[Transaction]) -> None:
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for t in txns:
            row = asdict(t)
            for f in ("req_to_ack_ms", "req_to_resp_ms", "ack_to_resp_ms"):
                if row[f] is not None:
                    row[f] = round(row[f], 4)
            w.writerow({k: row.get(k, "") for k in CSV_COLUMNS})


def write_json(path: str, txns: list[Transaction], per_device: dict) -> None:
    payload = {
        "meta": {
            "description": "DNP3-over-TCP ACK/response transaction characterization",
            "dnp3_port": DNP3_PORT,
            "classification_scheme": {
                CLS_COMBINED: "first reverse packet carries both TCP ACK and DNP3 payload",
                CLS_SEPARATE: "pure TCP ACK first, DNP3 response later",
                CLS_OTHER: "unclassifiable (no response / control packet / confused)",
            },
            "total_transactions": len(txns),
        },
        "per_device_summary": per_device,
        "transactions": [asdict(t) for t in txns],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)


def _fmt(v) -> str:
    return "-" if v is None else (f"{v:.2f}" if isinstance(v, float) else str(v))


def write_summary_md(path: str, by_group: dict, device_totals: dict) -> None:
    lines: list[str] = []
    lines.append("# DNP3 ACK / Response Trace Characterization")
    lines.append("")
    lines.append("Per-transaction reconstruction of six real-device DNP3-over-TCP "
                 "captures (port 20000). A transaction is anchored at each "
                 "payload-bearing DNP3 REQUEST (master -> outstation) and matched "
                 "to the first reverse-direction TCP packet and the first "
                 "payload-bearing DNP3 RESPONSE.")
    lines.append("")
    lines.append("Terminology: **pure TCP ACK** = zero-payload TCP acknowledgement; "
                 "**ACK-bearing DNP3 RESPONSE** = a DNP3 response packet that also "
                 "acknowledges (piggyback). The DNP3 response is never called an "
                 "\"application ACK\"; \"DNP3 application CONFIRM\" is reserved for an "
                 "actual DNP3 CONFIRM function code (none observed here).")
    lines.append("")

    # Top-level table (one row per pcap+outstation group)
    lines.append("## Top-level summary (per pcap, per outstation IP)")
    lines.append("")
    hdr = ("| pcap | outstation IP | role | txns | combined% | separate% | other% "
           "| ack->resp med (ms) | ack->resp p95 | ack->resp max | resp sizes |")
    sep = "|---|---|---|---|---|---|---|---|---|---|---|"
    lines.append(hdr)
    lines.append(sep)
    for (pcap, oip), s in by_group.items():
        role = "reference" if oip == REFERENCE_IP else "device"
        a = s["ack_to_resp_ms"]
        rs = ", ".join(f"{k}:{v}" for k, v in s["response_sizes"].items())
        lines.append(
            f"| {pcap} | {oip} | {role} | {s['total_transactions']} "
            f"| {s['combined_pct']} | {s['separate_pct']} | {s['other_pct']} "
            f"| {_fmt(a['median'])} | {_fmt(a['p95'])} | {_fmt(a['max'])} | {rs} |"
        )
    lines.append("")

    # Per-device detail
    lines.append("## Per-device detail")
    lines.append("")
    for (pcap, oip), s in by_group.items():
        role = "reference" if oip == REFERENCE_IP else "device-specific"
        lines.append(f"### {pcap}  |  outstation {oip} ({role})")
        lines.append("")
        lines.append(f"- Transactions: **{s['total_transactions']}**  "
                     f"(combined {s['combined']} / {s['combined_pct']}%, "
                     f"separate {s['separate']} / {s['separate_pct']}%, "
                     f"other {s['other']} / {s['other_pct']}%)")
        lines.append(f"- Pure-TCP-ACK-first count: {s['pure_ack_first_count']}")
        for label, key in (("request->ACK", "req_to_ack_ms"),
                           ("request->response", "req_to_resp_ms"),
                           ("ACK->response gap", "ack_to_resp_ms")):
            d = s[key]
            lines.append(
                f"- {label} (ms): median {_fmt(d['median'])}, "
                f"p95 {_fmt(d['p95'])}, max {_fmt(d['max'])}, "
                f"mean {_fmt(d['mean'])}, n {d['n']}")
        lines.append(f"- Request sizes (bytes): "
                     f"{', '.join(f'{k}:{v}' for k, v in s['request_sizes'].items()) or '-'}")
        lines.append(f"- Response sizes (bytes): "
                     f"{', '.join(f'{k}:{v}' for k, v in s['response_sizes'].items()) or '-'}")
        lines.append(f"- Request DNP3 funcs: "
                     f"{', '.join(f'{k}:{v}' for k, v in s['request_funcs'].items()) or '-'}")
        lines.append(f"- Response DNP3 funcs: "
                     f"{', '.join(f'{k}:{v}' for k, v in s['response_funcs'].items()) or '-'}")
        lines.append(f"- Retransmissions: {s['retransmissions']}, "
                     f"duplicate ACKs: {s['duplicate_acks']}, "
                     f"resets: {s['resets']}, out-of-order: {s['out_of_order']}")
        lines.append("")

    # Expected-pattern validation
    lines.append("## Measured validation of the expected pattern")
    lines.append("")
    lines.append("Expectation under test: *SEL-751 traces should mostly show "
                 "SEPARATE_ACK_RESPONSE; AB1400 and ION7550 mostly "
                 "COMBINED_ACK_RESPONSE.* Measured (device-specific outstation, "
                 "base+L aggregated):")
    lines.append("")
    lines.append("| device | outstation IP | txns | combined% | separate% | other% | verdict |")
    lines.append("|---|---|---|---|---|---|---|")
    for dev, s in device_totals.items():
        oip = DEVICE_OUTSTATION_IP[dev]
        if dev == "SEL751":
            verdict = "mostly SEPARATE" if s["separate_pct"] >= 90 else "NOT separate-dominant"
        else:
            verdict = "mostly COMBINED" if s["combined_pct"] >= 90 else "NOT combined-dominant"
        lines.append(f"| {DEVICE_DISPLAY[dev]} | {oip} | {s['total_transactions']} "
                     f"| {s['combined_pct']} | {s['separate_pct']} | {s['other_pct']} "
                     f"| {verdict} |")
    lines.append("")

    with open(path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def build_profile(device: str, txns: list[Transaction], source_pcaps: list[str]) -> dict:
    oip = DEVICE_OUTSTATION_IP[device]
    dev_txns = [t for t in txns if t.outstation_ip == oip and t.device_label == device]
    ack_mode = "separate" if device == "SEL751" else "combined"
    return {
        "device": DEVICE_DISPLAY[device],
        "device_label": device,
        "outstation_ip": oip,
        "ack_mode": ack_mode,
        "sample_count": len(dev_txns),
        "source_pcaps": sorted(source_pcaps),
        "classification_breakdown": {
            CLS_COMBINED: sum(t.classification == CLS_COMBINED for t in dev_txns),
            CLS_SEPARATE: sum(t.classification == CLS_SEPARATE for t in dev_txns),
            CLS_OTHER: sum(t.classification == CLS_OTHER for t in dev_txns),
        },
        "request_to_ack_ms": dist([t.req_to_ack_ms for t in dev_txns]),
        "request_to_response_ms": dist([t.req_to_resp_ms for t in dev_txns]),
        "ack_to_response_ms": dist([t.ack_to_resp_ms for t in dev_txns]),
        "request_size_bytes": size_hist([t.req_size for t in dev_txns]),
        "response_size_bytes": size_hist([t.resp_size for t in dev_txns]),
        "request_dnp3_funcs": size_hist([t.req_func for t in dev_txns]),
        "response_dnp3_funcs": size_hist([t.resp_func for t in dev_txns]),
    }


# ---------------------------------------------------------------------------
# Ground-truth checks
# ---------------------------------------------------------------------------
def ground_truth_checks(all_txns: list[Transaction], by_group: dict) -> tuple[bool, list[str]]:
    ok = True
    report: list[str] = []

    # SEL-751 base pcap, outstation 10.0.0.1
    key = ("SEL751.pcap", "10.0.0.1")
    s = by_group.get(key)
    if s is None:
        ok = False
        report.append("FAIL: no SEL751.pcap / 10.0.0.1 group found")
    else:
        c_sep = s["separate_pct"] >= 90.0
        c_n = 290 <= s["total_transactions"] <= 305
        med = s["ack_to_resp_ms"]["median"]
        mean = s["ack_to_resp_ms"]["mean"]
        mx = s["ack_to_resp_ms"]["max"]
        c_med = med is not None and 9.0 <= med <= 13.0
        c_mean = mean is not None and 12.0 <= mean <= 18.0
        c_max = mx is not None and 100.0 <= mx <= 220.0
        passed = c_sep and c_n and c_med and c_mean and c_max
        ok = ok and passed
        report.append(
            f"[{'PASS' if passed else 'FAIL'}] SEL751 base 10.0.0.1: "
            f"separate={s['separate_pct']}% (>=90 {c_sep}), "
            f"n={s['total_transactions']} (290-305 {c_n}), "
            f"ack->resp median={med}ms (9-13 {c_med}), "
            f"mean={mean}ms (12-18 {c_mean}), max={mx}ms (100-220 {c_max})")

    # Combined outstations: device-specific + reference should be combined-dominant
    combined_targets = [
        ("AB1400", "10.0.0.12"), ("AB1400", "10.0.0.2"),
        ("ION7550", "10.0.0.11"), ("ION7550", "10.0.0.2"),
        ("SEL751", "10.0.0.2"),
    ]
    for dev, oip in combined_targets:
        # aggregate across base+L pcaps for that device_label+outstation
        grp = [t for t in all_txns if t.device_label == dev and t.outstation_ip == oip]
        if not grp:
            continue
        total = len(grp)
        n_comb = sum(t.classification == CLS_COMBINED for t in grp)
        n_pure = sum(t.first_rev_is_pure_ack for t in grp)
        comb_pct = pct(n_comb, total)
        passed = comb_pct >= 90.0 and pct(n_pure, total) <= 5.0
        ok = ok and passed
        report.append(
            f"[{'PASS' if passed else 'FAIL'}] {DEVICE_DISPLAY[dev]} {oip}: "
            f"combined={comb_pct}% (>=90), pure-ACK-first={n_pure}/{total} "
            f"({pct(n_pure, total)}%, <=5 expected)")

    return ok, report


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def device_from_pcap(pcap_path: str) -> str:
    stem = os.path.basename(pcap_path)[:-len(".pcap")]
    return stem[:-1] if stem.endswith("L") else stem


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--traffic-dir",
                    default="/home/philip/Projects/DNP3/Traffic Trace",
                    help="directory holding the six device PCAPs")
    ap.add_argument("--out-dir",
                    default=os.path.dirname(os.path.abspath(__file__)),
                    help="dnp3_split_harness root (reports/ and profiles/ live here)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    reports_dir = os.path.join(args.out_dir, "reports")
    profiles_dir = os.path.join(args.out_dir, "profiles")
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(profiles_dir, exist_ok=True)

    pcaps = sorted(glob.glob(os.path.join(args.traffic_dir, "*.pcap")))
    if not pcaps:
        logger.error("no PCAPs found under %s", args.traffic_dir)
        return 2
    logger.info("found %d PCAPs: %s", len(pcaps), [os.path.basename(p) for p in pcaps])

    all_txns: list[Transaction] = []
    device_sources: dict[str, set[str]] = {}
    for pcap in pcaps:
        name = os.path.basename(pcap)
        device = device_from_pcap(pcap)
        packets = run_tshark(pcap)
        txns = build_transactions(packets, name, device)
        all_txns += txns
        device_sources.setdefault(device, set()).add(name)
        logger.info("  %s -> %d transactions", name, len(txns))

    # deterministic order
    all_txns.sort(key=lambda t: (t.pcap, t.stream, t.req_frame))

    # per (pcap, outstation_ip) groups, ordered by pcap then device-before-reference
    by_group: dict[tuple[str, str], dict] = {}
    group_keys = sorted(
        {(t.pcap, t.outstation_ip) for t in all_txns},
        key=lambda k: (k[0], k[1] == REFERENCE_IP, k[1]),
    )
    for pcap, oip in group_keys:
        grp = [t for t in all_txns if t.pcap == pcap and t.outstation_ip == oip]
        by_group[(pcap, oip)] = group_summary(grp)

    # per-device totals (device-specific outstation, base+L aggregated)
    device_totals: dict[str, dict] = {}
    for dev in ("SEL751", "AB1400", "ION7550"):
        oip = DEVICE_OUTSTATION_IP[dev]
        grp = [t for t in all_txns if t.device_label == dev and t.outstation_ip == oip]
        device_totals[dev] = group_summary(grp)

    # JSON-friendly per-device summary block (string keys)
    per_device_json = {
        f"{pcap}|{oip}": summ for (pcap, oip), summ in by_group.items()
    }

    # --- write outputs ---------------------------------------------------------
    csv_path = os.path.join(reports_dir, "ack_trace_characterization.csv")
    json_path = os.path.join(reports_dir, "ack_trace_characterization.json")
    md_path = os.path.join(reports_dir, "ack_trace_summary.md")
    write_csv(csv_path, all_txns)
    write_json(json_path, all_txns, per_device_json)
    write_summary_md(md_path, by_group, device_totals)

    profile_paths = {}
    for dev, fname in (("SEL751", "sel751_separate_ack.json"),
                       ("AB1400", "ab1400_combined_ack.json"),
                       ("ION7550", "ion7550_combined_ack.json")):
        prof = build_profile(dev, all_txns, list(device_sources.get(dev, [])))
        p = os.path.join(profiles_dir, fname)
        with open(p, "w") as fh:
            json.dump(prof, fh, indent=2)
        profile_paths[dev] = p

    # --- ground-truth checks ---------------------------------------------------
    ok, gt_report = ground_truth_checks(all_txns, by_group)

    # --- completion summary ----------------------------------------------------
    print("\n" + "=" * 72)
    print("DNP3 ACK/RESPONSE CHARACTERIZATION - COMPLETE")
    print("=" * 72)
    print(f"Total transactions: {len(all_txns)}  across {len(pcaps)} pcaps")
    print("\nFiles written:")
    for p in (csv_path, json_path, md_path, *profile_paths.values()):
        print(f"  {p}")
    print("\nPer device-specific outstation (base+L aggregated):")
    print(f"  {'device':10} {'oip':11} {'txns':>5} {'comb%':>7} {'sep%':>7} "
          f"{'oth%':>6} {'ackResp_med':>11} {'ackResp_p95':>11} {'ackResp_max':>11}")
    for dev, s in device_totals.items():
        a = s["ack_to_resp_ms"]
        print(f"  {DEVICE_DISPLAY[dev]:10} {DEVICE_OUTSTATION_IP[dev]:11} "
              f"{s['total_transactions']:>5} {s['combined_pct']:>7} "
              f"{s['separate_pct']:>7} {s['other_pct']:>6} "
              f"{_fmt(a['median']):>11} {_fmt(a['p95']):>11} {_fmt(a['max']):>11}")
    print("\nGround-truth checks:")
    for line in gt_report:
        print(f"  {line}")
    n_other = sum(t.classification == CLS_OTHER for t in all_txns)
    print(f"\nOTHER_OR_AMBIGUOUS transactions: {n_other}")
    print("=" * 72)
    print("GROUND TRUTH: " + ("ALL PASS" if ok else "FAILURES PRESENT"))
    print("=" * 72)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
