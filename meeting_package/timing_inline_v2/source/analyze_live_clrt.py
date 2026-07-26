#!/usr/bin/env python3
"""Pipeline (a): exact DNP3 CLRT transaction extraction from a master-side pcap.

CLRT (Cross-Layer Response Time) is defined here, following Formby et al. (NDSS 2016), as

    CLRT = t(DNP3 RESPONSE, function 129) - t(the qualifying pure TCP ACK)

measured at the master-side capture point.

Independence note
-----------------
This pipeline deliberately does NOT use Wireshark's DNP3 dissector. It reads only
TCP/IP fields from tshark and decodes the DNP3 link/transport/application headers
itself from `tcp.payload`, including a CRC-16/DNP check on the link header. The
companion pipeline (b) (`pipeline_b_tshark.sh`) does the opposite: it trusts the
dissector fields and pairs on the DNP3 application sequence number. The two are
cross-checked against each other; any disagreement is reported, never silently
resolved.

Pairing is EXACT, never by timing proximity:
  * the READ is a master->outstation segment whose decoded DNP3 application
    function code is 1 (READ);
  * expected_ack = READ.tcp.seq_raw + READ.tcp.len;
  * a qualifying ACK is the FIRST outstation->master segment after the READ with
    tcp.len == 0, no SYN/FIN/RST, and tcp.ack_raw == expected_ack;
  * the RESPONSE is the FIRST outstation->master segment after that ACK with
    tcp.len > 0 whose decoded DNP3 application function code is 129.
Anything that fails a check is recorded with an explicit validation failure
rather than guessed.

Timestamps are handled as integer nanoseconds throughout (parsed from the
"seconds.nanoseconds" text form) so no floating-point error is introduced before
the final subtraction.

Usage:
    analyze_live_clrt.py --pcap FILE --label native --outdir DIR [--master IP] [--outstation IP]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants of the analysis. Everything that could be a silent convention is
# named here and echoed into the summary JSON.
# ---------------------------------------------------------------------------

MASTER_IP_DEFAULT = "192.168.10.1"
OUTSTATION_IP_DEFAULT = "192.168.10.7"
DNP3_TCP_PORT = 20000

DNP3_FUNC_READ = 1
DNP3_FUNC_RESPONSE = 129

BOOTSTRAP_ITERATIONS = 20000
BOOTSTRAP_SEED = 20260725
BOOTSTRAP_CI = 0.95

# Observer histogram resolutions, in milliseconds.
ENTROPY_RESOLUTIONS_MS = [0.010, 0.050, 0.100, 0.500, 1.000]
# Bin origin is 0.0 ms; bin k covers the half-open interval [k*w, (k+1)*w).
BIN_ORIGIN_MS = 0.0
BIN_INTERVAL_CONVENTION = "half-open [k*w, (k+1)*w), k = floor((v - origin) / w)"

# G, the normalization target used in the protected runs (ms). Native samples
# above this are protection-miss candidates: a hold-to-deadline scheme cannot
# delay a response that already arrived after the deadline.
G_MS = 25.0

TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.len",
    "tcp.hdr_len",
    "ip.len",
    "frame.len",
    "tcp.flags",
    "tcp.analysis.flags",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.out_of_order",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.lost_segment",
    "_ws.malformed",
    "tcp.payload",
]

# TCP flag bits
FLAG_FIN = 0x001
FLAG_SYN = 0x002
FLAG_RST = 0x004
FLAG_PSH = 0x008
FLAG_ACK = 0x010


# ---------------------------------------------------------------------------
# DNP3 decoding (independent of the Wireshark dissector)
# ---------------------------------------------------------------------------

def dnp3_crc(data: bytes) -> int:
    """CRC-16/DNP as used by the DNP3 data link layer (reflected 0xA6BC, final XOR)."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def decode_dnp3(payload: bytes) -> Dict[str, object]:
    """Decode the first DNP3 link frame in a TCP payload from raw bytes.

    Returns a dict with the decoded fields plus 'decode_ok' and 'decode_note'.
    """
    out: Dict[str, object] = {
        "decode_ok": False,
        "decode_note": "",
        "dnp3_start": "",
        "dnp3_len": "",
        "dnp3_ctrl": "",
        "dnp3_src": "",
        "dnp3_dst": "",
        "dnp3_hdr_crc_ok": "",
        "dnp3_tr_ctl": "",
        "dnp3_tr_seq": "",
        "dnp3_al_ctl": "",
        "dnp3_al_seq": "",
        "dnp3_al_func": "",
        "dnp3_frame_total_len": "",
    }
    if len(payload) < 13:
        out["decode_note"] = "payload shorter than a minimal DNP3 frame with an app func"
        return out
    if payload[0] != 0x05 or payload[1] != 0x64:
        out["decode_note"] = "no 0x0564 start octets at payload offset 0"
        return out

    link_len = payload[2]
    ctrl = payload[3]
    dst = payload[4] | (payload[5] << 8)
    src = payload[6] | (payload[7] << 8)
    hdr_crc_wire = payload[8] | (payload[9] << 8)  # transmitted low octet first
    hdr_crc_calc = dnp3_crc(payload[0:8])

    tr_ctl = payload[10]
    al_ctl = payload[11]
    al_func = payload[12]

    # Total wire length of the link frame: 10-byte header + user data + a 2-byte
    # CRC after every (up to) 16 user-data octets.
    user_bytes = max(link_len - 5, 0)
    n_blocks = (user_bytes + 15) // 16
    total = 10 + user_bytes + 2 * n_blocks

    out.update(
        {
            "decode_ok": True,
            "dnp3_start": "0x0564",
            "dnp3_len": link_len,
            "dnp3_ctrl": "0x%02x" % ctrl,
            "dnp3_src": src,
            "dnp3_dst": dst,
            "dnp3_hdr_crc_ok": bool(hdr_crc_wire == hdr_crc_calc),
            "dnp3_tr_ctl": "0x%02x" % tr_ctl,
            "dnp3_tr_seq": tr_ctl & 0x3F,
            "dnp3_al_ctl": "0x%02x" % al_ctl,
            "dnp3_al_seq": al_ctl & 0x0F,
            "dnp3_al_func": al_func,
            "dnp3_frame_total_len": total,
        }
    )
    if hdr_crc_wire != hdr_crc_calc:
        out["decode_note"] = "link header CRC mismatch wire=0x%04x calc=0x%04x" % (
            hdr_crc_wire,
            hdr_crc_calc,
        )
    return out


# ---------------------------------------------------------------------------
# pcap ingestion
# ---------------------------------------------------------------------------

def parse_epoch_ns(text: str) -> int:
    """Parse 'seconds.nanoseconds' into an exact integer nanosecond count."""
    if "." in text:
        sec, frac = text.split(".", 1)
    else:
        sec, frac = text, ""
    frac = (frac + "000000000")[:9]
    return int(sec) * 1_000_000_000 + int(frac)


def read_packets(pcap: str) -> List[Dict[str, object]]:
    cmd = [
        "tshark",
        "-r",
        pcap,
        "-o",
        "tcp.relative_sequence_numbers:FALSE",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError("tshark failed on %s: %s" % (pcap, res.stderr.strip()))

    packets: List[Dict[str, object]] = []
    for line in res.stdout.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        cols += [""] * (len(TSHARK_FIELDS) - len(cols))
        rec = dict(zip(TSHARK_FIELDS, cols))
        pkt: Dict[str, object] = {
            "frame": int(rec["frame.number"]),
            "ts_ns": parse_epoch_ns(rec["frame.time_epoch"]),
            "ip_src": rec["ip.src"],
            "ip_dst": rec["ip.dst"],
            "stream": int(rec["tcp.stream"]) if rec["tcp.stream"] else -1,
            "sport": int(rec["tcp.srcport"]) if rec["tcp.srcport"] else -1,
            "dport": int(rec["tcp.dstport"]) if rec["tcp.dstport"] else -1,
            "seq_raw": int(rec["tcp.seq_raw"]) if rec["tcp.seq_raw"] else -1,
            "ack_raw": int(rec["tcp.ack_raw"]) if rec["tcp.ack_raw"] else -1,
            "tcp_len": int(rec["tcp.len"]) if rec["tcp.len"] else 0,
            "tcp_hdr_len": int(rec["tcp.hdr_len"]) if rec["tcp.hdr_len"] else -1,
            "ip_len": int(rec["ip.len"]) if rec["ip.len"] else -1,
            "frame_len": int(rec["frame.len"]) if rec["frame.len"] else -1,
            "flags": int(rec["tcp.flags"], 16) if rec["tcp.flags"] else 0,
            "an_flags": rec["tcp.analysis.flags"],
            "retrans": bool(rec["tcp.analysis.retransmission"]),
            "fast_retrans": bool(rec["tcp.analysis.fast_retransmission"]),
            "ooo": bool(rec["tcp.analysis.out_of_order"]),
            "dupack": bool(rec["tcp.analysis.duplicate_ack"]),
            "lost_seg": bool(rec["tcp.analysis.lost_segment"]),
            "malformed": bool(rec["_ws.malformed"]),
            "payload_hex": rec["tcp.payload"].replace(":", ""),
        }
        if pkt["payload_hex"]:
            try:
                pkt["payload"] = bytes.fromhex(pkt["payload_hex"])
            except ValueError:
                pkt["payload"] = b""
        else:
            pkt["payload"] = b""
        pkt["dnp3"] = decode_dnp3(pkt["payload"]) if pkt["payload"] else None
        packets.append(pkt)
    return packets


# ---------------------------------------------------------------------------
# Exact transaction pairing
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "txn_index",
    "tcp_stream",
    "read_frame",
    "read_ts_epoch",
    "read_tcp_seq",
    "read_tcp_len",
    "read_tcp_hdr_len",
    "read_ip_len",
    "read_frame_len",
    "read_dnp3_func",
    "read_dnp3_al_seq",
    "read_dnp3_tr_seq",
    "read_dnp3_src",
    "read_dnp3_dst",
    "read_dnp3_hdr_crc_ok",
    "expected_ack",
    "ack_frame",
    "ack_ts_epoch",
    "ack_tcp_seq",
    "ack_tcp_ack",
    "ack_tcp_len",
    "ack_tcp_hdr_len",
    "ack_ip_len",
    "ack_frame_len",
    "resp_frame",
    "resp_ts_epoch",
    "resp_tcp_seq",
    "resp_tcp_ack",
    "resp_tcp_len",
    "resp_tcp_hdr_len",
    "resp_ip_len",
    "resp_frame_len",
    "resp_dnp3_func",
    "resp_dnp3_al_seq",
    "resp_dnp3_tr_seq",
    "resp_dnp3_src",
    "resp_dnp3_dst",
    "resp_dnp3_hdr_crc_ok",
    "resp_dnp3_frame_total_len",
    "clrt_ms",
    "clrt_ns",
    "read_to_ack_ms",
    "read_to_read_ms",
    "prev_resp_to_read_ms",
    "retransmission_flags",
    "tcp_analysis_flags",
    "ws_malformed",
    "protection_miss_candidate",
    "ambiguity",
    "validation_failure",
]


def fmt_ts(ns: Optional[int]) -> str:
    if ns is None:
        return ""
    return "%d.%09d" % (ns // 1_000_000_000, ns % 1_000_000_000)


def extract_transactions(
    packets: List[Dict[str, object]], master: str, outstation: str, is_native: bool
) -> Tuple[List[Dict[str, object]], List[str]]:
    """Exact READ -> qualifying pure ACK -> RESPONSE pairing."""
    notes: List[str] = []
    rows: List[Dict[str, object]] = []

    reads = [
        p
        for p in packets
        if p["ip_src"] == master
        and p["ip_dst"] == outstation
        and p["tcp_len"] > 0
        and p["dnp3"]
        and p["dnp3"]["decode_ok"]
        and p["dnp3"]["dnp3_al_func"] == DNP3_FUNC_READ
    ]

    for idx, rd in enumerate(reads):
        amb: List[str] = []
        fail: List[str] = []

        expected_ack = (rd["seq_raw"] + rd["tcp_len"]) % (1 << 32)

        later = [
            p
            for p in packets
            if p["stream"] == rd["stream"]
            and p["frame"] > rd["frame"]
            and p["ip_src"] == outstation
        ]

        # --- qualifying pure ACK -------------------------------------------
        ack_candidates = [
            p
            for p in later
            if p["tcp_len"] == 0
            and not (p["flags"] & (FLAG_SYN | FLAG_FIN | FLAG_RST))
            and (p["flags"] & FLAG_ACK)
            and p["ack_raw"] == expected_ack
        ]
        # Stop scanning at the next READ so an ACK belonging to a later
        # transaction can never be borrowed by this one.
        next_read_frame = reads[idx + 1]["frame"] if idx + 1 < len(reads) else None
        if next_read_frame is not None:
            ack_candidates = [p for p in ack_candidates if p["frame"] < next_read_frame]

        ack = ack_candidates[0] if ack_candidates else None
        if ack is None:
            fail.append("no qualifying pure ACK (tcp.len==0, no SYN/FIN/RST, tcp.ack==%d)" % expected_ack)
        elif len(ack_candidates) > 1:
            amb.append(
                "multiple qualifying pure ACKs before the next READ: frames %s"
                % ",".join(str(p["frame"]) for p in ack_candidates)
            )

        # --- DNP3 RESPONSE --------------------------------------------------
        resp = None
        if ack is not None:
            resp_candidates = [
                p
                for p in later
                if p["frame"] > ack["frame"]
                and p["tcp_len"] > 0
                and p["dnp3"]
                and p["dnp3"]["decode_ok"]
                and p["dnp3"]["dnp3_al_func"] == DNP3_FUNC_RESPONSE
            ]
            if next_read_frame is not None:
                resp_candidates = [p for p in resp_candidates if p["frame"] < next_read_frame]
            if not resp_candidates:
                fail.append("no DNP3 RESPONSE (func 129) after the qualifying ACK")
            else:
                resp = resp_candidates[0]
                if len(resp_candidates) > 1:
                    amb.append(
                        "multiple DNP3 RESPONSEs before the next READ: frames %s"
                        % ",".join(str(p["frame"]) for p in resp_candidates)
                    )

        # --- cross checks ---------------------------------------------------
        clrt_ns: Optional[int] = None
        if ack is not None and resp is not None:
            clrt_ns = resp["ts_ns"] - ack["ts_ns"]
            if clrt_ns <= 0:
                fail.append("RESPONSE timestamp is not after the ACK timestamp")
            if resp["seq_raw"] != ack["seq_raw"]:
                amb.append(
                    "RESPONSE tcp.seq %d != ACK tcp.seq %d (outstation byte stream discontinuity)"
                    % (resp["seq_raw"], ack["seq_raw"])
                )
            if resp["ack_raw"] != expected_ack:
                amb.append(
                    "RESPONSE tcp.ack %d != expected %d" % (resp["ack_raw"], expected_ack)
                )
            if resp["dnp3"]["dnp3_al_seq"] != rd["dnp3"]["dnp3_al_seq"]:
                fail.append(
                    "DNP3 application sequence mismatch: READ %s vs RESPONSE %s"
                    % (rd["dnp3"]["dnp3_al_seq"], resp["dnp3"]["dnp3_al_seq"])
                )
            if resp["dnp3"]["dnp3_src"] != rd["dnp3"]["dnp3_dst"] or (
                resp["dnp3"]["dnp3_dst"] != rd["dnp3"]["dnp3_src"]
            ):
                amb.append("DNP3 link addresses are not mirrored between READ and RESPONSE")
            if not resp["dnp3"]["dnp3_hdr_crc_ok"]:
                fail.append("RESPONSE DNP3 link header CRC failed")
            if not rd["dnp3"]["dnp3_hdr_crc_ok"]:
                fail.append("READ DNP3 link header CRC failed")

        retrans_bits = []
        for p, tag in ((rd, "read"), (ack, "ack"), (resp, "resp")):
            if p is None:
                continue
            if p["retrans"]:
                retrans_bits.append(tag + ":retransmission")
            if p["fast_retrans"]:
                retrans_bits.append(tag + ":fast_retransmission")
            if p["ooo"]:
                retrans_bits.append(tag + ":out_of_order")
            if p["dupack"]:
                retrans_bits.append(tag + ":duplicate_ack")
            if p["lost_seg"]:
                retrans_bits.append(tag + ":lost_segment")

        an_flags = ";".join(
            v for v in ((rd["an_flags"]), (ack["an_flags"] if ack else ""), (resp["an_flags"] if resp else "")) if v
        )
        malformed = any(p["malformed"] for p in (rd, ack, resp) if p is not None)

        clrt_ms = (clrt_ns / 1e6) if clrt_ns is not None else None
        # A "protection miss candidate" is only meaningful for a NATIVE series:
        # it marks a transaction whose undefended CLRT already exceeded G, so a
        # hold-to-deadline scheme could not have delayed it to G. In a PROTECTED
        # series a CLRT slightly above G is the intended outcome (G plus the
        # release tail), not a miss, so the flag is not applicable there.
        if is_native:
            miss = bool(clrt_ms is not None and clrt_ms > G_MS)
        else:
            miss = "n/a"

        row = {
            "txn_index": idx,
            "tcp_stream": rd["stream"],
            "read_frame": rd["frame"],
            "read_ts_epoch": fmt_ts(rd["ts_ns"]),
            "read_tcp_seq": rd["seq_raw"],
            "read_tcp_len": rd["tcp_len"],
            "read_tcp_hdr_len": rd["tcp_hdr_len"],
            "read_ip_len": rd["ip_len"],
            "read_frame_len": rd["frame_len"],
            "read_dnp3_func": rd["dnp3"]["dnp3_al_func"],
            "read_dnp3_al_seq": rd["dnp3"]["dnp3_al_seq"],
            "read_dnp3_tr_seq": rd["dnp3"]["dnp3_tr_seq"],
            "read_dnp3_src": rd["dnp3"]["dnp3_src"],
            "read_dnp3_dst": rd["dnp3"]["dnp3_dst"],
            "read_dnp3_hdr_crc_ok": rd["dnp3"]["dnp3_hdr_crc_ok"],
            "expected_ack": expected_ack,
            "ack_frame": ack["frame"] if ack else "",
            "ack_ts_epoch": fmt_ts(ack["ts_ns"]) if ack else "",
            "ack_tcp_seq": ack["seq_raw"] if ack else "",
            "ack_tcp_ack": ack["ack_raw"] if ack else "",
            "ack_tcp_len": ack["tcp_len"] if ack else "",
            "ack_tcp_hdr_len": ack["tcp_hdr_len"] if ack else "",
            "ack_ip_len": ack["ip_len"] if ack else "",
            "ack_frame_len": ack["frame_len"] if ack else "",
            "resp_frame": resp["frame"] if resp else "",
            "resp_ts_epoch": fmt_ts(resp["ts_ns"]) if resp else "",
            "resp_tcp_seq": resp["seq_raw"] if resp else "",
            "resp_tcp_ack": resp["ack_raw"] if resp else "",
            "resp_tcp_len": resp["tcp_len"] if resp else "",
            "resp_tcp_hdr_len": resp["tcp_hdr_len"] if resp else "",
            "resp_ip_len": resp["ip_len"] if resp else "",
            "resp_frame_len": resp["frame_len"] if resp else "",
            "resp_dnp3_func": resp["dnp3"]["dnp3_al_func"] if resp else "",
            "resp_dnp3_al_seq": resp["dnp3"]["dnp3_al_seq"] if resp else "",
            "resp_dnp3_tr_seq": resp["dnp3"]["dnp3_tr_seq"] if resp else "",
            "resp_dnp3_src": resp["dnp3"]["dnp3_src"] if resp else "",
            "resp_dnp3_dst": resp["dnp3"]["dnp3_dst"] if resp else "",
            "resp_dnp3_hdr_crc_ok": resp["dnp3"]["dnp3_hdr_crc_ok"] if resp else "",
            "resp_dnp3_frame_total_len": resp["dnp3"]["dnp3_frame_total_len"] if resp else "",
            "clrt_ms": ("%.6f" % clrt_ms) if clrt_ms is not None else "",
            "clrt_ns": clrt_ns if clrt_ns is not None else "",
            "read_to_ack_ms": ("%.6f" % ((ack["ts_ns"] - rd["ts_ns"]) / 1e6)) if ack else "",
            "read_to_read_ms": (
                "%.6f" % ((reads[idx + 1]["ts_ns"] - rd["ts_ns"]) / 1e6)
            ) if idx + 1 < len(reads) else "",
            "prev_resp_to_read_ms": "",  # filled in after all rows exist
            "retransmission_flags": ";".join(retrans_bits),
            "tcp_analysis_flags": an_flags,
            "ws_malformed": malformed,
            "protection_miss_candidate": miss,
            "ambiguity": " | ".join(amb),
            "validation_failure": " | ".join(fail),
        }
        rows.append(row)

    # Master cadence: idle gap between one RESPONSE and the master's next READ.
    # This is the master's configured inter-poll sleep and must match between
    # the native and protected arms for the comparison to be like-for-like.
    frame_ts = {p["frame"]: p["ts_ns"] for p in packets}
    for i in range(1, len(rows)):
        prev_resp = rows[i - 1]["resp_frame"]
        this_read = rows[i]["read_frame"]
        if prev_resp != "":
            rows[i]["prev_resp_to_read_ms"] = "%.6f" % (
                (frame_ts[this_read] - frame_ts[prev_resp]) / 1e6
            )

    # Whole-capture sanity notes
    streams = sorted({p["stream"] for p in packets if p["stream"] >= 0})
    if len(streams) != 1:
        notes.append("capture contains %d TCP streams: %s" % (len(streams), streams))
    resets = [p["frame"] for p in packets if p["flags"] & FLAG_RST]
    if resets:
        notes.append("TCP RST present in frames %s" % resets)
    return rows, notes


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def percentile(sorted_vals: List[float], q: float) -> float:
    """Linear interpolation between order statistics (numpy 'linear' default)."""
    if not sorted_vals:
        return float("nan")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = (len(sorted_vals) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_vals[int(pos)]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def median_of(vals: List[float]) -> float:
    s = sorted(vals)
    n = len(s)
    if n == 0:
        return float("nan")
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def pstdev(vals: List[float]) -> float:
    n = len(vals)
    if n == 0:
        return float("nan")
    m = sum(vals) / n
    return math.sqrt(sum((v - m) ** 2 for v in vals) / n)


def sstdev(vals: List[float]) -> float:
    n = len(vals)
    if n < 2:
        return float("nan")
    m = sum(vals) / n
    return math.sqrt(sum((v - m) ** 2 for v in vals) / (n - 1))


def mad(vals: List[float]) -> float:
    """Median absolute deviation from the median (no consistency scaling)."""
    med = median_of(vals)
    return median_of([abs(v - med) for v in vals])


def bootstrap_ci(vals: List[float], stat_fn, iterations: int, seed: int, ci: float):
    if len(vals) < 2:
        return {"lo": None, "hi": None, "note": "n < 2, bootstrap not computed"}
    rng = random.Random(seed)
    n = len(vals)
    reps = []
    for _ in range(iterations):
        sample = [vals[rng.randrange(n)] for _ in range(n)]
        reps.append(stat_fn(sample))
    reps.sort()
    alpha = (1.0 - ci) / 2.0
    return {
        "lo": percentile(reps, alpha),
        "hi": percentile(reps, 1.0 - alpha),
        "note": "",
    }


def describe(vals: List[float]) -> Dict[str, object]:
    if not vals:
        return {"n": 0}
    s = sorted(vals)
    n = len(s)
    out = {
        "n": n,
        "min": s[0],
        "max": s[-1],
        "mean": sum(s) / n,
        "median": median_of(s),
        "sd_population_ddof0": pstdev(s),
        "sd_sample_ddof1": sstdev(s),
        "p5": percentile(s, 0.05),
        "p25": percentile(s, 0.25),
        "p75": percentile(s, 0.75),
        "p95": percentile(s, 0.95),
        "p99": percentile(s, 0.99),
        "range": s[-1] - s[0],
        "mad": mad(s),
        "values_sorted": s,
    }
    out["bootstrap"] = {
        "iterations": BOOTSTRAP_ITERATIONS,
        "seed": BOOTSTRAP_SEED,
        "confidence": BOOTSTRAP_CI,
        "method": "nonparametric percentile bootstrap, resampling with replacement",
        "rng": "python random.Random(seed).randrange(n)",
        "median_ci": bootstrap_ci(s, median_of, BOOTSTRAP_ITERATIONS, BOOTSTRAP_SEED, BOOTSTRAP_CI),
        "sd_population_ci": bootstrap_ci(
            s, pstdev, BOOTSTRAP_ITERATIONS, BOOTSTRAP_SEED + 1, BOOTSTRAP_CI
        ),
        "sd_sample_ci": bootstrap_ci(
            s, sstdev, BOOTSTRAP_ITERATIONS, BOOTSTRAP_SEED + 2, BOOTSTRAP_CI
        ),
    }
    return out


def histogram_entropy(vals: List[float], width_ms: float) -> Dict[str, object]:
    """Occupied-bin count and Shannon entropy of the observer's histogram."""
    counts: Dict[int, int] = {}
    for v in vals:
        k = math.floor((v - BIN_ORIGIN_MS) / width_ms)
        counts[k] = counts.get(k, 0) + 1
    n = len(vals)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return {
        "bin_width_ms": width_ms,
        "bin_origin_ms": BIN_ORIGIN_MS,
        "interval_convention": BIN_INTERVAL_CONVENTION,
        "occupied_bins": len(counts),
        "shannon_entropy_bits": ent,
        "max_possible_entropy_bits": math.log2(n) if n else 0.0,
        "bin_counts": {str(k): c for k, c in sorted(counts.items())},
    }


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--label", required=True, help="native | protected")
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--master", default=MASTER_IP_DEFAULT)
    ap.add_argument("--outstation", default=OUTSTATION_IP_DEFAULT)
    args = ap.parse_args()

    is_native = args.label.lower().startswith("native")
    packets = read_packets(args.pcap)
    rows, notes = extract_transactions(packets, args.master, args.outstation, is_native)

    os.makedirs(args.outdir, exist_ok=True)
    csv_path = os.path.join(args.outdir, "%s_transactions.csv" % args.label)
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    good = [r for r in rows if not r["validation_failure"] and r["clrt_ms"] != ""]
    vals = [float(r["clrt_ms"]) for r in good]

    stats = describe(vals)
    entropies = {}
    for w_ms in ENTROPY_RESOLUTIONS_MS:
        key = ("%gus" % (w_ms * 1000)) if w_ms < 1 else ("%gms" % w_ms)
        entropies[key] = histogram_entropy(vals, w_ms)

    if is_native:
        misses = [
            {
                "txn_index": r["txn_index"],
                "dnp3_al_seq": r["read_dnp3_al_seq"],
                "clrt_ms": float(r["clrt_ms"]),
                "ack_frame": r["ack_frame"],
                "resp_frame": r["resp_frame"],
                "excess_over_G_ms": float(r["clrt_ms"]) - G_MS,
            }
            for r in good
            if float(r["clrt_ms"]) > G_MS
        ]
    else:
        misses = "n/a - protection-miss is defined only on a native series"

    cadence = {
        "note": "prev_resp_to_read is the master's idle gap between one DNP3 "
                "RESPONSE and its next READ, i.e. the configured inter-poll sleep",
        "prev_resp_to_read_ms": describe(
            [float(r["prev_resp_to_read_ms"]) for r in rows if r["prev_resp_to_read_ms"]]
        ),
        "read_to_read_ms": describe(
            [float(r["read_to_read_ms"]) for r in rows if r["read_to_read_ms"]]
        ),
        "read_to_ack_ms": describe(
            [float(r["read_to_ack_ms"]) for r in rows if r["read_to_ack_ms"]]
        ),
    }

    # first-transaction sensitivity: the cold poll dominates the native spread
    excl_first = vals[1:] if len(vals) > 1 else []

    sha = subprocess.run(["sha256sum", args.pcap], capture_output=True, text=True).stdout.split()[0]

    summary = {
        "pcap": os.path.basename(args.pcap),
        "pcap_sha256": sha,
        "label": args.label,
        "pipeline": "a (own DNP3 byte decoder + exact TCP seq/ack pairing)",
        "tshark_version": subprocess.run(["tshark", "-v"], capture_output=True, text=True).stdout.splitlines()[0],
        "clrt_definition": "t(DNP3 RESPONSE func 129) - t(qualifying pure TCP ACK), master-side capture",
        "master_ip": args.master,
        "outstation_ip": args.outstation,
        "tcp_port": DNP3_TCP_PORT,
        "packets_in_capture": len(packets),
        "transactions_found": len(rows),
        "transactions_valid": len(good),
        "transactions_with_ambiguity": sum(1 for r in rows if r["ambiguity"]),
        "transactions_with_validation_failure": sum(1 for r in rows if r["validation_failure"]),
        "capture_notes": notes,
        "statistics_ms": stats,
        "entropy": entropies,
        "G_ms": G_MS,
        "protection_miss_candidates": misses,
        "master_cadence": cadence,
        "sensitivity_excluding_first_transaction": describe(excl_first) if excl_first else {},
        "response_sizes": {
            "tcp_len_set": sorted({r["resp_tcp_len"] for r in good}),
            "ip_len_set": sorted({r["resp_ip_len"] for r in good}),
            "frame_len_set": sorted({r["resp_frame_len"] for r in good}),
            "tcp_hdr_len_set": sorted({r["resp_tcp_hdr_len"] for r in good}),
        },
        "integrity": {
            "any_retransmission_flags": any(r["retransmission_flags"] for r in rows),
            "any_tcp_analysis_flags": any(r["tcp_analysis_flags"] for r in rows),
            "any_ws_malformed": any(r["ws_malformed"] for r in rows),
            "all_dnp3_hdr_crc_ok": all(
                r["read_dnp3_hdr_crc_ok"] is True and r["resp_dnp3_hdr_crc_ok"] is True for r in good
            ),
        },
    }

    json_path = os.path.join(args.outdir, "%s_summary.json" % args.label)
    with open(json_path, "w") as fh:
        json.dump(summary, fh, indent=2, default=str)

    print("%-32s n=%d valid=%d amb=%d fail=%d  median=%.6f  sd_pop=%.6f  sd_samp=%.6f  max=%.6f" % (
        os.path.basename(args.pcap),
        len(rows),
        len(good),
        summary["transactions_with_ambiguity"],
        summary["transactions_with_validation_failure"],
        stats.get("median", float("nan")),
        stats.get("sd_population_ddof0", float("nan")),
        stats.get("sd_sample_ddof1", float("nan")),
        stats.get("max", float("nan")),
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
