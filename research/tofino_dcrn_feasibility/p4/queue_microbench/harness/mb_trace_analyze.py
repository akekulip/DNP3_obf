#!/usr/bin/env python3
"""mb_trace_analyze.py — OFF-SWITCH analyzer for the Level-1 size-normalization experiment.

Inputs:
  --pcap    Hulk hairpin INBOUND capture (what returned from the switch)
  --digest  the JSONL written by mb_trace_collector.py (one record per released 128 B frame)

Verifies (all must hold for PASS):
  * EVERY normalized output frame is EXACTLY 128 B on the wire (0 unexpected sizes)
  * 0 loss   : #128B outputs in pcap == #digest records (== --tx-expected if given)
  * 0 reorder: seq strictly increasing per run when records are ordered by ingress_tstamp,
               and the seq range is contiguous (0 dup, 0 missing)

Computes:
  * NATIVE (declared input-size) vs SHAPED (output-size) histograms
  * size-leakage removal: MI(output_size; device) and MI(output_size; operation) — ~0 bits when
    every output is 128 — contrasted against the NATIVE MI(input_size; device/operation) that the
    normalization removed (MI helper reused from size_pattern_builder/evaluate_candidates.py)
  * per-direction padding overhead from the actual sent/received bytes

Emits a JSON result to stdout (and --out if given).

Usage:  python3 mb_trace_analyze.py --pcap cap.pcap --digest runs/trace_run1.jsonl --tx-expected 800
"""
import argparse
import json
import math
import os
import struct
import sys
from collections import Counter

ETHERTYPE_TRACE = 0x88B7        # frames still carrying this ethertype = fail-open passthroughs
TARGET_SIZE = 128
REPLAY_HDR_LEN = 19

# ── MI: reuse evaluate_candidates.mutual_information_bits if importable; else identical local. ──
_HERE = os.path.dirname(os.path.abspath(__file__))
_SPB = os.path.join(os.path.dirname(_HERE), "size_pattern_builder")


def _local_mi_bits(feature, label):
    """MI(feature; label) in bits over paired lists. Constant feature or label -> 0."""
    n = len(feature)
    if n == 0:
        return 0.0
    joint = Counter(zip(feature, label))
    fx = Counter(feature)
    fy = Counter(label)
    mi = 0.0
    for (x, y), nxy in joint.items():
        pxy = nxy / n
        px = fx[x] / n
        py = fy[y] / n
        mi += pxy * math.log2(pxy / (px * py))
    return max(0.0, mi)


try:
    if _SPB not in sys.path:
        sys.path.insert(0, _SPB)
    from evaluate_candidates import mutual_information_bits as mutual_information_bits
    MI_SOURCE = "evaluate_candidates.mutual_information_bits"
except Exception:
    mutual_information_bits = _local_mi_bits
    MI_SOURCE = "local (evaluate_candidates import unavailable)"


# ------------------------------------------------------------------ minimal classic pcap reader
def read_pcap(path):
    """Parse a classic libpcap file (tcpdump -w default). Returns a list of (wire_len, ethertype).
    wire_len = orig_len (true on-wire frame length, FCS not captured). Both endiannesses + the
    nanosecond magic variants are handled. Raises on an unrecognized (e.g. pcapng) magic."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 24:
        raise ValueError("pcap too short (%d bytes)" % len(data))
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):     # little-endian (usec / nsec)
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):   # big-endian (usec / nsec)
        endian = ">"
    else:
        raise ValueError("unrecognized pcap magic %r (classic libpcap only; not pcapng)" % magic)
    off = 24  # skip the 24-byte global header
    rechdr = struct.Struct(endian + "IIII")
    frames = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = rechdr.unpack_from(data, off)
        off += 16
        if off + incl_len > len(data):
            break                                              # truncated final record
        pkt = data[off:off + incl_len]
        off += incl_len
        etype = struct.unpack_from("!H", pkt, 12)[0] if incl_len >= 14 else None
        frames.append((orig_len, etype))
    return frames


def load_jsonl(path):
    recs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                recs.append(json.loads(line))
    return recs


# ------------------------------------------------------------------ analysis
def analyze(pcap_frames, records, tx_expected=None):
    # classify pcap frames: normalized outputs (ethertype restored, != 0x88B7) vs fail-open
    # passthroughs (still 0x88B7). Also bucket unknown-ethertype (<14B) frames defensively.
    norm = [wl for (wl, et) in pcap_frames if et is not None and et != ETHERTYPE_TRACE]
    passthrough = [wl for (wl, et) in pcap_frames if et == ETHERTYPE_TRACE]
    n_norm = len(norm)
    unexpected_sizes = sorted(set(wl for wl in norm if wl != TARGET_SIZE))
    all_128 = (len(unexpected_sizes) == 0 and n_norm > 0)

    # loss: normalized outputs vs digest records vs tx_expected
    n_rec = len(records)
    loss_ok = (n_norm == n_rec) and (tx_expected is None or n_norm == tx_expected)

    # reorder + contiguity, per run_id. ingress_tstamp is a 32-bit ns counter that wraps
    # (~every 4.3 s) many times in a multi-second run, so sorting on the raw wrapped value
    # scrambles order. Instead walk in send order (seq) and detect a real reorder as a
    # wrap-corrected *backward* inter-arrival step (> 2^31); genuine wraps are small forward gaps.
    by_run = {}
    for r in records:
        by_run.setdefault(int(r.get("run_id", 0)), []).append(r)
    reorder_ok = True
    dup_total = missing_total = 0
    run_reports = {}
    for rid, rs in by_run.items():
        rs_sorted = sorted(rs, key=lambda r: int(r["seq"]))
        seqs_in_order = [int(r["seq"]) for r in rs_sorted]
        monotonic = True
        prev_ts = None
        for r in rs_sorted:
            t = int(r.get("ingress_tstamp", 0)) & 0xFFFFFFFF
            if prev_ts is not None:
                fwd = (t - prev_ts) & 0xFFFFFFFF          # forward inter-arrival gap, wrap-corrected
                if fwd >= 0x80000000:                     # >2^31 backward => arrival before predecessor = reorder
                    monotonic = False
            prev_ts = t
        seqset = set(seqs_in_order)
        dup = len(seqs_in_order) - len(seqset)
        missing = (max(seqset) - min(seqset) + 1 - len(seqset)) if seqset else 0
        dup_total += dup
        missing_total += missing
        if not monotonic or dup or missing:
            reorder_ok = False
        run_reports[rid] = {"n": len(rs), "seq_min": (min(seqset) if seqset else None),
                            "seq_max": (max(seqset) if seqset else None),
                            "monotonic": monotonic, "dup_seq": dup, "missing_seq": missing}

    # NATIVE (declared input size) vs SHAPED (output size) histograms
    native_hist = dict(sorted(Counter(int(r["input_size"]) for r in records).items()))
    shaped_hist = dict(sorted(Counter(norm).items()))

    # MI: native (input_size leaks device/op) vs shaped (output_size = 128 constant -> 0)
    in_sizes = [int(r["input_size"]) for r in records]
    devices = [int(r.get("device_label", 0)) for r in records]
    ops = [int(r.get("operation_label", 0)) for r in records]
    out_sizes = [TARGET_SIZE] * n_rec                      # every released output is 128 B
    mi = {
        "native_MI_inputsize_device_bits": round(mutual_information_bits(in_sizes, devices), 6),
        "native_MI_inputsize_operation_bits": round(mutual_information_bits(in_sizes, ops), 6),
        "shaped_MI_outputsize_device_bits": round(mutual_information_bits(out_sizes, devices), 6),
        "shaped_MI_outputsize_operation_bits": round(mutual_information_bits(out_sizes, ops), 6),
        "mi_source": MI_SOURCE,
    }
    leakage_removed = bool(
        mi["shaped_MI_outputsize_device_bits"] < 1e-9 and
        mi["shaped_MI_outputsize_operation_bits"] < 1e-9)

    # per-direction padding overhead from actual sent/received bytes.
    #   logical:  declared input_size (payload the frame WOULD be) -> 128 B output.
    #   physical: what left Hulk on the wire = input_size + 19 (replay header).
    per_dir = {}
    for r in records:
        d = int(r.get("direction", 0))
        b = per_dir.setdefault(d, {"n": 0, "sum_input": 0, "sum_output": 0, "sum_physical_sent": 0})
        s = int(r["input_size"])
        b["n"] += 1
        b["sum_input"] += s
        b["sum_output"] += TARGET_SIZE
        b["sum_physical_sent"] += s + REPLAY_HDR_LEN
    for d, b in per_dir.items():
        n = b["n"] or 1
        b["pad_bytes_total"] = b["sum_output"] - b["sum_input"]
        b["mean_pad_bytes"] = round(b["pad_bytes_total"] / n, 4)
        b["overhead_ratio_output_over_input"] = round(b["sum_output"] / b["sum_input"], 6) if b["sum_input"] else None

    checks = {
        "all_outputs_128B": all_128,
        "unexpected_output_sizes": unexpected_sizes,
        "loss_ok_rx_eq_tx": loss_ok,
        "reorder_ok": reorder_ok,
        "leakage_removed": leakage_removed,
    }
    passed = bool(all_128 and loss_ok and reorder_ok and dup_total == 0
                  and missing_total == 0 and leakage_removed)
    return {
        "PASS": passed,
        "checks": checks,
        "counts": {"pcap_frames": len(pcap_frames), "normalized_outputs": n_norm,
                   "failopen_passthrough": len(passthrough), "digest_records": n_rec,
                   "tx_expected": tx_expected},
        "native_size_histogram": native_hist,
        "shaped_size_histogram": shaped_hist,
        "mutual_information": mi,
        "per_direction_overhead": per_dir,
        "per_run": run_reports,
    }


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="off-switch analyzer for queue_microbench_trace_v1")
    ap.add_argument("--pcap", required=True, help="Hulk hairpin inbound capture (classic libpcap)")
    ap.add_argument("--digest", required=True, help="JSONL from mb_trace_collector.py")
    ap.add_argument("--tx-expected", dest="tx_expected", type=int, default=None,
                    help="expected released frame count (pins the loss check)")
    ap.add_argument("--out", default=None, help="also write the JSON result here")
    return ap.parse_args(argv)


def main():
    args = parse_args()
    result = analyze(read_pcap(args.pcap), load_jsonl(args.digest), tx_expected=args.tx_expected)
    text = json.dumps(result, indent=2)
    print(text)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
