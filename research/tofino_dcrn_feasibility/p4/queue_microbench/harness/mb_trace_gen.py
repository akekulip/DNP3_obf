#!/usr/bin/env python3
"""mb_trace_gen.py — trace-replay frame generator for queue_microbench_trace_v1 (run ON Hulk).

Sends ONLY well-formed trace-replay frames (ethertype 0x88B7) out of Hulk's NIC via raw
AF_PACKET (stdlib only — same idiom as mb_gen_raw.py). There is NO metronome, NO cover/chaff,
NO external filler concept: every frame is a single 0x88B7 replay frame carrying MEASUREMENT-ONLY
labels + the declared input_size_class that keys the switch's 13-entry pad table. The switch
strips the 19 B replay header and pads each supported class to EXACTLY 128 B.

Frame format is the executable spec build_trace_frame() in queue_microbench_trace_setup.py
(imported and reused verbatim for the 13 supported sizes). physical wire size = input_size + 19.

Modes:
  --smoke     : one frame for each of the 6 required smoke inputs
                (60 min-supported, 66 pure-ACK, 89 READ-request, 120 response, 120 largest,
                 200 UNSUPPORTED oversize -> fail-open probe). seq 0..5.
  --campaign  : replay campaign_base_distribution.json at its empirical frequencies for N
                transactions, wide spacing (~200 ms), unique incrementing per-frame seq, and
                the run_id passed on the command line.

Both modes print the EXACT per-size send counts.

Usage:
  sudo python3 mb_trace_gen.py --iface enp59s0f0np0 --smoke --run-id 900
  sudo python3 mb_trace_gen.py --iface enp59s0f0np0 --campaign -N 800 --run-id 1 --interval-ms 200
  python3 mb_trace_gen.py --smoke --dry-run          # build + print counts, send nothing (off-switch)
"""
import argparse
import os
import random
import socket
import struct
import sys
import time

# ── reuse the canonical frame-format spec from the setup module (one dir up) ──
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)
from queue_microbench_trace_setup import (  # noqa: E402
    build_trace_frame, SIZE_TO_ACTION, INPUT_SIZES,
    ETHERTYPE_TRACE, REPLAY_HDR_LEN, ETH_LEN,
)

DEFAULT_CAMPAIGN = os.path.join(_PARENT, "size_pattern_builder", "campaign_base_distribution.json")
DST_MAC = b"\x02\x00\x00\x00\x00\x02"
SRC_MAC = b"\x02\x00\x00\x00\x00\x01"

# ── canonical measurement-only label encoders (0 = unknown/reserved). These are the ONLY
#    numeric encoding of the campaign's string labels; the digest round-trips them back and
#    mb_trace_analyze.py decodes with the reverse maps below. ──
DEVICE_ENC  = {"AB1400": 1, "ION7550": 2, "SEL751": 3}
OP_ENC      = {"ACK": 1, "READ": 2, "DIRECT_OPERATE": 3, "RESPONSE": 4, "other": 5}
DIR_ENC     = {"in": 1, "out": 2}
ACKMODE_ENC = {"combined": 1, "separate": 2, "incomplete": 3, "ambiguous": 4}
DEVICE_DEC  = {v: k for k, v in DEVICE_ENC.items()}
OP_DEC      = {v: k for k, v in OP_ENC.items()}
DIR_DEC     = {v: k for k, v in DIR_ENC.items()}
ACKMODE_DEC = {v: k for k, v in ACKMODE_ENC.items()}


def build_unsupported_frame(input_size_class, seq=0, run_id=0, device_label=0, operation_label=0,
                            direction=0, transaction_id=0, ack_mode=0, orig_ethertype=0x0800,
                            tx_tstamp=0, dst_mac=DST_MAC, src_mac=SRC_MAC, fill=b"\x00"):
    """Build a well-formed 0x88B7 trace frame whose declared input_size_class is NOT one of the
    13 supported sizes (the fail-open probe). SAME physical layout / packing as
    build_trace_frame() but WITHOUT the 13-set validation, so we can exercise the switch's
    unsupported -> forward-unchanged path. physical wire size = input_size_class + 19."""
    if not (ETH_LEN <= input_size_class <= 0xFF):
        raise ValueError("unsupported-frame size must be in [%d, 255], got %r"
                         % (ETH_LEN, input_size_class))
    eth = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_TRACE)
    replay = struct.pack("!H I B B B B H B H I",
                         run_id & 0xFFFF, seq & 0xFFFFFFFF,
                         device_label & 0xFF, operation_label & 0xFF, direction & 0xFF,
                         input_size_class & 0xFF, transaction_id & 0xFFFF, ack_mode & 0xFF,
                         orig_ethertype & 0xFFFF, tx_tstamp & 0xFFFFFFFF)
    body_len = input_size_class - ETH_LEN
    body = (fill * body_len)[:body_len]
    frame = eth + replay + body
    assert len(frame) == input_size_class + REPLAY_HDR_LEN, "physical size mismatch"
    return frame


# ── one smoke frame-spec per required input. supported=False marks the fail-open oversize. ──
SMOKE_SPECS = [
    {"size": 60,  "device": "AB1400", "op": "ACK",      "dir": "in",  "ack": "combined", "supported": True,  "note": "min supported"},
    {"size": 66,  "device": "SEL751", "op": "ACK",      "dir": "in",  "ack": "separate", "supported": True,  "note": "pure-ACK sized"},
    {"size": 89,  "device": "AB1400", "op": "READ",     "dir": "in",  "ack": "combined", "supported": True,  "note": "READ-request sized"},
    {"size": 120, "device": "SEL751", "op": "RESPONSE", "dir": "out", "ack": "separate", "supported": True,  "note": "response sized"},
    {"size": 120, "device": "SEL751", "op": "RESPONSE", "dir": "out", "ack": "separate", "supported": True,  "note": "largest supported"},
    {"size": 200, "device": None,     "op": "other",    "dir": "in",  "ack": "combined", "supported": False, "note": "UNSUPPORTED oversize (fail-open probe)"},
]


def _spec_to_frame(spec, seq, run_id, tx_tstamp):
    """Turn a {size, device, op, dir, ack, supported, transaction_id} spec into raw wire bytes."""
    dev = DEVICE_ENC.get(spec.get("device"), 0)
    op = OP_ENC.get(spec.get("op"), 0)
    dr = DIR_ENC.get(spec.get("dir"), 0)
    am = ACKMODE_ENC.get(spec.get("ack"), 0)
    txn = spec.get("transaction_id", seq) & 0xFFFF
    builder = build_trace_frame if spec.get("supported", True) else build_unsupported_frame
    return builder(spec["size"], seq=seq, run_id=run_id, device_label=dev, operation_label=op,
                   direction=dr, transaction_id=txn, ack_mode=am, tx_tstamp=tx_tstamp)


# ------------------------------------------------------------------ campaign plan
def load_campaign(path):
    import json
    with open(path) as f:
        return json.load(f)


def apportion(counts, N):
    """Largest-remainder (Hamilton) apportionment: split N into len(counts) integers that sum
    EXACTLY to N and match the empirical proportions as closely as possible. Deterministic."""
    total = sum(counts)
    if total <= 0 or N <= 0:
        return [0] * len(counts)
    exact = [c / total * N for c in counts]
    floors = [int(x) for x in exact]
    rem = N - sum(floors)
    # distribute the remaining `rem` units to the largest fractional parts (ties -> lower index)
    order = sorted(range(len(counts)), key=lambda i: (exact[i] - floors[i], counts[i]), reverse=True)
    for i in order[:rem]:
        floors[i] += 1
    return floors


def build_campaign_plan(campaign, N, seed):
    """Return a deterministically-ordered list of frame-specs (length N) drawn from the campaign
    distribution at its empirical frequencies. Order is a seeded shuffle so sizes interleave
    (order is immaterial to the size result but kept reproducible)."""
    dist = campaign["distribution"]
    alloc = apportion([e["count"] for e in dist], N)
    plan = []
    for e, k in zip(dist, alloc):
        for _ in range(k):
            plan.append({"size": e["input_size"], "device": e["device"], "op": e["operation"],
                         "dir": e["direction"], "ack": e["ack_mode"], "supported": True})
    random.Random(seed).shuffle(plan)
    for i, spec in enumerate(plan):
        spec["transaction_id"] = (i + 1) & 0xFFFF
    return plan


# ------------------------------------------------------------------ send
def _open_socket(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    return s


def send_plan(plan, iface, run_id, interval_ms, dry_run):
    """Send each spec in order with `interval_ms` spacing, assigning incrementing seq (0-based)
    and a live tx timestamp. Returns (sent, per_size_counts)."""
    from collections import Counter
    per_size = Counter()
    sock = None if dry_run else _open_socket(iface)
    interval = interval_ms / 1000.0
    sent = 0
    t0 = time.time()
    for seq, spec in enumerate(plan):
        tx_ts = time.time_ns() & 0xFFFFFFFF
        frame = _spec_to_frame(spec, seq=seq, run_id=run_id, tx_tstamp=tx_ts)
        if sock is not None:
            sock.send(frame)
        per_size[spec["size"]] += 1
        sent += 1
        if sock is not None and sent < len(plan) and interval > 0:
            time.sleep(interval)
    dt = time.time() - t0
    if sock is not None:
        sock.close()
    return sent, per_size, dt


def _print_counts(mode, run_id, sent, per_size, dt, dry_run, extra=None):
    print("=" * 78)
    print("mb_trace_gen %s  run_id=%d  %s" % (mode, run_id, "[DRY-RUN: nothing sent]" if dry_run else ""))
    print("=" * 78)
    print("exact per-size send counts:")
    for s in sorted(per_size):
        tag = "" if s in SIZE_TO_ACTION else "  (UNSUPPORTED -> fail-open, forwarded unchanged)"
        phys = s + REPLAY_HDR_LEN
        out = 128 if s in SIZE_TO_ACTION else phys
        print("    size=%-4d  n=%-6d  physical_wire=%-4dB  expected_output=%-4dB%s"
              % (s, per_size[s], phys, out, tag))
    print("    ---- total frames: %d ----" % sent)
    if extra:
        for line in extra:
            print("    " + line)
    if not dry_run:
        print("sent %d frames in %.3f s (%.1f pps)" % (sent, dt, sent / dt if dt else 0))


def run_smoke(args):
    plan = [dict(s) for s in SMOKE_SPECS]
    for i, spec in enumerate(plan):
        spec["transaction_id"] = (i + 1) & 0xFFFF
    sent, per_size, dt = send_plan(plan, args.iface, args.run_id, args.interval_ms, args.dry_run)
    extra = ["smoke inputs (seq order): " +
             ", ".join("%d:%s" % (s["size"], s["note"]) for s in SMOKE_SPECS)]
    _print_counts("SMOKE", args.run_id, sent, per_size, dt, args.dry_run, extra)


def run_campaign(args):
    campaign = load_campaign(args.campaign_file)
    plan = build_campaign_plan(campaign, args.n, args.seed)
    sent, per_size, dt = send_plan(plan, args.iface, args.run_id, args.interval_ms, args.dry_run)
    extra = ["campaign=%s  n_requested=%d  seed=%d  (empirical corpus n=%d)"
             % (os.path.basename(args.campaign_file), args.n, args.seed,
                campaign.get("n_packets", "?"))]
    _print_counts("CAMPAIGN", args.run_id, sent, per_size, dt, args.dry_run, extra)


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="trace-replay frame generator (queue_microbench_trace_v1)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--smoke", action="store_true", help="send the 6 required smoke frames")
    mode.add_argument("--campaign", action="store_true", help="replay the base distribution for N transactions")
    ap.add_argument("--iface", default=None, help="Hulk NIC (e.g. enp59s0f0np0); required unless --dry-run")
    ap.add_argument("--run-id", dest="run_id", type=int, default=1, help="run epoch stamped into every frame")
    ap.add_argument("-N", "--count", dest="n", type=int, default=800, help="campaign transaction count")
    ap.add_argument("--interval-ms", dest="interval_ms", type=float, default=200.0, help="inter-frame spacing (ms)")
    ap.add_argument("--seed", type=int, default=1234, help="deterministic campaign interleave seed")
    ap.add_argument("--campaign-file", default=DEFAULT_CAMPAIGN, help="campaign distribution JSON")
    ap.add_argument("--dry-run", action="store_true", help="build + print counts, send nothing")
    args = ap.parse_args(argv)
    if not args.dry_run and not args.iface:
        ap.error("--iface is required unless --dry-run")
    return args


def main():
    args = parse_args()
    if args.smoke:
        run_smoke(args)
    else:
        run_campaign(args)


if __name__ == "__main__":
    main()
