#!/usr/bin/env python3
"""Corrected READ driver: function 1, Group 10 Variation 2, points 0..22.

Same request bytes as the campaign, because the frame is built by the frozen
`relay_read_g10_23.read_frame`. What differs is everything after the send: an explicit
monotonic transaction deadline, the remaining budget passed to each receive, full frame
reassembly with CRC validation, and explicit outcomes.

READ is non-actuating, so it needs no point allowlist. It still refuses to open a socket
without `DEFENSE4_HW_AUTHORIZED=1`, and `--dry-run` is the default.

    python3 read_driver.py --dry-run
    DEFENSE4_HW_AUTHORIZED=1 python3 read_driver.py --count 100 --budget-ms 500 --out log.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from dnp3_codec import FUNC_READ, parse_frame
from frozen_builders import read_frame
from session import Session, Outcome, OUTCOME_NOT_ATTEMPTED

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"


def build(seq: int) -> bytes:
    frame = read_frame(seq & 0x0F)
    parsed, rest = parse_frame(frame)              # CRC-validate what we are about to send
    if parsed is None or rest:
        raise ValueError("built READ frame does not parse cleanly")
    if parsed.user_data[2] != FUNC_READ:
        raise ValueError("refusing: built frame is not a READ")
    return frame


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--gap-ms", type=float, default=20.0)
    ap.add_argument("--budget-ms", type=float, default=500.0,
                    help="per-transaction deadline; the campaign's effective value was 3000")
    ap.add_argument("--relay", default=RELAY_IP)
    ap.add_argument("--src", default=SRC_IP)
    ap.add_argument("--out", default=None, help="JSONL outcome log")
    ap.add_argument("--dry-run", action="store_true", default=None,
                    help="build and validate frames, open no socket (the default)")
    ap.add_argument("--live", dest="dry_run", action="store_false",
                    help="open a socket; also requires DEFENSE4_HW_AUTHORIZED=1")
    a = ap.parse_args(argv)
    dry = True if a.dry_run in (None, True) else False

    if dry:
        print("dry run: building %d READ frames, opening no socket" % a.count)
        for i in range(min(a.count, 3)):
            f = build(i)
            print("  seq=%x len=%d %s" % (i & 0x0F, len(f), f.hex()))
        print("frames build and CRC-validate; nothing was sent")
        return 0

    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        print("REFUSED: live operation needs DEFENSE4_HW_AUTHORIZED=1", file=sys.stderr)
        return 2

    fh = open(a.out, "w") if a.out else None
    counts = {}
    try:
        with Session(a.relay, RELAY_PORT, source_address=(a.src, 0)) as s:
            print("connected %s -> %s:%d" % (a.src, a.relay, RELAY_PORT))
            for i in range(a.count):
                seq = i & 0x0F
                try:
                    frame = build(seq)
                except ValueError as exc:
                    out = Outcome(operation="READ", function=FUNC_READ, app_seq=seq,
                                  outcome=OUTCOME_NOT_ATTEMPTED, problems=[str(exc)])
                else:
                    out = s.transaction(operation="READ", frame=frame, function=FUNC_READ,
                                        app_seq=seq, budget_ms=a.budget_ms)
                counts[out.outcome] = counts.get(out.outcome, 0) + 1
                if fh:
                    fh.write(json.dumps(out.as_dict()) + "\n")
                if not out.ok:
                    print("  seq=%x %s %s" % (seq, out.outcome, "; ".join(out.problems)))
                time.sleep(a.gap_ms / 1e3)
    finally:
        if fh:
            fh.close()
    print("outcomes: %s" % counts)
    return 0 if counts.get("OK", 0) == a.count else 1


if __name__ == "__main__":
    sys.exit(main())
