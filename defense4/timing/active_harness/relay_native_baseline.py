#!/usr/bin/env python3
"""READ-ONLY native-shape baseline for the two relay READ workloads (mixed, integrity).

Purpose: record the relay's NATIVE READ response wire bytes so the padded targets can be derived
from real bytes, not a measured length alone. Both requests are function 0x01 (READ), non-actuating;
this driver can emit nothing else. It opens ONE persistent TCP connection master .1 -> relay .7:20000
(the production/passthrough switch path forwards it unchanged, so what arrives here is the relay's
native response), sends the requests sequentially, and for each records:

  * the exact request wire bytes,
  * every byte received for the response, re-parsed into CRC-valid link frames (LEN per frame),
  * the transport reassembly (segment count) and the reassembled application fragment,
  * the application decode (function, app seq, IIN, first object group/variation/qualifier),
  * the total native wire length.

Link-frame reassembly (Reassembler) and transport reassembly (TransportAssembler) are the tested
codec; TCP segmentation is a distinct layer and is never read as DNP3 segmentation (correction 2).

Gating: --dry-run is the default and opens no socket; --live additionally refuses unless
DEFENSE4_HW_AUTHORIZED=1 is set in the environment.

    python3 relay_native_baseline.py --dry-run
    DEFENSE4_HW_AUTHORIZED=1 python3 relay_native_baseline.py --live --each 5 --out native.json
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time

from dnp3_codec import (Reassembler, TransportAssembler, TransportError,
                        parse_application_response, validate_response, FUNC_READ)
from session import Session
from read_requests import mixed_read_frame, integrity_read_frame

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"
WORKLOADS = {"mixed": (mixed_read_frame, {(1, 2), (30, 1)}),
             "integrity": (integrity_read_frame, {(1, 2), (10, 2), (30, 4)})}


def decode_response_bytes(raw: bytes):
    """Decode complete fragments offline; retain framing/transport errors explicitly."""
    rx = Reassembler(verify_crc=True)
    rx.feed(raw)
    frames = list(rx.frames())
    asm, fragments, transport_problems = TransportAssembler(), [], []
    for fr in frames:
        try:
            fragment = asm.add(fr.user_data)
        except TransportError as exc:
            transport_problems.append(str(exc))
            asm.reset()
            continue
        if fragment is not None:
            fragments.append(fragment)
    if asm.in_progress:
        transport_problems.append("incomplete transport fragment (FIN missing)")
    consumed = sum(fr.total for fr in frames)
    rec = dict(wire_len=consumed, n_link_frames=len(frames),
               link_lens=[fr.total for fr in frames],
               link_len_fields=[len(fr.user_data)+5 for fr in frames],
               n_transport_segments=len(frames), crc_failures=rx.crc_failures,
               trailing_bytes=len(raw)-consumed, transport_problems=transport_problems,
               app_fragment_hex=None, app_len=None)
    if fragments:
        resp = parse_application_response(fragments[0])
        rec.update(app_fragment_hex=fragments[0].hex(), app_len=len(fragments[0]),
                   decode=dict(function=resp.function, app_seq=resp.app_seq, iin=resp.iin,
                               group=resp.group, variation=resp.variation, qualifier=resp.qualifier,
                               objects=resp.objects, problems=resp.problems))
    return rec, fragments


def one_transaction(sock, workload, seq, budget_ms):
    """Use the same completed-fragment session validator as padded acceptance.

    Accept a Session to preserve connection ownership, or an already-connected socket for
    the original API. No socket is opened here.
    """
    builder, groups = WORKLOADS[workload]
    frame = builder(seq)
    if isinstance(sock, Session):
        master = sock
    else:
        master = Session(RELAY_IP, RELAY_PORT)
        master.sock = sock
    out = master.transaction(operation="READ", frame=frame, function=FUNC_READ, app_seq=seq,
        budget_ms=budget_ms, expect_read_groups=groups, expect_read_workload=workload)
    rec, _ = decode_response_bytes(bytes.fromhex(out.response_wire_hex))
    return dict(workload=workload, app_seq=out.app_seq, outcome=out.outcome,
                request_hex=frame.hex(), request_len=len(frame),
                response_wire_hex=out.response_wire_hex, response_app_hex=out.response_app_hex,
                response_frames_hex=out.response_frames_hex,
                received_wire_hex=out.received_wire_hex,
                received_wire_len=len(bytes.fromhex(out.received_wire_hex)),
                received_frames_hex=out.received_frames_hex,
                elapsed_ms=round(out.elapsed_ms, 3),
                validation_problems=out.problems, local_address=out.local_address,
                peer_address=out.peer_address, master_outcome=out.as_dict(), **rec)


def reevaluate_record(record):
    """New offline verdict for retained bytes; never mutate the historical record."""
    raw = bytes.fromhex(record["response_wire_hex"])
    rec, fragments = decode_response_bytes(raw)
    problems = list(rec["transport_problems"])
    # New records distinguish matched response bytes from the entire received batch.
    # Re-evaluating the matched bytes cannot erase an observed batch/deadline failure.
    master_outcome = record.get("master_outcome")
    if master_outcome is not None and master_outcome.get("outcome") != "OK":
        problems.extend(master_outcome.get("problems") or ["session did not complete successfully"])
    if rec["crc_failures"] or rec["trailing_bytes"] or len(fragments) != 1:
        problems.append("requires exactly one complete CRC-valid response and no trailing bytes")
    if len(fragments) == 1:
        problems.extend(validate_response(parse_application_response(fragments[0]),
            expect_seq=record["app_seq"], expect_function=FUNC_READ,
            expect_read_workload=record["workload"]))
    return dict(workload=record["workload"], app_seq=record["app_seq"],
                historical_outcome=record.get("outcome"),
                historical_validation_problems=record.get("validation_problems", []),
                corrected_outcome="INVALID" if problems else "OK", validation_problems=problems,
                **rec)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--each", type=int, default=3, help="requests per workload (default 3, as 2026-10-23)")
    ap.add_argument("--budget-ms", type=float, default=2000.0)
    ap.add_argument("--connect-timeout-ms", type=float, default=5000.0)
    ap.add_argument("--gap-ms", type=float, default=50.0)
    ap.add_argument("--relay", default=RELAY_IP)
    ap.add_argument("--src", default=SRC_IP)
    ap.add_argument("--out", default=None)
    ap.add_argument("--dry-run", action="store_true", default=None)
    ap.add_argument("--live", dest="dry_run", action="store_false")
    a = ap.parse_args(argv)
    dry = True if a.dry_run in (None, True) else False
    if (a.each <= 0 or not math.isfinite(a.budget_ms) or a.budget_ms <= 0
            or not math.isfinite(a.connect_timeout_ms) or a.connect_timeout_ms <= 0
            or not math.isfinite(a.gap_ms) or a.gap_ms < 0):
        print("REFUSED: --each must be positive; budget/connect timeout must be finite and positive; "
              "gap must be finite and nonnegative", file=sys.stderr)
        return 2

    if dry:
        print("dry run: building request frames, opening no socket")
        for wl in ("mixed", "integrity"):
            f = WORKLOADS[wl][0](0)
            print("  %-9s seq=0 len=%d %s" % (wl, len(f), f.hex()))
        print("frames build and CRC-validate; nothing was sent")
        return 0

    if os.environ.get("DEFENSE4_HW_AUTHORIZED") != "1":
        print("REFUSED: live operation needs DEFENSE4_HW_AUTHORIZED=1", file=sys.stderr)
        return 2

    results, seq = [], 0
    master = Session(a.relay, RELAY_PORT, source_address=(a.src, 0),
                     connect_timeout_ms=a.connect_timeout_ms)
    master.connect()
    print("connected %s -> %s (one persistent connection)" %
          (master.local_address, master.peer_address))
    try:
        for i in range(a.each):
            for wl in ("mixed", "integrity"):
                r = one_transaction(master, wl, seq, a.budget_ms)
                results.append(r)
                d = r.get("decode") or {}
                print("  %-9s seq=%x %-11s wire=%s len_fields=%s frames=%d seg=%d func=0x%02x grp=%s var=%s"
                      % (wl, r["app_seq"], r["outcome"], r["wire_len"], r["link_len_fields"],
                         r["n_link_frames"], r["n_transport_segments"],
                         d.get("function", 0), d.get("group"), d.get("variation")))
                seq = (seq + 1) & 0x0F
                time.sleep(a.gap_ms / 1e3)
    finally:
        master.close()
    doc = dict(when=time.strftime("%Y-%m-%dT%H:%M:%S"), src=a.src, relay=a.relay, port=RELAY_PORT,
               each=a.each, transactions=results,
               summary={wl: sorted({r["wire_len"] for r in results if r["workload"] == wl and r["outcome"] == "OK"})
                        for wl in WORKLOADS})
    text = json.dumps(doc, indent=2)
    if a.out:
        open(a.out, "w").write(text)
        print("wrote %s" % a.out)
    else:
        print(text)
    oks = sum(1 for r in results if r["outcome"] == "OK")
    print("OK %d / %d" % (oks, len(results)))
    return 0 if oks == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
