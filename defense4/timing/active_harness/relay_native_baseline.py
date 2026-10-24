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
import os
import socket
import sys
import time

from dnp3_codec import (Reassembler, TransportAssembler, parse_frame, parse_response,
                        validate_response, FUNC_RESPONSE)
from read_requests import mixed_read_frame, integrity_read_frame

RELAY_IP, RELAY_PORT, SRC_IP = "192.168.10.7", 20000, "192.168.10.1"
WORKLOADS = {"mixed": (mixed_read_frame, {(1, 2), (30, 1)}),
             "integrity": (integrity_read_frame, None)}  # integrity returns class data; group not gated


def decode_response_bytes(raw: bytes):
    """Re-parse accumulated response bytes into CRC-valid link frames and reassemble. Pure/offline."""
    rx = Reassembler(verify_crc=True)
    rx.feed(raw)
    frames = list(rx.frames())
    asm, fragments, consumed = TransportAssembler(), [], 0
    seg = 0
    for fr in frames:
        consumed += fr.total
        seg += 1
        frag = asm.add(fr.user_data)
        if frag is not None:
            fragments.append(frag)
    rec = dict(wire_len=consumed, n_link_frames=len(frames),
               link_lens=[fr.total for fr in frames],
               link_len_fields=[len(fr.user_data) + 5 for fr in frames],
               n_transport_segments=seg, crc_failures=rx.crc_failures,
               trailing_bytes=len(raw) - consumed)
    if frames:
        # parse_response expects the link user data with the transport header at [0]
        # (the contract session.py relies on); the FIR frame carries the application header.
        resp = parse_response(frames[0].user_data)
        rec.update(app_fragment_hex=(fragments[0].hex() if fragments else None),
                   app_len=(len(fragments[0]) if fragments else None),
                   decode=dict(function=resp.function, app_seq=resp.app_seq, iin=resp.iin,
                               group=resp.group, variation=resp.variation, qualifier=resp.qualifier))
    return rec, fragments


def one_transaction(sock, workload, seq, budget_ms):
    builder, groups = WORKLOADS[workload]
    frame = builder(seq)
    raw = bytearray()
    rx, asm = Reassembler(verify_crc=True), TransportAssembler()
    t0 = time.monotonic()
    deadline = t0 + budget_ms / 1e3
    sock.settimeout(max(0.0, deadline - time.monotonic()))
    sock.sendall(frame)
    outcome, resp = "TIMEOUT", None
    while time.monotonic() < deadline:
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            outcome = "PEER_CLOSED"
            break
        raw += chunk
        rx.feed(chunk)
        done = False
        for fr in rx.frames():
            # decode from the link user data (transport header at [0]); the FIR frame carries
            # the application header. complete when transport FIN closes the fragment and the
            # application answer is a RESPONSE for this sequence.
            r = parse_response(fr.user_data)
            frag = asm.add(fr.user_data)
            if frag is not None and r.function == FUNC_RESPONSE and r.app_seq == (seq & 0x0F):
                resp, outcome, done = r, "OK", True
                break
        if done:
            break
    elapsed_ms = (time.monotonic() - t0) * 1e3
    rec, _ = decode_response_bytes(bytes(raw))
    problems = []
    if resp is not None:
        problems = validate_response(resp, expect_seq=seq, expect_function=0x01,
                                     expect_read_groups=groups)
    return dict(workload=workload, app_seq=seq & 0x0F, outcome=outcome,
                request_hex=frame.hex(), request_len=len(frame),
                response_wire_hex=bytes(raw).hex(), elapsed_ms=round(elapsed_ms, 3),
                validation_problems=problems, **rec)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--each", type=int, default=3, help="requests per workload (default 3, as 2026-10-23)")
    ap.add_argument("--budget-ms", type=float, default=2000.0)
    ap.add_argument("--gap-ms", type=float, default=50.0)
    ap.add_argument("--relay", default=RELAY_IP)
    ap.add_argument("--src", default=SRC_IP)
    ap.add_argument("--out", default=None)
    ap.add_argument("--dry-run", action="store_true", default=None)
    ap.add_argument("--live", dest="dry_run", action="store_false")
    a = ap.parse_args(argv)
    dry = True if a.dry_run in (None, True) else False

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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.bind((a.src, 0))
    except OSError as exc:
        print("note: could not bind source %s (%s); routing will choose" % (a.src, exc), file=sys.stderr)
    s.settimeout(5.0)
    s.connect((a.relay, RELAY_PORT))
    print("connected %s -> %s:%d (one persistent connection)" % (a.src, a.relay, RELAY_PORT))
    try:
        for i in range(a.each):
            for wl in ("mixed", "integrity"):
                r = one_transaction(s, wl, seq, a.budget_ms)
                results.append(r)
                d = r.get("decode") or {}
                print("  %-9s seq=%x %-11s wire=%s len_fields=%s frames=%d seg=%d func=0x%02x grp=%s var=%s"
                      % (wl, r["app_seq"], r["outcome"], r["wire_len"], r["link_len_fields"],
                         r["n_link_frames"], r["n_transport_segments"],
                         d.get("function", 0), d.get("group"), d.get("variation")))
                seq = (seq + 1) & 0x0F
                time.sleep(a.gap_ms / 1e3)
    finally:
        s.close()
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
