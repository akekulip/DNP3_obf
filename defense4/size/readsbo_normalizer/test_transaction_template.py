#!/usr/bin/env python3
"""Tests for the unified READ<->SBO O2 transaction template.

Proves O1 and O2 indistinguishability, the safety properties of the decoys, and
HONESTLY asserts the O3 residual (a stateful correlator still separates them).
Exits nonzero on any failure. No hardware.
"""
import sys
import readsbo_normalizer as N
import transaction_template as T

FAIL = []
def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAIL.append(name)

def main():
    r, s = T.build_read_txn(), T.build_sbo_txn()

    print("Indistinguishability against the committed observer:")
    check("O1 (counting) MATCHES", T.O1(r) == T.O1(s))
    check("O2 (single-packet DPI) MATCHES", T.O2(r) == T.O2(s))

    print("The parity is real (not vacuous):")
    check("response object-group multiset == {G12:2, G30:1} for both",
          T.O2(r)["resp_group_multiset"] == [("G12", 2), ("G30", 1)]
          and T.O2(s)["resp_group_multiset"] == [("G12", 2), ("G30", 1)])
    check("request func-code multiset == {0x01,0x03,0x04} for both",
          T.O2(r)["req_func_multiset"] == [(0x01, 1), (0x03, 1), (0x04, 1)]
          and T.O2(s)["req_func_multiset"] == [(0x01, 1), (0x03, 1), (0x04, 1)])
    check("each direction has 3 frames in both", T.O1(r)["req_count"] == 3 and T.O1(r)["resp_count"] == 3)
    check("response pad target fits the 3-block split MVP (<=64 B link)",
          T._targets()["resp"] <= 48 and N.link_wire_len(T._targets()["resp"]) <= 64)

    print("Decoy safety (READ-only posture preserved):")
    check("READ transaction actuates nothing", T.O3(r)["actuations"] == 0)
    check("SBO transaction actuates exactly once (the real control only)", T.O3(s)["actuations"] == 1)
    check("every decoy frame is phantom-addressed",
          all(f.dest == T.PHANTOM for f in r + s if not f.real))
    check("every real frame uses master/outstation address only",
          all(f.dest in (T.MASTER, T.OUTSTATION) for f in r + s if f.real))

    print("Frames are well-formed after padding (CRCs valid):")
    for f, frame in T._pad_frames(r) + T._pad_frames(s):
        if not N.crc_ok(frame):
            check(f"CRC valid ({'real' if f.real else 'decoy'} {f.direction})", False)
    check("all padded frames have valid CRCs", not FAIL or all(not x.startswith("CRC valid") for x in FAIL))

    print("Honest residual (asserted, never silently claimed away):")
    check("O3 (stateful correlator) STILL SEPARATES them", T.O3(r) != T.O3(s))
    check("O3 separators exist: actuation and/or address/order differ",
          T.O3(r)["actuations"] != T.O3(s)["actuations"]
          or T.O3(r)["dest_order"] != T.O3(s)["dest_order"]
          or T.O3(r)["dpi_order"] != T.O3(s)["dpi_order"])

    print(f"\n{'ALL PASS' if not FAIL else 'FAILURES: ' + ', '.join(FAIL)}")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
