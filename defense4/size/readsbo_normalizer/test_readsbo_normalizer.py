#!/usr/bin/env python3
"""Self-checking tests for the READ<->SBO size+segmentation normalizer.

Proves what the mechanism DOES (byte-preservation, CRC validity, size+segmentation
collapse) and HONESTLY demonstrates the residual it does NOT close (object-group).
Exits nonzero on any failure. No hardware.
"""
import sys
import readsbo_normalizer as N

FAIL = []
def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond:
        FAIL.append(name)

def main():
    print("CRC-16/DNP verified against the already-golden cover bytes:")
    check("header-block CRC == 0xC750", N.crc_dnp(bytes.fromhex("0564094432000100")) == 0xC750)
    check("data-block CRC   == 0x2ED8", N.crc_dnp(bytes.fromhex("c0c10200")) == 0x2ED8)

    r_nat = N.build_frame(0x44, 1, 0, N.READ_USER)
    s_nat = N.build_frame(0x44, 1, 0, N.SBO_USER)
    print("\nNative frames are well-formed:")
    check("READ native frame CRCs valid", N.crc_ok(r_nat))
    check("SBO  native frame CRCs valid", N.crc_ok(s_nat))
    check("READ native size == link_wire_len", len(r_nat) == N.link_wire_len(len(N.READ_USER)))
    check("split is byte-preserving (READ)", b"".join(N.split_at_crc(r_nat)) == r_nat)
    check("split is byte-preserving (SBO)",  b"".join(N.split_at_crc(s_nat)) == s_nat)
    print("Native leaks on all four axes (this is the problem):")
    check("native O_count DIFFERS",       len(r_nat) != len(s_nat))
    check("native segmentation DIFFERS",  [len(b) for b in N.split_at_crc(r_nat)] != [len(b) for b in N.split_at_crc(s_nat)])

    r, s = N.normalize_pair(N.READ_USER, N.SBO_USER)
    print("\nAfter normalize (split READ, pad SBO):")
    # byte-preservation of the REAL content
    check("READ real APDU preserved as verbatim prefix", N.frame_user(r.frame).startswith(r.real_user))
    check("SBO  real APDU preserved as verbatim prefix",  N.frame_user(s.frame).startswith(s.real_user))
    # every block CRC still valid (header + real + filler blocks)
    check("READ normalized frame CRCs valid", N.crc_ok(r.frame))
    check("SBO  normalized frame CRCs valid",  N.crc_ok(s.frame))
    # SOLVED axes
    check("O_count MATCHES after normalize",      N.o_count(r) == N.o_count(s))
    check("segmentation MATCHES after normalize", N.o_segmentation(r) == N.o_segmentation(s))
    # HONEST residual: the parser still separates them; assert it stays distinct so
    # the model can never silently claim structure is hidden.
    check("residual: object group STILL DISTINCT (0x1E vs 0x0C)",
          N.o_parse_group(r) != N.o_parse_group(s)
          and N.o_parse_group(r) == 0x1E and N.o_parse_group(s) == 0x0C)

    print(f"\n{'ALL PASS' if not FAIL else 'FAILURES: ' + ', '.join(FAIL)}")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
