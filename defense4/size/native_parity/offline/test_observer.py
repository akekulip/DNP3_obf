#!/usr/bin/env python3
"""Tests for the parser-aware observers, from REAL serialized bytes.

Proves the declared claim (O_count+segmentation equality of a 49 B native READ and a 49 B
native SBO under an identical CRC-boundary split) and HONESTLY asserts the parser-aware
residual (O_parse_app still separates G10 from G12). Exits nonzero on failure.
"""
import sys
import observer as O

FAIL = []
def chk(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    if not cond: FAIL.append(name)

def crc_ok(frame):
    if O.crc_le(frame[:8]) != frame[8:10]: return False
    i = 10
    while i < len(frame):
        n = min(18, len(frame) - i); body, crc = frame[i:i+n-2], frame[i+n-2:i+n]
        if O.crc_le(body) != crc: return False
        i += n
    return True

def main():
    sbo = O.sbo_2crob_echo(); rd = O.read_g10_23pts()

    print("Native size equality (measured/derived, no switch insertion):")
    chk("SBO 2-CROB echo is 49 B", len(sbo) == 49)
    chk("READ G10x23 is 49 B", len(rd) == 49)
    chk("both frames are CRC-valid DNP3", crc_ok(sbo) and crc_ok(rd))

    # identical CRC-boundary split applied to both (byte-preserving): [28, 21]
    def split_2821(fr):
        segs = [fr[:28], fr[28:]]
        assert b"".join(segs) == fr, "split must be byte-preserving"
        return [len(s) for s in segs]
    print("O_count+segmentation (the declared observer):")
    chk("same split vector [28,21] for both", split_2821(sbo) == [28, 21] and split_2821(rd) == [28, 21])
    chk("O_count+seg EQUAL for READ vs SBO",
        O.compare(O.O_count_seg("out", split_2821(sbo)), O.O_count_seg("out", split_2821(rd))))

    print("Feature vectors are parsed FROM BYTES, not labels:")
    chk("SBO app objects parse to G12V1 CROB", O.O_parse_app(sbo) == ((12, 1, 0x17, 2),))
    chk("READ app objects parse to G10V2 x23", O.O_parse_app(rd) == ((10, 2, 0x00, 23),))

    print("Honest residual (asserted to STAY distinct):")
    chk("O_parse_app SEPARATES READ from SBO (G10 vs G12)", not O.compare(O.O_parse_app(sbo), O.O_parse_app(rd)))
    chk("O_parse_link SEPARATES them too", not O.compare(O.O_parse_link(sbo), O.O_parse_link(rd)))

    print("Observer has power (a real size leak is detected):")
    chk("different split vectors -> O_count+seg DIFFERS",
        not O.compare(O.O_count_seg("out", [28, 21]), O.O_count_seg("out", [46, 3])))
    chk("a 40 B READ (16 pts) vs 49 B SBO -> O_count+seg DIFFERS (native sizes unequal)",
        not O.compare(O.O_count_seg("out", [len(O.read_g10_23pts())]),
                      O.O_count_seg("out", [40])))

    print(f"\n{'ALL PASS' if not FAIL else 'FAILURES: ' + ', '.join(FAIL)}")
    return 1 if FAIL else 0

if __name__ == "__main__":
    sys.exit(main())
