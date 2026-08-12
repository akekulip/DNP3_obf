#!/usr/bin/env python3
"""FIX 1 — cover-frame GOLDEN byte vector + independent CRC verification.

The Defense-4 size kernel prepends ONE fixed CRC-valid DNP3 unconfirmed-user-data
link frame in front of the real response. If ANY byte of that cover is wrong (a
placeholder CRC, or a byte-reversed link address) the master's DNP3 link layer
fails the header CRC, resynchronises by scanning for the next 0x0564, and can
mis-frame the real response that follows. So the cover bytes are load-bearing and
must be verified, not asserted.

This module:
  1. Implements CRC-16/DNP two INDEPENDENT ways and cross-checks them against the
     repo's known-good captured vector.
  2. Builds the cover frame field-by-field with EXPLICIT wire byte order.
  3. Emits the GOLDEN 16-byte vector and asserts it.
  4. Parses the frame back (header CRC + block CRC + length) and rejects a
     corrupted copy (negative control).
  5. Prints the exact P4 header-field CONSTANTS. Because a TNA deparser emits a
     bit<16> field in NETWORK (big-endian) order, a little-endian link field
     (dst/src) and the low-first DNP3 CRCs must be byte-SWAPPED in the P4 constant
     so the wire bytes come out right. Those swapped constants are what the
     repaired defense4_cover_kernel.p4 uses.

Run:  python3 cover_frame_golden.py        # prints report, exits non-zero on any mismatch
"""
from __future__ import annotations
import struct
import sys

# ------------------------------------------------------------------ CRC impl A
# Bitwise, reflected polynomial 0xA6BC (the reflected form of the canonical
# CRC-16/DNP poly 0x3D65). Same routine used across the repo's harnesses.
def crc_dnp_bitwise(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFF


# ------------------------------------------------------------------ CRC impl B
# Independent table-driven. The table is built from the reflected poly, and the
# reflected poly is DERIVED here by reflecting the canonical 0x3D65 (not copied),
# so agreement with impl A is a genuine cross-check of the parameters.
def _reflect(v: int, width: int) -> int:
    r = 0
    for i in range(width):
        if v & (1 << i):
            r |= 1 << (width - 1 - i)
    return r

_RPOLY = _reflect(0x3D65, 16)
assert _RPOLY == 0xA6BC, f"reflected poly derivation wrong: {_RPOLY:#06x}"
_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ _RPOLY if (_c & 1) else (_c >> 1)
    _TABLE.append(_c & 0xFFFF)

def crc_dnp_table(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc = (crc >> 8) ^ _TABLE[(crc ^ b) & 0xFF]
    return (~crc) & 0xFFFF


def crc_dnp(data: bytes) -> int:
    """Both implementations, asserted equal."""
    a, b = crc_dnp_bitwise(data), crc_dnp_table(data)
    assert a == b, f"CRC impls disagree on {data.hex()}: {a:#06x} vs {b:#06x}"
    return a


# --------------------------------------------------- cover-frame field constants
# DNP3 data-link framing (IEEE 1815):
#   start  : the fixed 2-byte sync pair 0x05,0x64 (NOT a little-endian word)
#   length : octet count of CONTROL + DEST + SRC + user-data, EXCLUDING CRCs
#   control: 0x44 = DIR=0, PRM=1, function 4 (UNCONFIRMED_USER_DATA)
#   dest   : 2-byte LINK address, LITTLE-ENDIAN on the wire
#   source : 2-byte LINK address, LITTLE-ENDIAN on the wire
#   hdr crc: CRC-16/DNP over the 8 header bytes, transmitted LOW BYTE FIRST
#   then one <=16-byte user-data block + its CRC (also low byte first).
COVER_LEN_FIELD = 0x09          # = 5 (ctrl+dst+src) + 4 user-data bytes
COVER_CTRL      = 0x44
COVER_DEST      = 0x0032        # 50 : an INDIVIDUAL, non-endpoint link address
COVER_SRC       = 0x0001        # 1
# 4 user-data (application/transport) bytes; irrelevant content, frame is discarded
COVER_UD        = bytes([0xC0, 0xC1, 0x02, 0x00])   # tp=0xC0(FIR|FIN,seq0) ac=0xC1 fc=0x02 pad=0x00


def build_cover() -> bytes:
    link_hdr = b"\x05\x64" + struct.pack("<BBHH",
                                         COVER_LEN_FIELD, COVER_CTRL,
                                         COVER_DEST, COVER_SRC)     # 8 bytes, wire order
    assert len(link_hdr) == 8
    hdr_crc = crc_dnp(link_hdr)
    blk_crc = crc_dnp(COVER_UD)
    return (link_hdr
            + struct.pack("<H", hdr_crc)   # low byte first
            + COVER_UD
            + struct.pack("<H", blk_crc))  # low byte first


# The verified golden vector (asserted below against build_cover()).
GOLDEN_HEX = "05 64 09 44 32 00 01 00 50 C7 C0 C1 02 00 D8 2E"
GOLDEN = bytes.fromhex(GOLDEN_HEX.replace(" ", ""))


def parse_cover(frame: bytes) -> dict:
    """Independent decode: verify start, both CRCs, and the length field."""
    if frame[0:2] != b"\x05\x64":
        raise ValueError("bad start pair")
    length = frame[2]
    ctrl = frame[3]
    dest = struct.unpack("<H", frame[4:6])[0]
    src = struct.unpack("<H", frame[6:8])[0]
    hdr_crc = struct.unpack("<H", frame[8:10])[0]
    if crc_dnp(frame[0:8]) != hdr_crc:
        raise ValueError("header CRC invalid")
    udlen = length - 5                      # ctrl+dst+src = 5
    body = frame[10:10 + udlen]
    blk_crc = struct.unpack("<H", frame[10 + udlen:12 + udlen])[0]
    if crc_dnp(body) != blk_crc:
        raise ValueError("block CRC invalid")
    return {"length": length, "ctrl": ctrl, "dest": dest, "src": src,
            "hdr_crc": hdr_crc, "body": body, "blk_crc": blk_crc,
            "total_len": 12 + udlen}


def p4_constants() -> dict:
    """The exact bit<16>/bit<8> constants the repaired P4 must use. A TNA deparser
    emits a bit<16> field big-endian, so a little-endian link field or a low-first
    CRC is byte-SWAPPED in the P4 constant to land the right wire bytes."""
    frame = build_cover()
    hdr_crc_wire = frame[8:10]        # e.g. 50 C7  (low first)
    blk_crc_wire = frame[14:16]       # e.g. D8 2E
    def swap16_from_wire(two: bytes) -> int:
        # constant whose big-endian emission == these two wire bytes = as-is
        return (two[0] << 8) | two[1]
    return {
        "COVER_START":   0x0564,                       # emits 05 64 (already correct)
        "COVER_DL_LEN":  COVER_LEN_FIELD,              # 0x09
        "COVER_CTRL":    COVER_CTRL,                   # 0x44
        # dst wire = 32 00  -> bit<16> constant 0x3200 (big-endian emit -> 32 00)
        "COVER_DST":     (COVER_DEST & 0xFF) << 8 | (COVER_DEST >> 8),
        "COVER_SRC":     (COVER_SRC & 0xFF) << 8 | (COVER_SRC >> 8),
        "COVER_DL_CRC":  swap16_from_wire(hdr_crc_wire),   # 0x50C7
        "COVER_TP":      COVER_UD[0], "COVER_AC": COVER_UD[1],
        "COVER_FC":      COVER_UD[2], "COVER_PAD": COVER_UD[3],
        "COVER_BCRC":    swap16_from_wire(blk_crc_wire),   # 0xD82E
    }


def main() -> int:
    ok = True
    # 1. cross-check impls on the repo known-good vector
    kg = bytes.fromhex("05642b4401000a00")
    if not (crc_dnp_bitwise(kg) == crc_dnp_table(kg) == 0x610b):
        print("FAIL: known-good vector CRC mismatch"); ok = False
    else:
        print(f"known-good vector 05642b4401000a00 -> CRC 0x{crc_dnp(kg):04x}  (both impls agree)")

    # 2/3. build + assert golden
    frame = build_cover()
    print("built cover frame:", " ".join(f"{x:02X}" for x in frame))
    print("golden vector    :", GOLDEN_HEX)
    if frame != GOLDEN:
        print("FAIL: built frame != golden"); ok = False
    else:
        print("MATCH golden: OK")

    # 4. parse + negative control
    dec = parse_cover(frame)
    print("decoded:", {k: (v.hex() if isinstance(v, bytes) else v) for k, v in dec.items()})
    if dec["dest"] != 50 or dec["src"] != 1 or dec["total_len"] != 16:
        print("FAIL: decoded fields wrong"); ok = False
    bad = bytearray(frame); bad[8] ^= 0xFF
    try:
        parse_cover(bytes(bad)); print("FAIL: parser accepted a corrupted CRC"); ok = False
    except ValueError as e:
        print(f"negative control rejected corrupted frame: {e}  OK")

    # 5. P4 constants
    print("\n-- exact repaired P4 constants (bit<16> emitted big-endian) --")
    for k, v in p4_constants().items():
        w = 4 if v > 0xFF else 2
        print(f"  const  {k:14s} = 0x{v:0{w}X}")

    print("\nGOLDEN:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
