#!/usr/bin/env python3
"""READ<->SBO size+segmentation normalizer — byte-preserving reference model.

Mechanism (Philip's design): split the larger response at DNP3 CRC-block boundaries
into a target TCP-segment pattern, and pad the smaller response up to the same
block-aligned size with CRC-valid DNP3 filler, so a READ transaction and an SBO
transaction present an IDENTICAL size and segmentation to a passive observer.

This is a software reference + emulator (no hardware, no proxy). It operates on the
real OpenDNP3 response bytes from defense4/size/evidence and:
  - preserves the real application objects byte-for-byte (they are a verbatim prefix),
  - keeps every DNP3 block CRC valid (header block + data blocks + filler blocks),
  - collapses O_count and the segmentation channel for the READ<->SBO pair,
and HONESTLY reports the residual (a parser still reads the real object-group byte;
the two-phase SBO request direction is untouched). Those two residual axes are the
open problem handed to the domain experts — this model is where their solutions plug in.

DNP3 link framing (IEEE 1815 s9): frame = 10-byte header block
(05 64, LEN, CTRL, DEST[2 LE], SRC[2 LE], CRC[2 LE]) + data blocks of <=16 user
bytes each with a trailing 2-byte block CRC. User bytes = 1 transport header + APDU.
"""
from __future__ import annotations
import math
from dataclasses import dataclass

# ---- CRC-16/DNP (poly 0x3D65 reflected = 0xA6BC, init 0, xorout 0xFFFF) ----
def crc_dnp(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFF) & 0xFFFF

def _crc_le(data: bytes) -> bytes:
    c = crc_dnp(data)
    return bytes([c & 0xFF, (c >> 8) & 0xFF])   # transmitted low byte first

# ---- link framing ----
HEADER_USER_OVERHEAD = 5     # LEN counts CTRL+DEST+SRC + user bytes
BLOCK_USER = 16              # max user bytes per data block

def link_wire_len(n_user: int) -> int:
    return 10 + n_user + 2 * math.ceil(n_user / BLOCK_USER)

def build_frame(ctrl: int, dest: int, src: int, user: bytes) -> bytes:
    """Build a full on-wire link frame from user bytes (transport+APDU)."""
    hdr = bytes([0x05, 0x64, HEADER_USER_OVERHEAD + len(user), ctrl,
                 dest & 0xFF, (dest >> 8) & 0xFF, src & 0xFF, (src >> 8) & 0xFF])
    frame = bytearray(hdr + _crc_le(hdr))
    for i in range(0, len(user), BLOCK_USER):
        blk = user[i:i + BLOCK_USER]
        frame += blk + _crc_le(blk)
    return bytes(frame)

def frame_blocks(frame: bytes) -> list[bytes]:
    """Split a frame into its CRC blocks: [10B header block, then <=18B data blocks]."""
    out = [frame[:10]]
    i = 10
    while i < len(frame):
        # each data block = up to 16 user bytes + 2 CRC; last may be short
        n = min(BLOCK_USER + 2, len(frame) - i)
        out.append(frame[i:i + n])
        i += n
    return out

def crc_ok(frame: bytes) -> bool:
    """Verify header-block CRC and every data-block CRC."""
    if _crc_le(frame[:8]) != frame[8:10]:
        return False
    for blk in frame_blocks(frame)[1:]:
        body, crc = blk[:-2], blk[-2:]
        if _crc_le(body) != crc:
            return False
    return True

def frame_user(frame: bytes) -> bytes:
    """Reassemble user bytes (transport+APDU) by stripping block CRCs."""
    return b"".join(blk[:-2] for blk in frame_blocks(frame)[1:])

# ---- the mechanism: split (segment on CRC boundaries) + pad ----
def split_at_crc(frame: bytes) -> list[bytes]:
    """TCP segments cut on DNP3 CRC-block boundaries. Byte-preserving:
    b''.join(split_at_crc(f)) == f."""
    return frame_blocks(frame)

def pad_user_to(real_user: bytes, target_user_len: int, filler: int = 0x00) -> bytes:
    """Grow user bytes to target_user_len; the REAL bytes stay a verbatim prefix.
    Filler bytes are opaque here — their DNP3 object encoding (a benign decoy the
    master parses-and-discards) is the semantics question handed to the domain expert."""
    assert target_user_len >= len(real_user)
    return real_user + bytes([filler]) * (target_user_len - len(real_user))

@dataclass
class Normalized:
    frame: bytes
    segments: list[bytes]
    real_user: bytes          # the verbatim real user bytes (transport+APDU)

def normalize_pair(read_user: bytes, sbo_user: bytes,
                   ctrl=0x44, dest=1, src=0) -> tuple[Normalized, Normalized]:
    """Normalize a READ and an SBO response to one common block-aligned size and an
    identical CRC-boundary segment pattern. The larger is split; the smaller is padded."""
    target_user = max(len(read_user), len(sbo_user))
    # block-align the target so both land on a clean block boundary
    target_user = math.ceil(target_user / BLOCK_USER) * BLOCK_USER
    out = []
    for u in (read_user, sbo_user):
        padded = pad_user_to(u, target_user)
        f = build_frame(ctrl, dest, src, padded)
        out.append(Normalized(frame=f, segments=split_at_crc(f), real_user=u))
    return out[0], out[1]

# ---- observer models ----
def o_count(n: Normalized) -> int:                 # byte-counting observer
    return len(n.frame)
def o_segmentation(n: Normalized) -> list[int]:    # per-packet size sequence
    return [len(s) for s in n.segments]
def o_parse_group(n: Normalized) -> int:
    """Structure-parsing observer: the application object group byte.
    user = [transport(1)][app_ctrl(1) func(1) IIN(2)][group ...] -> group at index 5."""
    return frame_user(n.frame)[5]

# ---- real response bytes from defense4/size/evidence ----
# READ: G30V1 (group 0x1E) analog, 12 points (larger response -> gets SPLIT)
READ_APDU = bytes.fromhex(
    "C0 81 80 00 1E 01 00 00 0B"
    "01 E8 03 00 00 01 E9 03 00 00 01 EA 03 00 00 01 EB 03 00 00"
    "01 54 C3 00 00 01 55 C3 00 00 01 56 C3 00 00 01 57 C3 00 00"
    "01 58 C3 00 00 01 59 C3 00 00 01 5A C3 00 00 01 5B C3 00 00".replace(" ", ""))
# SBO OPERATE echo: G12V1 (group 0x0C) single CROB (smaller response -> gets PADDED)
SBO_APDU = bytes.fromhex(
    "C0 81 80 00 0C 01 28 01 00 01 00 01 01 64 00 00 00 64 00 00 00 00".replace(" ", ""))
TRANSPORT = bytes([0xC0])   # one transport header byte (FIR/FIN/seq)
READ_USER = TRANSPORT + READ_APDU
SBO_USER = TRANSPORT + SBO_APDU


def _demo():
    print(f"CRC self-check (golden cover block bytes):")
    print(f"  header 05 64 09 44 32 00 01 00 -> {crc_dnp(bytes.fromhex('0564094432000100')):#06x} (expect 0xc750)")
    print(f"  body   c0 c1 02 00             -> {crc_dnp(bytes.fromhex('c0c10200')):#06x} (expect 0x2ed8)")

    r_nat = build_frame(0x44, 1, 0, READ_USER)
    s_nat = build_frame(0x44, 1, 0, SBO_USER)
    print(f"\nNATIVE:")
    print(f"  READ {len(r_nat):>3}B  segments {[len(b) for b in split_at_crc(r_nat)]}  group {frame_user(r_nat)[5]:#04x}")
    print(f"  SBO  {len(s_nat):>3}B  segments {[len(b) for b in split_at_crc(s_nat)]}  group {frame_user(s_nat)[5]:#04x}")

    r, s = normalize_pair(READ_USER, SBO_USER)
    print(f"\nNORMALIZED (split READ, pad SBO):")
    print(f"  READ {o_count(r):>3}B  segments {o_segmentation(r)}  group {o_parse_group(r):#04x}")
    print(f"  SBO  {o_count(s):>3}B  segments {o_segmentation(s)}  group {o_parse_group(s):#04x}")
    print(f"\n  O_count            : {'MATCH' if o_count(r)==o_count(s) else 'DIFFER'}  ({o_count(r)}B)")
    print(f"  Segmentation       : {'MATCH' if o_segmentation(r)==o_segmentation(s) else 'DIFFER'}")
    print(f"  Parser (obj group) : {'MATCH' if o_parse_group(r)==o_parse_group(s) else 'DIFFER'}"
          f"  ({o_parse_group(r):#04x} vs {o_parse_group(s):#04x})  <- residual for the experts")


if __name__ == "__main__":
    _demo()
