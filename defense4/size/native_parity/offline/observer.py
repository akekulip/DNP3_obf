#!/usr/bin/env python3
"""observer.py -- parser-aware DNP3 observers, computed from REAL serialized bytes.

Four observers of increasing power (dir.md "Observer definitions"). Each takes actual
TCP-payload bytes and/or a segment-length vector and returns a feature vector derived
from the bytes -- never from a packet-class label. compare() decides equality per level.

The declared claim is O_count+segmentation equality between a READ and an SBO transaction
whose responses are made the same NATIVE size by configured real/decoy points and then
split identically at CRC boundaries. Parser-aware observers (O_parse_link/app) are expected
to still distinguish them (G10/G30 vs G12); this module proves that residual honestly.
"""
from __future__ import annotations
import math
from dataclasses import dataclass

def crc_dnp(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    return (crc ^ 0xFFFF) & 0xFFFF
def crc_le(d): c = crc_dnp(d); return bytes([c & 0xFF, (c >> 8) & 0xFF])

def link_size(u): return 10 + u + 2*math.ceil(u/16)

# ---- DNP3 parse from bytes ----
@dataclass
class Obj:
    group: int; var: int; qual: int; count: int

@dataclass
class Frame:
    dest: int; src: int; ctrl: int; app_ctrl: int; func: int; iin: bytes
    objs: list; block_boundaries: tuple; user: bytes

def deframe_user(payload: bytes):
    """Yield (frame_bytes, user_bytes, block_boundaries) for each DNP3 link frame."""
    i = 0
    while i + 10 <= len(payload):
        if payload[i] != 0x05 or payload[i+1] != 0x64:
            i += 1; continue
        ulen = payload[i+2] - 5
        nblk = (ulen + 15)//16 if ulen > 0 else 0
        total = 10 + ulen + 2*nblk
        if i + total > len(payload): break
        # block boundaries (byte offsets within this frame where a completed CRC block ends)
        bounds = [10]; p = 10; rem = ulen
        while rem > 0:
            t = min(16, rem); p += t + 2; bounds.append(p); rem -= t
        user = bytearray(); q = i + 10; rem = ulen
        while rem > 0:
            t = min(16, rem); user += payload[q:q+t]; q += t + 2; rem -= t
        yield payload[i:i+total], bytes(user), tuple(bounds)
        i += total

def _parse_objs(apdu_objs: bytes):
    """Best-effort object-header walk: (group,var,qual,count). Handles range 0/1 and count 7/8."""
    out = []; k = 0
    while k + 3 <= len(apdu_objs):
        g, v, q = apdu_objs[k], apdu_objs[k+1], apdu_objs[k+2]; k += 3
        rng = q & 0x0F; pfx = (q >> 4) & 0x07
        if rng == 0 and k+2 <= len(apdu_objs):
            start, stop = apdu_objs[k], apdu_objs[k+1]; k += 2; n = stop - start + 1
        elif rng == 1 and k+4 <= len(apdu_objs):
            start = apdu_objs[k] | (apdu_objs[k+1] << 8); stop = apdu_objs[k+2] | (apdu_objs[k+3] << 8); k += 4; n = stop - start + 1
        elif rng == 7 and k < len(apdu_objs):
            n = apdu_objs[k]; k += 1
        elif rng == 8 and k+2 <= len(apdu_objs):
            n = apdu_objs[k] | (apdu_objs[k+1] << 8); k += 2
        else:
            out.append(Obj(g, v, q, -1)); break
        out.append(Obj(g, v, q, n))
        # advance past point payload: we don't need exact per-var sizing for the feature vector
        # (group/var/qual/count are the discriminators); stop after the first object for headers we can't size.
        break
    return out

def parse_frames(payload: bytes):
    frames = []
    for _fb, user, bounds in deframe_user(payload):
        if len(user) < 5:  # transport + app header minimum
            continue
        app = user[1:]  # strip transport header
        app_ctrl, func = app[0], app[1]
        iin = app[2:4] if len(app) >= 4 else b""
        objs = _parse_objs(app[4:]) if func in (0x81, 0x82) else _parse_objs(app[2:]) if func in (0x01,0x03,0x04) else []
        # link header fields
        # frame_bytes[3]=ctrl, [4:6]=dest LE, [6:8]=src LE
        # recover from the original frame via bounds start
        frames.append((app_ctrl, func, iin, objs, bounds, user))
    return frames

# ---- observers ----
def O_count_seg(direction: str, segment_lens: list) -> tuple:
    """Counting + segmentation observer: direction, packet count, ordered payload-length vector."""
    return (direction, len(segment_lens), tuple(segment_lens))

def O_parse_link(payload: bytes) -> tuple:
    """Link + fragment: per-frame (app func, IIN, block-boundary vector)."""
    fr = parse_frames(payload)
    return tuple((f[1], bytes(f[2]).hex(), f[4]) for f in fr)

def O_parse_app(payload: bytes) -> tuple:
    """Application objects: sorted multiset of (group,var,qual,count) across frames."""
    fr = parse_frames(payload)
    objs = []
    for f in fr:
        for o in f[3]:
            objs.append((o.group, o.var, o.qual, o.count))
    return tuple(sorted(objs))

def O_profile(payload: bytes, real_indices: set) -> tuple:
    """Config-aware: object groups after removing decoy (odd/real-unknown) indices is out of scope
    for a size claim; here we expose the raw object-group multiset the profiler would keep."""
    return tuple(sorted({(o.group, o.var) for f in parse_frames(payload) for o in f[3]}))

def compare(a, b) -> bool:
    return a == b


# ---- helpers to build the two real-size candidates for the crux demonstration ----
def build_frame(user: bytes, dest=1, src=0, ctrl=0x44) -> bytes:
    hdr = bytes([0x05, 0x64, 5 + len(user), ctrl, dest & 0xFF, (dest >> 8) & 0xFF, src & 0xFF, (src >> 8) & 0xFF])
    f = bytearray(hdr + crc_le(hdr))
    for i in range(0, len(user), 16):
        blk = user[i:i+16]; f += blk + crc_le(blk)
    return bytes(f)

def sbo_2crob_echo() -> bytes:
    # exact 32-byte APDU measured on the real relay (relay_sbo_2crob.py): two G12V1 CROBs.
    # prepend the 1-byte transport header so user = transport + APDU -> 49 B wire.
    apdu = bytes.fromhex("c28184000c011702000101c80000000000000000010101c80000000000000000")
    return build_frame(bytes([0xC0]) + apdu)

def read_g10_23pts() -> bytes:
    # G10V2 binary-output-status, 23 points (indices 0..22), each octet 0x01 (ONLINE, state 0)
    apdu = bytes.fromhex("c0818000") + bytes([0x0A, 0x02, 0x00, 0x00, 0x16]) + bytes([0x01]) * 23
    return build_frame(bytes([0xC0]) + apdu)


if __name__ == "__main__":
    sbo = sbo_2crob_echo(); rd = read_g10_23pts()
    print(f"SBO 2-CROB echo : {len(sbo)} B   READ G10x23 : {len(rd)} B")
    # apply the same CRC-boundary split vector [28,21] to both
    def split_2821(fr): return [len(fr[:28]), len(fr[28:])]
    print("O_count+seg  equal:", compare(O_count_seg("out", split_2821(sbo)), O_count_seg("out", split_2821(rd))))
    print("O_parse_link equal:", compare(O_parse_link(sbo), O_parse_link(rd)))
    print("O_parse_app  equal:", compare(O_parse_app(sbo), O_parse_app(rd)),
          "  SBO objs", O_parse_app(sbo), " READ objs", O_parse_app(rd))
