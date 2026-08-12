#!/usr/bin/env python3
"""Byte-precise behavioral emulator of defense4_split_kernel.p4 (egress).

Mirrors the P4 egress exactly for the compile-only MVP:

  * FAIL-OPEN gate: only a clean IPv4/TCP (ihl==5, not fragmented, dofs==5)
    segment whose payload is a 1..3 full-block DNP3 frame (ip.total_len in
    {68,86,104}) enters the size layer; everything else is passed NATIVE.
  * SPLIT (policy SPLIT): the frame is re-segmented into a fixed 2-way split on
    the first DNP3 CRC-block boundary (offset 28 = 10-byte header block + one
    18-byte data block). window0 = dl+blk0 (seq=base), window1 = blk1+blk2
    (seq=base+28). Pure re-segmentation: byte-preserving, no CRC recompute, no
    transport state. Each window gets its own IP total_len and recomputed
    IPv4/TCP checksums. (The P4 produces the two windows physically via
    mirror->multicast; here we model the two output segments directly.)
  * PAD (policy PAD): a smaller BLOCK-ALIGNED frame is grown to the shared
    3-block target (48 user bytes): the DNP3 header LEN is rewritten to 0x35,
    the header-block CRC recomputed, and (3-nblk) constant CRC-valid 0x00 filler
    blocks (block CRC over 16 zero bytes = 0xFFFF, wire ff ff) appended. The
    single-insertion epoch records Delta = added wire bytes and translates the
    reverse ACK (master->outstation) by -clamp(ack-b0, 0, Delta).

Validated against the reference model readsbo_normalizer.py by
test_split_conformance.py. Pure stdlib. `python3 p4_split_emulator.py` self-demo.
"""
from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# reference model (DNP3 framing + CRC) and cover-emulator checksum helpers
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "readsbo_normalizer"))
from readsbo_normalizer import (  # noqa: E402
    build_frame, crc_dnp, frame_blocks, crc_ok, pad_user_to, _crc_le,
)
from p4_cover_emulator import _ones_sum, ipv4_checksum, tcp_checksum  # noqa: E402

PORT_DNP3 = 20000
SEQ_MOD = 1 << 32
TARGET_USER = 48                 # 3 full data blocks (16*3)
DL_LEN_TGT = 0x35                # 5 + 48 user bytes
FILL_BLOCK = bytes(16) + b"\xff\xff"          # CRC-16/DNP over 16 zero bytes = 0xFFFF
SIZE_OK_TOTALS = {68: 1, 86: 2, 104: 3}       # ip.total_len -> block count
W0_PAYLOAD = 28                  # dl(10) + blk0(18)
POL_NONE, POL_PAD, POL_SPLIT = "NONE", "PAD", "SPLIT"


def mod32(x: int) -> int:
    return x % SEQ_MOD


# --------------------------------------------------------------------------- #
# packet model (a DNP3 response over TCP)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Pkt:
    sip: int
    dip: int
    sport: int
    dport: int
    seq: int
    ack: int
    payload: bytes = b""          # the DNP3 link frame (or any TCP payload)
    syn: bool = False
    fin: bool = False
    rst: bool = False
    ihl: int = 5
    dofs: int = 5
    mf: int = 0
    frag: int = 0
    is_ipv4: bool = True
    proto: int = 6

    def flags_byte(self) -> int:
        v = 0x10
        if self.fin: v |= 0x01
        if self.syn: v |= 0x02
        if self.rst: v |= 0x04
        return v

    def total_len(self) -> int:
        return 20 + 4 * (self.ihl - 5) + 4 * self.dofs + len(self.payload)


def wire(p: Pkt, seq: Optional[int] = None, ack: Optional[int] = None,
         payload: Optional[bytes] = None) -> bytes:
    """Serialize eth+ip+tcp+payload with VALID IPv4/TCP checksums."""
    seq = p.seq if seq is None else seq
    ack = p.ack if ack is None else ack
    payload = p.payload if payload is None else payload
    eth = bytes.fromhex("0000000000010000000000020800")
    total = 20 + 4 * (p.ihl - 5) + 4 * p.dofs + len(payload)
    ip_opts = b"\x00" * (4 * (p.ihl - 5))
    ver_ihl = (4 << 4) | p.ihl
    flags_frag = (p.mf << 13) | (p.frag & 0x1FFF)
    ip_wo = struct.pack("!BBHHHBBH", ver_ihl, 0, total, 0x1234, flags_frag, 64, p.proto, 0) + \
        struct.pack("!II", p.sip, p.dip) + ip_opts
    ipc = ipv4_checksum(ip_wo[:20] + ip_opts) if p.ihl == 5 else ipv4_checksum(ip_wo)
    ip = ip_wo[:10] + struct.pack("!H", ipc) + ip_wo[12:]
    tcp_opts = b"\x00" * (4 * (p.dofs - 5))
    off = (p.dofs << 4)
    tcp_wo = struct.pack("!HHIIBBHHH", p.sport, p.dport, mod32(seq), mod32(ack),
                         off, p.flags_byte(), 65535, 0, 0) + tcp_opts
    tc = tcp_checksum(p.sip, p.dip, tcp_wo + payload)
    tcp = tcp_wo[:16] + struct.pack("!H", tc) + tcp_wo[18:]
    return eth + ip + tcp + payload


@dataclass
class Seg:
    """One emitted output segment."""
    seq: int
    payload: bytes
    total_len: int
    wire: bytes
    ipv4_ok: bool
    tcp_ok: bool
    kind: str                     # WINDOW0 / WINDOW1 / PAD / NATIVE


@dataclass
class Result:
    outcome: str                  # SPLIT / PAD / NATIVE
    segs: List[Seg]
    touched_state: bool = False
    delta: int = 0                # PAD: recorded Delta (added wire bytes)
    out_ack: Optional[int] = None # PAD reverse: translated ack (if this was REV)


# --------------------------------------------------------------------------- #
# helpers shared with the P4 semantics
# --------------------------------------------------------------------------- #
def grow_frame(frame: bytes) -> Tuple[bytes, int, int]:
    """PAD: grow a BLOCK-ALIGNED frame to the 3-block target. Returns
    (grown_frame, delta_wire_bytes, nblk). Mirrors the P4: rewrite dl.len=0x35,
    recompute the header-block CRC, append (3-nblk) constant 0x00 filler blocks.
    The real data blocks are carried unchanged."""
    blocks = frame_blocks(frame)
    nblk = len(blocks) - 1
    new_hdr8 = frame[0:2] + bytes([DL_LEN_TGT]) + frame[3:8]
    new_dl = new_hdr8 + _crc_le(new_hdr8)
    real_blocks = frame[10:]
    fillers = FILL_BLOCK * (3 - nblk)
    grown = new_dl + real_blocks + fillers
    return grown, len(fillers), nblk


def verify_checksums(w: bytes) -> Tuple[bool, bool]:
    ip_off = 14
    ihl = (w[ip_off] & 0xF) * 4
    ipv4_ok = (_ones_sum(w[ip_off:ip_off + ihl]) == 0xFFFF)
    total_len = struct.unpack("!H", w[ip_off + 2:ip_off + 4])[0]
    sip = struct.unpack("!I", w[ip_off + 12:ip_off + 16])[0]
    dip = struct.unpack("!I", w[ip_off + 16:ip_off + 20])[0]
    tcp_seg = w[ip_off + ihl:ip_off + total_len]
    pseudo = struct.pack("!IIBBH", sip, dip, 0, 6, len(tcp_seg))
    tcp_ok = (_ones_sum(pseudo + tcp_seg) == 0xFFFF)
    return ipv4_ok, tcp_ok


def _mkseg(p: Pkt, seq: int, payload: bytes, kind: str) -> Seg:
    w = wire(p, seq=seq, payload=payload)
    ip_ok, tcp_ok = verify_checksums(w)
    return Seg(seq=mod32(seq), payload=payload, total_len=40 + len(payload),
               wire=w, ipv4_ok=ip_ok, tcp_ok=tcp_ok, kind=kind)


# --------------------------------------------------------------------------- #
# the emulator
# --------------------------------------------------------------------------- #
class SplitPadEmulator:
    def __init__(self, owner_tuple: Optional[Tuple[int, int, int, int]] = None,
                 policy: str = POL_NONE):
        self.owner_tuple = owner_tuple           # normalized (nm_ip,nr_ip,nm_pt,nr_pt)
        self.policy = policy
        self.pdelta: Dict[int, int] = {}         # flow_idx -> stored Delta (0 = closed)
        self.pb0: Dict[int, int] = {}            # flow_idx -> boundary seq

    @staticmethod
    def _norm(p: Pkt) -> Tuple[int, Tuple[int, int, int, int]]:
        if p.sport == PORT_DNP3:                 # out -> master
            return 1, (p.dip, p.sip, p.dport, p.sport)
        return 0, (p.sip, p.dip, p.sport, p.dport)

    @staticmethod
    def _idx(norm) -> int:
        return hash(norm) & 0x3FF

    def _native(self, p: Pkt, note: str = "") -> Result:
        return Result("NATIVE", [_mkseg(p, p.seq, p.payload, "NATIVE")])

    def process(self, p: Pkt) -> Result:
        # FAIL-OPEN gate 1: clean TCP only
        if not (p.is_ipv4 and p.proto == 6 and p.ihl == 5 and p.mf == 0 and p.frag == 0 and p.dofs == 5):
            return self._native(p, "not-clean-tcp")
        d_out, norm = self._norm(p)
        owner = (self.owner_tuple is not None and norm == self.owner_tuple)
        idx = self._idx(norm)
        is_ctl = p.syn or p.fin or p.rst

        # REVERSE direction (master -> outstation): PAD ack translation only
        if d_out == 0:
            if owner and self.policy == POL_PAD and self.pdelta.get(idx, 0) != 0:
                delta = self.pdelta[idx]; b0 = self.pb0.get(idx, 0)
                a = mod32(p.ack - b0)
                if a == 0 or a >= (SEQ_MOD >> 1):
                    sub = 0
                elif a < delta:
                    sub = a
                else:
                    sub = delta
                out_ack = mod32(p.ack - sub)
                seg = _mkseg(Pkt(**{**p.__dict__, "ack": out_ack}), p.seq, p.payload, "NATIVE")
                return Result("NATIVE", [seg], touched_state=True, out_ack=out_ack)
            return self._native(p, "rev-native")

        # FORWARD (outstation -> master). Only DNP3 data frames of the right size.
        size_ok = (p.total_len() in SIZE_OK_TOTALS) and len(p.payload) >= 10 and p.payload[:2] == b"\x05\x64"
        if not owner or is_ctl or not size_ok:
            return self._native(p, "fwd-native")

        if self.policy == POL_SPLIT:
            f = p.payload
            w0 = _mkseg(p, p.seq, f[:W0_PAYLOAD], "WINDOW0")
            w1 = _mkseg(p, mod32(p.seq + W0_PAYLOAD), f[W0_PAYLOAD:], "WINDOW1")
            return Result("SPLIT", [w0, w1])

        if self.policy == POL_PAD:
            grown, delta, nblk = grow_frame(p.payload)
            # single-insertion epoch: open on the first eligible response
            opened = self.pdelta.get(idx, 0) != 0
            if not opened:
                self.pdelta[idx] = delta
                self.pb0[idx] = p.seq
            seg = _mkseg(p, p.seq, grown, "PAD")
            return Result("PAD", [seg], touched_state=True, delta=delta)

        return self._native(p, "no-policy")


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613
    owner = (MAS_IP, OUT_IP, 40000, PORT_DNP3)

    # SPLIT: a 3-block response (48 user bytes) re-segmented 2-way
    user3 = bytes([0xC0]) + bytes(range(47))
    f3 = build_frame(0x44, 1, 0, user3)
    assert len(f3) == 64, len(f3)
    e = SplitPadEmulator(owner_tuple=owner, policy=POL_SPLIT)
    r = e.process(Pkt(OUT_IP, MAS_IP, PORT_DNP3, 40000, seq=1000, ack=5, payload=f3))
    print(f"SPLIT: {len(r.segs)} segs sizes={[s.total_len for s in r.segs]} "
          f"seqs={[s.seq for s in r.segs]} join_ok={b''.join(s.payload for s in r.segs)==f3} "
          f"csum_ok={all(s.ipv4_ok and s.tcp_ok for s in r.segs)}")
    assert b"".join(s.payload for s in r.segs) == f3
    assert r.segs[0].seq == 1000 and r.segs[1].seq == 1028
    assert all(s.ipv4_ok and s.tcp_ok for s in r.segs)

    # PAD: a 1-block response (16 user) grown to 3 blocks
    user1 = bytes([0xC0]) + bytes(15)
    f1 = build_frame(0x44, 1, 0, user1)
    e2 = SplitPadEmulator(owner_tuple=owner, policy=POL_PAD)
    rp = e2.process(Pkt(OUT_IP, MAS_IP, PORT_DNP3, 40000, seq=2000, ack=5, payload=f1))
    grown = rp.segs[0].payload
    ref = build_frame(0x44, 1, 0, pad_user_to(user1, TARGET_USER))
    print(f"PAD:   grown {len(f1)}->{len(grown)}B delta={rp.delta} "
          f"crc_ok={crc_ok(grown)} matches_ref={grown==ref} csum_ok={rp.segs[0].tcp_ok}")
    assert grown == ref and crc_ok(grown) and rp.segs[0].tcp_ok
    print("self-demo OK")
