#!/usr/bin/env python3
"""Byte-precise behavioral emulator of defense4_padnorm_kernel.p4 (egress).

The v2 PAD-normalization kernel removes the block-alignment barrier: it grows the
MEASURED non-block-aligned SEL-751 responses to a common 64 B target by rebuilding
the short trailing DNP3 block as [real-prefix ++ zero-fill] with a runtime block CRC.

  READ = 40 B on-wire (total_len 80, user 26) -> 64 B  (delta +24)
  SBO  = 49 B on-wire (total_len 89, user 33) -> 64 B  (delta +15)

Modeled exactly (dl LEN -> 0x35 + recomputed header-block CRC; full real blocks
reused unchanged; the trailing mixed block = real_tail ++ zeros with its CRC over
the 16 reconstructed bytes; pure-zero filler to 3 blocks). Faithful to the reference
model build_frame(pad_user_to(real_user, 48)).

HONEST WALL: this is a SINGLE-INSERTION epoch — at most ONE response per connection
is normalized. A live READ+SBO stream (interleaved +24 / +15 deltas) needs a
variable-delta multi-boundary transport ledger, which the Tofino-1 SALU cannot
maintain; so continuous stream normalization is NOT achievable on one TF1 chip.

Pure stdlib. `python3 p4_padnorm_emulator.py` self-demo.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..", "readsbo_normalizer"))
from readsbo_normalizer import (  # noqa: E402
    build_frame, pad_user_to, crc_ok, frame_user, _crc_le,
)
from p4_split_emulator import Pkt, wire, verify_checksums, mod32, PORT_DNP3  # noqa: E402

TARGET_USER = 48
TARGET_ONWIRE = 64
DL_LEN_TGT = 0x35
SIZE_MAP = {80: ("READ", 24), 89: ("SBO", 15)}   # ip.total_len -> (name, delta)


def v2_reconstruct(frame: bytes) -> bytes:
    """The v2 kernel's egress byte construction (see module docstring)."""
    user = frame_user(frame)
    K = len(user) % 16
    nfull = len(user) // 16
    new_hdr8 = frame[0:2] + bytes([DL_LEN_TGT]) + frame[3:8]
    out = bytearray(new_hdr8 + _crc_le(new_hdr8))            # dl' (LEN 0x35 + runtime CRC)
    for i in range(nfull):                                   # reuse full real blocks unchanged
        out += frame[10 + i * 18: 10 + i * 18 + 18]
    real_tail = user[nfull * 16: nfull * 16 + K]
    mix_user = real_tail + bytes(16 - K)                     # reconstructed mixed block user
    out += mix_user + _crc_le(mix_user)                      # + runtime CRC
    for _ in range(3 - (nfull + 1)):                         # pure-zero filler to 3 blocks
        out += bytes(16) + _crc_le(bytes(16))
    return bytes(out)


@dataclass
class Seg:
    seq: int
    payload: bytes
    total_len: int
    wire: bytes
    ipv4_ok: bool
    tcp_ok: bool
    kind: str


@dataclass
class Result:
    outcome: str
    segs: List[Seg]
    touched_state: bool = False
    delta: int = 0
    out_ack: Optional[int] = None


def _mkseg(p: Pkt, seq: int, payload: bytes, kind: str) -> Seg:
    w = wire(p, seq=seq, payload=payload)
    ip_ok, tcp_ok = verify_checksums(w)
    return Seg(mod32(seq), payload, 40 + len(payload), w, ip_ok, tcp_ok, kind)


class PadNormEmulator:
    def __init__(self, owner_tuple: Optional[Tuple[int, int, int, int]] = None, pad_on: bool = True):
        self.owner_tuple = owner_tuple
        self.pad_on = pad_on
        self.pdelta: Dict[int, int] = {}
        self.pb0: Dict[int, int] = {}

    @staticmethod
    def _norm(p: Pkt):
        if p.sport == PORT_DNP3:
            return 1, (p.dip, p.sip, p.dport, p.sport)
        return 0, (p.sip, p.dip, p.sport, p.dport)

    @staticmethod
    def _idx(norm):
        return hash(norm) & 0x3FF

    def _native(self, p: Pkt) -> Result:
        return Result("NATIVE", [_mkseg(p, p.seq, p.payload, "NATIVE")])

    def process(self, p: Pkt) -> Result:
        if not (p.is_ipv4 and p.proto == 6 and p.ihl == 5 and p.mf == 0 and p.frag == 0 and p.dofs == 5):
            return self._native(p)
        d_out, norm = self._norm(p)
        owner = (self.owner_tuple is not None and norm == self.owner_tuple)
        idx = self._idx(norm)
        is_ctl = p.syn or p.fin or p.rst

        # reverse direction: single-insertion ACK translation
        if d_out == 0:
            if owner and self.pad_on and self.pdelta.get(idx, 0) != 0:
                delta, b0 = self.pdelta[idx], self.pb0.get(idx, 0)
                a = mod32(p.ack - b0)
                sub = 0 if (a == 0 or a >= (1 << 31)) else (a if a < delta else delta)
                out_ack = mod32(p.ack - sub)
                seg = _mkseg(Pkt(**{**p.__dict__, "ack": out_ack}), p.seq, p.payload, "NATIVE")
                return Result("NATIVE", [seg], touched_state=True, out_ack=out_ack)
            return self._native(p)

        # forward: only the two measured DNP3 response sizes are normalized
        info = SIZE_MAP.get(p.total_len())
        if not (owner and self.pad_on and not is_ctl and info and p.payload[:2] == b"\x05\x64"):
            return self._native(p)
        name, delta = info
        opened = self.pdelta.get(idx, 0) != 0
        if opened:                                   # single-insertion: later responses NOT padded
            return self._native(p)
        self.pdelta[idx] = delta
        self.pb0[idx] = p.seq
        grown = v2_reconstruct(p.payload)
        return Result("PAD", [_mkseg(p, p.seq, grown, "PAD")], touched_state=True, delta=delta)


if __name__ == "__main__":
    from readsbo_normalizer import link_wire_len
    OUT, MAS = 0x0A0A360A, 0x0A0A3613
    owner = (MAS, OUT, 40000, PORT_DNP3)
    for name, onwire in (("READ", 40), ("SBO", 49)):
        u = next(n for n in range(1, 60) if link_wire_len(n) == onwire)
        frame = build_frame(0x44, 1, 0, bytes([0xC0]) + bytes(u - 1))
        e = PadNormEmulator(owner, pad_on=True)
        r = e.process(Pkt(OUT, MAS, PORT_DNP3, 40000, seq=1000, ack=5, payload=frame))
        ref = build_frame(0x44, 1, 0, pad_user_to(frame_user(frame), TARGET_USER))
        g = r.segs[0].payload
        print(f"{name}: {onwire}->{len(g)}B delta=+{r.delta} matches_ref={g == ref} "
              f"crc_ok={crc_ok(g)} csum_ok={r.segs[0].tcp_ok}")
        assert g == ref and crc_ok(g) and len(g) == 64 and r.segs[0].tcp_ok
    print("self-demo OK")
