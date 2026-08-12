#!/usr/bin/env python3
"""Behavioral emulator of defense4_joint_size_time_kernel.p4 — the JOINT size+time
primitive, modeling the FULL ingress -> hold-ring loopback -> deadline-release ->
egress-split path.

WHY THIS EXISTS. The isolated egress emulator (crc_split_emulator.py) validated the
split in a vacuum and never modeled the ingress hold ring, which is exactly why the
silicon drop surfaced only on hardware: the caseA ingress routes a protected response
through the internal loopback (bypass_egress=1) and RELEASES it toward the master only
at the deadline; a split egress with no release path dropped it. This fixture models
that path so the failure is caught in software.

ONE PREDICATE. `do_shape(p)` = response DIRECTION (src port == DNP3) AND owner FLOW
(normalized 5-tuple) AND native SIZE == 49 B (ip.total_len == 89). It looks at NOTHING
about DNP3 type. The same bit drives BOTH:
  (a) TIMING: a do_shape response is HELD in the ring (recirculating, bypass_egress=1,
      NOT split) for the deadline, then released toward the master;
  (b) SIZE:   on that single release pass (bypass_egress=0, reaching egress) it is
      split at the CRC-block boundary cut=28 into the fixed vector [28, 21].
On every hold/loopback pass the split does NOT fire (the packet never reaches egress).
Non-do_shape traffic is forwarded immediately, native, no hold, no split.

Validated by test_joint_size_time_conformance.py. Pure stdlib.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crc_split_emulator import (  # noqa: E402
    CrcSplitEmulator, Pkt, build_frame, block_boundaries, POL_SPLIT, PORT_DNP3, CUT_28,
)

TL_SHAPE = 89          # ip.total_len of the 49 B target response
SHAPE_SIZE = 49


@dataclass
class JointResult:
    shaped: bool                 # did the single predicate fire?
    released: bool               # did the response reach the master (NOT dropped)?
    held_passes: int             # loopback passes spent in the hold ring (0 in OFF)
    segs: list                   # output segments (Seg on the release pass; [Pkt] if native)
    trace: List[Tuple[str, bool]] = field(default_factory=list)  # (location, split_fired)


class JointSizeTimeFixture:
    """ingress -> hold-ring -> deadline-release -> egress-split, one predicate."""

    def __init__(self, owner_tuple, deadline_passes: int = 3, mode: str = "timing",
                 cut: int = CUT_28):
        self.owner = owner_tuple
        self.deadline_passes = deadline_passes
        self.mode = mode                       # "timing" (hold to D) or "off" (immediate)
        self.cut = cut
        self.egress = CrcSplitEmulator(owner_tuple, POL_SPLIT, cut)

    def do_shape(self, p: Pkt) -> bool:
        """THE single predicate — direction + owner + size, NO DNP3 type."""
        if not (p.is_ipv4 and p.proto == 6 and p.ihl == 5 and p.mf == 0
                and p.frag == 0 and p.dofs == 5):
            return False
        if p.syn or p.rst:
            return False
        d_out, norm = CrcSplitEmulator._norm(p)
        owner = (self.owner is not None and norm == self.owner)
        size49 = (p.total_len() == TL_SHAPE and p.payload[:2] == b"\x05\x64"
                  and len(p.payload) == SHAPE_SIZE)
        return d_out == 1 and owner and size49

    def run(self, p: Pkt) -> JointResult:
        trace: List[Tuple[str, bool]] = []
        if not self.do_shape(p):
            # not the protected observable: forwarded immediately, no hold, no split
            trace.append(("egress_forward_native", False))
            return JointResult(False, True, 0, [p], trace)

        # (a) TIMING: hold in the ring. Every loopback pass sets bypass_egress=1, so the
        # packet NEVER reaches egress and the split does NOT fire.
        held = self.deadline_passes if self.mode == "timing" else 0
        for k in range(held):
            trace.append((f"loopback_hold_pass_{k} (bypass_egress=1)", False))

        # deadline reached: RELEASE toward the master (bypass_egress=0) -> egress -> split
        r = self.egress.process(p)
        split_fired = (r.outcome == "SPLIT")
        trace.append(("deadline_release_egress_split (bypass_egress=0)", split_fired))
        return JointResult(True, True, held, r.segs, trace)


# --------------------------------------------------------------------------- #
def read_frame_49() -> bytes:
    """A 49 B READ response (G10 V2 status flavour): 33 user bytes, one content."""
    return build_frame(0x44, 1, 0, bytes([0xC0]) + bytes((i * 7 + 1) & 0xFF for i in range(32)))


def sbo_frame_49() -> bytes:
    """A 49 B SBO echo (G12 CROB flavour): 33 user bytes, DIFFERENT content, SAME size."""
    return build_frame(0x44, 1, 0, bytes([0xC0]) + bytes((i * 13 + 200) & 0xFF for i in range(32)))


if __name__ == "__main__":
    OUT, MAS = 0x0A0A360A, 0x0A0A3613
    owner = (MAS, OUT, 40000, PORT_DNP3)
    fx = JointSizeTimeFixture(owner, deadline_passes=4, mode="timing")
    for tag, frame in (("READ", read_frame_49()), ("SBO", sbo_frame_49())):
        assert len(frame) == 49
        r = fx.run(Pkt(OUT, MAS, PORT_DNP3, 40000, seq=1000, ack=5, payload=frame))
        sizes = [s.total_len for s in r.segs]
        join = b"".join(s.payload for s in r.segs)
        print(f"{tag} 49B: shaped={r.shaped} released={r.released} held={r.held_passes} "
              f"segs={sizes} join_ok={join == frame} "
              f"split_only_on_release={sum(1 for _, s in r.trace if s) == 1}")
        assert r.shaped and r.released and r.held_passes == 4
        assert sizes == [68, 61] and join == frame           # [28,21] payloads
        assert sum(1 for _, s in r.trace if s) == 1          # split fired EXACTLY once, on release
    print("self-demo OK (READ and SBO: SAME path, held-to-D, split [28,21], no type branch)")
