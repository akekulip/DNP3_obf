#!/usr/bin/env python3
"""Conformance + mutation harness for defense4_split_kernel.p4 (via its emulator).

Runs a packet-vector corpus through the P4 behavioral emulator (p4_split_emulator)
and validates every output against the INDEPENDENT reference model
readsbo_normalizer.py (split_at_crc / pad_user_to / build_frame / crc_ok) and the
repo's receiver-side StreamReassembler. For each vector we assert:

  SPLIT  * byte-exact reassembly: the master's TCP stack, fed the emitted segments
           by sequence number, reconstructs the ORIGINAL frame (no gap, no conflict);
         * per-segment seq is contiguous (seg1.seq == seg0.seq + len(seg0.payload));
         * the split boundary lands on a real DNP3 CRC-block boundary (subset of
           readsbo_normalizer.split_at_crc);
         * every emitted segment carries a VALID IPv4 AND TCP checksum;
         * the observed per-packet size sequence is the target [68, 76].
  PAD    * the grown frame is byte-identical to build_frame(pad_user_to(real,48));
         * the grown frame is DNP3 CRC-valid (crc_ok) at the target size (64 B);
         * the recorded Delta == added wire bytes; reverse ACK is translated by
           -clamp(ack-b0, 0, Delta) (single-insertion epoch).
  NATIVE * fail-open vectors (non-DNP3, fragment, TCP options, non-owner, wrong
           size) are emitted unchanged, touch no state, and stay checksum-valid.

Then a MUTATION section flips one emulator behavior at a time and proves at least
one named conformance check dies for each mutant (a green count with no mutation
harness is false-green). Pure stdlib. Exit 0 iff baseline passes AND every mutant
is killed. Run: `python3 test_split_conformance.py`.
"""
from __future__ import annotations

import os
import sys
from typing import Callable, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..", "readsbo_normalizer"))

from readsbo_normalizer import build_frame, split_at_crc, pad_user_to, crc_ok, frame_blocks
from stream_reconstruction import StreamReassembler
import p4_split_emulator as E
from p4_split_emulator import SplitPadEmulator, Pkt, POL_SPLIT, POL_PAD, PORT_DNP3, TARGET_USER, mod32

OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613
MPORT = 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)      # normalized (nm_ip, nr_ip, nm_pt, nr_pt)


def block_boundaries(frame: bytes) -> set:
    """Cumulative byte offsets at DNP3 CRC-block boundaries (from split_at_crc)."""
    offs, acc = {0}, 0
    for b in split_at_crc(frame):
        acc += len(b); offs.add(acc)
    return offs


def resp(seq: int, ack: int, user: bytes, **kw) -> Pkt:
    return Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=seq, ack=ack,
               payload=build_frame(0x44, 1, 0, user), **kw)


def rev(seq: int, ack: int, **kw) -> Pkt:
    return Pkt(MAS_IP, OUT_IP, MPORT, PORT_DNP3, seq=seq, ack=ack, payload=b"", **kw)


# --------------------------------------------------------------------------- #
# conformance checks (return list of failure strings)
# --------------------------------------------------------------------------- #
def check_split(fails: List[str], emu: SplitPadEmulator, user: bytes, seq: int) -> None:
    frame = build_frame(0x44, 1, 0, user)
    r = emu.process(resp(seq, 5, user))
    loc = f"SPLIT[len={len(frame)}]"
    if r.outcome != "SPLIT":
        fails.append(f"{loc}: outcome {r.outcome} != SPLIT"); return
    # (1) byte-exact reassembly through the receiver's TCP reassembler
    ra = StreamReassembler(seq)
    for s in r.segs:
        ra.deliver(s.seq, s.payload)
    data, gaps = ra.reconstruct()
    if ra.conflicts:
        fails.append(f"{loc}: reassembly conflicts {ra.conflicts}")
    if gaps:
        fails.append(f"{loc}: reassembly gaps {gaps}")
    if data != frame:
        fails.append(f"{loc}: reassembled stream != original frame")
    # (2) contiguous per-segment seq
    if r.segs[1].seq != mod32(r.segs[0].seq + len(r.segs[0].payload)):
        fails.append(f"{loc}: seq not contiguous ({r.segs[0].seq},{r.segs[1].seq})")
    # (3) boundary on a real CRC-block boundary
    cut = len(r.segs[0].payload)
    if cut not in block_boundaries(frame):
        fails.append(f"{loc}: split boundary {cut} not on a CRC-block boundary")
    # (4) per-segment checksums valid
    if not all(s.ipv4_ok and s.tcp_ok for s in r.segs):
        fails.append(f"{loc}: a segment has an invalid checksum")
    # (5) target per-packet size sequence
    sizes = [s.total_len for s in r.segs]
    if sizes != [68, 76]:
        fails.append(f"{loc}: size sequence {sizes} != [68, 76]")


def check_pad(fails: List[str], emu: SplitPadEmulator, user: bytes, seq: int) -> None:
    small = build_frame(0x44, 1, 0, user)
    r = emu.process(resp(seq, 5, user))
    loc = f"PAD[nuser={len(user)}]"
    if r.outcome != "PAD":
        fails.append(f"{loc}: outcome {r.outcome} != PAD"); return
    grown = r.segs[0].payload
    ref = build_frame(0x44, 1, 0, pad_user_to(user, TARGET_USER))
    if grown != ref:
        fails.append(f"{loc}: grown frame != build_frame(pad_user_to)")
    if not crc_ok(grown):
        fails.append(f"{loc}: grown frame fails DNP3 crc_ok")
    if len(grown) != 64:
        fails.append(f"{loc}: grown size {len(grown)} != 64 (target 3 blocks)")
    if r.delta != len(grown) - len(small):
        fails.append(f"{loc}: delta {r.delta} != {len(grown) - len(small)}")
    if not r.segs[0].tcp_ok or not r.segs[0].ipv4_ok:
        fails.append(f"{loc}: padded segment has an invalid checksum")
    # reverse ACK translation: master acks the whole padded stream -> outstation sees native end
    b0 = seq
    ack_full = mod32(b0 + len(grown))
    rr = emu.process(rev(5, ack_full))
    if rr.out_ack is None or rr.out_ack != mod32(b0 + len(small)):
        fails.append(f"{loc}: reverse ack {rr.out_ack} != {mod32(b0 + len(small))} (native end)")


def check_native(fails: List[str], emu: SplitPadEmulator, p: Pkt, why: str) -> None:
    r = emu.process(p)
    if r.outcome != "NATIVE":
        fails.append(f"NATIVE[{why}]: outcome {r.outcome} != NATIVE")
    elif len(r.segs) != 1 or r.segs[0].payload != p.payload or r.segs[0].seq != p.seq:
        fails.append(f"NATIVE[{why}]: not passed through unchanged")
    elif not (r.segs[0].ipv4_ok and r.segs[0].tcp_ok):
        fails.append(f"NATIVE[{why}]: emitted an invalid checksum")


def run_conformance() -> List[str]:
    fails: List[str] = []

    # ---- SPLIT: 3-block frames (48 user bytes) ----
    for tag in range(3):
        u = bytes([0xC0]) + bytes(((tag * 131 + i * 17) & 0xFF) for i in range(47))
        check_split(fails, SplitPadEmulator(OWNER, POL_SPLIT), u, seq=1000 + tag * 64)

    # ---- PAD: 1-block (16) and 2-block (32) BLOCK-ALIGNED frames grown to 3 blocks ----
    check_pad(fails, SplitPadEmulator(OWNER, POL_PAD), bytes([0xC0]) + bytes(15), seq=2000)
    check_pad(fails, SplitPadEmulator(OWNER, POL_PAD), bytes([0xC0]) + bytes(range(31)), seq=3000)

    # ---- fail-open (NATIVE) ----
    e = SplitPadEmulator(OWNER, POL_SPLIT)
    u3 = bytes([0xC0]) + bytes(47)
    check_native(fails, e, resp(9000, 5, u3, dofs=8), "tcp-options")      # dofs>5
    check_native(fails, e, resp(9100, 5, u3, frag=3), "fragment")        # non-zero frag
    check_native(fails, e, Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=9200, ack=5,
                               payload=b"\x00\x00" + bytes(62)), "non-dnp3")  # no 05 64
    check_native(fails, SplitPadEmulator((1, 2, 3, 4), POL_SPLIT),
                 resp(9300, 5, u3), "non-owner")                          # owner mismatch
    check_native(fails, e, resp(9400, 5, bytes([0xC0]) + bytes(range(60))), "wrong-size")  # 4+ blocks

    return fails


# --------------------------------------------------------------------------- #
# mutation harness: each mutant flips ONE emulator behavior; a mutant that
# SURVIVES (0 conformance failures) is an undefended invariant -> harness fails.
# --------------------------------------------------------------------------- #
def run_mutation() -> Tuple[int, List[str]]:
    survived: List[str] = []
    killed = 0
    orig_grow = E.grow_frame
    orig_w0 = E.W0_PAYLOAD
    orig_fill = E.FILL_BLOCK

    mutations = {
        "M1_window_off_by_one":  lambda: setattr(E, "W0_PAYLOAD", 27),           # boundary off block
        "M2_bad_filler_crc":     lambda: setattr(E, "FILL_BLOCK", bytes(16) + b"\x00\x00"),  # wrong CRC
        "M3_grow_drops_delta":   lambda: setattr(E, "grow_frame",
                                                 lambda f: (orig_grow(f)[0][:-18], orig_grow(f)[1], orig_grow(f)[2])),
        "M4_grow_wrong_len":     lambda: setattr(E, "DL_LEN_TGT", 0x99),         # wrong header LEN byte
    }
    restore = {
        "M1_window_off_by_one":  lambda: setattr(E, "W0_PAYLOAD", orig_w0),
        "M2_bad_filler_crc":     lambda: setattr(E, "FILL_BLOCK", orig_fill),
        "M3_grow_drops_delta":   lambda: setattr(E, "grow_frame", orig_grow),
        "M4_grow_wrong_len":     lambda: setattr(E, "DL_LEN_TGT", 0x35),
    }
    for name, apply_mut in mutations.items():
        apply_mut()
        try:
            f = run_conformance()
        finally:
            restore[name]()
        if f:
            killed += 1
        else:
            survived.append(name)
    return killed, survived


def main() -> int:
    fails = run_conformance()
    n_split = 3
    n_pad = 2
    n_native = 5
    print(f"[corpus]   {n_split} SPLIT + {n_pad} PAD + {n_native} fail-open vectors "
          f"through emulator + reference model + StreamReassembler")
    if fails:
        print(f"\nCONFORMANCE FAIL ({len(fails)}):")
        for x in fails[:40]:
            print("  -", x)
        return 1

    killed, survived = run_mutation()
    total_mut = killed + len(survived)
    print(f"[mutation] {killed}/{total_mut} mutants killed by the conformance checks")
    if survived:
        print("\nMUTATION FAIL — undefended invariants (mutants survived):")
        for s in survived:
            print("  -", s)
        return 1

    print(f"\nPASS: {n_split + n_pad + n_native} vectors conform to the reference model "
          f"(byte-exact split reassembly, per-segment seq + checksums, PAD == build_frame, "
          f"reverse-ACK epoch, fail-open native), {killed}/{total_mut} mutants killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
