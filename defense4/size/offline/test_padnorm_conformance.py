#!/usr/bin/env python3
"""Conformance + mutation harness for defense4_padnorm_kernel.p4 (via its emulator).

Validates the v2 PAD-normalization egress against the INDEPENDENT reference model
readsbo_normalizer.py. For the two MEASURED SEL-751 response sizes it asserts:

  * the grown frame is byte-identical to build_frame(pad_user_to(real_user, 48));
  * the grown frame is DNP3 CRC-valid (crc_ok) at exactly 64 B on-wire;
  * the recorded Delta == the intended per-response delta (READ +24, SBO +15);
  * the padded segment carries valid IPv4 + TCP checksums;
  * reverse ACK is translated by -clamp(ack-b0, 0, Delta).

and fail-open (non-owner, wrong size, TCP options) is passed native unchanged, plus
the SINGLE-INSERTION wall is demonstrated (a second response on the same flow is NOT
padded). A mutation section flips one emulator behavior at a time and proves at least
one named check dies for each. Exit 0 iff baseline passes AND every mutant is killed.
"""
from __future__ import annotations

import os
import sys
from typing import List, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..", "readsbo_normalizer"))

from readsbo_normalizer import build_frame, pad_user_to, crc_ok, frame_user, link_wire_len
import p4_padnorm_emulator as E
from p4_padnorm_emulator import PadNormEmulator, Pkt, PORT_DNP3, TARGET_USER, mod32

OUT_IP, MAS_IP, MPORT = 0x0A0A360A, 0x0A0A3613, 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)


def frame_of(onwire: int) -> bytes:
    u = next(n for n in range(1, 60) if link_wire_len(n) == onwire)
    return build_frame(0x44, 1, 0, bytes([0xC0]) + bytes(u - 1))


def resp(seq, frame, **kw):
    return Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=seq, ack=5, payload=frame, **kw)


def rev(seq, ack, **kw):
    return Pkt(MAS_IP, OUT_IP, MPORT, PORT_DNP3, seq=seq, ack=ack, payload=b"", **kw)


def check_pad(fails: List[str], onwire: int, want_delta: int, seq: int) -> None:
    frame = frame_of(onwire)
    e = PadNormEmulator(OWNER, pad_on=True)
    r = e.process(resp(seq, frame))
    loc = f"PAD[{onwire}B]"
    if r.outcome != "PAD":
        fails.append(f"{loc}: outcome {r.outcome} != PAD"); return
    grown = r.segs[0].payload
    ref = build_frame(0x44, 1, 0, pad_user_to(frame_user(frame), TARGET_USER))
    if grown != ref:
        fails.append(f"{loc}: grown != build_frame(pad_user_to)")
    if not crc_ok(grown):
        fails.append(f"{loc}: grown fails DNP3 crc_ok")
    if len(grown) != 64:
        fails.append(f"{loc}: grown size {len(grown)} != 64")
    if r.delta != want_delta:
        fails.append(f"{loc}: delta {r.delta} != {want_delta}")
    if not (r.segs[0].ipv4_ok and r.segs[0].tcp_ok):
        fails.append(f"{loc}: invalid checksum on padded segment")
    # reverse ack: master acks the whole padded stream -> outstation sees native end
    b0 = seq
    rr = e.process(rev(5, mod32(b0 + len(grown))))
    if rr.out_ack != mod32(b0 + onwire):
        fails.append(f"{loc}: reverse ack {rr.out_ack} != native end {mod32(b0 + onwire)}")


def check_native(fails: List[str], e: PadNormEmulator, p: Pkt, why: str) -> None:
    r = e.process(p)
    if r.outcome != "NATIVE" or r.segs[0].payload != p.payload or r.segs[0].seq != p.seq:
        fails.append(f"NATIVE[{why}]: not passed through unchanged (outcome {r.outcome})")
    elif not (r.segs[0].ipv4_ok and r.segs[0].tcp_ok):
        fails.append(f"NATIVE[{why}]: invalid checksum")


def check_single_insertion(fails: List[str]) -> None:
    """A second forward response on the same flow is NOT padded (documented wall)."""
    e = PadNormEmulator(OWNER, pad_on=True)
    r1 = e.process(resp(1000, frame_of(40)))
    r2 = e.process(resp(1000 + 64, frame_of(49)))
    if r1.outcome != "PAD":
        fails.append("single-insertion: first response not padded")
    if r2.outcome != "NATIVE":
        fails.append("single-insertion: second response was padded (epoch should be closed)")


def run_conformance() -> List[str]:
    fails: List[str] = []
    check_pad(fails, 40, 24, seq=1000)     # READ
    check_pad(fails, 49, 15, seq=2000)     # SBO
    check_single_insertion(fails)
    e = PadNormEmulator(OWNER, pad_on=True)
    check_native(fails, e, resp(3000, frame_of(40), dofs=8), "tcp-options")
    check_native(fails, e, resp(3100, frame_of(40), frag=3), "fragment")
    check_native(fails, e, resp(3200, build_frame(0x44, 1, 0, bytes([0xC0]) + bytes(60))), "wrong-size")
    check_native(fails, PadNormEmulator((1, 2, 3, 4), True), resp(3300, frame_of(49)), "non-owner")
    return fails


def run_mutation() -> Tuple[int, List[str]]:
    survived, killed = [], 0
    orig_recon = E.v2_reconstruct
    orig_map = dict(E.SIZE_MAP)
    muts = {
        "M1_no_zero_fill": lambda: setattr(
            E, "v2_reconstruct", lambda f: orig_recon(f)[:-18] + orig_recon(f)[-18:-2].replace(b"\x00", b"\x11") + orig_recon(f)[-2:]),
        "M2_wrong_delta": lambda: E.SIZE_MAP.__setitem__(80, ("READ", 18)),
        "M3_drop_a_block": lambda: setattr(E, "v2_reconstruct", lambda f: orig_recon(f)[:-18]),
    }
    restore = {
        "M1_no_zero_fill": lambda: setattr(E, "v2_reconstruct", orig_recon),
        "M2_wrong_delta": lambda: (E.SIZE_MAP.clear(), E.SIZE_MAP.update(orig_map)),
        "M3_drop_a_block": lambda: setattr(E, "v2_reconstruct", orig_recon),
    }
    for name, apply_mut in muts.items():
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
    print("[corpus]   2 PAD (READ 40->64, SBO 49->64) + single-insertion + 4 fail-open vectors")
    if fails:
        print(f"\nCONFORMANCE FAIL ({len(fails)}):")
        for x in fails[:40]:
            print("  -", x)
        return 1
    killed, survived = run_mutation()
    print(f"[mutation] {killed}/{killed + len(survived)} mutants killed")
    if survived:
        print("MUTATION FAIL — survived:", survived)
        return 1
    print("\nPASS: v2 PAD-normalization conforms to the reference model "
          "(real 40/49 B -> 64 B byte-exact, CRC-valid, reverse-ACK epoch, "
          "single-insertion wall shown, fail-open native), all mutants killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
