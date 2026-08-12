#!/usr/bin/env python3
"""Conformance + mutation harness for defense4_joint_size_time_kernel.p4 via the
ingress -> hold-ring -> deadline-release -> egress-split fixture.

Asserts the JOINT behaviour the silicon run needed and the isolated egress emulator
could not see:

  * SAME PATH, NO TYPE BRANCH: a 49 B READ response and a 49 B SBO echo (same size,
    different DNP3 content) both fire the single predicate, are HELD to the deadline D,
    and are split to the identical vector [28, 21] byte-exact (join == frame). The two
    traces are structurally identical.
  * RELEASED, NOT DROPPED: every shaped response reaches the master (released=True).
    (This is the exact regression: the broken splitter held the response and never
    released it -> 0-byte response on silicon.)
  * SPLIT FIRES ONLY ON THE RELEASE PASS: never on a loopback/hold pass (bypass_egress=1
    passes never reach egress). Exactly one split event per shaped response.
  * TIMING PRESERVED: held_passes == D in timing mode; 0 in OFF (immediate release).
  * FAIL-OPEN: a non-49 B response, a non-owner flow, SYN/RST, or TCP options are
    forwarded native — not held, not split.
  * per-window IPv4/TCP checksums valid.

Then a MUTATION section reintroduces the silicon bug (never release), a split-on-hold
bug, a type-branch bug, and a wrong-vector bug, and proves each is killed. Exit 0 iff
baseline passes AND every mutant is killed. Pure stdlib.
"""
from __future__ import annotations

import os
import sys
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import joint_size_time_emulator as J
from joint_size_time_emulator import JointSizeTimeFixture, read_frame_49, sbo_frame_49
from crc_split_emulator import Pkt, build_frame, PORT_DNP3

OUT_IP, MAS_IP, MPORT = 0x0A0A360A, 0x0A0A3613, 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)
D = 4


def resp(frame, seq=1000, **kw):
    return Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=seq, ack=5, payload=frame, **kw)


def _shaped_checks(fails: List[str], tag: str, r) -> None:
    if not r.shaped:
        fails.append(f"{tag}: predicate did not fire (do_shape=0)")
    if not r.released:
        fails.append(f"{tag}: response NOT released (the silicon drop regression)")
    if r.held_passes != D:
        fails.append(f"{tag}: held {r.held_passes} passes != deadline {D}")
    # segs on the release pass must be carved Seg windows; a Pkt here means the shape
    # was (wrongly) skipped and the response went out native — a real failure, not a crash.
    sizes = [getattr(s, "total_len", None) for s in r.segs]
    if sizes != [68, 61]:
        fails.append(f"{tag}: split vector {sizes} != [68,61] (payloads [28,21])")
    n_split = sum(1 for _, s in r.trace if s)
    if n_split != 1:
        fails.append(f"{tag}: split fired {n_split} times (must be exactly once, on release)")
    for loc, fired in r.trace:
        if fired and "loopback" in loc:
            fails.append(f"{tag}: split fired on a HOLD pass ({loc}) — never on the ring")
    if not all(getattr(s, "ipv4_ok", False) and getattr(s, "tcp_ok", False) for s in r.segs):
        fails.append(f"{tag}: a window has an invalid checksum")


def run_conformance() -> List[str]:
    fails: List[str] = []
    fx = JointSizeTimeFixture(OWNER, deadline_passes=D, mode="timing")

    read_f, sbo_f = read_frame_49(), sbo_frame_49()
    r_read = fx.run(resp(read_f))
    r_sbo = fx.run(resp(sbo_f))
    _shaped_checks(fails, "READ-49", r_read)
    _shaped_checks(fails, "SBO-49", r_sbo)

    # SAME PATH, NO TYPE BRANCH: the two traces are structurally identical
    if [loc for loc, _ in r_read.trace] != [loc for loc, _ in r_sbo.trace]:
        fails.append("READ and SBO took DIFFERENT code paths (a type branch leaked in)")
    if b"".join(s.payload for s in r_read.segs) != read_f:
        fails.append("READ reassembly != original frame")
    if b"".join(s.payload for s in r_sbo.segs) != sbo_f:
        fails.append("SBO reassembly != original frame")

    # OFF mode: immediate release (no hold), still split
    off = JointSizeTimeFixture(OWNER, deadline_passes=D, mode="off")
    r_off = off.run(resp(read_f))
    if r_off.held_passes != 0 or not r_off.released or [s.total_len for s in r_off.segs] != [68, 61]:
        fails.append(f"OFF mode: expected immediate release + split, got held={r_off.held_passes}")

    # FAIL-OPEN (not shaped -> native forward, no hold, no split)
    def native_ok(tag, p):
        r = fx.run(p)
        if r.shaped or r.held_passes != 0 or sum(1 for _, s in r.trace if s) != 0:
            fails.append(f"NATIVE[{tag}]: was shaped/held/split (should pass through)")
    native_ok("wrong-size", resp(build_frame(0x44, 1, 0, bytes([0xC0]) + bytes(range(47)))))  # 64B
    native_ok("syn", resp(read_f, syn=True))
    native_ok("tcp-options", resp(read_f, dofs=8))
    # non-owner needs its own fixture (owner mismatch)
    r_no = JointSizeTimeFixture((1, 2, 3, 4), D).run(resp(read_f))
    if r_no.shaped:
        fails.append("NATIVE[non-owner]: shaped a non-owner flow")
    return fails


def run_mutation() -> Tuple[int, List[str]]:
    survived, killed = [], 0
    orig_run = JointSizeTimeFixture.run
    orig_doshape = JointSizeTimeFixture.do_shape

    def m_no_release(self, p):                     # the silicon bug: held, never released
        r = orig_run(self, p)
        if r.shaped:
            r.released = False
            r.segs = []
        return r

    def m_split_on_hold(self, p):                  # split leaks onto a loopback pass
        r = orig_run(self, p)
        if r.shaped and len(r.trace) > 1:
            loc, _ = r.trace[0]
            r.trace[0] = (loc, True)
        return r

    def m_type_branch(self, p):                    # do_shape depends on DNP3 content
        base = orig_doshape(self, p)               # payload[11] differs: READ=1, SBO=200
        return base and (len(p.payload) > 11 and p.payload[11] < 0x80)

    def m_wrong_vector(self, p):                   # cut moved off the [28,21] target
        self.egress.cut = 46                       # the split reads self.egress.cut
        return orig_run(self, p)

    muts = {
        "M1_never_release (silicon bug)": ("run", m_no_release),
        "M2_split_on_hold_pass": ("run", m_split_on_hold),
        "M3_type_branch": ("do_shape", m_type_branch),
        "M4_wrong_split_vector": ("run", m_wrong_vector),
    }
    for name, (attr, fn) in muts.items():
        setattr(JointSizeTimeFixture, attr, fn)
        try:
            f = run_conformance()
        finally:
            JointSizeTimeFixture.run = orig_run
            JointSizeTimeFixture.do_shape = orig_doshape
        if f:
            killed += 1
        else:
            survived.append(name)
    return killed, survived


def main() -> int:
    fails = run_conformance()
    print("[fixture]  ingress -> hold-ring(D) -> deadline-release -> split; READ+SBO 49B, "
          "OFF-mode, 4 fail-open vectors")
    if fails:
        print(f"\nCONFORMANCE FAIL ({len(fails)}):")
        for x in fails[:40]:
            print("  -", x)
        return 1
    killed, survived = run_mutation()
    print(f"[mutation] {killed}/{killed + len(survived)} mutants killed "
          "(incl. the never-release silicon regression)")
    if survived:
        print("MUTATION FAIL — survived:", survived)
        return 1
    print("\nPASS: joint size+time — READ 49B and SBO 49B take the SAME type-agnostic path, "
          "held to D, released (not dropped), split to [28,21] byte-exact; split fires only on "
          "the release pass; fail-open native; all mutants killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
