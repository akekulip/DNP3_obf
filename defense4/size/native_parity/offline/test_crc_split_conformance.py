#!/usr/bin/env python3
"""Conformance + mutation harness for defense4_crc_split_kernel.p4 (via its emulator).

Runs a packet-vector corpus through the P4 behavioral emulator (crc_split_emulator)
and validates every output against the INDEPENDENT reference model
readsbo_normalizer.py (build_frame / frame_blocks / crc_ok / split_at_crc) and a
receiver-side TCP StreamReassembler. This is the byte-preserving native-parity
splitter, so the invariants are (from defense4/dir.md "Splitter"):

  SPLIT   * byte-exact reassembly: the master's TCP stack, fed the emitted segments
            by sequence number, reconstructs the ORIGINAL frame (no gap, no conflict);
          * per-segment seq is contiguous (seg1.seq == seg0.seq + len(seg0.payload));
          * the split boundary lands on a real DNP3 CRC-block boundary (a subset of
            readsbo_normalizer.split_at_crc);
          * ACK number and window are preserved on BOTH segments;
          * PSH and FIN appear ONLY on the final segment (cleared on the earlier);
          * every emitted segment carries a VALID IPv4 AND TCP checksum, and fits MTU;
          * READ and SBO of the same size S emit the identical segment vector.
  NATIVE  * fail-open vectors (reverse dir, non-owner, wrong port, TCP options,
            fragment, SYN, RST, short/coalesced/partial/unrecognized size) are
            emitted unchanged, touch no state, and stay checksum-valid.
  RETX    * an exact native retransmission regenerates an identical pair of segments;
          * losing either generated segment + a retransmit regenerates deterministically
            and the receiver deduplicates by sequence number (no conflict, no gap);
          * a differently-segmented / partial retransmission passes native and still
            reassembles consistently (byte-preserving, never corrupts the stream).

Then a MUTATION section breaks ONE behavior at a time (bad offset, uncleared PSH/FIN,
un-offset seq, dropped byte, corrupted checksum, wrong length) and proves at least one
named conformance check dies for each mutant — a green count with no mutation harness
is false-green. Pure stdlib. Exit 0 iff baseline passes AND every mutant is killed.
Run: `python3 test_crc_split_conformance.py`.
"""
from __future__ import annotations

import os
import struct
import sys
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "..", "..", "readsbo_normalizer"))

# INDEPENDENT reference model (separately authored)
from readsbo_normalizer import build_frame as ref_build_frame, split_at_crc, crc_ok, frame_blocks
import crc_split_emulator as E
from crc_split_emulator import (
    CrcSplitEmulator, Pkt, Result, Seg, POL_SPLIT, PORT_DNP3, MTU,
    CUT_28, CUT_46, mod32, block_boundaries, wire, verify_checksums, _mkseg,
)

OUT_IP, MAS_IP = 0x0A0A360A, 0x0A0A3613
MPORT = 40000
OWNER = (MAS_IP, OUT_IP, MPORT, PORT_DNP3)      # normalized (nm_ip, nr_ip, nm_pt, nr_pt)


# --------------------------------------------------------------------------- #
# receiver-side TCP reassembly (dedup by absolute sequence offset)
# --------------------------------------------------------------------------- #
class StreamReassembler:
    def __init__(self, isn: int):
        self.isn = isn
        self.buf: Dict[int, int] = {}
        self.conflicts: List[Tuple[int, int, int]] = []

    def deliver(self, seq: int, data: bytes) -> None:
        off = mod32(seq - self.isn)
        for i, b in enumerate(data):
            p = off + i
            if p in self.buf and self.buf[p] != b:
                self.conflicts.append((p, self.buf[p], b))
            self.buf[p] = b

    def reconstruct(self) -> Tuple[bytes, List[int]]:
        if not self.buf:
            return b"", []
        hi = max(self.buf) + 1
        gaps = [p for p in range(hi) if p not in self.buf]
        return bytes(self.buf.get(p, 0) for p in range(hi)), gaps


def resp(seq: int, ack: int, user: bytes, **kw) -> Pkt:
    return Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=seq, ack=ack,
               payload=ref_build_frame(0x44, 1, 0, user), **kw)


def rev(seq: int, ack: int, **kw) -> Pkt:
    return Pkt(MAS_IP, OUT_IP, MPORT, PORT_DNP3, seq=seq, ack=ack, payload=b"", **kw)


# --------------------------------------------------------------------------- #
# conformance checks (return list of failure strings)
# --------------------------------------------------------------------------- #
def check_split(fails: List[str], r: Result, p: Pkt, cut: int, loc: str) -> None:
    frame = p.payload
    if r.outcome != "SPLIT" or len(r.segs) != 2:
        fails.append(f"{loc}: outcome {r.outcome} / {len(r.segs)} segs != SPLIT/2"); return
    s0, s1 = r.segs
    # (1) byte-exact reassembly through a receiver TCP reassembler
    ra = StreamReassembler(p.seq)
    for s in r.segs:
        ra.deliver(s.seq, s.payload)
    data, gaps = ra.reconstruct()
    if ra.conflicts:
        fails.append(f"{loc}: reassembly conflicts {ra.conflicts[:3]}")
    if gaps:
        fails.append(f"{loc}: reassembly gaps {gaps[:5]}")
    if data != frame:
        fails.append(f"{loc}: reassembled stream != original frame")
    # (2) contiguous per-segment seq
    if s1.seq != mod32(s0.seq + len(s0.payload)):
        fails.append(f"{loc}: seq not contiguous ({s0.seq},{s1.seq})")
    if s0.seq != mod32(p.seq):
        fails.append(f"{loc}: window0 seq {s0.seq} != base {mod32(p.seq)}")
    # (3) boundary lands on a real DNP3 CRC-block boundary (subset of split_at_crc)
    boundary = len(s0.payload)
    ref_offs = {0}; acc = 0
    for b in split_at_crc(frame):
        acc += len(b); ref_offs.add(acc)
    if boundary not in ref_offs or boundary != cut:
        fails.append(f"{loc}: split boundary {boundary} not a CRC-block boundary/{cut}")
    # (4) ACK number + window preserved on BOTH segments
    for s in r.segs:
        if s.ack != mod32(p.ack):
            fails.append(f"{loc}: {s.kind} ack {s.ack} != {mod32(p.ack)}")
        if s.win != p.win:
            fails.append(f"{loc}: {s.kind} win {s.win} != {p.win}")
    # (5) PSH(0x08)+FIN(0x01) ONLY on the final segment
    if (s0.flags & 0x09) != 0:
        fails.append(f"{loc}: window0 flags {hex(s0.flags)} still carry PSH/FIN")
    if (s1.flags & 0x08) != (p.flags_byte() & 0x08) or (s1.flags & 0x01) != (p.flags_byte() & 0x01):
        fails.append(f"{loc}: window1 flags {hex(s1.flags)} lost PSH/FIN vs {hex(p.flags_byte())}")
    # (6) valid checksums + MTU
    for s in r.segs:
        if not (s.ipv4_ok and s.tcp_ok):
            fails.append(f"{loc}: {s.kind} invalid checksum (ip={s.ipv4_ok} tcp={s.tcp_ok})")
        if len(s.wire) > MTU:
            fails.append(f"{loc}: {s.kind} wire {len(s.wire)} exceeds MTU")


def check_native(fails: List[str], emu: CrcSplitEmulator, p: Pkt, why: str) -> None:
    r = emu.process(p)
    if r.outcome != "NATIVE":
        fails.append(f"NATIVE[{why}]: outcome {r.outcome} != NATIVE")
    elif len(r.segs) != 1 or r.segs[0].payload != p.payload or r.segs[0].seq != mod32(p.seq):
        fails.append(f"NATIVE[{why}]: not passed through unchanged")
    elif not (r.segs[0].ipv4_ok and r.segs[0].tcp_ok):
        fails.append(f"NATIVE[{why}]: emitted an invalid checksum")


# corpus of splittable frames: (user_bytes, cut) with the target vectors from dir.md
def split_vectors() -> List[Tuple[bytes, int, List[int]]]:
    return [
        (bytes([0xC0]) + bytes(range(32)), CUT_28, [28, 21]),   # S=49 -> [28,21]
        (bytes([0xC0]) + bytes(range(44)), CUT_28, [28, 33]),   # S=61 -> [28,33]
        (bytes([0xC0]) + bytes(range(44)), CUT_46, [46, 15]),   # S=61 -> [46,15]
        (bytes([0xC0]) + bytes(range(47)), CUT_28, [28, 36]),   # S=64 -> [28,36]
        (bytes([0xC0]) + bytes(range(31)), CUT_28, [28, 18]),   # S=46 -> [28,18]
    ]


def run_conformance() -> List[str]:
    fails: List[str] = []

    # ---- SPLIT: the target vectors, checked against the reference model + reassembler ----
    for user, cut, want in split_vectors():
        emu = CrcSplitEmulator(OWNER, POL_SPLIT, cut=cut)
        p = resp(1000, 5, user)
        r = emu.process(p)
        loc = f"SPLIT[S={len(p.payload)},cut={cut}]"
        check_split(fails, r, p, cut, loc)
        got = [len(s.payload) for s in r.segs]
        if got != want:
            fails.append(f"{loc}: payload vector {got} != {want}")

    # ---- FIN placement: an outstation that closes after the response ----
    emu = CrcSplitEmulator(OWNER, POL_SPLIT, cut=CUT_28)
    pf = resp(1000, 5, bytes([0xC0]) + bytes(range(44)), fin=True)
    rf = emu.process(pf)
    check_split(fails, rf, pf, CUT_28, "SPLIT[FIN]")
    if rf.outcome == "SPLIT" and (rf.segs[1].flags & 0x01) != 0x01:
        fails.append("SPLIT[FIN]: FIN not carried on the final segment")

    # ---- READ / SBO parity: same S, same cut -> identical segment vector ----
    read_u = bytes([0xC0]) + bytes(range(44))
    sbo_u = bytes([0xC0]) + bytes([0xFF]) * 44
    er = CrcSplitEmulator(OWNER, POL_SPLIT, cut=CUT_28)
    rr = er.process(resp(2000, 5, read_u))
    rs = er.process(resp(2000, 5, sbo_u))
    if [len(s.payload) for s in rr.segs] != [len(s.payload) for s in rs.segs]:
        fails.append("PARITY: READ and SBO of the same size produce different vectors")

    # ---- invalid CRC: split is byte-preserving and CRC-agnostic (reassembly == input) ----
    bad = bytearray(ref_build_frame(0x44, 1, 0, bytes([0xC0]) + bytes(range(44))))
    bad[30] ^= 0xFF                                   # corrupt a data-block byte (size unchanged)
    pbad = Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=1000, ack=5, payload=bytes(bad))
    rb = CrcSplitEmulator(OWNER, POL_SPLIT, cut=CUT_28).process(pbad)
    if rb.outcome == "SPLIT":
        ra = StreamReassembler(1000)
        for s in rb.segs:
            ra.deliver(s.seq, s.payload)
        data, gaps = ra.reconstruct()
        if data != bytes(bad) or gaps or ra.conflicts:
            fails.append("INVALID_CRC: byte-preservation broken on a bad-CRC frame")

    # ---- out-of-order delivery still reassembles ----
    emu = CrcSplitEmulator(OWNER, POL_SPLIT, cut=CUT_28)
    p = resp(1000, 5, bytes([0xC0]) + bytes(range(44)))
    r = emu.process(p)
    if r.outcome == "SPLIT":
        ra = StreamReassembler(1000)
        for s in reversed(r.segs):                    # window1 first
            ra.deliver(s.seq, s.payload)
        data, gaps = ra.reconstruct()
        if data != p.payload or gaps or ra.conflicts:
            fails.append("OUT_OF_ORDER: reassembly failed with reversed delivery")

    # ---- exact retransmission -> identical pair (deterministic, stateless) ----
    r2 = emu.process(p)
    if [(s.seq, s.payload, s.flags) for s in r.segs] != [(s.seq, s.payload, s.flags) for s in r2.segs]:
        fails.append("RETX_EXACT: retransmission produced a different segment pair")

    # ---- loss of window1 + retransmit: dedup by seq, receiver recovers ----
    if r.outcome == "SPLIT":
        ra = StreamReassembler(1000)
        ra.deliver(r.segs[0].seq, r.segs[0].payload)  # window0 arrives; window1 lost
        rre = emu.process(p)                          # TCP retransmits the original -> same pair
        for s in rre.segs:                            # both arrive on retransmit
            ra.deliver(s.seq, s.payload)
        data, gaps = ra.reconstruct()
        if data != p.payload or gaps or ra.conflicts:
            fails.append("LOSS_RECOVERY: window1 loss + retransmit did not recover cleanly")

    # ---- differently-segmented retransmission passes native, reassembles consistently ----
    if r.outcome == "SPLIT":
        ra = StreamReassembler(1000)
        for s in r.segs:
            ra.deliver(s.seq, s.payload)              # original split delivered
        # a retransmit of only the first CRC block as an unrecognized-size native packet
        first_block = p.payload[:10]                  # header block only -> not splittable
        pn = Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=1000, ack=5, payload=first_block)
        rn = emu.process(pn)
        if rn.outcome != "NATIVE":
            fails.append("RETX_PARTIAL: partial retransmit was not passed native")
        else:
            ra.deliver(rn.segs[0].seq, rn.segs[0].payload)
            data, gaps = ra.reconstruct()
            if data != p.payload or gaps or ra.conflicts:
                fails.append("RETX_PARTIAL: partial native retransmit corrupted the stream")

    # ---- fail-open (NATIVE) battery ----
    e = CrcSplitEmulator(OWNER, POL_SPLIT, cut=CUT_28)
    u3 = bytes([0xC0]) + bytes(range(44))                                     # a normal S=61
    check_native(fails, e, resp(9000, 5, u3, dofs=8), "tcp-options")         # dofs>5
    check_native(fails, e, resp(9100, 5, u3, frag=3), "fragment")           # frag != 0
    check_native(fails, e, resp(9110, 5, u3, mf=1), "mf-set")               # more-fragments
    check_native(fails, e, resp(9120, 5, u3, syn=True), "syn")             # SYN
    check_native(fails, e, resp(9130, 5, u3, rst=True), "rst")             # RST (conservative)
    check_native(fails, e, rev(9200, 5), "reverse-dir")                     # master->outstation
    check_native(fails, e, Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=9300, ack=5,
                               payload=b"\x00\x00" + bytes(59)), "non-dnp3")  # no 05 64
    check_native(fails, CrcSplitEmulator((1, 2, 3, 4), POL_SPLIT, cut=CUT_28),
                 resp(9400, 5, u3), "non-owner")                             # owner mismatch
    check_native(fails, e, resp(9500, 5, bytes([0xC0]) + bytes(15)), "short-1block")  # S=28
    check_native(fails, e, resp(9600, 5, bytes([0xC0]) + bytes(range(60))), "oversize")  # 5 blocks
    # coalesced: two S=61 responses back to back -> total_len unrecognized
    coalesced = ref_build_frame(0x44, 1, 0, u3) + ref_build_frame(0x44, 1, 0, u3)
    check_native(fails, e, Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=9700, ack=5,
                               payload=coalesced), "coalesced")
    # split-across-packets: only the first data block delivered (partial frame)
    check_native(fails, e, Pkt(OUT_IP, MAS_IP, PORT_DNP3, MPORT, seq=9800, ack=5,
                               payload=ref_build_frame(0x44, 1, 0, u3)[:28]), "partial-frame")
    # wrong port (outstation not on the DNP3 port for this flow) -> reverse-normalized, non-owner
    check_native(fails, e, Pkt(OUT_IP, MAS_IP, 12345, MPORT, seq=9900, ack=5,
                               payload=ref_build_frame(0x44, 1, 0, u3)), "wrong-port")

    return fails


# --------------------------------------------------------------------------- #
# mutation harness: each mutant breaks ONE behavior; a mutant that SURVIVES
# (0 conformance failures on a splittable vector) is an undefended invariant.
# --------------------------------------------------------------------------- #
def _base_split() -> Tuple[Pkt, int]:
    user = bytes([0xC0]) + bytes(range(44))          # S=61
    return resp(1000, 5, user), CUT_28


def _mutate(name: str) -> Result:
    """Produce a deliberately-broken split of the base vector."""
    p, cut = _base_split()
    f = p.payload
    base = p.flags_byte()
    if name == "M1_boundary_off_by_one":
        c = cut - 1                                  # not a CRC-block boundary
        s0 = _mkseg(p, p.seq, f[:c], base & 0xF6, "WINDOW0")
        s1 = _mkseg(p, mod32(p.seq + c), f[c:], base, "WINDOW1")
    elif name == "M2_psh_fin_not_cleared":
        s0 = _mkseg(p, p.seq, f[:cut], base, "WINDOW0")   # PSH kept on window0
        s1 = _mkseg(p, mod32(p.seq + cut), f[cut:], base, "WINDOW1")
    elif name == "M3_seq_not_offset":
        s0 = _mkseg(p, p.seq, f[:cut], base & 0xF6, "WINDOW0")
        s1 = _mkseg(p, p.seq, f[cut:], base, "WINDOW1")   # window1 seq == base
    elif name == "M4_drop_byte":
        s0 = _mkseg(p, p.seq, f[:cut], base & 0xF6, "WINDOW0")
        s1 = _mkseg(p, mod32(p.seq + cut), f[cut + 1:], base, "WINDOW1")  # 1 byte lost
    elif name == "M5_bad_checksum":
        s0 = _mkseg(p, p.seq, f[:cut], base & 0xF6, "WINDOW0")
        s1 = _mkseg(p, mod32(p.seq + cut), f[cut:], base, "WINDOW1")
        w = bytearray(s1.wire); w[16 + 14 + 20 - 4] ^= 0xFF                # corrupt TCP csum area
        ip_ok, tcp_ok = verify_checksums(bytes(w))
        s1 = Seg(s1.seq, s1.payload, s1.total_len, s1.flags, s1.ack, s1.win, bytes(w), ip_ok, tcp_ok, s1.kind)
    elif name == "M6_ack_not_preserved":
        s0 = _mkseg(p, p.seq, f[:cut], base & 0xF6, "WINDOW0")
        s1 = _mkseg(p, mod32(p.seq + cut), f[cut:], base, "WINDOW1")
        s1 = Seg(s1.seq, s1.payload, s1.total_len, s1.flags, mod32(s1.ack + 7), s1.win, s1.wire, s1.ipv4_ok, s1.tcp_ok, s1.kind)
    else:
        raise ValueError(name)
    return Result("SPLIT", [s0, s1])


def run_mutation() -> Tuple[int, List[str]]:
    p, cut = _base_split()
    mutants = ["M1_boundary_off_by_one", "M2_psh_fin_not_cleared", "M3_seq_not_offset",
               "M4_drop_byte", "M5_bad_checksum", "M6_ack_not_preserved"]
    survived, killed = [], 0
    for name in mutants:
        fails: List[str] = []
        check_split(fails, _mutate(name), p, cut, f"MUT[{name}]")
        if fails:
            killed += 1
        else:
            survived.append(name)
    return killed, survived


def main() -> int:
    fails = run_conformance()
    print("[corpus]   5 SPLIT target vectors + FIN + parity + invalid-CRC + out-of-order")
    print("           + retransmit(exact/loss/partial) + 13 fail-open, vs reference model")
    if fails:
        print(f"\nCONFORMANCE FAIL ({len(fails)}):")
        for x in fails[:40]:
            print("  -", x)
        return 1

    killed, survived = run_mutation()
    total = killed + len(survived)
    print(f"[mutation] {killed}/{total} mutants killed by the conformance checks")
    if survived:
        print("\nMUTATION FAIL — undefended invariants (mutants survived):")
        for s in survived:
            print("  -", s)
        return 1

    print(f"\nPASS: byte-exact split reassembly, seq offsets, ACK/window preserved, "
          f"PSH/FIN only-last, valid IPv4+TCP checksums, READ/SBO parity, fail-open "
          f"native, deterministic retransmit + loss recovery; {killed}/{total} mutants killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
