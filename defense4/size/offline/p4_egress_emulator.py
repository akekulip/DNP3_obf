#!/usr/bin/env python3
"""Byte-precise emulator of the defense4_joint.p4 EGRESS Layer-S canonicalizer.

This is NOT a second oracle. It mirrors the *exact* header carving, constant rewrites, and
CRC field-lists that the P4 egress control uses, so that a byte-diff against the real oracle
(canonical_response.canonicalize) proves the P4 decomposition reproduces the ground truth.

The P4 cannot be run without the model/injection harness, so this emulator is the offline
stand-in: every step here maps 1:1 to a P4 statement (annotated), and the P4 is written to
match it line for line. If emulator == oracle for all corpus devices, the P4 logic is correct
modulo faithful P4 translation (which is traced separately).

Egress classes (parser select on dofs/total_len, THEN the parsed DNP3 object header):
  * CLS_RESP_V3       (dofs=5, ip.total_len=94)  -> 54 B DNP3 V3, PASS-THROUGH, delta 0
  * CLS_RESP_V1       (dofs=5, ip.total_len=101) AND object == (G30, V1, qual0, start1)
                       -> the ELIGIBLE 61 B V1 response, SHRINK to 54 B, delta -7
  * CLS_RESP_V1_PASS  (dofs=5, ip.total_len=101) but object != the eligible G30/V1 object
                       -> 61 B V1-LENGTH but NON-eligible (G32, G30-V2, non-DNP3): PASS THROUGH
                          the DNP3 content verbatim, delta bump 0, seq/ack STILL shifted by the
                          flow's accumulated delta.  (matches canonical_response.transform_or_passthrough)
  * CLS_BARE          (dofs=5, ip.total_len=40)  -> pure ACK, seq/ack translate only
  * default: fail open (no rewrite)

The tightening (2026-08-11): the V1 rewrite used to key on LENGTH alone, so a same-length
non-eligible 61 B segment was mis-transformed. The egress parser now gates the shrink on the
parsed object header (grp/var/qual/start at wire offsets 15..18); a non-eligible 61 B segment
passes through byte-identical.  This emulator now diffs the DNP3 CONTENT against the fail-open
CONTRACT canonical_response.transform_or_passthrough, and additionally models reg_delta + the
per-flow seq shift to prove the passthrough keeps the sequence space consistent.
"""
import os
import sys
import struct

_HARNESS = "/home/philip/Projects/DNP3/dnp3_split_harness"
sys.path.insert(0, _HARNESS)
from dnp3_crc import dnp3_crc16                       # the lab CRC-16/DNP (matches P4 CRCPolynomial)
sys.path.insert(0, os.path.dirname(__file__))
import canonical_response as ORACLE

# ---- P4 constants (mirror defense4_joint.p4) ----
G30, VAR3, QUAL00, PUB_STOP = 0x1E, 0x03, 0x00, 0x07


def _crc_emit(block_bytes):
    """P4: c = h.get(...); hdr.crc = c[7:0] ++ c[15:8]  (DNP3 low-octet-first)."""
    c = dnp3_crc16(block_bytes)                        # CRCPolynomial(0x3D65,rev,init0,xor0xFFFF)
    return struct.pack('<H', c)                        # low octet first == c[7:0] ++ c[15:8]


def egress_v1_to_v3(frame):
    """CLS_RESP_V1 path: parse the 61 B V1 response into the P4's v1b0/v1b1/v1b2 field slices,
    repopulate the canonical V3 blkA/blkB/blkC layout, rewrite var=03/stop=07/len, recompute all
    CRCs, and re-serialize the 54 B frame. Byte offsets are the wire offsets proven from the corpus.
    """
    assert len(frame) == 61, "V1 class is the fixed 7-point [1,7] 61 B corpus response"

    # ---- egress parser: dnp3_dl_h (10 B link header) ----
    dl_start = frame[0:2]                              # hdr.dl.start (0x0564)
    dl_len   = frame[2]                                # hdr.dl.len   (0x32 = 50)  -> rewrite
    dl_ctrl  = frame[3]                                # hdr.dl.ctrl
    dl_dst   = frame[4:6]                              # hdr.dl.dst
    dl_src   = frame[6:8]                              # hdr.dl.src   (preserved residual)
    # frame[8:10] = old link crc (dropped; recomputed)

    # ---- egress parser: v1b0 (block0 data, 16 B) = ud[0:16] ----
    b0 = frame[10:26]
    v_t, v_ac, v_f = b0[0], b0[1], b0[2]              # transport, app_ctrl, func(0x81)
    v_iin = b0[3:5]
    v_grp, v_var, v_qual, v_start, v_stop = b0[5], b0[6], b0[7], b0[8], b0[9]
    # b0[10] = flag0 (stripped)
    val0 = b0[11:15]
    # b0[15] = flag1 (stripped)   -- flag1 belongs to point1 whose value is in block1
    # frame[26:28] = crc0 (dropped)

    # ---- egress parser: v1b1 (block1 data, 16 B) = ud[16:32] ----
    b1 = frame[28:44]
    val1 = b1[0:4]                                     # v1b1.val1
    # b1[4] = flag2
    val2 = b1[5:9]                                     # v1b1.val2
    # b1[9] = flag3
    val3 = b1[10:14]                                   # v1b1.val3
    # b1[14] = flag4
    val4_hi = b1[15:16]                                # v1b1.val4hi (1 byte, straddles crc1)
    # frame[44:46] = crc1 (dropped)

    # ---- egress parser: v1b2 (block2 data, 13 B) = ud[32:45] ----
    b2 = frame[46:59]
    val4_lo = b2[0:3]                                  # v1b2.val4lo (3 bytes)
    # b2[3] = flag5
    val5 = b2[4:8]                                     # v1b2.val5
    # b2[8] = flag6
    val6 = b2[9:13]                                    # v1b2.val6
    # frame[59:61] = crc2 (dropped)

    val4 = val4_hi + val4_lo                           # P4: blkB.v4hi=val4hi ; blkB.v4lo=val4lo

    # ---- egress control: populate canonical V3 blkA (16 B) ----
    # blkA = t ac f iin grp VAR3 qual start STOP7 val0(4) val1[hi16]
    blkA = bytes([v_t, v_ac, v_f]) + v_iin + \
        bytes([v_grp, VAR3, v_qual, v_start, PUB_STOP]) + val0 + val1[0:2]
    assert len(blkA) == 16
    crcA = _crc_emit(blkA)

    # ---- egress control: populate canonical V3 blkB (16 B) ----
    # blkB = val1[lo16] val2(4) val3(4) val4[hi8] val4[lo24] val5[hi16]
    blkB = val1[2:4] + val2 + val3 + val4[0:1] + val4[1:4] + val5[0:2]
    assert len(blkB) == 16
    crcB = _crc_emit(blkB)

    # ---- egress control: populate canonical V3 blkC (6 B) ----
    # blkC = val5[lo16] val6(4)
    blkC = val5[2:4] + val6
    assert len(blkC) == 6
    crcC = _crc_emit(blkC)

    # ---- egress control: rewrite dl.len = 0x2B (const) and recompute the link CRC ----
    # canonical user data = blkA(16)+blkB(16)+blkC(6) = 38 B ; len = 5 + 38 = 43 = 0x2B.
    # The P4 sets hdr.dl.len to this compile-time constant (output size is fixed 54 B).
    LEN_V3 = 5 + (len(blkA) + len(blkB) + len(blkC))            # == 43 = 0x2B
    link_hdr = dl_start + bytes([LEN_V3, dl_ctrl]) + dl_dst + dl_src
    dl_crc = _crc_emit(link_hdr)

    # ---- egress deparser: emit dl + blkA crcA blkB crcB blkC crcC (v1b* NOT emitted) ----
    return link_hdr + dl_crc + blkA + crcA + blkB + crcB + blkC + crcC


def egress_v3_passthrough(frame):
    """CLS_RESP_V3 path: recompute link CRC + block0 CRC (to the same values, since no DNP3 byte
    is changed) and leave blocks 1..2 untouched. delta 0 -> no seq shift. Output == input."""
    assert len(frame) == 54
    dl_start, dl_len, dl_ctrl, dl_dst, dl_src = frame[0:2], frame[2], frame[3], frame[4:6], frame[6:8]
    link_hdr = dl_start + bytes([dl_len, dl_ctrl]) + dl_dst + dl_src
    dl_crc = _crc_emit(link_hdr)                        # P4: h_dlcrc over dl fields
    block0 = frame[10:26]                               # 16 B (unchanged)
    crc0 = _crc_emit(block0)                            # P4: h_blkcrc over db fields
    rest = frame[28:]                                   # blocks 1..2 + crcs, MAU-untouched
    return link_hdr + dl_crc + block0 + crc0 + rest


def v1_eligible(frame):
    """Mirror the egress parser select in state c_resp_v1 (defense4_joint_canon.p4 ~line 726):
    a 61 B V1-length segment is the ELIGIBLE canonical-shrink object ONLY when the parsed object
    header at wire offsets 15..18 is (grp=0x1E, var=0x01, qual=0x00, start=0x01). stop is
    length-implied (61 B => 7 points => stop = start+6), so the P4 select does not test it and
    neither does this mirror. Everything else at 61 B is CLS_RESP_V1_PASS (pass through verbatim)."""
    return (len(frame) == 61
            and (frame[15], frame[16], frame[17], frame[18]) == (0x1E, 0x01, 0x00, 0x01))


def egress_content(frame):
    """The DNP3-content result of the egress Layer-S transform (NOT the seq/ack shift, which is
    modelled separately in EgressFlow). Mirrors the class decode + the eligibility gate:
      * 61 B eligible  -> egress_v1_to_v3  (CLS_RESP_V1, the -7 shrink)
      * 61 B NON-elig  -> verbatim         (CLS_RESP_V1_PASS: fills/CRC skipped, v1b/v1c emitted)
      * 54 B           -> egress_v3_passthrough (CLS_RESP_V3)
      * otherwise      -> verbatim (fail open)."""
    n = len(frame)
    if n == 61:
        return egress_v1_to_v3(frame) if v1_eligible(frame) else bytes(frame)
    if n == 54:
        return egress_v3_passthrough(frame)
    return bytes(frame)


def _to_i32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


class EgressFlow:
    """Byte-precise model of the P4 out-direction (outstation->master) reg_delta + seq rewrite for
    ONE flow, no retransmits. Mirrors defense4_joint_canon.p4:
      * reg_delta access (~L881): CLS_RESP_V1 (eligible) -> delta_bump_v1 (returns delta_old, v+=-7);
        every other class (V3, CLS_RESP_V1_PASS, ACK) -> delta_read (returns v, no change).
      * seq addend (~L891): m.seq_add = m.delta (delta_old on a fresh eligible response, the accumulated
        delta on a passthrough / V3).  seq += seq_add (~L905, condition now includes CLS_RESP_V1_PASS)."""
    def __init__(self):
        self.delta = 0                         # reg_delta, signed two's-complement byte offset

    def out(self, frame, seq):
        content = egress_content(frame)
        seq_add = self.delta                   # delta_read value / delta_old (pre-bump) — the accumulated Δ
        if v1_eligible(frame):                 # delta_bump_v1: returns delta_old (already captured), then -7
            self.delta = _to_i32(self.delta - 7)
        # CLS_RESP_V1_PASS and V3: delta_read, so self.delta is UNCHANGED here.
        seq_out = (seq + seq_add) & 0xFFFFFFFF
        return content, seq_out


def _build_noneligible_61B(corpus):
    """The three same-LENGTH non-eligible 61 B segments, built EXACTLY as canonical_response.py's
    self-test builds them, so the P4 gate is checked against the identical fail-open parity inputs."""
    ion = corpus["ion7550"][1]
    ic, idst, isrc, iud = ORACLE._strip_blocks(ion)
    g32_61 = ORACLE._reframe(ic, idst, isrc, iud[:5] + b'\x20' + iud[6:])   # 61 B, G30->G32 (valid CRC)
    v2_61 = ORACLE._reframe(ic, idst, isrc, iud[:6] + b'\x02' + iud[7:])    # 61 B, G30 V1->V2 (valid CRC)
    nondnp61 = b'\xaa' * len(ion)                                          # 61 B non-DNP3 blob
    for f in (g32_61, v2_61, nondnp61):
        assert len(f) == 61, "non-eligible parity inputs must share the V1 length class"
    return g32_61, v2_61, nondnp61


def main():
    corpus = ORACLE._load_corpus()
    checks = []

    # ---- 1. the real devices: DNP3 content must match transform_or_passthrough (== canonicalize, eligible) ----
    print("%-20s %-28s %-8s %-8s %s" % ("case", "class", "p4_len", "oracle", "delta"))
    print("-" * 78)
    for dev, (fn, frame) in corpus.items():
        contract = ORACLE.transform_or_passthrough(frame)     # eligible -> canonicalize
        p4_out = egress_content(frame)
        if len(frame) == 61:
            cls = "CLS_RESP_V1 (elig shrink -7)"
        elif len(frame) == 54:
            cls = "CLS_RESP_V3 (passthrough)"
        else:
            cls = "n/a"
        ok = (p4_out == contract)
        checks.append((f"{dev}: transform matches transform_or_passthrough", ok))
        print("%-20s %-28s %-8d %-8d %+d %s"
              % (dev, cls, len(p4_out), len(contract), len(contract) - len(frame),
                 "" if ok else "  <-- MISMATCH"))
        if not ok:
            for i, (a, b) in enumerate(zip(p4_out, contract)):
                if a != b:
                    print(f"        first mismatch @byte {i}: p4=0x{a:02x} contract=0x{b:02x}"); break

    # ---- 2. the tightening: same-LENGTH non-eligible 61 B segments must pass through BYTE-IDENTICAL ----
    g32_61, v2_61, nondnp61 = _build_noneligible_61B(corpus)
    print()
    for name, frame in [("61B G32 (non-G30)", g32_61),
                        ("61B G30-but-V2", v2_61),
                        ("61B non-DNP3", nondnp61)]:
        contract = ORACLE.transform_or_passthrough(frame)     # non-eligible -> byte-identical
        p4_out = egress_content(frame)
        ok = (p4_out == contract == frame)                    # verbatim on BOTH sides
        checks.append((f"non-eligible {name}: P4 passthrough == frame (byte-identical)", ok))
        print("%-20s %-28s %-8d %-8d %+d %s"
              % (name, "CLS_RESP_V1_PASS (verbatim)", len(p4_out), len(contract),
                 len(contract) - len(frame), "" if ok else "  <-- MISMATCH"))

    # ---- 3. criterion 4: a NON-eligible packet between two eligible responses on ONE flow.
    #         Its seq is shifted by the PRIOR accumulated Δ, and Δ is UNCHANGED after it. ----
    ion = corpus["ion7550"][1]                                # the eligible 61 B V1 response
    flow = EgressFlow()
    c1, s1 = flow.out(ion, 1000);        d1 = flow.delta      # eligible: seq_add 0, Δ -> -7
    c2, s2 = flow.out(g32_61, 1061);     d2 = flow.delta      # NON-elig: seq_add -7, Δ unchanged
    c3, s3 = flow.out(ion, 1200);        d3 = flow.delta      # eligible: seq_add -7, Δ -> -14
    print("\ntwo-response flow with a non-eligible packet in the middle (reg_delta + seq):")
    print("  pkt1 eligible  V1   seq 1000 -> %d   (Δ_add=%+d)  Δ_after=%+d" % (s1, s1 - 1000, d1))
    print("  pkt2 NON-elig  PASS seq 1061 -> %d   (Δ_add=%+d)  Δ_after=%+d" % (s2, s2 - 1061, d2))
    print("  pkt3 eligible  V1   seq 1200 -> %d   (Δ_add=%+d)  Δ_after=%+d" % (s3, s3 - 1200, d3))
    checks.append(("flow: pkt1 eligible content == canonicalize", c1 == ORACLE.canonicalize(ion)))
    checks.append(("flow: pkt2 content passes through verbatim (== g32_61)", c2 == g32_61))
    checks.append(("flow: pkt2 seq shifted by PRIOR Δ (1061 + (-7) = 1054)", s2 == 1061 - 7))
    checks.append(("flow: pkt2 leaves Δ UNCHANGED (no bump on passthrough): Δ_after == Δ_before == -7",
                   d2 == d1 == -7))
    checks.append(("flow: pkt3 eligible seq shifted by accumulated Δ (1200 + (-7) = 1193)", s3 == 1200 - 7))
    checks.append(("flow: pkt3 bumps Δ to -14 (eligible resumes accumulating)", d3 == -14))
    checks.append(("flow: pkt3 content == canonicalize", c3 == ORACLE.canonicalize(ion)))

    print("\n" + "-" * 78)
    npass = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
    print("-" * 78)
    print("P4-EGRESS EMULATOR vs transform_or_passthrough CONTRACT: %d/%d checks pass" % (npass, len(checks)))
    print("\nHeadline: the 3 real devices still transform (V1->V3 / V3 passthrough), the 3 same-length")
    print("non-eligible 61 B segments now pass through BYTE-IDENTICAL, and a passthrough packet shifts")
    print("seq by the flow's accumulated Δ without bumping Δ. Matches the tightened fail-open contract.")
    sys.exit(0 if npass == len(checks) else 1)


if __name__ == "__main__":
    main()
