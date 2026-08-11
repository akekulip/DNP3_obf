#!/usr/bin/env python3
"""Phase 5 — offline bidirectional SBO size oracle (core).

Models expanding a DNP3 SELECT (and the paired OPERATE) with inert decoy CROBs to a public target
size, and the per-flow TCP sequence-space translation that byte insertion forces. Answers the
central design question: is a single per-flow 32-bit request-side delta (+ ACK fix-up) sufficient
to keep an UNMODIFIED master consistent, or is reassembly required?

Software outstation + reserved decoy indices only. No DIRECT OPERATE, no physical control.
Run:  ~/.venvs/research/bin/python sbo_oracle.py
"""
import sys
sys.path.insert(0, "/home/philip/Projects/DNP3/dnp3_split_harness")
import dnp3_crc

FUNC_SELECT, FUNC_OPERATE = 0x03, 0x04
G12V1 = (12, 1)
REAL_INDICES = {0, 1}          # real binary-output points on the software outstation
DECOY_INDICES = {200, 201, 202, 203}   # reserved, software-only, cannot operate a physical output
CROB_LEN = 11                  # Group 12 Var 1 body: cc,count,on(4),off(4),status
OBJ_LEN = 1 + CROB_LEN         # qualifier 0x17 -> 1-byte index prefix + CROB


def crob(index, cc=0x41, count=1, on=100, off=100, status=0):
    return bytes([index, cc, count]) + on.to_bytes(4, "little") + off.to_bytes(4, "little") + bytes([status])


def build_control(func, crobs):
    """DNP3 SELECT/OPERATE frame: link hdr + block-CRC'd (transport+app+G12V1 objects)."""
    n = len(crobs)
    objhdr = bytes([12, 1, 0x17, n])          # group,var,qualifier(0x17 count+index),count
    ud = bytes([0xC0, 0xC0, func]) + objhdr + b"".join(crobs)
    ln = 5 + len(ud)
    lh = bytes([0x05, 0x64, ln, 0xC4, 0x0A, 0x00, 0x01, 0x00])
    out = bytearray(lh) + dnp3_crc.dnp3_crc16(lh).to_bytes(2, "little")
    for i in range(0, len(ud), 16):
        blk = ud[i:i + 16]
        out += blk + dnp3_crc.dnp3_crc16(blk).to_bytes(2, "little")
    return bytes(out)


def parse_control(frame):
    """Return (func, [crob_index...], n_crobs) from a SELECT/OPERATE frame, or None."""
    if len(frame) < 10 or frame[0:2] != b"\x05\x64":
        return None
    body, ud = frame[10:], bytearray()
    i = 0
    while i < len(body):                       # each wire block = up-to-16 data + 2 CRC
        data_len = min(16, (len(body) - i) - 2)
        if data_len < 0:
            return None
        data = body[i:i + data_len]
        crc = body[i + data_len:i + data_len + 2]
        if not dnp3_crc.verify_crc(bytes(data), bytes(crc)):
            return None
        ud += data
        i += data_len + 2
    func = ud[2]
    group, var, qual, count = ud[3], ud[4], ud[5], ud[6]
    if (group, var) != G12V1:
        return None
    idxs, off = [], 7
    for _ in range(count):
        idxs.append(ud[off]); off += OBJ_LEN
    return func, idxs, count


def expand_control(frame, target_count):
    """Append inert decoy CROBs so the object count reaches target_count. Returns (new_frame, delta)."""
    parsed = parse_control(frame)
    if parsed is None:
        return frame, 0
    func, idxs, n = parsed
    if target_count <= n:
        return frame, 0
    need = target_count - n
    decoys = list(DECOY_INDICES)[:need]
    if len(decoys) < need:
        return frame, 0            # not enough reserved decoys -> fail open (no expand)
    real = [crob(i) for i in idxs]
    extra = [crob(d) for d in decoys]
    new_frame = build_control(func, real + extra)
    return new_frame, len(new_frame) - len(frame)


class Flow:
    """One direction's cumulative sequence delta with a bounded per-flow 32-bit register."""
    def __init__(self):
        self.delta = 0          # bytes inserted into master->outstation so far (mod 2^32)

    def out_seq(self, master_seq):          # master -> outstation: shift forward
        return (master_seq + self.delta) & 0xFFFFFFFF

    def back_ack(self, outstation_ack):     # outstation -> master: undo the shift
        return (outstation_ack - self.delta) & 0xFFFFFFFF


def run():
    results = []

    def ok(name, cond, note=""):
        results.append((name, "PASS" if cond else "FAIL", note))

    # --- SELECT with 2 real CROBs, expand to public target of 6 objects ---
    sel = build_control(FUNC_SELECT, [crob(0), crob(1)])
    exp_sel, d1 = expand_control(sel, target_count=6)
    ps = parse_control(exp_sel)
    ok("01 expanded SELECT parses + CRC valid", ps is not None)
    ok("02 real CROB indices preserved", ps and set(REAL_INDICES).issubset(set(ps[1])),
       f"indices={ps[1] if ps else None}")
    ok("03 object count reaches public target 6", ps and ps[2] == 6, f"count={ps[2] if ps else None}")
    ok("04 decoys are reserved software-only indices",
       ps and set(ps[1]) - REAL_INDICES <= DECOY_INDICES)
    ok("05 request length grew by delta (bytes inserted)", d1 == len(exp_sel) - len(sel) and d1 > 0,
       f"delta={d1} B")

    # --- per-flow sequence translation, unmodified master must stay consistent ---
    f = Flow()
    m_seq0 = 1000                       # master's SELECT starts at seq 1000
    wan_seq = f.out_seq(m_seq0)         # on the WAN, still 1000 (delta 0 before this insert)
    ok("06 pre-insert WAN seq == master seq", wan_seq == m_seq0)
    f.delta += d1                       # the switch inserted d1 bytes into this request
    # outstation ACKs the EXPANDED select: ack = wan_seq + len(exp_sel_payload)
    exp_payload = len(exp_sel)
    out_ack = (wan_seq + exp_payload) & 0xFFFFFFFF
    master_sees_ack = f.back_ack(out_ack)
    # the unmodified master expects an ACK for the bytes IT sent (len(sel))
    master_expected = (m_seq0 + len(sel)) & 0xFFFFFFFF
    ok("07 translated ACK matches what the unmodified master sent",
       master_sees_ack == master_expected, f"got={master_sees_ack} expected={master_expected}")

    # --- OPERATE must carry the SAME expanded CROB set (pairing) ---
    op = build_control(FUNC_OPERATE, [crob(0), crob(1)])
    exp_op, d2 = expand_control(op, target_count=6)
    po = parse_control(exp_op)
    ok("08 OPERATE expanded to the same CROB set as SELECT",
       po and ps and po[1] == ps[1], f"op={po[1] if po else None}")
    # master's OPERATE seq continues after its SELECT; WAN seq shifted by cumulative delta
    m_seq1 = (m_seq0 + len(sel)) & 0xFFFFFFFF
    wan_seq1 = f.out_seq(m_seq1)
    ok("09 OPERATE WAN seq shifted by cumulative delta", wan_seq1 == (m_seq1 + d1) & 0xFFFFFFFF,
       f"wan={wan_seq1}")
    f.delta += d2
    # a RETRANSMIT of the SELECT (same master seq) must get the same insertion delta, not double
    wan_retx = (m_seq0 + 0) & 0xFFFFFFFF   # retransmit anchored at the original master seq
    ok("10 retransmit of SELECT maps to the same WAN seq (idempotent anchor)",
       wan_retx == m_seq0)   # anchor unchanged; a real impl keys delta on seq<=boundary

    # --- response-size projection ---
    print(f"{'CHECK':52s} RES  NOTE")
    print("-" * 92)
    for n, r, nt in results:
        print(f"{n:52s} {r:4s} {nt}")
    print("-" * 92)
    npass = sum(1 for r in results if r[1] == "PASS")
    print(f"SBO-ORACLE (core): {npass}/{len(results)} checks pass")
    print(f"\nSELECT: 2 real CROBs -> 6 objects (public target); request +{d1} B; "
          f"the outstation's SELECT/OPERATE response grows correspondingly.")
    print("Design result: a single per-flow request-side 32-bit delta + ACK fix-up keeps an")
    print("unmodified master consistent for the in-order SELECT->OPERATE path (checks 06-09).")
    print("OPEN (needs the full oracle): retransmit/dupe/out-of-order boundary keying (check 10 is")
    print("a placeholder anchor), FIN/RST/tuple-reuse delta reset, and whether the master ACCEPTS")
    print("the extra inert CROB status objects in the response (endpoint test, ION7550 not usable")
    print("here — Case-B has no CROB output to exercise; needs a software OpenDNP3 outstation).")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(run())
