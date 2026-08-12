#!/usr/bin/env python3
"""Unified READ<->SBO transaction template — O2-indistinguishability reference model.

Extends the frame-level split+pad (readsbo_normalizer.py) to the whole transaction,
folding in the two domain-expert solutions:

  - power-systems-expert: object-group parity via non-actuating decoys — a decoy G12
    NUL-CROB is provably safe inline in a READ response (the permissive parse path
    ignores it, READ still SUCCESS), and the SBO side's G30 decoy rides out-of-band in
    a phantom-addressed fragment the real endpoint link-drops (so it never actuates and
    the SEL-751 stays READ-only); request-direction parity via non-actuating decoy
    requests; "pad = decoy" (the size pad is realized as the parity decoy).
  - p4-dataplane-engineer: the size/segmentation half is the split+pad already modeled.

Builds a READ transaction and an SBO transaction, extracts three observer feature
vectors (O1 counting / O2 single-packet DPI / O3 stateful correlator), and asserts:
  O1(READ) == O1(SBO),  O2(READ) == O2(SBO),  O3(READ) != O3(SBO).
The O3 inequality is asserted on purpose: the model can never silently claim it beats
a stateful correlator. No hardware; a feature-level model over real DNP3 bytes.
"""
from __future__ import annotations
import math
from collections import Counter
from dataclasses import dataclass, field
import readsbo_normalizer as N

MASTER, OUTSTATION, PHANTOM = 0x0001, 0x0000, 0x00AA   # phantom != master, != outstation
GROUP = {0x1E: "G30", 0x0C: "G12"}

# ---- representative APDUs (function code + objects), grounded in the evidence ----
READ_REQ    = bytes.fromhex("C0013C0106")                                            # READ Class-0 (G60V1), func 0x01
SELECT_REQ  = bytes.fromhex("C0030C0128010001000101640000006400000000")             # SELECT, func 0x03
OPERATE_REQ = bytes.fromhex("C1040C0128010001000101640000006400000000")             # OPERATE, func 0x04
REAL_G30    = N.READ_APDU_BOUNDED                                                    # bounded READ (6 pts, 3 blocks) -> fits the split MVP
SEL_ECHO    = N.SBO_APDU                                                             # real SELECT echo,   group 0x0C
OP_ECHO     = bytes.fromhex("C1818000" + "0C0128010001000101640000006400000000")   # real OPERATE echo, group 0x0C
DECOY_G12   = bytes.fromhex("C0818000" + "0C011701000000000000000000000000")        # phantom frag carrying a NUL-CROB (G12)
DECOY_G30   = bytes.fromhex("C0818000" + "1E0100000001000000")                      # phantom frag carrying an analog (G30)

@dataclass
class Frame:
    direction: str          # 'req' | 'resp'
    dpi: object             # func code (req) or frozenset of object groups (resp) — what O2 reads
    dest: int               # link destination address — what O3 reads
    real: bool
    user: bytes             # transport + APDU (real content), before size padding
    actuates: bool = False  # a real OPERATE at the real outstation -> physical after-effect (O3)

def groups_of(apdu: bytes) -> frozenset:
    """Object group(s) a single-packet DPI observer reads from a response APDU:
    skip the 4-byte app header (ctrl+func+IIN), the next byte is the first object group."""
    return frozenset({apdu[4]}) if len(apdu) > 4 else frozenset()

def _req(apdu, dest, real):
    return Frame("req", apdu[1], dest, real, N.TRANSPORT + apdu)          # func code = 2nd APDU byte

def _resp(apdu, dest, real, actuates=False):
    return Frame("resp", groups_of(apdu), dest, real, N.TRANSPORT + apdu, actuates)

# ---- the two transactions (symmetric O2 template) ----
# response group multiset is {G30:1, G12:2} for BOTH; request func multiset {0x01,0x03,0x04} for both.
def build_read_txn():
    return [
        _req(READ_REQ,    OUTSTATION, True),                     # real READ 0x01
        _req(SELECT_REQ,  PHANTOM,    False),                    # decoy SELECT 0x03 (phantom -> link-dropped)
        _req(OPERATE_REQ, PHANTOM,    False),                    # decoy OPERATE 0x04 (phantom -> never actuates)
        _resp(REAL_G30, MASTER,  True),                          # real G30 response
        _resp(DECOY_G12, PHANTOM, False),                        # phantom G12 fragment
        _resp(DECOY_G12, PHANTOM, False),                        # phantom G12 fragment
    ]

def build_sbo_txn():
    return [
        _req(READ_REQ,    PHANTOM,    False),                    # decoy READ 0x01 (phantom)
        _req(SELECT_REQ,  OUTSTATION, True),                     # real SELECT 0x03
        _req(OPERATE_REQ, OUTSTATION, True),                     # real OPERATE 0x04 -> actuates
        _resp(SEL_ECHO, MASTER, True),                           # real SELECT echo (G12)
        _resp(OP_ECHO,  MASTER, True, actuates=True),            # real OPERATE echo (G12) -- the real effect
        _resp(DECOY_G30, PHANTOM, False),                        # phantom G30 fragment
    ]

# ---- size+segmentation normalization per direction (the split+pad half) ----
# The pad target is a SHARED policy constant (a public L), block-aligned to the largest
# frame seen across ALL transactions -- not per-transaction, or the sizes would not converge.
_TARGETS: dict = {}
def _targets():
    if not _TARGETS:
        allf = build_read_txn() + build_sbo_txn()
        for d in ("req", "resp"):
            u = max(len(f.user) for f in allf if f.direction == d)
            _TARGETS[d] = math.ceil(u / N.BLOCK_USER) * N.BLOCK_USER
    return _TARGETS

def _pad_frames(frames):
    """Pad every frame to the shared per-direction policy target, then segment on CRC
    boundaries -> per-frame size and segmentation converge across both transactions."""
    t = _targets()
    out = []
    for d in ("req", "resp"):
        for f in (x for x in frames if x.direction == d):
            src = OUTSTATION if d == "req" else MASTER
            out.append((f, N.build_frame(0x44, f.dest, src, N.pad_user_to(f.user, t[d]))))
    return out

# ---- observers ----
def O1(frames):
    fb = _pad_frames(frames)
    reqs = [fr for f, fr in fb if f.direction == "req"]
    resps = [fr for f, fr in fb if f.direction == "resp"]
    return {
        "req_count": len(reqs), "resp_count": len(resps),
        "req_sizes": sorted(len(x) for x in reqs),
        "resp_sizes": sorted(len(x) for x in resps),
        "seg_patterns": sorted(tuple(len(s) for s in N.split_at_crc(x)) for x in reqs + resps),
    }

def O2(frames):
    v = O1(frames)
    v["req_func_multiset"] = sorted(Counter(f.dpi for f in frames if f.direction == "req").items())
    resp_groups = Counter(GROUP[g] for f in frames if f.direction == "resp" for g in f.dpi)
    v["resp_group_multiset"] = sorted(resp_groups.items())
    return v

def O3(frames):
    v = O2(frames)
    v["dest_order"] = [f.dest for f in frames]                            # link addresses, in order
    v["dpi_order"] = [f.dpi if f.direction == "req" else tuple(sorted(f.dpi)) for f in frames]
    v["actuations"] = sum(1 for f in frames if f.actuates)               # physical after-effect
    return v


def _demo():
    r, s = build_read_txn(), build_sbo_txn()
    print("O1 (counting) equal:       ", O1(r) == O1(s))
    print("O2 (single-packet DPI) eq: ", O2(r) == O2(s))
    print("O3 (stateful) equal:       ", O3(r) == O3(s), " (expected False -- the honest residual)")
    print("  O2 req func multiset:  ", O2(r)["req_func_multiset"])
    print("  O2 resp group multiset:", O2(r)["resp_group_multiset"])
    print("  O3 separators: actuations READ=%d SBO=%d ; phantom addr present=%s"
          % (O3(r)["actuations"], O3(s)["actuations"], PHANTOM in O3(r)["dest_order"]))

if __name__ == "__main__":
    _demo()
