"""
Verification suite for length_synth.py.

Checks, and exits nonzero on any failure:
  1. link_size() against actually serialized DNP3 frames (byte-counted).
  2. Every u_* formula against the measured SEL-751 anchors.
  3. Mutation tests: perturb each fixed-overhead constant by +/-1 and assert the
     model then FAILS to reproduce the anchors -- i.e. each constant is pinned.
  4. crc_boundaries() geometry and byte-preserving splits (concat == original).

Run:  python3 test_length_synth.py
"""

from __future__ import annotations

import math
import sys
import traceback
from typing import Callable, List

import length_synth as ls

# Measured anchors (physical SEL-751, 2026-08-12): (label, wire_bytes, u)
ANCHOR_SBO = [("1-CROB echo", 35, 21), ("2-CROB echo", 49, 33)]
ANCHOR_READ = [
    ("G10V2 x32 status", 58, 42, "G10V2", 32),
    ("G1 binary-in x16", 40, 26, "G1V2", 16),
]

_failures: List[str] = []
_passes = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passes
    if cond:
        _passes += 1
        print(f"  PASS  {name}")
    else:
        _failures.append(f"{name} :: {detail}")
        print(f"  FAIL  {name} :: {detail}")


def section(title: str) -> None:
    print(f"\n=== {title} ===")


# ---------------------------------------------------------------------------
# 1. link_size against serialized frames
# ---------------------------------------------------------------------------
def test_link_size_vs_serialized() -> None:
    section("1. link_size() vs actually serialized frames")
    # SBO echoes
    for k, expect_wire, expect_u in [(1, 35, 21), (2, 49, 33), (3, 61, 45),
                                     (4, 75, 57), (5, 89, 69)]:
        payload = ls.build_sbo_response_payload(k)
        frame = ls.serialize_frame(payload)
        u = len(payload)
        check(f"SBO K={k}: u == {expect_u}", u == expect_u, f"got u={u}")
        check(f"SBO K={k}: serialized len == {expect_wire}",
              len(frame) == expect_wire, f"got {len(frame)}")
        check(f"SBO K={k}: link_size(u) == serialized len",
              ls.link_size(u) == len(frame), f"{ls.link_size(u)} vs {len(frame)}")
    # READ responses
    for obj_key, qual, n, expect_wire, expect_u in [
            ("G10V2", ls.Q_STARTSTOP_1B, 23, 49, 33),
            ("G10V2", ls.Q_STARTSTOP_1B, 11, 35, 21),
            ("G10V2", ls.Q_STARTSTOP_1B, 32, 58, 42),
            ("G30V1", ls.Q_STARTSTOP_1B, 7, 61, 45)]:
        obj = next(o for o in ls.READ_OBJS if o.key == obj_key)
        payload = ls.build_read_response_payload(obj, qual, n)
        frame = ls.serialize_frame(payload)
        u = len(payload)
        check(f"READ {obj_key} N={n}: u == {expect_u}", u == expect_u, f"got u={u}")
        check(f"READ {obj_key} N={n}: serialized len == {expect_wire}",
              len(frame) == expect_wire, f"got {len(frame)}")
        check(f"READ {obj_key} N={n}: link_size(u) == serialized len",
              ls.link_size(u) == len(frame), f"{ls.link_size(u)} vs {len(frame)}")
    # Pure formula spot-checks for the wire model
    for u, w in [(21, 35), (33, 49), (45, 61), (57, 75), (69, 89), (42, 58),
                 (26, 40), (110, 134)]:
        check(f"link_size({u}) == {w}", ls.link_size(u) == w, f"got {ls.link_size(u)}")


# ---------------------------------------------------------------------------
# 2. u_* formulas vs measured anchors
# ---------------------------------------------------------------------------
def test_u_formulas_vs_anchors() -> None:
    section("2. u_*() formulas vs measured anchors")
    # SBO: u_sbo(K) must equal 9 + 12K AND match the two anchors' u.
    for k in range(1, 6):
        check(f"u_sbo({k}) == 9 + 12*{k}", ls.u_sbo(k) == 9 + 12 * k,
              f"got {ls.u_sbo(k)}")
    for label, wire, u in ANCHOR_SBO:
        k = {35: 1, 49: 2}[wire]
        check(f"anchor {label}: u_sbo({k}) == {u}", ls.u_sbo(k) == u,
              f"got {ls.u_sbo(k)}")
        check(f"anchor {label}: link_size(u_sbo({k})) == {wire}",
              ls.link_size(ls.u_sbo(k)) == wire, f"got {ls.link_size(ls.u_sbo(k))}")
    # READ anchors
    for label, wire, u, obj_key, n in ANCHOR_READ:
        obj = next(o for o in ls.READ_OBJS if o.key == obj_key)
        got = ls.u_read(obj, ls.Q_STARTSTOP_1B, n)
        check(f"anchor {label}: u_read({obj_key},N={n}) == {u}", got == u,
              f"got {got}")
        check(f"anchor {label}: link_size == {wire}", ls.link_size(got) == wire,
              f"got {ls.link_size(got)}")
    # Cross-triangulation: SBO+READ anchors jointly pin RESP_FIXED and G12 header.
    # READ G10V2 x32 (u=42): RESP_FIXED = 42 - header(5) - 32*1 = 5.
    g10 = next(o for o in ls.READ_OBJS if o.key == "G10V2")
    resp_fixed_from_read = 42 - ls.obj_header_bytes(ls.Q_STARTSTOP_1B) - 32 * g10.point_bytes
    check("triangulation: RESP_FIXED derived from READ anchor == 5",
          resp_fixed_from_read == ls.RESP_FIXED, f"got {resp_fixed_from_read}")
    # SBO 1-CROB (u=21): G12 header = 21 - RESP_FIXED - 12 = 4.
    g12_header_from_sbo = 21 - ls.RESP_FIXED - (ls.Q_INDEXED_1B.prefix_bytes + ls.CROB.point_bytes)
    check("triangulation: G12 header derived from SBO anchor == 4",
          g12_header_from_sbo == ls.obj_header_bytes(ls.Q_INDEXED_1B),
          f"got {g12_header_from_sbo}")


# ---------------------------------------------------------------------------
# 3. Mutation tests -- each fixed overhead is load-bearing
# ---------------------------------------------------------------------------
def _sbo_wire_with(link_header: int, block_data: int, block_crc: int,
                   resp_fixed: int, g12_header: int, per_point: int, k: int) -> int:
    """Recompute an SBO echo wire size with mutated constants."""
    u = resp_fixed + g12_header + k * per_point
    nb = 0 if u <= 0 else math.ceil(u / block_data)
    return link_header + u + block_crc * nb


def test_mutations() -> None:
    section("3. mutation tests -- perturbing each constant breaks the anchors")
    base = dict(link_header=ls.LINK_HEADER, block_data=ls.BLOCK_DATA,
                block_crc=ls.BLOCK_CRC, resp_fixed=ls.RESP_FIXED,
                g12_header=ls.obj_header_bytes(ls.Q_INDEXED_1B),
                per_point=ls.Q_INDEXED_1B.prefix_bytes + ls.CROB.point_bytes)
    # sanity: base reproduces BOTH anchors
    check("mutation base: reproduces 35 & 49",
          _sbo_wire_with(**base, k=1) == 35 and _sbo_wire_with(**base, k=2) == 49,
          f"k1={_sbo_wire_with(**base, k=1)} k2={_sbo_wire_with(**base, k=2)}")

    def anchors_hold(cfg) -> bool:
        return (_sbo_wire_with(**cfg, k=1) == 35 and _sbo_wire_with(**cfg, k=2) == 49)

    # Constants the two SBO anchors alone should pin (each +/-1 must break >=1 anchor):
    for cname in ["link_header", "block_crc", "resp_fixed", "g12_header", "per_point"]:
        for delta in (-1, +1):
            cfg = dict(base)
            cfg[cname] = base[cname] + delta
            check(f"mutate {cname} {delta:+d} breaks an anchor",
                  not anchors_hold(cfg),
                  f"still holds: k1={_sbo_wire_with(**cfg, k=1)} "
                  f"k2={_sbo_wire_with(**cfg, k=2)}")

    # block_data: honest note -- the 35/49 anchors do NOT distinguish 15 vs 16
    # (ceil(21/15)=ceil(21/16)=2, ceil(33/15)=ceil(33/16)=3). block_data=16 is a
    # DNP3 spec constant; block_data=17 IS anchor-rejectable. Assert both facts.
    cfg17 = dict(base); cfg17["block_data"] = 17
    check("mutate block_data 17 breaks 49-anchor (ceil(33/17)=2)",
          not anchors_hold(cfg17), f"k2={_sbo_wire_with(**cfg17, k=2)}")
    cfg15 = dict(base); cfg15["block_data"] = 15
    check("HONEST: block_data 15 is anchor-indistinguishable (spec-pinned, not "
          "anchor-pinned)", anchors_hold(cfg15),
          f"k1={_sbo_wire_with(**cfg15, k=1)} k2={_sbo_wire_with(**cfg15, k=2)}")

    # READ per-point mutation: G10V2 point=2 must break the x32 READ anchor (58 B)
    g10 = next(o for o in ls.READ_OBJS if o.key == "G10V2")
    u_bad = ls.RESP_FIXED + ls.obj_header_bytes(ls.Q_STARTSTOP_1B) + 32 * 2
    check("mutate G10V2 point_bytes 1->2 breaks 58-anchor",
          ls.link_size(u_bad) != 58, f"got {ls.link_size(u_bad)}")


# ---------------------------------------------------------------------------
# 4. CRC-boundary geometry + byte-preserving splits
# ---------------------------------------------------------------------------
def test_boundaries_and_split() -> None:
    section("4. CRC boundaries + byte-preserving split")
    check("crc_boundaries(33) == [10,28,46,49]",
          ls.crc_boundaries(33) == [10, 28, 46, 49], f"got {ls.crc_boundaries(33)}")
    check("crc_boundaries(45) == [10,28,46,61]",
          ls.crc_boundaries(45) == [10, 28, 46, 61], f"got {ls.crc_boundaries(45)}")
    check("crc_boundaries(21) == [10,28,35]",
          ls.crc_boundaries(21) == [10, 28, 35], f"got {ls.crc_boundaries(21)}")
    check("balanced_split(33) == (28,21)", ls.balanced_split(33) == (28, 21),
          f"got {ls.balanced_split(33)}")
    check("balanced_split(45) == (28,33)", ls.balanced_split(45) == (28, 33),
          f"got {ls.balanced_split(45)}")

    # Byte preservation: split a real serialized frame at every CRC boundary and
    # at the balanced cut; concatenation must equal the original bytes exactly.
    for k in (1, 2, 3):
        payload = ls.build_sbo_response_payload(k)
        frame = ls.serialize_frame(payload)
        u = len(payload)
        bounds = [0] + ls.crc_boundaries(u)
        chunks = [frame[bounds[i]:bounds[i + 1]] for i in range(len(bounds) - 1)]
        check(f"SBO K={k}: concat(CRC-boundary chunks) == frame",
              b"".join(chunks) == frame,
              f"reassembly mismatch len {len(b''.join(chunks))} vs {len(frame)}")
        cut, _ = ls.balanced_split(u)
        check(f"SBO K={k}: concat(balanced split) == frame",
              frame[:cut] + frame[cut:] == frame, "split identity failed")
        # every boundary lands inside the frame
        check(f"SBO K={k}: final boundary == wire size",
              ls.crc_boundaries(u)[-1] == len(frame),
              f"{ls.crc_boundaries(u)[-1]} vs {len(frame)}")


# ---------------------------------------------------------------------------
# 5. Seed candidate + solver self-consistency
# ---------------------------------------------------------------------------
def test_seed_and_solver() -> None:
    section("5. seed candidate + solver")
    # Seed: 2-CROB SBO (49) == G10V2 N=23 (49)
    check("SEED: u_sbo(2) == u_read(G10V2,N=23)",
          ls.u_sbo(2) == ls.u_read(next(o for o in ls.READ_OBJS if o.key == "G10V2"),
                                   ls.Q_STARTSTOP_1B, 23) == 33, "seed size mismatch")
    check("SEED: 3-CROB == G30V1 N=7",
          ls.u_sbo(3) == ls.u_read(next(o for o in ls.READ_OBJS if o.key == "G30V1"),
                                   ls.Q_STARTSTOP_1B, 7) == 45, "analog seed mismatch")
    cands = ls.find_intersections(kmax=5, nmax=260, include_residue=True)
    # There must be a Tier-1 G10V2 match for every K (N = u_SBO(K) - 10)
    for k in range(1, 6):
        want_n = ls.u_sbo(k) - 10
        hit = [c for c in cands if c.tier == 1 and c.read_obj == "G10V2"
               and c.k_crobs == k and c.read_points == want_n]
        check(f"solver: Tier-1 G10V2 match for K={k} at N={want_n}", len(hit) == 1,
              f"found {len(hit)}")
    # G30V1 must match ONLY K=3 in Tier-1 (residue obstruction elsewhere)
    g30_t1 = sorted({c.k_crobs for c in cands
                     if c.tier == 1 and c.read_obj == "G30V1"})
    check("solver: G30V1 Tier-1 matches exactly {3}", g30_t1 == [3], f"got {g30_t1}")
    # Equal u <=> equal wire <=> equal geometry (monotonicity), for every cand
    ok_geo = all(ls.link_size(c.u) == c.wire
                 and ls.crc_boundaries(c.u)[-1] == c.wire for c in cands)
    check("solver: every candidate has consistent wire+geometry", ok_geo, "")
    print(f"\n  (solver returned {len(cands)} intersections; "
          f"{sum(1 for c in cands if c.tier == 1)} Tier-1)")


def main() -> int:
    tests: List[Callable[[], None]] = [
        test_link_size_vs_serialized,
        test_u_formulas_vs_anchors,
        test_mutations,
        test_boundaries_and_split,
        test_seed_and_solver,
    ]
    for t in tests:
        try:
            t()
        except Exception:
            _failures.append(f"{t.__name__} raised")
            traceback.print_exc()
    print("\n" + "=" * 60)
    print(f"RESULT: {_passes} passed, {len(_failures)} failed")
    if _failures:
        print("FAILURES:")
        for f in _failures:
            print(f"  - {f}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
