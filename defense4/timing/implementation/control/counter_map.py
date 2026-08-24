"""The single source of truth for Case A Defense 3 counter indices (CORRECTIONS.md §4.2).

Before this module, the counter indices were duplicated as bare numbers in the P4, the
setup script, setarm.py, the injector and the analyzers, and they had DRIFTED: the P4
defines `CF_BLOCK_REJECT = 17` (added with R3), but setarm cleared only `range(17)`
(indices 0..16), leaving index 17 cumulative across campaign blocks.

These maps mirror the `const bit<8> CF_*/CD_*` declarations in
`p4/case_a_defense3.p4`. `verify_against_p4()` reads the P4 and asserts they still
agree, so a future edit to the P4 that is not reflected here fails loudly instead of
silently under-resetting a counter.
"""
from __future__ import annotations
import re

# ctr_fresh — the ingress "fresh"/classification counter array (CF_*).
CF = {
    "BYPASS_FWD": 0,
    "BAD_PORT": 1,
    "ARM_FRESH": 2,
    "ARM_DUP": 3,
    "ARM_BUSY": 4,
    "ACK_HOLD": 5,
    "ACK_DUP_HOLD": 6,
    "ACK_REJECT": 7,
    "RESP_HOLD_EARLY": 8,
    "RESP_HOLD_LATE": 9,
    "RESP_BYPASS": 10,
    "UNSUP_SEG": 11,
    "BLOCK_ENQ": 12,
    "PKTGEN_ADMIT": 13,
    "PKTGEN_DROP": 14,
    "CLONE_SEEN": 15,
    "RESP_DUP_SUPP": 16,
    "BLOCK_REJECT": 17,   # R3: fresh host 0x88C1 rejected before Q_BLOCK
}

# ctr_deq — the dequeue-side counter array (CD_*).
CD = {
    "BLOCK_LOOP": 0,
    "BLOCK_TERM_STALE": 1,
    "BLOCK_TERM_DL": 2,
    "BLOCK_TERM_TMO": 3,
    "RELEASE_DEADLINE": 4,
    "RELEASE_FAILOPEN": 5,
    "ACK_RELEASE": 6,
    "ACK_REL_RETIRE": 7,
}

# One-past-the-last index for a full reset (so BLOCK_REJECT=17 IS cleared).
N_FRESH = max(CF.values()) + 1   # 18
N_DEQ = max(CD.values()) + 1     # 8


def fresh_reset_range():
    """Indices to zero for ctr_fresh (0..17 inclusive)."""
    return range(N_FRESH)


def deq_reset_range():
    """Indices to zero for ctr_deq (0..7 inclusive)."""
    return range(N_DEQ)


def verify_against_p4(p4_path):
    """Assert these maps match the `const bit<8> CF_*/CD_* = 8wN` in the P4 source.
    Returns (ok: bool, mismatches: list[str]). Never raises on a missing file — the
    caller decides how strict to be (the switch may not carry the source).
    """
    try:
        src = open(p4_path).read()
    except OSError as e:
        return False, ["cannot read %s: %s" % (p4_path, e)]
    mism = []
    pat = re.compile(r"const\s+bit<8>\s+C([FD])_([A-Z0-9_]+)\s*=\s*8w(\d+)")
    seen = {"F": {}, "D": {}}
    for grp, name, num in pat.findall(src):
        seen[grp][name] = int(num)
    for grp, table in (("F", CF), ("D", CD)):
        for name, idx in table.items():
            got = seen[grp].get(name)
            if got is None:
                mism.append("C%s_%s (=%d here) not found in P4" % (grp, name, idx))
            elif got != idx:
                mism.append("C%s_%s: P4=%d but map=%d" % (grp, name, got, idx))
        for name, num in seen[grp].items():
            if name not in table:
                mism.append("C%s_%s=%d in P4 but missing from map" % (grp, name, num))
    return (not mism), mism


def _selftest():
    fails = 0
    assert N_FRESH == 18, N_FRESH
    assert N_DEQ == 8, N_DEQ
    assert CF["BLOCK_REJECT"] == 17
    assert 17 in fresh_reset_range(), "BLOCK_REJECT (17) must be in the reset range"
    # values are unique and contiguous
    for tbl, n in ((CF, N_FRESH), (CD, N_DEQ)):
        vals = sorted(tbl.values())
        if vals != list(range(n)):
            print("  FAIL non-contiguous:", vals); fails += 1
    print("counter_map self-test: %d failure(s)" % fails)
    return fails


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    if "--verify-p4" in sys.argv:
        p4 = sys.argv[sys.argv.index("--verify-p4") + 1]
        ok, mism = verify_against_p4(p4)
        print("MATCH" if ok else "MISMATCH")
        for m in mism:
            print("  -", m)
        raise SystemExit(0 if ok else 1)
    print("CF (%d):" % N_FRESH, CF)
    print("CD (%d):" % N_DEQ, CD)
