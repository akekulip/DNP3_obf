#!/usr/bin/env python3
"""Generate a WIDENED-COVERAGE probe of p13_size_do8.p4.

P13 ships 13 discrete length classes, which happen to cover 100 % of the measured
SEL751 corpus. This generator asks the separate question the brief raised: how many
classes can the egress normalizer hold before it hits a resource wall, i.e. how much
coverage headroom is actually there?

It replaces the 13 classes with a CONTIGUOUS range of ipv4.total_len from LO to HI,
which is the strongest coverage statement available ("every IPv4/TCP frame with
ihl = 5 and total_len in [LO,HI], at any data_offset, leaves at exactly 128 B").
Everything else in the program is untouched.

  N (bytes consumed after the 20 B TCP base header) = total_len - 40
  D (pad bytes)                                     = 128 - 14 - total_len = 74 - N
  so N + D == 74 for every class -> the SAME pay*/pad* header set serves all of them
  and the widening costs parser states, table entries and actions, NOT tagalong.

Usage: python3 gen_widen_probe.py <LO> <HI> <outfile>
"""
import re
import sys
from pathlib import Path

ETH, HDRS, TARGET = 14, 54, 128


def chunks(n):
    """Descending power-of-2 decomposition, matching extraction and emit order."""
    return [c for c in (64, 32, 16, 8, 4, 2, 1) if n & c]


def main():
    lo, hi, outfile = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    whole = (Path(__file__).parent / "p13_size_do8.p4").read_text()
    lens = list(range(lo, hi + 1))
    assert all(0 <= L - 40 and TARGET - ETH - L >= 0 for L in lens), "class out of range"

    # Operate on the EGRESS region only. `const entries = {` also appears in ingress
    # tables (tbl_state_decode, tbl_deadline_expiry); an unanchored regex matches the
    # ingress one first and eats the whole file. Ingress must not be touched at all.
    cut = whole.index("struct eg_meta_t")
    head, src = whole[:cut], whole[cut:]

    # ---- 1. parser select + pl_* states -------------------------------------
    sel = "\n".join(f"            16w{L:<4}: pl_{L - 40};" for L in lens)
    states = "\n".join(
        f"    state pl_{L - 40} {{ "
        + "".join(f"pkt.extract(hdr.pay{c}); " for c in chunks(L - 40))
        + "transition accept; }"
        for L in lens)
    src = re.sub(r"(transition select\(hdr\.ipv4\.total_len\) \{\n).*?(\n\s*default : accept;)",
                 lambda m: m.group(1) + sel + m.group(2), src, flags=re.S)
    # `\s*\{` not ` \{`: p6c aligns the short states as `state pl_6  {` (two spaces),
    # and a single-space pattern starts the match at pl_12 and leaves pl_6/pl_8 behind
    # as duplicate declarations.
    src = re.sub(r"    state pl_\d+\s*\{.*?\n\}\n\ncontrol Egress",
                 states + "\n}\n\ncontrol Egress", src, flags=re.S)

    # ---- 2. pad actions ------------------------------------------------------
    acts = "\n".join(
        f"    action pad_d{TARGET - ETH - L}() {{ meta.normalized = 8w1; "
        + "".join(f"hdr.pad{c}.setValid(); hdr.pad{c}.f = 0; "
                  for c in chunks(TARGET - ETH - L))
        + "}"
        for L in lens)
    src = re.sub(r"    action pad_d8\(\).*?\n\n", acts + "\n\n", src, flags=re.S)

    # ---- 3. table action list + entries -------------------------------------
    names = "; ".join(f"pad_d{TARGET - ETH - L}" for L in lens)
    src = re.sub(r"actions = \{ pad_none;.*?\}\n", f"actions = {{ pad_none; {names}; }}\n",
                 src, flags=re.S)
    ent = "\n".join(f"            (16w{L:<4}, 16w{L + ETH:<4}) : pad_d{TARGET - ETH - L}();"
                    for L in lens)
    src = re.sub(r"(const entries = \{\n).*?(\n\s*\}\n\s*const default_action)",
                 lambda m: m.group(1) + ent + m.group(2), src, flags=re.S)
    src = re.sub(r"size = 16;", f"size = {max(16, 2 * len(lens))};", src)

    Path(outfile).write_text(head + src)
    print(f"wrote {outfile}: {len(lens)} classes, total_len {lo}..{hi}, "
          f"pad {TARGET - ETH - hi}..{TARGET - ETH - lo} B")


if __name__ == "__main__":
    main()
