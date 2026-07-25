#!/usr/bin/env python3
"""Static consistency + byte-identity check for p6c_true_trailer.p4.

Parses the P4 source itself (parser select, pl_* states, pad table, pad actions)
and proves, for all 13 length classes:
  * parser select maps ipv4.total_len -> the pl_ state for payload = total_len-40
  * the pay-chunk subset sums to the payload length
  * the pad-chunk subset sums to (128 - wire) and matches the pad table entry
  * output length is exactly 128 B
  * the deparser residual is EMPTY (so the pads are a true Ethernet trailer)
  * the inner frame (eth+ip+tcp+payload) is reconstructed BYTE-IDENTICALLY

This models the parser/deparser emit order; it is not a silicon test.
Run: python3 verify_p6c_arithmetic.py
"""
import re
import random
import sys
from pathlib import Path

ETH, HDRS, TARGET = 14, 54, 128   # eth=14, eth+ip+tcp=54, one output state=128 B


def main() -> int:
    src = (Path(__file__).parent / "p6c_true_trailer.p4").read_text()
    pl = {int(m.group(1)): [int(x) for x in re.findall(r"hdr\.pay(\d+)\)", m.group(2))]
          for m in re.finditer(r"state pl_(\d+)\s*\{(.*?)transition accept;", src, flags=re.S)}
    sel = {int(tl): int(n) for tl, n in
           re.findall(r"\(4w5,\s*16w(\d+)\s*\)\s*:\s*pl_(\d+);", src)}
    pad = {int(k): int(v) for k, v in re.findall(r"16w(\d+)\s*:\s*pad_d(\d+)\(\);", src)}
    pa = {int(m.group(1)): [int(x) for x in re.findall(r"hdr\.pad(\d+)\.setValid", m.group(2))]
          for m in re.finditer(r"action pad_d(\d+)\(\)\s*\{(.*?)\}\n", src, flags=re.S)}

    ok = True
    random.seed(7)
    for wire in sorted(pad):
        tl, payload = wire - ETH, wire - ETH - 40
        pc, dc = pl.get(payload, []), pa[pad[wire]]
        checks = {
            "select->pl_": sel.get(tl) == payload,
            "pay sums": sum(pc) == payload,
            "pad sums": sum(dc) == pad[wire],
            "delta correct": pad[wire] == TARGET - wire,
            "out == 128": HDRS + sum(pc) + sum(dc) == TARGET,
            "pay distinct": len(set(pc)) == len(pc),
            "pad distinct": len(set(dc)) == len(dc),
        }
        inner = bytes(random.randrange(256) for _ in range(wire))
        off, got = HDRS, b""
        for c in pc:
            got += inner[off:off + c]
            off += c
        residual = inner[off:]
        out = inner[:HDRS] + got + b"\x00" * sum(dc) + residual
        checks["residual empty"] = residual == b""
        checks["inner byte-identical"] = out[:wire] == inner
        checks["output 128 B"] = len(out) == TARGET
        bad = [k for k, v in checks.items() if not v]
        ok &= not bad
        print(f"wire={wire:4}  tot_len={tl:4}  payload={payload:3}  pay={str(pc):<22}"
              f"delta={pad[wire]:3}  pad={str(dc):<22}" + ("OK" if not bad else f"FAIL {bad}"))

    print(f"\nclasses={len(pad)}  select={len(sel)}  pl_states={len(pl)}")
    print("RESULT:", "PASS" if ok and len(pad) == 13 else "FAIL")
    return 0 if ok and len(pad) == 13 else 1


if __name__ == "__main__":
    sys.exit(main())
