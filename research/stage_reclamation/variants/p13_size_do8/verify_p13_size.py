#!/usr/bin/env python3
"""Static consistency + byte-identity + CORPUS-COVERAGE check for p13_size_do8.p4.

Checks the SOURCE against the COMPILED artifact (out/pipe/context.json), so a claim
here is a claim about what bf-p4c actually emitted, not about what the P4 text says.

What P13 changed relative to P6c/P12, and therefore what this has to prove:

 (a) The egress parser select key is `ipv4.total_len` ALONE — `tcp.data_offset` is
     gone. So the model must hold for EVERY data_offset, not just 5. A pl_* state
     consumes `total_len - 40` bytes, an arbitrary mixture of TCP OPTION bytes and
     payload bytes; the check builds frames at data_offset 5, 8 and 10 and requires
     the inner IP datagram to come out byte-identical in all three.

 (b) `size_norm` no longer reads `eg_intr_md.pkt_length` at all — on silicon that
     field's convention is unknown and the table never fired. The pad now comes from
     `wire = max(60, 14 + total_len)`, which the corpus measurement below justifies.

 (c) The key is (tcp.isValid(), total_len). tcp-valid proves the egress parser
     reached parse_tcp; a listed total_len proves it consumed the datagram past the
     TCP base header. ARM 2 enumerates the frames that could otherwise have had pads
     emitted BEFORE a non-empty residual, which would split the IP datagram.

This models the parser/deparser emit order; it is NOT a silicon test.
Run: python3 verify_p13_size.py
"""
import json
import random
import re
import sys
from pathlib import Path

ETH, HDRS, TARGET, ETH_MIN = 14, 54, 128, 60

# Measured with tshark over all 2104 packets of `Traffic Trace/SEL751.pcap`:
#   tshark -r SEL751.pcap -T fields -e ip.hdr_len -e tcp.hdr_len -e ip.len -e frame.len
# and separately: frame.len - ip.len == 14 for EVERY packet (no Ethernet trailer,
# no frame below the 60 B minimum) -- which is what licenses wire = 14 + total_len.
CORPUS = [
    (32,  52,  66, 906, "pure TCP ACK        (data_offset=8)"),
    (32,  74,  88, 198, "DNP3 READ request   (data_offset=8)"),
    (32,  87, 101, 400, "DNP3 response       (data_offset=8)"),
    (32,  89, 103, 400, "DNP3 response       (data_offset=8)"),
    (32, 106, 120, 198, "DNP3 response       (data_offset=8)"),
    (40,  60,  74,   2, "SYN / SYN-ACK       (data_offset=10)"),
]
# The coordinator's data_offset=5 replay frames, run on silicon 2026-07-25.
REPLAY = [
    (20,  40,  60, "pure TCP ACK        (data_offset=5, MAC-padded 54 -> 60)"),
    (20,  62,  76, "DNP3 READ request   (data_offset=5)"),
    (20,  94, 108, "DNP3 response       (data_offset=5)"),
]


def wire_of(total_len):
    """The on-wire frame length implied by the declared IP length."""
    return max(ETH_MIN, ETH + total_len)


def load():
    """Source-derived parser tables + compiler-derived entry table."""
    src = (Path(__file__).parent / "p13_size_do8.p4").read_text()
    pl = {int(m.group(1)): [int(x) for x in re.findall(r"hdr\.pay(\d+)\)", m.group(2))]
          for m in re.finditer(r"state pl_(\d+)\s*\{(.*?)transition accept;", src, flags=re.S)}
    sel = {int(a): int(b) for a, b in re.findall(r"16w(\d+)\s*: pl_(\d+);", src)}
    pa = {int(m.group(1)): [int(x) for x in re.findall(r"hdr\.pad(\d+)\.setValid", m.group(2))]
          for m in re.finditer(r"action pad_d(\d+)\(\)\s*\{(.*?)\}\n", src, flags=re.S)}
    ctx = json.load(open(Path(__file__).parent / "out/pipe/context.json"))
    ent = {}
    for t in ctx["tables"]:
        if t["name"].endswith("size_norm"):
            hmap = {a["handle"]: a["name"].split(".")[-1] for a in t["actions"]}
            for e in t["static_entries"]:
                kv = {f["field_name"]: int(str(f["value"]), 0)
                      for f in e["match_key_fields_values"]}
                act = hmap[e["action_handle"]]
                ent[(kv["hdr.tcp.$valid"], kv["hdr.ipv4.total_len"])] = int(act.split("_d")[-1])
    return pl, sel, pa, ent


def simulate(inner, consume, pads):
    """Model EgParser extraction + EgDeparser emission, both DESCENDING.

    The deparser emits eth+ipv4+tcp (54 B), then the pay chunks descending, then the
    pad chunks; the hardware appends whatever the parser never consumed (the residual)
    last. Returns (output, residual).
    """
    off, got = HDRS, b""
    for c in consume:
        got += inner[off:off + c]
        off += c
    residual = inner[off:]
    return inner[:HDRS] + got + b"\x00" * sum(pads) + residual, residual


def main():
    pl, sel, pa, ent = load()
    ok = True
    random.seed(7)

    print("=== ARM 1: every COMPILED entry, at three data_offset values ===")
    print(f"{'tot_len':>7} {'wire':>5} {'consume':>7} {'pay chunks':<24}{'pad':>4}  "
          f"{'pad chunks':<22}{'out':>4}  verdict")
    for (valid, L), D in sorted(ent.items(), key=lambda kv: kv[0][1]):
        n, W = L - 40, wire_of(L)
        pc, dc = pl.get(n, []), pa[D]
        checks = {
            "entry is gated on tcp.isValid()==1": valid == 1,
            "pad chunks sum to the action's delta": sum(dc) == D,
            "wire + pad == 128": W + D == TARGET,
            "pad chunks distinct powers of 2": len(set(dc)) == len(dc),
            "pad chunks descending": dc == sorted(dc, reverse=True),
        }
        if n == 0:
            # total_len == 40 is the one class with nothing to consume: the IP
            # datagram is exactly ip(20)+tcp(20), so "the parser consumed everything
            # past the TCP base header" is true by arithmetic, not by a pl_ state.
            # bf-p4c duly folds `state pl_0 { transition accept; }` into accept.
            checks["L==40 has nothing past the TCP base header"] = (L == 40)
        else:
            checks["select maps total_len -> pl_(L-40)"] = sel.get(L) == n
            checks["pay chunks sum to L-40"] = sum(pc) == n
            checks["pay chunks distinct powers of 2"] = len(set(pc)) == len(pc)
            checks["pay chunks descending"] = pc == sorted(pc, reverse=True)
        for do in (5, 8, 10):
            if 20 + 4 * do > L:
                continue                       # a header that size would not fit in L
            inner = bytes(random.randrange(1, 256) for _ in range(W))
            out, residual = simulate(inner, pc, dc)
            # For L==40 the residual is the sending MAC's Ethernet padding, which is
            # OUTSIDE the IP datagram, so it is legitimately non-empty.
            dgram = ETH + L
            checks[f"do={do}: residual is outside the IP datagram"] = \
                len(residual) == W - dgram
            checks[f"do={do}: inner IP datagram byte-identical"] = out[:dgram] == inner[:dgram]
            checks[f"do={do}: pads land after the datagram"] = \
                out[dgram:dgram + D] == b"\x00" * D
            checks[f"do={do}: output exactly 128 B"] = len(out) == TARGET
        bad = [k for k, v in checks.items() if not v]
        ok &= not bad
        print(f"{L:7} {W:5} {n:7} {str(pc):<24}{D:4}  {str(dc):<22}{W + D:4}  "
              + ("OK" if not bad else f"FAIL {bad}"))

    print("\n=== ARM 2: frames that must NOT be padded (would split the datagram) ===")
    # An ihl != 5 or non-TCP frame never reaches parse_tcp, so hdr.tcp is invalid and
    # its options/TCP/payload sit in the residual. With the old pkt_length-only key
    # such a frame could still match and be padded ahead of that residual. Now every
    # entry requires tcp.$valid == 1.
    unguarded = [k for k in ent if k[0] != 1]
    print(f"  entries not gated on tcp.isValid(): {len(unguarded)} -> "
          + ("every entry is gated (ihl!=5 / non-TCP / non-IPv4 all fail open)"
             if not unguarded else f"LEAK {unguarded}"))
    ok &= not unguarded
    # And no entry exists for a total_len the parser does not fully consume.
    unconsumed = [L for (_, L) in ent if L != 40 and L not in sel]
    print(f"  entries whose total_len has no parser class: {len(unconsumed)} -> "
          + ("none" if not unconsumed else f"LEAK {unconsumed}"))
    ok &= not unconsumed
    # Oversize must fail open, never truncate.
    over = [L for (_, L) in ent if wire_of(L) > TARGET]
    print(f"  entries that would need a NEGATIVE pad (oversize): {len(over)} -> "
          + ("none; total_len > 114 has no entry and takes pad_none" if not over
             else f"LEAK {over}"))
    ok &= not over

    print("\n=== ARM 3: measured SEL751.pcap corpus (data_offset = 8 and 10) ===")
    covered = total = 0
    for tcp_hl, L, frame_len, count, what in CORPUS:
        total += count
        assert frame_len == wire_of(L), f"corpus frame {frame_len} != model {wire_of(L)}"
        hit = (1, L) in ent
        covered += count if hit else 0
        ok &= hit
        print(f"  do={tcp_hl // 4:2}  total_len={L:4}  wire={frame_len:4}  n={count:5}  "
              f"{what:36}" + ("-> 128 B" if hit else "MISSED"))
    print(f"  corpus coverage: {covered}/{total} packets ({100.0 * covered / total:.1f} %)")
    ok &= (covered == total)

    print("\n=== ARM 4: the coordinator's data_offset = 5 replay frames ===")
    for tcp_hl, L, frame_len, what in REPLAY:
        assert frame_len == wire_of(L), f"replay frame {frame_len} != model {wire_of(L)}"
        hit = (1, L) in ent
        ok &= hit
        print(f"  do={tcp_hl // 4:2}  total_len={L:4}  wire={frame_len:4}  {what:52}"
              + ("-> 128 B" if hit else "MISSED"))

    print(f"\ncompiled entries={len(ent)}  parser classes={len(sel)}  "
          f"pl_states={len(pl)}  pad actions={len(pa)}")
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
