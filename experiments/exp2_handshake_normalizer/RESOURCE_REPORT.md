# Experiment 2B — resource report

From `evidence/metrics.json` (bf-p4c 9.13.1, target tofino), the compiled program's pipeline cost.
The headline is that the normalizer is **small and stateless**.

## MAU

| Resource | Used |
|---|---|
| Logical tables | 29 |
| SRAM blocks | 5 |
| TCAM blocks | 1 |
| Map RAMs | 2 |
| Stateful ALUs (registers) | **0** |
| Meter ALUs | **0** |
| Ingress MAU latency | 162 cycles |
| Egress MAU latency | 168 cycles |

The 29 logical tables are almost all compiler-generated implicit tables for the apply-block
statements (the 1-bit flag gateways, the single `ctr.count`, the L3 scrub) plus the three explicit
tables `t_norm`, `t_exp`, `t_clamp`. The **single TCAM block** is the `t_clamp` range match
(`orig_mss` 1461–65535); everything else is exact/gateway logic in SRAM.

## Stateless — the load-bearing property

- **No `Register`, `RegisterAction`, or `Meter` is declared in the source** (grep count 0), and
  **no stateful ALU is allocated** in any PHV/MAU log. The only stateful object is the packet
  **stats `Counter`** (`ctr`), which records per-outcome telemetry; it holds no per-flow
  connection state and is not on the correctness path.
- There is **no per-flow table, no TSval/ISN/sequence translation, no reassembly**. The program is
  packet-bounded: every decision comes from fields in the packet in front of it. This is the
  property the Experiment 2A design argued for, now confirmed by the allocator.

## PHV

| Pool | 8-bit | 16-bit | 32-bit |
|---|---|---|---|
| Normal (containers occupied) | 6 | 13 | 1 |
| Tagalong (containers occupied) | 11 | 22 | 14 |

The option-region headers (`o0`, `e1`…`e5`) and the bytes that are only parsed-and-re-emitted ride
**tagalong** PHV, exactly as the frozen Defense-4 program keeps its `tcp_opt*` in tagalong — the
normal PHV pressure stays low (≈44 bits of 8-bit, 187 of 16-bit, one 32-bit container). **0 CLOT
bits** are allocated; the option region is handled through PHV, which is required because the
program both reads (classification) and rewrites (canonicalization) it.

## Deparser

Two checksum engines: the always-on IPv4 header checksum and the norm-gated TCP checksum recompute
over the rewritten no-payload handshake (covered region entirely in PHV, so a full
`Checksum.update()` needs no payload read). Present and allocated; see `mau.resources.log`.

## Interpretation

The normalizer "fits comfortably," as the Experiment 2A review predicted: a single TCAM block, a
handful of SRAMs, no registers, modest normal-PHV pressure, sub-200-cycle MAU latency. There is
ample headroom to add the rest of a real edge program around it. The one genuine resource note is
that the fixed-width `data_offset`-keyed option parse plus the tagalong option region is the main
consumer, not the checksum or any state.
