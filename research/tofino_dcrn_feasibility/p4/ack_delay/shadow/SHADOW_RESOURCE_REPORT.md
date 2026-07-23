# dnp3_shadow.p4 — Tofino-1 resource report

Phase 1 of `research/END_TO_END_IMPLEMENTATION_PLAN.md` (charter §G, gap row 2). PASSIVE DNP3
shadow classifier: parses/classifies every packet, emits a measurement Digest, changes NOTHING on
the wire (bump-in-the-wire, byte + order identity). **Offline compile only — nothing loaded on the
switch (GATE 1 not crossed).**

## Compile verdict: **PASS**

| Item | Value |
|---|---|
| Compiler | `bf-p4c` **9.13.1** (SHA `e558d01`), local `/home/philip/bf-sde-9.13.1` |
| Command | `bf-p4c --target tofino --arch tna -g -o out dnp3_shadow.p4` |
| Exit code | **0** |
| Errors | **0** |
| Warnings | **2** (both benign — see below) |
| Binary generated | yes (`out/pipe/dnp3_shadow.{bfa,bin}`, `out/dnp3_shadow.conf`, `out/bfrt.json`) |
| Full log | `shadow/compile.log` |

### Warnings (not failures)
Both are the identical line:
> `warning: Parser state min_parse_depth_accept_loop will be unrolled up to 3 times due to @pragma max_loop_depth.`

This is emitted by the **TNA library**, not by any construct in `dnp3_shadow.p4`. It is the
compiler auto-padding the (deliberately minimal) egress parser to Tofino-1's minimum parse depth;
the same warning appears verbatim in the known-good reference build
`../compile_defense1_telem/compile.stderr.log`. It does **not** indicate unsupported behavior. No
Class-7 hash canary (`Expected single call to get for hash instance`) and no silent Class-6 ICE
(`1 error generated` with no text) appeared.

## Ingress stage fit: **4 / 12 — FITS Tofino-1 with 8 stages to spare**

Occupied ingress MAU stages: **0, 1, 2, 3** (from `out/pipe/logs/resources.json` +
`out/pipe/context.json`; all 31 logical tables are `ingress`). The egress is a no-op pass-through
with **zero MAU tables**. As predicted in the plan (§5), the shadow — which has no recirc/hold/
release logic — is far smaller than the 12/12-stage Defense-1.

Per-stage occupancy (ingress):

| Stage | Logical tables | Gateways | SRAM | TCAM | Map RAM | Stats ALU | Stateful ALU | VLIW |
|------:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 9  | 2 | 3 | 0 | 2 | 0 | 1 (`reg_shadow_enable`) | 5 |
| 1 | 5  | 2 | 0 | 0 | 0 | 0 | 0 | 3 |
| 2 | 16 | 2 | 0 | 0 | 0 | 0 | 0 | 9 |
| 3 | 1  | 2 | 2 | 0 | 2 | 1 (`class_ctr`) | 0 | 1 |

## MAU resource totals (of Tofino-1 budget)

| Resource | Used | Device budget | Notes |
|---|---:|---:|---|
| Ingress stages | **4** | 12 | stages 0–3 |
| SRAM blocks | 5 | 480 | tcp_overhead const table (stage 0) + class_ctr counter (stage 3) |
| TCAM blocks | **0** | 24 | no ternary/range match tables in the MAU |
| Map RAM | 4 | 480 | counter/register attached RAMs |
| Gateways | 8 units | — | the if/else-if classification chain + conditions |
| Stats ALUs | 1 | 24 | `class_ctr` (per-class packet Counter, stage 3) |
| Stateful ALUs | 1 | 48 | `reg_shadow_enable` RegisterAction (stage 0) |
| Logical tables | 31 | — | mostly compiler-generated gateways/conditions |
| VLIW instr | 18 | — | |
| Crossbar bytes | 39 | — | |

## PHV (from `out/pipe/logs/phv_allocation_summary_3.log`)

| Container width | Used | Available | % |
|---|---:|---:|---:|
| 8-bit  | 8  | 32 | 25.0% |
| 16-bit | 30 | 48 | 62.5% |
| 32-bit | 15 | 32 | 46.9% |
| **Total bits** | **1024** | 2048 (these MAU groups) | 50.0% |

Counts include the egress min-parse-depth padding collections. No Class-3 SuperCluster failure
(every metadata flag is `bit<8>`; no sub-byte metadata adjacent to 32-bit register outputs).

## Parser

| | Ingress | Egress |
|---|---:|---:|
| States | 12 | 5 |
| Longest path | 9 states | 5 states |
| Match rows (range-expanded) | **≈163** | — |

The ingress parser reuses Defense-1's length-gate: the `parse_tcp` `select` range-matches
`ipv4.total_len` per `data_offset` (11 ranges `50..65535 … 90..65535`) with SYN excluded
(`flags[1:1]==0`). Range matching expands into ~163 parser match rows — the same order as
Defense-1's noted 171/256, and slightly fewer here because the shadow drops the `ETHERTYPE_DCRN`
Ethernet branch and the `parse_bridge` state (Ethernet branches on IPv4 only). Well within the
256-row parser TCAM budget.

## Learn digest: **fits the 48 B quantum (ends at byte 43)**

The digest (`ShadowIngressDeparser.shadow_digest`, one per TCP packet, A/B-gated by
`reg_shadow_enable`) is **34 logical bytes**. The 48 B learn-quantum cap (constraint Class 4) is on
the **container-aligned physical layout**, not the logical bit sum. An initial ungrouped field
order fragmented the layout to **~51 B and the assembler rejected it**
(`learning digest limited to 48 bytes`). Fix (Class 4): trim `ingress_tstamp` 48→32 bits (ample for
a ~13 ms CLRT; wrap handled offline), narrow the two dev-port fields to `bit<8>` (dp8/dp9 fit
exactly), and **group the digest fields by width (32b, then 16b, then 8b)** to remove the alignment
padding. Final physical layout (from `out/pipe/dnp3_shadow.bfa` `context_json`) ends at byte offset
**42+1 = 43**, under 48 with margin.

## Iteration history (three compile fixes, all offline)

1. `Counter(bit<32> size…)` ctor rejected a `bit<8>` size const → retyped `NUM_CLASSES` to `bit<32>`.
2. `bool on_dnp3 = hdr.tcp.isValid() && …` → `source of modify_field invalid`. Assigning an
   `isValid()`-derived expression into a `bool` local is unsupported; recomputed `on_dnp3` as a
   guarded `bit<8>` flag (`isValid()` stays inside `if` conditions only — the Defense-1 idiom).
3. Learn digest 51 B > 48 B → trimmed + width-grouped as above.

## Artifacts

- P4 source: `shadow/dnp3_shadow.p4`
- Full compiler log: `shadow/compile.log`
- Compiled output tree: `shadow/out/` (`bfrt.json`, `dnp3_shadow.conf`, `pipe/dnp3_shadow.bfa`, `pipe/logs/*`)
- Control-plane stub (dry-run by default): `shadow/dnp3_shadow_setup.py`
