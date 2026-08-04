# MB-1 evidence freeze

**Frozen 2026-08-04 per directive §3. The MB-1 decisive ingress-resource result and its provenance.
Do not re-derive; cite this. All numbers VERIFIED from the compile artifacts this session.**

## Verdict (directive §1 wording)

> **The unified Defense 4 ingress control core compiles in one Tofino-1 pipeline image at 10/12 ingress
> stages, with critical path 9.** This establishes resource feasibility for the complete ingress
> decision, transaction-state and size-control surface.

This is **not** a claim that the complete end-to-end Defense 4 is proven (directive §2). Physical padding
emission, exact outer-frame sizing, decoding, padding removal, filler generation, and four-level Traffic
Manager behaviour remain unverified.

## Provenance

| item | value |
|---|---|
| commit (evidence base) | `9cd06e2` on `main` (this freeze added after) |
| compiler | `p4c 9.13.1 (SHA e558d01)` — `/home/philip/bf-sde-9.13.1/install/bin/bf-p4c` |
| command | `bf-p4c --target tofino --arch tna -g -o build_mb1 mb1_unified_skeleton.p4` |
| MB-1 source sha256 | `df3470c5e33ce91440daad7dab095f07f930df696daa014d1d3785f2890ec897` (`mb1_unified_skeleton.p4`) |
| stripped-D2 source sha256 | `6f94c27dc6a63b43282f504f7d0ecc9f9a8a6b9950d3028834db052fc984b69b` (`d2_core_stripped.p4`) |
| `.bfa` sha256 | `bcaa4c8e296483a737782ce2f464be2401ac0610527f96126ecd1714ba8b4483` |
| `context.json` sha256 | `943c87b00da545d6b2457519a13bf25ebc448e5f4ddcda5e84324649766cb43c` |
| artifacts | `build_mb1/pipe/{mb1_unified_skeleton.bfa, context.json, logs/{table_summary,mau.resources,phv_allocation_summary_0}.log}` ; transcript `build_mb1_compile.log` |

## Resources (MB-1, VERIFIED)

| ingress stages | egress | critical path | tables | SRAM | Map RAM | TCAM | Meter/SALU | Stats ALU | Gateways | VLIW | LTID |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **10 / 12** | 0 | **9** | 75 | 41 | 28 | 3 | **6** | 8 | 37 | 44 | 75 |

PHV normal 44 containers (19.6%) / 650 bits; the one full group is B0-15 (8-bit ingress). 2 empty
ingress stages (st10/11); egress 0/12 free. Stateful ALUs: `reg_tag`, `reg_deadline`, `reg_phase`,
`reg_event`, `reg_slot_clock`, `reg_slot_bitmap`.

## Table→stage allocation (leading tables)

`tbl_params` (mode + size_profile), `tbl_guard`, `tbl_encap` (outer fields) at stage 0; `tbl_slot_assign`
at stage 1; `tbl_slot_onehot`, `tbl_slot_size`, `tbl_realfill`, `tbl_phase_decode`, `tbl_state_decode`,
`tbl_release_select` across stages 0-9. Full map in `build_mb1/pipe/logs/table_summary.log`.

## Reachability — every predicate/phase/size/outer element present, NOT optimized away (directive §3)

Confirmed from `context.json` and the source:

| element | evidence |
|---|---|
| 5 release predicates | `MODE_IMMEDIATE=0, MODE_MATCH_EVENT=1, MODE_ABS_DEADLINE=2, MODE_PRED_OFFSET=3, MODE_FAIL_OPEN=4` (source const) → `tbl_release_select` ternary match on `(mode, response_seen, ack_gone, fail_open)` → `do_release`/`do_hold` (both entries present in context.json) |
| phase transitions | `reg_phase` + `Ingress.tbl_phase_decode` present; SELECT→OPERATE linkage by flow+phase+generation |
| size lookup | `Ingress.tbl_slot_size` present, **keyed on `[meta.size_profile, meta.slot_id]`** (verified) |
| outer fields | `Ingress.tbl_encap` present; `hdr.outer.{direction,txn_tag,slot_id,realfill,size_bytes}` deparser-emitted (overlaid onto computed `meta.*` containers → 0 extra instructions, live) |
| slot state | `tbl_slot_assign`, `tbl_slot_onehot` present |
| real/filler tag | `tbl_realfill` present |
| params/size_profile select | `tbl_params` → `set_params` present |

## Stripped-D2 baseline (directive §4 — retire the "7–8" estimate)

**Controlling measured result: 9 ingress stages / CP 7 / 50 tables / 2 SALU.** The estimated "7–8" is
RETIRED. `build_d2core/pipe/logs/table_summary.log`.

## Caveat (directive §9)

The PHV overlay proves the outer-field ASSIGNMENTS are inexpensive. It does NOT prove the complete
padding-and-restoration mechanism. Physical padding emission, exact observer-visible frame lengths,
encoder/decoder port paths, padding removal, byte-identical restoration, and hidden real/filler
discrimination are the subject of the SEPARATE size-data-path offline gate (MB-8), not yet run.
