# MB-1 evidence freeze

**Frozen 2026-08-04 per directive §3. The MB-1 decisive ingress-resource result and its provenance.
Do not re-derive; cite this. All numbers VERIFIED from the compile artifacts this session.**

## Verdict (corrected after review — this is a PLACEHOLDER lower bound, not the complete-core proof)

> **The present MB-1 PLACEHOLDER control surface compiles in one Tofino-1 pipeline image at 10/12 ingress
> stages, with critical path 9.** This is a **lower bound** on the ingress cost of a unified Defense 4,
> **not** proof that the semantically complete ingress core fits.

A 2026-08-04 review established that `mb1_unified_skeleton.p4` does **not** implement several required
semantics, so its 10-stage result understates the true cost. The missing semantics (each verified absent
in the source):

| gap | evidence in `mb1_unified_skeleton.p4` |
|---|---|
| depth-1 registers, **no flow-key** indexing (all `Register<…, bit<1>>(1,0)`, index const 0) | reg_tag/deadline/phase/event/slot_clock/slot_bitmap |
| linkage keyed on **DNP3 app_control**, which increments SELECT→OPERATE (so a legit pair never matches) | parser `meta.gen_in = hdr.dnp3_app.app_control` (~L384); `phase_rmw` `gen_in - v` (~L441) |
| **every RESPONSE clears the phase**, including the SELECT-response (wipes SBO linkage before OPERATE) | ingress `PCLASS_CLEAR` on `ROLE_RESP` (~L736–738) |
| **no `ack_gone`** state | absent |
| **fail-open only under `MODE_FAIL_OPEN`**, not a universal backstop | `tbl_release_select` (~L671) |
| **slot-bitmap return discarded**; `slot_occupied` read by `tbl_realfill` before it is written | (~L680, L784–788) |
| **no epoch cleanup** of the slot bitmap | absent |
| **only 2 QIDs** (7,1), not the 4-queue construction | `QID_BLOCK=7, QID_RESP=1` |
| exact transaction matching + complete cleanup absent | subtraction on depth-1 registers |

**Honest status: RESOLVED by MB-1 v2 (see the result block at the bottom).** The corrected, semantically
complete ingress core (`mb1_v2_unified_core.p4`, all nine corrections) **compiles at 10/12 ingress,
critical path 8 — it FITS**, verified this session. This skeleton record is retained as the placeholder
lower-bound; the load-bearing feasibility number is now v2's 10/12.

This is also **not** a claim that end-to-end Defense 4 is proven (directive §2): physical padding
emission, exact outer-frame sizing, decode, padding removal, filler generation, and four-level Traffic
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

---

## MB-1 v2 RESULT — the semantically complete ingress core (2026-08-04, VERIFIED)

The placeholder verdict above is now ANSWERED. `mb1_v2_unified_core.p4` implements all nine corrections
and **compiles at 10/12 ingress stages, critical path 8** — it FITS, with 2 empty ingress stages of
margin and a critical path *lower* than the placeholder (CP 8 vs 9). Independently verified this session
(hashes, `table_summary.log`, per-correction source lines).

| item | value |
|---|---|
| file | `mb1_v2_unified_core.p4` sha256 `d25e28114971d67175f86645061444768981a95c5e13d394ef0888c4bfd54281` |
| command | `bf-p4c --target tofino --arch tna -g -o build_mb1v2 mb1_v2_unified_core.p4` (p4c 9.13.1) |
| result | **exit 0, 0 errors, 3 benign warnings** |
| ingress / egress / CP | **10 / 12** · 0 · **8** |
| tables / gateways | 96 / 58 |
| SALU (Meter ALU) / Stats ALU | 8 / 9 |
| SRAM / Map RAM / TCAM | 47 / 34 / 4 |
| per-stage LTID | [16,10,11,11,5,4,1,16,16,6] |
| PHV saturation | B0-15 **16/16** AND H0-15 **16/16** container-saturated; W0-15 11/16; upper groups empty |
| registers placed | reg_slot_clock(st1); reg_tag/reg_phase/reg_active_flow(st2); reg_ack_gone/reg_event(st3); reg_deadline(st4); reg_slot_bitmap(st5) |

**All nine corrections implemented and verified in source** (line cites confirmed this session):
1. **Flow-keyed state** — 5 per-txn registers `Register<…, bit<10>>(1024,0)` indexed by a CRC16 hash over
   the 5-tuple (`flow_hash`, L436-455); slot_clock/bitmap left global (per scheduler domain) by design.
2. **Internal generation** — `reg_tag` open-increment counter is the linkage key; DNP3 `app_control`
   captured as `meta.app_seq` **reference-only, never a match key** (L405-411).
3. **Correct SELECT-response handling** — phase FSM {IDLE, SELECT_SEEN, OPERATE_SEEN}; `phase_resp`
   clears to IDLE ONLY when `v==PH_OPERATE_SEEN` (OPERATE-response) and PRESERVES on the SELECT-response.
4. **ack_gone** — `reg_ack_gone` (L524), set on reservoir drain, consumed by the release predicate.
5. **Universal fail-open** — `tbl_release_select` mode-WILDCARD backstops (abs-deadline expiry L835,
   budget exhaustion L836) release under EVERY mode, above the per-mode predicates.
6. **Working slot state** — bitmap RA return captured into `meta.slot_occupied`; occupancy computed
   BEFORE `tbl_realfill` reads it (ordering bug fixed).
7. **Slot epoch cleanup** — `tbl_rollover` (slot_id==0) → `bitmap_clear`.
8. **Four QIDs** — QID_ACK_BLOCK=7 > QID_ACK_HOLD=5 > QID_RESP_BLOCK=3 > QID_RESP_HOLD=0, with routing.
9. **Exact matching + cleanup** — keyed on (flow, internal generation); cleanup on completion and on
   FIN/RST (`tbl_fin_rst`).

Two real bf-p4c constraints were hit and resolved during bringup (3 compiles): TF1 caps RegisterActions
at 4 per Register (the phase FSM collapsed from 5 to 3 actions); and whole-struct parser start-init of
MAU-assigned fields raised `clear-on-write assigned multiple times` (init only MAU-written metadata in
`start`). Stage count (10) exceeds CP (8) for the same LTID-tail reason as Defense 3 — the ACT-block
forwarding tables saturate the 16-LTID cap in st7/st8 and spill to st9 (a placement tail, not dependency
depth); ~42 free LTIDs remain in st9-11. No fallback (egress move / 2-pass) needed.

**Bounds this proves and does NOT prove.** PROVES: the resource feasibility of the *semantically complete
ingress control core* on one Tofino-1 pipeline. Does NOT prove: end-to-end operation, the egress padding
data path (MB-8), four-level TM priority on silicon (MB-3), byte-identical restore, or same-device
`Obs(READ)≈Obs(SBO)`. It is a COMPILE (resource) result, not a silicon/functional validation.
Artifacts: `build_mb1v2/pipe/logs/`, transcript `build_mb1v2_compile.log`.
