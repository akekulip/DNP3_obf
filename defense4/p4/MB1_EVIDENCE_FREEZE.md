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

**Honest status: RESOLVED by MB-1 v3 (see the v3 result block at the bottom; v2 is SUPERSEDED).** The
**defect-free** semantically complete ingress core (`mb1_v3_unified_core.p4`, all ten fixes) **compiles at
12/12 ingress, critical path 11 — it FITS, but EXACTLY at the ceiling with zero ingress headroom**,
independently verified this session with raw evidence committed (`evidence_mb1v3/`). v2's 10/12 came from
a defective program and is retired as the load-bearing number.

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

## MB-1 v2 RESULT — SUPERSEDED (a later review found fatal logic defects)

> **SUPERSEDED 2026-08-04.** A second review found MB-1 v2 has **fatal logic defects** (directional
> non-canonical flow key so request/response never share state; pktgen blocker path can never activate;
> generation-parity validity; response reservoir never seeded; incomplete cleanup; slot_occupied matched
> with a wildcard mask; 6-byte header with no inner_len; **MODE_FAIL_OPEN has no release entry** → falls
> to hold; uninitialized parser metadata). So v2's 10/12 / CP 8 is the cost of a **DEFECTIVE** program and
> does **not** establish the GO. The verdict is being re-decided by **MB-1 v3** (`mb1_v3_unified_core.p4`),
> which fixes all defects; see the v3 result block. The v2 numbers below are retained only as a record.

The placeholder verdict above was answered by v2 (now superseded). `mb1_v2_unified_core.p4` implements the
nine corrections and **compiles at 10/12 ingress stages, critical path 8** — but with the logic defects
listed above, so this is not a valid GO. Independently verified compile numbers (hashes,
`table_summary.log`) this session.

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

---

## MB-1 v3 RESULT — the DEFECT-FREE complete ingress core (2026-08-04, VERIFIED, raw evidence committed)

MB-1 v2 was superseded for fatal logic defects. `mb1_v3_unified_core.p4` fixes all ten and **compiles at
12/12 ingress stages, critical path 11 — it FITS, but EXACTLY at the ceiling: 0 empty ingress stages,
0 margin.** The ten fixes cost +2 ingress (10→12) and +3 critical path (8→11) over the defective v2. No
required fix was dropped to fit. Independently verified (compile numbers, header width, per-fix source
lines, warning elimination, integrity); **raw compiler evidence committed** in `evidence_mb1v3/`.

| item | value |
|---|---|
| file | `mb1_v3_unified_core.p4` sha256 `4b0d1951926caaeab43e902c8b1ce087e7087d1aa6bea0892e530544d59fc48a` |
| command | `bf-p4c --target tofino --arch tna -g -o build_mb1v3 mb1_v3_unified_core.p4` (p4c 9.13.1) |
| result | **exit 0, 0 errors, 2 benign warnings** (TNA pktgen parser-unroll, from `tna.p4`); the v2 `uninitialized_out_param` is ELIMINATED |
| ingress / egress / CP | **12 / 12** · 0 · **11** |
| tables / gateways | 122 / 77 |
| SALU (Meter ALU) / Stats ALU | 10 / 11 |
| SRAM / Map RAM / TCAM | 59 / 42 / 9 |
| per-stage LTID | [14,6,8,9,6,14,14,6,1,16,16,12] — st9/st10 16/16 saturated (the ACT forwarding/counter tail) |
| PHV | B0-15, H0-15, W0-15 all 16/16 container-full; absorbed by B32-47 + non-overlapping W0-15 live-range overlay; upper groups free |
| context.json / .bfa sha256 | `4733cb09c53e30f7c8b2456aff85cec5db7813dd63ad01011151f61af7ff2bbc` / `dc936fee6988bdc3e9814c9cc99233ec1314ea0e6bb972ffc847ec67d37b8d00` |

**All ten fixes verified in source (line cites confirmed independently this session):**
1. **Canonical bidirectional flow key** — signed-lexicographic endpoint ordering (`tbl_key_order`) before
   the hash, so request and response share the index (L713–770).
2. **Collision-guarded fingerprint → fail open** — `reg_fp` second-poly fingerprint per index; mismatch
   sets `collision` → the packet FAILS OPEN and state-writes are suppressed (L507–521, L779–791, L1238).
   The 10-bit hash is now "hash index + collision-guarded fingerprint", not "exact matching".
3. **pktgen ordering** — reads `reg_active_flow` FIRST → folds the index → reads the valid generation,
   then stamps the token (L1108→1128→1136).
4. **Explicit validity bit** — `reg_valid`; `tbl_pktgen_active` keys on `valid_cur`, not generation
   parity (L524–535, L882).
5. **Both reservoirs seeded** — ROLE_BLOCK→QID_ACK_BLOCK(7) AND ROLE_RESP_BLK→QID_RESP_BLOCK(3)
   (L55, L667–674, L1055–1067).
6. **Full state retirement** — event/ack_gone/deadline/slot/active-flow/fingerprint/validity cleared on
   terminal completion, fail-open, and FIN/RST; a new SELECT clears prior event+ack_gone (L1115–1220).
7. **Occupancy + expected-slot** — `tbl_realfill` matches `slot_hit` on the FULL 32-bit mask AND requires
   `slot_ok` (in-expected-slot); v2's wildcard-0 defect fixed (L1013–1027).
8. **8-byte D4 header with true `inner_len`** — `outer_encap_h` = 64 bits incl 16-bit `inner_len`
   (= total_len + 14), written in ingress and deparser-emitted (L141–148, L972–978, L1317).
9. **MODE_FAIL_OPEN release entry** — explicit `do_release()` (L1001).
10. **Safe parser init** — every safety-governing metadata field initialized to its bypass/fail-open-safe
    default; unclassified packets route to `accept_bypass`; **`uninitialized_out_param` absent** (L283–345).

**Verdict: Unified ingress core = GO, but QUALIFIED — it fits at 12/12 with ZERO ingress headroom.** Any
further ingress logic needs an egress move or a 2-pass split. Egress is entirely free (0/12) for the
MB-8 padding action. This is a COMPILE/resource result, not a silicon/functional validation; end-to-end,
the size data path (MB-8), and four-level TM on silicon (MB-3) remain unproven.
Integrity: v2 (`d25e2811…`) and skeleton (`df3470c…`) sha256 unchanged; switch not touched (offline
`bf-p4c` only). Raw logs: `evidence_mb1v3/{table_summary,mau.resources,phv_allocation_summary_0}.log`,
`EVIDENCE.md`, `compile_transcript.log`.
