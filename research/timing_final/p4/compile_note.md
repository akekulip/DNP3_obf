# dnp3_timing_normalizer.p4 — compile note

Canonical **timing-only** reference for the meeting deliverable: `p12_combined.p4`
with the egress size-normalization removed (replaced by the `ibspg_dnp3.p4`
byte-preserving pass-through) and a **G-selection guard** added to the ingress.

- **Source SHA-256:** `d6fcd530ef73f9607b73f3f7a34691f0ea06881208cf79f187c28faa0984537c`
- **File:** `research/timing_final/p4/dnp3_timing_normalizer.p4` (854 lines)
- **Compiler:** bf-p4c **9.13.1** (local), `--target tofino --arch tna -g`
- **Result:** **0 errors, 3 warnings** (all benign — see below).
- **Verdict:** compiles clean; **ingress 10/12 stages**, **egress 0/12 stages**.

Compile command (exactly as run; see `compile.log` for full output):

```bash
PATH=/home/philip/bf-sde-9.13.1/install/bin:$PATH \
  bf-p4c --target tofino --arch tna -g -o out dnp3_timing_normalizer.p4
```

The 3 warnings are the same benign ones the base programs emit and are **not**
resource/placement issues: `out parameter 'meta' may be uninitialized` (the parser
relies on the compiler's all-zero metadata init for the classification fields, by
design — Tofino has no parser clear-on-write) and two
`min_parse_depth_accept_loop will be unrolled` parser notes.

## Resource table (measured, from `out/pipe/logs/`)

| Resource | timing_normalizer | p12_combined (baseline) | Δ |
|---|---|---|---|
| Ingress MAU stages | **10 / 12** | 8 / 12 | **+2** |
| Egress MAU stages | **0 / 12** | 2 / 12 | **−2** |
| Critical path (dep-graph) | **8** | 8 | **0** |
| Logical tables | 57 | 48 | +9 |
| SRAM (of 480) | 55 | 47 | +8 |
| Map RAM (of 384) | 54 | 40 | +14 |
| TCAM (of 288) | 1 | 1 | 0 |
| Stateful ALU / registers (Meter-ALU slots) | 9 | 6 | +3 |
| Stats ALU (counters) | 18 | 14 | +4 |
| Ingress parser states / TCAM rows | 13 / 90 | 12 / 89 | +1 / +1 |
| Egress parser states / TCAM rows | 5 / 8 | 36 / 54 | −31 / −46 |

Baseline column was produced by compiling `p12_combined.p4` with the **same** bf-p4c
9.13.1 into a scratch dir, so the delta is measured, not asserted. The task's stated
baseline ("8/12 ingress, 2/12 egress") is confirmed.

**vs the timing-only expectation.** The removed size code was egress-only, so removing
it cannot change ingress stage count and drops the egress to a pure pass-through
(2 → 0 egress stages, egress parser 36 → 5 states). The G-guard is added to the
ingress and costs **+2 ingress stages (8 → 10)**, comfortably inside the 12-stage
limit. Critical path is **unchanged at 8** — the guard's dependency chain
(reg_t_ack → clrt_diff → clrt_guard) does not lengthen the longest chain; it places
in later stages for resource reasons but the graph depth stays 8. This matches the
expectation for a timing-only build: no size logic anywhere, guard cost bounded and
well within budget.

Register inventory (9 total): the 6 frozen ones (`reg_tag`, `reg_deadline`,
`reg_ts_first_block`, `reg_ts_ack_arm`, `reg_ts_block_term`,
`reg_ts_first_resp_release`) + 3 new (`reg_t_ack`, `reg_native_clrt`,
`reg_protection`). Counter inventory: 17 `Counter` externs (the 11 frozen + 6 new);
the Stats-ALU total of 18 reflects the compiler replicating some counters across
stages, which is normal.

## STEP 1 — what size code was removed (all egress-only)

Deleted from `p12_combined.p4`'s egress and replaced with the `ibspg_dnp3.p4`
pass-through:

- the `pay1..pay64` / `pad1..pad64` payload-chunk headers and the `eg_headers_t`
  struct that held them;
- the `EgParser` payload-chunking states (`pl_6..pl_66`) and its `total_len` select;
- the `size_norm` table and all 14 `pad_*` actions;
- the `ctr_size_normalized` / `ctr_size_failopen` counters and the `meta.normalized`
  field/logic (`eg_meta_t` is now empty);
- the pad emission in `EgDeparser`.

New egress (`dnp3_timing_normalizer.p4:812–848`) is the verbatim byte-preserving
pass-through: `EgParser` extracts only ethernet (`:829`), `Egress` apply is empty
(`:839`), `EgDeparser` emits only ethernet and lets everything after it ride out as
residual (`:846`). A released ACK or RESPONSE (`bypass_egress=0`) therefore egresses
byte-identical.

## STEP 2 — what the G-selection guard added (directive §3)

At the point a fresh RESPONSE from the outstation (`dir == DIR_OUT`) is admitted and
enqueued to `Q_RESP`, using values already in the pipeline:

- `native_clrt = t_response_arrival − t_ack`, produced by a new shadow register
  `reg_t_ack` whose single RegisterAction returns `rv = now − v` and captures `t_ack`
  on the qualifying ACK via the already-set `meta.ack_ok` write-enable
  (`:473–479`, read at `:763`). Stored in `reg_native_clrt` (`:484`) for control-plane
  readout.
- `clrt_diff = native_clrt − G` in its own table `tbl_build_clrt_diff` (`:619–624`),
  then `protection = (native_clrt < G)` via the **sign-bit ternary** table
  `tbl_clrt_guard`, mask `0x80000000` (`:631–642`) — the same ternary-on-sign-bit
  technique the deadline expiry uses (`:611`), **no bit-slice** of an arithmetic
  field anywhere. Stored in `reg_protection` (`:488`).
- Two compares, deliberately independent (cross-check; equal because
  `deadline = t_ack + G`): compare (1) `now vs deadline` reuses the existing
  `meta.expired` (drives `ctr_response_before_deadline` /
  `ctr_response_at_or_after_deadline`); compare (2) `native_clrt vs G` from
  `tbl_clrt_guard` (drives `ctr_response_actually_held` / `ctr_response_zero_hold`)
  (`:769–780`).
- Release-cause counters `ctr_release_deadline` / `ctr_release_fail_open` are added at
  the existing dequeued-RESPONSE release site (`:750–751`), attributed by the
  already-computed `meta.expired` of the dequeued response (deadline passed ⇒ drained
  on the deadline; not passed ⇒ drained early on the pass budget = fail-open). These
  are **added, not derived** from `ctr_block_term_deadline` / `ctr_block_term_timeout`:
  the block-term counters increment K times per reservoir drain, whereas these give a
  clean 1:1-with-release attribution. The block-term counters remain unchanged for the
  per-token view.

Semantics (directive §3) exactly: `native_clrt < G` ⇒ `effective_hold = G − native_clrt`,
`protection_applied = true`; else `effective_hold = 0`, `protection_applied = false`,
`low_G_warning = true`. `native_clrt` and `protection` are both live-readable
registers.

## Per-property preservation (each holds identically; file:line)

A line-level diff of the ingress control (`p12_combined` → `dnp3_timing_normalizer`)
shows **every** difference is either a comment or an additive G-guard construct — no
existing timing-mechanism line (register bodies, `tbl_guard`, `tbl_build_now`,
`tbl_build_cand`, `tbl_state_decode`, `tbl_deadline_expiry`, and apply levels 0–5 plus
the ACT block) was changed. The ingress parser is verbatim except for four all-zero
init lines for the new scratch fields.

- **Generation safety — PRESERVED.** `reg_tag` SALU still returns the generation
  difference `rv = meta.gen_in − v` (`:426`); the blocker decode entry fires only on
  an exact tag match `(CLASS_BLOCK_DEQ, 8w0x00 &&& 8w0xFF) : dec_live()` (`:594`), so
  only a token of the current generation is ever `tag_ok`. JOIN B keeps the ACK path
  out. Unchanged bytes.
- **Fail-open (pass-budget) — PRESERVED.** `meta.tag_val = TAG_INACTIVE` on
  `budget_zero` (`:672`) and the `ctr_block_term_timeout` drop branch (`:738–741`) are
  unchanged; a stale tag then retires every later token.
- **Token isolation — PRESERVED.** Ethertype `0x88C1` is still FORCED to `ROLE_BLOCK`
  in the parser `parse_token` state (`:328`), so a token can only reach `to_block()`
  or `drop_pkt()`, never a host port.
- **Deadline / timing mechanism — PRESERVED.** `reg_deadline` returns the age
  `rv = meta.now_word − v`; `tbl_deadline_expiry` tests the armed-and-due pattern
  `0x00000000 &&& 0x800000FF` (`:611`). The guard adds no dependency into this chain.
- **Byte preservation (ingress) — PRESERVED.** `IgDeparser` emits in extraction order
  (`:797–806`); the only field written anywhere in ingress is the internal token's own
  pass counter `hdr.ib.seq` (`:736`). The guard writes only metadata and registers,
  never a host-frame byte.
- **Byte preservation (egress) — PRESERVED (now via the pass-through).** `EgParser`
  extracts only ethernet (`:829`), `Egress` apply is empty (`:839`), `EgDeparser`
  emits ethernet + residual (`:846`). Egress MAU is empty (0 stages), so no egress
  action can touch a frame byte. A released ACK/RESPONSE is byte-identical to the
  ingress deparser output.

No safety property had to be weakened or removed to make the guard fit.

## Build artifacts

`out/` (git-ignored, regenerable): `pipe/logs/table_summary.log` (stage counts),
`pipe/logs/mau.resources.log` (per-stage ALU/SRAM/TCAM), `pipe/logs/metrics.json`
(totals), `pipe/logs/parser.characterize.log` (parser states). `compile.log` holds
the exact compiler stdout/stderr for this build.
