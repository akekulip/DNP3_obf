# dnp3_timing_normalizer.p4 — compile note

Canonical **timing-only** reference for the meeting deliverable: `p12_combined.p4`
with the egress size-normalization removed (replaced by the `ibspg_dnp3.p4`
byte-preserving pass-through) and a **G-selection guard** added to the ingress.

- **Source SHA-256:** `82f572ce63d05baf94cf1d7ba39c68195326531581a848d4b958edeace3eadb0`
  (post fix B-D1, 2026-07-25; pre-fix was `d6fcd530…537c`)
- **File:** `research/timing_final/p4/dnp3_timing_normalizer.p4` (923 lines)
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

---

## 2026-07-25 — fix B-D1: first-ACK deadline-arming idempotency

**What was wrong.** The deadline-arming path was not idempotent. Every qualifying pure
ACK re-armed `reg_deadline` (via `dec_ack_arm` → `dl_val = dl_cand`, written
unconditionally by `deadline_rmw`) and re-captured `reg_t_ack` (via
`if (meta.ack_ok == 8w1) v = ts32`). So a duplicate/retransmitted ACK pushed the
deadline out to `t_lastACK + G`, and the measured native CLRT became
`(t_lastACK − t_firstACK) + G` — ACK spacing leaked into the normalized interval.

**The fix (arming path only).** Anchor to the FIRST qualifying ACK; ignore later ACKs of
the same armed transaction. Enforced atomically inside the stateful ALUs — no
read-then-write race, no metadata guard, no extra register access.

- **Deadline — `RegisterAction deadline_arm_once` on `reg_deadline`** (new, second RA on
  the *same* register). Compare-and-arm-once:
  `rv = now_word − v; if (v == UNARMED_WORD) v = dl_val;`. It runs for the qualifying
  ACK only (call site branches on `meta.ack_ok == 1`); every other packet — **including
  the ARM, which still disarms via `dl_val = UNARMED_WORD`** — uses the unchanged
  `deadline_rmw`. Because the ARM leaves `v == UNARMED_WORD` and the first ACK's write
  sets the armed word (marker bit 0 set, `!= UNARMED_WORD`), a second ACK reads a
  non-unarmed word and the guarded write does not fire → the deadline is untouched. The
  predicate is a full-32-bit **memory-vs-constant** compare (identical shape to the
  write-if-zero ts registers); no bit-slice, no gateway/arithmetic-field slice. PHV
  inputs: `now_word`, `dl_val` = 2 (unchanged from `deadline_rmw`).

- **Shadow t_ack — three RАs on `reg_t_ack`** (`t_ack_reset` / `t_ack_capture` /
  `t_ack_read`), mutually exclusive (one access per packet), mirroring the deadline's
  reset/arm-once so t_ack tracks the same transaction boundary. The ARM resets t_ack to
  0 (`t_ack_reset`, so the next transaction captures fresh); the FIRST qualifying ACK
  captures `ts32` only while `v == 0` (`t_ack_capture`); a duplicate ACK reads `v != 0`
  and leaves it; the RESPONSE and all others read `now − t_ack` (`t_ack_read`). Reset on
  ARM is required for multi-transaction correctness (a pure write-if-zero would capture
  only the first-ever transaction). Native CLRT is therefore now `t_response − t_firstACK`
  — the correct behavior. PHV input: `ts32` only (write values are `ts32` or the
  constant 0); ≤2.

Call sites: `reg_deadline` at apply level 4 became a 2-way branch on `meta.ack_ok`;
`reg_t_ack` at the G-guard section became a 3-way branch on
`meta.pkt_class == CLASS_ARM` / `meta.ack_ok == 1` / else. `dec_ack_arm` and
`tbl_state_decode` are unchanged (`ack_ok == 1 ⟺ dl_val == dl_cand`, so `arm_once`
always sees a valid armed word).

**Why atomic-in-SALU and not a metadata guard.** A metadata guard would need the armed
state of `reg_deadline` *before* the decode sets `dl_val`, but the deadline is read once
per packet at level 4 (after the decode) and TF1 forbids a second access — so the only
place with race-free access to "was it already armed" is inside the deadline SALU itself.
The atomic form fit within the 2-PHV-input budget, so no fallback was needed.

**Compile result (bf-p4c 9.13.1, `--target tofino --arch tna -g`).**

- **0 errors**, 3 warnings (the same benign ones: parser `meta` all-zero init +
  two `min_parse_depth_accept_loop` unroll notes).
- **Ingress 10 / 12 stages, egress 0 / 12** — unchanged from the pre-fix 10/0.
- **Critical path (dep-graph) 8** — unchanged.
- **Registers (Meter-ALU) 9, counters (Stats-ALU) 18 — unchanged**; SRAM 55, Map RAM 54,
  TCAM 1 — unchanged. The three extra RegisterActions live on the two *existing*
  registers, so no new register/SALU/SRAM was consumed. Logical tables 57 → 60 (+3, the
  added arm-once gateway/RA variants); no placement-failure messages in any log.
- **Source SHA-256:** `82f572ce63d05baf94cf1d7ba39c68195326531581a848d4b958edeace3eadb0`
  (was `d6fcd530ef73f9607b73f3f7a34691f0ea06881208cf79f187c28faa0984537c`). 923 lines.

**Per-property preservation (each verified unchanged by the fix).**

- **Deadline expiry — UNCHANGED.** `age = now_word − v` is still returned by both deadline
  RAs identically; `tbl_deadline_expiry` still tests `0x00000000 &&& 0x800000FF`. The fix
  only gates the *write*, never the returned age.
- **Packed transaction state — UNCHANGED.** `reg_tag` (`rv = gen_in − v`) and its
  generation gate are untouched; the armed marker still rides in the low byte of the
  deadline word; `dec_ack_arm`, `dec_arm`, `dec_none`, `dec_live` and `tbl_state_decode`
  entries (including `CLASS_ACK 0x00 &&& 0xFE`) are byte-for-byte unchanged.
- **Blocker reservoir loop — UNCHANGED.** The dequeued `ROLE_BLOCK` branch (stale →
  deadline → budget termination, `hdr.ib.seq − 1` re-enqueue) is untouched.
- **Fail-open — UNCHANGED.** `meta.tag_val = TAG_INACTIVE` on `budget_zero` and the
  `ctr_block_term_timeout` drop branch are untouched.
- **Token isolation — UNCHANGED.** `0x88C1` is still forced to `ROLE_BLOCK` in the parser.
- **Byte preservation — UNCHANGED.** The only host-frame field written anywhere is still
  `hdr.ib.seq` (the internal token's own counter); ingress/egress deparse order and the
  egress pass-through are untouched. The fix writes only registers/metadata.

**Behavioral confirmation.** A second (duplicate/retransmitted) qualifying ACK for the
same armed transaction now reads `reg_deadline == dl_cand (≠ UNARMED_WORD)` → deadline
write suppressed, and `reg_t_ack != 0` → t_ack write suppressed. It therefore moves
neither the deadline nor t_ack; the effective CLRT normalization anchors to `t_firstACK`.
