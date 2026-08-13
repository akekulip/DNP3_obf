# RRC stage-recovery — can re-engineering RRC ITSELF net-remove an ingress stage?

**Question.** Prior BOR work froze RRC and consolidated only BOR, hitting an irreducible
13-ingress-stage floor for RRC + faithful one-pipe BOR. This is the untried path: **change RRC
itself.** Can a re-engineered RRC net-remove ≥1 ingress MAU stage so that RRC + a faithful one-pipe
BOR (Bounded OPERATE Release) core places at **≤12 ingress stages on ONE Tofino-1 pipe**?

## 1. VERDICT — **NO.**

A re-engineered RRC does **not** let RRC + faithful BOR fit ≤12 ingress on one pipe. RRC's own
12 ingress stages decompose into a **7-stage register-arm dependency head + a 5-stage
capacity-bound caseA release/drain tail**, and neither can shed a stage without cutting into
load-bearing, silicon-validated mechanism. The only content in RRC that is provably **not**
load-bearing — four forensic timestamp registers — was removed and **compile-proven to recover no
stage**: pure RRC stays 12→12, and the full faithful combined build stays 13→13.

- Compiler: `bf-p4c` 9.13.1 (`~/bf-sde-9.13.1`), `--target tofino --arch tna -g`. Compile-only;
  nothing loaded on hardware.
- Frozen files **not modified** (`git diff` empty): `p4/defense4_rrc_kernel.p4`, the caseA sources,
  `p4/defense4_rrc_bor_sr_probe.p4`. All work is in two NEW probe files (copy + `#ifndef` guard):
  - `p4/defense4_rrc_stagerecovery_probe.p4` — frozen kernel + one guard (`RRC_STRIP_TS_TELEMETRY`);
    diff vs frozen = **4 guard lines only** (verified).
  - `p4/defense4_rrc_bor_stagerecovery_probe.p4` — SR probe + the same guard.
- Raw evidence: `evidence/rrc_stage_recovery/<variant>/`
  (`table_summary.log`, `mau.resources.log`, `table_dependency_summary.log`, `stage_adv.log`,
  `compile.stderr.log`).

## 2. The stage / table matrix

| Variant | source + flags | ingress | egress | crit path | logical tables | binary | fit |
|---|---|---:|---:|---:|---:|:--|:--|
| **Frozen RRC** (baseline) | `defense4_rrc_kernel.p4` | **12** | 3 | 10 | 125 | yes | **FITS** |
| RRC probe, control (no strip) | `…stagerecovery_probe.p4` | 12 | 3 | 10 | 125 | yes | FITS (**≡ frozen**, identical per-stage LTID) |
| **RRC probe, telemetry strip** | `…stagerecovery_probe.p4 -DRRC_STRIP_TS_TELEMETRY` | **12** | 3 | 10 | **121** | yes | FITS — but **no stage shed** (12→12) |
| Combined faithful (report verdict) | `…bor_sr_probe.p4 -DSR1 -DSR2 -DSR3 -DSR4` | **13** | 3 | 11 | 143 | no | **+1 NO-FIT** |
| **Combined faithful + telemetry strip** | `…bor_stagerecovery_probe.p4 -DSR1..4 -DRRC_STRIP_TS_TELEMETRY` | **13** | 3 | 11 | 139 | no | **+1 NO-FIT** |

Ingress stage counts are the authoritative settled values: the two FITTING builds emit a
`tofino.bin` and a final `table_summary`/`mau.resources` (12 ingress); the two NO-FIT builds emit
`bfa: error: tofino supports up to 12 stages, using 13` and produce **no binary**
(`combined_SR1234_orig/compile.stderr.log`, `combined_SR1234_strip/compile.stderr.log`). The
combined-orig **13 reproduces the prior report's faithful verdict exactly**, so the methodology is
consistent.

**Per-stage Logical-TableID occupancy (from `mau.resources.log`, emitted only for a build that
fits):**

```
frozen / control : s0:16 s1:16 s2:9 s3:3 s4:6 s5:2 s6:6 s7:16 s8:16 s9:16 s10:16 s11:3   (125)
telemetry strip  : s0:16 s1:16 s2:5 s3:5 s4:1 s5:6 s6:2 s7:6  s8:16 s9:16 s10:16 s11:16  (121)
```

The control's profile is **byte-identical** to the frozen kernel → the probe is the frozen program.
The strip removed 4 LTIDs (the four forensic registers) — the compiler **repacked the tail**
(stage 7 dropped 16→6, stage 11 rose 3→16) but the tail still occupies **five stages (7–11)**, so
the ingress count is unchanged at 12.

## 3. The dependency spine that forces 12 (diagnosis)

From `mau.resources.log` + `table_summary.log` on the clean frozen compile: critical path is **10**
but 12 stages are used. The 12 stages decompose into two structurally distinct regions:

**HEAD — stages 0–6, a register-arm dependency chain (this sets the critical path).**
`tbl_build_exp_ack → tbl_session → tbl_params → tbl_build_now → tbl_build_cand/_resp →
tbl_resp_authorise → reg_deadline/reg_tresp arm`. Each link is a serialized RegisterAction /
table-data dependency; stages 2–6 are LTID-sparse (1–6 of 16) yet cannot be compressed because the
chain is depth-serial, not capacity-limited.

**TAIL — stages 7–11, the caseA release / hold / drain / block-termination branch tree
(capacity-bound).** After the stage-7 deadline/tresp-expiry compare (`tbl_deadline_expiry`,
`tbl_tresp_expiry`), a wide if/else tree over `(role, dequeued, expired, verdict)` produces **~67
logical tables with min-stage ≥7** (the bare-action TM tables `tbl_to_block{,_0,_1}`,
`tbl_to_resp_block{,_0}`, `tbl_to_hold`, `tbl_to_resp_hold`, `tbl_arm_clone`, plus dozens of
anonymous action tables and `cond-NNN` gateways). 67 tables at 16 LTIDs/stage cannot fit in four
stages (67 > 64), and the min-stage-≥8 subset cannot use stage 7's slack, so the tail genuinely
needs **five** stages. This is exactly where BOR's added tables spill forward.

**Head (7) + Tail (5) = 12.** To reach 11, either the head chain shortens by one link, or ~16 LTIDs
leave the min-stage-≥7 tail.

## 4. The lever attempted, and why it does not shed a stage

**What was changed (the single invariant-safe RRC-internal lever): remove the 4 forensic timestamp
registers** `reg_ts_first_block`, `reg_ts_ack_arm`, `reg_ts_block_term`, `reg_ts_ack_release` and
their four call sites. These are the *only* content in RRC that is provably not load-bearing: the
kernel itself states (lines 529–530) "No predicate, no forwarding decision and no state transition
reads either of them"; their guard flags `meta.ev_*` are set in the tail but consumed **only** by
these writes. Removing them touches **none** of the required invariants — exactly-once OPERATE
release, T0-anchoring, fail-open delivery, RRC carve/reassembly/checksum, and D4 timing are all
untouched (they are write-only forensic instrumentation). **No re-silicon-validation of the
mechanism would be needed** — the defense behavior is bit-for-bit identical; only in-pipeline
telemetry for silicon forensics is lost.

**Why it fails to help.** In the frozen build these four writes happened to sit at the *end* of the
placement (three of them were the *only* tables in stage 11), which made "empty stage 11" look
reachable. It is an illusion: with 12 stages available the allocator spreads freely, so stage 11
looked nearly empty. Once the telemetry is gone the allocator **repacks the real caseA release/drain
tables to fill stages 7–11 anyway** — the tail's genuine 5-stage capacity demand is unchanged. Pure
RRC therefore stays **12→12**, and the combined faithful build stays **13→13** (the 4 freed LTIDs do
not collapse the ~14-table overflow into stage 12/13).

## 5. Why RRC's own structure cannot shed the stage (the irreducible element)

Both routes to 11 are structurally closed:

- **Head register merge — closed, and documented in the frozen kernel.** The natural way to shorten
  the head is to merge/collapse a register pair. RRC has already done the one available collapse:
  `defense4_rrc_kernel.p4` lines 500–514 record that adding a second register
  (`response_pending_gen`) to the ACK/RESP paths forms a **static dependency cycle** — `CLASS_RESP`
  needs `reg_tag` before `reg_ack_rel` while `CLASS_ACK_REL` needs the reverse — which **"DOES NOT
  PLACE"** (reproduced in `probe_retire_dependency.p4 -DPROBE_CYCLE` →
  `Table placement cannot make any more progress`). The resolution — phase-encoding the pending
  state *inside* `reg_tag` (generation-bound marker) — is the collapse the prompt referenced, and it
  is **already spent**. `D` is likewise deliberately **not** a register (folded into `tbl_params`'
  default action). The head is at minimum register count; any further merge re-opens the documented
  unplaceable cycle. The reg_tag↔reg_ack_rel co-location is exactly what holds the head at 7, so it
  cannot be shortened without reintroducing the cycle.

- **Tail LTID reduction — only by cutting load-bearing mechanism.** Removing ~16 LTIDs from the
  min-stage-≥7 tail means folding the caseA release/hold/drain/block-termination branch tree. That
  is precisely the SR1 TM-dispatch fold — and **SR1 is already applied in the combined verdict
  build**, which is still 13. The remaining tables are the silicon-validated exactly-once
  hold/release and blocker-termination logic; folding or deleting them alters mechanism behavior and
  would require **re-silicon-validation**, breaking the "preserve invariants / do not modify the
  silicon-proven mechanism" constraint. A stage bought that way is **not a valid result**, and this
  report does not claim it.

**Precise irreducible element:** the **5-stage caseA release/drain tail** (the exactly-once
hold → deadline-expiry → release/blocker-terminate branch tree, ~67 load-bearing logical tables at
min-stage ≥7), sitting on top of the already-minimized **7-stage register-arm head** whose one
available register collapse is spent and whose next merge is a compile-proven unplaceable cycle.
RRC's non-load-bearing slack (4 forensic registers) is real but does not occupy a *binding* stage,
so removing it cannot move the wall.

## 6. Invariants — what each change touched

| Change | exactly-once OPERATE | T0-anchoring | fail-open | RRC carve/reassembly/checksum | D4 timing |
|---|:--|:--|:--|:--|:--|
| Telemetry strip (this work) | untouched | untouched | untouched | untouched | untouched |

The telemetry strip is behavior-preserving (forensic-only), so **no invariant was traded** — but it
also does not buy a stage. No change that *would* buy a stage (head register merge, tail mechanism
fold/delete) is available without breaking an invariant or requiring re-silicon-validation.

## 7. Honesty boundary

Compile-fit is not silicon; the fitting probes here are compile-only and load nothing. The negative
is a *compile* result: the two NO-FIT builds emit no binary and the authoritative
`tofino supports up to 12 stages, using 13` error. The prior two-pipe faithful split
(`BOR_TWO_PIPE_FAITHFUL_RESULT.md`: pipe0 12/3, pipe1 10/0) remains the standing path for a faithful
BOR + RRC on the single chip's two physical pipes; this report confirms the one-pipe route stays
closed even after re-engineering RRC itself, because RRC has no removable ingress stage of its own.

## 8. Source + evidence

```
defense4_rrc_kernel.p4                    4861169f…  (frozen, untouched)
defense4_rrc_stagerecovery_probe.p4       e9ae7087…  (frozen + RRC_STRIP_TS_TELEMETRY guard; diff=4 lines)
defense4_rrc_bor_stagerecovery_probe.p4   0f5c11e3…  (SR probe + same guard)
defense4_rrc_bor_sr_probe.p4              0964e450…  (frozen SR probe, untouched)
```

Evidence dirs under `evidence/rrc_stage_recovery/`: `frozen_rrc_baseline/`,
`rrc_probe_control_nostrip/`, `rrc_probe_telemetry_strip/`, `combined_SR1234_orig/`,
`combined_SR1234_strip/`.
