# D9 bottlenecks: compiler and runtime

> **►► VERDICT (2026-08-07): TIMING EXPERIMENTS PARTIAL WITH CLOSED CLAIM BOUNDARY** — accepted for the timing normalization on the corrected binary; boundary (live negatives, byte identity, classification) physically blocked. Authority: `EXPERIMENTAL_EVIDENCE_FREEZE.md`.


> **►► RECONCILED 2026-08-07 (authoritative).** The source/binary in the next paragraph are the PRE-fix
> build (historical). The CURRENT repaired build is source sha256 `1242ca4d…` (fix commit `e47bcaa`),
> binary `97175e7d…`; its raw artifacts are in `compiler_9132_fix/`. The resource facts are stable
> across the fix (12/12 ingress, +3 logical tables absorbed with no stage increase), but any RUNTIME
> "live campaign" figure below is REOPENED and not accepted until Phase 6. R11 remains OPEN.

All compiler facts here come from the raw 9.13.2 build artifacts preserved in `compiler_9132_raw/`
(manifest.json, stage_adv.log, table_summary.log, phv_allocation_summary_0.log, mau.json,
resources.json, metrics.json, power.json) for the PRE-fix source (sha256 `1272679...`,
binary `0ec4e452...`); the corrected build's artifacts are in `compiler_9132_fix/`. Nothing here is a
hand summary without a backing artifact.

## Hardware and compiler bottlenecks

| resource | value | source |
|---|---|---|
| ingress stages | 12 of 12 (0 stage headroom) | table_summary.log: "Number of stages for ingress table allocation: 12" |
| egress stages | 0 of 12 | table_summary.log |
| critical path (true dependency depth) | 10 | caseA_9132_deployment_compile.txt |
| logical tables | 104 | metrics.json /mau/logical_tables |
| SRAM | 47 | metrics.json /mau/srams |
| TCAM | 10 | metrics.json /mau/tcams |
| stateful ALUs | 12 (the 12 core registers) | caseA_9132_deployment_compile.txt |
| stats ALUs | 9 | caseA_9132_deployment_compile.txt |
| ingress parser TCAM rows | 103 | metrics.json /parser/ingress/tcam_rows |

The binding constraint is not dependency depth (critical path 10 < 12) and not raw capacity (SRAM
47, TCAM 10 are well under budget). It is placement and co-location plus PHV-group pressure:

- The 32-bit PHV word group W0 through W15 is fully occupied, all sixteen 32-bit containers used
  by the deadline and timestamp arithmetic and the session trackers: `hdr.ib.seq`, `budget_init`,
  `read_len`, `exp_ack_cand`, `ingress_mac_tstamp[31:0]`, `ts32`, `seq_m`, `da_dr`, `ts_m`,
  `now_word`, `dl_cand`, `tresp_cand`, plus the port and address fields (phv_allocation_summary_0).
  Defense 4 added `da_dr`, `tresp_cand`, and the response-side scratch to this group over Defense 3,
  which is what tightened it.

### Why splitting reg_deadline and reg_tresp resolved the earlier co-location wall

A Tofino register occupies one MAU stage and every RegisterAction on it executes in that stage, so
two accesses at different control-flow depths cannot co-locate. Gate-2B (`GATE2B_RESULT.md`) proved
on the earlier consolidated probe that a single dual-purpose `reg_deadline` with four access sites
(reset, arm, held-ACK read, held-RESP read) could not share a stage with the pop register and forced
placement to about 19 stages. The shipped program instead uses two registers, `reg_deadline` (T_A,
two sites: `deadline_arm_once` and `deadline_rmw`) and `reg_tresp` (T_RESP, two sites: `tresp_arm_once`
and `tresp_rmw`). Two 2-site registers co-locate where one 4-site register did not, which is what
brings the program to 12 of 12 ingress. This is the direct application of the Gate-2B finding that
per-register access-site count, not register count, is the fit constraint.

### The next limiting dependency

With ingress at 12 of 12 and the W0-15 group full, the next headroom is only the empty egress
pipeline (0 of 12). Using it requires bridging metadata ingress to egress, which is out of the
authorized scope and deferred. So the current program has no in-scope room for additional ingress
logic (for example a combined-ACK classifier or a data-plane reservoir-readiness guard) without
first relieving the 32-bit PHV group or moving loop-only reads to egress.

## Runtime bottlenecks (measured on the deployed binary)

| property | measurement | source |
|---|---|---|
| reservoir establishment vs earliest ACK | `reg_ts_ack_arm - reg_ts_first_block` about 1.42 ms at the sampled transaction; native READ to ACK median 0.462 ms (p99 2.42) | live evidence-dump; PARAMETER_CALIBRATION.md |
| qid7 (ACK) reservoir peak occupancy | watermark 43 of 64 cells (blockers drain as they are generated, so the full 64 are not simultaneously resident); qid5 (RESP) reaches 64 | evidence-dump across campaigns |
| release tail (D3 ACK deadline) | CLRT median 0.032 ms, p95 0.044 ms | Campaign A |
| release tail (D4 dual) | CLRT p95 minus median about 0.05 ms (7.997 to 8.047) | Campaign A |
| deadline release fraction (D4 at D_A=4, D_R=8) | 80 to 88 of 120 per campaign; the remainder is the native tail arriving after T_RESP | Campaign A / grid |
| fail-open horizon H (budget 18000, K=64) | about 30.8 ms model | parameter policy |
| poll interval used | 400 ms; holds are single-digit ms, horizon about 30.8 ms, so the poll is far above the hold | campaigns |
| concurrency | one active transaction per scheduler domain (one global `reg_tag`); one protected session | source + spec |
| generation reuse | DNP3 app-seq C0..CF, 16-value reuse; at 400 ms polling the reuse interval is 6.4 s versus about 8 ms holds and 30.8 ms horizon, so reuse is safe | Campaign A (C0..CF exercised, 0 stale releases) |
| static policy update | mode and delays change only between inactive verified blocks (`set-policy` refuses while active) | harness B1 |
| reservoir depth | fixed K = 64 per role, seeded as a 2K = 128 burst split by packet_id | source + bring-up |

### Reservoir-readiness note (risk carried forward)

The ACK reservoir peak watermark of 43 of 64 and the establishment time of about 1.42 ms sit against
a native READ to ACK median of 0.462 ms. The design has no data-plane readiness guard; it relies on
the measured margin that the reservoir stands before the ACK is eligible. Across 1080 protected
transactions in Campaign A there were zero ordering violations and zero ACK escapes, which is
consistent with the margin holding in this lab, but the guard is a measured property, not a
structural guarantee (R11 remains open). Do not claim general scalability from one global register
slot or one protected session.
