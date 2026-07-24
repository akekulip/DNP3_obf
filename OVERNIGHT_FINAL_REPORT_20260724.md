# Overnight Autonomous Run — Final Report (Session 2, 2026-07-24)

**Branch:** `overnight-autonomy-20260723-2255` · **HEAD:** `f0b48ea` · **End:** 2026-07-24 10:03 EDT.
Continuation of the offline fallback after the on-site Vision cold-restart. Governing plan: `autunomous.md`
(Session-2 continuation instruction). Append-only detail: `OVERNIGHT_RUN_20260723-2255.md` (Session 2 block).

**Headline:** dp8 remains physically blocked; **physical GATE-1 was not completed and is NOT marked
complete**. No SEL contact. Work advanced the roadmap as far as is safely possible without dp8, preserving
the seven-level validation distinction (impl / compiled / offline / bmv2 / tofino-partial / tofino-full /
sel). **Nothing below is Tofino- or SEL-validated this run.**

## dp8 status
Cold power cycle (on-site) + authorized read-only link check → dp8 `$PORT_UP=false`, carrier=0, DAC still
detected. Neither warm reboot nor cold power cycle recovers it. Root cause **unisolated** (Vision NIC/PHY/
firmware, DAC/breakout-leg, switch lane 15/0, connector, or interaction) — no controlled substitution done.

## Exactly what was IMPLEMENTED (new code this run)
- `shadow/gate1_validator_selftest.py` — negative-fixture self-test for the GATE-1 validator.
- `shadow/gate1_run.py` — single-command GATE-1 orchestrator (bounded timeouts, link precondition gate,
  finally-restore, complete-evidence-only PASS).
- `txncore/txncore_refmodel.py` — added runtime `enabled` (disabled-mode transparency).
- `tests/run_offline.py` — pytest-free runner for the repo's reference tests.
- `physical_sel751/size_inventory_20260724/size_inventory.py` — Phase-5 size-inventory analysis.
- `joint_eval/leakage_metrics.py` + `eval_schema.json` — Phase-7 leakage-analysis skeleton + schema.
- Reference-model coverage tests added (disabled-mode, duplicate-response, 8 GATE-1 corruptions, 3 leakage).

## Exactly what COMPILED (local bf-p4c 9.13.1; no switch)
- `dcrn_defense1_gen.p4` (generation **carried**): exit 0, **12/12 ingress**, `reg_gen` at stage 5, 2 benign
  TNA parser warnings, 0 errors. (Generation **enforced** does NOT fit — measured last session.)
- Frozen `dcrn_defense1.p4` recompiled as baseline: 12/12. `dcrn_defense2.p4`: 10/12 (prior record).

## Exactly what PASSED OFFLINE TESTS (re-run at close, 10:03 EDT)
| Suite | Result |
|---|---|
| Phase-1 shadow replay (300-poll) | PASS (300 READ/RESP, ACK triples, byte/order identity) |
| Phase-1 shadow negatives | PASS (14/14) |
| GATE-1 validator self-test | PASS (positive control + 8 corruptions detected) |
| Phase-2 txncore units | PASS (24/24) |
| Phase-2 txncore replay | PASS (ARM/HELD/RELEASED = 300 each, 0 stale, 0 residue) |
| Defense-1 reference model | PASS (17/17: zero-inversion, combined bypass, fail-open) |
| Defense-2 reference model | PASS (10/10: deadline-governed, miss, broken-clock) |
| Hardening FIX 1+2+4 | PASS (12/12) |
| Joint-eval leakage metrics | PASS (3/3: leaky detected, normalized at chance) |

## Partially validated on Tofino (PRIOR runs — unchanged, not re-claimed)
- Phase-1 shadow **dir-1 only**: 300 DNP3_RESP / 302 PURE_ACK / 605 frames, 0 loss (silicon, commit `d30d1dc`).

## Remains UNTESTED on Tofino (blocked on dp8)
- Phase-1 dir-0 (300 READ), byte-identity, forwarding — the B1 bidirectional GATE-1.
- Defense-1 continuous silicon replay; Defense-2 recirc/qid calibration; any joint/size silicon run.
- Generation enforcement (does not fit 12/12 — human redesign before it can even be loaded).

## SEL validation
- **None.** No DNP3 request was sent to the relay. (A prior read-only 300-poll Class-0 baseline exists.)

## Compiler + resource results
- gen-carried variant: 12/12 ingress, `reg_gen` stage 5, SRAM/TCAM/SALU match frozen Defense-1 profile.
- Defense 1 = 12/12 (0 headroom); Defense 2 = 10/12; shadow = 4/12. Logs in `txncore/evidence/`.

## Size evidence (Phase-5, analysis only — no mechanism)
23,382 responses inventoried. Physical relay response = **200 B wire / 134 B TCP-payload / 115 B DNP3-len**
(resolves the prior "134 B" = TCP payload, not wire). Global max wire 200 B → a single fixed cover must be
**≥256 B**; the existing 128 B state does NOT cover it (contradiction C5 quantified).

## Commits created (Session 2; all authored by Philip)
`403e97a` (cold-restart dp8 result) · `699aef0` (GATE-1 infra + reconciliation) · `028aa83` (txncore matrix
+ gate) · `09690d6` (defense offline gates + runner) · `484fa74` (size inventory) · `f0b48ea` (joint-eval
skeleton).

## Failures / unresolved ambiguity
- **1 test failure encountered and fixed** mid-run (duplicate-response test expected bypass without
  draining; corrected to drain first — the model was right). No failing tests remain.
- **7 spec contradictions** flagged (`SPEC_RECONCILIATION_20260724.md`): C1 native-CLRT (1.9 vs 12.9 ms),
  C2 Defense-2 G_i set (4 regimes), C3/C4 size mechanism + single-ASIC vs platform-split, C5 size coverage,
  C6 refmodel-vs-silicon direction, C7 "Case B" terminology. These are **human decisions** — not resolved
  autonomously. Phases 2-enforcement, 4-calibration, and 5-mechanism are blocked on them.

## Restored runtime state (verified at close)
- Switch: `queue_microbench_abs.conf` bound (1 bf_switchd), dp8 absent (`$PORT` empty), no stray procs. ✅
- Vision: reachable `10.10.54.19` (on eno1, with relay `192.168.10.1`); relay `192.168.10.7` reachable. ✅
- Hulk: clean. No replay/tcpdump/dumpcap/probe on any host. ✅
- Repo: frozen `dcrn_defense1.p4` / `dcrn_defense2.p4` / `dnp3_shadow.p4` all unchanged. ✅

## Next physical substitution procedure (the one gating step)
1. With Vision up, **reseat the dp8 SFP/DAC** on both ends (Vision `enp59s0f0np0` and the Tofino 15/0 leg).
2. Read-only check: `gate1_run.py`'s precondition (or `lane_probe add 8` + `read`) — need `$PORT_UP=true`
   + carrier + **≥5 min stable**.
3. If still down: **move the DAC to a known-good empty leg** (15/2=dp10 or 15/3=dp11) and/or swap the DAC
   cable; re-check. This isolates NIC vs DAC vs lane vs connector (the missing controlled substitution).
4. Once dp8 is stable, run `gate1_run.py run --evidence <dir>` — it gates on the link, runs B1, verifies
   against the self-tested validator, and restores the microbench in a finally path. GATE-1 completes in minutes.
