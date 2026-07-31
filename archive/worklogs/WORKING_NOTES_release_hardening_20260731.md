> **ARCHIVED WORKLOG (2026-07-31).** The release-hardening pass this log tracks is
> complete and hardware-validated. Current state lives in `RESUME_STATE.md`; the
> release manifest is `defense3/MANIFEST.yaml`. Kept as a worklog, not a source of truth.

# WORKING NOTES — release-hardening pass (CORRECTIONS.md)

**Task:** execute the CORRECTIONS.md audit (release-hardening + repo-pruning) to completion,
verifying on hardware. Autonomous run authorized by Philip incl. hardware.

## Status (2026-07-31) — COMPLETE. §10.A + §5.5(B) + §5.6 all hardware-validated.

Branch `main`, all committed + pushed through `5a56564`. Switch restored to **Defense 2**
(`pktgen_abs.conf`), one `bf_switchd`. Working tree clean.

**Done + hardware-validated on Tofino-1 9.13.2:**
- §2.1 canonical `defense3/p4/case_a_defense3.p4` (R1/R2/R3 unconditional; token-identical to
  the flagged build; core 10/12·p10, tel/synth/inj 11/12·p10, 0 warnings). Pre-audit sources
  archived to `defense3/archive/pre_audit/`. Toggled A/B = `p4/probes/case_a_defense3_toggled.p4`.
- §2.2/§2.3 default `case_a_defense3` everywhere + arm-guard (silicon: R1/R2/R3 objects present);
  safe restore = final or Defense 2.
- §3 `control/parameter_policy.py` (single D/H/RTO/wrap authority; dropped 40 ms clamp + 22 ms
  guard); §4.2 `control/counter_map.py` (CF_BLOCK_REJECT=17 reset). §3.4 reg_failopen clean.
  §4.1 SyncCounters (`harness/read_counters.py`). §4.3 campaign fail-closed + `preflight.py`.
  §4.4 block.py hardened.
- §5.6 parser warning ELIMINATED (0 uninitialized_out_param, 9.13.2). §5.2/5.3 wording.
- §6.1 ledger relink; §6.2 `assert_salu_asm --require-r2` PASS on `artifacts/final/final_core_sde9132.bfa`.
- §7 report/README claims; §8 pruning+archiving; §9 MANIFEST.yaml + evidence/INDEX.md;
  §25 CLAUDE.md + RESUME_STATE rewritten. CORRECTIONS.md -> archive/audit/ORIGINAL_AUDIT.md.
- Hardware: `evidence/final_silicon/` — compile + assembly + `setup --config` 43/43 +
  **Gate 2 PASS (1/0)**. A regression the run caught (out['D'] key rename) was fixed.
- §10.B open-work #13 core-vs-telemetry parity established at artifact level.

**§5.5 (B) DONE:** writer/reader split applied to `case_a_defense3.p4`; 9.13.2 resource-neutral
(10/11 stages, path 10, 0 warn), assembly proves exp_seq_w is an unconditional store (seq 0
lands), assert_salu_asm --require-r2 PASS, Gate 2 PASS 1/0. Committed ab47aac.

## NEXT ACTION

Nothing outstanding from the audit. The release-hardening + repo-pruning pass (CORRECTIONS.md)
is complete and hardware-validated. Remaining items (REPORT §12 / MANIFEST open_items) are
NOT uniformly lab-blocked — corrected 2026-07-31: only external-wire R1/R3 injection is
genuinely topology-blocked (dp64 faces the SEL-751 directly). The hardware-timestamped capture
and the egress-retirement sweep are READY EXPERIMENTS (Vision's NIC supports hardware RX
timestamps); K-minimization is post-freeze optimization gated by the K=64 safety pin; the full
physical core-vs-telemetry parity campaign is the larger open part of an already-done
artifact-level parity. Switch on Defense 2; main clean.

## Traps re-confirmed this session
- run_defense3.sh restores to Defense 2 automatically (safe baseline). Swap needs synth loaded first.
- setup imports control/ via sys.path (/home/decps/d3/control staged flat + as pkg).
- `pgrep -cx bf_switchd` (not -f). Switch swap via /home/decps/d3/swap_generic.sh.
- Hardware verification is load-bearing: it caught the out['D'] regression that offline checks missed.
