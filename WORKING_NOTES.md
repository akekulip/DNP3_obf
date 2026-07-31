# WORKING NOTES — release-hardening pass (CORRECTIONS.md)

**Task:** execute the CORRECTIONS.md audit (release-hardening + repo-pruning) to completion,
verifying on hardware. Autonomous run authorized by Philip incl. hardware.

## Status (2026-07-31) — §10.A complete + hardware-validated; (B) in flight

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

**IN FLIGHT:** the §5.5 (B) TCP-sequence-zero fix (writer/reader split on reg_exp_relay_seq).
The p4-dataplane-engineer agent (id ac831b428c4e3dc73) is applying it to
`defense3/p4/case_a_defense3.p4` and compiling all four variants to confirm zero stage cost.

## NEXT ACTION (when the (B) agent reports)

1. Read its report: did B compile at the SAME resources (core 10/12·p10, others 11/12·p10),
   0 errors, 0 warnings, reg_exp_relay_seq with 2 RegisterActions within the 2-PHV-input budget?
2. If yes: stage `case_a_defense3.p4` to the switch, recompile 9.13.2, **re-run Gate 2**
   (swap d3_final_synth.conf; `D3_NO_TMUX=1 PROG=case_a_defense3 bash run/run_defense3.sh --gate2`),
   confirm 1 PASS/0 FAIL, re-archive the final .bfa, then commit + push. Restore to Defense 2, verify.
3. If B increases stages or errors: `git checkout defense3/p4/case_a_defense3.p4`, leave B as the
   designed-but-deferred item (already listed in MANIFEST open_items) and document why.

## Traps re-confirmed this session
- run_defense3.sh restores to Defense 2 automatically (safe baseline). Swap needs synth loaded first.
- setup imports control/ via sys.path (/home/decps/d3/control staged flat + as pkg).
- `pgrep -cx bf_switchd` (not -f). Switch swap via /home/decps/d3/swap_generic.sh.
- Hardware verification is load-bearing: it caught the out['D'] regression that offline checks missed.
