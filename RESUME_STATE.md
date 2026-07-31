# RESUME STATE — DNP3 project

**Reflects the tree through the release-hardening pass (2026-07-30/31); this status file was
committed immediately afterward.** For the exact current commit, run `git rev-parse HEAD` — do
not rely on a SHA written here (it goes stale the moment this file is committed).

Read this first, then `CLAUDE.md` for the rules and layout, and `defense3/REPORT.pdf` for the
work itself.

---

## Current headline

**Case A Defense 3 (predetermined in-network ACK delay) is complete, hardware-validated, and
release-hardened.** Everything lives in `defense3/`. The canonical program is
`defense3/p4/case_a_defense3.p4` (R1/R2/R3 unconditional — a no-flag build is the safe
repaired program). It was compiled on the deploy compiler (bf-p4c 9.13.2), the parser
`uninitialized_out_param` warning is eliminated, the R2 note predicate is present in the
assembly, `setup --config` passes 43/43 on silicon, and Gate 2 passes end-to-end. The switch
is restored to the frozen Defense 2 baseline.

## Repository / git state

- **Single branch `main`**, work committed and pushed in the same pass (no feature branches).
  Commits in Philip's name only.
- The release-hardening pass (CORRECTIONS.md) is complete for the release-blocking items and
  hardware-verified; see the audit response below.

## Switch state

- Restored to **Defense 2** (`dnp3_timing_normalizer_pktgen`, the frozen silicon-proven
  baseline), one `bf_switchd`. Verified.
- The final confs on the switch: `d3_final.conf` (core), `d3_final_synth.conf` (synthetic).
  Safe restore targets are the final repaired build or Defense 2 — **never** the unrepaired
  program, which loads only behind `--load-unrepaired-control` (CORRECTIONS.md §2.3).
- Hardware/switch changes remain gated on explicit Philip authorization.

## What the release-hardening pass did (CORRECTIONS.md)

- §2.1 canonical `case_a_defense3.p4` (R1/R2/R3 unconditional); pre-audit sources archived.
- §2.2 default program = `case_a_defense3` everywhere; a final-repair arm-guard refuses a
  non-final build. §2.3 safe restore baseline.
- §3 `control/parameter_policy.py` — one D/H/RTO/poll-rate authority (dropped the impossible
  40 ms clamp and the stale 22 ms guard); §4.2 `control/counter_map.py` (CF_BLOCK_REJECT=17
  now reset). §3.4 reg_failopen in clean/cleanup. §4.1 SyncCounters. §4.3 campaign fail-closed.
- §5.6 parser warning eliminated; §5.2/§5.3 duplicate-suppression wording qualified.
- §6.1 ledger link fix; §6.2 assert_salu_asm `--require-r2`; final artifacts under
  `artifacts/final/`. §7 report/README claim corrections. §8 pruning + archiving.
- Hardware: 9.13.2 compile (all targets, 0 warnings) + Gate 2 PASS + restore, in
  `defense3/evidence/final_silicon/`. A regression the run caught (out['D'] keys) was fixed.

## Open items (deferred / lab-blocked)

- **(B) §5.5 TCP-sequence-zero sentinel** — DONE: writer/reader split applied to the canonical
  P4, 9.13.2 resource-neutral, Gate 2 PASS, seq-0 store proven in the assembly.
- §10.B hardware (assessed 2026-07-31, `defense3/evidence/final_silicon/*/remaining_10B_assessment.md`):
  #13 core-vs-telemetry parity DONE at artifact level (full physical core campaign = larger open
  part); #14 hardware-timestamped capture and #12 egress sweep are **achievable** (Vision's NIC
  supports hardware RX timestamps) — ready experiments, not hard blocks; external-wire R1/R3
  injection is genuinely topology-blocked (dp64 faces the SEL-751); K-minimization is post-freeze
  optimization gated by the intentional K==64 safety pin (KVAL now wired into gate2).
- Defect-2 cross-transaction generation-wrap: model-checked, not physically reproduced.

## Key pointers

- `defense3/REPORT.pdf` / `REPORT.md` — the full report. `defense3/README.md` — directory map.
- `defense3/MANIFEST.yaml` — claims bound to source/artifact/evidence/analyzer.
- `defense3/evidence/INDEX.md` — what each evidence directory holds.
- `defense3/AUDIT_RESPONSE.md` — the audit resolution record.
- `defense3/archive/audit/ORIGINAL_AUDIT.md` — the original audit text (was `CORRECTIONS.md`).
- `CLAUDE.md` — rules and layout; `meeting.md` and archived directions under `defense3/archive/`.
