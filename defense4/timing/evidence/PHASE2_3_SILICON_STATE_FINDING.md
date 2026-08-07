# Silicon state finding (read-only probe, 2026-08-07) — the fix was NOT deployed

Before any Phase 2/3 work, a read-only probe of the running switch established ground truth. It
contradicts the archived freeze's "final switch state."

## What is actually running

- `bf_switchd` is up on the switch (`ufispace`, `decps@10.10.54.81`), program `defense4_caseA`.
- The loaded conf is `/home/decps/d4_build/build9132/... ` via `defense4_caseA_fix.conf`, and its
  pipeline `config` path is `/home/decps/d4_build/build9132/pipe/tofino.bin`.
- **sha256 of that loaded binary = `0ec4e452f63a63c2…` — the PRE-FIX binary** (the one with the
  mode-blind `tag_retire_if_unmarked` lifecycle defect: D2 240/240 bypass, D4 80/240 bypass).
- The corrected binary `97175e7dc1a77c3c…` exists on disk at
  `/home/decps/d4_fix_build/out/defense4_caseA/pipe/tofino.bin`, but the running pipeline does not
  load it. The "fix" conf name is misleading: it points at the pre-fix binary.

## Consequence

- The archived freeze statement "the switch runs the corrected binary `97175e7d`" is **not
  supported**. The corrected binary was compiled but never deployed to the running pipeline.
- `run_campaign.sh`'s old preflight ran `sha256sum` on the `d4_fix_build` disk file and compared it to
  the expected fix sha. That check passed because the FILE exists with that sha, but it never verified
  the LOADED pipeline. It would have rubber-stamped a run on the pre-fix binary. Fixed: the preflight
  now derives the binary path from the loaded conf's pipeline `config` and shas THAT, so it verifies
  the actually-running binary.

## Effect on the plan

- The current silicon state is **pre-fix (`0ec4e452`)**. Phase 2 (controlled software outstation) will
  therefore be expected to reproduce the pre-fix D2/D4 RESPONSE bypass, confirming the defect through
  the controlled path.
- Phase 3 must actually DEPLOY the corrected binary: verify the corrected source (`1242ca4d…`)
  compiles to `97175e7d…` on BF-SDE 9.13.2, point the loaded conf at it (or rebuild `build9132` from
  the fix), reload under the snapshot + watchdog + D3-rollback protocol, and verify the LOADED
  pipeline sha == `97175e7d` (not a disk file). No timing claim on the corrected binary is accepted
  until it is the verified loaded pipeline.
- Physical SEL-751 stays READ-only throughout. SELECT/OPERATE only ever hit the software outstation.
