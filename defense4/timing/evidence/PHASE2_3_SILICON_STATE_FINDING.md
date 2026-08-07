# Silicon state (read-only probe, 2026-08-07) — RETRACTION + corrected finding

## ►► RETRACTION of the first version of this file

An earlier version of this file claimed "the corrected binary was NEVER deployed; the switch runs the
pre-fix binary `0ec4e452`." **That claim was WRONG and is retracted.** It came from a careless probe
that hard-coded the path `d4_build/build9132/pipe/tofino.bin` instead of reading the binary path from
the actually-loaded conf. That is the same class of error this project has been correcting: a
conclusion from a check that did not measure what it claimed to measure.

## Corrected finding (derived from the loaded conf, no hard-coding)

The running `bf_switchd` loads conf `/home/decps/d4_fix_build/defense4_caseA_fix.conf`, whose pipeline
`config` is `/home/decps/d4_fix_build/out/defense4_caseA/pipe/tofino.bin`, sha256 `97175e7dc1a77c3c…`.
**That is the CORRECTED binary** (from corrected source `1242ca4d…`, identical to the repo). So:

- The switch **is** running the corrected Defense 4 binary `97175e7d`. The fix is deployed.
- The pre-fix binary `0ec4e452` (from old source `1272679c`) also exists on disk under
  `d4_build/build9132/`, but it is NOT what the running pipeline loads. It is historical.

## What IS a real (minor) issue

- The **repo** conf `defense4/timing/control/deploy/defense4_caseA.conf` points its `config` at
  `d4_build/build9132/pipe/tofino.bin` (the pre-fix path). That repo conf is stale and misleading: it
  is not the conf the switch actually loads. It should be updated to the corrected binary path, or
  clearly marked as not-the-deployed-conf, so no future reader repeats my mistake.
- The `run_campaign.sh` preflight improvement stands and is correct on its own merits: it now derives
  the binary sha from the LOADED conf's pipeline `config`, not from a disk file. Had I used that logic
  in the probe instead of hard-coding a path, I would not have made the false claim. (It is now the
  preflight, so a future run verifies the actually-loaded binary.)

## Corrected effect on the plan

- Phase 3's DEPLOY is effectively already done and now correctly VERIFIED: loaded program
  `defense4_caseA`, loaded binary sha `97175e7d`. Phase 3 still owes: confirm ports/queues/pktgen/
  policy/forwarding on this loaded binary, and a reproducible-compile check of the corrected source on
  BF-SDE 9.13.2.
- No live reload is required to get onto the corrected binary; it is already loaded. That removes the
  high-stakes reload I had flagged. Any switch write from here (policy set for a campaign) is still done
  behind the snapshot + watchdog + D3-rollback protocol.
- Physical SEL-751 stays READ-only. SELECT/OPERATE only ever hit the software outstation.
